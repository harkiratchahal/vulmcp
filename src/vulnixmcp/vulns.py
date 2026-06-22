import os
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from loguru import logger
import time


_kev_cache = None
_kev_cache_time = None


def query_osv(package_name: str, version: str) -> list[dict]:
    try:
        url = "https://api.osv.dev/v1/query"
        payload = {
            "version": version,
            "package": {"name": package_name, "ecosystem": "PyPI"}
        }
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()

        data = response.json()
        vulns = data.get("vulns", [])

        results = []
        for v in vulns:
            results.append({
                "id": v.get("id"),
                "summary": v.get("summary"),
                "details": v.get("details"),
                "aliases": v.get("aliases", [])
            })
        return results
    except Exception as e:
        logger.error(f"OSV query failed for {package_name} {version}: {e}")
        return []


def query_nvd(software_name: str, version: str) -> list[dict]:
    time.sleep(0.7)
    try:
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = {
            "keywordSearch": f"{software_name} {version}",
            "resultsPerPage": 20
        }

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        response = requests.get(url, params=params, headers=headers, timeout=15)

        # Handle NVD rate limiting gracefully
        if response.status_code == 403:
            logger.warning(f"NVD rate limited for {software_name} {version}, skipping")
            return []

        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        results = []
        for item in vulnerabilities:
            cve_item = item.get("cve", {})
            cve_id = cve_item.get("id")

            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

            cvss_score = None
            metrics = cve_item.get("metrics", {})
            if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

            if cve_id:
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score
                })

        return results
    except Exception as e:
        logger.error(f"NVD query failed for {software_name} {version}: {e}")
        return []


def get_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}

    try:
        cves_str = ",".join(cve_ids)
        url = f"https://api.first.org/data/v1/epss?cve={cves_str}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        data = response.json()

        results = {}
        for item in data.get("data", []):
            cve = item.get("cve")
            if cve:
                results[cve] = {
                    "epss": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0))
                }

        return results
    except Exception as e:
        logger.error(f"EPSS query failed: {e}")
        return {}


def check_kev() -> set[str]:
    global _kev_cache, _kev_cache_time

    now = datetime.now()
    if _kev_cache is not None and _kev_cache_time is not None:
        if now - _kev_cache_time < timedelta(hours=1):
            return _kev_cache

    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=20)
        response.raise_for_status()

        data = response.json()
        _kev_cache = set()

        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if cve_id:
                _kev_cache.add(cve_id)

        _kev_cache_time = now
        return _kev_cache
    except Exception as e:
        logger.error(f"KEV check failed: {e}")
        return _kev_cache or set()


def _query_asset_vulns(asset: dict) -> list[dict]:
    """Query OSV and NVD for a single asset. Runs in a thread pool."""
    name = asset.get("component_name")
    version = asset.get("version")

    if not name or not version:
        return []

    # Run OSV and NVD queries in parallel for this asset
    osv_results = query_osv(name, version)
    nvd_results = query_nvd(name, version)

    # Deduplicate and merge by CVE ID
    cve_map = {}

    for osv in osv_results:
        cves = [a for a in osv.get("aliases", []) if a.startswith("CVE-")]
        for cve in cves:
            if cve not in cve_map:
                cve_map[cve] = {
                    "cve_id": cve,
                    "description": osv.get("details") or osv.get("summary") or "",
                    "cvss_score": None,
                    "asset": asset
                }

    for nvd in nvd_results:
        cve = nvd.get("id")
        if cve:
            if cve in cve_map:
                if nvd.get("cvss_score"):
                    cve_map[cve]["cvss_score"] = nvd.get("cvss_score")
                if nvd.get("description") and not cve_map[cve]["description"]:
                    cve_map[cve]["description"] = nvd.get("description")
            else:
                cve_map[cve] = {
                    "cve_id": cve,
                    "description": nvd.get("description") or "",
                    "cvss_score": nvd.get("cvss_score"),
                    "asset": asset
                }

    return list(cve_map.values())


def get_all_vulnerabilities(assets: list[dict]) -> list[dict]:
    all_findings = []

    # Pre-fetch the KEV list once (not per-asset)
    kev_set = check_kev()

    # Query each asset for vulnerabilities (parallelized across assets)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_query_asset_vulns, asset): asset for asset in assets}
        for future in as_completed(futures):
            try:
                asset_findings = future.result()
                all_findings.extend(asset_findings)
            except Exception as e:
                asset = futures[future]
                logger.error(f"Vuln query failed for asset {asset.get('component_name')}: {e}")

    # Batch-fetch EPSS scores for all CVEs at once
    all_cve_ids = [f["cve_id"] for f in all_findings]
    if all_cve_ids:
        epss_scores = get_epss_scores(all_cve_ids[:100])

        for finding in all_findings:
            cve = finding["cve_id"]
            finding["epss_score"] = epss_scores.get(cve, {}).get("epss")
            finding["epss_percentile"] = epss_scores.get(cve, {}).get("percentile")
            finding["is_kev"] = cve in kev_set

    return all_findings
