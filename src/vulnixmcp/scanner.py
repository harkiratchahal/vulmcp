import nmap
import ipaddress
import socket

PORT_TO_COMPONENT = {
    11434: {"name": "ollama",    "service_type": "llm_server",   "label": "Ollama LLM Server"},
    6333:  {"name": "qdrant",    "service_type": "vector_db",    "label": "Qdrant Vector DB"},
    6334:  {"name": "qdrant",    "service_type": "vector_db",    "label": "Qdrant gRPC"},
    8001:  {"name": "chromadb",  "service_type": "vector_db",    "label": "ChromaDB"},
    8000:  {"name": "litellm",   "service_type": "llm_proxy",    "label": "LiteLLM / FastAPI"},
    8080:  {"name": "langserve", "service_type": "ai_framework", "label": "LangServe / AI API"},
    6379:  {"name": "redis",     "service_type": "cache",        "label": "Redis"},
    5432:  {"name": "postgres",  "service_type": "database",     "label": "PostgreSQL"},
    7474:  {"name": "neo4j",     "service_type": "graph_db",     "label": "Neo4j"},
    19530: {"name": "milvus",    "service_type": "vector_db",    "label": "Milvus"},
    9090:  {"name": "prometheus","service_type": "monitoring",   "label": "Prometheus"},
    3000:  {"name": "grafana",   "service_type": "monitoring",   "label": "Grafana"},
}

def scan_target(target: str) -> list[dict]:
    nm = nmap.PortScanner()
    ports_str = ",".join(str(p) for p in PORT_TO_COMPONENT.keys())
    
    nm.scan(target, arguments=f"-p {ports_str} -sV --version-intensity 2 -T4 --open --host-timeout 60s")
    
    results = []
    
    # We only care about the single target.
    # IP might be different from target string, so we iterate all returned hosts
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                if state == 'open':
                    service = nm[host][proto][port].get('name', '')
                    version = nm[host][proto][port].get('version', None)
                    product = nm[host][proto][port].get('product', None)
                    
                    if not version:
                        version = None
                    if not product:
                        product = None
                        
                    results.append({
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "version": version,
                        "product": product,
                        "target": target
                    })
    return results

def is_ip_public(ip_or_host: str) -> bool:
    try:
        ip = getattr(ipaddress, "ip_address")(ip_or_host)
    except ValueError:
        try:
            ip_str = socket.gethostbyname(ip_or_host)
            ip = getattr(ipaddress, "ip_address")(ip_str)
        except socket.error:
            return False
            
    return not ip.is_private

def identify_ai_components(services: list[dict]) -> list[dict]:
    enriched = []
    
    for s in services:
        port = s["port"]
        target = s["target"]
        
        comp = PORT_TO_COMPONENT.get(port)
        if comp:
            enriched.append({
                **s,
                "component_name": comp["name"],
                "service_type": comp["service_type"],
                "label": comp["label"],
                "is_public": is_ip_public(target)
            })
            
    return enriched
