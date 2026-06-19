# VulnixMCP

VulnixMCP is a security scanner Model Context Protocol (MCP) server purpose-built for AI infrastructure stacks. It provides Claude Desktop with the capability to scan targets for vulnerabilities in modern AI components such as LiteLLM, Ollama, ChromaDB, Qdrant, LangChain, and FastMCP.

By utilizing VulnixMCP, Claude gains access to real tools to scan infrastructure, query CVE data, calculate contextual risk scores, identify intelligent attack chains, and write complete security reports—all through natural conversation.

## Features

- **AI Infra Intelligence**: Tailored port scanning and fingerprinting for AI services (Vector databases, LLM servers, Frameworks).
- **Vulnerability Enrichment**: Automatically queries OSV, NVD, EPSS, and the CISA Known Exploited Vulnerabilities (KEV) catalogs.
- **Contextual Risk Scoring**: Uses a custom risk formula blending CVSS, EPSS, CISA KEV presence, and internet exposure.
- **Claude-powered Attack Chains**: Asynchronously feeds finding data into Claude (via Anthropic API) to identify logical exploitation attack paths based on the contextual findings.
- **Asynchronous Execution**: Built on Celery and Redis to handle long-running security scans asynchronously without blocking Claude's conversational flow.
- **Full Markdown Reporting**: Generates visually friendly, structured reports through Jinja2 templates directly into the Claude UI.

## Tech Stack

- **Python** (>= 3.11)
- **FastMCP** (MCP server framework)
- **Nmap** (Network scanning & fingerprinting)
- **Celery & Redis** (Asynchronous tasks queue)
- **SQLAlchemy & PostgreSQL** (Data persistence)
- **Anthropic API** (Attack chain synthesis)

## Prerequisites

1. [uv](https://github.com/astral-sh/uv) - Python package manager
2. **Nmap** (`sudo apt-get install nmap` on Debian/Ubuntu/WSL)
3. Hosted **PostgreSQL** instance (e.g., [Neon](https://neon.tech/))
4. Hosted **Redis** instance (e.g., [Upstash](https://upstash.com/))
5. **Anthropic API Key** (for attack path analysis via Claude 3.5 Sonnet)
6. **NVD API Key** (free from [NIST](https://nvd.nist.gov/developers/request-an-api-key))

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/harkiratchahal/vulmcp.git
   cd vulnixmcp
   ```

2. **Sync dependencies using `uv`:**
   ```bash
   uv sync
   ```

3. **Environment Variables:**
   Copy the example environment file and fill in your secrets.
   ```bash
   cp .env.example .env
   ```

4. **Initialize the Database:**
   ```bash
   uv run python -c "from vulnixmcp.database import create_tables; create_tables()"
   ```

## Running the Components

VulnixMCP relies on a Celery worker for processing the actual scans within the background.

1. **Start the Celery worker (in a dedicated terminal):**
   ```bash
   uv run celery -A vulnixmcp.tasks worker --loglevel=info
   ```

2. **Start the MCP Server on stdio (Optional for manual testing):**
   ```bash
   uv run python main.py
   ```

## Usage in Claude

Once configured and the worker is running, you can ask Claude Desktop:

1. **Start a scan:** 
   > *"Run a full security scan on 127.0.0.1. I authorize this scan, my name is [Your Name], and I explicitly confirm it."*
2. **Check the status:**
   > *"What is the status of the scan you just started?"*
3. **Generate the report:**
   > *"Generate the full security report for the completed scan."*

## Architecture

- **`scanner.py`**: Executes Nmap on specified AI-native ports and fingerprints services.
- **`vulns.py`**: Looks up unauthenticated vulnerability feeds (OSV, NVD) and pulls context points (EPSS, KEV).
- **`scoring.py`**: Evaluates environmental parameters into a `0.0` - `10.0` risk score.
- **`server.py`**: Binds the FastMCP tools for Claude over stdio.
- **`reporter.py`**: Utilizes Jinja2 to output structured Markdown reporting.

## Deployment to FastMCP Cloud

To deploy this server to FastMCP Cloud/Horizon, simply ensure that your `.env` variables (Database URL, Redis URL, API keys) are configured in your Horizon project dashboard. FastMCP cloud natively detects your FastMCP instance (`mcp`) in the code when you link the repository.
