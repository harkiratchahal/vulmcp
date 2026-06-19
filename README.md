<div align="center">
  <h1>🛡️ VulnixMCP</h1>
  <p><strong>An Intelligent Security Scanner MCP Server for AI Infrastructure</strong></p>
</div>

VulnixMCP is a Model Context Protocol (MCP) server purpose-built to give Claude Desktop (and other MCP clients) the ability to autonomously scan targets for vulnerabilities in modern AI components such as LiteLLM, Ollama, ChromaDB, Qdrant, LangChain, and FastMCP.

By utilizing VulnixMCP, Claude gains access to real tools to scan infrastructure, query CVE data, calculate contextual risk scores, identify intelligent attack chains, and write complete security reports—all through natural conversation.

---

## 🚀 Live Server URL
The MCP server is currently deployed and live at:
**`https://vul-mcp.fastmcp.app/mcp`**

### Connecting to Claude Desktop
To use VulnixMCP in Claude Desktop, add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "VulnixMCP": {
      "command": "npx",
      "args": ["-y", "@fastmcp/client", "https://vul-mcp.fastmcp.app/mcp"]
    }
  }
}
```
*(Note: Because this is an HTTP-based remote server, we use the FastMCP client adapter to bridge it to Claude's STDIO protocol).*

---

## ✨ Features

- **🤖 AI Infra Intelligence**: Tailored port scanning and fingerprinting for AI services (Vector databases, LLM servers, Frameworks).
- **🔍 Vulnerability Enrichment**: Automatically queries OSV, NVD, EPSS, and the CISA Known Exploited Vulnerabilities (KEV) catalogs.
- **📊 Contextual Risk Scoring**: Uses a custom risk formula blending CVSS, EPSS, CISA KEV presence, and internet exposure.
- **🧠 Claude-powered Attack Chains**: Asynchronously feeds finding data into Claude (via Anthropic API) to identify logical exploitation attack paths based on the contextual findings.
- **⚡ Asynchronous Execution**: Built on Celery and Redis to handle long-running security scans asynchronously without blocking Claude's conversational flow.
- **📝 Full Markdown Reporting**: Generates visually friendly, structured reports through Jinja2 templates directly into the Claude UI.

---

## 🏗️ Architecture & Deployment

VulnixMCP uses a split architecture to handle long-running port scans without timing out the MCP protocol:

1. **The MCP Server (FastMCP)**: Hosted on FastMCP Cloud (`https://vul-mcp.fastmcp.app/mcp`). This provides the tools that Claude calls.
2. **The Celery Worker**: Because scanning and fetching CVEs takes time, the actual work is dispatched to a Redis queue and processed by a Celery worker. **You must run the Celery worker somewhere else** (e.g., Render, Railway, AWS).

### 🛠️ Tech Stack
- **Python** (>= 3.11)
- **FastMCP** (MCP server framework)
- **Nmap** (Network scanning & fingerprinting)
- **Celery & Redis** (Asynchronous tasks queue)
- **SQLAlchemy & PostgreSQL** (Data persistence)
- **Anthropic API** (Attack chain synthesis)

---

## 💻 Local Setup & Worker Deployment

If you are hosting the Celery worker, you will need the following prerequisites:
1. [uv](https://github.com/astral-sh/uv) - Python package manager
2. **Nmap** (`sudo apt-get install nmap` on Debian/Ubuntu)
3. Hosted **PostgreSQL** instance
4. Hosted **Redis** instance
5. **API Keys**: Anthropic API Key (for attack paths) and NVD API Key (from NIST).

### Installation
```bash
git clone https://github.com/harkiratchahal/vulmcp.git
cd vulnixmcp
uv sync
```

### Environment Configuration
Copy the template and fill in your database, Redis, and API keys:
```bash
cp .env.example .env
```
Initialize the database:
```bash
uv run python -c "from vulnixmcp.database import create_tables; create_tables()"
```

### Running the Worker
To process the scans triggered by Claude, start the Celery worker:
```bash
uv run celery -A vulnixmcp.tasks worker --loglevel=info
```

*(Optional: To run the MCP Server locally for testing, use `uv run python main.py`)*

---

## 🗣️ Usage in Claude

Once connected and the worker is running, you can ask Claude Desktop:

1. **Start a scan:** 
   > *"Run a full security scan on 127.0.0.1. I authorize this scan, my name is [Your Name], and I explicitly confirm it."*
2. **Check the status:**
   > *"What is the status of the scan you just started?"*
3. **Generate the report:**
   > *"Generate the full security report for the completed scan."*
