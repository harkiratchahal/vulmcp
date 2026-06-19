FROM python:3.11-slim

# Install system dependencies, specifically Nmap
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Install uv (Python package manager)
RUN pip install uv

WORKDIR /app

# Copy dependency files first for caching
COPY pyproject.toml .

# Install dependencies using uv without the local package
RUN uv sync --no-install-project

# Copy the rest of the application code
COPY . .

# Final sync to install the project itself
RUN uv sync

# Let the host environment (like FastMCP Horizon) execute the required entry point.
# For manual docker runs, start the MCP on stdio:
CMD ["uv", "run", "python", "main.py"]
