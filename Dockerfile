FROM python:3.11-slim

# Install system dependencies, specifically Nmap
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Install uv (Python package manager)
RUN pip install uv

WORKDIR /app

# Copy dependency files first for caching
COPY pyproject.toml uv.lock ./

# Install dependencies using uv without the local package
RUN uv sync --no-install-project

# Copy the rest of the application code
COPY . .

# Final sync to install the project itself
RUN uv sync

# Expose the default server port
EXPOSE 8000

# Start the MCP server with HTTP transport
CMD ["uv", "run", "python", "main.py"]
