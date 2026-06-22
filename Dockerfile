FROM python:3.11-slim

# Install Nmap
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Tell uv to install into system Python, not a venv
ENV UV_SYSTEM_PYTHON=1

WORKDIR /app

# Copy lockfile first — layer cache only busts on dependency changes
COPY pyproject.toml uv.lock ./
RUN uv sync --no-install-project --frozen

# Copy source and install project itself
COPY . .
RUN uv sync --frozen

EXPOSE 8080

CMD ["uv", "run", "python", "main.py"]