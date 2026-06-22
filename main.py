import os
from vulnixmcp.server import mcp

def main():
    # Bind to 0.0.0.0 for remote/cloud deployment
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        path="/mcp",
    )

if __name__ == "__main__":
    main()
