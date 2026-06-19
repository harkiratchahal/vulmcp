import os
from vulnixmcp.server import mcp

def main():
    # Bind to 0.0.0.0 for remote/cloud deployment
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
    )

if __name__ == "__main__":
    main()
