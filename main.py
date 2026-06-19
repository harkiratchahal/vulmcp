from vulnixmcp.server import mcp

def main():
    # Run with HTTP transport
    mcp.run(transport="http", host="127.0.0.1", port=9000)

if __name__ == "__main__":
    main()
