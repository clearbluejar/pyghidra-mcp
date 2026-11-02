"""Keep MCP Python SDK 1 and 2 differences at the server boundary."""

from importlib.metadata import version as package_version
from typing import TYPE_CHECKING, Any, Literal, cast

IS_MCP_V2 = int(package_version("mcp").split(".", 1)[0]) >= 2

if TYPE_CHECKING or IS_MCP_V2:
    from mcp.server.mcpserver import Context as Context, MCPServer as MCPServer
    from mcp.server.mcpserver.exceptions import ToolError as ToolError
else:
    from mcp.server.fastmcp import Context as Context, FastMCP as MCPServer
    from mcp.server.fastmcp.exceptions import ToolError as ToolError
    from mcp.server.fastmcp.server import Settings

    # SDK 1 leaves a lifespan forward reference unresolved with newer Pydantic.
    Settings.model_rebuild()


def create_server(name: str, *, version: str = "", lifespan=None) -> MCPServer:
    """Construct the installed SDK's server and advertise our package version."""
    if IS_MCP_V2:
        return MCPServer(name, version=version, lifespan=lifespan)
    server = MCPServer(name, lifespan=lifespan)
    cast(Any, server)._mcp_server.version = version
    return server


def run_server(
    server: MCPServer,
    transport: Literal["stdio", "sse", "streamable-http"],
    host: str,
    port: int,
) -> None:
    """SDK 1 stores network settings; SDK 2 accepts them when running."""
    if transport == "stdio":
        server.run(transport="stdio")
    elif IS_MCP_V2:
        server.run(transport=transport, host=host, port=port)
    else:
        legacy_server = cast(Any, server)
        legacy_server.settings.host = host
        legacy_server.settings.port = port
        server.run(transport=transport)
