import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_stdio_client_initialization(server_params):
    """Test stdio client initialization."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            result = await session.initialize()

            # Check that we got a proper response
            assert result is not None
            assert hasattr(result, "protocolVersion")


@pytest.mark.asyncio
async def test_stdio_client_list_tools(server_params):
    """Test listing available tools."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # List available tools
            tools = await session.list_tools()

            # Check that we got a response
            assert tools is not None
            # Check that we have at least the decompile_function tool
            assert any(tool.name == "decompile_function" for tool in tools.tools)
            assert any(tool.name == "list_project_binaries" for tool in tools.tools)


@pytest.mark.asyncio
async def test_stdio_client_list_resources(server_params):
    """Test listing available resources."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # List available resources
            resources = await session.list_resources()

            # Check that we got a response
            assert resources is not None
