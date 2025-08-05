import pytest
import tempfile
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        c_file = f.name
        f.write("""
#include <stdio.h>

int main() {
    printf(\"Hello, World!\\n\");
    return 0;
}
""")

    # Compile to binary
    bin_file = c_file.replace('.c', '')
    os.system(f'gcc -o {bin_file} {c_file}')

    yield bin_file

    # Clean up
    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        args=["-m", "pyghidra_mcp", test_binary],  # Run with test binary
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_stdio_client_initialization(server_params):
    """Test stdio client initialization."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            result = await session.initialize()

            # Check that we got a proper response
            assert result is not None
            assert hasattr(result, 'protocolVersion')


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
            assert any(
                tool.name == "decompile_function" for tool in tools.tools)
            assert any(
                tool.name == "list_project_binaries" for tool in tools.tools)
            assert any(
                tool.name == "list_project_program_info" for tool in tools.tools)


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
