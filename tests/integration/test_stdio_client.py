import json
import pytest
import tempfile
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# Create a simple test binary
def create_test_binary():
    """Create a simple test binary for testing."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write("""
#include <stdio.h>

int main() {
    printf("Hello, World!\\n");
    return 0;
}
""")
        c_file = f.name

    # Compile to binary
    bin_file = c_file.replace('.c', '')
    os.system(f'gcc -o {bin_file} {c_file}')

    return bin_file


# Create server parameters for stdio connection
def get_server_params(binary_path: str):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        args=["-m", "pyghidra_mcp", binary_path],  # Run with test binary
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_stdio_client_initialization():
    """Test stdio client initialization."""
    bin_file = create_test_binary()
    server_params = get_server_params(bin_file)
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize the connection
                result = await session.initialize()

                # Check that we got a proper response
                assert result is not None
                assert hasattr(result, 'protocolVersion')
    finally:
        os.unlink(bin_file + '.c')
        os.unlink(bin_file)


@pytest.mark.asyncio
async def test_stdio_client_list_tools():
    """Test listing available tools."""
    bin_file = create_test_binary()
    server_params = get_server_params(bin_file)
    try:
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
    finally:
        os.unlink(bin_file + '.c')
        os.unlink(bin_file)


@pytest.mark.asyncio
async def test_stdio_client_list_resources():
    """Test listing available resources."""
    bin_file = create_test_binary()
    server_params = get_server_params(bin_file)
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize the connection
                await session.initialize()

                # List available resources
                resources = await session.list_resources()

                # Check that we got a response
                assert resources is not None
    finally:
        os.unlink(bin_file + '.c')
        os.unlink(bin_file)
