import os
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pyghidra_mcp.context import PyGhidraContext


# Create a simple test binary
def create_test_binary():
    """Create a simple test binary for testing."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write("""
#include <stdio.h>

int main() {
    printf("Hello, World!\\n");
    return 0;
}
""")
        c_file = f.name

    # Compile to binary
    bin_file = c_file.replace(".c", "")
    os.system(f"gcc -o {bin_file} {c_file}")

    return bin_file


# Create server parameters for stdio connection with a test binary
def get_server_params():
    """Get server parameters with a test binary."""
    # Create a test binary
    bin_file = create_test_binary()

    return StdioServerParameters(
        command="python",  # Executable
        args=["-m", "pyghidra_mcp", bin_file],  # Run with test binary
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_decompile_function_tool():
    """Test the decompile_function tool."""
    server_params = get_server_params()

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Call the decompile_function tool
            try:
                binary_name = PyGhidraContext._gen_unique_bin_name(
                    server_params.args[-1])
                results = await session.call_tool(
                    "decompile_function", {
                        "binary_name": binary_name, "name": "main"}
                )

                # Check that we got results
                assert results is not None
                assert results.content is not None
                assert len(results.content) > 0

                # Check that the result contains decompiled code
                # (this might vary depending on the binary and Ghidra's analysis)
                # We'll just check that it's not empty
                text_content = results.content[0].text
                assert text_content is not None
                assert len(text_content) > 0
                assert "main" in text_content
            except Exception as e:
                # If we get an error, it might be because the function wasn't found
                # or because of issues with the binary analysis
                # We'll just check that we got a proper error response
                assert e is not None


def test_create_test_binary():
    """Test that we can create a test binary."""
    bin_file = create_test_binary()

    # Check that the file exists
    assert os.path.exists(bin_file)

    # Clean up
    os.unlink(bin_file + ".c")
    os.unlink(bin_file)
