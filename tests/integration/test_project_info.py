import json
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
async def test_list_project_binaries_tool():
    """Test the list_project_binaries tool."""
    bin_file = create_test_binary()
    server_params = get_server_params(bin_file)
    binary_name = PyGhidraContext._gen_unique_bin_name(bin_file)

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize the connection
                await session.initialize()

                # Call the list_project_binaries tool
                results = await session.call_tool("list_project_binaries", {})

                # Check that we got results
                assert results is not None
                assert results.content is not None
                assert len(results.content) > 0

                # The result should be a list of program basic info
                text_content = results.content[0].text
                program_infos = json.loads(text_content)
                assert "programs" in program_infos
                assert isinstance(program_infos["programs"], list)
                program_infos = program_infos["programs"]
                assert len(program_infos) > 0

                found = False
                for program in program_infos:
                    if program["name"] == binary_name:
                        found = True
                        assert program["analysis_complete"]
                        break

                assert found

    finally:
        # Clean up the test binary and its source
        c_file = bin_file + ".c"
        if os.path.exists(c_file):
            os.unlink(c_file)
        if os.path.exists(bin_file):
            os.unlink(bin_file)


@pytest.mark.asyncio
async def test_list_project_program_info_tool():
    """Test the list_project_program_info tool."""
    bin_file = create_test_binary()
    server_params = get_server_params(bin_file)
    binary_name = PyGhidraContext._gen_unique_bin_name(bin_file)

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize the connection
                await session.initialize()

                # Call the list_project_program_info tool
                results = await session.call_tool("list_project_program_info", {})

                # Check that we got results
                assert results is not None
                assert results.content is not None
                assert len(results.content) > 0

                # The result should be a JSON object with a 'programs' key
                text_content = results.content[0].text
                assert text_content is not None
                program_infos = json.loads(text_content)
                assert "programs" in program_infos
                assert isinstance(program_infos["programs"], list)
                assert len(program_infos["programs"]) > 0

                # Check that our binary is in the list
                found = False
                for prog_info in program_infos["programs"]:
                    if prog_info["name"] == binary_name:
                        found = True
                        assert prog_info["file_path"] is not None
                        assert prog_info["analysis_complete"] is True
                assert found

    finally:
        # Clean up the test binary and its source
        c_file = bin_file + ".c"
        if os.path.exists(c_file):
            os.unlink(c_file)
        if os.path.exists(bin_file):
            os.unlink(bin_file)
