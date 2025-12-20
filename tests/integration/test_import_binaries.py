import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


def find_binary_in_list_response(response, binary_name):
    text_content = response.content[0].text
    program_infos = json.loads(text_content)["programs"]

    found_program = None
    for program in program_infos:
        if binary_name in program["name"]:
            found_program = program
            break

    return found_program


@pytest.fixture()
def binaries_in_directory():
    """Create a temporary filesystem with multiple test binaries in subdirectories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir) / "filesystem"
        bin_dir = root / "bin"
        lib_dir = root / "lib"
        bin_dir.mkdir(parents=True, exist_ok=True)
        lib_dir.mkdir(parents=True, exist_ok=True)

        # Create first binary in bin/
        c_file_1 = bin_dir / "program1.c"
        c_file_1.write_text(
            """
#include <stdio.h>

int main() {
    printf("Program 1");
    return 0;
}
"""
        )
        bin_file_1 = bin_dir / "program1"
        os.system(f"gcc -o {bin_file_1} {c_file_1}")

        # Create second binary in lib/
        c_file_2 = lib_dir / "program2.c"
        c_file_2.write_text(
            """
#include <stdio.h>

void hello() {
    printf("Program 2");
}
"""
        )
        bin_file_2 = lib_dir / "program2.so"
        os.system(f"gcc -shared -o {bin_file_2} {c_file_2}")

        # Create a non-binary file (should be skipped)
        readme = root / "README.txt"
        readme.write_text("This is not a binary")

        yield root, bin_file_1, bin_file_2

        # Cleanup
        c_file_1.unlink(missing_ok=True)
        c_file_2.unlink(missing_ok=True)
        readme.unlink(missing_ok=True)
        bin_file_1.unlink(missing_ok=True)
        bin_file_2.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_import_binaries_recursive(binaries_in_directory, server_params_no_input):
    """
    Test that import_binaries recursively discovers and imports multiple binaries
    from a directory structure, skipping non-binary files.
    """
    filesystem_root, bin_file_1, bin_file_2 = binaries_in_directory

    async with stdio_client(server_params_no_input) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Import the entire filesystem directory recursively
            response = await session.call_tool(
                "import_binary", {"binary_path": str(filesystem_root)}
            )
            content = response.content[0].text
            assert "Importing" in content

            bin_1_name = PyGhidraContext._gen_unique_bin_name(bin_file_1)
            bin_2_name = PyGhidraContext._gen_unique_bin_name(bin_file_2)

            # Wait for both binaries to be ready
            bin_1_ready = False
            bin_2_ready = False

            for _ in range(240):
                await asyncio.sleep(1)

                response = await session.call_tool("list_project_binaries", {})
                program_1 = find_binary_in_list_response(response, bin_1_name)
                program_2 = find_binary_in_list_response(response, bin_2_name)

                if program_1 and program_1["analysis_complete"]:
                    bin_1_ready = True

                if program_2 and program_2["analysis_complete"]:
                    bin_2_ready = True

                if bin_1_ready and bin_2_ready:
                    break

            assert bin_1_ready, f"Binary {bin_1_name} did not complete analysis"
            assert bin_2_ready, f"Binary {bin_2_name} did not complete analysis"
