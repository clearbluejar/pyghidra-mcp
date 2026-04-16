import asyncio
import os
import tempfile

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


@pytest.fixture()
def test_binary_for_import():
    """Must be unique for this test"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

int main() {
    printf("Hello, World!");
    return 0;
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield os.path.abspath(bin_file)

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture()
def raw_blob_for_import():
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
        f.write(bytes(range(256)) * 4)
        blob_file = f.name

    yield os.path.abspath(blob_file)

    os.unlink(blob_file)


@pytest.mark.asyncio
async def test_import_binary(
    test_binary_for_import, server_params_no_input, find_binary_in_list_response
):
    """
    Test for the string Hello in the example binary.
    """
    async with stdio_client(server_params_no_input) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            test_binary_name = PyGhidraContext._gen_unique_bin_name(test_binary_for_import)

            response = await session.call_tool(
                "import_binary", {"binary_path": test_binary_for_import}
            )

            content = response.content[0].text
            assert test_binary_for_import in content
            assert '"queued_count": 1' in content

            ready = False
            for _ in range(240):
                # Try until binary is ready
                await asyncio.sleep(1)

                response = await session.call_tool("list_project_binaries", {})
                program = find_binary_in_list_response(response, test_binary_name)
                if not program:
                    continue
                if program["analysis_complete"]:
                    ready = True
                    break

            assert ready


@pytest.mark.asyncio
async def test_import_raw_binary_single_file(
    raw_blob_for_import, server_params_no_input, find_binary_in_list_response
):
    async with stdio_client(server_params_no_input) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            raw_binary_name = PyGhidraContext._gen_unique_bin_name(raw_blob_for_import)

            response = await session.call_tool(
                "import_binary", {"binary_path": raw_blob_for_import}
            )

            content = response.content[0].text
            assert raw_blob_for_import in content
            assert '"queued_count": 0' in content
            assert '"skipped_count": 1' in content
            assert "no supported Ghidra loader detected" in content

            imported = False
            for _ in range(5):
                await asyncio.sleep(1)

                response = await session.call_tool("list_project_binaries", {})
                program = find_binary_in_list_response(response, raw_binary_name)
                if program:
                    imported = True
                    break

            assert not imported, f"Raw binary {raw_binary_name} should have been skipped"
