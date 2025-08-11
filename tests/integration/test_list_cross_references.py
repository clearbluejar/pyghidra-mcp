import json
import os
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import CrossReferenceInfos

base_url = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8000")


@pytest.fixture(scope="module")
def test_binary():
    """
    Create a simple binary for testing.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

int main() {
    function_one();
    return 0;
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")
    cmd = f"gcc -o {bin_file} {c_file}"
    ret = os.system(cmd)
    if ret != 0:
        raise RuntimeError(f"Compilation failed: {cmd}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", test_binary],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_list_cross_references(server_params):
    """
    Tests the list_cross_references tool to ensure it returns
    a list of cross-references from the binary.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "list_cross_references",
                {"binary_name": binary_name, "name_or_address": "function_one"},
            )

            cross_reference_infos_result = json.loads(response.content[0].text)
            cross_reference_infos = CrossReferenceInfos(**cross_reference_infos_result)

            assert len(cross_reference_infos.cross_references) > 0
            assert any(
                [ref.function_name == "main" for ref in cross_reference_infos.cross_references]
            )
