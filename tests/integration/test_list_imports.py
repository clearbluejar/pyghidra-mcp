import json
import os
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import ImportInfos


@pytest.fixture(scope="module")
def test_shared_object():
    """
    Create a simple shared object for testing.
    """
    # 1. Write the C source to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

// No main() needed for a shared library
"""
        )
        c_file = f.name

    # 2. Compile as a shared object
    so_file = c_file.replace(".c", ".so")
    cmd = f"gcc -fPIC -shared -o {so_file} {c_file}"
    ret = os.system(cmd)
    if ret != 0:
        raise RuntimeError(f"Compilation failed: {cmd}")

    # 3. Yield path to .so for tests
    yield so_file

    # 4. Clean up
    os.unlink(c_file)
    os.unlink(so_file)


@pytest.fixture(scope="module")
def server_params(test_shared_object):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", test_shared_object],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_list_imports(server_params):
    """Test listing imports from a binary."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
            response = await session.call_tool("list_imports", {"binary_name": binary_name})
            import_infos_result = json.loads(response.content[0].text)
            import_infos = ImportInfos(**import_infos_result)
            assert len(import_infos.imports) > 0
            assert any("printf" in imp.name for imp in import_infos.imports)
