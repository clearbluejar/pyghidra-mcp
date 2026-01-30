import os
import sys
import tempfile

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import CodeSearchResults, DecompiledFunction


@pytest.fixture(scope="module")
def test_binary():
    """
    Create a test binary with a specific function for search_code testing.

    NOTE: This fixture is customized for this test (includes function_to_find)
    and cannot use the generic test_binary fixture from conftest.py.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_to_find() {
    printf("This is a function to be found by search_code.");
}

int main() {
    printf("Hello, World!");
    function_to_find();
    return 0;
}
"""
        )
        c_file = f.name

    # On Windows, gcc adds .exe extension automatically
    bin_ext = ".exe" if sys.platform == "win32" else ""
    bin_file = c_file.replace(".c", bin_ext)

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.mark.asyncio
async def test_search_code(shared_mcp_session, test_binary):
    """
    Tests searching for code using similarity search.

    NOTE: This test uses its own test_binary fixture (with function_to_find)
    instead of the pre-imported demo binary, because it needs a specific function
    for semantic code search testing.
    """
    # Use shared MCP session
    session = shared_mcp_session

    # Import the test binary (with function_to_find)
    from pyghidra_mcp.context import PyGhidraContext
    import asyncio

    binary_name = PyGhidraContext._gen_unique_bin_name(test_binary)
    await session.call_tool("import_binary", {"binary_path": test_binary})

    # Wait for import and analysis to complete
    timeout_seconds = 120
    start_time = asyncio.get_event_loop().time()

    while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
        await asyncio.sleep(1)
        prog_resp = await session.call_tool("list_project_binaries", {})
        import json
        prog_result = json.loads(prog_resp.content[0].text)
        prog_infos = prog_result.get("programs", [])

        for pi in prog_infos:
            if binary_name in pi.get("name", ""):
                if (pi.get("analysis_complete") and
                    pi.get("code_collection") and
                    pi.get("strings_collection")):
                    break
        else:
            continue
        break

    # 1. Decompile a function to get its code to use as a query
    decompile_response = await session.call_tool(
        "decompile_function",
        {"binary_name": binary_name, "name_or_address": "function_to_find"},
    )

    decompiled_function = DecompiledFunction.model_validate_json(
        decompile_response.content[0].text
    )
    query_code = decompiled_function.code

    # 2. Use the decompiled code to search for the function
    search_response = await session.call_tool(
        "search_code", {"binary_name": binary_name, "query": query_code, "limit": 1}
    )

    search_results = CodeSearchResults.model_validate_json(search_response.content[0].text)

    # 3. Assert the results
    assert len(search_results.results) > 0
    # The top result should be the function we searched for
    assert "function_to_find" in search_results.results[0].function_name
