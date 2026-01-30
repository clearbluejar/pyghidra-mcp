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
async def test_search_code(shared_mcp_session):
    """
    Tests searching for code using similarity search.
    """
    # Use shared MCP session with pre-imported demo binary
    session = shared_mcp_session
    binary_name = session.demo_binary_name

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
