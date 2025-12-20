import os
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import CodeSearchResults, DecompiledFunction


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
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

    bin_file = c_file.replace(".c", "")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--no-threaded", test_binary],  # no-thread for search_code
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_search_code(server_params):
    """
    Tests searching for code using similarity search.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

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
