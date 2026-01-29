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

            # 4. Verify new fields are populated
            # 4. Verify new fields are populated
            assert search_results.query == query_code
            assert search_results.search_mode.value == "semantic"  # Default mode
            assert search_results.returned_count > 0
            assert search_results.literal_total >= 0  # Dual-mode count
            assert search_results.semantic_total > 0
            assert search_results.total_functions > 0
            # semantic_total should be <= total_functions
            assert search_results.semantic_total <= search_results.total_functions


@pytest.mark.asyncio
async def test_search_code_literal(server_params):
    """
    Tests searching for code using literal (exact string) search mode.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Search for a literal string that should be in the decompiled code
            # "printf" should appear in the decompiled output
            literal_query = "printf"

            # Use literal search mode
            search_response = await session.call_tool(
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": literal_query,
                    "limit": 5,
                    "search_mode": "literal",
                },
            )

            search_results = CodeSearchResults.model_validate_json(search_response.content[0].text)

            # Assert the results
            assert search_results.search_mode.value == "literal"
            assert search_results.literal_total > 0  # Should find functions containing "printf"

            # Each result should contain the literal query string
            for result in search_results.results:
                assert literal_query in result.code
                assert result.search_mode.value == "literal"
                assert result.similarity == 1.0  # Literal matches have similarity 1.0
