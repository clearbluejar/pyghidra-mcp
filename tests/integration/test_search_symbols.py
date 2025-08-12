import os
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import SymbolSearchResults


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
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

int main() {
    printf("Hello, World!");
    function_one();
    function_two();
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
        args=["-m", "pyghidra_mcp", test_binary],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_search_symbols_by_name(server_params):
    """
    Tests searching for symbols by name.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "search_symbols_by_name", {"binary_name": binary_name, "query": "function"}
            )

            search_results = SymbolSearchResults.model_validate_json(response.content[0].text)
            assert len(search_results.symbols) >= 2
            assert any("function_one" in s.name for s in search_results.symbols)
            assert any("function_two" in s.name for s in search_results.symbols)
