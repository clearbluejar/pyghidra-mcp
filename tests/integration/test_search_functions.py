import platform

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import SymbolSearchResults


@pytest.mark.asyncio
async def test_search_functions_by_name(server_params):
    """Tests searching for functions by name."""
    name_one = "_function_one" if platform.system() == "Darwin" else "function_one"
    name_two = "_function_two" if platform.system() == "Darwin" else "function_two"

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "search_functions_by_name",
                {"binary_name": binary_name, "query": "function_"},
            )

            search_results = SymbolSearchResults.model_validate_json(response.content[0].text)
            assert len(search_results.symbols) >= 2
            assert any(name_one in s.name for s in search_results.symbols)
            assert any(name_two in s.name for s in search_results.symbols)
