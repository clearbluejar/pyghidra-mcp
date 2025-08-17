import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import SymbolSearchResults


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
