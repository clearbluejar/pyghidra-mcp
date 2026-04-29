import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import SymbolSearchResults


@pytest.mark.asyncio
async def test_search_symbols_by_name(server_params, func_prefix):
    """
    Tests searching for symbols by name.
    """
    name_one = f"{func_prefix}function_one"
    name_two = f"{func_prefix}function_two"
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
            assert any(name_one in s.name for s in search_results.symbols)
            assert any(name_two in s.name for s in search_results.symbols)
            assert all(hasattr(symbol, "is_thunk") for symbol in search_results.symbols)
            assert all(symbol.is_thunk is False for symbol in search_results.symbols)
