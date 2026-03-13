import platform

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import SymbolSearchResults
from tests.benchmark_helpers import benchmark_repeated_tool_call


@pytest.mark.asyncio
async def test_search_symbols_by_name(server_params):
    """
    Tests searching for symbols by name.
    """
    name_one = "_function_one" if platform.system() == "Darwin" else "function_one"
    name_two = "_function_two" if platform.system() == "Darwin" else "function_two"
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


@pytest.mark.asyncio
async def test_search_symbols_by_name_repeated_call_timings(server_params):
    """Measure repeated search_symbols_by_name timings for the same binary."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "search_symbols_by_name",
                {"binary_name": binary_name, "query": "function"},
                scenario="search_symbols_by_name",
                validator=SymbolSearchResults.model_validate_json,
            )

            assert timing_metrics.first_call_seconds > 0
            assert timing_metrics.warm_call_median_seconds > 0
            assert len(timing_metrics.all_call_seconds[1:]) == 3
            assert all(timing > 0 for timing in timing_metrics.all_call_seconds[1:])
            assert len(results) == 4
            assert all(len(search_results.symbols) >= 2 for search_results in results)


@pytest.mark.asyncio
async def test_search_functions_by_name(server_params):
    """
    Tests searching for functions by name.
    """
    name_one = "_function_one" if platform.system() == "Darwin" else "function_one"
    name_two = "_function_two" if platform.system() == "Darwin" else "function_two"
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "search_functions_by_name", {"binary_name": binary_name, "query": "function"}
            )

            search_results = SymbolSearchResults.model_validate_json(response.content[0].text)
            assert len(search_results.symbols) >= 2
            assert any(name_one in s.name for s in search_results.symbols)
            assert any(name_two in s.name for s in search_results.symbols)
            assert all(s.type == "Function" for s in search_results.symbols)
