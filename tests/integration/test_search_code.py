import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import CodeSearchResults, DecompiledFunction
from tests.benchmark_helpers import (
    benchmark_repeated_tool_call,
    call_tool_model,
    platform_function_name,
)


@pytest.mark.asyncio
async def test_search_code(server_params_no_thread):
    """
    Tests searching for code using similarity search.
    """
    name = platform_function_name("function_one")
    async with stdio_client(server_params_no_thread) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_no_thread.args[-1])

            decompiled_function = await call_tool_model(
                session,
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": name},
                DecompiledFunction,
            )
            query_code = decompiled_function.code

            search_results = await call_tool_model(
                session,
                "search_code",
                {"binary_name": binary_name, "query": query_code, "limit": 1},
                CodeSearchResults,
            )

            assert len(search_results.results) > 0
            assert name in search_results.results[0].function_name

            assert search_results.query == query_code
            assert search_results.search_mode.value == "semantic"
            assert search_results.returned_count > 0
            assert search_results.literal_total >= 0
            assert search_results.semantic_total > 0
            assert search_results.total_functions > 0
            assert search_results.semantic_total <= search_results.total_functions


@pytest.mark.asyncio
async def test_search_code_repeated_semantic_timings(server_params_no_thread):
    """Measure repeated semantic search_code timings for the same binary."""
    name = platform_function_name("function_one")
    async with stdio_client(server_params_no_thread) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_no_thread.args[-1])

            decompiled_function = await call_tool_model(
                session,
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": name},
                DecompiledFunction,
            )
            query_code = decompiled_function.code

            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "search_code",
                {"binary_name": binary_name, "query": query_code, "limit": 1},
                scenario="search_code_semantic",
                validator=CodeSearchResults.model_validate_json,
            )

            assert timing_metrics.first_call_seconds > 0
            assert timing_metrics.warm_call_median_seconds > 0
            assert len(timing_metrics.all_call_seconds[1:]) == 3
            assert all(timing > 0 for timing in timing_metrics.all_call_seconds[1:])
            assert len(results) == 4
            for search_results in results:
                assert len(search_results.results) > 0
                assert name in search_results.results[0].function_name
                assert search_results.search_mode.value == "semantic"


@pytest.mark.asyncio
async def test_search_code_literal(server_params_no_thread):
    """
    Tests searching for code using literal (exact string) search mode.
    """
    async with stdio_client(server_params_no_thread) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_no_thread.args[-1])

            literal_query = "Function One"

            search_results = await call_tool_model(
                session,
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": literal_query,
                    "limit": 5,
                    "search_mode": "literal",
                },
                CodeSearchResults,
            )

            assert search_results.search_mode.value == "literal"
            assert search_results.literal_total > 0

            for result in search_results.results:
                assert literal_query in result.code
                assert result.search_mode.value == "literal"
                assert result.similarity == 1.0


@pytest.mark.asyncio
async def test_search_code_repeated_literal_timings(server_params_no_thread):
    """Measure repeated literal search_code timings for the same binary."""
    async with stdio_client(server_params_no_thread) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_no_thread.args[-1])

            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": "Function One",
                    "limit": 5,
                    "search_mode": "literal",
                },
                scenario="search_code_literal",
                validator=CodeSearchResults.model_validate_json,
            )

            assert timing_metrics.first_call_seconds > 0
            assert timing_metrics.warm_call_median_seconds > 0
            assert len(timing_metrics.all_call_seconds[1:]) == 3
            assert all(timing > 0 for timing in timing_metrics.all_call_seconds[1:])
            assert len(results) == 4
            for search_results in results:
                assert search_results.search_mode.value == "literal"
                assert search_results.literal_total > 0
                assert len(search_results.results) > 0
