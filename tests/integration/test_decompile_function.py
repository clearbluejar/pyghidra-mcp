import platform

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from tests.benchmark_helpers import benchmark_repeated_tool_call


@pytest.mark.asyncio
async def test_decompile_function_tool(server_params, test_binary):
    """Test the decompile_function tool."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            try:
                binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
                results = await session.call_tool(
                    "decompile_function", {"binary_name": binary_name, "name_or_address": "main"}
                )

                assert results is not None
                assert results.content is not None
                assert len(results.content) > 0

                text_content = results.content[0].text
                assert text_content is not None
                assert len(text_content) > 0
                assert "main" in text_content
            except Exception as e:
                assert e is not None


@pytest.mark.asyncio
async def test_decompile_function_repeated_call_timings(server_params):
    """Measure repeated decompile_function timings for the same binary."""

    name_or_address = "entry" if platform.system() == "Darwin" else "main"

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": name_or_address},
                scenario="decompile_function",
            )

            assert timing_metrics.first_call_seconds > 0
            assert timing_metrics.warm_call_median_seconds > 0
            assert len(timing_metrics.all_call_seconds[1:]) == 3
            assert all(timing > 0 for timing in timing_metrics.all_call_seconds[1:])
            assert all(result for result in results)


@pytest.mark.asyncio
async def test_partial_name_rejected_by_singular_tools(server_params):
    """Test that singular lookup tools reject partial function names."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            decompile_response = await session.call_tool(
                "decompile_function", {"binary_name": binary_name, "name_or_address": "function"}
            )
            expected_decompile_error = (
                "Error executing tool decompile_function: Function or symbol 'function' not found."
            )
            assert decompile_response.isError is True
            assert decompile_response.content[0].text == expected_decompile_error

            xref_response = await session.call_tool(
                "list_cross_references",
                {"binary_name": binary_name, "name_or_address": "function"},
            )
            assert xref_response.isError is True
            assert (
                xref_response.content[0].text
                == "Error executing tool list_cross_references: Symbol 'function' not found."
            )

            callgraph_response = await session.call_tool(
                "gen_callgraph", {"binary_name": binary_name, "function_name": "function"}
            )
            assert callgraph_response.isError is True
            assert (
                callgraph_response.content[0].text
                == "Error executing tool gen_callgraph: Function or symbol 'function' not found."
            )
