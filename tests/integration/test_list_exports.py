import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import ExportInfos
from tests.benchmark_helpers import benchmark_repeated_tool_call


@pytest.mark.asyncio
async def test_list_exports(server_params_shared_object):
    """
    Tests the list_exports tool to ensure it returns a list of exports from the binary.
    """
    async with stdio_client(server_params_shared_object) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_shared_object.args[-1])

            # Test without params
            response = await session.call_tool("list_exports", {"binary_name": binary_name})
            export_infos = ExportInfos.model_validate_json(response.content[0].text)
            assert len(export_infos.exports) >= 2
            assert any("shared_func_one" in export.name for export in export_infos.exports)
            assert any("shared_func_two" in export.name for export in export_infos.exports)
            all_exports_list = export_infos.exports

            # Test limit
            response = await session.call_tool(
                "list_exports", {"binary_name": binary_name, "limit": 1}
            )
            export_infos = ExportInfos.model_validate_json(response.content[0].text)
            assert len(export_infos.exports) == 1

            # Test offset
            response = await session.call_tool(
                "list_exports", {"binary_name": binary_name, "offset": 1, "limit": 1}
            )
            export_infos = ExportInfos.model_validate_json(response.content[0].text)
            assert len(export_infos.exports) == 1
            assert export_infos.exports[0].name == all_exports_list[1].name

            # Test query
            response = await session.call_tool(
                "list_exports", {"binary_name": binary_name, "query": "shared_func_one"}
            )
            export_infos = ExportInfos.model_validate_json(response.content[0].text)
            assert len(export_infos.exports) >= 1
            assert "shared_func_one" in export_infos.exports[0].name

            # Test query with no results
            response = await session.call_tool(
                "list_exports", {"binary_name": binary_name, "query": "non_existent_function"}
            )
            export_infos = ExportInfos.model_validate_json(response.content[0].text)
            assert len(export_infos.exports) == 0


@pytest.mark.asyncio
async def test_list_exports_repeated_call_timings(server_params_shared_object):
    """Measure repeated list_exports timings for the same binary."""
    async with stdio_client(server_params_shared_object) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_shared_object.args[-1])

            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "list_exports",
                {"binary_name": binary_name, "query": "shared"},
                scenario="list_exports",
                validator=ExportInfos.model_validate_json,
            )

            assert timing_metrics.first_call_seconds > 0
            assert timing_metrics.warm_call_median_seconds > 0
            assert len(timing_metrics.all_call_seconds[1:]) == 3
            assert all(timing > 0 for timing in timing_metrics.all_call_seconds[1:])
            assert len(results) == 4
            assert all(len(export_infos.exports) >= 2 for export_infos in results)
