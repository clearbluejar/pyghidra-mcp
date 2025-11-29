import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import ExportInfos


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
            assert any("function_one" in export.name for export in export_infos.exports)
            assert any("function_two" in export.name for export in export_infos.exports)
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
                "list_exports", {"binary_name": binary_name, "query": "function_one"}
            )
            export_infos = ExportInfos.model_validate_json(response.content[0].text)
            assert len(export_infos.exports) >= 1
            assert "function_one" in export_infos.exports[0].name

            # Test query with no results
            response = await session.call_tool(
                "list_exports", {"binary_name": binary_name, "query": "non_existent_function"}
            )
            export_infos = ExportInfos.model_validate_json(response.content[0].text)
            assert len(export_infos.exports) == 0
