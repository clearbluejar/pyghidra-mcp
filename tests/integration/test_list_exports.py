import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import ExportInfos


@pytest.mark.asyncio
async def test_list_exports(shared_mcp_session, test_shared_object):
    """
    Tests the list_exports tool to ensure it returns a list of exports from the binary.

    Note: This test uses test_shared_object (a .so/.dll) instead of the pre-imported
    demo binary because we need to test export symbols which are specific to shared libraries.
    """
    # Use shared MCP session
    session = shared_mcp_session

    # Import shared object and wait for analysis
    from pyghidra_mcp.context import PyGhidraContext

    binary_name = PyGhidraContext._gen_unique_bin_name(test_shared_object)
    await session.call_tool("import_binary", {"binary_path": test_shared_object})

    # Wait for import to complete
    import asyncio
    timeout_seconds = 60
    start_time = asyncio.get_event_loop().time()

    while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
        await asyncio.sleep(1)
        response = await session.call_tool("list_project_binaries", {})
        import json
        program_infos = json.loads(response.content[0].text)["programs"]
        for program in program_infos:
            if binary_name in program["name"] and program.get("analysis_complete"):
                break
        else:
            continue
        break

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
