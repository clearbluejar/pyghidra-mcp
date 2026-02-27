import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import ImportInfos


@pytest.mark.asyncio
async def test_list_imports(server_params_shared_object, test_shared_object):
    """Test listing imports from a shared object."""
    async with stdio_client(server_params_shared_object) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_shared_object.args[-1])

            # Test without params
            response = await session.call_tool("list_imports", {"binary_name": binary_name})
            import_infos = ImportInfos.model_validate_json(response.content[0].text)
            assert len(import_infos.imports) > 0
            assert any("printf" in imp.name for imp in import_infos.imports)
            assert any(
                "malloc" in imp.name for imp in import_infos.imports
            )  # in shared object but not in binary
            all_import_names = [imp.name for imp in import_infos.imports]

            # Test limit (filter to a known import for determinism)
            response = await session.call_tool(
                "list_imports", {"binary_name": binary_name, "query": "printf", "limit": 1}
            )
            import_infos = ImportInfos.model_validate_json(response.content[0].text)
            assert len(import_infos.imports) == 1

            # Test offset
            response = await session.call_tool(
                "list_imports", {"binary_name": binary_name, "offset": 1, "limit": 1}
            )
            import_infos = ImportInfos.model_validate_json(response.content[0].text)
            assert len(import_infos.imports) == 1
            assert import_infos.imports[0].name in all_import_names

            # Test query
            response = await session.call_tool(
                "list_imports", {"binary_name": binary_name, "query": "printf"}
            )
            import_infos = ImportInfos.model_validate_json(response.content[0].text)
            assert len(import_infos.imports) >= 1
            assert "printf" in import_infos.imports[0].name

            # Test query with no results
            response = await session.call_tool(
                "list_imports", {"binary_name": binary_name, "query": "non_existent_import"}
            )
            import_infos = ImportInfos.model_validate_json(response.content[0].text)
            assert len(import_infos.imports) == 0
