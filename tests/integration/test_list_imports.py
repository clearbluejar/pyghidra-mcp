import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import ImportInfos

# @pytest.fixture(scope="module")
# def test_shared_object():
#     """
#     Create a simple shared object for testing.
#     """
#     # 1. Write the C source to a temp file
#     with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
#         f.write(
#             """
# #include <stdio.h>

# void function_one() {
#     printf("Function One");
# }

# void function_two() {
#     printf("Function Two");
# }

# // No main() needed for a shared library
# """
#         )
#         c_file = f.name

#     # 2. Compile as a shared object
#     so_file = c_file.replace(".c", ".so")
#     cmd = f"gcc -fPIC -shared -o {so_file} {c_file}"
#     ret = os.system(cmd)
#     if ret != 0:
#         raise RuntimeError(f"Compilation failed: {cmd}")

#     # 3. Yield path to .so for tests
#     yield so_file

#     # 4. Clean up
#     os.unlink(c_file)
#     os.unlink(so_file)


@pytest.mark.asyncio
async def test_list_imports(shared_mcp_session):
    """Test listing imports from a binary - tests pagination and filtering."""
    # Use shared MCP session with pre-imported demo binary
    session = shared_mcp_session
    binary_name = session.demo_binary_name

    # Get all imports to understand what we're working with
    response = await session.call_tool("list_imports", {"binary_name": binary_name})
    import_infos = ImportInfos.model_validate_json(response.content[0].text)
    all_imports_list = import_infos.imports

    # Test 1: Verify imports exist
    assert len(all_imports_list) > 0, "Binary should have at least one import"

    # Test 2: Verify imports are ImportInfo objects with required fields
    for imp in all_imports_list[:5]:  # Check first 5
        assert hasattr(imp, "name")
        assert hasattr(imp, "library")
        assert imp.name is not None
        assert imp.library is not None

    # Test 3: Test limit parameter (pagination)
    if len(all_imports_list) > 1:
        response = await session.call_tool(
            "list_imports", {"binary_name": binary_name, "limit": 1}
        )
        import_infos = ImportInfos.model_validate_json(response.content[0].text)
        assert len(import_infos.imports) == 1
        assert import_infos.imports[0].name == all_imports_list[0].name

    # Test 4: Test offset parameter (pagination)
    if len(all_imports_list) > 2:
        # Get second import with offset=1, limit=1
        response = await session.call_tool(
            "list_imports", {"binary_name": binary_name, "offset": 1, "limit": 1}
        )
        import_infos = ImportInfos.model_validate_json(response.content[0].text)
        assert len(import_infos.imports) == 1
        assert import_infos.imports[0].name == all_imports_list[1].name

    # Test 5: Test query parameter (case-insensitive substring search)
    # Use "Critical" or "Sleep" as common Windows API patterns
    has_critical_section = any("critical" in imp.name.lower() for imp in all_imports_list)
    has_sleep = any("sleep" in imp.name.lower() for imp in all_imports_list)

    if has_critical_section:
        response = await session.call_tool(
            "list_imports", {"binary_name": binary_name, "query": "Critical"}
        )
        import_infos = ImportInfos.model_validate_json(response.content[0].text)
        assert len(import_infos.imports) >= 1
        assert all("critical" in imp.name.lower() for imp in import_infos.imports)
    elif has_sleep:
        response = await session.call_tool(
            "list_imports", {"binary_name": binary_name, "query": "Sleep"}
        )
        import_infos = ImportInfos.model_validate_json(response.content[0].text)
        assert len(import_infos.imports) >= 1
        assert all("sleep" in imp.name.lower() for imp in import_infos.imports)

    # Test 6: Test query with no results
    response = await session.call_tool(
        "list_imports", {"binary_name": binary_name, "query": "NonExistentFunction12345"}
    )
    import_infos = ImportInfos.model_validate_json(response.content[0].text)
    assert len(import_infos.imports) == 0

    # Test 7: Test offset + limit beyond available range
    response = await session.call_tool(
        "list_imports", {"binary_name": binary_name, "offset": 9999, "limit": 1}
    )
    import_infos = ImportInfos.model_validate_json(response.content[0].text)
    assert len(import_infos.imports) == 0
