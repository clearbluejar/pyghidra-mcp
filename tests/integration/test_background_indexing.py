import asyncio

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import StringSearchResults


@pytest.fixture(scope="module")
def server_params_background_indexing(test_binary, ghidra_env, isolated_project_root):
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(isolated_project_root / "background_indexing"),
            "--project-name",
            "background_indexing_project",
            test_binary,
        ],
        env=ghidra_env,
    )


@pytest.mark.asyncio
async def test_background_indexing_eventually_enables_string_search(
    server_params_background_indexing,
    find_binary_in_list_response,
):
    async with stdio_client(server_params_background_indexing) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(
                server_params_background_indexing.args[-1]
            )

            strings_indexed = False
            for _ in range(240):
                response = await session.call_tool("list_project_binaries", {})
                program = find_binary_in_list_response(response, binary_name)
                if program and program["strings_indexed"]:
                    strings_indexed = True
                    break
                await asyncio.sleep(1)

            assert strings_indexed

            response = await session.call_tool(
                "search_strings",
                {"binary_name": binary_name, "query": "hello"},
            )
            search_results = StringSearchResults.model_validate_json(response.content[0].text)
            assert any("World" in result.value for result in search_results.strings)
