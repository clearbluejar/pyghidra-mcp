import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


@pytest.mark.asyncio
async def test_list_project_binaries_tool(server_params):
    """Test the list_project_binaries tool."""

    binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Call the list_project_binaries tool
            results = await session.call_tool("list_project_binaries", {})

            # Check that we got results
            assert results is not None
            assert results.content is not None
            assert len(results.content) > 0

            # The result should be a list of program basic info
            text_content = results.content[0].text
            program_infos = json.loads(text_content)
            assert "programs" in program_infos
            assert isinstance(program_infos["programs"], list)
            program_infos = program_infos["programs"]
            assert len(program_infos) > 0

            found = False
            for program in program_infos:
                if program["name"] == binary_name:
                    found = True
                    assert program["analysis_complete"]
                    break

            assert found


@pytest.mark.asyncio
async def test_list_project_program_info_tool(server_params):
    """Test the list_project_program_info tool."""

    binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Call the list_project_program_info tool
            results = await session.call_tool("list_project_program_info", {})

            # Check that we got results
            assert results is not None
            assert results.content is not None
            assert len(results.content) > 0

            # The result should be a JSON object with a 'programs' key
            text_content = results.content[0].text
            assert text_content is not None
            program_infos = json.loads(text_content)
            assert "programs" in program_infos
            assert isinstance(program_infos["programs"], list)
            assert len(program_infos["programs"]) > 0

            # Check that our binary is in the list
            found = False
            for prog_info in program_infos["programs"]:
                if prog_info["name"] == binary_name:
                    found = True
                    assert prog_info["file_path"] is not None
                    assert prog_info["analysis_complete"] is True
            assert found
