import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    ProgramInfos,
)


@pytest.mark.asyncio
async def test_delete_project_binary(server_params_no_thread):
    """Test the delete_project_binary tool."""

    async with stdio_client(server_params_no_thread) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Generate a unique binary name for the test binary
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_no_thread.args[-1])

            # Verify that the binary is in project
            tool_resp = await session.call_tool("list_project_binaries", {})
            program_infos_result = json.loads(tool_resp.content[0].text)
            program_infos = ProgramInfos(**program_infos_result)

            assert program_infos is not None
            names = [b.name for b in program_infos.programs]
            assert binary_name in names

            # Delete the binary
            tool_resp = await session.call_tool(
                "delete_project_binary", {"binary_name": binary_name}
            )
            assert tool_resp is not None
            delete_result = tool_resp.content[0].text
            assert "Successfully deleted binary" in delete_result

            # Verify that the binary is deleted
            tool_resp = await session.call_tool("list_project_binaries", {})
            program_infos_result = json.loads(tool_resp.content[0].text)
            program_infos = ProgramInfos(**program_infos_result)

            assert program_infos is not None
            names = [b.name for b in program_infos.programs]
            assert binary_name not in names
