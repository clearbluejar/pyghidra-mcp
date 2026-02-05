import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import ProgramInfos


@pytest.mark.asyncio
async def test_list_project_binary_metadata(server_params):
    """
    Test the list_project_binary_metadata tool.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # First, list binaries to get a valid binary name
            tool_resp = await session.call_tool("list_project_binaries", {})
            program_infos_result = json.loads(tool_resp.content[0].text)
            program_infos = ProgramInfos(**program_infos_result)

            assert program_infos is not None
            assert len(program_infos.programs) > 0
            binary_name = program_infos.programs[0].name

            # Get the metadata
            tool_resp = await session.call_tool(
                "list_project_binary_metadata", {"binary_name": binary_name}
            )

            assert tool_resp is not None
            metadata = json.loads(tool_resp.content[0].text)

            assert isinstance(metadata, dict)
            assert metadata.get("Executable Location") is not None
            assert metadata.get("Compiler") is not None
            assert metadata.get("Processor") is not None
            assert metadata.get("Endian") is not None
            assert metadata.get("Address Size") is not None
            assert binary_name is not None
            assert metadata.get("Program Name") is not None
            assert metadata.get("Program Name") in binary_name
