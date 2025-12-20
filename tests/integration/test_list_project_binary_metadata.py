import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import BinaryMetadata, ProgramInfos


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
            metadata_result = json.loads(tool_resp.content[0].text)

            # The server returns a pydantic model which is serialized.
            # We load it back into the model for validation.
            metadata = BinaryMetadata(**metadata_result)

            assert isinstance(metadata, BinaryMetadata)
            assert metadata.executable_location is not None
            assert metadata.compiler is not None
            assert metadata.processor is not None
            assert metadata.endian is not None
            assert metadata.address_size is not None
            assert binary_name is not None
            assert metadata.program_name is not None
            assert metadata.program_name in binary_name
