import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import CrossReferenceInfos


@pytest.mark.asyncio
async def test_list_cross_references(server_params):
    """
    Tests the list_cross_references tool to ensure it returns
    a list of cross-references from the binary.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "list_cross_references",
                {"binary_name": binary_name, "name_or_address": "function_one"},
            )

            cross_reference_infos_result = json.loads(response.content[0].text)
            cross_reference_infos = CrossReferenceInfos(**cross_reference_infos_result)

            assert len(cross_reference_infos.cross_references) > 0
            assert any(
                [ref.function_name == "main" for ref in cross_reference_infos.cross_references]
            )
