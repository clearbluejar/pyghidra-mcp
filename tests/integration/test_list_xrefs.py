import json
import platform

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import CrossReferenceInfos


@pytest.mark.asyncio
async def test_list_xrefs(server_params):
    """
    Tests the list_xrefs tool to ensure it returns
    a list of cross-references from the binary.
    """
    name_one = "_function_one" if platform.system() == "Darwin" else "function_one"
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "list_xrefs",
                {"binary_name": binary_name, "name_or_address": name_one},
            )

            # FastMCP serializes each list item as a separate content block
            assert len(response.content) >= 1
            cross_reference_infos = CrossReferenceInfos(**json.loads(response.content[0].text))

            assert cross_reference_infos.target == name_one
            assert len(cross_reference_infos.cross_references) > 0
            name = "entry" if platform.system() == "Darwin" else "main"
            assert any(ref.function_name == name for ref in cross_reference_infos.cross_references)


@pytest.mark.asyncio
async def test_list_xrefs_batch(server_params):
    """Test list_xrefs with batch targets (one valid, one invalid)."""
    name_one = "_function_one" if platform.system() == "Darwin" else "function_one"
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "list_xrefs",
                {
                    "binary_name": binary_name,
                    "name_or_address": [name_one, "nonexistent_symbol_xyz"],
                },
            )

            # Batch returns one content block per item
            assert len(response.content) >= 2
            success = CrossReferenceInfos(**json.loads(response.content[0].text))
            failure = CrossReferenceInfos(**json.loads(response.content[1].text))

            assert success.target == name_one
            assert len(success.cross_references) > 0
            assert success.error is None

            assert failure.target == "nonexistent_symbol_xyz"
            assert failure.cross_references == []
            assert failure.error is not None
