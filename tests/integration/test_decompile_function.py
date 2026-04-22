import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


@pytest.mark.asyncio
async def test_decompile_function_tool(server_params, test_binary, main_func_name):
    """Test the decompile_function tool."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": main_func_name},
            )

            assert results is not None
            assert results.content is not None
            assert len(results.content) > 0

            text_content = results.content[0].text
            assert text_content is not None
            result_dict = json.loads(text_content)
            assert isinstance(result_dict, dict)
            assert result_dict["code"] != ""
            assert main_func_name in result_dict["name"]


@pytest.mark.asyncio
async def test_decompile_function_rich_response(server_params, test_binary, main_func_name):
    """Test decompile_function with include_callees and include_xrefs flags."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            results = await session.call_tool(
                "decompile_function",
                {
                    "binary_name": binary_name,
                    "name_or_address": main_func_name,
                    "include_callees": True,
                    "include_xrefs": True,
                },
            )

            assert len(results.content) >= 1
            result_dict = json.loads(results.content[0].text)
            assert isinstance(result_dict, dict)
            assert "callees" in result_dict
            assert isinstance(result_dict["callees"], list)
            assert "xrefs" in result_dict
            assert isinstance(result_dict["xrefs"], list)


@pytest.mark.asyncio
async def test_decompile_function_batch(server_params, test_binary, func_prefix):
    """Test decompile_function with batch targets (list of names)."""
    name_one = f"{func_prefix}function_one"

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            results = await session.call_tool(
                "decompile_function",
                {
                    "binary_name": binary_name,
                    "name_or_address": [name_one, "nonexistent_function_xyz"],
                },
            )

            # Batch returns one content block per item
            assert len(results.content) >= 2
            success = json.loads(results.content[0].text)
            failure = json.loads(results.content[1].text)

            assert success["code"] != ""
            assert success.get("error") is None

            assert failure["code"] == ""
            assert failure["error"] is not None
            assert "not found" in failure["error"].lower()
