"""
Integration test for the read_bytes functionality.

Simple smoke test to verify read_bytes works through the MCP interface.
"""

import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import BytesReadResult


@pytest.mark.asyncio
async def test_read_bytes_tool(server_params):
    """Test that read_bytes works - basic smoke test."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Find "Hello, World!" string in the binary
            string_response = await session.call_tool(
                "search_strings",
                {"binary_name": binary_name, "query": "Hello", "limit": 1}
            )
            string_result = json.loads(string_response.content[0].text)

            if not string_result.get("strings"):
                pytest.skip("Could not find 'Hello' string in test binary")

            hello_string = string_result["strings"][0]
            string_addr = hello_string["address"]

            # Read bytes from that address
            response = await session.call_tool(
                "read_bytes",
                {"binary_name": binary_name, "address": string_addr, "size": 13}
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)

            # "Hello, World!" in hex (13 bytes)
            expected_hex = "48656c6c6f2c20576f726c6421"  # "Hello, World!"
            assert result.data == expected_hex
            assert result.size == 13
