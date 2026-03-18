"""
Integration test for the read_bytes functionality.

Simple smoke test to verify read_bytes works through the MCP interface.
"""

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import BytesReadResult, StringSearchResults


@pytest.mark.asyncio
async def test_read_bytes_tool(server_params_no_thread):
    """Test that read_bytes works - basic smoke test."""
    async with stdio_client(server_params_no_thread) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_no_thread.args[-1])

            string_response = await session.call_tool(
                "search_strings",
                {"binary_name": binary_name, "query": "Hello, World!", "limit": 1},
            )
            string_results = StringSearchResults.model_validate_json(
                string_response.content[0].text
            )
            assert len(string_results.strings) == 1

            response = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": string_results.strings[0].address,
                    "size": len("Hello"),
                },
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)
            assert result.data == "48656c6c6f"
            assert result.size == len("Hello")
