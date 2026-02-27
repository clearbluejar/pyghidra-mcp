"""
Integration test for the read_bytes functionality.

Simple smoke test to verify read_bytes works through the MCP interface.
"""

import platform
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

            # Try reading from platform-default base addresses
            address = "100000000" if platform.system() == "Darwin" else "100000"
            response = await session.call_tool(
                "read_bytes", {"binary_name": binary_name, "address": address, "size": 4}
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)

            # Check magic bytes by platform
            if platform.system() == "Darwin":
                # Accept either MH_MAGIC_64 (feedfacf) or byte-swapped MH_CIGAM_64 (cffaedfe)
                assert result.data.lower() in {"feedfacf", "cffaedfe"}
                assert result.address == "100000000"
            else:
                assert result.data == "7f454c46"  # 0x7F + "ELF" in hex
                assert result.address == "00100000"
            assert result.size == 4
