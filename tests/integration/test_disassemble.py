"""
Integration test for the disassemble functionality.

Smoke test to verify disassemble works through the MCP interface and returns a
compact text listing (optionally with raw instruction bytes).
"""

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DisassembleResult


@pytest.mark.asyncio
async def test_disassemble_tool(server_params, base_address):
    """Test that disassemble returns an aligned text listing without bytes by default."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "disassemble",
                {"binary_name": binary_name, "address": base_address, "count": 5},
            )

            result = DisassembleResult.model_validate_json(response.content[0].text)

            assert result.count > 0
            assert result.count <= 5
            # listing has one line per disassembled instruction.
            lines = result.listing.splitlines()
            assert len(lines) == result.count
            # Every line starts with an address.
            for line in lines:
                assert line.split()[0]


@pytest.mark.asyncio
async def test_disassemble_tool_include_bytes(server_params, base_address):
    """Test that include_bytes adds a raw hex byte column to the listing."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            without = await session.call_tool(
                "disassemble",
                {"binary_name": binary_name, "address": base_address, "count": 5},
            )
            with_bytes = await session.call_tool(
                "disassemble",
                {
                    "binary_name": binary_name,
                    "address": base_address,
                    "count": 5,
                    "include_bytes": True,
                },
            )

            without_result = DisassembleResult.model_validate_json(without.content[0].text)
            with_result = DisassembleResult.model_validate_json(with_bytes.content[0].text)

            # Including bytes adds a column, so each line is at least as long.
            assert len(with_result.listing) > len(without_result.listing)


@pytest.mark.asyncio
async def test_disassemble_invalid_count(server_params, base_address):
    """Test that out-of-range count values are rejected."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            response = await session.call_tool(
                "disassemble",
                {"binary_name": binary_name, "address": base_address, "count": 999},
            )

            assert response.isError
            assert "200" in response.content[0].text
