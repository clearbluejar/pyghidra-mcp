"""
Simple integration tests for the read_bytes functionality.

Tests the happy path by reading the ELF header, which is predictable
and exists at address 0 in every ELF binary.
"""

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import BytesReadResult


@pytest.mark.asyncio
async def test_read_elf_magic(server_params):
    """Test reading ELF magic bytes - verifies basic functionality."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Read the first 4 bytes (ELF magic: 0x7F + "ELF")
            response = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": "0",
                    "size": 4
                }
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)

            # Verify we got the ELF magic bytes
            assert result.data == "7f454c46"  # 0x7F + "ELF" in hex
            assert result.size == 4
            assert result.address == "00000000"


@pytest.mark.asyncio
async def test_read_elf_header_larger(server_params):
    """Test reading more of the ELF header."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Read first 16 bytes of ELF header
            response = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": "0",
                    "size": 16
                }
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)

            # Should still start with ELF magic
            assert result.data.startswith("7f454c46")
            assert result.size == 16
            assert len(result.data) == 32  # 16 bytes = 32 hex chars


@pytest.mark.asyncio
async def test_read_with_hex_prefixes(server_params):
    """Test reading with different address formats."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Test with 0x prefix
            response1 = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": "0x0",
                    "size": 4
                }
            )

            result1 = BytesReadResult.model_validate_json(response1.content[0].text)
            assert result1.data == "7f454c46"

            # Test with 0X prefix (uppercase)
            response2 = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": "0X0",
                    "size": 4
                }
            )

            result2 = BytesReadResult.model_validate_json(response2.content[0].text)
            assert result2.data == "7f454c46"


@pytest.mark.asyncio
async def test_read_from_offset(server_params):
    """Test reading from offset 1 (should get "ELF" part)."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Read 3 bytes starting from offset 1
            response = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": "1",
                    "size": 3
                }
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)

            # Should get "ELF" part (bytes 1, 2, 3 of the magic)
            assert result.data == "454c46"  # "ELF" in hex
            assert result.size == 3
            assert result.address == "00000001"


@pytest.mark.asyncio
async def test_read_default_size(server_params):
    """Test reading with default size parameter."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Call without size parameter (should default to 32)
            response = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": "0"
                }
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)

            # Should read 32 bytes by default
            assert result.size == 32
            assert len(result.data) == 64  # 32 bytes * 2 hex chars

            # Should still start with ELF magic
            assert result.data.startswith("7f454c46")


@pytest.mark.asyncio
async def test_read_larger_size(server_params):
    """Test reading a larger chunk."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Read 256 bytes
            response = await session.call_tool(
                "read_bytes",
                {
                    "binary_name": binary_name,
                    "address": "0",
                    "size": 256
                }
            )

            result = BytesReadResult.model_validate_json(response.content[0].text)

            assert result.size == 256
            assert len(result.data) == 512  # 256 bytes * 2 hex chars
            assert result.data.startswith("7f454c46")