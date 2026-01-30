"""
Integration test for the read_bytes functionality.

Simple smoke test to verify read_bytes works through the MCP interface.
"""

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import BytesReadResult, ImageBaseResult


@pytest.mark.asyncio
async def test_read_bytes_tool(shared_mcp_session):
    """Test that read_bytes works - basic smoke test."""
    # Use shared MCP session with pre-imported demo binary
    session = shared_mcp_session
    binary_name = session.demo_binary_name

    # Get the image base address (differs between ELF and PE)
    response = await session.call_tool(
        "get_image_base", {"binary_name": binary_name}
    )
    image_base_result = ImageBaseResult.model_validate_json(response.content[0].text)
    image_base = image_base_result.image_base

    # Try reading from the image base
    response = await session.call_tool(
        "read_bytes", {"binary_name": binary_name, "address": image_base, "size": 4}
    )

    result = BytesReadResult.model_validate_json(response.content[0].text)

    # Check if we got either ELF or PE magic bytes (4 bytes)
    # ELF: 0x7F + "ELF" in hex = "7f454c46"
    # PE (Windows): "MZ" + header bytes = "4d5a9000" (0x4D 0x5A 0x90 0x00)
    assert result.data in ("7f454c46", "4d5a9000"), f"Unexpected magic bytes: {result.data}"
    assert result.size == 4
