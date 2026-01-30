import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import CrossReferenceInfos


@pytest.mark.asyncio
async def test_list_cross_references(shared_mcp_session):
    """
    Tests the list_cross_references tool to ensure it returns
    a list of cross-references from the binary.
    """
    # Use shared MCP session (no need to create new connection)
    session = shared_mcp_session

    # Use pre-imported demo binary from shared session
    binary_name = await import_binary_and_wait(session, test_binary, wait_for_code=False, wait_for_strings=False)

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
