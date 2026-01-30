import asyncio
import os
import sys

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


@pytest.mark.asyncio
async def test_import_binary(
    test_binary, shared_mcp_session, find_binary_in_list_response
):
    """
    Test for the string Hello in the example binary.
    """
    # Use shared MCP session (no need to create new connection)
    session = shared_mcp_session

    test_binary_name = PyGhidraContext._gen_unique_bin_name(test_binary)

    response = await session.call_tool(
        "import_binary", {"binary_path": test_binary}
    )

    content = response.content[0].text
    assert test_binary in content

    ready = False
    for _ in range(240):
        # Try until binary is ready
        await asyncio.sleep(1)

        response = await session.call_tool("list_project_binaries", {})
        program = find_binary_in_list_response(response, test_binary_name)
        if not program:
            continue
        if program["analysis_complete"]:
            ready = True
            break

    assert ready
