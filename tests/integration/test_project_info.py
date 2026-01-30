import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client



@pytest.mark.asyncio
async def test_list_project_binaries_tool(shared_mcp_session):
    """Test the list_project_binaries tool."""

    # Use shared MCP session with pre-imported demo binary
    session = shared_mcp_session
    binary_name = session.demo_binary_name

    # Call the list_project_binaries tool
    results = await session.call_tool("list_project_binaries", {})

    # Check that we got results
    assert results is not None
    assert results.content is not None
    assert len(results.content) > 0

    # The result should be a list of program basic info
    text_content = results.content[0].text
    program_infos = json.loads(text_content)
    assert "programs" in program_infos
    assert isinstance(program_infos["programs"], list)
    program_infos = program_infos["programs"]
    assert len(program_infos) > 0

    found = False
    for program in program_infos:
        if binary_name in program["name"]:
            found = True
            assert program["analysis_complete"]
            break

    assert found
