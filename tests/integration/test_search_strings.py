import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import StringSearchResults


@pytest.mark.asyncio
async def test_search_strings_hello(shared_mcp_session):
    """
    Test for the string Hello in the example binary.
    """
    # Use shared MCP session with pre-imported demo binary
    session = shared_mcp_session
    binary_name = session.demo_binary_name

    response = await session.call_tool(
        "search_strings", {"binary_name": binary_name, "query": "hello"}
    )

    search_results = StringSearchResults.model_validate_json(response.content[0].text)
    assert len(search_results.strings) >= 1
    assert any("World" in s.value for s in search_results.strings)
