import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import SymbolSearchResults


@pytest.mark.asyncio
async def test_search_symbols_by_name(shared_mcp_session):
    """
    Tests searching for symbols by name.
    """
    # Use shared MCP session (no need to create new connection)
    session = shared_mcp_session

    # Use pre-imported demo binary from shared session
    binary_name = await import_binary_and_wait(session, test_binary, wait_for_code=False, wait_for_strings=False)

    response = await session.call_tool(
        "search_symbols_by_name", {"binary_name": binary_name, "query": "function"}
    )

    search_results = SymbolSearchResults.model_validate_json(response.content[0].text)
    assert len(search_results.symbols) >= 2
    assert any("function_one" in s.name for s in search_results.symbols)
    assert any("function_two" in s.name for s in search_results.symbols)
