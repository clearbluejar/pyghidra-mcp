import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import CallGraphResult


@pytest.mark.asyncio
async def test_gen_callgraph_tool(shared_mcp_session):
    """Test the gen_callgraph tool."""

    # Use shared MCP session with pre-imported demo binary
    session = shared_mcp_session
    binary_name = session.demo_binary_name

    # Call the gen_callgraph tool
    results = await session.call_tool(
        "gen_callgraph",
        {
            "binary_name": binary_name,
            "function_name": "function_two",
            "direction": "calling",
            "display_type": "flow",
        },
    )

    # Check that we got results
    assert results is not None
    assert results.content is not None
    assert len(results.content) > 0

    # Check that the result contains CallGraph data
    text_content = results.content[0].text
    assert text_content is not None
    assert len(text_content) > 0

    # Check that the content is valid JSON and deserializes to CallGraph
    data = text_content.strip()
    assert data.startswith("{") and data.endswith("}")
    call_graph_data = CallGraphResult.model_validate_json(data)

    assert (
        call_graph_data.function_name == "function_two"
    )  # Assuming 'main' is always present/searched for default
    assert call_graph_data.direction == "calling"
    assert call_graph_data.display_type == "flow"
    assert len(call_graph_data.graph) > 0
