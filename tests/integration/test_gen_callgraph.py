import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import CallGraphResult


@pytest.mark.asyncio
async def test_gen_callgraph_tool(server_params, test_binary):
    """Test the gen_callgraph tool."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Call the gen_callgraph tool

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
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
