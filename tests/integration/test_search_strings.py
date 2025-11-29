import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import StringSearchResults


@pytest.mark.asyncio
async def test_search_strings_hello(server_params_no_thread):
    """
    Test for the string Hello in the example binary.
    """
    async with stdio_client(server_params_no_thread) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params_no_thread.args[-1])

            response = await session.call_tool(
                "search_strings", {"binary_name": binary_name, "query": "hello"}
            )

            search_results = StringSearchResults.model_validate_json(response.content[0].text)
            assert len(search_results.strings) >= 1
            assert any("World" in s.value for s in search_results.strings)
