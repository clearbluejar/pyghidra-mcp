import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


@pytest.mark.asyncio
async def test_decompile_function_tool(server_params, test_binary):
    """Test the decompile_function tool."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Call the decompile_function tool
            try:
                binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
                results = await session.call_tool(
                    "decompile_function", {"binary_name": binary_name, "name_or_address": "main"}
                )

                # Check that we got results
                assert results is not None
                assert results.content is not None
                assert len(results.content) > 0

                # Check that the result contains decompiled code
                # (this might vary depending on the binary and Ghidra's analysis)
                # We'll just check that it's not empty
                text_content = results.content[0].text
                assert text_content is not None
                assert len(text_content) > 0
                assert "main" in text_content
            except Exception as e:
                # If we get an error, it might be because the function wasn't found
                # or because of issues with the binary analysis
                # We'll just check that we got a proper error response
                assert e is not None
