import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from tests.benchmark_helpers import collect_list_tools_metrics

TRACKED_TOOL_NAMES = {
    "search_code",
    "search_symbols_by_name",
    "list_exports",
    "list_imports",
    "list_cross_references",
    "gen_callgraph",
    "list_project_binaries",
}
LIST_TOOLS_PAYLOAD_BYTES_BUDGET = 16000
TOOL_TOTAL_JSON_BUDGETS = {
    "search_code": 2900,
    "search_symbols_by_name": 1450,
    "list_exports": 950,
    "list_imports": 950,
    "list_cross_references": 1250,
    "gen_callgraph": 2000,
    "list_project_binaries": 1450,
}


@pytest.mark.asyncio
async def test_stdio_client_initialization(server_params):
    """Test stdio client initialization."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            result = await session.initialize()

            assert result is not None
            assert hasattr(result, "protocolVersion")


@pytest.mark.asyncio
async def test_stdio_client_list_tools(server_params):
    """Test listing available tools."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()

            assert tools is not None
            assert any(tool.name == "decompile_function" for tool in tools.tools)
            assert any(tool.name == "search_functions_by_name" for tool in tools.tools)
            assert any(tool.name == "list_project_binaries" for tool in tools.tools)


@pytest.mark.asyncio
async def test_stdio_client_list_tools_surface_metrics(server_params):
    """Measure real MCP tool payload sizes from list_tools."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            payload_bytes, tool_metrics = collect_list_tools_metrics(tools)
            largest_tools = [
                metric.to_dict()
                for metric in sorted(
                    tool_metrics.values(),
                    key=lambda metric: metric.total_json_bytes,
                    reverse=True,
                )[:7]
            ]

            assert TRACKED_TOOL_NAMES.issubset(tool_metrics)
            assert payload_bytes <= LIST_TOOLS_PAYLOAD_BYTES_BUDGET, {
                "payload_bytes": payload_bytes,
                "largest_tools": largest_tools,
            }
            for name in TRACKED_TOOL_NAMES:
                metrics = tool_metrics[name]
                assert metrics.description_length > 0
                assert metrics.input_schema_bytes > 0
                assert metrics.output_schema_bytes > 0
                assert metrics.total_json_bytes <= TOOL_TOTAL_JSON_BUDGETS[name], {
                    "name": name,
                    "metrics": metrics.to_dict(),
                    "largest_tools": largest_tools,
                }


@pytest.mark.asyncio
async def test_stdio_client_list_tools_schema_contracts(server_params):
    """Verify compatibility-sensitive MCP schemas for tool discovery."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            tool_entries = {
                tool.name: tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                for tool in tools.tools
            }

            list_project_binaries_schema = tool_entries["list_project_binaries"]["inputSchema"]
            assert list_project_binaries_schema["type"] == "object"
            assert list_project_binaries_schema.get("properties") == {}
            assert list_project_binaries_schema.get("additionalProperties") is False

            metadata_output_schema = tool_entries["list_project_binary_metadata"].get(
                "outputSchema"
            )
            assert metadata_output_schema is not None
            assert metadata_output_schema["type"] == "object"


@pytest.mark.asyncio
async def test_stdio_client_list_resources(server_params):
    """Test listing available resources."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            resources = await session.list_resources()

            assert resources is not None
