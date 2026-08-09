"""Unit tests for the pyghidra-mcp client."""

from unittest.mock import AsyncMock, Mock

import pytest


def test_client_import():
    """Test that the client module can be imported."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    assert PyGhidraMcpClient is not None


def test_client_instantiation():
    """Test that client can be instantiated with default parameters."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    client = PyGhidraMcpClient()
    assert client.host == "127.0.0.1"
    assert client.port == 8000


def test_client_custom_params():
    """Test that client can be instantiated with custom parameters."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    client = PyGhidraMcpClient(host="localhost", port=9000)
    assert client.host == "localhost"
    assert client.port == 9000


# @pytest.mark.skip(reason="Requires running server - this is an integration test")
def test_client_error_exception():
    """Test ClientError exception."""
    from pyghidra_mcp_cli.client import ClientError

    with pytest.raises(ClientError):
        raise ClientError("Test error")


def test_binary_not_found_error_exception():
    """Test BinaryNotFoundError exception."""
    from pyghidra_mcp_cli.client import BinaryNotFoundError

    with pytest.raises(BinaryNotFoundError):
        raise BinaryNotFoundError("Binary not found")


def test_client_has_edit_methods():
    """Test that edit-tool client methods exist."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    client = PyGhidraMcpClient()
    assert callable(client.rename_function)
    assert callable(client.rename_variable)
    assert callable(client.set_variable_type)
    assert callable(client.set_function_prototype)
    assert callable(client.set_comment)


def test_client_has_gui_methods():
    """Test that GUI-tool client methods exist."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    client = PyGhidraMcpClient()
    assert callable(client.list_open_programs)
    assert callable(client.open_program_in_gui)
    assert callable(client.set_current_program)
    assert callable(client.goto)


def test_client_extracts_mcp_v2_structured_content():
    """Test extraction from an MCP 2 result using Python field names."""
    from mcp.types import CallToolResult

    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    result = CallToolResult(content=[], structured_content={"programs": []})

    assert PyGhidraMcpClient()._extract_result(result) == {"programs": []}


def test_client_extracts_mcp_v2_tool_errors():
    """Test that MCP tool execution errors remain actionable CLI errors."""
    from mcp.types import CallToolResult, TextContent

    from pyghidra_mcp_cli.client import ClientError, PyGhidraMcpClient

    result = CallToolResult(
        content=[TextContent(type="text", text="count must be <= 200")],
        is_error=True,
    )

    with pytest.raises(ClientError, match="count must be <= 200"):
        PyGhidraMcpClient()._extract_result(result)


@pytest.mark.asyncio
async def test_gui_client_methods_call_expected_tools():
    """Test GUI client wrappers call the expected MCP tools."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    client = PyGhidraMcpClient()
    client._connected = True
    client._session = AsyncMock()
    mcp_result = Mock()
    mcp_result.model_dump.return_value = {"structuredContent": {"ok": True}}
    client._session.call_tool.return_value = mcp_result

    assert await client.list_open_programs() == {"ok": True}
    client._session.call_tool.assert_awaited_with("list_open_programs", {})

    await client.open_program_in_gui("sample", new_window=False)
    client._session.call_tool.assert_awaited_with(
        "open_program_in_gui",
        {"binary_name": "sample", "new_window": False},
    )

    await client.set_current_program("sample")
    client._session.call_tool.assert_awaited_with(
        "set_current_program",
        {"binary_name": "sample"},
    )

    await client.goto("sample", "entry", "function")
    client._session.call_tool.assert_awaited_with(
        "goto",
        {"binary_name": "sample", "target": "entry", "target_type": "function"},
    )
    assert mcp_result.model_dump.call_count == 4
    mcp_result.model_dump.assert_called_with(by_alias=True)
