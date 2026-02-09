"""Unit tests for the pyghidra-mcp client."""

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
