"""MCP Client wrapper for pyghidra-mcp server.

This module provides a simplified async client interface to the pyghidra-mcp server
via HTTP transport only.

Usage:
    client = PyGhidraMcpClient(host="localhost", port=8000)
    await client.connect()
    result = await client.list_project_binaries()
    await client.close()
"""

import asyncio
import json
from typing import Any

from mcp import ClientSession

from .utils import get_server_start_message


class ClientError(Exception):
    """Custom exception for client errors."""

    pass


class ServerNotRunningError(ClientError):
    """Raised when the pyghidra-mcp server is not running."""

    pass


class BinaryNotFoundError(ClientError):
    """Raised when a binary is not found in the project."""

    pass


class PyGhidraMcpClient:
    """
    Wrapper around MCP ClientSession for pyghidra-mcp server.

    Handles connection management and provides a simpler interface
    for common operations via HTTP transport.

    Usage:
        async with PyGhidraMcpClient(host="localhost", port=8000) as client:
            result = await client.list_project_binaries()
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
    ):
        """
        Initialize the MCP client.

        Args:
            host: Server host
            port: Server port
        """
        self.host = host
        self.port = port
        self._session: ClientSession | None = None
        self._session_cm = None
        self._transport_cm = None
        self._connected = False

    async def __aenter__(self):
        """Async context manager entry - establishes connection to server."""
        await self._connect_internal()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - closes connection and cleanup resources."""
        await self._close_internal()
        # Return None to propagate exceptions normally
        return None

    async def _connect_internal(self) -> None:
        """Internal connection logic - establish connection to the pyghidra-mcp server."""
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        url = f"http://{self.host}:{self.port}/mcp"

        transport_gen = streamablehttp_client(url)
        try:
            read, write, _ = await asyncio.wait_for(transport_gen.__aenter__(), timeout=5.0)
        except asyncio.TimeoutError:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            raise ServerNotRunningError(
                f"Cannot connect to pyghidra-mcp server at {url}\n\n{get_server_start_message()}"
            )
        except (ConnectionError, OSError) as e:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            raise ServerNotRunningError(
                f"Cannot connect to pyghidra-mcp server at {url}\n\n{get_server_start_message()}"
            ) from e
        except Exception as e:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            error_msg = str(e)
            if any(x in error_msg for x in ["ConnectError", "connection", "ConnectionRefused"]):
                raise ServerNotRunningError(
                    f"Cannot connect to pyghidra-mcp server at {url}\n\n{get_server_start_message()}"
                ) from e
            raise ServerNotRunningError(
                f"Cannot connect to pyghidra-mcp server at {url}: {e}\n\n{get_server_start_message()}"
            ) from e

        self._transport_cm = transport_gen
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        self._connected = True

    async def _close_internal(self) -> None:
        """Internal cleanup logic - close the connection and cleanup resources."""
        if self._session_cm and self._connected:
            self._connected = False
            try:
                await self._session_cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._session_cm = None
            self._session = None

        if self._transport_cm:
            try:
                await self._transport_cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._transport_cm = None

    def _extract_result(self, result) -> dict[str, Any]:
        """Extract data from MCP result, handling structuredContent and errors."""
        result_dict = result.model_dump()

        if result_dict.get("isError"):
            content = result_dict.get("content", [])
            if content and len(content) > 0:
                error_text = content[0].get("text", "Unknown error")
                raise ClientError(error_text)
            raise ClientError("Unknown error occurred")

        if "structuredContent" in result_dict:
            structured = result_dict["structuredContent"]
            if structured is None:
                # Check if there's valid data in content[0].text (for metadata responses)
                content = result_dict.get("content", [])
                if content and len(content) > 0 and content[0].get("text"):
                    try:
                        return json.loads(content[0]["text"])
                    except (json.JSONDecodeError, KeyError):
                        pass
                raise BinaryNotFoundError(
                    "Binary not found. "
                    "Run 'pyghidra-mcp-cli list binaries' to see available binaries."
                )
            return structured

        if result_dict is None or (isinstance(result_dict, dict) and not result_dict):
            raise BinaryNotFoundError(
                "Binary not found. Run 'pyghidra-mcp-cli list binaries' to see available binaries."
            )

        return result_dict

    async def list_project_binaries(self) -> dict[str, Any]:
        """List all binaries in the project."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool("list_project_binaries", {})
        return self._extract_result(result)

    async def decompile_function(
        self, binary_name: str, function_name_or_address: str
    ) -> dict[str, Any]:
        """Decompile a function."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "decompile_function",
            {"binary_name": binary_name, "name_or_address": function_name_or_address},
        )
        return self._extract_result(result)

    async def search_symbols(
        self, binary_name: str, query: str, offset: int = 0, limit: int = 25
    ) -> dict[str, Any]:
        """Search for symbols by name."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "search_symbols_by_name",
            {
                "binary_name": binary_name,
                "query": query,
                "offset": offset,
                "limit": limit,
            },
        )
        return self._extract_result(result)

    async def search_code(
        self,
        binary_name: str,
        query: str,
        limit: int = 5,
        offset: int = 0,
        search_mode: str = "semantic",
        include_full_code: bool = True,
        preview_length: int = 500,
        similarity_threshold: float = 0.0,
    ) -> dict[str, Any]:
        """Search code by query."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "search_code",
            {
                "binary_name": binary_name,
                "query": query,
                "limit": limit,
                "offset": offset,
                "search_mode": search_mode,
                "include_full_code": include_full_code,
                "preview_length": preview_length,
                "similarity_threshold": similarity_threshold,
            },
        )
        return self._extract_result(result)

    async def search_strings(
        self, binary_name: str, query: str, limit: int = 100
    ) -> dict[str, Any]:
        """Search for strings in the binary."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "search_strings",
            {"binary_name": binary_name, "query": query, "limit": limit},
        )
        return self._extract_result(result)

    async def list_imports(
        self, binary_name: str, query: str = ".*", offset: int = 0, limit: int = 25
    ) -> dict[str, Any]:
        """List imports in the binary."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "list_imports",
            {"binary_name": binary_name, "query": query, "offset": offset, "limit": limit},
        )
        return self._extract_result(result)

    async def list_exports(
        self, binary_name: str, query: str = ".*", offset: int = 0, limit: int = 25
    ) -> dict[str, Any]:
        """List exports in the binary."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "list_exports",
            {"binary_name": binary_name, "query": query, "offset": offset, "limit": limit},
        )
        return self._extract_result(result)

    async def list_cross_references(self, binary_name: str, name_or_address: str) -> dict[str, Any]:
        """List cross-references to a symbol or address."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "list_cross_references",
            {"binary_name": binary_name, "name_or_address": name_or_address},
        )
        return self._extract_result(result)

    async def read_bytes(self, binary_name: str, address: str, size: int = 32) -> dict[str, Any]:
        """Read bytes from memory."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "read_bytes",
            {"binary_name": binary_name, "address": address, "size": size},
        )
        return self._extract_result(result)

    async def gen_callgraph(
        self,
        binary_name: str,
        function_name: str,
        direction: str = "calling",
        display_type: str = "flow",
        condense_threshold: int = 50,
        top_layers: int = 3,
        bottom_layers: int = 3,
        max_run_time: int = 120,
    ) -> dict[str, Any]:
        """Generate a call graph for a function."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "gen_callgraph",
            {
                "binary_name": binary_name,
                "function_name": function_name,
                "direction": direction,
                "display_type": display_type,
                "condense_threshold": condense_threshold,
                "top_layers": top_layers,
                "bottom_layers": bottom_layers,
                "max_run_time": max_run_time,
            },
        )
        return self._extract_result(result)

    async def import_binary(self, binary_path: str) -> dict[str, Any]:
        """Import a binary into the project."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "import_binary",
            {"binary_path": binary_path},
        )
        return self._extract_result(result)

    async def delete_binary(self, binary_name: str) -> dict[str, Any]:
        """Delete a binary from the project."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "delete_project_binary",
            {"binary_name": binary_name},
        )
        return self._extract_result(result)

    async def list_project_binary_metadata(self, binary_name: str) -> dict[str, Any]:
        """Get metadata for a binary."""
        if not self._connected:
            raise ClientError("Not connected")

        result = await self._session.call_tool(
            "list_project_binary_metadata",
            {"binary_name": binary_name},
        )
        return self._extract_result(result)
