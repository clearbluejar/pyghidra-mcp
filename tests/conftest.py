"""Protocol test transport for either supported MCP Python SDK."""

from contextlib import asynccontextmanager

import anyio
import pytest

from pyghidra_mcp.mcp_compat import IS_MCP_V2


@pytest.fixture
def mcp_transport():
    if IS_MCP_V2:
        from mcp.client._memory import InMemoryTransport

        return InMemoryTransport

    from mcp.shared.memory import create_client_server_memory_streams

    @asynccontextmanager
    async def transport(server):
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            lowlevel = server._mcp_server
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(
                    lowlevel.run,
                    *server_streams,
                    lowlevel.create_initialization_options(),
                )
                try:
                    yield client_streams
                finally:
                    tasks.cancel_scope.cancel()

    return transport
