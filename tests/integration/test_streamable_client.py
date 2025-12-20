import asyncio
import json
import os
import subprocess
import time

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction

base_url = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8000")


@pytest.fixture(scope="module")
def streamable_server(test_binary):
    """Fixture to start the pyghidra-mcp server in a separate process."""
    proc = subprocess.Popen(
        [
            "python",
            "-m",
            "pyghidra_mcp",
            "--wait-for-analysis",
            "--transport",
            "streamable-http",
            test_binary,
        ],
        env={**os.environ, "GHIDRA_INSTALL_DIR": "/ghidra"},
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    async def wait_for_server(timeout=240):
        async with aiohttp.ClientSession() as session:
            for _ in range(timeout):  # Poll for 20 seconds
                try:
                    async with session.get(f"{base_url}/mcp") as response:
                        if response.status == 406:
                            return
                except aiohttp.ClientConnectorError:
                    pass
                await asyncio.sleep(1)
            raise RuntimeError("Server did not start in time")

    asyncio.run(wait_for_server())

    time.sleep(2)

    yield test_binary
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_streamable_client_smoke(streamable_server):
    async with streamablehttp_client(f"{base_url}/mcp") as (
        read_stream,
        write_stream,
        _,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            binary_name = PyGhidraContext._gen_unique_bin_name(streamable_server)

            # Decompile a function
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": "main"},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, dict)
            assert len(content.keys()) == len(DecompiledFunction.model_fields.keys())
            assert "main(void)" in content["code"]
            print(json.dumps(content, indent=2))
