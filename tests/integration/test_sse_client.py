import json
import os
import subprocess
import time
import tempfile

import pytest
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from pyghidra_mcp.models import DecompiledFunction
import aiohttp
import asyncio

base_url = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8000")

print(f"MCP_BASE_URL: {base_url}")


@pytest.fixture(scope="module")
def sse_server():
    # Start the SSE server
    proc = subprocess.Popen(
        ["python", "-m", "pyghidra_mcp", "--transport", "sse", "/bin/ls"],
        env={**os.environ, "GHIDRA_INSTALL_DIR": "/ghidra"},
    )

    async def wait_for_server():
        async with aiohttp.ClientSession() as session:
            for _ in range(20):  # Poll for 20 seconds
                try:
                    async with session.get(f"{base_url}/sse") as response:
                        if response.status == 200:
                            return
                except aiohttp.ClientConnectorError:
                    pass
                await asyncio.sleep(1)
            raise RuntimeError("Server did not start in time")

    asyncio.run(wait_for_server())

    time.sleep(2)

    yield
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_sse_client_smoke(sse_server):
    async with sse_client(f"{base_url}/sse") as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            # Decompile a function
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": "ls", "name": "entry"},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, dict)
            assert len(content.keys()) == len(
                DecompiledFunction.model_fields.keys())
            assert "entry" in content["code"]
            print(json.dumps(content, indent=2))
