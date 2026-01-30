import asyncio
import json
import os
import platform
import subprocess
import sys
import time

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction

print(f"MCP_BASE_URL: Using dynamic port from pytest fixture")


@pytest.fixture(scope="module")
def sse_server(ghidra_install_dir, base_url, test_binary):
    # Extract port from base_url
    port = base_url.split(":")[-1]

    # Start the SSE server with test_binary (cross-platform)
    proc = subprocess.Popen(
        [sys.executable, "-m", "pyghidra_mcp", "--no-threaded", "--transport", "sse", "--port", port, test_binary],
        env={**os.environ, "GHIDRA_INSTALL_DIR": ghidra_install_dir},
        # stdout/stderr inherit from parent (no redirection)
        # This prevents deadlock when pipe buffers fill up
    )

    async def wait_for_server(timeout=240):
        async with aiohttp.ClientSession() as session:
            for _ in range(timeout):  # Poll for 60 seconds
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

    yield test_binary, base_url
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_sse_client_smoke(sse_server):
    test_binary_path, base_url = sse_server
    # Generate the binary name that Ghidra will use
    binary_name = PyGhidraContext._gen_unique_bin_name(test_binary_path)

    # Use platform-specific entry point
    # Windows: mainCRTStartup is the actual entry function
    # Linux: main is more reliable as entry point may vary
    if platform.system() == "Windows":
        entry_function = "mainCRTStartup"
    else:
        # Linux/Unix: use 'main' as it's always available
        entry_function = "main"

    async with sse_client(f"{base_url}/sse") as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            # Wait for binary to be imported and analyzed (server started with test_binary)
            # Note: The SSE server was started with test_binary, so it should already be imported
            # We just need to wait for analysis to complete
            timeout_seconds = 120
            start_time = asyncio.get_event_loop().time()

            while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
                await asyncio.sleep(1)
                prog_resp = await session.call_tool("list_project_binaries", {})
                prog_result = json.loads(prog_resp.content[0].text)
                prog_infos = prog_result.get("programs", [])

                for pi in prog_infos:
                    if binary_name in pi.get("name", ""):
                        if pi.get("analysis_complete"):
                            break
                else:
                    continue
                break

            # Decompile entry point function (platform-specific)
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": entry_function},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, dict)
            assert len(content.keys()) == len(DecompiledFunction.model_fields.keys())
            assert entry_function in content["code"] or "main" in content["code"]
            print(json.dumps(content, indent=2))
