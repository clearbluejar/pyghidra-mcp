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
from mcp.client.streamable_http import streamable_http_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction

@pytest.fixture(scope="module")
def streamable_server(test_binary, ghidra_install_dir, base_url):
    """Fixture to start the pyghidra-mcp server in a separate process."""
    # Extract port from base_url
    port = base_url.split(":")[-1]

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "pyghidra_mcp",
            "--transport",
            "streamable-http",
            "--port",
            port,
        ],
        env={**os.environ, "GHIDRA_INSTALL_DIR": ghidra_install_dir},
        # stdout/stderr inherit from parent (no redirection)
        # This prevents deadlock when pipe buffers fill up
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

    yield test_binary, base_url
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_streamable_client_smoke(streamable_server, import_binary_and_wait):
    test_binary, base_url = streamable_server

    # Generate the binary name that Ghidra will use
    binary_name = PyGhidraContext._gen_unique_bin_name(test_binary)

    async with streamable_http_client(f"{base_url}/mcp") as (
        read_stream,
        write_stream,
        _,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            # Import binary and wait for analysis
            await import_binary_and_wait(session, test_binary, wait_for_code=False, wait_for_strings=False)

            # Use platform-specific function to decompile
            # Windows: mainCRTStartup is the entry, main should also work
            # Linux: main is always available
            if platform.system() == "Windows":
                # On Windows, try mainCRTStartup first, fall back to main
                target_function = "mainCRTStartup"
            else:
                target_function = "main"

            # Decompile a function
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": target_function},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, dict)
            assert len(content.keys()) == len(DecompiledFunction.model_fields.keys())
            # Check that function name appears in code
            assert target_function in content["code"] or "main" in content["code"]
            print(json.dumps(content, indent=2))
