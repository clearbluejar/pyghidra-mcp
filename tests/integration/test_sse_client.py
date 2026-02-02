import asyncio
import json
import os
import platform
import socket
import subprocess
import sys

import pytest
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction

print(f"MCP_BASE_URL: Using dynamic port from pytest fixture")


async def _wait_for_port(host: str, port: int, timeout: int = 60):
    """Wait for a TCP port to be accepting connections."""
    start_time = asyncio.get_event_loop().time()
    while (asyncio.get_event_loop().time() - start_time) < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            await asyncio.sleep(1)
    return False


async def _wait_for_jvm_ready(session: ClientSession, timeout: int = 240):
    """Wait for JVM to be ready by polling list_project_binaries."""
    for i in range(timeout):
        try:
            response = await session.call_tool("list_project_binaries", {})
        except Exception as e:
            print(f"[WAIT] Server not ready yet: {e}, retrying...")
            await asyncio.sleep(1)
            continue

        if response.content and len(response.content) > 0:
            text_content = response.content[0].text

            if i == 0:
                print(f"\n[DEBUG] First list_project_binaries response:")
                print(f"Length: {len(text_content)}")
                print(f"Content (first 500 chars): {repr(text_content[:500])}")

            if "without jvm" in text_content.lower() or "not started" in text_content.lower():
                if i % 10 == 0:
                    print(f"[WAIT] Waiting for JVM... ({i}/{timeout}s)")
                await asyncio.sleep(1)
                continue

            try:
                data = json.loads(text_content)
                print(f"[SUCCESS] JVM and server ready! Programs: {len(data.get('programs', []))}")
                return
            except json.JSONDecodeError:
                print(f"[WARN] JSON decode error, retrying...")
                await asyncio.sleep(1)
                continue
        else:
            print(f"[WARN] Empty response, retrying...")
            await asyncio.sleep(1)
            continue

    raise RuntimeError(f"JVM did not start in {timeout} seconds")


@pytest.mark.asyncio
async def test_sse_client_smoke(ghidra_install_dir, test_binary, import_binary_and_wait):
    """Test SSE client with lazy initialization."""
    # Get a dedicated port for this test (don't use session-scoped base_url)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]

    host = "127.0.0.1"
    base_url = f"http://{host}:{port}"

    # Start the SSE server process
    proc = subprocess.Popen(
        [sys.executable, "-m", "pyghidra_mcp", "--transport", "sse", "--port", str(port)],
        env={**os.environ, "GHIDRA_INSTALL_DIR": ghidra_install_dir},
    )

    try:
        # Wait for HTTP server to be ready using TCP port check
        # This avoids establishing an SSE connection which could trigger JVM shutdown
        print(f"[WAIT] Waiting for HTTP server to start on port {port}...")
        if not await _wait_for_port(host, port, timeout=60):
            raise RuntimeError("HTTP server did not start in time")
        print(f"[WAIT] HTTP server ready!")

        # Establish SSE connection and keep it open
        print(f"[WAIT] Establishing SSE connection and waiting for JVM...")
        async with sse_client(f"{base_url}/sse") as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # Wait for JVM to be ready
                await _wait_for_jvm_ready(session)

                # Generate the binary name that Ghidra will use
                binary_name = PyGhidraContext._gen_unique_bin_name(test_binary)

                # Use platform-specific entry point
                if platform.system() == "Windows":
                    entry_function = "mainCRTStartup"
                else:
                    entry_function = "main"

                # Import binary and wait for analysis to complete
                await import_binary_and_wait(session, test_binary)

                # Decompile entry point function
                results = await session.call_tool(
                    "decompile_function",
                    {"binary_name": binary_name, "name_or_address": entry_function},
                )

                # Verify results
                assert results is not None
                content = json.loads(results.content[0].text)
                assert isinstance(content, dict)
                assert len(content.keys()) == len(DecompiledFunction.model_fields.keys())
                assert entry_function in content["code"] or "main" in content["code"]
                print(json.dumps(content, indent=2))

    finally:
        # Cleanup: terminate server process
        print(f"[CLEANUP] Terminating server process...")
        proc.terminate()
        proc.wait()
