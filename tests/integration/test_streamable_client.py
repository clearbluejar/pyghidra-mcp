import asyncio
import json
import socket
import subprocess
import time

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def streamable_project_args(tmp_path_factory):
    project_path = tmp_path_factory.mktemp("streamable-project")
    return ["--project-path", str(project_path), "--project-name", "streamable_client_project"]


@pytest.fixture(scope="module")
def streamable_base_url():
    return f"http://127.0.0.1:{_find_free_port()}"


@pytest.fixture(scope="module")
def streamable_server(test_binary, ghidra_env, streamable_project_args, streamable_base_url):
    """Fixture to start the pyghidra-mcp server in a separate process."""
    port = int(streamable_base_url.rsplit(":", 1)[1])
    proc = subprocess.Popen(
        [
            "python",
            "-m",
            "pyghidra_mcp",
            *streamable_project_args,
            "--wait-for-analysis",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            test_binary,
        ],
        env=ghidra_env,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    async def wait_for_server(timeout=240):
        async with aiohttp.ClientSession() as session:
            for _ in range(timeout):
                try:
                    async with session.get(f"{streamable_base_url}/mcp") as response:
                        if response.status == 406:
                            return
                except aiohttp.ClientConnectorError:
                    pass
                await asyncio.sleep(1)
            raise RuntimeError("Server did not start in time")

    try:
        asyncio.run(wait_for_server())
    except Exception:
        proc.terminate()
        proc.wait()
        raise

    time.sleep(2)

    yield test_binary, streamable_base_url
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_streamable_client_smoke(streamable_server, main_func_name):
    streamable_binary, streamable_base_url = streamable_server
    async with streamable_http_client(f"{streamable_base_url}/mcp") as (
        read_stream,
        write_stream,
        _,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            binary_name = PyGhidraContext._gen_unique_bin_name(streamable_binary)

            # Decompile a function
            name = main_func_name
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": name},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, dict)
            assert len(content.keys()) == len(DecompiledFunction.model_fields.keys())
            assert f"{name}(" in content["code"]
            print(json.dumps(content, indent=2))
