import asyncio
import json
import socket
import subprocess
import time

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def sse_project_args(tmp_path_factory):
    project_path = tmp_path_factory.mktemp("sse-project")
    return ["--project-path", str(project_path), "--project-name", "sse_client_project"]


@pytest.fixture(scope="module")
def sse_base_url():
    return f"http://127.0.0.1:{_find_free_port()}"


@pytest.fixture(scope="module")
def sse_server(test_binary, ghidra_env, sse_project_args, sse_base_url):
    port = int(sse_base_url.rsplit(":", 1)[1])
    proc = subprocess.Popen(
        [
            "python",
            "-m",
            "pyghidra_mcp",
            *sse_project_args,
            "--no-threaded",
            "--wait-for-analysis",
            "--transport",
            "sse",
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
                    async with session.get(f"{sse_base_url}/sse") as response:
                        if response.status == 200:
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

    yield test_binary, sse_base_url
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_sse_client_smoke(sse_server, main_func_name):
    sse_binary, sse_base_url = sse_server
    async with sse_client(f"{sse_base_url}/sse") as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            binary_name = PyGhidraContext._gen_unique_bin_name(sse_binary)

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
