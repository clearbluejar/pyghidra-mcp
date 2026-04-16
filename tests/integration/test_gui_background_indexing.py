import asyncio
import json
import signal
import socket
import subprocess

import aiohttp
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from pyghidra_mcp.context import PyGhidraContext


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _wait_for_http_server(
    base_url: str,
    proc: subprocess.Popen[str],
    timeout: int = 240,
) -> None:
    async with aiohttp.ClientSession() as session:
        for _ in range(timeout):
            if proc.poll() is not None:
                stdout = proc.stdout.read() if proc.stdout else ""
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(
                    "GUI server exited before startup.\n"
                    f"exit_code={proc.returncode}\n"
                    f"stdout:\n{stdout}\n"
                    f"stderr:\n{stderr}"
                )
            try:
                async with session.get(f"{base_url}/mcp") as response:
                    if response.status == 406:
                        return
            except aiohttp.ClientConnectorError:
                pass
            await asyncio.sleep(1)
    raise RuntimeError("GUI server did not start in time")


def _gui_env_or_skip(env: dict[str, str], is_macos: bool) -> dict[str, str]:
    if not is_macos and not env.get("DISPLAY"):
        pytest.skip("GUI indexing test requires DISPLAY on Linux (e.g. Xvfb in CI).")
    if is_macos and env.get("GITHUB_ACTIONS") == "true":
        pytest.skip("GUI indexing test is not supported on GitHub-hosted macOS runners.")
    return env


@pytest.mark.asyncio
async def test_gui_background_indexing_eventually_enables_string_search(
    test_binary,
    ghidra_env,
    isolated_project_root,
    is_macos,
    find_binary_in_list_response,
):
    gui_env = _gui_env_or_skip(dict(ghidra_env), is_macos)
    headless_env = dict(ghidra_env)
    if not is_macos:
        headless_env.pop("DISPLAY", None)
    fixture_name = "gui_background_indexing"
    project_dir = isolated_project_root / fixture_name
    project_name = f"{fixture_name}_project"

    headless_params = StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(project_dir),
            "--project-name",
            project_name,
            "--wait-for-analysis",
            test_binary,
        ],
        env=headless_env,
    )

    binary_name = PyGhidraContext._gen_unique_bin_name(test_binary)

    async with stdio_client(headless_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            ready = False
            for _ in range(240):
                response = await session.call_tool("list_project_binaries", {})
                program = find_binary_in_list_response(response, binary_name)
                if program and program["analysis_complete"]:
                    ready = True
                    break
                await asyncio.sleep(1)

            assert ready

    project_gpr = project_dir / f"{project_name}.gpr"
    assert project_gpr.exists()

    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [
            "python",
            "-m",
            "pyghidra_mcp",
            "--gui",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--project-path",
            str(project_gpr),
        ],
        env=gui_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        await _wait_for_http_server(base_url, proc)

        async with streamable_http_client(f"{base_url}/mcp") as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                opened = await session.call_tool(
                    "open_program_in_gui",
                    {"binary_name": binary_name, "current": True},
                )
                opened_payload = json.loads(opened.content[0].text)
                assert opened_payload["current"] is True

                strings_indexed = False
                for _ in range(240):
                    binaries = await session.call_tool("list_project_binaries", {})
                    program = find_binary_in_list_response(binaries, binary_name)
                    if program and program["strings_indexed"]:
                        strings_indexed = True
                        break
                    await asyncio.sleep(1)

                assert strings_indexed

                response = await session.call_tool(
                    "search_strings",
                    {"binary_name": binary_name, "query": "hello"},
                )
                payload = json.loads(response.content[0].text)
                values = [entry["value"] for entry in payload["strings"]]
                assert any("World" in value for value in values)
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

        stderr = proc.stderr.read() if proc.stderr else ""
        assert "AWT blocker activation interrupted" not in stderr
