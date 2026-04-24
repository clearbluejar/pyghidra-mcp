import asyncio
import json
import os
import platform
import signal
import socket
import subprocess
from pathlib import Path

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


async def _wait_for_http_server(  # noqa: C901
    base_url: str,
    proc: subprocess.Popen[str],
    env: dict[str, str],
    timeout: int = 240,
) -> None:
    def _safe_read_stream(stream) -> str:
        if stream is None:
            return ""
        try:
            return stream.read()
        except ValueError:
            return ""

    def _application_log_contents(env: dict[str, str]) -> str:
        home = env.get("HOME")
        ghidra_version = env.get("GHIDRA_VERSION")
        if not home or not ghidra_version:
            return ""

        app_log = (
            Path(home)
            / ".config"
            / "ghidra"
            / f"ghidra_{ghidra_version}_PUBLIC"
            / "application.log"
        )
        if not app_log.exists():
            return ""

        try:
            return app_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    async with aiohttp.ClientSession() as session:
        for _ in range(timeout):
            if proc.poll() is not None:
                stdout = _safe_read_stream(proc.stdout)
                stderr = _safe_read_stream(proc.stderr)
                raise RuntimeError(
                    "GUI server exited before startup.\n"
                    f"exit_code={proc.returncode}\n"
                    f"stdout:\n{stdout}\n"
                    f"stderr:\n{stderr}\n"
                    f"application_log:\n{_application_log_contents(env)}"
                )
            try:
                async with session.get(f"{base_url}/mcp") as response:
                    if response.status == 406:
                        return
            except aiohttp.ClientConnectorError:
                pass
            await asyncio.sleep(1)
    proc.terminate()
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=10)
    raise RuntimeError(
        "GUI server did not start in time.\n"
        f"exit_code={proc.returncode}\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}\n"
        f"application_log:\n{_application_log_contents(env)}"
    )


def _gui_env_or_skip(env: dict[str, str]) -> dict[str, str]:
    if platform.system() == "Linux" and not env.get("DISPLAY"):
        pytest.skip("GUI smoke test requires DISPLAY on Linux (e.g. Xvfb in CI).")
    if platform.system() == "Darwin" and os.environ.get("GITHUB_ACTIONS") == "true":
        pytest.skip("GUI smoke test is not supported on GitHub-hosted macOS runners.")
    return env


@pytest.mark.asyncio
async def test_gui_smoke(
    test_binary,
    ghidra_env,
    isolated_project_root,
    main_func_name,
    find_binary_in_list_response,
):
    gui_env = _gui_env_or_skip(dict(ghidra_env))
    headless_env = dict(ghidra_env)
    if platform.system() == "Linux":
        headless_env.pop("DISPLAY", None)
    fixture_name = "gui_smoke"
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
            "-u",
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
        env={**gui_env, "PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        await _wait_for_http_server(base_url, proc, gui_env)

        async with streamable_http_client(f"{base_url}/mcp") as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                binaries = await session.call_tool("list_project_binaries", {})
                program = find_binary_in_list_response(binaries, binary_name)
                assert program is not None
                assert program["analysis_complete"] is True

                opened = await session.call_tool(
                    "open_program_in_gui",
                    {"binary_name": binary_name, "current": True},
                )
                opened_payload = json.loads(opened.content[0].text)
                assert opened_payload["current"] is True
                assert opened_payload["analysis_complete"] is True

                goto_result = await session.call_tool(
                    "goto",
                    {
                        "binary_name": binary_name,
                        "target": main_func_name,
                        "target_type": "function",
                    },
                )
                goto_payload = json.loads(goto_result.content[0].text)
                assert goto_payload["success"] is True

                comment_result = await session.call_tool(
                    "set_comment",
                    {
                        "binary_name": binary_name,
                        "target": main_func_name,
                        "comment_type": "decompiler",
                        "comment": "GUI smoke test comment.",
                    },
                )
                comment_payload = json.loads(comment_result.content[0].text)
                assert comment_payload["comment_type"] == "decompiler"
                assert comment_payload["comment"] == "GUI smoke test comment."

                # Test get_gui_context after goto, which typically activates Listing and specific address
                # Wait briefly for Swing UI to settle after goto
                await asyncio.sleep(0.5)
                context_result = await session.call_tool("get_gui_context", {})
                context_payload = json.loads(context_result.content[0].text)
                # The provider might be Listing, Decompiler, or CodeBrowser; importantly, an address should be detected.
                assert context_payload.get("active_address") is not None
                assert context_payload.get("active_program") is not None
                assert context_payload.get("active_function") == main_func_name
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

        try:
            stderr = proc.stderr.read() if proc.stderr else ""
        except ValueError:
            stderr = ""
        assert "AWT blocker activation interrupted" not in stderr
