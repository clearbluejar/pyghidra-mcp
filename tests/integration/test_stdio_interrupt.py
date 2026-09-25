import os
import select
import signal
import subprocess
import sys
import time

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="Unix SIGINT test")
def test_stdio_ctrl_c_exits_without_additional_input(ghidra_env, tmp_path):
    """Clean shutdown must not wait for another line on an open MCP stdin."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "pyghidra_mcp", "--project-path", str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=ghidra_env,
    )
    output = bytearray()
    try:
        deadline = time.monotonic() + 90
        while b"Server intialized" not in output and time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stderr], [], [], 0.5)
            if ready:
                chunk = os.read(proc.stderr.fileno(), 8192)
                if not chunk:
                    break
                output.extend(chunk)
            if proc.poll() is not None:
                break

        assert b"Server intialized" in output, output.decode(errors="replace")

        # The startup log precedes entering MCP's stdio reader.
        time.sleep(0.2)
        proc.send_signal(signal.SIGINT)
        try:
            exit_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pytest.fail("Server stayed alive after Ctrl+C until stdin received another line")

        assert exit_code == 130
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)
