"""Test fixtures for integration tests."""

import subprocess
import time
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def server_process():
    """Start pyghidra-mcp server for integration tests."""
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

int main() {
    printf("Hello, World!");
    return 0;
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")
    subprocess.run(f"gcc -o {bin_file} {c_file}", shell=True, check=True)

    proc = subprocess.Popen(
        ["pyghidra-mcp", "--transport", "stdio", bin_file],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(2)

    yield proc

    proc.terminate()
    proc.wait(timeout=5)
    Path(c_file).unlink(missing_ok=True)
    Path(bin_file).unlink(missing_ok=True)
