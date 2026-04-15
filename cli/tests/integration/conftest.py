"""Test fixtures for integration tests."""

import platform
import subprocess
import time
from pathlib import Path

import pytest

_IS_MACOS = platform.system() == "Darwin"


@pytest.fixture(scope="session")
def func_prefix():
    """Return '_' on macOS (Mach-O prepends underscore), '' on Linux."""
    return "_" if _IS_MACOS else ""


@pytest.fixture(scope="session")
def main_func_name():
    """Return 'entry' on macOS, 'main' on Linux."""
    return "entry" if _IS_MACOS else "main"


@pytest.fixture(scope="session")
def base_address():
    """Return default base address for platform test binaries."""
    return "100000000" if _IS_MACOS else "100000"


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
