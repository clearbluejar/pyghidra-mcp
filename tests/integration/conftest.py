import os
import tempfile

import pytest
from mcp import StdioServerParameters


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

int main() {
    printf("Hello, World!");
    function_one();
    function_two();
    return 0;
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", test_binary],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )
import os
import tempfile

import pytest
from mcp import StdioServerParameters


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

int main() {
    printf("Hello, World!");
    function_one();
    function_two();
    return 0;
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", test_binary],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )
