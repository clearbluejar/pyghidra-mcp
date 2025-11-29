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
def test_shared_object():
    """
    Create a simple shared object for testing.
    """
    # 1. Write the C source to a temp file
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

// No main() needed for a shared library
"""
        )
        c_file = f.name

    # 2. Compile as a shared object
    so_file = c_file.replace(".c", ".so")
    cmd = f"gcc -fPIC -shared -o {so_file} {c_file}"
    ret = os.system(cmd)
    if ret != 0:
        raise RuntimeError(f"Compilation failed: {cmd}")

    # 3. Yield path to .so for tests
    yield so_file

    # 4. Clean up
    os.unlink(c_file)
    os.unlink(so_file)


@pytest.fixture(scope="module")
def server_params_no_input():
    """Get server parameters with no test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis"],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis", test_binary],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_no_thread(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--no-threaded", test_binary],  # no-thread for chromadb_testing
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_shared_object(test_shared_object):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis", test_shared_object],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )
