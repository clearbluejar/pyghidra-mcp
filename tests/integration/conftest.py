import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path

import pytest
from mcp import StdioServerParameters


@pytest.fixture(scope="session")
def ghidra_env():
    """Derive a valid environment for locating Ghidra or skip if unavailable.

    Policy:
    - If GHIDRA_INSTALL_DIR is set and is a valid directory, use it.
    - Else if /ghidra exists, set GHIDRA_INSTALL_DIR to /ghidra.
    - Else skip tests that require a Ghidra installation.
    """
    env = os.environ.copy()
    ghidra_dir = env.get("GHIDRA_INSTALL_DIR")
    if ghidra_dir and os.path.isdir(ghidra_dir):
        return env
    if os.path.isdir("/ghidra"):
        env["GHIDRA_INSTALL_DIR"] = "/ghidra"
        return env
    pytest.skip(
        "GHIDRA installation not found. Set GHIDRA_INSTALL_DIR to a valid Ghidra install, "
        "or ensure /ghidra exists."
    )


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing.

    On macOS produce a Mach-O; on Linux, produce an ELF. The main symbol name and base
    address differ by platform and are handled downstream by tests.
    """
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
#include <stdlib.h>

void shared_func_one() {
    char *buf = malloc(10);
    printf("Function One: %p", (void *)buf);
    free(buf);
}

void shared_func_two() {
    printf("Function Two");
}

// No main() needed for a shared library
"""
        )
        c_file = f.name

    # 2. Compile as a shared object (Mach-O on macOS, ELF shared object on Linux)
    is_macos = platform.system() == "Darwin"
    shared_ext = ".dylib" if is_macos else ".so"
    shared_file = c_file.replace(".c", shared_ext)
    compile_cmd = (
        ["gcc", "-dynamiclib", "-o", shared_file, c_file]
        if is_macos
        else ["gcc", "-fPIC", "-shared", "-o", shared_file, c_file]
    )
    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        cmd_text = " ".join(compile_cmd)
        raise RuntimeError(f"Compilation failed: {cmd_text}\nSTDERR:\n{result.stderr}")

    # 3. Yield path to shared library for tests
    yield shared_file

    # 4. Clean up
    os.unlink(c_file)
    os.unlink(shared_file)


def _isolated_project_args(project_root: Path, fixture_name: str) -> list[str]:
    project_path = project_root / fixture_name
    project_name = f"{fixture_name}_project"
    return ["--project-path", str(project_path), "--project-name", project_name]


@pytest.fixture(scope="module")
def isolated_project_root(tmp_path_factory, request):
    module_name = Path(str(request.node.path)).stem
    return tmp_path_factory.mktemp(f"{module_name}-projects")


@pytest.fixture(scope="module")
def server_params_no_input(ghidra_env, isolated_project_root):
    """Get server parameters with no test binary."""
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            *_isolated_project_args(isolated_project_root, "server_params_no_input"),
            "--wait-for-analysis",
        ],
        env=ghidra_env,
    )


@pytest.fixture(scope="module")
def server_params(test_binary, ghidra_env, isolated_project_root):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            *_isolated_project_args(isolated_project_root, "server_params"),
            "--wait-for-analysis",
            test_binary,
        ],
        env=ghidra_env,
    )


@pytest.fixture(scope="module")
def server_params_no_thread(test_binary, ghidra_env, isolated_project_root):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            *_isolated_project_args(isolated_project_root, "server_params_no_thread"),
            "--no-threaded",
            test_binary,
        ],
        env=ghidra_env,
    )


@pytest.fixture(scope="module")
def server_params_shared_object(test_shared_object, ghidra_env, isolated_project_root):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            *_isolated_project_args(isolated_project_root, "server_params_shared_object"),
            "--wait-for-analysis",
            test_shared_object,
        ],
        env=ghidra_env,
    )


@pytest.fixture()
def find_binary_in_list_response():
    """Return a helper that finds a binary by generated name in a list_project_binaries response."""

    def _finder(response, binary_name):
        text_content = response.content[0].text
        program_infos = json.loads(text_content)["programs"]

        for program in program_infos:
            if binary_name in program["name"]:
                return program

        return None

    return _finder


@pytest.fixture(scope="module")
def server_params_existing_notepad_project(ghidra_env):
    """Server with existing notepad project from other_projects/"""
    project_path = Path(__file__).parent.parent.parent / "other_projects" / "notepad.gpr"
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", "--project-path", str(project_path), "--wait-for-analysis"],
        env=ghidra_env,
    )


@pytest.fixture(scope="module")
def custom_project_directory():
    """Create temporary directory for custom named projects"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture(scope="module")
def server_params_custom_project_name(custom_project_directory, ghidra_env):
    """Server with custom project path and name"""
    custom_project = custom_project_directory / "my_analysis_project"
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", "--project-path", str(custom_project), "--wait-for-analysis"],
        env=ghidra_env,
    )


@pytest.fixture(scope="module")
def server_params_nested_project_location(custom_project_directory, ghidra_env):
    """Server with nested project location"""
    nested_project = custom_project_directory / "deeply/nested/location/test_project"
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", "--project-path", str(nested_project), "--wait-for-analysis"],
        env=ghidra_env,
    )
