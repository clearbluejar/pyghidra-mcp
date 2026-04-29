"""Integration tests for pyghidra-mcp CLI commands."""

import asyncio
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import aiohttp
import pytest


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
def test_dir():
    """Create a unique temp directory for this test module."""
    test_dir = tempfile.mkdtemp(prefix="pyghidra_cli_test_")
    yield test_dir
    shutil.rmtree(test_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def server_port():
    """Pick a free TCP port for the test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def test_binary(test_dir):
    """Create a test binary in the unique temp directory."""
    c_file = os.path.join(test_dir, "test_binary.c")
    bin_file = os.path.join(test_dir, "test_binary")

    with open(c_file, "w") as f:
        f.write("""
#include <stdio.h>

void function_one(int x) {
    if (x > 0) {
        printf("Positive: %d", x);
    } else {
        printf("Non-positive: %d", x);
    }
}

void function_two(char* str) {
    printf("%s", str);
}

int main() {
    function_one(42);
    function_two("Hello, World!");
    return 0;
}
""")

    subprocess.run(f"gcc -o {bin_file} {c_file}", shell=True, check=True)

    yield bin_file


@pytest.fixture(scope="module")
def streamable_server(test_binary, test_dir, ghidra_env, server_port):
    """Fixture to start the pyghidra-mcp server in a separate process with isolated project."""
    project_dir = os.path.join(test_dir, "project.gpr")
    base_url = f"http://127.0.0.1:{server_port}"

    proc = subprocess.Popen(
        [
            "pyghidra-mcp",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(server_port),
            "--project-path",
            project_dir,
            test_binary,
        ],
        env=ghidra_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if proc.poll() is not None:
        out, err = proc.communicate(timeout=5)
        raise RuntimeError(
            f"pyghidra-mcp exited early with code {proc.returncode}.\n"
            f"STDOUT:\n{out}\nSTDERR:\n{err}"
        )

    async def wait_for_server(timeout=240):
        async with aiohttp.ClientSession() as session:
            for _ in range(timeout):
                try:
                    async with session.get(f"{base_url}/mcp") as response:
                        if response.status == 406:
                            return
                except aiohttp.ClientConnectorError:
                    pass
                await asyncio.sleep(1)
        raise RuntimeError("Server did not start in time")

    async def wait_for_analysis(timeout=240):
        from pyghidra_mcp_cli.client import PyGhidraMcpClient

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                async with PyGhidraMcpClient(host="127.0.0.1", port=server_port) as client:
                    result = await client.list_project_binaries()
                    programs = result.get("programs", [])
                    if programs and all(
                        p.get("analysis_complete", False)
                        and p.get("code_indexed", False)
                        and p.get("strings_indexed", False)
                        for p in programs
                    ):
                        return
            except Exception:
                pass
            await asyncio.sleep(2)
        raise RuntimeError(f"Analysis not complete after {timeout}s")

    asyncio.run(wait_for_server())
    asyncio.run(wait_for_analysis())

    try:
        yield test_binary
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


@pytest.fixture
def client(server_port):
    """Create a PyGhidraMcpClient for testing."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    return PyGhidraMcpClient(host="127.0.0.1", port=server_port)


def run_cli(server_port: int, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the installed CLI against the test server."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pyghidra_mcp_cli.main",
            "--port",
            str(server_port),
            "--format",
            "json",
            *args,
        ],
        check=True,
        text=True,
        capture_output=True,
    )


async def resolve_function_symbol(client, binary_name: str, query: str) -> dict:
    """Resolve a function symbol in a cross-platform way."""
    async with client:
        result = await client.search_symbols(binary_name, query, functions_only=True, limit=25)
        for symbol in result.get("symbols", []):
            name = symbol.get("name", "")
            if name.endswith(query):
                return symbol
    raise AssertionError(f"Unable to resolve function {query!r}")


async def resolve_parameter_name(client, binary_name: str, function_name: str) -> str:
    """Resolve the current decompiler parameter name for a function."""
    async with client:
        result = await client.decompile_function(binary_name, function_name)
    header = result["code"].split("{", 1)[0]
    match = re.search(r"\((.*?)\)", header, re.DOTALL)
    if not match:
        raise AssertionError(f"Unable to parse parameter list for {function_name!r}")
    params = match.group(1).strip()
    if not params or params == "void":
        raise AssertionError(f"No parameter found for {function_name!r}")
    first_param = params.split(",", 1)[0].strip()
    return first_param.split()[-1].lstrip("*")


@pytest.fixture
def binary_name(client, streamable_server):
    """Get the binary name from the server."""

    async def _get_binary_name():
        async with client:
            result = await client.list_project_binaries()
            programs = result.get("programs", [])
            for prog in programs:
                name = prog.get("name", "")
                if "test_binary" in name or name.startswith("/"):
                    return name
            # If no test binary found, use the first available binary
            if programs:
                return programs[0].get("name", "")
            raise ValueError(
                f"No binaries found. Available: {[p.get('name', '') for p in programs]}"
            )

    return asyncio.run(_get_binary_name())


@pytest.mark.asyncio
async def test_list_binaries(client, streamable_server):
    """Test listing binaries in the project."""
    async with client:
        result = await client.list_project_binaries()
        assert "programs" in result
        assert len(result["programs"]) >= 1


@pytest.mark.asyncio
async def test_decompile_function(client, binary_name, main_func_name):
    """Test decompiling a function."""
    async with client:
        result = await client.decompile_function(binary_name, main_func_name)
        assert "code" in result
        assert main_func_name in result["code"]


@pytest.mark.asyncio
async def test_decompile_function_with_callees(client, binary_name, main_func_name):
    """Test decompile_function with include_callees flag."""
    async with client:
        result = await client.decompile_function(binary_name, main_func_name, include_callees=True)
        assert "code" in result
        assert main_func_name in result["code"]
        assert "callees" in result
        assert isinstance(result["callees"], list)


@pytest.mark.asyncio
async def test_search_symbols(client, binary_name, func_prefix):
    """Test searching for symbols."""
    async with client:
        result = await client.search_symbols(binary_name, "function", offset=0, limit=10)
        name_one = f"{func_prefix}function_one"
        name_two = f"{func_prefix}function_two"
        assert "symbols" in result
        assert len(result["symbols"]) >= 2
        assert any(name_one in s["name"] for s in result["symbols"])
        assert any(name_two in s["name"] for s in result["symbols"])


@pytest.mark.asyncio
async def test_search_code(client, binary_name, func_prefix):
    """Test searching code."""
    name_one = f"{func_prefix}function_one"
    async with client:
        result = await client.search_code(
            binary_name,
            query=name_one,
            limit=5,
            offset=0,
            search_mode="semantic",
            include_full_code=True,
            preview_length=200,
            similarity_threshold=0.0,
        )
        assert "results" in result
        assert len(result["results"]) > 0
        assert (
            name_one in result["results"][0]["function_name"]
            or result["results"][0]["function_name"]
        )


@pytest.mark.asyncio
async def test_search_strings(client, binary_name):
    """Test searching strings."""
    async with client:
        result = await client.search_strings(binary_name, "Hello", limit=10)
        assert "strings" in result
        assert len(result["strings"]) > 0
        assert any("Hello" in s["value"] for s in result["strings"])


@pytest.mark.asyncio
async def test_list_imports(client, binary_name):
    """Test listing imports."""
    async with client:
        result = await client.list_imports(binary_name, query=".*printf.*", offset=0, limit=10)
        assert "imports" in result
        assert len(result["imports"]) > 0
        assert any("printf" in imp["name"] for imp in result["imports"])


@pytest.mark.asyncio
async def test_list_exports(client, binary_name, func_prefix):
    """Test listing exports."""
    name_one = f"{func_prefix}function_one"
    async with client:
        result = await client.list_exports(binary_name, query=".*function.*", offset=0, limit=10)
        assert "exports" in result
        assert len(result["exports"]) > 0
        assert any(name_one in exp["name"] for exp in result["exports"])


@pytest.mark.asyncio
async def test_list_xrefs(client, binary_name, func_prefix):
    """Test listing cross-references."""
    name_one = f"{func_prefix}function_one"
    async with client:
        result = await client.list_xrefs(binary_name, name_one)
        assert "cross_references" in result
        assert len(result["cross_references"]) > 0


@pytest.mark.asyncio
async def test_read_bytes(client, binary_name, base_address):
    """Test reading bytes from memory."""
    async with client:
        result = await client.read_bytes(binary_name, address=base_address, size=32)
        assert "data" in result
        assert "address" in result
        assert result["size"] == 32


@pytest.mark.asyncio
async def test_gen_callgraph(client, binary_name, main_func_name):
    """Test generating a call graph."""
    async with client:
        result = await client.gen_callgraph(
            binary_name,
            function_name=main_func_name,
            direction="calling",
            display_type="flow",
            condense_threshold=50,
            top_layers=3,
            bottom_layers=3,
            max_run_time=60,
        )
        assert "graph" in result
        assert "function_name" in result
        assert main_func_name in result["function_name"]


@pytest.mark.asyncio
async def test_list_binary_metadata(client, binary_name):
    """Test listing binary metadata."""
    async with client:
        result = await client.list_project_binary_metadata(binary_name)
        assert isinstance(result, dict)
        assert len(result) > 0


@pytest.mark.asyncio
async def test_cli_set_function_prototype_command(client, binary_name, server_port):
    """Test the grouped CLI set function-prototype command."""
    function_one_name = (await resolve_function_symbol(client, binary_name, "function_one"))["name"]
    completed = run_cli(
        server_port,
        "set",
        "function-prototype",
        "--binary",
        binary_name,
        function_one_name,
        "void function_one(int count)",
    )
    assert '"new_prototype"' in completed.stdout
    assert "function_one" in completed.stdout


@pytest.mark.asyncio
async def test_cli_set_comment_command(client, binary_name, server_port):
    """Test the grouped CLI set comment command."""
    function_one = await resolve_function_symbol(client, binary_name, "function_one")
    decimal_address = str(int(function_one["address"], 16))
    completed = run_cli(
        server_port,
        "set",
        "comment",
        "--binary",
        binary_name,
        "--type",
        "plate",
        decimal_address,
        "CLI comment test",
    )
    assert '"comment_type"' in completed.stdout
    assert '"plate"' in completed.stdout


@pytest.mark.asyncio
async def test_cli_rename_variable_command(client, binary_name, server_port):
    """Test the grouped CLI rename variable command."""
    function_one_name = (await resolve_function_symbol(client, binary_name, "function_one"))["name"]
    run_cli(
        server_port,
        "set",
        "function-prototype",
        "--binary",
        binary_name,
        function_one_name,
        "void function_one(int count)",
    )
    completed = run_cli(
        server_port,
        "rename",
        "variable",
        "--binary",
        binary_name,
        function_one_name,
        "count",
        "item_count",
    )
    assert '"new_name"' in completed.stdout
    assert '"item_count"' in completed.stdout

    async with client:
        result = await client.decompile_function(binary_name, function_one_name)
        assert "item_count" in result["code"]
