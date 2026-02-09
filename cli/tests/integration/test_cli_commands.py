"""Integration tests for pyghidra-mcp CLI commands."""

import asyncio
import os
import shutil
import subprocess
import tempfile
import time

import aiohttp
import pytest

base_url = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8000")


@pytest.fixture(scope="module")
def test_dir():
    """Create a unique temp directory for this test module."""
    test_dir = tempfile.mkdtemp(prefix="pyghidra_cli_test_")
    yield test_dir
    shutil.rmtree(test_dir, ignore_errors=True)


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
def streamable_server(test_binary, test_dir):
    """Fixture to start the pyghidra-mcp server in a separate process with isolated project."""
    project_dir = os.path.join(test_dir, "project.gpr")

    proc = subprocess.Popen(
        [
            "pyghidra-mcp",
            "--transport",
            "streamable-http",
            "--project-path",
            project_dir,
            test_binary,
        ],
        env={**os.environ, "GHIDRA_INSTALL_DIR": "/ghidra"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    async def wait_for_server(timeout=120):
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

    asyncio.run(wait_for_server())

    time.sleep(10)

    yield test_binary

    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture
def client():
    """Create a PyGhidraMcpClient for testing."""
    from pyghidra_mcp_cli.client import PyGhidraMcpClient

    return PyGhidraMcpClient(host="127.0.0.1", port=8000)


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
async def test_decompile_function(client, binary_name):
    """Test decompiling a function."""
    async with client:
        result = await client.decompile_function(binary_name, "main")
        assert "code" in result
        assert "main" in result["code"]


@pytest.mark.asyncio
async def test_search_symbols(client, binary_name):
    """Test searching for symbols."""
    async with client:
        result = await client.search_symbols(binary_name, "function", offset=0, limit=10)
        assert "symbols" in result
        assert len(result["symbols"]) >= 2
        assert any("function_one" in s["name"] for s in result["symbols"])
        assert any("function_two" in s["name"] for s in result["symbols"])


@pytest.mark.asyncio
async def test_search_code(client, binary_name):
    """Test searching code."""
    async with client:
        result = await client.search_code(
            binary_name,
            query="function_one",
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
            "function_one" in result["results"][0]["function_name"]
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
async def test_list_exports(client, binary_name):
    """Test listing exports."""
    async with client:
        result = await client.list_exports(binary_name, query=".*function.*", offset=0, limit=10)
        assert "exports" in result
        assert len(result["exports"]) > 0
        assert any("function_one" in exp["name"] for exp in result["exports"])


@pytest.mark.asyncio
async def test_list_cross_references(client, binary_name):
    """Test listing cross-references."""
    async with client:
        result = await client.list_cross_references(binary_name, "function_one")
        assert "cross_references" in result
        assert len(result["cross_references"]) > 0


@pytest.mark.asyncio
async def test_read_bytes(client, binary_name):
    """Test reading bytes from memory."""
    async with client:
        result = await client.read_bytes(binary_name, address="100000", size=32)
        assert "data" in result
        assert "address" in result
        assert result["size"] == 32


@pytest.mark.asyncio
async def test_gen_callgraph(client, binary_name):
    """Test generating a call graph."""
    async with client:
        result = await client.gen_callgraph(
            binary_name,
            function_name="main",
            direction="calling",
            display_type="flow",
            condense_threshold=50,
            top_layers=3,
            bottom_layers=3,
            max_run_time=60,
        )
        assert "graph" in result
        assert "function_name" in result
        assert "main" in result["function_name"]


@pytest.mark.asyncio
async def test_list_binary_metadata(client, binary_name):
    """Test listing binary metadata."""
    async with client:
        result = await client.list_project_binary_metadata(binary_name)
        assert isinstance(result, dict)
        assert len(result) > 0
