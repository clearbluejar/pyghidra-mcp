import asyncio
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from pyghidra_mcp.models import DecompiledFunction, ExportInfos, FunctionSearchResults, ProgramInfos
from pyghidra_mcp.context import PyGhidraContext

base_url = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8000")


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
def streamable_server(test_binary):
    """Fixture to start the pyghidra-mcp server in a separate process."""
    proc = subprocess.Popen(
        ["python", "-m", "pyghidra_mcp", "--transport",
            "streamable-http", test_binary],
        env={**os.environ, "GHIDRA_INSTALL_DIR": "/ghidra"},
    )

    async def wait_for_server(timeout=120):
        async with aiohttp.ClientSession() as session:
            for _ in range(timeout):  # Poll for 20 seconds
                try:
                    async with session.get(f"{base_url}/mcp") as response:
                        if response.status == 406:
                            return
                except aiohttp.ClientConnectorError:
                    pass
                await asyncio.sleep(1)
            raise RuntimeError("Server did not start in time")

    asyncio.run(wait_for_server())

    time.sleep(2)

    yield test_binary
    proc.terminate()
    proc.wait()


async def invoke_tool_concurrently(server_binary_path):
    async with streamablehttp_client(f"{base_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(
                Path(server_binary_path))

            tasks = [
                session.call_tool(
                    "decompile_function", {
                        "binary_name": binary_name, "name": "main"}
                ),
                session.call_tool(
                    "search_functions_by_name", {
                        "binary_name": binary_name, "query": "function"}
                ),
                session.call_tool("list_project_binaries", {}),
                session.call_tool("list_project_program_info", {}),
                session.call_tool(
                    "list_exports", {"binary_name": binary_name}),
            ]

            responses = await asyncio.gather(*tasks)
            return responses


@pytest.mark.asyncio
async def test_concurrent_streamable_client_invocations(streamable_server):
    """
    Tests concurrent client connections and tool invocations to the pyghidra-mcp server
    using streamable-http transport.
    """
    num_clients = 5
    tasks = [invoke_tool_concurrently(streamable_server)
             for _ in range(num_clients)]
    results = await asyncio.gather(*tasks)

    assert len(results) == num_clients

    for client_responses in results:
        assert len(client_responses) == 5

        # Decompiled function
        decompiled_func_result = json.loads(
            client_responses[0].content[0].text)
        decompiled_function = DecompiledFunction(**decompiled_func_result)
        assert "main" in decompiled_function.name
        assert "main" in decompiled_function.code

        # Function search results
        search_results_result = json.loads(client_responses[1].content[0].text)
        search_results = FunctionSearchResults(**search_results_result)
        assert len(search_results.functions) >= 2
        assert any(
            "function_one" in func.name for func in search_results.functions)
        assert any(
            "function_two" in func.name for func in search_results.functions)

        # List project binaries
        binaries_result = client_responses[2].content
        assert isinstance(binaries_result, list)
        assert any([os.path.basename(streamable_server)
                   in name.text for name in binaries_result])

        # List project program info
        program_infos_result = json.loads(client_responses[3].content[0].text)
        program_infos = ProgramInfos(**program_infos_result)
        assert len(program_infos.programs) >= 1
        assert os.path.basename(
            streamable_server) in program_infos.programs[0].name

        # List exports
        export_infos_result = json.loads(client_responses[4].content[0].text)
        export_infos = ExportInfos(**export_infos_result)
        assert len(export_infos.exports) > 0
        assert any(
            ["function_one" in export.name for export in export_infos.exports])
