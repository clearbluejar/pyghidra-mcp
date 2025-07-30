import json
import os
import subprocess
import time
import tempfile

import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from pyghidra_mcp.models import DecompiledFunction

base_url = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8000")


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
    # Create a temporary file
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

    # Compile to binary
    bin_file = c_file.replace(".c", "")
    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    # Clean up
    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def streamable_server(test_binary):
    # Start the streamable-http server
    proc = subprocess.Popen(
        ["python", "-m", "pyghidra_mcp", "--transport",
            "streamable-http", test_binary],
        env={**os.environ, "GHIDRA_INSTALL_DIR": "/ghidra"},
    )
    # Wait briefly to ensure the server starts
    time.sleep(2)
    yield
    time.sleep(2)
    # Teardown: terminate the server
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_streamable_client_smoke(streamable_server):
    async with streamablehttp_client(f"{base_url}/mcp") as (
        read_stream,
        write_stream,
        _,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            # Decompile a function
            results = await session.call_tool(
                "decompile_function",
                {"name": "main"},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, dict)
            assert len(content.keys()) == len(
                DecompiledFunction.model_fields.keys())
            assert "main(void)" in content["code"]
            print(json.dumps(content, indent=2))
