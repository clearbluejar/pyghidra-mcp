import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    BinaryMetadata,
    BytesReadResult,
    CallGraphResult,
    CodeSearchResults,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    ImportInfos,
    ProgramInfos,
    StringSearchResults,
    SymbolSearchResults,
)

@pytest.fixture(scope="module")
def streamable_server(ghidra_install_dir, base_url):
    """Fixture to start the pyghidra-mcp server in a separate process."""
    # Extract port from base_url
    port = base_url.split(":")[-1]

    # Start server (binary will be imported via import_binary tool)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "pyghidra_mcp",
            "--wait-for-analysis",
            "--transport",
            "streamable-http",
            "--port",
            port,
            # Don't pass test_binary - will use import_binary tool instead
        ],
        env={**os.environ, "GHIDRA_INSTALL_DIR": ghidra_install_dir},
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

    time.sleep(3)

    async def wait_for_collections(test_binary, timeout: int = 120) -> None:
        """
        Repeatedly call `list_project_binaries` until all programs have both
        collections populated, or until *timeout* seconds elapse.
        """
        deadline = time.time() + timeout

        # Open a single persistent connection - re-using it keeps the overhead low.
        async with streamablehttp_client(f"{base_url}/mcp") as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                while True:
                    tool_resp = await session.call_tool("list_project_binaries", {})
                    program_infos_result = json.loads(tool_resp.content[0].text)
                    program_infos = ProgramInfos(**program_infos_result)

                    has_test_binary = any(
                        PyGhidraContext._gen_unique_bin_name(Path(test_binary)) in pi.name
                        for pi in program_infos.programs
                    )

                    has_missing = any(
                        pi.code_collection is False or pi.strings_collection is False
                        for pi in program_infos.programs
                    )

                    if (
                        not has_missing and has_test_binary
                    ):  # All collections are present - success!
                        return

                    if time.time() > deadline:  # pragma: no cover
                        raise RuntimeError(f"Collections still missing after {timeout}s: ")

                    await asyncio.sleep(1)  # Wait a bit before the next call

    yield base_url
    proc.terminate()
    proc.wait()


async def invoke_tool_concurrently(binary_name, base_url, image_base):
    async with streamable_http_client(f"{base_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tasks = [
                session.call_tool(
                    "decompile_function", {"binary_name": binary_name, "name_or_address": "main"}
                ),
                session.call_tool(
                    "search_symbols_by_name", {"binary_name": binary_name, "query": "function"}
                ),
                session.call_tool("list_project_binaries", {}),
                session.call_tool("list_project_binary_metadata", {"binary_name": binary_name}),
                session.call_tool("list_exports", {"binary_name": binary_name}),
                session.call_tool("list_imports", {"binary_name": binary_name}),
                session.call_tool(
                    "list_cross_references",
                    {"binary_name": binary_name, "name_or_address": "function_one"},
                ),
                session.call_tool(
                    "search_symbols_by_name", {"binary_name": binary_name, "query": "function"}
                ),
                session.call_tool(
                    "search_code", {"binary_name": binary_name, "query": "Function One", "limit": 1}
                ),
                session.call_tool(
                    "search_strings", {"binary_name": binary_name, "query": "hello", "limit": 1}
                ),
                session.call_tool(
                    "read_bytes", {"binary_name": binary_name, "address": image_base, "size": 4}
                ),
                session.call_tool(
                    "gen_callgraph", {"binary_name": binary_name, "function_name": "main"}
                ),
            ]

            responses = await asyncio.gather(*tasks)
            return responses


@pytest.mark.asyncio
async def test_concurrent_streamable_client_invocations(streamable_server, test_binary):
    """
    Tests concurrent client connections and tool invocations to the pyghidra-mcp server
    using streamable-http transport.
    """
    base_url = streamable_server
    binary_name = PyGhidraContext._gen_unique_bin_name(Path(test_binary))

    # Import binary in one session, then run concurrent clients
    # Keep the import session alive to avoid lifecycle issues
    async with streamable_http_client(f"{base_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Import binary
            import_resp = await session.call_tool("import_binary", {"binary_path": test_binary})

            # Wait for analysis AND collections to complete
            for _ in range(120):  # Wait up to 2 minutes
                await asyncio.sleep(1)
                prog_resp = await session.call_tool("list_project_binaries", {})
                prog_result = json.loads(prog_resp.content[0].text)
                prog_infos = ProgramInfos(**prog_result)

                # Check if analysis complete AND collections ready
                if any(
                    binary_name in pi.name
                    and pi.analysis_complete
                    and pi.code_collection
                    and pi.strings_collection
                    for pi in prog_infos.programs
                ):
                    break
            else:
                raise RuntimeError(f"Binary {binary_name} not ready (analysis + collections) after timeout")

            # Get image base address once (for read_bytes tool)
            image_base_resp = await session.call_tool(
                "get_image_base", {"binary_name": binary_name}
            )
            resp_text = image_base_resp.content[0].text
            # Check if response is valid
            if not resp_text or resp_text.startswith("Error") or len(resp_text) < 10:
                pytest.fail(f"get_image_base returned invalid response: '{resp_text}'")
            try:
                image_base_result = json.loads(resp_text)
                image_base = image_base_result["image_base"]
            except json.JSONDecodeError as e:
                pytest.fail(f"get_image_base returned non-JSON response: '{resp_text}'. Error: {e}")

            # Now run concurrent clients (while keeping the import session alive)
            num_clients = 6
            tasks = [invoke_tool_concurrently(binary_name, base_url, image_base) for _ in range(num_clients)]
            results = await asyncio.gather(*tasks)

    assert len(results) == num_clients

    for client_responses in results:
        assert len(client_responses) == 12

        # Decompiled function
        decompiled_func_result = json.loads(client_responses[0].content[0].text)
        decompiled_function = DecompiledFunction(**decompiled_func_result)
        assert "main" in decompiled_function.name
        assert "main" in decompiled_function.code

        # Symbol search results (formerly function search results)
        search_results_result = json.loads(client_responses[1].content[0].text)
        search_results = SymbolSearchResults(**search_results_result)
        assert len(search_results.symbols) >= 2
        assert any("function_one" in s.name for s in search_results.symbols)
        assert any("function_two" in s.name for s in search_results.symbols)

        # List project binaries
        program_infos_result = json.loads(client_responses[2].content[0].text)
        program_infos = ProgramInfos(**program_infos_result)
        assert len(program_infos.programs) >= 1
        # Check that our binary is in the list
        binary_name = PyGhidraContext._gen_unique_bin_name(Path(test_binary))
        assert any(binary_name in pi.name for pi in program_infos.programs)

        # List project binary metadata
        bin_metadata_result = json.loads(client_responses[3].content[0].text)
        metadata = BinaryMetadata(**bin_metadata_result)
        assert isinstance(metadata, BinaryMetadata)
        assert metadata.executable_location is not None
        assert metadata.compiler is not None
        assert metadata.processor is not None
        assert metadata.endian is not None
        assert metadata.address_size is not None
        assert binary_name in metadata.program_name

        # List exports - validate structure exists, don't assume specific exports
        export_infos_result = json.loads(client_responses[4].content[0].text)
        export_infos = ExportInfos(**export_infos_result)
        # Just verify the structure is valid - exports list may be empty for some binaries
        assert isinstance(export_infos.exports, list)

        # List imports - verify imports exist, don't assume specific functions
        import_infos_result = json.loads(client_responses[5].content[0].text)
        import_infos = ImportInfos(**import_infos_result)
        assert len(import_infos.imports) > 0
        # Just verify we have imports, not specific function names

        # List cross-references
        cross_references_result = json.loads(client_responses[6].content[0].text)
        cross_reference_infos = CrossReferenceInfos(**cross_references_result)
        assert len(cross_reference_infos.cross_references) > 0
        assert any([ref.function_name == "main" for ref in cross_reference_infos.cross_references])

        # Search symbols results
        search_symbols_result = json.loads(client_responses[7].content[0].text)
        search_symbols = SymbolSearchResults(**search_symbols_result)
        assert len(search_symbols.symbols) >= 2
        assert any("function_one" in s.name for s in search_symbols.symbols)
        assert any("function_two" in s.name for s in search_symbols.symbols)

        # Search code results
        search_code_result = json.loads(client_responses[8].content[0].text)
        code_search_results = CodeSearchResults(**search_code_result)
        assert len(code_search_results.results) > 0
        assert "function_one" in code_search_results.results[0].function_name

        # Search strings
        search_string_result = json.loads(client_responses[9].content[0].text)
        string_search_results = StringSearchResults(**search_string_result)
        assert len(string_search_results.strings) > 0
        assert "World" in string_search_results.strings[0].value

        # Read bytes - verify structure exists, don't assume specific values
        read_bytes_result = json.loads(client_responses[10].content[0].text)
        bytes_result = BytesReadResult(**read_bytes_result)
        assert bytes_result.size == 4
        assert bytes_result.data is not None
        assert bytes_result.address is not None

        # Call graph
        call_graph_result = json.loads(client_responses[11].content[0].text)
        call_graph = CallGraphResult(**call_graph_result)
        assert len(call_graph.graph) > 0
        assert "main" in call_graph.function_name

        # Delete binary
        # This test is omitted due to complexity in concurrent scenarios
