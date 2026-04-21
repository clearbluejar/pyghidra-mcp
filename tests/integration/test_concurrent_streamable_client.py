import asyncio
import json
import os
import platform
import socket
import subprocess
import time
from pathlib import Path

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    BytesReadResult,
    CallGraphResult,
    CodeSearchResults,
    CommentResponse,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    ImportInfos,
    ProgramInfos,
    RenameResponse,
    StringSearchResults,
    SymbolSearchResults,
)

_IS_MACOS = platform.system() == "Darwin"
_FUNC_PREFIX = "_" if _IS_MACOS else ""
_MAIN_FUNC_NAME = "entry" if _IS_MACOS else "main"
_BASE_ADDRESS = "100000000" if _IS_MACOS else "100000"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def wait_for_server(base_url: str, timeout=120):
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


async def wait_for_collections(base_url: str, test_binary, timeout: int = 120) -> None:
    """
    Repeatedly call `list_project_binaries` until all programs have both
    collections populated, or until *timeout* seconds elapse.
    """
    deadline = time.time() + timeout

    async with streamable_http_client(f"{base_url}/mcp") as (read, write, _):
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
                    pi.code_indexed is False or pi.strings_indexed is False
                    for pi in program_infos.programs
                )

                if not has_missing and has_test_binary:  # All collections are present - success!
                    return

                if time.time() > deadline:  # pragma: no cover
                    raise RuntimeError(f"Collections still missing after {timeout}s: ")

                await asyncio.sleep(1)


@pytest.fixture(scope="module")
def streamable_project_args(tmp_path_factory):
    project_path = tmp_path_factory.mktemp("concurrent-streamable-project")
    return ["--project-path", str(project_path), "--project-name", "concurrent_streamable_project"]


@pytest.fixture(scope="module")
def streamable_base_url():
    return f"http://127.0.0.1:{_find_free_port()}"


@pytest.fixture(scope="module")
def streamable_server(test_binary, ghidra_env, streamable_project_args, streamable_base_url):
    """Fixture to start the pyghidra-mcp server in a separate process."""
    port = int(streamable_base_url.rsplit(":", 1)[1])
    proc = subprocess.Popen(
        [
            "python",
            "-m",
            "pyghidra_mcp",
            *streamable_project_args,
            "--wait-for-analysis",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            test_binary,
        ],
        env=ghidra_env,
    )

    try:
        asyncio.run(wait_for_server(streamable_base_url))
    except Exception:
        proc.terminate()
        proc.wait()
        raise

    time.sleep(3)

    try:
        asyncio.run(wait_for_collections(streamable_base_url, test_binary))
    except Exception:
        proc.terminate()
        proc.wait()
        raise

    time.sleep(2)

    yield test_binary, streamable_base_url
    proc.terminate()
    proc.wait()


async def invoke_tool_concurrently(base_url: str, server_binary_path):
    async with streamable_http_client(f"{base_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(Path(server_binary_path))

            name_one = f"{_FUNC_PREFIX}function_one"
            responses = [
                await session.call_tool(
                    "decompile_function",
                    {"binary_name": binary_name, "name_or_address": _MAIN_FUNC_NAME},
                ),
                await session.call_tool(
                    "search_symbols_by_name", {"binary_name": binary_name, "query": "function"}
                ),
                await session.call_tool("list_project_binaries", {}),
                await session.call_tool(
                    "list_project_binary_metadata", {"binary_name": binary_name}
                ),
                await session.call_tool("list_exports", {"binary_name": binary_name}),
                await session.call_tool("list_imports", {"binary_name": binary_name}),
                await session.call_tool(
                    "list_xrefs",
                    {"binary_name": binary_name, "name_or_address": name_one},
                ),
                await session.call_tool(
                    "search_symbols_by_name", {"binary_name": binary_name, "query": "function"}
                ),
                await session.call_tool(
                    "search_code", {"binary_name": binary_name, "query": "Function One", "limit": 1}
                ),
                await session.call_tool(
                    "search_strings", {"binary_name": binary_name, "query": "hello", "limit": 1}
                ),
                await session.call_tool(
                    "read_bytes",
                    {"binary_name": binary_name, "address": _BASE_ADDRESS, "size": 4},
                ),
                await session.call_tool(
                    "gen_callgraph",
                    {"binary_name": binary_name, "function_name": _MAIN_FUNC_NAME},
                ),
            ]
            return responses


async def invoke_mutation_tools(base_url: str, server_binary_path):
    async with streamable_http_client(f"{base_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(Path(server_binary_path))

            old_name = f"{_FUNC_PREFIX}function_two"
            new_name = f"{old_name}_renamed"

            rename_response = await session.call_tool(
                "rename_function",
                {
                    "binary_name": binary_name,
                    "name_or_address": old_name,
                    "new_name": new_name,
                },
            )
            comment_response = await session.call_tool(
                "set_comment",
                {
                    "binary_name": binary_name,
                    "target": new_name,
                    "comment": "Renamed during concurrent streamable integration test.",
                    "comment_type": "decompiler",
                },
            )
            listing_comment_response = await session.call_tool(
                "set_comment",
                {
                    "binary_name": binary_name,
                    "target": new_name,
                    "comment": "Listing comment via symbol resolution.",
                    "comment_type": "plate",
                },
            )
            symbol_response = await session.call_tool(
                "search_symbols_by_name",
                {"binary_name": binary_name, "query": new_name},
            )
            decompile_response = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": new_name},
            )

            return (
                rename_response,
                comment_response,
                listing_comment_response,
                symbol_response,
                decompile_response,
            )


@pytest.mark.asyncio
async def test_concurrent_streamable_client_invocations(streamable_server):
    """
    Tests concurrent client connections and tool invocations to the pyghidra-mcp server
    using streamable-http transport.
    """
    streamable_binary, streamable_base_url = streamable_server
    num_clients = 2
    name_one = f"{_FUNC_PREFIX}function_one"
    name_two = f"{_FUNC_PREFIX}function_two"
    tasks = [
        invoke_tool_concurrently(streamable_base_url, streamable_binary) for _ in range(num_clients)
    ]
    results = await asyncio.gather(*tasks)

    assert len(results) == num_clients

    for client_responses in results:
        assert len(client_responses) == 12

        # Decompiled function
        decompiled_func_result = json.loads(client_responses[0].content[0].text)
        decompiled_function = DecompiledFunction(**decompiled_func_result)
        assert _MAIN_FUNC_NAME in decompiled_function.name
        assert _MAIN_FUNC_NAME in decompiled_function.code

        # Symbol search results (formerly function search results)
        search_results_result = json.loads(client_responses[1].content[0].text)
        search_results = SymbolSearchResults(**search_results_result)
        assert len(search_results.symbols) >= 2
        assert any(name_one in s.name for s in search_results.symbols)
        assert any(name_two in s.name for s in search_results.symbols)

        # List project binaries
        program_infos_result = json.loads(client_responses[2].content[0].text)
        program_infos = ProgramInfos(**program_infos_result)
        assert len(program_infos.programs) >= 1
        assert any(
            os.path.basename(streamable_binary) in program.name
            for program in program_infos.programs
        )

        # List project binary metadata
        metadata = json.loads(client_responses[3].content[0].text)
        assert isinstance(metadata, dict)
        assert metadata.get("Executable Location") is not None
        assert metadata.get("Compiler") is not None
        assert metadata.get("Processor") is not None
        assert metadata.get("Endian") is not None
        assert metadata.get("Address Size") is not None
        assert os.path.basename(streamable_binary) in metadata.get("Program Name")

        # List exports
        export_infos_result = json.loads(client_responses[4].content[0].text)
        export_infos = ExportInfos(**export_infos_result)
        assert len(export_infos.exports) > 0
        assert any([name_one in export.name for export in export_infos.exports])

        # List imports
        import_infos_result = json.loads(client_responses[5].content[0].text)
        import_infos = ImportInfos(**import_infos_result)
        assert len(import_infos.imports) > 0
        assert any(["printf" in imp.name for imp in import_infos.imports])

        # List cross-references
        cross_references_result = json.loads(client_responses[6].content[0].text)
        cross_reference_infos = CrossReferenceInfos(**cross_references_result)
        assert len(cross_reference_infos.cross_references) > 0
        assert any(
            ref.function_name == _MAIN_FUNC_NAME for ref in cross_reference_infos.cross_references
        )

        # Search symbols results
        search_symbols_result = json.loads(client_responses[7].content[0].text)
        search_symbols = SymbolSearchResults(**search_symbols_result)
        assert len(search_symbols.symbols) >= 2
        assert any(name_one in s.name for s in search_symbols.symbols)
        assert any(name_two in s.name for s in search_symbols.symbols)

        # Search code results
        search_code_result = json.loads(client_responses[8].content[0].text)
        code_search_results = CodeSearchResults(**search_code_result)
        assert len(code_search_results.results) > 0
        assert name_one in code_search_results.results[0].function_name
        # Verify new fields
        assert code_search_results.query == "Function One"
        assert code_search_results.search_mode.value == "semantic"  # Default mode
        assert code_search_results.returned_count > 0
        assert code_search_results.literal_total >= 0
        assert code_search_results.semantic_total > 0
        assert code_search_results.total_functions > 0

        # Search strings
        search_string_result = json.loads(client_responses[9].content[0].text)
        string_search_results = StringSearchResults(**search_string_result)
        assert len(string_search_results.strings) > 0
        assert any("World" in s.value for s in string_search_results.strings)

        # Read bytes
        read_bytes_result = json.loads(client_responses[10].content[0].text)
        bytes_result = BytesReadResult(**read_bytes_result)
        assert bytes_result.size == 4
        if _IS_MACOS:
            assert bytes_result.data.lower() == "cffaedfe"  # Mach-O 64-bit magic (little-endian)
            assert bytes_result.address == "100000000"
        else:
            assert bytes_result.data == "7f454c46"  # ELF magic
            assert bytes_result.address == "00100000"

        # Call graph
        call_graph_result = json.loads(client_responses[11].content[0].text)
        call_graph = CallGraphResult(**call_graph_result)
        assert len(call_graph.graph) > 0
        assert _MAIN_FUNC_NAME in call_graph.function_name
        # Graph should be non-empty; entry node name may vary by platform/toolchain
        assert len(call_graph.graph.strip()) > 0

    (
        rename_response,
        comment_response,
        listing_comment_response,
        symbol_response,
        decompile_response,
    ) = await invoke_mutation_tools(streamable_base_url, streamable_binary)

    renamed_name = f"{_FUNC_PREFIX}function_two_renamed"

    rename_result = json.loads(rename_response.content[0].text)
    rename = RenameResponse(**rename_result)
    assert rename.old_name == f"{_FUNC_PREFIX}function_two"
    assert rename.new_name == renamed_name

    comment_result = json.loads(comment_response.content[0].text)
    comment = CommentResponse(**comment_result)
    assert comment.comment_type == "decompiler"
    assert comment.comment == "Renamed during concurrent streamable integration test."

    listing_comment_result = json.loads(listing_comment_response.content[0].text)
    listing_comment = CommentResponse(**listing_comment_result)
    assert listing_comment.comment_type == "plate"
    assert listing_comment.comment == "Listing comment via symbol resolution."

    symbol_result = json.loads(symbol_response.content[0].text)
    symbol_search = SymbolSearchResults(**symbol_result)
    assert any(renamed_name in symbol.name for symbol in symbol_search.symbols)
    assert all(hasattr(symbol, "is_thunk") for symbol in symbol_search.symbols)

    decompile_result = json.loads(decompile_response.content[0].text)
    decompiled = DecompiledFunction(**decompile_result)
    assert renamed_name in decompiled.name
    assert renamed_name in decompiled.code
