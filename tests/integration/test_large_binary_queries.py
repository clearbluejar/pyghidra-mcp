import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import (
    CodeSearchResults,
    DecompiledFunction,
    ExportInfos,
    ImportInfos,
    StringSearchResults,
    SymbolSearchResults,
)
from tests.benchmark_helpers import (
    GeneratedBinarySpec,
    call_tool_model,
    call_tool_text,
    platform_function_name,
    wait_for_binary_readiness,
)


@pytest.fixture(scope="module")
def large_executable_artifact(generated_binary_factory):
    return generated_binary_factory(
        GeneratedBinarySpec(
            stem="crowded_executable",
            function_count=80,
            string_count=20,
            global_count=48,
            call_fanout=2,
        )
    )


@pytest.fixture(scope="module")
def large_shared_object_artifact(generated_shared_object_factory):
    return generated_shared_object_factory(
        GeneratedBinarySpec(
            stem="crowded_shared",
            function_count=64,
            string_count=16,
            global_count=40,
            call_fanout=2,
            exported_function_count=24,
        )
    )


@pytest.mark.asyncio
async def test_large_binary_queries_remain_discoverable_and_paginated(
    large_executable_artifact,
    stdio_server_params_factory,
):
    server_params = stdio_server_params_factory(
        large_executable_artifact.binary_path,
        fixture_name="large_binary_queries",
        threaded=False,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready_program = await wait_for_binary_readiness(
                session,
                file_path=large_executable_artifact.binary_path,
                require_code_collection=True,
                require_strings_collection=True,
                timeout_seconds=180,
            )
            binary_name = ready_program.name
            spec = large_executable_artifact.spec

            first_twelve_functions_text = await call_tool_text(
                session,
                "search_functions_by_name",
                {"binary_name": binary_name, "query": "noise_function_", "limit": 12},
            )
            first_twelve_functions = SymbolSearchResults.model_validate_json(
                first_twelve_functions_text
            )
            page_one_functions = await call_tool_model(
                session,
                "search_functions_by_name",
                {"binary_name": binary_name, "query": "noise_function_", "offset": 0, "limit": 5},
                SymbolSearchResults,
            )
            page_two_function_text = await call_tool_text(
                session,
                "search_functions_by_name",
                {"binary_name": binary_name, "query": "noise_function_", "offset": 5, "limit": 5},
            )
            page_two_functions = SymbolSearchResults.model_validate_json(page_two_function_text)
            sentinel_function_results = await call_tool_model(
                session,
                "search_functions_by_name",
                {"binary_name": binary_name, "query": spec.sentinel_function_stem, "limit": 5},
                SymbolSearchResults,
            )

            assert [symbol.name for symbol in page_one_functions.symbols] == [
                symbol.name for symbol in first_twelve_functions.symbols[:5]
            ]
            assert [symbol.name for symbol in page_two_functions.symbols] == [
                symbol.name for symbol in first_twelve_functions.symbols[5:10]
            ]
            assert len(page_two_functions.symbols) == 5
            assert len(page_two_function_text.encode()) < len(first_twelve_functions_text.encode())
            assert any(
                spec.sentinel_function_stem in symbol.name
                for symbol in sentinel_function_results.symbols
            )

            small_symbol_text = await call_tool_text(
                session,
                "search_symbols_by_name",
                {
                    "binary_name": binary_name,
                    "query": spec.sentinel_symbol_stem,
                    "offset": 0,
                    "limit": 3,
                },
            )
            symbol_results = SymbolSearchResults.model_validate_json(small_symbol_text)
            assert len(symbol_results.symbols) <= 3
            assert len(small_symbol_text.encode()) < 5000
            assert any(
                spec.sentinel_symbol_stem in symbol.name for symbol in symbol_results.symbols
            )

            sentinel_name = platform_function_name(spec.sentinel_function_stem)
            decompiled_function = await call_tool_model(
                session,
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": sentinel_name},
                DecompiledFunction,
            )
            semantic_text = await call_tool_text(
                session,
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": decompiled_function.code,
                    "limit": 3,
                    "include_full_code": False,
                    "preview_length": 80,
                },
            )
            semantic_results = CodeSearchResults.model_validate_json(semantic_text)
            literal_text = await call_tool_text(
                session,
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": spec.sentinel_code_literal,
                    "limit": 2,
                    "offset": 1,
                    "search_mode": "literal",
                    "include_full_code": False,
                    "preview_length": 40,
                },
            )
            literal_results = CodeSearchResults.model_validate_json(literal_text)

            assert semantic_results.returned_count <= 3
            assert len(semantic_text.encode()) < 8000
            assert any(
                spec.sentinel_function_stem in result.function_name
                for result in semantic_results.results
            )
            assert literal_results.returned_count <= 2
            assert literal_results.literal_total >= literal_results.returned_count
            assert len(literal_text.encode()) < 6000
            assert all(result.preview is not None for result in literal_results.results)
            assert all(result.code == result.preview for result in literal_results.results)
            assert all(len(result.code) <= 43 for result in literal_results.results)

            strings_text = await call_tool_text(
                session,
                "search_strings",
                {
                    "binary_name": binary_name,
                    "query": spec.sentinel_string,
                    "limit": 4,
                },
            )
            string_results = StringSearchResults.model_validate_json(strings_text)
            assert len(string_results.strings) <= 4
            assert len(strings_text.encode()) < 4000
            assert any(spec.sentinel_string in result.value for result in string_results.strings)


@pytest.mark.asyncio
async def test_large_shared_object_exports_and_imports_stay_filtered_and_paginated(
    large_shared_object_artifact,
    stdio_server_params_factory,
):
    server_params = stdio_server_params_factory(
        large_shared_object_artifact.binary_path,
        fixture_name="large_shared_queries",
        threaded=False,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready_program = await wait_for_binary_readiness(
                session,
                file_path=large_shared_object_artifact.binary_path,
                timeout_seconds=180,
            )
            binary_name = ready_program.name
            spec = large_shared_object_artifact.spec

            first_twelve_exports_text = await call_tool_text(
                session,
                "list_exports",
                {"binary_name": binary_name, "query": "noise_function_", "limit": 12},
            )
            first_twelve_exports = ExportInfos.model_validate_json(first_twelve_exports_text)
            page_one_exports = await call_tool_model(
                session,
                "list_exports",
                {"binary_name": binary_name, "query": "noise_function_", "offset": 0, "limit": 5},
                ExportInfos,
            )
            page_two_exports_text = await call_tool_text(
                session,
                "list_exports",
                {"binary_name": binary_name, "query": "noise_function_", "offset": 5, "limit": 5},
            )
            page_two_exports = ExportInfos.model_validate_json(page_two_exports_text)
            sentinel_exports = await call_tool_model(
                session,
                "list_exports",
                {"binary_name": binary_name, "query": spec.sentinel_export_stem, "limit": 3},
                ExportInfos,
            )

            assert [export.name for export in page_one_exports.exports] == [
                export.name for export in first_twelve_exports.exports[:5]
            ]
            assert [export.name for export in page_two_exports.exports] == [
                export.name for export in first_twelve_exports.exports[5:10]
            ]
            assert len(page_two_exports.exports) == 5
            assert len(page_two_exports_text.encode()) < len(first_twelve_exports_text.encode())
            assert any(
                spec.sentinel_export_stem in export.name for export in sentinel_exports.exports
            )

            broad_import_text = await call_tool_text(
                session,
                "list_imports",
                {"binary_name": binary_name, "query": "printf", "limit": 5},
            )
            import_results = ImportInfos.model_validate_json(broad_import_text)
            assert len(import_results.imports) <= 5
            assert len(broad_import_text.encode()) < 2000
            assert any(spec.import_query in item.name for item in import_results.imports)
