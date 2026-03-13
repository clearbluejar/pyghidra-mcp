from pyghidra_mcp.models import SearchMode
from tests.benchmark_helpers import (
    FakeCodeCollection,
    FakeFunction,
    FakeMcpTool,
    FakeProgram,
    FakeSymbol,
    collect_internal_call_counts,
    get_program_tools,
    json_size,
    make_runtime_program_info,
    tool_surface_metrics,
)


def test_tool_surface_metrics_measure_description_and_schema_sizes():
    tool = FakeMcpTool(
        name="search_code",
        description="Search binary code.",
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"results": {"type": "array"}}},
    )

    metrics = tool_surface_metrics(tool)

    assert metrics.description_length == len("Search binary code.")
    assert metrics.input_schema_bytes == json_size(tool.model_dump()["inputSchema"])
    assert metrics.output_schema_bytes == json_size(tool.model_dump()["outputSchema"])
    assert metrics.total_json_bytes == json_size(tool.model_dump())


def test_search_code_semantic_preserves_contract_and_avoids_literal_page_fetch():
    code_collection = FakeCodeCollection(
        documents=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
            },
            {
                "id": "func2",
                "document": "printf beta branch with extra text",
                "metadata": {"function_name": "func2"},
            },
            {
                "id": "func3",
                "document": "gamma branch without literal match",
                "metadata": {"function_name": "func3"},
            },
        ],
        query_results=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
                "distance": 0.0,
            },
            {
                "id": "func2",
                "document": "printf beta branch with extra text",
                "metadata": {"function_name": "func2"},
                "distance": 1.0,
            },
            {
                "id": "func3",
                "document": "gamma branch without literal match",
                "metadata": {"function_name": "func3"},
                "distance": 9.0,
            },
        ],
    )
    program_info = make_runtime_program_info(code_collection=code_collection)
    tools = get_program_tools(program_info)

    results = tools.search_code(
        query="printf",
        limit=2,
        offset=1,
        search_mode=SearchMode.SEMANTIC,
        include_full_code=False,
        preview_length=10,
        similarity_threshold=0.4,
    )
    tools.search_code(query="printf", limit=1, offset=0, search_mode=SearchMode.SEMANTIC)

    assert code_collection.count_calls == 1
    assert len(code_collection.get_calls) == 2
    assert all(call["include"] == [] for call in code_collection.get_calls)
    assert all(call["limit"] is None for call in code_collection.get_calls)
    assert all(call["offset"] is None for call in code_collection.get_calls)
    assert len(code_collection.query_calls) == 2

    assert results.query == "printf"
    assert results.search_mode == SearchMode.SEMANTIC
    assert results.offset == 1
    assert results.limit == 2
    assert results.literal_total == 2
    assert results.semantic_total == 2
    assert results.total_functions == 3
    assert results.returned_count == 1
    assert results.results[0].function_name == "func2"
    assert results.results[0].preview == "printf bet..."
    assert results.results[0].code == "printf bet..."
    assert results.results[0].similarity == 0.5


def test_search_code_literal_uses_paginated_fetch_and_preview_contract():
    code_collection = FakeCodeCollection(
        documents=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
            },
            {
                "id": "func2",
                "document": "printf beta branch with extra text",
                "metadata": {"function_name": "func2"},
            },
            {
                "id": "func3",
                "document": "gamma branch without literal match",
                "metadata": {"function_name": "func3"},
            },
        ]
    )
    program_info = make_runtime_program_info(code_collection=code_collection)
    tools = get_program_tools(program_info)

    results = tools.search_code(
        query="printf",
        limit=1,
        offset=1,
        search_mode=SearchMode.LITERAL,
        include_full_code=False,
        preview_length=6,
    )

    assert code_collection.count_calls == 1
    assert len(code_collection.get_calls) == 2
    assert code_collection.get_calls[0]["include"] == []
    assert code_collection.get_calls[0]["limit"] is None
    assert code_collection.get_calls[0]["offset"] is None
    assert code_collection.get_calls[1]["include"] == ["metadatas", "documents"]
    assert code_collection.get_calls[1]["limit"] == 1
    assert code_collection.get_calls[1]["offset"] == 1
    assert len(code_collection.query_calls) == 0

    assert results.search_mode == SearchMode.LITERAL
    assert results.offset == 1
    assert results.limit == 1
    assert results.literal_total == 2
    assert results.semantic_total == 3
    assert results.total_functions == 3
    assert results.returned_count == 1
    assert results.results[0].function_name == "func2"
    assert results.results[0].preview == "printf..."
    assert results.results[0].code == "printf..."
    assert results.results[0].similarity == 1.0


def test_search_symbols_by_name_paginates_before_refcounts():
    symbols = [
        FakeSymbol("match_one", "0x1"),
        FakeSymbol("match_two", "0x2"),
        FakeSymbol("match_three", "0x3"),
        FakeSymbol("other", "0x4"),
    ]
    program = FakeProgram(
        symbols=symbols,
        references_by_address={
            "0x1": [object(), object()],
            "0x2": [object()],
            "0x3": [object(), object(), object()],
        },
    )
    program_info = make_runtime_program_info(program=program)
    tools = get_program_tools(program_info)

    second_page = tools.search_symbols_by_name("match", offset=1, limit=1)
    first_page = tools.search_symbols_by_name("match", offset=0, limit=1)

    assert program.symbol_table.all_symbols_calls == 1
    assert program.reference_manager.calls == ["0x2", "0x1"]
    assert [symbol.name for symbol in second_page] == ["match_two"]
    assert [symbol.refcount for symbol in second_page] == [1]
    assert [symbol.name for symbol in first_page] == ["match_one"]
    assert [symbol.refcount for symbol in first_page] == [2]


def test_search_functions_by_name_paginates_before_refcounts():
    func_one = FakeFunction(FakeSymbol("func_one", "0x10"), "0x10")
    func_two = FakeFunction(FakeSymbol("func_two", "0x20"), "0x20")
    func_three = FakeFunction(FakeSymbol("func_three", "0x30"), "0x30")
    program = FakeProgram(
        functions=[func_one, func_two, func_three],
        references_by_address={
            "0x10": [object()],
            "0x20": [object(), object()],
            "0x30": [object(), object(), object()],
        },
    )
    program_info = make_runtime_program_info(program=program)
    tools = get_program_tools(program_info)

    second_page = tools.search_functions_by_name("func", offset=1, limit=1)
    first_page = tools.search_functions_by_name("func", offset=0, limit=1)

    assert program.function_manager.get_functions_calls == 1
    assert program.reference_manager.calls == ["0x20", "0x10"]
    assert [symbol.name for symbol in second_page] == ["func_two"]
    assert [symbol.refcount for symbol in second_page] == [2]
    assert [symbol.name for symbol in first_page] == ["func_one"]
    assert [symbol.refcount for symbol in first_page] == [1]


def test_list_exports_and_imports_reuse_cached_symbol_views():
    export_one = FakeSymbol("shared_func_one", "0x1", external_entry=True)
    helper = FakeSymbol("helper", "0x2")
    export_two = FakeSymbol("shared_func_two", "0x3", external_entry=True)
    import_one = FakeSymbol("printf", "0x4", external=True, namespace="libc")
    import_two = FakeSymbol("malloc", "0x5", external=True, namespace="libc")
    program = FakeProgram(
        symbols=[export_one, helper, export_two],
        external_symbols=[import_one, import_two],
    )
    program_info = make_runtime_program_info(program=program)
    tools = get_program_tools(program_info)

    first_export_page = tools.list_exports(query="shared", offset=0, limit=1)
    second_export_page = tools.list_exports(query="shared", offset=1, limit=1)
    printf_import = tools.list_imports(query="printf", offset=0, limit=1)
    malloc_import = tools.list_imports(query="malloc", offset=0, limit=1)

    assert program.symbol_table.all_symbols_calls == 1
    assert program.symbol_table.external_symbols_calls == 1
    assert [item.name for item in first_export_page] == ["shared_func_one"]
    assert [item.name for item in second_export_page] == ["shared_func_two"]
    assert [item.name for item in printf_import] == ["printf"]
    assert [item.name for item in malloc_import] == ["malloc"]


def test_program_info_invalidation_clears_shared_tool_caches():
    func_one = FakeFunction(FakeSymbol("func_one", "0x10"), "0x10")
    func_two = FakeFunction(FakeSymbol("func_two", "0x20"), "0x20")
    symbols = [FakeSymbol("match_one", "0x1"), FakeSymbol("match_two", "0x2")]
    code_collection = FakeCodeCollection(
        documents=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
            },
            {
                "id": "func2",
                "document": "printf beta branch with extra text",
                "metadata": {"function_name": "func2"},
            },
        ],
        query_results=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
                "distance": 0.0,
            }
        ],
    )
    program = FakeProgram(
        symbols=symbols,
        functions=[func_one, func_two],
        references_by_address={"0x1": [object()], "0x10": [object()]},
    )
    program_info = make_runtime_program_info(program=program, code_collection=code_collection)
    tools = get_program_tools(program_info)

    tools.search_symbols_by_name("match", limit=1)
    tools.search_functions_by_name("func", limit=1)
    tools.search_code(query="printf", limit=1, search_mode=SearchMode.SEMANTIC)

    assert program_info.get_tools() is tools
    assert program.symbol_table.all_symbols_calls == 1
    assert program.function_manager.get_functions_calls == 1
    assert code_collection.count_calls == 1

    program_info.invalidate_derived_caches()

    tools.search_symbols_by_name("match", limit=1)
    tools.search_functions_by_name("func", limit=1)
    tools.search_code(query="printf", limit=1, search_mode=SearchMode.SEMANTIC)

    assert program_info.derived_cache_version == 1
    assert program.symbol_table.all_symbols_calls == 2
    assert program.function_manager.get_functions_calls == 2
    assert code_collection.count_calls == 2


def test_large_scale_internal_call_counts_remain_bounded():
    counts = collect_internal_call_counts()

    assert counts["search_code_semantic"].chroma_count_calls == 1
    assert counts["search_code_semantic"].chroma_get_calls == 2
    assert counts["search_code_semantic"].chroma_query_calls == 2

    assert counts["search_code_literal"].chroma_count_calls == 1
    assert counts["search_code_literal"].chroma_get_calls == 2
    assert counts["search_code_literal"].chroma_query_calls == 0

    assert counts["search_symbols_by_name"].symbol_table_all_symbols_calls == 1
    assert counts["search_symbols_by_name"].reference_lookup_calls == 50

    assert counts["search_functions_by_name"].function_manager_get_functions_calls == 1
    assert counts["search_functions_by_name"].reference_lookup_calls == 50

    assert counts["list_exports"].symbol_table_all_symbols_calls == 1
    assert counts["list_imports"].symbol_table_external_symbols_calls == 1


def test_search_strings_combines_literal_hits_with_semantic_fill():
    strings_collection = FakeCodeCollection(
        documents=[
            {
                "id": "str1",
                "document": "sentinel alpha string",
                "metadata": {"address": "0x1"},
            },
            {
                "id": "str2",
                "document": "sentinel beta string",
                "metadata": {"address": "0x2"},
            },
        ],
        query_results=[
            {
                "id": "str3",
                "document": "semantic gamma string",
                "metadata": {"address": "0x3"},
                "distance": 0.1,
            },
            {
                "id": "str4",
                "document": "semantic delta string",
                "metadata": {"address": "0x4"},
                "distance": 0.2,
            },
        ],
    )
    program_info = make_runtime_program_info(strings_collection=strings_collection)
    tools = get_program_tools(program_info)

    results = tools.search_strings("sentinel", limit=4)

    assert len(strings_collection.get_calls) == 1
    assert len(strings_collection.query_calls) == 1
    assert len(results) == 4
    assert [result.address for result in results[:2]] == ["0x1", "0x2"]
    assert results[0].similarity == 1
    assert results[2].address == "0x3"
    assert results[3].address == "0x4"
