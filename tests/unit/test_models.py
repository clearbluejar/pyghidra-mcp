from pyghidra_mcp.models import (
    BytesReadResult,
    CodeSearchResult,
    CodeSearchResults,
    CrossReferenceInfo,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfo,
    ExportInfos,
    ImportInfo,
    ImportInfos,
    ProgramBasicInfo,
    ProgramBasicInfos,
    ProgramInfo,
    ProgramInfos,
    StringInfo,
    StringSearchResult,
    StringSearchResults,
    SymbolInfo,
    SymbolSearchResults,
)


def test_decompiled_function_model():
    """Test the DecompiledFunction model."""
    func = DecompiledFunction(
        name="test_function",
        code="int test_function() { return 0; }",
        signature="int test_function()",
    )

    assert func.name == "test_function"
    assert func.code == "int test_function() { return 0; }"
    assert func.signature == "int test_function()"


def test_program_basic_info_model():
    """Test the ProgramBasicInfo model."""
    info = ProgramBasicInfo(name="test_program", analysis_complete=True)
    assert info.name == "test_program"
    assert info.analysis_complete is True


def test_program_basic_infos_model():
    """Test the ProgramBasicInfos model."""
    infos = ProgramBasicInfos(
        programs=[
            ProgramBasicInfo(name="test_program1", analysis_complete=True),
            ProgramBasicInfo(name="test_program2", analysis_complete=False),
        ]
    )
    assert len(infos.programs) == 2
    assert infos.programs[0].name == "test_program1"
    assert infos.programs[1].analysis_complete is False


def test_program_info_model():
    """Test the ProgramInfo model."""
    info = ProgramInfo(
        name="test_program",
        file_path="/path/to/program",
        load_time=1.23,
        analysis_complete=True,
        metadata={"key": "value"},
        code_collection=True,
        strings_collection=False,
    )
    assert info.name == "test_program"
    assert info.file_path == "/path/to/program"
    assert info.load_time == 1.23
    assert info.analysis_complete is True
    assert info.metadata == {"key": "value"}
    assert info.code_collection is True
    assert info.strings_collection is False


def test_program_infos_model():
    """Test the ProgramInfos model."""
    infos = ProgramInfos(
        programs=[
            ProgramInfo(
                name="test_program1",
                file_path="/path/to/program1",
                load_time=1.23,
                analysis_complete=True,
                metadata={"key": "value"},
                code_collection=True,
                strings_collection=False,
            ),
            ProgramInfo(
                name="test_program2",
                file_path="/path/to/program2",
                load_time=4.56,
                analysis_complete=False,
                metadata={},
                code_collection=False,
                strings_collection=True,
            ),
        ]
    )
    assert len(infos.programs) == 2
    assert infos.programs[0].name == "test_program1"
    assert infos.programs[1].analysis_complete is False


def test_export_info_model():
    """Test the ExportInfo model."""
    export = ExportInfo(name="test_export", address="0x1234")
    assert export.name == "test_export"
    assert export.address == "0x1234"


def test_export_infos_model():
    """Test the ExportInfos model."""
    exports = ExportInfos(
        exports=[
            ExportInfo(name="test_export1", address="0x1234"),
            ExportInfo(name="test_export2", address="0x5678"),
        ]
    )
    assert len(exports.exports) == 2
    assert exports.exports[0].name == "test_export1"
    assert exports.exports[1].address == "0x5678"


def test_import_info_model():
    """Test the ImportInfo model."""
    imp = ImportInfo(name="test_import", library="test_lib")
    assert imp.name == "test_import"
    assert imp.library == "test_lib"


def test_import_infos_model():
    """Test the ImportInfos model."""
    imports = ImportInfos(
        imports=[
            ImportInfo(name="test_import1", library="test_lib1"),
            ImportInfo(name="test_import2", library="test_lib2"),
        ]
    )
    assert len(imports.imports) == 2
    assert imports.imports[0].name == "test_import1"
    assert imports.imports[1].library == "test_lib2"


def test_cross_reference_info_model():
    """Test the CrossReferenceInfo model."""
    xref = CrossReferenceInfo(
        function_name="test_func",
        from_address="0x1111",
        to_address="0x2222",
        type="read",
    )
    assert xref.function_name == "test_func"
    assert xref.from_address == "0x1111"
    assert xref.to_address == "0x2222"
    assert xref.type == "read"


def test_cross_reference_infos_model():
    """Test the CrossReferenceInfos model."""
    xrefs = CrossReferenceInfos(
        cross_references=[
            CrossReferenceInfo(
                function_name="test_func1",
                from_address="0x1111",
                to_address="0x2222",
                type="read",
            ),
            CrossReferenceInfo(
                function_name="test_func2",
                from_address="0x3333",
                to_address="0x4444",
                type="write",
            ),
        ]
    )
    assert len(xrefs.cross_references) == 2
    assert xrefs.cross_references[0].function_name == "test_func1"
    assert xrefs.cross_references[1].type == "write"


def test_symbol_info_model():
    """Test the SymbolInfo model."""
    symbol = SymbolInfo(
        name="test_symbol",
        address="0x1234",
        type="function",
        namespace="global",
        source="user",
        refcount=5,
    )
    assert symbol.name == "test_symbol"
    assert symbol.address == "0x1234"
    assert symbol.type == "function"
    assert symbol.namespace == "global"
    assert symbol.source == "user"
    assert symbol.refcount == 5


def test_symbol_search_results_model():
    """Test the SymbolSearchResults model."""
    results = SymbolSearchResults(
        symbols=[
            SymbolInfo(
                name="test_symbol1",
                address="0x1234",
                type="function",
                namespace="global",
                source="user",
                refcount=5,
            ),
            SymbolInfo(
                name="test_symbol2",
                address="0x5678",
                type="variable",
                namespace="local",
                source="analysis",
                refcount=1,
            ),
        ]
    )
    assert len(results.symbols) == 2
    assert results.symbols[0].name == "test_symbol1"
    assert results.symbols[1].refcount == 1


def test_code_search_result_model():
    """Test the CodeSearchResult model."""
    result = CodeSearchResult(
        function_name="test_func",
        code="int i = 0;",
        similarity=0.9,
    )
    assert result.function_name == "test_func"
    assert result.code == "int i = 0;"
    assert result.similarity == 0.9


def test_code_search_results_model():
    """Test the CodeSearchResults model."""
    results = CodeSearchResults(
        results=[
            CodeSearchResult(
                function_name="test_func1",
                code="int i = 0;",
                similarity=0.9,
            ),
            CodeSearchResult(
                function_name="test_func2",
                code="return 1;",
                similarity=0.8,
            ),
        ]
    )
    assert len(results.results) == 2
    assert results.results[0].function_name == "test_func1"
    assert results.results[1].similarity == 0.8


def test_string_info_model():
    """Test the StringInfo model."""
    info = StringInfo(value="test_string", address="0x1234")
    assert info.value == "test_string"
    assert info.address == "0x1234"


def test_string_search_result_model():
    """Test the StringSearchResult model."""
    result = StringSearchResult(value="test_string", address="0x1234", similarity=0.95)
    assert result.value == "test_string"
    assert result.address == "0x1234"
    assert result.similarity == 0.95


def test_string_search_results_model():
    """Test the StringSearchResults model."""
    results = StringSearchResults(
        strings=[
            StringSearchResult(value="test_string1", address="0x1234", similarity=0.95),
            StringSearchResult(value="test_string2", address="0x5678", similarity=0.85),
        ]
    )
    assert len(results.strings) == 2
    assert results.strings[0].value == "test_string1"
    assert results.strings[1].similarity == 0.85


def test_bytes_read_result_model():
    """Test the BytesReadResult model."""
    result = BytesReadResult(
        address="0x1234",
        size=4,
        data="01020304",
    )
    assert result.address == "0x1234"
    assert result.size == 4
    assert result.data == "01020304"
