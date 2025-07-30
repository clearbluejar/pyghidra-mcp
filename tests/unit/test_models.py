import pytest
from pyghidra_mcp.models import DecompiledFunction, FunctionInfo, FunctionSearchResults


def test_decompiled_function_model():
    """Test the DecompiledFunction model."""
    func = DecompiledFunction(
        name="test_function",
        code="int test_function() { return 0; }",
        signature="int test_function()"
    )

    assert func.name == "test_function"
    assert func.code == "int test_function() { return 0; }"
    assert func.signature == "int test_function()"


def test_function_info_model():
    """Test the FunctionInfo model."""
    func_info = FunctionInfo(
        name="test_function",
        entry_point="0x1000"
    )

    assert func_info.name == "test_function"
    assert func_info.entry_point == "0x1000"


def test_function_search_results_model():
    """Test the FunctionSearchResults model."""
    func1 = FunctionInfo(name="function1", entry_point="0x1000")
    func2 = FunctionInfo(name="function2", entry_point="0x2000")

    search_results = FunctionSearchResults(functions=[func1, func2])

    assert len(search_results.functions) == 2
    assert search_results.functions[0].name == "function1"
    assert search_results.functions[1].name == "function2"
