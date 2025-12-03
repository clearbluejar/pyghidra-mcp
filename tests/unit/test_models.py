from pyghidra_mcp.models import DecompiledFunction


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
