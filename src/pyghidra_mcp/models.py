from typing import Any

from pydantic import BaseModel, Field


class DecompiledFunction(BaseModel):
    """Represents a single function decompiled by Ghidra."""

    name: str = Field(..., description="The name of the function.")
    code: str = Field(..., description="The decompiled pseudo-C code of the function.")
    signature: str | None = Field(None, description="The signature of the function.")


class FunctionInfo(BaseModel):
    """Provides basic information about a function within a binary."""

    name: str = Field(..., description="The name of the function.")
    entry_point: str = Field(..., description="The entry point address of the function.")


class FunctionSearchResults(BaseModel):
    """A container for a list of functions found during a search."""

    functions: list[FunctionInfo] = Field(
        ..., description="A list of functions that match the search criteria."
    )


class ProgramInfo(BaseModel):
    """Detailed information about a program (binary) loaded in Ghidra."""

    name: str = Field(..., description="The name of the program.")
    file_path: str | None = Field(None, description="The file path of the program.")
    load_time: float | None = Field(
        None, description="The time it took to load the program in seconds."
    )
    analysis_complete: bool = Field(
        ..., description="Indicates if Ghidra's analysis of the program has completed."
    )
    metadata: dict = Field(..., description="A dictionary of metadata associated with the program.")
    collection: Any | None = Field(None, description="The chromadb collection for the program.")


class ProgramInfos(BaseModel):
    """A container for a list of program information objects."""

    programs: list[ProgramInfo] = Field(..., description="A list of program information objects.")


class ExportInfo(BaseModel):
    """Represents a single exported function or symbol from a binary."""

    name: str = Field(..., description="The name of the export.")
    address: str = Field(..., description="The address of the export.")


class ExportInfos(BaseModel):
    """A container for a list of exports from a binary."""

    exports: list[ExportInfo] = Field(..., description="A list of exports.")


class ImportInfo(BaseModel):
    """Represents a single imported function or symbol."""

    name: str = Field(..., description="The name of the import.")
    library: str = Field(
        ..., description="The name of the library from which the symbol is imported."
    )


class ImportInfos(BaseModel):
    """A container for a list of imports."""

    imports: list[ImportInfo] = Field(..., description="A list of imports.")


class CrossReferenceInfo(BaseModel):
    """Represents a cross-reference to a specific address in the binary."""

    function_name: str | None = Field(
        None, description="The name of the function containing the cross-reference."
    )
    from_address: str = Field(..., description="The address where the cross-reference originates.")
    to_address: str = Field(..., description="The address that is being referenced.")
    type: str = Field(..., description="The type of the cross-reference.")


class CrossReferenceInfos(BaseModel):
    """A container for a list of cross-references."""

    cross_references: list[CrossReferenceInfo] = Field(
        ..., description="A list of cross-references."
    )


class SymbolInfo(BaseModel):
    """Represents a symbol within the binary."""

    name: str = Field(..., description="The name of the symbol.")
    address: str = Field(..., description="The address of the symbol.")
    type: str = Field(..., description="The type of the symbol.")
    namespace: str = Field(..., description="The namespace of the symbol.")
    source: str = Field(..., description="The source of the symbol.")
    refcount: int = Field(..., description="The reference count of the symbol.")


class SymbolSearchResults(BaseModel):
    """A container for a list of symbols found during a search."""

    symbols: list[SymbolInfo] = Field(
        ..., description="A list of symbols that match the search criteria."
    )


class CodeSearchResult(BaseModel):
    """Represents a single search result from the codebase."""

    function_name: str = Field(
        ..., description="The name of the function where the code was found."
    )
    code: str = Field(..., description="The code snippet that matched the search query.")
    similarity: float = Field(..., description="The similarity score of the search result.")


class CodeSearchResults(BaseModel):
    """A container for a list of code search results."""

    results: list[CodeSearchResult] = Field(..., description="A list of code search results.")


class StringInfo(BaseModel):
    """Represents a string found within the binary."""

    value: str = Field(..., description="The value of the string.")
    address: str = Field(..., description="The address of the string.")


class StringSearchResult(StringInfo):
    """Represents a string search result found within the binary."""

    similarity: float = Field(..., description="The similarity score of the search result.")


class StringSearchResults(BaseModel):
    """A container for a list of string search results."""

    strings: list[StringSearchResult] = Field(..., description="A list of string search results.")
