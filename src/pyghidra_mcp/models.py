from enum import Enum

from pydantic import BaseModel, Field, RootModel

BinaryMetadataValue = str | int | float | bool | None


class DecompiledFunction(BaseModel):
    """Decompiled function."""

    name: str = Field(..., description="Function name.")
    code: str = Field(..., description="Pseudo-C code.")
    signature: str | None = Field(None, description="Function signature.")


class ProgramBasicInfo(BaseModel):
    """Basic program info."""

    name: str = Field(..., description="Program name.")
    analysis_complete: bool = Field(..., description="True when analysis is finished.")


class ProgramBasicInfos(BaseModel):
    """Basic program list."""

    programs: list[ProgramBasicInfo] = Field(..., description="Programs.")


class BinaryMetadata(RootModel[dict[str, BinaryMetadataValue]]):
    """Binary metadata keyed by Ghidra property name."""


class ProgramInfo(BaseModel):
    """Program details."""

    name: str = Field(..., description="Program name.")
    file_path: str | None = Field(None, description="Binary path.")
    load_time: float | None = Field(None, description="Load timestamp.")
    analysis_complete: bool = Field(..., description="True when analysis is finished.")
    metadata: dict = Field(
        ...,
        description="Empty here; call list_project_binary_metadata for details.",
    )
    code_collection: bool = Field(..., description="Semantic code search ready.")
    strings_collection: bool = Field(..., description="String search ready.")


class ProgramInfos(BaseModel):
    """Program details list."""

    programs: list[ProgramInfo] = Field(..., description="Programs.")


class ExportInfo(BaseModel):
    """Exported symbol."""

    name: str = Field(..., description="Export name.")
    address: str = Field(..., description="Export address.")


class ExportInfos(BaseModel):
    """Export list."""

    exports: list[ExportInfo] = Field(..., description="Exports.")


class ImportInfo(BaseModel):
    """Imported symbol."""

    name: str = Field(..., description="Import name.")
    library: str = Field(..., description="Import library.")


class ImportInfos(BaseModel):
    """Import list."""

    imports: list[ImportInfo] = Field(..., description="Imports.")


class CrossReferenceInfo(BaseModel):
    """Cross-reference."""

    function_name: str | None = Field(None, description="Containing function.")
    from_address: str = Field(..., description="Source address.")
    to_address: str = Field(..., description="Target address.")
    type: str = Field(..., description="Reference type.")


class CrossReferenceInfos(BaseModel):
    """Cross-reference list."""

    cross_references: list[CrossReferenceInfo] = Field(..., description="Cross-references.")


class SymbolInfo(BaseModel):
    """Binary symbol."""

    name: str = Field(..., description="Symbol name.")
    address: str = Field(..., description="Symbol address.")
    type: str = Field(..., description="Symbol type.")
    namespace: str = Field(..., description="Symbol namespace.")
    source: str = Field(..., description="Symbol source.")
    refcount: int = Field(..., description="Reference count.")
    external: bool = Field(..., description="External symbol.")


class SymbolSearchResults(BaseModel):
    """Symbol search results."""

    symbols: list[SymbolInfo] = Field(..., description="Matching symbols.")


class SearchMode(str, Enum):
    """Code search mode."""

    SEMANTIC = "semantic"
    LITERAL = "literal"


class CodeSearchResult(BaseModel):
    """Code search hit."""

    function_name: str = Field(..., description="Function name.")
    code: str = Field(..., description="Matched code.")
    similarity: float = Field(..., description="Similarity score.")
    search_mode: SearchMode = Field(
        ...,
        description="semantic = similarity, literal = exact text.",
    )
    preview: str | None = Field(None, description="Truncated code preview.")


class CodeSearchResults(BaseModel):
    """Code search response."""

    results: list[CodeSearchResult] = Field(..., description="Search results.")
    query: str = Field(..., description="Search query.")
    search_mode: SearchMode = Field(
        ...,
        description="semantic = similarity, literal = exact text.",
    )
    returned_count: int = Field(..., description="Returned results.")
    offset: int = Field(..., description="Pagination offset.")
    limit: int = Field(..., description="Pagination limit.")
    literal_total: int = Field(
        ...,
        description="Functions containing the literal query, even in semantic mode.",
    )
    semantic_total: int = Field(..., description="Estimated semantic matches.")
    total_functions: int = Field(..., description="Indexed functions.")


class StringInfo(BaseModel):
    """Binary string."""

    value: str = Field(..., description="String value.")
    address: str = Field(..., description="String address.")


class StringSearchResult(StringInfo):
    """String search hit."""

    similarity: float = Field(..., description="Similarity score.")


class StringSearchResults(BaseModel):
    """String search response."""

    strings: list[StringSearchResult] = Field(..., description="Matching strings.")


class BytesReadResult(BaseModel):
    """Raw byte read."""

    address: str = Field(..., description="Normalized address.")
    size: int = Field(..., description="Bytes returned.")
    data: str = Field(..., description="Hex bytes.")


class CallGraphDirection(str, Enum):
    """Call graph direction."""

    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    """Call graph display type."""

    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    """Call graph response."""

    function_name: str = Field(..., description="Function name.")
    direction: CallGraphDirection = Field(..., description="Call graph direction.")
    display_type: CallGraphDisplayType = Field(..., description="Graph display type.")
    graph: str = Field(..., description="Mermaid graph.")
    mermaid_url: str = Field(
        ...,
        description="URL for rendering the Mermaid graph output.",
    )
