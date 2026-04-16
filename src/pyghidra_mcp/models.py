from enum import Enum

from pydantic import BaseModel, Field


class DecompiledFunction(BaseModel):
    name: str
    code: str
    signature: str | None = None
    error: str | None = None
    # Rich response fields (populated when include_* flags are set)
    callees: list[str] | None = None
    referenced_strings: list[str] | None = None
    xrefs: list["CrossReferenceInfo"] | None = None


class ProgramBasicInfo(BaseModel):
    name: str
    analysis_complete: bool


class ProgramBasicInfos(BaseModel):
    programs: list[ProgramBasicInfo]


class ProgramInfo(BaseModel):
    name: str
    file_path: str | None = None
    load_time: float | None = None
    analysis_complete: bool
    metadata: dict
    code_indexed: bool
    strings_indexed: bool


class ProgramInfos(BaseModel):
    programs: list[ProgramInfo]


class OpenProgramInfo(BaseModel):
    name: str
    path: str
    current: bool
    analysis_complete: bool


class OpenProgramInfos(BaseModel):
    programs: list[OpenProgramInfo]


class GotoResponse(BaseModel):
    binary_name: str
    address: str
    success: bool


class RenameResponse(BaseModel):
    binary_name: str
    address: str
    old_name: str
    new_name: str


class CommentResponse(BaseModel):
    binary_name: str
    address: str
    comment: str
    comment_type: str


class ExportInfo(BaseModel):
    name: str
    address: str


class ExportInfos(BaseModel):
    exports: list[ExportInfo]


class ImportInfo(BaseModel):
    name: str
    library: str


class ImportInfos(BaseModel):
    imports: list[ImportInfo]


class CrossReferenceInfo(BaseModel):
    function_name: str | None = None
    from_address: str
    to_address: str
    type: str


class CrossReferenceInfos(BaseModel):
    target: str | None = None
    cross_references: list[CrossReferenceInfo]
    error: str | None = None


# Resolve forward reference for DecompiledFunction.xrefs
DecompiledFunction.model_rebuild()


class SymbolInfo(BaseModel):
    name: str
    address: str
    type: str
    namespace: str
    source: str
    refcount: int
    external: bool


class SymbolSearchResults(BaseModel):
    symbols: list[SymbolInfo]


class SearchMode(str, Enum):
    """Search mode for code search."""

    SEMANTIC = "semantic"  # Vector similarity search
    LITERAL = "literal"  # Exact string match ($contains)


class CodeSearchResult(BaseModel):
    function_name: str
    code: str
    similarity: float
    search_mode: SearchMode
    preview: str | None = None


class CodeSearchResults(BaseModel):
    results: list[CodeSearchResult]
    query: str
    search_mode: SearchMode
    returned_count: int
    offset: int
    limit: int
    literal_total: int = Field(..., description="total literal matches")
    semantic_total: int = Field(..., description="estimated semantic matches")
    total_functions: int


class StringInfo(BaseModel):
    value: str
    address: str


class StringSearchResult(StringInfo):
    similarity: float


class StringSearchResults(BaseModel):
    strings: list[StringSearchResult]


class BytesReadResult(BaseModel):
    address: str
    size: int
    data: str = Field(..., description="hex string")


class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph."""

    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph."""

    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    function_name: str
    direction: CallGraphDirection
    display_type: CallGraphDisplayType
    graph: str = Field(..., description="MermaidJS graph string")
    mermaid_url: str
