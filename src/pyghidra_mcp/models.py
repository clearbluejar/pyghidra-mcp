from enum import Enum
from typing import Any, Literal

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


class SessionInfo(BaseModel):
    role: Literal["primary", "fork"]
    project: str
    fork_id: str | None = None
    parent_project: str | None = None
    journal_ops: int | None = Field(None, description="edits journaled by this fork")
    pending_fork_ops: int | None = Field(None, description="unmerged edits across all forks")
    hint: str | None = None


class ProgramInfos(BaseModel):
    programs: list[ProgramInfo]
    session: SessionInfo | None = None


class OpenProgramInfo(BaseModel):
    name: str
    path: str
    current: bool
    analysis_complete: bool


class OpenProgramInfos(BaseModel):
    programs: list[OpenProgramInfo]


class SkippedImport(BaseModel):
    path: str
    reason: str


class ImportRequestResult(BaseModel):
    requested_path: str
    queued_count: int
    queued_paths: list[str]
    skipped_count: int
    skipped: list[SkippedImport]
    message: str


class SaveRequestResult(BaseModel):
    pass


class GotoResponse(BaseModel):
    binary_name: str
    address: str
    success: bool


class GuiContextResponse(BaseModel):
    active_program: str | None = None
    active_provider: str | None = None
    active_address: str | None = None
    active_function: str | None = None
    selection: str | None = None
    location_type: str | None = None


class RenameResponse(BaseModel):
    binary_name: str
    address: str
    old_name: str
    new_name: str


class VariableRenameResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    old_name: str
    new_name: str


class VariableTypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    variable_name: str
    old_type: str
    new_type: str


class FunctionPrototypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    old_prototype: str
    new_prototype: str


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
    is_thunk: bool = False
    thunk_target: str | None = None


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


class DisassembleResult(BaseModel):
    address: str
    count: int
    listing: str = Field(
        ...,
        description=(
            "Newline-delimited disassembly listing. Each line is single-space separated: "
            "address, optional raw bytes (hex, when include_bytes=True), mnemonic, operands."
        ),
    )


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


class ForkInfo(BaseModel):
    fork_id: str
    label: str | None = None
    status: str
    alive: bool | None = Field(None, description="fork server running; null if on another host")
    pid: int | None = None
    created_at: str
    journal_ops: int
    resolved_ops: int
    pending_ops: int
    path: str


class ForkList(BaseModel):
    session: SessionInfo | None = None
    forks: list[ForkInfo]


class ForkMergeEntry(BaseModel):
    seq: int
    op: str
    binary: str
    target: str
    status: str = Field(
        ...,
        description=(
            "applied, already_applied, overwritten, queued, ignored (final); "
            "conflict, skipped, failed (retried by the next merge); "
            "would_apply, would_overwrite (dry run)"
        ),
    )
    detail: str | None = None


class ForkMergeResult(BaseModel):
    fork_id: str
    dry_run: bool
    on_conflict: str
    counts: dict[str, int]
    entries: list[ForkMergeEntry]
    pending_ops: int


class RvaTranslateResult(BaseModel):
    status: str = "ok"
    va: str
    rva: str
    va_int: int
    rva_int: int
    image_base: str
    time_ms: float


class GpuAdrpMatchItem(BaseModel):
    adrp_index: int
    adrp_offset: str
    adrp_pc: str
    adrp_insn: str
    adrp_rd: str
    paired_index: int
    paired_offset: str
    paired_pc: str
    paired_insn: str
    paired_type: str
    paired_rn: str
    paired_rt: str
    immediate: str
    resolved_target: str
    register_matched: bool


class GpuAdrpScanResult(BaseModel):
    status: str = "ok"
    binary_name: str
    backend: str
    total_matches: int
    matches: list[GpuAdrpMatchItem] = Field(default_factory=list)
    applied_xrefs: int | None = None
    message: str | None = None


class GpuFunctionSeedItem(BaseModel):
    entry_vaddr: str
    sources: list[str]
    confidence: float
    prologue_type: str
    caller_count: int
    callers: list[str]
    data_ref_count: int
    data_refs: list[str]


class GpuSeedFunctionsResult(BaseModel):
    status: str = "ok"
    binary_name: str
    backend: str
    total_seeds: int
    seeds: list[GpuFunctionSeedItem]
    applied_to_program: int | None = None


class GovernorPolicy(BaseModel):
    mode: str
    thread_count: int | None = None
    thread_priority: int | None = None
    duty_cycle_ms: int | None = None
    max_native_decompilers: int | None = None
    decompiler_idle_timeout_sec: int | None = None
    soft_max_heap_mb: int | None = None
    zgc_uncommit_delay_sec: int | None = None
    tiered_stop_at_level: int | None = None
    default_simplification: str | None = None
    tier2_downshift: str | None = None
    tier3_downshift: str | None = None
    max_payload_mb: int | None = None


class GovernorModeResult(BaseModel):
    status: str = "ok"
    mode: str
    message: str | None = None
    idle_timeout_sec: float | None = None
    policy: GovernorPolicy | None = None


class HibernateResult(BaseModel):
    status: str = "ok"
    message: str
    hibernated: bool = True
    is_hibernating: bool = True


class ClearCacheResult(BaseModel):
    status: str = "ok"
    cleared_entries: int
    message: str


class FieldMigrationItem(BaseModel):
    field_name: str
    old_offset: str
    new_offset: str
    delta: int
    shift_type: str
    confidence: float
    old_offset_int: int
    new_offset_int: int
    access_size: int = 4
    sample_v1_insn: str = ""
    sample_v2_insn: str = ""


class StructInsertionItem(BaseModel):
    offset: str
    offset_int: int
    size: int
    probable_type: str


class MigrateStructShiftsResult(BaseModel):
    status: str = "ok"
    old_binary: str
    new_binary: str
    struct_name: str | None = None
    total_shifts_detected: int
    matched_functions: int
    max_delta: int = 0
    field_migrations: list[FieldMigrationItem]
    insertions: list[StructInsertionItem]
    cpp_header_patch: str
    updated_header: str
    migration_report_json: str
    summary: str
    message: str


class SmtVerificationResult(BaseModel):
    status: str = "ok"
    equivalent: bool
    smt_status: str  # "UNSAT", "SAT", "UNKNOWN", "ERROR"
    details: str
    obligation_id: str | None = None
    counterexample: dict[str, Any] | None = None
    model_inputs: dict[str, Any] | None = None
    pcode_out: str | None = None
    c_out: str | None = None
    target_reg: str = "x0"
    message: str


class SyntheticSymbolExportResult(BaseModel):
    status: str = "ok"
    output_base_path: str
    exported_files: dict[str, str]
    formats: list[str]
    total_symbols: int
    message: str


class JniMatchItem(BaseModel):
    class_name: str
    method_name: str
    signature: str
    binding_type: str
    symbol_name: str
    target_address: str
    target_rva: str
    confidence: float


class ApkJniCrossRefResult(BaseModel):
    status: str = "ok"
    total_java_methods: int
    total_matches: int
    matches: list[JniMatchItem]
    ghidra_script: str
    message: str


class BinaryMatchItem(BaseModel):
    func_a_id: str
    func_a_name: str
    func_a_addr: int
    func_b_id: str
    func_b_name: str
    func_b_addr: int
    similarity: float
    confidence: str
    match_type: str


class BinaryDiffResult(BaseModel):
    status: str = "ok"
    total_matches: int
    match_rate_pct: float
    avg_similarity: float
    execution_time_ms: float
    matches: list[BinaryMatchItem]
    unmatched_a: list[str]
    unmatched_b: list[str]
    message: str


class EmulatorMemoryVerifyResult(BaseModel):
    status: str = "ok"
    device_serial: str
    allowed: bool
    action: str
    is_valid: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    message: str


class NeuralDecompileSkinResult(BaseModel):
    status: str = "ok"
    function_address: str
    function_rva: str
    function_name: str
    return_type: str
    signature: str
    skeleton_source: str
    verified_struct_fields: dict[str, str]
    evidence_proof_hashes: list[str]
    confidence: float
    model_identifier: str
    is_safe_to_commit: bool
    message: str


class MigratedEventRecordItem(BaseModel):
    original_event_id: str
    event_type: str
    status: str
    similarity: float
    confidence: str
    match_detail: str
    migrated_event_id: str | None = None


class MigrateSemanticDeltasResult(BaseModel):
    status: str = "ok"
    total_baseline_events: int
    migrated_verified_count: int
    migrated_unverified_count: int
    skipped_unmatched_count: int
    evidence_rejected_count: int
    migration_rate_pct: float
    elapsed_time_ms: float
    output_delta_log_path: str | None = None
    records: list[MigratedEventRecordItem] = Field(default_factory=list)
    message: str


class PreindexDwarfPdbResult(BaseModel):
    status: str = "ok"
    input_path: str
    db_output_path: str
    total_canonical_types: int
    total_symbols: int
    total_struct_members: int
    query: str | None = None
    c_declaration: str | None = None
    matched_symbols: list[dict[str, Any]] = Field(default_factory=list)
    message: str


class InspectBinaryResult(BaseModel):
    status: str = "ok"
    path: str
    format: str = Field(description="elf | pe | macho | raw")
    arch: str = Field(description="x86 | x86_64 | arm | arm64 | mips | riscv64 | ppc | ...")
    bits: int
    endian: str
    image_base: str
    entry: str | None = None
    is_library: bool
    is_dotnet: bool = False
    pdb_path: str | None = None
    libraries: list[str] = Field(default_factory=list)
    sections: list[dict[str, Any]] = Field(default_factory=list)
    exports: list[dict[str, Any]] = Field(default_factory=list)
    imports: list[dict[str, Any]] = Field(default_factory=list)
    total_exports: int = 0
    total_imports: int = 0
    total_function_starts: int = 0
    message: str = ""


class RecoverCppClassesResult(BaseModel):
    status: str = "ok"
    path: str
    arch: str
    total_mfc_classes: int = 0
    total_serializable: int = 0
    total_rtti_classes: int = 0
    mfc_classes: list[dict[str, Any]] = Field(
        default_factory=list,
        description="CRuntimeClass records: name, object_size, schema, base_name, vtable, serialize, create_object",
    )
    rtti_classes: list[dict[str, Any]] = Field(default_factory=list)
    message: str = ""


class TraceSerializeResult(BaseModel):
    status: str = "ok"
    path: str
    arch: str
    total_traced: int = 0
    total_mirrored: int = Field(0, description="Classes whose load and store paths perform the same operations")
    traces: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Per class: function, schema, mirrored, loading/storing ops (kind, size, member, gates, repeat)",
    )
    message: str = ""


class DecodeCArchiveResult(BaseModel):
    status: str = "ok"
    stream_path: str
    length: int = 0
    layout_binaries: list[str] = Field(default_factory=list)
    layouts: int = Field(0, description="Classes with a decode layout")
    env: dict[str, Any] = Field(default_factory=dict, description="Gate operand values used (e.g. file version)")
    calibration: dict[str, Any] | None = None
    stats: dict[str, int] = Field(default_factory=dict)
    map_reliable: bool = True
    classes: list[dict[str, Any]] = Field(default_factory=list, description="Classes in the load map, in order")
    gaps: list[dict[str, Any]] = Field(default_factory=list)
    objects: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False
    message: str = ""


