# ruff: noqa: N802

from __future__ import annotations

import asyncio
import json
import platform
import statistics
import subprocess
import sys
import time
import types
from dataclasses import asdict, dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypeVar

from mcp import ClientSession

from pyghidra_mcp.context import ProgramInfo as RuntimeProgramInfo, PyGhidraContext
from pyghidra_mcp.models import (
    CodeSearchResults,
    ProgramInfo as PublicProgramInfo,
    ProgramInfos,
    SearchMode,
)
from pyghidra_mcp.tools import GhidraTools

T = TypeVar("T")


@dataclass(frozen=True)
class ToolSurfaceMetrics:
    name: str
    description_length: int
    input_schema_bytes: int
    output_schema_bytes: int
    total_json_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ToolTimingMetrics:
    scenario: str
    tool_name: str
    first_call_seconds: float
    warm_call_median_seconds: float
    all_call_seconds: list[float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InternalCallCounts:
    chroma_count_calls: int = 0
    chroma_get_calls: int = 0
    chroma_query_calls: int = 0
    symbol_table_all_symbols_calls: int = 0
    symbol_table_external_symbols_calls: int = 0
    function_manager_get_functions_calls: int = 0
    reference_lookup_calls: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class GeneratedBinarySpec:
    stem: str
    function_count: int = 96
    string_count: int = 96
    global_count: int = 64
    call_fanout: int = 2
    exported_function_count: int = 16
    sentinel_function_stem: str = "sentinel_target_function"
    sentinel_symbol_stem: str = "sentinel_global_state"
    sentinel_export_stem: str = "sentinel_export_entry"
    sentinel_string: str = "SENTINEL_RUNTIME_STRING"
    sentinel_code_literal: str = "SENTINEL_CODE_LITERAL"
    import_query: str = "printf"


@dataclass(frozen=True)
class GeneratedBinaryArtifact:
    binary_path: Path
    source_path: Path
    spec: GeneratedBinarySpec


def json_size(payload: object) -> int:
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def tool_surface_metrics(tool) -> ToolSurfaceMetrics:
    tool_entry = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
    return ToolSurfaceMetrics(
        name=tool.name,
        description_length=len(tool.description or ""),
        input_schema_bytes=json_size(tool_entry["inputSchema"]),
        output_schema_bytes=json_size(tool_entry.get("outputSchema") or {}),
        total_json_bytes=json_size(tool_entry),
    )


def collect_list_tools_metrics(tools_response) -> tuple[int, dict[str, ToolSurfaceMetrics]]:
    payload_bytes = json_size(
        tools_response.model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    return payload_bytes, {tool.name: tool_surface_metrics(tool) for tool in tools_response.tools}


async def call_tool_text(session: ClientSession, tool_name: str, arguments: dict[str, Any]) -> str:
    response = await session.call_tool(tool_name, arguments)
    if response.isError:
        raise RuntimeError(response.content[0].text)
    if not response.content:
        raise RuntimeError(f"Tool {tool_name} returned no content")
    return response.content[0].text


async def call_tool_json(
    session: ClientSession, tool_name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    return json.loads(await call_tool_text(session, tool_name, arguments))


async def call_tool_model(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
    model_cls: type[T],
) -> T:
    return model_cls.model_validate_json(await call_tool_text(session, tool_name, arguments))


def warm_call_median(samples: list[float]) -> float:
    if not samples:
        raise ValueError("Expected at least one timing sample")
    warm_samples = samples[1:] if len(samples) > 1 else samples
    return statistics.median(warm_samples)


async def measure_tool_call(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    validator: Any | None = None,
) -> tuple[float, Any]:
    start = time.perf_counter()
    text = await call_tool_text(session, tool_name, arguments)
    elapsed = time.perf_counter() - start
    return elapsed, validator(text) if validator else text


async def benchmark_repeated_tool_call(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    scenario: str,
    runs: int = 4,
    validator: Any | None = None,
) -> tuple[ToolTimingMetrics, list[Any]]:
    timings: list[float] = []
    results: list[Any] = []
    for _ in range(runs):
        elapsed, parsed = await measure_tool_call(
            session,
            tool_name,
            arguments,
            validator=validator,
        )
        timings.append(elapsed)
        results.append(parsed)

    return (
        ToolTimingMetrics(
            scenario=scenario,
            tool_name=tool_name,
            first_call_seconds=timings[0],
            warm_call_median_seconds=warm_call_median(timings),
            all_call_seconds=timings,
        ),
        results,
    )


async def list_project_programs(session: ClientSession) -> ProgramInfos:
    return await call_tool_model(session, "list_project_binaries", {}, ProgramInfos)


def resolve_program_name_by_path(program_infos: ProgramInfos, file_path: str | Path) -> str:
    target_path = Path(file_path).resolve()
    for program in program_infos.programs:
        if program.file_path and Path(program.file_path).resolve() == target_path:
            return program.name
    return PyGhidraContext._gen_unique_bin_name(target_path)


def _program_matches_target(
    program: PublicProgramInfo,
    *,
    binary_name: str | None,
    target_path: Path | None,
) -> bool:
    if binary_name and program.name == binary_name:
        return True
    if target_path and program.file_path and Path(program.file_path).resolve() == target_path:
        return True
    return False


def _program_is_ready(
    program: PublicProgramInfo,
    *,
    require_code_collection: bool,
    require_strings_collection: bool,
) -> bool:
    ready = program.analysis_complete
    if require_code_collection:
        ready = ready and program.code_collection
    if require_strings_collection:
        ready = ready and program.strings_collection
    return ready


async def wait_for_binary_readiness(
    session: ClientSession,
    *,
    file_path: str | Path | None = None,
    binary_name: str | None = None,
    require_code_collection: bool = False,
    require_strings_collection: bool = False,
    timeout_seconds: int = 120,
    poll_interval_seconds: float = 1.0,
) -> PublicProgramInfo:
    if file_path is None and binary_name is None:
        raise ValueError("Either file_path or binary_name is required")

    deadline = time.time() + timeout_seconds
    target_path = Path(file_path).resolve() if file_path is not None else None

    while True:
        program_infos = await list_project_programs(session)
        candidate = next(
            (
                program
                for program in program_infos.programs
                if _program_matches_target(
                    program,
                    binary_name=binary_name,
                    target_path=target_path,
                )
            ),
            None,
        )

        if candidate is not None and _program_is_ready(
            candidate,
            require_code_collection=require_code_collection,
            require_strings_collection=require_strings_collection,
        ):
            return candidate

        if time.time() > deadline:
            raise RuntimeError(
                f"Binary readiness timeout for {binary_name or file_path}. "
                f"Last seen state: {candidate}"
            )

        await asyncio.sleep(poll_interval_seconds)


async def wait_for_binaries_readiness(
    session: ClientSession,
    file_paths: list[str | Path],
    *,
    require_code_collection: bool = False,
    require_strings_collection: bool = False,
    timeout_seconds: int = 120,
    poll_interval_seconds: float = 1.0,
) -> dict[str, PublicProgramInfo]:
    deadline = time.time() + timeout_seconds
    targets = {str(Path(path).resolve()): Path(path).resolve() for path in file_paths}

    while True:
        program_infos = await list_project_programs(session)
        ready_programs: dict[str, PublicProgramInfo] = {}

        for raw_path, target_path in targets.items():
            for program in program_infos.programs:
                if program.file_path and Path(program.file_path).resolve() == target_path:
                    ready = program.analysis_complete
                    if require_code_collection:
                        ready = ready and program.code_collection
                    if require_strings_collection:
                        ready = ready and program.strings_collection
                    if ready:
                        ready_programs[raw_path] = program
                    break

        if len(ready_programs) == len(targets):
            return ready_programs

        if time.time() > deadline:
            raise RuntimeError(
                f"Binary readiness timeout for {sorted(targets)}. Ready: {sorted(ready_programs)}"
            )

        await asyncio.sleep(poll_interval_seconds)


def default_executable_entry_lookup() -> str:
    return "entry" if platform.system() == "Darwin" else "main"


def platform_function_name(name: str) -> str:
    return f"_{name}" if platform.system() == "Darwin" else name


def _compile_generated_c(source_path: Path, output_path: Path, *, shared: bool) -> Path:
    is_macos = platform.system() == "Darwin"
    compile_cmd = ["gcc", "-O0", "-fno-inline", "-fno-builtin"]
    if shared:
        compile_cmd.extend(["-dynamiclib"] if is_macos else ["-fPIC", "-shared"])
    compile_cmd.extend(["-o", str(output_path), str(source_path)])

    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        command_text = " ".join(compile_cmd)
        raise RuntimeError(f"Compilation failed: {command_text}\nSTDERR:\n{result.stderr}")

    return output_path


def _render_generated_c_source(spec: GeneratedBinarySpec, *, shared: bool) -> str:
    literal_mod = max(1, spec.function_count // max(1, spec.string_count))
    call_fanout = max(1, spec.call_fanout)
    exported_count = min(spec.exported_function_count, spec.function_count)
    shared_prefix = "EXPORT " if shared else ""

    lines = [
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "#if defined(__GNUC__)",
        "#define NOINLINE __attribute__((noinline))",
        "#define USED __attribute__((used))",
        '#define EXPORT __attribute__((visibility("default")))',
        "#else",
        "#define NOINLINE",
        "#define USED",
        "#define EXPORT",
        "#endif",
        "",
        "volatile int g_keepalive_sink = 0;",
        f"volatile int {spec.sentinel_symbol_stem} = 7;",
    ]

    for index in range(spec.global_count):
        lines.append(f"volatile int noise_global_{index:04d} = {index};")

    lines.extend(
        [
            "",
            "NOINLINE USED void record_side_effect(int value) {",
            "    g_keepalive_sink += value;",
            "}",
            "",
            "NOINLINE USED int allocate_and_measure(const char *text, int seed) {",
            "    size_t text_len = strlen(text);",
            "    char *buffer = (char *)malloc(text_len + 32);",
            "    if (!buffer) {",
            "        return seed;",
            "    }",
            '    snprintf(buffer, text_len + 32, "%s-%d", text, seed);',
            '    printf("%s\\n", buffer);',
            "    puts(buffer);",
            "    int result = (int)strlen(buffer);",
            "    free(buffer);",
            "    return result;",
            "}",
            "",
        ]
    )

    for index in range(spec.function_count):
        export_prefix = "EXPORT " if shared and index < exported_count else ""
        lines.append(f"{export_prefix}NOINLINE USED int noise_function_{index:04d}(int depth);")

    lines.extend(
        [
            f"{shared_prefix}NOINLINE USED int {spec.sentinel_function_stem}(int seed);",
            f"{shared_prefix}NOINLINE USED int {spec.sentinel_export_stem}(int seed);",
            "",
        ]
    )

    for index in range(spec.function_count):
        literal_text = (
            f"{spec.sentinel_code_literal} function {index:04d}"
            if index % literal_mod == 0
            else f"noise string {index:04d}"
        )
        next_calls = []
        for fanout_index in range(1, call_fanout + 1):
            target = index + fanout_index
            if target < spec.function_count:
                next_calls.append(
                    f"    total += noise_function_{target:04d}(depth + {fanout_index});"
                )

        lines.extend(
            [
                f"{('EXPORT ' if shared and index < exported_count else '')}"
                f"NOINLINE USED int noise_function_{index:04d}(int depth) {{",
                f'    const char *message = "{literal_text}";',
                f"    int total = noise_global_{index % max(1, spec.global_count):04d} + depth;",
                f"    total += allocate_and_measure(message, {index});",
                f"    record_side_effect(total + {spec.sentinel_symbol_stem});",
                *next_calls,
                "    return total;",
                "}",
                "",
            ]
        )

    lines.extend(
        [
            f"{shared_prefix}NOINLINE USED int {spec.sentinel_function_stem}(int seed) {{",
            f'    const char *message = "{spec.sentinel_string}";',
            "    int total = seed;",
            "    total += allocate_and_measure(message, seed);",
            (
                f"    total += noise_function_"
                f"{min(1, max(0, spec.function_count - 1)):04d}(seed + 1);"
            ),
            (
                f"    total += noise_function_"
                f"{min(5, max(0, spec.function_count - 1)):04d}(seed + 2);"
            ),
            (
                f"    total += noise_function_"
                f"{min(9, max(0, spec.function_count - 1)):04d}(seed + 3);"
            ),
            f"    record_side_effect(total + {spec.sentinel_symbol_stem});",
            "    return total;",
            "}",
            "",
            f"{shared_prefix}NOINLINE USED int {spec.sentinel_export_stem}(int seed) {{",
            f"    return {spec.sentinel_function_stem}(seed + 11);",
            "}",
            "",
        ]
    )

    if shared:
        lines.extend(
            [
                "NOINLINE USED int library_entry_point(void) {",
                f"    return {spec.sentinel_export_stem}(3);",
                "}",
            ]
        )
    else:
        lines.extend(
            [
                "int main(void) {",
                f"    return {spec.sentinel_function_stem}(5) == 0;",
                "}",
            ]
        )

    return "\n".join(lines) + "\n"


def build_generated_binary(
    output_dir: Path,
    spec: GeneratedBinarySpec,
    *,
    shared: bool,
) -> GeneratedBinaryArtifact:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_path = output_dir / f"{spec.stem}.c"
    binary_suffix = (
        ".dylib" if shared and platform.system() == "Darwin" else ".so" if shared else ""
    )
    binary_path = output_dir / f"{spec.stem}{binary_suffix}"
    source_path.write_text(_render_generated_c_source(spec, shared=shared))
    _compile_generated_c(source_path, binary_path, shared=shared)
    return GeneratedBinaryArtifact(binary_path=binary_path, source_path=source_path, spec=spec)


class FakeMcpTool:
    def __init__(self, name: str, description: str, input_schema: dict, output_schema: dict):
        self.name = name
        self.description = description
        self._payload = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "outputSchema": output_schema,
        }

    def model_dump(self, **_kwargs):
        return self._payload


class FakeCodeCollection:
    def __init__(self, documents: list[dict], query_results: list[dict] | None = None):
        self.documents = documents
        self.query_results = query_results or documents
        self.get_calls: list[dict] = []
        self.query_calls: list[dict] = []
        self.count_calls = 0

    def _matching_documents(self, where_document: dict | None) -> list[dict]:
        if not where_document:
            return self.documents
        needle = where_document.get("$contains", "")
        return [document for document in self.documents if needle in document["document"]]

    def get(
        self,
        ids=None,
        where=None,
        limit: int | None = None,
        offset: int | None = None,
        where_document: dict | None = None,
        include=("metadatas", "documents"),
    ) -> dict:
        include_list = list(include)
        self.get_calls.append(
            {
                "ids": ids,
                "where": where,
                "limit": limit,
                "offset": offset,
                "where_document": where_document,
                "include": include_list,
            }
        )
        matches = self._matching_documents(where_document)
        start = offset or 0
        end = None if limit is None else start + limit
        page = matches[start:end]
        result = {"ids": [item["id"] for item in page]}
        if "documents" in include_list:
            result["documents"] = [item["document"] for item in page]
        if "metadatas" in include_list:
            result["metadatas"] = [item["metadata"] for item in page]
        return result

    def query(
        self,
        query_texts=None,
        n_results: int = 10,
        where=None,
        where_document=None,
        include=("metadatas", "documents", "distances"),
    ) -> dict:
        include_list = list(include)
        self.query_calls.append(
            {
                "query_texts": query_texts,
                "n_results": n_results,
                "where": where,
                "where_document": where_document,
                "include": include_list,
            }
        )
        rows = self.query_results[:n_results]
        result = {"ids": [[row["id"] for row in rows]]}
        if "documents" in include_list:
            result["documents"] = [[row["document"] for row in rows]]
        if "metadatas" in include_list:
            result["metadatas"] = [[row["metadata"] for row in rows]]
        if "distances" in include_list:
            result["distances"] = [[row["distance"] for row in rows]]
        return result

    def count(self) -> int:
        self.count_calls += 1
        return len(self.documents)


class FakeReferenceManager:
    def __init__(self, references_by_address: dict[str, list[object]] | None = None):
        self.references_by_address = references_by_address or {}
        self.calls: list[str] = []

    def getReferencesTo(self, address: str):
        self.calls.append(address)
        return list(self.references_by_address.get(address, []))


class FakeSymbol:
    def __init__(
        self,
        name: str,
        address: str,
        *,
        symbol_type: str = "Function",
        namespace: str = "Global",
        source: str = "Analysis",
        external: bool = False,
        external_entry: bool = False,
    ):
        self.name = name
        self._address = address
        self._symbol_type = symbol_type
        self._namespace = namespace
        self._source = source
        self._external = external
        self._external_entry = external_entry

    def __hash__(self) -> int:
        return hash((self.name, self._address))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FakeSymbol):
            return False
        return (self.name, self._address) == (other.name, other._address)

    def getName(self, _include_namespace: bool = False) -> str:
        return self.name

    def getAddress(self) -> str:
        return self._address

    def getSymbolType(self) -> str:
        return self._symbol_type

    def getParentNamespace(self) -> str:
        return self._namespace

    def getSource(self) -> str:
        return self._source

    def isExternal(self) -> bool:
        return self._external

    def isExternalEntryPoint(self) -> bool:
        return self._external_entry


class FakeFunction:
    def __init__(self, symbol: FakeSymbol, entry_point: str, *, external: bool = False):
        self._symbol = symbol
        self._entry_point = entry_point
        self._external = external
        self.thunk = False

    def getSymbol(self) -> FakeSymbol:
        return self._symbol

    def getEntryPoint(self) -> str:
        return self._entry_point

    def getSignature(self) -> str:
        return f"{self._symbol.name}()"

    def isExternal(self) -> bool:
        return self._external


class FakeFunctionManager:
    def __init__(self, functions: list[FakeFunction]):
        self.functions = functions
        self.get_functions_calls = 0

    def getFunctions(self, _forward: bool):
        self.get_functions_calls += 1
        return list(self.functions)

    def getFunctionAt(self, address: str):
        for function in self.functions:
            if function.getEntryPoint() == address:
                return function
        return None


class FakeSymbolTable:
    def __init__(self, symbols: list[FakeSymbol], external_symbols: list[FakeSymbol] | None = None):
        self.symbols = symbols
        self.external_symbols = external_symbols or [
            symbol for symbol in symbols if symbol.isExternal()
        ]
        self.all_symbols_calls = 0
        self.external_symbols_calls = 0

    def getAllSymbols(self, _include_dynamic: bool):
        self.all_symbols_calls += 1
        return list(self.symbols)

    def getExternalSymbols(self):
        self.external_symbols_calls += 1
        return list(self.external_symbols)

    def getSymbols(self, address: str):
        return [symbol for symbol in self.symbols if symbol.getAddress() == address]


class FakeAddressFactory:
    def getAddress(self, value: str) -> str:
        return value


class FakeProgram:
    def __init__(
        self,
        *,
        symbols: list[FakeSymbol] | None = None,
        functions: list[FakeFunction] | None = None,
        external_symbols: list[FakeSymbol] | None = None,
        references_by_address: dict[str, list[object]] | None = None,
    ):
        self.symbol_table = FakeSymbolTable(symbols or [], external_symbols=external_symbols)
        self.function_manager = FakeFunctionManager(functions or [])
        self.reference_manager = FakeReferenceManager(references_by_address)
        self.address_factory = FakeAddressFactory()

    def getSymbolTable(self) -> FakeSymbolTable:
        return self.symbol_table

    def getFunctionManager(self) -> FakeFunctionManager:
        return self.function_manager

    def getReferenceManager(self) -> FakeReferenceManager:
        return self.reference_manager

    def getAddressFactory(self) -> FakeAddressFactory:
        return self.address_factory


def _install_legacy_ghidra_runtime_shims() -> None:
    """Install minimal ghidra modules needed by legacy benchmark code paths."""
    if "ghidra.program.model.symbol" in sys.modules:
        return

    ghidra_module = sys.modules.setdefault("ghidra", types.ModuleType("ghidra"))
    program_module = sys.modules.setdefault("ghidra.program", types.ModuleType("ghidra.program"))
    model_module = sys.modules.setdefault(
        "ghidra.program.model", types.ModuleType("ghidra.program.model")
    )
    symbol_module = sys.modules.setdefault(
        "ghidra.program.model.symbol", types.ModuleType("ghidra.program.model.symbol")
    )

    if not hasattr(symbol_module, "SymbolTable"):

        class SymbolTable:
            pass

        symbol_module.SymbolTable = SymbolTable  # type: ignore[attr-defined]

    ghidra_module.program = program_module  # type: ignore[attr-defined]
    program_module.model = model_module  # type: ignore[attr-defined]
    model_module.symbol = symbol_module  # type: ignore[attr-defined]


def make_runtime_program_info(
    *,
    program: FakeProgram | None = None,
    code_collection: FakeCodeCollection | None = None,
    strings_collection: FakeCodeCollection | None = None,
) -> RuntimeProgramInfo:
    dataclass_fields = getattr(RuntimeProgramInfo, "__dataclass_fields__", {})
    kwargs = {
        "name": "fake-bin",
        "program": program or FakeProgram(),
        "flat_api": None,
        "decompiler": SimpleNamespace(),
        "metadata": {},
        "ghidra_analysis_complete": True,
        "file_path": None,
        "load_time": None,
        "code_collection": code_collection,
        "strings_collection": strings_collection,
    }
    if "ghidra_tools" in dataclass_fields:
        kwargs["ghidra_tools"] = None
    if "derived_cache_version" in dataclass_fields:
        kwargs["derived_cache_version"] = 0
    return RuntimeProgramInfo(**kwargs)


def get_program_tools(program_info: RuntimeProgramInfo) -> GhidraTools:
    if hasattr(program_info, "get_tools"):
        return program_info.get_tools()

    _install_legacy_ghidra_runtime_shims()
    tools = getattr(program_info, "_benchmark_tools", None)
    if tools is None:
        tools = GhidraTools(program_info)
        program_info._benchmark_tools = tools  # type: ignore[attr-defined]
    return tools


def _build_code_documents(total: int = 512) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    documents = []
    query_results = []
    for index in range(total):
        function_name = f"match_func_{index:04d}"
        literal = "printf hot path" if index % 2 == 0 else "branch without literal match"
        document = f"{literal} block {index:04d} with extra text"
        row = {
            "id": function_name,
            "document": document,
            "metadata": {"function_name": function_name},
        }
        documents.append(row)
        query_results.append({**row, "distance": float(index) / 10.0})
    return documents, query_results


def _build_symbol_program(total: int = 512) -> FakeProgram:
    symbols = [
        FakeSymbol(f"match_symbol_{index:04d}", f"0x{index + 1:x}") for index in range(total)
    ]
    references = {
        symbol.getAddress(): [object() for _ in range((index % 4) + 1)]
        for index, symbol in enumerate(symbols)
    }
    return FakeProgram(symbols=symbols, references_by_address=references)


def _build_function_program(total: int = 512) -> FakeProgram:
    functions = []
    references = {}
    for index in range(total):
        address = f"0x{index + 16:x}"
        symbol = FakeSymbol(f"match_function_{index:04d}", address)
        functions.append(FakeFunction(symbol, address))
        references[address] = [object() for _ in range((index % 5) + 1)]
    return FakeProgram(functions=functions, references_by_address=references)


def _build_import_export_program(total: int = 256) -> FakeProgram:
    exports = [
        FakeSymbol(f"sentinel_export_{index:04d}", f"0x{index + 1:x}", external_entry=True)
        for index in range(total)
    ]
    helper_symbols = [
        FakeSymbol(f"helper_{index:04d}", f"0x{index + total + 1:x}") for index in range(total)
    ]
    imports = [
        FakeSymbol(
            f"printf_variant_{index:04d}",
            f"0x{index + (2 * total) + 1:x}",
            external=True,
            namespace="libc",
        )
        for index in range(total)
    ]
    return FakeProgram(symbols=exports + helper_symbols, external_symbols=imports)


def collect_internal_call_counts() -> dict[str, InternalCallCounts]:
    documents, query_results = _build_code_documents()

    semantic_collection = FakeCodeCollection(documents=documents, query_results=query_results)
    semantic_info = make_runtime_program_info(code_collection=semantic_collection)
    semantic_tools = get_program_tools(semantic_info)
    semantic_tools.search_code(
        query="printf",
        limit=25,
        offset=5,
        search_mode=SearchMode.SEMANTIC,
        include_full_code=False,
        preview_length=32,
        similarity_threshold=0.1,
    )
    semantic_tools.search_code(
        query="printf",
        limit=10,
        offset=0,
        search_mode=SearchMode.SEMANTIC,
    )

    literal_collection = FakeCodeCollection(documents=documents, query_results=query_results)
    literal_info = make_runtime_program_info(code_collection=literal_collection)
    literal_tools = get_program_tools(literal_info)
    literal_tools.search_code(
        query="printf",
        limit=20,
        offset=10,
        search_mode=SearchMode.LITERAL,
        include_full_code=False,
        preview_length=24,
    )

    symbol_program = _build_symbol_program()
    symbol_info = make_runtime_program_info(program=symbol_program)
    symbol_tools = get_program_tools(symbol_info)
    symbol_tools.search_symbols_by_name("match_symbol_", offset=200, limit=25)
    symbol_tools.search_symbols_by_name("match_symbol_", offset=0, limit=25)

    function_program = _build_function_program()
    function_info = make_runtime_program_info(program=function_program)
    function_tools = get_program_tools(function_info)
    function_tools.search_functions_by_name("match_function_", offset=200, limit=25)
    function_tools.search_functions_by_name("match_function_", offset=0, limit=25)

    import_export_program = _build_import_export_program()
    import_export_info = make_runtime_program_info(program=import_export_program)
    import_export_tools = get_program_tools(import_export_info)
    import_export_tools.list_exports(query="sentinel_export_", offset=0, limit=25)
    import_export_tools.list_exports(query="sentinel_export_", offset=25, limit=25)
    import_export_tools.list_imports(query="printf_variant_", offset=0, limit=25)
    import_export_tools.list_imports(query="printf_variant_", offset=25, limit=25)

    return {
        "search_code_semantic": InternalCallCounts(
            chroma_count_calls=semantic_collection.count_calls,
            chroma_get_calls=len(semantic_collection.get_calls),
            chroma_query_calls=len(semantic_collection.query_calls),
        ),
        "search_code_literal": InternalCallCounts(
            chroma_count_calls=literal_collection.count_calls,
            chroma_get_calls=len(literal_collection.get_calls),
            chroma_query_calls=len(literal_collection.query_calls),
        ),
        "search_symbols_by_name": InternalCallCounts(
            symbol_table_all_symbols_calls=symbol_program.symbol_table.all_symbols_calls,
            reference_lookup_calls=len(symbol_program.reference_manager.calls),
        ),
        "search_functions_by_name": InternalCallCounts(
            function_manager_get_functions_calls=function_program.function_manager.get_functions_calls,
            reference_lookup_calls=len(function_program.reference_manager.calls),
        ),
        "list_exports": InternalCallCounts(
            symbol_table_all_symbols_calls=import_export_program.symbol_table.all_symbols_calls,
        ),
        "list_imports": InternalCallCounts(
            symbol_table_external_symbols_calls=import_export_program.symbol_table.external_symbols_calls,
        ),
    }


def collect_internal_call_counts_json() -> str:
    counts = {
        scenario: metrics.to_dict() for scenario, metrics in collect_internal_call_counts().items()
    }
    return json.dumps(counts, sort_keys=True)


def validate_code_search_result(text: str) -> CodeSearchResults:
    return CodeSearchResults.model_validate_json(text)
