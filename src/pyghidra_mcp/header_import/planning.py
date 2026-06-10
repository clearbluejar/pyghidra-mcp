from __future__ import annotations

import os
import posixpath
import re
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pyghidra_mcp.header_import.ir import (
    ArrayType,
    BuiltinType,
    CompositeDef,
    FieldDef,
    FunctionParam,
    FunctionType,
    FunctionTypeDef,
    HeaderImportPlan,
    NamedType,
    PlanBuilder,
    PointerType,
    TypedefDef,
)

SUPPORTED_SYSTEM_HEADERS = {
    "stdint.h": """
        typedef signed char int8_t;
        typedef short int16_t;
        typedef int int32_t;
        typedef long long int64_t;
        typedef unsigned char uint8_t;
        typedef unsigned short uint16_t;
        typedef unsigned int uint32_t;
        typedef unsigned long long uint64_t;
        typedef long long intptr_t;
        typedef unsigned long long uintptr_t;
    """,
    "stddef.h": """
        typedef unsigned long size_t;
        typedef long ptrdiff_t;
    """,
    "stdbool.h": "typedef unsigned char bool;",
    "stdarg.h": "typedef void *va_list;",
}

ALLOWED_PREPROCESSOR_DIRECTIVES = ("#include", "#pragma once")
BUILTIN_NAMES = {
    "_Bool",
    "bool",
    "char",
    "double",
    "float",
    "int",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "intptr_t",
    "long",
    "long double",
    "long long",
    "ptrdiff_t",
    "short",
    "signed char",
    "size_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uintptr_t",
    "unsigned char",
    "unsigned int",
    "unsigned long",
    "unsigned long long",
    "unsigned short",
    "void",
}

_INCLUDE_RE = re.compile(r'^\s*#include\s*([<"])([^">]+)[>"]')
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LAYOUT_START_RE = re.compile(
    r"^\s*(?:typedef\s+)?(?P<kind>struct|union)\s*(?P<tag>[A-Za-z_]\w*)?\s*\{\s*$"
)
_LAYOUT_END_RE = re.compile(r"^\s*\}\s*(?P<alias>[A-Za-z_]\w*)?\s*;\s*$")
_INLINE_LAYOUT_RE = re.compile(
    r"\b(?:typedef\s+)?(?P<kind>struct|union)\s*(?P<tag>[A-Za-z_]\w*)?\s*"
    r"\{(?P<body>.*?)\}\s*(?P<alias>[A-Za-z_]\w*)?\s*;"
)
_OFFSET_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/")
_SIZE_RE = re.compile(r"size=0x([0-9A-Fa-f]+)")


@dataclass(frozen=True)
class FieldLayout:
    offset: int
    comment: str = ""


@dataclass(frozen=True)
class CompositeLayout:
    size: int | None
    fields: tuple[FieldLayout, ...]


class PlanningError(ValueError):
    pass


def translate_header_path(header_path: str | Path) -> str:
    path_text = str(header_path)
    source_path = PurePosixPath(path_text)
    if not source_path.is_absolute():
        return path_text

    mappings = _header_path_mappings()
    if not mappings:
        return path_text

    selected: tuple[PurePosixPath, Path] | None = None
    for source_prefix, server_prefix in mappings:
        if source_path != source_prefix and source_prefix not in source_path.parents:
            continue
        if selected is None or len(source_prefix.parts) > len(selected[0].parts):
            selected = (source_prefix, server_prefix)

    if selected is None:
        return path_text

    source_prefix, server_prefix = selected
    relative_path = source_path.relative_to(source_prefix)
    server_root = server_prefix.expanduser().resolve()
    translated_path = (server_root / Path(*relative_path.parts)).resolve()
    try:
        translated_path.relative_to(server_root)
    except ValueError as exc:
        raise PlanningError(
            f"Mapped header path escapes configured server root: {path_text}"
        ) from exc
    return str(translated_path)


def _header_path_mappings() -> list[tuple[PurePosixPath, Path]]:
    mapping_text = os.environ.get("PYGHIDRA_MCP_HEADER_PATH_MAP", "")
    mappings: list[tuple[PurePosixPath, Path]] = []
    for entry in mapping_text.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "=" not in entry:
            raise PlanningError("Invalid PYGHIDRA_MCP_HEADER_PATH_MAP entry: missing '='")
        source_text, server_text = (part.strip() for part in entry.split("=", 1))
        source_prefix = PurePosixPath(source_text)
        server_prefix = Path(server_text).expanduser()
        if not source_prefix.is_absolute() or not server_prefix.is_absolute():
            raise PlanningError("PYGHIDRA_MCP_HEADER_PATH_MAP entries must use absolute paths")
        mappings.append((source_prefix, server_prefix))
    return mappings


def build_header_import_plan(header_path: str | Path) -> HeaderImportPlan:
    root = Path(header_path).expanduser().resolve()
    if not root.exists():
        raise PlanningError(f"Header file not found: {root}")
    if root.is_dir():
        raise PlanningError(f"Expected a file but received a directory: {root}")

    builder = PlanBuilder(header_path=root)
    local_sources: OrderedDict[Path, str] = OrderedDict()
    system_headers: list[str] = []
    _resolve_header_graph(root, builder, local_sources, system_headers, set())
    return _build_plan_from_local_sources(root, builder, local_sources, system_headers)


def build_header_import_plan_from_source(
    header_content: str,
    *,
    header_name: str = "input.h",
    include_files: dict[str, str] | None = None,
) -> HeaderImportPlan:
    root = _normalize_virtual_header_path(header_name or "input.h")
    sources: dict[Path, str] = {root: header_content}
    for include_name, include_content in (include_files or {}).items():
        sources[_normalize_virtual_header_path(include_name)] = include_content

    builder = PlanBuilder(header_path=root)
    local_sources: OrderedDict[Path, str] = OrderedDict()
    system_headers: list[str] = []
    _resolve_virtual_header_graph(root, sources, builder, local_sources, system_headers, set())
    return _build_plan_from_local_sources(root, builder, local_sources, system_headers)


def build_header_import_plan_from_files(header_files: list[dict[str, str]]) -> HeaderImportPlan:
    if not header_files:
        raise PlanningError("header_files must contain at least one file")

    root_file = header_files[0]
    root_name = _header_file_field(root_file, "name", 0)
    root_content = _header_file_field(root_file, "content", 0)
    include_files: dict[str, str] = {}
    seen_names = {_normalize_virtual_header_path(root_name)}

    for index, header_file in enumerate(header_files[1:], start=1):
        include_name = _header_file_field(header_file, "name", index)
        include_path = _normalize_virtual_header_path(include_name)
        if include_path in seen_names:
            raise PlanningError(f"Duplicate header file name in header_files: {include_name}")
        seen_names.add(include_path)
        include_files[include_name] = _header_file_field(header_file, "content", index)

    return build_header_import_plan_from_source(
        root_content,
        header_name=root_name,
        include_files=include_files,
    )


def _header_file_field(header_file: dict[str, str], field_name: str, index: int) -> str:
    value = header_file.get(field_name)
    if not isinstance(value, str) or not value:
        raise PlanningError(f"header_files[{index}] must include a non-empty '{field_name}' string")
    return value


def _build_plan_from_local_sources(
    root: Path,
    builder: PlanBuilder,
    local_sources: OrderedDict[Path, str],
    system_headers: list[str],
) -> HeaderImportPlan:
    synthetic_source, stub_line_count = _build_synthetic_translation_unit(
        local_sources, system_headers
    )

    try:
        from pycparser import c_ast, c_parser
    except ImportError as exc:  # pragma: no cover - dependency install failure
        raise PlanningError("pycparser is required to import reviewed headers") from exc

    parser = c_parser.CParser()
    try:
        ast = parser.parse(synthetic_source, filename=str(root))
    except Exception as exc:
        raise PlanningError(f"Failed to parse header import translation unit: {exc}") from exc

    layouts = _extract_layouts(local_sources)
    top_level_nodes = [ext for ext in ast.ext if getattr(ext.coord, "line", 0) > stub_line_count]
    tag_aliases = _collect_tag_aliases(top_level_nodes, c_ast)
    composites, enums, function_types, typedefs = _collect_definitions(
        top_level_nodes,
        layouts,
        tag_aliases,
        builder,
        c_ast,
    )
    _validate_named_references(composites, enums, function_types, typedefs, builder)
    composite_order = _order_composites(composites, enums, function_types, typedefs, builder)

    return HeaderImportPlan(
        header_path=root,
        resolved_local_includes=tuple(local_sources.keys()),
        resolved_system_includes=tuple(system_headers),
        composites=tuple(composites.values()),
        enums=tuple(enums.values()),
        function_types=tuple(function_types.values()),
        typedefs=tuple(typedefs.values()),
        composite_order=tuple(composite_order),
        diagnostics=tuple(builder.diagnostics),
    )


def _normalize_virtual_header_path(path: str) -> Path:
    normalized = posixpath.normpath(path.replace("\\", "/"))
    if normalized in ("", "."):
        normalized = "input.h"
    return Path(normalized)


def _resolve_header_graph(
    path: Path,
    builder: PlanBuilder,
    local_sources: OrderedDict[Path, str],
    system_headers: list[str],
    resolving: set[Path],
) -> None:
    if path in local_sources:
        return
    if path in resolving:
        builder.add_diagnostic(
            "warning",
            f"Detected include cycle involving {path}",
            str(path),
        )
        return

    text = path.read_text(encoding="utf-8")
    resolving.add(path)
    try:
        _validate_preprocessor_directives(path, text, builder)

        for delimiter, include_name in _scan_includes(text):
            if delimiter == '"':
                include_path = (path.parent / include_name).resolve()
                if not include_path.exists():
                    builder.add_diagnostic(
                        "error",
                        f"Missing local include '{include_name}'",
                        str(path),
                    )
                    continue
                _resolve_header_graph(
                    include_path, builder, local_sources, system_headers, resolving
                )
                continue

            if include_name not in SUPPORTED_SYSTEM_HEADERS:
                builder.add_diagnostic(
                    "error",
                    f"Unsupported system include '{include_name}'",
                    str(path),
                )
                continue
            if include_name not in system_headers:
                system_headers.append(include_name)
    finally:
        resolving.remove(path)

    local_sources[path] = text
    builder.local_includes.append(path)
    for include_name in system_headers:
        if include_name not in builder.system_includes:
            builder.system_includes.append(include_name)


def _resolve_virtual_header_graph(
    path: Path,
    sources: dict[Path, str],
    builder: PlanBuilder,
    local_sources: OrderedDict[Path, str],
    system_headers: list[str],
    resolving: set[Path],
) -> None:
    if path in local_sources or path in resolving:
        return

    text = sources[path]
    resolving.add(path)
    _validate_preprocessor_directives(path, text, builder)

    for delimiter, include_name in _scan_includes(text):
        if delimiter == '"':
            include_path = _normalize_virtual_header_path(str(path.parent / include_name))
            if include_path not in sources:
                builder.add_diagnostic(
                    "error",
                    f"Missing local include '{include_name}'",
                    str(path),
                )
                continue
            _resolve_virtual_header_graph(
                include_path,
                sources,
                builder,
                local_sources,
                system_headers,
                resolving,
            )
            continue

        if include_name not in SUPPORTED_SYSTEM_HEADERS:
            builder.add_diagnostic(
                "error",
                f"Unsupported system include '{include_name}'",
                str(path),
            )
            continue
        if include_name not in system_headers:
            system_headers.append(include_name)

    resolving.remove(path)
    local_sources[path] = text
    builder.local_includes.append(path)
    for include_name in system_headers:
        if include_name not in builder.system_includes:
            builder.system_includes.append(include_name)


def _validate_preprocessor_directives(path: Path, text: str, builder: PlanBuilder) -> None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        if _is_allowed_preprocessor_directive(stripped):
            continue
        builder.add_diagnostic(
            "error",
            f"Unsupported preprocessor directive: {stripped}",
            f"{path}:{line_number}",
        )


def _is_allowed_preprocessor_directive(stripped: str) -> bool:
    if stripped == "#pragma once":
        return True
    return _INCLUDE_RE.fullmatch(stripped) is not None


def _scan_includes(text: str) -> list[tuple[str, str]]:
    includes: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = _INCLUDE_RE.match(line)
        if not match:
            continue
        includes.append((match.group(1), match.group(2).strip()))
    return includes


def _build_synthetic_translation_unit(
    local_sources: OrderedDict[Path, str],
    system_headers: list[str],
) -> tuple[str, int]:
    system_sections = [
        SUPPORTED_SYSTEM_HEADERS[header_name].strip() for header_name in system_headers
    ]
    system_source = "\n\n".join(section for section in system_sections if section)
    local_source = "\n\n".join(
        _sanitize_source_for_parser(source) for source in local_sources.values()
    )

    if system_source and local_source:
        synthetic_source = f"{system_source}\n\n{local_source}"
    else:
        synthetic_source = system_source or local_source

    stub_lines = system_source.count("\n") + 1 if system_source else 0
    return synthetic_source, stub_lines


def _sanitize_source_for_parser(source: str) -> str:
    lines: list[str] = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#include") or stripped.startswith("#pragma once"):
            lines.append("")
            continue
        lines.append(line)
    return _strip_comments_preserving_lines("\n".join(lines))


def _strip_comments_preserving_lines(source: str) -> str:
    def replacer(match: re.Match[str]) -> str:
        text = match.group(0)
        newline_count = text.count("\n")
        if newline_count == 0:
            return " "
        return "\n" * newline_count

    return _COMMENT_RE.sub(replacer, source)


def _extract_layouts(local_sources: OrderedDict[Path, str]) -> dict[str, CompositeLayout]:
    layouts: dict[str, CompositeLayout] = {}
    for path, source in local_sources.items():
        per_file = _extract_file_layouts(path, source)
        for name, layout in per_file.items():
            layouts[name] = layout
    return layouts


def _extract_file_layouts(path: Path, source: str) -> dict[str, CompositeLayout]:
    layouts: dict[str, CompositeLayout] = {}
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        inline_layout = _extract_inline_layout(lines[index], path)
        if inline_layout is not None:
            name, layout = inline_layout
            layouts[name] = layout
            index += 1
            continue

        match = _LAYOUT_START_RE.match(lines[index])
        if not match:
            index += 1
            continue

        tag = match.group("tag")
        fields: list[FieldLayout] = []
        size = _extract_nearby_size(lines, index)
        end_index = index + 1
        alias: str | None = None
        while end_index < len(lines):
            end_match = _LAYOUT_END_RE.match(lines[end_index])
            if end_match:
                alias = end_match.group("alias")
                break
            offset_match = _OFFSET_RE.search(lines[end_index])
            if offset_match:
                comments = re.findall(r"/\*(.*?)\*/", lines[end_index])
                trailing_comment = comments[-1].strip() if len(comments) > 1 else ""
                fields.append(
                    FieldLayout(offset=int(offset_match.group(1), 16), comment=trailing_comment)
                )
            end_index += 1

        final_name = alias or tag
        if final_name:
            layouts[final_name] = CompositeLayout(size=size, fields=tuple(fields))
        else:
            raise PlanningError(f"Anonymous composite without typedef alias in {path}")
        index = end_index + 1
    return layouts


def _extract_inline_layout(line: str, path: Path) -> tuple[str, CompositeLayout] | None:
    match = _INLINE_LAYOUT_RE.search(line)
    if not match:
        return None

    final_name = match.group("alias") or match.group("tag")
    if not final_name:
        raise PlanningError(f"Anonymous composite without typedef alias in {path}")

    fields: list[FieldLayout] = []
    for field_text in match.group("body").split(";"):
        offset_match = _OFFSET_RE.search(field_text)
        if not offset_match:
            continue
        comments = re.findall(r"/\*(.*?)\*/", field_text)
        trailing_comment = comments[-1].strip() if len(comments) > 1 else ""
        fields.append(FieldLayout(offset=int(offset_match.group(1), 16), comment=trailing_comment))

    size_match = _SIZE_RE.search(line[: match.start()]) or _SIZE_RE.search(line)
    size = int(size_match.group(1), 16) if size_match else None
    return final_name, CompositeLayout(size=size, fields=tuple(fields))


def _extract_nearby_size(lines: list[str], index: int) -> int | None:
    window_start = max(0, index - 8)
    window = "\n".join(lines[window_start:index])
    match = _SIZE_RE.search(window)
    if not match:
        return None
    return int(match.group(1), 16)


def _collect_tag_aliases(top_level_nodes, c_ast) -> dict[tuple[str, str], str]:
    aliases: dict[tuple[str, str], str] = {}
    for node in top_level_nodes:
        if not isinstance(node, c_ast.Typedef):
            continue
        tagged = _named_tagged_type(node.type, c_ast)
        if not tagged:
            continue
        kind, tag_name, _has_body = tagged
        aliases[(kind, tag_name)] = node.name
    return aliases


def _collect_definitions(top_level_nodes, layouts, tag_aliases, builder, c_ast):
    composites: dict[str, CompositeDef] = {}
    enums: dict[str, object] = {}
    function_types: dict[str, FunctionTypeDef] = {}
    typedefs: dict[str, TypedefDef] = {}

    for node in top_level_nodes:
        if isinstance(node, c_ast.Typedef):
            _handle_typedef(
                node,
                layouts,
                tag_aliases,
                builder,
                composites,
                enums,
                function_types,
                typedefs,
                c_ast,
            )
            continue
        if isinstance(node, c_ast.Decl):
            _handle_decl(node, layouts, tag_aliases, builder, composites, enums, c_ast)
            continue

    return composites, enums, function_types, typedefs


def _handle_typedef(
    node,
    layouts,
    tag_aliases,
    builder,
    composites,
    enums,
    function_types,
    typedefs,
    c_ast,
) -> None:
    tagged = _named_tagged_type(node.type, c_ast)
    if tagged:
        kind, tag_name, has_body = tagged
        canonical_name = tag_aliases.get((kind, tag_name), node.name)
        if kind in {"struct", "union"}:
            if has_body:
                composite = _build_composite_def(
                    canonical_name,
                    _unwrap_named_tagged_type(node.type, c_ast),
                    layouts,
                    tag_aliases,
                    builder,
                    c_ast,
                )
                composites[canonical_name] = composite
            else:
                composites.setdefault(
                    canonical_name,
                    CompositeDef(kind=kind, name=canonical_name, fields=(), size=0, opaque=True),
                )
            if node.name != canonical_name:
                typedefs[node.name] = TypedefDef(name=node.name, target=NamedType(canonical_name))
            return
        if kind == "enum":
            enum_node = _unwrap_named_tagged_type(node.type, c_ast)
            if has_body:
                enum_def = _build_enum_def(canonical_name, enum_node, builder, c_ast)
                enums[canonical_name] = enum_def
            if node.name != canonical_name:
                typedefs[node.name] = TypedefDef(name=node.name, target=NamedType(canonical_name))
            return

    try:
        converted = _convert_type(node.type, tag_aliases, builder, c_ast)
    except PlanningError as exc:
        builder.add_diagnostic("error", str(exc), _coord(node))
        return

    if isinstance(converted, FunctionType):
        function_types[node.name] = FunctionTypeDef(name=node.name, signature=converted)
        return
    if isinstance(converted, PointerType) and isinstance(converted.target, FunctionType):
        function_types[node.name] = FunctionTypeDef(
            name=node.name,
            signature=converted.target,
            pointer_alias=True,
        )
        return
    typedefs[node.name] = TypedefDef(name=node.name, target=converted)


def _handle_decl(node, layouts, tag_aliases, builder, composites, enums, c_ast) -> None:
    if isinstance(node.type, c_ast.FuncDecl):
        return
    if isinstance(node.type, (c_ast.Struct, c_ast.Union)):
        try:
            composite = _build_declared_composite(node.type, layouts, tag_aliases, builder, c_ast)
        except PlanningError as exc:
            builder.add_diagnostic("error", str(exc), _coord(node))
            return
        composites[composite.name] = composite
        return
    if isinstance(node.type, c_ast.Enum) and node.type.values is not None:
        enum_name = tag_aliases.get(("enum", node.type.name), node.type.name)
        if enum_name is None:
            builder.add_diagnostic("error", "Anonymous enums are not supported", _coord(node))
            return
        enums[enum_name] = _build_enum_def(enum_name, node.type, builder, c_ast)


def _build_declared_composite(node, layouts, tag_aliases, builder, c_ast) -> CompositeDef:
    if node.name is None:
        raise PlanningError("Anonymous composite declarations are not supported")
    kind = _composite_kind(node)
    canonical_name = tag_aliases.get((kind, node.name), node.name)
    if node.decls is None:
        return CompositeDef(kind=kind, name=canonical_name, fields=(), size=0, opaque=True)
    return _build_composite_def(canonical_name, node, layouts, tag_aliases, builder, c_ast)


def _build_composite_def(name, node, layouts, tag_aliases, builder, c_ast) -> CompositeDef:
    layout = layouts.get(name)
    if layout is None:
        builder.add_diagnostic(
            "error",
            f"Missing layout metadata for composite '{name}'",
            _coord(node),
        )
        layout = CompositeLayout(size=None, fields=())

    if node.decls is None:
        return CompositeDef(
            kind=_composite_kind(node), name=name, fields=(), size=layout.size, opaque=True
        )

    if len(layout.fields) not in {0, len(node.decls)}:
        builder.add_diagnostic(
            "error",
            (
                f"Field count mismatch for composite '{name}': "
                f"expected {len(node.decls)} offsets, found {len(layout.fields)}"
            ),
            _coord(node),
        )

    fields: list[FieldDef] = []
    for index, decl in enumerate(node.decls):
        if decl.bitsize is not None:
            builder.add_diagnostic("error", "Bitfields are not supported", _coord(decl))
            continue
        if decl.name is None:
            builder.add_diagnostic(
                "error",
                f"Anonymous fields are not supported in '{name}'",
                _coord(decl),
            )
            continue
        try:
            field_type = _convert_type(decl.type, tag_aliases, builder, c_ast)
        except PlanningError as exc:
            builder.add_diagnostic("error", str(exc), _coord(decl))
            continue
        if index < len(layout.fields):
            offset = layout.fields[index].offset
            comment = layout.fields[index].comment
        else:
            offset = 0
            comment = ""
            builder.add_diagnostic(
                "error",
                f"Missing explicit offset comment for field '{decl.name}' in '{name}'",
                _coord(decl),
            )
        fields.append(FieldDef(name=decl.name, type=field_type, offset=offset, comment=comment))

    return CompositeDef(
        kind=_composite_kind(node),
        name=name,
        fields=tuple(fields),
        size=layout.size,
    )


def _build_enum_def(name, node, builder, c_ast):
    members = []
    next_value = 0
    for enumerator in node.values.enumerators:
        if enumerator.value is None:
            value = next_value
        else:
            try:
                value = _evaluate_integer_constant(enumerator.value, builder, c_ast)
            except PlanningError as exc:
                builder.add_diagnostic("error", str(exc), _coord(enumerator))
                value = next_value
        members.append((enumerator.name, value))
        next_value = value + 1

    from pyghidra_mcp.header_import.ir import EnumDef, EnumMember

    return EnumDef(
        name=name, members=tuple(EnumMember(member_name, value) for member_name, value in members)
    )


def _evaluate_integer_constant(node, builder, c_ast) -> int:
    if isinstance(node, c_ast.Constant):
        if node.type != "int":
            raise PlanningError(f"Unsupported enum constant type '{node.type}'")
        return int(node.value, 0)
    if isinstance(node, c_ast.UnaryOp) and node.op in {"+", "-"}:
        value = _evaluate_integer_constant(node.expr, builder, c_ast)
        return value if node.op == "+" else -value
    raise PlanningError("Only integer enum constants are supported")


def _convert_type(node, tag_aliases, builder, c_ast):
    if isinstance(node, c_ast.TypeDecl):
        return _convert_type_decl(node, tag_aliases, builder, c_ast)
    if isinstance(node, c_ast.PtrDecl):
        return PointerType(_convert_type(node.type, tag_aliases, builder, c_ast))
    if isinstance(node, c_ast.ArrayDecl):
        if node.dim is None:
            raise PlanningError("Flexible array members are not supported")
        count = _evaluate_array_size(node.dim, c_ast)
        return ArrayType(
            element_type=_convert_type(node.type, tag_aliases, builder, c_ast),
            count=count,
        )
    if isinstance(node, c_ast.FuncDecl):
        params: list[FunctionParam] = []
        variadic = False
        args = node.args.params if node.args and node.args.params else []
        for param in args:
            if isinstance(param, c_ast.EllipsisParam):
                variadic = True
                continue
            param_type = _convert_type(param.type, tag_aliases, builder, c_ast)
            if len(args) == 1 and param.name is None and param_type == BuiltinType("void"):
                continue
            params.append(
                FunctionParam(
                    name=param.name,
                    type=param_type,
                )
            )
        return FunctionType(
            return_type=_convert_type(node.type, tag_aliases, builder, c_ast),
            parameters=tuple(params),
            variadic=variadic,
        )
    raise PlanningError(f"Unsupported declaration node: {type(node).__name__}")


def _convert_type_decl(node, tag_aliases, builder, c_ast):
    inner = node.type
    if isinstance(inner, c_ast.IdentifierType):
        name = " ".join(inner.names)
        if name in BUILTIN_NAMES:
            return BuiltinType(name)
        return NamedType(name)
    if isinstance(inner, c_ast.Struct):
        return _convert_tag_reference(inner, "struct", tag_aliases)
    if isinstance(inner, c_ast.Union):
        return _convert_tag_reference(inner, "union", tag_aliases)
    if isinstance(inner, c_ast.Enum):
        if inner.name is None:
            raise PlanningError("Anonymous enums are not supported")
        return NamedType(tag_aliases.get(("enum", inner.name), inner.name))
    raise PlanningError(f"Unsupported type declaration node: {type(inner).__name__}")


def _convert_tag_reference(node, kind: str, tag_aliases):
    if node.name is None:
        raise PlanningError("Anonymous composites are not supported")
    return NamedType(tag_aliases.get((kind, node.name), node.name))


def _evaluate_array_size(node, c_ast) -> int:
    if isinstance(node, c_ast.Constant) and node.type == "int":
        return int(node.value, 0)
    raise PlanningError("Only fixed integer array sizes are supported")


def _named_tagged_type(node, c_ast):
    candidate = _unwrap_named_tagged_type(node, c_ast)
    if candidate is None or candidate.name is None:
        return None
    if isinstance(candidate, c_ast.Struct):
        return ("struct", candidate.name, candidate.decls is not None)
    if isinstance(candidate, c_ast.Union):
        return ("union", candidate.name, candidate.decls is not None)
    if isinstance(candidate, c_ast.Enum):
        return ("enum", candidate.name, candidate.values is not None)
    return None


def _unwrap_named_tagged_type(node, c_ast):
    current = node
    while isinstance(current, c_ast.TypeDecl):
        current = current.type
    if isinstance(current, (c_ast.Struct, c_ast.Union, c_ast.Enum)):
        return current
    return None


def _composite_kind(node) -> str:
    return "union" if node.__class__.__name__ == "Union" else "struct"


def _validate_named_references(composites, enums, function_types, typedefs, builder) -> None:
    known_names = set(BUILTIN_NAMES)
    known_names.update(composites)
    known_names.update(enums)
    known_names.update(function_types)
    known_names.update(typedefs)

    def validate_type(type_expr, location: str) -> None:
        if isinstance(type_expr, BuiltinType):
            return
        if isinstance(type_expr, NamedType):
            if type_expr.name not in known_names:
                builder.add_diagnostic(
                    "error",
                    f"Unknown referenced type '{type_expr.name}'",
                    location,
                )
            return
        if isinstance(type_expr, PointerType):
            validate_type(type_expr.target, location)
            return
        if isinstance(type_expr, ArrayType):
            validate_type(type_expr.element_type, location)
            return
        if isinstance(type_expr, FunctionType):
            validate_type(type_expr.return_type, location)
            for parameter in type_expr.parameters:
                validate_type(parameter.type, location)

    for composite in composites.values():
        for field in composite.fields:
            validate_type(field.type, f"{builder.header_path}:{composite.name}.{field.name}")
    for function_def in function_types.values():
        validate_type(function_def.signature, f"{builder.header_path}:{function_def.name}")
    for typedef in typedefs.values():
        validate_type(typedef.target, f"{builder.header_path}:{typedef.name}")


def _order_composites(composites, enums, function_types, typedefs, builder) -> list[str]:
    composite_names = set(composites)

    def hard_dependencies(type_expr) -> set[str]:
        if isinstance(type_expr, BuiltinType):
            return set()
        if isinstance(type_expr, NamedType):
            target_name = type_expr.name
            if target_name in composite_names:
                return {target_name}
            if target_name in enums or target_name in function_types:
                return set()
            if target_name in typedefs:
                return hard_dependencies(typedefs[target_name].target)
            return set()
        if isinstance(type_expr, PointerType):
            return set()
        if isinstance(type_expr, ArrayType):
            return hard_dependencies(type_expr.element_type)
        if isinstance(type_expr, FunctionType):
            deps = hard_dependencies(type_expr.return_type)
            for parameter in type_expr.parameters:
                deps.update(hard_dependencies(parameter.type))
            return deps
        return set()

    dependency_map: dict[str, set[str]] = {}
    for name, composite in composites.items():
        deps: set[str] = set()
        for field in composite.fields:
            deps.update(hard_dependencies(field.type))
        deps.discard(name)
        dependency_map[name] = deps

    ordered: list[str] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(name: str) -> None:
        if name in permanent:
            return
        if name in temporary:
            builder.add_diagnostic(
                "error",
                f"Detected by-value composite dependency cycle involving '{name}'",
                str(builder.header_path),
            )
            return
        temporary.add(name)
        for dependency in sorted(dependency_map.get(name, set())):
            visit(dependency)
        temporary.remove(name)
        permanent.add(name)
        ordered.append(name)

    for name in sorted(composites):
        visit(name)
    return ordered


def _coord(node) -> str | None:
    coord = getattr(node, "coord", None)
    return None if coord is None else str(coord)
