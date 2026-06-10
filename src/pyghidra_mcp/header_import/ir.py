from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Severity = Literal["error", "warning"]
CompositeKind = Literal["struct", "union"]


@dataclass(frozen=True)
class Diagnostic:
    severity: Severity
    message: str
    location: str | None = None


class TypeExpr:
    """Base class for normalized C type expressions."""


@dataclass(frozen=True)
class BuiltinType(TypeExpr):
    name: str


@dataclass(frozen=True)
class NamedType(TypeExpr):
    name: str


@dataclass(frozen=True)
class PointerType(TypeExpr):
    target: TypeExpr


@dataclass(frozen=True)
class ArrayType(TypeExpr):
    element_type: TypeExpr
    count: int


@dataclass(frozen=True)
class FunctionParam:
    name: str | None
    type: TypeExpr


@dataclass(frozen=True)
class FunctionType(TypeExpr):
    return_type: TypeExpr
    parameters: tuple[FunctionParam, ...] = ()
    variadic: bool = False


@dataclass(frozen=True)
class FieldDef:
    name: str
    type: TypeExpr
    offset: int
    comment: str = ""


@dataclass(frozen=True)
class CompositeDef:
    kind: CompositeKind
    name: str
    fields: tuple[FieldDef, ...]
    size: int | None = None
    comment: str = ""
    opaque: bool = False


@dataclass(frozen=True)
class EnumMember:
    name: str
    value: int


@dataclass(frozen=True)
class EnumDef:
    name: str
    members: tuple[EnumMember, ...]
    width: int = 4


@dataclass(frozen=True)
class FunctionTypeDef:
    name: str
    signature: FunctionType
    pointer_alias: bool = False


@dataclass(frozen=True)
class TypedefDef:
    name: str
    target: TypeExpr


@dataclass(frozen=True)
class HeaderImportPlan:
    header_path: Path
    resolved_local_includes: tuple[Path, ...] = ()
    resolved_system_includes: tuple[str, ...] = ()
    composites: tuple[CompositeDef, ...] = ()
    enums: tuple[EnumDef, ...] = ()
    function_types: tuple[FunctionTypeDef, ...] = ()
    typedefs: tuple[TypedefDef, ...] = ()
    composite_order: tuple[str, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()

    def has_errors(self) -> bool:
        return any(d.severity == "error" for d in self.diagnostics)

    def error_messages(self) -> list[str]:
        messages = []
        for diagnostic in self.diagnostics:
            if diagnostic.severity != "error":
                continue
            if diagnostic.location:
                messages.append(f"{diagnostic.location}: {diagnostic.message}")
            else:
                messages.append(diagnostic.message)
        return messages

    def raise_for_errors(self) -> None:
        errors = self.error_messages()
        if errors:
            raise ValueError("; ".join(errors))

    @property
    def definition_names(self) -> tuple[str, ...]:
        names = [definition.name for definition in self.composites]
        names.extend(definition.name for definition in self.enums)
        names.extend(definition.name for definition in self.function_types)
        names.extend(definition.name for definition in self.typedefs)
        return tuple(names)


def describe_type(type_expr: TypeExpr) -> str:
    if isinstance(type_expr, BuiltinType):
        return type_expr.name
    if isinstance(type_expr, NamedType):
        return type_expr.name
    if isinstance(type_expr, PointerType):
        return f"{describe_type(type_expr.target)} *"
    if isinstance(type_expr, ArrayType):
        return f"{describe_type(type_expr.element_type)}[{type_expr.count}]"
    if isinstance(type_expr, FunctionType):
        parts = [describe_type(param.type) for param in type_expr.parameters]
        if type_expr.variadic:
            parts.append("...")
        return f"{describe_type(type_expr.return_type)} ({', '.join(parts)})"
    raise TypeError(f"Unsupported type expression: {type_expr!r}")


def iter_named_references(type_expr: TypeExpr, *, through_pointers: bool = True) -> list[str]:
    if isinstance(type_expr, BuiltinType):
        return []
    if isinstance(type_expr, NamedType):
        return [type_expr.name]
    if isinstance(type_expr, PointerType):
        if not through_pointers:
            return []
        return iter_named_references(type_expr.target, through_pointers=through_pointers)
    if isinstance(type_expr, ArrayType):
        return iter_named_references(type_expr.element_type, through_pointers=through_pointers)
    if isinstance(type_expr, FunctionType):
        refs = iter_named_references(type_expr.return_type, through_pointers=through_pointers)
        for parameter in type_expr.parameters:
            refs.extend(iter_named_references(parameter.type, through_pointers=through_pointers))
        return refs
    raise TypeError(f"Unsupported type expression: {type_expr!r}")


@dataclass
class PlanBuilder:
    header_path: Path
    local_includes: list[Path] = field(default_factory=list)
    system_includes: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def add_diagnostic(
        self,
        severity: Severity,
        message: str,
        location: str | None = None,
    ) -> None:
        self.diagnostics.append(Diagnostic(severity=severity, message=message, location=location))
