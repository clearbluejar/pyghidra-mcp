from __future__ import annotations

from dataclasses import dataclass

from pyghidra_mcp.header_import.ir import (
    ArrayType,
    BuiltinType,
    FunctionType,
    HeaderImportPlan,
    NamedType,
    PointerType,
)

CANONICAL_CATEGORY_ROOT = "/pyghidra_mcp/imported_headers"
INTERNAL_CATEGORY_ROOT = f"{CANONICAL_CATEGORY_ROOT}/__internal"


@dataclass(frozen=True)
class HeaderImportApplyResult:
    category_root: str
    created_types: tuple[str, ...]
    updated_types: tuple[str, ...]
    created_type_paths: tuple[str, ...] = ()
    updated_type_paths: tuple[str, ...] = ()


def apply_header_import_plan(program, plan: HeaderImportPlan) -> HeaderImportApplyResult:
    plan.raise_for_errors()

    from ghidra.program.model.data import (  # type: ignore
        ArrayDataType,
        ByteDataType,
        CategoryPath,
        CharDataType,
        DataTypeConflictHandler,
        DoubleDataType,
        EnumDataType,
        FloatDataType,
        FunctionDefinitionDataType,
        IntegerDataType,
        LongLongDataType,
        ParameterDefinitionImpl,
        PointerDataType,
        ShortDataType,
        StructureDataType,
        TypedefDataType,
        UnionDataType,
        UnsignedCharDataType,
        UnsignedIntegerDataType,
        UnsignedLongLongDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    dtm = program.getDataTypeManager()
    ptr_size = program.getDefaultPointerSize()
    root_category = CategoryPath(CANONICAL_CATEGORY_ROOT)
    internal_category = CategoryPath(INTERNAL_CATEGORY_ROOT)

    def pointer_to(data_type):
        return PointerDataType(data_type)

    def type_length(data_type):
        length = data_type.getLength()
        return ptr_size if length <= 0 else length

    def add_or_replace(data_type):
        return dtm.addDataType(data_type, DataTypeConflictHandler.REPLACE_HANDLER)

    builtin_factories = {
        "void": VoidDataType,
        "char": CharDataType,
        "bool": UnsignedCharDataType,
        "_Bool": UnsignedCharDataType,
        "unsigned char": UnsignedCharDataType,
        "uint8_t": UnsignedCharDataType,
        "signed char": ByteDataType,
        "int8_t": ByteDataType,
        "short": ShortDataType,
        "int16_t": ShortDataType,
        "unsigned short": UnsignedShortDataType,
        "uint16_t": UnsignedShortDataType,
        "int": IntegerDataType,
        "int32_t": IntegerDataType,
        "unsigned int": UnsignedIntegerDataType,
        "uint32_t": UnsignedIntegerDataType,
        "long long": LongLongDataType,
        "int64_t": LongLongDataType,
        "unsigned long long": UnsignedLongLongDataType,
        "uint64_t": UnsignedLongLongDataType,
        "float": FloatDataType,
        "double": DoubleDataType,
    }

    def long_double_data_type():
        try:
            from ghidra.program.model.data import LongDoubleDataType  # type: ignore
        except ImportError as exc:
            raise ValueError(
                "Builtin type 'long double' is not supported by this Ghidra runtime"
            ) from exc
        return LongDoubleDataType()

    def builtin_data_type(name: str):
        factory = builtin_factories.get(name)
        if factory is not None:
            return factory()
        if name in {"long", "ptrdiff_t", "intptr_t"}:
            return IntegerDataType() if ptr_size <= 4 else LongLongDataType()
        if name in {"unsigned long", "size_t", "uintptr_t"}:
            return UnsignedIntegerDataType() if ptr_size <= 4 else UnsignedLongLongDataType()
        if name == "long double":
            return long_double_data_type()
        raise KeyError(name)

    named_types: dict[str, object] = {}
    created_types: list[str] = []
    updated_types: list[str] = []
    created_type_paths: list[str] = []
    updated_type_paths: list[str] = []

    def resolve_type(type_expr):
        if isinstance(type_expr, BuiltinType):
            return builtin_data_type(type_expr.name)
        if isinstance(type_expr, NamedType):
            try:
                return named_types[type_expr.name]
            except KeyError as exc:
                raise ValueError(f"Unknown type reference '{type_expr.name}'") from exc
        if isinstance(type_expr, PointerType):
            return pointer_to(resolve_type(type_expr.target))
        if isinstance(type_expr, ArrayType):
            element_type = resolve_type(type_expr.element_type)
            return ArrayDataType(element_type, type_expr.count, type_length(element_type))
        if isinstance(type_expr, FunctionType):
            raise ValueError("Inline function types must be declared as named typedefs")
        raise TypeError(f"Unsupported type expression: {type_expr!r}")

    def existing_type(path: str) -> bool:
        return dtm.getDataType(path) is not None

    def record_added_type(name: str, data_type, existed: bool) -> None:
        path = str(data_type.getPathName())
        if existed:
            updated_types.append(name)
            updated_type_paths.append(path)
        else:
            created_types.append(name)
            created_type_paths.append(path)

    enum_defs = {}
    for enum_def in plan.enums:
        enum_data_type = EnumDataType(root_category, enum_def.name, enum_def.width)
        for member in enum_def.members:
            enum_data_type.add(member.name, member.value)
        enum_defs[enum_def.name] = enum_data_type
        named_types[enum_def.name] = enum_data_type

    function_defs = {}
    for function_def in plan.function_types:
        helper_name = function_def.name
        category = root_category
        if function_def.pointer_alias:
            helper_name = f"__fn_{function_def.name}"
            category = internal_category
        function_data_type = FunctionDefinitionDataType(category, helper_name)
        function_defs[function_def.name] = function_data_type
        if not function_def.pointer_alias:
            named_types[function_def.name] = function_data_type

    composite_defs = {}
    for composite in plan.composites:
        if composite.kind == "struct":
            structure = StructureDataType(root_category, composite.name, composite.size or 0)
            composite_defs[composite.name] = structure
            named_types[composite.name] = structure
        else:
            union = UnionDataType(root_category, composite.name)
            composite_defs[composite.name] = union
            named_types[composite.name] = union

    for function_def in plan.function_types:
        function_data_type = function_defs[function_def.name]
        function_data_type.setReturnType(resolve_type(function_def.signature.return_type))
        function_data_type.setArguments(
            [
                ParameterDefinitionImpl(param.name or f"arg{index}", resolve_type(param.type), "")
                for index, param in enumerate(function_def.signature.parameters)
            ]
        )
        if function_def.signature.variadic:
            function_data_type.setVarArgs(True)

    typedef_defs = {}
    for function_def in plan.function_types:
        if not function_def.pointer_alias:
            continue
        typedef_data_type = TypedefDataType(
            root_category,
            function_def.name,
            pointer_to(function_defs[function_def.name]),
        )
        typedef_defs[function_def.name] = typedef_data_type
        named_types[function_def.name] = typedef_data_type

    remaining_typedefs = list(plan.typedefs)
    while remaining_typedefs:
        progress = False
        unresolved = []
        for typedef in remaining_typedefs:
            try:
                target = resolve_type(typedef.target)
            except ValueError:
                unresolved.append(typedef)
                continue
            typedef_data_type = TypedefDataType(root_category, typedef.name, target)
            typedef_defs[typedef.name] = typedef_data_type
            named_types[typedef.name] = typedef_data_type
            progress = True
        if progress:
            remaining_typedefs = unresolved
            continue
        unresolved_names = ", ".join(sorted(typedef.name for typedef in unresolved))
        raise ValueError(f"Unable to resolve typedef dependencies: {unresolved_names}")

    for composite in plan.composites:
        data_type = composite_defs[composite.name]
        if isinstance(data_type, StructureDataType):
            for field in composite.fields:
                field_type = resolve_type(field.type)
                data_type.replaceAtOffset(
                    field.offset,
                    field_type,
                    type_length(field_type),
                    field.name,
                    field.comment,
                )
            continue
        if isinstance(data_type, UnionDataType):
            for field in composite.fields:
                if field.offset not in {0, None}:
                    raise ValueError(
                        f"Union field '{composite.name}.{field.name}' must have offset 0"
                    )
                field_type = resolve_type(field.type)
                data_type.add(field_type, field.name, field.comment)

    for enum_def in plan.enums:
        existed = existing_type(f"{CANONICAL_CATEGORY_ROOT}/{enum_def.name}")
        named = add_or_replace(enum_defs[enum_def.name])
        named_types[enum_def.name] = named
        record_added_type(enum_def.name, named, existed)

    for function_def in plan.function_types:
        expected_path = (
            f"{INTERNAL_CATEGORY_ROOT}/__fn_{function_def.name}"
            if function_def.pointer_alias
            else f"{CANONICAL_CATEGORY_ROOT}/{function_def.name}"
        )
        existed = existing_type(expected_path)
        named = add_or_replace(function_defs[function_def.name])
        function_defs[function_def.name] = named
        if not function_def.pointer_alias:
            named_types[function_def.name] = named
            record_added_type(function_def.name, named, existed)

    for composite_name in plan.composite_order:
        existed = existing_type(f"{CANONICAL_CATEGORY_ROOT}/{composite_name}")
        named = add_or_replace(composite_defs[composite_name])
        named_types[composite_name] = named
        record_added_type(composite_name, named, existed)

    for typedef_name, typedef_data_type in typedef_defs.items():
        existed = existing_type(f"{CANONICAL_CATEGORY_ROOT}/{typedef_name}")
        named = add_or_replace(typedef_data_type)
        named_types[typedef_name] = named
        record_added_type(typedef_name, named, existed)

    return HeaderImportApplyResult(
        category_root=CANONICAL_CATEGORY_ROOT,
        created_types=tuple(created_types),
        updated_types=tuple(updated_types),
        created_type_paths=tuple(created_type_paths),
        updated_type_paths=tuple(updated_type_paths),
    )
