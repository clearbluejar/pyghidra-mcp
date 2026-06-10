from pathlib import Path

import pytest

from pyghidra_mcp.header_import.ir import BuiltinType, FunctionType, NamedType, PointerType
from pyghidra_mcp.header_import.planning import (
    PlanningError,
    build_header_import_plan,
    build_header_import_plan_from_files,
    build_header_import_plan_from_source,
    translate_header_path,
)


def _write_header(path: Path, content: str) -> Path:
    path.write_text(content.strip() + "\n", encoding="utf-8")
    return path


def test_build_header_import_plan_parses_reviewed_header_dialect(tmp_path):
    header_path = _write_header(
        tmp_path / "types.h",
        """
        #pragma once
        #include <stdint.h>

        typedef uint64_t Word;

        /*
         * Intrusive list node.
         * size=0x10
         */
        typedef struct Node {
            /* 0x000 */ struct Node *next;
            /* 0x008 */ Word value;
        } Node;
        """,
    )

    plan = build_header_import_plan(header_path)

    assert not plan.has_errors(), plan.error_messages()
    assert plan.resolved_system_includes == ("stdint.h",)
    assert plan.resolved_local_includes == (header_path.resolve(),)
    assert plan.composite_order == ("Node",)

    typedef_word = next(definition for definition in plan.typedefs if definition.name == "Word")
    assert isinstance(typedef_word.target, BuiltinType)
    assert typedef_word.target.name == "uint64_t"

    node = next(definition for definition in plan.composites if definition.name == "Node")
    assert node.size == 0x10
    assert [field.name for field in node.fields] == ["next", "value"]
    assert [field.offset for field in node.fields] == [0x0, 0x8]
    assert isinstance(node.fields[0].type, PointerType)
    assert isinstance(node.fields[0].type.target, NamedType)
    assert node.fields[0].type.target.name == "Node"


def test_build_header_import_plan_resolves_local_includes_and_function_typedefs(tmp_path):
    shared_header = _write_header(
        tmp_path / "shared.h",
        """
        #pragma once

        struct Runtime;

        typedef int InterruptHandler(struct Runtime *rt, void *opaque);
        typedef int (*InterruptThunk)(struct Runtime *rt, void *opaque);
        """,
    )
    root_header = _write_header(
        tmp_path / "root.h",
        f"""
        #pragma once
        #include \"{shared_header.name}\"

        /* size=0x8 */
        typedef struct Runtime {{
            /* 0x000 */ InterruptHandler *handler;
        }} Runtime;
        """,
    )

    plan = build_header_import_plan(root_header)

    assert not plan.has_errors(), plan.error_messages()
    assert plan.resolved_local_includes == (shared_header.resolve(), root_header.resolve())

    by_name = {definition.name: definition for definition in plan.function_types}
    assert by_name["InterruptHandler"].pointer_alias is False
    assert by_name["InterruptThunk"].pointer_alias is True

    runtime = next(definition for definition in plan.composites if definition.name == "Runtime")
    assert runtime.size == 0x8
    assert runtime.fields[0].name == "handler"
    assert runtime.fields[0].offset == 0x0


def test_build_header_import_plan_reports_missing_include(tmp_path):
    header_path = _write_header(
        tmp_path / "broken.h",
        """
        #pragma once
        #include \"missing.h\"
        typedef int Count;
        """,
    )

    plan = build_header_import_plan(header_path)

    assert plan.has_errors()
    assert any("Missing local include 'missing.h'" in message for message in plan.error_messages())


def test_build_header_import_plan_handles_filesystem_include_cycles(tmp_path):
    a_header = tmp_path / "a.h"
    b_header = tmp_path / "b.h"
    _write_header(
        a_header,
        """
        #pragma once
        #include "b.h"
        typedef B A;
        """,
    )
    _write_header(
        b_header,
        """
        #pragma once
        #include "a.h"
        typedef int B;
        """,
    )

    plan = build_header_import_plan(a_header)

    assert not plan.has_errors(), plan.error_messages()
    assert plan.resolved_local_includes == (b_header.resolve(), a_header.resolve())
    assert [definition.name for definition in plan.typedefs] == ["B", "A"]
    assert any("Detected include cycle" in diagnostic.message for diagnostic in plan.diagnostics)


def test_build_header_import_plan_from_source_parses_root_header():
    plan = build_header_import_plan_from_source(
        """
        #pragma once
        #include <stdint.h>

        typedef uint32_t Word;

        /* size=0x8 */ typedef struct ApiNode { /* 0x000 */ Word value; } ApiNode;
        """.strip(),
        header_name="api_types.h",
    )

    assert not plan.has_errors(), plan.error_messages()
    assert plan.header_path == Path("api_types.h")
    assert plan.resolved_local_includes == (Path("api_types.h"),)
    assert plan.resolved_system_includes == ("stdint.h",)
    assert any(definition.name == "Word" for definition in plan.typedefs)
    assert plan.composite_order == ("ApiNode",)
    api_node = next(definition for definition in plan.composites if definition.name == "ApiNode")
    assert api_node.size == 0x8
    assert api_node.fields[0].offset == 0x0


def test_build_header_import_plan_from_source_resolves_include_files():
    plan = build_header_import_plan_from_source(
        """
        #pragma once
        #include "shared.h"
        typedef Count LocalCount;
        """.strip(),
        header_name="api/root.h",
        include_files={
            "api/shared.h": "typedef int Count;",
        },
    )

    assert not plan.has_errors(), plan.error_messages()
    assert plan.resolved_local_includes == (Path("api/shared.h"), Path("api/root.h"))
    assert [definition.name for definition in plan.typedefs] == ["Count", "LocalCount"]


def test_build_header_import_plan_from_source_handles_void_function_parameters():
    plan = build_header_import_plan_from_source(
        """
        typedef int Fn(void);
        typedef int (*FnPtr)(void);
        typedef int (*WithPointer)(void *opaque);
        """.strip(),
        header_name="callbacks.h",
    )

    assert not plan.has_errors(), plan.error_messages()
    by_name = {definition.name: definition for definition in plan.function_types}
    assert by_name["Fn"].signature.parameters == ()
    assert by_name["FnPtr"].pointer_alias is True
    assert by_name["FnPtr"].signature.parameters == ()
    assert isinstance(by_name["WithPointer"].signature, FunctionType)
    assert len(by_name["WithPointer"].signature.parameters) == 1
    assert by_name["WithPointer"].signature.parameters[0].name == "opaque"


def test_build_header_import_plan_from_source_rejects_include_next():
    plan = build_header_import_plan_from_source(
        """
        #include_next <stdint.h>
        typedef int Count;
        """.strip(),
        header_name="bad_directive.h",
    )

    assert plan.has_errors()
    assert any(
        "Unsupported preprocessor directive: #include_next" in message
        for message in plan.error_messages()
    )


def test_build_header_import_plan_from_files_uses_first_file_as_root():
    plan = build_header_import_plan_from_files(
        [
            {
                "name": "api/root.h",
                "content": '#include "shared.h"\ntypedef Count LocalCount;',
            },
            {
                "name": "api/shared.h",
                "content": "typedef int Count;",
            },
        ]
    )

    assert not plan.has_errors(), plan.error_messages()
    assert plan.header_path == Path("api/root.h")
    assert plan.resolved_local_includes == (Path("api/shared.h"), Path("api/root.h"))
    assert [definition.name for definition in plan.typedefs] == ["Count", "LocalCount"]


def test_build_header_import_plan_from_source_reports_missing_include():
    plan = build_header_import_plan_from_source(
        """
        #pragma once
        #include "missing.h"
        typedef int Count;
        """.strip(),
        header_name="broken.h",
    )

    assert plan.has_errors()
    assert any("Missing local include 'missing.h'" in message for message in plan.error_messages())


def test_translate_header_path_uses_longest_configured_prefix(monkeypatch, tmp_path):
    broad_root = tmp_path / "broad"
    narrow_root = tmp_path / "narrow"
    monkeypatch.setenv(
        "PYGHIDRA_MCP_HEADER_PATH_MAP",
        f"/container={broad_root},/container/work={narrow_root}",
    )

    translated = translate_header_path("/container/work/project/types.h")

    assert translated == str((narrow_root / "project/types.h").resolve())


def test_translate_header_path_rejects_mapped_escapes(monkeypatch, tmp_path):
    server_root = tmp_path / "host"
    monkeypatch.setenv("PYGHIDRA_MCP_HEADER_PATH_MAP", f"/container/work={server_root}")

    with pytest.raises(PlanningError, match="escapes configured server root"):
        translate_header_path("/container/work/../secret.h")


def test_build_header_import_plan_rejects_by_value_composite_cycles(tmp_path):
    header_path = _write_header(
        tmp_path / "cycle.h",
        """
        #pragma once

        /* size=0x8 */
        typedef struct A {
            /* 0x000 */ struct B value;
        } A;

        /* size=0x8 */
        typedef struct B {
            /* 0x000 */ A value;
        } B;
        """,
    )

    plan = build_header_import_plan(header_path)

    assert plan.has_errors()
    assert any("dependency cycle" in message for message in plan.error_messages())
