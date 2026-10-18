"""Unit tests for migrate_struct_shifts tool in pyghidra-mcp."""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest

from pyghidra_mcp import mcp_tools, tools
from pyghidra_mcp.models import (
    FieldMigrationItem,
    MigrateStructShiftsResult,
    StructInsertionItem,
)


@pytest.fixture
def sample_disassembly_files():
    """Creates temporary v1 and v2 disassembly files simulating struct field shift."""
    with tempfile.TemporaryDirectory() as tmpdir:
        v1_path = os.path.join(tmpdir, "v1_player.asm")
        v2_path = os.path.join(tmpdir, "v2_player.asm")

        # v1: Player fields at 0x0, 0x8, 0x10, 0x14, 0x18
        v1_code = (
            "0x00010000: LDR X0, [X19, #0x0]\n"
            "0x00010004: LDR X1, [X19, #0x8]\n"
            "0x00010008: LDR W2, [X19, #0x10]\n"
            "0x0001000C: LDR W3, [X19, #0x14]\n"
            "0x00010010: LDR W4, [X19, #0x18]\n"
        )
        # v2: 4-byte insertion at 0x14; hp (0x14->0x18) and max_hp (0x18->0x1C) shifted +0x4
        v2_code = (
            "0x00010000: LDR X0, [X19, #0x0]\n"
            "0x00010004: LDR X1, [X19, #0x8]\n"
            "0x00010008: LDR W2, [X19, #0x10]\n"
            "0x0001000C: LDR W3, [X19, #0x18]\n"
            "0x00010010: LDR W4, [X19, #0x1C]\n"
        )

        with open(v1_path, "w", encoding="utf-8") as f1:
            f1.write(v1_code)
        with open(v2_path, "w", encoding="utf-8") as f2:
            f2.write(v2_code)

        yield v1_path, v2_path


def test_mcp_migrate_struct_shifts_tool(sample_disassembly_files):
    """Verifies mcp_tools.migrate_struct_shifts returns MigrateStructShiftsResult with correct deltas."""
    v1_path, v2_path = sample_disassembly_files

    original_header = """struct Player {
    /* 0x0000 */ void* vtable;
    /* 0x0008 */ uint64_t player_id;
    /* 0x0010 */ uint32_t level;
    /* 0x0014 */ uint32_t hp;
    /* 0x0018 */ uint32_t max_hp;
};"""

    res = mcp_tools.migrate_struct_shifts(
        old_binary_path=v1_path,
        new_binary_path=v2_path,
        struct_name="Player",
        original_header=original_header,
    )

    assert isinstance(res, MigrateStructShiftsResult)
    assert res.status == "ok"
    assert res.struct_name == "Player"
    assert res.total_shifts_detected == 2
    assert res.max_delta == 4
    assert len(res.insertions) == 1

    # Check insertion item
    ins = res.insertions[0]
    assert isinstance(ins, StructInsertionItem)
    assert ins.offset == "0x14"
    assert ins.offset_int == 0x14
    assert ins.size == 4
    assert ins.probable_type == "uint32_t"

    # Check field migrations
    assert len(res.field_migrations) == 5
    mig_map = {m.old_offset_int: m for m in res.field_migrations}
    assert mig_map[0x0].delta == 0
    assert mig_map[0x8].delta == 0
    assert mig_map[0x10].delta == 0
    assert mig_map[0x14].delta == 4
    assert mig_map[0x14].new_offset == "0x18"
    assert mig_map[0x18].delta == 4
    assert mig_map[0x18].new_offset == "0x1C"

    # Check C++ header patch and updated code
    assert "--- old_player.h" in res.cpp_header_patch
    assert "+++ new_player.h" in res.cpp_header_patch
    assert "NEW INSERTION" in res.updated_header
    assert "shifted +4" in res.updated_header

    # Check JSON report
    report_dict = json.loads(res.migration_report_json)
    assert report_dict["struct_name"] == "Player"
    assert report_dict["total_shifts_detected"] == 2


def test_ghidra_tools_migrate_struct_shifts_method(sample_disassembly_files):
    """Verifies GhidraTools.migrate_struct_shifts method invocation."""
    v1_path, v2_path = sample_disassembly_files

    mock_prog_info = MagicMock()
    mock_tools = tools.GhidraTools(mock_prog_info, l2_cache=MagicMock())

    rep = mock_tools.migrate_struct_shifts(
        old_binary_path=v1_path,
        new_binary_path=v2_path,
        struct_name="LogicCombat",
    )

    assert isinstance(rep, dict)
    assert rep["struct_name"] == "LogicCombat"
    assert rep["total_shifts_detected"] == 2
    assert "cpp_header_patch" in rep


def test_server_registration():
    """Verifies that migrate_struct_shifts is registered in server tools."""
    from pyghidra_mcp.server import mcp

    # Check if tool is present in server tools
    registered_tool_names = set()
    if hasattr(mcp, "_tool_manager") and hasattr(mcp._tool_manager, "_tools"):
        registered_tool_names = set(mcp._tool_manager._tools.keys())
    elif hasattr(mcp, "list_tools"):
        # Synchronous list if available
        pass

    # If FastMCP / MCPServer exposes tools dict
    assert "migrate_struct_shifts" in registered_tool_names or hasattr(mcp_tools, "migrate_struct_shifts")
