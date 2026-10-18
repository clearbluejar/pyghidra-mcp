"""MCP tools backed by SuperGhidra's binary_loader and msvc_class_recovery."""

import os
import sys
from pathlib import Path

import pytest

from pyghidra_mcp import mcp_tools

SUPERGHIDRA = os.environ.get("SUPERGHIDRA_PATH") or str(Path(__file__).resolve().parents[3] / "SuperGhidra")
pytestmark = pytest.mark.skipif(not Path(SUPERGHIDRA, "binary_loader.py").exists(),
                                reason="SuperGhidra checkout with binary_loader.py not found")


@pytest.fixture
def mfc_dll(tmp_path):
    sys.path.insert(0, SUPERGHIDRA)
    try:
        from test_msvc_class_recovery import build_mfc_dll
    finally:
        sys.path.remove(SUPERGHIDRA)
    p = tmp_path / "feature.dll"
    p.write_bytes(build_mfc_dll())
    return p


@pytest.fixture
def export_dll(tmp_path):
    sys.path.insert(0, SUPERGHIDRA)
    try:
        from test_binary_loader import build_pe
    finally:
        sys.path.remove(SUPERGHIDRA)
    p = tmp_path / "demo.dll"
    p.write_bytes(build_pe(64)[0])
    return p


def test_inspect_binary_pe(export_dll):
    res = mcp_tools.inspect_binary(str(export_dll))
    assert (res.format, res.arch, res.bits, res.is_library) == ("pe", "x86_64", 64, True)
    assert {e["name"] for e in res.exports} >= {"FuncA", "FuncB"}
    assert res.total_imports == 2
    assert res.pdb_path == "C:\\build\\demo.pdb"


def test_inspect_binary_filter_and_limit(export_dll):
    res = mcp_tools.inspect_binary(str(export_dll), name_filter="funcb", limit=10)
    assert [e["name"] for e in res.exports] == ["FuncB"]
    assert res.total_exports == 3


def test_inspect_binary_missing_file(tmp_path):
    with pytest.raises(Exception):
        mcp_tools.inspect_binary(str(tmp_path / "nope.dll"))


@pytest.fixture
def serialize_dll(tmp_path):
    sys.path.insert(0, SUPERGHIDRA)
    try:
        from test_serialize_trace import build_serialize_dll, write_stream
    finally:
        sys.path.remove(SUPERGHIDRA)
    p = tmp_path / "point.dll"
    p.write_bytes(build_serialize_dll())
    return p, write_stream


def test_trace_serialize(serialize_dll):
    dll, _ = serialize_dll
    res = mcp_tools.trace_serialize(str(dll))
    assert res.total_traced == 1 and res.total_mirrored == 1
    t = res.traces[0]
    assert t["class"] == "CPoint3"
    assert [o["text"] for o in t["storing"]] == ["write u32 <- this+0x8", "write f64  [this+0x18 >= 0x5]"]


def test_decode_carchive(serialize_dll, tmp_path):
    import struct

    dll, write_stream = serialize_dll
    stream = tmp_path / "stream.bin"
    stream.write_bytes(write_stream([("CPoint3", 2, struct.pack("<I", 7)), ("CPoint3", 2, struct.pack("<I", 8))]))
    res = mcp_tools.decode_carchive(str(stream), [str(dll)])
    assert res.calibration["variable"] == "this+0x18" and res.env["this+0x18"] < 5
    assert res.stats["decoded"] == 2 and not res.gaps
    assert [f["value"] for o in res.objects for f in o["fields"]] == [7, 8]


def test_recover_cpp_classes(mfc_dll):
    res = mcp_tools.recover_cpp_classes(str(mfc_dll), serializable_only=True)
    assert res.total_serializable == 1
    cls = res.mfc_classes[0]
    assert cls["name"] == "CFeature"
    assert cls["schema"] == 3 and cls["versionable"] is True
    assert cls["serialize"] == hex(0x180000000 + 0x1020)
    assert res.rtti_classes[0]["name"] == "CFeature"
