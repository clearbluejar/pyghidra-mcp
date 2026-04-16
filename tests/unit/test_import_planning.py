from pathlib import Path

import pyghidra_mcp.import_planning as import_planning


def test_build_import_plan_allows_raw_single_file_but_not_directory_children(monkeypatch, tmp_path):
    raw_file = tmp_path / "blob.bin"
    raw_file.write_bytes(b"\x00" * 32)
    nested_dir = tmp_path / "tree"
    nested_dir.mkdir()
    nested_raw = nested_dir / "nested.bin"
    nested_raw.write_bytes(b"\x00" * 32)

    def fake_is_ghidra_importable(path: Path, *, allow_binary_loader: bool = False) -> bool:
        return allow_binary_loader

    monkeypatch.setattr(import_planning, "is_ghidra_importable", fake_is_ghidra_importable)

    single_plan = import_planning.build_import_plan([raw_file])
    directory_plan = import_planning.build_import_plan([nested_dir])

    assert [candidate.path for candidate in single_plan.candidates] == [raw_file]
    assert single_plan.skipped == []

    assert directory_plan.candidates == []
    assert len(directory_plan.skipped) == 1
    assert directory_plan.skipped[0].path == nested_raw


def test_build_import_plan_skips_archives_even_for_single_file(tmp_path):
    archive = tmp_path / "payload.zip"
    archive.write_bytes(b"PK\x03\x04")

    plan = import_planning.build_import_plan([archive])

    assert plan.candidates == []
    assert len(plan.skipped) == 1
    assert plan.skipped[0].path == archive
    assert "archive/container" in plan.skipped[0].reason
