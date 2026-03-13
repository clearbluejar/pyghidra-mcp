import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ghidra_install_dir() -> str | None:
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_dir and Path(ghidra_dir).is_dir():
        return ghidra_dir
    fallback_dir = Path("/ghidra")
    if fallback_dir.is_dir():
        return str(fallback_dir)
    return None


def test_compare_snapshot_cli_smoke(tmp_path):
    ghidra_dir = _ghidra_install_dir()
    if ghidra_dir is None:
        pytest.skip("GHIDRA installation not found for benchmark smoke test")

    report_path = tmp_path / "compare-snapshot.json"
    env = os.environ.copy()
    env["GHIDRA_INSTALL_DIR"] = ghidra_dir

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.benchmarks.compare_snapshot",
            "--timing-runs",
            "1",
            "--json-out",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=1200,
    )

    if result.returncode != 0:
        stdout_tail = "\n".join(result.stdout.splitlines()[-80:])
        stderr_tail = "\n".join(result.stderr.splitlines()[-80:])
        pytest.fail(
            f"compare_snapshot failed\nSTDOUT tail:\n{stdout_tail}\n\nSTDERR tail:\n{stderr_tail}"
        )

    report = json.loads(report_path.read_text())

    assert report["baseline"]["label"] == "baseline"
    assert report["current"]["label"] == "current"
    assert "list_tools_payload_bytes" in report["delta"]
    assert "search_code_semantic" in report["delta"]["timings"]
    assert "search_symbols_by_name" in report["delta"]["internal_calls"]
