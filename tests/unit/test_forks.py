import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import click
import pytest

import pyghidra_mcp.server as server
from pyghidra_mcp import forks, mcp_tools
from pyghidra_mcp.project_spec import ProjectSpec


def _make_parent_project(tmp_path: Path, name: str = "proj") -> ProjectSpec:
    spec = ProjectSpec.from_cli(tmp_path / "projects", name)
    spec.project_directory.mkdir(parents=True)
    spec.gpr_path.write_text("")
    rep = spec.project_directory / f"{name}.rep"
    (rep / "idata").mkdir(parents=True)
    (rep / "idata" / "~index.dat").write_text("VERSION=1\n")
    (rep / "project.prp").write_text("<props/>")
    (spec.project_directory / f"{name}.lock").write_text("held")
    (spec.pyghidra_mcp_dir / "chromadb").mkdir(parents=True)
    (spec.pyghidra_mcp_dir / "chromadb" / "chroma.sqlite3").write_bytes(b"db")
    return spec


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _stop(fork: forks.ForkSession, *, closed: bool = True) -> None:
    """Make a fork look like its server has gone away."""
    meta_path = fork.fork_dir / forks.FORK_META_FILE
    meta = json.loads(meta_path.read_text())
    meta["pid"] = _dead_pid()
    meta["status"] = "closed" if closed else "active"
    meta_path.write_text(json.dumps(meta))


# Fork creation and journaling
# ---------------------------------------------------------------------------------


def test_create_fork_clones_project_without_locks_and_seeds_index(tmp_path):
    parent = _make_parent_project(tmp_path)

    fork = forks.create_fork(parent, label="agent b!")

    assert fork.fork_dir.parent == parent.pyghidra_mcp_dir / "forks"
    assert "agent_b" in fork.fork_id
    spec = fork.project_spec
    assert spec.gpr_path.is_file()
    assert (spec.project_directory / "proj.rep" / "idata" / "~index.dat").is_file()
    assert not (spec.project_directory / "proj.lock").exists()
    assert (spec.pyghidra_mcp_dir / "chromadb" / "chroma.sqlite3").read_bytes() == b"db"

    meta = json.loads((fork.fork_dir / forks.FORK_META_FILE).read_text())
    assert meta["status"] == "active"
    assert meta["pid"] == os.getpid()
    assert meta["parent_project"] == str(parent.gpr_path.absolute())


def test_create_fork_can_skip_index_seed(tmp_path):
    parent = _make_parent_project(tmp_path)
    fork = forks.create_fork(parent, seed_index=False)
    assert not (fork.project_spec.pyghidra_mcp_dir / "chromadb").exists()


def test_journal_records_are_sequenced_and_survive_reload(tmp_path):
    fork = forks.create_fork(_make_parent_project(tmp_path))

    fork.record("rename_function", "/bin-abc123", address="1000", old="FUN_1000", new="main")
    fork.record("set_comment", "/bin-abc123", address="1000", comment_type="eol", new="x")
    with open(fork.fork_dir / forks.JOURNAL_FILE, "a") as f:
        f.write('{"seq": 3, "op": "rename_fun')  # torn write still in progress

    entries = forks.read_journal(fork.fork_dir)
    assert [e["seq"] for e in entries] == [1, 2]
    assert entries[0]["new"] == "main"

    reloaded = forks.ForkSession.load(fork.fork_dir)
    assert reloaded.op_count == 2
    assert reloaded.record("rename_function", "/b", address="2", old="a", new="b")["seq"] == 3


def test_list_forks_reports_liveness_and_pending_edits(tmp_path):
    parent = _make_parent_project(tmp_path)
    running = forks.create_fork(parent, label="running")
    stopped = forks.create_fork(parent, label="stopped")
    stopped.record("rename_function", "/b", address="1", old="a", new="b")
    stopped.record("rename_function", "/b", address="2", old="c", new="d")
    (stopped.fork_dir / forks.MERGE_STATE_FILE).write_text(
        json.dumps({"resolved": {"1": "applied"}})
    )
    _stop(stopped, closed=False)

    by_label = {info["label"]: info for info in forks.list_forks(parent.pyghidra_mcp_dir)}

    assert by_label["running"]["alive"] is True
    assert by_label["running"]["fork_id"] == running.fork_id
    assert by_label["stopped"]["alive"] is False
    assert by_label["stopped"]["journal_ops"] == 2
    assert by_label["stopped"]["resolved_ops"] == 1
    assert by_label["stopped"]["pending_ops"] == 1


def test_pid_alive_distinguishes_running_and_exited_processes():
    assert forks.pid_alive(os.getpid()) is True
    assert forks.pid_alive(_dead_pid()) is False
    assert forks.pid_alive(None) is False


def test_find_reusable_fork_prefers_stopped_fork_with_pending_edits(tmp_path):
    parent = _make_parent_project(tmp_path)
    empty = forks.create_fork(parent, label="hermes")
    _stop(empty)
    pending = forks.create_fork(parent, label="hermes")
    pending.record("rename_function", "/b", address="1", old="a", new="b")
    _stop(pending)
    other = forks.create_fork(parent, label="claude")
    other.record("rename_function", "/b", address="1", old="a", new="b")
    _stop(other)

    reused = forks.find_reusable_fork(parent, "hermes")

    assert reused is not None
    assert reused.fork_id == pending.fork_id
    assert reused.op_count == 1
    assert forks.find_reusable_fork(parent, None) is None
    assert forks.find_reusable_fork(parent, "nobody") is None


def test_resolve_fork_dir_rejects_unknown_and_escaping_ids(tmp_path):
    parent = _make_parent_project(tmp_path)
    forks.create_fork(parent)

    with pytest.raises(ValueError, match="not found"):
        forks.resolve_fork_dir(parent.pyghidra_mcp_dir, "nope")
    with pytest.raises(ValueError, match="not found"):
        forks.resolve_fork_dir(parent.pyghidra_mcp_dir, "../../projects")


def test_discard_fork_refuses_running_forks_and_deletes_stopped_ones(tmp_path):
    parent = _make_parent_project(tmp_path)
    fork = forks.create_fork(parent)

    with pytest.raises(ValueError, match="still be in use"):
        forks.discard_fork(parent.pyghidra_mcp_dir, fork.fork_id)

    _stop(fork)
    forks.discard_fork(parent.pyghidra_mcp_dir, fork.fork_id)
    assert not fork.fork_dir.exists()


# Merge engine
# ---------------------------------------------------------------------------------


class FakeTools:
    """In-memory stand-in for GhidraTools over one program."""

    def __init__(self, state):
        self.state = state

    def find_function(self, address):
        if address not in self.state["functions"]:
            raise ValueError(f"Function or symbol '{address}' not found.")
        fn = self.state["functions"][address]
        return SimpleNamespace(
            getName=lambda: fn["name"],
            getSignature=lambda: fn["signature"],
            getComment=lambda: fn.get("comment"),
        )

    def rename_function(self, address, new_name):
        self.state["functions"][address]["name"] = new_name

    def find_variable(self, function_address, *, storage=None, names=()):
        variables = self.state["variables"].get(function_address, [])
        for var in variables:
            if storage and var["storage"] == storage:
                break
        else:
            var = next((v for n in names for v in variables if v["name"] == n), None)
            if var is None:
                raise ValueError("Variable not found")
        return (
            None,
            "local",
            SimpleNamespace(
                getName=lambda: var["name"],
                getDataType=lambda: SimpleNamespace(getDisplayName=lambda: var["type"]),
            ),
        )

    def _variable(self, function_address, name):
        return next(v for v in self.state["variables"][function_address] if v["name"] == name)

    def rename_variable(self, function_address, variable_name, new_name):
        self._variable(function_address, variable_name)["name"] = new_name

    def set_variable_type(self, function_address, variable_name, type_name):
        self._variable(function_address, variable_name)["type"] = type_name

    def set_function_prototype(self, address, prototype):
        self.state["functions"][address]["signature"] = prototype

    def get_comment(self, address, comment_type):
        return self.state["comments"].get((address, comment_type))

    def set_comment(self, address, comment, comment_type):
        self.state["comments"][(address, comment_type)] = comment


class FakePrimary:
    def __init__(self, pyghidra_mcp_dir, programs):
        self.pyghidra_mcp_dir = pyghidra_mcp_dir
        self.programs = programs
        self.save = Mock()
        self.imported: list[Path] = []

    def get_program_info(self, binary_name):
        if binary_name not in self.programs:
            raise ValueError(f"Binary {binary_name} not found.")
        return self.programs[binary_name]

    def list_binaries(self):
        return list(self.programs)

    def import_binary_backgrounded(self, path):
        self.imported.append(Path(path))
        return SimpleNamespace(message=f"Queued 1 import(s) from {path} in the background.")


BIN = "/target.exe-abc123"


def _program_state():
    return {
        "functions": {
            "1000": {"name": "FUN_1000", "signature": "undefined FUN_1000(void)"},
            "2000": {"name": "FUN_2000", "signature": "undefined FUN_2000(void)"},
        },
        "variables": {"1000": [{"name": "local_10", "storage": "Stack[-0x10]:4", "type": "int"}]},
        "comments": {},
    }


@pytest.fixture
def merge_setup(tmp_path):
    parent = _make_parent_project(tmp_path)
    fork = forks.create_fork(parent, label="b")
    state = _program_state()
    primary = FakePrimary(parent.pyghidra_mcp_dir, {BIN: state})
    merger = forks.ForkMerger(primary, FakeTools)
    return fork, state, primary, merger


def test_merge_applies_edits_and_is_idempotent(merge_setup):
    fork, state, primary, merger = merge_setup
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="parse_args")
    fork.record(
        "rename_variable",
        BIN,
        function_address="1000",
        storage="Stack[-0x10]:4",
        old="local_10",
        new="count",
    )
    fork.record(
        "set_variable_type",
        BIN,
        function_address="1000",
        storage="Stack[-0x10]:4",
        variable_name="count",
        type_name="uint",
        old="int",
        new="uint",
    )
    fork.record(
        "set_function_prototype",
        BIN,
        address="2000",
        prototype="int helper(int x)",
        old="undefined FUN_2000(void)",
        new="int helper(int x)",
    )
    fork.record("set_comment", BIN, address="1000", comment_type="plate", old=None, new="entry")

    result = merger.merge(fork.fork_id)

    assert result["counts"] == {"applied": 5}
    assert result["pending_ops"] == 0
    assert state["functions"]["1000"]["name"] == "parse_args"
    assert state["variables"]["1000"][0] == {
        "name": "count",
        "storage": "Stack[-0x10]:4",
        "type": "uint",
    }
    assert state["functions"]["2000"]["signature"] == "int helper(int x)"
    assert state["comments"][("1000", "plate")] == "entry"
    primary.save.assert_called_once_with()

    again = merger.merge(fork.fork_id)
    assert again["entries"] == []
    assert again["pending_ops"] == 0
    assert primary.save.call_count == 1


def test_merge_detects_conflicts_and_retries_them(merge_setup):
    fork, state, primary, merger = merge_setup
    state["functions"]["1000"]["name"] = "primary_name"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_name")

    result = merger.merge(fork.fork_id)

    assert result["counts"] == {"conflict": 1}
    assert "primary has 'primary_name'" in result["entries"][0]["detail"]
    assert state["functions"]["1000"]["name"] == "primary_name"
    assert result["pending_ops"] == 1
    primary.save.assert_not_called()

    forced = merger.merge(fork.fork_id, on_conflict="overwrite")
    assert forced["counts"] == {"overwritten": 1}
    assert state["functions"]["1000"]["name"] == "fork_name"
    assert forced["pending_ops"] == 0


def test_merge_recognizes_edits_already_present_on_primary(merge_setup):
    fork, state, _primary, merger = merge_setup
    state["functions"]["1000"]["name"] = "parse_args"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="parse_args")

    assert merger.merge(fork.fork_id)["counts"] == {"already_applied": 1}


def test_dry_run_reports_without_applying_or_resolving(merge_setup):
    fork, state, primary, merger = merge_setup
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="parse_args")

    preview = merger.merge(fork.fork_id, dry_run=True)

    assert preview["counts"] == {"would_apply": 1}
    assert state["functions"]["1000"]["name"] == "FUN_1000"
    assert not (fork.fork_dir / forks.MERGE_STATE_FILE).exists()
    primary.save.assert_not_called()
    assert merger.merge(fork.fork_id)["counts"] == {"applied": 1}


def test_ops_chain_in_journal_order(merge_setup):
    fork, state, _primary, merger = merge_setup
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="first")
    fork.record("rename_function", BIN, address="1000", old="first", new="second")

    assert merger.merge(fork.fork_id)["counts"] == {"applied": 2}
    assert state["functions"]["1000"]["name"] == "second"


def test_missing_binary_is_skipped_and_retried_later(merge_setup):
    fork, _state, primary, merger = merge_setup
    other = "/new.exe-def456"
    fork.record("rename_function", other, address="1000", old="FUN_1000", new="main")

    first = merger.merge(fork.fork_id)
    assert first["counts"] == {"skipped": 1}
    assert first["pending_ops"] == 1

    primary.programs[other] = _program_state()
    assert merger.merge(fork.fork_id)["counts"] == {"applied": 1}


def test_deletions_are_never_replayed(merge_setup):
    fork, _state, primary, merger = merge_setup
    fork.record("delete_project_binary", BIN)

    result = merger.merge(fork.fork_id)

    assert result["counts"] == {"ignored": 1}
    assert result["pending_ops"] == 0
    assert BIN in primary.programs


def test_imports_are_queued_on_the_primary(merge_setup, tmp_path):
    fork, _state, primary, merger = merge_setup
    binary = tmp_path / "extra.bin"
    binary.write_bytes(b"\x7fELF")
    fork.record("import_binary", "", path=str(binary))
    fork.record("import_binary", "", path=str(tmp_path / "gone.bin"))

    result = merger.merge(fork.fork_id)

    assert result["counts"] == {"queued": 1, "failed": 1}
    assert primary.imported == [binary]


def test_failing_edit_is_reported_and_others_still_merge(merge_setup):
    fork, state, _primary, merger = merge_setup
    fork.record("rename_function", BIN, address="dead", old="a", new="b")
    fork.record("rename_function", BIN, address="2000", old="FUN_2000", new="helper")

    result = merger.merge(fork.fork_id)

    assert result["counts"] == {"failed": 1, "applied": 1}
    assert state["functions"]["2000"]["name"] == "helper"


def test_merge_runs_edits_through_the_supplied_runner(merge_setup):
    fork, _state, primary, _merger = merge_setup
    calls = []

    def runner(fn):
        calls.append(fn)
        return fn()

    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="x")
    forks.ForkMerger(primary, FakeTools, run=runner).merge(fork.fork_id)

    assert len(calls) == 1


# Session wiring
# ---------------------------------------------------------------------------------


def test_session_info_for_fork_and_primary(tmp_path):
    parent = _make_parent_project(tmp_path)
    fork = forks.create_fork(parent)
    fork.record("rename_function", "/b", address="1", old="a", new="b")

    fork_info = forks.session_info(SimpleNamespace(fork_session=fork))
    assert fork_info["role"] == "fork"
    assert fork_info["journal_ops"] == 1

    primary = SimpleNamespace(
        fork_session=None,
        pyghidra_mcp_dir=parent.pyghidra_mcp_dir,
        project_path=parent.project_directory,
        project_name=parent.project_name,
    )
    primary_info = forks.session_info(primary)
    assert primary_info["role"] == "primary"
    assert primary_info["pending_fork_ops"] == 1
    assert "merge_fork" in primary_info["hint"]
    assert "THIS SESSION IS FORK" in forks.server_instructions(SimpleNamespace(fork_session=fork))


def _tool_ctx(pyghidra_context):
    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    return ctx


def test_rename_on_fork_session_is_journaled(tmp_path, monkeypatch):
    fork = forks.create_fork(_make_parent_project(tmp_path))
    program_info = Mock()
    program_info.program.getDomainFile.return_value.getPathname.return_value = BIN
    pyghidra_context = SimpleNamespace(
        fork_session=fork, get_program_info=lambda _name: program_info
    )
    fake_tools = Mock()
    fake_tools.rename_function.return_value = {
        "address": "1000",
        "old_name": "FUN_1000",
        "new_name": "main",
    }
    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    mcp_tools.rename_function(
        binary_name="target.exe",
        name_or_address="FUN_1000",
        new_name="main",
        ctx=_tool_ctx(pyghidra_context),
    )

    (entry,) = forks.read_journal(fork.fork_dir)
    assert entry["op"] == "rename_function"
    assert entry["binary"] == BIN
    assert (entry["address"], entry["old"], entry["new"]) == ("1000", "FUN_1000", "main")


def test_merge_fork_tool_refuses_to_run_on_a_fork(tmp_path):
    fork = forks.create_fork(_make_parent_project(tmp_path))
    with pytest.raises(Exception, match="itself a fork"):
        mcp_tools.merge_fork(
            fork_id=fork.fork_id, ctx=_tool_ctx(SimpleNamespace(fork_session=fork))
        )


def _context_kwargs():
    return {"force_analysis": False, "gzfs_path": "/shared/gzfs", "threaded": True}


def test_create_project_context_forks_when_project_is_locked(tmp_path, monkeypatch):
    parent = _make_parent_project(tmp_path)
    opened = []

    def fake_context(**kwargs):
        opened.append(kwargs)
        if len(opened) == 1:
            raise forks.ProjectLockedError("locked")
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(server, "PyGhidraContext", fake_context)

    context = server.create_project_context(
        project_spec=parent, fork_label="b", **_context_kwargs()
    )

    fork = context.fork_session
    assert isinstance(fork, forks.ForkSession)
    assert opened[1]["project_path"] == fork.fork_dir
    assert opened[1]["pyghidra_mcp_dir"] == fork.project_spec.pyghidra_mcp_dir
    assert opened[1]["gzfs_path"] is None  # never write GZFs into the primary's store


def test_create_project_context_fail_mode_exits_with_guidance(tmp_path, monkeypatch):
    parent = _make_parent_project(tmp_path)
    monkeypatch.setattr(
        server, "PyGhidraContext", Mock(side_effect=forks.ProjectLockedError("locked"))
    )

    with pytest.raises(click.ClickException, match="streamable-http"):
        server.create_project_context(
            project_spec=parent, on_project_locked="fail", **_context_kwargs()
        )


def test_create_project_context_retries_a_fork_that_fails_to_open(tmp_path, monkeypatch):
    parent = _make_parent_project(tmp_path)
    calls = []

    def fake_context(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise forks.ProjectLockedError("locked")
        if len(calls) == 2:
            raise RuntimeError("torn copy")
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(server, "PyGhidraContext", fake_context)

    context = server.create_project_context(project_spec=parent, **_context_kwargs())

    remaining = forks.list_forks(parent.pyghidra_mcp_dir)
    assert [info["fork_id"] for info in remaining] == [context.fork_session.fork_id]
    assert not (context.fork_session.project_spec.pyghidra_mcp_dir / "chromadb").exists()
