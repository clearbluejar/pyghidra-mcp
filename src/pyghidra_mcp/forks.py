"""
Multi-agent project sharing through project forks.

Ghidra lets only one process open a project for update; a second process gets a
``LockException``. Instead of failing, a server that finds its project locked can
clone it into a *fork* and work there. Every edit made on the fork is appended to
a journal, and the session that owns the main project (the *primary*) later
replays that journal with ``merge_fork``.

On-disk layout, inside the main project's pyghidra-mcp directory::

    <name>-pyghidra-mcp/forks/<fork_id>/
        <name>.gpr, <name>.rep/     cloned Ghidra project (same program paths)
        <name>-pyghidra-mcp/        the fork's own Chroma index and GZFs
        fork.json                   written by the fork process only
        journal.jsonl               append-only edit log, written by the fork only
        merge_state.json            written by the merging (primary) process only

Each file has exactly one writing process, so no cross-process locking is needed.
Journal entries carry the value before and after each edit, which lets a merge
tell "not yet applied" apart from "changed independently on the primary" (a
conflict) without diffing program databases.
"""

import json
import logging
import os
import re
import shutil
import socket
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pyghidra_mcp.project_spec import ProjectSpec

logger = logging.getLogger(__name__)

FORKS_DIRNAME = "forks"
FORK_META_FILE = "fork.json"
JOURNAL_FILE = "journal.jsonl"
MERGE_STATE_FILE = "merge_state.json"

# Ghidra's project lock lives beside the .gpr marker; never clone a held lock.
_LOCK_FILE_SUFFIXES = (".lock", ".lock~", ".ulock")

# Merge outcomes that are final: the entry is not replayed by later merges.
RESOLVED_STATUSES = frozenset({"applied", "already_applied", "overwritten", "queued", "ignored"})

_merge_lock = threading.Lock()


class ProjectLockedError(RuntimeError):
    """Another process holds the Ghidra project lock."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """Write atomically; retry briefly because Windows refuses to replace open files."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def pid_alive(pid: int | None) -> bool:
    """Return True if a process with ``pid`` exists on this host."""
    if not pid or pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if sys.platform == "win32":
        # os.kill(pid, 0) would *terminate* the process on Windows.
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        process_query_limited_information = 0x1000
        still_active = 259
        error_access_denied = 5

        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return ctypes.get_last_error() == error_access_denied
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            return exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def read_journal(fork_dir: Path) -> list[dict[str, Any]]:
    """Read complete journal entries; a torn trailing line is still being written."""
    path = fork_dir / JOURNAL_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("seq"), int):
            entries.append(entry)
    return entries


def load_merge_state(fork_dir: Path) -> dict[str, Any]:
    state = _read_json(fork_dir / MERGE_STATE_FILE)
    state.setdefault("resolved", {})
    state.setdefault("merges", [])
    return state


def forks_root(pyghidra_mcp_dir: Path) -> Path:
    return Path(pyghidra_mcp_dir) / FORKS_DIRNAME


def _sanitize_label(label: str | None) -> str | None:
    if not label:
        return None
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", label).strip("._-")[:32]
    return cleaned or None


@dataclass
class ForkSession:
    """The journaling side of a fork, owned by the process working on it."""

    fork_id: str
    fork_dir: Path
    project_name: str
    parent_project: Path
    label: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _next_seq: int = field(default=1, repr=False)

    @property
    def project_spec(self) -> ProjectSpec:
        return ProjectSpec(
            project_directory=self.fork_dir,
            project_name=self.project_name,
            gpr_path=self.fork_dir / f"{self.project_name}.gpr",
            pyghidra_mcp_dir=self.fork_dir / f"{self.project_name}-pyghidra-mcp",
            was_gpr_path=False,
        )

    @property
    def parent_pyghidra_mcp_dir(self) -> Path:
        return self.fork_dir.parent.parent

    @property
    def op_count(self) -> int:
        return self._next_seq - 1

    @classmethod
    def load(cls, fork_dir: Path) -> "ForkSession":
        meta = _read_json(fork_dir / FORK_META_FILE)
        if not meta:
            raise ValueError(f"Not a pyghidra-mcp fork: {fork_dir}")
        session = cls(
            fork_id=meta["fork_id"],
            fork_dir=fork_dir,
            project_name=meta["project_name"],
            parent_project=Path(meta["parent_project"]),
            label=meta.get("label"),
        )
        journal = read_journal(fork_dir)
        session._next_seq = max((e["seq"] for e in journal), default=0) + 1
        return session

    def record(self, op: str, binary: str, **fields: Any) -> dict[str, Any]:
        """Append one edit to the journal and flush it to disk before returning."""
        with self._lock:
            entry = {"seq": self._next_seq, "ts": time.time(), "op": op, "binary": binary}
            entry.update(fields)
            with open(self.fork_dir / JOURNAL_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._next_seq += 1
        return entry

    def mark(self, status: str) -> None:
        meta = _read_json(self.fork_dir / FORK_META_FILE)
        meta["status"] = status
        meta["pid"] = os.getpid()
        meta["host"] = socket.gethostname()
        meta[f"{status}_at"] = _now_iso()
        _write_json(self.fork_dir / FORK_META_FILE, meta)


def _ignore_lock_files(_directory: str, names: list[str]) -> list[str]:
    return [name for name in names if name.endswith(_LOCK_FILE_SUFFIXES)]


def create_fork(
    parent: ProjectSpec,
    label: str | None = None,
    *,
    seed_index: bool = True,
) -> ForkSession:
    """Clone the parent project's last saved state into a new fork directory.

    Programs the lock holder has modified but not saved are not part of the
    clone. Merges compare against the primary's *current* values, so that
    staleness shows up as conflicts rather than silent overwrites.
    """
    label = _sanitize_label(label)
    fork_id = "-".join(
        part for part in (time.strftime("%Y%m%d-%H%M%S"), label, uuid.uuid4().hex[:6]) if part
    )
    fork_dir = forks_root(parent.pyghidra_mcp_dir) / fork_id
    fork_dir.mkdir(parents=True)
    name = parent.project_name

    started = time.monotonic()
    try:
        shutil.copy2(parent.gpr_path, fork_dir / f"{name}.gpr")
        shutil.copytree(
            parent.project_directory / f"{name}.rep",
            fork_dir / f"{name}.rep",
            ignore=_ignore_lock_files,
        )
    except Exception:
        shutil.rmtree(fork_dir, ignore_errors=True)
        raise

    state_dir = fork_dir / f"{name}-pyghidra-mcp"
    state_dir.mkdir()
    source_index = parent.pyghidra_mcp_dir / "chromadb"
    if seed_index and source_index.is_dir():
        # Reusing the primary's completed code index saves re-decompiling every
        # function. A torn copy is detected when the fork opens it, and the
        # caller retries with seed_index=False.
        try:
            shutil.copytree(source_index, state_dir / "chromadb")
        except Exception:
            logger.warning("Could not seed fork index from %s; it will be rebuilt.", source_index)
            shutil.rmtree(state_dir / "chromadb", ignore_errors=True)

    _write_json(
        fork_dir / FORK_META_FILE,
        {
            "fork_id": fork_id,
            "label": label,
            "project_name": name,
            "parent_project": str(parent.gpr_path.absolute()),
            "created_at": _now_iso(),
            "status": "active",
            "pid": os.getpid(),
            "host": socket.gethostname(),
        },
    )
    logger.info("Created fork %s of %s in %.1fs.", fork_id, name, time.monotonic() - started)
    return ForkSession(
        fork_id=fork_id,
        fork_dir=fork_dir,
        project_name=name,
        parent_project=parent.gpr_path.absolute(),
        label=label,
    )


def find_reusable_fork(parent: ProjectSpec, label: str | None) -> ForkSession | None:
    """Return the newest stopped fork with ``label`` that still has unmerged edits.

    This lets an agent whose server restarts pick up its own fork again instead of
    starting from a fresh clone that lacks its earlier, not-yet-merged work.
    """
    label = _sanitize_label(label)
    if not label:
        return None
    candidates = [
        info
        for info in list_forks(parent.pyghidra_mcp_dir)
        if info["label"] == label and info["alive"] is False and info["pending_ops"] > 0
    ]
    if not candidates:
        return None
    newest = max(candidates, key=lambda info: info["created_at"])
    return ForkSession.load(Path(newest["path"]))


def describe_fork(fork_dir: Path) -> dict[str, Any] | None:
    meta = _read_json(fork_dir / FORK_META_FILE)
    if not meta.get("fork_id"):
        return None
    journal = read_journal(fork_dir)
    resolved = load_merge_state(fork_dir)["resolved"]
    resolved_count = sum(1 for entry in journal if str(entry["seq"]) in resolved)

    status = meta.get("status", "active")
    alive: bool | None
    if status == "closed":
        alive = False
    elif meta.get("host") == socket.gethostname():
        alive = pid_alive(meta.get("pid"))
    else:
        alive = None  # cannot check a process on another host

    return {
        "fork_id": meta["fork_id"],
        "label": meta.get("label"),
        "status": status,
        "alive": alive,
        "pid": meta.get("pid"),
        "created_at": meta.get("created_at", ""),
        "journal_ops": len(journal),
        "resolved_ops": resolved_count,
        "pending_ops": len(journal) - resolved_count,
        "path": str(fork_dir),
    }


def list_forks(pyghidra_mcp_dir: Path) -> list[dict[str, Any]]:
    root = forks_root(pyghidra_mcp_dir)
    if not root.is_dir():
        return []
    forks = [describe_fork(child) for child in sorted(root.iterdir()) if child.is_dir()]
    return [info for info in forks if info is not None]


def resolve_fork_dir(pyghidra_mcp_dir: Path, fork_id: str) -> Path:
    root = forks_root(pyghidra_mcp_dir)
    fork_dir = root / fork_id
    # fork_id comes from a client; refuse anything that escapes the forks root.
    if fork_dir.resolve().parent != root.resolve() or not (fork_dir / FORK_META_FILE).is_file():
        known = [info["fork_id"] for info in list_forks(pyghidra_mcp_dir)]
        raise ValueError(f"Fork '{fork_id}' not found. Known forks: {known}")
    return fork_dir


def discard_fork(pyghidra_mcp_dir: Path, fork_id: str) -> dict[str, Any]:
    fork_dir = resolve_fork_dir(pyghidra_mcp_dir, fork_id)
    info = describe_fork(fork_dir) or {}
    if info.get("alive") is not False:
        raise ValueError(
            f"Fork '{fork_id}' may still be in use (pid {info.get('pid')}). "
            "Stop the server working on it before discarding."
        )
    shutil.rmtree(fork_dir)
    return info


# Merge
# ---------------------------------------------------------------------------------


def _same(a: Any, b: Any) -> bool:
    # Ghidra reports a missing comment as None; a journal may hold "" for it.
    return (a or None) == (b or None)


@dataclass
class _Outcome:
    status: str
    target: str
    detail: str | None = None


def _reconcile(
    *,
    target: str,
    current: Any,
    old: Any,
    new: Any,
    apply: Callable[[], Any],
    dry_run: bool,
    on_conflict: str,
) -> _Outcome:
    """Three-way decision for one edit: fork base (old), fork result (new), primary now."""
    if _same(current, new):
        return _Outcome("already_applied", target)
    if _same(current, old):
        if dry_run:
            return _Outcome("would_apply", target, f"{old!r} -> {new!r}")
        apply()
        return _Outcome("applied", target, f"{old!r} -> {new!r}")
    detail = f"primary has {current!r}; fork changed {old!r} -> {new!r}"
    if on_conflict == "overwrite":
        if dry_run:
            return _Outcome("would_overwrite", target, detail)
        apply()
        return _Outcome("overwritten", target, detail)
    return _Outcome("conflict", target, detail)


def _merge_rename_function(tools, op, dry_run, on_conflict) -> _Outcome:
    func = tools.find_function(op["address"])
    return _reconcile(
        target=f"function @ {op['address']}",
        current=str(func.getName()),
        old=op["old"],
        new=op["new"],
        apply=lambda: tools.rename_function(op["address"], op["new"]),
        dry_run=dry_run,
        on_conflict=on_conflict,
    )


def _merge_rename_variable(tools, op, dry_run, on_conflict) -> _Outcome:
    _func, _kind, variable = tools.find_variable(
        op["function_address"], storage=op.get("storage"), names=(op["old"], op["new"])
    )
    current = str(variable.getName())
    return _reconcile(
        target=f"variable {op.get('storage') or op['old']} in {op['function_address']}",
        current=current,
        old=op["old"],
        new=op["new"],
        apply=lambda: tools.rename_variable(op["function_address"], current, op["new"]),
        dry_run=dry_run,
        on_conflict=on_conflict,
    )


def _merge_set_variable_type(tools, op, dry_run, on_conflict) -> _Outcome:
    _func, _kind, variable = tools.find_variable(
        op["function_address"], storage=op.get("storage"), names=(op["variable_name"],)
    )
    name = str(variable.getName())
    return _reconcile(
        target=f"type of {name} in {op['function_address']}",
        current=str(variable.getDataType().getDisplayName()),
        old=op["old"],
        new=op["new"],
        apply=lambda: tools.set_variable_type(op["function_address"], name, op["type_name"]),
        dry_run=dry_run,
        on_conflict=on_conflict,
    )


def _merge_set_function_prototype(tools, op, dry_run, on_conflict) -> _Outcome:
    func = tools.find_function(op["address"])
    return _reconcile(
        target=f"prototype @ {op['address']}",
        current=str(func.getSignature()),
        old=op["old"],
        new=op["new"],
        apply=lambda: tools.set_function_prototype(op["address"], op["prototype"]),
        dry_run=dry_run,
        on_conflict=on_conflict,
    )


def _merge_set_comment(tools, op, dry_run, on_conflict) -> _Outcome:
    return _reconcile(
        target=f"{op['comment_type']} comment @ {op['address']}",
        current=tools.get_comment(op["address"], op["comment_type"]),
        old=op.get("old"),
        new=op["new"],
        apply=lambda: tools.set_comment(op["address"], op["new"], op["comment_type"]),
        dry_run=dry_run,
        on_conflict=on_conflict,
    )


_PROGRAM_EDIT_HANDLERS = {
    "rename_function": _merge_rename_function,
    "rename_variable": _merge_rename_variable,
    "set_variable_type": _merge_set_variable_type,
    "set_function_prototype": _merge_set_function_prototype,
    "set_comment": _merge_set_comment,
}


class ForkMerger:
    """Replays a fork's journal into the project owned by ``context``.

    ``run`` executes each Ghidra mutation; GUI mode passes a Swing-thread runner.
    """

    def __init__(
        self,
        context: Any,
        tools_factory: Callable[[Any], Any],
        run: Callable[[Callable[[], Any]], Any] = lambda fn: fn(),
    ):
        self.context = context
        self.tools_factory = tools_factory
        self.run = run

    def merge(
        self,
        fork_id: str,
        *,
        dry_run: bool = False,
        on_conflict: str = "skip",
    ) -> dict[str, Any]:
        if on_conflict not in {"skip", "overwrite"}:
            raise ValueError("on_conflict must be 'skip' or 'overwrite'")

        fork_dir = resolve_fork_dir(self.context.pyghidra_mcp_dir, fork_id)
        with _merge_lock:
            state = load_merge_state(fork_dir)
            resolved: dict[str, str] = state["resolved"]
            journal = read_journal(fork_dir)
            entries = []
            for op in journal:
                if str(op["seq"]) in resolved:
                    continue
                outcome = self._merge_one(op, dry_run=dry_run, on_conflict=on_conflict)
                entries.append(
                    {
                        "seq": op["seq"],
                        "op": op["op"],
                        "binary": op.get("binary", ""),
                        "target": outcome.target,
                        "status": outcome.status,
                        "detail": outcome.detail,
                    }
                )
                if not dry_run and outcome.status in RESOLVED_STATUSES:
                    resolved[str(op["seq"])] = outcome.status

            counts: dict[str, int] = {}
            for entry in entries:
                counts[entry["status"]] = counts.get(entry["status"], 0) + 1

            if not dry_run:
                state["merges"] = [*state["merges"], {"at": _now_iso(), "counts": counts}][-20:]
                _write_json(fork_dir / MERGE_STATE_FILE, state)
                if counts.get("applied") or counts.get("overwritten"):
                    self.context.save()

        return {
            "fork_id": fork_id,
            "dry_run": dry_run,
            "on_conflict": on_conflict,
            "counts": counts,
            "entries": entries,
            "pending_ops": sum(1 for op in journal if str(op["seq"]) not in resolved),
        }

    def _merge_one(self, op: dict[str, Any], *, dry_run: bool, on_conflict: str) -> _Outcome:
        kind = op.get("op")
        if kind == "delete_project_binary":
            return _Outcome(
                "ignored",
                op.get("binary", ""),
                "deletions are never merged automatically; delete on the primary if intended",
            )
        if kind == "import_binary":
            return self._merge_import(op, dry_run=dry_run)

        handler = _PROGRAM_EDIT_HANDLERS.get(str(kind))
        if handler is None:
            return _Outcome("ignored", op.get("binary", ""), f"unsupported journal op '{kind}'")

        try:
            program_info = self.context.get_program_info(op["binary"])
        except Exception as e:
            # Typically a binary the fork imported that is not (yet) analyzed here.
            return _Outcome("skipped", op["binary"], f"binary unavailable on primary: {e}")

        tools = self.tools_factory(program_info)
        try:
            return self.run(lambda: handler(tools, op, dry_run, on_conflict))
        except Exception as e:
            return _Outcome("failed", op.get("address") or op.get("function_address") or "", str(e))

    def _merge_import(self, op: dict[str, Any], *, dry_run: bool) -> _Outcome:
        path = Path(op["path"])
        if not path.exists():
            return _Outcome("failed", str(path), "source path no longer exists")
        if path.is_file():
            from pyghidra_mcp.context import PyGhidraContext

            program_name = PyGhidraContext._gen_unique_bin_name(path)
            if any(Path(name).name == program_name for name in self.context.list_binaries()):
                return _Outcome("already_applied", str(path))
        if dry_run:
            return _Outcome("would_apply", str(path), "would import into the primary project")
        result = self.context.import_binary_backgrounded(path)
        return _Outcome("queued", str(path), result.message)


def session_info(context: Any) -> dict[str, Any] | None:
    """Describe whether ``context`` is a fork or the primary, for tool responses."""
    fork = getattr(context, "fork_session", None)
    if isinstance(fork, ForkSession):
        return {
            "role": "fork",
            "project": str(fork.project_spec.gpr_path),
            "fork_id": fork.fork_id,
            "parent_project": str(fork.parent_project),
            "journal_ops": fork.op_count,
            "hint": (
                "Another session holds the main project, so this one works on a private "
                "fork. Edits are journaled for the primary session to merge with merge_fork; "
                "changes made there after the fork are not visible here."
            ),
        }

    pyghidra_mcp_dir = getattr(context, "pyghidra_mcp_dir", None)
    if not isinstance(pyghidra_mcp_dir, Path):
        return None
    pending = sum(info["pending_ops"] for info in list_forks(pyghidra_mcp_dir))
    project_path = getattr(context, "project_path", None)
    project_name = getattr(context, "project_name", None)
    project = (
        str(Path(project_path) / f"{project_name}.gpr")
        if isinstance(project_path, (str, Path)) and isinstance(project_name, str)
        else ""
    )
    return {
        "role": "primary",
        "project": project,
        "pending_fork_ops": pending,
        "hint": (
            f"{pending} edit(s) from other sessions' forks await merging: "
            "see list_forks, then merge_fork."
            if pending
            else None
        ),
    }


def server_instructions(context: Any) -> str:
    info = session_info(context)
    base = (
        "pyghidra-mcp exposes a Ghidra project. Several agents can share one project: "
        "the session that opens it first is the primary; later sessions get a private "
        "fork whose edits are journaled and merged back by the primary with merge_fork."
    )
    if info and info["role"] == "fork":
        return f"{base}\n\nTHIS SESSION IS FORK {info['fork_id']}. {info['hint']}"
    return base
