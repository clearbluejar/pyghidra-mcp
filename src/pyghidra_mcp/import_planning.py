from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pyghidra_mcp.import_detection import is_ghidra_importable

ARCHIVE_SUFFIXES = (
    ".zip",
    ".jar",
    ".apk",
    ".ipa",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
)


@dataclass(frozen=True)
class ImportCandidate:
    path: Path
    relative_path: Path | None = None


@dataclass(frozen=True)
class SkippedImport:
    path: Path
    reason: str


@dataclass(frozen=True)
class ImportPlan:
    candidates: list[ImportCandidate]
    skipped: list[SkippedImport]


def build_import_plan(binary_paths: Iterable[str | Path]) -> ImportPlan:
    candidates: list[ImportCandidate] = []
    skipped: list[SkippedImport] = []

    for raw_path in binary_paths:
        path = Path(raw_path)
        if path.is_dir():
            for candidate in path.rglob("*"):
                if not candidate.is_file():
                    continue
                allowed, reason = _classify_import_path(candidate, allow_raw_binary=False)
                if allowed:
                    candidates.append(
                        ImportCandidate(candidate, candidate.relative_to(path).parent)
                    )
                else:
                    skipped.append(SkippedImport(candidate, reason))
            continue

        if path.is_file():
            allowed, reason = _classify_import_path(path, allow_raw_binary=True)
            if allowed:
                candidates.append(ImportCandidate(path, None))
            else:
                skipped.append(SkippedImport(path, reason))

    return ImportPlan(candidates=candidates, skipped=skipped)


def _classify_import_path(path: Path, *, allow_raw_binary: bool) -> tuple[bool, str]:
    if _is_archive_like(path):
        return False, "archive/container imports are not supported"
    if not is_ghidra_importable(path, allow_binary_loader=allow_raw_binary):
        return False, "no supported Ghidra loader detected"
    return True, ""


def _is_archive_like(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)
