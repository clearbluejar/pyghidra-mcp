"""Compare benchmark metrics between the current tree and a baseline snapshot."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.models import (
    CodeSearchResults,
    DecompiledFunction,
    ExportInfos,
    ImportInfos,
    SymbolSearchResults,
)
from tests.benchmark_helpers import (
    GeneratedBinaryArtifact,
    GeneratedBinarySpec,
    benchmark_repeated_tool_call,
    build_generated_binary,
    call_tool_model,
    collect_list_tools_metrics,
    default_executable_entry_lookup,
    platform_function_name,
    wait_for_binary_readiness,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE_REV = "07cb54a"


@dataclass(frozen=True)
class SnapshotTarget:
    label: str
    tree_path: Path
    scratch_root: Path
    env: dict[str, str]


@dataclass(frozen=True)
class SnapshotMetrics:
    label: str
    tree_path: str
    list_tools_payload_bytes: int
    tool_surface: dict[str, dict[str, Any]]
    timings: dict[str, dict[str, Any]]
    internal_calls: dict[str, dict[str, int]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-tree", type=Path)
    parser.add_argument("--baseline-rev", default=DEFAULT_BASELINE_REV)
    parser.add_argument("--current-tree", type=Path, default=REPO_ROOT)
    parser.add_argument("--scratch-dir", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--timing-runs", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    return parser.parse_args()


def ensure_worktree(repo_root: Path, scratch_dir: Path, revision: str) -> Path:
    worktrees_root = scratch_dir / "worktrees"
    worktrees_root.mkdir(parents=True, exist_ok=True)
    worktree_path = Path(tempfile.mkdtemp(prefix=f"baseline-{revision}-", dir=worktrees_root))
    subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "add", "--detach", str(worktree_path), revision],
        check=True,
        capture_output=True,
        text=True,
    )
    return worktree_path


def remove_worktree(repo_root: Path, worktree_path: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(worktree_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def build_target_env(target_tree: Path, repo_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    pythonpath_entries = [str(target_tree / "src"), str(repo_root)]
    if env.get("PYTHONPATH"):
        pythonpath_entries.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    return env


def make_target(label: str, tree_path: Path, scratch_dir: Path) -> SnapshotTarget:
    scratch_root = scratch_dir / label
    shutil.rmtree(scratch_root, ignore_errors=True)
    scratch_root.mkdir(parents=True, exist_ok=True)
    return SnapshotTarget(
        label=label,
        tree_path=tree_path,
        scratch_root=scratch_root,
        env=build_target_env(tree_path, REPO_ROOT),
    )


def make_stdio_server_params(
    target: SnapshotTarget,
    *,
    project_tag: str,
    binary_path: Path | None = None,
) -> StdioServerParameters:
    project_root = target.scratch_root / "projects" / project_tag
    args = [
        "-m",
        "pyghidra_mcp",
        "--project-path",
        str(project_root),
        "--project-name",
        project_tag,
        "--wait-for-analysis",
        "--no-threaded",
    ]
    if binary_path is not None:
        args.append(str(binary_path))
    return StdioServerParameters(command=sys.executable, args=args, env=target.env)


def generate_artifacts(
    scratch_dir: Path,
) -> tuple[GeneratedBinaryArtifact, GeneratedBinaryArtifact]:
    artifacts_root = scratch_dir / "artifacts"
    executable = build_generated_binary(
        artifacts_root / "executable",
        GeneratedBinarySpec(
            stem="benchmark_executable",
            function_count=96,
            string_count=24,
            global_count=64,
            call_fanout=2,
        ),
        shared=False,
    )
    shared_object = build_generated_binary(
        artifacts_root / "shared_object",
        GeneratedBinarySpec(
            stem="benchmark_shared",
            function_count=72,
            string_count=18,
            global_count=48,
            call_fanout=2,
            exported_function_count=32,
        ),
        shared=True,
    )
    return executable, shared_object


async def collect_surface_metrics(target: SnapshotTarget) -> tuple[int, dict[str, dict[str, Any]]]:
    server_params = make_stdio_server_params(target, project_tag="surface_metrics")
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            payload_bytes, tool_metrics = collect_list_tools_metrics(await session.list_tools())
            return payload_bytes, {
                name: metrics.to_dict() for name, metrics in tool_metrics.items()
            }


async def measure_decompile_function(
    target: SnapshotTarget,
    artifact: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    server_params = make_stdio_server_params(
        target,
        project_tag="timing_decompile_function",
        binary_path=artifact.binary_path,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready = await wait_for_binary_readiness(
                session,
                file_path=artifact.binary_path,
                timeout_seconds=timeout_seconds,
            )
            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "decompile_function",
                {
                    "binary_name": ready.name,
                    "name_or_address": default_executable_entry_lookup(),
                },
                scenario="decompile_function",
                runs=timing_runs,
            )
            assert all(results)
            return timing_metrics.to_dict()


async def measure_search_symbols_by_name(
    target: SnapshotTarget,
    artifact: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    server_params = make_stdio_server_params(
        target,
        project_tag="timing_search_symbols_by_name",
        binary_path=artifact.binary_path,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready = await wait_for_binary_readiness(
                session,
                file_path=artifact.binary_path,
                timeout_seconds=timeout_seconds,
            )
            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "search_symbols_by_name",
                {
                    "binary_name": ready.name,
                    "query": artifact.spec.sentinel_symbol_stem,
                    "limit": 5,
                },
                scenario="search_symbols_by_name",
                runs=timing_runs,
                validator=SymbolSearchResults.model_validate_json,
            )
            assert all(result.symbols for result in results)
            return timing_metrics.to_dict()


async def measure_search_code_semantic(
    target: SnapshotTarget,
    artifact: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    server_params = make_stdio_server_params(
        target,
        project_tag="timing_search_code_semantic",
        binary_path=artifact.binary_path,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready = await wait_for_binary_readiness(
                session,
                file_path=artifact.binary_path,
                require_code_collection=True,
                timeout_seconds=timeout_seconds,
            )
            decompiled = await call_tool_model(
                session,
                "decompile_function",
                {
                    "binary_name": ready.name,
                    "name_or_address": platform_function_name(artifact.spec.sentinel_function_stem),
                },
                DecompiledFunction,
            )
            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "search_code",
                {
                    "binary_name": ready.name,
                    "query": decompiled.code,
                    "limit": 3,
                    "include_full_code": False,
                    "preview_length": 80,
                },
                scenario="search_code_semantic",
                runs=timing_runs,
                validator=CodeSearchResults.model_validate_json,
            )
            assert all(result.returned_count > 0 for result in results)
            return timing_metrics.to_dict()


async def measure_search_code_literal(
    target: SnapshotTarget,
    artifact: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    server_params = make_stdio_server_params(
        target,
        project_tag="timing_search_code_literal",
        binary_path=artifact.binary_path,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready = await wait_for_binary_readiness(
                session,
                file_path=artifact.binary_path,
                require_code_collection=True,
                timeout_seconds=timeout_seconds,
            )
            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "search_code",
                {
                    "binary_name": ready.name,
                    "query": artifact.spec.sentinel_code_literal,
                    "limit": 3,
                    "search_mode": "literal",
                    "include_full_code": False,
                    "preview_length": 60,
                },
                scenario="search_code_literal",
                runs=timing_runs,
                validator=CodeSearchResults.model_validate_json,
            )
            assert all(result.literal_total >= result.returned_count for result in results)
            return timing_metrics.to_dict()


async def measure_list_exports(
    target: SnapshotTarget,
    artifact: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    server_params = make_stdio_server_params(
        target,
        project_tag="timing_list_exports",
        binary_path=artifact.binary_path,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready = await wait_for_binary_readiness(
                session,
                file_path=artifact.binary_path,
                timeout_seconds=timeout_seconds,
            )
            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "list_exports",
                {"binary_name": ready.name, "query": "noise_function_", "limit": 5},
                scenario="list_exports",
                runs=timing_runs,
                validator=ExportInfos.model_validate_json,
            )
            assert all(result.exports for result in results)
            return timing_metrics.to_dict()


async def measure_list_imports(
    target: SnapshotTarget,
    artifact: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    server_params = make_stdio_server_params(
        target,
        project_tag="timing_list_imports",
        binary_path=artifact.binary_path,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ready = await wait_for_binary_readiness(
                session,
                file_path=artifact.binary_path,
                timeout_seconds=timeout_seconds,
            )
            timing_metrics, results = await benchmark_repeated_tool_call(
                session,
                "list_imports",
                {"binary_name": ready.name, "query": artifact.spec.import_query, "limit": 5},
                scenario="list_imports",
                runs=timing_runs,
                validator=ImportInfos.model_validate_json,
            )
            assert all(result.imports for result in results)
            return timing_metrics.to_dict()


async def collect_timing_metrics(
    target: SnapshotTarget,
    executable: GeneratedBinaryArtifact,
    shared_object: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> dict[str, dict[str, Any]]:
    return {
        "decompile_function": await measure_decompile_function(
            target,
            executable,
            timing_runs=timing_runs,
            timeout_seconds=timeout_seconds,
        ),
        "search_symbols_by_name": await measure_search_symbols_by_name(
            target,
            executable,
            timing_runs=timing_runs,
            timeout_seconds=timeout_seconds,
        ),
        "search_code_semantic": await measure_search_code_semantic(
            target,
            executable,
            timing_runs=timing_runs,
            timeout_seconds=timeout_seconds,
        ),
        "search_code_literal": await measure_search_code_literal(
            target,
            executable,
            timing_runs=timing_runs,
            timeout_seconds=timeout_seconds,
        ),
        "list_exports": await measure_list_exports(
            target,
            shared_object,
            timing_runs=timing_runs,
            timeout_seconds=timeout_seconds,
        ),
        "list_imports": await measure_list_imports(
            target,
            shared_object,
            timing_runs=timing_runs,
            timeout_seconds=timeout_seconds,
        ),
    }


def collect_internal_call_counts(target: SnapshotTarget) -> dict[str, dict[str, int]]:
    script = (
        "from tests.benchmark_helpers import collect_internal_call_counts_json; "
        "print(collect_internal_call_counts_json())"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        env=target.env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Internal benchmark subprocess failed for "
            f"{target.label} ({target.tree_path}).\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return json.loads(result.stdout)


async def collect_snapshot_metrics(
    target: SnapshotTarget,
    executable: GeneratedBinaryArtifact,
    shared_object: GeneratedBinaryArtifact,
    *,
    timing_runs: int,
    timeout_seconds: int,
) -> SnapshotMetrics:
    payload_bytes, tool_surface = await collect_surface_metrics(target)
    timings = await collect_timing_metrics(
        target,
        executable,
        shared_object,
        timing_runs=timing_runs,
        timeout_seconds=timeout_seconds,
    )
    internal_calls = collect_internal_call_counts(target)
    return SnapshotMetrics(
        label=target.label,
        tree_path=str(target.tree_path),
        list_tools_payload_bytes=payload_bytes,
        tool_surface=tool_surface,
        timings=timings,
        internal_calls=internal_calls,
    )


def compare_snapshots(baseline: SnapshotMetrics, current: SnapshotMetrics) -> dict[str, Any]:
    delta_tool_surface: dict[str, dict[str, int]] = {}
    for tool_name in sorted(set(baseline.tool_surface) | set(current.tool_surface)):
        base_metrics = baseline.tool_surface.get(tool_name, {})
        current_metrics = current.tool_surface.get(tool_name, {})
        delta_tool_surface[tool_name] = {
            metric_name: int(current_metrics.get(metric_name, 0))
            - int(base_metrics.get(metric_name, 0))
            for metric_name in (
                "description_length",
                "input_schema_bytes",
                "output_schema_bytes",
                "total_json_bytes",
            )
        }

    delta_timings: dict[str, dict[str, float]] = {}
    for scenario in sorted(set(baseline.timings) | set(current.timings)):
        base_metrics = baseline.timings.get(scenario, {})
        current_metrics = current.timings.get(scenario, {})
        delta_timings[scenario] = {
            metric_name: float(current_metrics.get(metric_name, 0.0))
            - float(base_metrics.get(metric_name, 0.0))
            for metric_name in ("first_call_seconds", "warm_call_median_seconds")
        }

    delta_internal_calls: dict[str, dict[str, int]] = {}
    for scenario in sorted(set(baseline.internal_calls) | set(current.internal_calls)):
        base_metrics = baseline.internal_calls.get(scenario, {})
        current_metrics = current.internal_calls.get(scenario, {})
        delta_internal_calls[scenario] = {
            metric_name: int(current_metrics.get(metric_name, 0))
            - int(base_metrics.get(metric_name, 0))
            for metric_name in sorted(set(base_metrics) | set(current_metrics))
        }

    return {
        "baseline": baseline.to_dict(),
        "current": current.to_dict(),
        "delta": {
            "list_tools_payload_bytes": current.list_tools_payload_bytes
            - baseline.list_tools_payload_bytes,
            "tool_surface": delta_tool_surface,
            "timings": delta_timings,
            "internal_calls": delta_internal_calls,
        },
    }


def print_human_summary(report: dict[str, Any]) -> None:
    baseline = report["baseline"]
    current = report["current"]
    delta = report["delta"]

    print("== list_tools payload ==")
    print(
        f"baseline={baseline['list_tools_payload_bytes']} bytes "
        f"current={current['list_tools_payload_bytes']} bytes "
        f"delta={delta['list_tools_payload_bytes']:+d} bytes"
    )
    print()

    print("== tool surface bytes ==")
    for tool_name, metrics in sorted(delta["tool_surface"].items()):
        print(
            f"{tool_name}: total_json={metrics['total_json_bytes']:+d} "
            f"desc={metrics['description_length']:+d} "
            f"input={metrics['input_schema_bytes']:+d} "
            f"output={metrics['output_schema_bytes']:+d}"
        )
    print()

    print("== timing deltas (seconds) ==")
    for scenario, metrics in sorted(delta["timings"].items()):
        print(
            f"{scenario}: first={metrics['first_call_seconds']:+.6f} "
            f"warm_median={metrics['warm_call_median_seconds']:+.6f}"
        )
    print()

    print("== deterministic internal call deltas ==")
    for scenario, metrics in sorted(delta["internal_calls"].items()):
        compact = " ".join(f"{name}={value:+d}" for name, value in metrics.items())
        print(f"{scenario}: {compact}")


async def async_main(args: argparse.Namespace) -> dict[str, Any]:
    scratch_dir = args.scratch_dir or Path(tempfile.mkdtemp(prefix="pyghidra-mcp-bench-"))
    scratch_dir.mkdir(parents=True, exist_ok=True)

    baseline_tree = args.baseline_tree
    created_worktree = False
    if baseline_tree is None:
        baseline_tree = ensure_worktree(REPO_ROOT, scratch_dir, args.baseline_rev)
        created_worktree = True

    try:
        executable, shared_object = generate_artifacts(scratch_dir)
        baseline_target = make_target("baseline", baseline_tree, scratch_dir)
        current_target = make_target("current", args.current_tree, scratch_dir)

        baseline_metrics = await collect_snapshot_metrics(
            baseline_target,
            executable,
            shared_object,
            timing_runs=args.timing_runs,
            timeout_seconds=args.timeout_seconds,
        )
        current_metrics = await collect_snapshot_metrics(
            current_target,
            executable,
            shared_object,
            timing_runs=args.timing_runs,
            timeout_seconds=args.timeout_seconds,
        )
        return compare_snapshots(baseline_metrics, current_metrics)
    finally:
        if created_worktree and baseline_tree is not None:
            remove_worktree(REPO_ROOT, baseline_tree)


def main() -> None:
    args = parse_args()
    report = asyncio.run(async_main(args))
    print_human_summary(report)
    print()
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.json_out is not None:
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
