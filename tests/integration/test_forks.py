import json

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


def _shared_project_params(project_root, ghidra_env, *extra):
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(project_root / "shared"),
            "--project-name",
            "shared",
            *extra,
        ],
        env=ghidra_env,
    )


async def _call(session, tool, **args):
    result = await session.call_tool(tool, args)
    assert result.is_error is False, result.content[0].text
    return json.loads(result.content[0].text)


@pytest.mark.asyncio
async def test_locked_project_forks_and_primary_merges(
    test_binary, ghidra_env, isolated_project_root, func_prefix, main_func_name
):
    """A second server on a locked project works on a fork the primary can merge."""
    primary = _shared_project_params(
        isolated_project_root, ghidra_env, "--wait-for-analysis", test_binary
    )
    secondary = _shared_project_params(isolated_project_root, ghidra_env, "--fork-label", "b")
    binary_name = PyGhidraContext._gen_unique_bin_name(test_binary)

    async with stdio_client(primary) as (read_a, write_a):
        async with ClientSession(read_a, write_a) as a:
            await a.initialize()

            async with stdio_client(secondary) as (read_b, write_b):
                async with ClientSession(read_b, write_b) as b:
                    init = await b.initialize()
                    assert "THIS SESSION IS FORK" in (init.instructions or "")

                    session = (await _call(b, "list_project_binaries"))["session"]
                    assert session["role"] == "fork"
                    fork_id = session["fork_id"]

                    await _call(
                        b,
                        "rename_function",
                        binary_name=binary_name,
                        name_or_address=f"{func_prefix}function_one",
                        new_name="fork_one",
                    )
                    await _call(
                        b,
                        "rename_function",
                        binary_name=binary_name,
                        name_or_address=f"{func_prefix}function_two",
                        new_name="fork_two",
                    )

            # The primary changed function_two independently: a conflict.
            await _call(
                a,
                "rename_function",
                binary_name=binary_name,
                name_or_address=f"{func_prefix}function_two",
                new_name="primary_two",
            )

            forks = (await _call(a, "list_forks"))["forks"]
            assert [f["fork_id"] for f in forks] == [fork_id]
            assert forks[0]["pending_ops"] == 2

            preview = await _call(a, "merge_fork", fork_id=fork_id, dry_run=True)
            assert preview["counts"] == {"would_apply": 1, "conflict": 1}

            merged = await _call(a, "merge_fork", fork_id=fork_id)
            assert merged["counts"] == {"applied": 1, "conflict": 1}
            assert merged["pending_ops"] == 1

            decompiled = await _call(
                a, "decompile_function", binary_name=binary_name, name_or_address=main_func_name
            )
            assert "fork_one" in decompiled["code"]
            assert "primary_two" in decompiled["code"]

            forced = await _call(a, "merge_fork", fork_id=fork_id, on_conflict="overwrite")
            assert forced["counts"] == {"overwritten": 1}
            assert forced["pending_ops"] == 0


@pytest.mark.asyncio
async def test_locked_project_can_refuse_to_fork(test_binary, ghidra_env, isolated_project_root):
    primary = _shared_project_params(
        isolated_project_root, ghidra_env, "--wait-for-analysis", test_binary
    )
    secondary = _shared_project_params(
        isolated_project_root, ghidra_env, "--on-project-locked", "fail"
    )

    async with stdio_client(primary) as (read_a, write_a):
        async with ClientSession(read_a, write_a) as a:
            await a.initialize()
            with pytest.raises(Exception):  # noqa: B017 - server exits before initialize
                async with stdio_client(secondary) as (read_b, write_b):
                    async with ClientSession(read_b, write_b) as b:
                        await b.initialize()
