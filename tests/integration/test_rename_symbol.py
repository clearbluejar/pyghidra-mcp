"""Integration tests for the rename_symbol tool."""

import json
import os
import re
import subprocess
import sys
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SOURCE = """
int global_data = 42;

__attribute__((noinline)) int function_one(int count) {
    return count + global_data;
}

int main(void) {
    return function_one(3);
}
"""


def _payload(result) -> dict:
    text = result.content[0].text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pytest.fail(f"Tool returned an error: {text}")


async def _resolve_binary_name(session: ClientSession) -> str:
    programs = _payload(await session.call_tool("list_project_binaries", {})).get("programs") or []
    if len(programs) != 1:
        raise AssertionError(f"Expected exactly one imported binary, got {programs}")
    return programs[0]["name"]


async def _decompile(session: ClientSession, binary_name: str, function: str) -> str:
    result = await session.call_tool(
        "decompile_function", {"binary_name": binary_name, "name_or_address": function}
    )
    return _payload(result)["code"]


async def _rename(session: ClientSession, binary_name: str, target: str, new_name: str) -> dict:
    result = await session.call_tool(
        "rename_symbol",
        {"binary_name": binary_name, "name_or_address": target, "new_name": new_name},
    )
    return _payload(result)


def _build(strip_global: bool):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(SOURCE)
        c_file = f.name
    bin_file = c_file.replace(".c", "")

    if strip_global:
        # No -g: DWARF would let Ghidra recover the name we strip below.
        subprocess.run(["gcc", "-O0", "-o", bin_file, c_file], check=True)
        # Dropping the symtab entry leaves the global as an unnamed DAT_ label.
        subprocess.run(["strip", "--strip-symbol=global_data", bin_file], check=True)
    else:
        subprocess.run(["gcc", "-g", "-O0", "-o", bin_file, c_file], check=True)

    return c_file, bin_file


def _server_params(binary, ghidra_env, project_root, name) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(project_root / name),
            "--project-name",
            f"{name}_project",
            "--wait-for-analysis",
            binary,
        ],
        env=ghidra_env,
    )


@pytest.fixture(scope="module")
def symbol_test_binary():
    c_file, bin_file = _build(strip_global=False)
    yield bin_file
    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def dat_test_binary():
    c_file, bin_file = _build(strip_global=True)
    yield bin_file
    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def symbol_server_params(symbol_test_binary, ghidra_env, isolated_project_root):
    return _server_params(
        symbol_test_binary, ghidra_env, isolated_project_root, "symbol_server_params"
    )


@pytest.fixture(scope="module")
def dat_server_params(dat_test_binary, ghidra_env, isolated_project_root):
    return _server_params(dat_test_binary, ghidra_env, isolated_project_root, "dat_server_params")


@pytest.mark.asyncio
async def test_rename_symbol_by_name(symbol_server_params, func_prefix):
    original_name = f"{func_prefix}global_data"
    new_name = f"{original_name}_renamed"

    async with stdio_client(symbol_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = await _resolve_binary_name(session)

            renamed = await _rename(session, binary_name, original_name, new_name)
            assert renamed["old_name"] == original_name
            assert renamed["new_name"] == new_name

            search = await session.call_tool(
                "search_symbols_by_name",
                {"binary_name": binary_name, "query": new_name, "functions_only": False},
            )
            symbols = _payload(search).get("symbols") or []
            assert any(s.get("name") == new_name for s in symbols), "Renamed symbol not found"

            restored = await _rename(session, binary_name, new_name, original_name)
            assert restored["old_name"] == new_name
            assert restored["new_name"] == original_name


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "darwin", reason="strip --strip-symbol is GNU binutils only")
async def test_rename_symbol_dat_label_by_address(dat_server_params, func_prefix):
    function_name = f"{func_prefix}function_one"

    async with stdio_client(dat_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = await _resolve_binary_name(session)

            before = await _decompile(session, binary_name, function_name)
            match = re.search(r"DAT_([0-9a-fA-F]+)", before)
            assert match, f"Expected a DAT_ reference in {function_name}:\n{before}"
            dat_name, address = match.group(0), match.group(1)

            # Unnamed DAT_ labels are resolved by address, not by name.
            renamed = await _rename(session, binary_name, address, "renamed_global")
            assert renamed["old_name"] == dat_name
            assert renamed["new_name"] == "renamed_global"
            assert renamed["address"].lower() == address.lower()

            # Decompiler output must reflect the rename, not the old DAT_ name.
            after = await _decompile(session, binary_name, function_name)
            assert "renamed_global" in after
            assert dat_name not in after

            # The label is now a stored symbol, so lookup by its new name works.
            again = await _rename(session, binary_name, "renamed_global", "renamed_global_2")
            assert again["old_name"] == "renamed_global"
