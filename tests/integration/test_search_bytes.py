"""Exercise byte searches over MCP using known data in a small compiled binary."""

import subprocess

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import BytesSearchResults, SymbolSearchResults


@pytest.fixture
def byte_search_server(tmp_path, ghidra_env):
    source = tmp_path / "patterns.c"
    source.write_text(
        """
volatile unsigned char search_fixture[64] __attribute__((aligned(8))) = {
    0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33,
    0xde, 0xad, 0xbe, 0xef, 0x44,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xaa, 0xef,
    0xb6, 0x47, 0, 0, 0xb7, 0x47, 0, 0, 0, 0, 0x47, 0xb6,
    0xaa, 0xaa, 0xaa, 0xaa,
    0, 0, 0, 0,
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    0, 0, 0, 0,
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
};
volatile unsigned char search_uninitialized[128];
int main(void) { return search_fixture[0] + search_uninitialized[0]; }
"""
    )
    binary = tmp_path / "patterns"
    subprocess.run(["gcc", "-o", str(binary), str(source)], check=True, capture_output=True)
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(tmp_path / "project"),
            "--wait-for-analysis",
            str(binary),
        ],
        env=ghidra_env,
    )


@pytest.mark.asyncio
async def test_search_bytes(byte_search_server):
    async with stdio_client(byte_search_server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(byte_search_server.args[-1])

            async def symbol_address(name):
                response = await session.call_tool(
                    "search_symbols_by_name", {"binary_name": binary_name, "query": f"{name}$"}
                )
                assert not response.is_error, response.content
                symbols = SymbolSearchResults.model_validate_json(response.content[0].text).symbols
                assert len(symbols) == 1
                return int(symbols[0].address, 16)

            base = await symbol_address("search_fixture")
            bss = await symbol_address("search_uninitialized")
            scope = {"start": hex(base), "end": hex(base + 63)}

            async def search(**kwargs):
                response = await session.call_tool(
                    "search_bytes", {"binary_name": binary_name, **kwargs}
                )
                assert not response.is_error, response.content
                return BytesSearchResults.model_validate_json(response.content[0].text)

            def offsets(result):
                return [int(hit.address, 16) - base for hit in result.hits]

            # The default search covers initialized blocks and exposes no bytes.
            exact = await search(pattern="DEADBEEF")
            assert offsets(exact) == [0, 7, 12]
            assert exact.total_matches == exact.returned_count == 3
            assert not exact.truncated
            assert all(hit.block in exact.searched_blocks for hit in exact.hits)
            assert all(
                hit.context_before is None and hit.context_after is None for hit in exact.hits
            )
            assert not any("bss" in name.lower() for name in exact.searched_blocks)

            wildcard = await search(pattern="de ad ?? ef", **scope)
            assert offsets(wildcard) == [0, 7, 12, 16]
            for alignment in (2, 4):
                aligned = await search(pattern="de ad be ef", alignment=alignment, **scope)
                assert offsets(aligned) == [0, 12]

            # Bounds include the whole match; a match may not spill past end.
            ranged = await search(pattern="deadbeef", start=hex(base + 1), end=hex(base + 15))
            assert offsets(ranged) == [7, 12]
            clipped = await search(pattern="deadbeef", start=hex(base + 7), end=hex(base + 9))
            assert clipped.total_matches == 0
            lower_only = await search(pattern="deadbeef", start=hex(base + 8))
            assert offsets(lower_only) == [12]
            upper_only = await search(pattern="deadbeef", end=hex(base + 10))
            assert offsets(upper_only) == [0, 7]

            truncated = await search(pattern="deadbeef", max_results=2, **scope)
            assert offsets(truncated) == [0, 7]
            assert truncated.returned_count == 2
            assert truncated.truncated and truncated.total_matches is None
            exact_limit = await search(pattern="deadbeef", max_results=3, **scope)
            assert not exact_limit.truncated and exact_limit.total_matches == 3
            filtered_limit = await search(pattern="deadbeef", max_results=2, alignment=4, **scope)
            assert offsets(filtered_limit) == [0, 12]
            assert not filtered_limit.truncated

            value = await search(value="0x47b6", width=4, **scope)
            assert offsets(value) == [20]
            thumb = await search(value=0x47B6, width=4, thumb=True, **scope)
            assert offsets(thumb) == [20, 24]
            odd = await search(value="0x47b7", width=4, thumb=True, **scope)
            assert offsets(odd) == [24]
            short = await search(value=0x47B6, width=2, **scope)
            assert offsets(short) == [20]
            big = await search(value="0x47b6", width=4, endian="big", **scope)
            assert offsets(big) == [28]
            big_thumb = await search(value=0x47B6, width=4, endian="big", thumb=True, **scope)
            assert offsets(big_thumb) == [28]
            byte = await search(value=0xDE, width=1, **scope)
            assert offsets(byte) == [0, 7, 12, 16]
            wide = await search(value="0x0123456789abcdef", width=8, **scope)
            assert offsets(wide) == [40, 52]
            wide_by_4 = await search(value=0x0123456789ABCDEF, width=8, alignment=4, **scope)
            assert offsets(wide_by_4) == [40, 52]
            wide_aligned = await search(value="0x0123456789abcdef", width=8, alignment=8, **scope)
            assert offsets(wide_aligned) == [40]
            overlap = await search(pattern="aa aa", **scope)
            assert offsets(overlap) == [32, 33, 34]
            wild_only = await search(pattern="?? ??", start=hex(base), end=hex(base + 3))
            assert offsets(wild_only) == [0, 1, 2]
            absent = await search(pattern="f0f1f2f3", **scope)
            assert absent.total_matches == 0 and not absent.truncated
            uninitialized = await search(pattern="00", start=hex(bss), end=hex(bss + 127))
            assert not uninitialized.hits and not uninitialized.searched_blocks

            context = await search(pattern="deadbeef", context_bytes=2, **scope)
            assert context.hits[0].context_before == ""
            assert context.hits[0].context_after == "1122"
            assert context.hits[1].context_before == "2233"
            assert context.hits[1].context_after == "44de"
            edge = await search(
                pattern="deadbeef", start=hex(base + 7), end=hex(base + 10), context_bytes=16
            )
            assert edge.hits[0].context_before == edge.hits[0].context_after == ""

            # Errors must survive the MCP boundary with actionable text.
            invalid = [
                ({}, "exactly one"),
                ({"pattern": "aa", "value": 1}, "exactly one"),
                ({"pattern": ""}, "hex byte pairs"),
                ({"pattern": "a?"}, "hex byte pairs"),
                ({"pattern": "gg"}, "hex byte pairs"),
                ({"pattern": "a"}, "hex byte pairs"),
                ({"pattern": "aa", "thumb": True}, "only to value"),
                ({"value": -1}, "unsigned"),
                ({"value": 256, "width": 1}, "unsigned"),
                ({"value": "0x10000000000000000", "width": 8}, "unsigned"),
                ({"value": "not-a-number"}, "unsigned"),
                ({"pattern": "aa", "max_results": 0}, "between 1 and 1000"),
                ({"pattern": "aa", "max_results": 1001}, "between 1 and 1000"),
                ({"pattern": "aa", "context_bytes": -1}, "between 0 and 16"),
                ({"pattern": "aa", "context_bytes": 17}, "between 0 and 16"),
                ({"pattern": "aa", "start": "bogus"}, "Invalid memory address"),
                ({"pattern": "aa", "start": hex(base + 1), "end": hex(base)}, "ordered"),
            ]
            for arguments, message in invalid:
                response = await session.call_tool(
                    "search_bytes", {"binary_name": binary_name, **arguments}
                )
                assert response.is_error, arguments
                assert message in response.content[0].text, response.content

            response = await session.call_tool(
                "read_bytes", {"binary_name": binary_name, "address": hex(base), "size": 8193}
            )
            assert response.is_error
            assert "8192" in response.content[0].text and "search_bytes" in response.content[0].text
