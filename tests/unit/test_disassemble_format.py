"""Unit tests for the disassembly listing formatter (GhidraTools._format_disassembly).

The formatter is pure (no Ghidra runtime needed), so it is exercised directly.
"""

from pyghidra_mcp.tools import GhidraTools

# (address, bytes_hex, mnemonic, operands)
ROWS = [
    ("1400019c0", "4883ec28", "SUB", "RSP,0x28"),
    ("1400019c4", "e8cf050000", "CALL", "0x140001f98"),
    ("1400019c9", "4883c428", "ADD", "RSP,0x28"),
    ("1400019cd", "c3", "RET", ""),
]


def test_format_without_bytes_omits_byte_column():
    listing = GhidraTools._format_disassembly(ROWS, include_bytes=False)
    lines = listing.split("\n")

    assert len(lines) == 4
    # No raw byte strings should appear when include_bytes is False.
    for raw in ("4883ec28", "e8cf050000", "4883c428"):
        assert raw not in listing
    # Fields are single-space separated: address mnemonic operands.
    assert lines[0] == "1400019c0 SUB RSP,0x28"
    assert lines[1] == "1400019c4 CALL 0x140001f98"
    # An operand-less instruction emits just address and mnemonic, no trailing space.
    assert lines[3] == "1400019cd RET"
    assert lines[3] == lines[3].rstrip()


def test_format_with_bytes_includes_byte_column():
    listing = GhidraTools._format_disassembly(ROWS, include_bytes=True)
    lines = listing.split("\n")

    assert len(lines) == 4
    # Raw bytes appear as the second field: address bytes mnemonic operands.
    assert lines[0] == "1400019c0 4883ec28 SUB RSP,0x28"
    assert lines[1] == "1400019c4 e8cf050000 CALL 0x140001f98"
    assert lines[3] == "1400019cd c3 RET"
    # No alignment padding: lines have no runs of consecutive spaces.
    for line in lines:
        assert "  " not in line


def test_format_empty_rows_returns_empty_string():
    assert GhidraTools._format_disassembly([], include_bytes=False) == ""
    assert GhidraTools._format_disassembly([], include_bytes=True) == ""
