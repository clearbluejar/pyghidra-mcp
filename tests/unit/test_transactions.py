import pytest

from pyghidra_mcp.tools import ghidra_transaction


class FakeProgram:
    def __init__(self):
        self.ended = []

    def startTransaction(self, description):  # noqa: N802
        self.description = description
        return 7

    def endTransaction(self, tx_id, committed):  # noqa: N802
        self.ended.append((tx_id, committed))


def test_ghidra_transaction_commits_on_success():
    program = FakeProgram()

    with ghidra_transaction(program, "test transaction"):
        pass

    assert program.description == "test transaction"
    assert program.ended == [(7, True)]


def test_ghidra_transaction_rolls_back_on_exception():
    program = FakeProgram()

    with pytest.raises(RuntimeError):
        with ghidra_transaction(program, "test transaction"):
            raise RuntimeError("boom")

    assert program.ended == [(7, False)]
