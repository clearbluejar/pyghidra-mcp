import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock

from pyghidra_mcp.tools import GhidraTools


def _make_tools():
    tools = GhidraTools.__new__(GhidraTools)
    tools.program = Mock()
    tools.decompiler_pool = Mock()
    tools.invalidate_decompiler_cache = Mock()
    return tools


def _install_listing_module(monkeypatch):
    listing_module = SimpleNamespace(
        CommentType=SimpleNamespace(PLATE=0, PRE=1, EOL=2, POST=3, REPEATABLE=4)
    )
    monkeypatch.setitem(sys.modules, "ghidra.program.model.listing", listing_module)


def test_set_comment_resolves_symbol_target(monkeypatch):
    tools = _make_tools()
    _install_listing_module(monkeypatch)
    monkeypatch.setattr(
        "pyghidra_mcp.tools.ghidra_transaction",
        lambda *_args, **_kwargs: nullcontext(),
    )

    addr = Mock()
    addr.__str__ = Mock(return_value="10001000")
    symbol = Mock()
    symbol.getAddress.return_value = addr

    tools._parse_address = Mock(side_effect=ValueError("not an address"))
    tools.find_symbol = Mock(return_value=symbol)
    tools.find_function = Mock(side_effect=AssertionError("should not fall back to function"))

    result = tools.set_comment("safe_exec", "note", "plate")

    tools.program.getListing.return_value.setComment.assert_called_once_with(addr, 0, "note")
    assert result["address"] == "10001000"
    assert result["comment_type"] == "plate"


def test_set_comment_resolves_decimal_address(monkeypatch):
    tools = _make_tools()
    _install_listing_module(monkeypatch)
    monkeypatch.setattr(
        "pyghidra_mcp.tools.ghidra_transaction",
        lambda *_args, **_kwargs: nullcontext(),
    )

    parsed_addr = Mock()
    parsed_addr.__str__ = Mock(return_value="1000")
    tools._parse_address = Mock(side_effect=ValueError("hex parse failed"))
    tools.find_symbol = Mock(side_effect=ValueError("not a symbol"))
    tools.find_function = Mock(side_effect=ValueError("not a function"))
    addr_space = tools.program.getAddressFactory.return_value.getDefaultAddressSpace.return_value
    addr_space.getAddress.return_value = parsed_addr

    result = tools.set_comment("4096", "note", "plate")

    tools.program.getListing.return_value.setComment.assert_called_once_with(parsed_addr, 0, "note")
    assert result["address"] == "1000"
