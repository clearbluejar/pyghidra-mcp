from click.testing import CliRunner

from pyghidra_mcp_cli.main import cli


def test_top_level_help_lists_edit_groups():
    runner = CliRunner()

    result = runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "rename" in result.output
    assert "set" in result.output


def test_set_help_lists_edit_subcommands():
    runner = CliRunner()

    result = runner.invoke(cli, ["set", "--help"])

    assert result.exit_code == 0
    assert "variable-type" in result.output
    assert "function-prototype" in result.output
    assert "comment" in result.output


def test_rename_help_lists_edit_subcommands():
    runner = CliRunner()

    result = runner.invoke(cli, ["rename", "--help"])

    assert result.exit_code == 0
    assert "function" in result.output
    assert "variable" in result.output
