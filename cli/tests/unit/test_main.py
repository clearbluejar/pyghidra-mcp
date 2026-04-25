from click.testing import CliRunner

from pyghidra_mcp_cli.main import cli


def test_top_level_help_lists_edit_groups():
    runner = CliRunner()

    result = runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "rename" in result.output
    assert "set" in result.output
    assert "open" in result.output
    assert "goto" in result.output


def test_set_help_lists_edit_subcommands():
    runner = CliRunner()

    result = runner.invoke(cli, ["set", "--help"])

    assert result.exit_code == 0
    assert "variable-type" in result.output
    assert "function-prototype" in result.output
    assert "comment" in result.output
    assert "current-program" in result.output


def test_rename_help_lists_edit_subcommands():
    runner = CliRunner()

    result = runner.invoke(cli, ["rename", "--help"])

    assert result.exit_code == 0
    assert "function" in result.output
    assert "variable" in result.output


def test_list_help_lists_gui_subcommand():
    runner = CliRunner()

    result = runner.invoke(cli, ["list", "--help"])

    assert result.exit_code == 0
    assert "open-programs" in result.output


def test_open_help_lists_program_subcommand():
    runner = CliRunner()

    result = runner.invoke(cli, ["open", "--help"])

    assert result.exit_code == 0
    assert "program" in result.output


def test_goto_help_lists_gui_options():
    runner = CliRunner()

    result = runner.invoke(cli, ["goto", "--help"])

    assert result.exit_code == 0
    assert "--binary" in result.output
    assert "--type" in result.output
