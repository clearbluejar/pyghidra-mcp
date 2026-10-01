import tomli
from click.testing import CliRunner

from pyghidra_mcp_cli import __version__
from pyghidra_mcp_cli.main import cli


def test_version_matches_pyproject():
    """Ensures that the version in pyproject.toml and __init__.py match."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    assert __version__ == pyproject["project"]["version"]


def test_cli_reports_package_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"pyghidra-mcp-cli, version {__version__}"
