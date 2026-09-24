import tomli
from click.testing import CliRunner

from pyghidra_mcp import __version__
from pyghidra_mcp.server import main, mcp


def test_version_matches_pyproject():
    """Ensures that the version in pyproject.toml and __init__.py match."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    assert __version__ == pyproject["project"]["version"]


def test_server_reports_package_version_to_mcp_clients():
    options = mcp._mcp_server.create_initialization_options()
    assert options.server_version == __version__


def test_server_cli_reports_package_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_mcp_dependency_excludes_incompatible_v2():
    """Keep the legacy FastMCP import on the compatible MCP major version."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)

    expected = "mcp[cli]>=1.26.0,<2"
    assert expected in pyproject["project"]["dependencies"]
    assert expected in pyproject["dependency-groups"]["dev"]
    assert expected in pyproject["project"]["optional-dependencies"]["dev"]
