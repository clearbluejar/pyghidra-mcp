import tomli

from pyghidra_mcp import __version__


def test_version_matches_pyproject():
    """Ensures that the version in pyproject.toml and __init__.py match."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    assert __version__ == pyproject["project"]["version"]


def test_mcp_dependency_excludes_incompatible_v2():
    """Keep the legacy FastMCP import on the compatible MCP major version."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)

    expected = "mcp[cli]>=1.26.0,<2"
    assert expected in pyproject["project"]["dependencies"]
    assert expected in pyproject["dependency-groups"]["dev"]
    assert expected in pyproject["project"]["optional-dependencies"]["dev"]
