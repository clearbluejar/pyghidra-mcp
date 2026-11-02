from unittest.mock import Mock

import pytest
import tomli
from click.testing import CliRunner
from mcp import ClientSession

from pyghidra_mcp import __version__
from pyghidra_mcp.server import main, mcp


def test_version_matches_pyproject():
    """Ensures that the version in pyproject.toml and __init__.py match."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    assert __version__ == pyproject["project"]["version"]


@pytest.mark.asyncio
async def test_server_reports_package_version_to_mcp_clients(monkeypatch, mcp_transport):
    monkeypatch.setattr(mcp, "_pyghidra_context", Mock(), raising=False)

    async with mcp_transport(mcp) as (read, write):
        async with ClientSession(read, write) as session:
            result = await session.initialize()

    assert result.model_dump(by_alias=True)["serverInfo"]["version"] == __version__


def test_server_cli_reports_package_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_mcp_dependency_supports_both_sdk_majors():
    """Keep the runtime and development dependency bounds consistent."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)

    expected = "mcp[cli]>=1.26.0,<3"
    assert expected in pyproject["project"]["dependencies"]
    assert expected in pyproject["dependency-groups"]["dev"]
    assert expected in pyproject["project"]["optional-dependencies"]["dev"]
