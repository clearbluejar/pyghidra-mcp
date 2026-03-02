import os
from pathlib import Path

import pytest

SHARED_SERVER_PARAMS_FIXTURES = (
    "server_params_no_input",
    "server_params",
    "server_params_no_thread",
    "server_params_shared_object",
)


@pytest.fixture(scope="module")
def ghidra_env():
    return os.environ.copy()


@pytest.fixture(scope="module")
def test_binary(tmp_path_factory):
    fake_binary = tmp_path_factory.mktemp("fake-binary") / "fake.bin"
    fake_binary.write_bytes(b"\x7fELF")
    return str(fake_binary)


@pytest.fixture(scope="module")
def test_shared_object(tmp_path_factory):
    fake_shared_object = tmp_path_factory.mktemp("fake-shared-object") / "fake.so"
    fake_shared_object.write_bytes(b"\x7fELF")
    return str(fake_shared_object)


@pytest.mark.parametrize("fixture_name", SHARED_SERVER_PARAMS_FIXTURES)
def test_shared_fixtures_use_explicit_project_path(request, fixture_name):
    server_params = request.getfixturevalue(fixture_name)

    assert "--project-path" in server_params.args
    project_path_index = server_params.args.index("--project-path") + 1
    project_path = Path(server_params.args[project_path_index])

    assert project_path.is_absolute()
    assert project_path.name != "pyghidra_mcp_projects"
