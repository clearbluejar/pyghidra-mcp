import json
import tempfile
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.fixture(scope="module")
def multi_project_directory():
    """Create a temporary directory for multi-project testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        project_dir = Path(temp_dir)
        yield project_dir


@pytest.fixture(scope="module")
def server_params_specific_project(multi_project_directory):
    """Server pointing to specific project directory in multi-project directory"""
    project_dir = multi_project_directory / "afd-11"
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(project_dir),
            "--project-name",
            "afd-11",
            "--wait-for-analysis",
        ],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_other_project(multi_project_directory):
    """Server pointing to different project directory in same directory"""
    project_dir = multi_project_directory / "macos-test"
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(project_dir),
            "--project-name",
            "macos-test",
            "--wait-for-analysis",
        ],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_open_specific_project_from_multi_project_directory(
    server_params_specific_project, multi_project_directory
):
    """Test opening specific project when multiple projects exist in same directory"""
    async with stdio_client(server_params_specific_project) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Should be able to list binaries (may be empty for new project)
            results = await session.call_tool("list_project_binaries", {})
            assert results is not None
            assert len(results.content) > 0

            program_infos = json.loads(results.content[0].text)
            assert "programs" in program_infos
            assert isinstance(program_infos["programs"], list)

            # Verify that the correct project was opened
            # The project should be "afd-11" from the project name
            afd_artifact_dir = multi_project_directory / "afd-11" / "afd-11-pyghidra-mcp"
            assert afd_artifact_dir.exists(), "Artifact directory for afd-11 should be created"
            assert (afd_artifact_dir / "chromadb").exists(), "ChromaDB should exist for afd-11"
            assert (afd_artifact_dir / "gzfs").exists(), "GZFS should exist for afd-11"


@pytest.mark.asyncio
async def test_open_different_project_from_same_directory(
    server_params_other_project, multi_project_directory
):
    """Test opening different project from same multi-project directory"""
    async with stdio_client(server_params_other_project) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Should be able to list binaries
            results = await session.call_tool("list_project_binaries", {})
            assert results is not None
            assert len(results.content) > 0

            program_infos = json.loads(results.content[0].text)
            assert "programs" in program_infos
            assert isinstance(program_infos["programs"], list)

            # Verify that the correct project was opened
            # The project should be "macos-test" from the project name
            macos_artifact_dir = multi_project_directory / "macos-test" / "macos-test-pyghidra-mcp"
            assert macos_artifact_dir.exists(), (
                "Artifact directory for macos-test should be created"
            )
            assert (macos_artifact_dir / "chromadb").exists(), (
                "ChromaDB should exist for macos-test"
            )
            assert (macos_artifact_dir / "gzfs").exists(), "GZFS should exist for macos-test"


@pytest.mark.asyncio
async def test_projects_are_isolated(
    server_params_specific_project, server_params_other_project, multi_project_directory
):
    """Test that different projects create isolated project directories"""
    # Start first project
    async with stdio_client(server_params_specific_project) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Verify afd-11 project directory was created
            afd_project_dir = multi_project_directory / "afd-11" / "afd-11-pyghidra-mcp"
            assert afd_project_dir.exists(), "afd-11 project directory should exist"

    # Start second project
    async with stdio_client(server_params_other_project) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Verify macos-test project directory was created
            macos_project_dir = multi_project_directory / "macos-test" / "macos-test-pyghidra-mcp"
            assert macos_project_dir.exists(), "macos-test project directory should exist"

    # Verify both projects are separate
    afd_project_dir = multi_project_directory / "afd-11" / "afd-11-pyghidra-mcp"
    macos_project_dir = multi_project_directory / "macos-test" / "macos-test-pyghidra-mcp"

    assert afd_project_dir.exists() and macos_project_dir.exists()
    assert afd_project_dir != macos_project_dir, "Projects should be in separate directories"

    # Verify artifact directories have expected structure
    assert (afd_project_dir / "chromadb").exists(), "afd-11 chromadb should exist"
    assert (afd_project_dir / "gzfs").exists(), "afd-11 gzfs should exist"
    assert (macos_project_dir / "chromadb").exists(), "macos-test chromadb should exist"
    assert (macos_project_dir / "gzfs").exists(), "macos-test gzfs should exist"


@pytest.mark.asyncio
async def test_shared_base_directory_projects():
    """Test that multiple .gpr projects in same base directory get separate artifact directories"""
    with tempfile.TemporaryDirectory() as temp_dir:
        base_dir = Path(temp_dir)

        # Create two project directories in same base directory
        proj1_dir = base_dir / "proj1"
        proj2_dir = base_dir / "proj2"

        server_params1 = StdioServerParameters(
            command="python",
            args=[
                "-m",
                "pyghidra_mcp",
                "--project-path",
                str(proj1_dir),
                "--project-name",
                "proj1",
                "--no-threaded",
            ],
            env={"GHIDRA_INSTALL_DIR": "/ghidra"},
        )

        server_params2 = StdioServerParameters(
            command="python",
            args=[
                "-m",
                "pyghidra_mcp",
                "--project-path",
                str(proj2_dir),
                "--project-name",
                "proj2",
                "--no-threaded",
            ],
            env={"GHIDRA_INSTALL_DIR": "/ghidra"},
        )

        # Start first project
        async with stdio_client(server_params1) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

        # Start second project
        async with stdio_client(server_params2) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

        # Verify both projects have separate artifact directories
        proj1_artifacts = base_dir / "proj1" / "proj1-pyghidra-mcp"
        proj2_artifacts = base_dir / "proj2" / "proj2-pyghidra-mcp"

        assert proj1_artifacts.exists(), "proj1-pyghidra-mcp should be created"
        assert proj2_artifacts.exists(), "proj2-pyghidra-mcp should be created"
        assert proj1_artifacts != proj2_artifacts, (
            "Projects should have separate artifact directories"
        )

        # Verify artifact structure
        assert (proj1_artifacts / "chromadb").exists(), "proj1 chromadb should exist"
        assert (proj1_artifacts / "gzfs").exists(), "proj1 gzfs should exist"
        assert (proj2_artifacts / "chromadb").exists(), "proj2 chromadb should exist"
        assert (proj2_artifacts / "gzfs").exists(), "proj2 gzfs should exist"

        # Verify consistent naming (always append -pyghidra-mcp)
        assert proj1_artifacts.name == "proj1-pyghidra-mcp", (
            "proj1 artifacts should have project name"
        )
        assert proj2_artifacts.name == "proj2-pyghidra-mcp", (
            "proj2 artifacts should have project name"
        )
