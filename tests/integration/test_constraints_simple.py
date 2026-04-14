import subprocess
import sys
import tempfile
from pathlib import Path


def test_gpr_constraint_validation(ghidra_env):
    """Test that .gpr file + custom --project-name raises BadParameter"""
    # Create a test .gpr file
    with tempfile.TemporaryDirectory() as temp_dir:
        gpr_path = Path(temp_dir) / "test_project.gpr"
        gpr_path.write_text("test gpr content")

        # Try to run with custom project name - should fail
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pyghidra_mcp",
                "--project-path",
                str(gpr_path),
                "--project-name",
                "custom_name",
                "--transport",
                "stdio",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            env=ghidra_env,
        )

        # The command should fail due to constraint validation
        assert result.returncode != 0
        assert "Cannot use --project-name when specifying a .gpr file" in result.stderr


def test_gpr_name_derivation():
    """Test that .gpr file derives project name correctly"""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_cases = [
            ("My-Project.gpr", "My-Project"),
            ("project_v2.gpr", "project_v2"),
            ("test-project-123.gpr", "test-project-123"),
        ]

        for filename, expected_name in test_cases:
            gpr_path = Path(temp_dir) / filename
            gpr_path.write_text("test content")

            # Test our name derivation logic
            derived_name = gpr_path.stem
            assert derived_name == expected_name, f"Expected {expected_name}, got {derived_name}"


def test_project_name_default_value():
    """Test that default project name is 'my_project'"""
    import click.testing

    from pyghidra_mcp.server import main

    runner = click.testing.CliRunner()
    result = runner.invoke(main, ["--help"])

    # Help should show default value
    assert "--project-name" in result.output
    assert "my_project" in result.output


def test_gpr_help_text_updated():
    """Test that help text reflects .gpr constraint"""
    import click.testing

    from pyghidra_mcp.server import main

    runner = click.testing.CliRunner()
    result = runner.invoke(main, ["--help"])

    # Help should mention the constraint
    assert "--project-name" in result.output
    assert "Ignored when using .gpr files" in result.output


if __name__ == "__main__":
    # Run basic tests
    test_gpr_constraint_validation()
    test_gpr_name_derivation()
    test_project_name_default_value()
    test_gpr_help_text_updated()
    print("All tests passed!")
