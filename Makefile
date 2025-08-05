# PyGhidra MCP Makefile
# Development and deployment commands for the PyGhidra MCP server

.PHONY: help install install-dev run test test-integration test-unit lint format typecheck clean pre-commit-install check dev build

# Default target
help:
	@echo "PyGhidra MCP - A Ghidra integration for modern IDEs"
	@echo ""
	@echo "Available commands:"
	@echo "  install            Install project dependencies"
	@echo "  install-dev        Install with development dependencies"
	@echo "  run                Run the MCP server"
	@echo "  test               Run the full test suite (unit and integration)"
	@echo "  test-unit          Run unit tests"
	@echo "  test-integration   Run integration tests"
	@echo "  lint               Check code style with ruff"
	@echo "  format             Format code with ruff"
	@echo "  typecheck          Run type checking with ruff"
	@echo "  pre-commit-install Install pre-commit hooks"
	@echo "  clean              Clean build artifacts and cache"
	@echo "  dev-setup          Setup development environment"
	@echo "  check              Run all quality checks"
	@echo "  dev                Run development workflow"
	@echo "  build              Build distribution packages"

# Installation targets
install:
	@echo "Installing PyGhidra MCP dependencies..."
	uv sync

install-dev:
	@echo "Installing PyGhidra MCP with development dependencies..."
	uv sync --extra dev

# Run the server
run:
	@echo "Starting PyGhidra MCP server..."
	uv run pyghidra-mcp

# Testing targets
test: test-unit test-integration
	@echo "Running full test suite..."

test-unit:
	@echo "Running unit tests..."
	uv run pytest tests/unit/ -v

test-integration:
	@echo "Running integration tests..."
	uv run pytest tests/integration/ -v

# Code quality targets
lint:
	@echo "Checking code style with ruff..."
	uv run ruff check src/ tests/

format:
	@echo "Formatting code with ruff..."
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

typecheck:
	@echo "Running type checking with ruff..."
	uv run ruff check src/ --select=F

# Pre-commit setup
pre-commit-install:
	@echo "Installing pre-commit hooks..."
	uv run pre-commit install
	@echo "✅ Pre-commit hooks installed"
	@echo "   Hooks will run automatically on git commit"
	@echo "   To run manually: uv run pre-commit run --all-files"

# Maintenance
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Development workflow
dev-setup: install-dev pre-commit-install
	@echo "Development environment setup complete!"
	@echo "Run 'make run' to start the server"
	@echo "Run 'make test' to run tests"
	@echo "Pre-commit hooks are installed and will run on git commit"

# Build and quality check
check: lint typecheck test
	@echo "All checks passed!"

# Complete development workflow
dev: format check
	@echo "Development workflow complete!"

# Release preparation
build:
	@echo "Building distribution packages..."
	uv build
