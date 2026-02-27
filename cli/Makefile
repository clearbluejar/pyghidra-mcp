# PyGhidra MCP CLI Makefile
# Development and deployment commands for the PyGhidra MCP CLI

.PONY: help install install-dev test test-unit lint format typecheck clean pre-commit-install check dev build

export UV_CACHE_DIR := $(CURDIR)/.uv-cache

# Default target
help:
	@echo "PyGhidra MCP CLI - Command-line client for pyghidra-mcp"
	@echo ""
	@echo "Available commands:"
	@echo "  install            Install project dependencies"
	@echo "  install-dev        Install with development dependencies"
	@echo "  test               Run all tests"
	@echo "  test-unit          Run unit tests"
	@echo "  lint               Check code style with ruff"
	@echo "  format             Format code with ruff"
	@echo "  typecheck          Run type checking"
	@echo "  pre-commit-install Install pre-commit hooks"
	@echo "  clean              Clean build artifacts and cache"
	@echo "  dev-setup          Setup development environment"
	@echo "  check              Run all quality checks"
	@echo "  build              Build distribution packages"

# Installation targets
install:
	@echo "Installing PyGhidra MCP CLI dependencies..."
	uv sync

install-dev:
	@echo "Installing PyGhidra MCP CLI with development dependencies..."
	uv sync --extra dev

# Testing targets
test:
	@echo "Running tests..."
	uv run pytest tests/ -v

test-unit:
	@echo "Running unit tests..."
	uv run pytest tests/unit/ -v

# Code quality targets
lint:
	@echo "Checking code style with ruff..."
	uv run ruff check src/

format:
	@echo "Formatting code with ruff..."
	uv run ruff format src/
	uv run ruff check --fix src/

typecheck:
	@echo "Running type checking..."
	uv run ruff check src/ --select=F

# Pre-commit setup
pre-commit-install:
	@echo "Installing pre-commit hooks..."
	# Ensure pre-commit is available in the environment.
	# (It's intentionally not a runtime dependency, so it must be installed via the dev extra.)
	uv run python -c "import shutil,sys; sys.exit(0 if shutil.which('pre-commit') else 1)" \
		|| (echo "Error: pre-commit is not installed. Run 'make install-dev' (or 'uv sync --extra dev') first." && exit 1)
	uv run pre-commit install
	@echo "Pre-commit hooks installed"
	@echo "Hooks will run automatically on git commit"
	@echo "To run manually: uv run pre-commit run --all-files"

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
	@echo "Run tests with 'make test'"
	@echo "Pre-commit hooks are installed and will run on git commit"

# Build and quality check
check: lint typecheck test
	@echo "All checks passed!"

# Release preparation
build:
	@echo "Building distribution packages..."
	uv build
