"""Ghidra context management package."""

from pyghidra_mcp.context.analysis_manager import AnalysisManager
from pyghidra_mcp.context.models import ProgramInfo
from pyghidra_mcp.context.project_manager import ProjectManager

# Alias for convenience
PyGhidraContext = ProjectManager

__all__ = ["AnalysisManager", "ProgramInfo", "ProjectManager", "PyGhidraContext"]
