from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from .context import ProgramInfo
    from .models import ProgramInfo as ProgramInfoModel


class MCPContext(Protocol):
    """Tool-facing context contract shared by headless and GUI modes."""

    programs: dict[str, "ProgramInfo"]

    def get_program_info(self, binary_name: str) -> "ProgramInfo": ...

    def list_binaries(self) -> list[str]: ...

    def list_binary_domain_files(self) -> list[Any]: ...

    def list_program_infos(self) -> list["ProgramInfo"]: ...

    def list_project_binary_infos(self) -> list["ProgramInfoModel"]: ...

    def delete_program(self, program_name: str) -> bool: ...

    def import_binary_backgrounded(self, binary_path: str | Path) -> None: ...

    def close(self, save: bool = True) -> None: ...
