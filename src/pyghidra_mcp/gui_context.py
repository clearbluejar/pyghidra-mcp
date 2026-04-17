import concurrent.futures
import json
import logging
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pyghidra_mcp.context import ProgramInfo
from pyghidra_mcp.import_detection import is_ghidra_importable
from pyghidra_mcp.import_planning import ImportCandidate, build_import_plan
from pyghidra_mcp.indexing_mixin import IndexingMixin
from pyghidra_mcp.models import (
    ImportRequestResult,
    ProgramInfo as ProgramInfoModel,
    SkippedImport as SkippedImportModel,
)
from pyghidra_mcp.project_spec import ProjectSpec

logger = logging.getLogger(__name__)


def _run_on_swing(fn, *args, **kwargs):
    import jpype
    from ghidra.util import Swing
    from java.lang import Runnable  # type: ignore

    result_box: list[Any] = [None]
    exc_box: list[BaseException | None] = [None]

    def runnable():
        try:
            result_box[0] = fn(*args, **kwargs)
        except BaseException as e:
            exc_box[0] = e

    Swing.runNow(jpype.JProxy(Runnable, dict={"run": runnable}))
    if exc_box[0] is not None:
        raise exc_box[0]
    return result_box[0]


class GuiPyGhidraContext(IndexingMixin):
    """MCP context backed by the active in-process Ghidra GUI project.

    The GUI owns the project and Program lifecycle. This context owns only MCP-side
    helpers such as DecompInterface instances and Python references.
    """

    def __init__(
        self,
        project_spec: ProjectSpec,
        *,
        pyghidra_mcp_dir: Path | None = None,
        readiness_timeout: float = 30.0,
        readiness_interval: float = 0.2,
    ):
        self.project_spec = project_spec
        self.project_name = project_spec.project_name
        self.project_path = project_spec.project_directory
        self.pyghidra_mcp_dir = pyghidra_mcp_dir or project_spec.pyghidra_mcp_dir
        self.programs: dict[str, ProgramInfo] = {}
        self._programs_lock = threading.RLock()
        self.import_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._init_indexing_state(self.pyghidra_mcp_dir, threaded=True)

        self.project = self.wait_for_gui_ready(
            project_spec,
            timeout=readiness_timeout,
            interval=readiness_interval,
        )
        self.refresh_programs()

    @staticmethod
    def wait_for_gui_ready(
        project_spec: ProjectSpec,
        timeout: float = 30.0,
        interval: float = 0.2,
    ):
        """Wait until Ghidra has an active project, opening it if the GUI is idle."""
        from ghidra.framework.main import AppInfo

        deadline = time.time() + timeout
        attempted_open = False
        while time.time() < deadline:
            project = AppInfo.getActiveProject()
            if project is not None:
                return project

            front_end_tool = AppInfo.getFrontEndTool()
            if front_end_tool is not None and not attempted_open:
                attempted_open = True

                def do_open(front_end_tool=front_end_tool, project_spec=project_spec):
                    from ghidra.framework.model import ProjectLocator

                    active_project = AppInfo.getActiveProject()
                    if active_project is not None:
                        return active_project

                    project_manager = front_end_tool.getProjectManager()
                    locator = project_manager.getLastOpenedProject()
                    if locator is None:
                        locator = ProjectLocator(
                            str(project_spec.project_directory.absolute()),
                            project_spec.project_name,
                        )
                    opened_project = project_manager.openProject(locator, True, False)
                    front_end_tool.setActiveProject(opened_project)
                    return opened_project

                try:
                    project = _run_on_swing(do_open)
                except Exception:
                    logger.exception(
                        "Failed to explicitly open GUI project %s; continuing to wait.",
                        project_spec.gpr_path,
                    )
                else:
                    if project is not None:
                        return project
            time.sleep(interval)

        raise RuntimeError("Timed out waiting for Ghidra GUI active project.")

    def refresh_programs(self) -> None:
        active: dict[str, Any] = {}
        for program_manager in self._get_program_managers():
            for program in program_manager.getAllOpenPrograms():
                domain_file = program.getDomainFile()
                key = domain_file.getPathname() if domain_file else program.getName()
                active[str(key)] = program

        with self._programs_lock:
            stale_keys = set(self.programs) - set(active)
            for key in stale_keys:
                self._dispose_decompiler(self.programs[key])
                del self.programs[key]

            for key, program in active.items():
                if key not in self.programs:
                    self.programs[key] = self._init_program_info(program)
                    continue

                program_info = self.programs[key]
                if program_info.program != program:
                    self._dispose_decompiler(program_info)
                    self.programs[key] = self._init_program_info(program)
                    continue

                self._sync_program_info(program_info, program)

    def list_binaries(self) -> list[str]:
        return [df.getPathname() for df in self.list_binary_domain_files()]

    def list_binary_domain_files(self) -> list[Any]:
        return self._list_folder_domain_files(self.project.getProjectData().getRootFolder())

    def list_open_programs(self) -> list[dict[str, Any]]:
        self.refresh_programs()
        program_manager = self._get_primary_program_manager(required=False)
        current_program = program_manager.getCurrentProgram() if program_manager else None

        with self._programs_lock:
            results = []
            for path, program_info in self.programs.items():
                results.append(
                    {
                        "name": program_info.name,
                        "path": path,
                        "current": program_info.program == current_program,
                        "analysis_complete": program_info.analysis_complete,
                    }
                )
            return results

    def open_program_in_gui(self, binary_name: str, *, current: bool = False) -> dict[str, Any]:
        from ghidra.app.services import ProgramManager
        from ghidra.framework.model import DomainFile

        domain_file = self._find_domain_file(binary_name)
        program_manager = self._get_primary_program_manager(required=False)
        if program_manager is None:
            from java.util import List  # type: ignore

            tool = self.project.getToolServices().launchDefaultTool(List.of(domain_file))
            if tool is None:
                raise RuntimeError(f"Failed to launch a Ghidra tool for {binary_name}")
            program_manager = self._get_primary_program_manager()

        assert program_manager is not None
        state = ProgramManager.OPEN_CURRENT if current else ProgramManager.OPEN_VISIBLE
        program_manager.openProgram(domain_file, DomainFile.DEFAULT_VERSION, state)

        expected_path = str(domain_file.getPathname())
        deadline = time.time() + 10
        while time.time() < deadline:
            self.refresh_programs()
            with self._programs_lock:
                program_info = self.programs.get(expected_path)
                if program_info is not None:
                    self.schedule_indexing(expected_path)
                    return {
                        "name": program_info.name,
                        "path": expected_path,
                        "current": current
                        or program_info.program == program_manager.getCurrentProgram(),
                        "analysis_complete": program_info.analysis_complete,
                    }
            time.sleep(0.1)

        raise RuntimeError(f"Timed out waiting for GUI to open program {expected_path}")

    def set_current_program(self, binary_name: str) -> dict[str, Any]:
        return self.open_program_in_gui(binary_name, current=True)

    def run_on_swing(self, fn, *args, **kwargs):
        return _run_on_swing(fn, *args, **kwargs)

    def goto(self, binary_name: str, target: str, target_type: str) -> dict[str, Any]:
        normalized_type = target_type.lower()
        program_info = self._resolve_program_info(binary_name)

        if normalized_type == "function":
            from pyghidra_mcp.tools import GhidraTools

            function = GhidraTools(program_info).find_function(target)
            address_obj = function.getEntryPoint()
        elif normalized_type == "address":
            address_obj = self._parse_address(program_info.program, target)
        else:
            raise ValueError(
                f"Invalid target_type '{target_type}'. Expected one of: ['address', 'function']"
            )

        tool = self._find_tool_for_program(program_info.program)

        from ghidra.app.services import GoToService

        service = tool.getService(GoToService)
        if service is None:
            raise RuntimeError("No GoToService is available in the active Ghidra tool.")

        def do_goto():
            return bool(service.goTo(address_obj, program_info.program))

        success = bool(self.run_on_swing(do_goto))
        return {
            "binary_name": binary_name,
            "address": str(address_obj),
            "success": success,
        }

    def _get_program_managers(self) -> list[Any]:
        from ghidra.app.services import ProgramManager

        program_managers = []
        for tool in self.project.getToolServices().getRunningTools():
            program_manager = tool.getService(ProgramManager)
            if program_manager is not None:
                program_managers.append(program_manager)
        return program_managers

    def _get_primary_program_manager(self, *, required: bool = True):
        program_managers = self._get_program_managers()
        if program_managers:
            return program_managers[0]
        if required:
            raise RuntimeError("No Ghidra tool with ProgramManager is available.")
        return None

    def _find_tool_for_program(self, program):
        from ghidra.app.services import ProgramManager

        fallback_tool = None
        for tool in self.project.getToolServices().getRunningTools():
            program_manager = tool.getService(ProgramManager)
            if program_manager is None:
                continue
            fallback_tool = fallback_tool or tool
            if program in list(program_manager.getAllOpenPrograms()):
                return tool
        if fallback_tool is not None:
            return fallback_tool
        raise RuntimeError("No Ghidra tool with ProgramManager is available.")

    def _find_domain_file(self, binary_name: str):
        matches = []
        for domain_file in self.list_binary_domain_files():
            path = str(domain_file.getPathname())
            name = str(domain_file.getName())
            if binary_name in {path, name, Path(path).name}:
                matches.append(domain_file)

        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            paths = [str(domain_file.getPathname()) for domain_file in matches]
            raise ValueError(
                f"Binary name '{binary_name}' is ambiguous. Use one of these paths: {paths}"
            )
        raise ValueError(f"Binary {binary_name} not found in project.")

    @staticmethod
    def _parse_address(program, address: str):
        addr_str = address[2:] if address.lower().startswith("0x") else address
        addr = program.getAddressFactory().getAddress(addr_str)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")
        return addr

    @staticmethod
    def _list_folder_domain_files(folder) -> list[Any]:
        def list_folder_domain_files(folder) -> list[Any]:
            files: list[Any] = []
            for subfolder in folder.getFolders():
                files.extend(list_folder_domain_files(subfolder))
            files.extend([f for f in folder.getFiles() if f.getContentType() == "Program"])
            return files

        return list_folder_domain_files(folder)

    def list_program_infos(self) -> list[ProgramInfo]:
        self.refresh_programs()
        with self._programs_lock:
            return list(self.programs.values())

    def list_project_binary_infos(self) -> list[ProgramInfoModel]:
        self.refresh_programs()
        with self._programs_lock:
            live_programs = dict(self.programs)

        program_infos = []
        for domain_file in self.list_binary_domain_files():
            path = str(domain_file.getPathname())
            live_info = live_programs.get(path)
            if live_info is not None:
                program_infos.append(
                    ProgramInfoModel(
                        name=path,
                        file_path=str(live_info.file_path) if live_info.file_path else None,
                        load_time=live_info.load_time,
                        analysis_complete=live_info.analysis_complete,
                        metadata=live_info.metadata,
                        code_indexed=live_info.code_collection is not None,
                        strings_indexed=live_info.strings is not None,
                    )
                )
                continue

            metadata = dict(domain_file.getMetadata() or {})
            executable_location = metadata.get("Executable Location")
            analyzed_value = str(metadata.get("Analyzed", "")).lower()
            program_infos.append(
                ProgramInfoModel(
                    name=path,
                    file_path=executable_location,
                    load_time=None,
                    analysis_complete=analyzed_value == "true",
                    metadata=metadata,
                    code_indexed=False,
                    strings_indexed=False,
                )
            )
        return program_infos

    def get_program_info(self, binary_name: str) -> ProgramInfo:
        program_info = self._resolve_program_info(binary_name)

        if not program_info.analysis_complete:
            raise RuntimeError(
                json.dumps(
                    {
                        "message": f"Analysis incomplete for binary '{binary_name}'.",
                        "binary_name": binary_name,
                        "ghidra_analysis_complete": program_info.ghidra_analysis_complete,
                        "code_indexed": program_info.code_collection is not None,
                        "strings_indexed": program_info.strings is not None,
                        "suggestion": "Wait and try tool call again.",
                    }
                )
            )
        self.schedule_indexing(binary_name)
        return program_info

    def _resolve_program_info(self, binary_name: str) -> ProgramInfo:
        self.refresh_programs()
        with self._programs_lock:
            program_info = self.programs.get(binary_name)
            if program_info is None:
                program_info = self._get_unique_short_name_match(binary_name)

            if program_info is None:
                available_progs = list(self.programs.keys())
                try:
                    opened_info = self.open_program_in_gui(binary_name)
                except ValueError:
                    raise ValueError(
                        f"Binary {binary_name} not found. Available binaries: {available_progs}"
                    ) from None
                program_info = self.programs.get(opened_info["path"])
                if program_info is None:
                    raise ValueError(
                        f"Binary {binary_name} could not be opened. Available binaries: "
                        f"{available_progs}"
                    )
        return program_info

    def delete_program(self, program_name: str) -> bool:
        try:
            program_info = self._resolve_program_info(program_name)
            program = program_info.program
            domain_file = program.getDomainFile()
        except ValueError:
            program_info = None
            program = None
            domain_file = self._find_domain_file(program_name)

        for program_manager in self._get_program_managers():
            if program is not None and program in list(program_manager.getAllOpenPrograms()):
                if not bool(program_manager.closeProgram(program, False)):
                    return False

        if program_info is not None:
            self._dispose_decompiler(program_info)

        domain_file.delete()
        self.refresh_programs()
        return True

    def import_binaries(self, binary_paths: Sequence[str | Path]) -> list[str]:
        import_plan = build_import_plan(binary_paths)
        for skipped in import_plan.skipped:
            logger.info("Skipping %s: %s", skipped.path, skipped.reason)

        return self._import_candidates(import_plan.candidates)

    def _import_candidates(self, candidates: list[ImportCandidate]) -> list[str]:
        imported_programs: list[str] = []
        for candidate in candidates:
            imported = self.import_binary(candidate.path, relative_path=candidate.relative_path)
            if isinstance(imported, list):
                imported_programs.extend(imported)
            else:
                imported_programs.append(imported)
        return imported_programs

    def import_binary(
        self, binary_path: str | Path, relative_path: Path | None = None
    ) -> str | list[str]:
        from ghidra.app.util.importer import ProgramLoader
        from ghidra.util.task import TaskMonitor
        from java.io import File  # type: ignore

        from pyghidra_mcp.context import PyGhidraContext

        binary_path = Path(binary_path)
        if binary_path.is_dir():
            return self.import_binaries([binary_path])

        program_name = PyGhidraContext._gen_unique_bin_name(binary_path)
        folder_path = (
            "/" if relative_path is None or str(relative_path) == "." else f"/{relative_path}"
        )
        expected_path = str(Path(folder_path) / program_name)

        try:
            self.open_program_in_gui(expected_path)
            return expected_path
        except ValueError:
            pass

        load_results = None
        try:
            load_results = (
                ProgramLoader.builder()
                .source(File(str(binary_path.absolute())))
                .project(self.project)
                .projectFolderPath(folder_path)
                .name(program_name)
                .monitor(TaskMonitor.DUMMY)
                .load()
            )
            domain_file = load_results.getPrimary().save(TaskMonitor.DUMMY)
        finally:
            if load_results is not None:
                load_results.close()

        opened = self.open_program_in_gui(str(domain_file.getPathname()))
        return str(opened["path"])

    def import_binary_backgrounded(self, binary_path: str | Path) -> ImportRequestResult:
        binary_path = Path(binary_path)
        if not binary_path.exists():
            raise FileNotFoundError(f"The file {binary_path} cannot be found")

        import_plan = build_import_plan([binary_path])

        if import_plan.candidates:
            future = self.import_executor.submit(self._import_candidates, import_plan.candidates)
            future.add_done_callback(self._import_done_callback)

        queued_paths = [str(candidate.path) for candidate in import_plan.candidates]
        skipped = [
            SkippedImportModel(path=str(skipped.path), reason=skipped.reason)
            for skipped in import_plan.skipped
        ]
        message = (
            f"Queued {len(queued_paths)} import(s) from {binary_path} in the background."
            if queued_paths
            else f"No importable files were queued from {binary_path}."
        )
        return ImportRequestResult(
            requested_path=str(binary_path),
            queued_count=len(queued_paths),
            queued_paths=queued_paths,
            skipped_count=len(skipped),
            skipped=skipped,
            message=message,
        )

    def schedule_startup_indexing(self, *, max_binaries: int | None = None) -> None:
        """Index currently open GUI programs in the background."""
        self.refresh_programs()
        with self._programs_lock:
            program_paths = list(self.programs)
        for binary_name in program_paths:
            self.schedule_indexing(binary_name)

    def close(self, save: bool = True) -> None:
        """Release MCP-owned resources. Does not close the GUI project or programs."""
        self.import_executor.shutdown(wait=True)
        self.shutdown_indexing()
        with self._programs_lock:
            for program_info in self.programs.values():
                self._dispose_decompiler(program_info)
            self.programs.clear()

    @staticmethod
    def _is_binary_file(path: Path) -> bool:
        return is_ghidra_importable(path)

    @staticmethod
    def _import_done_callback(future: concurrent.futures.Future) -> None:
        try:
            future.result()
            logger.info("GUI background import completed successfully.")
        except Exception:
            logger.error("GUI background import failed.", exc_info=True)

    def _get_unique_short_name_match(self, binary_name: str) -> ProgramInfo | None:
        matches: list[tuple[str, ProgramInfo]] = []
        for full_path, program_info in self.programs.items():
            domain_file = program_info.program.getDomainFile()
            names = {Path(full_path).name, program_info.name}
            if domain_file is not None:
                names.add(str(domain_file.getName()))
            if binary_name in names:
                matches.append((full_path, program_info))

        if len(matches) == 1:
            return matches[0][1]
        if len(matches) > 1:
            paths = [path for path, _program_info in matches]
            raise ValueError(
                f"Binary name '{binary_name}' is ambiguous. Use one of these paths: {paths}"
            )
        return None

    def _lookup_program_info(self, binary_name: str) -> ProgramInfo | None:
        try:
            return self._resolve_program_info(binary_name)
        except ValueError:
            return None

    def _init_program_info(self, program) -> ProgramInfo:
        from ghidra.program.flatapi import FlatProgramAPI

        program_info = ProgramInfo(
            name=program.getName(),
            program=program,
            flat_api=FlatProgramAPI(program),
            decompiler=self._setup_decompiler(program),
            metadata={},
            ghidra_analysis_complete=False,
            file_path=None,
            load_time=time.time(),
            code_collection=None,
            strings=None,
        )
        self._sync_program_info(program_info, program)
        return program_info

    def _sync_program_info(self, program_info: ProgramInfo, program) -> None:
        metadata = dict(program.getMetadata())
        executable_location = metadata.get("Executable Location")

        program_info.name = program.getName()
        program_info.program = program
        program_info.metadata = metadata
        program_info.file_path = Path(executable_location) if executable_location else None
        program_info.ghidra_analysis_complete = self._is_program_analysis_complete(program)

    @staticmethod
    def _is_program_analysis_complete(program) -> bool:
        from ghidra.program.util import GhidraProgramUtilities

        try:
            return not bool(GhidraProgramUtilities.shouldAskToAnalyze(program))
        except Exception:
            logger.debug("Could not determine GUI program analysis state", exc_info=True)
            return False

    @staticmethod
    def _setup_decompiler(program):
        from ghidra.app.decompiler import DecompileOptions, DecompInterface

        options = DecompileOptions()
        options.grabFromProgram(program)
        options.setMaxPayloadMBytes(100)

        decompiler = DecompInterface()
        decompiler.setOptions(options)
        decompiler.openProgram(program)
        return decompiler

    @staticmethod
    def _dispose_decompiler(program_info: ProgramInfo) -> None:
        decompiler = program_info.decompiler
        for method_name in ("dispose", "closeProgram"):
            method = getattr(decompiler, method_name, None)
            if method is not None:
                try:
                    method()
                except Exception:
                    logger.debug("Failed to dispose decompiler with %s", method_name, exc_info=True)
                return
