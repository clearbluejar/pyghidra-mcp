import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def is_ghidra_importable(path: Path, *, allow_binary_loader: bool = False) -> bool:
    """Return whether Ghidra advertises any loader support for this file."""
    if not path.is_file():
        return False

    from ghidra.app.util.opinion import LoaderService
    from ghidra.formats.gfilesystem import FileSystemService
    from ghidra.util.task import TaskMonitor
    from java.io import File  # type: ignore

    fs_service = FileSystemService.getInstance()
    provider = None

    try:
        fsrl = fs_service.getLocalFSRL(File(str(path.absolute())))
        provider = fs_service.getByteProvider(fsrl, True, TaskMonitor.DUMMY)
        loader_map = LoaderService.getAllSupportedLoadSpecs(provider)
        if bool(loader_map.isEmpty()):
            return False

        loader_names = {
            str(loader.getClass().getSimpleName()) for loader in loader_map.keySet().toArray()
        }
        if loader_names == {"BinaryLoader"}:
            return allow_binary_loader
        return True
    except Exception:
        logger.debug("Failed to detect Ghidra import support for %s", path, exc_info=True)
        return False
    finally:
        if provider is not None:
            try:
                provider.close()
            except Exception:
                logger.debug("Failed to close ByteProvider for %s", path, exc_info=True)
