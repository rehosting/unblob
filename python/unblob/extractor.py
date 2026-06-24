"""File extraction related functions."""

import errno
from pathlib import Path

from structlog import get_logger

from .file_utils import carve
from .models import Chunk, File, PaddingChunk, TaskResult, UnknownChunk, ValidChunk

logger = get_logger()

FILE_PERMISSION_MASK = 0
DIR_PERMISSION_MASK = 0


def carve_chunk_to_file(carve_path: Path, file: File, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    logger.debug("Carving chunk", path=carve_path)
    carve(carve_path, file, chunk.start_offset, chunk.size)


def fix_permission(path: Path):
    if path.is_symlink():
        return

    if not path.exists():
        return

    mode = path.stat().st_mode

    if path.is_file():
        mode |= FILE_PERMISSION_MASK
    elif path.is_dir():
        mode |= DIR_PERMISSION_MASK

    path.chmod(mode)


def fix_extracted_directory(outdir: Path, task_result: TaskResult):  # noqa: ARG001
    def _fix_extracted_directory(directory: Path):
        if not directory.exists():
            return
        for path in directory.iterdir():
            try:
                fix_permission(path)
                if path.is_symlink():
                    # Unlike upstream unblob, we allow symlinks to do anything they want. We run in docker so this
                    # isn't as dangerous as it would be otherwise, but it's still probably
                    # a questionable decision.
                    continue
                if path.is_dir():
                    _fix_extracted_directory(path)
            except OSError as e:
                if e.errno == errno.ENAMETOOLONG:
                    continue
                raise e from None

    fix_permission(outdir)
    _fix_extracted_directory(outdir)


def carve_unknown_chunk(
    extract_dir: Path, file: File, chunk: UnknownChunk | PaddingChunk
) -> Path:
    extension = "unknown"
    if isinstance(chunk, PaddingChunk):
        extension = "padding"

    filename = f"{chunk.start_offset}-{chunk.end_offset}.{extension}"
    carve_path = extract_dir / filename
    logger.info("Extracting unknown chunk", path=carve_path, chunk=chunk)
    carve_chunk_to_file(carve_path, file, chunk)
    return carve_path


def carve_valid_chunk(extract_dir: Path, file: File, chunk: ValidChunk) -> Path:
    filename = f"{chunk.start_offset}-{chunk.end_offset}.{chunk.handler.NAME}"
    carve_path = extract_dir / filename
    logger.info("Extracting valid chunk", path=carve_path, chunk=chunk)
    carve_chunk_to_file(carve_path, file, chunk)
    return carve_path
