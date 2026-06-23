import itertools
from pathlib import Path, PosixPath

import pytest

from unblob.extractor import (
    DIR_PERMISSION_MASK,
    FILE_PERMISSION_MASK,
    carve_unknown_chunk,
    fix_extracted_directory,
    fix_permission,
)
from unblob.models import File, TaskResult, UnknownChunk


def test_carve_unknown_chunk(tmp_path: Path):
    content = b"test file"
    test_file = File.from_bytes(content)
    chunk = UnknownChunk(start_offset=1, end_offset=8)
    carve_unknown_chunk(tmp_path, test_file, chunk)
    written_path = tmp_path / "1-8.unknown"
    assert list(tmp_path.iterdir()) == [written_path]
    assert written_path.read_bytes() == content[1:8]

    # carving the second time will fail, while not changing the file
    unchanged_content = b"content is unchanged"
    written_path.write_bytes(unchanged_content)

    with pytest.raises(FileExistsError):
        carve_unknown_chunk(tmp_path, test_file, chunk)

    assert written_path.read_bytes() == unchanged_content


def test_fix_permission(tmpdir: Path):
    # Keep the container traversable throughout: the rehosting fork zeroes the
    # permission masks, so fix_permission preserves modes verbatim and does NOT
    # make a restrictive parent accessible again (unlike upstream). Vary a child
    # under an always-0o755 base so the test's own setup/teardown can access it.
    base = PosixPath(tmpdir / "dir")
    base.mkdir()
    tmpfile = PosixPath(base / "file.txt")
    subdir = PosixPath(base / "subdir")

    for user, group, others in itertools.product(range(8), repeat=3):
        permission = (user << 6) + (group << 3) + others

        tmpfile.touch()
        tmpfile.chmod(permission)
        fix_permission(tmpfile)
        assert (tmpfile.stat().st_mode & 0o777) == permission | FILE_PERMISSION_MASK
        tmpfile.chmod(0o644)
        tmpfile.unlink()

        subdir.mkdir()
        subdir.chmod(permission)
        fix_permission(subdir)
        assert (subdir.stat().st_mode & 0o777) == permission | DIR_PERMISSION_MASK
        subdir.chmod(0o755)
        subdir.rmdir()


def test_fix_extracted_directory(tmpdir: Path, task_result: TaskResult):
    tmpdir = PosixPath(tmpdir)
    subdir = PosixPath(tmpdir / "testdir2")
    subdir.mkdir()
    tmpfile = PosixPath(subdir / "file.txt")
    tmpfile.touch()

    tmpfile.chmod(0o640)
    subdir.chmod(0o750)
    tmpdir.chmod(0o750)

    fix_extracted_directory(tmpdir, task_result)
    # The rehosting fork zeroes the permission masks, so fix_extracted_directory
    # preserves the source modes verbatim instead of forcing 0o775/0o644.
    assert (tmpdir.stat().st_mode & 0o777) == 0o750
    assert (subdir.stat().st_mode & 0o777) == 0o750
    assert (tmpfile.stat().st_mode & 0o777) == 0o640
