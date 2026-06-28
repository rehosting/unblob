"""Unit tests for the cramfs permission walker (rehosting/fw2tar#5).

``7z`` recovers data from an opposite-endian cramfs but loses unix permissions
(directories collapse to ``0700`` and setuid/setgid/sticky bits are dropped).
``CramFSExtractor`` re-applies the real modes by parsing them straight out of
the cramfs inodes, so the walker that reads those modes is what we pin here.
The committed integration fixtures are byte-for-byte images, so these tests
need no external tooling (mkcramfs/7z).
"""

from pathlib import Path

import pytest

from unblob.handlers.filesystem.cramfs import (
    BIG_ENDIAN_MAGIC_BYTES,
    walk_cramfs_modes,
)

FIXTURES = Path(__file__).parent / "integration" / "filesystem" / "cramfs"


@pytest.mark.parametrize(
    "image",
    [
        FIXTURES / "big_endian" / "__input__" / "fruits.cramfs_be",
        FIXTURES / "little_endian" / "__input__" / "fruits.cramfs_le",
    ],
    ids=["big_endian", "little_endian"],
)
def test_walk_cramfs_modes_reads_real_modes(image: Path):
    data = image.read_bytes()
    big_endian = data[:4] == BIG_ENDIAN_MAGIC_BYTES

    entries = dict(walk_cramfs_modes(data, big_endian=big_endian))

    # Regular files in the fixture are 0664 — exactly what 7z would clobber.
    assert entries == {"/apple.txt": 0o100664, "/cherry.txt": 0o100664}


def test_walk_cramfs_modes_ignores_truncated_image():
    assert walk_cramfs_modes(b"", big_endian=False) == []
    assert walk_cramfs_modes(BIG_ENDIAN_MAGIC_BYTES, big_endian=True) == []
