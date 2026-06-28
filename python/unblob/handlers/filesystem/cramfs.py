import binascii
import stat
import struct
import sys
from pathlib import Path

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, convert_int32, get_endian
from ...models import (
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

logger = get_logger()

CRAMFS_FLAG_FSID_VERSION_2 = 0x00000001
BIG_ENDIAN_MAGIC = 0x28_CD_3D_45
BIG_ENDIAN_MAGIC_BYTES = b"\x28\xcd\x3d\x45"

# cramfs on-disk layout: a 64-byte superblock followed by the root inode.
CRAMFS_SUPERBLOCK_SIZE = 64
CRAMFS_INODE_SIZE = 12
PERMISSION_BITS = 0o7777


def swap_int32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]


def walk_cramfs_modes(data: bytes, *, big_endian: bool) -> list[tuple[str, int]]:
    """Walk a cramfs image and return ``(relative_posix_path, mode)`` for every entry.

    cramfs packs each inode into 12 bytes of C bitfields
    (``mode:16, uid:16; size:24, gid:8; namelen:6, offset:26``), so the bit
    positions of ``namelen``/``offset`` and ``size``/``gid`` differ between a
    big-endian and a little-endian image. ``namelen`` is the name length in
    32-bit words; for directories ``offset`` (in 32-bit words) points at the
    first child inode and ``size`` is the total byte length of the child inodes.
    """
    endian = ">" if big_endian else "<"
    results: list[tuple[str, int]] = []

    def parse_inode(off: int) -> tuple[int, int, int, int]:
        mode = struct.unpack_from(endian + "H", data, off)[0]
        size_gid = struct.unpack_from(endian + "I", data, off + 4)[0]
        name_off = struct.unpack_from(endian + "I", data, off + 8)[0]
        if big_endian:
            size = size_gid >> 8
            namelen = name_off >> 26
            offset = name_off & 0x3FFFFFF
        else:
            size = size_gid & 0xFFFFFF
            namelen = name_off & 0x3F
            offset = name_off >> 6
        return mode, size, namelen, offset

    def walk(data_off: int, total: int, parent: str) -> None:
        pos = data_off
        end = min(data_off + total, len(data))
        while pos + CRAMFS_INODE_SIZE <= end:
            mode, size, namelen, offset = parse_inode(pos)
            # Only the (nameless) root inode legitimately has namelen 0; hitting
            # it again means we walked off the directory — stop rather than spin.
            if namelen == 0:
                break
            name = data[
                pos + CRAMFS_INODE_SIZE : pos + CRAMFS_INODE_SIZE + namelen * 4
            ].rstrip(b"\x00")
            child = f"{parent}/{name.decode('utf-8', 'surrogateescape')}"
            results.append((child, mode))
            if stat.S_ISDIR(mode):
                walk(offset * 4, size, child)
            pos += CRAMFS_INODE_SIZE + namelen * 4

    if len(data) < CRAMFS_SUPERBLOCK_SIZE + CRAMFS_INODE_SIZE:
        return results
    _mode, root_size, _namelen, root_offset = parse_inode(CRAMFS_SUPERBLOCK_SIZE)
    walk(root_offset * 4, root_size, "")
    return results


class CramFSExtractor(Extractor):
    """Extract cramfs, choosing the tool by image endianness.

    ``cramfsck`` preserves permissions but only reads host-endian images: on a
    little-endian host a big-endian cramfs makes it bail ("superblock magic not
    found") and silently extract nothing. ``7z`` reads either endianness but
    does not restore unix permissions (it collapses directories to ``0700`` and
    drops setuid/setgid/sticky bits). So use ``cramfsck`` for native-endian
    images (full fidelity) and fall back to ``7z`` for the opposite endianness,
    then re-apply the real modes parsed straight out of the cramfs inodes.
    """

    def __init__(self):
        self._native = Command(
            "cramfsck", "-x", "{outdir}", "{inpath}", make_outdir=False
        )
        self._foreign = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def get_dependencies(self) -> list[str]:
        return self._native.get_dependencies() + self._foreign.get_dependencies()

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        with inpath.open("rb") as f:
            is_big_endian = f.read(4) == BIG_ENDIAN_MAGIC_BYTES
        host_big_endian = sys.byteorder == "big"
        if is_big_endian == host_big_endian:
            return self._native.extract(inpath, outdir)
        result = self._foreign.extract(inpath, outdir)
        try:
            self._restore_modes(inpath, outdir, big_endian=is_big_endian)
        except Exception:
            logger.warning(
                "Failed to restore cramfs source permission bits", exc_info=True
            )
        return result

    @staticmethod
    def _restore_modes(inpath: Path, outdir: Path, *, big_endian: bool) -> None:
        entries = walk_cramfs_modes(inpath.read_bytes(), big_endian=big_endian)
        # Deepest paths first so re-applying a restrictive directory mode never
        # blocks chmod-ing the entries inside it.
        for relpath, mode in sorted(
            entries, key=lambda item: item[0].count("/"), reverse=True
        ):
            target = outdir / relpath.lstrip("/")
            if target.is_symlink() or not target.exists():
                continue
            target.chmod(mode & PERMISSION_BITS)


class CramFSHandler(StructHandler):
    NAME = "cramfs"

    PATTERNS = [
        HexString("28 CD 3D 45"),  # big endian
        HexString("45 3D CD 28"),  # little endian
    ]

    C_DEFINITIONS = r"""
        typedef struct cramfs_header {
            uint32 magic;
            uint32 fs_size;
            uint32 flags;
            uint32 future;
            char signature[16];
            uint32 fsid_crc;
            uint32 fsid_edition;
            uint32 fsid_blocks;
            uint32 fsid_files;
            char name[16];
        } cramfs_header_t;
    """
    HEADER_STRUCT = "cramfs_header_t"

    EXTRACTOR = CramFSExtractor()

    DOC = HandlerDoc(
        name="CramFS",
        description="CramFS is a lightweight, read-only file system format designed for simplicity and efficiency in embedded systems. It uses zlib compression for file data and stores metadata in a compact, contiguous structure.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="CramFS Documentation",
                url="https://web.archive.org/web/20160304053532/http://sourceforge.net/projects/cramfs/",
            ),
            Reference(
                title="CramFS Wikipedia",
                url="https://en.wikipedia.org/wiki/Cramfs",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        endian = get_endian(file, BIG_ENDIAN_MAGIC)
        header = self.parse_header(file, endian)
        valid_signature = header.signature == b"Compressed ROMFS"

        if valid_signature and self._is_crc_valid(file, start_offset, header, endian):
            return ValidChunk(
                start_offset=start_offset,
                end_offset=start_offset + header.fs_size,
            )
        return None

    def _is_crc_valid(
        self,
        file: File,
        start_offset: int,
        header,
        endian: Endian,
    ) -> bool:
        # old cramfs format do not support crc
        if not (header.flags & CRAMFS_FLAG_FSID_VERSION_2):
            return True
        file.seek(start_offset)
        content = bytearray(file.read(header.fs_size))
        file.seek(start_offset + 32)
        crc_bytes = file.read(4)
        header_crc = convert_int32(crc_bytes, endian)
        content[32:36] = b"\x00\x00\x00\x00"
        computed_crc = binascii.crc32(content)
        # some vendors like their CRC's swapped, don't ask why
        return header_crc == computed_crc or header_crc == swap_int32(computed_crc)
