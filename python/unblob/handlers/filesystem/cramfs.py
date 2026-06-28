import binascii
import struct
import sys
from pathlib import Path

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

CRAMFS_FLAG_FSID_VERSION_2 = 0x00000001
BIG_ENDIAN_MAGIC = 0x28_CD_3D_45
BIG_ENDIAN_MAGIC_BYTES = b"\x28\xcd\x3d\x45"


def swap_int32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]


class CramFSExtractor(Extractor):
    """Extract cramfs, choosing the tool by image endianness.

    ``cramfsck`` preserves permissions but only reads host-endian images: on a
    little-endian host a big-endian cramfs makes it bail ("superblock magic not
    found") and silently extract nothing. ``7z`` reads either endianness but
    does not restore unix permissions. So use ``cramfsck`` for native-endian
    images (full fidelity) and fall back to ``7z`` for the opposite endianness
    (data is recovered; permissions come out as 7z defaults).
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
        extractor = self._native if is_big_endian == host_big_endian else self._foreign
        return extractor.extract(inpath, outdir)


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
