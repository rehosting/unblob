import binascii
import io
import os
import stat
from pathlib import Path

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    InvalidInputFormat,
    StructParser,
    convert_int16,
    read_until_past,
    round_up,
)

from ...extractors import Command
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


BLOCK_ALIGNMENT = 4
JFFS2_MAGICS = [0x1985, 0x8519, 0x1984, 0x8419]

# Compatibility flags.
JFFS2_NODE_ACCURATE = 0x2000
JFFS2_FEATURE_INCOMPAT = 0xC000
JFFS2_FEATURE_RWCOMPAT_DELETE = 0x0000

DIRENT = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 1
INODE = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 2
CLEANMARKER = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3
PADDING = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 4
SUMMARY = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 6
XATTR = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 8
XREF = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 9

JFFS2_NODETYPES = {DIRENT, INODE, CLEANMARKER, PADDING, SUMMARY, XATTR, XREF}

# JFFS2 root directory inode number (its dirent has no parent in the image).
JFFS2_ROOT_INO = 1


class JFFS2Extractor(Extractor):
    """Extract JFFS2 with ``jefferson`` then restore directory permissions.

    ``jefferson`` writes directories with ``os.makedirs`` and never chmods
    them, so every directory comes out with the default ``0o777 & ~umask``
    (typically ``0o755``) regardless of its real mode -- restrictive,
    setgid, setuid and sticky directory bits are silently lost. File modes
    are preserved because ``jefferson`` explicitly chmods regular files.

    We re-parse the JFFS2 metadata after extraction to recover the real
    directory modes and re-apply them deepest-first (so re-applying a
    restrictive parent mode never blocks chmod-ing a child).
    """

    C_DEFINITIONS = r"""
        typedef struct jffs2_raw_dirent {
            uint16 magic;
            uint16 nodetype;
            uint32 totlen;
            uint32 hdr_crc;
            uint32 pino;
            uint32 version;
            uint32 ino;
            uint32 mctime;
            uint8 nsize;
            uint8 type;
            uint8 unused[2];
            uint32 node_crc;
            uint32 name_crc;
        } jffs2_raw_dirent_t;

        typedef struct jffs2_raw_inode {
            uint16 magic;
            uint16 nodetype;
            uint32 totlen;
            uint32 hdr_crc;
            uint32 ino;
            uint32 version;
            uint32 mode;
            uint16 uid;
            uint16 gid;
            uint32 isize;
            uint32 atime;
            uint32 mtime;
            uint32 ctime;
            uint32 offset;
            uint32 csize;
            uint32 dsize;
            uint8 compr;
            uint8 usercompr;
            uint16 flags;
            uint32 data_crc;
            uint32 node_crc;
        } jffs2_raw_inode_t;
    """

    DIRENT_HEADER_LEN = 40

    def __init__(self):
        self._command = Command("jefferson", "-v", "-f", "-d", "{outdir}", "{inpath}")
        self._struct_parser = StructParser(self.C_DEFINITIONS)

    def get_dependencies(self) -> list[str]:
        return self._command.get_dependencies()

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        result = self._command.extract(inpath, outdir)
        try:
            self._restore_directory_modes(inpath, outdir)
        except Exception:
            # Mode restoration is best-effort: never fail an otherwise
            # successful extraction because we could not re-parse metadata.
            logger.warning(
                "Failed to restore JFFS2 directory modes", exc_info=True, _verbosity=2
            )
        return result

    def _restore_directory_modes(self, inpath: Path, outdir: Path):
        content = inpath.read_bytes()
        if len(content) < 2:
            return

        magic = convert_int16(content[:2], Endian.BIG)
        endian = Endian.BIG if magic in (0x1985, 0x1984) else Endian.LITTLE

        dirents, inode_modes = self._scan_metadata(content, endian)

        # ino -> dirent (keep the highest version, like jefferson does).
        node_dict: dict[int, object] = {}
        for dirent in dirents:
            existing = node_dict.get(dirent.ino)
            if existing is None or dirent.version > existing.version:
                node_dict[dirent.ino] = dirent

        dir_modes = self._collect_dir_modes(node_dict, inode_modes, outdir)

        # Re-apply deepest-first so re-applying a restrictive parent mode
        # never blocks chmod-ing a child still beneath it.
        for path, mode in sorted(
            dir_modes, key=lambda pm: len(pm[0].parts), reverse=True
        ):
            try:
                if path.is_dir() and not path.is_symlink():
                    os.chmod(path, mode)  # noqa: PTH101
            except OSError as e:
                logger.warning(
                    "Could not chmod JFFS2 directory",
                    path=str(path),
                    error=str(e),
                    _verbosity=2,
                )

    def _collect_dir_modes(
        self, node_dict: dict, inode_modes: dict[int, int], outdir: Path
    ) -> list[tuple[Path, int]]:
        """Collect (path, mode) for every directory inode under outdir."""
        dir_modes: list[tuple[Path, int]] = []
        outdir_real = outdir.resolve()
        for dirent in node_dict.values():
            mode = inode_modes.get(dirent.ino)
            if mode is None or not stat.S_ISDIR(mode):
                continue

            rel = self._reconstruct_path(dirent, node_dict)
            if rel is None:
                continue

            target = (outdir / rel).resolve()
            if outdir_real != os.path.commonpath((outdir_real, target)):
                # Path traversal -- jefferson would have discarded it too.
                continue
            dir_modes.append((target, stat.S_IMODE(mode)))
        return dir_modes

    def _scan_metadata(self, content: bytes, endian: Endian):
        """Return (list of dirents, {ino: highest-version inode mode})."""
        le_magics = (b"\x85\x19", b"\x84\x19")
        be_magics = (b"\x19\x85", b"\x19\x84")
        markers = le_magics if endian is Endian.LITTLE else be_magics

        dirents = []
        inode_modes: dict[int, int] = {}
        inode_versions: dict[int, int] = {}

        size = len(content)
        pos = 0
        while pos < size - 12:
            if content[pos : pos + 2] not in markers:
                pos += 1
                continue

            totlen = self._read_u32(content, pos + 4, endian)
            nodetype = convert_int16(content[pos + 2 : pos + 4], endian)
            if totlen < 12 or pos + totlen > size:
                pos += 2
                continue

            node = content[pos : pos + totlen]
            if nodetype == DIRENT and totlen >= self.DIRENT_HEADER_LEN:
                dirent = self._parse_dirent(node, endian)
                if dirent is not None:
                    dirents.append(dirent)
            elif nodetype == INODE:
                self._parse_inode(node, endian, inode_modes, inode_versions)

            pos += round_up(totlen, BLOCK_ALIGNMENT)

        return dirents, inode_modes

    def _parse_dirent(self, node: bytes, endian: Endian):
        try:
            dirent = self._struct_parser.parse("jffs2_raw_dirent_t", node, endian)
            name = node[self.DIRENT_HEADER_LEN : self.DIRENT_HEADER_LEN + dirent.nsize]
            dirent.name = name
        except Exception:
            logger.debug("Skipping unparsable JFFS2 dirent", _verbosity=3)
            return None
        return dirent if dirent.ino != 0 else None

    def _parse_inode(
        self,
        node: bytes,
        endian: Endian,
        inode_modes: dict[int, int],
        inode_versions: dict[int, int],
    ):
        try:
            inode = self._struct_parser.parse("jffs2_raw_inode_t", node, endian)
        except Exception:
            logger.debug("Skipping unparsable JFFS2 inode", _verbosity=3)
            return
        if inode.ino not in inode_versions or inode.version > inode_versions[inode.ino]:
            inode_versions[inode.ino] = inode.version
            inode_modes[inode.ino] = inode.mode

    @staticmethod
    def _read_u32(content: bytes, offset: int, endian: Endian) -> int:
        byteorder = "little" if endian is Endian.LITTLE else "big"
        return int.from_bytes(content[offset : offset + 4], byteorder)

    @staticmethod
    def _reconstruct_path(dirent, node_dict: dict[int, object]) -> Path | None:
        names = [dirent.name]
        pino = dirent.pino
        for _ in range(100):
            if pino == JFFS2_ROOT_INO or pino not in node_dict:
                break
            parent = node_dict[pino]
            names.append(parent.name)
            pino = parent.pino
        names.reverse()
        try:
            parts = [n.decode() for n in names]
        except UnicodeDecodeError:
            return None
        if not all(parts):
            return None
        return Path(*parts)


class _JFFS2Base(StructHandler):
    C_DEFINITIONS = r"""
        typedef struct jffs2_unknown_node
        {
            uint16 magic;
            uint16 nodetype;
            uint32 totlen;
            uint32 hdr_crc;
        } jffs2_unknown_node_t;
    """

    HEADER_STRUCT = "jffs2_unknown_node_t"

    BIG_ENDIAN_MAGIC = 0x19_85

    EXTRACTOR = JFFS2Extractor()

    def guess_endian(self, file: File) -> Endian:
        magic = convert_int16(file.read(2), Endian.BIG)
        endian = Endian.BIG if magic == self.BIG_ENDIAN_MAGIC else Endian.LITTLE
        file.seek(-2, io.SEEK_CUR)
        return endian

    def valid_header(self, header, node_start_offset: int, eof: int) -> bool:
        header_crc = (binascii.crc32(header.dumps()[:-4], -1) ^ -1) & 0xFFFFFFFF
        check_crc = True

        if header.nodetype not in JFFS2_NODETYPES:
            if header.nodetype | JFFS2_NODE_ACCURATE not in JFFS2_NODETYPES:
                logger.debug(
                    "Invalid JFFS2 node type", node_type=header.nodetype, _verbosity=2
                )
                return False
            logger.debug(
                "Not accurate JFFS2 node type, ignore CRC",
                node_type=header.nodetype,
                _verbosity=2,
            )
            check_crc = False

        if check_crc and header_crc != header.hdr_crc:
            logger.debug("node header CRC missmatch", _verbosity=2)
            return False

        if node_start_offset + header.totlen > eof:
            logger.debug(
                "node length greater than total file size",
                node_len=header.totlen,
                file_size=eof,
                _verbosity=2,
            )
            return False

        if header.totlen < len(header):
            logger.debug(
                "node length greater than header size",
                node_len=header.totlen,
                _verbosity=2,
            )
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(0, io.SEEK_END)
        eof = file.tell()
        file.seek(start_offset)

        endian = self.guess_endian(file)
        current_offset = start_offset

        while current_offset < eof:
            node_start_offset = current_offset
            file.seek(current_offset)
            try:
                header = self.parse_header(file, endian=endian)
            except EOFError:
                break

            if header.magic not in JFFS2_MAGICS:
                # JFFS2 allows padding at the end with 0xFF or 0x00, usually
                # to the size of an erase block.
                if header.magic in [0x0000, 0xFFFF]:
                    file.seek(-len(header), io.SEEK_CUR)
                    current_offset = read_until_past(file, b"\x00\xff")
                    continue

                logger.debug(
                    "unexpected header magic",
                    header_magic=header.magic,
                    _verbosity=2,
                )
                break

            if not self.valid_header(header, node_start_offset, eof):
                return None

            node_len = round_up(header.totlen, BLOCK_ALIGNMENT)
            current_offset += node_len

        if current_offset > eof:
            raise InvalidInputFormat("Corrupt file or last chunk isn't really JFFS2")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=current_offset,
        )


class JFFS2OldHandler(_JFFS2Base):
    NAME = "jffs2_old"

    PATTERNS = [
        HexString("84 19 ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) ( e0 | 20 )"),  # LE
        HexString("19 84 ( e0 | 20 ) ( 01 | 02 | 03 | 04 | 06 | 08 | 09 )"),  # BE
    ]

    BIG_ENDIAN_MAGIC = 0x19_84

    DOC = HandlerDoc(
        name="JFFS2 (old)",
        description="JFFS2 (Journaling Flash File System version 2) is a log-structured file system for flash memory devices, using an older magic number to identify its nodes. It organizes data into nodes with headers containing metadata and CRC checks for integrity.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="JFFS2 Documentation",
                url="https://sourceware.org/jffs2/",
            ),
            Reference(
                title="JFFS2 Wikipedia",
                url="https://en.wikipedia.org/wiki/JFFS2",
            ),
        ],
        limitations=[],
    )


class JFFS2NewHandler(_JFFS2Base):
    NAME = "jffs2_new"

    PATTERNS = [
        HexString("85 19 ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) ( e0 | 20 )"),  # LE
        HexString("19 85 ( e0 | 20 ) ( 01 | 02 | 03 | 04 | 06 | 08 | 09 )"),  # BE
    ]

    BIG_ENDIAN_MAGIC = 0x19_85

    DOC = HandlerDoc(
        name="JFFS2 (new)",
        description="JFFS2 (Journaling Flash File System version 2) is a log-structured file system for flash memory devices, using an older magic number to identify its nodes. It organizes data into nodes with headers containing metadata and CRC checks for integrity.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="JFFS2 Documentation",
                url="https://sourceware.org/jffs2/",
            ),
            Reference(
                title="JFFS2 Wikipedia",
                url="https://en.wikipedia.org/wiki/JFFS2",
            ),
        ],
        limitations=[],
    )
