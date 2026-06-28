import re
import subprocess
from pathlib import Path

from structlog import get_logger

from unblob.file_utils import InvalidInputFormat

from ...extractors import Command
from ...extractors.command import COMMAND_TIMEOUT
from ...models import (
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

logger = get_logger()


EXT_BLOCK_SIZE = 0x400
MAGIC_OFFSET = 0x438

# Permission bits (setuid/setgid/sticky + rwx) — the part of st_mode `debugfs
# stat` prints and that we want to mirror from the source inodes.
PERMISSION_BITS = 0o7777

# Header line of a `debugfs stat` block, e.g.
#   Inode: 13   Type: regular    Mode:  04755   Flags: 0x80000
# debugfs prints only the permission bits (no file-type bits) in octal. When
# commands are fed on stdin debugfs prefixes the line with its `debugfs:  `
# prompt, so the pattern is not anchored to the start of the line.
DEBUGFS_MODE_RE = re.compile(rb"Inode:\s*\d+\s+Type:.*?Mode:\s*0?([0-7]+)")

OS_LIST = [
    (0x0, "Linux"),
    (0x1, "GNU HURD"),
    (0x2, "MASIX"),
    (0x3, "FreeBSD"),
    (
        0x4,
        "Other",
    ),  # Other "Lites" (BSD4.4-Lite derivatives such as NetBSD, OpenBSD, XNU/Darwin, etc.)
]


class ExtFSExtractor(Command):
    """``debugfs -R`` extractor that is safe for output paths with metacharacters.

    ``debugfs`` parses the ``-R`` request through libss, which re-tokenises the
    string: whitespace separates arguments, double quotes group whitespace, and
    a literal ``"`` inside a quoted token must be written as ``""``. The output
    directory is interpolated into a quoted token (``rdump / "{outdir}"``), so
    without escaping an ``outdir`` containing a ``"`` produces an
    "Unbalanced quotes in command line" parse error. ``debugfs`` then exits 0
    having run nothing, which would make unblob silently skip the whole ext
    filesystem (no error reported). Escaping keeps the request well-formed for
    any directory name produced during recursive extraction.
    """

    def _make_extract_command(self, inpath: Path, outdir: Path):
        escaped_outdir = Path(str(outdir).replace('"', '""'))
        return super()._make_extract_command(inpath, escaped_outdir)

    def extract(self, inpath: Path, outdir: Path):
        result = super().extract(inpath, outdir)
        # ``debugfs rdump`` preserves the low rwx bits but drops setuid/setgid/
        # sticky (e.g. busybox 04755 -> 0755), so an extracted rootfs silently
        # loses those modes. Re-read each inode's mode straight from the image
        # and re-apply it. Best-effort: extraction already succeeded, so never
        # let a restore problem fail the whole extraction.
        try:
            self._restore_source_modes(inpath, outdir)
        except Exception:
            logger.warning(
                "Failed to restore ext source permission bits", exc_info=True
            )
        return result

    @staticmethod
    def _restore_source_modes(inpath: Path, outdir: Path):
        entries = [
            path
            for path in outdir.rglob("*")
            if not path.is_symlink() and (path.is_file() or path.is_dir())
        ]
        if not entries:
            return

        # Re-apply deepest-first so restoring a restrictive directory mode (one
        # without owner-execute) never blocks chmod-ing the entries beneath it.
        entries.sort(key=lambda path: len(path.parts), reverse=True)

        def source_path(path: Path) -> str:
            # rdump extracts the image root into outdir, so the in-image path is
            # the extracted path relative to outdir. debugfs re-tokenises -R/-f
            # requests, where an embedded `"` must be doubled.
            rel = path.relative_to(outdir).as_posix()
            return "/" + rel.replace('"', '""')

        # Feed the stat requests on stdin rather than via ``-f scriptfile``:
        # extraction runs inside unblob's sandbox, which would deny a scratch
        # file written outside the extraction tree.
        request = "".join(f'stat "{source_path(p)}"\n' for p in entries) + "quit\n"
        proc = subprocess.run(
            ["debugfs", str(inpath)],
            input=request.encode(),
            capture_output=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )

        modes = DEBUGFS_MODE_RE.findall(proc.stdout)
        if len(modes) != len(entries):
            # A stat that failed to resolve would shift the 1:1 pairing; rather
            # than risk applying the wrong mode, leave rdump's result in place.
            logger.warning(
                "ext mode restore skipped: debugfs stat count mismatch",
                extracted=len(entries),
                statted=len(modes),
            )
            return

        for path, mode in zip(entries, modes, strict=True):
            path.chmod(int(mode, 8) & PERMISSION_BITS)


class EXTHandler(StructHandler):
    NAME = "extfs"

    PATTERNS = [HexString("53 ef ( 00 | 01 | 02 ) 00 ( 00 | 01 | 02 | 03 | 04 ) 00")]

    C_DEFINITIONS = r"""
        typedef struct ext4_superblock {
            char blank[0x400];              // Not a part of the spec. But we expect the magic to be at 0x438.
            uint32 s_inodes_count;          // Total number of inodes in file system
            uint32 s_blocks_count_lo;       // Total number of blocks in file system
            uint32 s_r_blocks_count_lo;     // Number of blocks reserved for superuser (see offset 80)
            uint32 s_free_blocks_count_lo;  // Total number of unallocated blocks
            uint32 s_free_inodes_count;     // Total number of unallocated inodes
            uint32 s_first_data_block;      // Block number of the block containing the superblock
            uint32 s_log_block_size;        // log2 (block size) - 10  (In other words, the number to shift 1,024 to the left by to obtain the block size)
            uint32 s_log_cluster_size;      // log2 (fragment size) - 10. (In other words, the number to shift 1,024 to the left by to obtain the fragment size)
            uint32 s_blocks_per_group;      // Number of blocks in each block group
            uint32 s_clusters_per_group;    // Number of fragments in each block group
            uint32 s_inodes_per_group;      // Number of inodes in each block group
            uint32 s_mtime;                 // Last mount time
            uint32 s_wtime;                 // Last written time
            uint16 s_mnt_count;             // Number of times the volume has been mounted since its last consistency check
            uint16 s_max_mnt_count;         // Number of mounts allowed before a consistency check must be done
            uint16 s_magic;                 // Ext signature (0xef53), used to help confirm the presence of Ext2 on a volume
            uint16 s_state;                 // File system state (0x1 - clean or 0x2 - has errors)
            uint16 s_errors;                // What to do when an error is detected (ignore/remount/kernel panic)
            uint16 s_minor_rev_level;       // Minor portion of version (combine with Major portion below to construct full version field)
            uint32 s_lastcheck;             // time of last consistency check
            uint32 s_checkinterval;         // Interval between forced consistency checks
            uint32 s_creator_os;            // Operating system ID from which the filesystem on this volume was created
            uint32 s_rev_level;             // Major portion of version (combine with Minor portion above to construct full version field)
            uint16 s_def_resuid;            // User ID that can use reserved blocks
            uint16 s_def_resgid;            // Group ID that can use reserved blocks
        } ext4_superblock_t;
    """
    HEADER_STRUCT = "ext4_superblock_t"

    PATTERN_MATCH_OFFSET = -MAGIC_OFFSET

    EXTRACTOR = ExtFSExtractor("debugfs", "-R", 'rdump / "{outdir}"', "{inpath}")

    DOC = HandlerDoc(
        name="ExtFS",
        description="ExtFS (Ext2/Ext3/Ext4) is a family of journaling file systems commonly used in Linux-based operating systems. It supports features like large file sizes, extended attributes, and journaling for improved reliability.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="Ext4 Documentation",
                url="https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html",
            ),
            Reference(
                title="ExtFS Wikipedia",
                url="https://en.wikipedia.org/wiki/Ext4",
            ),
        ],
        limitations=[],
    )

    def valid_header(self, header) -> bool:
        if header.s_state not in [0x0, 0x1, 0x2]:
            logger.debug("ExtFS header state not valid", state=header.s_state)
            return False
        if header.s_errors not in [0x0, 0x1, 0x2, 0x3]:
            logger.debug(
                "ExtFS header error handling method value not valid",
                errors=header.s_errors,
            )
            return False
        if header.s_creator_os not in [x[0] for x in OS_LIST]:
            logger.debug("Creator OS value not valid.", creator_os=header.s_creator_os)
            return False
        if header.s_rev_level > 2:
            logger.debug(
                "ExtFS header major version too high", rev_level=header.s_rev_level
            )
            return False
        if header.s_log_block_size > 6:
            logger.debug(
                "ExtFS header s_log_block_size is too large",
                s_log_block_size=header.s_log_block_size,
            )
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file)

        if not self.valid_header(header):
            raise InvalidInputFormat("Invalid ExtFS header.")

        end_offset = start_offset + (
            header.s_blocks_count_lo * (EXT_BLOCK_SIZE << header.s_log_block_size)
        )

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
