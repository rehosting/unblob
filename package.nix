{
  nix-filter,
  lib,
  libiconv,
  python3,
  makeWrapper,
  rustPlatform,
  stdenvNoCC,
  e2fsprogs-nofortify,
  erofs-utils,
  jefferson,
  lz4,
  lziprecover,
  lzop,
  sevenzip,
  partclone,
  sasquatch,
  sasquatch-v4be,
  simg2img,
  cramfsprogs,
  ubi_reader,
  unar,
  upx,
  zstd,
  versionCheckHook,
}:

let
  # These dependencies are only added to PATH
  runtimeDeps = [
    e2fsprogs-nofortify
    erofs-utils
    jefferson
    lziprecover
    lzop
    sevenzip
    sasquatch
    sasquatch-v4be
    ubi_reader
    simg2img
    unar
    upx
    # provides `cramfsck`, which the rehosting fork uses to extract cramfs
    # (upstream uses 7z); without it cramfs extraction fails. Note this is the
    # standalone cramfs userland, not util-linux's fsck.cramfs.
    cramfsprogs
    zstd
    lz4
  ]
  ++ lib.optional stdenvNoCC.isLinux partclone;
  pyproject_toml = builtins.fromTOML (builtins.readFile ./pyproject.toml);
  inherit (pyproject_toml.project) version;
in
python3.pkgs.buildPythonApplication {
  pname = "unblob";
  inherit version;
  pyproject = true;
  disabled = python3.pkgs.pythonOlder "3.9";

  src = nix-filter {
    root = ./.;
    include = [
      "Cargo.lock"
      "Cargo.toml"
      "pyproject.toml"
      "python"
      "rust"
      "tests"
      "README.md"
    ];
  };

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };

  strictDeps = true;

  build-system = with python3.pkgs; [ poetry-core ];

  buildInputs = lib.optionals stdenvNoCC.hostPlatform.isDarwin [ libiconv ];

  dependencies = with python3.pkgs; [
    arpy
    attrs
    click
    cryptography
    dissect-cstruct
    lark
    lief.py
    lzallright
    python3.pkgs.lz4 # shadowed by pkgs.lz4
    plotext
    pluggy
    pydantic
    pyfatfs
    pymdown-extensions
    pyperscan
    python-magic
    pyzstd
    rarfile
    rich
    structlog
    treelib
  ];

  nativeBuildInputs = with rustPlatform; [
    makeWrapper
    maturinBuildHook
    cargoSetupHook
  ];

  # These are runtime-only CLI dependencies, which are used through
  # their CLI interface
  pythonRemoveDeps = [
    "jefferson"
    "ubi-reader"
  ];

  pythonRelaxDeps = [
    "lz4"
    "pymdown-extensions"
  ];

  pythonImportsCheck = [ "unblob" ];

  makeWrapperArgs = [
    "--prefix PATH : ${lib.makeBinPath runtimeDeps}"
  ];

  nativeCheckInputs =
    with python3.pkgs;
    [
      pytestCheckHook
      pexpect
      psutil
      pytest-cov-stub
      pytest-timeout
      versionCheckHook
    ]
    ++ runtimeDeps;

  pytestFlags = [
    "--timeout=600"
    "--with-e2e"
  ];

  # These integration cases cannot run in the Nix build sandbox; they are not
  # rehosting-fork divergences but environment limitations (also disabled by
  # nixpkgs' own unblob package). Real extraction behaviour for the fork is
  # covered by fw2tar's in-Docker behaviour harness (fw2tar/tests/behavior).
  disabledTests = [
    # debugfs rdump exits non-zero on these images in the sandbox
    # https://github.com/tytso/e2fsprogs/issues/152
    "test_all_handlers[filesystem.extfs]"
    # regression in erofs-utils >=1.9
    "test_all_handlers[filesystem.android.erofs]"
    # unblob's landlock sandbox denies hardlinks within the extract dir (EXDEV)
    "test_all_handlers[filesystem.romfs]"
    "test_all_handlers[filesystem.yaffs]"
    # btrfs extraction renames across the /build tmpfs -> os.rename EXDEV in the
    # sandbox (same cross-device limitation as romfs/yaffs).
    "test_all_handlers[filesystem.btrfs_stream]"
    # this sample carries setuid/setgid/sticky files; the fork's carve() chmods
    # those bits to preserve permissions, which EPERMs as non-root in the nosuid
    # build sandbox. In production unblob runs under fakeroot, where it succeeds.
    "test_all_handlers[archive.cpio.cpio_portable_ascii]"
  ];

  versionCheckProgramArg = "--version";

  passthru = {
    # helpful to easily add these to a nix-shell environment
    inherit runtimeDeps;
  };

}
