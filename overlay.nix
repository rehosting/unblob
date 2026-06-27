final: prev:

{
  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs (super: {
    pname = "e2fsprogs-nofortify";
    hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
    nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
  });

  sevenzip =
    let
      inherit (final) _7zz;
      _7z-link = final.runCommand "_7z-link" { } ''
        mkdir -p $out/bin
        ln -sfn ${_7zz}/bin/7zz "$out/bin/7z"
      '';
    in
    final.symlinkJoin {
      name = "sevenzip";
      paths = [
        _7zz
        _7z-link
      ];
    };

  erofs-utils = prev.erofs-utils.overrideAttrs (_: rec {
    version = "1.8.10";
    src = final.fetchFromGitHub {
      owner = "erofs";
      repo = "erofs-utils";
      rev = "v${version}";
      sha256 = "1qlig9q1fdjl0zn7206dbv7w5ssjg4az4hg7y3vk69ly0zbmwkil";
    };
  });

  pythonPackagesExtensions = (prev.pythonPackagesExtensions or [ ]) ++ [
    (python-final: python-prev: {
      # The arpy on PyPI/nixpkgs (2.3.0, viraptor) crashes on ar archives that
      # carry a GNU 64-bit symbol table (a `/SYM64/` member): it misclassifies
      # the member as a long-name reference and evaluates `int(b"SYM64")`,
      # raising ValueError. unblob's ar handler only catches ArchiveFormatError,
      # so the exception aborts chunk calculation and the archive silently fails
      # to extract (onekey-sec/unblob#767; reproduces on the TP-Link ER7206
      # firmware). The unblob maintainer's fork (onekey-sec/arpy) carries the
      # fix; point at it until a fixed arpy is published to PyPI/nixpkgs.
      #
      # The fork dropped setup.py for a PEP 621 pyproject (setuptools PEP 517
      # default backend), so the build must move off the legacy setuptools
      # phase. Older nixpkgs package arpy with `format = "setuptools"`, newer
      # ones with `pyproject = true`; force pyproject and clear format so the
      # override builds under both (a consumer on a newer nixpkgs, e.g. fw2tar,
      # otherwise trips the `pyproject != null -> format == null` assertion).
      arpy = python-prev.arpy.overridePythonAttrs (old: {
        version = "2.3.0-unstable-2026-05-08";
        src = final.fetchFromGitHub {
          owner = "onekey-sec";
          repo = "arpy";
          rev = "f6746c566b92a193bfe57edb312809b6299ddab1";
          hash = "sha256-t5LtuXRHLtJaMOCxa/crDVa8sdJjEXTmlIMBdwO3yHM=";
        };
        pyproject = true;
        format = null;
        nativeBuildInputs =
          (old.nativeBuildInputs or [ ])
          ++ (with python-final; [
            setuptools
            wheel
          ]);
        # The fork's pyproject declares no build backend and leaves the root a
        # flat layout with a second top-level module (vulture_whitelist.py), so
        # setuptools auto-discovery refuses to build. Pin the backend and the
        # single shipped module explicitly.
        postPatch = (old.postPatch or "") + ''
          cat >> pyproject.toml <<'EOF'

          [build-system]
          requires = ["setuptools"]
          build-backend = "setuptools.build_meta"

          [tool.setuptools]
          py-modules = ["arpy"]
          EOF
        '';
        # arpy's own test suite (pytest + 90% coverage gate, fixtures under
        # test/) is not the contract we depend on; unblob's ar integration
        # fixtures exercise the behaviour we care about.
        doCheck = false;
      });
    })
  ];

  unblob = final.callPackage ./package.nix { };
}
