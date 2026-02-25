{
  description = "passkms - FIDO2 passkey authenticator backed by AWS KMS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    systems.url = "github:nix-systems/default";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, systems, rust-overlay, crane, advisory-db, ... }:
    let
      eachSystem = nixpkgs.lib.genAttrs (import systems);

      # Helper to get pkgs for a system with rust-overlay applied
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      # Rust toolchain (with Windows MSVC cross-compilation target)
      rustToolchainFor = system:
        let pkgs = pkgsFor system;
        in pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "llvm-tools-preview" ];
          targets = [ "x86_64-pc-windows-msvc" ];
        };

      # Create crane lib for each system
      cranelibFor = system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor system;
        in
        (crane.mkLib pkgs).overrideToolchain rustToolchain;

      # Common arguments for native builds (core + server only)
      commonArgsFor = system:
        let
          pkgs = pkgsFor system;
          craneLib = cranelibFor system;
        in
        {
          pname = "passkms";
          src = let
            filter = path: type:
              (craneLib.filterCargoSources path type)
              || (builtins.match ".*\\.(svg|ico|rc|png)$" path != null);
          in pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = filter;
            name = "passkms-source";
          };
          strictDeps = true;

          buildInputs = [
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
            pkgs.darwin.apple_sdk.frameworks.Security
          ];

          nativeBuildInputs = [
          ];
        };

      # Build only dependencies (for caching)
      cargoArtifactsFor = system:
        let craneLib = cranelibFor system;
        in craneLib.buildDepsOnly (commonArgsFor system);

      # Windows SDK via xwin (fixed-output derivation for reproducibility)
      # SDK 10.0.26100, CRT 14.44.17.14
      windowsSdkFor = system:
        let pkgs = pkgsFor system;
        in pkgs.stdenvNoCC.mkDerivation {
          name = "windows-sdk";
          nativeBuildInputs = [ pkgs.xwin ];
          outputHashAlgo = "sha256";
          outputHashMode = "recursive";
          outputHash = "sha256-C6lv6HS87LOu/gaA/bdcOKrTW+fkb9vWnVRRqpZHSUM=";
          buildCommand = ''
            export HOME=$(mktemp -d)
            xwin --accept-license --manifest-version 17 splat --output $out
          '';
        };

      # MSVC cross-compilation environment variables
      msvcEnvFor = system:
        let
          pkgs = pkgsFor system;
          windowsSdk = windowsSdkFor system;
          clangMajor = pkgs.lib.versions.major pkgs.llvmPackages.clang-unwrapped.version;
          msvcFlags = builtins.concatStringsSep " " [
            "--target=x86_64-pc-windows-msvc"
            "-Wno-unused-command-line-argument"
            "-fuse-ld=lld-link"
            "/imsvc${pkgs.llvmPackages.clang-unwrapped.lib}/lib/clang/${clangMajor}/include"
            "/imsvc${windowsSdk}/crt/include"
            "/imsvc${windowsSdk}/sdk/include/ucrt"
            "/imsvc${windowsSdk}/sdk/include/um"
            "/imsvc${windowsSdk}/sdk/include/shared"
          ];
        in
        {
          CARGO_BUILD_TARGET = "x86_64-pc-windows-msvc";
          CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = "lld-link";
          CC_x86_64_pc_windows_msvc = "clang-cl";
          CXX_x86_64_pc_windows_msvc = "clang-cl";
          AR_x86_64_pc_windows_msvc = "llvm-lib";
          CFLAGS_x86_64_pc_windows_msvc = msvcFlags;
          CXXFLAGS_x86_64_pc_windows_msvc = msvcFlags;
          CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = builtins.concatStringsSep " " [
            "-Clinker-flavor=lld-link"
            "-Lnative=${windowsSdk}/crt/lib/x86_64"
            "-Lnative=${windowsSdk}/sdk/lib/um/x86_64"
            "-Lnative=${windowsSdk}/sdk/lib/ucrt/x86_64"
          ];
        };

      # Cross-compilation build tools
      crossBuildInputsFor = system:
        let pkgs = pkgsFor system;
        in [
          pkgs.llvmPackages.clang-unwrapped
          pkgs.llvmPackages.lld
          pkgs.llvmPackages.llvm
        ];

      # Generate ICO and PNG assets from SVG source
      assetsFor = system:
        let pkgs = pkgsFor system;
        in pkgs.stdenvNoCC.mkDerivation {
          name = "passkms-assets";
          nativeBuildInputs = [ pkgs.imagemagick ];
          buildCommand = ''
            mkdir -p $out
            svg=${./assets/logo.svg}
            magick -background none -density 1024 "$svg" -resize 16x16 icon_16.png
            magick -background none -density 1024 "$svg" -resize 32x32 icon_32.png
            magick -background none -density 1024 "$svg" -resize 48x48 icon_48.png
            magick -background none -density 1024 "$svg" -resize 256x256 icon_256.png
            magick icon_16.png icon_32.png icon_48.png icon_256.png $out/logo.ico
            magick -background none -density 1024 "$svg" -resize 50x50 $out/StoreLogo.png
          '';
        };

    in
    {
      # The main package outputs
      packages = eachSystem (system:
        let
          craneLib = cranelibFor system;
          commonArgs = commonArgsFor system;
          cargoArtifacts = cargoArtifactsFor system;
        in
        {
          # Build default workspace members (core + server)
          default = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false;
          });

          passkms-server = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            cargoExtraArgs = "-p passkms-server";
            doCheck = false;
          });

          passkms-assets = assetsFor system;

          # Windows cross-compiled build (with cached dependency artifacts)
          passkms-windows =
            let
              assets = assetsFor system;
              windowsArgs = (commonArgs // {
                pname = "passkms-windows";
                cargoExtraArgs = "-p passkms-windows";
                nativeBuildInputs = crossBuildInputsFor system;
                doCheck = false;
                preConfigure = ''
                  mkdir -p assets crates/passkms-windows/Assets
                  cp ${assets}/logo.ico assets/logo.ico
                  cp ${assets}/StoreLogo.png crates/passkms-windows/Assets/StoreLogo.png
                '';
              }) // msvcEnvFor system;
              windowsCargoArtifacts = craneLib.buildDepsOnly windowsArgs;
            in
            craneLib.buildPackage (windowsArgs // {
              cargoArtifacts = windowsCargoArtifacts;
            });
        });

      # Checks run by `nix flake check`
      checks = eachSystem (system:
        let
          craneLib = cranelibFor system;
          commonArgs = commonArgsFor system;
          cargoArtifacts = cargoArtifactsFor system;
        in
        {
          # Build the crate as part of checks
          build = self.packages.${system}.default;

          # Cross-compile Windows crate
          windows-build = self.packages.${system}.passkms-windows;

          # Run clippy (native crates)
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          # Run clippy (Windows cross-compiled crate)
          # Reuses the same base args and dependency artifacts as the Windows build
          # to avoid compiling Windows dependencies twice.
          windows-clippy =
            let
              assets = assetsFor system;
              windowsBaseArgs = (commonArgs // {
                pname = "passkms-windows";
                cargoExtraArgs = "-p passkms-windows";
                nativeBuildInputs = crossBuildInputsFor system;
                preConfigure = ''
                  mkdir -p assets crates/passkms-windows/Assets
                  cp ${assets}/logo.ico assets/logo.ico
                  cp ${assets}/StoreLogo.png crates/passkms-windows/Assets/StoreLogo.png
                '';
              }) // msvcEnvFor system;
              windowsCargoArtifacts = craneLib.buildDepsOnly windowsBaseArgs;
            in
            craneLib.cargoClippy (windowsBaseArgs // {
              cargoArtifacts = windowsCargoArtifacts;
              cargoClippyExtraArgs = "-- --deny warnings";
            });

          # Check formatting
          fmt = craneLib.cargoFmt {
            src = commonArgs.src;
          };

          # Run tests
          test = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
          });

          # Run tests with coverage
          coverage = craneLib.cargoLlvmCov (commonArgs // {
            inherit cargoArtifacts;
          });

          # Verify documentation builds without warnings
          doc = craneLib.cargoDoc (commonArgs // {
            inherit cargoArtifacts;
            cargoDocExtraArgs = "--no-deps";
            RUSTDOCFLAGS = "-D warnings";
          });

          # Audit dependencies for known vulnerabilities
          audit = craneLib.cargoAudit {
            inherit advisory-db;
            src = commonArgs.src;
          };
        });

      # Runnable applications
      apps = eachSystem (system: {
        default = self.apps.${system}.passkms-server;

        passkms-server = {
          type = "app";
          program = "${self.packages.${system}.passkms-server}/bin/passkms-server";
        };
      });

      # Development shell
      devShells = eachSystem (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor system;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.default ];

            nativeBuildInputs = [
              # Rust toolchain (includes rust-analyzer, rustfmt, clippy)
              rustToolchain

              # Fast test runner
              pkgs.cargo-nextest

              # Code coverage
              pkgs.cargo-llvm-cov

              # Watch mode for rapid development
              pkgs.bacon

              # Dependency management
              pkgs.cargo-edit

              # Security auditing
              pkgs.cargo-audit

              # Macro expansion (debugging)
              pkgs.cargo-expand

              # Windows cross-compilation
              pkgs.cargo-xwin
              pkgs.llvmPackages.clang-unwrapped  # clang-cl
              pkgs.llvmPackages.lld              # lld-link
              pkgs.llvmPackages.llvm             # llvm-lib
            ];

            # Environment variables for development
            RUST_BACKTRACE = "1";
          };
        });

    };
}
