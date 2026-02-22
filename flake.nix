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

    # nix-direnv for the development shell
    nix-direnv = {
      url = "github:nix-community/nix-direnv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, systems, rust-overlay, crane, nix-direnv, ... }:
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
          src = craneLib.cleanCargoSource ./.;
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
        in
        {
          CARGO_BUILD_TARGET = "x86_64-pc-windows-msvc";
          CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = "lld-link";
          CC_x86_64_pc_windows_msvc = "clang-cl";
          CXX_x86_64_pc_windows_msvc = "clang-cl";
          AR_x86_64_pc_windows_msvc = "llvm-lib";
          CFLAGS_x86_64_pc_windows_msvc = builtins.concatStringsSep " " [
            "--target=x86_64-pc-windows-msvc"
            "-Wno-unused-command-line-argument"
            "-fuse-ld=lld-link"
            "/imsvc${pkgs.llvmPackages.clang-unwrapped.lib}/lib/clang/${clangMajor}/include"
            "/imsvc${windowsSdk}/crt/include"
            "/imsvc${windowsSdk}/sdk/include/ucrt"
            "/imsvc${windowsSdk}/sdk/include/um"
            "/imsvc${windowsSdk}/sdk/include/shared"
          ];
          CXXFLAGS_x86_64_pc_windows_msvc = builtins.concatStringsSep " " [
            "--target=x86_64-pc-windows-msvc"
            "-Wno-unused-command-line-argument"
            "-fuse-ld=lld-link"
            "/imsvc${pkgs.llvmPackages.clang-unwrapped.lib}/lib/clang/${clangMajor}/include"
            "/imsvc${windowsSdk}/crt/include"
            "/imsvc${windowsSdk}/sdk/include/ucrt"
            "/imsvc${windowsSdk}/sdk/include/um"
            "/imsvc${windowsSdk}/sdk/include/shared"
          ];
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

          # Windows cross-compiled build
          passkms-windows = craneLib.buildPackage ((commonArgs // {
            pname = "passkms-windows";
            cargoExtraArgs = "-p passkms-windows";
            nativeBuildInputs = crossBuildInputsFor system;
            # Tests can't run on Linux
            doCheck = false;
          }) // msvcEnvFor system);
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

          # Run clippy
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
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

              # nix-direnv for this flake's shell
              nix-direnv.packages.${system}.default
            ];

            # Environment variables for development
            RUST_BACKTRACE = "1";
            RUST_LOG = "debug";
          };
        });

      # Expose nix-direnv for .envrc to use
      lib = {
        inherit nix-direnv;
      };
    };
}
