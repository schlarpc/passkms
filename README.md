# rust-flake

A Rust application built with Nix flakes, demonstrating best practices for reproducible Rust development.

## Features

- **Reproducible builds** via Nix flakes
- **Fast incremental builds** using [Crane](https://crane.dev) with cached dependencies
- **Multi-platform support** (Linux x86_64/aarch64, macOS x86_64/aarch64)
- **Development shell** with all necessary tools pre-configured
- **Code quality tooling**: formatting, linting, testing, coverage

## Prerequisites

- [Nix](https://nixos.org/download.html) with flakes enabled
- [direnv](https://direnv.net/) (optional, for automatic shell activation)

### Enable Nix Flakes

If you haven't enabled flakes, add this to `~/.config/nix/nix.conf`:

```
experimental-features = nix-command flakes
```

## Quick Start

### With direnv (recommended)

```bash
# Allow the .envrc file (one-time setup)
direnv allow

# The development shell activates automatically when you cd into the directory
```

### Without direnv

```bash
# Enter the development shell manually
nix develop
```

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Build with Nix (produces result symlink)
nix build
```

### Running

```bash
# Run in debug mode (fast compile, no optimizations)
cargo run

# Run in release mode
cargo run --release

# Run the Nix-built binary
./result/bin/rust-flake
```

### Fast Development Iteration

For rapid feedback during development, use [bacon](https://github.com/Canop/bacon):

```bash
# Start bacon (watches files and runs cargo check)
bacon

# Key bindings in bacon:
#   t - run tests
#   c - run clippy
#   d - open docs in browser
#   q - quit
```

Alternatively, use the cargo aliases:

```bash
cargo c    # cargo check
cargo r    # cargo run
cargo t    # cargo test
cargo tn   # cargo nextest run (faster test runner)
```

### Testing

```bash
# Run tests with cargo
cargo test

# Run tests with nextest (faster, better output)
cargo nextest run

# Run tests with coverage
cargo llvm-cov nextest
# or use the alias:
cargo tc

# Generate HTML coverage report
cargo llvm-cov nextest --html
open target/llvm-cov/html/index.html
```

### Linting

```bash
# Run clippy
cargo clippy --all-targets

# Or use the alias:
cargo lint

# Auto-fix clippy warnings
cargo lint-fix
```

### Formatting

```bash
# Check formatting
cargo fmt --check

# Auto-format
cargo fmt
```

## Nix Commands

### Build the package

```bash
# Build the default package
nix build

# Build and run
nix run

# Build for a specific system
nix build .#packages.x86_64-linux.default
```

### Run checks

```bash
# Run all checks (build, test, clippy, fmt, coverage)
nix flake check

# Run specific checks
nix build .#checks.x86_64-linux.clippy
nix build .#checks.x86_64-linux.test
nix build .#checks.x86_64-linux.fmt
nix build .#checks.x86_64-linux.coverage
```

### Update dependencies

```bash
# Update all flake inputs
nix flake update

# Update specific input
nix flake lock --update-input nixpkgs
nix flake lock --update-input rust-overlay
```

## Project Structure

```
.
├── .cargo/
│   └── config.toml      # Cargo configuration and aliases
├── .envrc               # direnv configuration
├── src/
│   └── main.rs          # Application entry point
├── Cargo.toml           # Rust package manifest
├── Cargo.lock           # Locked dependencies
├── flake.nix            # Nix flake definition
├── flake.lock           # Locked Nix inputs
├── rustfmt.toml         # Formatting configuration
├── CLAUDE.md            # AI agent documentation
└── README.md            # This file
```

## Architecture

### Why these choices?

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Nix build | [Crane](https://crane.dev) | Composable builds, excellent caching, native Cargo.lock support |
| Rust toolchain | [oxalica/rust-overlay](https://github.com/oxalica/rust-overlay) | Version flexibility, rust-toolchain.toml support |
| Multi-platform | [nix-systems](https://github.com/nix-systems/default) | Clean system enumeration, consumer-overridable |
| Test runner | [cargo-nextest](https://nexte.st/) | Faster parallel execution, better output |
| Coverage | [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) | Source-based accuracy, cross-platform |
| Watch mode | [bacon](https://github.com/Canop/bacon) | Modern cargo-watch replacement, minimal UI |

### Dev Dependencies

Development dependencies (tests, dev tools) are isolated from the production build:
- In Rust: `[dev-dependencies]` in Cargo.toml
- In Nix: `devShells` vs `packages` outputs

The `nix build` output contains only the production binary with no dev tooling.

## License

MIT
