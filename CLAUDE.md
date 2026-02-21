# rust-flake - Agent Documentation

This document provides technical guidance for AI agents working on this Rust + Nix codebase.

## Quick Reference

| Task | Command |
|------|---------|
| Build (debug) | `cargo build` |
| Build (release) | `cargo build --release` |
| Run | `cargo run` |
| Test | `cargo nextest run` |
| Lint | `cargo clippy --all-targets` |
| Format | `cargo fmt` |
| Format check | `cargo fmt --check` |
| Coverage | `cargo llvm-cov nextest` |
| Nix build | `nix build` |
| Nix check all | `nix flake check` |

## Build System

### Nix (flake.nix)

The project uses Nix flakes with Crane for Rust builds.

**Key inputs:**
- `nixpkgs` - Package repository
- `rust-overlay` (oxalica) - Rust toolchain provider
- `crane` - Rust-aware Nix build library
- `systems` (nix-systems/default) - Multi-platform support

**Outputs:**
- `packages.${system}.default` - Production binary
- `devShells.${system}.default` - Development environment
- `checks.${system}.*` - CI checks (build, clippy, fmt, test, coverage)

**Build caching:** Crane splits dependency compilation (`buildDepsOnly`) from source compilation (`buildPackage`). Dependencies are cached separately, so source-only changes rebuild quickly.

### Cargo (Cargo.toml)

Standard Cargo project with these conventions:
- Production deps in `[dependencies]`
- Test/dev-only deps in `[dev-dependencies]`
- Lints configured in `[lints.rust]` and `[lints.clippy]`

## File Locations

| Purpose | Location |
|---------|----------|
| Main entry point | `src/main.rs` |
| Package manifest | `Cargo.toml` |
| Locked deps | `Cargo.lock` |
| Nix flake | `flake.nix` |
| Format config | `rustfmt.toml` |
| Cargo config | `.cargo/config.toml` |

## Code Style

### Formatting
Configured in `rustfmt.toml`. Run `cargo fmt` before committing.

Key settings:
- Max line width: 100
- Spaces, not tabs (4 spaces)
- Imports grouped: std, external, crate

### Linting
Clippy lints configured in `Cargo.toml` under `[lints.clippy]`.

Current policy: `all = "warn"` with pedantic/nursery disabled.

To check: `cargo clippy --all-targets`
To fix: `cargo clippy --all-targets --fix --allow-dirty`

## Testing

### Unit Tests
Located in `#[cfg(test)] mod tests` blocks within source files.

```bash
# Fast parallel execution
cargo nextest run

# With coverage
cargo llvm-cov nextest

# HTML coverage report
cargo llvm-cov nextest --html
# Output: target/llvm-cov/html/index.html
```

### Writing Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {
        assert_eq!(function_to_test(input), expected);
    }
}
```

## Adding Dependencies

### Production Dependencies
```bash
cargo add <crate-name>
```
Or edit `Cargo.toml` under `[dependencies]`.

### Dev-Only Dependencies
```bash
cargo add --dev <crate-name>
```
Or edit `Cargo.toml` under `[dev-dependencies]`.

After adding dependencies, run `cargo build` to update `Cargo.lock`.

## Nix-Specific Notes

### Entering Dev Shell
The dev shell provides all tools (rust-analyzer, clippy, rustfmt, cargo-nextest, cargo-llvm-cov, bacon, cargo-edit, cargo-audit, cargo-expand).

```bash
# With direnv (auto-activates)
direnv allow

# Manual
nix develop
```

### Building with Nix
```bash
# Build package
nix build

# Binary located at
./result/bin/rust-flake

# Check all CI conditions
nix flake check
```

### Updating Nix Inputs
```bash
# Update all
nix flake update

# Update specific input
nix flake lock --update-input rust-overlay
```

## CI Checks

The flake defines these checks in `checks.${system}`:

| Check | Purpose |
|-------|---------|
| `build` | Compile the package |
| `clippy` | Lint with --deny warnings |
| `fmt` | Verify formatting |
| `test` | Run test suite via nextest |
| `coverage` | Generate coverage report |

Run all: `nix flake check`

## Common Tasks

### Add a new function
1. Add function to `src/main.rs` or new module
2. Add tests in the `mod tests` block
3. Run `cargo fmt && cargo clippy --all-targets && cargo nextest run`

### Add a new binary
1. Create `src/bin/<name>.rs`
2. Add `[[bin]]` section to `Cargo.toml` if customization needed
3. Run with `cargo run --bin <name>`

### Add a library alongside binary
1. Create `src/lib.rs`
2. Move shared code there
3. Use `use rust_flake::*;` in `main.rs`

### Create a module
1. Create `src/<module_name>.rs` or `src/<module_name>/mod.rs`
2. Add `mod <module_name>;` to `main.rs` or `lib.rs`
3. Use `pub` for items that need external visibility

## Error Resolution

### Clippy warnings
```bash
# See all warnings
cargo clippy --all-targets

# Auto-fix what's possible
cargo clippy --all-targets --fix --allow-dirty
```

### Format issues
```bash
cargo fmt
```

### Test failures
```bash
# Run specific test
cargo nextest run <test_name>

# Run with output
cargo nextest run --no-capture
```

### Nix build failures
```bash
# Verbose output
nix build -L

# Check if it's a check failure
nix flake check -L
```

## Performance Tips

- Use `cargo check` instead of `cargo build` for quick syntax validation
- Use `bacon` for continuous background checking
- Debug builds (`cargo build`) compile faster than release
- Nix caches dependencies; source-only changes rebuild quickly
