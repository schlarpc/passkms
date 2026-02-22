# passkms - Agent Documentation

This document provides technical guidance for AI agents working on this Rust + Nix codebase.

## Quick Reference

| Task | Command |
|------|---------|
| Build core (debug) | `cargo build -p passkms-core` |
| Check core | `cargo check -p passkms-core` |
| Test core | `cargo nextest run -p passkms-core` |
| Integration tests | `RUN_KMS_TESTS=1 cargo nextest run --test kms_integration` |
| Lint core | `cargo clippy -p passkms-core --all-targets` |
| Format | `cargo fmt` |
| Format check | `cargo fmt --check` |
| Build Windows (cross) | `nix build .#passkms-windows` |
| Nix check all | `nix flake check` |

**Important:** The Windows crate (`passkms-windows`) cannot be built with `cargo build` due to
Windows-only dependencies. Always use `nix build .#passkms-windows` for cross-compilation.
New files must be `git add`ed before `nix build` because Nix copies from the git tree.

## Project Structure

This is a Cargo workspace with three crates:

| Crate | Purpose |
|-------|---------|
| `passkms-core` | Platform-agnostic FIDO2 authenticator logic, KMS credential store, COSE key conversion |
| `passkms-server` | CLI tool for testing registration, authentication, and credential listing against real KMS |
| `passkms-windows` | Windows COM server implementing IPluginAuthenticator for the WebAuthn Plugin API |

### File Locations

| Purpose | Location |
|---------|----------|
| Workspace manifest | `Cargo.toml` |
| Core crate | `crates/passkms-core/` |
| Server crate | `crates/passkms-server/` |
| Windows crate | `crates/passkms-windows/` |
| Core authenticator | `crates/passkms-core/src/authenticator.rs` |
| Core credential store | `crates/passkms-core/src/credential_store.rs` |
| Core COSE helpers | `crates/passkms-core/src/cose.rs` |
| Core KMS signer | `crates/passkms-core/src/kms_signer.rs` |
| Windows COM plugin | `crates/passkms-windows/src/com_plugin.rs` |
| Windows COM factory | `crates/passkms-windows/src/com_factory.rs` |
| Windows registration | `crates/passkms-windows/src/registration.rs` |
| Windows FFI bindings | `crates/passkms-windows/src/bindings.rs` |
| Server CLI | `crates/passkms-server/src/main.rs` |
| Integration tests | `crates/passkms-core/tests/kms_integration.rs` |
| Nix flake | `flake.nix` |
| Format config | `rustfmt.toml` |

## Build System

### Nix (flake.nix)

The project uses Nix flakes with Crane for Rust builds and cross-compilation to Windows.

**Outputs:**
- `packages.${system}.default` - Native build (core + server)
- `packages.${system}.passkms-server` - Server CLI binary
- `packages.${system}.passkms-windows` - Windows cross-compiled binary
- `devShells.${system}.default` - Development environment
- `checks.${system}.*` - CI checks (build, clippy, fmt, test)

### Cargo (Cargo.toml)

Workspace with three member crates. Lints configured at the workspace level.

## Testing

### Unit Tests
Located in `#[cfg(test)] mod tests` blocks within source files. Run with:

```bash
cargo nextest run -p passkms-core
```

### Integration Tests (KMS)
Require real AWS credentials. Opt-in via environment variable:

```bash
RUN_KMS_TESTS=1 cargo nextest run --test kms_integration
```

Without `RUN_KMS_TESTS=1`, these tests are skipped (return early with a message).

## Code Style

### Formatting
Configured in `rustfmt.toml`. Max width 100, 4-space indentation.

### Linting
Clippy with `all = "warn"`. Check with `cargo clippy -p passkms-core --all-targets`.

## Nix-Specific Notes

### Entering Dev Shell
```bash
# With direnv (auto-activates)
direnv allow

# Manual
nix develop
```

### Cross-Building for Windows
```bash
nix build .#passkms-windows
```

The result is a Windows `.exe` at `./result/bin/passkms-windows.exe`.
