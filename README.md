# passkms

A FIDO2/WebAuthn passkey authenticator backed by AWS KMS. Private keys never leave KMS --
all cryptographic operations are performed remotely via the KMS Sign API.

passkms registers as a Windows WebAuthn plugin authenticator, enabling passkey-based
authentication in browsers and applications that use the Windows WebAuthn platform API.

## How it works

1. **Registration:** Creates an ECC_NIST_P256 key in AWS KMS, stores credential metadata
   (RP ID, user handle, display names) as KMS key tags, and returns the key UUID as the
   credential ID with a "none" attestation object.

2. **Authentication:** Looks up the KMS key by credential ID (via alias) or by discovering
   all credentials for an RP (via tag scan), builds authenticator data, and calls KMS Sign
   to produce the ECDSA signature.

3. **Windows integration:** Runs as a COM server implementing `IPluginAuthenticator`. The
   Windows WebAuthn platform invokes `MakeCredential` and `GetAssertion` over COM, and
   passkms delegates to the core library which handles the KMS interactions.

All credentials are always discoverable (resident). The sign counter is a constant 0,
signaling "no counter support" per the WebAuthn spec.

## Prerequisites

- [Nix](https://nixos.org/download.html) with flakes enabled
- AWS credentials with KMS permissions (`kms:CreateKey`, `kms:CreateAlias`, `kms:Sign`,
  `kms:DescribeKey`, `kms:GetPublicKey`, `kms:ListAliases`, `kms:ListResourceTags`,
  `kms:ScheduleKeyDeletion`, `kms:DeleteAlias`, `kms:TagResource`)
- Windows 10/11 for the WebAuthn plugin (the core library and CLI work on any platform)

## Project structure

```
.
├── crates/
│   ├── passkms-core/        # Platform-agnostic FIDO2 authenticator logic
│   │   ├── src/
│   │   │   ├── authenticator.rs     # makeCredential / getAssertion
│   │   │   ├── credential_store.rs  # KMS key + alias management
│   │   │   ├── cose.rs             # SPKI DER to COSE key conversion
│   │   │   └── kms_signer.rs       # AsyncSigner impl over KMS Sign
│   │   └── tests/
│   │       └── kms_integration.rs   # Integration tests (require AWS creds)
│   ├── passkms-server/      # CLI for testing registration/authentication
│   └── passkms-windows/     # Windows COM server (WebAuthn plugin)
│       └── src/
│           ├── com_plugin.rs    # IPluginAuthenticator implementation
│           ├── com_factory.rs   # COM class factory
│           ├── registration.rs  # Plugin registration with Windows
│           ├── bindings.rs      # FFI type definitions
│           └── util.rs          # UTF-16 string helpers
├── flake.nix                # Nix build, checks, dev shell, cross-compilation
└── Cargo.toml               # Workspace manifest
```

## Building

```bash
# Enter the dev shell (or use direnv)
nix develop

# Build and test the core library
cargo build -p passkms-core
cargo nextest run -p passkms-core

# Build the test server
cargo build -p passkms-server

# Cross-compile the Windows binary (requires Nix)
nix build .#passkms-windows
# Output: ./result/bin/passkms-windows.exe
```

The Windows crate cannot be built with `cargo build` due to Windows-only dependencies.
Always use `nix build .#passkms-windows` for cross-compilation.

## Testing

```bash
# Unit tests (run automatically, no AWS needed)
cargo nextest run -p passkms-core

# Integration tests (require real AWS credentials)
cargo nextest run --test kms_integration --run-ignored

# Run all Nix checks (build, clippy, fmt, test, coverage, audit)
nix flake check

# Test CLI
cargo run -p passkms-server -- register example.com testuser
cargo run -p passkms-server -- authenticate example.com <credential-id>
cargo run -p passkms-server -- list example.com
```

## License

MIT
