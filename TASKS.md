# passkms Task Tracking

<!-- AGENT RESUME CONTEXT
If resuming work on this project, read this file first to understand current state.
Then check the task list via TaskList tool for current progress.
Key files: PLAN.md (architecture), this file (status/decisions), CLAUDE.md (build commands)

Current state: All 6 checkpoints complete. Core library has 12 tests (10 unit + 2 integration).
Server CLI works for register/authenticate/list. Windows COM bindings + server cross-compile
to x86_64-pc-windows-msvc via `nix build .#passkms-windows`. MSIX manifest created.
`nix build .#passkms-windows` produces passkms-windows.exe (PE32+ x86_64, ~10MB).
-->

## Checkpoints

| # | Milestone | Status | Notes |
|---|-----------|--------|-------|
| 1 | Project scaffolding (workspace, crates, deps, flake) | done | |
| 2 | KmsSigner + COSE conversion + unit tests | done | 5 tests |
| 3 | CredentialStore + Authenticator (full core lib) | done | 10 unit tests |
| 4 | Server CLI + integration tests with real AWS KMS | done | 12 total tests, signature verification passing |
| 5 | Windows COM bindings + server | done | Cross-compiles via cargo-xwin for x86_64-pc-windows-msvc |
| 6 | Cross-compilation + MSIX packaging | done | `nix build .#passkms-windows` produces PE32+ exe |

## Ambiguity Log

Items flagged for review at checkpoints:

| # | Item | Phase | Resolution |
|---|------|-------|------------|
| 1 | Signature counter storage | 3 | Unix timestamp (seconds). No state persistence needed. |
| 2 | Credential ID format | 3 | KMS key UUID directly. |
| 3 | Credential metadata storage | 3 | KMS key tags with `passkms:` prefix. |
| 4 | Attestation format | 4 | Self-attestation: `packed` fmt, ES256 alg. |
| 5 | passkey-types version | 1 | Using 0.5, coset 0.4. |
| 6 | Windows COM approach | 5 | Manual bindings from MS webauthn headers. `#[interface]` attribute macro + `#[implement]`. |
| 7 | MSIX signing | 6 | `winapp create-debug-identity` for dev, Microsoft Store for long-term. |

## Decisions Made

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Credential ID = KMS key UUID | Opaque, no embedded info, simplifies alias-to-key lookup |
| 2 | Metadata in KMS key tags (`passkms:` prefix) | Simple, no extra infra, tags support up to 50 per key |
| 3 | Signature counter = Unix timestamp (seconds) | Stateless, no extra API call, monotonically increasing, fits u32 until 2106 |
| 4 | Self-attestation (`packed` fmt, ES256) | Minimal overhead (one Sign call), some RPs check for it |
| 5 | passkey-types 0.5, coset 0.4 | Latest stable versions, API compatible with plan |
| 6 | passkms-windows in workspace default-members exclude | Uses `default-members` so `cargo build` skips it; `cargo xwin check -p passkms-windows --target x86_64-pc-windows-msvc` to build |
| 7 | windows 0.62, windows-interface 0.59 | `implement` feature removed in 0.62 (always-on). BOOL from windows_core, not Win32::Foundation. |
| 8 | Decode/encode CBOR via Windows helpers | `WebAuthNDecodeMakeCredentialRequest` / `WebAuthNEncodeGetAssertionResponse` etc. from webauthn.dll |
| 9 | raw-dylib linking for webauthn.dll | Plugin API symbols not in standard SDK import lib; raw-dylib resolves at runtime |
| 10 | xwin SDK hash pinned in flake.nix | Fixed-output derivation with `--manifest-version 17`, hash `sha256-C6lv6HS87LOu/gaA/bdcOKrTW+fkb9vWnVRRqpZHSUM=` |
