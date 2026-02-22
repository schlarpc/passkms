# Codebase Audit Findings

Comprehensive audit of the passkms codebase covering security, type safety, error handling,
test coverage, unsafe code, architecture, Rust idioms, performance, Nix build system, and
documentation accuracy.

Previously resolved findings have been removed. Items below are from the current audit.

---

## High

### H1. Operation signing key is saved but never verified
**Category:** Security
**Files:** `crates/passkms-windows/src/registration.rs:356`, `crates/passkms-windows/src/com_plugin.rs:62-68,273-279`

The `OpSignPubKey` from `WebAuthNPluginAddAuthenticator` is saved to the registry.
`load_op_sign_key()` exists but is marked `#[allow(dead_code)]`. Neither `MakeCredential` nor
`GetAssertion` verifies the `pbRequestSignature` from incoming requests. Any local COM client
can forge WebAuthn requests to the plugin.

**Fix:** Implement signature verification using the stored public key before processing
requests.

### ~~H2. Invalid UTF-8 RP ID silently becomes "unknown"~~ RESOLVED

Both `MakeCredential` and `GetAssertion` now return `E_INVALIDARG` for non-UTF-8 RP IDs
instead of silently substituting `"unknown"`.

---

## Medium

### M1. No mock infrastructure for AWS KMS -- core logic untestable offline
**Category:** Testing / Architecture
**Files:** `crates/passkms-core/src/credential_store.rs:79-87`, `crates/passkms-core/src/authenticator.rs:137,226`

`CredentialStore` holds a concrete `aws_sdk_kms::Client` with no trait abstraction.
`make_credential()` and `get_assertion()` -- the two most critical functions -- have zero unit
tests. The only test coverage comes from opt-in integration tests requiring real AWS credentials.
`delete_credential()` has zero test coverage anywhere.

**Fix:** Introduce a `CredentialStorage` trait to decouple from the concrete KMS client,
enabling mock-based unit testing of `Authenticator`, `CredentialStore`, and `KmsSigner`.

### M2. UP flag always asserted without actual user presence check
**Category:** Security / Spec compliance
**Files:** `crates/passkms-core/src/authenticator.rs:189,280`

The UP flag is unconditionally set. This is acceptable for the Windows plugin (platform handles
UP via credential picker) but incorrect for the server/headless use case (`passkms-server`).

**Fix:** Accept a `user_presence_verified` flag in the request structs rather than hardcoding.

### ~~M3. `CredentialStoreError::Kms` conflates API errors with internal logic errors~~ RESOLVED

Added `Internal(String)` variant for missing response fields. `get_signing_key` now
distinguishes `NotFoundException` (mapped to `NotFound`) from other API errors (mapped to
`Kms`), preventing network/permission errors from being misidentified as missing credentials.

### ~~M4. Debug logging enabled by default persists PII to disk~~ RESOLVED

Default log level changed from `debug` to `info`. Debug-level logging (which includes
user names, display names, etc.) is still available via `RUST_LOG=debug`.

### ~~M5. No credential algorithm negotiation~~ RESOLVED

`MakeCredentialRequest` now includes `pub_key_cred_params` and `make_credential` validates
that ES256 (-7) is in the requested algorithm list, returning `UnsupportedAlgorithm` if not.
The COM plugin extracts the algorithm list from the decoded CTAP2 request.

### ~~M6. Double `get_signing_key` calls in `get_assertion` authentication flow~~ RESOLVED

The `KmsSigner` from the allow-list existence check is now cached and reused for signing,
eliminating redundant KMS `DescribeKey` API calls.

### M7. COM plugin code duplication between `MakeCredential` and `GetAssertion`
**Category:** Code quality / Maintainability
**Files:** `crates/passkms-windows/src/com_plugin.rs:43-252,254-456`

Both methods share nearly identical patterns for null-checking pointers, extracting RP IDs,
client data hashes, credential lists, decoding CBOR, and encoding responses. This duplication
in unsafe pointer manipulation code increases the risk of divergent bugs.

**Fix:** Extract shared helpers for `extract_rp_id`, `extract_client_data_hash`,
`extract_credential_list`.

### ~~M8. `client_data_hash` should be `[u8; 32]` not `Vec<u8>`~~ RESOLVED

Changed `client_data_hash` to `[u8; 32]` in both request structs, removing the need for
runtime length checks. Changed `sign_prehashed` to accept `&[u8; 32]`. The COM plugin now
validates the hash length at the FFI boundary with `try_from`.

### ~~M9. CLAUDE.md is outdated -- says "two crates" but there are three~~ RESOLVED

Updated CLAUDE.md to document all three crates, added `passkms-server` to the project
structure table and file locations, and added missing Nix outputs.

### ~~M10. Magic version numbers in COM response structs~~ RESOLVED

Replaced magic version numbers with named constants:
`WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION`, `WEBAUTHN_ASSERTION_VERSION`,
`WEBAUTHN_CREDENTIAL_VERSION`.

---

## Low

### L1. Credential IDs are KMS UUIDs, enabling authenticator fingerprinting
**Category:** Security / Privacy
**Files:** `crates/passkms-core/src/credential_store.rs:153,179`

Credential IDs are the UTF-8 string bytes of KMS key UUIDs. The UUID v4 format with hyphens is
distinctive and reveals the authenticator type to relying parties. Most authenticators use
opaque random binary credential IDs.

### L2. Non-atomic KMS key + alias creation
**Category:** Robustness
**Files:** `crates/passkms-core/src/credential_store.rs:143-165`

If the process crashes between key creation and alias creation, an orphaned key exists with no
alias. Not a security issue but a resource leak in a cost-bearing service.

### L3. `list_aliases` fetches all aliases, filters client-side
**Category:** Performance
**Files:** `crates/passkms-core/src/credential_store.rs:270`

The KMS `ListAliases` API does not support server-side prefix filtering. All aliases in the
account are fetched and filtered client-side. Slow in accounts with many aliases.

### L4. `#![allow(unsafe_code)]` at crate level -- NOT FIXED (acceptable)

Every module in `passkms-windows` uses `unsafe` for COM/FFI interop. Scoping to individual
functions would add noise without meaningful safety improvement. The crate-level allow is
appropriate for a COM interop crate.

### ~~L5. Integration tests show as "passed" instead of "ignored" when skipped~~ RESOLVED

Replaced `should_run()` early-return pattern with `#[ignore]` attribute. Tests now correctly
report as "ignored" and can be run with `--run-ignored`.

### L6. Integration tests leak KMS resources on assertion failure
**Category:** Testing
**Files:** `crates/passkms-core/tests/kms_integration.rs:169`

Cleanup (`cleanup_key`) only runs if all assertions pass. A `Drop` guard or `scopeguard`
pattern would prevent resource leaks when tests fail.

### L7. `kms_signer_stores_key_id` test is tautological
**Category:** Testing
**Files:** `crates/passkms-core/src/kms_signer.rs:105-113`

The test only verifies that `KmsSigner::new` has a specific type signature (`fn(Client, String)
-> KmsSigner`). It does not construct a `KmsSigner` or verify any behavior. The test name
is misleading.

### ~~L8. Unnecessary `clone()` in credential ID UTF-8 conversion~~ RESOLVED

Changed `String::from_utf8(cred_id_bytes.clone())` to `std::str::from_utf8(cred_id_bytes)`
in both exclude list and allow list paths.

### ~~L9. Inconsistent `unwrap()` vs `expect()` on Tag builders~~ RESOLVED

All Tag builder `.unwrap()` calls replaced with `.expect("tag_key and tag_value both set")`.

### L10. `CredentialMetadata` returned with all-`None` fields treated as valid
**Category:** Type safety
**Files:** `crates/passkms-core/src/credential_store.rs:301-345`

If a KMS key has no passkms tags, `get_credential_metadata` returns a `CredentialMetadata`
with only `key_id` populated and all optional fields `None`. The `TAG_MANAGED` tag is set
during creation but never checked during discovery, so non-passkms keys could appear in
results.

### ~~L11. `passkms-server` `list_credentials` creates redundant AWS client~~ RESOLVED

`list_credentials` now uses the passed `authenticator.store()` instead of creating
a redundant AWS client.

### L12. No timeout on KMS operations in COM plugin
**Category:** Robustness
**Files:** `crates/passkms-windows/src/com_plugin.rs:199-201,369-371`

`runtime.block_on()` has no timeout. If KMS is unreachable, the COM thread blocks
indefinitely. Combined with `CancelOperation` being a no-op, there is no way to interrupt
stuck operations.

### ~~L13. `.envrc` watches non-existent `rust-toolchain.toml`~~ RESOLVED

Removed `rust-toolchain.toml` from the `watch_file` directive.

### L14. No `buildDepsOnly` cache for Windows cross-compilation
**Category:** Nix / Build performance
**Files:** `flake.nix:164-170`

The `passkms-windows` build does not use a separate `cargoArtifacts` for the cross-compilation
target. Dependencies are rebuilt from scratch every time, making builds slower than necessary.

**Fix:** Create a `buildDepsOnly` derivation for the Windows target and pass it as
`cargoArtifacts`.

### ~~L15. Silent base64 decode failure for `user_handle` in metadata~~ RESOLVED

Base64 decode failures for `user_handle` now log a warning with the key ID and error
instead of silently becoming `None`.

### ~~L16. `Authenticator` does not derive `Clone`~~ RESOLVED

Added `#[derive(Clone)]` to `Authenticator`.

### L17. No Nix clippy check for Windows cross-compiled crate
**Category:** Nix / CI
**Files:** `flake.nix`

The Nix `checks` include clippy for the native crates but not for `passkms-windows`. Lint
issues in the Windows crate would only be caught by the cross-compilation build, not a
dedicated lint check.

### L18. `nix-direnv` included as flake input but unused by `.envrc`
**Category:** Nix
**Files:** `flake.nix:11`, `.envrc:1`

The flake declares `nix-direnv` as an input, includes it in `devShells`, and exposes it via
`lib`. But `.envrc` fetches `nix-direnv` from nixpkgs with `--inputs-from .` rather than using
the flake's input. The flake input and `lib` export are dead code.

---

## Summary

| Severity | Total | Resolved | Remaining | Key themes |
|----------|-------|----------|-----------|------------|
| High | 2 | 1 | 1 | ~~Silent RP ID substitution~~, operation signing verification |
| Medium | 10 | 8 | 2 | ~~Type safety, spec compliance, performance, docs, error handling~~, test infra, UP flag |
| Low | 18 | 6 | 12 | ~~Idioms, error handling, Nix ergonomics~~, resource leaks, robustness |

### Remaining priorities

1. **H1** -- Implement operation request signature verification
2. **M1** -- Introduce trait abstraction for KMS to enable unit testing
3. **M2** -- Accept `user_presence_verified` flag instead of hardcoding UP
