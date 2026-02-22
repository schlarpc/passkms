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

### L4. `#![allow(unsafe_code)]` at crate level
**Category:** Unsafe code
**Files:** `crates/passkms-windows/src/main.rs:2`

Blanket allow suppresses warnings for accidentally introduced unsafe code in new modules.

**Fix:** Use function-level `#[allow(unsafe_code)]` only where needed.

### L5. Integration tests show as "passed" instead of "ignored" when skipped
**Category:** Testing
**Files:** `crates/passkms-core/tests/kms_integration.rs:20-22`

The `should_run()` pattern returns early, making skipped tests appear as "passed" in CI.
The `#[ignore]` attribute would correctly report them as "ignored" and allow running with
`--run-ignored`.

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

### L11. `passkms-server` `list_credentials` creates redundant AWS client
**Category:** Code quality
**Files:** `crates/passkms-server/src/main.rs:136-139`

The function accepts an `&Authenticator` parameter but ignores it, creating a new AWS
config/client/store from scratch. Should use `authenticator.store()` instead.

### L12. No timeout on KMS operations in COM plugin
**Category:** Robustness
**Files:** `crates/passkms-windows/src/com_plugin.rs:199-201,369-371`

`runtime.block_on()` has no timeout. If KMS is unreachable, the COM thread blocks
indefinitely. Combined with `CancelOperation` being a no-op, there is no way to interrupt
stuck operations.

### L13. `.envrc` watches non-existent `rust-toolchain.toml`
**Category:** Nix / Developer experience
**Files:** `.envrc:3`

The `watch_file` directive references `rust-toolchain.toml` which does not exist. The Rust
toolchain is managed by the Nix flake, not a `rust-toolchain.toml` file. Harmless but
misleading.

### L14. No `buildDepsOnly` cache for Windows cross-compilation
**Category:** Nix / Build performance
**Files:** `flake.nix:164-170`

The `passkms-windows` build does not use a separate `cargoArtifacts` for the cross-compilation
target. Dependencies are rebuilt from scratch every time, making builds slower than necessary.

**Fix:** Create a `buildDepsOnly` derivation for the Windows target and pass it as
`cargoArtifacts`.

### L15. Silent base64 decode failure for `user_handle` in metadata
**Category:** Error handling
**Files:** `crates/passkms-core/src/credential_store.rs:329`

Base64 decode failure for `user_handle` silently becomes `None` via `.ok()`. Data corruption
would be masked without any log entry.

### L16. `Authenticator` does not derive `Clone`
**Category:** API design
**Files:** `crates/passkms-core/src/authenticator.rs:111-115`

All fields are `Clone` but the struct does not derive it. The Windows crate wraps it in
`Arc<Authenticator>` to share it. Adding `Clone` would improve ergonomics.

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

| Severity | Count | Key themes |
|----------|-------|------------|
| High | 2 | Operation signing verification, silent RP ID substitution |
| Medium | 10 | Test infrastructure, type safety, spec compliance, performance, docs |
| Low | 18 | Resource leaks, idioms, error handling, Nix ergonomics, robustness |

### Top priorities for action

1. **H2** -- Reject invalid RP IDs rather than silently substituting "unknown"
2. **H1** -- Implement operation request signature verification
3. **M1** -- Introduce trait abstraction for KMS to enable unit testing
4. **M3** -- Distinguish KMS API errors from internal logic errors
5. **M4** -- Change default log level from `debug` to `info`
6. **M6** -- Eliminate double `get_signing_key` calls in authentication
7. **M5** -- Check `pubKeyCredParams` before creating credentials
