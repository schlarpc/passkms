# Codebase Audit Findings

Comprehensive audit of the passkms codebase covering security, type safety, error handling,
test coverage, unsafe code, architecture, Rust idioms, performance, Nix build system, and
documentation accuracy.

Previously resolved findings have been removed. Items below are from the current audit.

---

## High

### H1. Operation signing key is saved but never verified
**Category:** Security
**Files:** `crates/passkms-windows/src/registration.rs:384`, `crates/passkms-windows/src/com_plugin.rs:79,331`

The `OpSignPubKey` from `WebAuthNPluginAddAuthenticator` is saved to the registry.
`load_op_sign_key()` exists but is marked `#[allow(dead_code)]`. Neither `MakeCredential` nor
`GetAssertion` verifies the `pbRequestSignature` from incoming requests. Any local COM client
can forge WebAuthn requests to the plugin.

**Fix:** Implement signature verification using the stored public key before processing
requests.

---

## Medium

### M1. No mock infrastructure for AWS KMS -- core logic untestable offline
**Category:** Testing / Architecture
**Files:** `crates/passkms-core/src/credential_store.rs:79-87`, `crates/passkms-core/src/authenticator.rs:132-140`

`CredentialStore` holds a concrete `aws_sdk_kms::Client` with no trait abstraction.
`make_credential()` and `get_assertion()` -- the two most critical functions -- have zero unit
tests. The only test coverage comes from opt-in integration tests requiring real AWS credentials.
`delete_credential()` and `list_all_credentials()` have zero test coverage anywhere.

Effective automated test coverage: 8 unit tests run during `nix flake check`. Integration
tests are `#[ignore]` and never run in CI. Error path test coverage is ~8% (1 of 13 error
variants tested).

**Fix:** Introduce a `CredentialStorage` trait to decouple from the concrete KMS client,
enabling mock-based unit testing of `Authenticator`, `CredentialStore`, and `KmsSigner`.

### M6. Non-atomic credential sync creates a gap with no credentials
**Category:** Correctness
**Files:** `crates/passkms-windows/src/registration.rs:233-258`

The `sync_credentials` function calls `RemoveAllCredentials` then `AddCredentials`. Between
these two calls, a concurrent WebAuthn operation would find zero credentials. This is a
transient window of inconsistency.

**Fix:** Investigate whether the plugin API supports an atomic replace, or minimize the
window by preparing data before removing.

---

## Low

### L1. Credential IDs are KMS UUIDs, enabling authenticator fingerprinting
**Category:** Security / Privacy
**Files:** `crates/passkms-core/src/credential_store.rs:153,179`

Credential IDs are the UTF-8 string bytes of KMS key UUIDs. The UUID v4 format with hyphens is
distinctive and reveals the authenticator type to relying parties. Most authenticators use
opaque random binary credential IDs.

### L2. `list_aliases` fetches all aliases, filters client-side
**Category:** Performance
**Files:** `crates/passkms-core/src/credential_store.rs:297-331`

The KMS `ListAliases` API does not support server-side prefix filtering. All aliases in the
account are fetched and filtered client-side. Slow in accounts with many aliases. Additionally,
`get_credential_metadata` is called sequentially for each discovered alias, making N+1 API
calls. Concurrent fetching with `FuturesUnordered` would improve latency for larger credential
sets.

### L3. `#![allow(unsafe_code)]` at crate level -- NOT FIXED (acceptable)

Every module in `passkms-windows` uses `unsafe` for COM/FFI interop. Scoping to individual
functions would add noise without meaningful safety improvement. The crate-level allow is
appropriate for a COM interop crate.

### L5. `CredentialStoreError::Kms` type-erases all KMS errors
**Category:** Error handling
**Files:** `crates/passkms-core/src/credential_store.rs:39-40,55-61`

The blanket `From<SdkError<E>>` routes all KMS errors into a single `Kms(Box<dyn Error>)`
variant. Callers cannot programmatically distinguish throttling from access denied from key
not found (except the one manual `NotFoundException` intercept in `get_signing_key`).

### L6. `windows-interface` version skew with `windows` crate -- NOT FIXABLE
**Category:** Dependencies
**Files:** `Cargo.toml:73`

`windows-interface` is at 0.59 while `windows` and `windows-core` are at 0.62. Investigation
confirmed 0.59.3 is the latest published version of `windows-interface`; the Microsoft
`windows-*` ecosystem did not publish a 0.62 release for this crate. Not fixable by bumping.

### L10. No MSRV specified in Cargo.toml
**Category:** Rust conventions
**Files:** `Cargo.toml`

`rust-version` is not set in `workspace.package`. While acceptable when Nix manages the
toolchain, specifying MSRV is conventional for Rust projects and helps downstream consumers.

### L11. `wide_ptr_to_string` truncation is silent to callers
**Category:** Robustness
**Files:** `crates/passkms-windows/src/util.rs:20-33`

When a wide string exceeds `MAX_WIDE_STRING_LEN` (4096), it is silently truncated with a
`tracing::warn` log. The caller receives `Some(truncated_string)` with no indication the
value was truncated. For WebAuthn RP/user names this limit is generous, but the function's
contract is unclear.

### L13. No `nix run` app output or rustdoc derivation
**Category:** Nix / Ergonomics
**Files:** `flake.nix`

The flake does not define `apps` outputs, so `nix run .#passkms-server` does not work via
the explicit apps mechanism. There is also no documentation build derivation for verifying
doc comments or publishing API docs.

### L14. `const_cast` pattern in COM response building
**Category:** Unsafe / Code quality
**Files:** `crates/passkms-windows/src/com_plugin.rs:273,275,484,486,498`

Immutable `Vec<u8>` buffers are cast from `*const u8` to `*mut u8` via `as_ptr() as *mut u8`
to satisfy Windows struct field types. While the Windows API should not mutate these buffers,
the cast technically permits it. This is a pragmatic compromise given the FFI binding types.

---

## Summary

| Severity | Total | Resolved | Remaining | Key themes |
|----------|-------|----------|-----------|------------|
| High | 3 | 2 | 1 | Request signing not verified |
| Medium | 6 | 4 | 2 | Test infra, non-atomic sync |
| Low | 15 | 6 | 9 | Privacy, performance, conventions |

### Resolved items

- **H2** -- Removed dead `discoverable` field; all credentials are always discoverable
- **H3** -- Replaced README template with actual project documentation
- **M2** -- Added warn-level logging for swallowed KMS errors in allow-list flow
- **M3** -- Added CTAP2_CBOR request type validation in COM plugin
- **M4** -- Extracted shared `extract_rp_id`, `extract_client_data_hash`, `extract_credential_list` helpers
- **M5** -- Introduced `CredentialId(String)` newtype with validation on construction
- **L4** -- Replaced all `len() as u32` casts with `len_as_u32()` using `u32::try_from`
- **L7** -- Extracted `SIGN_COUNT` and `KEY_DELETION_PENDING_DAYS` named constants
- **L8** -- Replaced `expect()` in `cose.rs` with `MissingCoordinate` error variant
- **L9** -- Added `cargo audit` check to Nix flake using RustSec advisory-db
- **L12** -- Extracted shared `msvcFlags` binding in flake.nix
- **L15** -- Summary table updated (this revision)

### Remaining priorities

1. **H1** -- Implement operation request signature verification
2. **M1** -- Introduce trait abstraction for KMS to enable unit testing
3. **M6** -- Investigate atomic credential sync
