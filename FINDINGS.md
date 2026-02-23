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

### L1. Credential IDs are KMS UUIDs, enabling authenticator fingerprinting -- NOT FIXABLE
**Category:** Security / Privacy
**Files:** `crates/passkms-core/src/credential_store.rs:153,179`

Credential IDs are the UTF-8 string bytes of KMS key UUIDs. The UUID v4 format with hyphens is
distinctive and reveals the authenticator type to relying parties. This is an inherent trade-off
of the KMS-backed architecture: credential IDs must map directly to KMS key UUIDs for the
alias-based lookup system. Making them opaque would require a separate mapping store.

### L3. `#![allow(unsafe_code)]` at crate level -- NOT FIXED (acceptable)

Every module in `passkms-windows` uses `unsafe` for COM/FFI interop. Scoping to individual
functions would add noise without meaningful safety improvement. The crate-level allow is
appropriate for a COM interop crate.

### L5. `CredentialStoreError::Kms` type-erases all KMS errors -- ACCEPTABLE
**Category:** Error handling
**Files:** `crates/passkms-core/src/credential_store.rs:39-40,55-61`

The blanket `From<SdkError<E>>` routes all KMS errors into a single `Kms(Box<dyn Error>)`
variant. No callers currently need to distinguish error types beyond `NotFoundException`
(already handled in `get_signing_key`). Adding structured variants without consumers would
violate YAGNI. Error messages are preserved via Display for logging.

### L6. `windows-interface` version skew with `windows` crate -- NOT FIXABLE
**Category:** Dependencies
**Files:** `Cargo.toml:73`

`windows-interface` is at 0.59 while `windows` and `windows-core` are at 0.62. Investigation
confirmed 0.59.3 is the latest published version of `windows-interface`; the Microsoft
`windows-*` ecosystem did not publish a 0.62 release for this crate. Not fixable by bumping.

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
| Medium | 6 | 5 | 1 | Non-atomic credential sync |
| Low | 15 | 10 | 5 | Privacy, deps, FFI (all acceptable/unfixable) |

### Resolved items

- **H2** -- Removed dead `discoverable` field; all credentials are always discoverable
- **H3** -- Replaced README template with actual project documentation
- **M1** -- Introduced `CredentialBackend` trait; 13 unit tests with mock store
- **M2** -- Added warn-level logging for swallowed KMS errors in allow-list flow
- **M3** -- Added CTAP2_CBOR request type validation in COM plugin
- **M4** -- Extracted shared `extract_rp_id`, `extract_client_data_hash`, `extract_credential_list` helpers
- **M5** -- Introduced `CredentialId(String)` newtype with validation on construction
- **L2** -- Concurrent credential metadata fetching with `futures::future::join_all`
- **L4** -- Replaced all `len() as u32` casts with `len_as_u32()` using `u32::try_from`
- **L7** -- Extracted `SIGN_COUNT` and `KEY_DELETION_PENDING_DAYS` named constants
- **L8** -- Replaced `expect()` in `cose.rs` with `MissingCoordinate` error variant
- **L9** -- Added `cargo audit` check to Nix flake using RustSec advisory-db
- **L10** -- Added `rust-version = "1.75"` MSRV to workspace Cargo.toml
- **L11** -- Reject oversized wide strings instead of silently truncating
- **L12** -- Extracted shared `msvcFlags` binding in flake.nix
- **L13** -- Added `nix run` apps output and rustdoc check derivation
- **L15** -- Summary table updated

### Remaining priorities

1. **H1** -- Implement operation request signature verification
2. **M6** -- Investigate atomic credential sync
