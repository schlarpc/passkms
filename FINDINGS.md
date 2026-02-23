# Codebase Audit Findings

Comprehensive audit of the passkms codebase covering security, type safety, error handling,
test coverage, unsafe code, architecture, Rust idioms, performance, Nix build system, and
documentation accuracy.

Previously resolved findings have been removed. Items below are from the current audit.

---

## Critical / High

### H1. Operation signing key is saved but never verified
**Category:** Security — COM
**Files:** `crates/passkms-windows/src/registration.rs:384`, `crates/passkms-windows/src/com_plugin.rs:153-154,365-366`

The `OpSignPubKey` from `WebAuthNPluginAddAuthenticator` is saved to the registry.
`load_op_sign_key()` exists but is marked `#[allow(dead_code)]`. Neither `MakeCredential` nor
`GetAssertion` verifies the `pbRequestSignature` from incoming requests. Any local COM client
can forge WebAuthn requests to the plugin. This is the most significant security finding.

**Fix:** Implement signature verification using the stored public key before processing
requests.

### H2. No unit tests for KmsSigner signing logic
**Category:** Test coverage
**Files:** `crates/passkms-core/src/kms_signer.rs:47-86`

The only test is a `Send + Sync` compile-time check. The actual signing logic — prehashing
with SHA-256, calling KMS, parsing DER signatures — has zero unit tests. The mock in
`authenticator.rs` uses `p256::ecdsa::SigningKey` which does NOT exercise the same code path
as `KmsSigner::sign_bytes`. The prehash-then-send-digest logic is only covered by ignored
integration tests requiring real AWS credentials.

**Fix:** Create a mock KMS client (using `aws-smithy-mocks` or a trait-based shim) to unit
test `sign_bytes` and `sign_prehashed` without AWS credentials.

### H3. CredentialStore has no unit tests for any KMS operations
**Category:** Test coverage
**Files:** `crates/passkms-core/src/credential_store.rs:200-517`

The only unit tests cover the pure helper functions `alias_name` and `alias_prefix`. All
KMS-interacting methods (`create_credential`, `get_signing_key`, `discover_credentials`,
`get_public_key`, `delete_credential`, `list_all_credentials`, `get_credential_metadata`) are
exclusively tested by 2 ignored integration tests. Error handling paths like alias creation
failure with orphan key cleanup (lines 270-291) are completely untested.

**Fix:** Introduce a mock KMS client or use `aws-smithy-mocks` to unit test error paths,
especially the orphan key cleanup on alias creation failure.

### H4. No tests for the Windows crate
**Category:** Test coverage
**Files:** `crates/passkms-windows/src/*.rs`

Zero `#[test]` or `#[cfg(test)]` blocks in the entire crate. Several items are testable
cross-platform without Windows:
- `util.rs`: `wide_nul`, `len_as_u32`, `pcwstr` are pure functions
- `registration.rs`: `build_authenticator_info()` is a pure CBOR builder
- `com_plugin.rs`: data extraction helpers could be refactored to accept slices

**Fix:** Add unit tests for at minimum `wide_nul`, `len_as_u32`, and
`build_authenticator_info`. Consider extracting pure logic from COM helpers into testable
functions.

---

## Medium

### M1. Non-atomic credential sync creates a gap with no credentials
**Category:** Correctness — COM
**Files:** `crates/passkms-windows/src/registration.rs:233-258`

`sync_credentials` calls `RemoveAllCredentials` then `AddCredentials`. Between these two
calls, a concurrent WebAuthn operation would find zero credentials.

**Fix:** Investigate whether the plugin API supports an atomic replace, or minimize the
window by preparing all data before removing.

### M2. Raw `Vec<u8>` used for semantically distinct byte arrays
**Category:** Type safety
**Files:** `crates/passkms-core/src/authenticator.rs:62-123`

`MakeCredentialRequest/Response` and `GetAssertionRequest/Response` use raw `Vec<u8>` for
credential IDs, user handles, attestation objects, auth data bytes, and signatures. These are
all semantically distinct. The `credential_id` field in responses is `Vec<u8>` even though the
codebase has a `CredentialId` newtype. `exclude_list` and `allow_list` are `Vec<Vec<u8>>`.

**Fix:** Consider newtypes or at least using `CredentialId` in the response structs for
credential ID fields. The allow/exclude lists could use `Vec<Vec<u8>>` with a type alias.

### M3. `rp_id` is a raw `String` with no validation
**Category:** Type safety
**Files:** `crates/passkms-core/src/authenticator.rs:66,101`

Per the WebAuthn spec, an RP ID must be a valid domain. No validation is performed. While the
platform is responsible for RP ID validation before calling the authenticator, a newtype like
`RpId(String)` would make the intent clearer and prevent bugs from empty strings or
arbitrary values.

**Fix:** Consider an `RpId` newtype, even if validation is minimal (e.g., non-empty).

### M6. `GetLockStatus` always returns Unlocked — DESIGN DECISION
**Category:** Security — COM
**Files:** `crates/passkms-windows/src/com_plugin.rs:570-581`

The authenticator reports no PIN or biometric gate. Any local user session can use the
authenticator without additional verification. The security boundary is AWS IAM credentials,
not a local PIN. This is a deliberate design choice but worth documenting prominently.

### M10. No property-based testing or fuzzing
**Category:** Test coverage
**Files:** entire codebase

No `proptest`, `quickcheck`, `arbitrary`, or `fuzz` targets exist. Key areas that would
benefit:
- `spki_der_to_cose_key` with arbitrary byte sequences (ensure no panics)
- `CredentialId::from_bytes` round-trip property
- `wide_nul` / `wide_ptr_to_string` round-trip property
- `build_authenticator_info` always produces parseable CBOR

**Fix:** Add at least fuzz targets for the DER/COSE conversion and CBOR encoding paths.

---

## Low

### L1. Credential IDs are KMS UUIDs, enabling authenticator fingerprinting — NOT FIXABLE
**Category:** Security / Privacy
**Files:** `crates/passkms-core/src/credential_store.rs:153,179`

Credential IDs are the UTF-8 bytes of KMS key UUIDs. The UUID v4 format with hyphens is
distinctive and reveals the authenticator type. This is inherent to the KMS-backed
architecture.

### L2. `#![allow(unsafe_code)]` at crate level — ACCEPTABLE
**Category:** Unsafe code
**Files:** `crates/passkms-windows/src/main.rs:2`

Every module in `passkms-windows` uses `unsafe` for COM/FFI interop. Scoping to individual
functions would add noise without meaningful safety improvement.

### L3. `CredentialStoreError::Kms` type-erases all KMS errors — ACCEPTABLE
**Category:** Error handling
**Files:** `crates/passkms-core/src/credential_store.rs:92-93,108-114`

The blanket `From<SdkError<E>>` routes all KMS errors into `Kms(Box<dyn Error>)`. No callers
currently need to distinguish error types beyond `NotFoundException`. Adding structured
variants without consumers would violate YAGNI.

### L4. `windows-interface` version skew with `windows` crate — NOT FIXABLE
**Category:** Dependencies
**Files:** `Cargo.toml:73`

`windows-interface` is at 0.59 while `windows`/`windows-core` are at 0.62. Investigation
confirmed 0.59.3 is the latest published version; Microsoft did not publish a 0.62 release
for this crate.

### L5. `const_cast` pattern in COM response building
**Category:** Unsafe / FFI
**Files:** `crates/passkms-windows/src/com_plugin.rs:309,311,489,491,505`

Immutable `Vec<u8>` buffers cast from `*const u8` to `*mut u8` to satisfy Windows struct
field types. If Windows were to write through these pointers, it would be UB. Pragmatic
compromise given the FFI binding types.

### L6. `pub_key_cred_params` uses raw `i64`
**Category:** Type safety
**Files:** `crates/passkms-core/src/authenticator.rs:84`

COSE algorithm identifiers are raw `i64` values. A newtype like `CoseAlgorithm(i64)` or
using `coset::iana::Algorithm` would make intent clearer.

### L8. `CancelOperation` is a no-op
**Category:** Completeness — COM
**Files:** `crates/passkms-windows/src/com_plugin.rs:547-568`

Logged and returns `S_OK` without canceling in-flight KMS operations. The 30-second timeout
bounds the wait, but users cannot cancel a hanging operation sooner.

### L9. `CredentialBackend` uses RPITIT, preventing `dyn` trait usage
**Category:** Architecture
**Files:** `crates/passkms-core/src/credential_store.rs:140-178`

Uses `-> impl Future<Output = ...> + Send` return types instead of `async fn` in trait.
This prevents `dyn CredentialBackend` trait objects. Currently fine since `Authenticator`
is generic over `S: CredentialBackend`, but constrains future flexibility.

### L10. Non-atomic alias-then-key deletion
**Category:** Correctness
**Files:** `crates/passkms-core/src/credential_store.rs:372-392`

`delete_credential` deletes the alias first, then schedules key deletion. A crash between
these operations leaves an orphaned key requiring manual cleanup via the AWS console.

### L11. Sequential credential lookup in allow-list flow
**Category:** Performance
**Files:** `crates/passkms-core/src/authenticator.rs:267-293`

Credentials are looked up sequentially (one `DescribeKey` per ID). The discoverable flow
uses `join_all` for concurrency. For typical allow lists (1-3 entries) this is fine, but
the pattern is inconsistent.

### L12. Unbounded concurrency in metadata fetch
**Category:** Performance
**Files:** `crates/passkms-core/src/credential_store.rs:428-433`

`join_all` launches one `list_resource_tags` call per credential with no concurrency limit.
Could hit KMS rate limits for accounts with many credentials. A
`buffer_unordered(N)` pattern would be safer.

### L14. `missing_docs` lint is `allow`
**Category:** Documentation
**Files:** `Cargo.toml:84`

No compile-time enforcement of rustdoc on public items. Public items generally have good
doc comments, but nothing prevents regression. The Nix check's `RUSTDOCFLAGS = "-D warnings"`
only catches broken links, not missing docs.

### L17. Crane input does not follow nixpkgs — NOT FIXABLE
**Category:** Nix
**Files:** `flake.nix`, `flake.lock`

The `crane` input brings its own nixpkgs. Investigation confirmed crane no longer has a
`nixpkgs` input to follow in the current version, so this is not applicable.

---

## Summary

| Severity | Total | Resolved | Remaining | Key themes |
|----------|-------|----------|-----------|------------|
| High | 5 | 1 | 4 | Request signing, test coverage for KMS/Windows code |
| Medium | 11 | 6 | 5 | Type safety, credential sync, lock status, fuzz testing |
| Low | 18 | 5 | 13 | Privacy, deps, FFI, architecture, docs (mostly acceptable/unfixable) |

### Resolved items (this session)

- **H5** — Added `delete_credential_removes_from_discovery` and `list_all_credentials_across_rps` tests
- **M4** — Used `signature::Error::from_source()` to preserve error chains in KmsSigner
- **M5** — Added `MAX_FIELD_BYTES` bounds checks on all `from_raw_parts` lengths at FFI boundary
- **M7** — Made `CredentialMetadata::rp_id` non-optional; returns error if tag missing
- **M8** — Check `GetMessageW` return value explicitly for -1 error
- **M9** — Replaced `expect()` with `Result` propagation in COM server startup
- **M11** — Exclude list now distinguishes `NotFound` from transient KMS errors
- **L7** — COM plugin now maps `NoCredential` to `NTE_NOT_FOUND`, `CredentialExcluded` to `NTE_EXISTS`
- **L13** — Added historical document disclaimers to PLAN.md and TASKS.md
- **L15** — Added Windows SDK version comment to WebAuthn struct version constants
- **L16** — Removed unnecessary `#[allow(clippy::cast_possible_truncation)]` annotations
- **L18** — Shared Windows dependency artifacts between build and clippy checks

Plus 8 new unit tests covering: non-UTF-8 credential IDs in exclude/allow lists,
multi-credential discoverable flow, attestation object field validation,
`CredentialId::from_bytes` edge cases.

### Remaining priorities

1. **H1** — Implement operation request signature verification
2. **H2–H4** — Expand test coverage (KmsSigner mocking, CredentialStore mocking, Windows crate)
3. **M10** — Add fuzz targets for DER/COSE/CBOR paths
4. **M2/M3** — Type safety improvements (newtypes for byte arrays, RpId)
