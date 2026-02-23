# passkms Task Tracking (Historical)

> **Note:** This is a historical task tracking document from the initial implementation.
> Some decisions recorded here were later revised. See `README.md` for current behavior.

<!-- AGENT RESUME CONTEXT
If resuming work on this project, read this file first to understand current state.
Then check the task list via TaskList tool for current progress.
Key files: PLAN.md (architecture), this file (status/decisions), CLAUDE.md (build commands)

Current state: Checkpoints 1-7 complete. MakeCredential and GetAssertion both work end-to-end
on webauthn.io. Core library has 12 tests. Windows COM plugin cross-compiles via
`nix build .#passkms-windows`. Deploy via `Add-AppxPackage -Register AppxManifest.xml`.
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
| 7 | Plugin lifecycle (register, credential sync, arg parsing) | done | MakeCredential + GetAssertion verified on webauthn.io |

## Checkpoint 7 Tasks

### 7a. Argument parsing and mode dispatch
- Detect `-PluginActivated` arg (Windows launches exe with this for COM activation)
- Default mode (no args): auto-register if needed, then enter COM server loop
- `--unregister` flag: remove plugin registration and exit
- Future: could add `--status` to query `WebAuthNPluginGetAuthenticatorState`

### 7b. Auto-registration on first run
- On startup (non-PluginActivated mode), call `WebAuthNPluginGetAuthenticatorState` to check
- If `NTE_NOT_FOUND`: call `WebAuthNPluginAddAuthenticator` with:
  - Authenticator name: "passkms"
  - CLSID: `{a3b2c1d0-e4f5-6789-abcd-ef0123456789}`
  - Hardcoded minimal `authenticatorGetInfo` CBOR blob:
    - Versions: `["FIDO_2_0"]`, Algorithms: `[ES256]`
    - AAGUID: fixed UUID for passkms
    - Options: `rk=true`, `uv=false`, `up=false`
  - No SVG logos (null pointers)
  - No RP ID restrictions (all RPs)
- Save returned operation signing public key to `HKCU\Software\passkms\OpSignPubKey`
- If already registered: skip, proceed to COM server

### 7c. Credential sync with OS
- After registration check, call `WebAuthNPluginAuthenticatorAddCredentials` to sync
  KMS-backed credentials with the Windows passkey picker UI
- Use `CredentialStore::list_credentials` to enumerate all passkms credentials
- Map each to `WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS` (credential ID, RP ID, user info)
- This makes credentials appear in the Windows passkey selection dialog

### 7d. Unregister support
- `--unregister` flag: call `WebAuthNPluginRemoveAuthenticator(CLSID)` and exit
- Clean up registry key if present
- Note: MSIX uninstall has no hook, so orphaned registrations are expected (same as Contoso sample)

## Debugging Notes

### Registration (`0x80090027` NotSupportedError)
- `WebAuthNPluginAddAuthenticator` rejected our call before processing the payload (no event
  log entry, unlike Contoso which logged errors even for malformed CBOR).
- **Root cause:** `pwszPluginRpId` was null. The API requires it non-null.
- **Fix:** Set `pwszPluginRpId` to `"passkms.dev"`. Also added SVG logos (base64-encoded).
- Additionally: use `Add-AppxPackage -Register` (not `Invoke-CommandInDesktopPackage`) for
  proper MSIX package registration, and `#![windows_subsystem = "windows"]` for GUI subsystem.

### MakeCredential encode (`0x8007000D` ERROR_INVALID_DATA)
- `WebAuthNEncodeMakeCredentialResponse` rejected the V1 `WEBAUTHN_CREDENTIAL_ATTESTATION`.
- **Root cause:** Struct must use current version (V8, `dwVersion: 8`) with full field layout.
- **Fix:** Use `std::mem::zeroed()` for full V8 struct, attestation format `"none"` (not `"packed"`).

### COM response signature (silent failure, no PluginMakeCredentialResponse event)
- MakeCredential returned S_OK but Windows modal stayed open indefinitely.
- **Root cause:** IPluginAuthenticator COM interface had `*mut *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE`
  (pointer-to-pointer) instead of `*mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE` (single pointer).
  The `EXPERIMENTAL_IPluginAuthenticator` uses `**` but the current interface uses `*`.
- **Fix:** Changed to single pointer, removed `CoTaskMemAlloc`, write directly to caller-provided struct.

### GetAssertion encode (`0x8007000D` ERROR_INVALID_DATA)
- Same version issue as MakeCredential attestation.
- **Root cause:** `WEBAUTHN_ASSERTION` struct was V1 but must be current version (V6, `dwVersion: 6`).
- **Fix:** Full V6 struct with `std::mem::zeroed()`.

### Credential sync (`0x8009000F` NTE_EXISTS)
- `WebAuthNPluginAuthenticatorAddCredentials` failed when credentials already existed.
- **Fix:** Call `WebAuthNPluginAuthenticatorRemoveAllCredentials` before adding.

## Ambiguity Log

Items flagged for review at checkpoints:

| # | Item | Phase | Resolution |
|---|------|-------|------------|
| 1 | Signature counter storage | 3 | Unix timestamp (seconds). No state persistence needed. |
| 2 | Credential ID format | 3 | KMS key UUID directly. |
| 3 | Credential metadata storage | 3 | KMS key tags with `passkms:` prefix. |
| 4 | Attestation format | 7 | `none` fmt (Windows plugin encode rejects `packed`). |
| 5 | passkey-types version | 1 | Using 0.5, coset 0.4. |
| 6 | Windows COM approach | 5 | Manual bindings from MS webauthn headers. `#[interface]` attribute macro + `#[implement]`. |
| 7 | MSIX signing | 6 | `winapp create-debug-identity` for dev, Microsoft Store for long-term. |
| 8 | Operation signing key storage | 7 | Windows registry: `HKCU\Software\passkms\OpSignPubKey`. |
| 9 | authenticatorGetInfo content | 7 | Hardcoded CBOR. FIDO_2_0+2_1, ES256, rk=true, up=false, uv=false, transport=internal. |
| 10 | Auto-register behavior | 7 | Auto-register on first run, no explicit --register needed. |

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
| 11 | Op signing key in HKCU registry | `HKCU\Software\passkms\OpSignPubKey`. Conventional for Windows apps. |
| 12 | Auto-register on first run | Check state, register if needed, no UI required. Simpler than Contoso's button-driven model. |
| 13 | -PluginActivated arg for COM mode | Windows launches exe with this arg. Match Contoso sample convention. |
| 14 | pwszPluginRpId = "passkms.dev" | API silently rejects null. Value is the plugin's "home" RP, not a restriction. |
| 15 | Attestation/Assertion struct versions | Must use current versions (V8/V6) with full field layout + `std::mem::zeroed()`. Older versions rejected by encode APIs. |
| 16 | COM response is single pointer | `*mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE`, NOT `*mut *mut`. Write directly to caller-provided struct. |
