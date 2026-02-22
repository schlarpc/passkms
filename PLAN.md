# passkms

A Rust-based software FIDO2 passkey implementation backed entirely by AWS KMS.
Private key material never leaves KMS -- no envelope encryption, no local keys.

## Vision

- A shared Rust core library that handles all CTAP2 authenticator logic and KMS interaction
- A Windows desktop application that integrates with the native "Choose a passkey" dialog
  via the Windows 11 WebAuthn Plugin API
- A server-side component (Lambda/EC2) that can authenticate as the user headlessly using
  the same core library
- Future cross-platform support: macOS, Linux, browser (WASM)
- Workflow: register for a site with a passkey on the desktop, then AWS infra can log in
  as the user without ever touching key material

## How FIDO2 Maps to KMS

### Key Generation (Registration)

FIDO2 requires generating an ECDSA P-256 key pair per credential.

- `CreateKey(KeySpec::EccNistP256, KeyUsage::SignVerify)` creates the key pair inside KMS
- `GetPublicKey` returns the public key as DER-encoded SubjectPublicKeyInfo (SPKI)
- The public key must be converted to COSE format for the attestation object
- Each credential gets its own KMS key (KMS has no in-HSM asymmetric key derivation)

### Signing (Authentication)

FIDO2 authentication signs `authenticatorData || SHA-256(clientDataJSON)`.

- Pre-compute SHA-256 of the concatenated authenticator data and client data hash
- Call `Sign` with `SigningAlgorithmSpec::EcdsaSha256` and `MessageType::Digest`
- The message blob must be the **raw 32-byte SHA-256 digest**, NOT hex-encoded (64 bytes)
  -- this is a common mistake (see aws-sdk-rust discussion #571)
- KMS returns a DER-encoded ECDSA signature per ANSI X9.62

### Credential Index (Aliases)

KMS aliases serve as the credential-to-key mapping:

- Naming scheme: `alias/passkms/{rpIdHash}/{credentialId}` -> KeyId
- Non-discoverable flow: RP sends credential ID, construct alias name, call
  `DescribeKey(alias/passkms/...)` to resolve the KeyId, then `Sign` directly
- Discoverable flow: `ListAliases` with prefix `alias/passkms/{rpIdHash}/` to enumerate
  all credentials for an RP -- this is the only case that requires listing
- Credential metadata (user handle, display name, etc.) can be stored in KMS key tags
  or in a lightweight side store (DynamoDB, S3, KMS key description)

### Cost

- $1/key/month per credential -- unavoidable given the constraint of no local key material
- KMS has no derivation mechanism that produces new asymmetric signing keys inside the HSM
- Every derivation-shaped operation (GenerateDataKey, etc.) returns material to the caller,
  violating the "key material stays in KMS" requirement

## Project Structure

```
passkms/
  flake.nix                     # Nix flake: dev shells, cross-compilation, builds
  flake.lock
  rust-toolchain.toml           # Pin Rust version + MSVC target
  Cargo.toml                    # Workspace root
  crates/
    passkms-core/               # Platform-agnostic shared library (async)
      Cargo.toml
      src/
        lib.rs
        kms_signer.rs           # impl AsyncSigner for KmsSigner
        credential_store.rs     # Credential storage via KMS aliases + tags
        authenticator.rs        # CTAP2 make_credential / get_assertion logic
        attestation.rs          # AuthenticatorData, AttestationObject construction
        cose.rs                 # SPKI-to-COSE public key conversion
    passkms-windows/            # Windows desktop app (MSIX-packaged)
      Cargo.toml
      src/
        main.rs                 # COM server entry point, tokio runtime
        com_plugin.rs           # #[implement(IPluginAuthenticator)]
        com_factory.rs          # #[implement(IClassFactory)]
        bindings.rs             # Manual IPluginAuthenticator + struct definitions
      Package.appxmanifest      # MSIX manifest with COM server registration
    passkms-server/             # Lambda / EC2 headless auth service
      Cargo.toml
      src/
        main.rs
    passkms-linux/              # Future: virtual UHID FIDO2 device
      Cargo.toml
      src/
        main.rs
```

## Crate Dependencies

### passkms-core

```toml
[dependencies]
# AWS SDK
aws-config = { version = "1", features = ["behavior-version-latest"] }
aws-sdk-kms = "1"

# Async runtime
tokio = { version = "1", features = ["full"] }

# WebAuthn/CTAP2 data structures (from 1Password's passkey-rs)
passkey-types = "0.4"

# COSE key encoding
coset = "0.3"

# CBOR serialization
ciborium = "0.2"

# Elliptic curve crypto (public key parsing, signature verification)
p256 = { version = "0.13", features = ["ecdsa", "pkcs8"] }
sha2 = "0.10"
ecdsa = { version = "0.16", features = ["der"] }

# Async signing trait (the trait KmsSigner implements)
async-signature = "0.5"
signature = "2"
```

### passkms-windows

```toml
[dependencies]
passkms-core = { path = "../passkms-core" }
tokio = { version = "1", features = ["full"] }

[dependencies.windows]
version = "0.62"
features = [
    "implement",
    "Win32_System_Com",
    "Win32_Foundation",
]

[dependencies.windows-interface]
version = "0.59"
```

### passkms-server

```toml
[dependencies]
passkms-core = { path = "../passkms-core" }
tokio = { version = "1", features = ["full"] }
aws-config = { version = "1", features = ["behavior-version-latest"] }
```

### passkms-linux (future)

```toml
[dependencies]
passkms-core = { path = "../passkms-core" }
tokio = { version = "1", features = ["full"] }
uhid-virt = "0.0.6"  # or tokio-linux-uhid for async
```

## Core Library Design (passkms-core)

### KmsSigner

Implements `async_signature::AsyncSigner<Signature<NistP256>>`. This is the RustCrypto
trait designed specifically for cloud KMS / HSM async signing.

```rust
pub struct KmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
}

impl AsyncSigner<ecdsa::Signature<p256::NistP256>> for KmsSigner {
    async fn sign_async(&self, msg: &[u8]) -> Result<ecdsa::Signature<p256::NistP256>, signature::Error> {
        let digest = Sha256::digest(msg);
        let resp = self.client.sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(MessageType::Digest)
            .message(Blob::new(digest.as_slice()))  // raw 32 bytes, NOT hex
            .send()
            .await
            .map_err(|_| signature::Error::new())?;
        let sig_der = resp.signature().ok_or_else(signature::Error::new)?;
        ecdsa::Signature::<p256::NistP256>::from_der(sig_der.as_ref())
            .map_err(|_| signature::Error::new())
    }
}
```

### CredentialStore

Manages credentials via KMS aliases and key metadata:

- `create_credential(rp_id, user_handle, ...) -> CredentialId`
  - Calls `CreateKey(ECC_NIST_P256, SIGN_VERIFY)`
  - Calls `CreateAlias(alias/passkms/{rpIdHash}/{credentialId}, keyId)`
  - Stores user metadata in key tags or description
  - Returns the credential ID (could be the alias suffix or a random ID)

- `get_signing_key(rp_id, credential_id) -> KmsSigner`
  - Constructs alias `alias/passkms/{rpIdHash}/{credentialId}`
  - Calls `DescribeKey(alias)` to resolve KeyId
  - Returns a `KmsSigner` with that KeyId

- `discover_credentials(rp_id) -> Vec<CredentialMetadata>`
  - Calls `ListAliases` with prefix `alias/passkms/{rpIdHash}/`
  - Fetches metadata from key tags for each match

- `get_public_key(key_id) -> CoseKey`
  - Calls `GetPublicKey` to get DER SPKI
  - Parses with `p256::PublicKey::from_public_key_der()`
  - Converts to `coset::CoseKey` with EC2 curve parameters

### Authenticator Logic

The `passkey-authenticator` crate has a sealed `Ctap2Api` trait and hardcoded crypto --
cannot plug in KMS. Instead, build ~200 lines of custom authenticator logic using
`passkey-types` for data structures:

- `make_credential(params) -> AttestationObject`
  1. Validate RP ID, user info, credential parameters
  2. Call `credential_store.create_credential(...)` to generate KMS key
  3. Call `credential_store.get_public_key(...)` to get COSE public key
  4. Build `AuthenticatorData` (RP ID hash + flags + counter + attested credential data)
  5. Build `AttestationObject` with `fmt: "none"` (or self-attestation)
  6. Sign if doing self-attestation, using `KmsSigner`

- `get_assertion(params) -> AssertionResponse`
  1. Look up credential: either from allowList (non-discoverable) or discover (discoverable)
  2. Get `KmsSigner` from credential store
  3. Build `AuthenticatorData` (RP ID hash + flags + counter, no attested credential data)
  4. Compute `SHA-256(clientDataJSON)` (provided by caller)
  5. Sign `authenticatorData || clientDataHash` using `KmsSigner`
  6. Return authenticator data + signature

### SPKI to COSE Conversion

KMS `GetPublicKey` returns DER-encoded SPKI. WebAuthn needs COSE-encoded public key:

1. Parse SPKI with `p256::PublicKey::from_public_key_der(der_bytes)`
2. Extract uncompressed EC point (65 bytes: 0x04 || x || y)
3. Build `coset::CoseKeyBuilder::new_ec2_pub_key()`
   - `iana::EllipticCurve::P_256`
   - x coordinate (32 bytes)
   - y coordinate (32 bytes)
   - Algorithm: `iana::Algorithm::ES256`

### Signature Counter

FIDO2 requires a monotonically increasing signature counter per credential. Options:

- Store in KMS key tags (but tags are limited and updates require `TagResource` call)
- Store in a side store (DynamoDB item, S3 object, or local file)
- Use a simple atomic counter in DynamoDB keyed by credential ID
- For the server-side use case, a DynamoDB counter is natural
- For the desktop use case, a local file or DynamoDB both work

## Windows Integration (passkms-windows)

### IPluginAuthenticator COM Interface

The Windows 11 passkey plugin API (GA November 2025, 24H2+) uses the
`IPluginAuthenticator` COM interface. It is NOT in `windows` crate metadata yet --
must be defined manually.

```rust
use windows::core::{HRESULT, IUnknown, interface};

#[interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
unsafe trait IPluginAuthenticator: IUnknown {
    fn MakeCredential(
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;

    fn GetAssertion(
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;

    fn CancelOperation(
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT;

    fn GetLockStatus(
        lock_status: *mut PLUGIN_LOCK_STATUS,
    ) -> HRESULT;
}
```

The `WEBAUTHN_PLUGIN_OPERATION_REQUEST` and response structs must also be defined
manually as `#[repr(C)]` structs matching the C headers from `pluginauthenticator.h`
and `webauthnplugin.h` in the microsoft/webauthn repository.

### COM Server Registration

Out-of-process EXE COM server pattern:

```rust
use windows::Win32::System::Com::*;

fn main() {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).unwrap();

        let factory: IUnknown = PasskeyClassFactory.into();
        let cookie = CoRegisterClassObject(
            &PASSKEY_CLSID,
            &factory,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED,
        ).unwrap();
        CoResumeClassObjects().unwrap();

        // Run tokio runtime on background thread for async KMS calls
        // Main thread handles COM message pump

        CoRevokeClassObject(cookie).unwrap();
        CoUninitialize();
    }
}
```

### MSIX Manifest

Required for the WebAuthn plugin API -- unpackaged apps cannot register as passkey
providers.

```xml
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:com="http://schemas.microsoft.com/appx/manifest/com/windows10"
  xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
  IgnorableNamespaces="com uap10">

  <Identity Name="passkms"
            Publisher="CN=passkms"
            Version="1.0.0.0"
            ProcessorArchitecture="x64"/>

  <Properties>
    <DisplayName>passkms</DisplayName>
    <PublisherDisplayName>passkms</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>

  <Applications>
    <Application Id="App"
                 Executable="passkms-windows.exe"
                 EntryPoint="windows.fullTrustApplication"
                 uap10:RuntimeBehavior="packagedClassicApp"
                 uap10:TrustLevel="mediumIL">
      <Extensions>
        <com:Extension Category="windows.comServer">
          <com:ComServer>
            <com:ExeServer Executable="passkms-windows.exe"
                           DisplayName="passkms Plugin Authenticator">
              <com:Class Id="{GENERATE-CLSID-GUID}"
                         DisplayName="PasskmsPluginAuthenticator"/>
            </com:ExeServer>
          </com:ComServer>
        </com:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
```

### Runtime Registration

After MSIX install, the app calls `WebAuthNPluginAddAuthenticator` to register with
Windows. It then uses `WebAuthNPluginAuthenticatorAddCredentials` and
`WebAuthNPluginAuthenticatorRemoveCredentials` to sync credential metadata with the OS.

### SDK Requirements

- Windows SDK version 10.0.26100.7175+
- Windows 11 version 24H2 (Build 26100, Minor >= 6725) or 25H2
- The WebAuthn Plugin APIs are defined in headers only available in recent SDK builds

### Reference Implementation

Microsoft's Contoso PasskeyManager sample (C++/WinUI):
https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/PasskeyManager

### Development Workflow

Use `winapp create-debug-identity` to test with package identity without full MSIX
packaging during development:

```
cargo build
winapp create-debug-identity .\target\debug\passkms-windows.exe
.\target\debug\passkms-windows.exe  # now has package identity
```

Full MSIX packaging for end-to-end testing:
```
winapp init
cargo build --release
winapp pack .\dist --cert .\devcert.pfx
winapp cert install .\devcert.pfx
```

## Build System (Nix)

### Cross-Compilation Strategy

Target `x86_64-pc-windows-msvc` (NOT `x86_64-pc-windows-gnu`).

Modern `windows-rs` (0.62+) uses `raw-dylib` unconditionally. The GNU target has a
known incompatibility with `raw-dylib` (rust-lang/rust#140704 -- missing `dlltool`).
The MSVC target avoids this entirely.

Use `cargo-xwin` + LLVM tools for cross-compilation. Both `xwin` and `cargo-xwin` are
packaged in nixpkgs. `xwin` downloads the Microsoft CRT and Windows SDK. `clang-cl`
acts as the C compiler, `lld-link` as the linker.

### Reference: komorebi flake.nix

The komorebi project (github.com/LGUG2Z/komorebi) is a production Rust Windows app
using `windows-rs` COM/Win32 APIs, cross-compiled from Linux using Nix. Its flake.nix
uses:

- `rust-overlay` (oxalica) for the Rust toolchain
- `crane` for building
- A fixed-output derivation for the Windows SDK (via `xwin`)
- LLVM tools (`clang-cl`, `lld-link`, `llvm-lib`) for cross-compilation

### flake.nix Sketch

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Rust toolchain with Windows MSVC target
        toolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ "x86_64-pc-windows-msvc" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

        # Fixed-output derivation for Windows SDK
        windowsSdk = pkgs.stdenvNoCC.mkDerivation {
          name = "windows-sdk";
          nativeBuildInputs = [ pkgs.xwin ];
          outputHashAlgo = "sha256";
          outputHashMode = "recursive";
          outputHash = ""; # fill after first build attempt
          buildCommand = ''
            export HOME=$(mktemp -d)
            xwin --accept-license splat --output $out
          '';
        };

        # Environment variables for MSVC cross-compilation
        clangVersion = pkgs.lib.versions.major
          pkgs.llvmPackages.clang.version;

        msvcEnv = {
          CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = "lld-link";
          CC_x86_64_pc_windows_msvc = "clang-cl";
          CXX_x86_64_pc_windows_msvc = "clang-cl";
          AR_x86_64_pc_windows_msvc = "llvm-lib";
          CFLAGS_x86_64_pc_windows_msvc = builtins.concatStringsSep " " [
            "--target=x86_64-pc-windows-msvc"
            "-Wno-unused-command-line-argument"
            "-fuse-ld=lld-link"
            "/imsvc${windowsSdk}/crt/include"
            "/imsvc${windowsSdk}/sdk/include/ucrt"
            "/imsvc${windowsSdk}/sdk/include/um"
            "/imsvc${windowsSdk}/sdk/include/shared"
          ];
          CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS =
            builtins.concatStringsSep " " [
              "-Clinker-flavor=lld-link"
              "-Lnative=${windowsSdk}/crt/lib/x86_64"
              "-Lnative=${windowsSdk}/sdk/lib/um/x86_64"
              "-Lnative=${windowsSdk}/sdk/lib/ucrt/x86_64"
            ];
        };

        # Cross-compilation build tools
        crossBuildInputs = [
          pkgs.llvmPackages.clang-unwrapped  # clang-cl
          pkgs.llvmPackages.lld              # lld-link
          pkgs.llvmPackages.llvm             # llvm-lib
        ];

      in {
        devShells = {
          # Native Linux development (core + server)
          default = craneLib.devShell {
            packages = [
              pkgs.cargo-xwin
            ] ++ crossBuildInputs;
          };

          # Quick Windows cross-compile via cargo-xwin
          windows = pkgs.mkShell ({
            packages = [ pkgs.cargo-xwin ] ++ crossBuildInputs;
            CARGO_BUILD_TARGET = "x86_64-pc-windows-msvc";
          } // msvcEnv);
        };

        packages = {
          # Native Linux builds
          passkms-core = craneLib.buildPackage {
            pname = "passkms-core";
            src = craneLib.cleanCargoSource ./.;
            cargoExtraArgs = "-p passkms-core";
          };

          passkms-server = craneLib.buildPackage {
            pname = "passkms-server";
            src = craneLib.cleanCargoSource ./.;
            cargoExtraArgs = "-p passkms-server";
          };

          # Windows cross-compiled build
          passkms-windows = craneLib.buildPackage ({
            pname = "passkms-windows";
            src = craneLib.cleanCargoSource ./.;
            cargoExtraArgs = "-p passkms-windows";
            CARGO_BUILD_TARGET = "x86_64-pc-windows-msvc";
            nativeBuildInputs = crossBuildInputs;
            # Tests can't run on Linux
            doCheck = false;
          } // msvcEnv);
        };
      });
}
```

### rust-toolchain.toml

```toml
[toolchain]
channel = "stable"
targets = ["x86_64-pc-windows-msvc"]
```

## WASM Considerations (Future)

The core library can compile to WASM for browser use:

- `passkey-types`, `coset`, `ciborium`, `p256`, `sha2` all work in WASM
- `aws-sdk-kms` does NOT work in browser WASM (depends on hyper/tokio networking)
- Architecture: WASM handles CTAP2 data framing and authenticator logic; a companion
  backend API handles the actual KMS calls and returns signatures
- The `KmsSigner` trait implementation would need a WASM-specific variant that calls
  the backend API via `fetch` instead of calling KMS directly

## Cross-Platform Summary

| Platform       | Integration Surface                              | Crate / Mechanism         | Status            |
|----------------|--------------------------------------------------|---------------------------|-------------------|
| Windows 11     | Plugin API (IPluginAuthenticator COM, MSIX)      | `windows` crate + manual  | GA Nov 2025       |
| macOS          | ASCredentialProviderViewController               | Swift bridge required     | Stable (macOS 14) |
| Linux          | Virtual UHID FIDO2 device                        | `uhid-virt` crate         | Works today       |
| Linux (future) | D-Bus portal (org.freedesktop.portal.Credentials)| `linux-credentials` libs  | In development    |
| Browser        | WASM + backend API                               | wasm-bindgen + fetch      | Feasible          |

## Existing Crate Assessment

### passkey-rs (1Password) v0.4.0

- `passkey-types`: USE THIS -- WebAuthn/CTAP2 data structures with CBOR serialization
- `passkey-authenticator`: CANNOT USE directly -- `Ctap2Api` trait is sealed, crypto is
  hardcoded to `p256` crate. Cannot plug in KMS. Use as reference implementation only.
- `passkey-client`: Potentially useful for the WASM/browser path
- License: Apache-2.0 / MIT dual

### webauthn-rs (kanidm) v0.5.2

- `webauthn-rs`: Server-side / relying party. Not needed for authenticator role.
- `webauthn-authenticator-rs`: Has `SoftPasskey` and `AuthenticatorBackend` trait
  (unsealed), but plugging in KMS means reimplementing all authenticator logic anyway.
  Use as reference.
- License: MPL-2.0

### coset (Google) v0.3.8

- USE THIS for COSE key encoding/decoding
- Built on ciborium
- Builder patterns for CoseKey, CoseSign1, etc.

### ciborium v0.2.2

- USE THIS for CBOR serialization (coset depends on it)
- De facto standard, serde-based
- Development has slowed but is stable

### windows crate (Microsoft) v0.62

- USE THIS for COM implementation
- `#[implement]` macro for implementing COM interfaces
- `#[interface]` macro (from `windows-interface`) for defining custom interfaces
- `CoRegisterClassObject` for out-of-process COM server
- Fully supports stable Rust (no nightly needed)
- `com-rs` crate is DEPRECATED -- use `windows` crate instead

## AWS Credential Flow

The `aws-config` crate handles credential resolution automatically via the default
credential provider chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, etc.)
2. Shared config/credentials files (`~/.aws/config`, `~/.aws/credentials`)
3. Web Identity Token (EKS)
4. ECS Container credentials
5. SSO / IAM Identity Center (from profile config with `sso_session`)
6. EC2 Instance Metadata (IMDSv2)

### Desktop (developer machine)

Use SSO / IAM Identity Center:

```ini
# ~/.aws/config
[profile passkms]
sso_session = my-sso
sso_account_id = 111122223333
sso_role_name = PasskmsRole

[sso-session my-sso]
sso_region = us-east-1
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_registration_scopes = sso:account:access
```

```
aws sso login --profile passkms
AWS_PROFILE=passkms passkms-windows.exe
```

The Rust SDK resolves SSO credentials automatically -- no additional crate dependencies
needed beyond `aws-config`.

### Server (Lambda / EC2)

Lambda: credentials injected via environment variables (automatic).
EC2: credentials from instance metadata / instance profile (automatic).

## Implementation Order

1. **passkms-core: KmsSigner** -- implement `AsyncSigner` wrapping KMS Sign
2. **passkms-core: SPKI-to-COSE** -- convert KMS public keys to COSE format
3. **passkms-core: CredentialStore** -- KMS alias CRUD + metadata
4. **passkms-core: Authenticator** -- make_credential + get_assertion using passkey-types
5. **passkms-server** -- minimal CLI/service that exercises core for headless auth
6. **passkms-windows: COM bindings** -- define IPluginAuthenticator + structs
7. **passkms-windows: COM server** -- implement plugin, wire up to core
8. **passkms-windows: MSIX packaging** -- manifest + build pipeline
9. **Nix flake** -- dev shells + cross-compilation + reproducible builds
10. **Integration testing** -- register credential, authenticate, verify

## Key References

- Microsoft WebAuthn Plugin API: https://github.com/microsoft/webauthn
- Contoso PasskeyManager sample: https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/PasskeyManager
- windows-rs: https://github.com/microsoft/windows-rs
- passkey-rs: https://github.com/1Password/passkey-rs
- webauthn-rs: https://github.com/kanidm/webauthn-rs
- coset: https://github.com/google/coset
- komorebi flake.nix (cross-compile reference): https://github.com/LGUG2Z/komorebi
- KMS Sign API: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- KMS GetPublicKey API: https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html
- FIDO2 CTAP2 spec: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
- WebAuthn Level 3 spec: https://www.w3.org/TR/webauthn-3/
- aws-sdk-kms digest signing gotcha: https://github.com/awslabs/aws-sdk-rust/discussions/571
- raw-dylib GNU target bug: https://github.com/rust-lang/rust/issues/140704
- winapp CLI: https://github.com/microsoft/WinAppCli
