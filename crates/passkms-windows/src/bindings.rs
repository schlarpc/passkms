//! Manual bindings for the Windows 11 WebAuthn Plugin Authenticator API.
//!
//! These types are not yet in the `windows` crate metadata and must be defined
//! manually from the C headers in the microsoft/webauthn repository:
//! - `pluginauthenticator.h` (COM interface)
//! - `webauthnplugin.h` (CTAP CBOR structs, registration APIs)
//! - `webauthn.h` (shared WebAuthn types)

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;

use windows::core::{IUnknown, GUID, HRESULT};
use windows::Win32::Foundation::HWND;
use windows_core::{IUnknown_Vtbl, BOOL};

// ---------------------------------------------------------------------------
// IPluginAuthenticator COM interface
// ---------------------------------------------------------------------------

#[windows_interface::interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
pub unsafe trait IPluginAuthenticator: IUnknown {
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;

    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;

    unsafe fn CancelOperation(
        &self,
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT;

    unsafe fn GetLockStatus(&self, lock_status: *mut PLUGIN_LOCK_STATUS) -> HRESULT;
}

// ---------------------------------------------------------------------------
// Plugin operation request/response (pluginauthenticator.h)
// ---------------------------------------------------------------------------

/// Request type for plugin operations.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WEBAUTHN_PLUGIN_REQUEST_TYPE {
    CTAP2_CBOR = 0x1,
}

/// Incoming operation request from Windows to the plugin.
///
/// Contains the CBOR-encoded CTAP2 request and a signature for verification.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_PLUGIN_OPERATION_REQUEST {
    pub hWnd: HWND,
    pub transactionId: GUID,
    pub cbRequestSignature: u32,
    pub pbRequestSignature: *const u8,
    pub requestType: WEBAUTHN_PLUGIN_REQUEST_TYPE,
    pub cbEncodedRequest: u32,
    pub pbEncodedRequest: *const u8,
}

/// Response from the plugin back to Windows.
///
/// Contains the CBOR-encoded CTAP2 response.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
    pub cbEncodedResponse: u32,
    pub pbEncodedResponse: *mut u8,
}

/// Request to cancel an in-flight operation.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST {
    pub transactionId: GUID,
    pub cbRequestSignature: u32,
    pub pbRequestSignature: *const u8,
}

/// Plugin lock status.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PLUGIN_LOCK_STATUS {
    Locked = 0,
    Unlocked = 1,
}

// ---------------------------------------------------------------------------
// WebAuthn entity types (webauthn.h)
// ---------------------------------------------------------------------------

/// Relying Party entity information.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_RP_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub pwszId: *const u16,
    pub pwszName: *const u16,
    pub pwszIcon: *const u16,
}

/// User entity information.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_USER_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszName: *const u16,
    pub pwszIcon: *const u16,
    pub pwszDisplayName: *const u16,
}

/// A single COSE credential parameter (algorithm).
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    pub dwVersion: u32,
    pub pwszCredentialType: *const u16,
    pub lAlg: i32,
}

/// Array of COSE credential parameters (inline in request structs).
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
    pub cCredentialParameters: u32,
    pub pCredentialParameters: *const WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
}

/// A credential identifier with transport hints.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CREDENTIAL_EX {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszCredentialType: *const u16,
    pub dwTransports: u32,
}

/// List of credential identifiers (inline in request structs).
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CREDENTIAL_LIST {
    pub cCredentials: u32,
    pub ppCredentials: *const *const WEBAUTHN_CREDENTIAL_EX,
}

/// A credential identifier (no transport hints).
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CREDENTIAL {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszCredentialType: *const u16,
}

/// Extension data.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_EXTENSION {
    pub pwszExtensionIdentifier: *const u16,
    pub cbExtension: u32,
    pub pvExtension: *const c_void,
}

/// Array of extensions.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_EXTENSIONS {
    pub cExtensions: u32,
    pub pExtensions: *const WEBAUTHN_EXTENSION,
}

/// HMAC secret salt.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_HMAC_SECRET_SALT {
    pub cbFirst: u32,
    pub pbFirst: *const u8,
    pub cbSecond: u32,
    pub pbSecond: *const u8,
}

// ---------------------------------------------------------------------------
// CTAP CBOR authenticator options (webauthnplugin.h)
// ---------------------------------------------------------------------------

pub const WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS_VERSION_1: u32 = 1;

/// Authenticator options from the CTAP2 CBOR request.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS {
    pub dwVersion: u32,
    /// +1 = TRUE, 0 = Not defined, -1 = FALSE
    pub lUp: i32,
    /// +1 = TRUE, 0 = Not defined, -1 = FALSE
    pub lUv: i32,
    /// +1 = TRUE, 0 = Not defined, -1 = FALSE
    pub lRequireResidentKey: i32,
}

// ---------------------------------------------------------------------------
// CTAP CBOR ECC public key (webauthnplugin.h)
// ---------------------------------------------------------------------------

pub const WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY_VERSION_1: u32 = 1;

/// ECC public key in CTAP CBOR format.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY {
    pub dwVersion: u32,
    pub lKty: i32,
    pub lAlg: i32,
    pub lCrv: i32,
    pub cbX: u32,
    pub pbX: *const u8,
    pub cbY: u32,
    pub pbY: *const u8,
}

// ---------------------------------------------------------------------------
// CTAP CBOR HMAC salt extension (webauthnplugin.h)
// ---------------------------------------------------------------------------

pub const WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION_VERSION_1: u32 = 1;

/// HMAC salt extension data from CTAP2 request.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION {
    pub dwVersion: u32,
    pub pKeyAgreement: *const WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY,
    pub cbEncryptedSalt: u32,
    pub pbEncryptedSalt: *const u8,
    pub cbSaltAuth: u32,
    pub pbSaltAuth: *const u8,
}

// ---------------------------------------------------------------------------
// CTAP CBOR MakeCredential request (webauthnplugin.h)
// ---------------------------------------------------------------------------

pub const WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST_VERSION_1: u32 = 1;

/// Decoded MakeCredential request from the CTAP2 CBOR blob.
///
/// Obtained by calling `WebAuthNDecodeMakeCredentialRequest` on the
/// `pbEncodedRequest` from `WEBAUTHN_PLUGIN_OPERATION_REQUEST`.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST {
    pub dwVersion: u32,
    pub cbRpId: u32,
    pub pbRpId: *const u8,
    pub cbClientDataHash: u32,
    pub pbClientDataHash: *const u8,
    pub pRpInformation: *const WEBAUTHN_RP_ENTITY_INFORMATION,
    pub pUserInformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
    pub WebAuthNCredentialParameters: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    pub CredentialList: WEBAUTHN_CREDENTIAL_LIST,
    pub cbCborExtensionsMap: u32,
    pub pbCborExtensionsMap: *const u8,
    pub pAuthenticatorOptions: *const WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS,
    pub fEmptyPinAuth: BOOL,
    pub cbPinAuth: u32,
    pub pbPinAuth: *const u8,
    pub lHmacSecretExt: i32,
    pub pHmacSecretMcExtension: *const WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION,
    pub lPrfExt: i32,
    pub cbHmacSecretSaltValues: u32,
    pub pbHmacSecretSaltValues: *const u8,
    pub dwCredProtect: u32,
    pub dwPinProtocol: u32,
    pub dwEnterpriseAttestation: u32,
    pub cbCredBlobExt: u32,
    pub pbCredBlobExt: *const u8,
    pub lLargeBlobKeyExt: i32,
    pub dwLargeBlobSupport: u32,
    pub lMinPinLengthExt: i32,
    pub cbJsonExt: u32,
    pub pbJsonExt: *const u8,
}

// ---------------------------------------------------------------------------
// CTAP CBOR GetAssertion request (webauthnplugin.h)
// ---------------------------------------------------------------------------

pub const WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST_VERSION_1: u32 = 1;

/// Decoded GetAssertion request from the CTAP2 CBOR blob.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST {
    pub dwVersion: u32,
    pub pwszRpId: *const u16,
    pub cbRpId: u32,
    pub pbRpId: *const u8,
    pub cbClientDataHash: u32,
    pub pbClientDataHash: *const u8,
    pub CredentialList: WEBAUTHN_CREDENTIAL_LIST,
    pub cbCborExtensionsMap: u32,
    pub pbCborExtensionsMap: *const u8,
    pub pAuthenticatorOptions: *const WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS,
    pub fEmptyPinAuth: BOOL,
    pub cbPinAuth: u32,
    pub pbPinAuth: *const u8,
    pub pHmacSaltExtension: *const WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION,
    pub cbHmacSecretSaltValues: u32,
    pub pbHmacSecretSaltValues: *const u8,
    pub dwPinProtocol: u32,
    pub lCredBlobExt: i32,
    pub lLargeBlobKeyExt: i32,
    pub dwCredLargeBlobOperation: u32,
    pub cbCredLargeBlobCompressed: u32,
    pub pbCredLargeBlobCompressed: *const u8,
    pub dwCredLargeBlobOriginalSize: u32,
    pub cbJsonExt: u32,
    pub pbJsonExt: *const u8,
}

// ---------------------------------------------------------------------------
// CTAP CBOR GetAssertion response (webauthnplugin.h)
// ---------------------------------------------------------------------------

/// Assertion response for the WebAuthn platform (full struct through V6).
#[repr(C)]
pub struct WEBAUTHN_ASSERTION {
    // V1
    pub dwVersion: u32,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *mut u8,
    pub cbSignature: u32,
    pub pbSignature: *mut u8,
    pub Credential: WEBAUTHN_CREDENTIAL,
    pub cbUserId: u32,
    pub pbUserId: *mut u8,
    // V2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub cbCredLargeBlob: u32,
    pub pbCredLargeBlob: *mut u8,
    pub dwCredLargeBlobStatus: u32,
    // V3
    pub pHmacSecret: *const WEBAUTHN_HMAC_SECRET_SALT,
    // V4
    pub dwUsedTransport: u32,
    // V5
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *mut u8,
    // V6
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: *mut u8,
    pub cbAuthenticationResponseJSON: u32,
    pub pbAuthenticationResponseJSON: *mut u8,
}

/// Decoded GetAssertion response to encode back to CBOR.
#[repr(C)]
pub struct WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
    pub WebAuthNAssertion: WEBAUTHN_ASSERTION,
    pub pUserInformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
    pub dwNumberOfCredentials: u32,
    pub lUserSelected: i32,
    pub cbLargeBlobKey: u32,
    pub pbLargeBlobKey: *const u8,
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *const u8,
}

// ---------------------------------------------------------------------------
// Credential attestation (webauthn.h, used by EncodeMakeCredentialResponse)
// ---------------------------------------------------------------------------

/// Credential attestation result (full struct through V8).
#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_ATTESTATION {
    // V1
    pub dwVersion: u32,
    pub pwszFormatType: *const u16,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *mut u8,
    pub cbAttestation: u32,
    pub pbAttestation: *mut u8,
    pub dwAttestationDecodeType: u32,
    pub pvAttestationDecode: *const c_void,
    pub cbAttestationObject: u32,
    pub pbAttestationObject: *mut u8,
    pub cbCredentialId: u32,
    pub pbCredentialId: *mut u8,
    // V2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    // V3
    pub dwUsedTransport: u32,
    // V4
    pub bEpAtt: BOOL,
    pub bLargeBlobSupported: BOOL,
    pub bResidentKey: BOOL,
    // V5
    pub bPrfEnabled: BOOL,
    // V6
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *const u8,
    // V7
    pub pHmacSecret: *const WEBAUTHN_HMAC_SECRET_SALT,
    pub bThirdPartyPayment: BOOL,
    // V8
    pub dwTransports: u32,
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: *const u8,
    pub cbRegistrationResponseJSON: u32,
    pub pbRegistrationResponseJSON: *const u8,
}

// ---------------------------------------------------------------------------
// Plugin registration types (webauthnplugin.h)
// ---------------------------------------------------------------------------

/// Authenticator state.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AUTHENTICATOR_STATE {
    Disabled = 0,
    Enabled = 1,
}

/// Options for registering a plugin authenticator with Windows.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
    pub pwszAuthenticatorName: *const u16,
    pub rclsid: *const GUID,
    pub pwszPluginRpId: *const u16,
    pub pwszLightThemeLogoSvg: *const u16,
    pub pwszDarkThemeLogoSvg: *const u16,
    pub cbAuthenticatorInfo: u32,
    pub pbAuthenticatorInfo: *const u8,
    pub cSupportedRpIds: u32,
    pub ppwszSupportedRpIds: *const *const u16,
}

/// Response from adding an authenticator -- contains the operation signing public key.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE {
    pub cbOpSignPubKey: u32,
    pub pbOpSignPubKey: *mut u8,
}

/// Credential details for autofill / credential sync with the OS.
#[repr(C)]
#[derive(Debug)]
pub struct WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
    pub cbCredentialId: u32,
    pub pbCredentialId: *const u8,
    pub pwszRpId: *const u16,
    pub pwszRpName: *const u16,
    pub cbUserId: u32,
    pub pbUserId: *const u8,
    pub pwszUserName: *const u16,
    pub pwszUserDisplayName: *const u16,
}

// ---------------------------------------------------------------------------
// External functions from webauthn.dll (webauthnplugin.h)
// ---------------------------------------------------------------------------

#[link(name = "webauthn", kind = "raw-dylib")]
unsafe extern "system" {
    // --- CTAP CBOR decode/encode ---

    pub fn WebAuthNDecodeMakeCredentialRequest(
        cbEncoded: u32,
        pbEncoded: *const u8,
        ppMakeCredentialRequest: *mut *mut WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST,
    ) -> HRESULT;

    pub fn WebAuthNFreeDecodedMakeCredentialRequest(
        pMakeCredentialRequest: *mut WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST,
    );

    pub fn WebAuthNDecodeGetAssertionRequest(
        cbEncoded: u32,
        pbEncoded: *const u8,
        ppGetAssertionRequest: *mut *mut WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST,
    ) -> HRESULT;

    pub fn WebAuthNFreeDecodedGetAssertionRequest(
        pGetAssertionRequest: *mut WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST,
    );

    pub fn WebAuthNEncodeMakeCredentialResponse(
        pCredentialAttestation: *const WEBAUTHN_CREDENTIAL_ATTESTATION,
        pcbResp: *mut u32,
        ppbResp: *mut *mut u8,
    ) -> HRESULT;

    pub fn WebAuthNEncodeGetAssertionResponse(
        pGetAssertionResponse: *const WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE,
        pcbResp: *mut u32,
        ppbResp: *mut *mut u8,
    ) -> HRESULT;

    // --- Plugin registration ---

    pub fn WebAuthNPluginAddAuthenticator(
        pPluginAddAuthenticatorOptions: *const WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS,
        ppPluginAddAuthenticatorResponse: *mut *mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE,
    ) -> HRESULT;

    pub fn WebAuthNPluginFreeAddAuthenticatorResponse(
        pPluginAddAuthenticatorResponse: *mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE,
    );

    pub fn WebAuthNPluginRemoveAuthenticator(rclsid: *const GUID) -> HRESULT;

    pub fn WebAuthNPluginGetAuthenticatorState(
        rclsid: *const GUID,
        pluginAuthenticatorState: *mut AUTHENTICATOR_STATE,
    ) -> HRESULT;

    // --- Credential management ---

    pub fn WebAuthNPluginAuthenticatorAddCredentials(
        rclsid: *const GUID,
        cCredentialDetails: u32,
        pCredentialDetails: *const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS,
    ) -> HRESULT;

    pub fn WebAuthNPluginAuthenticatorRemoveCredentials(
        rclsid: *const GUID,
        cCredentialDetails: u32,
        pCredentialDetails: *const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS,
    ) -> HRESULT;

    pub fn WebAuthNPluginAuthenticatorRemoveAllCredentials(rclsid: *const GUID) -> HRESULT;

    // --- Operation signing key ---

    pub fn WebAuthNPluginGetOperationSigningPublicKey(
        rclsid: *const GUID,
        pcbOpSignPubKey: *mut u32,
        ppbOpSignPubKey: *mut *mut u8,
    ) -> HRESULT;

    pub fn WebAuthNPluginFreePublicKeyResponse(pbOpSignPubKey: *mut u8);
}
