//! IPluginAuthenticator COM implementation.
//!
//! This is the core COM object that Windows calls into for WebAuthn operations.
//! It decodes the CTAP2 CBOR requests, delegates to `passkms-core`, and encodes
//! the responses back to CBOR for the platform.

use std::sync::Arc;

use windows::core::{implement, HRESULT};

use crate::bindings::*;

/// The plugin authenticator COM object.
///
/// Each instance holds a reference to the tokio runtime for async KMS operations.
#[implement(IPluginAuthenticator)]
pub struct PluginAuthenticator {
    runtime: Arc<tokio::runtime::Runtime>,
}

impl PluginAuthenticator {
    pub fn new(runtime: Arc<tokio::runtime::Runtime>) -> Self {
        Self { runtime }
    }
}

impl IPluginAuthenticator_Impl for PluginAuthenticator_Impl {
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        if request.is_null() || response.is_null() {
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        let req = &*request;
        tracing::info!(
            transaction_id = ?req.transactionId,
            cbor_len = req.cbEncodedRequest,
            "MakeCredential request received"
        );

        // Decode the CTAP2 CBOR request using the Windows helper
        let mut decoded: *mut WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST = std::ptr::null_mut();
        let hr = WebAuthNDecodeMakeCredentialRequest(
            req.cbEncodedRequest,
            req.cbEncodedRequest as *const u8,
            &mut decoded,
        );
        if hr.is_err() {
            tracing::error!(?hr, "failed to decode MakeCredential request");
            return hr;
        }

        let decoded_ref = &*decoded;

        // Extract fields from decoded request
        let rp_id = std::str::from_utf8(std::slice::from_raw_parts(
            decoded_ref.pbRpId,
            decoded_ref.cbRpId as usize,
        ))
        .unwrap_or("unknown");

        let client_data_hash = std::slice::from_raw_parts(
            decoded_ref.pbClientDataHash,
            decoded_ref.cbClientDataHash as usize,
        )
        .to_vec();

        // Extract user info
        let user_info = &*decoded_ref.pUserInformation;
        let user_handle =
            std::slice::from_raw_parts(user_info.pbId, user_info.cbId as usize).to_vec();

        let user_name = wide_ptr_to_string(user_info.pwszName);
        let user_display_name = wide_ptr_to_string(user_info.pwszDisplayName);

        // Check if resident key is requested
        let discoverable = decoded_ref
            .pAuthenticatorOptions
            .as_ref()
            .map_or(false, |opts| opts.lRequireResidentKey > 0);

        let rp_id_owned = rp_id.to_string();

        // Delegate to passkms-core on the tokio runtime
        let core_request = passkms_core::MakeCredentialRequest {
            client_data_hash,
            rp_id: rp_id_owned.clone(),
            rp_name: wide_ptr_to_string((*decoded_ref.pRpInformation).pwszName),
            user_handle,
            user_name: user_name.clone(),
            user_display_name: user_display_name.clone(),
            discoverable,
        };

        let result = self.runtime.block_on(async {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let kms_client = aws_sdk_kms::Client::new(&config);
            let store = passkms_core::CredentialStore::new(kms_client);
            let authenticator = passkms_core::Authenticator::new(store);
            authenticator.make_credential(&core_request).await
        });

        // Free the decoded request
        WebAuthNFreeDecodedMakeCredentialRequest(decoded);

        match result {
            Ok(core_response) => {
                // Build the attestation struct for encoding
                let fmt_wide = wide_string("packed\0");
                let attestation = WEBAUTHN_CREDENTIAL_ATTESTATION_V1 {
                    dwVersion: 1,
                    pwszFormatType: fmt_wide.as_ptr(),
                    cbAuthenticatorData: core_response.auth_data_bytes.len() as u32,
                    pbAuthenticatorData: core_response.auth_data_bytes.as_ptr() as *mut u8,
                    cbAttestation: 0,
                    pbAttestation: std::ptr::null_mut(),
                    dwAttestationDecodeType: 0,
                    pvAttestationDecode: std::ptr::null(),
                    cbAttestationObject: core_response.attestation_object.len() as u32,
                    pbAttestationObject: core_response.attestation_object.as_ptr() as *mut u8,
                    cbCredentialId: core_response.credential_id.len() as u32,
                    pbCredentialId: core_response.credential_id.as_ptr() as *mut u8,
                };

                let mut cb_resp: u32 = 0;
                let mut pb_resp: *mut u8 = std::ptr::null_mut();
                let hr =
                    WebAuthNEncodeMakeCredentialResponse(&attestation, &mut cb_resp, &mut pb_resp);

                if hr.is_err() {
                    tracing::error!(?hr, "failed to encode MakeCredential response");
                    return hr;
                }

                // Allocate response struct using CoTaskMemAlloc
                let resp_ptr = windows::Win32::System::Com::CoTaskMemAlloc(std::mem::size_of::<
                    WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
                >()) as *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE;

                if resp_ptr.is_null() {
                    return windows::Win32::Foundation::E_OUTOFMEMORY;
                }

                (*resp_ptr).cbEncodedResponse = cb_resp;
                (*resp_ptr).pbEncodedResponse = pb_resp;
                *response = resp_ptr;

                HRESULT(0) // S_OK
            }
            Err(e) => {
                tracing::error!(error = %e, "MakeCredential failed");
                windows::Win32::Foundation::E_FAIL
            }
        }
    }

    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        if request.is_null() || response.is_null() {
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        let req = &*request;
        tracing::info!(
            transaction_id = ?req.transactionId,
            cbor_len = req.cbEncodedRequest,
            "GetAssertion request received"
        );

        // Decode the CTAP2 CBOR request
        let mut decoded: *mut WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST = std::ptr::null_mut();
        let hr = WebAuthNDecodeGetAssertionRequest(
            req.cbEncodedRequest,
            req.pbEncodedRequest,
            &mut decoded,
        );
        if hr.is_err() {
            tracing::error!(?hr, "failed to decode GetAssertion request");
            return hr;
        }

        let decoded_ref = &*decoded;

        // Extract RP ID from raw UTF-8 bytes
        let rp_id = std::str::from_utf8(std::slice::from_raw_parts(
            decoded_ref.pbRpId,
            decoded_ref.cbRpId as usize,
        ))
        .unwrap_or("unknown");

        let client_data_hash = std::slice::from_raw_parts(
            decoded_ref.pbClientDataHash,
            decoded_ref.cbClientDataHash as usize,
        )
        .to_vec();

        // Build allow list from credential list
        let mut allow_list = Vec::new();
        for i in 0..decoded_ref.CredentialList.cCredentials {
            let cred_ptr = *decoded_ref.CredentialList.ppCredentials.add(i as usize);
            if !cred_ptr.is_null() {
                let cred = &*cred_ptr;
                let id = std::slice::from_raw_parts(cred.pbId, cred.cbId as usize).to_vec();
                allow_list.push(id);
            }
        }

        let rp_id_owned = rp_id.to_string();

        let core_request = passkms_core::GetAssertionRequest {
            rp_id: rp_id_owned,
            client_data_hash,
            allow_list,
        };

        let result = self.runtime.block_on(async {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let kms_client = aws_sdk_kms::Client::new(&config);
            let store = passkms_core::CredentialStore::new(kms_client);
            let authenticator = passkms_core::Authenticator::new(store);
            authenticator.get_assertion(&core_request).await
        });

        WebAuthNFreeDecodedGetAssertionRequest(decoded);

        match result {
            Ok(assertions) => {
                if assertions.is_empty() {
                    tracing::warn!("no assertions returned");
                    return windows::Win32::Foundation::E_FAIL;
                }

                // Return the first assertion (Windows expects one at a time)
                let assertion = &assertions[0];

                let cred_type_wide = wide_string("public-key\0");

                let ga_response = WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
                    WebAuthNAssertion: WEBAUTHN_ASSERTION_V1 {
                        dwVersion: 1,
                        cbAuthenticatorData: assertion.auth_data_bytes.len() as u32,
                        pbAuthenticatorData: assertion.auth_data_bytes.as_ptr() as *mut u8,
                        cbSignature: assertion.signature.len() as u32,
                        pbSignature: assertion.signature.as_ptr() as *mut u8,
                        Credential: WEBAUTHN_CREDENTIAL {
                            dwVersion: 1,
                            cbId: assertion.credential_id.len() as u32,
                            pbId: assertion.credential_id.as_ptr(),
                            pwszCredentialType: cred_type_wide.as_ptr(),
                        },
                        cbUserId: assertion.user_handle.as_ref().map_or(0, |h| h.len() as u32),
                        pbUserId: assertion
                            .user_handle
                            .as_ref()
                            .map_or(std::ptr::null_mut(), |h| h.as_ptr() as *mut u8),
                    },
                    pUserInformation: std::ptr::null(),
                    dwNumberOfCredentials: assertions.len() as u32,
                    lUserSelected: 0,
                    cbLargeBlobKey: 0,
                    pbLargeBlobKey: std::ptr::null(),
                    cbUnsignedExtensionOutputs: 0,
                    pbUnsignedExtensionOutputs: std::ptr::null(),
                };

                let mut cb_resp: u32 = 0;
                let mut pb_resp: *mut u8 = std::ptr::null_mut();
                let hr =
                    WebAuthNEncodeGetAssertionResponse(&ga_response, &mut cb_resp, &mut pb_resp);

                if hr.is_err() {
                    tracing::error!(?hr, "failed to encode GetAssertion response");
                    return hr;
                }

                let resp_ptr = windows::Win32::System::Com::CoTaskMemAlloc(std::mem::size_of::<
                    WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
                >()) as *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE;

                if resp_ptr.is_null() {
                    return windows::Win32::Foundation::E_OUTOFMEMORY;
                }

                (*resp_ptr).cbEncodedResponse = cb_resp;
                (*resp_ptr).pbEncodedResponse = pb_resp;
                *response = resp_ptr;

                HRESULT(0) // S_OK
            }
            Err(e) => {
                tracing::error!(error = %e, "GetAssertion failed");
                windows::Win32::Foundation::E_FAIL
            }
        }
    }

    unsafe fn CancelOperation(
        &self,
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT {
        if request.is_null() {
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        let req = &*request;
        tracing::info!(
            transaction_id = ?req.transactionId,
            "CancelOperation request received"
        );

        // We don't currently support cancellation of in-flight KMS operations.
        // Return S_OK to acknowledge the request.
        HRESULT(0)
    }

    unsafe fn GetLockStatus(&self, lock_status: *mut PLUGIN_LOCK_STATUS) -> HRESULT {
        if lock_status.is_null() {
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        // We're always unlocked -- no local PIN or biometric gate.
        *lock_status = PLUGIN_LOCK_STATUS::Unlocked;
        HRESULT(0)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a wide (UTF-16) null-terminated pointer to an Option<String>.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16(slice).ok()
}

/// Create a null-terminated UTF-16 string from a Rust &str (must end with \0).
fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
