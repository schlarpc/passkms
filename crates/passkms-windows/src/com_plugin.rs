//! IPluginAuthenticator COM implementation.
//!
//! This is the core COM object that Windows calls into for WebAuthn operations.
//! It decodes the CTAP2 CBOR requests, delegates to `passkms-core`, and encodes
//! the responses back to CBOR for the platform.

use std::sync::Arc;
use std::time::Duration;

use windows::core::{implement, HRESULT};

use crate::bindings::*;
use crate::util::{wide_nul, wide_ptr_to_string};

/// Timeout for KMS operations via the COM plugin.
/// Prevents indefinite blocking if KMS is unreachable.
const KMS_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Version constants for WebAuthn COM structs.
/// These must match the versions expected by `webauthn.dll`'s encode functions.
const WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION: u32 = 8;
const WEBAUTHN_ASSERTION_VERSION: u32 = 6;
const WEBAUTHN_CREDENTIAL_VERSION: u32 = 1;

/// The plugin authenticator COM object.
///
/// Each instance shares a reference to the tokio runtime (for blocking on async
/// operations) and the passkms-core `Authenticator` (for KMS-backed FIDO2 logic).
#[implement(IPluginAuthenticator)]
pub struct PluginAuthenticator {
    runtime: Arc<tokio::runtime::Runtime>,
    authenticator: Arc<passkms_core::Authenticator>,
}

impl PluginAuthenticator {
    pub fn new(
        runtime: Arc<tokio::runtime::Runtime>,
        authenticator: Arc<passkms_core::Authenticator>,
    ) -> Self {
        Self {
            runtime,
            authenticator,
        }
    }
}

/// COM interface implementation.
///
/// All methods are `unsafe fn` because they are called by the Windows COM runtime
/// with raw pointers. Each method validates its pointer arguments before use and
/// copies all data from Windows-allocated structs into owned Rust types immediately
/// to avoid use-after-free when the decoded requests are freed.
impl IPluginAuthenticator_Impl for PluginAuthenticator_Impl {
    #[allow(clippy::cast_possible_truncation)]
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        tracing::debug!("MakeCredential entry");
        if request.is_null() || response.is_null() {
            tracing::debug!(
                request_null = request.is_null(),
                response_null = response.is_null(),
                "MakeCredential null parameter"
            );
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        // Zero-initialize the caller-provided response struct
        *response = std::mem::zeroed();

        let req = &*request;
        tracing::info!(
            transaction_id = ?req.transactionId,
            cbor_len = req.cbEncodedRequest,
            request_type = ?req.requestType,
            hwnd = ?req.hWnd,
            signature_len = req.cbRequestSignature,
            "MakeCredential request received"
        );

        // Decode the CTAP2 CBOR request using the Windows helper
        tracing::debug!("decoding CTAP2 CBOR MakeCredential request");
        let mut decoded: *mut WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST = std::ptr::null_mut();
        let hr = WebAuthNDecodeMakeCredentialRequest(
            req.cbEncodedRequest,
            req.pbEncodedRequest,
            &mut decoded,
        );
        if hr.is_err() {
            tracing::error!(?hr, "failed to decode MakeCredential request");
            return hr;
        }
        tracing::debug!("CTAP2 CBOR MakeCredential request decoded successfully");

        let decoded_ref = &*decoded;

        // Copy all data from the decoded request into owned Rust types immediately,
        // then free the decoded struct. This avoids any risk of use-after-free since
        // the decoded struct is Windows-allocated memory with no Rust lifetime tracking.

        let rp_id = if decoded_ref.pbRpId.is_null() {
            tracing::error!("pbRpId is null in decoded MakeCredential request");
            WebAuthNFreeDecodedMakeCredentialRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        } else {
            match std::str::from_utf8(std::slice::from_raw_parts(
                decoded_ref.pbRpId,
                decoded_ref.cbRpId as usize,
            )) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    tracing::error!(error = %e, "invalid UTF-8 in RP ID");
                    WebAuthNFreeDecodedMakeCredentialRequest(decoded);
                    return windows::Win32::Foundation::E_INVALIDARG;
                }
            }
        };

        let client_data_hash = if decoded_ref.pbClientDataHash.is_null() {
            tracing::error!("pbClientDataHash is null in decoded MakeCredential request");
            WebAuthNFreeDecodedMakeCredentialRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        } else {
            let slice = std::slice::from_raw_parts(
                decoded_ref.pbClientDataHash,
                decoded_ref.cbClientDataHash as usize,
            );
            let Ok(hash) = <[u8; 32]>::try_from(slice) else {
                tracing::error!(
                    len = decoded_ref.cbClientDataHash,
                    "client data hash is not 32 bytes"
                );
                WebAuthNFreeDecodedMakeCredentialRequest(decoded);
                return windows::Win32::Foundation::E_INVALIDARG;
            };
            hash
        };

        if decoded_ref.pUserInformation.is_null() {
            tracing::error!("pUserInformation is null in decoded MakeCredential request");
            WebAuthNFreeDecodedMakeCredentialRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        }
        let user_info = &*decoded_ref.pUserInformation;

        let user_handle = if user_info.pbId.is_null() && user_info.cbId > 0 {
            tracing::error!("user pbId is null with non-zero cbId");
            WebAuthNFreeDecodedMakeCredentialRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        } else if user_info.pbId.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(user_info.pbId, user_info.cbId as usize).to_vec()
        };

        let user_name = wide_ptr_to_string(user_info.pwszName);
        let user_display_name = wide_ptr_to_string(user_info.pwszDisplayName);

        let rp_name = if decoded_ref.pRpInformation.is_null() {
            None
        } else {
            wide_ptr_to_string((*decoded_ref.pRpInformation).pwszName)
        };

        let mut pub_key_cred_params = Vec::new();
        let cred_params = &decoded_ref.WebAuthNCredentialParameters;
        if cred_params.cCredentialParameters > 0 && !cred_params.pCredentialParameters.is_null() {
            for i in 0..cred_params.cCredentialParameters {
                let param = &*cred_params.pCredentialParameters.add(i as usize);
                pub_key_cred_params.push(param.lAlg as i64);
            }
        }

        let mut exclude_list = Vec::new();
        let excl_list_valid = decoded_ref.CredentialList.cCredentials == 0
            || !decoded_ref.CredentialList.ppCredentials.is_null();
        if !excl_list_valid {
            tracing::error!("ppCredentials is null with non-zero cCredentials in exclude list");
            WebAuthNFreeDecodedMakeCredentialRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        }
        for i in 0..decoded_ref.CredentialList.cCredentials {
            let cred_ptr = *decoded_ref.CredentialList.ppCredentials.add(i as usize);
            if !cred_ptr.is_null() {
                let cred = &*cred_ptr;
                if cred.pbId.is_null() && cred.cbId > 0 {
                    tracing::warn!(
                        index = i,
                        "exclude list credential has null pbId with non-zero cbId, skipping"
                    );
                    continue;
                }
                let id = if cred.pbId.is_null() {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(cred.pbId, cred.cbId as usize).to_vec()
                };
                exclude_list.push(id);
            }
        }

        // All data copied — free the decoded request immediately
        WebAuthNFreeDecodedMakeCredentialRequest(decoded);

        tracing::debug!(
            rp_id = %rp_id,
            client_data_hash_len = client_data_hash.len(),
            user_handle_len = user_handle.len(),
            user_name = ?user_name,
            display_name = ?user_display_name,
            rp_name = ?rp_name,
            exclude_list_len = exclude_list.len(),
            "decoded MakeCredential fields"
        );

        let core_request = passkms_core::MakeCredentialRequest {
            client_data_hash,
            rp_id: rp_id.clone(),
            rp_name,
            user_handle,
            user_name: user_name.clone(),
            user_display_name: user_display_name.clone(),
            user_presence: true, // Platform handles UP via credential picker
            exclude_list,
            pub_key_cred_params,
        };

        tracing::debug!("delegating MakeCredential to passkms-core");
        let result = self.runtime.block_on(async {
            tokio::time::timeout(
                KMS_OPERATION_TIMEOUT,
                self.authenticator.make_credential(&core_request),
            )
            .await
        });

        let result = match result {
            Ok(inner) => inner,
            Err(_) => {
                tracing::error!("MakeCredential timed out");
                return windows::Win32::Foundation::E_FAIL;
            }
        };

        match result {
            Ok(core_response) => {
                tracing::debug!(
                    credential_id_len = core_response.credential_id.len(),
                    credential_id = %hex::encode(&core_response.credential_id),
                    auth_data_len = core_response.auth_data_bytes.len(),
                    attestation_object_len = core_response.attestation_object.len(),
                    "MakeCredential core response received"
                );

                // Build the attestation struct for encoding.
                // Use "none" attestation format and current version, matching the
                // Contoso sample. The encode function rejects older versions.
                let fmt_wide = wide_nul("none");
                let mut attestation: WEBAUTHN_CREDENTIAL_ATTESTATION =
                    unsafe { std::mem::zeroed() };
                attestation.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION;
                attestation.pwszFormatType = fmt_wide.as_ptr();
                attestation.cbAuthenticatorData = core_response.auth_data_bytes.len() as u32;
                attestation.pbAuthenticatorData = core_response.auth_data_bytes.as_ptr() as *mut u8;
                attestation.cbCredentialId = core_response.credential_id.len() as u32;
                attestation.pbCredentialId = core_response.credential_id.as_ptr() as *mut u8;

                tracing::debug!("encoding MakeCredential response to CTAP2 CBOR");
                let mut cb_resp: u32 = 0;
                let mut pb_resp: *mut u8 = std::ptr::null_mut();
                let hr =
                    WebAuthNEncodeMakeCredentialResponse(&attestation, &mut cb_resp, &mut pb_resp);

                if hr.is_err() {
                    tracing::error!(?hr, "failed to encode MakeCredential response");
                    return hr;
                }
                tracing::debug!(encoded_len = cb_resp, "MakeCredential response encoded");

                (*response).cbEncodedResponse = cb_resp;
                (*response).pbEncodedResponse = pb_resp;

                tracing::info!(
                    credential_id = %hex::encode(&core_response.credential_id),
                    rp_id = %rp_id,
                    "MakeCredential completed successfully"
                );
                HRESULT(0) // S_OK
            }
            Err(e) => {
                tracing::error!(error = %e, "MakeCredential failed");
                windows::Win32::Foundation::E_FAIL
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        tracing::debug!("GetAssertion entry");
        if request.is_null() || response.is_null() {
            tracing::debug!(
                request_null = request.is_null(),
                response_null = response.is_null(),
                "GetAssertion null parameter"
            );
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        // Zero-initialize the caller-provided response struct
        *response = std::mem::zeroed();

        let req = &*request;
        tracing::info!(
            transaction_id = ?req.transactionId,
            cbor_len = req.cbEncodedRequest,
            request_type = ?req.requestType,
            hwnd = ?req.hWnd,
            signature_len = req.cbRequestSignature,
            "GetAssertion request received"
        );

        // Decode the CTAP2 CBOR request
        tracing::debug!("decoding CTAP2 CBOR GetAssertion request");
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
        tracing::debug!("CTAP2 CBOR GetAssertion request decoded successfully");

        let decoded_ref = &*decoded;

        // Copy all data from the decoded request into owned Rust types immediately,
        // then free the decoded struct. This avoids any risk of use-after-free since
        // the decoded struct is Windows-allocated memory with no Rust lifetime tracking.

        let rp_id = if decoded_ref.pbRpId.is_null() {
            tracing::error!("pbRpId is null in decoded GetAssertion request");
            WebAuthNFreeDecodedGetAssertionRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        } else {
            match std::str::from_utf8(std::slice::from_raw_parts(
                decoded_ref.pbRpId,
                decoded_ref.cbRpId as usize,
            )) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    tracing::error!(error = %e, "invalid UTF-8 in RP ID");
                    WebAuthNFreeDecodedGetAssertionRequest(decoded);
                    return windows::Win32::Foundation::E_INVALIDARG;
                }
            }
        };

        let client_data_hash = if decoded_ref.pbClientDataHash.is_null() {
            tracing::error!("pbClientDataHash is null in decoded GetAssertion request");
            WebAuthNFreeDecodedGetAssertionRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        } else {
            let slice = std::slice::from_raw_parts(
                decoded_ref.pbClientDataHash,
                decoded_ref.cbClientDataHash as usize,
            );
            let Ok(hash) = <[u8; 32]>::try_from(slice) else {
                tracing::error!(
                    len = decoded_ref.cbClientDataHash,
                    "client data hash is not 32 bytes"
                );
                WebAuthNFreeDecodedGetAssertionRequest(decoded);
                return windows::Win32::Foundation::E_INVALIDARG;
            };
            hash
        };

        let mut allow_list = Vec::new();
        let cred_list_valid = decoded_ref.CredentialList.cCredentials == 0
            || !decoded_ref.CredentialList.ppCredentials.is_null();
        if !cred_list_valid {
            tracing::error!("ppCredentials is null with non-zero cCredentials");
            WebAuthNFreeDecodedGetAssertionRequest(decoded);
            return windows::Win32::Foundation::E_INVALIDARG;
        }
        for i in 0..decoded_ref.CredentialList.cCredentials {
            let cred_ptr = *decoded_ref.CredentialList.ppCredentials.add(i as usize);
            if !cred_ptr.is_null() {
                let cred = &*cred_ptr;
                if cred.pbId.is_null() && cred.cbId > 0 {
                    tracing::warn!(
                        index = i,
                        "credential has null pbId with non-zero cbId, skipping"
                    );
                    continue;
                }
                let id = if cred.pbId.is_null() {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(cred.pbId, cred.cbId as usize).to_vec()
                };
                allow_list.push(id);
            }
        }

        // All data copied — free the decoded request immediately
        WebAuthNFreeDecodedGetAssertionRequest(decoded);

        tracing::debug!(
            rp_id = %rp_id,
            client_data_hash_len = client_data_hash.len(),
            allow_list_len = allow_list.len(),
            "decoded GetAssertion fields"
        );

        let core_request = passkms_core::GetAssertionRequest {
            rp_id: rp_id.clone(),
            client_data_hash,
            user_presence: true, // Platform handles UP via credential picker
            allow_list,
        };

        tracing::debug!("delegating GetAssertion to passkms-core");
        let result = self.runtime.block_on(async {
            tokio::time::timeout(
                KMS_OPERATION_TIMEOUT,
                self.authenticator.get_assertion(&core_request),
            )
            .await
        });

        let result = match result {
            Ok(inner) => inner,
            Err(_) => {
                tracing::error!("GetAssertion timed out");
                return windows::Win32::Foundation::E_FAIL;
            }
        };

        match result {
            Ok(assertions) => {
                tracing::debug!(
                    num_assertions = assertions.len(),
                    "GetAssertion core response received"
                );

                if assertions.is_empty() {
                    tracing::warn!("no assertions returned");
                    return windows::Win32::Foundation::E_FAIL;
                }

                // Return the first assertion (Windows expects one at a time)
                let assertion = &assertions[0];

                tracing::debug!(
                    credential_id = %hex::encode(&assertion.credential_id),
                    auth_data_len = assertion.auth_data_bytes.len(),
                    signature_len = assertion.signature.len(),
                    has_user_handle = assertion.user_handle.is_some(),
                    "using first assertion"
                );

                let cred_type_wide = wide_nul("public-key");

                let mut webauthn_assertion: WEBAUTHN_ASSERTION = std::mem::zeroed();
                webauthn_assertion.dwVersion = WEBAUTHN_ASSERTION_VERSION;
                webauthn_assertion.cbAuthenticatorData = assertion.auth_data_bytes.len() as u32;
                webauthn_assertion.pbAuthenticatorData =
                    assertion.auth_data_bytes.as_ptr() as *mut u8;
                webauthn_assertion.cbSignature = assertion.signature.len() as u32;
                webauthn_assertion.pbSignature = assertion.signature.as_ptr() as *mut u8;
                webauthn_assertion.Credential = WEBAUTHN_CREDENTIAL {
                    dwVersion: WEBAUTHN_CREDENTIAL_VERSION,
                    cbId: assertion.credential_id.len() as u32,
                    pbId: assertion.credential_id.as_ptr(),
                    pwszCredentialType: cred_type_wide.as_ptr(),
                };
                webauthn_assertion.cbUserId =
                    assertion.user_handle.as_ref().map_or(0, |h| h.len() as u32);
                webauthn_assertion.pbUserId = assertion
                    .user_handle
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |h| h.as_ptr() as *mut u8);

                let ga_response = WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
                    WebAuthNAssertion: webauthn_assertion,
                    pUserInformation: std::ptr::null(),
                    dwNumberOfCredentials: assertions.len() as u32,
                    lUserSelected: 0,
                    cbLargeBlobKey: 0,
                    pbLargeBlobKey: std::ptr::null(),
                    cbUnsignedExtensionOutputs: 0,
                    pbUnsignedExtensionOutputs: std::ptr::null(),
                };

                tracing::debug!("encoding GetAssertion response to CTAP2 CBOR");
                let mut cb_resp: u32 = 0;
                let mut pb_resp: *mut u8 = std::ptr::null_mut();
                let hr =
                    WebAuthNEncodeGetAssertionResponse(&ga_response, &mut cb_resp, &mut pb_resp);

                if hr.is_err() {
                    tracing::error!(?hr, "failed to encode GetAssertion response");
                    return hr;
                }
                tracing::debug!(encoded_len = cb_resp, "GetAssertion response encoded");

                (*response).cbEncodedResponse = cb_resp;
                (*response).pbEncodedResponse = pb_resp;

                tracing::info!(
                    credential_id = %hex::encode(&assertion.credential_id),
                    rp_id = %rp_id,
                    "GetAssertion completed successfully"
                );
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
        tracing::debug!("CancelOperation entry");
        if request.is_null() {
            tracing::debug!("CancelOperation null request");
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        let req = &*request;
        tracing::info!(
            transaction_id = ?req.transactionId,
            signature_len = req.cbRequestSignature,
            "CancelOperation request received"
        );

        // We don't currently support cancellation of in-flight KMS operations.
        // Return S_OK to acknowledge the request.
        tracing::debug!("CancelOperation acknowledged (no-op, KMS operations not cancellable)");
        HRESULT(0)
    }

    unsafe fn GetLockStatus(&self, lock_status: *mut PLUGIN_LOCK_STATUS) -> HRESULT {
        tracing::debug!("GetLockStatus entry");
        if lock_status.is_null() {
            tracing::debug!("GetLockStatus null pointer");
            return windows::Win32::Foundation::E_INVALIDARG;
        }

        // We're always unlocked -- no local PIN or biometric gate.
        *lock_status = PLUGIN_LOCK_STATUS::Unlocked;
        tracing::debug!(status = ?PLUGIN_LOCK_STATUS::Unlocked, "GetLockStatus returning Unlocked");
        HRESULT(0)
    }
}
