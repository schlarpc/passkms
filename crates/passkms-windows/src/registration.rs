//! Plugin authenticator registration with the Windows WebAuthn subsystem.
//!
//! Handles calling `WebAuthNPluginAddAuthenticator` to register passkms as a
//! passkey provider, persisting the operation signing key, and checking
//! registration state.

use std::ptr;

use windows::core::HRESULT;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_BINARY, REG_OPTION_NON_VOLATILE,
};

use crate::bindings::*;
use crate::com_factory::PASSKEY_CLSID;
use crate::util::{pcwstr, wide_nul};

/// NTE_NOT_FOUND: The specified item was not found. (0x80090011)
const NTE_NOT_FOUND: HRESULT = HRESULT(0x80090011_u32.cast_signed());

/// AAGUID identifying passkms as an authenticator model. Shared with passkms-core
/// to ensure the authenticatorGetInfo response matches the attested credential data.
const PASSKMS_AAGUID: [u8; 16] = passkms_core::PASSKMS_AAGUID;

const REGISTRY_KEY: &str = "Software\\passkms";
const REGISTRY_VALUE_OP_SIGN_KEY: &str = "OpSignPubKey";

/// Check if the plugin is already registered with Windows.
///
/// Returns `Ok(true)` if registered, `Ok(false)` if not found.
pub fn is_registered() -> Result<bool, HRESULT> {
    tracing::debug!(clsid = ?PASSKEY_CLSID, "querying plugin registration state");
    let mut state = AUTHENTICATOR_STATE::Disabled;
    // SAFETY: PASSKEY_CLSID is a valid GUID; state is a valid mutable reference.
    // The FFI function reads the GUID and writes the state output.
    let hr = unsafe { WebAuthNPluginGetAuthenticatorState(&PASSKEY_CLSID, &mut state) };
    if hr.is_ok() {
        tracing::info!(?state, "plugin is registered");
        Ok(true)
    } else if hr == NTE_NOT_FOUND {
        tracing::info!("plugin is not registered (NTE_NOT_FOUND)");
        Ok(false)
    } else {
        tracing::error!(
            ?hr,
            hresult = format!("0x{:08x}", hr.0),
            "failed to query plugin state"
        );
        Err(hr)
    }
}

/// Register the plugin authenticator with Windows.
///
/// Calls `WebAuthNPluginAddAuthenticator` and persists the returned operation
/// signing public key to the Windows registry.
#[allow(clippy::cast_possible_truncation)]
pub fn register() -> Result<(), HRESULT> {
    tracing::debug!("building authenticator registration info");
    let name = wide_nul("passkms");
    let authenticator_info = build_authenticator_info();
    tracing::debug!(
        authenticator_info_len = authenticator_info.len(),
        "authenticatorGetInfo CBOR blob built"
    );

    // Minimal SVG logo (base64-encoded). The API may require non-null logos.
    let logo = wide_nul("PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI0MCIgZmlsbD0iIzMzNiIvPjwvc3ZnPg==");

    let rp_id = wide_nul("passkms.dev");

    let options = WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
        pwszAuthenticatorName: name.as_ptr(),
        rclsid: &PASSKEY_CLSID,
        pwszPluginRpId: rp_id.as_ptr(),
        pwszLightThemeLogoSvg: logo.as_ptr(),
        pwszDarkThemeLogoSvg: logo.as_ptr(),
        cbAuthenticatorInfo: crate::util::len_as_u32(authenticator_info.len()),
        pbAuthenticatorInfo: authenticator_info.as_ptr(),
        cSupportedRpIds: 0,
        ppwszSupportedRpIds: ptr::null(),
    };

    tracing::debug!(clsid = ?PASSKEY_CLSID, "calling WebAuthNPluginAddAuthenticator");
    let mut response: *mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE = ptr::null_mut();
    // SAFETY: options fields all point into local stack-owned Vecs (name, logo, rp_id,
    // authenticator_info) that outlive this call. response is an out-parameter.
    let hr = unsafe { WebAuthNPluginAddAuthenticator(&options, &mut response) };

    if hr.is_err() {
        tracing::error!(
            ?hr,
            hresult = format!("0x{:08x}", hr.0),
            "WebAuthNPluginAddAuthenticator failed"
        );
        return Err(hr);
    }
    tracing::debug!("WebAuthNPluginAddAuthenticator succeeded");

    // SAFETY: response was populated by a successful WebAuthNPluginAddAuthenticator call.
    // The pointer is valid until we call WebAuthNPluginFreeAddAuthenticatorResponse.
    let resp = unsafe { &*response };
    tracing::debug!(
        op_sign_key_len = resp.cbOpSignPubKey,
        op_sign_key_null = resp.pbOpSignPubKey.is_null(),
        "registration response received"
    );
    if resp.cbOpSignPubKey > 0 && !resp.pbOpSignPubKey.is_null() {
        // SAFETY: We checked pbOpSignPubKey is non-null and cbOpSignPubKey > 0.
        // The data is valid for the lifetime of the response (freed below).
        let key_data = unsafe {
            std::slice::from_raw_parts(resp.pbOpSignPubKey, resp.cbOpSignPubKey as usize)
        };
        tracing::debug!(
            key_len = key_data.len(),
            "operation signing public key received"
        );
        if let Err(e) = save_op_sign_key(key_data) {
            tracing::error!(error = ?e, "failed to save operation signing key to registry");
        } else {
            tracing::info!(
                key_len = resp.cbOpSignPubKey,
                "saved operation signing public key to registry"
            );
        }
    }

    // SAFETY: response was allocated by WebAuthNPluginAddAuthenticator and has not
    // been freed yet. All references to response data (key_data) are out of scope.
    unsafe { WebAuthNPluginFreeAddAuthenticatorResponse(response) };

    tracing::info!("plugin registered successfully");
    Ok(())
}

/// Unregister the plugin authenticator from Windows.
pub fn unregister() -> Result<(), HRESULT> {
    tracing::debug!(clsid = ?PASSKEY_CLSID, "calling WebAuthNPluginRemoveAuthenticator");
    // SAFETY: PASSKEY_CLSID is a valid GUID.
    let hr = unsafe { WebAuthNPluginRemoveAuthenticator(&PASSKEY_CLSID) };
    if hr.is_err() {
        tracing::error!(
            ?hr,
            hresult = format!("0x{:08x}", hr.0),
            "WebAuthNPluginRemoveAuthenticator failed"
        );
        return Err(hr);
    }

    tracing::debug!("deleting registry key");
    delete_registry_key();
    tracing::info!("plugin unregistered successfully");
    Ok(())
}

/// Ensure the plugin is registered, registering if needed.
pub fn ensure_registered() -> Result<(), HRESULT> {
    match is_registered()? {
        true => Ok(()),
        false => register(),
    }
}

/// Sync credentials from KMS with the Windows passkey picker.
///
/// Calls `WebAuthNPluginAuthenticatorAddCredentials` so credentials appear
/// in the Windows passkey selection UI.
#[allow(clippy::cast_possible_truncation)]
pub fn sync_credentials(
    runtime: &tokio::runtime::Runtime,
    store: &passkms_core::CredentialStore,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!("listing all credentials from KMS");
    let credentials = runtime.block_on(store.list_all_credentials())?;

    if credentials.is_empty() {
        tracing::info!("no credentials to sync");
        return Ok(());
    }

    tracing::debug!(count = credentials.len(), "discovered credentials from KMS");

    // Pre-compute owned data that WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS will point into.
    struct CredData {
        key_id_bytes: Vec<u8>,
        user_handle: Vec<u8>,
        rp_id: Vec<u16>,
        rp_name: Vec<u16>,
        user_name: Vec<u16>,
        display_name: Vec<u16>,
    }

    let owned: Vec<CredData> = credentials
        .iter()
        .enumerate()
        .map(|(i, cred)| {
            let rp_id_str = cred.rp_id.as_deref().unwrap_or("unknown");
            tracing::debug!(
                index = i,
                key_id = %cred.key_id,
                rp_id = %rp_id_str,
                user_name = ?cred.user_name,
                display_name = ?cred.display_name,
                has_user_handle = cred.user_handle.is_some(),
                "syncing credential"
            );
            CredData {
                key_id_bytes: cred.key_id.as_bytes().to_vec(),
                user_handle: cred.user_handle.clone().unwrap_or_default(),
                rp_id: wide_nul(rp_id_str),
                rp_name: wide_nul(rp_id_str),
                user_name: wide_nul(cred.user_name.as_deref().unwrap_or("")),
                display_name: wide_nul(cred.display_name.as_deref().unwrap_or("")),
            }
        })
        .collect();

    let details: Vec<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> = owned
        .iter()
        .map(|d| WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
            cbCredentialId: crate::util::len_as_u32(d.key_id_bytes.len()),
            pbCredentialId: d.key_id_bytes.as_ptr(),
            pwszRpId: d.rp_id.as_ptr(),
            pwszRpName: d.rp_name.as_ptr(),
            cbUserId: crate::util::len_as_u32(d.user_handle.len()),
            pbUserId: d.user_handle.as_ptr(),
            pwszUserName: d.user_name.as_ptr(),
            pwszUserDisplayName: d.display_name.as_ptr(),
        })
        .collect();

    // Clear existing credentials first to avoid NTE_EXISTS on re-sync
    tracing::debug!(clsid = ?PASSKEY_CLSID, "removing all existing credentials before sync");
    // SAFETY: PASSKEY_CLSID is a valid GUID identifying our authenticator.
    let hr = unsafe { WebAuthNPluginAuthenticatorRemoveAllCredentials(&PASSKEY_CLSID) };
    if hr.is_err() {
        tracing::warn!(
            ?hr,
            hresult = format!("0x{:08x}", hr.0),
            "RemoveAllCredentials failed (may be expected on first run)"
        );
    }

    tracing::debug!(
        num_details = details.len(),
        clsid = ?PASSKEY_CLSID,
        "calling WebAuthNPluginAuthenticatorAddCredentials"
    );
    // SAFETY: PASSKEY_CLSID is a valid GUID. details is a valid slice of structs whose
    // pointer fields (rp_id, user_name, etc.) all point into the `owned` Vec which
    // is still alive. details.len() matches the actual array length.
    let hr = unsafe {
        WebAuthNPluginAuthenticatorAddCredentials(
            &PASSKEY_CLSID,
            crate::util::len_as_u32(details.len()),
            details.as_ptr(),
        )
    };

    if hr.is_err() {
        tracing::error!(
            ?hr,
            hresult = format!("0x{:08x}", hr.0),
            "WebAuthNPluginAuthenticatorAddCredentials failed"
        );
        return Err(format!("credential sync failed: {:?}", hr).into());
    }

    tracing::info!(count = credentials.len(), "synced credentials with Windows");
    Ok(())
}

// ---------------------------------------------------------------------------
// authenticatorGetInfo CBOR builder
// ---------------------------------------------------------------------------

/// Build a minimal CTAP2 authenticatorGetInfo CBOR response.
///
/// Map keys per CTAP2 spec:
/// - 0x01: versions (array of text)
/// - 0x03: aaguid (bstr, 16 bytes)
/// - 0x04: options (map of text -> bool)
/// - 0x0A: algorithms (array of maps with "alg" and "type")
fn build_authenticator_info() -> Vec<u8> {
    use ciborium::Value;

    let info = Value::Map(vec![
        // 0x01: versions
        (
            Value::Integer(0x01.into()),
            Value::Array(vec![Value::Text("FIDO_2_0".to_string())]),
        ),
        // 0x03: aaguid (16-byte byte string)
        (
            Value::Integer(0x03.into()),
            Value::Bytes(PASSKMS_AAGUID.to_vec()),
        ),
        // 0x04: options
        (
            Value::Integer(0x04.into()),
            Value::Map(vec![
                (Value::Text("rk".to_string()), Value::Bool(true)),
                (Value::Text("up".to_string()), Value::Bool(false)),
                (Value::Text("uv".to_string()), Value::Bool(false)),
            ]),
        ),
        // 0x09: transports
        (
            Value::Integer(0x09.into()),
            Value::Array(vec![Value::Text("internal".to_string())]),
        ),
        // 0x0A: algorithms (ES256 = COSE algorithm -7)
        (
            Value::Integer(0x0A.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("alg".to_string()), Value::Integer((-7).into())),
                (
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                ),
            ])]),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&info, &mut buf).expect("CBOR encoding failed");
    tracing::debug!(
        cbor_len = buf.len(),
        aaguid = %hex::encode(PASSKMS_AAGUID),
        versions = "FIDO_2_0",
        algorithms = "ES256 (-7)",
        options = "rk=true, up=false, uv=false",
        "built authenticatorGetInfo CBOR"
    );
    buf
}

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------

fn save_op_sign_key(data: &[u8]) -> windows::core::Result<()> {
    tracing::debug!(
        data_len = data.len(),
        registry_key = REGISTRY_KEY,
        registry_value = REGISTRY_VALUE_OP_SIGN_KEY,
        "saving operation signing key to registry"
    );
    let reg_key_wide = wide_nul(REGISTRY_KEY);
    let reg_value_wide = wide_nul(REGISTRY_VALUE_OP_SIGN_KEY);
    // SAFETY: All wide string pointers (reg_key_wide, reg_value_wide) are
    // null-terminated and live for the duration of the registry calls.
    // hkey is properly opened and closed within this block.
    unsafe {
        let mut hkey = HKEY::default();
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            pcwstr(&reg_key_wide),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()?;

        let result = RegSetValueExW(
            hkey,
            pcwstr(&reg_value_wide),
            Some(0),
            REG_BINARY,
            Some(data),
        );
        let _ = RegCloseKey(hkey);
        result.ok()
    }
}

/// Load the operation signing public key from the registry.
#[allow(dead_code)]
pub fn load_op_sign_key() -> Option<Vec<u8>> {
    tracing::debug!(
        registry_key = REGISTRY_KEY,
        registry_value = REGISTRY_VALUE_OP_SIGN_KEY,
        "loading operation signing key from registry"
    );
    let reg_key_wide = wide_nul(REGISTRY_KEY);
    let reg_value_wide = wide_nul(REGISTRY_VALUE_OP_SIGN_KEY);
    // SAFETY: All wide string pointers are null-terminated and live for the
    // duration of the registry calls. We query the size first, allocate a
    // buffer, then read exactly that many bytes. hkey is closed on all paths.
    unsafe {
        let mut hkey = HKEY::default();
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            pcwstr(&reg_key_wide),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_READ,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .ok()?;

        // Query size first
        let mut size: u32 = 0;
        RegQueryValueExW(
            hkey,
            pcwstr(&reg_value_wide),
            None,
            None,
            None,
            Some(&mut size),
        )
        .ok()
        .ok()?;

        if size == 0 {
            let _ = RegCloseKey(hkey);
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        RegQueryValueExW(
            hkey,
            pcwstr(&reg_value_wide),
            None,
            None,
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        )
        .ok()
        .ok()?;

        let _ = RegCloseKey(hkey);
        buf.truncate(size as usize);
        tracing::debug!(
            key_len = buf.len(),
            "loaded operation signing key from registry"
        );
        Some(buf)
    }
}

fn delete_registry_key() {
    let reg_key_wide = wide_nul(REGISTRY_KEY);
    // SAFETY: reg_key_wide is a null-terminated wide string that outlives the call.
    unsafe {
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, pcwstr(&reg_key_wide));
    }
}
