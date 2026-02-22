//! CTAP2 authenticator logic: make_credential and get_assertion.
//!
//! This module implements the core FIDO2 authenticator operations
//! using passkey-types for data structures and KMS for cryptographic
//! operations.

use std::time::{SystemTime, UNIX_EPOCH};

use async_signature::AsyncSigner;
use coset::iana;
use coset::iana::EnumI64;
use passkey_types::ctap2::{Aaguid, AttestedCredentialData, AuthenticatorData, Flags};

use crate::credential_store::CredentialStore;

/// AAGUID identifying passkms as an authenticator model.
///
/// This value is embedded in attested credential data during registration
/// and must match the value reported in the CTAP2 authenticatorGetInfo response.
pub const PASSKMS_AAGUID: [u8; 16] = [
    0x70, 0x61, 0x73, 0x73, // "pass"
    0x6b, 0x6d, 0x73, 0x00, // "kms\0"
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
];

/// Errors from authenticator operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorError {
    /// Credential store error.
    #[error("credential store: {0}")]
    CredentialStore(#[from] crate::credential_store::CredentialStoreError),

    /// Signing error.
    #[error("signing: {0}")]
    Signing(#[from] signature::Error),

    /// No supported algorithm in the request.
    #[error("no supported algorithm (only ES256 is supported)")]
    UnsupportedAlgorithm,

    /// No credential found for the given allow list.
    #[error("no matching credential found")]
    NoCredential,

    /// Internal error building authenticator data.
    #[error("internal: {0}")]
    Internal(String),
}

/// Parameters for a makeCredential operation.
#[derive(Debug)]
pub struct MakeCredentialRequest {
    /// Hash of the client data JSON (computed by the client/platform).
    pub client_data_hash: Vec<u8>,
    /// The relying party ID (domain).
    pub rp_id: String,
    /// Human-friendly RP name.
    pub rp_name: Option<String>,
    /// The user handle (opaque ID from the RP).
    pub user_handle: Vec<u8>,
    /// User name.
    pub user_name: Option<String>,
    /// User display name.
    pub user_display_name: Option<String>,
    /// Whether to create a discoverable (resident) credential.
    pub discoverable: bool,
}

/// Result of a successful makeCredential operation.
#[derive(Debug)]
pub struct MakeCredentialResponse {
    /// The credential ID (KMS key UUID).
    pub credential_id: Vec<u8>,
    /// CBOR-encoded attestation object.
    pub attestation_object: Vec<u8>,
    /// The raw authenticator data bytes (for the client to use).
    pub auth_data_bytes: Vec<u8>,
}

/// Parameters for a getAssertion operation.
#[derive(Debug)]
pub struct GetAssertionRequest {
    /// The relying party ID (domain).
    pub rp_id: String,
    /// Hash of the client data JSON (computed by the client/platform).
    pub client_data_hash: Vec<u8>,
    /// List of allowed credential IDs (from the RP). If empty, uses discoverable credentials.
    pub allow_list: Vec<Vec<u8>>,
}

/// Result of a successful getAssertion operation.
#[derive(Debug)]
pub struct GetAssertionResponse {
    /// The credential ID that was used.
    pub credential_id: Vec<u8>,
    /// The raw authenticator data bytes.
    pub auth_data_bytes: Vec<u8>,
    /// The ECDSA signature over `authenticatorData || clientDataHash`.
    pub signature: Vec<u8>,
    /// User handle (for discoverable credentials).
    pub user_handle: Option<Vec<u8>>,
}

/// The main authenticator that coordinates credential management and signing.
///
/// Uses a `CredentialStore` for KMS key management and performs FIDO2
/// authenticator operations (makeCredential, getAssertion).
pub struct Authenticator {
    store: CredentialStore,
    /// AAGUID identifying this authenticator type.
    aaguid: Aaguid,
}

impl Authenticator {
    /// Create a new authenticator with the given credential store.
    ///
    /// Uses the passkms AAGUID to identify this authenticator model.
    pub fn new(store: CredentialStore) -> Self {
        Self {
            store,
            aaguid: Aaguid::from(PASSKMS_AAGUID),
        }
    }

    /// Create a new authenticator with a custom AAGUID.
    pub fn with_aaguid(store: CredentialStore, aaguid: Aaguid) -> Self {
        Self { store, aaguid }
    }

    /// Access the underlying credential store.
    pub fn store(&self) -> &CredentialStore {
        &self.store
    }

    /// Perform a makeCredential operation (registration).
    ///
    /// Creates a new KMS key, builds the authenticator data with attested
    /// credential data, and returns a self-attested attestation object.
    pub async fn make_credential(
        &self,
        request: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, AuthenticatorError> {
        // 1. Create the KMS key and alias
        let (key_id, signer) = self
            .store
            .create_credential(
                &request.rp_id,
                &request.user_handle,
                request.user_name.as_deref(),
                request.user_display_name.as_deref(),
            )
            .await?;

        // 2. Get the COSE public key
        let cose_key = self.store.get_public_key(&key_id).await?;

        // 3. Build attested credential data
        let credential_id = key_id.as_bytes().to_vec();
        let attested_credential_data =
            AttestedCredentialData::new(self.aaguid, credential_id.clone(), cose_key)
                .map_err(|e| AuthenticatorError::Internal(e.to_string()))?;

        // 4. Build authenticator data
        let counter = current_timestamp_counter();
        let auth_data = AuthenticatorData::new(&request.rp_id, Some(counter))
            .set_attested_credential_data(attested_credential_data)
            .set_flags(Flags::UP);

        let auth_data_bytes = auth_data.to_vec();

        // 5. Self-attestation: sign authenticatorData || clientDataHash
        let mut to_sign = auth_data_bytes.clone();
        to_sign.extend_from_slice(&request.client_data_hash);
        let sig = signer.sign_async(&to_sign).await?;
        let sig_der = sig.to_der();

        // 6. Build packed self-attestation statement
        //    { "alg": -7 (ES256), "sig": <signature bytes> }
        let att_stmt = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("alg".to_string()),
                ciborium::Value::Integer(iana::Algorithm::ES256.to_i64().into()),
            ),
            (
                ciborium::Value::Text("sig".to_string()),
                ciborium::Value::Bytes(sig_der.as_bytes().to_vec()),
            ),
        ]);

        // 7. Build attestation object CBOR
        let attestation_object_value = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("packed".to_string()),
            ),
            (ciborium::Value::Text("attStmt".to_string()), att_stmt),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(auth_data_bytes.clone()),
            ),
        ]);

        let mut attestation_object = Vec::new();
        ciborium::ser::into_writer(&attestation_object_value, &mut attestation_object)
            .map_err(|e| AuthenticatorError::Internal(e.to_string()))?;

        Ok(MakeCredentialResponse {
            credential_id,
            attestation_object,
            auth_data_bytes,
        })
    }

    /// Perform a getAssertion operation (authentication).
    ///
    /// Looks up the credential by allow list or discovery, builds authenticator
    /// data, and signs `authenticatorData || clientDataHash`.
    pub async fn get_assertion(
        &self,
        request: &GetAssertionRequest,
    ) -> Result<Vec<GetAssertionResponse>, AuthenticatorError> {
        // 1. Find matching credentials
        let matches = if request.allow_list.is_empty() {
            // Discoverable flow: enumerate all credentials for this RP
            let discovered = self.store.discover_credentials(&request.rp_id).await?;
            if discovered.is_empty() {
                return Err(AuthenticatorError::NoCredential);
            }
            discovered
                .into_iter()
                .map(|m| (m.key_id.clone(), m.user_handle.clone()))
                .collect::<Vec<_>>()
        } else {
            // Non-discoverable flow: try each credential in the allow list
            let mut found = Vec::new();
            for cred_id_bytes in &request.allow_list {
                let cred_id = match String::from_utf8(cred_id_bytes.clone()) {
                    Ok(s) => s,
                    Err(_) => {
                        tracing::warn!(
                            credential_id_hex = %hex::encode(cred_id_bytes),
                            "skipping non-UTF-8 credential ID in allow list"
                        );
                        continue;
                    }
                };
                match self.store.get_signing_key(&request.rp_id, &cred_id).await {
                    Ok(_) => found.push((cred_id, None)),
                    Err(_) => continue,
                }
            }
            if found.is_empty() {
                return Err(AuthenticatorError::NoCredential);
            }
            found
        };

        // 2. For each match, build assertion response
        let mut responses = Vec::new();
        for (key_id, user_handle) in &matches {
            let signer = self.store.get_signing_key(&request.rp_id, key_id).await?;

            // Build authenticator data (no attested credential data for assertions)
            let counter = current_timestamp_counter();
            let auth_data =
                AuthenticatorData::new(&request.rp_id, Some(counter)).set_flags(Flags::UP);

            let auth_data_bytes = auth_data.to_vec();

            // Sign authenticatorData || clientDataHash
            let mut to_sign = auth_data_bytes.clone();
            to_sign.extend_from_slice(&request.client_data_hash);
            let sig = signer.sign_async(&to_sign).await?;
            let sig_der = sig.to_der();

            responses.push(GetAssertionResponse {
                credential_id: key_id.as_bytes().to_vec(),
                auth_data_bytes,
                signature: sig_der.as_bytes().to_vec(),
                user_handle: user_handle.clone(),
            });
        }

        Ok(responses)
    }
}

/// Get the current Unix timestamp as a u32 signature counter.
///
/// Using a timestamp as the counter avoids needing to persist state.
/// The counter is monotonically increasing (at second granularity).
fn current_timestamp_counter() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_counter_is_nonzero() {
        let counter = current_timestamp_counter();
        assert!(counter > 0);
    }

    #[test]
    fn timestamp_counter_is_reasonable() {
        let counter = current_timestamp_counter();
        // Should be after 2024-01-01 (~1704067200)
        assert!(counter > 1_704_067_200);
        // Should be before 2100 (~4102444800, but u32 max is ~4294967295)
        assert!(counter < u32::MAX);
    }
}
