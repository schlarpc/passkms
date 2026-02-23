//! CTAP2 authenticator logic: make_credential and get_assertion.
//!
//! This module implements the core FIDO2 authenticator operations
//! using passkey-types for data structures and KMS for cryptographic
//! operations.

use async_signature::AsyncSigner;
use passkey_types::ctap2::{Aaguid, AttestedCredentialData, AuthenticatorData, Flags};

use crate::credential_store::{CredentialBackend, CredentialId, CredentialStore};

/// Sign counter value for authenticator data.
///
/// A constant 0 signals "no counter support" per WebAuthn spec, which is safer
/// than a timestamp-based counter that can go backwards with clock adjustments.
const SIGN_COUNT: u32 = 0;

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

    /// A credential in the exclude list already exists for this RP.
    #[error("credential already exists (excluded)")]
    CredentialExcluded,

    /// No credential found for the given allow list.
    #[error("no matching credential found")]
    NoCredential,

    /// None of the requested algorithms are supported.
    #[error("unsupported algorithm: only ES256 (-7) is supported")]
    UnsupportedAlgorithm,

    /// Internal error building authenticator data.
    #[error("internal: {0}")]
    Internal(String),
}

/// Parameters for a makeCredential operation.
///
/// All credentials created by passkms are always discoverable (resident).
/// The user handle and metadata are stored as KMS key tags, enabling
/// credential discovery via `get_assertion` with an empty allow list.
#[derive(Debug)]
pub struct MakeCredentialRequest {
    /// SHA-256 hash of the client data JSON (computed by the client/platform).
    pub client_data_hash: [u8; 32],
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
    /// Whether user presence has been verified by the platform.
    /// When true, the UP flag is set in authenticator data.
    pub user_presence: bool,
    /// Credential IDs to exclude. If any match an existing credential for this RP,
    /// registration must fail (WebAuthn Section 6.3.2 step 7).
    pub exclude_list: Vec<Vec<u8>>,
    /// COSE algorithm identifiers requested by the relying party (e.g., -7 for ES256).
    /// If non-empty, registration fails unless ES256 (-7) is in the list.
    /// An empty list is treated as "any algorithm acceptable" for backwards compatibility.
    pub pub_key_cred_params: Vec<i64>,
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
    /// SHA-256 hash of the client data JSON (computed by the client/platform).
    pub client_data_hash: [u8; 32],
    /// Whether user presence has been verified by the platform.
    /// When true, the UP flag is set in authenticator data.
    pub user_presence: bool,
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
/// Uses a [`CredentialBackend`] for key management and performs FIDO2
/// authenticator operations (makeCredential, getAssertion). Defaults to
/// [`CredentialStore`] (AWS KMS) but can be parameterized with a mock
/// backend for testing.
#[derive(Clone)]
pub struct Authenticator<S = CredentialStore> {
    store: S,
    /// AAGUID identifying this authenticator type.
    aaguid: Aaguid,
}

impl<S: CredentialBackend> Authenticator<S> {
    /// Create a new authenticator with the given credential store.
    ///
    /// Uses the passkms AAGUID to identify this authenticator model.
    pub fn new(store: S) -> Self {
        Self {
            store,
            aaguid: Aaguid::from(PASSKMS_AAGUID),
        }
    }

    /// Access the underlying credential store.
    pub fn store(&self) -> &S {
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
        // 0. Validate inputs
        // Check that ES256 (-7) is in the requested algorithm list (CTAP2 spec).
        // An empty list is treated as "any algorithm acceptable".
        const ES256_COSE_ALG: i64 = -7;
        if !request.pub_key_cred_params.is_empty()
            && !request.pub_key_cred_params.contains(&ES256_COSE_ALG)
        {
            return Err(AuthenticatorError::UnsupportedAlgorithm);
        }

        // 1. Check exclude list: if any credential already exists, reject
        for cred_id_bytes in &request.exclude_list {
            let Some(cred_id) = CredentialId::from_bytes(cred_id_bytes) else {
                continue;
            };
            if self
                .store
                .get_signing_key(&request.rp_id, &cred_id)
                .await
                .is_ok()
            {
                return Err(AuthenticatorError::CredentialExcluded);
            }
        }

        // 2. Create the KMS key and alias
        let (key_id, _signer) = self
            .store
            .create_credential(
                &request.rp_id,
                &request.user_handle,
                request.user_name.as_deref(),
                request.user_display_name.as_deref(),
            )
            .await?;

        // 3. Get the COSE public key
        let cose_key = self.store.get_public_key(&key_id).await?;

        // 4. Build attested credential data
        let credential_id_bytes = key_id.as_bytes().to_vec();
        let attested_credential_data =
            AttestedCredentialData::new(self.aaguid, credential_id_bytes.clone(), cose_key)
                .map_err(|e| AuthenticatorError::Internal(e.to_string()))?;

        // 5. Build authenticator data
        let mut auth_data = AuthenticatorData::new(&request.rp_id, Some(SIGN_COUNT))
            .set_attested_credential_data(attested_credential_data);
        if request.user_presence {
            auth_data = auth_data.set_flags(Flags::UP);
        }

        let auth_data_bytes = auth_data.to_vec();

        // 6. Build "none" attestation object (no attestation statement).
        //    The Windows plugin platform handles attestation itself, so we
        //    use the "none" format to avoid a wasted KMS Sign call.
        let attestation_object_value = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("none".to_string()),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(auth_data_bytes.clone()),
            ),
        ]);

        let mut attestation_object = Vec::new();
        ciborium::ser::into_writer(&attestation_object_value, &mut attestation_object)
            .map_err(|e| AuthenticatorError::Internal(e.to_string()))?;

        Ok(MakeCredentialResponse {
            credential_id: credential_id_bytes,
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
        // 1. Find matching credentials (with signers for the non-discoverable flow)
        type Match<T> = (CredentialId, Option<Vec<u8>>, Option<T>);
        let matches: Vec<Match<S::Signer>> = if request.allow_list.is_empty() {
            // Discoverable flow: enumerate all credentials for this RP
            let discovered = self.store.discover_credentials(&request.rp_id).await?;
            if discovered.is_empty() {
                return Err(AuthenticatorError::NoCredential);
            }
            discovered
                .into_iter()
                .map(|m| (m.key_id, m.user_handle, None))
                .collect()
        } else {
            // Non-discoverable flow: try each credential in the allow list
            let mut found = Vec::new();
            for cred_id_bytes in &request.allow_list {
                let Some(cred_id) = CredentialId::from_bytes(cred_id_bytes) else {
                    tracing::warn!(
                        credential_id_hex = %hex::encode(cred_id_bytes),
                        "skipping non-UTF-8 credential ID in allow list"
                    );
                    continue;
                };
                match self.store.get_signing_key(&request.rp_id, &cred_id).await {
                    Ok(signer) => {
                        found.push((cred_id, None, Some(signer)));
                    }
                    Err(e) => {
                        tracing::warn!(
                            credential_id = %cred_id,
                            error = %e,
                            "failed to look up credential in allow list, skipping"
                        );
                        continue;
                    }
                }
            }
            if found.is_empty() {
                return Err(AuthenticatorError::NoCredential);
            }
            found
        };

        // 2. For each match, build assertion response
        let mut responses = Vec::new();
        for (key_id, user_handle, cached_signer) in &matches {
            let signer = match cached_signer {
                Some(s) => s.clone(),
                None => self.store.get_signing_key(&request.rp_id, key_id).await?,
            };

            // Build authenticator data (no attested credential data for assertions)
            let mut auth_data = AuthenticatorData::new(&request.rp_id, Some(SIGN_COUNT));
            if request.user_presence {
                auth_data = auth_data.set_flags(Flags::UP);
            }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_store::{CredentialMetadata, CredentialStoreError};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// In-memory P-256 signer for testing.
    #[derive(Clone)]
    struct MockSigner(p256::ecdsa::SigningKey);

    impl async_signature::AsyncSigner<ecdsa::Signature<p256::NistP256>> for MockSigner {
        async fn sign_async(
            &self,
            msg: &[u8],
        ) -> Result<ecdsa::Signature<p256::NistP256>, signature::Error> {
            use signature::Signer;
            self.0.try_sign(msg)
        }
    }

    struct MockCredential {
        rp_id: String,
        user_handle: Vec<u8>,
        user_name: Option<String>,
        display_name: Option<String>,
        signing_key: p256::ecdsa::SigningKey,
    }

    /// In-memory credential store for testing authenticator logic without KMS.
    #[derive(Clone)]
    struct MockStore {
        credentials: Arc<Mutex<HashMap<String, MockCredential>>>,
        next_id: Arc<Mutex<u32>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                credentials: Arc::new(Mutex::new(HashMap::new())),
                next_id: Arc::new(Mutex::new(1)),
            }
        }
    }

    impl CredentialBackend for MockStore {
        type Signer = MockSigner;

        async fn create_credential(
            &self,
            rp_id: &str,
            user_handle: &[u8],
            user_name: Option<&str>,
            display_name: Option<&str>,
        ) -> Result<(CredentialId, Self::Signer), CredentialStoreError> {
            let mut id_counter = self.next_id.lock().unwrap();
            let key_id = format!("mock-key-{}", *id_counter);
            *id_counter += 1;

            let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let signer = MockSigner(signing_key.clone());

            self.credentials.lock().unwrap().insert(
                key_id.clone(),
                MockCredential {
                    rp_id: rp_id.to_string(),
                    user_handle: user_handle.to_vec(),
                    user_name: user_name.map(String::from),
                    display_name: display_name.map(String::from),
                    signing_key,
                },
            );
            Ok((CredentialId::new(key_id), signer))
        }

        async fn get_signing_key(
            &self,
            rp_id: &str,
            credential_id: &CredentialId,
        ) -> Result<Self::Signer, CredentialStoreError> {
            let creds = self.credentials.lock().unwrap();
            let cred = creds
                .get(credential_id.as_str())
                .filter(|c| c.rp_id == rp_id)
                .ok_or_else(|| CredentialStoreError::NotFound(credential_id.to_string()))?;
            Ok(MockSigner(cred.signing_key.clone()))
        }

        async fn discover_credentials(
            &self,
            rp_id: &str,
        ) -> Result<Vec<CredentialMetadata>, CredentialStoreError> {
            let creds = self.credentials.lock().unwrap();
            Ok(creds
                .iter()
                .filter(|(_, c)| c.rp_id == rp_id)
                .map(|(id, c)| CredentialMetadata {
                    key_id: CredentialId::new(id.clone()),
                    user_handle: Some(c.user_handle.clone()),
                    display_name: c.display_name.clone(),
                    user_name: c.user_name.clone(),
                    rp_id: Some(c.rp_id.clone()),
                })
                .collect())
        }

        async fn get_public_key(
            &self,
            key_id: &CredentialId,
        ) -> Result<coset::CoseKey, CredentialStoreError> {
            use p256::pkcs8::EncodePublicKey;
            let creds = self.credentials.lock().unwrap();
            let cred = creds
                .get(key_id.as_str())
                .ok_or_else(|| CredentialStoreError::NotFound(key_id.to_string()))?;
            let der = cred
                .signing_key
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| CredentialStoreError::Internal(e.to_string()))?;
            crate::cose::spki_der_to_cose_key(der.as_ref()).map_err(CredentialStoreError::from)
        }

        async fn delete_credential(
            &self,
            _rp_id: &str,
            credential_id: &CredentialId,
        ) -> Result<(), CredentialStoreError> {
            self.credentials
                .lock()
                .unwrap()
                .remove(credential_id.as_str());
            Ok(())
        }

        async fn list_all_credentials(
            &self,
        ) -> Result<Vec<CredentialMetadata>, CredentialStoreError> {
            let creds = self.credentials.lock().unwrap();
            Ok(creds
                .iter()
                .map(|(id, c)| CredentialMetadata {
                    key_id: CredentialId::new(id.clone()),
                    user_handle: Some(c.user_handle.clone()),
                    display_name: c.display_name.clone(),
                    user_name: c.user_name.clone(),
                    rp_id: Some(c.rp_id.clone()),
                })
                .collect())
        }
    }

    fn make_authenticator() -> Authenticator<MockStore> {
        Authenticator::new(MockStore::new())
    }

    fn registration_request(rp_id: &str) -> MakeCredentialRequest {
        MakeCredentialRequest {
            client_data_hash: [0u8; 32],
            rp_id: rp_id.to_string(),
            rp_name: Some("Test RP".to_string()),
            user_handle: b"user-1".to_vec(),
            user_name: Some("alice".to_string()),
            user_display_name: Some("Alice".to_string()),
            user_presence: true,
            exclude_list: vec![],
            pub_key_cred_params: vec![-7],
        }
    }

    #[tokio::test]
    async fn make_credential_returns_valid_attestation() {
        let auth = make_authenticator();
        let response = auth
            .make_credential(&registration_request("example.com"))
            .await
            .unwrap();

        assert!(!response.credential_id.is_empty());
        // Auth data includes 37-byte base + attested credential data
        assert!(response.auth_data_bytes.len() > 37);

        // Verify attestation object is valid CBOR with "none" format
        let att_obj: ciborium::Value =
            ciborium::de::from_reader(response.attestation_object.as_slice()).unwrap();
        if let ciborium::Value::Map(entries) = &att_obj {
            let fmt = entries
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("fmt".to_string()))
                .map(|(_, v)| v);
            assert_eq!(fmt, Some(&ciborium::Value::Text("none".to_string())));
        } else {
            panic!("attestation object should be a CBOR map");
        }
    }

    #[tokio::test]
    async fn make_credential_rejects_unsupported_algorithm() {
        let auth = make_authenticator();
        let mut request = registration_request("example.com");
        request.pub_key_cred_params = vec![-257]; // RS256, not supported

        let result = auth.make_credential(&request).await;
        assert!(matches!(
            result,
            Err(AuthenticatorError::UnsupportedAlgorithm)
        ));
    }

    #[tokio::test]
    async fn make_credential_allows_empty_algorithm_list() {
        let auth = make_authenticator();
        let mut request = registration_request("example.com");
        request.pub_key_cred_params = vec![]; // empty = any algorithm

        let result = auth.make_credential(&request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn make_credential_rejects_excluded_credential() {
        let auth = make_authenticator();
        let rp_id = "example.com";

        // Register a credential first
        let reg = auth
            .make_credential(&registration_request(rp_id))
            .await
            .unwrap();

        // Try to register again with exclude list containing the first credential
        let mut request = registration_request(rp_id);
        request.exclude_list = vec![reg.credential_id.clone()];

        let result = auth.make_credential(&request).await;
        assert!(matches!(
            result,
            Err(AuthenticatorError::CredentialExcluded)
        ));
    }

    #[tokio::test]
    async fn make_credential_ignores_excluded_credential_for_different_rp() {
        let auth = make_authenticator();

        // Register for one RP
        let reg = auth
            .make_credential(&registration_request("rp-a.com"))
            .await
            .unwrap();

        // Exclude list with same credential but different RP should succeed
        let mut request = registration_request("rp-b.com");
        request.exclude_list = vec![reg.credential_id.clone()];

        let result = auth.make_credential(&request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn get_assertion_with_allow_list() {
        let auth = make_authenticator();
        let rp_id = "example.com";

        let reg = auth
            .make_credential(&registration_request(rp_id))
            .await
            .unwrap();

        let request = GetAssertionRequest {
            rp_id: rp_id.to_string(),
            client_data_hash: [1u8; 32],
            user_presence: true,
            allow_list: vec![reg.credential_id.clone()],
        };

        let responses = auth.get_assertion(&request).await.unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].credential_id, reg.credential_id);
        assert_eq!(responses[0].auth_data_bytes.len(), 37);
        assert!(!responses[0].signature.is_empty());
    }

    #[tokio::test]
    async fn get_assertion_discoverable() {
        let auth = make_authenticator();
        let rp_id = "example.com";

        let reg = auth
            .make_credential(&registration_request(rp_id))
            .await
            .unwrap();

        let request = GetAssertionRequest {
            rp_id: rp_id.to_string(),
            client_data_hash: [2u8; 32],
            user_presence: true,
            allow_list: vec![], // empty = discoverable flow
        };

        let responses = auth.get_assertion(&request).await.unwrap();
        assert!(!responses.is_empty());
        assert!(responses
            .iter()
            .any(|r| r.credential_id == reg.credential_id));
        // Discoverable flow should include user_handle
        assert!(responses[0].user_handle.is_some());
    }

    #[tokio::test]
    async fn get_assertion_no_credential_returns_error() {
        let auth = make_authenticator();

        let request = GetAssertionRequest {
            rp_id: "nonexistent.com".to_string(),
            client_data_hash: [0u8; 32],
            user_presence: false,
            allow_list: vec![b"fake-key-id".to_vec()],
        };

        let result = auth.get_assertion(&request).await;
        assert!(matches!(result, Err(AuthenticatorError::NoCredential)));
    }

    #[tokio::test]
    async fn get_assertion_discoverable_no_credentials_returns_error() {
        let auth = make_authenticator();

        let request = GetAssertionRequest {
            rp_id: "nonexistent.com".to_string(),
            client_data_hash: [0u8; 32],
            user_presence: false,
            allow_list: vec![],
        };

        let result = auth.get_assertion(&request).await;
        assert!(matches!(result, Err(AuthenticatorError::NoCredential)));
    }

    #[tokio::test]
    async fn get_assertion_wrong_rp_returns_error() {
        let auth = make_authenticator();

        let reg = auth
            .make_credential(&registration_request("rp-a.com"))
            .await
            .unwrap();

        // Try to authenticate with the credential against a different RP
        let request = GetAssertionRequest {
            rp_id: "rp-b.com".to_string(),
            client_data_hash: [0u8; 32],
            user_presence: false,
            allow_list: vec![reg.credential_id.clone()],
        };

        let result = auth.get_assertion(&request).await;
        assert!(matches!(result, Err(AuthenticatorError::NoCredential)));
    }

    #[tokio::test]
    async fn signature_is_valid_ecdsa() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::VerifyingKey;
        use sha2::{Digest, Sha256};

        let auth = make_authenticator();
        let rp_id = "example.com";

        let reg = auth
            .make_credential(&registration_request(rp_id))
            .await
            .unwrap();

        let client_data_hash = [42u8; 32];
        let assertion_req = GetAssertionRequest {
            rp_id: rp_id.to_string(),
            client_data_hash,
            user_presence: true,
            allow_list: vec![reg.credential_id.clone()],
        };

        let assertions = auth.get_assertion(&assertion_req).await.unwrap();
        let assertion = &assertions[0];

        // Get the public key from the store to verify
        let cred_id = CredentialId::from_bytes(&reg.credential_id).unwrap();
        let cose_key = auth.store().get_public_key(&cred_id).await.unwrap();

        // Extract x, y from the COSE key
        use coset::iana::Ec2KeyParameter;
        use coset::iana::EnumI64;
        let x_label = coset::Label::Int(Ec2KeyParameter::X.to_i64());
        let y_label = coset::Label::Int(Ec2KeyParameter::Y.to_i64());
        let x = cose_key
            .params
            .iter()
            .find(|(l, _)| *l == x_label)
            .and_then(|(_, v)| v.as_bytes())
            .unwrap();
        let y = cose_key
            .params
            .iter()
            .find(|(l, _)| *l == y_label)
            .and_then(|(_, v)| v.as_bytes())
            .unwrap();

        // Reconstruct the public key
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(x);
        uncompressed.extend_from_slice(y);
        let public_key = p256::PublicKey::from_sec1_bytes(&uncompressed).expect("valid public key");
        let verifying_key = VerifyingKey::from(public_key);

        // The authenticator signs: authenticatorData || clientDataHash
        let mut signed_data = assertion.auth_data_bytes.clone();
        signed_data.extend_from_slice(&client_data_hash);

        // KmsSigner prehashes before signing; the mock uses try_sign which
        // hashes internally. Verify with the standard (non-prehash) verifier.
        let sig =
            p256::ecdsa::Signature::from_der(&assertion.signature).expect("valid DER signature");
        let digest = Sha256::digest(&signed_data);
        verifying_key
            .verify_prehash(&digest, &sig)
            .expect("signature should verify");
    }

    #[tokio::test]
    async fn user_presence_flag_is_set() {
        let auth = make_authenticator();
        let mut request = registration_request("example.com");
        request.user_presence = true;

        let response = auth.make_credential(&request).await.unwrap();
        // UP flag is bit 0 of the flags byte (byte index 32 in auth data)
        assert!(
            response.auth_data_bytes[32] & 0x01 != 0,
            "UP flag should be set"
        );
    }

    #[tokio::test]
    async fn user_presence_flag_unset_when_false() {
        let auth = make_authenticator();
        let mut request = registration_request("example.com");
        request.user_presence = false;

        let response = auth.make_credential(&request).await.unwrap();
        assert!(
            response.auth_data_bytes[32] & 0x01 == 0,
            "UP flag should not be set"
        );
    }
}
