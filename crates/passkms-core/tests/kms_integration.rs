//! Integration tests against real AWS KMS.
//!
//! These tests are marked `#[ignore]` and require:
//! - Valid AWS credentials configured (default profile)
//! - KMS access permissions (CreateKey, CreateAlias, Sign, GetPublicKey, etc.)
//!
//! Run with: `cargo nextest run --test kms_integration --run-ignored`

use aws_sdk_kms::Client;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use sha2::{Digest, Sha256};

use passkms_core::{Authenticator, CredentialStore, GetAssertionRequest, MakeCredentialRequest};

async fn make_kms_client() -> Client {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    Client::new(&config)
}

/// Helper to clean up a KMS key created during tests.
async fn cleanup_key(client: &Client, rp_id: &str, key_id: &str) {
    let rp_id_hash = hex::encode(Sha256::digest(rp_id.as_bytes()));
    let alias_name = format!("alias/passkms/{rp_id_hash}/{key_id}");

    let _ = client.delete_alias().alias_name(&alias_name).send().await;

    let _ = client
        .schedule_key_deletion()
        .key_id(key_id)
        .pending_window_in_days(7)
        .send()
        .await;
}

/// RAII guard that cleans up a KMS key on drop, even if assertions panic.
struct CleanupGuard {
    client: Client,
    rp_id: String,
    key_id: String,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let client = self.client.clone();
        let rp_id = self.rp_id.clone();
        let key_id = self.key_id.clone();
        // Use the current tokio runtime to run async cleanup synchronously on drop.
        let handle = tokio::runtime::Handle::current();
        // spawn_blocking + block_on to avoid blocking the async executor thread
        let _ = std::thread::spawn(move || {
            handle.block_on(cleanup_key(&client, &rp_id, &key_id));
        })
        .join();
    }
}

#[tokio::test]
#[ignore = "requires AWS credentials (run with --run-ignored)"]
async fn test_full_registration_and_authentication_flow() {
    let client = make_kms_client().await;
    let store = CredentialStore::new(client.clone());
    let authenticator = Authenticator::new(store);
    let rp_id = "integration-test.passkms.dev";

    // --- Registration ---
    let client_data_hash: [u8; 32] = Sha256::digest(b"test-client-data-register").into();
    let request = MakeCredentialRequest {
        client_data_hash,
        rp_id: rp_id.to_string(),
        rp_name: Some("Integration Test RP".to_string()),
        user_handle: b"test-user-id".to_vec(),
        user_name: Some("testuser".to_string()),
        user_display_name: Some("Test User".to_string()),
        user_presence: true,
        exclude_list: vec![],
        pub_key_cred_params: vec![-7], // ES256
    };

    let reg_response = authenticator.make_credential(&request).await.unwrap();
    let cred_id = String::from_utf8(reg_response.credential_id.clone()).unwrap();

    // Ensure cleanup runs even if assertions below panic
    let _guard = CleanupGuard {
        client: client.clone(),
        rp_id: rp_id.to_string(),
        key_id: cred_id.clone(),
    };

    // Verify authenticator data has expected length (37 bytes base + attested cred data)
    assert!(
        reg_response.auth_data_bytes.len() > 37,
        "auth data should include attested credential data"
    );

    // Verify attestation object is valid CBOR
    let att_obj: ciborium::Value =
        ciborium::de::from_reader(reg_response.attestation_object.as_slice()).unwrap();
    if let ciborium::Value::Map(entries) = &att_obj {
        // Check fmt is "none" (platform handles attestation)
        let fmt = entries
            .iter()
            .find(|(k, _)| k == &ciborium::Value::Text("fmt".to_string()))
            .map(|(_, v)| v);
        assert_eq!(
            fmt,
            Some(&ciborium::Value::Text("none".to_string())),
            "attestation format should be 'none'"
        );
    } else {
        panic!("attestation object should be a CBOR map");
    }

    // --- Authentication ---
    let auth_client_data_hash: [u8; 32] = Sha256::digest(b"test-client-data-auth").into();
    let auth_request = GetAssertionRequest {
        rp_id: rp_id.to_string(),
        client_data_hash: auth_client_data_hash,
        user_presence: true,
        allow_list: vec![cred_id.as_bytes().to_vec()],
    };

    let auth_responses = authenticator.get_assertion(&auth_request).await.unwrap();
    assert_eq!(auth_responses.len(), 1);

    let assertion = &auth_responses[0];
    assert_eq!(
        assertion.auth_data_bytes.len(),
        37,
        "assertion auth data should be 37 bytes"
    );
    assert!(
        !assertion.signature.is_empty(),
        "signature should not be empty"
    );

    // --- Verify the signature locally ---
    // Get the public key from KMS
    let get_pk_resp = client
        .get_public_key()
        .key_id(&cred_id)
        .send()
        .await
        .unwrap();

    let pk_der = get_pk_resp.public_key().unwrap().as_ref();
    let public_key = PublicKey::from_public_key_der(pk_der).unwrap();
    let verifying_key = VerifyingKey::from(public_key);

    // Reconstruct the signed message: authenticatorData || clientDataHash
    let mut signed_data = assertion.auth_data_bytes.clone();
    signed_data.extend_from_slice(&auth_client_data_hash);

    // Our signer hashes the full message (SHA-256) before sending to KMS.
    // To verify, we also prehash and use PrehashVerifier.
    let digest = Sha256::digest(&signed_data);
    let sig_from_digest = p256::ecdsa::Signature::from_der(&assertion.signature).unwrap();

    // Use the low-level verification with prehashed digest
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    verifying_key
        .verify_prehash(&digest, &sig_from_digest)
        .expect("signature verification should succeed");

    // --- Discoverable credential flow ---
    let discover_request = GetAssertionRequest {
        rp_id: rp_id.to_string(),
        client_data_hash: Sha256::digest(b"test-client-data-discover").into(),
        user_presence: true,
        allow_list: vec![],
    };

    let discover_responses = authenticator
        .get_assertion(&discover_request)
        .await
        .unwrap();
    assert!(
        !discover_responses.is_empty(),
        "should discover at least one credential"
    );
    assert!(
        discover_responses
            .iter()
            .any(|r| r.credential_id == cred_id.as_bytes()),
        "discovered credentials should include our test credential"
    );

    // Cleanup handled by _guard on drop
}

#[tokio::test]
#[ignore = "requires AWS credentials (run with --run-ignored)"]
async fn test_credential_metadata_stored_in_tags() {
    let client = make_kms_client().await;
    let store = CredentialStore::new(client.clone());
    let rp_id = "metadata-test.passkms.dev";

    let (key_id, _signer) = store
        .create_credential(
            rp_id,
            b"user-handle-123",
            Some("alice"),
            Some("Alice Smith"),
        )
        .await
        .unwrap();

    // Ensure cleanup runs even if assertions below panic
    let _guard = CleanupGuard {
        client: client.clone(),
        rp_id: rp_id.to_string(),
        key_id: key_id.clone(),
    };

    // List credentials and verify metadata
    let credentials = store.discover_credentials(rp_id).await.unwrap();
    assert!(!credentials.is_empty());

    let our_cred = credentials.iter().find(|c| c.key_id == key_id).unwrap();
    assert_eq!(our_cred.user_name.as_deref(), Some("alice"));
    assert_eq!(our_cred.display_name.as_deref(), Some("Alice Smith"));
    assert_eq!(our_cred.rp_id.as_deref(), Some(rp_id));
    assert_eq!(
        our_cred.user_handle.as_deref(),
        Some(b"user-handle-123".as_slice())
    );

    // Cleanup handled by _guard on drop
}
