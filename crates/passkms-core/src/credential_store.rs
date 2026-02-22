//! Credential storage and retrieval via AWS KMS aliases and key metadata.
//!
//! Each FIDO2 credential maps to a KMS asymmetric signing key.
//! Aliases provide the credential-to-key mapping:
//! `alias/passkms/{rpIdHash}/{keyId}` -> KeyId
//!
//! Credential metadata (user handle, display name) is stored in KMS key tags
//! with the `passkms:` prefix.

use aws_sdk_kms::types::{KeySpec, KeyUsageType, Tag};
use aws_sdk_kms::Client;
use sha2::{Digest, Sha256};

use crate::cose;
use crate::KmsSigner;

macro_rules! passkms_tag {
    ($suffix:literal) => {
        concat!("passkms:", $suffix)
    };
}

/// Prefix for all passkms KMS key tags.
const TAG_PREFIX: &str = passkms_tag!("");

/// Base prefix for all passkms KMS aliases.
const ALIAS_BASE_PREFIX: &str = "alias/passkms/";

const TAG_USER_HANDLE: &str = passkms_tag!("user_handle");
const TAG_DISPLAY_NAME: &str = passkms_tag!("display_name");
const TAG_USER_NAME: &str = passkms_tag!("user_name");
const TAG_RP_ID: &str = passkms_tag!("rp_id");
const TAG_MANAGED: &str = passkms_tag!("managed");

/// Errors from credential store operations.
#[derive(Debug, thiserror::Error)]
pub enum CredentialStoreError {
    /// KMS API error (preserves the underlying error for source chain).
    #[error("{0}")]
    Kms(Box<dyn std::error::Error + Send + Sync>),

    /// Internal logic error (unexpected missing fields in KMS responses).
    #[error("internal error: {0}")]
    Internal(String),

    /// Failed to parse public key from KMS.
    #[error("public key conversion error: {0}")]
    PublicKey(#[from] cose::CoseConversionError),

    /// Credential not found.
    #[error("credential not found: {0}")]
    NotFound(String),
}

impl<E: std::error::Error + Send + Sync + 'static> From<aws_sdk_kms::error::SdkError<E>>
    for CredentialStoreError
{
    fn from(e: aws_sdk_kms::error::SdkError<E>) -> Self {
        Self::Kms(Box::new(e))
    }
}

/// Metadata about a discovered credential.
#[derive(Debug, Clone)]
pub struct CredentialMetadata {
    /// The KMS key ID (also used as the FIDO2 credential ID).
    pub key_id: String,
    /// The user handle (opaque bytes from the RP).
    pub user_handle: Option<Vec<u8>>,
    /// The user display name.
    pub display_name: Option<String>,
    /// The user name.
    pub user_name: Option<String>,
    /// The RP ID this credential is scoped to.
    pub rp_id: Option<String>,
}

/// Manages FIDO2 credentials backed by AWS KMS keys.
///
/// Each credential is a KMS ECC_NIST_P256 signing key. Metadata is stored
/// in key tags. Aliases map RP ID hashes to key IDs for lookup.
#[derive(Clone, Debug)]
pub struct CredentialStore {
    client: Client,
}

impl CredentialStore {
    /// Create a new credential store using the given KMS client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Create a new FIDO2 credential backed by a KMS key.
    ///
    /// Returns the KMS key ID (which serves as the credential ID) and a
    /// `KmsSigner` bound to the new key.
    pub async fn create_credential(
        &self,
        rp_id: &str,
        user_handle: &[u8],
        user_name: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<(String, KmsSigner), CredentialStoreError> {
        use data_encoding::BASE64URL_NOPAD;

        let user_handle_b64 = BASE64URL_NOPAD.encode(user_handle);

        let mut tags = vec![
            Tag::builder()
                .tag_key(TAG_MANAGED)
                .tag_value("true")
                .build()
                .expect("tag_key and tag_value both set"),
            Tag::builder()
                .tag_key(TAG_RP_ID)
                .tag_value(rp_id)
                .build()
                .expect("tag_key and tag_value both set"),
            Tag::builder()
                .tag_key(TAG_USER_HANDLE)
                .tag_value(&user_handle_b64)
                .build()
                .expect("tag_key and tag_value both set"),
        ];

        if let Some(name) = user_name {
            tags.push(
                Tag::builder()
                    .tag_key(TAG_USER_NAME)
                    .tag_value(name)
                    .build()
                    .expect("tag_key and tag_value both set"),
            );
        }

        if let Some(name) = display_name {
            tags.push(
                Tag::builder()
                    .tag_key(TAG_DISPLAY_NAME)
                    .tag_value(name)
                    .build()
                    .expect("tag_key and tag_value both set"),
            );
        }

        // Create the KMS key
        let create_resp = self
            .client
            .create_key()
            .key_spec(KeySpec::EccNistP256)
            .key_usage(KeyUsageType::SignVerify)
            .description(format!("passkms credential for {rp_id}"))
            .set_tags(Some(tags))
            .send()
            .await?;

        let key_id = create_resp
            .key_metadata()
            .map(|m| m.key_id().to_string())
            .ok_or_else(|| {
                CredentialStoreError::Internal("missing key metadata in CreateKey response".into())
            })?;

        // Create alias for lookup: alias/passkms/{rpIdHash}/{keyId}
        let alias_name = alias_name(rp_id, &key_id);
        self.client
            .create_alias()
            .alias_name(&alias_name)
            .target_key_id(&key_id)
            .send()
            .await?;

        tracing::info!(key_id = %key_id, alias = %alias_name, "created credential");

        let signer = KmsSigner::new(self.client.clone(), key_id.clone());
        Ok((key_id, signer))
    }

    /// Get a signer for an existing credential, identified by RP ID and credential ID (key ID).
    pub async fn get_signing_key(
        &self,
        rp_id: &str,
        credential_id: &str,
    ) -> Result<KmsSigner, CredentialStoreError> {
        use aws_sdk_kms::operation::describe_key::DescribeKeyError;

        // Verify the alias exists by trying to describe the key through the alias
        let alias_name = alias_name(rp_id, credential_id);
        let describe_resp = self
            .client
            .describe_key()
            .key_id(&alias_name)
            .send()
            .await
            .map_err(|e| {
                if e.as_service_error()
                    .is_some_and(|se| matches!(se, DescribeKeyError::NotFoundException(_)))
                {
                    CredentialStoreError::NotFound(format!("alias {alias_name}"))
                } else {
                    CredentialStoreError::Kms(Box::new(e))
                }
            })?;

        let key_id = describe_resp
            .key_metadata()
            .map(|m| m.key_id().to_string())
            .ok_or_else(|| {
                CredentialStoreError::Internal(
                    "missing key metadata in DescribeKey response".into(),
                )
            })?;

        Ok(KmsSigner::new(self.client.clone(), key_id))
    }

    /// Discover all credentials for a given RP ID.
    ///
    /// Lists aliases with the prefix `alias/passkms/{rpIdHash}/` and fetches
    /// metadata from key tags for each match.
    pub async fn discover_credentials(
        &self,
        rp_id: &str,
    ) -> Result<Vec<CredentialMetadata>, CredentialStoreError> {
        let prefix = alias_prefix(rp_id);
        self.list_credentials_by_prefix(&prefix).await
    }

    /// Get the COSE-encoded public key for a credential.
    pub async fn get_public_key(
        &self,
        key_id: &str,
    ) -> Result<coset::CoseKey, CredentialStoreError> {
        let resp = self.client.get_public_key().key_id(key_id).send().await?;

        let der_bytes = resp
            .public_key()
            .ok_or_else(|| {
                CredentialStoreError::Internal("missing public key in GetPublicKey response".into())
            })?
            .as_ref();

        cose::spki_der_to_cose_key(der_bytes).map_err(CredentialStoreError::from)
    }

    /// Delete a credential (schedule KMS key for deletion and remove alias).
    pub async fn delete_credential(
        &self,
        rp_id: &str,
        credential_id: &str,
    ) -> Result<(), CredentialStoreError> {
        let alias = alias_name(rp_id, credential_id);

        // Delete the alias first
        self.client.delete_alias().alias_name(&alias).send().await?;

        // Schedule the key for deletion (minimum 7 days)
        self.client
            .schedule_key_deletion()
            .key_id(credential_id)
            .pending_window_in_days(7)
            .send()
            .await?;

        tracing::info!(key_id = %credential_id, "deleted credential");
        Ok(())
    }

    /// List all passkms credentials across all RPs.
    ///
    /// Enumerates all aliases with the `alias/passkms/` prefix and fetches
    /// metadata for each. Used for syncing credentials with the OS.
    pub async fn list_all_credentials(
        &self,
    ) -> Result<Vec<CredentialMetadata>, CredentialStoreError> {
        self.list_credentials_by_prefix(ALIAS_BASE_PREFIX).await
    }

    /// List credentials matching a given alias prefix.
    async fn list_credentials_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<CredentialMetadata>, CredentialStoreError> {
        let mut credentials = Vec::new();

        let mut paginator = self.client.list_aliases().into_paginator().send();

        while let Some(page) = paginator.next().await {
            let page = page?;
            for alias in page.aliases() {
                let name = alias.alias_name().unwrap_or_default();
                if !name.starts_with(prefix) {
                    continue;
                }

                let Some(target_key_id) = alias.target_key_id() else {
                    continue;
                };

                match self.get_credential_metadata(target_key_id).await {
                    Ok(metadata) => credentials.push(metadata),
                    Err(e) => {
                        tracing::warn!(
                            key_id = %target_key_id,
                            error = %e,
                            "skipping credential with unreadable metadata"
                        );
                    }
                }
            }
        }

        Ok(credentials)
    }

    /// Fetch credential metadata from KMS key tags.
    async fn get_credential_metadata(
        &self,
        key_id: &str,
    ) -> Result<CredentialMetadata, CredentialStoreError> {
        let resp = self
            .client
            .list_resource_tags()
            .key_id(key_id)
            .send()
            .await?;

        let mut metadata = CredentialMetadata {
            key_id: key_id.to_string(),
            user_handle: None,
            display_name: None,
            user_name: None,
            rp_id: None,
        };

        let mut is_managed = false;

        for tag in resp.tags() {
            let key = tag.tag_key();
            if !key.starts_with(TAG_PREFIX) {
                continue;
            }
            let value = tag.tag_value();
            match key {
                k if k == TAG_MANAGED => {
                    is_managed = true;
                }
                k if k == TAG_USER_HANDLE => {
                    use data_encoding::BASE64URL_NOPAD;
                    match BASE64URL_NOPAD.decode(value.as_bytes()) {
                        Ok(decoded) => metadata.user_handle = Some(decoded),
                        Err(e) => {
                            tracing::warn!(
                                key_id = %key_id,
                                error = %e,
                                "failed to decode user_handle base64 tag"
                            );
                        }
                    }
                }
                k if k == TAG_DISPLAY_NAME => {
                    metadata.display_name = Some(value.to_string());
                }
                k if k == TAG_USER_NAME => {
                    metadata.user_name = Some(value.to_string());
                }
                k if k == TAG_RP_ID => {
                    metadata.rp_id = Some(value.to_string());
                }
                _ => {}
            }
        }

        if !is_managed {
            return Err(CredentialStoreError::NotFound(format!(
                "key {key_id} is not a passkms-managed credential"
            )));
        }

        Ok(metadata)
    }
}

/// Compute the alias name for a credential.
fn alias_name(rp_id: &str, key_id: &str) -> String {
    let rp_id_hash = hex::encode(Sha256::digest(rp_id.as_bytes()));
    format!("{ALIAS_BASE_PREFIX}{rp_id_hash}/{key_id}")
}

/// Compute the alias prefix for an RP ID (for discovery).
fn alias_prefix(rp_id: &str) -> String {
    let rp_id_hash = hex::encode(Sha256::digest(rp_id.as_bytes()));
    format!("{ALIAS_BASE_PREFIX}{rp_id_hash}/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_name_format() {
        let result = alias_name("example.com", "test-key-id");
        assert!(result.starts_with(ALIAS_BASE_PREFIX));
        assert!(result.ends_with("/test-key-id"));
        // SHA-256 hex is 64 chars, plus prefix and key_id
        let hash_part = result
            .strip_prefix(ALIAS_BASE_PREFIX)
            .unwrap()
            .strip_suffix("/test-key-id")
            .unwrap();
        assert_eq!(hash_part.len(), 64);
    }

    #[test]
    fn alias_prefix_format() {
        let prefix = alias_prefix("example.com");
        assert!(prefix.starts_with(ALIAS_BASE_PREFIX));
        assert!(prefix.ends_with('/'));
    }

    #[test]
    fn alias_name_starts_with_prefix() {
        let name = alias_name("example.com", "some-key");
        let prefix = alias_prefix("example.com");
        assert!(name.starts_with(&prefix));
    }

    #[test]
    fn rp_id_hash_is_deterministic() {
        let a = alias_name("example.com", "key1");
        let b = alias_name("example.com", "key1");
        assert_eq!(a, b);

        let different = alias_name("other.com", "key1");
        assert_ne!(a, different);
    }
}
