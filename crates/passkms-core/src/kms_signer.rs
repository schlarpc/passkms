//! AWS KMS-backed ECDSA signer.
//!
//! Implements the `AsyncSigner` trait from the RustCrypto ecosystem,
//! delegating all signing to KMS. Private key material never leaves KMS.

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use aws_sdk_kms::Client;
use ecdsa::Signature;
use p256::NistP256;
use sha2::{Digest, Sha256};

/// A signer that delegates ECDSA P-256 signing to AWS KMS.
///
/// Private key material never leaves KMS -- all signing is performed
/// remotely via the KMS Sign API with `ECDSA_SHA_256`.
#[derive(Clone, Debug)]
pub struct KmsSigner {
    client: Client,
    key_id: String,
}

impl KmsSigner {
    /// Create a new KMS signer for the given key.
    pub fn new(client: Client, key_id: impl Into<String>) -> Self {
        Self {
            client,
            key_id: key_id.into(),
        }
    }

    /// Returns the KMS key ID this signer is bound to.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns a reference to the underlying KMS client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Sign a raw message by first computing SHA-256 and then calling KMS Sign.
    ///
    /// The KMS Sign API is called with `MessageType::Digest` and the raw 32-byte
    /// SHA-256 hash (not hex-encoded). KMS returns a DER-encoded ECDSA signature
    /// which is parsed into the RustCrypto `Signature` type.
    pub async fn sign_bytes(&self, msg: &[u8]) -> Result<Signature<NistP256>, signature::Error> {
        let digest: [u8; 32] = Sha256::digest(msg).into();
        self.sign_prehashed(&digest).await
    }

    /// Sign a prehashed 32-byte SHA-256 digest by calling KMS Sign directly.
    ///
    /// The digest must be a raw 32-byte SHA-256 hash, NOT hex-encoded.
    /// This is a common gotcha with the KMS Sign API.
    pub async fn sign_prehashed(
        &self,
        digest: &[u8; 32],
    ) -> Result<Signature<NistP256>, signature::Error> {
        let resp = self
            .client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(MessageType::Digest)
            .message(Blob::new(digest))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "KMS Sign failed");
                signature::Error::new()
            })?;

        let sig_der = resp
            .signature()
            .ok_or_else(|| {
                tracing::error!("KMS Sign response missing signature field");
                signature::Error::new()
            })?
            .as_ref();

        Signature::<NistP256>::from_der(sig_der).map_err(|e| {
            tracing::error!(error = %e, "failed to parse DER signature from KMS");
            signature::Error::new()
        })
    }
}

impl async_signature::AsyncSigner<Signature<NistP256>> for KmsSigner {
    async fn sign_async(&self, msg: &[u8]) -> Result<Signature<NistP256>, signature::Error> {
        self.sign_bytes(msg).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kms_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KmsSigner>();
    }
}
