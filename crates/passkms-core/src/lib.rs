pub mod cose;
pub mod credential_store;
pub mod kms_signer;

mod authenticator;

pub use authenticator::{
    Authenticator, AuthenticatorError, GetAssertionRequest, GetAssertionResponse,
    MakeCredentialRequest, MakeCredentialResponse, PASSKMS_AAGUID,
};
pub use credential_store::{CredentialMetadata, CredentialStore, CredentialStoreError};
pub use kms_signer::KmsSigner;
