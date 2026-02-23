mod authenticator;
mod cose;
mod credential_store;
mod kms_signer;

pub use authenticator::{
    Authenticator, AuthenticatorError, GetAssertionRequest, GetAssertionResponse,
    MakeCredentialRequest, MakeCredentialResponse, PASSKMS_AAGUID,
};
pub use credential_store::{
    CredentialBackend, CredentialId, CredentialMetadata, CredentialStore, CredentialStoreError,
};
pub use kms_signer::KmsSigner;
