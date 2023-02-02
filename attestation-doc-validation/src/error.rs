//! Module for categorizing errors returned during attestation
use thiserror::Error;

/// Generic Result type for the top level functions of the library
pub type AttestResult<T> = Result<T, AttestError>;
/// Generic Result type for the attestation doc module
pub type AttestationDocResult<T> = Result<T, AttestationDocError>;
/// Generic Result type for the cert module
pub type CertResult<T> = Result<T, CertError>;

/// Top level wrapper to show which step in the attesation process failed.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum AttestError
where
    Self: Send + Sync,
{
    #[error("An error occurred while validating the attestation document received: {0}")]
    AttestationDocError(#[from] AttestationDocError),
    #[error("An error occurred while validating the TLS Certificate received: {0}")]
    CertError(#[from] CertError),
}

/// Wrapping type to record the specific error that occurred while validating the attestation document.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum AttestationDocError
where
    Self: Send + Sync,
{
    #[error("COSE error: `{0}`")]
    InvalidCose(String),
    #[error(transparent)]
    InvalidCbor(#[from] serde_cbor::error::Error),
    #[error("A part of the attestation doc structure was deemed invalid")]
    DocStructureInvalid,
    #[error("The COSE signature does not match the public key provided in the attestation doc")]
    InvalidCoseSignature,
    #[error(
        "The PCRs found were different to the expected values.\n\nExpected:\n{0}\n\nReceived:\n{1}"
    )]
    UnexpectedPCRs(String, String),
    #[error("PCR{0} was missing in the attestation doc")]
    MissingPCR(usize),
    #[error("User data was not set in the attestation doc")]
    MissingUserData,
    #[error("User data in attestation doc did not contain the certificate public key")]
    UserDataMismatch,
    #[error("Nonce in the attestation doc did not match the nonce provided,\n\nExpected: {expected}\nReceived: {received:?}")]
    NonceMismatch {
        expected: String,
        received: Option<String>,
    },
}

/// Wrapping type to record the specific error that occurred while validating the TLS Cert.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum CertError
where
    Self: Send + Sync,
{
    #[error(transparent)]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("The certificate in the attestation doc was detected as not having the NSM as root")]
    UntrustedCert,
    #[error("The received certificate had no Subject Alt Name extension")]
    NoSubjectAltNames,
    #[error("Attempts to parse certificate from PEM and DER encoding failed")]
    DecodeError,
    #[error("Unable to parse attestation doc bytes from Subject Alt Name extension")]
    ParseError,
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    #[error("Failed to compute seconds since the unix epoch")]
    TimeError,
}
