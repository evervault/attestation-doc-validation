//! Module for categorizing errors returned during attestation
use thiserror::Error;

use crate::nsm::error::NsmError as InnerNsm;

/// Generic Result type for the top level functions of the library
pub type AttestResult<T> = Result<T, AttestError>;
/// Generic Result type for the attestation doc module
pub type AttestationResult<T> = Result<T, AttestationError>;
/// Generic Result type for the cert module
pub type CertResult<T> = Result<T, CertError>;

/// Top level wrapper to show which step in the attesation process failed.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum AttestError
where
    Self: Send + Sync,
{
    #[error("An error occurred while attesting the connection received: {0}")]
    AttestationError(#[from] AttestationError),
    #[error("An error occurred while validating the TLS Certificate received: {0}")]
    CertError(#[from] CertError),
    #[error("An error occurred interfacing with the Nitro Security Module: {0}")]
    NsmError(#[from] InnerNsm),
    #[error("An error occured decoding the public key from the attestation doc's userdata")]
    DecodeError(#[from] base64::DecodeError),
    #[error("An error occured parsing the expiry date from the attestation doc's userdata")]
    DateParseError(#[from] chrono::ParseError),
}

/// Wrapping type to record the specific error that occurred while validating the attestation document.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum AttestationError
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
    #[error("The module id was missing from the attestation doc")]
    MissingModuleId,
    #[error("The digest in the attestation was not SHA384")]
    DigestAlgorithmInvalid,
    #[error("The PCRs in the attestation doc were invalid")]
    InvalidPCRs,
    #[error("The CA bundle length in the attestation doc was invalid")]
    InvalidCABundle,
    #[error("The public key length in the attestation doc was invalid")]
    InvalidPublicKey,
    #[error("The nonce length in the attestation doc was invalid")]
    InvalidNonce,
    #[error("The user data length in the attestation doc was invalid")]
    InvalidUserData,
    #[error("The supplied attestation doc has expired")]
    ExpiredDocument,
}

/// Wrapping type to record the specific error that occurred while validating the TLS Cert.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum CertError
where
    Self: Send + Sync,
{
    // Webpki errors don't implement stderr, so must be serialized before wrapping in custom err.
    #[error("Failed to validate the trust chain for the provided cert — {0}")]
    InvalidTrustChain(String),
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
    #[error("Failed to parse cert from pem encoding")]
    PemError(#[from] x509_parser::error::PEMError),
    #[error("Failed to parse x509 cert from pem encoding")]
    X509Error,
    #[error("No cert given")]
    NoCertGiven,
}

impl std::convert::From<webpki::Error> for CertError {
    fn from(value: webpki::Error) -> Self {
        Self::InvalidTrustChain(value.to_string())
    }
}
