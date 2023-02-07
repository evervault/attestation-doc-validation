use thiserror::Error;

pub type NsmResult<T> = std::result::Result<T, NsmError>;

/// Wrapping type to record the specific error that occurred while processing the encoded attestation doc.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum NsmError {
    #[error("Failed to obtain sufficient entropy")]
    EntropyError(Box<dyn std::error::Error>),
    #[error("Failed to compute hash")]
    HashingError(Box<dyn std::error::Error>),
    #[error("Unimplemented code path hit.")]
    UnimplementedError,
    #[error("Unsupported: {0}")]
    UnsupportedError(String),
    #[error("An error occurred while decoding the attestation from CBOR — {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("Failed to verify signature")]
    UnverifiedSignature,
    #[error("Failed to perform signature")]
    SignatureError(Box<dyn std::error::Error>),
    #[error("Specification violated - {0}")]
    SpecificationError(String),
    #[error("Tag was missing or invalid: {0:?}")]
    TagError(Option<u64>),
    #[error("Failed to perform an encryption operation")]
    EncryptionError(Box<dyn std::error::Error>),
}
