use thiserror::Error;

pub type NsmResult<T> = std::result::Result<T, NsmError>;

/// Wrapping type to record the specific error that occurred while processing the encoded attestation doc.
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum NsmError
where
    Self: Send + Sync,
{
    #[error("Failed to obtain sufficient entropy")]
    EntropyError(String),
    #[error("Failed to compute hash")]
    HashingError(String),
    #[error("Unimplemented code path hit.")]
    UnimplementedError,
    #[error("Unsupported: {0}")]
    UnsupportedError(String),
    #[error("An error occurred while decoding the attestation from CBOR — {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("Failed to verify signature")]
    UnverifiedSignature,
    #[error("Failed to perform signature")]
    SignatureError(String),
    #[error("Specification violated - {0}")]
    SpecificationError(String),
    #[error("Tag was missing or invalid: {0:?}")]
    TagError(Option<u64>),
    #[error("Failed to perform an encryption operation")]
    EncryptionError(String),
    #[error("Failed to deserialize value from der")]
    DerDecodeError,
}

// Impl to support casting errors from AWS types to ours
use aws_nitro_enclaves_cose::error::CoseError;
impl std::convert::From<CoseError> for NsmError {
    /// Converts a `CoseError` into an `NsmError`.
    ///
    /// # Arguments
    ///
    /// * `value` - A `CoseError` that needs to be converted into an `NsmError`.
    ///
    /// # Returns
    ///
    /// An `NsmError` that corresponds to the input `CoseError`.
    ///
    /// # Example
    ///
    /// ```
    /// use my_crate::{CoseError, NsmError, from};
    ///
    /// let cose_err = CoseError::EntropyError("Failed to generate entropy".to_string());
    /// let nsm_err = from(cose_err);
    /// assert_eq!(nsm_err, NsmError::EntropyError("Failed to generate entropy".to_string()));
    /// ```
    fn from(value: CoseError) -> NsmError {
        match value {
            CoseError::EntropyError(inner) => NsmError::EntropyError(inner.to_string()),
            CoseError::HashingError(inner) => NsmError::HashingError(inner.to_string()),
            CoseError::UnimplementedError => NsmError::UnimplementedError,
            CoseError::UnsupportedError(inner) => NsmError::UnsupportedError(inner),
            CoseError::UnverifiedSignature => NsmError::UnverifiedSignature,
            CoseError::SpecificationError(inner) => NsmError::SpecificationError(inner),
            CoseError::SerializationError(inner) => NsmError::Cbor(inner),
            CoseError::TagError(inner) => NsmError::TagError(inner),
            CoseError::EncryptionError(inner) => NsmError::EncryptionError(inner.to_string()),
            CoseError::SignatureError(inner) => NsmError::SignatureError(inner.to_string()),
        }
    }
}
