use super::der::{EcParameters, SubjectPublicKeyInfo as Spki};
pub(crate) use aws_nitro_enclaves_cose::crypto::SigningPublicKey;
use aws_nitro_enclaves_cose::crypto::{MessageDigest, SignatureAlgorithm};
use aws_nitro_enclaves_cose::error::CoseError;
use core::str::FromStr;
use der::Decode;
use ecdsa::signature::hazmat::PrehashVerifier;
use x509_parser::oid_registry::asn1_rs::BitString;
use x509_parser::x509::SubjectPublicKeyInfo;

pub struct PublicKey<'a> {
    spki: Spki<'a>,
    public_key: &'a BitString<'a>, // inner: &'a SubjectPublicKeyInfo<'a>,
}

impl<'a> std::convert::TryFrom<&'a SubjectPublicKeyInfo<'a>> for PublicKey<'a> {
    type Error = super::error::NsmError;

    /// Converts a DER-encoded SubjectPublicKeyInfo value into a 'PublicKey' instance.
    
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to the DER-encoded SubjectPublicKeyInfo value.
    ///
    /// # Returns
    ///
    /// Returns a result containing a 'PublicKey' instance or an error of 'Self::Error' type.
    /// A 'Self::Error::DerDecodeError' is returned if the value cannot be decoded from DER.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::PublicKey;
    /// use ring::error::Unspecified;
    /// use ring::io::DerParser;
    /// use ring::io::parse_der;
    /// use ring::io::positive;
    /// use ring::io::ASN1;
    /// use ring::io::SPKI;
    ///
    /// #[cfg(test)]
    /// mod tests {
    ///     use super::*;
    ///
    ///     #[test]
    ///     fn test_try_from() {
    ///         let der_encoded_spki = vec![48, 129, 143, 48, 13, 6, 9, 42, 134, 72, 206, 61, 4, 1,
    ///             6, 5, 43, 129, 4, 0, 33, 3, 129, 129, 0, 200, 17, 117, 174, 128, 162, 218,
    ///             62, 23, 107, 162, 234, 231, 30, 113, 252, 230, 73, 96, 80, 159, 177, 47, 91,
    ///             186, 62, 106, 186, 0, 67, 232, 19, 0, 142, 145, 112, 241, 167, 149, 163, 109,
    ///             88, 132, 140, 19, 67, 248, 201, 160, 150, 199, 15, 225, 79, 204, 49, 1, 1];
    ///
    ///         let public_key_info = parse_der(DerParser::new(&der_encoded_spki)).unwrap();
    ///
    ///         let result = PublicKey::try_from(&public_key_info);
    ///         assert!(result.is_ok());
    ///     }
    /// }
    /// ```
    fn try_from(value: &'a SubjectPublicKeyInfo<'a>) -> Result<Self, Self::Error> {
        let public_key_info = Spki::from_der(value.raw).map_err(|_| Self::Error::DerDecodeError)?;
        Ok(Self {
            spki: public_key_info,
            public_key: &value.subject_public_key,
        })
    }
}

impl<'a> SigningPublicKey for PublicKey<'a> {
    /// Returns a tuple containing the signature algorithm and message digest used for the given EC key. Only named curves are supported, and the algorithm and digest are determined based on the curve name. 
    
    /// 
    ///
    /// # Arguments 
    ///
    /// * `self` - A reference to the given EC key.
    ///
    /// # Errors 
    ///
    /// Returns a `CoseError` indicating that only named curves are supported, or that an unsupported curve was received. 
    ///
    /// # Example 
    ///
    /// ```
    /// use crate::get_parameters;
    ///
    /// let (alg, dig) = get_parameters(&my_key).unwrap();
    /// ```
    ///
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let EcParameters::NamedCurve(curve_name) = self.spki.algorithm.parameters else {
          return Err(CoseError::UnsupportedError("Only named curves are supported".to_string()));
        };
        let curve_string = curve_name.to_string();
        let params = match curve_string.as_str() {
            "1.2.840.10045.3.1.7" => (SignatureAlgorithm::ES256, MessageDigest::Sha256),
            "1.3.132.0.34" => (SignatureAlgorithm::ES384, MessageDigest::Sha384),
            // OID for SECP521R1 to be used with ES512, [not a typo](https://github.com/awslabs/aws-nitro-enclaves-cose/blob/b95205c186e2093dd699d5f6a93ffc4e185e1994/src/crypto/openssl_pkey.rs#L26)
            "1.3.132.0.35" => (SignatureAlgorithm::ES512, MessageDigest::Sha512),
            oid => {
                return Err(CoseError::UnsupportedError(format!(
                    "Received unsupported curve: {oid}"
                )))
            }
        };
        Ok(params)
    }

    /// Verifies the COSE signature against the provided message digest.
    ///
    /// # Arguments
    ///
    /// * `digest` - A slice of bytes representing the message digest to verify against the signature.
    /// * `signature` - A slice of bytes representing the signature to be verified.
    ///
    /// # Returns
    ///
    /// Returns a `Result` with a boolean value indicating if the signature is valid or not. An error is returned if operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use cose::errors::CoseError;
    /// use cose::sign::{SignatureAlgorithm, CoseSign0};
    ///
    /// let cose_sign = CoseSign0::new();
    /// let digest = vec![1, 2, 3];
    /// let signature = vec![4, 5, 6];
    ///
    /// let verification_result = cose_sign.verify(&digest, &signature);
    ///
    /// assert_eq!(verification_result, Err(CoseError::InvalidState("missing key data".into())));
    /// ```
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        let (sig_alg, _) = self.get_parameters()?;
        let signature_verification_result = match sig_alg {
            SignatureAlgorithm::ES256 => self.verify_p256_signature(digest, signature),
            SignatureAlgorithm::ES384 => self.verify_p384_signature(digest, signature),
            SignatureAlgorithm::ES512 => self.verify_p521_signature(digest, signature),
        };
        signature_verification_result
            .map(|_| true)
            .or_else(|_| Ok(false))
    }
}

// Macro for converting errors from internal dependencies into `CoseError::UnverifiedSignature`
macro_rules! verify {
    ($op:expr) => {
        $op.map_err(|_| CoseError::UnverifiedSignature)
    };
}

// Macro to implement signature verification over the passed curve
macro_rules! impl_signature_verification {
    ($self:ident, $curve:ident, $digest:ident, $signature:ident) => {
        let encoded_point: $curve::EncodedPoint =
            verify!($curve::EncodedPoint::from_bytes($self.public_key()))?;
        let verifying_key: $curve::ecdsa::VerifyingKey = verify!(
            $curve::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)
        )?;
        let hex_string = hex::encode($signature);
        let sig = verify!($curve::ecdsa::Signature::from_str(&hex_string))?;
        return verify!(verifying_key.verify_prehash($digest, &sig));
    };
}

impl<'a> PublicKey<'a> {
    /// Returns a reference to the public key associated with this instance of the struct.
    ///
    /// The public key is stored as a `BitString`. This function returns a reference to that `BitString`, thus ensuring that the key cannot be modified without going through the correct channels.
    fn public_key(&self) -> &BitString {
        self.public_key
    }

    /// Verifies the P256 signature for the given digest and signature data.
    /// 
    /// # Arguments
    /// 
    /// * `self` - A reference to the struct implementing signature verification.
    /// * `digest` - A slice of bytes representing the digest data.
    /// * `signature` - A slice of bytes representing the signature data.
    /// 
    /// # Returns
    ///
    /// `Result<(), CoseError>` - An empty Ok result if the signature is valid.
    ///                         - An Err result containing a CoseError if the signature is invalid.
    fn verify_p256_signature(&self, digest: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        impl_signature_verification!(self, p256, digest, signature);
    }

    /// Verifies the signature of a given digest using the p384 algorithm.
    
    ///
    /// * `digest` - A reference to a byte slice that contains the digest to be verified.
    /// * `signature` - A reference to a byte slice that contains the signature to be verified.
    ///
    /// Returns a `Result` with an empty tuple `()` if the verification is successful. If the verification fails, `CoseError` is returned
    /// with a description of the error.
    fn verify_p384_signature(&self, digest: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        impl_signature_verification!(self, p384, digest, signature);
    }

    #[allow(clippy::unused_self)]
    /// Verifies a P-521 signature using the provided digest and signature bytes.
    
    ///
    /// # Arguments
    ///
    /// * `_digest`: A slice of bytes representing the digest being signed.
    /// * `_signature`: A slice of bytes representing the signature to be verified.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the signature is valid.
    /// * `Err(CoseError)` if the signature is invalid or cannot be verified.
    fn verify_p521_signature(&self, _digest: &[u8], _signature: &[u8]) -> Result<(), CoseError> {
        unimplemented!();
    }
}
