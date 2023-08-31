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

    fn try_from(value: &'a SubjectPublicKeyInfo<'a>) -> Result<Self, Self::Error> {
        let public_key_info = Spki::from_der(value.raw).map_err(|_| Self::Error::DerDecodeError)?;
        Ok(Self {
            spki: public_key_info,
            public_key: &value.subject_public_key,
        })
    }
}

impl<'a> SigningPublicKey for PublicKey<'a> {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let EcParameters::NamedCurve(curve_name) = self.spki.algorithm.parameters else {
            return Err(CoseError::UnsupportedError(
                "Only named curves are supported".to_string(),
            ));
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
    fn public_key(&self) -> &BitString {
        self.public_key
    }

    fn verify_p256_signature(&self, digest: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        impl_signature_verification!(self, p256, digest, signature);
    }

    fn verify_p384_signature(&self, digest: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        impl_signature_verification!(self, p384, digest, signature);
    }

    #[allow(clippy::unused_self)]
    fn verify_p521_signature(&self, _digest: &[u8], _signature: &[u8]) -> Result<(), CoseError> {
        unimplemented!();
    }
}
