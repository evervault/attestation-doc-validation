use super::der::{EcParameters, SubjectPublicKeyInfo as Spki};
pub(crate) use aws_nitro_enclaves_cose::crypto::SigningPublicKey;
use aws_nitro_enclaves_cose::crypto::{MessageDigest, SignatureAlgorithm};
use aws_nitro_enclaves_cose::error::CoseError;
use der::Decode;
use p384::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p384::{AffinePoint, EncodedPoint};
use ring::signature::UnparsedPublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

pub struct PublicKey<'a> {
    inner: &'a SubjectPublicKeyInfo<'a>,
}

impl<'a> std::convert::From<&'a SubjectPublicKeyInfo<'a>> for PublicKey<'a> {
    fn from(value: &'a SubjectPublicKeyInfo<'a>) -> Self {
        Self { inner: value }
    }
}

impl<'a> SigningPublicKey for PublicKey<'a> {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let spki = Spki::from_der(self.inner.raw).unwrap();
        let EcParameters::NamedCurve(curve_name) = spki.algorithm.parameters else { panic!("failed to parse algorithm") };
        let curve_string = curve_name.to_string();
        let params = match curve_string.as_str() {
            "1.2.840.10045.3.1.7" => (SignatureAlgorithm::ES256, MessageDigest::Sha256),
            "1.3.132.0.34" => (SignatureAlgorithm::ES384, MessageDigest::Sha384),
            "1.3.132.0.35" => (SignatureAlgorithm::ES512, MessageDigest::Sha512),
            oid => {
                println!("Unimplemented: {oid}");
                unimplemented!()
            }
        };
        Ok(params)
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        let (sig_alg, _) = self.get_parameters()?;
        let ecdsa_sig_alg = match sig_alg {
            SignatureAlgorithm::ES256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
            SignatureAlgorithm::ES384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
            _ => unimplemented!(),
        };

        let pub_key = &self.inner.subject_public_key;
        let hex_encoded = hex::encode(&pub_key.data);
        println!("Key: {hex_encoded}");
        let encoded_point: EncodedPoint = p384::EncodedPoint::from_bytes(pub_key).unwrap();
        let affine_point: AffinePoint = AffinePoint::from_encoded_point(&encoded_point).unwrap();
        let uncompressed_point = affine_point.to_encoded_point(false);
        println!(
            "Uncompressed Point: {}",
            hex::encode(uncompressed_point.as_bytes())
        );
        let pub_key = UnparsedPublicKey::new(ecdsa_sig_alg, uncompressed_point.as_bytes());
        pub_key
            .verify(digest, signature)
            .map(|_| true)
            .or_else(|err| {
                eprintln!("{err:?}");
                Ok(false)
            })
    }
}
