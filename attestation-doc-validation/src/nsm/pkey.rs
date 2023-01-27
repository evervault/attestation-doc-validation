
use aws_nitro_enclaves_cose::crypto::{MessageDigest, SignatureAlgorithm, SigningPublicKey};
use aws_nitro_enclaves_cose::error::CoseError;
// use x509_parser::public_key::{PublicKey as X509PublicKey, ECPoint};
use x509_parser::x509::SubjectPublicKeyInfo;
use der::Decode;
use ring::signature::{UnparsedPublicKey};
use super::der::{EcParameters, SupportedEcCurve};

// fn unwrap_ec_key<'a>(spki: &'a X509PublicKey) -> &'a ECPoint<'a> {
//   match spki {
//     X509PublicKey::EC(ec_point) => ec_point,
//     _ => unimplemented!()
//   }
// }

pub struct PublicKey<'a> {
  inner: SubjectPublicKeyInfo<'a>
}

impl<'a> std::convert::From<SubjectPublicKeyInfo<'a>> for PublicKey<'a> {
  fn from(value: SubjectPublicKeyInfo<'a>) -> Self {
      Self {
        inner: value
      }
  }
}

impl<'a> SigningPublicKey for PublicKey<'a> {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
      let algorithm_oid = self.inner.algorithm.oid().to_string();
      let params = match algorithm_oid.as_str() {
        "1.2.840.10045.4.3.2" => (SignatureAlgorithm::ES256, MessageDigest::Sha256),
        "1.2.840.10045.4.3.3" => (SignatureAlgorithm::ES384, MessageDigest::Sha384),
        "1.2.840.10045.4.3.4" => (SignatureAlgorithm::ES512, MessageDigest::Sha512),
        _ => unimplemented!()
      };
      Ok(params)
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
      let algorithm_params = self.inner.algorithm.parameters.as_ref().unwrap().as_bytes();
      let params = EcParameters::from_der(algorithm_params).unwrap();
      let matched_curve = SupportedEcCurve::try_from(&params.curve).unwrap();

      let ecdsa_sig_alg = match matched_curve {
        SupportedEcCurve::Secp256r1 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SupportedEcCurve::Secp384r1 => &ring::signature::ECDSA_P256_SHA384_ASN1,
        _ => unimplemented!(),
      };
      let pub_key = UnparsedPublicKey::new(ecdsa_sig_alg, self.inner.raw);
      pub_key.verify(digest, signature).map(|_| false).or_else(|_| Ok(false))
    }
}