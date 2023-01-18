use super::error::{CertError, CertResult};
use std::str::FromStr;
use std::time::SystemTime;
pub use x509_parser::certificate::X509Certificate;
use x509_parser::x509::SubjectPublicKeyInfo;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

static NITRO_ROOT_CA_BYTES: &[u8] = include_bytes!("nitro.pem");

pub(super) struct NitroSigningPublicKey<'a> {
  public_key: &'a SubjectPublicKeyInfo<'a>
}

impl<'a> aws_nitro_enclaves_cose::crypto::SigningPublicKey for NitroSigningPublicKey<'a> {
    fn get_parameters(&self) -> Result<(aws_nitro_enclaves_cose::crypto::SignatureAlgorithm, aws_nitro_enclaves_cose::crypto::MessageDigest), aws_nitro_enclaves_cose::error::CoseError> {
      let sig_alg = self.public_key.algorithm.oid().to_string();
      Ok((
        aws_nitro_enclaves_cose::crypto::SignatureAlgorithm::from_str(&sig_alg).unwrap(),
        aws_nitro_enclaves_cose::crypto::MessageDigest::Sha384
      ))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, aws_nitro_enclaves_cose::error::CoseError> {
        todo!()
    }
}

/// The self signed certificate provided by the enclave embeds the
/// cose-sign1 structure as a subject alternative name (SAN) in the form
///
/// `<hex_encoded_cose_sign_1>..*.cages.evervault.com`
///
/// In order to extract it, we simply pick the longest SAN, take the string before the first dot, and decode the hex.
pub fn extract_signed_cose_sign_1_from_certificate(
    certificate: &X509Certificate,
) -> CertResult<Vec<u8>> {
    let subject_alt_names = certificate
        .subject_alternative_name()
        .transpose()
        .ok_or(CertError::NoSubjectAltNames)?
        .map_err(|_| CertError::MalformedCert)?;
    let parsed_attestation_bytes = subject_alt_names
        .value
        .general_names
        .iter()
        .filter_map(|name| name.to_string().split('.').next())
        .reduce(|a, b| if a.len() > b.len() { a } else { b })
        .ok_or(CertError::ParseError)?;
    Ok(hex::decode(parsed_attestation_bytes)?)
}

pub(super) fn get_cert_public_key<'a>(cert: &'a X509Certificate) -> &'a SubjectPublicKeyInfo<'a> {
    cert.public_key()
}

pub(super) fn export_public_key_to_der(cert: &X509Certificate) -> Vec<u8> {
    let pub_key = get_cert_public_key(cert);
    pub_key.raw.to_vec()
}

pub(super) fn validate_cert_trust_chain(
    target: &[u8],
    intermediate_certs: &[&[u8]],
    now: SystemTime,
) -> CertResult<()> {
    let end_entity_cert =
        webpki::EndEntityCert::try_from(target).map_err(|_e| CertError::DecodeError)?;
    let seconds_since_epoch = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CertError::TimeError)?;
    let webpki_time = webpki::Time::from_seconds_since_unix_epoch(seconds_since_epoch.as_secs());

    let nitro_cert = parse_x509_pem(NITRO_ROOT_CA_BYTES)
        .map(|(_, cert)| cert.contents)
        .unwrap();
    let trust_anchors = [webpki::TrustAnchor::try_from_cert_der(nitro_cert.as_ref())
        .map_err(|_| CertError::TrustAnchorError)?];
    let server_trust_anchor = webpki::TlsServerTrustAnchors(&trust_anchors);

    let all_algs = [
        &webpki::ECDSA_P256_SHA256,
        &webpki::ECDSA_P256_SHA384,
        &webpki::ECDSA_P384_SHA256,
        &webpki::ECDSA_P384_SHA384,
        &webpki::ED25519,
    ];

    end_entity_cert
        .verify_is_valid_tls_server_cert(
            &all_algs,
            &server_trust_anchor,
            intermediate_certs,
            webpki_time,
        )
        .map_err(|_e| CertError::UntrustedCert)?;

    Ok(())
}

pub(super) fn parse_pem_cert(cert: &[u8]) -> CertResult<X509Certificate> {
    parse_x509_pem(cert)
        .map(|(_, cert)| parse_der_cert(&cert.contents))
        .map_err(|_| CertError::DecodeError)?
}

pub(super) fn parse_der_cert(cert: &[u8]) -> CertResult<X509Certificate> {
    parse_x509_certificate(cert)
        .map(|(_, cert)| cert)
        .map_err(|_| CertError::DecodeError)
}
