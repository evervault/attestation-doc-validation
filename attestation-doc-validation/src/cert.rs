//! Module for parsing and validating X509 certs
use super::{
    error::{CertError, CertResult},
    true_or_invalid,
};
use serde_bytes::ByteBuf;
use std::str::FromStr;
use webpki::{EndEntityCert, TrustAnchor};
use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, ParsedExtension, SubjectAlternativeName},
};

static NITRO_ROOT_CA_BYTES: &[u8] = include_bytes!("nitro.pem");

const SUBJECT_ALT_NAMES_OID: &str = "2.5.29.17";

static SUPPORTED_SIG_ALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/// The self signed certificate provided by the enclave embeds the
/// cose-sign1 structure as a subject alternative name (SAN) in the form `<hex_encoded_cose_sign_1>.<cage_name>.<app_uuid>.cages.evervault.com`.
/// This function extracts the longest SAN, takes the string before the first dot, and decode the hex.
///
/// # Errors
///
/// Returns a `CertError::NoSubjectAltNames` when the cert has no Subject Alt Names set.
/// Returns a `CertError::ParseError` if there was no Subject Alt Name which could be parsed.
/// Returns a `CertError::HexError` if the suspected attestation document failed to decode from hex.
pub fn extract_signed_cose_sign_1_from_certificate(
    certificate: &X509Certificate,
) -> CertResult<Vec<u8>> {
    let general_names = get_subject_alt_names_from_cert(certificate)?;
    let parsed_attestation_bytes = general_names
        .iter()
        .filter_map(|alt_name| {
            let GeneralName::DNSName(dns_name) = alt_name else { return None };
            dns_name.split('.').next().map(String::from)
        })
        .reduce(|a, b| if a.len() > b.len() { a } else { b })
        .ok_or(CertError::ParseError)?;
    Ok(hex::decode(parsed_attestation_bytes)?)
}

pub(super) fn get_subject_alt_names_from_cert<'a>(
    certificate: &X509Certificate<'a>,
) -> CertResult<Vec<GeneralName<'a>>> {
    let subject_alt_names_oid = x509_parser::oid_registry::Oid::from_str(SUBJECT_ALT_NAMES_OID)
        .expect("Infallible: hardcoded oid");
    let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName {
    general_names
  }) = certificate.get_extension_unique(&subject_alt_names_oid)
        .map_err(|_| CertError::NoSubjectAltNames)?
        .ok_or(CertError::NoSubjectAltNames)?
        .parsed_extension() else {
          return Err(CertError::NoSubjectAltNames)
        };

    Ok(general_names.clone())
}

pub(super) fn export_public_key_to_der<'a>(cert: &'a X509Certificate) -> &'a [u8] {
    cert.public_key().raw
}

/// Given an end entity certificate and a stack of CAs, attempt to validate that the Cert can be trusted.
/// Note that this function will validate the root of trust based solely on the CAs provided.
///
/// # Errors
///
/// Returns a `CertError::UntrustedCert` when the trust chain fails to validate
/// Returns a `CertError::Openssl` if an error occurred while preparing the context
pub fn validate_cert_trust_chain(target: &[u8], intermediates: &[&[u8]]) -> CertResult<()> {
    let end_entity_cert = EndEntityCert::try_from(target).map_err(|_| CertError::DecodeError)?;

    let (_, nitro_pem_cert) = x509_parser::pem::parse_x509_pem(NITRO_ROOT_CA_BYTES)
        .map_err(|_| CertError::DecodeError)?;
    let nitro_trust_anchor = [TrustAnchor::try_from_cert_der(&nitro_pem_cert.contents)
        .map_err(|_| CertError::DecodeError)?];
    let server_trust_anchors = webpki::TlsServerTrustAnchors(&nitro_trust_anchor);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time_since_epoch| time_since_epoch.as_secs())
        .map_err(|_| CertError::TimeError)?;
    let time = webpki::Time::from_seconds_since_unix_epoch(now);

    true_or_invalid(
        end_entity_cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &server_trust_anchors,
                intermediates,
                time,
            )
            .is_ok(),
        CertError::UntrustedCert,
    )
}

pub(super) fn parse_der_cert(cert: &[u8]) -> CertResult<X509Certificate<'_>> {
    let (_, parsed_cert) =
        x509_parser::parse_x509_certificate(cert).map_err(|_| CertError::DecodeError)?;
    Ok(parsed_cert)
}

/// Takes a byte buffer and attempts to create a stack of CAs from it.
///
/// # Errors
///
/// Returns a `CertError::Openssl` if an error occurred while preparing the stack
pub fn parse_cert_stack_from_cabundle(cabundle: &[ByteBuf]) -> CertResult<Vec<TrustAnchor>> {
    let trusted_certs: Vec<TrustAnchor> = cabundle
        .iter()
        .flat_map(|ca| TrustAnchor::try_from_cert_der(ca))
        .collect();

    Ok(trusted_certs)
}
