//! Module for parsing and validating X509 certs
use super::{
    error::{CertError, CertResult},
    true_or_invalid,
};
use openssl::{
    stack::Stack,
    x509::{store, X509StoreContext, X509},
};
use serde_bytes::ByteBuf;
use std::str::FromStr;
use x509_parser::{
    certificate::X509Certificate,
    extensions::{ParsedExtension, SubjectAlternativeName},
    pem::Pem,
};

static NITRO_ROOT_CA_BYTES: &[u8] = include_bytes!("nitro.pem");

const SUBJECT_ALT_NAMES_OID: &'static str = "2.5.29.17";

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

    let parsed_attestation_bytes = general_names
        .iter()
        .filter_map(|x| x.to_string().split('.').next())
        .reduce(|a, b| if a.len() > b.len() { a } else { b })
        .ok_or(CertError::ParseError)?;
    Ok(hex::decode(parsed_attestation_bytes)?)
}

pub(super) fn export_public_key_to_der<'a>(cert: &'a X509Certificate) -> CertResult<&'a [u8]> {
    Ok(cert.public_key().raw)
}

/// Given an end entity certificate and a stack of CAs, attempt to validate that the Cert can be trusted.
/// Note that this function will validate the root of trust based solely on the CAs provided.
///
/// # Errors
///
/// Returns a `CertError::UntrustedCert` when the trust chain fails to validate
/// Returns a `CertError::Openssl` if an error occurred while preparing the context
pub fn validate_cert_trust_chain(target: &X509, certificate_stack: &Stack<X509>) -> CertResult<()> {
    let mut certificate_store_builder = store::X509StoreBuilder::new()?;
    let nitro_root_ca = X509::from_pem(NITRO_ROOT_CA_BYTES)?;
    certificate_store_builder.add_cert(nitro_root_ca)?;
    let certificate_store = certificate_store_builder.build();
    let mut store_context = X509StoreContext::new()?;
    true_or_invalid(
        store_context.init(
            certificate_store.as_ref(),
            target.as_ref(),
            certificate_stack,
            openssl::x509::X509StoreContextRef::verify_cert,
        )?,
        CertError::UntrustedCert,
    )
}

pub(super) fn parse_pem_cert<'a>(cert: &'a [u8]) -> CertResult<X509Certificate<'a>> {
    for pem in Pem::iter_from_buffer(cert) {
        let cert = pem?;
        let parsed_cert = cert.parse_x509().map_err(|_| CertError::X509Error)?;
        return Ok(parsed_cert);
    }
    Err(CertError::NoCertGiven)
}

pub(super) fn parse_der_cert<'a>(cert: &'a [u8]) -> CertResult<X509Certificate<'a>> {
    let (_, parsed_cert) =
        x509_parser::parse_x509_certificate(cert).map_err(|_| CertError::DecodeError)?;
    Ok(parsed_cert)
}

/// Takes a byte buffer and attempts to create a stack of CAs from it.
///
/// # Errors
///
/// Returns a `CertError::Openssl` if an error occurred while preparing the stack
pub fn parse_cert_stack_from_cabundle(cabundle: &[ByteBuf]) -> CertResult<Stack<X509>> {
    let received_certificates: Vec<X509> =
        cabundle.iter().flat_map(|ca| X509::from_der(ca)).collect();
    let mut stack = Stack::new()?;
    for certificate in received_certificates {
        stack.push(certificate)?;
    }
    Ok(stack)
}
