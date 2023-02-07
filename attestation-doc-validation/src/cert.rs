//! Module for parsing and validating X509 certs
use super::{
    error::{CertError, CertResult},
    true_or_invalid,
};
use openssl::{
    pkey::{PKey, Public},
    stack::Stack,
    x509::{store, X509StoreContext, X509},
};
use serde_bytes::ByteBuf;

static NITRO_ROOT_CA_BYTES: &[u8] = include_bytes!("nitro.pem");

/// The self signed certificate provided by the enclave embeds the
/// cose-sign1 structure as a subject alternative name (SAN) in the form `<hex_encoded_cose_sign_1>.<cage_name>.<app_uuid>.cages.evervault.com`.
/// This function extracts the longest SAN, takes the string before the first dot, and decode the hex.
///
/// # Errors
///
/// Returns a `CertError::NoSubjectAltNames` when the cert has no Subject Alt Names set.
/// Returns a `CertError::ParseError` if there was no Subject Alt Name which could be parsed.
/// Returns a `CertError::HexError` if the suspected attestation document failed to decode from hex.
pub fn extract_signed_cose_sign_1_from_certificate(certificate: &X509) -> CertResult<Vec<u8>> {
    let subject_alt_names = certificate
        .subject_alt_names()
        .ok_or(CertError::NoSubjectAltNames)?;
    let parsed_attestation_bytes = subject_alt_names
        .iter()
        .filter_map(openssl::x509::GeneralNameRef::dnsname)
        .filter_map(|x| x.split('.').next())
        .reduce(|a, b| if a.len() > b.len() { a } else { b })
        .ok_or(CertError::ParseError)?;
    Ok(hex::decode(parsed_attestation_bytes)?)
}

pub(super) fn get_cert_public_key(cert: &X509) -> CertResult<PKey<Public>> {
    Ok(cert.public_key()?)
}

pub(super) fn export_public_key_to_der(cert: &X509) -> CertResult<Vec<u8>> {
    let pub_key = get_cert_public_key(cert)?;
    Ok(pub_key.public_key_to_der()?)
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

pub(super) fn parse_pem_cert(cert: &[u8]) -> CertResult<X509> {
    Ok(X509::from_pem(cert)?)
}

pub(super) fn parse_der_cert(cert: &[u8]) -> CertResult<X509> {
    Ok(X509::from_der(cert)?)
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
