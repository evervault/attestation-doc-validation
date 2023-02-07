pub mod attestation_doc;
pub mod cert;
pub mod error;
mod nsm;

pub use attestation_doc::{validate_expected_nonce, validate_expected_pcrs, PCRProvider};
use error::AttestResult as Result;
use nsm::nsm_api::AttestationDoc;

use nsm::CryptoClient;
use x509_parser::certificate::X509Certificate;

// Helper function to fail early on any variant of error::AttestError
fn true_or_invalid<E: Into<error::AttestError>>(check: bool, err: E) -> std::result::Result<(), E> {
    if check {
        Ok(())
    } else {
        Err(err)
    }
}

/// Attempts to DER decode a slice of bytes to an X509 Certificate
///
/// # Errors
///
/// If DER decoding of the certificate fail
pub fn parse_cert(given_cert: &[u8]) -> Result<X509Certificate<'_>> {
    Ok(cert::parse_der_cert(given_cert)?)
}

/// Attests a connection to a Cage by:
/// - Validating the cert structure
/// - Extracting the attestation doc from the Subject Alt Names
/// - Decoding and validating the attestation doc
/// - Validating the signature on the attestation doc
/// - Validating that the PCRs of the attestation doc are as expected
///
/// # Errors
///
/// Will return an error if:
/// - The cose1 encoded attestation doc fails to parse, or its signature is invalid
/// - The attestation document is not signed by the nitro cert chain
/// - The public key from the certificate is not present in the attestation document's challenge
/// - Any of the certificates are malformed
pub fn validate_attestation_doc_in_cert(
    given_cert: &X509Certificate<'_>,
) -> Result<AttestationDoc> {
    // Extract raw attestation doc from subject alt names
    let cose_signature = cert::extract_signed_cose_sign_1_from_certificate(given_cert)?;

    // Parse attestation doc from cose signature and validate structure
    let (cose_sign_1_decoded, decoded_attestation_doc) =
        attestation_doc::decode_attestation_document(&cose_signature)?;
    attestation_doc::validate_attestation_document_structure(&decoded_attestation_doc)?;

    // Validate that the attestation doc's signature can be tied back to the AWS Nitro CA
    let intermediate_certs: Vec<&[u8]> = decoded_attestation_doc
        .cabundle
        .iter()
        .map(|cert| cert.as_slice())
        .collect();
    cert::validate_cert_trust_chain(&decoded_attestation_doc.certificate, &intermediate_certs)?;

    // Validate Cose signature over attestation doc
    // let attestation_doc_signing_cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;
    // let attestation_doc_pub_key = cert::get_cert_public_key(&attestation_doc_signing_cert)?;

    let cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;
    let pub_key: nsm::PublicKey = cert.public_key().try_into()?;
    // attestation::validate_cose_signature::<aws_nitro_enclaves_cose::crypto::Openssl>(&attestation_doc_pub_key, &cose_sign_1_decoded)?;
    attestation_doc::validate_cose_signature::<CryptoClient>(&pub_key, &cose_sign_1_decoded)?;

    // Validate that the cert public key is embedded in the attestation doc
    let cage_cert_public_key = cert::export_public_key_to_der(given_cert);
    attestation_doc::validate_expected_challenge(&decoded_attestation_doc, cage_cert_public_key)?;

    Ok(decoded_attestation_doc)
}

/// Validates an attestation doc by:
/// - Validating the cert structure
/// - Decoding and validating the attestation doc
/// - Validating the signature on the attestation doc
/// - Validating that the PCRs of the attestation doc are as expected
///
/// # Errors
///
/// Will return an error if:
/// - The cose1 encoded attestation doc fails to parse, or its signature is invalid
/// - The attestation document is not signed by the nitro cert chain
/// - Any of the certificates are malformed
///
pub fn validate_attestation_doc(
    attestation_doc_cose_sign_1_bytes: &[u8],
) -> error::AttestResult<()> {
    // Parse attestation doc from cose signature and validate structure
    let (cose_sign_1_decoded, decoded_attestation_doc) =
        attestation_doc::decode_attestation_document(attestation_doc_cose_sign_1_bytes)?;
    attestation_doc::validate_attestation_document_structure(&decoded_attestation_doc)?;

    // Validate that the attestation doc's signature can be tied back to the AWS Nitro CA
    let attestation_doc_signing_cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;
    let received_certificates =
        cert::parse_cert_stack_from_cabundle(decoded_attestation_doc.cabundle.as_ref())?;

    cert::validate_cert_trust_chain(&attestation_doc_signing_cert, &received_certificates)?;

    // Validate Cose signature over attestation doc
    let attestation_doc_signing_cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;
    let attestation_doc_pub_key = cert::get_cert_public_key(&attestation_doc_signing_cert)?;
    attestation_doc::validate_cose_signature(&attestation_doc_pub_key, &cose_sign_1_decoded)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use cert::get_subject_alt_names_from_cert;
    use x509_parser::extensions::GeneralName;

    use rcgen::generate_simple_self_signed;

    fn embed_attestation_doc_in_cert(hostname: &str, cose_bytes: &[u8]) -> rcgen::Certificate {
        let subject_alt_names = vec![
            hostname.to_string(),
            format!("{}.{hostname}", hex::encode(cose_bytes)),
        ];

        generate_simple_self_signed(subject_alt_names).unwrap()
    }

    fn rcgen_cert_to_der(cert: rcgen::Certificate) -> Vec<u8> {
        cert.serialize_der().unwrap()
    }

    #[test]
    fn test_der_cert_parsing() {
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "../test-data/valid-attestation-doc-bytes",
        ))
        .unwrap();
        let hostname = "debug.cage.com".to_string();
        let cert = embed_attestation_doc_in_cert(&hostname, &sample_cose_sign_1_bytes);
        let der_cert = rcgen_cert_to_der(cert);
        let parsed_cert = parse_cert(der_cert.as_ref()).unwrap();
        let subject_alt_names = get_subject_alt_names_from_cert(&parsed_cert).unwrap();
        let matched_hostname = subject_alt_names.into_iter().any(|entries| {
            let GeneralName::DNSName(san) = entries else { return false };
            san == hostname
        });
        assert!(matched_hostname);
    }

    #[test]
    fn validate_debug_mode_attestation_doc() {
        // debug mode attestation docs fail due to an untrusted cert
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "../test-data/debug-mode-attestation-doc-bytes",
        ))
        .unwrap();
        let attestable_cert =
            embed_attestation_doc_in_cert("test-cage.localhost:6789", &sample_cose_sign_1_bytes);
        let cert = rcgen_cert_to_der(attestable_cert);
        let cert = parse_cert(&cert).unwrap();
        let err = validate_attestation_doc_in_cert(&cert).unwrap_err();
        assert!(matches!(
            err,
            error::AttestError::CertError(error::CertError::UntrustedCert)
        ));
    }
}
