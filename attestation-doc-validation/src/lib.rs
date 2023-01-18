mod attestation_doc;
mod cert;

use attestation_doc::AttestationDoc;
use cert::X509Certificate;

pub use attestation_doc::{validate_expected_pcrs, PCRProvider};
use serde_bytes::ByteBuf;
pub mod error;

// Helper function to fail early on any variant of error::AttestError
fn true_or_invalid<E: Into<error::AttestError>>(check: bool, err: E) -> Result<(), E> {
    if check {
        Ok(())
    } else {
        Err(err)
    }
}

/// Parses a slice of bytes into an X509. First attempts to parse PEM, but falls back to DER
///
/// # Errors
///
/// If both PEM and DER decoding of the certificate fail
pub fn parse_cert(given_cert: &[u8]) -> error::AttestResult<X509Certificate> {
    let parsed_cert =
        cert::parse_pem_cert(given_cert).or_else(|_| cert::parse_der_cert(given_cert))?;
    Ok(parsed_cert)
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
    given_cert: &X509Certificate,
) -> error::AttestResult<AttestationDoc> {
    // Extract raw attestation doc from subject alt names
    let cose_signature = cert::extract_signed_cose_sign_1_from_certificate(given_cert)?;

    // Parse attestation doc from cose signature and validate structure
    let (cose_sign_1_decoded, decoded_attestation_doc) =
        attestation_doc::decode_attestation_document(&cose_signature)?;
    attestation_doc::validate_attestation_document_structure(&decoded_attestation_doc)?;

    // Validate that the attestation doc's signature can be tied back to the AWS Nitro CA
    let attestation_doc_signing_cert = decoded_attestation_doc.certificate.as_slice();
    let received_certificates = decoded_attestation_doc
        .cabundle
        .iter()
        .map(ByteBuf::as_ref)
        .collect::<Vec<&[u8]>>();
    cert::validate_cert_trust_chain(
        &attestation_doc_signing_cert,
        &received_certificates,
        std::time::SystemTime::now(),
    )?;

    // Validate Cose signature over attestation doc
    let attestation_doc_signing_cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;
    let attestation_doc_pub_key = cert::get_cert_public_key(&attestation_doc_signing_cert);
    attestation_doc::validate_cose_signature(&attestation_doc_pub_key, &cose_sign_1_decoded)?;

    // Validate that the cert public key is embedded in the attestation doc
    let cage_cert_public_key = cert::export_public_key_to_der(given_cert)?;
    attestation_doc::validate_expected_challenge(&decoded_attestation_doc, &cage_cert_public_key)?;

    Ok(decoded_attestation_doc)
}

#[cfg(test)]
mod test {
    use super::*;

    use rcgen::generate_simple_self_signed;

    fn embed_attestation_doc_in_cert(hostname: &str, cose_bytes: &[u8]) -> rcgen::Certificate {
        let subject_alt_names = vec![
            hostname.to_string(),
            format!("{}.{hostname}", hex::encode(cose_bytes)),
        ];

        generate_simple_self_signed(subject_alt_names).unwrap()
    }

    fn rcgen_cert_to_pem(cert: rcgen::Certificate) -> Vec<u8> {
        cert.serialize_pem().unwrap().into_bytes()
    }

    fn rcgen_cert_to_der(cert: rcgen::Certificate) -> Vec<u8> {
        cert.serialize_der().unwrap()
    }

    #[test]
    fn test_der_cert_parsing() {
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "./test-files/valid-attestation-doc-bytes",
        ))
        .unwrap();
        let hostname = "debug.cage.com";
        let cert = embed_attestation_doc_in_cert(hostname, &sample_cose_sign_1_bytes);
        let der_cert = rcgen_cert_to_der(cert);
        let parsed_cert = parse_cert(der_cert.as_ref()).unwrap();
        let matched_hostname = parsed_cert
            .subject_alt_names()
            .into_iter()
            .flat_map(|entries| entries.into_iter())
            .any(|entries| {
                entries
                    .dnsname()
                    .map(|san| san == hostname)
                    .unwrap_or(false)
            });
        assert!(matched_hostname);
    }

    #[test]
    fn test_pem_cert_parsing() {
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "./test-files/valid-attestation-doc-bytes",
        ))
        .unwrap();
        let hostname = "debug.cage.com";
        let cert = embed_attestation_doc_in_cert(hostname, &sample_cose_sign_1_bytes);
        let cert = rcgen_cert_to_pem(cert);
        let parsed_cert = parse_cert(cert.as_ref()).unwrap();
        let matched_hostname = parsed_cert
            .subject_alt_names()
            .into_iter()
            .flat_map(|entries| entries.into_iter())
            .any(|entries| {
                entries
                    .dnsname()
                    .map(|san| san == hostname)
                    .unwrap_or(false)
            });
        assert!(matched_hostname);
    }

    #[test]
    fn validate_debug_mode_attestation_doc() {
        // debug mode attestation docs fail due to an untrusted cert
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "./test-files/debug-mode-attestation-doc-bytes",
        ))
        .unwrap();
        let attestable_cert =
            embed_attestation_doc_in_cert("test-cage.localhost:6789", &sample_cose_sign_1_bytes);
        let cert = rcgen_cert_to_pem(attestable_cert);
        let cert = parse_cert(&cert).unwrap();
        let err = validate_attestation_doc_in_cert(&cert).unwrap_err();
        assert!(matches!(
            err,
            error::AttestError::CertError(error::CertError::UntrustedCert)
        ));
    }
}
