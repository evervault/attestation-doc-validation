mod attestation_doc;
mod cert;
pub mod error;

use attestation_doc::AttestationDoc;
pub use attestation_doc::{validate_expected_pcrs, PCRProvider};
use openssl::x509::X509;

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
pub fn parse_cert(given_cert: &[u8]) -> error::AttestResult<X509> {
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
pub fn validate_attestation_doc_in_cert(given_cert: &X509) -> error::AttestResult<AttestationDoc> {
    // Extract raw attestation doc from subject alt names
    let cose_signature = cert::extract_signed_cose_sign_1_from_certificate(given_cert)?;

    // Parse attestation doc from cose signature and validate structure
    let (cose_sign_1_decoded, decoded_attestation_doc) =
        attestation_doc::decode_attestation_document(&cose_signature)?;
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

    // Validate that the cert public key is embedded in the attestation doc
    let cage_cert_public_key = cert::export_public_key_to_der(given_cert)?;
    attestation_doc::validate_expected_challenge(&decoded_attestation_doc, &cage_cert_public_key)?;

    Ok(decoded_attestation_doc)
}

#[cfg(test)]
mod test {
    use super::attestation_doc::PCRs;
    use super::*;

    use rcgen::{generate_simple_self_signed, Certificate};

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

    fn test_validation_on_attestable_cert<T: PCRProvider>(cert: Certificate, pcrs: &T) {
        let cert = rcgen_cert_to_pem(cert);
        let cert = parse_cert(&cert).unwrap();
        let validated_ad = validate_attestation_doc_in_cert(&cert);
        assert!(validated_ad.is_ok());
        let is_attested = validate_expected_pcrs(validated_ad.as_ref().unwrap(), pcrs).is_ok();
        assert!(is_attested);
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
    fn validate_valid_attestation_doc_time_sensitive() {
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "./test-files/valid-attestation-doc-bytes",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
        pcr_0: "f4d48b81a460c9916d1e685119074bf24660afd3e34fae9fca0a0d28d9d5599936332687e6f66fc890ac8cf150142d8b".to_string(),
        pcr_1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f".to_string(),
        pcr_2: "d8f114da658de5481f8d9ec73907feb553560787522f705c92d7d96beed8e15e2aa611984e098c576832c292e8dc469a".to_string(),
        pcr_8: "8790eb3cce6c83d07e84b126dc61ca923333d6f66615c4a79157de48c5ab2418bdc60746ea7b7afbff03a1c6210201cb".to_string(),
    };
        let attestable_cert =
            embed_attestation_doc_in_cert("test-cage.localhost:6789", &sample_cose_sign_1_bytes);
        test_validation_on_attestable_cert(attestable_cert, &expected_pcrs);
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

    #[test]
    fn validate_valid_attestation_doc_in_cert() {
        let sample_cert_bytes = std::fs::read(std::path::Path::new(
            "./test-files/debug-mode-cert-containing-attestation-doc-18-1-23.pem",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
          pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
          pcr_1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
          pcr_2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
          pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        let cert = parse_cert(&sample_cert_bytes).unwrap();
        let maybe_ad = validate_attestation_doc_in_cert(&cert);
        println!("{maybe_ad:?}");
        assert!(maybe_ad.is_ok());
        let is_valid = validate_expected_pcrs(&maybe_ad.unwrap(), &expected_pcrs).is_ok();
        assert!(is_valid);
    }

    #[test]
    fn validate_valid_attestation_doc_in_non_debug_mode_with_correct_pcrs() {
        let sample_cert_bytes = std::fs::read(std::path::Path::new(
            "./test-files/non-debug-cert-containing-attestation-document-18-1-23.pem",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
          pcr_0: "d265a83faa7b4fa0d73b82b6d06253e894445922937d0ee5a74fe4891da9817611a71e71b98e5329232902de3cf419af".to_string(),
          pcr_1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f".to_string(),
          pcr_2: "e4f634d24ad83b7f6e49fe283bafdb220f6252fb4a278a858e19d15b7cd0f263b9168ed0bacefb4444266df9f9a77f24".to_string(),
          pcr_8: "97c5395a83c0d6a04d53ff962663c714c178c24500bf97f78456ed3721d922cf3f940614da4bb90107c439bc4a1443ca".to_string(),
      };
        let cert = parse_cert(&sample_cert_bytes).unwrap();
        let maybe_ad = validate_attestation_doc_in_cert(&cert);
        assert!(maybe_ad.is_ok());
        let ad = maybe_ad.unwrap();
        let pcrs_match = validate_expected_pcrs(&ad, &expected_pcrs).is_ok();
        assert!(pcrs_match);
    }

    #[test]
    fn validate_valid_attestation_doc_in_cert_incorrect_pcrs() {
        let sample_cert_bytes = std::fs::read(std::path::Path::new(
            "./test-files/non-debug-cert-containing-attestation-document-18-1-23.pem",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
          pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
          pcr_1: "000000000000000incorrect000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
          pcr_2: "00000000000000000000000000000000000000000incorrect000000000000000000000000000000000000000".to_string(),
          pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
      };
        let cert = parse_cert(&sample_cert_bytes).unwrap();
        let maybe_ad = validate_attestation_doc_in_cert(&cert);
        assert!(maybe_ad.is_ok());
        let ad = maybe_ad.unwrap();
        let err = validate_expected_pcrs(&ad, &expected_pcrs).unwrap_err();
        assert!(matches!(
            err,
            error::AttestationDocError::UnexpectedPCRs(_, _)
        ));
    }

    #[test]
    fn validate_valid_attestation_doc_in_cert_der_encoding() {
        let sample_cert_bytes = std::fs::read(std::path::Path::new(
            "./test-files/non-debug-cert-containing-attestation-document-18-1-23-der.crt",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
          pcr_0: "d265a83faa7b4fa0d73b82b6d06253e894445922937d0ee5a74fe4891da9817611a71e71b98e5329232902de3cf419af".to_string(),
          pcr_1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f".to_string(),
          pcr_2: "e4f634d24ad83b7f6e49fe283bafdb220f6252fb4a278a858e19d15b7cd0f263b9168ed0bacefb4444266df9f9a77f24".to_string(),
          pcr_8: "97c5395a83c0d6a04d53ff962663c714c178c24500bf97f78456ed3721d922cf3f940614da4bb90107c439bc4a1443ca".to_string(),
      };
        let cert = parse_cert(&sample_cert_bytes).unwrap();
        let maybe_ad = validate_attestation_doc_in_cert(&cert);
        assert!(maybe_ad.is_ok());
        let is_attested =
            validate_expected_pcrs(maybe_ad.as_ref().unwrap(), &expected_pcrs).is_ok();
        assert!(is_attested);
    }
}
