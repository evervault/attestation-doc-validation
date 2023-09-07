pub mod attestation_doc;
pub mod cert;
pub mod error;
mod nsm;

pub use attestation_doc::{validate_expected_nonce, validate_expected_pcrs, PCRProvider};
use error::{AttestResult as Result, AttestationError};
use nsm::nsm_api::AttestationDoc;

use nsm::CryptoClient;
use serde_bytes::ByteBuf;
use x509_parser::certificate::X509Certificate;

// Helper function to fail early on any variant of error::AttestError
fn true_or_invalid<E: Into<error::AttestError>>(check: bool, err: E) -> std::result::Result<(), E> {
    if check {
        Ok(())
    } else {
        Err(err)
    }
}

// Helper function to convert the embedded `ca_bundle` into a `webpki` compatible cert stack
fn create_intermediate_cert_stack(ca_bundle: &[ByteBuf]) -> Vec<&[u8]> {
    ca_bundle.iter().map(|cert| cert.as_slice()).collect()
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

    // Validate that the attestation doc's signature can be tied back to the AWS Nitro CA
    let intermediate_certs = create_intermediate_cert_stack(&decoded_attestation_doc.cabundle);
    cert::validate_cert_trust_chain(&decoded_attestation_doc.certificate, &intermediate_certs)?;

    // Validate Cose signature over attestation doc
    let cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;
    let pub_key: nsm::PublicKey = cert.public_key().try_into()?;
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
/// - Validating the public key embedded in the attestation doc is the same public key in the cert
/// - Validating the expiry embedded in the attestation doc is in the future
///
/// The `given_cert` represents the cert of the connection of which the `attestation_document` was fetched
/// from the cage on.
///
/// # Errors
///
/// Will return an error if:
/// - The cose1 encoded attestation doc fails to parse, or its signature is invalid
/// - The attestation document is not signed by the nitro cert chain
/// - The public key from the certificate is not present in the attestation document's challenge
/// - Any of the certificates are malformed
/// - The attestation document has no `user_data`
/// - The binary encoded challenge cannot be decoded
/// - The base64 encoded public key within the challenge cannot be decoded
/// - The decoded public key raw bytes are not equal to those of the given cert's public key
pub fn validate_attestation_doc_against_cert(
    given_cert: &X509Certificate<'_>,
    attestation_doc_cose_sign_1_bytes: &[u8],
) -> Result<AttestationDoc> {
    // Parse attestation doc from cose signature and validate structure
    let (cose_sign_1_decoded, decoded_attestation_doc) =
        attestation_doc::decode_attestation_document(attestation_doc_cose_sign_1_bytes)?;
    attestation_doc::validate_attestation_document_structure(&decoded_attestation_doc)?;
    let attestation_doc_signing_cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;

    // Validate that the attestation doc's signature can be tied back to the AWS Nitro CA
    let intermediate_certs = create_intermediate_cert_stack(&decoded_attestation_doc.cabundle);
    cert::validate_cert_trust_chain(&decoded_attestation_doc.certificate, &intermediate_certs)?;

    // Validate Cose signature over attestation doc
    let pub_key: nsm::PublicKey = attestation_doc_signing_cert.public_key().try_into()?;
    attestation_doc::validate_cose_signature::<CryptoClient>(&pub_key, &cose_sign_1_decoded)?;

    // Validate the public key of the cert & the attestation doc match
    let user_data = decoded_attestation_doc
        .clone()
        .user_data
        .ok_or_else(|| AttestationError::MissingUserData)?;

    // Validate that the public key of the given cert and that of the challenge are the same
    true_or_invalid(
        user_data == given_cert.public_key().raw,
        AttestationError::InvalidPublicKey,
    )?;

    Ok(decoded_attestation_doc)
}

/// Validates an attestation doc by:
/// - Validating the cert structure
/// - Decoding and validating the attestation doc
/// - Validating the signature on the attestation doc
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
    let attestation_doc_signing_cert = cert::parse_der_cert(&decoded_attestation_doc.certificate)?;

    // Validate that the attestation doc's signature can be tied back to the AWS Nitro CA
    let intermediate_certs = create_intermediate_cert_stack(&decoded_attestation_doc.cabundle);
    cert::validate_cert_trust_chain(&decoded_attestation_doc.certificate, &intermediate_certs)?;

    // Validate Cose signature over attestation doc
    let pub_key: nsm::PublicKey = attestation_doc_signing_cert.public_key().try_into()?;
    attestation_doc::validate_cose_signature::<CryptoClient>(&pub_key, &cose_sign_1_decoded)?;

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
            "../test-data/beta/valid-attestation-doc-bytes",
        ))
        .unwrap();
        let hostname = "debug.cage.com".to_string();
        let cert = embed_attestation_doc_in_cert(&hostname, &sample_cose_sign_1_bytes);
        let der_cert = rcgen_cert_to_der(cert);
        let parsed_cert = parse_cert(der_cert.as_ref()).unwrap();
        let subject_alt_names = get_subject_alt_names_from_cert(&parsed_cert).unwrap();
        let matched_hostname = subject_alt_names.into_iter().any(|entries| {
            let GeneralName::DNSName(san) = entries else {
                return false;
            };
            san == hostname
        });
        assert!(matched_hostname);
    }

    #[test]
    fn validate_debug_mode_attestation_doc() {
        // debug mode attestation docs fail due to an untrusted cert
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "../test-data/beta/debug-mode-attestation-doc-bytes",
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

    /**
     *
     * The following tests act as integration tests, but require the #[cfg(test)] flag to be set in the cert module, so must be written as unit tests.
     *
     * Live Cage certs are required to have the public key match with the AD challenge (which in practice prevents MITM)
     * However, this introduces issues when testing. When the certs are more than 3 hours old, they will expire and fail
     * our validity checks. To get around this the tests corresponding to live certs are suffixed with time_sensitive_beta, and
     * only run in CI when the time has been spoofed to match their validity window.
     *
     * The certs being used were generated on January 18th 2023 at approximately 15:15. (epoch: 1674054914)
     */
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct TestPCRs {
        pub pcr_0: Option<String>,
        pub pcr_1: Option<String>,
        pub pcr_2: Option<String>,
        pub pcr_8: Option<String>,
    }

    impl PCRProvider for TestPCRs {
        fn pcr_0(&self) -> Option<&str> {
            self.pcr_0.as_deref()
        }
        fn pcr_1(&self) -> Option<&str> {
            self.pcr_1.as_deref()
        }
        fn pcr_2(&self) -> Option<&str> {
            self.pcr_2.as_deref()
        }
        fn pcr_8(&self) -> Option<&str> {
            self.pcr_8.as_deref()
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestSpec {
        file: String,
        pcrs: TestPCRs,
        is_attestation_doc_valid: bool,
        should_pcrs_match: bool,
    }

    const TEST_BASE_PATH: &'static str = "..";

    macro_rules! evaluate_test_from_spec {
        ($test_spec:literal) => {
            // Resolve test spec
            let test_def_filepath = format!("{}/test-specs/beta/{}", TEST_BASE_PATH, $test_spec);
            let test_definition = std::fs::read(std::path::Path::new(&test_def_filepath)).unwrap();
            let test_def_str = std::str::from_utf8(&test_definition).unwrap();
            let test_spec: TestSpec = serde_json::from_str(test_def_str).unwrap();

            // Read in static input file
            let test_input_file = format!("{}/{}", TEST_BASE_PATH, test_spec.file);
            let input_bytes = std::fs::read(std::path::Path::new(&test_input_file)).unwrap();

            // Perform test
            let is_pem_cert = test_spec.file.ends_with(".pem");
            let cert_content = if is_pem_cert {
                let pem_cert = pem::parse(input_bytes).unwrap();
                pem_cert.contents.clone()
            } else {
                input_bytes
            };
            let cert = parse_cert(&cert_content).unwrap();
            let maybe_attestation_doc = validate_attestation_doc_in_cert(&cert);
            if test_spec.is_attestation_doc_valid {
                assert!(maybe_attestation_doc.is_ok());
                let pcrs_match =
                    validate_expected_pcrs(&maybe_attestation_doc.unwrap(), &test_spec.pcrs);
                assert_eq!(pcrs_match.is_ok(), test_spec.should_pcrs_match);

                if !test_spec.should_pcrs_match {
                    let returned_error = pcrs_match.unwrap_err();
                    assert!(matches!(
                        returned_error,
                        error::AttestationError::UnexpectedPCRs(_, _)
                    ));
                }
            } else {
                assert!(maybe_attestation_doc.is_err());
            }
        };
    }

    #[test]
    fn validate_valid_attestation_doc_in_cert_time_sensitive_beta() {
        evaluate_test_from_spec!("valid_attestation_doc_in_cert_time_sensitive.json");
    }

    #[test]
    fn validate_valid_attestation_doc_in_non_debug_mode_with_correct_pcrs_time_sensitive_beta() {
        evaluate_test_from_spec!(
            "valid_attestation_doc_in_non_debug_mode_with_correct_pcrs_time_sensitive.json"
        );
    }

    #[test]
    fn validate_valid_attestation_doc_in_cert_incorrect_pcrs_time_sensitive_beta() {
        evaluate_test_from_spec!(
            "valid_attestation_doc_in_cert_incorrect_pcrs_time_sensitive.json"
        );
    }

    #[test]
    fn validate_valid_attestation_doc_in_cert_der_encoding_time_sensitive_beta() {
        evaluate_test_from_spec!("valid_attestation_doc_in_cert_der_encoding_time_sensitive.json");
    }

    #[test]
    fn valid_attestation_check_pcr8_only_time_sensitive_beta() {
        evaluate_test_from_spec!("valid_attestation_doc_check_pcr8_only_time_sensitive.json");
    }

    #[test]
    fn validate_valid_attestation_doc_in_cert_time_sensitive_ga() {
        let attestation_doc = std::fs::read(std::path::Path::new(
            &"../test-data/valid-attestation-doc-base64",
        ))
        .unwrap();
        let attestation_doc_str = std::str::from_utf8(&attestation_doc).unwrap();
        let attestation_doc_bytes =
            base64::decode_config(attestation_doc_str, base64::STANDARD).unwrap();

        let input_bytes =
            std::fs::read(std::path::Path::new("../test-data/valid-cage-cert")).unwrap();

        let cert = parse_cert(&input_bytes).unwrap();
        let maybe_attestation_doc =
            validate_attestation_doc_against_cert(&cert, &attestation_doc_bytes);
        assert!(maybe_attestation_doc.is_ok());
    }
}
