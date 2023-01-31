/**
 * Live Cage certs are required to have the public key match with the AD challenge (which in practice prevents MITM)
 * However, this introduces issues when testing. When the certs are more than 3 hours old, they will expire and fail
 * our validity checks. To get around this the tests corresponding to live certs are suffixed with time_sensitive, and
 * only run in CI when the time has been spoofed to match their validity window.
 *
 * The certs being used were generated on January 18th 2023 at approximately 15:15.
 */
use attestation_doc_validation::{
    attestation_doc::{validate_expected_pcrs, PCRProvider},
    error, parse_cert, validate_attestation_doc_in_cert,
};

use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TestPCRs {
    pub pcr_0: String,
    pub pcr_1: String,
    pub pcr_2: String,
    pub pcr_8: String,
}

impl PCRProvider for TestPCRs {
    fn pcr_0(&self) -> Option<&str> {
        Some(self.pcr_0.as_str())
    }
    fn pcr_1(&self) -> Option<&str> {
        Some(self.pcr_1.as_str())
    }
    fn pcr_2(&self) -> Option<&str> {
        Some(self.pcr_2.as_str())
    }
    fn pcr_8(&self) -> Option<&str> {
        Some(self.pcr_8.as_str())
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

const TEST_BASE_PATH: &'static str = "../test-specs";

macro_rules! evaluate_test_from_spec {
    ($test_spec:literal) => {
        // Resolve test spec
        let test_def_filepath = format!("{}/{}", TEST_BASE_PATH, $test_spec);
        let test_definition = std::fs::read(std::path::Path::new(&test_def_filepath)).unwrap();
        let test_def_str = std::str::from_utf8(&test_definition).unwrap();
        let test_spec: TestSpec = serde_json::from_str(test_def_str).unwrap();

        // Read in static input file
        let test_input_file = format!("{}/{}", TEST_BASE_PATH, test_spec.file);
        let input_bytes = std::fs::read(std::path::Path::new(&test_input_file)).unwrap();

        // Perform test
        let cert = parse_cert(&input_bytes).unwrap();
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
                    error::AttestationDocError::UnexpectedPCRs(_, _)
                ));
            }
        } else {
            assert!(maybe_attestation_doc.is_err());
        }
    };
}

#[test]
fn validate_valid_attestation_doc_in_cert_time_sensitive() {
    evaluate_test_from_spec!("valid_attestation_doc_in_cert_time_sensitive.json");
}

#[test]
fn validate_valid_attestation_doc_in_non_debug_mode_with_correct_pcrs_time_sensitive() {
    evaluate_test_from_spec!(
        "valid_attestation_doc_in_non_debug_mode_with_correct_pcrs_time_sensitive.json"
    );
}

#[test]
fn validate_valid_attestation_doc_in_cert_incorrect_pcrs_time_sensitive() {
    evaluate_test_from_spec!("valid_attestation_doc_in_cert_incorrect_pcrs_time_sensitive.json");
}

#[test]
fn validate_valid_attestation_doc_in_cert_der_encoding_time_sensitive() {
    evaluate_test_from_spec!("valid_attestation_doc_in_cert_der_encoding_time_sensitive.json");
}
