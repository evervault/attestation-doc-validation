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

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[test]
fn validate_valid_attestation_doc_in_cert_time_sensitive() {
    let sample_cert_bytes = std::fs::read(std::path::Path::new(
        "./test-files/debug-mode-cert-containing-attestation-doc-18-1-23.pem",
    ))
    .unwrap();
    let expected_pcrs = TestPCRs {
           pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
           pcr_1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
           pcr_2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
           pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
         };
    let cert = parse_cert(&sample_cert_bytes).unwrap();
    let maybe_ad = validate_attestation_doc_in_cert(&cert);
    assert!(maybe_ad.is_ok());
    let is_valid = validate_expected_pcrs(&maybe_ad.unwrap(), &expected_pcrs).is_ok();
    assert!(is_valid);
}

#[test]
fn validate_valid_attestation_doc_in_non_debug_mode_with_correct_pcrs_time_sensitive() {
    let sample_cert_bytes = std::fs::read(std::path::Path::new(
        "./test-files/non-debug-cert-containing-attestation-document-18-1-23.pem",
    ))
    .unwrap();
    let expected_pcrs = TestPCRs {
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
fn validate_valid_attestation_doc_in_cert_incorrect_pcrs_time_sensitive() {
    let sample_cert_bytes = std::fs::read(std::path::Path::new(
        "./test-files/non-debug-cert-containing-attestation-document-18-1-23.pem",
    ))
    .unwrap();
    let expected_pcrs = TestPCRs {
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
fn validate_valid_attestation_doc_in_cert_der_encoding_time_sensitive() {
    let sample_cert_bytes = std::fs::read(std::path::Path::new(
        "./test-files/non-debug-cert-containing-attestation-document-18-1-23-der.crt",
    ))
    .unwrap();
    let expected_pcrs = TestPCRs {
           pcr_0: "d265a83faa7b4fa0d73b82b6d06253e894445922937d0ee5a74fe4891da9817611a71e71b98e5329232902de3cf419af".to_string(),
           pcr_1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f".to_string(),
           pcr_2: "e4f634d24ad83b7f6e49fe283bafdb220f6252fb4a278a858e19d15b7cd0f263b9168ed0bacefb4444266df9f9a77f24".to_string(),
           pcr_8: "97c5395a83c0d6a04d53ff962663c714c178c24500bf97f78456ed3721d922cf3f940614da4bb90107c439bc4a1443ca".to_string(),
       };
    let cert = parse_cert(&sample_cert_bytes).unwrap();
    let maybe_ad = validate_attestation_doc_in_cert(&cert);
    assert!(maybe_ad.is_ok());
    let is_attested = validate_expected_pcrs(maybe_ad.as_ref().unwrap(), &expected_pcrs).is_ok();
    assert!(is_attested);
}
