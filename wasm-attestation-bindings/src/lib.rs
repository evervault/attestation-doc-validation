use attestation_doc_validation::{
    parse_cert, validate_and_parse_attestation_doc, validate_attestation_doc_against_cert,
    validate_expected_pcrs, PCRProvider,
};
use base64::prelude::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct JsPCRs {
    pub hash_algorithm: Option<String>,
    pub pcr_0: Option<String>,
    pub pcr_1: Option<String>,
    pub pcr_2: Option<String>,
    pub pcr_8: Option<String>,
}

#[wasm_bindgen]
impl JsPCRs {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            hash_algorithm: None,
            pcr_0: None,
            pcr_1: None,
            pcr_2: None,
            pcr_8: None,
        }
    }
}

impl PCRProvider for JsPCRs {
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

const LOG_NAMESPACE: &'static str = "ATTESTATION ::";

/// A client can call out to `<enclave-url>/.well-known/attestation` to fetch the attestation doc from the Enclave
/// The fetched attestation doc will have the public key of the domain's cert embedded inside it along with an expiry
#[wasm_bindgen]
pub fn attest_enclave(
    cert: Box<[u8]>,
    expected_pcrs_list: Box<[JsPCRs]>,
    attestation_doc: &str,
) -> bool {
    let parsed_cert = match parse_cert(cert.as_ref()) {
        Ok(parsed_cert) => parsed_cert,
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} Failed to parse provided cert: {e}");
            error(&error_msg);
            return false;
        }
    };

    let decoded_ad = match BASE64_STANDARD.decode(attestation_doc.as_bytes()) {
        Ok(ad) => ad,
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} Failed to decode the provided attestation document as base64 - {e}");
            error(&error_msg);
            return false;
        }
    };

    let validated_attestation_doc = match validate_attestation_doc_against_cert(
        &parsed_cert,
        decoded_ad.as_ref(),
    ) {
        Ok(attestation_doc) => attestation_doc,
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} An error occur while validating the attestation doc against the Enclave connection's cert: {e}");
            error(&error_msg);
            return false;
        }
    };

    let mut observed_error = None;
    for expected_pcrs in expected_pcrs_list.as_ref() {
        match validate_expected_pcrs(&validated_attestation_doc, expected_pcrs) {
            Ok(_) => return true,
            Err(err) => {
                observed_error = Some(err);
            }
        }
    }

    match observed_error {
        None => true,
        Some(e) => {
            let error_msg =
                format!("{LOG_NAMESPACE} Failed to validate that PCRs are as expected: {e}");
            error(&error_msg);
            false
        }
    }
}

/// A client can call out to `<enclave-url>/.well-known/attestation` to fetch the attestation doc from the Enclave
/// The fetched attestation doc will have the public key of the domain's cert embedded inside it along with an expiry
#[wasm_bindgen]
pub fn validate_attestation_doc_pcrs(
    attestation_doc: &str,
    expected_pcrs_list: JsPCRs,
) -> bool {
    console_error_panic_hook::set_once();
    let decoded_ad = match BASE64_STANDARD.decode(attestation_doc.as_bytes()) {
        Ok(ad) => ad,
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} Failed to decode the provided attestation document as base64 - {e}");
            error(&error_msg);
            return false;
        }
    };

    let validated_attestation_doc = match validate_and_parse_attestation_doc(decoded_ad.as_ref()) {
        Ok(attestation_doc) => attestation_doc,
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} An error occur while validating the attestation doc against the Enclave connection's cert: {e}");
            error(&error_msg);
            return false;
        }
    };

    let mut observed_error = None;
    match validate_expected_pcrs(&validated_attestation_doc, &expected_pcrs_list) {
        Ok(_) => return true,
        Err(err) => {
            observed_error = Some(err);
        }
    }

    match observed_error {
        None => true,
        Some(e) => {
            let error_msg =
                format!("{LOG_NAMESPACE} Failed to validate that PCRs are as expected: {e}");
            error(&error_msg);
            false
        }
    }
}
