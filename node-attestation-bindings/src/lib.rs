use attestation_doc_validation::attestation_doc::{validate_expected_pcrs, PCRProvider};
use attestation_doc_validation::{parse_cert, validate_attestation_doc_in_cert};
use napi::JsBuffer;
use napi_derive::napi;

#[napi(object)]
struct NodePCRs {
  pub hash_algorithm: Option<String>,
  pub pcr_0: Option<String>,
  pub pcr_1: Option<String>,
  pub pcr_2: Option<String>,
  pub pcr_8: Option<String>,
}

impl PCRProvider for NodePCRs {
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

#[napi]
fn attest_connection(cert: JsBuffer, expected_pcrs: Option<NodePCRs>) -> bool {
  let cert_val = match cert.into_value() {
    Ok(cert_value) => cert_value,
    Err(e) => {
      eprintln!("Failed to access cert value passed from node to rust: {e}");
      return false;
    }
  };

  let parsed_cert = match parse_cert(cert_val.as_ref()) {
    Ok(parsed_cert) => parsed_cert,
    Err(e) => {
      eprintln!("Failed to parse provided cert: {e}");
      return false;
    }
  };

  let attestation_doc = match validate_attestation_doc_in_cert(&parsed_cert) {
    Ok(attestation_doc) => attestation_doc,
    Err(e) => {
      eprintln!("An error occurred while validating the connection to this Cage: {e}");
      return false;
    }
  };

  let maybe_validated_pcrs = expected_pcrs
    .as_ref()
    .map(|given_pcrs| validate_expected_pcrs(&attestation_doc, given_pcrs))
    .transpose();
  match maybe_validated_pcrs {
    // Mismatched PCRs will always return an error
    Ok(_) => true,
    Err(e) => {
      eprintln!("Failed to validate that PCRs are as expected: {e}");
      false
    }
  }
}
