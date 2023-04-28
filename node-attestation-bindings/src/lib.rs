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
  /// Returns an optional reference to a string slice containing the value of PCR-0. PCR-0 is Platform Configuration Register 0, a register used in the Trusted Platform Module (TPM) cryptographic subsystem. If the value of PCR-0 is not available, returns None.
  
  /// # Examples
  ///
  /// ```
  /// let my_tpm = Tpm::new();
  /// assert_eq!(my_tpm.pcr_0(), None);
  /// ```
  fn pcr_0(&self) -> Option<&str> {
    self.pcr_0.as_deref()
  }

  /// Returns an Option containing a reference to the value of field "pcr_1" if present in the struct, else None, after converting the value to a string slice.
  fn pcr_1(&self) -> Option<&str> {
    self.pcr_1.as_deref()
  }

  /// This function returns an Option containing a reference to a string slice that is obtained by calling as_deref() on the self.pcr_2 field, which is an Option<String> field of the struct it is called on. If self.pcr_2 is None, the function returns None.
  fn pcr_2(&self) -> Option<&str> {
    self.pcr_2.as_deref()
  }

  /// Returns an optional reference to the string slice contained in the 8th PCR register,
  /// or `None` if the register is empty. The function is called on an instance of a struct
  /// that holds the PCR 8 register. The `as_deref()` method is called on the register,
  /// which returns an `Option<&str>`.
  fn pcr_8(&self) -> Option<&str> {
    self.pcr_8.as_deref()
  }
}

#[napi]
/// /**
 * Attest the connection with the Cage by validating the certificate and expected PCRs list.
 * 
 * # Arguments
 * 
 * * `cert` - The certificate buffer obtained from the Cage.
 * * `expected_pcrs_list` - The list of expected PCRs.
 * 
 * # Returns
 * 
 * Returns a boolean value indicating whether the attestation was successful.
 * 
 * # Examples
 * 
 * ```
 * let cert = JsBuffer::new(&mut cx, 1024)?;
 * let pcrs = vec![NodePCRs::new(0, [0u8; 20])];
 * let connection_ok = attest_connection(cert, pcrs);
 * ```
 */
fn attest_connection(cert: JsBuffer, expected_pcrs_list: Vec<NodePCRs>) -> bool {
    // function logic here
}
fn attest_connection(cert: JsBuffer, expected_pcrs_list: Vec<NodePCRs>) -> bool {
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

  let validated_attestation_doc = match validate_attestation_doc_in_cert(&parsed_cert) {
    Ok(attestation_doc) => attestation_doc,
    Err(e) => {
      eprintln!("An error occurred while validating the connection to this Cage: {e}");
      return false;
    }
  };

  let mut result = Ok(true);
  for expected_pcrs in expected_pcrs_list {
      match validate_expected_pcrs(&validated_attestation_doc, &expected_pcrs) {
          Ok(_) => return true,
          Err(err) => result = Err(err),
      }
  }
  
  match result {
      Ok(_) => true,
      Err(e) => {
          eprintln!("Failed to validate that PCRs are as expected: {e}");
          false
      }
  }
}
