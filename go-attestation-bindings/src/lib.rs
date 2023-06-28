extern crate libc;

use std::os::raw::{c_uchar};
use std::ffi::{CStr};
use attestation_doc_validation::attestation_doc::{validate_expected_pcrs, PCRProvider, get_pcrs};
use attestation_doc_validation::{parse_cert, validate_attestation_doc_in_cert};

#[repr(C)]
pub struct GoPCRs {
    pub pcr_0: *const libc::c_char,
    pub pcr_1: *const libc::c_char,
    pub pcr_2: *const libc::c_char,
    pub pcr_8: *const libc::c_char,
}

impl PCRProvider for GoPCRs {
    fn pcr_0(&self) -> Option<&str> {
        let pcr_0 = unsafe { CStr::from_ptr(self.pcr_0).to_str().unwrap() };
        Some(pcr_0)
    }
    fn pcr_1(&self) -> Option<&str> {
        let pcr_1 = unsafe { CStr::from_ptr(self.pcr_1).to_str().unwrap() };
        Some(pcr_1)
    }
    fn pcr_2(&self) -> Option<&str> {
        let pcr_2 = unsafe { CStr::from_ptr(self.pcr_2).to_str().unwrap() };
        Some(pcr_2)
    }
    fn pcr_8(&self) -> Option<&str> {
        let pcr_8 = unsafe { CStr::from_ptr(self.pcr_8).to_str().unwrap() };
        Some(pcr_8)
    }
}

#[no_mangle]
pub extern "C" fn attest_connection(cert: *const c_uchar, cert_len: usize, expected_pcs: *const GoPCRs) -> bool {

    let cert_slice = unsafe { std::slice::from_raw_parts(cert, cert_len) };
    let expected_pcs_ref = unsafe { &*expected_pcs };

    println!("cert: {}", cert_slice.len());

    let parsed_cert = match parse_cert(cert_slice) {
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
    println!("PCRS: {}", get_pcrs(&validated_attestation_doc).unwrap().pcr_0);
    match validate_expected_pcrs(&validated_attestation_doc, expected_pcs_ref) {
        Ok(_) => return true,
        Err(err) => result = Err(err),
    }

    match result {
        Ok(_) => true,
        Err(e) => {
            eprintln!("Failed to validate that PCRs are as expected: {e}");
            false
        }
    }
}
