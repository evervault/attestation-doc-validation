use attestation_doc_validation::attestation_doc::{validate_expected_pcrs, PCRProvider, self};
use attestation_doc_validation::{parse_cert, validate_attestation_doc_in_cert, validate_attestation_doc_against_cert};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::slice;

#[repr(C)]
#[derive(Clone)]
pub struct PCRs {
    pcr_0: *const c_char,
    pcr_1: *const c_char,
    pcr_2: *const c_char,
    pcr_8: *const c_char,
}

impl PCRProvider for &PCRs {
    fn pcr_0(&self) -> Option<&str> {
        unsafe {
            (*self)
                .pcr_0
                .as_ref()
                .and_then(|c_str| CStr::from_ptr(c_str).to_str().ok())
        }
    }

    fn pcr_1(&self) -> Option<&str> {
        unsafe {
            (*self)
                .pcr_1
                .as_ref()
                .and_then(|c_str| CStr::from_ptr(c_str).to_str().ok())
        }
    }

    fn pcr_2(&self) -> Option<&str> {
        unsafe {
            (*self)
                .pcr_2
                .as_ref()
                .and_then(|c_str| CStr::from_ptr(c_str).to_str().ok())
        }
    }

    fn pcr_8(&self) -> Option<&str> {
        unsafe {
            (*self)
                .pcr_8
                .as_ref()
                .and_then(|c_str| CStr::from_ptr(c_str).to_str().ok())
        }
    }
}

#[no_mangle]
pub extern "C" fn attest_connection(
    cert: *const u8,
    cert_len: usize,
    expected_pcrs_list: *const PCRs,
    expected_pcrs_len: usize
) -> bool {
    assert!(!cert.is_null());

    let cert_slice = unsafe { std::slice::from_raw_parts(cert, cert_len) };
    let expected_pcrs_slice =
        unsafe { std::slice::from_raw_parts(expected_pcrs_list, expected_pcrs_len) };

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
    for expected_pcrs in expected_pcrs_slice {
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

#[no_mangle]
pub extern "C" fn attest_cage(
    cert: *const u8,
    cert_len: usize,
    expected_pcrs_list: *const PCRs,
    expected_pcrs_len: usize,
    attestation_doc: *const u8,
    attestation_doc_len: usize,
) -> bool {
    assert!(!cert.is_null());
    assert!(!attestation_doc.is_null());

    let cert_slice = unsafe { std::slice::from_raw_parts(cert, cert_len) };
    let expected_pcrs_slice =
        unsafe { std::slice::from_raw_parts(expected_pcrs_list, expected_pcrs_len) };
    let attestation_doc_slice = unsafe { std::slice::from_raw_parts(attestation_doc, attestation_doc_len) };

    let parsed_cert = match parse_cert(cert_slice) {
        Ok(parsed_cert) => parsed_cert,
        Err(e) => {
            eprintln!("Failed to parse provided cert: {e}");
            return false;
        }
    };

    let validated_attestation_doc = match validate_attestation_doc_against_cert(&parsed_cert, &attestation_doc_slice) {
        Ok(attestation_doc) => attestation_doc,
        Err(err) => {
            eprintln!("An error occurred while validating the connection to this Cage: {err}");
            return false;
        },
    };

    let mut result = Ok(true);
    for expected_pcrs in expected_pcrs_slice {
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
