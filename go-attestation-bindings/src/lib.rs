extern crate libc;

use std::ffi::{CStr};
use std::slice;
use attestation_doc_validation::{
    attestation_doc::{validate_expected_pcrs, PCRProvider},
    parse_cert, validate_attestation_doc_in_cert,
};

#[repr(C)]
pub struct GoPCRs {
    pub hash_alg: *const libc::c_char,
    pub pcr_0: *const libc::c_char,
    pub pcr_1: *const libc::c_char,
    pub pcr_2: *const libc::c_char,
    pub pcr_8: *const libc::c_char,
}

#[no_mangle]
pub extern "C" fn attest_connection(cert: *const u32, cert_len: libc::size_t, pcrs: *const GoPCRs) -> *const libc::c_char {

    let hash_alg = unsafe { CStr::from_ptr((*pcrs).hash_alg).to_string_lossy().into_owned() };
    let pcr_0 = unsafe { CStr::from_ptr((*pcrs).pcr_0).to_string_lossy().into_owned() };
    let pcr_1 = unsafe { CStr::from_ptr((*pcrs).pcr_1).to_string_lossy().into_owned() };
    let pcr_2 = unsafe { CStr::from_ptr((*pcrs).pcr_2).to_string_lossy().into_owned() };
    let pcr_8 = unsafe { CStr::from_ptr((*pcrs).pcr_8).to_string_lossy().into_owned() };

    // Process the struct data in Rust
    println!("Hash Algorithm: {}", hash_alg);
    println!("PCR 0: {}", pcr_0);
    println!("PCR 1: {}", pcr_1);
    println!("PCR 2: {}", pcr_2);
    println!("PCR 8: {}", pcr_8);

    let cert_as_slice = unsafe {
        assert!(!cert.is_null());

        slice::from_raw_parts(cert, cert_len as usize)
    };

    let parsed_cert = convert_u32_to_u8(cert_as_slice);

    let cert_result = parse_cert(parsed_cert);
    match cert_result {
        Ok(_) => return 1 as *const libc::c_char,
        Err(error) => {
            println!("Error parsing certificate: {:?}", error);
            return 0 as *const libc::c_char
        }
    };
}

fn convert_u32_to_u8(slice: &[u32]) -> &[u8] {
    let len_u32 = slice.len();
    let len_u8 = len_u32 * 4; // Each u32 takes 4 bytes

    // Get a raw byte representation of the u32 slice
    let slice_u8: &[u8] = unsafe {
        std::slice::from_raw_parts(slice.as_ptr() as *const u8, len_u8)
    };

    slice_u8
}
