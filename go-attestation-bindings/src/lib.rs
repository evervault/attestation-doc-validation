extern crate libc;

use sha256::digest_bytes;
use std::ffi::{CStr, CString};
use std::slice;

#[repr(C)]
pub struct GoPCRs {
    pub hash_alg: *const libc::c_char,
    pub pcr_0: *const libc::c_char,
    pub pcr_1: *const libc::c_char,
    pub pcr_2: *const libc::c_char,
    pub pcr_8: *const libc::c_char,
}

#[no_mangle] 
pub extern "C" fn rustdemo(cert: *const u32, cert_len: libc::size_t, pcrs: *const GoPCRs) -> *const libc::c_char {

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

    println!("cert_len: {:?}", cert_as_slice.len());

    1 as *const libc::c_char
}
