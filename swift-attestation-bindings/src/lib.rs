use std::os::raw::c_int;
use std::os::raw::c_char;
use std::ffi::CStr;

#[repr(C)]
#[derive(Clone)]
pub struct PCRs {
  pcr_0: *const c_char,
  pcr_1: *const c_char,
  pcr_2: *const c_char,
  pcr_8: *const c_char,
}

#[no_mangle]
pub extern "C" fn attest_connection(cert: *const u8, cert_len: usize, expected_pcrs_list: *const PCRs, expected_pcrs_len: usize) -> bool {

  assert!(!cert.is_null());

  let cert_slice = unsafe { std::slice::from_raw_parts(cert, cert_len) };
    let expected_pcrs_slice = unsafe { std::slice::from_raw_parts(expected_pcrs_list, expected_pcrs_len) };

    if expected_pcrs_len > 0 {
        let first_pcrs = &expected_pcrs_slice[0];

        let expected_pcr0 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let expected_pcr1 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let expected_pcr2 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let expected_pcr8 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        let first_pcrs_pcr0 = unsafe { CStr::from_ptr(first_pcrs.pcr_0).to_str().unwrap() };
        let first_pcrs_pcr1 = unsafe { CStr::from_ptr(first_pcrs.pcr_1).to_str().unwrap() };
        let first_pcrs_pcr2 = unsafe { CStr::from_ptr(first_pcrs.pcr_2).to_str().unwrap() };
        let first_pcrs_pcr8 = unsafe { CStr::from_ptr(first_pcrs.pcr_8).to_str().unwrap() };

        return first_pcrs_pcr0 == expected_pcr0 &&
               first_pcrs_pcr1 == expected_pcr1 &&
               first_pcrs_pcr2 == expected_pcr2 &&
               first_pcrs_pcr8 == expected_pcr8;
    }

    return false;
}
