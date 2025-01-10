//! Module to expose a minimal Time API which is available even when compiled to WASM.
//! This is a minimal version of https://docs.rs/web-time/1.1.0/web_time to meet the requirements of the attestation crate.
pub use core::time::Duration;
use std::time::SystemTimeError;
use thiserror::Error;

#[derive(Debug,Error)]
pub enum TimeError {
  #[error("Failed to compute seconds since the unix epoch")]
  TimeSinceUnixEpochError(#[from] SystemTimeError),
  #[error("Failed to compute seconds since the unix epoch")]
  NegativeTimestamp,
}

#[cfg(target_arch = "wasm32")]
mod wasm {
  use wasm_bindgen::prelude::wasm_bindgen;
  use super::{TimeError, Duration};
  
  #[wasm_bindgen]
  extern "C" {
    /// Type for the [`Date` object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date).
    type Date;
  
    /// Binding to [`Date.now()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now).
    #[wasm_bindgen(static_method_of = Date)]
    fn now() -> f64;
  }
  
  pub fn epoch() -> Result<Duration, TimeError> {
    let signed_js_ts = Date::now() as i64;
    let js_ms = signed_js_ts.try_into().map_err(|_| TimeError::NegativeTimestamp)?;
    Ok(Duration::from_millis(js_ms))
  }
}
#[cfg(target_arch = "wasm32")]
pub use wasm::*;


#[cfg(not(target_arch = "wasm32"))]
pub fn epoch() -> Result<Duration, TimeError> {
  Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
}