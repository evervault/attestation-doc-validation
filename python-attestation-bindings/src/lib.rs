use attestation_doc_validation::{
    attestation_doc::{validate_expected_pcrs, PCRProvider},
    parse_cert, validate_attestation_doc_in_cert,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
#[derive(Debug, PartialEq, Eq, Clone, Default)]

pub struct PCRs {
    pcr_0: Option<String>,
    pcr_1: Option<String>,
    pcr_2: Option<String>,
    pcr_8: Option<String>,
}

#[pymethods]
impl PCRs {
    #[new]
    /// Creates a new instance of the PCRs struct with the given PCR values. Each PCR value is optional and defaults to None if not provided. The struct contains the following PCR fields: pcr_0, pcr_1, pcr_2, and pcr_8. Returns the created PCRs struct.
    pub fn new(
        pcr_0: Option<String>,
        pcr_1: Option<String>,
        pcr_2: Option<String>,
        pcr_8: Option<String>,
    ) -> Self {
        PCRs {
            pcr_0,
            pcr_1,
            pcr_2,
            pcr_8,
        }
    }

    #[staticmethod]
    /// Creates a new instance of PCRs with all the values set to their default values.
    /// 
    /// Returns:
    /// - A PCRs instance with all the PCR values set to their default values.
    pub fn empty() -> Self {
        PCRs::default()
    }

    fn lookup_pcr<'a>(&'a self, pcr_id: &str) -> Option<&'a str> {
        match pcr_id {
            "pcr0" | "pcr_0" => self.pcr_0(),
            "pcr1" | "pcr_1" => self.pcr_1(),
            "pcr2" | "pcr_2" => self.pcr_2(),
            "pcr8" | "pcr_8" => self.pcr_8(),
            _ => None,
        }
    }

    fn __contains__<'py>(&self, py: Python<'py>, key: PyObject) -> PyResult<bool> {
        let lookup_key = key.extract::<String>(py)?.to_lowercase();
        let matching_pcr = self.lookup_pcr(&lookup_key);
        Ok(matching_pcr.is_some())
    }

    fn __getitem__<'py>(&self, py: Python<'py>, key: PyObject) -> PyResult<PyObject> {
        let lookup_key = key.extract::<String>(py)?.to_lowercase();
        let matching_pcr = self.lookup_pcr(&lookup_key);
        let pcr_object = matching_pcr.map(String::from).to_object(py);
        Ok(pcr_object)
    }

    /// Returns a new String by converting the given object to a string using the to_string() method. This function is a wrapper around the to_string() method implemented by the object. This method is typically used for debugging purposes or when displaying objects in the console. 
    
    /// # Arguments
    ///
    /// * `self` - A reference to the object that needs to be converted to a string.
    ///
    /// # Example
    /// 
    /// ```
    /// let num = 27;
    /// let str_num = num.__str__();
    /// assert_eq!(str_num, "27");
    /// ```
    fn __str__(&self) -> String {
        self.to_string()
    }

    /// Returns a string representation of the object using `to_string()` method. This method is typically used for debugging purposes or for generating object representations to be read back in by `from_str()`.
    fn __repr__(&self) -> String {
        self.to_string()
    }
}

impl PCRProvider for PCRs {
    /// Returns an optional string reference to the value stored in PCR 0.
    /// If no value is stored in PCR 0, returns `None`.
    /// This function borrows the value stored in PCR 0 without consuming it.
    /// To obtain ownership of the stored value, use the `take_pcr_0` method instead.
    fn pcr_0(&self) -> Option<&str> {
        self.pcr_0.as_deref()
    }

    /// Returns an optional reference to the value of PCR_1. If PCR_1 is `None`, then `None` is returned. If PCR_1 is `Some`, then a reference to the string slice contained within `Some` is returned. 
    
    This function does not take any arguments and can only be called on a struct that contains a field of type `Option<String>`, named `pcr_1`.
    fn pcr_1(&self) -> Option<&str> {
        self.pcr_1.as_deref()
    }

    /// Returns an optional string reference to the PCR-2 value.
    
    ///
    /// The PCR-2 value represents the Platform Configuration Register 2, which is a 
    /// platform-specific register used to store measurements related to the system's 
    /// configuration. If the register exists and contains a valid value, it is returned
    /// as an optional string reference. Otherwise, the function returns `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use my_crate::TrustedPlatformModule;
    ///
    /// let tpm = TrustedPlatformModule::new();
    /// if let Some(pcr_2_value) = tpm.pcr_2() {
    ///     println!("PCR-2 value: {}", pcr_2_value);
    /// } else {
    ///     println!("PCR-2 value not available.");
    /// }
    /// ```
    fn pcr_2(&self) -> Option<&str> {
        self.pcr_2.as_deref()
    }

    /// Returns an optional reference to the PCR-8 value of a given object. If the value is present, the function returns a reference to the underlying string slice. If the value is absent, the function returns `None`.
    fn pcr_8(&self) -> Option<&str> {
        self.pcr_8.as_deref()
    }
}

/// Top level function to attest the Cage being connected to.
/// * If the cert fails to parse, return an error
/// * If the attestation doc fails to validate, return an error
/// * If the list of PCRs to check is empty, return true
/// * If any of the PCRs in the list match, return true
/// * If they all fail, return the last error
#[pyfunction]
/// /**
 * Validates the connection with an attestation certificate and a list of expected PCRs.
 *
 * # Arguments
 *
 * * `cert` - A byte slice containing certificate in X.509 format.
 * * `expected_pcrs_list` - A vector of expected PCRs to validate against.
 *
 * # Returns
 *
 * `Ok(true)` if validation is successful, otherwise returns a `PyValueError` error.
 *
 * # Example
 *
 * ```rust
 * use attestation::attest_connection;
 *
 * let cert = include_bytes!("path/to/certificate.cert");
 * let expected_pcrs_list = vec![PCRs::new(&[0x00, 0x01, 0x02, 0x03]).unwrap()];
 * let result = attest_connection(cert, expected_pcrs_list);
 * assert!(result.is_ok());
 * ```
 */
pub fn attest_connection(cert: &[u8], expected_pcrs_list: Vec<PCRs>) -> PyResult<bool> {
    let cert =
        parse_cert(cert).map_err(|parse_err| PyValueError::new_err(format!("{parse_err}")))?;

    let validated_attestation_doc = validate_attestation_doc_in_cert(&cert)
        .map_err(|cert_err| PyValueError::new_err(format!("{cert_err}")))?;

    let mut result = Ok(true);
    for expected_pcrs in expected_pcrs_list {
        match validate_expected_pcrs(&validated_attestation_doc, &expected_pcrs) {
            Ok(_) => return Ok(true),
            Err(err) => result = Err(PyValueError::new_err(format!("{err}"))),
        }
    }
    result
}

/// A small python module offering bindings to the rust attestation doc validation project
#[pymodule]
/// Generates evervault attestation bindings to be used in Python. Adds an attestation connection function and PCR class to the given PyModule. Returns a PyResult object upon successful completion of the function.
fn evervault_attestation_bindings(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(attest_connection, m)?)?;
    m.add_class::<PCRs>()?;
    Ok(())
}
