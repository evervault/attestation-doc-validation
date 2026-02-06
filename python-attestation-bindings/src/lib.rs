use attestation_doc_validation::{
    attestation_doc::{validate_expected_pcrs, PCRProvider},
    parse_cert, validate_attestation_doc_against_cert, validate_attestation_doc_in_cert,
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

    fn __str__(&self) -> String {
        self.to_string()
    }

    fn __repr__(&self) -> String {
        self.to_string()
    }
}

impl PCRProvider for PCRs {
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

/// Top level function to attest the Enclave being connected to.
/// * If the cert fails to parse, return an error
/// * If the attestation doc fails to validate, return an error
/// * If the list of PCRs to check is empty, return true
/// * If any of the PCRs in the list match, return true
/// * If they all fail, return the last error
#[pyfunction]
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

/// Note: this function is deprecated. Users should update to consume the `attest_enclave` entrypoint.
/// Top level function to attest the Cage being connected to.
/// * If the cert fails to parse, return an error
/// * If the attestation doc fails to validate, return an error
/// * If the list of PCRs to check is empty, return true
/// * If any of the PCRs in the list match, return true
/// * If they all fail, return the last error
#[pyfunction]
pub fn attest_cage(
    cert: &[u8],
    expected_pcrs_list: Vec<PCRs>,
    attestation_doc: &[u8],
) -> PyResult<bool> {
    let parsed_cert = parse_cert(cert.as_ref())
        .map_err(|parse_err| PyValueError::new_err(format!("{parse_err}")))?;

    let validated_attestation_doc =
        validate_attestation_doc_against_cert(&parsed_cert, attestation_doc.as_ref())
            .map_err(|parse_err| PyValueError::new_err(format!("{parse_err}")))?;

    let mut result = Ok(true);
    for expected_pcrs in expected_pcrs_list {
        match validate_expected_pcrs(&validated_attestation_doc, &expected_pcrs) {
            Ok(_) => return Ok(true),
            Err(err) => result = Err(PyValueError::new_err(format!("{err}"))),
        }
    }
    result
}

/// Top level function to attest the Enclave being connected to.
/// * If the cert fails to parse, return an error
/// * If the attestation doc fails to validate, return an error
/// * If the list of PCRs to check is empty, return true
/// * If any of the PCRs in the list match, return true
/// * If they all fail, return the last error
#[pyfunction]
pub fn attest_enclave(
    cert: &[u8],
    expected_pcrs_list: Vec<PCRs>,
    attestation_doc: &[u8],
) -> PyResult<bool> {
    let parsed_cert = parse_cert(cert.as_ref())
        .map_err(|parse_err| PyValueError::new_err(format!("{parse_err}")))?;

    let validated_attestation_doc =
        validate_attestation_doc_against_cert(&parsed_cert, attestation_doc.as_ref())
            .map_err(|parse_err| PyValueError::new_err(format!("{parse_err}")))?;

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
fn evervault_attestation_bindings(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(attest_connection, m)?)?;
    m.add_function(wrap_pyfunction!(attest_cage, m)?)?;
    m.add_function(wrap_pyfunction!(attest_enclave, m)?)?;
    m.add_class::<PCRs>()?;
    Ok(())
}
