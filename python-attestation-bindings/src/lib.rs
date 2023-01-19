use attestation_doc_validation::{
    parse_cert, validate_attestation_doc_in_cert, validate_expected_pcrs, PCRProvider,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
#[derive(Debug, PartialEq, Eq, Clone)]

pub struct PythonPCRs {
    pcr_0: Option<String>,
    pcr_1: Option<String>,
    pcr_2: Option<String>,
    pcr_8: Option<String>,
}

#[pymethods]
impl PythonPCRs {
    #[new]
    pub fn new(pcr_0: String, pcr_1: String, pcr_2: String, pcr_8: String) -> Self {
        PythonPCRs {
            pcr_0: Some(pcr_0),
            pcr_1: Some(pcr_1),
            pcr_2: Some(pcr_2),
            pcr_8: Some(pcr_8),
        }
    }
}

impl PCRProvider for PythonPCRs {
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

///
#[pyfunction]
pub fn attest_connection(cert: &[u8], expected_pcrs: &PythonPCRs) -> PyResult<bool> {
    let cert =
        parse_cert(cert).map_err(|parse_err| PyValueError::new_err(format!("{parse_err}")))?;

    let validated_attestation_doc = validate_attestation_doc_in_cert(&cert)
        .map_err(|cert_err| PyValueError::new_err(format!("{cert_err}")))?;

    validate_expected_pcrs(&validated_attestation_doc, expected_pcrs)
        .map_err(|pcr_err| PyValueError::new_err(format!("{pcr_err}")))?;

    Ok(true)
}

/// A Python module implemented in Rust.
#[pymodule]
fn python_attestation_bindings(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(attest_connection, m)?)?;
    m.add_class::<PythonPCRs>()?;
    Ok(())
}
