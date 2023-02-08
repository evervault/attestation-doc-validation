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

/// Top level function to attest the Cage being connected to. Returns true on successful attestation, or errors if attestation fails.
#[pyfunction]
pub fn attest_connection(cert: &[u8], expected_pcrs: &PCRs) -> PyResult<bool> {
    let cert =
        parse_cert(cert).map_err(|parse_err| PyValueError::new_err(format!("{parse_err}")))?;

    let validated_attestation_doc = validate_attestation_doc_in_cert(&cert)
        .map_err(|cert_err| PyValueError::new_err(format!("{cert_err}")))?;

    validate_expected_pcrs(&validated_attestation_doc, expected_pcrs)
        .map_err(|pcr_err| PyValueError::new_err(format!("{pcr_err}")))?;

    Ok(true)
}

/// A small python module offering bindings to the rust attestation doc validation project
#[pymodule]
fn python_attestation_bindings(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(attest_connection, m)?)?;
    m.add_class::<PCRs>()?;
    Ok(())
}
