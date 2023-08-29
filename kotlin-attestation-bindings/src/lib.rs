uniffi::include_scaffolding!("bindings");
use attestation_doc_validation::attestation_doc::{validate_expected_pcrs, PCRProvider};
use attestation_doc_validation::{parse_cert, validate_attestation_doc_in_cert};

pub struct PCRs {
    pcr0: String,
    pcr1: String,
    pcr2: String,
    pcr8: String
}

impl PCRProvider for PCRs {
    fn pcr_0(&self) -> Option<&str> {
        Some(&self.pcr0)
    }

    fn pcr_1(&self) -> Option<&str> {
        Some(&self.pcr1)
    }

    fn pcr_2(&self) -> Option<&str> {
        Some(&self.pcr2)
    }

    fn pcr_8(&self) -> Option<&str> {
        Some(&self.pcr8)
    }
}

pub fn attest_connection(cert: Vec<u8>, expected_pcrs_list: Vec<PCRs>) -> bool {
    let parsed_cert = match parse_cert(&cert) {
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
    for expected_pcrs in expected_pcrs_list {
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
