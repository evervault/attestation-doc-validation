uniffi::include_scaffolding!("bindings");
use attestation_doc_validation::attestation_doc::{validate_expected_pcrs, PCRProvider};
use attestation_doc_validation::{parse_cert, validate_attestation_doc_in_cert, validate_attestation_doc_against_cert};

pub struct PCRs {
    pcr0: Option<String>,
    pcr1: Option<String>,
    pcr2: Option<String>,
    pcr8: Option<String>,
}

impl PCRProvider for PCRs {
    fn pcr_0(&self) -> Option<&str> {
        self.pcr0.as_deref()
    }

    fn pcr_1(&self) -> Option<&str> {
        self.pcr1.as_deref()
    }

    fn pcr_2(&self) -> Option<&str> {
        self.pcr2.as_deref()
    }

    fn pcr_8(&self) -> Option<&str> {
        self.pcr8.as_deref()
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


pub fn attest_cage(cert: Vec<u8>, expected_pcrs_list: Vec<PCRs>, attestation_doc: Vec<u8>) -> bool {
    let parsed_cert = match parse_cert(&cert) {
        Ok(parsed_cert) => parsed_cert,
        Err(e) => {
            eprintln!("Failed to parse provided cert: {e}");
            return false;
        }
    };

    let validated_attestation_doc = match validate_attestation_doc_against_cert(&parsed_cert, &attestation_doc) {
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
