use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use openssl::{
    stack::Stack,
    x509::{store, X509StoreContext, X509},
};
use std::collections::BTreeMap;

/**
 * Adapted from code written by chinaza-evervault
**/

static NITRO_ROOT_CA_BYTES: &[u8] = include_bytes!("nitro.pem");

#[derive(Debug, PartialEq, Clone)]
pub struct PCRs {
    pub pcr_0: String,
    pub pcr_1: String,
    pub pcr_2: String,
    pub pcr_8: String,
}

impl ToString for PCRs {
    fn to_string(&self) -> String {
        format!(
            "PCR0: {},\nPCR1: {},\nPCR2: {},\nPCR8: {}",
            self.pcr_0, self.pcr_1, self.pcr_2, self.pcr_8
        )
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestationError
where
    Self: Send + Sync,
{
    #[error(transparent)]
    CertStacking(#[from] openssl::error::ErrorStack),
    #[error("COSE error: `{0}`")]
    Cose(String),
    #[error(transparent)]
    Cbor(#[from] serde_cbor::error::Error),
    #[error("A part of the attestation doc structure was deemed invalid")]
    DocStructure,
    #[error("The certificate in the attestation doc was detected as not having the NSM as root")]
    UntrustedCert,
    #[error("The COSE signature does not match the public key provided in the attestation doc")]
    InvalidCoseSignature,
    #[error("The PCRs found were different to those that were expected.\n\nExpected:\n{0}\n\nReceived:\n{1}")]
    UnexpectedPCRs(String, String),
    #[error("PCR{0} was missing in the attestation doc")]
    MissingPCR(usize),
}

pub type Result<T> = std::result::Result<T, AttestationError>;

fn extract_attestation_doc(
    cose_sign_1_decoded: &aws_nitro_enclaves_cose::CoseSign1,
) -> Result<AttestationDoc> {
    let cbor = cose_sign_1_decoded
        .get_payload::<aws_nitro_enclaves_cose::crypto::Openssl>(None)
        .map_err(|err| AttestationError::Cose(err.to_string()))?;
    Ok(serde_cbor::from_slice(&cbor)?)
}

fn true_or_invalid(check: bool, err: AttestationError) -> Result<()> {
    if check {
        Ok(())
    } else {
        Err(err)
    }
}

/// Derived from [AWS attestation process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md)
pub fn validate_attestation_document_structure(
    attestation_document: &AttestationDoc,
) -> Result<()> {
    let valid_structure_check = !attestation_document.module_id.is_empty()
        && attestation_document.digest == Digest::SHA384
        && !attestation_document.pcrs.is_empty()
        && attestation_document.pcrs.len() <= 32
        && attestation_document
            .pcrs
            .keys()
            .all(|&pcr_index| pcr_index < 32)
        && attestation_document
            .pcrs
            .values()
            .all(|pcr| [32, 48, 64].contains(&pcr.len()))
        && !attestation_document.cabundle.is_empty()
        && attestation_document
            .cabundle
            .iter()
            .all(|cert| cert.len() > 0 && cert.len() <= 1024)
        && attestation_document
            .public_key
            .as_ref()
            .map_or(true, |key| key.len() > 0 && key.len() <= 1024) // these default to true if not present
        && attestation_document
            .nonce
            .as_ref()
            .map_or(true, |nonce| nonce.len() > 0 && nonce.len() <= 512)
        && attestation_document
            .user_data
            .as_ref()
            .map_or(true, |user_data| user_data.len() > 0 && user_data.len() <= 512);
    true_or_invalid(valid_structure_check, AttestationError::DocStructure)
}

fn vec_to_certificate_stack(certificates: Vec<X509>) -> Result<Stack<X509>> {
    let mut stack = Stack::new()?;
    for certificate in certificates {
        stack.push(certificate)?;
    }
    Ok(stack)
}

fn verify_that_certificate_is_from_nitro_hypervisor(
    target: &X509,
    certificates: Vec<X509>,
) -> Result<()> {
    let mut certificate_store_builder = store::X509StoreBuilder::new()?;
    let nitro_root_ca = X509::from_pem(NITRO_ROOT_CA_BYTES)?;
    certificate_store_builder.add_cert(nitro_root_ca)?;
    let certificate_stack = vec_to_certificate_stack(certificates)?;
    let certificate_store = certificate_store_builder.build();
    let mut store_context = X509StoreContext::new()?;
    true_or_invalid(
        store_context.init(
            certificate_store.as_ref(),
            target.as_ref(),
            certificate_stack.as_ref(),
            openssl::x509::X509StoreContextRef::verify_cert,
        )?,
        AttestationError::UntrustedCert,
    )
}

fn validate_cose_signature(
    attestation_doc_signing_cert: &X509,
    cose_sign_1_decoded: &CoseSign1,
) -> Result<()> {
    let signing_cert_public_key = attestation_doc_signing_cert.public_key()?;
    true_or_invalid(
        cose_sign_1_decoded
            .verify_signature::<aws_nitro_enclaves_cose::crypto::Openssl>(&signing_cert_public_key)
            .map_err(|err| AttestationError::Cose(err.to_string()))?,
        AttestationError::InvalidCoseSignature,
    )
}

macro_rules! extract_pcr {
    ($measurements:expr, $idx:literal) => {{
        $measurements
            .get(&$idx)
            .ok_or(AttestationError::MissingPCR($idx))?
            .to_string()
    }};
}

fn pcrs_match(attestation_doc: &AttestationDoc, expected_pcrs: &PCRs) -> Result<()> {
    let encoded_measurements = attestation_doc
        .pcrs
        .iter()
        .map(|(&index, buf)| (index, hex::encode(&buf[..])))
        .collect::<BTreeMap<_, _>>();

    let received_pcrs = PCRs {
        pcr_0: extract_pcr!(encoded_measurements, 0),
        pcr_1: extract_pcr!(encoded_measurements, 1),
        pcr_2: extract_pcr!(encoded_measurements, 2),
        pcr_8: extract_pcr!(encoded_measurements, 8),
    };

    let same_pcrs = expected_pcrs == &received_pcrs;
    true_or_invalid(
        same_pcrs,
        AttestationError::UnexpectedPCRs(expected_pcrs.to_string(), received_pcrs.to_string()),
    )
}

pub fn validate_attestation_doc(
    attestation_doc_cose_sign_1_bytes: &[u8],
    expected_pcrs: &PCRs,
) -> Result<AttestationDoc> {
    let cose_sign_1_decoded: CoseSign1 = serde_cbor::from_slice(attestation_doc_cose_sign_1_bytes)?;
    let attestation_doc: AttestationDoc = extract_attestation_doc(&cose_sign_1_decoded)?;
    validate_attestation_document_structure(&attestation_doc)?;
    let attestation_doc_signing_cert = X509::from_der(&attestation_doc.certificate)?;
    let received_certificates: Vec<X509> = attestation_doc
        .cabundle
        .iter()
        .flat_map(|blob| X509::from_der(blob))
        .collect();
    verify_that_certificate_is_from_nitro_hypervisor(
        &attestation_doc_signing_cert,
        received_certificates,
    )?;
    validate_cose_signature(&attestation_doc_signing_cert, &cose_sign_1_decoded)?;
    pcrs_match(&attestation_doc, expected_pcrs)?;
    Ok(attestation_doc)
}

#[cfg(test)]
mod attestation_tests {
    use super::*;

    // todo add more unit tests for various situations

    #[test]
    fn validate_valid_attestation_doc_time_sensitive() {
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "./test-files/valid-attestation-doc-bytes",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
            pcr_0: "f4d48b81a460c9916d1e685119074bf24660afd3e34fae9fca0a0d28d9d5599936332687e6f66fc890ac8cf150142d8b".to_string(),
            pcr_1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f".to_string(),
            pcr_2: "d8f114da658de5481f8d9ec73907feb553560787522f705c92d7d96beed8e15e2aa611984e098c576832c292e8dc469a".to_string(),
            pcr_8: "8790eb3cce6c83d07e84b126dc61ca923333d6f66615c4a79157de48c5ab2418bdc60746ea7b7afbff03a1c6210201cb".to_string(),
        };
        let _attestation_doc =
            validate_attestation_doc(&sample_cose_sign_1_bytes, &expected_pcrs).unwrap();
    }

    #[test]
    fn validate_valid_attestation_doc_unexpected_pcrs_time_sensitive() {
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "./test-files/valid-attestation-doc-bytes",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
            pcr_0: "f4d48b81a460c9916dunnexpecteeeeeeeeed6fc890ac8cf150142d8b".to_string(),
            pcr_1: "bcdf05funnexpecteeeeeeeeeddee9e79bbff31e34bf28a99aa19e6b29c3unnexpecteeeeeeeeed7236edf26fcb78654e63f".to_string(),
            pcr_2: "d8f114da658de5481funnexpecteeeeeeeeed60787522f705c92d7d96beed8e15e2aunnexpecteeeeeeeeed92e8dc469a".to_string(),
            pcr_8: "8790eb3cce6unnexpecteeeeeeeeed23333d6f66615c4a79157de48c5ab24unnexpecteeeeeeeeedafbff03a1c6210201cb".to_string(),
        };
        let err = validate_attestation_doc(&sample_cose_sign_1_bytes, &expected_pcrs).unwrap_err();
        assert!(
            matches!(err, AttestationError::UnexpectedPCRs(expected_string, _) if expected_string == expected_pcrs.to_string())
        );
    }

    #[test]
    fn validate_debug_mode_attestation_doc() {
        // debug mode attestation docs fail due to an untrusted cert
        let sample_cose_sign_1_bytes = std::fs::read(std::path::Path::new(
            "./test-files/debug-mode-attestation-doc-bytes",
        ))
        .unwrap();
        let expected_pcrs = PCRs {
            pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        let err = validate_attestation_doc(&sample_cose_sign_1_bytes, &expected_pcrs).unwrap_err();
        assert!(matches!(err, AttestationError::UntrustedCert));
    }
}
