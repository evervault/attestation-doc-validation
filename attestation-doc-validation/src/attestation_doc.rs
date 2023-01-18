use super::{
    error::{AttestationDocError, AttestationDocResult},
    true_or_invalid,
};
pub(super) use aws_nitro_enclaves_cose::CoseSign1;
pub(super) use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use aws_nitro_enclaves_nsm_api::api::Digest;
use openssl::pkey::{PKey, Public};
use std::collections::BTreeMap;
use std::fmt::Write;

// Helper macros to get, write and compare PCRs
macro_rules! extract_pcr {
    ($measurements:expr, $idx:literal) => {{
        $measurements
            .get(&$idx)
            .ok_or(AttestationDocError::MissingPCR($idx))?
            .to_string()
    }};
}

macro_rules! write_pcr {
    ($provider:ident, $writer:expr, $pcr:ident, $label:expr) => {
        if let Some(pcr_val) = $provider.$pcr() {
            let _ = writeln!($writer, "{}: {}", $label, pcr_val);
        }
    };
}

macro_rules! compare_pcrs {
    ($lhs:ident, $rhs:ident, $pcr:ident) => {
        let $pcr = $lhs.$pcr().map(|lhs_pcr| {
            $rhs.$pcr()
                .map_or_else(|| false, |rhs_pcr| lhs_pcr == rhs_pcr)
        });
        if !$pcr.unwrap_or_else(|| true) {
            return false;
        }
    };
}

pub trait PCRProvider {
    fn pcr_0(&self) -> Option<&str>;
    fn pcr_1(&self) -> Option<&str>;
    fn pcr_2(&self) -> Option<&str>;
    fn pcr_8(&self) -> Option<&str>;

    fn to_string(&self) -> String {
        let mut pcrs_str = String::new();
        write_pcr!(self, &mut pcrs_str, pcr_0, "PCR0");
        write_pcr!(self, &mut pcrs_str, pcr_1, "PCR1");
        write_pcr!(self, &mut pcrs_str, pcr_2, "PCR2");
        write_pcr!(self, &mut pcrs_str, pcr_8, "PCR8");
        pcrs_str
    }

    fn eq<T: PCRProvider>(&self, rhs: &T) -> bool {
        compare_pcrs!(self, rhs, pcr_0);
        compare_pcrs!(self, rhs, pcr_1);
        compare_pcrs!(self, rhs, pcr_2);
        compare_pcrs!(self, rhs, pcr_8);
        true
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PCRs {
    pub pcr_0: String,
    pub pcr_1: String,
    pub pcr_2: String,
    pub pcr_8: String,
}

impl PCRProvider for PCRs {
    fn pcr_0(&self) -> Option<&str> {
        Some(self.pcr_0.as_str())
    }
    fn pcr_1(&self) -> Option<&str> {
        Some(self.pcr_1.as_str())
    }
    fn pcr_2(&self) -> Option<&str> {
        Some(self.pcr_2.as_str())
    }
    fn pcr_8(&self) -> Option<&str> {
        Some(self.pcr_8.as_str())
    }
}

///
///
/// # Errors
///
/// Returns an error if any of the expected PCRs are missing from the attestation document, or if the expected PCRs don't match the values embedded in the doc
pub fn validate_expected_pcrs<T: PCRProvider>(
    attestation_doc: &AttestationDoc,
    expected_pcrs: &T,
) -> AttestationDocResult<()> {
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

    let same_pcrs = expected_pcrs.eq(&received_pcrs);
    true_or_invalid(
        same_pcrs,
        AttestationDocError::UnexpectedPCRs(expected_pcrs.to_string(), received_pcrs.to_string()),
    )
}

pub(super) fn validate_cose_signature(
    signing_cert_public_key: &PKey<Public>,
    cose_sign_1_decoded: &CoseSign1,
) -> AttestationDocResult<()> {
    true_or_invalid(
        cose_sign_1_decoded
            .verify_signature::<aws_nitro_enclaves_cose::crypto::Openssl>(signing_cert_public_key)
            .map_err(|err| AttestationDocError::Cose(err.to_string()))?,
        AttestationDocError::InvalidCoseSignature,
    )
}

pub(super) fn validate_expected_challenge(
    attestation_doc: &AttestationDoc,
    expected_challenge: &[u8],
) -> AttestationDocResult<()> {
    let embedded_challenge = attestation_doc
        .user_data
        .as_ref()
        .ok_or(AttestationDocError::MissingUserData)?;
    true_or_invalid(
        embedded_challenge == expected_challenge,
        AttestationDocError::UserDataMismatch,
    )
}

/// Derived from [AWS attestation process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md)
pub(super) fn validate_attestation_document_structure(
    attestation_document: &AttestationDoc,
) -> AttestationDocResult<()> {
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
    true_or_invalid(valid_structure_check, AttestationDocError::DocStructure)
}

pub(super) fn decode_attestation_document(
    cose_sign_1_bytes: &[u8],
) -> AttestationDocResult<(CoseSign1, AttestationDoc)> {
    let cose_sign_1_decoded: CoseSign1 = serde_cbor::from_slice(cose_sign_1_bytes)?;
    let cbor = cose_sign_1_decoded
        .get_payload::<aws_nitro_enclaves_cose::crypto::Openssl>(None)
        .map_err(|err| AttestationDocError::Cose(err.to_string()))?;
    Ok((cose_sign_1_decoded, serde_cbor::from_slice(&cbor)?))
}
