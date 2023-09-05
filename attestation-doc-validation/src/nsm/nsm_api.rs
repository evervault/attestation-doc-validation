use super::error::{NsmError, NsmResult};
use serde::{Deserialize, Serialize};
/// Collection of structs and trait impls to act as a compatability layer with the AWS NSM crates
use serde_bytes::ByteBuf;
use serde_cbor::{from_slice, to_vec};
use std::collections::BTreeMap;

// Compatability for [aws_nitro_enclaves_nsm_api](https://docs.rs/aws-nitro-enclaves-nsm-api/0.2.1/aws_nitro_enclaves_nsm_api/index.html)

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum Digest {
    /// SHA256
    SHA256,
    /// SHA384
    SHA384,
    /// SHA512
    SHA512,
}

/// An attestation response.  This is also used for sealing
/// data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AttestationDoc {
    /// Issuing NSM ID
    pub module_id: String,

    /// The digest function used for calculating the register values
    /// Can be: "SHA256" | "SHA512"
    pub digest: Digest,

    /// UTC time when document was created expressed as milliseconds since Unix Epoch
    pub timestamp: u64,

    /// Map of all locked PCRs at the moment the attestation document was generated
    pub pcrs: BTreeMap<usize, ByteBuf>,

    /// The infrastucture certificate used to sign the document, DER encoded
    pub certificate: ByteBuf,
    /// Issuing CA bundle for infrastructure certificate
    pub cabundle: Vec<ByteBuf>,

    /// An optional DER-encoded key the attestation consumer can use to encrypt data with
    pub public_key: Option<ByteBuf>,

    /// Additional signed user data, as defined by protocol.
    pub user_data: Option<ByteBuf>,

    /// An optional cryptographic nonce provided by the attestation consumer as a proof of
    /// authenticity.
    pub nonce: Option<ByteBuf>,
}

impl AttestationDoc {
    /// Creates a new `AttestationDoc`.
    ///
    /// # Arguments
    ///
    /// * `module_id`: a String representing the name of the `NitroSecureModule`
    /// * digest: `nsm_io::Digest` that describes what the `PlatformConfigurationRegisters`
    ///           contain
    /// * pcrs: `BTreeMap` containing the index to PCR value
    /// * certificate: the serialized certificate that will be used to sign this `AttestationDoc`
    /// * cabundle: the serialized set of certificates up to the root of trust certificate that
    ///             emitted `certificate`
    /// * `user_data`: optional user definted data included in the `AttestationDoc`
    /// * nonce: optional cryptographic nonce that will be included in the `AttestationDoc`
    /// * `public_key`: optional DER-encoded public key that will be included in the `AttestationDoc`
    #[allow(clippy::too_many_arguments)]
    /// Creates a new AttestationDoc struct with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `module_id` - A String representing the ID of the module.
    /// * `digest` - A Digest representing the hash of the module.
    /// * `timestamp` - An unsigned 64-bit integer representing the timestamp of the attestation.
    /// * `pcrs` - A BTreeMap of unsigned integers to byte vectors representing the values of the platform configuration registers.
    /// * `certificate` - A byte vector representing the certificate used for the attestation.
    /// * `cabundle` - A vector of byte vectors representing the chain of trust for the certificate.
    /// * `user_data` - An optional byte vector representing user data to include in the attestation.
    /// * `nonce` - An optional byte vector representing a nonce to include in the attestation.
    /// * `public_key` - An optional byte vector representing the public key used for the attestation.
    pub fn new(
        module_id: String,
        digest: Digest,
        timestamp: u64,
        pcrs: BTreeMap<usize, Vec<u8>>,
        certificate: Vec<u8>,
        cabundle: Vec<Vec<u8>>,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Self {
        let mut pcrs_serialized = BTreeMap::new();

        for (i, pcr) in pcrs {
            let pcr = ByteBuf::from(pcr);
            pcrs_serialized.insert(i, pcr);
        }

        let cabundle_serialized = cabundle.into_iter().map(ByteBuf::from).collect();

        AttestationDoc {
            module_id,
            digest,
            timestamp,
            pcrs: pcrs_serialized,
            cabundle: cabundle_serialized,
            certificate: ByteBuf::from(certificate),
            user_data: user_data.map(ByteBuf::from),
            nonce: nonce.map(ByteBuf::from),
            public_key: public_key.map(ByteBuf::from),
        }
    }

    /// Helper function that converts an `AttestationDoc` structure to its CBOR representation
    pub fn to_binary(&self) -> Vec<u8> {
        // This should not fail
        to_vec(self).unwrap()
    }

    /// Helper function that parses a CBOR representation of an `AttestationDoc` and creates the
    /// structure from it, if possible.
    pub fn from_binary(bin: &[u8]) -> NsmResult<Self> {
        from_slice(bin).map_err(NsmError::Cbor)
    }
}
