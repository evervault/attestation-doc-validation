use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;
use serde_cbor::Value as CborValue;

use super::error::{NsmError, NsmResult};
use super::header_map::{map_to_empty_or_serialized, HeaderMap};
use aws_nitro_enclaves_cose::crypto::{Hash, SigningPrivateKey, SigningPublicKey};

///  Implementation of the Sig_structure as defined in
///  [RFC8152](https://tools.ietf.org/html/rfc8152#section-4.4).
///
///  In order to create a signature, a well-defined byte stream is needed.
///  The Sig_structure is used to create the canonical form.  This signing
///  and verification process takes in the body information (COSE_Sign or
///  COSE_Sign1), the signer information (COSE_Signature), and the
///  application data (external source).  A Sig_structure is a CBOR array.
///  The fields of the Sig_structure in order are:
///
///  1.  A text string identifying the context of the signature.  The
///      context string is:
///
///         "Signature" for signatures using the COSE_Signature structure.
///
///         "Signature1" for signatures using the COSE_Sign1 structure.
///
///         "CounterSignature" for signatures used as counter signature
///         attributes.
///
///  2.  The protected attributes from the body structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.
///
///  3.  The protected attributes from the signer structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.  This field is omitted for the COSE_Sign1
///      signature structure.
///
///  4.  The protected attributes from the application encoded in a bstr
///      type.  If this field is not supplied, it defaults to a zero-
///      length binary string.  (See Section 4.3 for application guidance
///      on constructing this field.)
///
///  5.  The payload to be signed encoded in a bstr type.  The payload is
///      placed here independent of how it is transported.
///
///  Note: A struct serializes to a map, while a tuple serializes to an array,
///  which is why this struct is actually a tuple
///  Note: This structure only needs to be serializable, since it's
///  used for generating a signature and not transported anywhere. Both
///  sides need to generate it independently.
#[derive(Debug, Clone, Serialize)]
pub struct SigStructure(
    /// context: "Signature" / "Signature1" / "CounterSignature"
    String,
    /// body_protected : empty_or_serialized_map,
    ByteBuf,
    /// ? sign_protected : empty_or_serialized_map,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    Option<ByteBuf>,
    /// external_aad : bstr,
    ByteBuf,
    /// payload : bstr
    ByteBuf,
);

impl SigStructure {
    /// Takes the protected field of the COSE_Sign object and a raw slice of bytes as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1(body_protected: &[u8], payload: &[u8]) -> NsmResult<Self> {
        Ok(SigStructure(
            String::from("Signature1"),
            ByteBuf::from(body_protected.to_vec()),
            None,
            ByteBuf::new(),
            ByteBuf::from(payload.to_vec()),
        ))
    }

    /// Takes the protected field of the COSE_Sign object and a CborValue as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1_cbor_value(body_protected: &[u8], payload: &CborValue) -> NsmResult<Self> {
        Self::new_sign1(body_protected, &serde_cbor::to_vec(payload)?)
    }

    /// Serializes the SigStructure to . We don't care about deserialization, since
    /// both sides are supposed to compute the SigStructure and compare.
    pub fn as_bytes(&self) -> NsmResult<Vec<u8>> {
        Ok(serde_cbor::to_vec(self)?)
    }
}

///  Implementation of the COSE_Sign1 structure as defined in
///  [RFC8152](https://tools.ietf.org/html/rfc8152#section-4.2).
///
///  The COSE_Sign1 signature structure is used when only one signature is
///  going to be placed on a message.  The parameters dealing with the
///  content and the signature are placed in the same pair of buckets
///  rather than having the separation of COSE_Sign.
///
///  The structure can be encoded as either tagged or untagged depending
///  on the context it will be used in.  A tagged COSE_Sign1 structure is
///  identified by the CBOR tag 18.  The CDDL fragment that represents
///  this is:
///
///  COSE_Sign1_Tagged = #6.18(COSE_Sign1)
///
///  The CBOR object that carries the body, the signature, and the
///  information about the body and signature is called the COSE_Sign1
///  structure.  Examples of COSE_Sign1 messages can be found in
///  Appendix C.2.
///
///  The COSE_Sign1 structure is a CBOR array.  The fields of the array in
///  order are:
///
///  protected:  This is as described in Section 3.
///
///  unprotected:  This is as described in Section 3.
///
///  payload:  This is as described in Section 4.1.
///
///  signature:  This field contains the computed signature value.  The
///     type of the field is a bstr.
///
///  The CDDL fragment that represents the above text for COSE_Sign1
///  follows.
///
///  COSE_Sign1 = [
///      Headers,
///      payload : bstr / nil,
///      signature : bstr
///  ]
///
///  # https://tools.ietf.org/html/rfc8152#section-3
///
///  Headers = (
///       protected : empty_or_serialized_map,
///       unprotected : header_map
///   )
///
///   header_map = {
///       Generic_Headers,
///       * label => values
///   }
///
///   empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
///
///   Generic_Headers = (
///       ? 1 => int / tstr,  ; algorithm identifier
///       ? 2 => [+label],    ; criticality
///       ? 3 => tstr / int,  ; content type
///       ? 4 => bstr,        ; key identifier
///       ? 5 => bstr,        ; IV
///       ? 6 => bstr,        ; Partial IV
///       ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
///   )
///
///   Note: Currently, the structures are not tagged, since it isn't required by
///   the spec and the only way to achieve this is to add the token at the
///   start of the serialized object, since the serde_cbor library doesn't
///   support custom tags.
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    /// protected: empty_or_serialized_map,
    protected: ByteBuf,
    /// unprotected: HeaderMap
    unprotected: HeaderMap,
    /// payload: bstr
    /// The spec allows payload to be nil and transported separately, but it's not useful at the
    /// moment, so this is just a ByteBuf for simplicity.
    payload: ByteBuf,
    /// signature: bstr
    signature: ByteBuf,
}

impl Serialize for CoseSign1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.protected)?;
        seq.serialize_element(&self.unprotected)?;
        seq.serialize_element(&self.payload)?;
        seq.serialize_element(&self.signature)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CoseSign1 {
    fn deserialize<D>(deserializer: D) -> Result<CoseSign1, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{Error, SeqAccess, Visitor};
        use std::fmt;

        struct CoseSign1Visitor;

        impl<'de> Visitor<'de> for CoseSign1Visitor {
            type Value = CoseSign1;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a possibly tagged CoseSign1 structure")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<CoseSign1, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // This is the untagged version
                let protected = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("protected")),
                };

                let unprotected = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("unprotected")),
                };
                let payload = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("payload")),
                };
                let signature = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("signature")),
                };

                Ok(CoseSign1 {
                    protected,
                    unprotected,
                    payload,
                    signature,
                })
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<CoseSign1, D::Error>
            where
                D: Deserializer<'de>,
            {
                // This is the tagged version: we ignore the tag part, and just go into it
                deserializer.deserialize_seq(CoseSign1Visitor)
            }
        }

        deserializer.deserialize_any(CoseSign1Visitor)
    }
}

impl CoseSign1 {
    /// Creates a CoseSign1 structure from the given payload and some unprotected data in the form
    /// of a HeaderMap. Signs the content with the given key using the recommedations from the spec
    /// and sets the protected part of the document to reflect the algorithm used.
    pub fn new<H: Hash>(
        payload: &[u8],
        unprotected: &HeaderMap,
        key: &dyn SigningPrivateKey,
    ) -> NsmResult<Self> {
        let (sig_alg, _) = key.get_parameters()?;

        let mut protected = HeaderMap::new();
        protected.insert(1.into(), (sig_alg as i8).into());

        Self::new_with_protected::<H>(payload, &protected, unprotected, key)
    }

    /// Creates a CoseSign1 structure from the given payload and some protected and unprotected data
    /// in the form of a HeaderMap. Signs the content with the given key using the recommedations
    /// from the spec and sets the algorithm used into the protected header.
    pub fn new_with_protected<H: Hash>(
        payload: &[u8],
        protected: &HeaderMap,
        unprotected: &HeaderMap,
        key: &dyn SigningPrivateKey,
    ) -> NsmResult<Self> {
        let (_, digest) = key.get_parameters()?;

        // Create the SigStruct to sign
        let protected_bytes = map_to_empty_or_serialized(protected)?;

        let sig_structure = SigStructure::new_sign1(&protected_bytes, payload)?;

        let struct_digest = H::hash(digest, &sig_structure.as_bytes()?)
            .map_err(|e| NsmError::SignatureError(Box::new(e)))?;

        let signature = key.sign(struct_digest.as_ref())?;

        Ok(CoseSign1 {
            protected: ByteBuf::from(protected_bytes),
            unprotected: unprotected.clone(),
            payload: ByteBuf::from(payload.to_vec()),
            signature: ByteBuf::from(signature),
        })
    }

    /// This function deserializes the structure, but doesn't check the contents for correctness
    /// at all. Accepts untagged structures or structures with tag 18.
    pub fn from_bytes(bytes: &[u8]) -> NsmResult<Self> {
        let cosesign1: serde_cbor::tags::Tagged<Self> = serde_cbor::from_slice(bytes)?;

        match cosesign1.tag {
            None | Some(18) => (),
            Some(tag) => return Err(NsmError::TagError(Some(tag))),
        }
        let protected = cosesign1.value.protected.as_slice();
        let _: HeaderMap = serde_cbor::from_slice(protected)?;
        Ok(cosesign1.value)
    }

    /// This checks the signature included in the structure against the given public key and
    /// returns true if the signature matches the given key.
    pub fn verify_signature<H: Hash>(&self, key: &dyn SigningPublicKey) -> NsmResult<bool> {
        // In theory, the digest itself does not have to match the curve, however,
        // this is the recommendation and the spec does not even provide a way to specify
        // another digest type, so, signatures will fail if this is done differently
        let (signature_alg, digest) = key.get_parameters()?;

        // The spec reads as follows:
        //    alg:  This parameter is used to indicate the algorithm used for the
        //        security processing.  This parameter MUST be authenticated where
        //        the ability to do so exists.  This support is provided by AEAD
        //        algorithms or construction (COSE_Sign, COSE_Sign0, COSE_Mac, and
        //        COSE_Mac0).  This authentication can be done either by placing the
        //        header in the protected header bucket or as part of the externally
        //        supplied data.  The value is taken from the "COSE Algorithms"
        //        registry (see Section 16.4).
        // TODO: Currently this only validates the case where the Signature Algorithm is included
        // in the protected headers. To be compatible with other implementations this should be
        // more flexible, as stated in the spec.
        let protected: HeaderMap = HeaderMap::from_bytes(&self.protected)?;

        if let Some(protected_signature_alg_val) = protected.get(&CborValue::Integer(1)) {
            let protected_signature_alg = match protected_signature_alg_val {
                CborValue::Integer(val) => val,
                _ => {
                    return Err(NsmError::SpecificationError(
                        "Protected Header contains invalid Signature Algorithm specification"
                            .to_string(),
                    ))
                }
            };
            if protected_signature_alg != &(signature_alg as i8 as i128) {
                // The key doesn't match the one specified in the HeaderMap, so this fails
                // signature verification immediately.
                return Ok(false);
            }
        } else {
            return Err(NsmError::SpecificationError(
                "Protected Header does not contain a valid Signature Algorithm specification"
                    .to_string(),
            ));
        }

        let sig_structure = SigStructure::new_sign1(&self.protected, &self.payload)?;

        let struct_digest = H::hash(digest, &sig_structure.as_bytes()?)
            .map_err(|e| NsmError::SignatureError(Box::new(e)))?;

        Ok(key.verify(struct_digest.as_ref(), &self.signature)?)
    }

    /// This gets the `payload` of the document. If `key` is provided, it only gets the payload
    /// if the signature is correctly verified, otherwise returns
    /// `Err(NsmError::UnverifiedSignature)`.
    pub fn get_payload<H: Hash>(&self, key: Option<&dyn SigningPublicKey>) -> NsmResult<Vec<u8>> {
        if key.is_some() && !self.verify_signature::<H>(key.unwrap())? {
            return Err(NsmError::UnverifiedSignature);
        }
        Ok(self.payload.to_vec())
    }
}
