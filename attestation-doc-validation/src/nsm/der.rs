use der::asn1::{BitString, Null, ObjectIdentifier, OctetString, UIntRef};
use der::{Choice, Sequence};

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FieldId<'a> {
    pub field_type: ObjectIdentifier,
    pub parameters: UIntRef<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Curve {
    pub a: OctetString,
    pub b: OctetString,
    pub seed: BitString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpecifiedCurve<'a> {
    pub version: u8,
    pub field_id: FieldId<'a>,
    pub curve: Curve,
    pub base: OctetString,
    pub order: UIntRef<'a>,
    pub cofactor: u8,
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum EcParameters<'a> {
    NamedCurve(ObjectIdentifier),
    ImplicitCurve(Null),
    SpecifiedCurve(SpecifiedCurve<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: EcParameters<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitString,
}

/// Converts a hexadecimal string into an OctetString.
///
/// # Arguments
///
/// * `hex_str` - a string slice that contains the hexadecimal representation of the octet string.
///
/// # Returns
///
/// * A `Result<OctetString, hex::FromHexError>` where the success variant contains the OctetString decoded from the hexadecimal string,
/// and the error variant indicates that the string could not be parsed as hexadecimal.
///
/// # Examples
///
/// ```
/// use my_crate::OctetString;
///
/// let hex_str = "68656c6c6f20776f726c64"; // "hello world" in hex
/// let octet_string = OctetString::from_hex(hex_str).unwrap();
/// assert_eq!(octet_string.to_string(), "hello world");
/// ```
pub fn octet_string_from_hex(hex_str: &str) -> Result<OctetString, hex::FromHexError> {
    let octet_string = OctetString::new(hex::decode(hex_str)?).unwrap();
    Ok(octet_string)
}

pub enum SupportedEcCurve {
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

impl SupportedEcCurve {
    /// Returns a `Curve` object based on the selected elliptic curve. The available options are `Secp256r1`, `Secp384r1`, and `Secp521r1`, each with their respective parameters sourced from official standards. The `Curve` object contains the `a` and `b` parameters of the curve, as well as a `BitString` seed value.
    fn to_curve(&self) -> Curve {
        match self {
            // Parameters from: https://neuromancer.sk/std/secg/secp256r1#
            Self::Secp256r1 => {
                let seed = hex::decode("C49D360886E704936A6678E1139D26B7819F7E90").unwrap();
                Curve {
                    a: octet_string_from_hex(
                        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                    )
                    .unwrap(),
                    b: octet_string_from_hex(
                        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                    )
                    .unwrap(),
                    seed: BitString::from_bytes(&seed).unwrap(),
                }
            }
            // Parameters from: https://neuromancer.sk/std/secg/secp384r1
            Self::Secp384r1 => {
                let seed = hex::decode("A335926AA319A27A1D00896A6773A4827ACDAC73").unwrap();
                Curve {
                  a: octet_string_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC").unwrap(),
                  b: octet_string_from_hex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF").unwrap(),
                  seed: BitString::from_bytes(&seed).unwrap(),
                }
            }
            // Parameters from: https://neuromancer.sk/std/secg/secp521r1#
            Self::Secp521r1 => {
                let seed = hex::decode("D09E8800291CB85396CC6717393284AAA0DA64BA").unwrap();
                Curve {
                  a: octet_string_from_hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC").unwrap(),
                  b: octet_string_from_hex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00").unwrap(),
                  seed: BitString::from_bytes(&seed).unwrap(),
                }
            }
        }
    }
}

macro_rules! compare_curve {
    ($curve_enum:expr, $val:ident) => {
        let supported_curve = $curve_enum;
        if supported_curve.to_curve() == *$val {
            return Ok(supported_curve);
        }
    };
}

impl std::convert::TryFrom<&Curve> for SupportedEcCurve {
    type Error = ();
    /// Attempts to convert the given reference to a Curve into Self, the concrete type implementing TryFrom<Curve>.
    ///
    /// If the given reference to a Curve is not one of the supported curves - Secp256r1, Secp384r1 or Secp521r1 - the function will return an error.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to a Curve that needs to be converted to Self.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - If `value` is successfully converted to Self.
    /// * `Err(())` - If `value` is not one of the supported curves.
    fn try_from(value: &Curve) -> Result<Self, Self::Error> {
        compare_curve!(Self::Secp256r1, value);
        compare_curve!(Self::Secp384r1, value);
        compare_curve!(Self::Secp521r1, value);
        Err(())
    }
}
