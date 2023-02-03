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
    fn try_from(value: &Curve) -> Result<Self, Self::Error> {
        compare_curve!(Self::Secp256r1, value);
        compare_curve!(Self::Secp384r1, value);
        compare_curve!(Self::Secp521r1, value);
        return Err(());
    }
}
