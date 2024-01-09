use crate::{
    Certificate, EccP256CurvePoint, EccP256CurvePointUncompressedP256, EccP384CurvePoint,
    EccP384CurvePointUncompressedP384, EcdsaP256Signature, EcdsaP384Signature, EcsigP256Signature,
    EncodeError, HeaderInfo, Ieee1609Dot2Content, Ieee1609Dot2Data, Packet, PublicVerificationKey,
    Signature, SignedData, SignerIdentifier, Uint8, VerificationKeyIndicator,
};
use ecdsa::{
    elliptic_curve::{point::DecompressPoint, subtle::Choice},
    signature::Verifier,
    VerifyingKey,
};
use num::Integer;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcKey, EcPoint},
    ecdsa::EcdsaSig,
};
use p256::{AffinePoint as P256AffinePoint, EncodedPoint as P256EncodedPoint, NistP256};
use p384::{AffinePoint as P384AffinePoint, EncodedPoint as P384EncodedPoint, NistP384};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256, Sha384};
use sm2::{dsa::VerifyingKey as Sm2VerifyingKey, AffinePoint as Sm2AffinePoint};
use sm3::Sm3;

pub trait Validate {
    ///  The `Validate` trait exposes a `validate` method that checks whether the implementing type is valid.
    /// `validate` runs the following checks:
    /// - The signature of a secured packet matches the certificate contained in the IEEE 1609.2 header
    /// - *WIP* The packet conforms to IEEE 1609.2 2016
    /// - *WIP* The packet conforms to ETSI TS 103 097 V2.1.1
    /// #### Returns
    /// - `Ok(ValidationResult::Success)` if all checks passed successful
    /// - `Ok(ValidationResult::Failure { reason: String })` if a check failed
    /// - `Ok(ValidationResult::NotApplicable { info: &'static str })` if no validation checks were run
    /// - `Err(ValidationError)` if an internal error occured during validation
    fn validate(&self) -> Result<ValidationResult, ValidationError>;
}

#[derive(Debug, PartialEq)]
pub enum ValidationResult {
    Success,
    Failure { reason: String },
    NotApplicable { info: &'static str },
}

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    InvalidInput(String),
    Unsupported(String),
    ReencodingError(String),
}

impl From<EncodeError> for ValidationError {
    fn from(value: EncodeError) -> Self {
        ValidationError::ReencodingError(value.message().into())
    }
}

impl Validate for Ieee1609Dot2Data<'_> {
    fn validate(&self) -> Result<ValidationResult, ValidationError> {
        if self.protocol_version != Uint8(3) {
            return Ok(ValidationResult::Failure {
                reason: format!(
                    "Protocol version of IEEE 1609.2 data must be 3. Found {}",
                    &self.protocol_version.0
                ),
            });
        }
        self.content.validate()
    }
}

impl Validate for Ieee1609Dot2Content<'_> {
    fn validate(&self) -> Result<ValidationResult, ValidationError> {
        match self {
            Ieee1609Dot2Content::UnsecuredData(_) => todo!(),
            Ieee1609Dot2Content::SignedData(s) => s.validate(),
            Ieee1609Dot2Content::EncryptedData(_) => todo!(),
            Ieee1609Dot2Content::SignedCertificateRequest(_) => todo!(),
            Ieee1609Dot2Content::SignedX509CertificateRequest(_) => todo!(),
        }
    }
}

macro_rules! validate_and_continue {
    ($candidate:expr) => {
        match $candidate.validate()? {
            ValidationResult::Success => (),
            ValidationResult::NotApplicable { .. } => (),
            failure => return Ok(failure),
        }
    };
}

impl Validate for Packet<'_> {
    fn validate(&self) -> Result<ValidationResult, ValidationError> {
        match self {
            Packet::Unsecured { .. } => Ok(ValidationResult::NotApplicable {
                info: "Unsecured GeoNetworking packets are not validated.",
            }),
            Packet::Secured { secured, .. } => secured.validate(),
        }
    }
}

impl Validate for SignedData<'_> {
    fn validate(&self) -> Result<ValidationResult, ValidationError> {
        let data = self.tbs_data.raw;

        validate_and_continue!(&self.tbs_data.header_info);
        validate_and_continue!(&self.signer);

        let (verifying_key, encoded_certificate) = match &self.signer {
            SignerIdentifier::Certificate(c) => {
                let certificate = c.0.get(0).ok_or(ValidationError::InvalidInput(
                    "Certificate list is empty!".into(),
                ))?;
                (&certificate.to_be_signed.verify_key_indicator, certificate.raw)
            }
            SignerIdentifier::Digest(_) => {
                // TODO: Support digest lookup
                return Err(ValidationError::Unsupported("Certificate retrieval by digest is unsupported!".into()))
            },
            SignerIdentifier::RsSelf(_) => {
                return Ok(ValidationResult::Failure {
                    reason: "Violates ETSI TS 103 097: Signer Identifier must be of type Digest or Certificate!".into(),
                })
            }
        };

        match (&self.signature, verifying_key) {
            (
                Signature::EcdsaNistP256Signature(EcdsaP256Signature { r_sig, s_sig }),
                VerificationKeyIndicator::VerificationKey(PublicVerificationKey::EcdsaNistP256(
                    key,
                )),
            ) => ecdsa_nist_p256(r_sig, s_sig, key, data, Some(encoded_certificate)),
            (
                Signature::EcdsaBrainpoolP256r1Signature(EcdsaP256Signature { r_sig, s_sig }),
                VerificationKeyIndicator::VerificationKey(
                    PublicVerificationKey::EcdsaBrainpoolP256r1(key),
                ),
            ) => ecdsa_brainpool_p256_r1(r_sig, s_sig, key, data, Some(encoded_certificate)),
            (
                Signature::EcdsaBrainpoolP384r1Signature(EcdsaP384Signature { r_sig, s_sig }),
                VerificationKeyIndicator::VerificationKey(
                    PublicVerificationKey::EcdsaBrainpoolP384r1(key),
                ),
            ) => ecdsa_brainpool_p384_r1(r_sig, s_sig, key, data, Some(encoded_certificate)),
            (
                Signature::EcdsaNistP384Signature(EcdsaP384Signature { r_sig, s_sig }),
                VerificationKeyIndicator::VerificationKey(PublicVerificationKey::EcdsaNistP384(
                    key,
                )),
            ) => ecdsa_nist_p384(r_sig, s_sig, key, data, Some(encoded_certificate)),
            (
                Signature::Sm2Signature(EcsigP256Signature { r_sig, s_sig }),
                VerificationKeyIndicator::VerificationKey(PublicVerificationKey::EcsigSm2(key)),
            ) => ecdsa_sm2(r_sig, s_sig, key, data, Some(encoded_certificate)),
            _ => Ok(ValidationResult::Failure {
                reason: format!(
                    "Elliptic curve mismatch between signature {:?} and verifying key {:?}",
                    self.signature, verifying_key
                ),
            }),
        }
    }
}

impl Validate for SignerIdentifier<'_> {
    fn validate(&self) -> Result<ValidationResult, ValidationError> {
        match self {
            SignerIdentifier::Digest(_) => Ok(ValidationResult::Success),
            SignerIdentifier::Certificate(c) if c.0.len() == 1 => Ok(ValidationResult::Success),
            SignerIdentifier::Certificate(_) => Ok(ValidationResult::Failure {
                reason: "Exactly one certificate must be included!".into(),
            }),
            SignerIdentifier::RsSelf(_) => Ok(ValidationResult::Failure {
                reason: "Violates ETSI TS 103 097: Signer Identifier must be of type Digest or Certificate!".into(),
            }),
        }
    }
}

impl Validate for Certificate<'_> {
    fn validate(&self) -> Result<ValidationResult, ValidationError> {
        Ok(ValidationResult::Success)
    }
}

impl Validate for HeaderInfo<'_> {
    fn validate(&self) -> Result<ValidationResult, ValidationError> {
        match (self.expiry_time.as_ref(), self.generation_time.as_ref()) {
            (Some(exp), Some(gen)) if gen <= exp => {
                return Ok(ValidationResult::Failure {
                    reason: "Expiry timestamp is older than generation timestamp.".into(),
                })
            }
            (_, None) => {
                return Ok(ValidationResult::Failure {
                    reason: "Generation time must be present!".into(),
                })
            }
            _ => (),
        };
        if self.p2pcd_learning_request.is_some() {
            return Ok(ValidationResult::Failure {
                reason: "P2PCD Learning Request must be absent!".into(),
            });
        }
        if self.missing_crl_identifier.is_some() {
            return Ok(ValidationResult::Failure {
                reason: "Missing CRL Identifier must be absent!".into(),
            });
        }
        Ok(ValidationResult::Success)
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

fn sm3(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sm3::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

fn ecdsa_brainpool_p256_r1(
    r: &EccP256CurvePoint,
    s: &[u8],
    curve_point: &EccP256CurvePoint,
    msg: &[u8],
    encoded_certificate: Option<&[u8]>,
) -> Result<ValidationResult, ValidationError> {
    let mut ctx = BigNumContext::new().unwrap();
    let curve = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::BRAINPOOL_P256R1).unwrap();
    let point = match curve_point {
        EccP256CurvePoint::CompressedY0(x) => {
            EcPoint::from_bytes(&curve, &[vec![0x02], x.to_vec()].concat(), &mut ctx).unwrap()
        }
        EccP256CurvePoint::CompressedY1(x) => {
            EcPoint::from_bytes(&curve, &[vec![0x03], x.to_vec()].concat(), &mut ctx).unwrap()
        }
        _ => panic!("Verifying key must be indicated in compressed-y, or uncompressed form!",),
    };
    let verifying_key = EcKey::from_public_key(&curve, &point).unwrap();
    verifying_key.check_key().unwrap();
    let r_unwrapped = match r {
        EccP256CurvePoint::XOnly(x) => x,
        EccP256CurvePoint::Fill(_) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP256CurvePoint::CompressedY0(x) => x,
        EccP256CurvePoint::CompressedY1(x) => x,
        EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, .. }) => x,
    };
    let signature = EcdsaSig::from_private_components(
        BigNum::from_slice(r_unwrapped).unwrap(),
        BigNum::from_slice(s).unwrap(),
    )
    .unwrap();
    match signature.verify(
        &[sha256(msg), sha256(encoded_certificate.unwrap_or(&[]))].concat(),
        &verifying_key,
    ) {
        Ok(true) => Ok(ValidationResult::Success),
        Ok(false) => Ok(ValidationResult::Failure {
            reason: "Signature verification failed!".into(),
        }),
        Err(e) => Err(ValidationError::InvalidInput(e.to_string())),
    }
}

fn ecdsa_brainpool_p384_r1(
    r: &EccP384CurvePoint,
    s: &[u8],
    curve_point: &EccP384CurvePoint,
    msg: &[u8],
    encoded_certificate: Option<&[u8]>,
) -> Result<ValidationResult, ValidationError> {
    let mut ctx = BigNumContext::new().unwrap();
    let curve = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::BRAINPOOL_P384R1).unwrap();
    let point = match curve_point {
        EccP384CurvePoint::CompressedY0(x) => {
            EcPoint::from_bytes(&curve, &[vec![0x02], x.to_vec()].concat(), &mut ctx).unwrap()
        }
        EccP384CurvePoint::CompressedY1(x) => {
            EcPoint::from_bytes(&curve, &[vec![0x03], x.to_vec()].concat(), &mut ctx).unwrap()
        }
        _ => panic!("Verifying key must be indicated in compressed-y, or uncompressed form!",),
    };
    let verifying_key = EcKey::from_public_key(&curve, &point).unwrap();
    verifying_key.check_key().unwrap();
    let r_unwrapped = match r {
        EccP384CurvePoint::XOnly(x) => x,
        EccP384CurvePoint::Fill(_) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP384CurvePoint::CompressedY0(x) => x,
        EccP384CurvePoint::CompressedY1(x) => x,
        EccP384CurvePoint::UncompressedP384(EccP384CurvePointUncompressedP384 { x, .. }) => x,
    };
    let signature = EcdsaSig::from_private_components(
        BigNum::from_slice(r_unwrapped).unwrap(),
        BigNum::from_slice(s).unwrap(),
    )
    .unwrap();
    match signature.verify(
        &[sha384(msg), sha384(encoded_certificate.unwrap_or(&[]))].concat(),
        &verifying_key,
    ) {
        Ok(true) => Ok(ValidationResult::Success),
        Ok(false) => Ok(ValidationResult::Failure {
            reason: "Signature verification failed!".into(),
        }),
        Err(e) => Err(ValidationError::InvalidInput(e.to_string())),
    }
}

fn ecdsa_nist_p256(
    r: &EccP256CurvePoint,
    s: &[u8],
    curve_point: &EccP256CurvePoint,
    msg: &[u8],
    encoded_certificate: Option<&[u8]>,
) -> Result<ValidationResult, ValidationError> {
    let r_unwrapped = match r {
        EccP256CurvePoint::XOnly(x) => x,
        EccP256CurvePoint::Fill(_) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP256CurvePoint::CompressedY0(x) => x,
        EccP256CurvePoint::CompressedY1(x) => x,
        EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, .. }) => x,
    };

    let signature = ecdsa::Signature::<NistP256>::from_scalars(
        *GenericArray::from_slice(r_unwrapped),
        *GenericArray::from_slice(s),
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP256CurvePoint::CompressedY0(x) => {
            let affine = P256AffinePoint::decompress((*x).into(), Choice::from(0)).unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::CompressedY1(x) => {
            let affine = P256AffinePoint::decompress((*x).into(), Choice::from(1)).unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, y }) => {
            let encoded =
                P256EncodedPoint::from_affine_coordinates((*x).into(), (*y).into(), false);
            VerifyingKey::from_encoded_point(&encoded)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        _ => Err(ValidationError::InvalidInput(
            "Verifying key must be indicated in compressed-y, or uncompressed form!".into(),
        )),
    }?;

    match verifying_key.verify(
        &[sha256(msg), sha256(encoded_certificate.unwrap_or(&[]))].concat(),
        &signature,
    ) {
        Ok(_) => Ok(ValidationResult::Success),
        Err(e) => Ok(ValidationResult::Failure {
            reason: format!("{e:?}"),
        }),
    }
}

fn ecdsa_nist_p384(
    r: &EccP384CurvePoint,
    s: &[u8],
    curve_point: &EccP384CurvePoint,
    msg: &[u8],
    encoded_certificate: Option<&[u8]>,
) -> Result<ValidationResult, ValidationError> {
    let r_unwrapped = match r {
        EccP384CurvePoint::XOnly(x) => x,
        EccP384CurvePoint::Fill(_) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP384CurvePoint::CompressedY0(x) => x,
        EccP384CurvePoint::CompressedY1(x) => x,
        EccP384CurvePoint::UncompressedP384(EccP384CurvePointUncompressedP384 { x, .. }) => x,
    };

    let signature = ecdsa::Signature::<NistP384>::from_scalars(
        *GenericArray::from_slice(r_unwrapped),
        *GenericArray::from_slice(s),
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP384CurvePoint::CompressedY0(x) => {
            let affine = P384AffinePoint::decompress((*x).into(), Choice::from(0)).unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP384CurvePoint::CompressedY1(x) => {
            let affine = P384AffinePoint::decompress((*x).into(), Choice::from(1)).unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP384CurvePoint::UncompressedP384(EccP384CurvePointUncompressedP384 { x, y }) => {
            let encoded =
                P384EncodedPoint::from_affine_coordinates((*x).into(), (*y).into(), false);
            VerifyingKey::from_encoded_point(&encoded)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        _ => Err(ValidationError::InvalidInput(
            "Verifying key must be indicated in compressed-y, or uncompressed form!".into(),
        )),
    }?;

    match verifying_key.verify(
        &[sha384(msg), sha384(encoded_certificate.unwrap_or(&[]))].concat(),
        &signature,
    ) {
        Ok(_) => Ok(ValidationResult::Success),
        Err(e) => Ok(ValidationResult::Failure {
            reason: format!("{e:?}"),
        }),
    }
}

fn ecdsa_sm2(
    r: &[u8],
    s: &[u8],
    curve_point: &EccP256CurvePoint,
    msg: &[u8],
    encoded_certificate: Option<&[u8]>,
) -> Result<ValidationResult, ValidationError> {
    let signature = sm2::dsa::Signature::from_scalars(
        *GenericArray::from_slice(r),
        *GenericArray::from_slice(s),
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP256CurvePoint::CompressedY0(x) => {
            let affine = Sm2AffinePoint::decompress((*x).into(), Choice::from(0)).unwrap();
            Sm2VerifyingKey::from_affine("verifier", affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::CompressedY1(x) => {
            let affine = Sm2AffinePoint::decompress((*x).into(), Choice::from(1)).unwrap();
            Sm2VerifyingKey::from_affine("verifier", affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, y }) => {
            let affine = Sm2AffinePoint::decompress(
                (*x).into(),
                Choice::from(if y.last().unwrap().is_even() { 0 } else { 1 }),
            )
            .unwrap();
            Sm2VerifyingKey::from_affine("verifier", affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        _ => Err(ValidationError::InvalidInput(
            "Verifying key must be indicated in compressed-y, or uncompressed form!".into(),
        )),
    }?;

    match verifying_key.verify(
        &[sm3(msg), sm3(encoded_certificate.unwrap_or(&[]))].concat(),
        &signature,
    ) {
        Ok(_) => Ok(ValidationResult::Success),
        Err(e) => Ok(ValidationResult::Failure {
            reason: format!("{e:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_ecdsa_nist_p256() {
        // Msg No. 3 rx_r1a.pcap
        println!(
            "{:?}",
            ecdsa_nist_p256(
                &EccP256CurvePoint::CompressedY0(&[
                    0x3c, 0xa4, 0x68, 0x09, 0x0a, 0xeb, 0xdd, 0x3e, 0x63, 0xaf, 0x42, 0x1a, 0x91,
                    0x10, 0x17, 0x76, 0x98, 0x9b, 0x32, 0xef, 0x64, 0xbf, 0x00, 0x5d, 0x4c, 0x10,
                    0x44, 0xd6, 0x88, 0x79, 0x49, 0x9b,
                ]),
                &[
                    0xb6, 0xd4, 0xbe, 0x84, 0xb3, 0x31, 0x86, 0x96, 0x80, 0x46, 0xff, 0xa3, 0x48,
                    0xc1, 0xe8, 0x6a, 0x0a, 0x9c, 0xa0, 0x71, 0x2c, 0xa6, 0xd0, 0x4f, 0x93, 0x4e,
                    0x92, 0xcc, 0x99, 0x45, 0xd2, 0xe8,
                ],
                &EccP256CurvePoint::CompressedY0(&[
                    0x13, 0x43, 0x08, 0xc4, 0x32, 0x4d, 0x5f, 0x47, 0xfc, 0xbe, 0x66, 0x5f, 0xb5,
                    0x5b, 0x40, 0x98, 0xb3, 0x8b, 0x9c, 0xaa, 0x48, 0x4b, 0xd4, 0x47, 0x4c, 0x6c,
                    0x52, 0x16, 0x00, 0xa7, 0x50, 0x8c,
                ]),
                &[
                    0x40, 0x03, 0x80, 0x78, 0x20, 0x50, 0x02, 0x80, 0x00, 0x54, 0x01, 0x00, 0x14,
                    0x00, 0xca, 0x83, 0x1a, 0x3f, 0x3d, 0x39, 0x70, 0xfc, 0x86, 0x68, 0x1f, 0xeb,
                    0x32, 0x07, 0x05, 0xec, 0x3a, 0xd3, 0x80, 0x04, 0x0b, 0x90, 0x00, 0x00, 0x00,
                    0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0x1a, 0x3f, 0x3d, 0x39, 0x86, 0x68,
                    0x40, 0x5a, 0xb2, 0x03, 0x60, 0xee, 0x26, 0xc1, 0x9a, 0x60, 0xb0, 0x0b, 0x00,
                    0x00, 0x34, 0x87, 0x8e, 0x48, 0xb9, 0x1f, 0xa0, 0x01, 0x10, 0x82, 0xe8, 0x92,
                    0x83, 0x33, 0xff, 0x01, 0xff, 0xfa, 0x00, 0x28, 0x33, 0x00, 0x00, 0x4b, 0xff,
                    0x74, 0xff, 0x2a, 0x2e, 0x68, 0x0c, 0xbb, 0xdf, 0xa4, 0x48, 0x24, 0x7e, 0x23,
                    0xd3, 0xc8, 0x1f, 0x02, 0x4a, 0xbe, 0xa5, 0xe8, 0xcf, 0x09, 0x69, 0xf8, 0x0d,
                    0xed, 0xf4, 0x24, 0x4c, 0x90, 0x33, 0x3f, 0x40, 0x01, 0x24, 0x00, 0x02, 0x30,
                    0x51, 0x5a, 0x70, 0x30, 0x2c
                ],
                Some(&[
                    0x80, 0x03, 0x00, 0x80, 0x5d, 0x5d, 0xcb, 0xee, 0xfb, 0xe7, 0xd2, 0x2d, 0x30,
                    0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x81, 0xd9, 0x85, 0x86, 0x00, 0x01,
                    0xe0, 0x01, 0x07, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80,
                    0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x8c, 0x81,
                    0x05, 0x04, 0x02, 0xff, 0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x02, 0x7e,
                    0x81, 0x02, 0x01, 0x01, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x00,
                    0x02, 0x03, 0xff, 0x80, 0x80, 0x82, 0x13, 0x43, 0x08, 0xc4, 0x32, 0x4d, 0x5f,
                    0x47, 0xfc, 0xbe, 0x66, 0x5f, 0xb5, 0x5b, 0x40, 0x98, 0xb3, 0x8b, 0x9c, 0xaa,
                    0x48, 0x4b, 0xd4, 0x47, 0x4c, 0x6c, 0x52, 0x16, 0x00, 0xa7, 0x50, 0x8c, 0x81,
                    0x80, 0x3d, 0x9a, 0x96, 0x8a, 0xc1, 0x19, 0x6e, 0x46, 0xea, 0x98, 0x22, 0x6c,
                    0x55, 0x20, 0x81, 0xa7, 0x7c, 0xdf, 0xbe, 0xd5, 0x8c, 0x76, 0x9a, 0xf2, 0x8c,
                    0x9f, 0xf9, 0x06, 0xe9, 0x26, 0xd9, 0x22, 0x40, 0x5f, 0x18, 0x9a, 0x1c, 0x6a,
                    0x03, 0x19, 0x89, 0x68, 0x96, 0x0a, 0x93, 0x32, 0x50, 0x06, 0xaf, 0xfb, 0x84,
                    0x40, 0x4c, 0x93, 0x16, 0x80, 0x69, 0x8f, 0xff, 0x27, 0xc8, 0xf3, 0x12, 0x7e,
                ])
            )
        );
    }
}
