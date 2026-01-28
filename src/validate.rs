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
use sha2::{Digest, Sha256, Sha384};

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
                let certificate = c.0.first().ok_or(ValidationError::InvalidInput(
                    "Certificate list is empty!".into(),
                ))?;
                (&certificate.to_be_signed.verify_key_indicator, certificate.raw)
            }
            SignerIdentifier::Digest(_) => {
                // TODO: Support digest lookup
                return Err(ValidationError::Unsupported("Certificate retrieval by digest is unsupported!".into()))
            },
            SignerIdentifier::RsSelf(()) => {
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
            SignerIdentifier::RsSelf(()) => Ok(ValidationResult::Failure {
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
        }
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
    let mut hasher = sm3::Sm3::new();
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
    let r_unwrapped = match r {
        EccP256CurvePoint::Fill(()) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP256CurvePoint::XOnly(x)
        | EccP256CurvePoint::CompressedY0(x)
        | EccP256CurvePoint::CompressedY1(x)
        | EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, .. }) => x,
    };

    let signature = ecdsa::Signature::<bp256::BrainpoolP256r1>::from_scalars(
        bp256::FieldBytes::try_from(*r_unwrapped)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid R length: {err:?}")))?,
        bp256::FieldBytes::try_from(s)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid S length: {err:?}")))?,
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP256CurvePoint::CompressedY0(x) => {
            let affine = bp256::r1::AffinePoint::decompress(
                &bp256::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y0 length: {err:?}"
                    ))
                })?,
                Choice::from(0),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::CompressedY1(x) => {
            let affine = bp256::r1::AffinePoint::decompress(
                &bp256::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y1 length: {err:?}"
                    ))
                })?,
                Choice::from(1),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, y }) => {
            let encoded = bp256::r1::EncodedPoint::from_affine_coordinates(
                &bp256::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key X length: {err:?}"
                    ))
                })?,
                &bp256::FieldBytes::try_from(*y).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key Y length: {err:?}"
                    ))
                })?,
                false,
            );
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
        Ok(()) => Ok(ValidationResult::Success),
        Err(e) => Ok(ValidationResult::Failure {
            reason: format!("{e:?}"),
        }),
    }
}

fn ecdsa_brainpool_p384_r1(
    r: &EccP384CurvePoint,
    s: &[u8],
    curve_point: &EccP384CurvePoint,
    msg: &[u8],
    encoded_certificate: Option<&[u8]>,
) -> Result<ValidationResult, ValidationError> {
    let r_unwrapped = match r {
        EccP384CurvePoint::Fill(()) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP384CurvePoint::XOnly(x)
        | EccP384CurvePoint::CompressedY0(x)
        | EccP384CurvePoint::CompressedY1(x)
        | EccP384CurvePoint::UncompressedP384(EccP384CurvePointUncompressedP384 { x, .. }) => x,
    };

    let signature = ecdsa::Signature::<bp384::BrainpoolP384r1>::from_scalars(
        bp384::FieldBytes::try_from(*r_unwrapped)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid R length: {err:?}")))?,
        bp384::FieldBytes::try_from(s)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid S length: {err:?}")))?,
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP384CurvePoint::CompressedY0(x) => {
            let affine = bp384::r1::AffinePoint::decompress(
                &bp384::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y0 length: {err:?}"
                    ))
                })?,
                Choice::from(0),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP384CurvePoint::CompressedY1(x) => {
            let affine = bp384::r1::AffinePoint::decompress(
                &bp384::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y1 length: {err:?}"
                    ))
                })?,
                Choice::from(1),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP384CurvePoint::UncompressedP384(EccP384CurvePointUncompressedP384 { x, y }) => {
            let encoded = bp384::r1::EncodedPoint::from_affine_coordinates(
                &bp384::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key X length: {err:?}"
                    ))
                })?,
                &bp384::FieldBytes::try_from(*y).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key Y length: {err:?}"
                    ))
                })?,
                false,
            );
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
        Ok(()) => Ok(ValidationResult::Success),
        Err(e) => Ok(ValidationResult::Failure {
            reason: format!("{e:?}"),
        }),
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
        EccP256CurvePoint::Fill(()) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP256CurvePoint::XOnly(x)
        | EccP256CurvePoint::CompressedY0(x)
        | EccP256CurvePoint::CompressedY1(x)
        | EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, .. }) => x,
    };

    let signature = ecdsa::Signature::<p256::NistP256>::from_scalars(
        p256::FieldBytes::try_from(*r_unwrapped)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid R length: {err:?}")))?,
        p256::FieldBytes::try_from(s)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid S length: {err:?}")))?,
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP256CurvePoint::CompressedY0(x) => {
            let affine = p256::AffinePoint::decompress(
                &p256::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y0 length: {err:?}"
                    ))
                })?,
                Choice::from(0),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::CompressedY1(x) => {
            let affine = p256::AffinePoint::decompress(
                &p256::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y1 length: {err:?}"
                    ))
                })?,
                Choice::from(1),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, y }) => {
            let encoded = p256::EncodedPoint::from_affine_coordinates(
                &p256::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key X length: {err:?}"
                    ))
                })?,
                &p256::FieldBytes::try_from(*y).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key Y length: {err:?}"
                    ))
                })?,
                false,
            );
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
        Ok(()) => Ok(ValidationResult::Success),
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
        EccP384CurvePoint::Fill(()) => {
            return Ok(ValidationResult::Failure {
                reason: "R value of signature is not given!".into(),
            })
        }
        EccP384CurvePoint::XOnly(x)
        | EccP384CurvePoint::CompressedY0(x)
        | EccP384CurvePoint::CompressedY1(x)
        | EccP384CurvePoint::UncompressedP384(EccP384CurvePointUncompressedP384 { x, .. }) => x,
    };

    let signature = ecdsa::Signature::<p384::NistP384>::from_scalars(
        p384::FieldBytes::try_from(*r_unwrapped)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid R length: {err:?}")))?,
        p384::FieldBytes::try_from(s)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid S length: {err:?}")))?,
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP384CurvePoint::CompressedY0(x) => {
            let affine = p384::AffinePoint::decompress(
                &p384::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y0 length: {err:?}"
                    ))
                })?,
                Choice::from(0),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP384CurvePoint::CompressedY1(x) => {
            let affine = p384::AffinePoint::decompress(
                &p384::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y1 length: {err:?}"
                    ))
                })?,
                Choice::from(1),
            )
            .unwrap();
            VerifyingKey::from_affine(affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP384CurvePoint::UncompressedP384(EccP384CurvePointUncompressedP384 { x, y }) => {
            let encoded = p384::EncodedPoint::from_affine_coordinates(
                &p384::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key X length: {err:?}"
                    ))
                })?,
                &p384::FieldBytes::try_from(*y).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key Y length: {err:?}"
                    ))
                })?,
                false,
            );
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
        Ok(()) => Ok(ValidationResult::Success),
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
        sm2::FieldBytes::try_from(r)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid R length: {err:?}")))?,
        sm2::FieldBytes::try_from(s)
            .map_err(|err| ValidationError::InvalidInput(format!("Invalid S length: {err:?}")))?,
    )
    .unwrap();

    let verifying_key = match curve_point {
        EccP256CurvePoint::CompressedY0(x) => {
            let affine = sm2::AffinePoint::decompress(
                &sm2::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y0 length: {err:?}"
                    ))
                })?,
                Choice::from(0),
            )
            .unwrap();
            sm2::dsa::VerifyingKey::from_affine("verifier", affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::CompressedY1(x) => {
            let affine = sm2::AffinePoint::decompress(
                &sm2::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key compressed-y1 length: {err:?}"
                    ))
                })?,
                Choice::from(1),
            )
            .unwrap();
            sm2::dsa::VerifyingKey::from_affine("verifier", affine)
                .map_err(|e| ValidationError::InvalidInput(format!("{e:?}")))
        }
        EccP256CurvePoint::UncompressedP256(EccP256CurvePointUncompressedP256 { x, y }) => {
            let affine = sm2::AffinePoint::decompress(
                &sm2::FieldBytes::try_from(*x).map_err(|err| {
                    ValidationError::InvalidInput(format!(
                        "Invalid verifying key uncompressed X length: {err:?}"
                    ))
                })?,
                Choice::from(u8::from(!y.last().unwrap().is_even())),
            )
            .unwrap();
            sm2::dsa::VerifyingKey::from_affine("verifier", affine)
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
        Ok(()) => Ok(ValidationResult::Success),
        Err(e) => Ok(ValidationResult::Failure {
            reason: format!("{e:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use crate::Decode as _;

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

    #[test]
    // Cohda demo cert CAM with full cert
    fn validates_nist_p256_cam() {
        let data: &'static [u8] = &[
            0x12, 0x00, 0x05, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x5f, 0x20, 0x50, 0x02,
            0x80, 0x00, 0x3b, 0x01, 0x00, 0x14, 0x00, 0x06, 0x42, 0x7e, 0x75, 0x45, 0x23, 0x30,
            0x3e, 0xbe, 0x08, 0x1f, 0xf3, 0x49, 0x66, 0x05, 0xfa, 0x99, 0x4c, 0x80, 0x00, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0x7e, 0x75, 0x45,
            0x23, 0xbe, 0x08, 0x40, 0x5a, 0xb3, 0x06, 0x4c, 0xce, 0x28, 0x8d, 0x69, 0x86, 0xaa,
            0x6a, 0xa0, 0x00, 0x34, 0x2e, 0xd0, 0x48, 0x22, 0x0f, 0xa0, 0x05, 0xad, 0xbf, 0xe9,
            0xea, 0x77, 0x33, 0xff, 0x01, 0xff, 0xfa, 0x00, 0x28, 0x33, 0x00, 0x00, 0x1c, 0x00,
            0x69, 0x00, 0x4b, 0x31, 0xf6, 0x00, 0x27, 0x80, 0x40, 0x01, 0x24, 0x00, 0x02, 0x79,
            0x8c, 0x75, 0x19, 0x83, 0x74, 0x81, 0x01, 0x01, 0x80, 0x03, 0x00, 0x80, 0x5d, 0x5d,
            0xcb, 0xee, 0xfb, 0xe7, 0xd2, 0x2d, 0x30, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29,
            0x84, 0x9d, 0x05, 0x86, 0x00, 0x01, 0xe0, 0x01, 0x07, 0x80, 0x01, 0x24, 0x81, 0x04,
            0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff,
            0x80, 0x01, 0x8c, 0x81, 0x05, 0x04, 0x02, 0xff, 0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80,
            0x02, 0x02, 0x7e, 0x81, 0x02, 0x01, 0x01, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01,
            0x01, 0x00, 0x02, 0x03, 0xff, 0x80, 0x80, 0x83, 0x7b, 0x2f, 0x6b, 0x07, 0x93, 0xc0,
            0xd8, 0x89, 0x44, 0x7f, 0xa6, 0xe3, 0xa5, 0x7a, 0x4d, 0xca, 0x9c, 0x3f, 0xe8, 0x3e,
            0xa5, 0x25, 0xfd, 0x11, 0x61, 0x6e, 0x0d, 0xfd, 0xe9, 0x91, 0x97, 0x39, 0x81, 0x80,
            0x28, 0x13, 0x79, 0x86, 0x20, 0xa7, 0x29, 0xcc, 0xe6, 0x7d, 0x8d, 0x70, 0x1a, 0x26,
            0x94, 0x8d, 0x64, 0x35, 0x61, 0x02, 0xd1, 0xd1, 0x99, 0xfb, 0x58, 0xfa, 0x7f, 0xaa,
            0x70, 0xa9, 0x49, 0xf6, 0x6f, 0x12, 0x84, 0xb5, 0xd3, 0x83, 0xcf, 0x62, 0xa2, 0x7c,
            0x3a, 0x89, 0x45, 0x73, 0x57, 0x6f, 0x5e, 0x4a, 0xef, 0x50, 0x6c, 0xe6, 0x0d, 0xf1,
            0xfe, 0x68, 0x70, 0x05, 0x0d, 0x17, 0xa0, 0x12, 0x80, 0x82, 0xdf, 0x57, 0x00, 0xe7,
            0xbf, 0x19, 0x6e, 0x1d, 0x1d, 0xcc, 0x9c, 0xf7, 0xfe, 0x55, 0x41, 0xd4, 0x53, 0x98,
            0x6d, 0x95, 0x82, 0x49, 0x3c, 0xad, 0x52, 0x26, 0x55, 0xdf, 0xcc, 0x89, 0x7c, 0x23,
            0xd2, 0x8e, 0x9e, 0x93, 0x3c, 0x76, 0x9d, 0xf3, 0xf7, 0x18, 0x1b, 0x02, 0x7a, 0x0f,
            0x80, 0x3c, 0xfb, 0xc2, 0x37, 0x43, 0x3f, 0x8d, 0x5b, 0x7e, 0x83, 0x7d, 0x9e, 0x9d,
            0x38, 0xd0, 0x62, 0xe6,
        ];

        let decoded = Packet::decode(data).unwrap();
        assert_eq!(Ok(ValidationResult::Success), decoded.decoded.validate());
    }

    #[test]
    // Cohda demo cert CAM with digest
    fn validates_nist_p256_cam_digest() {
        let data: &'static [u8] = &[
            0x12, 0x00, 0x05, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x54, 0x20, 0x50, 0x02,
            0x80, 0x00, 0x30, 0x01, 0x00, 0x14, 0x00, 0x06, 0x42, 0x7e, 0x75, 0x45, 0x23, 0x30,
            0x3e, 0xbe, 0xd0, 0x1f, 0xf3, 0x49, 0x68, 0x05, 0xfa, 0x99, 0x49, 0x80, 0x0c, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0x7e, 0x75, 0x45,
            0x23, 0xbe, 0xd0, 0x00, 0x5a, 0xb3, 0x06, 0x4d, 0x0e, 0x28, 0x8d, 0x69, 0x26, 0xae,
            0x6a, 0xe0, 0x00, 0x34, 0x2d, 0x92, 0x48, 0x22, 0x0f, 0xa0, 0x00, 0x98, 0xbf, 0xe9,
            0xea, 0x6f, 0x33, 0xff, 0x01, 0xff, 0xfa, 0x00, 0x28, 0x33, 0x00, 0x40, 0x01, 0x24,
            0x00, 0x02, 0x79, 0x8c, 0x75, 0x1b, 0x05, 0xc6, 0x80, 0xe7, 0x3f, 0x07, 0x42, 0x7e,
            0x75, 0x45, 0x23, 0x80, 0x83, 0x6f, 0xc4, 0xa9, 0x4f, 0xb0, 0xe0, 0x1d, 0xd7, 0x66,
            0xc3, 0x28, 0x1d, 0xfd, 0x38, 0x06, 0x55, 0xa8, 0x4c, 0xc4, 0x46, 0xc8, 0x7b, 0x33,
            0x75, 0x6d, 0x56, 0xfc, 0x26, 0x08, 0x6b, 0x55, 0x15, 0xac, 0x23, 0x8b, 0xfe, 0xd1,
            0x70, 0x21, 0x71, 0x6e, 0x6c, 0x95, 0x7c, 0x6e, 0xf7, 0xb5, 0xa1, 0x5f, 0x6e, 0x89,
            0x24, 0xfc, 0x21, 0x6e, 0xd4, 0x8f, 0xc2, 0x9a, 0x51, 0x94, 0xba, 0xd0, 0x7f,
        ];

        let decoded = Packet::decode(data).unwrap();

        assert!(matches!(
            decoded.decoded.validate(),
            Err(ValidationError::Unsupported(_))
        ));
    }

    #[test]
    // Some CAM with Brainpool P256r1 certificate
    fn validates_brainpool_p256r1_cam() {
        let data: &'static [u8] = &[
            0x12, 0x00, 0x1a, 0x02, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x74, 0x20, 0x40, 0x01,
            0x00, 0x00, 0x40, 0x02, 0x00, 0x33, 0x9f, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x50, 0x56,
            0xa2, 0x42, 0x5e, 0x16, 0x80, 0xb8, 0x27, 0x1c, 0x0e, 0x3f, 0x53, 0x09, 0x30, 0xe5,
            0x2f, 0x80, 0x00, 0x00, 0x00, 0x1c, 0x0e, 0x5f, 0x5a, 0x09, 0x30, 0xdc, 0xf1, 0x03,
            0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd2, 0x07, 0xd2, 0x02, 0x01, 0x00,
            0x00, 0x9c, 0x3f, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x32, 0x14, 0x42, 0xd0, 0x17,
            0x04, 0xe5, 0x10, 0xb4, 0x05, 0xc1, 0x3d, 0x1b, 0x34, 0x85, 0xa7, 0x47, 0xaa, 0xef,
            0x1f, 0xff, 0xff, 0xfe, 0x11, 0xdb, 0xba, 0x1f, 0x40, 0x0f, 0x01, 0xe2, 0x00, 0x40,
            0x00, 0x04, 0x80, 0x00, 0x60, 0x00, 0x1c, 0x73, 0x87, 0x7f, 0xda, 0x08, 0x3b, 0xc7,
            0x38, 0x50, 0x01, 0x25, 0x00, 0x02, 0x79, 0x27, 0xd8, 0xb3, 0x39, 0x38, 0x1c, 0x0e,
            0x3f, 0x53, 0x09, 0x30, 0xe5, 0x2f, 0x10, 0x00, 0x81, 0x01, 0x01, 0x80, 0x03, 0x00,
            0x80, 0xfb, 0x9f, 0xe6, 0x57, 0x1f, 0x7c, 0xe7, 0xf9, 0x10, 0x83, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x29, 0x77, 0x14, 0xd9, 0x84, 0x00, 0xa8, 0x01, 0x02, 0x80, 0x01, 0x25,
            0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x8b, 0x81, 0x07, 0x06, 0x01,
            0xc0, 0x40, 0x01, 0xff, 0xf8, 0x80, 0x81, 0x82, 0x37, 0x9e, 0x96, 0x25, 0xd2, 0xdd,
            0xb4, 0x4a, 0xe3, 0x00, 0xf1, 0x7c, 0x1c, 0x34, 0xb9, 0xaf, 0xb6, 0x91, 0x24, 0x8a,
            0x2d, 0xec, 0xf4, 0x72, 0x1f, 0x49, 0x6e, 0x47, 0x0e, 0x98, 0x86, 0x47, 0x80, 0x80,
            0xd7, 0xa0, 0xad, 0xd8, 0x85, 0xff, 0xae, 0x32, 0x76, 0xdb, 0xed, 0x6b, 0x90, 0x5d,
            0x8d, 0x72, 0xbe, 0xf3, 0x71, 0x6b, 0xc3, 0xf9, 0x83, 0xc6, 0x65, 0xff, 0xda, 0x8d,
            0x16, 0xba, 0x47, 0x2d, 0xdf, 0x46, 0xa7, 0x38, 0xa4, 0xd4, 0x6d, 0xdb, 0x24, 0xac,
            0xad, 0xa6, 0x08, 0x90, 0xd8, 0x5b, 0xf7, 0x5b, 0xf1, 0xc9, 0xe8, 0x06, 0x59, 0x2c,
            0xfb, 0x71, 0xc6, 0x23, 0xc4, 0xd9, 0x8b, 0x2f, 0x81, 0x80, 0x9e, 0x35, 0xa5, 0x16,
            0x38, 0xc0, 0xbe, 0x4d, 0x45, 0x7e, 0xcf, 0x50, 0x34, 0x4b, 0xfe, 0x89, 0xef, 0x37,
            0x10, 0x04, 0x38, 0xec, 0x33, 0x60, 0x77, 0x86, 0x47, 0xb1, 0xe5, 0x9d, 0x9b, 0xc6,
            0x2c, 0xe3, 0xb8, 0x2a, 0x24, 0xfd, 0x39, 0xee, 0x04, 0xac, 0x90, 0xe2, 0x19, 0x99,
            0x6a, 0xa1, 0x37, 0x00, 0x57, 0x0c, 0x7c, 0x60, 0xc7, 0x30, 0x72, 0xde, 0x3d, 0xc7,
            0x9a, 0xb7, 0x32, 0x60,
        ];

        let decoded = Packet::decode(data).unwrap();
        assert_eq!(Ok(ValidationResult::Success), decoded.decoded.validate());
    }
}
