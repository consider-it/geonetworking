extern crate alloc;

use core::fmt::Display;

use crate::{decode::BitwiseDecodable, util::write_into_vec_left_padded};
use bitvec::prelude::*;
use num::Integer;
use num_traits::ToBytes;

use super::*;

#[derive(Debug)]
pub enum EncodeError {
    Unsupported(alloc::string::String),
    Common(alloc::string::String),
    #[cfg(feature = "json")]
    Json(alloc::string::String),
}

impl EncodeError {
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Unsupported(message) => message,
            Self::Common(message) => message,
            #[cfg(feature = "json")]
            Self::Json(message) => message,
        }
    }
}

#[derive(Debug, Default)]
pub struct Encoder {
    bits: BitVec<u8, Msb0>,
}

impl Encoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bits: bitvec![u8, Msb0;],
        }
    }
}

impl From<Encoder> for alloc::vec::Vec<u8> {
    fn from(val: Encoder) -> Self {
        let mut vec = alloc::vec![];
        write_into_vec_left_padded(val.bits.bitwise(), &mut vec);
        vec
    }
}

impl From<Encoder> for bytes::Bytes {
    fn from(val: Encoder) -> Self {
        <Encoder as core::convert::Into<alloc::vec::Vec<u8>>>::into(val).into()
    }
}

impl From<Encoder> for BitVec<u8, Msb0> {
    fn from(val: Encoder) -> Self {
        val.bits
    }
}

/// Encoder for individual fields of the GeoNetworking header to binary data
///
/// Data encoding can be done using an [`Encoder`] or directly ([`encode`](`Self::encode`)) to a binary vector ([`encode_to_vec`](`Self::encode_to_vec`)).
///
/// # Examples
/// Encode using an encoder:
/// ```ignore
/// let mut encoder = geonetworking::Encoder::new();
/// packet.encode(&mut encoder).unwrap();
///
/// let output: Vec<u8> = encoder.into();
/// ```
///
/// Encode and return bytes:
/// ```ignore
/// let bytes = packet.encode_to_vec().unwrap();
/// ```
pub trait Encode {
    /// Encodes itself as binary data to the `output` [`Encoder`]
    ///
    /// Using an [`Encoder`] allows for concatenating multiple items in one encoding
    ///
    /// # Errors
    /// Returns an [`EncodeError`] when encoding failed
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError>;

    /// Encodes itself as binary data
    ///
    /// Compared to [`Self::encode`] this provides a shorthand that immediately returns the bytes of the encoding
    ///
    /// # Errors
    /// Returns an [`EncodeError`] when encoding failed
    fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder)?;
        Ok(encoder.into())
    }

    #[cfg(feature = "json")]
    /// Encodes itself to a JSON representation
    ///
    /// # Errors
    /// Returns an [`EncodeError`] when encoding failed
    fn encode_to_json(&self) -> Result<alloc::string::String, EncodeError>
    where
        Self: Sized + Serialize,
    {
        serde_json::to_string(self)
            .map_err(|e| EncodeError::Json(alloc::format!("Error encoding JSON: {e:?}")))
    }
}

impl Encode for bool {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        output.bits.push(*self);
        Ok(())
    }
}

#[allow(clippy::unnecessary_wraps, reason = "common interface")]
fn write_as_int<I: Integer + ToBytes + Display>(
    integer: &I,
    bit_count: usize,
    output: &mut Encoder,
) -> Result<(), EncodeError> {
    let bytes = integer.to_be_bytes();
    let bits = bytes.as_bits::<Msb0>();
    output
        .bits
        .extend_from_bitslice(&bits[(bits.len() - bit_count)..bits.len()]);
    Ok(())
}

impl<const SIZE: usize> Encode for Bits<SIZE> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        output.bits.extend_from_bitslice(&self.0);
        Ok(())
    }
}

impl<const SIZE: usize> Encode for [u8; SIZE] {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        output.bits.extend_from_bitslice(self.view_bits::<Msb0>());
        Ok(())
    }
}

impl Encode for &'_ [u8] {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        output.bits.extend_from_bitslice(self.as_bits::<Msb0>());
        Ok(())
    }
}

impl Encode for en302636_4_1::Lifetime {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.0, 8, output)
    }
}

impl Encode for en302636_4_1::Timestamp {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.0, 32, output)
    }
}

impl Encode for en302636_4_1::StationType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&(*self as u8), 5, output)
    }
}

impl Encode for en302636_4_1::Address {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.manually_configured.encode(output)?;
        self.station_type.encode(output)?;
        self.reserved.encode(output)?;
        self.address.encode(output)
    }
}

impl Encode for en302636_4_1::NextAfterBasic {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&(*self as u8), 4, output)
    }
}

impl Encode for en302636_4_1::BasicHeader {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.version, 4, output)?;
        self.next_header.encode(output)?;
        self.reserved.encode(output)?;
        self.lifetime.encode(output)?;
        write_as_int(&self.remaining_hop_limit, 8, output)
    }
}

impl Encode for en302636_4_1::LongPositionVector {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.gn_address.encode(output)?;
        self.timestamp.encode(output)?;
        write_as_int(&self.latitude, 32, output)?;
        write_as_int(&self.longitude, 32, output)?;
        self.position_accuracy.encode(output)?;
        write_as_int(&self.speed, 15, output)?;
        write_as_int(&self.heading, 16, output)
    }
}

impl Encode for en302636_4_1::ShortPositionVector {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.gn_address.encode(output)?;
        self.timestamp.encode(output)?;
        write_as_int(&self.latitude, 32, output)?;
        write_as_int(&self.longitude, 32, output)
    }
}

impl Encode for en302636_4_1::TrafficClass {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.store_carry_forward.encode(output)?;
        self.channel_offload.encode(output)?;
        write_as_int(&self.traffic_class_id, 6, output)
    }
}

impl Encode for en302636_4_1::NextAfterCommon {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&(*self as u8), 4, output)
    }
}

impl Encode for en302636_4_1::HeaderType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let (ty, subty) = match self {
            en302636_4_1::HeaderType::Any => (0, 0),
            en302636_4_1::HeaderType::Beacon => (1, 0),
            en302636_4_1::HeaderType::GeoUnicast => (2, 0),
            en302636_4_1::HeaderType::GeoAnycast(en302636_4_1::AreaType::Circular) => (3, 0),
            en302636_4_1::HeaderType::GeoAnycast(en302636_4_1::AreaType::Rectangular) => (3, 1),
            en302636_4_1::HeaderType::GeoAnycast(_) => (3, 2),
            en302636_4_1::HeaderType::GeoBroadcast(en302636_4_1::AreaType::Circular) => (4, 0),
            en302636_4_1::HeaderType::GeoBroadcast(en302636_4_1::AreaType::Rectangular) => (4, 1),
            en302636_4_1::HeaderType::GeoBroadcast(_) => (4, 2),
            en302636_4_1::HeaderType::TopologicallyScopedBroadcast(
                en302636_4_1::BroadcastType::SingleHop,
            ) => (5, 0),
            en302636_4_1::HeaderType::TopologicallyScopedBroadcast(_) => (5, 1),
            en302636_4_1::HeaderType::LocationService(
                en302636_4_1::LocationServiceType::Request,
            ) => (6, 0),
            en302636_4_1::HeaderType::LocationService(_) => (6, 1),
        };
        write_as_int(&ty, 4, output)?;
        write_as_int(&subty, 4, output)
    }
}

impl Encode for en302636_4_1::CommonHeader {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.next_header.encode(output)?;
        self.reserved_1.encode(output)?;
        self.header_type_and_subtype.encode(output)?;
        self.traffic_class.encode(output)?;
        self.flags.encode(output)?;
        write_as_int(&self.payload_length, 16, output)?;
        write_as_int(&self.maximum_hop_limit, 8, output)?;
        self.reserved_2.encode(output)
    }
}

impl Encode for en302636_4_1::GeoAnycast {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        self.reserved_1.encode(output)?;
        self.source_position_vector.encode(output)?;
        write_as_int(&self.geo_area_position_latitude, 32, output)?;
        write_as_int(&self.geo_area_position_longitude, 32, output)?;
        write_as_int(&self.distance_a, 16, output)?;
        write_as_int(&self.distance_b, 16, output)?;
        write_as_int(&self.angle, 16, output)?;
        self.reserved_2.encode(output)
    }
}

impl Encode for en302636_4_1::GeoUnicast {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        self.reserved.encode(output)?;
        self.source_position_vector.encode(output)?;
        self.destination_position_vector.encode(output)
    }
}

impl Encode for en302636_4_1::TopologicallyScopedBroadcast {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        self.reserved.encode(output)?;
        self.source_position_vector.encode(output)
    }
}

impl Encode for en302636_4_1::SingleHopBroadcast {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.source_position_vector.encode(output)?;
        self.media_dependent_data.encode(output)
    }
}

impl Encode for en302636_4_1::Beacon {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.source_position_vector.encode(output)
    }
}

impl Encode for en302636_4_1::LSRequest {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        self.reserved.encode(output)?;
        self.source_position_vector.encode(output)?;
        self.request_gn_address.encode(output)
    }
}

impl Encode for en302636_4_1::LSReply {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        self.reserved.encode(output)?;
        self.source_position_vector.encode(output)?;
        self.destination_position_vector.encode(output)
    }
}

impl Encode for Option<en302636_4_1::ExtendedHeader> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Some(en302636_4_1::ExtendedHeader::Beacon(b)) => b.encode(output),
            Some(en302636_4_1::ExtendedHeader::GAC(gac)) => gac.encode(output),
            Some(en302636_4_1::ExtendedHeader::GBC(gbc)) => gbc.encode(output),
            Some(en302636_4_1::ExtendedHeader::GUC(guc)) => guc.encode(output),
            Some(en302636_4_1::ExtendedHeader::LSReply(lsr)) => lsr.encode(output),
            Some(en302636_4_1::ExtendedHeader::LSRequest(lsr)) => lsr.encode(output),
            Some(en302636_4_1::ExtendedHeader::SHB(shb)) => shb.encode(output),
            Some(en302636_4_1::ExtendedHeader::TSB(tsb)) => tsb.encode(output),
            None => Ok(()),
        }
    }
}

impl Encode for Packet<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        if let Self::Unsecured {
            basic,
            common,
            extended,
            payload,
        } = self
        {
            basic.encode(output)?;
            common.encode(output)?;
            extended.encode(output)?;
            payload.encode(output)
        } else {
            Err(EncodeError::Unsupported(
                "Encoding secured headers is currently unsupported!".into(),
            ))
        }
    }
}

// ::::::::::: :::::::::: :::::::::: ::::::::::        :::   ::::::::   :::::::   ::::::::       ::::::::
//     :+:     :+:        :+:        :+:             :+:+:  :+:    :+: :+:   :+: :+:    :+:     :+:    :+:
//     +:+     +:+        +:+        +:+               +:+  +:+        +:+  :+:+ +:+    +:+           +:+
//     +#+     +#++:++#   +#++:++#   +#++:++#          +#+  +#++:++#+  +#+ + +:+  +#++:++#+         +#+
//     +#+     +#+        +#+        +#+               +#+  +#+    +#+ +#+#  +#+        +#+       +#+
//     #+#     #+#        #+#        #+#               #+#  #+#    #+# #+#   #+# #+#    #+# #+#  #+#
// ########### ########## ########## ##########      ####### ########   #######   ########  ### ##########

#[allow(clippy::unnecessary_wraps, reason = "common interface")]
fn encode_oer_length(length: usize, output: &mut Encoder) -> Result<(), EncodeError> {
    match length {
        len if len < 128 => {
            #[allow(clippy::cast_possible_truncation)]
            output.bits.extend_from_raw_slice(&[len as u8]);
            Ok(())
        }
        len => {
            let raw = len.to_be_bytes();
            let mut length_bytes = raw.as_ref();
            while length_bytes.len() > 1 && length_bytes[0] == 0 {
                length_bytes = &length_bytes[1..];
            }
            #[allow(clippy::cast_possible_truncation)]
            output
                .bits
                .extend_from_raw_slice(&[(length_bytes.len() + 128) as u8]);
            output.bits.extend_from_raw_slice(length_bytes);
            Ok(())
        }
    }
}

fn encode_oer_integer<I: Integer + ToBytes>(
    min: Option<i128>,
    max: Option<i128>,
    value: &I,
    output: &mut Encoder,
) -> Result<(), EncodeError> {
    match (min, max) {
        (Some(_), Some(_)) => {
            output
                .bits
                .extend_from_raw_slice(value.to_be_bytes().as_ref());
            Ok(())
        }
        (Some(min), _) if min >= 0 => {
            let raw = value.to_be_bytes();
            let mut bytes = raw.as_ref();
            while bytes.len() > 1 && bytes[0] == 0 {
                bytes = &bytes[1..];
            }
            encode_oer_length(bytes.len(), output)?;
            output.bits.extend_from_raw_slice(bytes);
            Ok(())
        }
        _ => Err(EncodeError::Unsupported(
            "Unconstrained or extensible integers are unsupported!".into(),
        )),
    }
}

fn encode_oer_enumerated(value: u8, output: &mut Encoder) -> Result<(), EncodeError> {
    encode_oer_integer(Some(0), Some(255), &value, output)
}

fn encode_oer_octetstring(
    min: Option<usize>,
    max: Option<usize>,
    value: &[u8],
    output: &mut Encoder,
) -> Result<(), EncodeError> {
    match (min, max) {
        (Some(min), Some(max)) if min == max => {
            output.bits.extend_from_raw_slice(value);
            Ok(())
        }
        _ => {
            encode_oer_length(value.len(), output)?;
            output.bits.extend_from_raw_slice(value);
            Ok(())
        }
    }
}

#[allow(clippy::unnecessary_wraps, reason = "common interface")]
fn encode_oer_fixed_bitstring(
    value: &BitVec<u8, Msb0>,
    output: &mut Encoder,
) -> Result<(), EncodeError> {
    output.bits.extend_from_bitslice(value);
    for _ in 0..(8 - value.len() % 8) {
        output.bits.push(false);
    }
    Ok(())
}

fn encode_oer_varlength_bitstring(value: &[bool], output: &mut Encoder) -> Result<(), EncodeError> {
    encode_oer_length(Integer::div_ceil(&value.len(), &8usize) + 1, output)?;
    #[allow(clippy::cast_possible_truncation)]
    let unused_bits = 8 - value.len() % 8;
    #[allow(clippy::cast_possible_truncation)]
    encode_oer_integer(Some(0), Some(8), &(unused_bits as u8), output)?;
    for bit in value {
        output.bits.push(*bit);
    }
    for _ in 0..unused_bits {
        output.bits.push(false);
    }
    Ok(())
}

fn encode_extension_and_optional_bitmap(
    is_extended: bool,
    bitmap: &[bool],
    output: &mut Encoder,
) -> Result<(), EncodeError> {
    output.bits.push(is_extended);
    for bit in bitmap {
        output.bits.push(*bit);
    }
    if bitmap.len() > 7 {
        return Err(EncodeError::Unsupported(
            "Optional bitmaps longer than 7 bits are unsupported!".into(),
        ));
    }
    for _ in 0..(7 - bitmap.len()) {
        output.bits.push(false);
    }
    Ok(())
}

fn encode_oer_tag(tag: u8, output: &mut Encoder) -> Result<(), EncodeError> {
    match tag {
        t if t < 63 => encode_oer_integer(Some(0), Some(255), &(t + 128), output),
        _ => Err(EncodeError::Unsupported(
            "Tag larger than 62 are unsupported!".into(),
        )),
    }
}

fn encode_oer_open_type<T: Encode>(value: &T, output: &mut Encoder) -> Result<(), EncodeError> {
    let bytes = value.encode_to_vec()?;
    encode_oer_octetstring(Some(0), None, &bytes, output)
}

macro_rules! encode_int {
    ($typ:ty, $min:expr, $max:expr) => {
        impl Encode for $typ {
            fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
                encode_oer_integer($min, $max, &self.0, output)
            }
        }
    };
}

encode_int!(
    ieee1609dot2::Latitude,
    Some(-900_000_000),
    Some(900_000_001)
);
encode_int!(
    ieee1609dot2::Longitude,
    Some(-1_799_999_999),
    Some(1_800_000_001)
);
encode_int!(ieee1609dot2::PduFunctionalType, Some(0), Some(255));
encode_int!(ieee1609dot2::HeaderInfoContributorId, Some(0), Some(255));
encode_int!(ieee1609dot2::Uint8, Some(0), Some(255));
encode_int!(ieee1609dot2::Uint16, Some(0), Some(65535));
encode_int!(ieee1609dot2::Uint32, Some(0), Some(4_294_967_295));
encode_int!(ieee1609dot2::ExtId, Some(0), Some(255));
encode_int!(ieee1609dot2::Psid, Some(0), None);

impl Encode for ieee1609dot2::CertificateBase<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_fixed_bitstring(
            &self
                .signature
                .as_ref()
                .map_or(bitvec![u8, Msb0; 0], |_| bitvec![u8, Msb0; 1]),
            output,
        )?;
        self.version.encode(output)?;
        self.r_type.encode(output)?;
        self.issuer.encode(output)?;
        self.to_be_signed.encode(output)?;
        if let Some(sig) = &self.signature {
            sig.encode(output)?;
        }
        Ok(())
    }
}

macro_rules! encode_octets {
    ($typ:ty, $min:expr, $max:expr) => {
        impl Encode for $typ {
            fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
                encode_oer_octetstring($min, $max, self.0, output)
            }
        }
    };
}

encode_octets!(ieee1609dot2::LinkageValue<'_>, Some(9), Some(9));
encode_octets!(ieee1609dot2::HashedId3<'_>, Some(3), Some(3));
encode_octets!(ieee1609dot2::HashedId8<'_>, Some(8), Some(8));
encode_octets!(ieee1609dot2::SubjectAssurance<'_>, Some(1), Some(1));
encode_octets!(ieee1609dot2::BitmapSsp<'_>, Some(0), Some(31));
encode_octets!(ieee1609dot2::Opaque<'_>, Some(0), None);
encode_octets!(ieee1609dot2::HashedId32<'_>, Some(32), Some(32));
encode_octets!(ieee1609dot2::HashedId48<'_>, Some(48), Some(48));

impl Encode for ieee1609dot2::CertificateType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_enumerated(*self as u8, output)
    }
}

impl Encode for ieee1609dot2::HashAlgorithm {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_enumerated(*self as u8, output)
    }
}

impl Encode for ieee1609dot2::IssuerIdentifier<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Sha256AndDigest(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::RsSelf(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::Sha384AndDigest(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
            Self::Sm3AndDigest(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ieee1609dot2::ToBeSignedCertificate<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let is_extended = self.flags.is_some()
            || self.app_extensions.is_some()
            || self.cert_issue_extensions.is_some()
            || self.cert_request_extension.is_some();
        let bitmap = [
            self.region.is_some(),
            self.assurance_level.is_some(),
            self.app_permissions.is_some(),
            self.cert_issue_permissions.is_some(),
            self.cert_request_permissions.is_some(),
            self.can_request_rollover.is_some(),
            self.encryption_key.is_some(),
        ];
        encode_extension_and_optional_bitmap(is_extended, &bitmap, output)?;
        self.id.encode(output)?;
        self.craca_id.encode(output)?;
        self.crl_series.encode(output)?;
        self.validity_period.encode(output)?;
        self.region
            .as_ref()
            .map_or(Ok(()), |reg| reg.encode(output))?;
        self.assurance_level
            .as_ref()
            .map_or(Ok(()), |sub_ass| sub_ass.encode(output))?;
        self.app_permissions
            .as_ref()
            .map_or(Ok(()), |app_perm| app_perm.encode(output))?;
        self.cert_issue_permissions
            .as_ref()
            .map_or(Ok(()), |cert_issue_perm| cert_issue_perm.encode(output))?;
        self.cert_request_permissions
            .as_ref()
            .map_or(Ok(()), |cert_request_perm| cert_request_perm.encode(output))?;
        self.encryption_key
            .as_ref()
            .map_or(Ok(()), |enc_key| enc_key.encode(output))?;
        self.verify_key_indicator.encode(output)?;
        let ext_bitmap = [
            self.flags.is_some(),
            self.app_extensions.is_some(),
            self.cert_issue_extensions.is_some(),
            self.cert_request_extension.is_some(),
        ];
        if is_extended {
            encode_oer_varlength_bitstring(&ext_bitmap, output)
        } else {
            Ok(())
        }?;
        self.flags.as_ref().map_or(Ok(()), |flags| {
            let mut encoder = Encoder::new();
            encode_oer_fixed_bitstring(&flags.0, &mut encoder).and_then(|()| {
                encode_oer_octetstring(Some(0), None, &Into::<Vec<u8>>::into(encoder), output)
            })
        })?;
        self.app_extensions
            .as_ref()
            .map_or(Ok(()), |app_ext| encode_oer_open_type(app_ext, output))?;
        self.cert_issue_extensions
            .as_ref()
            .map_or(Ok(()), |cert_ext| encode_oer_open_type(cert_ext, output))?;
        self.cert_request_extension
            .as_ref()
            .map_or(Ok(()), |cert_ext| encode_oer_open_type(cert_ext, output))?;
        Ok(())
    }
}

impl Encode for ieee1609dot2::AppExtension<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(output)?;
        encode_oer_octetstring(Some(0), None, self.content, output)
    }
}

impl Encode for ieee1609dot2::CertIssueExtensionPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Specific(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(0), None, inner, output)
            }
            Self::All(()) => encode_oer_tag(1, output),
        }
    }
}

impl Encode for ieee1609dot2::CertRequestExtensionPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Content(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(0), None, inner, output)
            }
            Self::All(()) => encode_oer_tag(1, output),
        }
    }
}

impl Encode for ieee1609dot2::CertIssueExtension<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(output)?;
        self.permissions.encode(output)
    }
}

impl Encode for ieee1609dot2::CertRequestExtension<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(output)?;
        self.permissions.encode(output)
    }
}

impl Encode for ieee1609dot2::VerificationKeyIndicator<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::VerificationKey(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::ReconstructionValue(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for ieee1609dot2::PublicVerificationKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::EcdsaNistP256(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::EcdsaBrainpoolP256r1(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::EcdsaBrainpoolP384r1(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
            Self::EcdsaNistP384(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_open_type(inner, output)
            }
            Self::EcsigSm2(inner) => {
                encode_oer_tag(4, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ieee1609dot2::PsidGroupPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [
            self.min_chain_length == 1,
            self.chain_length_range == 0,
            self.ee_type == ieee1609dot2::EndEntityType(crate::bits!(1, 0, 0, 0, 0, 0, 0, 0)),
        ];
        encode_oer_fixed_bitstring(&bitmap.iter().collect::<BitVec<u8, Msb0>>(), output)?;
        self.subject_permissions.encode(output)?;
        if bitmap[0] {
            encode_oer_integer(Some(0), None, &self.min_chain_length, output)
        } else {
            Ok(())
        }?;
        if bitmap[1] {
            encode_oer_integer(Some(0), None, &self.chain_length_range, output)
        } else {
            Ok(())
        }?;
        if bitmap[0] {
            self.ee_type.encode(output)
        } else {
            Ok(())
        }?;
        Ok(())
    }
}

impl Encode for ieee1609dot2::EndEntityType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_fixed_bitstring(&self.0 .0, output)
    }
}

impl Encode for ieee1609dot2::PsidSsp<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self.ssp {
            Some(_) => encode_oer_fixed_bitstring(&bitvec![u8, Msb0; 1], output),
            None => encode_oer_fixed_bitstring(&bitvec![u8, Msb0; 0], output),
        }?;
        self.psid.encode(output)?;
        self.ssp.as_ref().map_or(Ok(()), |ssp| ssp.encode(output))
    }
}

impl Encode for ieee1609dot2::PsidSspRange<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self.ssp_range {
            Some(_) => encode_oer_fixed_bitstring(&bitvec![u8, Msb0; 1], output),
            None => encode_oer_fixed_bitstring(&bitvec![u8, Msb0; 0], output),
        }?;
        self.psid.encode(output)?;
        self.ssp_range
            .as_ref()
            .map_or(Ok(()), |ssp| ssp.encode(output))
    }
}

impl Encode for ieee1609dot2::BitmapSspRange<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(1), Some(32), self.ssp_value, output)?;
        encode_oer_octetstring(Some(1), Some(32), self.ssp_bitmask, output)
    }
}

impl Encode for ieee1609dot2::SspRange<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Opaque(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::All(()) => encode_oer_tag(1, output),
            Self::BitmapSspRange(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ieee1609dot2::SubjectPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Explicit(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::All(()) => encode_oer_tag(1, output),
        }
    }
}

impl Encode for ieee1609dot2::ServiceSpecificPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Opaque(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(0), None, inner, output)
            }
            Self::BitmapSsp(inner) => {
                encode_oer_tag(1, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ieee1609dot2::BasePublicEncryptionKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::EciesNistP256(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::EciesBrainpoolP256r1(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::EcencSm2(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ieee1609dot2::EccP256CurvePoint<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::XOnly(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(32), Some(32), inner, output)
            }
            Self::Fill(()) => encode_oer_tag(1, output),
            Self::CompressedY0(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_octetstring(Some(32), Some(32), inner, output)
            }
            Self::CompressedY1(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_octetstring(Some(32), Some(32), inner, output)
            }
            Self::UncompressedP256(inner) => {
                encode_oer_tag(4, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for ieee1609dot2::EccP384CurvePoint<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::XOnly(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(48), Some(48), inner, output)
            }
            Self::Fill(()) => encode_oer_tag(1, output),
            Self::CompressedY0(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_octetstring(Some(48), Some(48), inner, output)
            }
            Self::CompressedY1(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_octetstring(Some(48), Some(48), inner, output)
            }
            Self::UncompressedP384(inner) => {
                encode_oer_tag(4, output)?;
                inner.encode(output)
            }
        }
    }
}

macro_rules! encode_sequence_of {
    ($typ:ty) => {
        impl Encode for $typ {
            fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
                encode_oer_integer(Some(0), None, &self.0.len(), output)?;
                for inner in &self.0 {
                    inner.encode(output)?;
                }
                Ok(())
            }
        }
    };
}

encode_sequence_of!(ieee1609dot2::SequenceOfUint16);
encode_sequence_of!(ieee1609dot2::SequenceOfUint8);
encode_sequence_of!(ieee1609dot2::SequenceOfRegionAndSubregions);
encode_sequence_of!(ieee1609dot2::SequenceOfRectangularRegion);
encode_sequence_of!(ieee1609dot2::SequenceOfIdentifiedRegion);
encode_sequence_of!(ieee1609dot2::PolygonalRegion);
encode_sequence_of!(ieee1609dot2::SequenceOfPsidSspRange<'_>);
encode_sequence_of!(ieee1609dot2::SequenceOfPsid);
encode_sequence_of!(ieee1609dot2::SequenceOfPsidSsp<'_>);
encode_sequence_of!(ieee1609dot2::SequenceOfOctetString<'_>);
encode_sequence_of!(ieee1609dot2::SequenceOfPsidGroupPermissions<'_>);
encode_sequence_of!(ieee1609dot2::SequenceOfAppExtensions<'_>);
encode_sequence_of!(ieee1609dot2::SequenceOfCertIssueExtensions<'_>);
encode_sequence_of!(ieee1609dot2::SequenceOfCertRequestExtensions<'_>);
encode_sequence_of!(ieee1609dot2::SequenceOfHashedId3<'_>);
encode_sequence_of!(ieee1609dot2::ContributedExtensionBlocks<'_>);
encode_sequence_of!(ieee1609dot2::ContributedExtensionBlockExtns<'_>);

macro_rules! encode_sequence {
    ($typ:ty, $( $field:ident ),*) => {
        impl Encode for $typ {
            fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
                $(
                    self.$field.encode(output)?;
                )*
                Ok(())
            }
        }
    };
}

encode_sequence!(ieee1609dot2::ValidityPeriod, start, duration);
encode_sequence!(ieee1609dot2::CountryAndRegions, country_only, regions);
encode_sequence!(ieee1609dot2::RegionAndSubregions, region, subregions);
encode_sequence!(
    ieee1609dot2::CountryAndSubregions,
    country_only,
    region_and_subregions
);
encode_sequence!(ieee1609dot2::ThreeDLocation, latitude, longitude, elevation);
encode_sequence!(ieee1609dot2::TwoDLocation, latitude, longitude);
encode_sequence!(ieee1609dot2::RectangularRegion, north_west, south_east);
encode_sequence!(ieee1609dot2::CircularRegion, center, radius);
encode_sequence!(
    ieee1609dot2::PublicEncryptionKey<'_>,
    supported_symm_alg,
    public_key
);
encode_sequence!(ieee1609dot2::ToBeSignedData<'_>, payload, header_info);
encode_sequence!(
    ieee1609dot2::Ieee1609Dot2Data<'_>,
    protocol_version,
    content
);
encode_sequence!(
    ieee1609dot2::ContributedExtensionBlock<'_>,
    contributor_id,
    extns
);

impl Encode for ieee1609dot2::SymmAlgorithm {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_enumerated(*self as u8, output)
    }
}

impl Encode for ieee1609dot2::GeographicRegion {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::CircularRegion(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::RectangularRegion(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::PolygonalRegion(inner) => {
                encode_oer_tag(2, output)?;
                inner.encode(output)
            }
            Self::IdentifiedRegion(inner) => {
                encode_oer_tag(3, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for ieee1609dot2::IdentifiedRegion {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::CountryOnly(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::CountryAndRegions(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::CountryAndSubregions(inner) => {
                encode_oer_tag(2, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for ieee1609dot2::Duration {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Microseconds(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::Milliseconds(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::Seconds(inner) => {
                encode_oer_tag(2, output)?;
                inner.encode(output)
            }
            Self::Minutes(inner) => {
                encode_oer_tag(3, output)?;
                inner.encode(output)
            }
            Self::Hours(inner) => {
                encode_oer_tag(4, output)?;
                inner.encode(output)
            }
            Self::SixtyHours(inner) => {
                encode_oer_tag(5, output)?;
                inner.encode(output)
            }
            Self::Years(inner) => {
                encode_oer_tag(6, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for ieee1609dot2::CertificateId<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::LinkageData(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::Name(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::BinaryId(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_octetstring(Some(1), Some(64), inner, output)
            }
            Self::None(()) => encode_oer_tag(3, output),
        }
    }
}

impl Encode for ieee1609dot2::Hostname {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(0), Some(255), self.0.as_bytes(), output)
    }
}

impl Encode for ieee1609dot2::LinkageData<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self.group_linkage_value {
            Some(_) => encode_oer_fixed_bitstring(&bitvec![u8, Msb0; 1], output),
            None => encode_oer_fixed_bitstring(&bitvec![u8, Msb0; 0], output),
        }?;
        self.i_cert.encode(output)?;
        self.linkage_value.encode(output)?;
        self.group_linkage_value
            .as_ref()
            .map_or(Ok(()), |glv| glv.encode(output))
    }
}

impl Encode for ieee1609dot2::GroupLinkageValue<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(4), Some(4), self.j_value, output)?;
        encode_oer_octetstring(Some(9), Some(9), self.value, output)
    }
}

impl Encode for ieee1609dot2::EccP256CurvePointUncompressedP256<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(32), Some(32), self.x, output)?;
        encode_oer_octetstring(Some(32), Some(32), self.y, output)
    }
}

impl Encode for ieee1609dot2::EccP384CurvePointUncompressedP384<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(48), Some(48), self.x, output)?;
        encode_oer_octetstring(Some(48), Some(48), self.y, output)
    }
}

impl Encode for ieee1609dot2::EcsigP256Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(32), Some(32), self.r_sig, output)?;
        encode_oer_octetstring(Some(32), Some(32), self.s_sig, output)
    }
}

impl Encode for ieee1609dot2::EcdsaP256Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.r_sig.encode(output)?;
        encode_oer_octetstring(Some(32), Some(32), self.s_sig, output)
    }
}

impl Encode for ieee1609dot2::EcdsaP384Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.r_sig.encode(output)?;
        encode_oer_octetstring(Some(48), Some(48), self.s_sig, output)
    }
}

impl Encode for ieee1609dot2::Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::EcdsaNistP256Signature(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::EcdsaBrainpoolP256r1Signature(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Self::EcdsaBrainpoolP384r1Signature(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
            Self::EcdsaNistP384Signature(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_open_type(inner, output)
            }
            Self::Sm2Signature(inner) => {
                encode_oer_tag(4, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ieee1609dot2::HashedData<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Sha256HashedData(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::Sha384HashedData(inner) => {
                encode_oer_tag(1, output)?;
                encode_oer_open_type(inner, output)
            }
            Self::Sm3HashedData(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ieee1609dot2::EncryptionKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Public(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Self::Symmetric(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for ieee1609dot2::SymmetricEncryptionKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Aes128Ccm(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(16), Some(16), inner, output)
            }
            Self::Sm4Ccm(inner) => {
                encode_oer_tag(1, output)?;
                let mut encoder = Encoder::new();
                encode_oer_octetstring(Some(16), Some(16), inner, &mut encoder)?;
                #[cfg(not(feature = "validate"))]
                let inner_encoded: Vec<u8> = encoder.into();
                #[cfg(feature = "validate")]
                let inner_encoded: alloc::vec::Vec<u8> = encoder.into();
                encode_oer_octetstring(Some(0), None, inner_encoded.as_slice(), output)
            }
        }
    }
}

impl Encode for ieee1609dot2::AnonymousContributedExtensionBlockExtns<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(0), None, self.0, output)
    }
}

impl Encode for ieee1609dot2::SignedDataPayload<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [self.data.is_some(), self.ext_data_hash.is_some()];
        encode_extension_and_optional_bitmap(self.omitted.is_some(), &bitmap, output)?;
        self.data
            .as_ref()
            .map_or(Ok(()), |data| data.encode(output))?;
        self.ext_data_hash
            .as_ref()
            .map_or(Ok(()), |hash| hash.encode(output))?;
        self.omitted
            .map_or(Ok(()), |()| encode_oer_varlength_bitstring(&[true], output))
    }
}

impl Encode for ieee1609dot2::Ieee1609Dot2Content<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            _ => todo!(),
        }
    }
}

encode_int!(
    ieee1609dot2::Uint64,
    Some(0),
    Some(18_446_744_073_709_551_615)
);

impl Encode for ieee1609dot2::HeaderInfo<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let is_extended = self.inline_p2pcd_request.is_some()
            || self.requested_certificate.is_some()
            || self.pdu_functional_type.is_some()
            || self.contributed_extensions.is_some();
        let bitmap = [
            self.generation_time.is_some(),
            self.expiry_time.is_some(),
            self.generation_location.is_some(),
            self.p2pcd_learning_request.is_some(),
            self.missing_crl_identifier.is_some(),
            self.encryption_key.is_some(),
        ];
        encode_extension_and_optional_bitmap(is_extended, &bitmap, output)?;
        self.psid.encode(output)?;
        self.generation_time
            .as_ref()
            .map_or(Ok(()), |time| time.encode(output))?;
        self.expiry_time
            .as_ref()
            .map_or(Ok(()), |time| time.encode(output))?;
        self.generation_location
            .as_ref()
            .map_or(Ok(()), |location| location.encode(output))?;
        self.p2pcd_learning_request
            .as_ref()
            .map_or(Ok(()), |id| id.encode(output))?;
        self.missing_crl_identifier
            .as_ref()
            .map_or(Ok(()), |id| id.encode(output))?;
        self.encryption_key
            .as_ref()
            .map_or(Ok(()), |enc_key| enc_key.encode(output))?;
        let ext_bitmap = [
            self.inline_p2pcd_request.is_some(),
            self.requested_certificate.is_some(),
            self.pdu_functional_type.is_some(),
            self.contributed_extensions.is_some(),
        ];
        if is_extended {
            encode_oer_varlength_bitstring(&ext_bitmap, output)
        } else {
            Ok(())
        }?;
        self.inline_p2pcd_request
            .as_ref()
            .map_or(Ok(()), |request| encode_oer_open_type(request, output))?;
        self.requested_certificate
            .as_ref()
            .map_or(Ok(()), |cert| encode_oer_open_type(cert, output))?;
        self.pdu_functional_type
            .as_ref()
            .map_or(Ok(()), |ty| encode_oer_open_type(ty, output))?;
        self.contributed_extensions
            .as_ref()
            .map_or(Ok(()), |ext| encode_oer_open_type(ext, output))?;
        Ok(())
    }
}

impl Encode for ieee1609dot2::MissingCrlIdentifier<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_extension_and_optional_bitmap(false, &[], output)?;
        self.craca_id.encode(output)?;
        self.crl_series.encode(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_oer_integer() {
        let mut encoder = Encoder::new();
        encode_oer_integer(Some(0), Some(255), &3u8, &mut encoder).unwrap();
        assert_eq!(
            &[3],
            <encode::Encoder as std::convert::Into<Vec<u8>>>::into(encoder).as_slice()
        );
        let mut encoder = Encoder::new();
        ieee1609dot2::Uint8(3).encode(&mut encoder).unwrap();
        assert_eq!(
            &[3],
            <encode::Encoder as std::convert::Into<Vec<u8>>>::into(encoder).as_slice()
        );
        let mut encoder = Encoder::new();
        encode_oer_integer(Some(-900_000_000), Some(900_000_001), &32i32, &mut encoder).unwrap();
        assert_eq!(
            &[0, 0, 0, 32],
            <encode::Encoder as std::convert::Into<Vec<u8>>>::into(encoder).as_slice()
        );
        let mut encoder = Encoder::new();
        ieee1609dot2::NinetyDegreeInt(32)
            .encode(&mut encoder)
            .unwrap();
        assert_eq!(
            &[0, 0, 0, 32],
            <encode::Encoder as std::convert::Into<Vec<u8>>>::into(encoder).as_slice()
        );
    }
}
