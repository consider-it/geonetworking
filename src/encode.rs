extern crate alloc;

use core::fmt::Display;

use crate::{decode::BitwiseDecodable, util::write_into_vec_left_padded};
use arbitrary_int::{traits::Integer, u10};
use bitvec::prelude::*;
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

pub trait Encode {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError>;

    fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder)?;
        Ok(encoder.into())
    }

    #[cfg(feature = "json")]
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
fn write_as_int<I: num::Integer + ToBytes + Display>(
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

impl Encode for u10 {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let value = self.as_u16();
        let mut bv: bitvec::vec::BitVec<u8, Msb0> = BitVec::new();
        for i in 0..10 {
            // we need to store MSB first
            // just creating an Lsb0 BitVec and storing LSB first didn't work
            bv.push((value << i & 0x0200) > 0);
        }

        output.bits.extend_from_bitslice(bv.as_bitslice());
        Ok(())
    }
}

impl Encode for u4 {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let value = self.as_u8();
        let mut bv: bitvec::vec::BitVec<u8, Msb0> = BitVec::new();
        for i in 0..4 {
            // we need to store MSB first
            // just creating an Lsb0 BitVec and storing LSB first didn't work
            bv.push((value << i & 0x08) > 0);
        }

        output.bits.extend_from_bitslice(bv.as_bitslice());
        Ok(())
    }
}

impl Encode for [bool; 8] {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let mut bv: bitvec::vec::BitVec<u8, Msb0> = BitVec::new();
        for bit in self {
            bv.push(*bit);
        }

        output.bits.extend_from_bitslice(bv.as_bitslice());
        Ok(())
    }
}

impl Encode for &'_ [u8] {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        output.bits.extend_from_bitslice(self.as_bits::<Msb0>());
        Ok(())
    }
}

impl Encode for Lifetime {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.0, 8, output)
    }
}

impl Encode for Timestamp {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.0, 32, output)
    }
}

impl Encode for StationType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&(*self as u8), 5, output)
    }
}

impl Encode for Address {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.manually_configured.encode(output)?;
        self.station_type.encode(output)?;
        self.reserved.encode(output)?;
        self.address.encode(output)
    }
}

impl Encode for NextAfterBasic {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&(*self as u8), 4, output)
    }
}

impl Encode for BasicHeader {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.version, 4, output)?;
        self.next_header.encode(output)?;
        write_as_int(&self.reserved, 8, output)?;
        self.lifetime.encode(output)?;
        write_as_int(&self.remaining_hop_limit, 8, output)
    }
}

impl Encode for LongPositionVector {
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

impl Encode for ShortPositionVector {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.gn_address.encode(output)?;
        self.timestamp.encode(output)?;
        write_as_int(&self.latitude, 32, output)?;
        write_as_int(&self.longitude, 32, output)
    }
}

impl Encode for TrafficClass {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.store_carry_forward.encode(output)?;
        self.channel_offload.encode(output)?;
        write_as_int(&self.traffic_class_id, 6, output)
    }
}

impl Encode for NextAfterCommon {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&(*self as u8), 4, output)
    }
}

impl Encode for HeaderType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let (ty, subty) = match self {
            HeaderType::Any => (0, 0),
            HeaderType::Beacon => (1, 0),
            HeaderType::GeoUnicast => (2, 0),
            HeaderType::GeoAnycast(AreaType::Circular) => (3, 0),
            HeaderType::GeoAnycast(AreaType::Rectangular) => (3, 1),
            HeaderType::GeoAnycast(_) => (3, 2),
            HeaderType::GeoBroadcast(AreaType::Circular) => (4, 0),
            HeaderType::GeoBroadcast(AreaType::Rectangular) => (4, 1),
            HeaderType::GeoBroadcast(_) => (4, 2),
            HeaderType::TopologicallyScopedBroadcast(BroadcastType::SingleHop) => (5, 0),
            HeaderType::TopologicallyScopedBroadcast(_) => (5, 1),
            HeaderType::LocationService(LocationServiceType::Request) => (6, 0),
            HeaderType::LocationService(_) => (6, 1),
        };
        write_as_int(&ty, 4, output)?;
        write_as_int(&subty, 4, output)
    }
}

impl Encode for CommonHeader {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.next_header.encode(output)?;
        self.reserved_1.encode(output)?;
        self.header_type_and_subtype.encode(output)?;
        self.traffic_class.encode(output)?;
        self.flags.encode(output)?;
        write_as_int(&self.payload_length, 16, output)?;
        write_as_int(&self.maximum_hop_limit, 8, output)?;
        write_as_int(&self.reserved_2, 8, output)
    }
}

impl Encode for GeoAnycast {
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

impl Encode for GeoUnicast {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        self.reserved.encode(output)?;
        self.source_position_vector.encode(output)?;
        self.destination_position_vector.encode(output)
    }
}

impl Encode for TopologicallyScopedBroadcast {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        self.reserved.encode(output)?;
        self.source_position_vector.encode(output)
    }
}

impl Encode for SingleHopBroadcast {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.source_position_vector.encode(output)?;
        self.media_dependent_data.encode(output)
    }
}

impl Encode for Beacon {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.source_position_vector.encode(output)
    }
}

impl Encode for LSRequest {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        write_as_int(&self.reserved, 16, output)?;
        self.source_position_vector.encode(output)?;
        self.request_gn_address.encode(output)
    }
}

impl Encode for LSReply {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        write_as_int(&self.sequence_number, 16, output)?;
        write_as_int(&self.reserved, 16, output)?;
        self.source_position_vector.encode(output)?;
        self.destination_position_vector.encode(output)
    }
}

impl Encode for Option<ExtendedHeader> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Some(ExtendedHeader::Beacon(b)) => b.encode(output),
            Some(ExtendedHeader::GAC(gac)) => gac.encode(output),
            Some(ExtendedHeader::GBC(gbc)) => gbc.encode(output),
            Some(ExtendedHeader::GUC(guc)) => guc.encode(output),
            Some(ExtendedHeader::LSReply(lsr)) => lsr.encode(output),
            Some(ExtendedHeader::LSRequest(lsr)) => lsr.encode(output),
            Some(ExtendedHeader::SHB(shb)) => shb.encode(output),
            Some(ExtendedHeader::TSB(tsb)) => tsb.encode(output),
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

// =====================================================
// ETSI TS 103 097/ IEEE 1609.2
// =====================================================

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

fn encode_oer_integer<I: num::Integer + ToBytes>(
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
fn encode_oer_fixed_bitstring(value: &[bool], output: &mut Encoder) -> Result<(), EncodeError> {
    let mut bv: bitvec::vec::BitVec<u8, Msb0> = BitVec::new();
    for bit in value {
        bv.push(*bit);
    }
    output.bits.extend_from_bitslice(bv.as_bitslice());

    let padding_bits = util::bitstring_padding_bits(value.len());
    for _ in 0..padding_bits {
        output.bits.push(false);
    }

    Ok(())
}

// ASN.1 OER "bitstring" values and the "extension addition presence bitmap"
fn encode_oer_varlength_bitstring(value: &[bool], output: &mut Encoder) -> Result<(), EncodeError> {
    encode_oer_length(util::bitstring_buffer_size(value.len()) + 1, output)?;

    let unused_bits = util::bitstring_padding_bits(value.len());

    // Note: using integer encoding is not 100% correct, but leads to same result in this case
    #[allow(clippy::cast_possible_truncation)]
    encode_oer_integer(Some(0), Some(8), &(unused_bits as u8), output)?;

    for bit in value {
        output.bits.push(*bit);
    }

    // add padding bits
    for _ in 0..unused_bits {
        output.bits.push(false);
    }

    Ok(())
}

/// Build ASN.1 SEQUENCE preamble
///
/// Extension bit is optional
#[allow(clippy::unnecessary_wraps, reason = "common interface")]
fn encode_extension_and_optional_bitmap(
    extension: Option<bool>,
    bitmap: &[bool],
    output: &mut Encoder,
) -> Result<(), EncodeError> {
    if let Some(is_extended) = extension {
        output.bits.push(is_extended);
    }

    for bit in bitmap {
        output.bits.push(*bit);
    }

    // determine required padding bits
    let padding_bits = util::bitstring_padding_bits(output.bits.len());

    for _ in 0..padding_bits {
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

impl<const SIZE: usize> Encode for BitString<SIZE> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_fixed_bitstring(&self.0, output)
    }
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

encode_int!(Latitude, Some(-900_000_000), Some(900_000_001));
encode_int!(Longitude, Some(-1_799_999_999), Some(1_800_000_001));
encode_int!(PduFunctionalType, Some(0), Some(255));
encode_int!(HeaderInfoContributorId, Some(0), Some(255));
encode_int!(Uint8, Some(0), Some(255));
encode_int!(Uint16, Some(0), Some(65535));
encode_int!(Uint32, Some(0), Some(4_294_967_295));
encode_int!(ExtId, Some(0), Some(255));
encode_int!(Psid, Some(0), None);

impl Encode for CertificateBase<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [self.signature.is_some()];
        encode_extension_and_optional_bitmap(None, &bitmap, output)?;

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

encode_octets!(LinkageValue<'_>, Some(9), Some(9));
encode_octets!(HashedId3<'_>, Some(3), Some(3));
encode_octets!(HashedId8<'_>, Some(8), Some(8));
encode_octets!(SubjectAssurance<'_>, Some(1), Some(1));
encode_octets!(BitmapSsp<'_>, Some(0), Some(31));
encode_octets!(Opaque<'_>, Some(0), None);
encode_octets!(HashedId32<'_>, Some(32), Some(32));
encode_octets!(HashedId48<'_>, Some(48), Some(48));

impl Encode for CertificateType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_enumerated(*self as u8, output)
    }
}

impl Encode for HashAlgorithm {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_enumerated(*self as u8, output)
    }
}

impl Encode for IssuerIdentifier<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            IssuerIdentifier::Sha256AndDigest(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            IssuerIdentifier::RsSelf(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            IssuerIdentifier::Sha384AndDigest(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
            IssuerIdentifier::Sm3AndDigest(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for ToBeSignedCertificate<'_> {
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
        encode_extension_and_optional_bitmap(Some(is_extended), &bitmap, output)?;

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
        self.flags
            .as_ref()
            .map_or(Ok(()), |flags| encode_oer_open_type(flags, output))?;
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

impl Encode for AppExtension<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(output)?;
        encode_oer_octetstring(Some(0), None, self.content, output)
    }
}

impl Encode for CertIssueExtensionPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            CertIssueExtensionPermissions::Specific(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(0), None, inner, output)
            }
            CertIssueExtensionPermissions::All(()) => encode_oer_tag(1, output),
        }
    }
}

impl Encode for CertRequestExtensionPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            CertRequestExtensionPermissions::Content(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(0), None, inner, output)
            }
            CertRequestExtensionPermissions::All(()) => encode_oer_tag(1, output),
        }
    }
}

impl Encode for CertIssueExtension<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(output)?;
        self.permissions.encode(output)
    }
}

impl Encode for CertRequestExtension<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(output)?;
        self.permissions.encode(output)
    }
}

impl Encode for VerificationKeyIndicator<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            VerificationKeyIndicator::VerificationKey(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            VerificationKeyIndicator::ReconstructionValue(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for PublicVerificationKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            PublicVerificationKey::EcdsaNistP256(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            PublicVerificationKey::EcdsaBrainpoolP256r1(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            PublicVerificationKey::EcdsaBrainpoolP384r1(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
            PublicVerificationKey::EcdsaNistP384(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_open_type(inner, output)
            }
            PublicVerificationKey::EcsigSm2(inner) => {
                encode_oer_tag(4, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for PsidGroupPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [
            self.min_chain_length == 1,
            self.chain_length_range == 0,
            self.ee_type
                == EndEntityType::from([true, false, false, false, false, false, false, false]),
        ];
        encode_extension_and_optional_bitmap(None, &bitmap, output)?;

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

impl Encode for EndEntityType {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.0.encode(output)
    }
}

impl Encode for PsidSsp<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [self.ssp.is_some()];
        encode_extension_and_optional_bitmap(None, &bitmap, output)?;

        self.psid.encode(output)?;
        self.ssp.as_ref().map_or(Ok(()), |ssp| ssp.encode(output))
    }
}

impl Encode for PsidSspRange<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [self.ssp_range.is_some()];
        encode_extension_and_optional_bitmap(None, &bitmap, output)?;

        self.psid.encode(output)?;
        self.ssp_range
            .as_ref()
            .map_or(Ok(()), |ssp| ssp.encode(output))
    }
}

impl Encode for BitmapSspRange<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(1), Some(32), self.ssp_value, output)?;
        encode_oer_octetstring(Some(1), Some(32), self.ssp_bitmask, output)
    }
}

impl Encode for SspRange<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            SspRange::Opaque(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            SspRange::All(()) => encode_oer_tag(1, output),
            SspRange::BitmapSspRange(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for SubjectPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            SubjectPermissions::Explicit(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            SubjectPermissions::All(()) => encode_oer_tag(1, output),
        }
    }
}

impl Encode for ServiceSpecificPermissions<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            ServiceSpecificPermissions::Opaque(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(0), None, inner, output)
            }
            ServiceSpecificPermissions::BitmapSsp(inner) => {
                encode_oer_tag(1, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for BasePublicEncryptionKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            BasePublicEncryptionKey::EciesNistP256(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            BasePublicEncryptionKey::EciesBrainpoolP256r1(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            BasePublicEncryptionKey::EcencSm2(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for EccP256CurvePoint<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            EccP256CurvePoint::XOnly(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(32), Some(32), inner, output)
            }
            EccP256CurvePoint::Fill(()) => encode_oer_tag(1, output),
            EccP256CurvePoint::CompressedY0(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_octetstring(Some(32), Some(32), inner, output)
            }
            EccP256CurvePoint::CompressedY1(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_octetstring(Some(32), Some(32), inner, output)
            }
            EccP256CurvePoint::UncompressedP256(inner) => {
                encode_oer_tag(4, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for EccP384CurvePoint<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            EccP384CurvePoint::XOnly(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(48), Some(48), inner, output)
            }
            EccP384CurvePoint::Fill(()) => encode_oer_tag(1, output),
            EccP384CurvePoint::CompressedY0(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_octetstring(Some(48), Some(48), inner, output)
            }
            EccP384CurvePoint::CompressedY1(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_octetstring(Some(48), Some(48), inner, output)
            }
            EccP384CurvePoint::UncompressedP384(inner) => {
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

encode_sequence_of!(SequenceOfUint16);
encode_sequence_of!(SequenceOfUint8);
encode_sequence_of!(SequenceOfRegionAndSubregions);
encode_sequence_of!(SequenceOfRectangularRegion);
encode_sequence_of!(SequenceOfIdentifiedRegion);
encode_sequence_of!(PolygonalRegion);
encode_sequence_of!(SequenceOfPsidSspRange<'_>);
encode_sequence_of!(SequenceOfPsid);
encode_sequence_of!(SequenceOfPsidSsp<'_>);
encode_sequence_of!(SequenceOfOctetString<'_>);
encode_sequence_of!(SequenceOfPsidGroupPermissions<'_>);
encode_sequence_of!(SequenceOfAppExtensions<'_>);
encode_sequence_of!(SequenceOfCertIssueExtensions<'_>);
encode_sequence_of!(SequenceOfCertRequestExtensions<'_>);
encode_sequence_of!(SequenceOfHashedId3<'_>);
encode_sequence_of!(ContributedExtensionBlocks<'_>);
encode_sequence_of!(ContributedExtensionBlockExtns<'_>);

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

encode_sequence!(ValidityPeriod, start, duration);
encode_sequence!(CountryAndRegions, country_only, regions);
encode_sequence!(RegionAndSubregions, region, subregions);
encode_sequence!(CountryAndSubregions, country_only, region_and_subregions);
encode_sequence!(ThreeDLocation, latitude, longitude, elevation);
encode_sequence!(TwoDLocation, latitude, longitude);
encode_sequence!(RectangularRegion, north_west, south_east);
encode_sequence!(CircularRegion, center, radius);
encode_sequence!(PublicEncryptionKey<'_>, supported_symm_alg, public_key);
encode_sequence!(ToBeSignedData<'_>, payload, header_info);
encode_sequence!(Ieee1609Dot2Data<'_>, protocol_version, content);
encode_sequence!(ContributedExtensionBlock<'_>, contributor_id, extns);

impl Encode for SymmAlgorithm {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_enumerated(*self as u8, output)
    }
}

impl Encode for GeographicRegion {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            GeographicRegion::CircularRegion(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            GeographicRegion::RectangularRegion(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            GeographicRegion::PolygonalRegion(inner) => {
                encode_oer_tag(2, output)?;
                inner.encode(output)
            }
            GeographicRegion::IdentifiedRegion(inner) => {
                encode_oer_tag(3, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for IdentifiedRegion {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            IdentifiedRegion::CountryOnly(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            IdentifiedRegion::CountryAndRegions(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            IdentifiedRegion::CountryAndSubregions(inner) => {
                encode_oer_tag(2, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for Duration {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Duration::Microseconds(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Duration::Milliseconds(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Duration::Seconds(inner) => {
                encode_oer_tag(2, output)?;
                inner.encode(output)
            }
            Duration::Minutes(inner) => {
                encode_oer_tag(3, output)?;
                inner.encode(output)
            }
            Duration::Hours(inner) => {
                encode_oer_tag(4, output)?;
                inner.encode(output)
            }
            Duration::SixtyHours(inner) => {
                encode_oer_tag(5, output)?;
                inner.encode(output)
            }
            Duration::Years(inner) => {
                encode_oer_tag(6, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for CertificateId<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            CertificateId::LinkageData(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            CertificateId::Name(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            CertificateId::BinaryId(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_octetstring(Some(1), Some(64), inner, output)
            }
            CertificateId::None(()) => encode_oer_tag(3, output),
        }
    }
}

impl Encode for Hostname {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(0), Some(255), self.0.as_bytes(), output)
    }
}

impl Encode for LinkageData<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [self.group_linkage_value.is_some()];
        encode_extension_and_optional_bitmap(None, &bitmap, output)?;

        self.i_cert.encode(output)?;
        self.linkage_value.encode(output)?;
        self.group_linkage_value
            .as_ref()
            .map_or(Ok(()), |glv| glv.encode(output))
    }
}

impl Encode for GroupLinkageValue<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(4), Some(4), self.j_value, output)?;
        encode_oer_octetstring(Some(9), Some(9), self.value, output)
    }
}

impl Encode for EccP256CurvePointUncompressedP256<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(32), Some(32), self.x, output)?;
        encode_oer_octetstring(Some(32), Some(32), self.y, output)
    }
}

impl Encode for EccP384CurvePointUncompressedP384<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(48), Some(48), self.x, output)?;
        encode_oer_octetstring(Some(48), Some(48), self.y, output)
    }
}

impl Encode for EcsigP256Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(32), Some(32), self.r_sig, output)?;
        encode_oer_octetstring(Some(32), Some(32), self.s_sig, output)
    }
}

impl Encode for EcdsaP256Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.r_sig.encode(output)?;
        encode_oer_octetstring(Some(32), Some(32), self.s_sig, output)
    }
}

impl Encode for EcdsaP384Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        self.r_sig.encode(output)?;
        encode_oer_octetstring(Some(48), Some(48), self.s_sig, output)
    }
}

impl Encode for Signature<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Signature::EcdsaNistP256Signature(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            Signature::EcdsaBrainpoolP256r1Signature(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
            Signature::EcdsaBrainpoolP384r1Signature(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
            Signature::EcdsaNistP384Signature(inner) => {
                encode_oer_tag(3, output)?;
                encode_oer_open_type(inner, output)
            }
            Signature::Sm2Signature(inner) => {
                encode_oer_tag(4, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for HashedData<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            HashedData::Sha256HashedData(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            HashedData::Sha384HashedData(inner) => {
                encode_oer_tag(1, output)?;
                encode_oer_open_type(inner, output)
            }
            HashedData::Sm3HashedData(inner) => {
                encode_oer_tag(2, output)?;
                encode_oer_open_type(inner, output)
            }
        }
    }
}

impl Encode for EncryptionKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            EncryptionKey::Public(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            EncryptionKey::Symmetric(inner) => {
                encode_oer_tag(1, output)?;
                inner.encode(output)
            }
        }
    }
}

impl Encode for SymmetricEncryptionKey<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            SymmetricEncryptionKey::Aes128Ccm(inner) => {
                encode_oer_tag(0, output)?;
                encode_oer_octetstring(Some(16), Some(16), inner, output)
            }
            SymmetricEncryptionKey::Sm4Ccm(inner) => {
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

impl Encode for AnonymousContributedExtensionBlockExtns<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_oer_octetstring(Some(0), None, self.0, output)
    }
}

impl Encode for SignedDataPayload<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        let bitmap = [self.data.is_some(), self.ext_data_hash.is_some()];
        encode_extension_and_optional_bitmap(Some(self.omitted.is_some()), &bitmap, output)?;

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

impl Encode for Ieee1609Dot2Content<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Ieee1609Dot2Content::UnsecuredData(inner) => {
                encode_oer_tag(0, output)?;
                inner.encode(output)
            }
            _ => todo!(),
        }
    }
}

encode_int!(Uint64, Some(0), Some(18_446_744_073_709_551_615));

impl Encode for HeaderInfo<'_> {
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
        encode_extension_and_optional_bitmap(Some(is_extended), &bitmap, output)?;

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

impl Encode for MissingCrlIdentifier<'_> {
    fn encode(&self, output: &mut Encoder) -> Result<(), EncodeError> {
        encode_extension_and_optional_bitmap(Some(false), &[], output)?;

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
        Uint8(3).encode(&mut encoder).unwrap();
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
        NinetyDegreeInt(32).encode(&mut encoder).unwrap();
        assert_eq!(
            &[0, 0, 0, 32],
            <encode::Encoder as std::convert::Into<Vec<u8>>>::into(encoder).as_slice()
        );
    }

    #[test]
    fn encodes_oer_bitstring() {
        let mut encoder = Encoder::new();
        encode_oer_fixed_bitstring(&[true], &mut encoder).unwrap();
        let output: Vec<u8> = encoder.into();
        assert_eq!(&[0x80], output.as_slice());

        let mut encoder = Encoder::new();
        encode_oer_fixed_bitstring(
            &[true, false, false, false, false, false, false, false],
            &mut encoder,
        )
        .unwrap();
        let output: Vec<u8> = encoder.into();
        assert_eq!(&[0x80], output.as_slice());

        let mut encoder = Encoder::new();
        encode_oer_fixed_bitstring(
            &[
                true, false, false, false, false, false, false, false, false, true,
            ],
            &mut encoder,
        )
        .unwrap();
        let output: Vec<u8> = encoder.into();
        assert_eq!(&[0x80, 0x40], output.as_slice());

        let mut encoder = Encoder::new();
        encode_oer_varlength_bitstring(&[true, false], &mut encoder).unwrap();
        let output: Vec<u8> = encoder.into();
        assert_eq!(&[2, 6, 0x80], output.as_slice());

        let mut encoder = Encoder::new();
        encode_oer_varlength_bitstring(
            &[true, false, false, false, false, false, false, false],
            &mut encoder,
        )
        .unwrap();
        let output: Vec<u8> = encoder.into();
        assert_eq!(&[2, 0, 0x80], output.as_slice());

        let mut encoder = Encoder::new();
        encode_oer_varlength_bitstring(
            &[
                true, false, false, false, false, false, false, false, false, true,
            ],
            &mut encoder,
        )
        .unwrap();
        let output: Vec<u8> = encoder.into();
        assert_eq!(&[3, 6, 0x80, 0x40], output.as_slice());

        let mut encoder = Encoder::new();
        encode_oer_varlength_bitstring(
            &[
                true, false, false, false, false, false, false, false, false, true, false, false,
                false, false, true, false,
            ],
            &mut encoder,
        )
        .unwrap();
        let output: Vec<u8> = encoder.into();
        assert_eq!(&[3, 0, 0x80, 0x42], output.as_slice());
    }
}
