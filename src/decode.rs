extern crate alloc;

use bitvec::prelude::*;
use nom::{
    bytes::streaming::take,
    combinator::{into, map, map_res},
    error::{ErrorKind, FromExternalError, ParseError},
    sequence::{pair, tuple},
    Needed, Parser,
};
use nom_bitvec::BSlice;
use num::{FromPrimitive, Integer};
#[cfg(not(any(feature = "validate", test)))]
use num_traits::float::FloatCore;

use crate::{
    util::{cast_nom_err, write_into_vec_left_padded},
    *,
};

type DecodeIn<'input> = BSlice<'input, u8, Msb0>;

/// Returns the value of a decoding attempt
#[derive(Debug, PartialEq)]
pub struct Decoded<T: Debug + PartialEq> {
    /// indicates the number of bytes that were consumed by the decoder
    pub bytes_consumed: usize,
    /// the decoded return value
    pub decoded: T,
}

pub trait Decode<'s>: Sized + Debug + PartialEq {
    /// Decoder trait for decoding the individual fields of the GeoNetworking header
    /// Takes binary data as input.
    /// The `Decoder` trait is implemented for all higher-order fields of the
    /// GeoNetworking header:
    ///  - `Packet`
    ///  - `BasicHeader`
    ///  - `CommonHeader`
    ///  - `Ieee1609Dot2Data` (a.k.a. Secured Header)
    ///  - `GeoUnicast`
    ///  - `TopologicallyScopedBroadcast`
    ///  - `SingleHopBroadcast`
    ///  - `GeoBroadcast`
    ///  - `GeoAnycast`
    ///  - `Beacon`
    ///  - `LSRequest`
    ///  - `LSReply`
    /// ### Usage
    /// ```rust
    /// # use geonetworking::*;
    /// let data: &'static [u8] = &[
    ///   0x12, 0x00, 0x15, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x82, 0x02, 0x7c, 0x20,
    ///   0x51, 0x01, 0x00, 0x02, 0x58, 0x01, 0x00, 0x12, 0x52, 0x00, 0x00, 0x3c, 0x00, 0x04,
    ///   0xe5, 0x48, 0x10, 0xc7, 0x2e, 0x71, 0x25, 0xab, 0x00, 0x1f, 0xeb, 0xef, 0x74, 0x05,
    ///   0xf2, 0xaf, 0x27, 0x80, 0x00, 0x00, 0x00,
    /// ];
    /// result = BasicHeader::decode(data).unwrap();
    /// assert_eq!(
    ///   result,
    ///   Decoded {
    ///     bytes_consumed: 4,
    ///     decoded: BasicHeader {
    ///         version: 1,
    ///         next_header: NextAfterBasic::SecuredPacket,
    ///         reserved: crate::bits!(0;8),
    ///         lifetime: Lifetime(21),
    ///         remaining_hop_limit: 1
    ///     }
    ///   }
    /// );
    /// ```
    fn decode<'input: 's, I: Into<&'input [u8]>>(
        input: I,
    ) -> Result<Decoded<Self>, DecodeError<&'input [u8]>>;
}

macro_rules! decode {
    ($typ:ty) => {
        impl<'s> Decode<'s> for $typ {
            fn decode<'input: 's, I: Into<&'input [u8]>>(
                input: I,
            ) -> Result<Decoded<Self>, DecodeError<&'input [u8]>> {
                let input = input.into();
                let (remaining, header) = <$typ>::decode_bytewise(input)?;
                Ok(Decoded {
                    bytes_consumed: input.len() - remaining.len(),
                    decoded: header,
                })
            }
        }
    };
}

decode!(Packet<'s>);
decode!(BasicHeader);
decode!(CommonHeader);
decode!(Ieee1609Dot2Data<'s>);
decode!(GeoUnicast);
decode!(TopologicallyScopedBroadcast);
decode!(SingleHopBroadcast);
decode!(GeoBroadcast);
decode!(Beacon);
decode!(LSRequest);
decode!(LSReply);
decode!(Certificate<'s>);
decode!(ToBeSignedData<'s>);

/// Helper struct for decoding unsecured GeoNetworking headers from JSON.
/// This crate focuses on zero-copy decoding from binary packets,
/// therefore, JSON deserialization features are limited to a
/// subset of GeoNetworking types.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct UnsecuredHeader {
    pub basic: BasicHeader,
    pub common: CommonHeader,
    pub extended: Option<ExtendedHeader>,
}

impl UnsecuredHeader {
    #[cfg(feature = "json")]
    /// Tries to deserialize an unsecured GeoNetworking header
    /// from JSON.
    /// ### Usage
    /// ```
    /// # use geonetworking::*;
    /// let json_header = r#"{"basic":{"version":1,"next_header":"CommonHeader","reserved":[false,false,false,false,false,false,false,false],"lifetime":80,"remaining_hop_limit":1},"secured":null,"common":{"next_header":"BTPB","reserved_1":[false,false,false,false],"header_type_and_subtype":{"TopologicallyScopedBroadcast":"SingleHop"},"traffic_class":{"store_carry_forward":false,"channel_offload":false,"traffic_class_id":2},"flags":[false,false,false,false,false,false,false,false],"payload_length":8,"maximum_hop_limit":1,"reserved_2":[false,false,false,false,false,false,false,false]},"extended":{"SHB":{"source_position_vector":{"gn_address":{"manually_configured":false,"station_type":"Unknown","reserved":[false,true,false,false,false,false,false,true,true,false],"address":[0,96,224,105,87,141]},"timestamp":542947520,"latitude":535574568,"longitude":99765648,"position_accuracy":false,"speed":680,"heading":2122},"media_dependent_data":[127,0,184,0]}}}"#;
    /// let payload: &'static [u8] = &[0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03];
    /// let unsecured_header = UnsecuredHeader::from_json(json_header).unwrap();
    /// let unsecured_packet: Packet = unsecured_header.with_payload(payload);
    /// ```
    pub fn from_json(json: &str) -> Result<Self, DecodeError<&str>> {
        serde_json::from_str(json).map_err(|e| DecodeError::Json(alloc::format!("{e:?}")))
    }

    /// Converts the `UnsecuredHeader` helper struct into a regular `Packet::Unsecured`.
    /// Takes a payload of the length specified in the GeoNetworking's Common Header.
    pub fn with_payload(self, payload: &[u8]) -> Result<Packet<'_>, EncodeError> {
        if self.common.payload_length as usize == payload.len() {
            Ok(Packet::Unsecured {
                basic: self.basic,
                common: self.common,
                extended: self.extended,
                payload,
            })
        } else {
            Err(EncodeError::Common(alloc::format!(
                "Payload length {} does not match `payload_length` field {} in Common Header",
                payload.len(),
                self.common.payload_length
            )))
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DecodeError<I> {
    IntegerError(alloc::string::String),
    EnumError(alloc::string::String),
    StringError(alloc::string::String),
    ArrayError(alloc::string::String),
    ParserError(alloc::string::String),
    Nom(I, ErrorKind),
    #[cfg(feature = "json")]
    Json(alloc::string::String),
}

impl<T> From<nom::Err<DecodeError<T>>> for DecodeError<T> {
    fn from(value: nom::Err<DecodeError<T>>) -> Self {
        match value {
            nom::Err::Incomplete(Needed::Size(n)) => DecodeError::ParserError(alloc::format!(
                "Unexpected end of input: Needs at least other {n} bytes!"
            )),
            nom::Err::Incomplete(_) => DecodeError::ParserError("Unexpected end of input!".into()),
            nom::Err::Error(e) | nom::Err::Failure(e) => e,
        }
    }
}

impl From<DecodeError<DecodeIn<'_>>> for DecodeError<&'_ [u8]> {
    fn from(value: DecodeError<DecodeIn<'_>>) -> Self {
        match value {
            DecodeError::IntegerError(s) => Self::IntegerError(s),
            DecodeError::EnumError(s) => Self::EnumError(s),
            DecodeError::StringError(s) => Self::StringError(s),
            DecodeError::ArrayError(s) => Self::ArrayError(s),
            DecodeError::ParserError(s) => Self::ParserError(s),
            DecodeError::Nom(_, k) => Self::Nom(&[], k),
            #[cfg(feature = "json")]
            DecodeError::Json(s) => Self::Json(s),
        }
    }
}

impl From<DecodeError<&'_ [u8]>> for DecodeError<DecodeIn<'_>> {
    fn from(value: DecodeError<&'_ [u8]>) -> Self {
        match value {
            DecodeError::IntegerError(s) => Self::IntegerError(s),
            DecodeError::EnumError(s) => Self::EnumError(s),
            DecodeError::StringError(s) => Self::StringError(s),
            DecodeError::ArrayError(s) => Self::ArrayError(s),
            DecodeError::ParserError(s) => Self::ParserError(s),
            DecodeError::Nom(_, k) => Self::Nom([0u8].bitwise(), k),
            #[cfg(feature = "json")]
            DecodeError::Json(s) => Self::Json(s),
        }
    }
}

impl<I> ParseError<I> for DecodeError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        DecodeError::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I, E> FromExternalError<I, E> for DecodeError<I> {
    fn from_external_error(input: I, kind: ErrorKind, _: E) -> Self {
        DecodeError::Nom(input, kind)
    }
}

pub type IResult<I, T> = nom::IResult<I, T, DecodeError<I>>;

pub(crate) trait BitwiseDecodable {
    /// Trait implemented by binary input data formats
    /// that can be decoded using the `Decode` trait
    fn bitwise(&self) -> DecodeIn<'_>;
}

macro_rules! impl_decodable {
    ($typ:ty) => {
        impl BitwiseDecodable for $typ {
            fn bitwise(&self) -> DecodeIn<'_> {
                DecodeIn::from(BitSlice::<u8, Msb0>::from_slice(self))
            }
        }
    };
}

impl_decodable![alloc::vec::Vec<u8>];
impl_decodable![Bytes];
impl_decodable![&[u8]];

impl<const SIZE: usize> BitwiseDecodable for [u8; SIZE] {
    fn bitwise(&self) -> DecodeIn<'_> {
        DecodeIn::from(BitSlice::<u8, Msb0>::from_slice(self))
    }
}

impl BitwiseDecodable for BitVec<u8, Msb0> {
    fn bitwise(&self) -> DecodeIn<'_> {
        DecodeIn::from(self.as_bitslice())
    }
}
trait InternalDecode<'s> {
    fn decode_bitwise(_: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        unimplemented!("This type does not support bitwise decoding!")
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized;
}

impl<'s> InternalDecode<'s> for i32 {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map_res(take(32usize), |bits: DecodeIn<'_>| {
            let mut vec = vec![];
            write_into_vec_left_padded(bits, &mut vec);
            vec.try_into().map(i32::from_be_bytes).map_err(|_| {
                DecodeError::IntegerError::<DecodeIn>(
                    "Integer value does not fit into 32 bits!".into(),
                )
            })
        })(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for bool {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map(take(1u8), |bits: DecodeIn<'_>| bits[0])(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

fn read_as_uint<'input, I: Integer + FromPrimitive>(
    bit_count: usize,
) -> impl FnMut(DecodeIn<'input>) -> IResult<DecodeIn<'input>, I> {
    map_res(take(bit_count), |bits: DecodeIn<'_>| {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let padding_bytes = 16 - ((bits.len() as f64 / 8.).ceil() as usize);
        let mut vec = alloc::vec![0u8; padding_bytes];

        write_into_vec_left_padded(bits, &mut vec);

        match vec.try_into() {
            Ok(arr) => I::from_i128(i128::from_be_bytes(arr)).ok_or_else(|| {
                DecodeError::IntegerError::<DecodeIn>(alloc::format!(
                    "Integer value does not fit into {} bits!",
                    bits.len()
                ))
            }),
            Err(_) => Err(DecodeError::IntegerError(
                "Error fitting bit slice into 16 bytes!".into(),
            )),
        }
    })
}

fn read_speed_value(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, i16> {
    map_res(take(15usize), |bits: DecodeIn<'_>| {
        let mut bitvec = bits.to_bitvec();
        if bitvec[0] {
            bitvec.insert(1, false);
        }
        let mut vec = alloc::vec![];

        write_into_vec_left_padded(bitvec.bitwise(), &mut vec);

        vec.try_into().map(i16::from_be_bytes).map_err(|_| {
            DecodeError::IntegerError::<DecodeIn>(
                "Integer value does not fit into 16 signed bits!".into(),
            )
        })
    })(input)
}

impl<'s, const SIZE: usize> InternalDecode<'s> for Bits<SIZE> {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map(take(SIZE), |bits: DecodeIn<'_>| Bits(bits.to_bitvec()))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s, const SIZE: usize> InternalDecode<'s> for [u8; SIZE] {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map_res(take(SIZE * 8), |bits: DecodeIn<'_>| {
            bits.chunks(8)
                .map(bitvec::field::BitField::load_be::<u8>)
                .collect::<alloc::vec::Vec<u8>>()
                .try_into()
                .map_err(|_| {
                    DecodeError::ArrayError::<DecodeIn>(alloc::format!(
                        "Failed to fit bits into byte vec of size {SIZE}"
                    ))
                })
        })(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for Address {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            bool::decode_bitwise,
            StationType::decode_bitwise,
            Bits::<10>::decode_bitwise,
            <[u8; 6]>::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(bool, StationType, Bits<10>, [u8; 6])> for Address {
    fn from(value: (bool, StationType, Bits<10>, [u8; 6])) -> Self {
        Self {
            manually_configured: value.0,
            station_type: value.1,
            reserved: value.2,
            address: value.3,
        }
    }
}

impl<'s> InternalDecode<'s> for StationType {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map_res(read_as_uint::<u8>(5), |val| match val {
            0 => Ok::<StationType, DecodeError<DecodeIn>>(Self::Unknown),
            1 => Ok(Self::Pedestrian),
            2 => Ok(Self::Cyclist),
            3 => Ok(Self::Moped),
            4 => Ok(Self::Motorcycle),
            5 => Ok(Self::PassengerCar),
            6 => Ok(Self::Bus),
            7 => Ok(Self::LightTruck),
            8 => Ok(Self::HeavyTruck),
            9 => Ok(Self::Trailer),
            10 => Ok(Self::SpecialVehicle),
            11 => Ok(Self::Tram),
            15 => Ok(Self::RoadSideUnit),
            i => Err(DecodeError::EnumError(alloc::format!(
                "No corresponding station type for value {i}!"
            ))),
        })(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for BasicHeader {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            read_as_uint(4),
            NextAfterBasic::decode_bitwise,
            Bits::<8>::decode_bitwise,
            Lifetime::decode_bitwise,
            read_as_uint(8),
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(u8, NextAfterBasic, Bits<8>, Lifetime, u8)> for BasicHeader {
    fn from(value: (u8, NextAfterBasic, Bits<8>, Lifetime, u8)) -> Self {
        Self {
            version: value.0,
            next_header: value.1,
            reserved: value.2,
            lifetime: value.3,
            remaining_hop_limit: value.4,
        }
    }
}

impl<'s> InternalDecode<'s> for NextAfterBasic {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map_res(read_as_uint::<u8>(4), |val| match val {
            0 => Ok::<NextAfterBasic, DecodeError<DecodeIn>>(Self::Any),
            1 => Ok(Self::CommonHeader),
            2 => Ok(Self::SecuredPacket),
            i => Err(DecodeError::EnumError(alloc::format!(
                "No corresponding header type for value {i}!"
            ))),
        })(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for Lifetime {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map(read_as_uint::<u8>(8), Lifetime)(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for Timestamp {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map(read_as_uint::<u32>(32), Timestamp)(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for LongPositionVector {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            Address::decode_bitwise,
            Timestamp::decode_bitwise,
            i32::decode_bitwise,
            i32::decode_bitwise,
            bool::decode_bitwise,
            read_speed_value,
            read_as_uint(16),
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(Address, Timestamp, i32, i32, bool, i16, u16)> for LongPositionVector {
    fn from(value: (Address, Timestamp, i32, i32, bool, i16, u16)) -> Self {
        Self {
            gn_address: value.0,
            timestamp: value.1,
            latitude: value.2,
            longitude: value.3,
            position_accuracy: value.4,
            speed: value.5,
            heading: value.6,
        }
    }
}

impl<'s> InternalDecode<'s> for ShortPositionVector {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            Address::decode_bitwise,
            Timestamp::decode_bitwise,
            i32::decode_bitwise,
            i32::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(Address, Timestamp, i32, i32)> for ShortPositionVector {
    fn from(value: (Address, Timestamp, i32, i32)) -> Self {
        Self {
            gn_address: value.0,
            timestamp: value.1,
            latitude: value.2,
            longitude: value.3,
        }
    }
}

impl<'s> InternalDecode<'s> for TrafficClass {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            bool::decode_bitwise,
            bool::decode_bitwise,
            read_as_uint(6),
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(bool, bool, u8)> for TrafficClass {
    fn from(value: (bool, bool, u8)) -> Self {
        Self {
            store_carry_forward: value.0,
            channel_offload: value.1,
            traffic_class_id: value.2,
        }
    }
}

impl<'s> InternalDecode<'s> for NextAfterCommon {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map_res(read_as_uint::<u8>(4), |val| match val {
            0 => Ok::<NextAfterCommon, DecodeError<DecodeIn>>(Self::Any),
            1 => Ok(Self::BTPA),
            2 => Ok(Self::BTPB),
            3 => Ok(Self::IPv6),
            i => Err(DecodeError::EnumError(alloc::format!(
                "No corresponding header type for value {i}!"
            ))),
        })(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for HeaderType {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        map_res(
            pair(read_as_uint(4), read_as_uint(4)),
            |(ty, subtype): (u8, u8)| {
                let error = DecodeError::EnumError::<DecodeIn>(alloc::format!(
                    "No corresponding header type for value {ty} and subtype value {subtype}!"
                ));
                match ty {
                    0 => Ok::<HeaderType, DecodeError<DecodeIn>>(Self::Any),
                    1 => Ok(Self::Beacon),
                    2 => Ok(Self::GeoUnicast),
                    3 => match subtype {
                        0 => Ok(Self::GeoAnycast(AreaType::Circular)),
                        1 => Ok(Self::GeoAnycast(AreaType::Rectangular)),
                        2 => Ok(Self::GeoAnycast(AreaType::Ellipsoidal)),
                        _ => Err(error),
                    },
                    4 => match subtype {
                        0 => Ok(Self::GeoBroadcast(AreaType::Circular)),
                        1 => Ok(Self::GeoBroadcast(AreaType::Rectangular)),
                        2 => Ok(Self::GeoBroadcast(AreaType::Ellipsoidal)),
                        _ => Err(error),
                    },
                    5 => match subtype {
                        0 => Ok(Self::TopologicallyScopedBroadcast(BroadcastType::SingleHop)),
                        1 => Ok(Self::TopologicallyScopedBroadcast(BroadcastType::MultiHop)),
                        _ => Err(error),
                    },
                    6 => match subtype {
                        0 => Ok(Self::LocationService(LocationServiceType::Request)),
                        1 => Ok(Self::LocationService(LocationServiceType::Reply)),
                        _ => Err(error),
                    },
                    _ => Err(error),
                }
            },
        )(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl<'s> InternalDecode<'s> for CommonHeader {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            NextAfterCommon::decode_bitwise,
            Bits::<4>::decode_bitwise,
            HeaderType::decode_bitwise,
            TrafficClass::decode_bitwise,
            Bits::<8>::decode_bitwise,
            read_as_uint(16),
            read_as_uint(8),
            Bits::<8>::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl
    From<(
        NextAfterCommon,
        Bits<4>,
        HeaderType,
        TrafficClass,
        Bits<8>,
        u16,
        u8,
        Bits<8>,
    )> for CommonHeader
{
    fn from(
        value: (
            NextAfterCommon,
            Bits<4>,
            HeaderType,
            TrafficClass,
            Bits<8>,
            u16,
            u8,
            Bits<8>,
        ),
    ) -> Self {
        Self {
            next_header: value.0,
            reserved_1: value.1,
            header_type_and_subtype: value.2,
            traffic_class: value.3,
            flags: value.4,
            payload_length: value.5,
            maximum_hop_limit: value.6,
            reserved_2: value.7,
        }
    }
}

impl<'s> InternalDecode<'s> for GeoAnycast {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            read_as_uint(16),
            Bits::<16>::decode_bitwise,
            LongPositionVector::decode_bitwise,
            i32::decode_bitwise,
            i32::decode_bitwise,
            read_as_uint(16),
            read_as_uint(16),
            read_as_uint(16),
            Bits::<16>::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl
    From<(
        u16,
        Bits<16>,
        LongPositionVector,
        i32,
        i32,
        u16,
        u16,
        u16,
        Bits<16>,
    )> for GeoAnycast
{
    fn from(
        value: (
            u16,
            Bits<16>,
            LongPositionVector,
            i32,
            i32,
            u16,
            u16,
            u16,
            Bits<16>,
        ),
    ) -> Self {
        Self {
            sequence_number: value.0,
            reserved_1: value.1,
            source_position_vector: value.2,
            geo_area_position_latitude: value.3,
            geo_area_position_longitude: value.4,
            distance_a: value.5,
            distance_b: value.6,
            angle: value.7,
            reserved_2: value.8,
        }
    }
}

impl<'s> InternalDecode<'s> for GeoUnicast {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            read_as_uint(16),
            Bits::<16>::decode_bitwise,
            LongPositionVector::decode_bitwise,
            ShortPositionVector::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(u16, Bits<16>, LongPositionVector, ShortPositionVector)> for GeoUnicast {
    fn from(value: (u16, Bits<16>, LongPositionVector, ShortPositionVector)) -> Self {
        Self {
            sequence_number: value.0,
            reserved: value.1,
            source_position_vector: value.2,
            destination_position_vector: value.3,
        }
    }
}

impl<'s> InternalDecode<'s> for TopologicallyScopedBroadcast {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            read_as_uint(16),
            Bits::<16>::decode_bitwise,
            LongPositionVector::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(u16, Bits<16>, LongPositionVector)> for TopologicallyScopedBroadcast {
    fn from(value: (u16, Bits<16>, LongPositionVector)) -> Self {
        Self {
            sequence_number: value.0,
            reserved: value.1,
            source_position_vector: value.2,
        }
    }
}

impl<'s> InternalDecode<'s> for SingleHopBroadcast {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            LongPositionVector::decode_bitwise,
            <[u8; 4]>::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(LongPositionVector, [u8; 4])> for SingleHopBroadcast {
    fn from(value: (LongPositionVector, [u8; 4])) -> Self {
        Self {
            source_position_vector: value.0,
            media_dependent_data: value.1,
        }
    }
}

impl<'s> InternalDecode<'s> for Beacon {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(LongPositionVector::decode_bitwise)(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<LongPositionVector> for Beacon {
    fn from(value: LongPositionVector) -> Self {
        Self {
            source_position_vector: value,
        }
    }
}

impl<'s> InternalDecode<'s> for LSRequest {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            read_as_uint(16),
            Bits::<16>::decode_bitwise,
            LongPositionVector::decode_bitwise,
            Address::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(u16, Bits<16>, LongPositionVector, Address)> for LSRequest {
    fn from(value: (u16, Bits<16>, LongPositionVector, Address)) -> Self {
        Self {
            sequence_number: value.0,
            reserved: value.1,
            source_position_vector: value.2,
            request_gn_address: value.3,
        }
    }
}

impl<'s> InternalDecode<'s> for LSReply {
    fn decode_bitwise(input: DecodeIn<'_>) -> IResult<DecodeIn<'_>, Self>
    where
        Self: Sized,
    {
        into(tuple((
            read_as_uint(16),
            Bits::<16>::decode_bitwise,
            LongPositionVector::decode_bitwise,
            ShortPositionVector::decode_bitwise,
        )))(input)
    }

    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (remaining, instance) = Self::decode_bitwise(input.bitwise()).map_err(cast_nom_err)?;
        Ok((
            &input[(input.len() - Integer::div_ceil(&remaining.len(), &8usize))..],
            instance,
        ))
    }
}

impl From<(u16, Bits<16>, LongPositionVector, ShortPositionVector)> for LSReply {
    fn from(value: (u16, Bits<16>, LongPositionVector, ShortPositionVector)) -> Self {
        Self {
            sequence_number: value.0,
            reserved: value.1,
            source_position_vector: value.2,
            destination_position_vector: value.3,
        }
    }
}

fn wrap_in_some<'input, T, F>(
    parser: F,
) -> impl FnMut(DecodeIn<'input>) -> IResult<DecodeIn<'input>, Option<T>>
where
    F: FnMut(DecodeIn<'input>) -> IResult<DecodeIn<'input>, T>,
{
    map(parser, |res| Some(res))
}

fn read_extended(
    header_type_and_subclass: HeaderType,
    input: DecodeIn<'_>,
) -> IResult<DecodeIn<'_>, Option<ExtendedHeader>> {
    match header_type_and_subclass {
        HeaderType::Any => Ok((input, None)),
        HeaderType::Beacon => {
            wrap_in_some(map(Beacon::decode_bitwise, ExtendedHeader::Beacon))(input)
        }
        HeaderType::GeoUnicast => {
            wrap_in_some(map(GeoUnicast::decode_bitwise, ExtendedHeader::GUC))(input)
        }
        HeaderType::GeoAnycast(_) => {
            wrap_in_some(map(GeoAnycast::decode_bitwise, ExtendedHeader::GAC))(input)
        }
        HeaderType::GeoBroadcast(_) => {
            wrap_in_some(map(GeoAnycast::decode_bitwise, ExtendedHeader::GBC))(input)
        }
        HeaderType::TopologicallyScopedBroadcast(BroadcastType::SingleHop) => {
            wrap_in_some(map(SingleHopBroadcast::decode_bitwise, ExtendedHeader::SHB))(input)
        }
        HeaderType::TopologicallyScopedBroadcast(_) => wrap_in_some(map(
            TopologicallyScopedBroadcast::decode_bitwise,
            ExtendedHeader::TSB,
        ))(input),
        HeaderType::LocationService(LocationServiceType::Request) => {
            wrap_in_some(map(LSRequest::decode_bitwise, ExtendedHeader::LSRequest))(input)
        }
        HeaderType::LocationService(_) => {
            wrap_in_some(map(LSReply::decode_bitwise, ExtendedHeader::LSReply))(input)
        }
    }
}

impl<'s> InternalDecode<'s> for Packet<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, basic) = BasicHeader::decode_bytewise(input)?;
        if basic.next_header == NextAfterBasic::SecuredPacket {
            let (remaining, secured) = Ieee1609Dot2Data::decode_bytewise(input)?;
            let data_payload = secured.data_payload().ok_or_else(|| {
                nom::Err::Error(DecodeError::<&[u8]>::ParserError(
                    "Could not retrieve payload from IEEE1609.2 Data!".into(),
                ))
            })?;
            let (input, common) =
                CommonHeader::decode_bitwise(data_payload.bitwise()).map_err(cast_nom_err)?;
            let (_, extended) =
                read_extended(common.header_type_and_subtype, input).map_err(cast_nom_err)?;
            Ok((
                remaining,
                Self::Secured {
                    basic,
                    secured,
                    common,
                    extended,
                },
            ))
        } else {
            let bitwise = input.bitwise();
            let (remaining, common) =
                CommonHeader::decode_bitwise(bitwise).map_err(cast_nom_err)?;
            let (remaining, extended) =
                read_extended(common.header_type_and_subtype, remaining).map_err(cast_nom_err)?;
            if (bitwise.len() - remaining.len()) % 8 != 0 {
                return Err(nom::Err::Error(DecodeError::ParserError(
                    "Bit Error: Unexpected unalignment!".into(),
                )));
            }
            let input = &input[((bitwise.len() - remaining.len()) / 8)..];
            let (input, payload) = take(common.payload_length)(input)?;
            Ok((
                input,
                Self::Unsecured {
                    basic,
                    common,
                    extended,
                    payload,
                },
            ))
        }
    }
}

// =====================================================
// ETSI TS 103 097/ IEEE 1609.2
// =====================================================

struct Slice<'i>(&'i [u8]);

impl<'i> From<&'i [u8]> for Slice<'i> {
    fn from(value: &'i [u8]) -> Self {
        Self(value)
    }
}

impl<'i, const SIZE: usize> TryInto<[u8; SIZE]> for Slice<'i> {
    type Error = nom::Err<DecodeError<&'i [u8]>>;

    fn try_into(self) -> Result<[u8; SIZE], Self::Error> {
        match self.0.len() {
            len if len == SIZE => Ok(self.0.try_into().unwrap()),
            len if len > SIZE => Err(nom::Err::Error(DecodeError::IntegerError(
                "Length exceeds supported integer range!".into(),
            ))),
            len => {
                let mut padding = alloc::vec![0; SIZE - len];
                padding.extend_from_slice(self.0);
                padding.try_into().map_err(|e| {
                    nom::Err::Error(DecodeError::IntegerError(alloc::format!(
                        "Failed to read length: {e:?}"
                    )))
                })
            }
        }
    }
}

fn decode_bytewise_length(input: &[u8]) -> IResult<&[u8], usize> {
    let (input, byte) = take(1usize)(input)?;
    match byte[0] {
        len if len < 128 => Ok((input, len.into())),
        len => {
            let (input, bytes): (&[u8], Slice) =
                into(take::<u8, &[u8], DecodeError<&[u8]>>(len & 0b0111_1111))(input)?;
            let length = bytes.try_into().map(usize::from_be_bytes)?;
            Ok((input, length))
        }
    }
}

macro_rules! int {
    ($typ:ty, $count:expr, $from:path) => {
        map_res(take($count), |bytes: &[u8]| {
            Slice::from(bytes)
                .try_into()
                .map(<$typ>::from_be_bytes)
                .map_err(|e| alloc::format!("Failed to read length: {e:?}"))
                .and_then(|int| $from(int).ok_or("Failed to fit value into integer type!".into()))
                .map_err(|e| nom::Err::Error(DecodeError::<&[u8]>::IntegerError(e)))
        })
    };
}

fn decode_bytewise_integer<I: Integer + FromPrimitive>(
    min: Option<i128>,
    max: Option<i128>,
    extensible: bool,
    input: &[u8],
) -> IResult<&[u8], I> {
    match (min, max, extensible) {
        (Some(min), Some(max), false) if min >= 0 && max <= 255 => {
            int!(u8, 1usize, I::from_u8)(input)
        }
        (Some(min), Some(max), false) if min >= 0 && max <= 65535 => {
            int!(u16, 2usize, I::from_u16)(input)
        }
        (Some(min), Some(max), false) if min >= 0 && max <= 4_294_967_295 => {
            int!(u32, 4usize, I::from_u32)(input)
        }
        (Some(min), Some(max), false) if min >= 0 && max <= 18_446_744_073_709_551_615 => {
            int!(u64, 8usize, I::from_u64)(input)
        }
        (Some(min), _, false) if min >= 0 => {
            let (input, length) = decode_bytewise_length(input)?;
            int!(u128, length, I::from_u128)(input)
        }
        (Some(min), Some(max), false) if min >= -128 && max <= 127 => {
            int!(i8, 1usize, I::from_i8)(input)
        }
        (Some(min), Some(max), false) if min >= -32768 && max <= 32767 => {
            int!(i16, 2usize, I::from_i16)(input)
        }
        (Some(min), Some(max), false) if min >= -2_147_483_648 && max <= 2_147_483_647 => {
            int!(i32, 4usize, I::from_i32)(input)
        }
        (Some(min), Some(max), false)
            if min >= -9_223_372_036_854_775_808 && max <= 9_223_372_036_854_775_807 =>
        {
            int!(i64, 8usize, I::from_i64)(input)
        }
        _ => {
            let (input, length) = decode_bytewise_length(input)?;
            int!(i128, length, I::from_i128)(input)
        }
    }
}

fn decode_bytewise_enumerated<E: TryFrom<i128>>(input: &[u8]) -> IResult<&[u8], E> {
    let (input, byte) = take(1usize)(input)?;
    match byte[0] {
        len if len < 128 => i128::from(len)
            .try_into()
            .map(|variant| (input, variant))
            .map_err(|_| nom::Err::Error(DecodeError::EnumError("Invalid enum index!".into()))),
        len => {
            let (input, bytes): (&[u8], Slice) =
                into(take::<u8, &[u8], DecodeError<&[u8]>>(len & 0b0111_1111))(input)?;
            let length = bytes.try_into().map(i128::from_be_bytes)?;
            length
                .try_into()
                .map(|variant| (input, variant))
                .map_err(|_| nom::Err::Error(DecodeError::EnumError("Invalid enum index!".into())))
        }
    }
}

/// Extracts bits from ASN.1 buffer
///
/// First bit is the MSB of the first byte in ASN.1
fn bitslice_to_bitvec(buffer: &[u8], offset: usize, count: usize) -> Vec<bool> {
    let mut bitvec = vec![];

    // iterate using 0-based index
    for i in offset..(offset + count) {
        let byte_idx = Integer::div_floor(&i, &8);
        let bit_idx = (8 - (i % 8)) - 1;

        bitvec.push((buffer[byte_idx] >> bit_idx & 0x01) > 0);
    }

    bitvec
}

/// Decodes ASN.1 SEQUENCE preamble
///
/// Note: Only execute, if there is either an extension bit or optional values present!
/// (Otherwise the sequence preamble will be omitted.)
fn decode_bytewise_sequence_preamble(
    has_extension: bool,
    presence_bits: usize,
    input: &[u8],
) -> IResult<&[u8], (bool, Vec<bool>)> {
    let (input, preamble) = take(util::bitstring_buffer_size(presence_bits))(input)?;

    let (ext, bitmap) = if has_extension {
        let extension = (preamble[0] & 0b1000_0000) > 0;
        let bitstring = bitslice_to_bitvec(preamble, 1, presence_bits);

        (extension, bitstring)
    } else {
        let bitstring = bitslice_to_bitvec(preamble, 0, presence_bits);

        (false, bitstring)
    };

    Ok((input, (ext, bitmap)))
}

// ASN.1 OER "bitstring" values
// ASN.1 OER "extension addition presence bitmap", if used without constraints or as extensible
fn decode_bytewise_bitstring(
    min: Option<usize>,
    max: Option<usize>,
    extensible: bool,
    input: &[u8],
) -> IResult<&[u8], Vec<bool>> {
    match (min, max, extensible) {
        (Some(min), Some(max), false) if min == max => {
            let (input, bytes) = take(util::bitstring_buffer_size(max))(input)?;

            let mut bitstring = vec![];
            for byte in bytes {
                for i in (0..8).rev() {
                    bitstring.push((byte >> i & 0x01) > 0);
                }
            }

            let to_pop = 8 - max % 8;
            if to_pop != 8 {
                (0..to_pop).for_each(|_| {
                    bitstring.pop();
                });
            }
            Ok((input, bitstring))
        }
        _ => {
            // length includes second (unused_bits) byte and subsequent bytes
            let (input, length) = decode_bytewise_length(input)?;

            // Note: using integer encoding is not 100% correct, but leads to same result in this case
            let (input, unused_bits) =
                decode_bytewise_integer::<usize>(Some(0), Some(8), false, input)?;
            if unused_bits > 7 {
                return Err(nom::Err::Error(DecodeError::ParserError(
                    alloc::format!("Extension addition presence bitmap contains invalid unused bits indication: {unused_bits}"),
            )));
            }

            let (input, bytes) = take(length - 1)(input)?;

            let mut bitstring = vec![];
            for byte in bytes {
                for i in (0..8).rev() {
                    bitstring.push((byte >> i & 0x01) > 0);
                }
            }

            // remove padding bits
            (0..unused_bits).for_each(|_| {
                bitstring.pop();
            });

            Ok((input, bitstring))
        }
    }
}

impl<'s, const SIZE: usize> InternalDecode<'s> for BitString<SIZE> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (rem, bitvec) = decode_bytewise_bitstring(Some(SIZE), Some(SIZE), false, input)?;
        Ok((rem, Self::from(bitvec)))
    }
}

fn decode_bytewise_octetstring(
    min: Option<usize>,
    max: Option<usize>,
    extensible: bool,
    input: &[u8],
) -> IResult<&[u8], &[u8]> {
    match (min, max, extensible) {
        (Some(min), Some(max), false) if min == max => {
            into(take::<usize, &[u8], DecodeError<&[u8]>>(max))(input)
        }
        _ => {
            let (input, length) = decode_bytewise_length(input)?;
            take::<usize, &[u8], DecodeError<&[u8]>>(length)(input)
        }
    }
}

fn decode_bytewise_tag(input: &[u8]) -> IResult<&[u8], u64> {
    let (input, byte) = take(1usize)(input)?;
    match byte[0] & 0b0011_1111 {
        len if len < 63 => Ok((input, len.into())),
        _ => unimplemented!(),
    }
}

fn decode_bytewise_open_type<'input, T, F>(
    decoder: F,
    input: &'input [u8],
) -> IResult<&'input [u8], T>
where
    F: Fn(&'input [u8]) -> IResult<&'input [u8], T>,
{
    let (input, length) = decode_bytewise_length(input)?;
    take(length).and_then(decoder).parse(input)
}

macro_rules! uint {
    ($typ:ty, $max:expr) => {
        impl<'s> InternalDecode<'s> for $typ {
            fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
            where
                Self: Sized,
            {
                let (input, inner) = decode_bytewise_integer(Some(0), $max, false, input)?;
                Ok((input, Self(inner)))
            }
        }
    };
}

uint!(Uint3, Some(7));
uint!(Uint8, Some(255));
uint!(ExtId, Some(255));
uint!(HeaderInfoContributorId, Some(255));
uint!(PduFunctionalType, Some(255));
uint!(Uint16, Some(65535));
uint!(Uint32, Some(4_294_967_295));
uint!(Uint64, Some(18_446_744_073_709_551_615));
uint!(Psid, None);

macro_rules! octets {
    ($typ:ty, $min:expr, $max:expr) => {
        impl<'s> InternalDecode<'s> for $typ {
            fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
            where
                Self: Sized,
            {
                let (input, inner) = decode_bytewise_octetstring($min, $max, false, input)?;
                Ok((input, Self(inner)))
            }
        }
    };
}

octets!(HashedId3<'s>, Some(3), Some(3));
octets!(HashedId8<'s>, Some(8), Some(8));
octets!(HashedId10<'s>, Some(10), Some(10));
octets!(HashedId32<'s>, Some(32), Some(32));
octets!(HashedId48<'s>, Some(48), Some(48));
octets!(Opaque<'s>, Some(0), None);
octets!(BitmapSsp<'s>, Some(0), Some(31));
octets!(SubjectAssurance<'s>, Some(1), Some(1));
octets!(LinkageValue<'s>, Some(9), Some(9));
octets!(LaId<'s>, Some(2), Some(2));
octets!(LinkageSeed<'s>, Some(16), Some(16));

macro_rules! enumerated {
    ($typ:ty) => {
        impl<'s> InternalDecode<'s> for $typ {
            fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
            where
                Self: Sized,
            {
                decode_bytewise_enumerated(input)
            }
        }
    };
}

enumerated!(HashAlgorithm);
enumerated!(SymmAlgorithm);
enumerated!(CertificateType);

macro_rules! sequence_of {
    ($typ:ty, $inner:ty, $min:expr, $max:expr) => {
        impl<'s> InternalDecode<'s> for $typ {
            fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
            where
                Self: Sized,
            {
                let mut sequence_of = alloc::vec![];
                let (mut input, count) = decode_bytewise_integer($min, $max, false, input)?;
                for _ in (0..count) {
                    let (rem, item) = <$inner>::decode_bytewise(input)?;
                    input = rem;
                    sequence_of.push(item);
                }
                Ok((input, Self(sequence_of)))
            }
        }
    };
}

sequence_of!(SequenceOfUint8, Uint8, Some(0), None);
sequence_of!(SequenceOfUint16, Uint16, Some(0), None);
sequence_of!(SequenceOfHashedId3<'s>, HashedId3, Some(0), None);
sequence_of!(
    SequenceOfRectangularRegion,
    RectangularRegion,
    Some(0),
    None
);
sequence_of!(SequenceOfIdentifiedRegion, IdentifiedRegion, Some(0), None);
sequence_of!(
    SequenceOfRegionAndSubregions,
    RegionAndSubregions,
    Some(0),
    None
);
sequence_of!(SequenceOfPsidSsp<'s>, PsidSsp, Some(0), None);
sequence_of!(SequenceOfPsidSspRange<'s>, PsidSspRange, Some(0), None);
sequence_of!(SequenceOfPsid, Psid, Some(0), None);
sequence_of!(SequenceOfLinkageSeed<'s>, LinkageSeed, Some(0), None);
sequence_of!(SequenceOfRecipientInfo<'s>, RecipientInfo, Some(0), None);
sequence_of!(SequenceOfAppExtensions<'s>, AppExtension, Some(1), None);
sequence_of!(
    SequenceOfCertIssueExtensions<'s>,
    CertIssueExtension,
    Some(1),
    None
);
sequence_of!(
    SequenceOfCertRequestExtensions<'s>,
    CertRequestExtension,
    Some(1),
    None
);
sequence_of!(SequenceOfCertificate<'s>, Certificate, Some(0), None);
sequence_of!(
    SequenceOfPsidGroupPermissions<'s>,
    PsidGroupPermissions,
    Some(0),
    None
);
sequence_of!(PolygonalRegion, TwoDLocation, Some(3), None);
sequence_of!(
    ContributedExtensionBlocks<'s>,
    ContributedExtensionBlock,
    Some(1),
    None
);

impl<'s> InternalDecode<'s> for SequenceOfOctetString<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let mut sequence_of = alloc::vec![];
        let (mut input, count) = decode_bytewise_integer(Some(0), None, false, input)?;
        for _ in 0..count {
            let (rem, item) = decode_bytewise_octetstring(Some(0), None, false, input)?;
            input = rem;
            sequence_of.push(item);
        }
        Ok((input, Self(sequence_of)))
    }
}

impl<'s> InternalDecode<'s> for Duration {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        let (input, inner) = Uint16::decode_bytewise(input)?;
        match tag {
            0 => Ok((input, Duration::Microseconds(inner))),
            1 => Ok((input, Duration::Milliseconds(inner))),
            2 => Ok((input, Duration::Seconds(inner))),
            3 => Ok((input, Duration::Minutes(inner))),
            4 => Ok((input, Duration::Hours(inner))),
            5 => Ok((input, Duration::SixtyHours(inner))),
            6 => Ok((input, Duration::Years(inner))),
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for ValidityPeriod {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, start) = Time32::decode_bytewise(input)?;
        let (input, duration) = Duration::decode_bytewise(input)?;
        Ok((input, Self { start, duration }))
    }
}

impl<'s> InternalDecode<'s> for EccP256CurvePointUncompressedP256<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, x) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
        let (input, y) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
        Ok((input, Self { x, y }))
    }
}

impl<'s> InternalDecode<'s> for EccP256CurvePoint<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, bytes) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
                Ok((input, EccP256CurvePoint::XOnly(bytes)))
            }
            1 => Ok((input, EccP256CurvePoint::Fill(()))),
            2 => {
                let (input, bytes) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
                Ok((input, EccP256CurvePoint::CompressedY0(bytes)))
            }
            3 => {
                let (input, bytes) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
                Ok((input, EccP256CurvePoint::CompressedY1(bytes)))
            }
            4 => {
                let (input, inner) = EccP256CurvePointUncompressedP256::decode_bytewise(input)?;
                Ok((input, EccP256CurvePoint::UncompressedP256(inner)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for EccP384CurvePointUncompressedP384<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, x) = decode_bytewise_octetstring(Some(48), Some(48), false, input)?;
        let (input, y) = decode_bytewise_octetstring(Some(48), Some(48), false, input)?;
        Ok((input, Self { x, y }))
    }
}

impl<'s> InternalDecode<'s> for EccP384CurvePoint<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, bytes) = decode_bytewise_octetstring(Some(48), Some(48), false, input)?;
                Ok((input, EccP384CurvePoint::XOnly(bytes)))
            }
            1 => Ok((input, EccP384CurvePoint::Fill(()))),
            2 => {
                let (input, bytes) = decode_bytewise_octetstring(Some(48), Some(48), false, input)?;
                Ok((input, EccP384CurvePoint::CompressedY0(bytes)))
            }
            3 => {
                let (input, bytes) = decode_bytewise_octetstring(Some(48), Some(48), false, input)?;
                Ok((input, EccP384CurvePoint::CompressedY1(bytes)))
            }
            4 => {
                let (input, inner) = EccP384CurvePointUncompressedP384::decode_bytewise(input)?;
                Ok((input, EccP384CurvePoint::UncompressedP384(inner)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for EcencP256EncryptedKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, v) = EccP256CurvePoint::decode_bytewise(input)?;
        let (input, c) = decode_bytewise_octetstring(Some(16), Some(16), false, input)?;
        let (input, t) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
        Ok((input, Self { v, c, t }))
    }
}

impl<'s> InternalDecode<'s> for EciesP256EncryptedKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, v) = EccP256CurvePoint::decode_bytewise(input)?;
        let (input, c) = decode_bytewise_octetstring(Some(16), Some(16), false, input)?;
        let (input, t) = decode_bytewise_octetstring(Some(16), Some(16), false, input)?;
        Ok((input, Self { v, c, t }))
    }
}

impl<'s> InternalDecode<'s> for BasePublicEncryptionKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, pt) = EccP256CurvePoint::decode_bytewise(input)?;
                Ok((input, BasePublicEncryptionKey::EciesNistP256(pt)))
            }
            1 => {
                let (input, pt) = EccP256CurvePoint::decode_bytewise(input)?;
                Ok((input, BasePublicEncryptionKey::EciesBrainpoolP256r1(pt)))
            }
            2 => {
                let (input, pt) =
                    decode_bytewise_open_type(EccP256CurvePoint::decode_bytewise, input)?;
                Ok((input, BasePublicEncryptionKey::EcencSm2(pt)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for PublicEncryptionKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, supported_symm_alg) = SymmAlgorithm::decode_bytewise(input)?;
        let (input, public_key) = BasePublicEncryptionKey::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                supported_symm_alg,
                public_key,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for SymmetricEncryptionKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, aes) = decode_bytewise_octetstring(Some(16), Some(16), false, input)?;
                Ok((input, SymmetricEncryptionKey::Aes128Ccm(aes)))
            }
            1 => {
                let (input, sm) = decode_bytewise_open_type(
                    |i| decode_bytewise_octetstring(Some(16), Some(16), false, i),
                    input,
                )?;
                Ok((input, SymmetricEncryptionKey::Sm4Ccm(sm)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for EncryptionKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, public) = PublicEncryptionKey::decode_bytewise(input)?;
                Ok((input, EncryptionKey::Public(public)))
            }
            1 => {
                let (input, symm) = SymmetricEncryptionKey::decode_bytewise(input)?;
                Ok((input, EncryptionKey::Symmetric(symm)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for GeographicRegion {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, region) = CircularRegion::decode_bytewise(input)?;
                Ok((input, GeographicRegion::CircularRegion(region)))
            }
            1 => {
                let (input, region) = SequenceOfRectangularRegion::decode_bytewise(input)?;
                Ok((input, GeographicRegion::RectangularRegion(region)))
            }
            2 => {
                let (input, region) = PolygonalRegion::decode_bytewise(input)?;
                Ok((input, GeographicRegion::PolygonalRegion(region)))
            }
            3 => {
                let (input, region) = SequenceOfIdentifiedRegion::decode_bytewise(input)?;
                Ok((input, GeographicRegion::IdentifiedRegion(region)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for CircularRegion {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, center) = TwoDLocation::decode_bytewise(input)?;
        let (input, radius) = Uint16::decode_bytewise(input)?;
        Ok((input, Self { center, radius }))
    }
}

impl<'s> InternalDecode<'s> for RectangularRegion {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, north_west) = TwoDLocation::decode_bytewise(input)?;
        let (input, south_east) = TwoDLocation::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                north_west,
                south_east,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for TwoDLocation {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, latitude) = Latitude::decode_bytewise(input)?;
        let (input, longitude) = Longitude::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                latitude,
                longitude,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for IdentifiedRegion {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, region) = UnCountryId::decode_bytewise(input)?;
                Ok((input, IdentifiedRegion::CountryOnly(region)))
            }
            1 => {
                let (input, region) = CountryAndRegions::decode_bytewise(input)?;
                Ok((input, IdentifiedRegion::CountryAndRegions(region)))
            }
            2 => {
                let (input, region) = CountryAndSubregions::decode_bytewise(input)?;
                Ok((input, IdentifiedRegion::CountryAndSubregions(region)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for CountryAndRegions {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, country_only) = UnCountryId::decode_bytewise(input)?;
        let (input, regions) = SequenceOfUint8::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                country_only,
                regions,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for CountryAndSubregions {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, country_only) = UnCountryId::decode_bytewise(input)?;
        let (input, region_and_subregions) = SequenceOfRegionAndSubregions::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                country_only,
                region_and_subregions,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for RegionAndSubregions {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, region) = Uint8::decode_bytewise(input)?;
        let (input, subregions) = SequenceOfUint16::decode_bytewise(input)?;
        Ok((input, Self { region, subregions }))
    }
}

impl<'s> InternalDecode<'s> for ThreeDLocation {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, latitude) = Latitude::decode_bytewise(input)?;
        let (input, longitude) = Longitude::decode_bytewise(input)?;
        let (input, elevation) = Elevation::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                latitude,
                longitude,
                elevation,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for NinetyDegreeInt {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, int) =
            decode_bytewise_integer(Some(-900_000_000), Some(900_000_001), false, input)?;
        Ok((input, Self(int)))
    }
}

impl<'s> InternalDecode<'s> for OneEightyDegreeInt {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, int) =
            decode_bytewise_integer(Some(-1_799_999_999), Some(1_800_000_001), false, input)?;
        Ok((input, Self(int)))
    }
}

impl<'s> InternalDecode<'s> for GroupLinkageValue<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, j_value) = decode_bytewise_octetstring(Some(4), Some(4), false, input)?;
        let (input, value) = decode_bytewise_octetstring(Some(9), Some(9), false, input)?;
        Ok((input, Self { j_value, value }))
    }
}

impl<'s> InternalDecode<'s> for Hostname {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, utf8) = decode_bytewise_octetstring(Some(0), Some(255), false, input)?;
        let hostname = alloc::string::String::from_utf8(utf8.to_vec()).map_err(|_| {
            nom::Err::Error(DecodeError::StringError(
                "Unable to decode UTF8 bytes!".into(),
            ))
        })?;
        Ok((input, Self(hostname)))
    }
}

impl<'s> InternalDecode<'s> for PsidSsp<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (_, bitmap)) = decode_bytewise_sequence_preamble(false, 1, input)?;

        let (input, psid) = Psid::decode_bytewise(input)?;
        let (input, ssp) = if bitmap[0] {
            map(ServiceSpecificPermissions::decode_bytewise, |inner| {
                Some(inner)
            })(input)?
        } else {
            (input, None)
        };
        Ok((input, Self { psid, ssp }))
    }
}

impl<'s> InternalDecode<'s> for ServiceSpecificPermissions<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, opaque) = decode_bytewise_octetstring(Some(0), None, false, input)?;
                Ok((input, ServiceSpecificPermissions::Opaque(opaque)))
            }
            1 => {
                let (input, bitmap_ssp) =
                    decode_bytewise_open_type(BitmapSsp::decode_bytewise, input)?;
                Ok((input, ServiceSpecificPermissions::BitmapSsp(bitmap_ssp)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for PsidSspRange<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (_, bitmap)) = decode_bytewise_sequence_preamble(false, 1, input)?;

        let (input, psid) = Psid::decode_bytewise(input)?;
        let (input, ssp_range) = if bitmap[0] {
            map(SspRange::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        Ok((input, Self { psid, ssp_range }))
    }
}

impl<'s> InternalDecode<'s> for SspRange<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, opaque) = SequenceOfOctetString::decode_bytewise(input)?;
                Ok((input, SspRange::Opaque(opaque)))
            }
            1 => Ok((input, SspRange::All(()))),
            2 => {
                let (input, bitmap_ssp) =
                    decode_bytewise_open_type(BitmapSspRange::decode_bytewise, input)?;
                Ok((input, SspRange::BitmapSspRange(bitmap_ssp)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for BitmapSspRange<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, ssp_value) = decode_bytewise_octetstring(Some(1), Some(32), false, input)?;
        let (input, ssp_bitmask) = decode_bytewise_octetstring(Some(1), Some(32), false, input)?;
        Ok((
            input,
            Self {
                ssp_value,
                ssp_bitmask,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for PublicVerificationKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, point) = EccP256CurvePoint::decode_bytewise(input)?;
                Ok((input, PublicVerificationKey::EcdsaNistP256(point)))
            }
            1 => {
                let (input, point) = EccP256CurvePoint::decode_bytewise(input)?;
                Ok((input, PublicVerificationKey::EcdsaBrainpoolP256r1(point)))
            }
            2 => {
                let (input, point) =
                    decode_bytewise_open_type(EccP384CurvePoint::decode_bytewise, input)?;
                Ok((input, PublicVerificationKey::EcdsaBrainpoolP384r1(point)))
            }
            3 => {
                let (input, point) =
                    decode_bytewise_open_type(EccP384CurvePoint::decode_bytewise, input)?;
                Ok((input, PublicVerificationKey::EcdsaNistP384(point)))
            }
            4 => {
                let (input, point) =
                    decode_bytewise_open_type(EccP256CurvePoint::decode_bytewise, input)?;
                Ok((input, PublicVerificationKey::EcsigSm2(point)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for Signature<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, sig) = EcdsaP256Signature::decode_bytewise(input)?;
                Ok((input, Signature::EcdsaNistP256Signature(sig)))
            }
            1 => {
                let (input, sig) = EcdsaP256Signature::decode_bytewise(input)?;
                Ok((input, Signature::EcdsaBrainpoolP256r1Signature(sig)))
            }
            2 => {
                let (input, sig) =
                    decode_bytewise_open_type(EcdsaP384Signature::decode_bytewise, input)?;
                Ok((input, Signature::EcdsaBrainpoolP384r1Signature(sig)))
            }
            3 => {
                let (input, sig) =
                    decode_bytewise_open_type(EcdsaP384Signature::decode_bytewise, input)?;
                Ok((input, Signature::EcdsaNistP384Signature(sig)))
            }
            4 => {
                let (input, sig) =
                    decode_bytewise_open_type(EcsigP256Signature::decode_bytewise, input)?;
                Ok((input, Signature::Sm2Signature(sig)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for EcdsaP256Signature<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, r_sig) = EccP256CurvePoint::decode_bytewise(input)?;
        let (input, s_sig) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
        Ok((input, Self { r_sig, s_sig }))
    }
}

impl<'s> InternalDecode<'s> for EcdsaP384Signature<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, r_sig) = EccP384CurvePoint::decode_bytewise(input)?;
        let (input, s_sig) = decode_bytewise_octetstring(Some(48), Some(48), false, input)?;
        Ok((input, Self { r_sig, s_sig }))
    }
}

impl<'s> InternalDecode<'s> for EcsigP256Signature<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, r_sig) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
        let (input, s_sig) = decode_bytewise_octetstring(Some(32), Some(32), false, input)?;
        Ok((input, Self { r_sig, s_sig }))
    }
}

impl<'s> InternalDecode<'s> for HashedData<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, hash) = HashedId32::decode_bytewise(input)?;
                Ok((input, HashedData::Sha256HashedData(hash)))
            }
            1 => {
                let (input, hash) = decode_bytewise_open_type(HashedId48::decode_bytewise, input)?;
                Ok((input, HashedData::Sha384HashedData(hash)))
            }
            2 => {
                let (input, hash) = decode_bytewise_open_type(HashedId32::decode_bytewise, input)?;
                Ok((input, HashedData::Sm3HashedData(hash)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for Ieee1609Dot2Data<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, protocol_version) = Uint8::decode_bytewise(input)?;
        let (input, content) = Ieee1609Dot2Content::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                protocol_version,
                content,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for Ieee1609Dot2Content<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, content) = Opaque::decode_bytewise(input)?;
                Ok((input, Ieee1609Dot2Content::UnsecuredData(content)))
            }
            1 => {
                let (input, content) = SignedData::decode_bytewise(input)?;
                Ok((
                    input,
                    Ieee1609Dot2Content::SignedData(alloc::boxed::Box::new(content)),
                ))
            }
            2 => {
                let (input, content) = EncryptedData::decode_bytewise(input)?;
                Ok((input, Ieee1609Dot2Content::EncryptedData(content)))
            }
            3 => {
                let (input, content) = Opaque::decode_bytewise(input)?;
                Ok((
                    input,
                    Ieee1609Dot2Content::SignedCertificateRequest(content),
                ))
            }
            4 => {
                let (input, content) = decode_bytewise_open_type(Opaque::decode_bytewise, input)?;
                Ok((
                    input,
                    Ieee1609Dot2Content::SignedX509CertificateRequest(content),
                ))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for SignedData<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, hash_id) = HashAlgorithm::decode_bytewise(input)?;
        let (input, tbs_data) = ToBeSignedData::decode_bytewise(input)?;
        let (input, signer) = SignerIdentifier::decode_bytewise(input)?;
        let (input, signature) = Signature::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                hash_id,
                tbs_data,
                signer,
                signature,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for ToBeSignedData<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        #[cfg(feature = "validate")]
        let (input_before, length_before) = (input, input.len());
        let (input, payload) = SignedDataPayload::decode_bytewise(input)?;
        let (input, header_info) = HeaderInfo::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                payload,
                header_info,
                #[cfg(feature = "validate")]
                raw: &input_before[..length_before - input.len()],
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for SignedDataPayload<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (extended, bitmap)) = decode_bytewise_sequence_preamble(true, 2, input)?;

        let (input, data) = if bitmap[0] {
            map(Ieee1609Dot2Data::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, ext_data_hash) = if bitmap[1] {
            map(HashedData::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, omitted) = if extended {
            let (input, bitmap) = decode_bytewise_bitstring(Some(0), None, false, input)?;

            #[allow(clippy::get_first, reason = "similarity to subsequent lines")]
            let (mut input, omitted) = if bitmap.get(0).is_some_and(|bit| *bit) {
                decode_bytewise_open_type(|i| Ok((i, Some(()))), input)?
            } else {
                (input, None)
            };

            // consume unknown extensions
            for bit in bitmap.get(1..).unwrap_or_default() {
                if *bit {
                    input = decode_bytewise_octetstring(Some(0), None, false, input)?.0;
                }
            }
            (input, omitted)
        } else {
            (input, None)
        };
        Ok((
            input,
            Self {
                data,
                ext_data_hash,
                omitted,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for RecipientInfo<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, info) = PreSharedKeyRecipientInfo::decode_bytewise(input)?;
                Ok((input, RecipientInfo::PskRecipInfo(info)))
            }
            1 => {
                let (input, info) = SymmRecipientInfo::decode_bytewise(input)?;
                Ok((input, RecipientInfo::SymmRecipInfo(info)))
            }
            2 => {
                let (input, info) = PKRecipientInfo::decode_bytewise(input)?;
                Ok((input, RecipientInfo::CertRecipInfo(info)))
            }
            3 => {
                let (input, info) = PKRecipientInfo::decode_bytewise(input)?;
                Ok((input, RecipientInfo::SignedDataRecipInfo(info)))
            }
            4 => {
                let (input, info) = PKRecipientInfo::decode_bytewise(input)?;
                Ok((input, RecipientInfo::RekRecipInfo(info)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for SignerIdentifier<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, id) = HashedId8::decode_bytewise(input)?;
                Ok((input, SignerIdentifier::Digest(id)))
            }
            1 => {
                let (input, id) = SequenceOfCertificate::decode_bytewise(input)?;
                Ok((input, SignerIdentifier::Certificate(id)))
            }
            2 => Ok((input, SignerIdentifier::RsSelf(()))),
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for MissingCrlIdentifier<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (extended, _)) = decode_bytewise_sequence_preamble(true, 0, input)?;

        let (input, craca_id) = HashedId3::decode_bytewise(input)?;
        let (input, crl_series) = CrlSeries::decode_bytewise(input)?;
        let input = if extended {
            let (mut input, bitmap) = decode_bytewise_bitstring(Some(0), None, false, input)?;

            // consume unknown extensions
            for bit in bitmap {
                if bit {
                    input = decode_bytewise_octetstring(Some(0), None, false, input)?.0;
                }
            }

            input
        } else {
            input
        };

        Ok((
            input,
            Self {
                craca_id,
                crl_series,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for HeaderInfo<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (extended, bitmap)) = decode_bytewise_sequence_preamble(true, 6, input)?;

        let (input, psid) = Psid::decode_bytewise(input)?;
        let (input, generation_time) = if bitmap[0] {
            map(Time64::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, expiry_time) = if bitmap[1] {
            map(Time64::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, generation_location) = if bitmap[2] {
            map(ThreeDLocation::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, p2pcd_learning_request) = if bitmap[3] {
            map(HashedId3::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, missing_crl_identifier) = if bitmap[4] {
            map(MissingCrlIdentifier::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, encryption_key) = if bitmap[5] {
            map(EncryptionKey::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (
            input,
            inline_p2pcd_request,
            requested_certificate,
            pdu_functional_type,
            contributed_extensions,
        ) = if extended {
            let (input, bitmap) = decode_bytewise_bitstring(Some(0), None, false, input)?;

            #[allow(clippy::get_first, reason = "similarity to subsequent lines")]
            let (input, inline_p2pcd_request) = if bitmap.get(0).is_some_and(|bit| *bit) {
                decode_bytewise_open_type(SequenceOfHashedId3::decode_bytewise, input)
                    .map(|(rem, req)| (rem, Some(req)))?
            } else {
                (input, None)
            };
            let (input, requested_certificate) = if bitmap.get(1).is_some_and(|bit| *bit) {
                decode_bytewise_open_type(Certificate::decode_bytewise, input)
                    .map(|(rem, cert)| (rem, Some(cert)))?
            } else {
                (input, None)
            };
            let (input, pdu_functional_type) = if bitmap.get(2).is_some_and(|bit| *bit) {
                decode_bytewise_open_type(PduFunctionalType::decode_bytewise, input)
                    .map(|(rem, ty)| (rem, Some(ty)))?
            } else {
                (input, None)
            };
            let (mut input, contributed_extensions) = if bitmap.get(3).is_some_and(|bit| *bit) {
                decode_bytewise_open_type(ContributedExtensionBlocks::decode_bytewise, input)
                    .map(|(rem, extensions)| (rem, Some(extensions)))?
            } else {
                (input, None)
            };

            // consume unknown extensions
            for bit in bitmap.get(4..).unwrap_or_default() {
                if *bit {
                    input = decode_bytewise_octetstring(Some(0), None, false, input)?.0;
                }
            }

            (
                input,
                inline_p2pcd_request,
                requested_certificate,
                pdu_functional_type,
                contributed_extensions,
            )
        } else {
            (input, None, None, None, None)
        };
        Ok((
            input,
            Self {
                psid,
                generation_time,
                expiry_time,
                generation_location,
                p2pcd_learning_request,
                missing_crl_identifier,
                encryption_key,
                inline_p2pcd_request,
                requested_certificate,
                pdu_functional_type,
                contributed_extensions,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for EncryptedData<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, recipients) = SequenceOfRecipientInfo::decode_bytewise(input)?;
        let (input, ciphertext) = SymmetricCiphertext::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                recipients,
                ciphertext,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for SymmRecipientInfo<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, recipient_id) = HashedId8::decode_bytewise(input)?;
        let (input, enc_key) = SymmetricCiphertext::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                recipient_id,
                enc_key,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for PKRecipientInfo<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, recipient_id) = HashedId8::decode_bytewise(input)?;
        let (input, enc_key) = EncryptedDataEncryptionKey::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                recipient_id,
                enc_key,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for One28BitCcmCiphertext<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, nonce) = decode_bytewise_octetstring(Some(12), Some(12), false, input)?;
        let (input, ccm_ciphertext) = Opaque::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                nonce,
                ccm_ciphertext,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for EncryptedDataEncryptionKey<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, key) = EciesP256EncryptedKey::decode_bytewise(input)?;
                Ok((input, EncryptedDataEncryptionKey::EciesNistP256(key)))
            }
            1 => {
                let (input, key) = EciesP256EncryptedKey::decode_bytewise(input)?;
                Ok((input, EncryptedDataEncryptionKey::EciesBrainpoolP256r1(key)))
            }
            2 => {
                let (input, key) =
                    decode_bytewise_open_type(EcencP256EncryptedKey::decode_bytewise, input)?;
                Ok((input, EncryptedDataEncryptionKey::EcencSm2256(key)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for SymmetricCiphertext<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, cipher) = One28BitCcmCiphertext::decode_bytewise(input)?;
                Ok((input, SymmetricCiphertext::Aes128ccm(cipher)))
            }
            1 => {
                let (input, cipher) =
                    decode_bytewise_open_type(One28BitCcmCiphertext::decode_bytewise, input)?;
                Ok((input, SymmetricCiphertext::Sm4Ccm(cipher)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for IssuerIdentifier<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, id) = HashedId8::decode_bytewise(input)?;
                Ok((input, IssuerIdentifier::Sha256AndDigest(id)))
            }
            1 => {
                let (input, id) = HashAlgorithm::decode_bytewise(input)?;
                Ok((input, IssuerIdentifier::RsSelf(id)))
            }
            2 => {
                let (input, id) = decode_bytewise_open_type(HashedId8::decode_bytewise, input)?;
                Ok((input, IssuerIdentifier::Sha384AndDigest(id)))
            }
            3 => {
                let (input, id) = decode_bytewise_open_type(HashedId8::decode_bytewise, input)?;
                Ok((input, IssuerIdentifier::Sm3AndDigest(id)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for CertificateBase<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        #[cfg(feature = "validate")]
        let (input_before, length_before) = (input, input.len());

        let (input, (_, bitmap)) = decode_bytewise_sequence_preamble(false, 1, input)?;

        let (input, version) = Uint8::decode_bytewise(input)?;
        let (input, r_type) = CertificateType::decode_bytewise(input)?;
        let (input, issuer) = IssuerIdentifier::decode_bytewise(input)?;
        let (input, to_be_signed) = ToBeSignedCertificate::decode_bytewise(input)?;
        let (input, signature) = if bitmap[0] {
            map(Signature::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        Ok((
            input,
            Self {
                r_type,
                to_be_signed,
                issuer,
                signature,
                version,
                #[cfg(feature = "validate")]
                raw: &input_before[..length_before - input.len()],
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for ToBeSignedCertificate<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (extended, bitmap)) = decode_bytewise_sequence_preamble(true, 7, input)?;

        let (input, id) = CertificateId::decode_bytewise(input)?;
        let (input, craca_id) = HashedId3::decode_bytewise(input)?;
        let (input, crl_series) = CrlSeries::decode_bytewise(input)?;
        let (input, validity_period) = ValidityPeriod::decode_bytewise(input)?;
        let (input, region) = if bitmap[0] {
            map(GeographicRegion::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, assurance_level) = if bitmap[1] {
            map(SubjectAssurance::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, app_permissions) = if bitmap[2] {
            map(SequenceOfPsidSsp::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, cert_issue_permissions) = if bitmap[3] {
            map(SequenceOfPsidGroupPermissions::decode_bytewise, |inner| {
                Some(inner)
            })(input)?
        } else {
            (input, None)
        };
        let (input, cert_request_permissions) = if bitmap[4] {
            map(SequenceOfPsidGroupPermissions::decode_bytewise, |inner| {
                Some(inner)
            })(input)?
        } else {
            (input, None)
        };
        let (input, can_request_rollover) = (input, bitmap[5].then_some(()));
        let (input, encryption_key) = if bitmap[6] {
            map(PublicEncryptionKey::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        let (input, verify_key_indicator) = VerificationKeyIndicator::decode_bytewise(input)?;
        let (input, flags, app_extensions, cert_issue_extensions, cert_request_extension) =
            if extended {
                let (input, bitmap) = decode_bytewise_bitstring(Some(0), None, false, input)?;

                #[allow(clippy::get_first, reason = "similarity to subsequent lines")]
                let (input, flags) = if bitmap.get(0).is_some_and(|bit| *bit) {
                    decode_bytewise_open_type(BitString::<8>::decode_bytewise, input)
                        .map(|(rem, flags)| (rem, Some(flags)))?
                } else {
                    (input, None)
                };
                let (input, app_extensions) = if bitmap.get(1).is_some_and(|bit| *bit) {
                    decode_bytewise_open_type(SequenceOfAppExtensions::decode_bytewise, input)
                        .map(|(rem, extensions)| (rem, Some(extensions)))?
                } else {
                    (input, None)
                };
                let (input, cert_issue_extensions) = if bitmap.get(2).is_some_and(|bit| *bit) {
                    decode_bytewise_open_type(SequenceOfCertIssueExtensions::decode_bytewise, input)
                        .map(|(rem, extensions)| (rem, Some(extensions)))?
                } else {
                    (input, None)
                };
                let (mut input, cert_request_extensions) = if bitmap.get(3).is_some_and(|bit| *bit)
                {
                    decode_bytewise_open_type(
                        SequenceOfCertRequestExtensions::decode_bytewise,
                        input,
                    )
                    .map(|(rem, extensions)| (rem, Some(extensions)))?
                } else {
                    (input, None)
                };

                // consume unknown extensions
                for bit in bitmap.get(4..).unwrap_or_default() {
                    if *bit {
                        input = decode_bytewise_octetstring(Some(0), None, false, input)?.0;
                    }
                }

                (
                    input,
                    flags,
                    app_extensions,
                    cert_issue_extensions,
                    cert_request_extensions,
                )
            } else {
                (input, None, None, None, None)
            };
        Ok((
            input,
            Self {
                id,
                craca_id,
                crl_series,
                validity_period,
                region,
                assurance_level,
                app_permissions,
                cert_issue_permissions,
                cert_request_permissions,
                can_request_rollover,
                encryption_key,
                verify_key_indicator,
                flags,
                app_extensions,
                cert_issue_extensions,
                cert_request_extension,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for AppExtension<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, id) = ExtId::decode_bytewise(input)?;
        let (input, content) = decode_bytewise_octetstring(Some(0), None, false, input)?;
        Ok((input, Self { id, content }))
    }
}

impl<'s> InternalDecode<'s> for ContributedExtensionBlockExtns<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let mut sequence_of = alloc::vec![];
        let (mut input, count) = decode_bytewise_integer(Some(1), None, false, input)?;
        for _ in 0..count {
            let (rem, item) = decode_bytewise_octetstring(Some(0), None, false, input)?;
            input = rem;
            sequence_of.push(AnonymousContributedExtensionBlockExtns(item));
        }
        Ok((input, Self(sequence_of)))
    }
}

impl<'s> InternalDecode<'s> for ContributedExtensionBlock<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, contributor_id) = HeaderInfoContributorId::decode_bytewise(input)?;
        let (input, extns) = ContributedExtensionBlockExtns::decode_bytewise(input)?;
        Ok((
            input,
            Self {
                contributor_id,
                extns,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for CertIssueExtension<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, id) = ExtId::decode_bytewise(input)?;
        let (input, permissions) = CertIssueExtensionPermissions::decode_bytewise(input)?;
        Ok((input, Self { id, permissions }))
    }
}

impl<'s> InternalDecode<'s> for CertIssueExtensionPermissions<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, data) = decode_bytewise_octetstring(Some(0), None, false, input)?;
                Ok((input, CertIssueExtensionPermissions::Specific(data)))
            }
            1 => Ok((input, CertIssueExtensionPermissions::All(()))),
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for CertRequestExtension<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, id) = ExtId::decode_bytewise(input)?;
        let (input, permissions) = CertRequestExtensionPermissions::decode_bytewise(input)?;
        Ok((input, Self { id, permissions }))
    }
}

impl<'s> InternalDecode<'s> for CertRequestExtensionPermissions<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, data) = decode_bytewise_octetstring(Some(0), None, false, input)?;
                Ok((input, CertRequestExtensionPermissions::Content(data)))
            }
            1 => Ok((input, CertRequestExtensionPermissions::All(()))),
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for CertificateId<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, id) = LinkageData::decode_bytewise(input)?;
                Ok((input, CertificateId::LinkageData(id)))
            }
            1 => {
                let (input, id) = Hostname::decode_bytewise(input)?;
                Ok((input, CertificateId::Name(id)))
            }
            2 => {
                let (input, id) = decode_bytewise_octetstring(Some(1), Some(64), false, input)?;
                Ok((input, CertificateId::BinaryId(id)))
            }
            3 => Ok((input, CertificateId::None(()))),
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for LinkageData<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (_, bitmap)) = decode_bytewise_sequence_preamble(false, 1, input)?;

        let (input, i_cert) = IValue::decode_bytewise(input)?;
        let (input, linkage_value) = LinkageValue::decode_bytewise(input)?;
        let (input, group_linkage_value) = if bitmap[0] {
            map(GroupLinkageValue::decode_bytewise, Some)(input)?
        } else {
            (input, None)
        };
        Ok((
            input,
            Self {
                i_cert,
                linkage_value,
                group_linkage_value,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for PsidGroupPermissions<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, (_, bitmap)) = decode_bytewise_sequence_preamble(false, 3, input)?;

        let (input, subject_permissions) = SubjectPermissions::decode_bytewise(input)?;
        let (input, min_chain_length) = if bitmap[0] {
            decode_bytewise_integer(None, None, false, input)?
        } else {
            (input, 1)
        };
        let (input, chain_length_range) = if bitmap[1] {
            decode_bytewise_integer(None, None, false, input)?
        } else {
            (input, 0)
        };
        let (input, ee_type) = if bitmap[2] {
            EndEntityType::decode_bytewise(input)?
        } else {
            (
                input,
                EndEntityType::from([true, false, false, false, false, false, false, false]),
            )
        };
        Ok((
            input,
            Self {
                subject_permissions,
                min_chain_length,
                chain_length_range,
                ee_type,
            },
        ))
    }
}

impl<'s> InternalDecode<'s> for EndEntityType {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, bitstring) = decode_bytewise_bitstring(Some(8), Some(8), false, input)?;
        Ok((input, bitstring.into()))
    }
}

impl<'s> InternalDecode<'s> for SubjectPermissions<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, exp) = SequenceOfPsidSspRange::decode_bytewise(input)?;
                Ok((input, SubjectPermissions::Explicit(exp)))
            }
            1 => Ok((input, SubjectPermissions::All(()))),
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

impl<'s> InternalDecode<'s> for VerificationKeyIndicator<'s> {
    fn decode_bytewise<'input: 's>(input: &'input [u8]) -> IResult<&'input [u8], Self>
    where
        Self: Sized,
    {
        let (input, tag) = decode_bytewise_tag(input)?;
        match tag {
            0 => {
                let (input, key) = PublicVerificationKey::decode_bytewise(input)?;
                Ok((input, VerificationKeyIndicator::VerificationKey(key)))
            }
            1 => {
                let (input, val) = EccP256CurvePoint::decode_bytewise(input)?;
                Ok((input, VerificationKeyIndicator::ReconstructionValue(val)))
            }
            _ => Err(nom::Err::Error(DecodeError::EnumError(
                "Invalid choice index!".into(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_bool() {
        assert!(
            bool::decode_bitwise(BSlice(bitvec::prelude::bits![u8, Msb0; 1]))
                .unwrap()
                .1
        );
        assert!(
            !bool::decode_bitwise(BSlice(bitvec::prelude::bits![u8, Msb0; 0]))
                .unwrap()
                .1
        );
    }

    #[test]
    fn decodes_integer() {
        assert_eq!(
            1u8,
            read_as_uint::<u8>(1)(BSlice(bitvec::prelude::bits![static u8, Msb0; 1]))
                .unwrap()
                .1
        );
        assert_eq!(
            1u8,
            read_as_uint::<u8>(3)(BSlice(bitvec::prelude::bits![static u8, Msb0; 0,0,1]))
                .unwrap()
                .1
        );
        assert_eq!(
            9u16,
            read_as_uint::<u16>(4)(BSlice(bitvec::prelude::bits![static u8, Msb0; 1,0,0,1]))
                .unwrap()
                .1
        );
    }

    #[test]
    fn decodes_oer_bitstring() {
        let ref_val = vec![true];
        let oer_input = &[0x80];
        let (_, decoded) = decode_bytewise_bitstring(Some(1), Some(1), false, oer_input).unwrap();
        assert_eq!(ref_val, decoded);

        let ref_val = vec![false, true, false, false, false, false, true, false];
        let oer_input = &[0x42];
        let (_, decoded) = decode_bytewise_bitstring(Some(8), Some(8), false, oer_input).unwrap();
        assert_eq!(ref_val, decoded);
        let (_, decoded) = BitString::<8>::decode_bytewise(oer_input).unwrap();
        assert_eq!(ref_val, decoded.0);

        let ref_val = vec![false, true];
        let oer_input = &[2, 6, 0x42];
        let (_, decoded) = decode_bytewise_bitstring(None, None, true, oer_input).unwrap();
        assert_eq!(ref_val, decoded);

        let ref_val = vec![
            true, false, false, false, false, false, false, false, false, true,
        ];
        let oer_input = &[3, 6, 0x80, 0x40];
        let (_, decoded) = decode_bytewise_bitstring(None, None, true, oer_input).unwrap();
        assert_eq!(ref_val, decoded);
    }

    #[test]
    fn decodes_basic_header() {
        let data: &'static [u8] = &[
            0x12, 0x00, 0x15, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x82, 0x02, 0x7c, 0x20,
            0x51, 0x01, 0x00, 0x02, 0x58, 0x01, 0x00, 0x12, 0x52, 0x00, 0x00, 0x3c, 0x00, 0x04,
            0xe5, 0x48, 0x10, 0xc7, 0x2e, 0x71, 0x25, 0xab, 0x00, 0x1f, 0xeb, 0xef, 0x74, 0x05,
            0xf2, 0xaf, 0x27, 0x80, 0x00, 0x00, 0x00,
        ];
        let result = BasicHeader::decode(data).unwrap();
        assert_eq!(
            result,
            Decoded {
                bytes_consumed: 4,
                decoded: BasicHeader {
                    version: 1,
                    next_header: NextAfterBasic::SecuredPacket,
                    reserved: crate::bits!(0;8),
                    lifetime: Lifetime(21),
                    remaining_hop_limit: 1
                }
            }
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn decodes_secure_header() {
        assert_eq!(
            Ieee1609Dot2Data::decode_bytewise(&[
                0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x78, 0x20, 0x50, 0x02, 0x80, 0x00, 0x54, 0x01,
                0x00, 0x14, 0x00, 0xca, 0x83, 0x1a, 0x3f, 0x3d, 0x39, 0x70, 0xfc, 0x82, 0x80, 0x1f,
                0xeb, 0x32, 0x0c, 0x05, 0xec, 0x3a, 0xfd, 0x80, 0x04, 0x0b, 0x90, 0x00, 0x00, 0x00,
                0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0x1a, 0x3f, 0x3d, 0x39, 0x82, 0x80, 0x40,
                0x5a, 0xb2, 0x03, 0x61, 0x8e, 0x26, 0xc1, 0x9f, 0xa0, 0xb4, 0x0b, 0x40, 0x00, 0x34,
                0x8c, 0x8e, 0x48, 0xb9, 0x1f, 0xa0, 0x00, 0x91, 0x82, 0xe8, 0x92, 0x7f, 0x33, 0xff,
                0x01, 0xff, 0xfa, 0x00, 0x28, 0x33, 0x00, 0x00, 0x4b, 0xff, 0x6a, 0xff, 0x15, 0x2e,
                0x40, 0x0c, 0x89, 0xdf, 0xa4, 0x48, 0x24, 0x7e, 0x23, 0xd3, 0xc8, 0x1f, 0x02, 0x4a,
                0xbe, 0xa5, 0xe8, 0xcf, 0x09, 0x69, 0xf8, 0x0d, 0xed, 0xf4, 0x24, 0x4c, 0x90, 0x33,
                0x3f, 0x40, 0x01, 0x24, 0x00, 0x02, 0x30, 0x51, 0x5a, 0x60, 0xed, 0xfa, 0x81, 0x01,
                0x01, 0x80, 0x03, 0x00, 0x80, 0x5d, 0x5d, 0xcb, 0xee, 0xfb, 0xe7, 0xd2, 0x2d, 0x30,
                0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x81, 0xd9, 0x85, 0x86, 0x00, 0x01, 0xe0,
                0x01, 0x07, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25,
                0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x8c, 0x81, 0x05, 0x04, 0x02,
                0xff, 0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x02, 0x7e, 0x81, 0x02, 0x01, 0x01,
                0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x00, 0x02, 0x03, 0xff, 0x80, 0x80,
                0x82, 0x13, 0x43, 0x08, 0xc4, 0x32, 0x4d, 0x5f, 0x47, 0xfc, 0xbe, 0x66, 0x5f, 0xb5,
                0x5b, 0x40, 0x98, 0xb3, 0x8b, 0x9c, 0xaa, 0x48, 0x4b, 0xd4, 0x47, 0x4c, 0x6c, 0x52,
                0x16, 0x00, 0xa7, 0x50, 0x8c, 0x81, 0x80, 0x3d, 0x9a, 0x96, 0x8a, 0xc1, 0x19, 0x6e,
                0x46, 0xea, 0x98, 0x22, 0x6c, 0x55, 0x20, 0x81, 0xa7, 0x7c, 0xdf, 0xbe, 0xd5, 0x8c,
                0x76, 0x9a, 0xf2, 0x8c, 0x9f, 0xf9, 0x06, 0xe9, 0x26, 0xd9, 0x22, 0x40, 0x5f, 0x18,
                0x9a, 0x1c, 0x6a, 0x03, 0x19, 0x89, 0x68, 0x96, 0x0a, 0x93, 0x32, 0x50, 0x06, 0xaf,
                0xfb, 0x84, 0x40, 0x4c, 0x93, 0x16, 0x80, 0x69, 0x8f, 0xff, 0x27, 0xc8, 0xf3, 0x12,
                0x7e, 0x80, 0x83, 0xfc, 0xbf, 0x3a, 0x5b, 0xf9, 0x8c, 0x14, 0x06, 0x3f, 0xc3, 0x71,
                0xff, 0xe0, 0xa7, 0x59, 0xc1, 0x58, 0x92, 0x13, 0x5d, 0x6a, 0xbb, 0x47, 0x1b, 0xa2,
                0x4e, 0xce, 0x6f, 0x00, 0xd3, 0x92, 0xfb, 0xd9, 0x43, 0xc5, 0x65, 0x5d, 0xae, 0x46,
                0x97, 0x1b, 0x3b, 0x09, 0x39, 0x59, 0x71, 0x15, 0x84, 0x10, 0x5b, 0x22, 0x30, 0x78,
                0x3d, 0x91, 0x72, 0x00, 0xfb, 0x3e, 0x9d, 0xdb, 0x44, 0x0b, 0x1c
            ])
            .unwrap()
            .1,
            Ieee1609Dot2Data {
                protocol_version: Uint8(3),
                content: Ieee1609Dot2Content::SignedData(Box::new(SignedData {
                    hash_id: HashAlgorithm::Sha256,
                    tbs_data: ToBeSignedData {
                        #[cfg(feature = "validate")]
                        raw: &[
                            64, 3, 128, 120, 32, 80, 2, 128, 0, 84, 1, 0, 20, 0, 202, 131, 26, 63,
                            61, 57, 112, 252, 130, 128, 31, 235, 50, 12, 5, 236, 58, 253, 128, 4,
                            11, 144, 0, 0, 0, 0, 7, 209, 0, 0, 2, 2, 26, 63, 61, 57, 130, 128, 64,
                            90, 178, 3, 97, 142, 38, 193, 159, 160, 180, 11, 64, 0, 52, 140, 142,
                            72, 185, 31, 160, 0, 145, 130, 232, 146, 127, 51, 255, 1, 255, 250, 0,
                            40, 51, 0, 0, 75, 255, 106, 255, 21, 46, 64, 12, 137, 223, 164, 72, 36,
                            126, 35, 211, 200, 31, 2, 74, 190, 165, 232, 207, 9, 105, 248, 13, 237,
                            244, 36, 76, 144, 51, 63, 64, 1, 36, 0, 2, 48, 81, 90, 96, 237, 250
                        ],
                        payload: SignedDataPayload {
                            data: Some(Ieee1609Dot2Data {
                                protocol_version: Uint8(3),
                                content: Ieee1609Dot2Content::UnsecuredData(Opaque(&[
                                    32, 80, 2, 128, 0, 84, 1, 0, 20, 0, 202, 131, 26, 63, 61, 57,
                                    112, 252, 130, 128, 31, 235, 50, 12, 5, 236, 58, 253, 128, 4,
                                    11, 144, 0, 0, 0, 0, 7, 209, 0, 0, 2, 2, 26, 63, 61, 57, 130,
                                    128, 64, 90, 178, 3, 97, 142, 38, 193, 159, 160, 180, 11, 64,
                                    0, 52, 140, 142, 72, 185, 31, 160, 0, 145, 130, 232, 146, 127,
                                    51, 255, 1, 255, 250, 0, 40, 51, 0, 0, 75, 255, 106, 255, 21,
                                    46, 64, 12, 137, 223, 164, 72, 36, 126, 35, 211, 200, 31, 2,
                                    74, 190, 165, 232, 207, 9, 105, 248, 13, 237, 244, 36, 76, 144,
                                    51, 63
                                ]))
                            }),
                            ext_data_hash: None,
                            omitted: None
                        },
                        header_info: HeaderInfo {
                            psid: Psid(36),
                            generation_time: Some(Uint64(616_075_920_207_354)),
                            expiry_time: None,
                            generation_location: None,
                            p2pcd_learning_request: None,
                            missing_crl_identifier: None,
                            encryption_key: None,
                            inline_p2pcd_request: None,
                            requested_certificate: None,
                            pdu_functional_type: None,
                            contributed_extensions: None
                        }
                    },
                    signer: SignerIdentifier::Certificate(SequenceOfCertificate(vec![
                        CertificateBase {
                            version: Uint8(3),
                            r_type: CertificateType::Explicit,
                            issuer: IssuerIdentifier::Sha256AndDigest(HashedId8(&[
                                93, 93, 203, 238, 251, 231, 210, 45
                            ])),
                            to_be_signed: ToBeSignedCertificate {
                                id: CertificateId::None(()),
                                craca_id: HashedId3(&[0, 0, 0]),
                                crl_series: Uint16(0),
                                validity_period: ValidityPeriod {
                                    start: Uint32(612_489_605),
                                    duration: Duration::Years(Uint16(1))
                                },
                                region: None,
                                assurance_level: Some(SubjectAssurance(&[224])),
                                app_permissions: Some(SequenceOfPsidSsp(vec![
                                    PsidSsp {
                                        psid: Psid(36),
                                        ssp: Some(ServiceSpecificPermissions::BitmapSsp(
                                            BitmapSsp(&[1, 255, 252])
                                        ))
                                    },
                                    PsidSsp {
                                        psid: Psid(37),
                                        ssp: Some(ServiceSpecificPermissions::BitmapSsp(
                                            BitmapSsp(&[1, 255, 255, 255])
                                        ))
                                    },
                                    PsidSsp {
                                        psid: Psid(140),
                                        ssp: Some(ServiceSpecificPermissions::BitmapSsp(
                                            BitmapSsp(&[2, 255, 255, 224])
                                        ))
                                    },
                                    PsidSsp {
                                        psid: Psid(141),
                                        ssp: None
                                    },
                                    PsidSsp {
                                        psid: Psid(638),
                                        ssp: Some(ServiceSpecificPermissions::BitmapSsp(
                                            BitmapSsp(&[1])
                                        ))
                                    },
                                    PsidSsp {
                                        psid: Psid(639),
                                        ssp: Some(ServiceSpecificPermissions::BitmapSsp(
                                            BitmapSsp(&[1])
                                        ))
                                    },
                                    PsidSsp {
                                        psid: Psid(1023),
                                        ssp: None
                                    }
                                ])),
                                cert_issue_permissions: None,
                                cert_request_permissions: None,
                                can_request_rollover: None,
                                encryption_key: None,
                                verify_key_indicator: VerificationKeyIndicator::VerificationKey(
                                    PublicVerificationKey::EcdsaNistP256(
                                        EccP256CurvePoint::CompressedY0(&[
                                            19, 67, 8, 196, 50, 77, 95, 71, 252, 190, 102, 95, 181,
                                            91, 64, 152, 179, 139, 156, 170, 72, 75, 212, 71, 76,
                                            108, 82, 22, 0, 167, 80, 140
                                        ])
                                    )
                                ),
                                flags: None,
                                app_extensions: None,
                                cert_issue_extensions: None,
                                cert_request_extension: None
                            },
                            signature: Some(Signature::EcdsaBrainpoolP256r1Signature(
                                EcdsaP256Signature {
                                    r_sig: EccP256CurvePoint::XOnly(&[
                                        61, 154, 150, 138, 193, 25, 110, 70, 234, 152, 34, 108, 85,
                                        32, 129, 167, 124, 223, 190, 213, 140, 118, 154, 242, 140,
                                        159, 249, 6, 233, 38, 217, 34
                                    ]),
                                    s_sig: &[
                                        64, 95, 24, 154, 28, 106, 3, 25, 137, 104, 150, 10, 147,
                                        50, 80, 6, 175, 251, 132, 64, 76, 147, 22, 128, 105, 143,
                                        255, 39, 200, 243, 18, 126
                                    ]
                                }
                            )),
                            #[cfg(feature = "validate")]
                            raw: &[
                                128, 3, 0, 128, 93, 93, 203, 238, 251, 231, 210, 45, 48, 131, 0, 0,
                                0, 0, 0, 36, 129, 217, 133, 134, 0, 1, 224, 1, 7, 128, 1, 36, 129,
                                4, 3, 1, 255, 252, 128, 1, 37, 129, 5, 4, 1, 255, 255, 255, 128, 1,
                                140, 129, 5, 4, 2, 255, 255, 224, 0, 1, 141, 128, 2, 2, 126, 129,
                                2, 1, 1, 128, 2, 2, 127, 129, 2, 1, 1, 0, 2, 3, 255, 128, 128, 130,
                                19, 67, 8, 196, 50, 77, 95, 71, 252, 190, 102, 95, 181, 91, 64,
                                152, 179, 139, 156, 170, 72, 75, 212, 71, 76, 108, 82, 22, 0, 167,
                                80, 140, 129, 128, 61, 154, 150, 138, 193, 25, 110, 70, 234, 152,
                                34, 108, 85, 32, 129, 167, 124, 223, 190, 213, 140, 118, 154, 242,
                                140, 159, 249, 6, 233, 38, 217, 34, 64, 95, 24, 154, 28, 106, 3,
                                25, 137, 104, 150, 10, 147, 50, 80, 6, 175, 251, 132, 64, 76, 147,
                                22, 128, 105, 143, 255, 39, 200, 243, 18, 126
                            ]
                        }
                    ])),
                    signature: Signature::EcdsaNistP256Signature(EcdsaP256Signature {
                        r_sig: EccP256CurvePoint::CompressedY1(&[
                            252, 191, 58, 91, 249, 140, 20, 6, 63, 195, 113, 255, 224, 167, 89,
                            193, 88, 146, 19, 93, 106, 187, 71, 27, 162, 78, 206, 111, 0, 211, 146,
                            251
                        ]),
                        s_sig: &[
                            217, 67, 197, 101, 93, 174, 70, 151, 27, 59, 9, 57, 89, 113, 21, 132,
                            16, 91, 34, 48, 120, 61, 145, 114, 0, 251, 62, 157, 219, 68, 11, 28
                        ]
                    })
                }))
            }
        );
    }

    #[test]
    // test to ensure proper encoding of BIT STRING data
    fn round_trip_to_be_signed_certificate() {
        let ref_bytes = &[
            0xb0, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x81, 0xd9, 0x85, 0x86, 0x00, 0x01,
            0xe0, 0x01, 0x07, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01,
            0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x8c, 0x81, 0x05, 0x04,
            0x02, 0xff, 0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x02, 0x7e, 0x81, 0x02, 0x01,
            0x01, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x00, 0x02, 0x03, 0xff, 0x80,
            0x80, 0x82, 0x13, 0x43, 0x08, 0xc4, 0x32, 0x4d, 0x5f, 0x47, 0xfc, 0xbe, 0x66, 0x5f,
            0xb5, 0x5b, 0x40, 0x98, 0xb3, 0x8b, 0x9c, 0xaa, 0x48, 0x4b, 0xd4, 0x47, 0x4c, 0x6c,
            0x52, 0x16, 0x00, 0xa7, 0x50, 0x8c,
            0x02, // extension addition presence bitmap: length determinant
            0x04, // extension addition presence bitmap: how many unused bits -> 4
            0x80, // extension addition presence bitmap: bitmap -> ext. 1 present, 2-4 not present
            0x01, // open type encoding: length
            0x80, // fixed size BIT STRING: 0b1000.0000
        ];

        let data = ToBeSignedCertificate {
            id: CertificateId::None(()),
            craca_id: HashedId3(&[0, 0, 0]),
            crl_series: Uint16(0),
            validity_period: ValidityPeriod {
                start: Uint32(612_489_605),
                duration: Duration::Years(Uint16(1)),
            },
            region: None,
            assurance_level: Some(SubjectAssurance(&[224])),
            app_permissions: Some(SequenceOfPsidSsp(vec![
                PsidSsp {
                    psid: Psid(36),
                    ssp: Some(ServiceSpecificPermissions::BitmapSsp(BitmapSsp(&[
                        1, 255, 252,
                    ]))),
                },
                PsidSsp {
                    psid: Psid(37),
                    ssp: Some(ServiceSpecificPermissions::BitmapSsp(BitmapSsp(&[
                        1, 255, 255, 255,
                    ]))),
                },
                PsidSsp {
                    psid: Psid(140),
                    ssp: Some(ServiceSpecificPermissions::BitmapSsp(BitmapSsp(&[
                        2, 255, 255, 224,
                    ]))),
                },
                PsidSsp {
                    psid: Psid(141),
                    ssp: None,
                },
                PsidSsp {
                    psid: Psid(638),
                    ssp: Some(ServiceSpecificPermissions::BitmapSsp(BitmapSsp(&[1]))),
                },
                PsidSsp {
                    psid: Psid(639),
                    ssp: Some(ServiceSpecificPermissions::BitmapSsp(BitmapSsp(&[1]))),
                },
                PsidSsp {
                    psid: Psid(1023),
                    ssp: None,
                },
            ])),
            cert_issue_permissions: None,
            cert_request_permissions: None,
            can_request_rollover: None,
            encryption_key: None,
            verify_key_indicator: VerificationKeyIndicator::VerificationKey(
                PublicVerificationKey::EcdsaNistP256(EccP256CurvePoint::CompressedY0(&[
                    19, 67, 8, 196, 50, 77, 95, 71, 252, 190, 102, 95, 181, 91, 64, 152, 179, 139,
                    156, 170, 72, 75, 212, 71, 76, 108, 82, 22, 0, 167, 80, 140,
                ])),
            ),
            flags: Some(vec![true, false, false, false, false, false, false, false].into()),
            app_extensions: None,
            cert_issue_extensions: None,
            cert_request_extension: None,
        };

        let decoded = ToBeSignedCertificate::decode_bytewise(ref_bytes).unwrap();
        pretty_assertions::assert_eq!(data, decoded.1);

        let bytes = data.encode_to_vec().unwrap();
        assert_eq!(*ref_bytes, *bytes);
    }
}
