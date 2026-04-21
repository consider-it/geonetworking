//! Message types from EN 302 636-4-1

extern crate alloc;

use arbitrary_int::{i15, traits::Integer, u4, u6};
#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 8 byte in total
pub struct Address {
    /// This bit allows distinguishing between manually configured network address (clause 10.2.1.3.3) (update)
    /// and the initial GeoNetworking address (clause 10.2.1.3.2). M is set to 1 if the address is manually configured otherwise it equals 0.
    pub manually_configured: bool, // 1 bit
    /// ITS Station type
    pub station_type: StationType, // 5 bits
    /// Reserved
    pub reserved: arbitrary_int::u10, // 10 bits
    /// Represents the `LL_ADDR`
    pub address: [u8; 6], // 48 bits (6 byte)
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum StationType {
    #[default]
    Unknown = 0,
    Pedestrian = 1,
    Cyclist = 2,
    Moped = 3,
    Motorcycle = 4,
    PassengerCar = 5,
    Bus = 6,
    LightTruck = 7,
    HeavyTruck = 8,
    Trailer = 9,
    SpecialVehicle = 10,
    Tram = 11,
    RoadSideUnit = 15,
}

impl TryFrom<u8> for StationType {
    type Error = alloc::string::String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
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

            i => Err(alloc::format!(
                "No corresponding station type for value {i}!"
            )),
        }
    }
}

/// Expresses the time in milliseconds at which the latitude and longitude
/// of the ITS-S were acquired by the GeoAdhoc router. The time is encoded as:
/// TST = TST(TAI) % 2^32
/// where TST(TAI) is the number of elapsed TAI milliseconds since 2004-01-01 00:00:00.000 UTC
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Timestamp(pub u32);

impl Timestamp {
    #[must_use]
    pub fn as_unix_timestamp(&self) -> u64 {
        u64::from(self.0) + 1_072_915_200_000
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 24 byte in total
pub struct LongPositionVector {
    pub gn_address: Address, // 64 bits
    /// Expresses the time in milliseconds at which the latitude and longitude
    /// of the ITS-S were acquired by the GeoAdhoc router. The time is encoded as:
    /// TST = TST(TAI) % 2^32
    /// where TST(TAI) is the number of elapsed TAI milliseconds since 2004-01-01 00:00:00.000 UTC
    pub timestamp: Timestamp, // 32 bits
    /// WGS 84 [i.6] latitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub latitude: i32, // 32 bits
    /// WGS 84 [i.6] longitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub longitude: i32, // 32 bits
    /// Position accuracy indicator of the GeoAdhoc router reference position
    /// Set to 1 (i.e. True) if the semiMajorConfidence of the `PosConfidenceEllipse` as specified in ETSI TS 102 894-2 \[11\]
    /// is smaller than the GN protocol constant itsGnPaiInterval / 2
    /// Set to 0 (i.e. False) otherwise
    pub position_accuracy: bool, // 1 bit
    /// Speed of the GeoAdhoc router expressed in signed units of 0.01 meter per second
    pub speed: i15, // 15 bits
    /// Heading of the GeoAdhoc router, expressed in unsigned units of 0.1 degree from North
    pub heading: u16, // 16 bits
}

impl LongPositionVector {
    const MPS_TO_INT_FACTOR: f32 = 100f32;

    #[allow(clippy::missing_errors_doc, reason = "no docs present")]
    pub fn try_new(
        gn_address: Address,
        timestamp: Timestamp,
        latitude: i32,
        longitude: i32,
        position_accuracy: bool,
        speed: i16,
        heading: u16,
    ) -> Result<Self, alloc::string::String> {
        let speed =
            i15::try_new(speed).map_err(|err| alloc::format!("Speed out of bounds: {err:?}"))?;

        Ok(Self {
            gn_address,
            timestamp,
            latitude,
            longitude,
            position_accuracy,
            speed,
            heading,
        })
    }

    pub fn set_speed_mps(&mut self, mps: f32) {
        #[allow(clippy::cast_possible_truncation)]
        let speed_int = (mps * Self::MPS_TO_INT_FACTOR) as i16;

        self.speed = i15::from_i16(speed_int.clamp(-16_384, 16_383));
    }

    #[must_use]
    pub fn get_speed_mps(&self) -> f32 {
        f32::from(self.speed.as_i16()) / Self::MPS_TO_INT_FACTOR
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 20 byte in total
pub struct ShortPositionVector {
    pub gn_address: Address, // 64 bits
    /// Expresses the time in milliseconds at which the latitude and longitude
    /// of the ITS-S were acquired by the GeoAdhoc router. The time is encoded as:
    /// TST = TST(TAI) % 2^32
    /// where TST(TAI) is the number of elapsed TAI milliseconds since 2004-01-01 00:00:00.000 UTC
    pub timestamp: Timestamp, // 32 bits
    /// WGS 84 [i.6] latitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub latitude: i32, // 32 bits
    /// WGS 84 [i.6] longitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub longitude: i32, // 32 bits
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 4 byte in total
pub struct BasicHeader {
    /// Identifies the version of the GeoNetworking protocol
    pub version: u4, // 4 bits
    /// Identifies the type of header immediately following the GeoNetworking Basic Header
    pub next_header: NextAfterBasic, // 4 bits (but only 2 LSB are used)
    /// Reserved. Set to 0
    pub reserved: u8, // 8 bits
    /// Lifetime field. Indicates the maximum tolerable time a packet may be buffered until it reaches its destination
    /// Bit 0 to Bit 5: LT sub-field Multiplier
    /// Bit 6 to Bit 7: LT sub-field Base
    pub lifetime: Lifetime, // 8 bits
    /// Decremented by 1 by each GeoAdhoc router that forwards the packet
    /// The packet shall not be forwarded if RHL is decremented to zero
    pub remaining_hop_limit: u8, // 8 bits
}

impl BasicHeader {
    #[allow(clippy::missing_errors_doc, reason = "no docs present")]
    pub fn try_new(
        version: u8,
        next_header: NextAfterBasic,
        lifetime: Lifetime,
        remaining_hop_limit: u8,
    ) -> Result<Self, alloc::string::String> {
        let version =
            u4::try_new(version).map_err(|err| alloc::format!("Version out of bounds: {err:?}"))?;
        Ok(Self {
            version,
            next_header,
            reserved: 0,
            lifetime,
            remaining_hop_limit,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Identifies the type of header immediately following the GeoNetworking Basic Header
pub enum NextAfterBasic {
    Any = 0,
    CommonHeader = 1,
    SecuredPacket = 2,
}

impl TryFrom<u8> for NextAfterBasic {
    type Error = alloc::string::String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Any),
            1 => Ok(Self::CommonHeader),
            2 => Ok(Self::SecuredPacket),
            i => Err(alloc::format!(
                "No corresponding header type for value {i}!"
            )),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Lifetime field. Indicates the maximum tolerable time a packet may be buffered until it reaches its destination
/// Bit 0 to Bit 5: LT sub-field Multiplier
/// Bit 6 to Bit 7: LT sub-field Base
pub struct Lifetime(pub u8);

impl Lifetime {
    #[must_use]
    pub fn from_raw(value: u8) -> Self {
        Self(value)
    }

    /// returns the lifetime base (bit 6 and 7)
    #[must_use]
    pub fn base(&self) -> u8 {
        self.0 & 0b0000_0011
    }

    /// returns the lifetime multiplier (bit 0 to 5)
    #[must_use]
    pub fn multiplier(&self) -> u8 {
        self.0 >> 2
    }

    /// returns the lifetime value in milliseconds
    #[must_use]
    pub fn as_milliseconds(&self) -> u32 {
        match self.base() {
            0 => 50 * u32::from(self.multiplier()),
            1 => 1000 * u32::from(self.multiplier()),
            2 => 10000 * u32::from(self.multiplier()),
            3 => 100_000 * u32::from(self.multiplier()),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 8 bytes in total
pub struct CommonHeader {
    /// Identifies the type of header immediately following the GeoNetworking headers
    pub next_header: NextAfterCommon, // 4 bits
    /// Reserved. Set to 0
    pub reserved_1: u4, // 4 bits
    /// Identifies the type and sub-type of the GeoNetworking header
    pub header_type_and_subtype: HeaderType, // 8 bits
    /// Traffic class that represents Facility-layer requirements on packet transport
    pub traffic_class: TrafficClass, // 8 bits
    /// Bit 0: Indicates whether the ITS-S is mobile or stationary (GN protocol constant itsGnIsMobile)
    /// Bit 1 to Bit 7: Reserve, set to 0
    pub flags: [bool; 8], // 8 bits
    /// Length of the GeoNetworking payload, i.e. the rest of the packet following the whole GeoNetworking header in octets, for example BTP + CAM
    pub payload_length: u16, // 16 bits
    /// The Maximum hop limit is not decremented by a GeoAdhoc router that forwards the packet
    pub maximum_hop_limit: u8, // 8 bits
    /// Reserved. Set to 0
    pub reserved_2: u8, // 8 bits
}

impl CommonHeader {
    #[must_use]
    pub fn new(
        next_header: NextAfterCommon,
        header_type_and_subtype: HeaderType,
        traffic_class: TrafficClass,
        flags: [bool; 8],
        payload_length: u16,
        maximum_hop_limit: u8,
    ) -> Self {
        Self {
            next_header,
            reserved_1: u4::from_u8(0),
            header_type_and_subtype,
            traffic_class,
            flags,
            payload_length,
            maximum_hop_limit,
            reserved_2: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Traffic class that represents Facility-layer requirements on packet transport
pub struct TrafficClass {
    /// Indicates whether the packet shall be buffered when no suitable neighbour exists
    pub store_carry_forward: bool,
    /// Indicates whether the packet may be offloaded to another channel than specified in the traffic class ID
    pub channel_offload: bool,
    /// Traffic class ID as specified in the media-dependent part of GeoNetworking corresponding to the interface
    /// over which the packet will be transmitted, e.g. in ETSI TS 102 636-4-2 [i.11] for ITS-G5 and ETSI TS 103 613 [i.10] for LTE-V2X
    pub traffic_class_id: u6, // 6 bits
}

impl TrafficClass {
    #[allow(clippy::missing_errors_doc, reason = "no docs present")]
    pub fn try_new(
        store_carry_forward: bool,
        channel_offload: bool,
        traffic_class_id: u8,
    ) -> Result<Self, alloc::string::String> {
        let traffic_class_id = u6::try_new(traffic_class_id)
            .map_err(|err| alloc::format!("Traffic class ID out of bounds: {err:?}"))?;

        Ok(Self {
            store_carry_forward,
            channel_offload,
            traffic_class_id,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Identifies the type of header immediately following the GeoNetworking Common Header
pub enum NextAfterCommon {
    Any = 0,
    /// Transport protocol (BTP-A for interactive packet transport) as defined in ETSI EN 302 636-5-1
    BTPA = 1,
    /// Transport protocol (BTP-B for non-interactive packet transport) as defined in ETSI EN 302 636-5-1
    BTPB = 2,
    /// IPv6 header as defined in ETSI EN 302 636-6-1
    IPv6 = 3,
}

impl TryFrom<u8> for NextAfterCommon {
    type Error = alloc::string::String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Any),
            1 => Ok(Self::BTPA),
            2 => Ok(Self::BTPB),
            3 => Ok(Self::IPv6),
            i => Err(alloc::format!(
                "No corresponding header type for value {i}!"
            )),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Identifies the type of the GeoNetworking header
pub enum HeaderType {
    Any,
    Beacon,
    GeoUnicast,
    /// Geographically-Scoped Anycast (GAC)
    GeoAnycast(AreaType),
    /// Geographically-Scoped broadcast (GBC)
    GeoBroadcast(AreaType),
    TopologicallyScopedBroadcast(BroadcastType),
    LocationService(LocationServiceType),
}

impl TryFrom<u8> for HeaderType {
    type Error = alloc::string::String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // let (input, output) =
        //     nom::bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(|data| {
        //         let (data, foo) = nom::bits::streaming::take(4usize)(data)?;
        //         let (data, bar) = nom::bits::streaming::take(4usize)(data)?;

        //         Ok((foo, bar))
        //     })(vec![value])?;

        let ty = (value >> 4) & 0x0F;
        let subtype = value & 0x0F;

        let error = alloc::format!(
            "No corresponding header type for value {ty} and subtype value {subtype}!"
        );

        match ty {
            0 => Ok(Self::Any),
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
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Area type used in header subtypes
pub enum AreaType {
    Circular,
    Rectangular,
    Ellipsoidal,
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Broadcast type used in header subtypes
pub enum BroadcastType {
    SingleHop,
    MultiHop,
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Subtype of location service
pub enum LocationServiceType {
    Request,
    Reply,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// different length depending on type
pub enum ExtendedHeader {
    GUC(GeoUnicast),
    TSB(TopologicallyScopedBroadcast),
    SHB(SingleHopBroadcast),
    GBC(GeoBroadcast),
    GAC(GeoAnycast),
    Beacon(Beacon),
    LSRequest(LSRequest),
    LSReply(LSReply),
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 48 byte in total
pub struct GeoUnicast {
    /// Sequence number field. Indicates the index of the sent GUC packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16, // 16 bits
    /// Reserved. Set to 0
    pub reserved: u16, // 16 bits
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector, // 192 bits (24 byte)
    /// Short Position Vector containing the position of the destination
    pub destination_position_vector: ShortPositionVector, // 160 bits (20 byte)
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 28 byte in total
pub struct TopologicallyScopedBroadcast {
    /// Sequence number field. Indicates the index of the sent TSB packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16, // 16 bits
    /// Reserved. Set to 0
    pub reserved: u16, // 16 bits
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector, // 192 bits (24 byte)
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 28 byte in total
pub struct SingleHopBroadcast {
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector, // 192 bits (24 byte)
    /// Used for media-dependent operations. If not used, it shall be set to 0
    pub media_dependent_data: [u8; 4], // 32 bits
}

pub type GeoBroadcast = GeoAnycast;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// In case of a circular area (GeoNetworking packet sub-type HST = 0), the fields shall be set to the following values:
/// 1) Distance a is set to the radius r.
/// 2) Distance b is set to 0.
/// 3) Angle is set to 0.
// 44 byte in total
pub struct GeoAnycast {
    /// Sequence number field. Indicates the index of the sent GBC/GAC packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16, // 16 bits
    /// Reserved. Set to 0
    pub reserved_1: u16, // 16 bits
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector, // 192 bits (24 byte)
    /// WGS 84 [i.6] latitude for the centre position of the geometric shape as defined in ETSI EN 302 931 \[8\] in 1/10 micro degree
    pub geo_area_position_latitude: i32, // 32 bits
    /// WGS 84 [i.6] longitude for the centre position of the geometric shape as defined in ETSI EN 302 931 \[8\] in 1/10 micro degree
    pub geo_area_position_longitude: i32, // 32 bits
    /// Distance a of the geometric shape as defined in ETSI EN 302 931 \[8\] in meters
    pub distance_a: u16, // 16 bits
    /// Distance b of the geometric shape as defined in ETSI EN 302 931 \[8\] in meters
    pub distance_b: u16, // 16 bits
    /// Angle of the geometric shape as defined in ETSI EN 302 931 \[8\] in degrees from North
    pub angle: u16, // 16 bits
    /// Reserved. Set to 0
    pub reserved_2: u16, // 16 bits
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 24 byte in total
pub struct Beacon {
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector, // 192 bits (24 byte)
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 36 byte in total
pub struct LSRequest {
    /// Sequence number field. Indicates the index of the sent LS Request packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16, // 16 bits
    /// Reserved. Set to 0
    pub reserved: u16, // 16 bits
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector, // 192 bits (24 byte)
    /// The `GN_ADDR` address for the GeoAdhoc router entity for which the location is being requested
    pub request_gn_address: Address, // 64 bits
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
// 48 byte in total
pub struct LSReply {
    /// Sequence number field. Indicates the index of the sent LS Reply packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16, // 16 bits
    /// Reserved. Set to 0
    pub reserved: u16, // 16 bits
    /// Long Position Vector containing the reference position of the source, which represents the Request `GN_ADDR` in the corresponding LS Request
    pub source_position_vector: LongPositionVector, // 192 bits (24 byte)
    /// Short Position Vector containing the position of the destination
    pub destination_position_vector: ShortPositionVector, // 160 bits (20 byte)
}
