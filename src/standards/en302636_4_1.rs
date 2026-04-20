//! Message types from EN 302 636-4-1

use crate::Bits;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Address {
    /// This bit allows distinguishing between manually configured network address (clause 10.2.1.3.3) (update)
    /// and the initial GeoNetworking address (clause 10.2.1.3.2). M is set to 1 if the address is manually configured otherwise it equals 0.
    pub manually_configured: bool,
    /// ITS Station type
    pub station_type: StationType,
    /// Reserved
    pub reserved: Bits<10>,
    /// Represents the `LL_ADDR`
    pub address: [u8; 6],
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum StationType {
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

/// Expresses the time in milliseconds at which the latitude and longitude
/// of the ITS-S were acquired by the GeoAdhoc router. The time is encoded as:
/// TST = TST(TAI) % 2^32
/// where TST(TAI) is the number of elapsed TAI milliseconds since 2004-01-01 00:00:00.000 UTC
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Timestamp(pub u32);

impl Timestamp {
    #[must_use]
    pub fn as_unix_timestamp(&self) -> u64 {
        u64::from(self.0) + 1_072_915_200_000
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct LongPositionVector {
    pub gn_address: Address,
    /// Expresses the time in milliseconds at which the latitude and longitude
    /// of the ITS-S were acquired by the GeoAdhoc router. The time is encoded as:
    /// TST = TST(TAI) % 2^32
    /// where TST(TAI) is the number of elapsed TAI milliseconds since 2004-01-01 00:00:00.000 UTC
    pub timestamp: Timestamp,
    /// WGS 84 [i.6] latitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub latitude: i32,
    /// WGS 84 [i.6] longitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub longitude: i32,
    /// Position accuracy indicator of the GeoAdhoc router reference position
    /// Set to 1 (i.e. True) if the semiMajorConfidence of the `PosConfidenceEllipse` as specified in ETSI TS 102 894-2 \[11\]
    /// is smaller than the GN protocol constant itsGnPaiInterval / 2
    /// Set to 0 (i.e. False) otherwise
    pub position_accuracy: bool,
    /// Speed of the GeoAdhoc router expressed in signed units of 0,01 meter per second
    pub speed: i16,
    /// Heading of the GeoAdhoc router, expressed in unsigned units of 0,1 degree from North
    pub heading: u16,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct ShortPositionVector {
    pub gn_address: Address,
    /// Expresses the time in milliseconds at which the latitude and longitude
    /// of the ITS-S were acquired by the GeoAdhoc router. The time is encoded as:
    /// TST = TST(TAI) % 2^32
    /// where TST(TAI) is the number of elapsed TAI milliseconds since 2004-01-01 00:00:00.000 UTC
    pub timestamp: Timestamp,
    /// WGS 84 [i.6] latitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub latitude: i32,
    /// WGS 84 [i.6] longitude of the GeoAdhoc router reference position expressed in 1/10 micro degree
    pub longitude: i32,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct BasicHeader {
    /// Identifies the version of the GeoNetworking protocol
    pub version: u8,
    /// Identifies the type of header immediately following the GeoNetworking Basic Header
    pub next_header: NextAfterBasic,
    /// Reserved. Set to 0
    pub reserved: Bits<8>,
    /// Lifetime field. Indicates the maximum tolerable time a packet may be buffered until it reaches its destination
    /// Bit 0 to Bit 5: LT sub-field Multiplier
    /// Bit 6 to Bit 7: LT sub-field Base
    pub lifetime: Lifetime,
    /// Decremented by 1 by each GeoAdhoc router that forwards the packet
    /// The packet shall not be forwarded if RHL is decremented to zero
    pub remaining_hop_limit: u8,
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Identifies the type of header immediately following the GeoNetworking Basic Header
pub enum NextAfterBasic {
    Any = 0,
    CommonHeader = 1,
    SecuredPacket = 2,
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// Lifetime field. Indicates the maximum tolerable time a packet may be buffered until it reaches its destination
/// Bit 0 to Bit 5: LT sub-field Multiplier
/// Bit 6 to Bit 7: LT sub-field Base
pub struct Lifetime(pub u8);

impl Lifetime {
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
pub struct CommonHeader {
    /// Identifies the type of header immediately following the GeoNetworking headers
    pub next_header: NextAfterCommon,
    /// Reserved. Set to 0
    pub reserved_1: Bits<4>,
    /// Identifies the type and sub-type of the GeoNetworking header
    pub header_type_and_subtype: HeaderType,
    /// Traffic class that represents Facility-layer requirements on packet transport
    pub traffic_class: TrafficClass,
    /// Bit 0: Indicates whether the ITS-S is mobile or stationary (GN protocol constant itsGnIsMobile)
    /// Bit 1 to Bit 7: Reserve, set to 0
    pub flags: Bits<8>,
    /// Length of the GeoNetworking payload, i.e. the rest of the packet following the whole GeoNetworking header in octets, for example BTP + CAM
    pub payload_length: u16,
    ///  The Maximum hop limit is not decremented by a GeoAdhoc router that forwards the packet
    pub maximum_hop_limit: u8,
    /// Reserved. Set to 0
    pub reserved_2: Bits<8>,
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
    pub traffic_class_id: u8,
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
pub struct GeoUnicast {
    /// Sequence number field. Indicates the index of the sent GUC packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16,
    /// Reserved. Set to 0
    pub reserved: Bits<16>,
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector,
    /// Short Position Vector containing the position of the destination
    pub destination_position_vector: ShortPositionVector,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct TopologicallyScopedBroadcast {
    /// Sequence number field. Indicates the index of the sent TSB packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16,
    /// Reserved. Set to 0
    pub reserved: Bits<16>,
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SingleHopBroadcast {
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector,
    /// Used for media-dependent operations. If not used, it shall be set to 0
    pub media_dependent_data: [u8; 4],
}

pub type GeoBroadcast = GeoAnycast;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
/// In case of a circular area (GeoNetworking packet sub-type HST = 0), the fields shall be set to the following values:
/// 1) Distance a is set to the radius r.
/// 2) Distance b is set to 0.
/// 3) Angle is set to 0.
pub struct GeoAnycast {
    /// Sequence number field. Indicates the index of the sent GBC/GAC packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16,
    /// Reserved. Set to 0
    pub reserved_1: Bits<16>,
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector,
    /// WGS 84 [i.6] latitude for the centre position of the geometric shape as defined in ETSI EN 302 931 \[8\] in 1/10 micro degree
    pub geo_area_position_latitude: i32,
    /// WGS 84 [i.6] longitude for the centre position of the geometric shape as defined in ETSI EN 302 931 \[8\] in 1/10 micro degree
    pub geo_area_position_longitude: i32,
    /// Distance a of the geometric shape as defined in ETSI EN 302 931 \[8\] in meters
    pub distance_a: u16,
    /// Distance b of the geometric shape as defined in ETSI EN 302 931 \[8\] in meters
    pub distance_b: u16,
    /// Angle of the geometric shape as defined in ETSI EN 302 931 \[8\] in degrees from North
    pub angle: u16,
    /// Reserved. Set to 0
    pub reserved_2: Bits<16>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Beacon {
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct LSRequest {
    /// Sequence number field. Indicates the index of the sent LS Request packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16,
    /// Reserved. Set to 0
    pub reserved: Bits<16>,
    /// Long Position Vector containing the reference position of the source
    pub source_position_vector: LongPositionVector,
    /// The `GN_ADDR` address for the GeoAdhoc router entity for which the location is being requested
    pub request_gn_address: Address,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct LSReply {
    /// Sequence number field. Indicates the index of the sent LS Reply packet (clause 8.3) and used to detect duplicate GeoNetworking packets
    pub sequence_number: u16,
    /// Reserved. Set to 0
    pub reserved: Bits<16>,
    /// Long Position Vector containing the reference position of the source, which represents the Request `GN_ADDR` in the corresponding LS Request
    pub source_position_vector: LongPositionVector,
    /// Short Position Vector containing the position of the destination
    pub destination_position_vector: ShortPositionVector,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gets_lifetime_base() {
        assert_eq!(Lifetime(127).base(), 3);
        assert_eq!(Lifetime(126).base(), 2);
        assert_eq!(Lifetime(125).base(), 1);
    }

    #[test]
    fn gets_lifetime_multiplier() {
        assert_eq!(Lifetime(5).multiplier(), 1);
        assert_eq!(Lifetime(9).multiplier(), 2);
        assert_eq!(Lifetime(125).multiplier(), 31);
        assert_eq!(Lifetime(255).multiplier(), 63);
    }
}
