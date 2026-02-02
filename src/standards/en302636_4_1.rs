//! Message types from EN 302 636-4-1

extern crate alloc;
use alloc::string::ToString;

use arbitrary_int::{i15, traits::Integer, u10, u4, u6};
#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

const LATLON_TO_INT_FACTOR: f32 = 1e7; // unit: 1/10 micro degree
const ANGLE_TO_INT_FACTOR: f32 = 10f32; // unit: 0.1 degree

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// (integer) value does not fit the target type
    ValueOutOfBounds(OutOfBoundsError),
    /// value does not fit the plausible value range
    ValueOutOfRange(alloc::string::String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ValueOutOfBounds(out_of_bounds_error) => write!(f, "{out_of_bounds_error}"),
            Error::ValueOutOfRange(value_name) => {
                write!(f, "Value out of range: '{value_name}' is not a sane value")
            }
        }
    }
}

impl core::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
pub struct OutOfBoundsError {
    pub value_name: alloc::string::String,
    pub bounds_name: alloc::string::String,
}

impl core::fmt::Display for OutOfBoundsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Value out of bounds: given '{}' does not fit inside an {}",
            self.value_name, self.bounds_name
        )
    }
}

impl OutOfBoundsError {
    fn new(value_name: &str, bounds_name: &str) -> Self {
        Self {
            value_name: value_name.to_string(),
            bounds_name: bounds_name.to_string(),
        }
    }
}

fn make_latitude(deg: f32) -> Result<i32, Error> {
    #[allow(clippy::cast_possible_truncation)]
    let raw = (deg * LATLON_TO_INT_FACTOR) as i32;
    if (-900_000_000..=900_000_000).contains(&raw) {
        Ok(raw)
    } else {
        Err(Error::ValueOutOfRange("latitude".to_string()))
    }
}

fn make_longitude(deg: f32) -> Result<i32, Error> {
    #[allow(clippy::cast_possible_truncation)]
    let raw = (deg * LATLON_TO_INT_FACTOR) as i32;
    if (-1_800_000_000..=1_800_000_000).contains(&raw) {
        Ok(raw)
    } else {
        Err(Error::ValueOutOfRange("longitude".to_string()))
    }
}

fn make_heading(deg: f32) -> Result<u16, Error> {
    if deg < 0. {
        return Err(Error::ValueOutOfRange("heading".to_string()));
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let raw = (deg * ANGLE_TO_INT_FACTOR) as u16;
    if raw > 3600 {
        Err(Error::ValueOutOfRange("heading".to_string()))
    } else {
        Ok(raw)
    }
}

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
    pub reserved: u10, // 10 bits
    /// Represents the `LL_ADDR`
    pub address: [u8; 6], // 48 bits (6 byte)
}

impl Address {
    #[must_use]
    pub fn new(manually_configured: bool, station_type: StationType, address: [u8; 6]) -> Self {
        Self {
            manually_configured,
            station_type,
            reserved: u10::from_u16(0),
            address,
        }
    }
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

    /// Creates a Geonetworking Timestamp from an `TimestampITS` value
    #[must_use]
    pub fn from_its_timestamp(timestamp_its: u64) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let ts_mod = (timestamp_its % 4_294_967_296) as u32;
        Self(ts_mod)
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
    const MPS_TO_INT_FACTOR: f32 = 100f32; // unit: 0.01 metre per second
    const SPEED_MIN: i16 = -16_384;
    const SPEED_MAX: i16 = 16_383;

    /// Creates new instance from floating point values
    ///
    /// Provide:
    /// - a timestamp as `TimestampIts` value
    /// - latitude and longitude in degrees north/ east
    /// - speed in meters per second
    /// - heading in degrees from north
    ///
    /// # Errors
    /// Returns [`Error::ValueOutOfRange`] when some input value is outside the plausible value range.
    /// Returns [`Error::ValueOutOfBounds`] when some input value does not fit the target value range.
    pub fn try_from_values(
        gn_address: Address,
        timestamp_its: u64,
        latitude_deg: f32,
        longitude_deg: f32,
        position_accuracy: bool,
        speed_mps: f32,
        heading_deg: f32,
    ) -> Result<Self, Error> {
        let latitude = make_latitude(latitude_deg)?;
        let longitude = make_longitude(longitude_deg)?;

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let speed = (speed_mps * Self::MPS_TO_INT_FACTOR) as i16; // integer value range will be checked by Self::try_new

        let heading = make_heading(heading_deg)?;

        let timestamp = Timestamp::from_its_timestamp(timestamp_its);

        Self::try_new(
            gn_address,
            timestamp,
            latitude,
            longitude,
            position_accuracy,
            speed,
            heading,
        )
    }

    /// Creates new instance from parts
    ///
    /// # Errors
    /// Returns [`Error::ValueOutOfBounds`] when some input value does not fit the target value range.
    /// The values will only be checked for integer range, not plausibility.
    pub fn try_new(
        gn_address: Address,
        timestamp: Timestamp,
        latitude: i32,
        longitude: i32,
        position_accuracy: bool,
        speed: i16,
        heading: u16,
    ) -> Result<Self, Error> {
        let speed = i15::try_new(speed)
            .map_err(|_| Error::ValueOutOfBounds(OutOfBoundsError::new("speed", "i15")))?;

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

    #[must_use]
    /// Returns latitude and longitude in degrees
    pub fn get_position_deg(&self) -> (f32, f32) {
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let lat = (self.latitude as f32) / LATLON_TO_INT_FACTOR;
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let lon = (self.longitude as f32) / LATLON_TO_INT_FACTOR;
        (lat, lon)
    }

    #[must_use]
    pub fn get_speed_mps(&self) -> f32 {
        f32::from(self.speed.as_i16()) / Self::MPS_TO_INT_FACTOR
    }

    #[must_use]
    pub fn get_heading_deg(&self) -> f32 {
        f32::from(self.heading) / ANGLE_TO_INT_FACTOR
    }

    /// Clamps a speed value in meters per second to the allowed value range in the LPV
    #[must_use]
    pub fn clamp_speed_mps(speed_mps: f32) -> f32 {
        let min_mps = f32::from(Self::SPEED_MIN) / Self::MPS_TO_INT_FACTOR;
        let max_mps = f32::from(Self::SPEED_MAX) / Self::MPS_TO_INT_FACTOR;

        speed_mps.clamp(min_mps, max_mps)
    }
}

#[derive(Debug, Clone, PartialEq)]
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

impl ShortPositionVector {
    /// Creates new instance from floating point values
    ///
    /// Provide:
    /// - a timestamp as `TimestampIts` value
    /// - latitude and longitude in degrees north/ east
    ///
    /// # Errors
    /// Returns [`Error::ValueOutOfRange`] when some input value is outside the plausible value range.
    pub fn try_from_values(
        gn_address: Address,
        timestamp_its: u64,
        latitude_deg: f32,
        longitude_deg: f32,
    ) -> Result<Self, Error> {
        let latitude = make_latitude(latitude_deg)?;
        let longitude = make_longitude(longitude_deg)?;

        let timestamp = Timestamp::from_its_timestamp(timestamp_its);

        Ok(Self {
            gn_address,
            timestamp,
            latitude,
            longitude,
        })
    }
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
    /// Creates new instance from parts
    ///
    /// # Errors
    /// Returns [`Error::ValueOutOfBounds`] when some input value does not fit the target value range.
    /// The values will only be checked for integer range, not plausibility.
    pub fn try_new(
        version: u8,
        next_header: NextAfterBasic,
        lifetime: Lifetime,
        remaining_hop_limit: u8,
    ) -> Result<Self, Error> {
        let version = u4::try_new(version)
            .map_err(|_| Error::ValueOutOfBounds(OutOfBoundsError::new("version", "u4")))?;

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

    #[must_use]
    pub fn from_milliseconds(millis: u32) -> Self {
        // lifetime bases:
        // - 0:  50 ms
        // - 1:   1 s
        // - 2:  10 s
        // - 3: 100 s
        // lifetime multiplier: 6 bit -> 0..63
        const ITS_GN_MAX_PACKET_LIFETIME: u32 = 600_000; // itsGnMaxPacketLifetime according to ETSI EN 302 636-4-1 V1.4.1

        // use base with highest resolution for as long as possible, but without creating "jumps".
        // e.g. 3150 ms is not represented as 63*50 ms because next higher value (3200 ms) can only be represented as 3*1 second.
        let (multiplier, base) = if millis < 3000 {
            // max. value which can be represented: 63 * 50 ms = 3150 ms
            let multiplier = millis / 50;

            (multiplier, 0) // multiplier 50ms
        } else if millis < 60_000 {
            // max. value which can be represented: 63 * 1 s = 63 s
            let multiplier = millis / 1000;

            (multiplier, 1) // multiplier 1s/ 1000ms
        } else if millis < 600_000 {
            // max. value which can be represented: 63 * 10 s = 630 s
            let multiplier = millis / 10_000;

            (multiplier, 2) // multiplier 10s/ 10000ms
        } else if millis < ITS_GN_MAX_PACKET_LIFETIME {
            let multiplier = millis / 100_000;

            (multiplier, 3) // multiplier 100s
        } else {
            (ITS_GN_MAX_PACKET_LIFETIME / 100_000, 3) // multiplier 100s/ 100000ms
        };

        #[allow(clippy::cast_possible_truncation)]
        let lifetime_data = (multiplier << 2) as u8 | (base & 0x03);

        Self(lifetime_data)
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
    /// Bit 1 to Bit 7: Reserved, set to 0
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

    /// Creates new instance from individual values
    #[must_use]
    pub fn from_values(
        next_header: NextAfterCommon,
        header_type_and_subtype: HeaderType,
        traffic_class: TrafficClass,
        is_mobile: bool,
        payload_length: u16,
        maximum_hop_limit: u8,
    ) -> Self {
        let flags = [is_mobile, false, false, false, false, false, false, false];

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
    /// Creates new instance from parts
    ///
    /// # Errors
    /// Returns [`Error::ValueOutOfBounds`] when some input value does not fit the target value range.
    /// The values will only be checked for integer range, not plausibility.
    pub fn try_new(
        store_carry_forward: bool,
        channel_offload: bool,
        traffic_class_id: u8,
    ) -> Result<Self, Error> {
        let traffic_class_id = u6::try_new(traffic_class_id).map_err(|_| {
            Error::ValueOutOfBounds(OutOfBoundsError::new("traffic_class_id", "u6"))
        })?;

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

impl HeaderType {
    /// Creates an instance from an [`ExtendedHeader`] type and some [`AreaType`] for GAC and GBC
    ///
    /// We can't infer the area type just from the `GeoAnycast` information,
    /// so in case of GAC or GBC the `area_type` parameter needs to be set.
    ///
    /// # Errors
    /// human-readable string when GAC/ GBC area type is not obvious (circular) and isn't provided.
    #[allow(unused)]
    pub fn new_from(
        value: &ExtendedHeader,
        area_type: Option<AreaType>,
    ) -> Result<Self, alloc::string::String> {
        Ok(match &value {
            ExtendedHeader::Beacon(_) => Self::Beacon,
            ExtendedHeader::GAC(gac) => {
                let atype = if gac.distance_b == 0 && gac.angle == 0 {
                    AreaType::Circular
                } else if let Some(area) = area_type {
                    area
                } else {
                    return Err("GAC area type can't be inferred and isn't provided".into());
                };
                Self::GeoAnycast(atype)
            }
            ExtendedHeader::GBC(gac) => {
                let atype = if gac.distance_b == 0 && gac.angle == 0 {
                    AreaType::Circular
                } else if let Some(area) = area_type {
                    area
                } else {
                    return Err("GBC area type can't be inferred and isn't provided".into());
                };
                Self::GeoBroadcast(atype)
            }
            ExtendedHeader::GUC(_) => Self::GeoUnicast,
            ExtendedHeader::TSB(_) => Self::TopologicallyScopedBroadcast(BroadcastType::MultiHop),
            ExtendedHeader::SHB(_) => Self::TopologicallyScopedBroadcast(BroadcastType::SingleHop),
            ExtendedHeader::LSRequest(_) => Self::LocationService(LocationServiceType::Request),
            ExtendedHeader::LSReply(_) => Self::LocationService(LocationServiceType::Reply),
        })
    }
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

impl GeoUnicast {
    #[must_use]
    pub fn new(
        sequence_number: u16,
        source_position_vector: LongPositionVector,
        destination_position_vector: ShortPositionVector,
    ) -> Self {
        Self {
            sequence_number,
            reserved: 0,
            source_position_vector,
            destination_position_vector,
        }
    }
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

impl TopologicallyScopedBroadcast {
    #[must_use]
    pub fn new(sequence_number: u16, source_position_vector: LongPositionVector) -> Self {
        Self {
            sequence_number,
            reserved: 0,
            source_position_vector,
        }
    }
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

impl GeoAnycast {
    /// Creates new instance from floating point values
    ///
    /// Provide:
    /// - latitude and longitude in degrees north/ east
    /// - distances in meters
    /// - angle in degrees from north
    ///
    /// # Errors
    /// Returns [`Error::ValueOutOfRange`] when some input value is outside the plausible value range.
    pub fn try_from_values(
        sequence_number: u16,
        source_position_vector: LongPositionVector,
        latitude_deg: f32,
        longitude_deg: f32,
        distance_a: u16,
        distance_b: u16,
        angle: u16,
    ) -> Result<Self, Error> {
        let latitude = make_latitude(latitude_deg)?;
        let longitude = make_longitude(longitude_deg)?;

        if angle > 360 {
            return Err(Error::ValueOutOfRange("angle".to_string()));
        }

        Ok(Self::new(
            sequence_number,
            source_position_vector,
            latitude,
            longitude,
            distance_a,
            distance_b,
            angle,
        ))
    }

    #[must_use]
    pub fn new(
        sequence_number: u16,
        source_position_vector: LongPositionVector,
        geo_area_position_latitude: i32,
        geo_area_position_longitude: i32,
        distance_a: u16,
        distance_b: u16,
        angle: u16,
    ) -> Self {
        Self {
            sequence_number,
            reserved_1: 0,
            source_position_vector,
            geo_area_position_latitude,
            geo_area_position_longitude,
            distance_a,
            distance_b,
            angle,
            reserved_2: 0,
        }
    }
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

impl LSRequest {
    #[must_use]
    pub fn new(
        sequence_number: u16,
        source_position_vector: LongPositionVector,
        request_gn_address: Address,
    ) -> Self {
        Self {
            sequence_number,
            reserved: 0,
            source_position_vector,
            request_gn_address,
        }
    }
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

impl LSReply {
    #[must_use]
    pub fn new(
        sequence_number: u16,
        source_position_vector: LongPositionVector,
        destination_position_vector: ShortPositionVector,
    ) -> Self {
        Self {
            sequence_number,
            reserved: 0,
            source_position_vector,
            destination_position_vector,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_latitude() {
        assert_eq!(Ok(0), make_latitude(0.));
        assert_eq!(Ok(900_000_000), make_latitude(90.));
        assert_eq!(Ok(-900_000_000), make_latitude(-90.));
        assert!(make_latitude(90.1).is_err());
        assert!(make_latitude(-90.1).is_err());
    }

    #[test]
    fn convert_longitude() {
        assert_eq!(Ok(0), make_longitude(0.));
        assert_eq!(Ok(1_800_000_000), make_longitude(180.));
        assert_eq!(Ok(-1_800_000_000), make_longitude(-180.));
        assert!(make_longitude(180.1).is_err());
        assert!(make_longitude(-180.1).is_err());
    }

    #[test]
    fn convert_heading() {
        assert_eq!(Ok(0), make_heading(0.));
        assert_eq!(Ok(3600), make_heading(360.));
        assert!(make_heading(360.1).is_err());
        assert!(make_heading(-1.).is_err());
    }

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
