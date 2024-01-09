# `geonetworking`
Rust tools for encoding and decoding GeoNetworking packets according to EN 302 636-4-1 v1.3.1.
Supports `#[no_std]`.

## Usage
The `geonetworking` library decodes and encodes GeoNetworking packets according to EN 302 636-4-1 v1.3.1

### Installation
Add `geonetworking = "0.1"` to the `[dependencies]` section of your project's `Cargo.toml` manifest. The default features include data validation functionalities and JSON serialization with `serde`. If you do not wish to include validation and JSON functionalities in your build, declare the dependency as follows: `geonetworking = { version = "0.1", default-features = false }`. The `"validation"` features requires the standard library as well as an openssl installation of major version 3.

#### Decoding
`geonetworking` provides a `Decode` trait that is implemented by the GeoNetworking `Packet` (containing all headers and payload), the subheaders `BasicHeader` `CommonHeader` `Ieee1609Dot2Data` (a.k.a. Secured Header) as well as the extended headers:
 - `GeoUnicast`
 - `TopologicallyScopedBroadcast`
 - `SingleHopBroadcast`
 - `GeoBroadcast`
 - `GeoAnycast`
 - `Beacon`
 - `LSRequest`
 - `LSReply`
 The trait's `decode` method returns a `Result`-wrapped `Decoded` struct, which contains the decoded data and the number of consumed bytes.
```rust
use geonetworking::*;

// GeoNetworking Header with security and a payload of BTP-B and CAM
let data: &'static [u8] = &[
        0x12, 0x00, 0x05, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x5f, 0x20, 0x50, 0x02, 0x80, 0x00, 0x3b, 0x01, 0x00, 0x14, 0x00, 0x1e, 0x0d, 0xdf, 0x3f, 0x5b, 0x7d, 0xa0, 0xcd, 0xf2, 0x54, 0x1c, 0x81, 0x28, 0xaf, 0x07, 0xc5, 0xdd, 0xa5, 0x80, 0x04, 0x09, 0xf6, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0xdf, 0x3f, 0x5b, 0x7d, 0xf2, 0x54, 0x40, 0x5a, 0x44, 0xc2, 0x35, 0xee, 0x61, 0xf5, 0xf4, 0xa2, 0x06, 0x20, 0x60, 0x00, 0x47, 0xbe, 0x50, 0x48, 0x9f, 0x7f, 0xa0, 0x02, 0x1c, 0xbf, 0xe9, 0xea, 0x83, 0x33, 0xff, 0x01, 0xff, 0xfa, 0x00, 0x28, 0x33, 0x00, 0x00, 0x1b, 0xfb, 0xc2, 0xff, 0x94, 0x36, 0x60, 0x7f, 0xff, 0x00, 0xc0, 0x01, 0x24, 0x00, 0x02, 0x34, 0xf4, 0x24, 0x7b, 0xf3, 0x0c, 0x02, 0x05, 0x80, 0x05, 0x01, 0x01, 0x7c, 0xe7, 0xf9, 0x81, 0x01, 0x01, 0x80, 0x03, 0x00, 0x80, 0x5d, 0x5d, 0xcb, 0xee, 0xfb, 0xe7, 0xd2, 0x2d, 0x30, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xbd, 0x2d, 0x05, 0x86, 0x00, 0x01, 0xe0, 0x01, 0x07, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x8c, 0x81, 0x05, 0x04, 0x02, 0xff, 0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x02, 0x7e, 0x81, 0x02, 0x01, 0x01, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x00, 0x02, 0x03, 0xff, 0x80, 0x80, 0x82, 0xde, 0xa0, 0x8e, 0xa8, 0xe8, 0x3e, 0x46, 0x24, 0x4a, 0x8f, 0x98, 0xa1, 0xdf, 0x15, 0x1e, 0x93, 0x8d, 0x26, 0x39, 0xac, 0xda, 0xa4, 0x10, 0x80, 0x48, 0x80, 0xaa, 0x36, 0x2e, 0x85, 0x5d, 0xad, 0x81, 0x83, 0x5b, 0xd8, 0x00, 0xfc, 0xe3, 0x7f, 0x70, 0x70, 0xdf, 0xf5, 0x90, 0x27, 0xa3, 0x9d, 0x19, 0xae, 0x8d, 0xe9, 0x60, 0x76, 0x12, 0xcb, 0xb2, 0x30, 0x9a, 0xf5, 0xfe, 0x89, 0x43, 0x30, 0x08, 0x02, 0x8e, 0x29, 0x4f, 0xf7, 0xef, 0xae, 0xca, 0xbf, 0x82, 0x4c, 0xab, 0x93, 0x27, 0x04, 0xcb, 0x98, 0x20, 0x80, 0xf3, 0x42, 0x90, 0x0c, 0x1f, 0xda, 0x11, 0xf6, 0xda, 0x43, 0x40, 0x05, 0xed, 0x85, 0x80, 0x82, 0x36, 0x99, 0x42, 0xdc, 0x48, 0x8d, 0xe7, 0x2f, 0x81, 0xeb, 0x82, 0x3b, 0xf9, 0x3d, 0xbd, 0xa1, 0xad, 0xb6, 0x37, 0x4b, 0xcd, 0x3d, 0x41, 0x69, 0x07, 0x33, 0x50, 0xc2, 0x6b, 0x72, 0x8b, 0xbe, 0x37, 0x47, 0x18, 0x35, 0x4a, 0x6f, 0xf6, 0xc1, 0x93, 0x6b, 0x25, 0x59, 0x94, 0xb9, 0x13, 0x49, 0xd2, 0x47, 0x5f, 0x73, 0x61, 0x97, 0x8b, 0xd7, 0x93, 0x21, 0x57, 0x37, 0x53, 0xc1, 0x4d, 0x36, 
    ];
let result = Packet::decode(data).unwrap();
println!("Consumed {} bytes and decoded GeoNetworking packet {:?}", result.bytes_consumed, result.decoded);
```

### Encoding a GeoNetworking Header
The crate's `Encode` trait provides two (three with the `json` feature enabled) methods for encoding items:
`decode` takes an `Encoder` as input and can be used for concatenating multiple items in one encoding.
For encoding a single item `decode_to_vec` provides a shorthand that returns immediately the bytes of the encoding.
**Currently, only non-secured packets can be encoded.**
```rust
use geonetworking::*;

let packet = Packet::Unsecured {
    basic: BasicHeader {
        version: 1,
        next_header: NextAfterBasic::CommonHeader,
        // The bits! macro accepts a comma-separated list of 1s and 0s (see below)
        // or a value (1 or 0) and a length value (usize), separated by a semicolon
        reserved: bits![0; 8],
        lifetime: Lifetime(80),
        remaining_hop_limit: 1,
    },
    common: CommonHeader {
        next_header: NextAfterCommon::BTPB,
        reserved_1: bits![0, 0, 0, 0],
        header_type_and_subtype: HeaderType::TopologicallyScopedBroadcast(
            BroadcastType::SingleHop,
        ),
        traffic_class: TrafficClass {
            store_carry_forward: false,
            channel_offload: false,
            traffic_class_id: 2,
        },
        flags: bits![0, 0, 0, 0, 0, 0, 0, 0],
        payload_length: 1,
        maximum_hop_limit: 1,
        reserved_2: bits![0, 0, 0, 0, 0, 0, 0, 0],
    },
    extended: Some(ExtendedHeader::SHB(SingleHopBroadcast {
        source_position_vector: LongPositionVector {
            gn_address: Address {
                manually_configured: false,
                station_type: StationType::Unknown,
                reserved: bits![0, 1, 0, 0, 0, 0, 0, 1, 1, 0],
                address: [0, 96, 224, 105, 87, 141],
            },
            timestamp: Timestamp(542947520),
            latitude: 535574568,
            longitude: 99765648,
            position_accuracy: false,
            speed: 680,
            heading: 2122,
        },
        media_dependent_data: [127, 0, 184, 0],
    })),
    payload: &[42]
};

/// Encode using an encoder
let mut encoder = Encoder::new();
packet.encode(&mut encoder).unwrap();

let output: Vec<u8> = encoder.into();

/// Encode and return bytes
let bytes = packet.encode_to_vec().unwrap();

assert_eq!(output, bytes);
```

### Validating a Packet
**For packet validation to be available, the `"validate"` feature must be enabled.**
The `Validate` trait exposes a `validate` method that checks whether the implementing type is valid.
`validate` runs the following checks:
- The signature of a secured packet matches the certificate contained in the IEEE 1609.2 header
- *WIP* The packet conforms to IEEE 1609.2 2016
- *WIP* The packet conforms to ETSI TS 103 097 V2.1.1
#### `validate` returns
- `Ok(ValidationResult::Success)` if all checks passed successful
- `Ok(ValidationResult::Failure { reason: String })` if a check failed
- `Ok(ValidationResult::NotApplicable { info: &'static str })` if no validation checks were run
- `Err(ValidationError)` if an internal error occured during validation

```rust
use geonetworking::*;

// GeoNetworking Header with security and a payload of BTP-B and CAM
let data: &'static [u8] = &[
        0x12, 0x00, 0x05, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x81, 0xbd, 0x20, 0x50, 0x02, 0x80, 0x00, 0x99, 0x01, 0x00, 0x14, 0x00, 0xca, 0xb0, 0xa5, 0x28, 0x3d, 0x0a, 0x2c, 0xd5, 0x54, 0xcf, 0x1c, 0x7f, 0x37, 0xa3, 0x07, 0xc6, 0xb6, 0x44, 0x82, 0xcc, 0x0b, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0xa5, 0x28, 0x3d, 0x0a, 0x54, 0xcf, 0x40, 0x5a, 0x44, 0x84, 0x14, 0x6e, 0x62, 0x11, 0x08, 0x80, 0xb8, 0x0b, 0x80, 0x00, 0x47, 0xa7, 0xce, 0x48, 0xbb, 0xf1, 0x01, 0x54, 0x08, 0x82, 0x98, 0x8a, 0x8f, 0x34, 0x12, 0x62, 0x01, 0x0a, 0x00, 0x28, 0x73, 0x00, 0x00, 0xcb, 0xff, 0x7d, 0x00, 0x54, 0x31, 0x92, 0x00, 0x09, 0xdf, 0xbf, 0xd8, 0x26, 0x75, 0x8f, 0x10, 0x07, 0x7f, 0x00, 0x1d, 0x40, 0x10, 0x4c, 0x69, 0x80, 0x95, 0xf7, 0xf5, 0xc6, 0x06, 0x5c, 0x64, 0x14, 0x06, 0x2b, 0xbf, 0x80, 0x70, 0x4b, 0x3b, 0x1e, 0xc0, 0x08, 0x1d, 0xfb, 0xf6, 0x82, 0x70, 0x98, 0xf1, 0x00, 0x31, 0xef, 0xe0, 0x1c, 0x13, 0x6c, 0xc7, 0x88, 0x01, 0x67, 0x7e, 0xfd, 0x60, 0x9e, 0x86, 0x3b, 0x00, 0x0b, 0x3b, 0xf8, 0xcb, 0x04, 0x7e, 0xb1, 0xc4, 0x00, 0x4f, 0xdf, 0xc5, 0xa8, 0x23, 0xdd, 0x8e, 0x20, 0x02, 0x7e, 0xfe, 0x2c, 0x41, 0x1c, 0xec, 0x67, 0x00, 0x13, 0xf7, 0xef, 0xa6, 0x09, 0xce, 0x63, 0x60, 0x00, 0xb3, 0x40, 0x01, 0x24, 0x00, 0x02, 0x3a, 0xff, 0x21, 0x55, 0xe9, 0x67, 0x81, 0x01, 0x01, 0x80, 0x03, 0x00, 0x80, 0x5d, 0x5d, 0xcb, 0xee, 0xfb, 0xe7, 0xd2, 0x2d, 0x30, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x47, 0x9a, 0x85, 0x86, 0x00, 0x01, 0xe0, 0x01, 0x07, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x8c, 0x81, 0x05, 0x04, 0x02, 0xff, 0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x02, 0x7e, 0x81, 0x02, 0x01, 0x01, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x00, 0x02, 0x03, 0xff, 0x80, 0x80, 0x83, 0x84, 0x16, 0x11, 0x01, 0xf5, 0x8b, 0x0a, 0x44, 0x8d, 0xb0, 0x60, 0x45, 0x96, 0x21, 0xec, 0x8b, 0xaf, 0xf0, 0xb2, 0x35, 0xd3, 0x5d, 0xc5, 0xe0, 0xd9, 0x7b, 0x3e, 0xee, 0x12, 0xc1, 0x5e, 0xe7, 0x81, 0x80, 0x9c, 0x28, 0x35, 0xd1, 0xd5, 0x7e, 0x28, 0x92, 0xd9, 0xb8, 0x66, 0x75, 0xd8, 0x0a, 0x4b, 0x75, 0x7c, 0x55, 0x49, 0x8f, 0x58, 0x41, 0xf0, 0xc5, 0xca, 0xe7, 0x7a, 0x4d, 0xd4, 0xc3, 0x4a, 0x74, 0x7c, 0x0a, 0x34, 0xd8, 0x2b, 0x5f, 0x28, 0x35, 0xde, 0xc9, 0x9e, 0x39, 0x45, 0x59, 0xde, 0x3d, 0x5e, 0x40, 0x43, 0x0a, 0x5c, 0x7a, 0x7e, 0x6e, 0x26, 0x06, 0x36, 0x9b, 0x6a, 0x96, 0xb1, 0x2c, 0x80, 0x83, 0xf6, 0xd4, 0x0f, 0x37, 0x94, 0xf1, 0x02, 0xf3, 0x37, 0xe2, 0xa8, 0xb7, 0x2a, 0x82, 0xf9, 0xca, 0xe8, 0xf6, 0x7f, 0x9f, 0x32, 0xf4, 0xe4, 0x61, 0x22, 0x43, 0x95, 0x6a, 0xab, 0x81, 0x6b, 0x92, 0x71, 0x39, 0x11, 0xd7, 0xb6, 0xe2, 0x93, 0x6f, 0xc4, 0xef, 0x79, 0x2e, 0x41, 0x55, 0x02, 0x58, 0x0f, 0x4e, 0xf5, 0xca, 0x4c, 0x12, 0x6d, 0xd9, 0x76, 0x7f, 0xab, 0x9c, 0x87, 0xd7, 0x36, 0xa5,
    ];
let packet = Packet::decode(data).unwrap().decoded;
assert_eq!(packet.validate(), Ok(ValidationResult::Success));
```