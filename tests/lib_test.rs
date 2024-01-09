use geonetworking::*;

#[test]
fn decode_beacon() {
    let data: &'static [u8] = &[
        0x11, 0x00, 0x1a, 0x01, 0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x00,
        0x0d, 0x41, 0x12, 0x36, 0x70, 0x71, 0x1e, 0xfd, 0xf4, 0x1f, 0xed, 0x2c, 0x46, 0x05, 0xf4,
        0x49, 0x6d, 0x80, 0x00, 0x0d, 0x4f,
    ];
    let result = Packet::decode(data).unwrap();
    assert_eq!(
        result,
        Decoded {
            bytes_consumed: 36,
            decoded: Packet::Unsecured {
                basic: BasicHeader {
                    version: 1,
                    next_header: NextAfterBasic::CommonHeader,
                    reserved: bits![0, 0, 0, 0, 0, 0, 0, 0],
                    lifetime: Lifetime(26),
                    remaining_hop_limit: 1
                },
                common: CommonHeader {
                    next_header: NextAfterCommon::Any,
                    reserved_1: bits![0, 0, 0, 0],
                    header_type_and_subtype: HeaderType::Beacon,
                    traffic_class: TrafficClass {
                        store_carry_forward: false,
                        channel_offload: false,
                        traffic_class_id: 3
                    },
                    flags: bits![0, 0, 0, 0, 0, 0, 0, 0],
                    payload_length: 0,
                    maximum_hop_limit: 1,
                    reserved_2: bits![0, 0, 0, 0, 0, 0, 0, 0]
                },
                extended: Some(ExtendedHeader::Beacon(Beacon {
                    source_position_vector: LongPositionVector {
                        gn_address: Address {
                            manually_configured: false,
                            station_type: StationType::RoadSideUnit,
                            reserved: bits![0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                            address: [0, 13, 65, 18, 54, 112]
                        },
                        timestamp: Timestamp(1897856500),
                        latitude: 535637062,
                        longitude: 99895661,
                        position_accuracy: true,
                        speed: 0,
                        heading: 3407
                    }
                })),
                payload: &[]
            },
        }
    )
}

#[test]
fn beacon_round_trip() {
    let data: &'static [u8] = &[
        0x11, 0x00, 0x1a, 0x01, 0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x00,
        0x0d, 0x41, 0x12, 0x36, 0x70, 0x71, 0x1e, 0xfd, 0xf4, 0x1f, 0xed, 0x2c, 0x46, 0x05, 0xf4,
        0x49, 0x6d, 0x80, 0x00, 0x0d, 0x4f,
    ];
    let decoded = Packet::decode(data).unwrap();
    let encoded = decoded.decoded.encode_to_vec().unwrap();
    assert_eq!(data, &encoded)
}

#[test]
fn unsecured_round_trip() {
    let expected = vec![
        0x11, 0x00, 0x50, 0x01, 0x20, 0x50, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x06, 0x00,
        0x60, 0xe0, 0x69, 0x57, 0x8d, 0x20, 0x5c, 0xb8, 0xc0, 0x1f, 0xec, 0x38, 0x28, 0x05, 0xf2,
        0x4d, 0x90, 0x02, 0xa8, 0x08, 0x4a, 0x7f, 0x00, 0xb8, 0x00, 0x00,
    ];
    let packet = Packet::Unsecured {
        basic: BasicHeader {
            version: 1,
            next_header: NextAfterBasic::CommonHeader,
            reserved: bits![0, 0, 0, 0, 0, 0, 0, 0],
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
        payload: &[0],
    };
    let encoded = packet.encode_to_vec().unwrap();
    let decoded = Packet::decode(encoded.as_slice()).unwrap();
    assert!(decoded.bytes_consumed == encoded.len());
    assert_eq!(expected, encoded);
    assert_eq!(decoded.decoded, packet);
}

#[test]
fn packet_to_json() {
    let data: Vec<u8> = vec![
        0x11, 0x00, 0x50, 0x01, 0x20, 0x50, 0x02, 0x00, 0x00, 0x2d, 0x01, 0x00, 0x01, 0x06, 0x00,
        0x60, 0xe0, 0x69, 0x57, 0x8d, 0x20, 0x5c, 0xb8, 0xc0, 0x1f, 0xec, 0x38, 0x28, 0x05, 0xf2,
        0x4d, 0x90, 0x02, 0xa8, 0x08, 0x4a, 0x7f, 0x00, 0xb8, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02,
        0x02, 0xe0, 0x69, 0x57, 0x8d, 0xb4, 0xd9, 0x00, 0x0a, 0xb2, 0x24, 0x63, 0xce, 0x27, 0x84,
        0x2b, 0x1f, 0xff, 0xff, 0xfc, 0x22, 0x31, 0xb5, 0xb2, 0x00, 0x80, 0x5f, 0x41, 0x2d, 0xa2,
        0xbf, 0xe9, 0xed, 0x07, 0x37, 0xfe, 0xeb, 0xff, 0xf6, 0x00,
    ];
    let result = Packet::decode(data.as_slice()).unwrap();
    let json = result.decoded.encode_to_json().unwrap();
    assert_eq!(
        String::from(
            r#"{"Unsecured":{"basic":{"version":1,"next_header":"CommonHeader","reserved":[false,false,false,false,false,false,false,false],"lifetime":80,"remaining_hop_limit":1},"common":{"next_header":"BTPB","reserved_1":[false,false,false,false],"header_type_and_subtype":{"TopologicallyScopedBroadcast":"SingleHop"},"traffic_class":{"store_carry_forward":false,"channel_offload":false,"traffic_class_id":2},"flags":[false,false,false,false,false,false,false,false],"payload_length":45,"maximum_hop_limit":1,"reserved_2":[false,false,false,false,false,false,false,false]},"extended":{"SHB":{"source_position_vector":{"gn_address":{"manually_configured":false,"station_type":"Unknown","reserved":[false,true,false,false,false,false,false,true,true,false],"address":[0,96,224,105,87,141]},"timestamp":542947520,"latitude":535574568,"longitude":99765648,"position_accuracy":false,"speed":680,"heading":2122},"media_dependent_data":[127,0,184,0]}},"payload":[7,209,0,0,2,2,224,105,87,141,180,217,0,10,178,36,99,206,39,132,43,31,255,255,252,34,49,181,178,0,128,95,65,45,162,191,233,237,7,55,254,235,255,246,0]}}"#
        ),
        json
    )
}

macro_rules! round_trip {
    ($typ:ty, $input: expr) => {
        let data: &'static [u8] = $input;
        let decoded = <$typ>::decode(data).unwrap().decoded;
        assert_eq!(data, decoded.encode_to_vec().unwrap().as_slice());
    };
}

#[test]
fn certificate_round_trip() {
    round_trip!(
        Certificate,
        &[
            0x80, 0x03, 0x00, 0x80, 0xfb, 0x9f, 0xe6, 0x57, 0x1f, 0x7c, 0xe7, 0xf9, 0x10, 0x83,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x69, 0x43, 0x01, 0x84, 0x00, 0x30, 0x01, 0x07,
            0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81, 0x05,
            0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x89, 0x81, 0x03, 0x02, 0x01, 0xe0, 0x80,
            0x01, 0x8a, 0x81, 0x03, 0x02, 0x01, 0xc0, 0x80, 0x01, 0x8b, 0x81, 0x07, 0x06, 0x01,
            0x64, 0x00, 0x01, 0xff, 0xff, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x40, 0x6b, 0x81, 0x03,
            0x02, 0x01, 0x80, 0x80, 0x80, 0x83, 0x40, 0x4f, 0x49, 0x7f, 0xf5, 0xae, 0x6c, 0xa8,
            0x92, 0xe5, 0xa8, 0x4c, 0xf0, 0x42, 0x26, 0xa3, 0x5c, 0x99, 0xdd, 0x6f, 0x68, 0x72,
            0x1f, 0x7e, 0x74, 0x60, 0x89, 0xe9, 0xac, 0x4f, 0xf0, 0xf0, 0x80, 0x80, 0x74, 0x89,
            0x6c, 0x85, 0x41, 0x23, 0xf3, 0x1f, 0x03, 0x42, 0x1a, 0x95, 0xc9, 0x0a, 0x3a, 0x69,
            0x31, 0x84, 0xa6, 0x0d, 0x54, 0x37, 0x6f, 0x5b, 0xbe, 0x73, 0x28, 0x7c, 0x5b, 0xcf,
            0x59, 0x4e, 0x24, 0x07, 0x7a, 0xb4, 0x0c, 0x44, 0xfb, 0x48, 0x96, 0xdb, 0x06, 0xc7,
            0x00, 0xb4, 0x01, 0xd7, 0x46, 0xa3, 0x45, 0x35, 0xb0, 0x5a, 0xec, 0x77, 0xc7, 0x06,
            0x12, 0xac, 0x37, 0xaa, 0xe0, 0x1b,
        ]
    );
    round_trip!(
        Certificate,
        &[
            0x80, 0x03, 0x00, 0x80, 0x5d, 0x5d, 0xcb, 0xee, 0xfb, 0xe7, 0xd2, 0x2d, 0x30, 0x83,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x81, 0xd9, 0x85, 0x86, 0x00, 0x01, 0xe0, 0x01,
            0x07, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81,
            0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x8c, 0x81, 0x05, 0x04, 0x02, 0xff,
            0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x02, 0x7e, 0x81, 0x02, 0x01, 0x01, 0x80,
            0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x00, 0x02, 0x03, 0xff, 0x80, 0x80, 0x82,
            0x13, 0x43, 0x08, 0xc4, 0x32, 0x4d, 0x5f, 0x47, 0xfc, 0xbe, 0x66, 0x5f, 0xb5, 0x5b,
            0x40, 0x98, 0xb3, 0x8b, 0x9c, 0xaa, 0x48, 0x4b, 0xd4, 0x47, 0x4c, 0x6c, 0x52, 0x16,
            0x00, 0xa7, 0x50, 0x8c, 0x81, 0x80, 0x3d, 0x9a, 0x96, 0x8a, 0xc1, 0x19, 0x6e, 0x46,
            0xea, 0x98, 0x22, 0x6c, 0x55, 0x20, 0x81, 0xa7, 0x7c, 0xdf, 0xbe, 0xd5, 0x8c, 0x76,
            0x9a, 0xf2, 0x8c, 0x9f, 0xf9, 0x06, 0xe9, 0x26, 0xd9, 0x22, 0x40, 0x5f, 0x18, 0x9a,
            0x1c, 0x6a, 0x03, 0x19, 0x89, 0x68, 0x96, 0x0a, 0x93, 0x32, 0x50, 0x06, 0xaf, 0xfb,
            0x84, 0x40, 0x4c, 0x93, 0x16, 0x80, 0x69, 0x8f, 0xff, 0x27, 0xc8, 0xf3, 0x12, 0x7e
        ]
    );
    round_trip!(
        Certificate,
        &[
            0x80, 0x03, 0x00, 0x80, 0x0a, 0xf6, 0x09, 0xda, 0x7c, 0xc5, 0xaa, 0x91, 0x30, 0x83,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x6f, 0x64, 0x85, 0x86, 0x00, 0x01, 0xe0, 0x01,
            0x0d, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81,
            0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x00, 0x03, 0x08, 0x40, 0x81, 0x80, 0x03, 0x08,
            0x40, 0x82, 0x81, 0x02, 0x01, 0x01, 0x80, 0x01, 0x89, 0x81, 0x03, 0x02, 0x01, 0xe0,
            0x80, 0x01, 0x8a, 0x81, 0x03, 0x02, 0x01, 0xc0, 0x80, 0x01, 0x8b, 0x81, 0x07, 0x06,
            0x01, 0xc7, 0x00, 0x01, 0xff, 0xff, 0x80, 0x01, 0x8c, 0x81, 0x05, 0x04, 0x02, 0xff,
            0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x02, 0x7d, 0x81, 0x02, 0x01, 0x01, 0x80,
            0x02, 0x02, 0x7e, 0x81, 0x02, 0x01, 0x01, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01,
            0x01, 0x80, 0x02, 0x02, 0x80, 0x81, 0x0b, 0x0a, 0x01, 0xc7, 0x00, 0x01, 0x00, 0x1d,
            0x00, 0x28, 0xc0, 0xc0, 0x80, 0x80, 0x83, 0x9f, 0xd0, 0xf3, 0xa8, 0x67, 0x7d, 0x68,
            0x1e, 0x52, 0x97, 0x80, 0x1c, 0x15, 0x60, 0x16, 0xc9, 0x85, 0x40, 0xf7, 0x8c, 0x46,
            0xa0, 0x27, 0x5e, 0x9b, 0xca, 0xa1, 0x13, 0x9c, 0x7b, 0xa0, 0xc5, 0x80, 0x80, 0xeb,
            0xe3, 0x6a, 0x0a, 0xd3, 0x42, 0xd5, 0x42, 0x17, 0x24, 0xd0, 0xdf, 0xa3, 0xa4, 0xc9,
            0xdc, 0x1b, 0x98, 0x12, 0x3a, 0x3d, 0x65, 0x7b, 0xa9, 0xc6, 0x0f, 0x3a, 0xb9, 0x87,
            0x33, 0x70, 0x85, 0x68, 0x74, 0x94, 0x1b, 0xbe, 0x8e, 0x93, 0xf0, 0x9f, 0xac, 0xaf,
            0x9b, 0x7b, 0x42, 0x77, 0x9d, 0x82, 0x93, 0x6d, 0x8c, 0x08, 0x33, 0x12, 0xf4, 0x21,
            0x0d, 0x99, 0x2c, 0x35, 0x1c, 0x7d, 0x0
        ]
    );
    round_trip!(
        Certificate,
        &[
            0x80, 0x03, 0x00, 0x80, 0xf2, 0x9b, 0xd6, 0x64, 0xa9, 0x9a, 0xba, 0xd2, 0x10, 0x83,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xb7, 0x00, 0x03, 0x84, 0x00, 0x30, 0x01, 0x06,
            0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xfe, 0x80, 0x01, 0x8a, 0x81,
            0x03, 0x02, 0x01, 0xc0, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x80, 0x01,
            0x8b, 0x81, 0x07, 0x06, 0x01, 0x00, 0x00, 0x00, 0xff, 0xf8, 0x80, 0x02, 0x02, 0x7d,
            0x81, 0x02, 0x01, 0x01, 0x80, 0x01, 0x89, 0x81, 0x03, 0x02, 0x01, 0xe0, 0x80, 0x81,
            0x82, 0x72, 0xc3, 0x51, 0x93, 0x89, 0xa9, 0x41, 0xc4, 0x95, 0xcd, 0x92, 0x69, 0x9e,
            0x29, 0x3e, 0x6f, 0xe9, 0x05, 0x0f, 0x2d, 0x96, 0xac, 0xb6, 0x35, 0xc4, 0x9a, 0x71,
            0xed, 0x15, 0x27, 0xa7, 0xb1, 0x81, 0x80, 0xa4, 0x23, 0xab, 0x17, 0xc0, 0x26, 0xbf,
            0xd9, 0x48, 0x4b, 0x84, 0xc2, 0x12, 0x92, 0xb6, 0x8a, 0x9e, 0x5b, 0x96, 0xb2, 0xcf,
            0x49, 0x88, 0x22, 0x38, 0x97, 0x94, 0x6a, 0x4c, 0x4e, 0x53, 0x10, 0x99, 0xbb, 0x66,
            0xf1, 0x16, 0x28, 0x79, 0x20, 0x24, 0x24, 0x58, 0xf7, 0x86, 0xaf, 0xea, 0x80, 0xe1,
            0x6f, 0x0f, 0x38, 0x30, 0x12, 0x5f, 0x25, 0xca, 0x7f, 0xf7, 0x56, 0xc8, 0x43, 0x1e,
            0xe1
        ]
    );
    round_trip!(
        Certificate,
        &[
            0x80, 0x03, 0x00, 0x80, 0xcd, 0xd7, 0xf4, 0x64, 0xc6, 0x3a, 0x43, 0x9b, 0x10, 0x83,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xb3, 0x36, 0xa8, 0x84, 0x00, 0xa8, 0x01, 0x05,
            0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xfe, 0x80, 0x01, 0x89, 0x81,
            0x03, 0x02, 0x01, 0xe0, 0x80, 0x01, 0x8a, 0x81, 0x03, 0x02, 0x01, 0xc0, 0x80, 0x01,
            0x8b, 0x81, 0x07, 0x06, 0x01, 0x94, 0x00, 0x00, 0xff, 0xf8, 0x80, 0x02, 0x02, 0x7d,
            0x81, 0x02, 0x01, 0x01, 0x80, 0x80, 0x82, 0xe6, 0x96, 0xf9, 0x5c, 0xfc, 0x16, 0x63,
            0xcf, 0xb7, 0x31, 0xe7, 0x23, 0x10, 0x16, 0xdf, 0x9f, 0x0f, 0x6e, 0x1e, 0x6f, 0x55,
            0xb8, 0xda, 0xca, 0x1f, 0x88, 0x41, 0xdb, 0x9e, 0xaa, 0xe8, 0x71, 0x80, 0x80, 0x26,
            0x04, 0xff, 0x4c, 0x0d, 0x84, 0x5d, 0x21, 0xdd, 0x57, 0xf0, 0x19, 0x15, 0xb4, 0xd7,
            0x29, 0x42, 0x4f, 0xf4, 0x35, 0x09, 0xfa, 0xad, 0x92, 0x33, 0xc2, 0x9c, 0x7c, 0x9f,
            0x99, 0x04, 0x13, 0x15, 0x79, 0x1c, 0x16, 0xb2, 0x8d, 0xd8, 0x56, 0x85, 0x62, 0xd7,
            0x0a, 0x17, 0x24, 0x8c, 0x1f, 0x34, 0xe5, 0x76, 0xee, 0x96, 0x40, 0x0c, 0xb2, 0x28,
            0xde, 0xc8, 0xca, 0x7c, 0x7c, 0x36, 0xbb
        ]
    );
    round_trip!(
        Certificate,
        &[
            0x80, 0x03, 0x00, 0x80, 0x4a, 0x66, 0xdc, 0x14, 0xf6, 0xaf, 0x48, 0xb3, 0x10, 0x83,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x6a, 0xec, 0xda, 0x84, 0x00, 0x24, 0x01, 0x02,
            0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0x02, 0x00, 0x80, 0x01, 0x25, 0x81, 0x05,
            0x04, 0x01, 0x00, 0x40, 0x10, 0x80, 0x80, 0x82, 0x1e, 0x0d, 0x63, 0x0b, 0x91, 0xe7,
            0x89, 0xdf, 0xaa, 0x05, 0x4d, 0x22, 0xab, 0x9d, 0x46, 0x34, 0x4d, 0x40, 0x4b, 0xde,
            0xe2, 0xed, 0x8d, 0x94, 0xb6, 0xf5, 0x40, 0xc0, 0xd8, 0xab, 0x78, 0x3b, 0x80, 0x80,
            0xe4, 0xa8, 0x0d, 0x30, 0x74, 0x77, 0xd3, 0x3b, 0xbc, 0x7d, 0x37, 0x5c, 0x27, 0xe1,
            0x73, 0x04, 0x75, 0x47, 0x70, 0xd4, 0xa4, 0x62, 0xe5, 0x0a, 0x63, 0xff, 0x79, 0x2d,
            0x08, 0x96, 0x20, 0x78, 0xca, 0x87, 0x03, 0xab, 0xbd, 0x48, 0x62, 0x20, 0x50, 0x8b,
            0xe6, 0x03, 0xf8, 0xb7, 0x30, 0x6e, 0x90, 0xb1, 0x1a, 0xfc, 0x06, 0xf6, 0x74, 0x74,
            0x93, 0xfd, 0x93, 0xf1, 0xb6, 0x24, 0xe3, 0x5d
        ]
    );
}

macro_rules! decode_and_validate {
    ($input: expr) => {
        let data: &'static [u8] = $input;
        let result = Packet::decode(data).unwrap().decoded;
        assert_eq!(Ok(ValidationResult::Success), result.validate())
    };
}

#[test]
fn decode_and_validate() {
    decode_and_validate!(&[
        0x12, 0x00, 0x05, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x81, 0xac, 0x20, 0x50, 0x02,
        0x80, 0x00, 0x88, 0x01, 0x00, 0x14, 0x00, 0x36, 0x83, 0xbb, 0x43, 0x01, 0xae, 0x2c, 0xb5,
        0x30, 0xb0, 0x1c, 0x7f, 0x0b, 0x41, 0x07, 0xc7, 0xff, 0x4b, 0x83, 0xc2, 0x03, 0x43, 0x00,
        0x00, 0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0xbb, 0x43, 0x01, 0xae, 0x30, 0xb0,
        0x40, 0x5a, 0x44, 0x7e, 0x88, 0x2e, 0x62, 0x3a, 0x29, 0x60, 0x58, 0x05, 0x80, 0x00, 0x48,
        0x19, 0x8c, 0x48, 0x34, 0x30, 0xc1, 0xe5, 0x85, 0x82, 0x98, 0x8a, 0x6b, 0x34, 0x08, 0x22,
        0x03, 0xfa, 0x00, 0x29, 0x33, 0x00, 0x00, 0xab, 0xff, 0x10, 0xfc, 0xeb, 0xb1, 0x92, 0x00,
        0x3b, 0xdf, 0xf4, 0x47, 0xd4, 0x4d, 0x8c, 0x40, 0x03, 0x1e, 0xff, 0xcb, 0xbe, 0x9c, 0x0c,
        0x64, 0x80, 0x18, 0xf7, 0xfc, 0xcd, 0xf4, 0xf2, 0x63, 0x24, 0x00, 0xc7, 0xbf, 0xe5, 0x0f,
        0xa6, 0x1b, 0x18, 0x80, 0x06, 0x3d, 0xff, 0x2b, 0x7d, 0x34, 0x58, 0xc9, 0x00, 0x31, 0xef,
        0xf9, 0x8b, 0xea, 0x82, 0xc6, 0x48, 0x01, 0x8f, 0x7f, 0xc7, 0x1f, 0x4a, 0xa6, 0x33, 0x80,
        0x0d, 0xbb, 0xfe, 0x44, 0xfa, 0x63, 0xb1, 0x9c, 0x00, 0x77, 0xdf, 0xf1, 0xd7, 0xd2, 0xb9,
        0x8d, 0x30, 0x03, 0xbc, 0xc0, 0x01, 0x24, 0x00, 0x02, 0x3a, 0xfe, 0xa3, 0xc7, 0xbc, 0x88,
        0x02, 0x05, 0x80, 0x05, 0x01, 0x01, 0x7c, 0xe7, 0xf9, 0x81, 0x01, 0x01, 0x80, 0x03, 0x00,
        0x80, 0x5d, 0x5d, 0xcb, 0xee, 0xfb, 0xe7, 0xd2, 0x2d, 0x30, 0x83, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x25, 0x47, 0x9a, 0x85, 0x86, 0x00, 0x01, 0xe0, 0x01, 0x07, 0x80, 0x01, 0x24, 0x81,
        0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff,
        0x80, 0x01, 0x8c, 0x81, 0x05, 0x04, 0x02, 0xff, 0xff, 0xe0, 0x00, 0x01, 0x8d, 0x80, 0x02,
        0x02, 0x7e, 0x81, 0x02, 0x01, 0x01, 0x80, 0x02, 0x02, 0x7f, 0x81, 0x02, 0x01, 0x01, 0x00,
        0x02, 0x03, 0xff, 0x80, 0x80, 0x83, 0x91, 0x6b, 0xf8, 0xd7, 0x7f, 0x38, 0xc4, 0x19, 0xcf,
        0x66, 0x40, 0x12, 0xa2, 0x2e, 0x3e, 0x31, 0x09, 0x1a, 0x7d, 0x95, 0x3b, 0xf0, 0xac, 0xde,
        0x58, 0x18, 0x93, 0xf9, 0x49, 0x14, 0x58, 0xd5, 0x81, 0x80, 0x39, 0x3a, 0x36, 0x3e, 0x61,
        0x11, 0xf1, 0x19, 0xb3, 0x2e, 0x32, 0x01, 0x8d, 0x33, 0x09, 0x44, 0x55, 0xab, 0x5d, 0x51,
        0x9c, 0xcb, 0xd0, 0x28, 0x24, 0xde, 0x62, 0x5f, 0xd0, 0xbb, 0x1b, 0x00, 0x62, 0xef, 0xdf,
        0x4c, 0x2f, 0xbc, 0x28, 0x11, 0x6f, 0xc0, 0x71, 0x85, 0xf2, 0xdc, 0x3c, 0xf6, 0x06, 0x7d,
        0x87, 0x26, 0xff, 0x51, 0xb3, 0x53, 0x3b, 0x72, 0xe9, 0x56, 0x1d, 0xf7, 0x24, 0x1f, 0x80,
        0x82, 0xc5, 0xf4, 0x53, 0x59, 0xac, 0x2a, 0xea, 0x7e, 0x54, 0xe7, 0xeb, 0xfe, 0x78, 0x19,
        0xc4, 0xfb, 0x90, 0xf8, 0x71, 0x64, 0x9b, 0x9c, 0x47, 0xc5, 0x2d, 0x6e, 0x26, 0x28, 0x5f,
        0xc9, 0xa1, 0x9e, 0x88, 0xa9, 0xe2, 0x3f, 0xec, 0x56, 0x95, 0x67, 0x5b, 0x97, 0x1f, 0x00,
        0xc1, 0x45, 0x24, 0xae, 0x64, 0x44, 0xc2, 0x00, 0x03, 0xd3, 0xe9, 0x65, 0x19, 0x20, 0xbe,
        0xbf, 0x7f, 0x79, 0x03, 0x9a,
    ]);
    decode_and_validate!(&[
        0x12, 0x00, 0x50, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x42, 0x20, 0x50, 0x02, 0x00,
        0x00, 0x1e, 0x01, 0x00, 0x3c, 0x00, 0x00, 0xe0, 0x6a, 0x01, 0x70, 0xd0, 0x28, 0x7d, 0x18,
        0x01, 0x1c, 0x7f, 0x7b, 0xb8, 0x07, 0xd7, 0x25, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0x00, 0xc3, 0x90, 0x35, 0x18, 0x07, 0x00,
        0xfa, 0x44, 0x8c, 0x97, 0x0e, 0x64, 0x1e, 0xea, 0x7f, 0xff, 0xff, 0xfc, 0x22, 0x57, 0xb7,
        0x5e, 0x80, 0x40, 0x01, 0x24, 0x00, 0x02, 0x3a, 0xee, 0x28, 0xa5, 0xdc, 0x9d, 0x81, 0x01,
        0x01, 0x80, 0x03, 0x00, 0x80, 0xfb, 0x9f, 0xe6, 0x57, 0x1f, 0x7c, 0xe7, 0xf9, 0x10, 0x83,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x69, 0x4d, 0xff, 0x84, 0x00, 0x30, 0x01, 0x07, 0x80,
        0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff, 0xfc, 0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01,
        0xff, 0xff, 0xff, 0x80, 0x01, 0x89, 0x81, 0x03, 0x02, 0x01, 0xe0, 0x80, 0x01, 0x8a, 0x81,
        0x03, 0x02, 0x01, 0xc0, 0x80, 0x01, 0x8b, 0x81, 0x07, 0x06, 0x01, 0x64, 0x00, 0x01, 0xff,
        0xff, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x40, 0x6b, 0x81, 0x03, 0x02, 0x01, 0x80, 0x80, 0x80,
        0x82, 0x10, 0x25, 0x98, 0xe9, 0x33, 0xf0, 0xef, 0xd8, 0x04, 0x07, 0xf1, 0x4d, 0x08, 0xae,
        0x1c, 0x58, 0x27, 0x98, 0xa6, 0x4c, 0x5c, 0x6e, 0x8f, 0xe7, 0x4f, 0xa9, 0x2c, 0x20, 0x99,
        0xa8, 0x5f, 0xae, 0x80, 0x80, 0x2e, 0xc8, 0xa2, 0xe5, 0x6a, 0x76, 0x24, 0x6f, 0xe3, 0x5c,
        0xc7, 0x1a, 0xe0, 0x80, 0x5c, 0x2a, 0xcc, 0x1b, 0x83, 0x13, 0xf3, 0xa6, 0xad, 0xef, 0x84,
        0x2c, 0x8c, 0x7b, 0xfb, 0xc5, 0xd8, 0x44, 0x54, 0x50, 0x9a, 0x7e, 0xb1, 0xa6, 0x71, 0x52,
        0x5c, 0x09, 0xf2, 0xb2, 0xc9, 0x6c, 0x7e, 0x61, 0xc0, 0xb9, 0x93, 0xdc, 0xd5, 0x08, 0xcd,
        0x19, 0x1b, 0xf8, 0xe9, 0x64, 0xc9, 0x94, 0x4a, 0xc8, 0x80, 0x80, 0xf4, 0xf6, 0x8b, 0x09,
        0x8d, 0xa7, 0xd5, 0x0a, 0x87, 0x67, 0x35, 0xfc, 0x33, 0x15, 0xdb, 0x74, 0x57, 0x3c, 0xa0,
        0x45, 0xc5, 0x3e, 0xc0, 0xe0, 0x19, 0x5e, 0x2d, 0x9b, 0xdd, 0x4b, 0x61, 0xcf, 0x5e, 0x48,
        0xfa, 0xd9, 0x57, 0x59, 0xec, 0xff, 0xe7, 0xd9, 0x40, 0x52, 0x73, 0x9a, 0xf3, 0xf4, 0xbc,
        0xb0, 0x1d, 0xe6, 0x00, 0x89, 0x20, 0xe8, 0x79, 0x04, 0xbf, 0x1c, 0x80, 0xa2, 0xe6, 0xb9
    ]);
    decode_and_validate!(&[
        0x12, 0x00, 0x50, 0x01, 0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x82, 0x03, 0xef, 0x20, 0x50,
        0x00, 0x00, 0x03, 0xcb, 0x01, 0x00, 0x3c, 0x00, 0x00, 0xe0, 0x6a, 0x01, 0xa7, 0x52, 0x2c,
        0xc6, 0x79, 0xb1, 0x1c, 0x7f, 0x35, 0xe7, 0x07, 0xc9, 0x70, 0x8c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0xd4, 0x00, 0x00, 0x02, 0x04, 0x00, 0x9f, 0x26, 0x46, 0x47,
        0x2b, 0xf7, 0x01, 0x88, 0x00, 0xf0, 0x01, 0xf8, 0x20, 0x20, 0x07, 0x2b, 0xf7, 0x11, 0x68,
        0x18, 0x00, 0x14, 0x43, 0x71, 0xff, 0x41, 0xff, 0x41, 0xff, 0x47, 0x22, 0x38, 0xff, 0xf0,
        0xff, 0xf0, 0xff, 0xf3, 0x91, 0x9c, 0x82, 0x28, 0x82, 0x28, 0x82, 0x29, 0xc9, 0x0e, 0x41,
        0x32, 0x41, 0x32, 0x41, 0x32, 0xe4, 0x37, 0x21, 0xcf, 0x22, 0x56, 0x21, 0xcf, 0x18, 0x01,
        0x22, 0x1b, 0x90, 0x4c, 0x90, 0x6f, 0x90, 0x63, 0x05, 0x11, 0xc8, 0x28, 0xc8, 0x3a, 0x48,
        0x34, 0x02, 0x8c, 0xe4, 0x1d, 0x24, 0x33, 0xa4, 0x1d, 0xc2, 0x48, 0x72, 0x0f, 0x82, 0x1a,
        0xc2, 0x0f, 0xd1, 0x21, 0xb9, 0x13, 0xa1, 0x15, 0xd1, 0x15, 0x30, 0x40, 0x0d, 0x10, 0xdc,
        0x7f, 0xbc, 0x7f, 0xbc, 0x7f, 0xbd, 0xc8, 0x8e, 0x3f, 0xf2, 0x3f, 0xf2, 0x3f, 0xf2, 0xe4,
        0x67, 0x20, 0x76, 0x20, 0x76, 0x20, 0x76, 0x72, 0x43, 0x90, 0x42, 0x90, 0x42, 0x90, 0x42,
        0xb9, 0x0d, 0xc8, 0x72, 0x88, 0x8f, 0x48, 0x72, 0x86, 0x00, 0x88, 0x86, 0xe4, 0x21, 0x84,
        0x27, 0xc4, 0x21, 0x84, 0x44, 0x72, 0x11, 0x62, 0x14, 0x82, 0x11, 0x62, 0x22, 0xb9, 0x0c,
        0x49, 0x11, 0xc1, 0x0c, 0x49, 0x11, 0xdc, 0x86, 0x60, 0x89, 0x1c, 0x86, 0x60, 0x88, 0x6e,
        0x45, 0xce, 0x46, 0xa0, 0x46, 0x32, 0x10, 0x05, 0x44, 0x37, 0x21, 0x0c, 0x21, 0x3e, 0x21,
        0x0c, 0x22, 0x23, 0x90, 0x8b, 0x10, 0xa4, 0x10, 0x8b, 0x11, 0x19, 0xc8, 0x62, 0x48, 0x8e,
        0x08, 0x62, 0x48, 0x90, 0xe4, 0x33, 0x04, 0x48, 0xe4, 0x33, 0x04, 0x43, 0x72, 0x2e, 0x72,
        0x35, 0x02, 0x31, 0x90, 0x80, 0x32, 0x23, 0x38, 0xfe, 0xd8, 0xfe, 0xd8, 0xfe, 0xdb, 0x92,
        0x1c, 0x7f, 0xa8, 0x7f, 0xa8, 0x7f, 0xa9, 0xc8, 0x6e, 0x41, 0x14, 0x41, 0x14, 0x41, 0x14,
        0xe4, 0x47, 0x20, 0x94, 0x20, 0x94, 0x20, 0x94, 0x72, 0x33, 0x90, 0xdb, 0x11, 0x32, 0x90,
        0xf4, 0x08, 0x01, 0xd1, 0x15, 0xc7, 0xf4, 0x47, 0xf4, 0x47, 0xf4, 0x5c, 0x8e, 0xe3, 0xfc,
        0x03, 0xfc, 0x03, 0xfc, 0x0e, 0x43, 0x72, 0x10, 0xc2, 0x13, 0xe2, 0x10, 0xc2, 0x22, 0x39,
        0x08, 0xb1, 0x0a, 0x41, 0x08, 0xb1, 0x11, 0x5c, 0x86, 0xb0, 0x89, 0x6c, 0x86, 0xb0, 0x60,
        0x10, 0x88, 0xce, 0x3f, 0xa2, 0x3f, 0xa2, 0x3f, 0xa2, 0xe4, 0x87, 0x1f, 0xe0, 0x1f, 0xe0,
        0x1f, 0xe0, 0x72, 0x1b, 0x90, 0x86, 0x10, 0x9f, 0x10, 0x86, 0x11, 0x11, 0xc8, 0x45, 0x88,
        0x52, 0x08, 0x45, 0x88, 0x8c, 0xe4, 0x35, 0x84, 0x4b, 0x64, 0x35, 0x83, 0x00, 0x93, 0x40,
        0x72, 0x10, 0x72, 0x10, 0x72, 0x10, 0x77, 0x23, 0x39, 0x0b, 0x09, 0x10, 0x81, 0x0b, 0x08,
        0xd0, 0x1c, 0x8b, 0x88, 0x8c, 0xc8, 0x8b, 0x88, 0x68, 0xce, 0x46, 0x6e, 0x48, 0x30, 0x46,
        0xdc, 0x10, 0x0a, 0x44, 0x37, 0x1f, 0xf4, 0x1f, 0xf4, 0x1f, 0xf4, 0x72, 0x23, 0x8f, 0xff,
        0x0f, 0xff, 0x0f, 0xff, 0x39, 0x15, 0xc8, 0x22, 0x88, 0x22, 0x88, 0x22, 0x9c, 0x8e, 0xe4,
        0x13, 0x24, 0x13, 0x24, 0x13, 0x2e, 0x43, 0x72, 0x1c, 0xf2, 0x25, 0x62, 0x1c, 0xf1, 0x80,
        0x5a, 0x21, 0xb9, 0x04, 0x01, 0x04, 0x01, 0x04, 0x03, 0x91, 0x1c, 0x82, 0x28, 0x82, 0x28,
        0x82, 0x29, 0xc8, 0xce, 0x41, 0xdc, 0x41, 0xdc, 0x41, 0xdc, 0xe4, 0x87, 0x20, 0xfd, 0x20,
        0xfd, 0x20, 0xfd, 0x72, 0x1b, 0x91, 0x2d, 0x91, 0x50, 0x91, 0x46, 0x88, 0x03, 0x0d, 0x0d,
        0xc7, 0xfe, 0x47, 0xfe, 0x47, 0xfe, 0x5c, 0x8c, 0xe4, 0x0b, 0x04, 0x0b, 0x04, 0x0b, 0x0e,
        0x43, 0x72, 0x1d, 0x42, 0x22, 0x92, 0x1d, 0x41, 0xa3, 0x39, 0x11, 0x71, 0x17, 0x11, 0x11,
        0x98, 0xc0, 0x34, 0xd0, 0xdc, 0x7f, 0xe4, 0x7f, 0xe4, 0x7f, 0xe5, 0xc8, 0xce, 0x40, 0xb0,
        0x40, 0xb0, 0x40, 0xb0, 0xe4, 0x37, 0x21, 0xd4, 0x22, 0x29, 0x21, 0xd4, 0x1a, 0x33, 0x91,
        0x17, 0x11, 0x71, 0x11, 0x19, 0x8c, 0x03, 0x8d, 0x0d, 0xc8, 0x41, 0xc8, 0x41, 0xc8, 0x41,
        0xdc, 0x8c, 0xe4, 0x2e, 0x04, 0x43, 0xe4, 0x2e, 0x03, 0x43, 0x72, 0x2e, 0x22, 0x34, 0x62,
        0x2e, 0x21, 0xa3, 0x39, 0x1a, 0x31, 0x21, 0x39, 0x1b, 0xe8, 0x40, 0x3c, 0xd0, 0xdc, 0x84,
        0x1c, 0x84, 0x1c, 0x84, 0x1d, 0xc8, 0xce, 0x42, 0xe0, 0x44, 0x3e, 0x42, 0xe0, 0x34, 0x37,
        0x22, 0xe2, 0x23, 0x46, 0x22, 0xe2, 0x1a, 0x33, 0x91, 0xa3, 0x12, 0x13, 0x91, 0xbe, 0x84,
        0x04, 0x0d, 0x0d, 0xc8, 0x41, 0xc8, 0x41, 0xc8, 0x41, 0xdc, 0x8c, 0xe4, 0x2e, 0x04, 0x43,
        0xe4, 0x2e, 0x03, 0x43, 0x72, 0x2e, 0x22, 0x34, 0x62, 0x2e, 0x21, 0xa3, 0x39, 0x1a, 0x31,
        0x21, 0x39, 0x1b, 0xe8, 0x40, 0x44, 0xd0, 0xdc, 0x84, 0x1c, 0x84, 0x1c, 0x84, 0x1d, 0xc8,
        0xce, 0x42, 0xe0, 0x44, 0x3e, 0x42, 0xe0, 0x34, 0x37, 0x22, 0xe2, 0x23, 0x46, 0x22, 0xe2,
        0x1a, 0x33, 0x91, 0xa3, 0x12, 0x13, 0x91, 0xbe, 0x84, 0x04, 0x8d, 0x0d, 0xc8, 0x41, 0xc8,
        0x41, 0xc8, 0x41, 0xdc, 0x8c, 0xe4, 0x2e, 0x04, 0x43, 0xe4, 0x2e, 0x03, 0x43, 0x72, 0x2e,
        0x22, 0x34, 0x62, 0x2e, 0x21, 0xa3, 0x39, 0x1a, 0x31, 0x21, 0x39, 0x1b, 0xe8, 0x40, 0x4c,
        0xd0, 0xdc, 0x84, 0x1c, 0x84, 0x1c, 0x84, 0x1d, 0xc8, 0xce, 0x42, 0xe0, 0x44, 0x3e, 0x42,
        0xe0, 0x34, 0x37, 0x22, 0xe2, 0x23, 0x46, 0x22, 0xe2, 0x1a, 0x33, 0x91, 0xa3, 0x12, 0x13,
        0x91, 0xbe, 0x84, 0x05, 0x0d, 0x0d, 0xc8, 0x41, 0xc8, 0x41, 0xc8, 0x41, 0xdc, 0x8c, 0xe4,
        0x2e, 0x04, 0x43, 0xe4, 0x2e, 0x03, 0x43, 0x72, 0x2e, 0x22, 0x34, 0x62, 0x2e, 0x21, 0xa3,
        0x39, 0x1a, 0x31, 0x21, 0x39, 0x1b, 0xe8, 0x40, 0x54, 0xd0, 0xdc, 0x84, 0x1c, 0x84, 0x1c,
        0x84, 0x1d, 0xc8, 0xce, 0x42, 0xe0, 0x44, 0x3e, 0x42, 0xe0, 0x34, 0x37, 0x22, 0xe2, 0x23,
        0x46, 0x22, 0xe2, 0x1a, 0x33, 0x91, 0xa3, 0x12, 0x13, 0x91, 0xbe, 0x84, 0x05, 0x8d, 0x0d,
        0xc7, 0xfb, 0xc7, 0xfb, 0xc7, 0xfb, 0xdc, 0x8c, 0xe4, 0x0b, 0x04, 0x0b, 0x04, 0x0b, 0x0e,
        0x43, 0x72, 0x1c, 0xa2, 0x22, 0x92, 0x1c, 0xa1, 0xa3, 0x39, 0x11, 0x71, 0x17, 0x11, 0x11,
        0x98, 0xc0, 0x5c, 0xd0, 0xdc, 0x7f, 0xbc, 0x7f, 0xbc, 0x7f, 0xbd, 0xc8, 0xce, 0x40, 0xb0,
        0x40, 0xb0, 0x40, 0xb0, 0xe4, 0x37, 0x21, 0xca, 0x22, 0x29, 0x21, 0xca, 0x1a, 0x33, 0x91,
        0x17, 0x11, 0x71, 0x11, 0x19, 0x8c, 0x06, 0x0d, 0x0d, 0xc7, 0xfe, 0x47, 0xfe, 0x47, 0xfe,
        0x5c, 0x8c, 0xe4, 0x0b, 0x04, 0x0b, 0x04, 0x0b, 0x0e, 0x43, 0x72, 0x1d, 0x42, 0x22, 0x92,
        0x1d, 0x41, 0xa3, 0x39, 0x11, 0x71, 0x17, 0x11, 0x11, 0x98, 0xc0, 0x64, 0xd0, 0xdc, 0x7f,
        0xe4, 0x7f, 0xe4, 0x7f, 0xe5, 0xc8, 0xce, 0x40, 0xb0, 0x40, 0xb0, 0x40, 0xb0, 0xe4, 0x37,
        0x21, 0xd4, 0x22, 0x29, 0x21, 0xd4, 0x1a, 0x33, 0x91, 0x17, 0x11, 0x71, 0x11, 0x19, 0x8c,
        0x50, 0x01, 0x89, 0x00, 0x02, 0x3a, 0xfe, 0xe7, 0x4c, 0x43, 0x3f, 0x1c, 0x7f, 0x35, 0xe7,
        0x07, 0xc9, 0x70, 0x8c, 0x00, 0x00, 0x81, 0x01, 0x01, 0x80, 0x03, 0x00, 0x80, 0xfb, 0x9f,
        0xe6, 0x57, 0x1f, 0x7c, 0xe7, 0xf9, 0x10, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x6a,
        0xf6, 0x1e, 0x84, 0x00, 0xa8, 0x01, 0x07, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01, 0xff,
        0xfc, 0x80, 0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xff, 0xff, 0x80, 0x01, 0x89, 0x81,
        0x03, 0x02, 0x01, 0xe0, 0x80, 0x01, 0x8a, 0x81, 0x03, 0x02, 0x01, 0xc0, 0x80, 0x01, 0x8b,
        0x81, 0x07, 0x06, 0x01, 0x64, 0x00, 0x01, 0xff, 0xff, 0x00, 0x01, 0x8d, 0x80, 0x02, 0x40,
        0x6b, 0x81, 0x03, 0x02, 0x01, 0x80, 0x80, 0x80, 0x82, 0x14, 0x5c, 0x4d, 0xf5, 0xb8, 0xec,
        0xa4, 0x38, 0x3a, 0x63, 0x0b, 0x38, 0xc9, 0x58, 0x48, 0x71, 0xd0, 0x6f, 0x6d, 0x57, 0x52,
        0x18, 0xc1, 0x4a, 0x40, 0x75, 0x75, 0xd6, 0x62, 0xb8, 0xe8, 0x23, 0x80, 0x80, 0x28, 0x61,
        0x54, 0x48, 0xa3, 0x85, 0xc2, 0x7b, 0xf4, 0x1d, 0x51, 0xf2, 0xad, 0x5d, 0x94, 0x99, 0x78,
        0x84, 0x49, 0x0d, 0xd0, 0xd1, 0x6f, 0x8a, 0x01, 0xc0, 0xdd, 0x8f, 0x3a, 0xf1, 0x03, 0x22,
        0xa4, 0x6f, 0x52, 0x67, 0x03, 0x01, 0x39, 0xec, 0x84, 0x78, 0x89, 0x54, 0xac, 0xe9, 0xcd,
        0x0d, 0x4c, 0x4e, 0xc0, 0x3f, 0x2a, 0xa0, 0xee, 0x54, 0xc1, 0xe2, 0xd2, 0xe6, 0x5d, 0x59,
        0x7f, 0x23, 0x80, 0x80, 0x20, 0x86, 0xa7, 0x6d, 0xd1, 0x89, 0xaa, 0xc7, 0xc6, 0xc4, 0xc9,
        0xfe, 0xb5, 0x62, 0xd1, 0x37, 0x3f, 0x95, 0x55, 0xab, 0x6c, 0x26, 0xb7, 0x97, 0x91, 0x5f,
        0xe4, 0x57, 0xda, 0x8b, 0x15, 0x88, 0x04, 0x7e, 0xe6, 0xd2, 0x0a, 0x2b, 0x3a, 0xa5, 0xbd,
        0x81, 0xb3, 0xb3, 0xfe, 0xc3, 0xc3, 0xa9, 0x15, 0x1c, 0xc2, 0x11, 0xa9, 0x1b, 0x6c, 0x7f,
        0x58, 0x4e, 0xe0, 0xd5, 0x3a, 0x11, 0xfb, 0xab
    ]);
}
