#[test]
fn secured_round_trip() {
    // CAM with full cert
    {
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
        // let encoded = decoded.decoded.encode_to_vec().unwrap();
        // assert_eq!(data, &encoded)

        // let packet = Packet::Secured {
        //     basic: BasicHeader {
        //         version: 1,
        //         next_header: NextAfterBasic::SecuredPacket,
        //         reserved: 0,
        //         lifetime: Lifetime(5),
        //         remaining_hop_limit: 1,
        //     },
        //     secured: Ieee1609Dot2Data {
        //         protocol_version: Uint8(3),
        //         content: crate::Ieee1609Dot2Content::SignedData(Box::new(SignedData {
        //             hash_id: crate::HashAlgorithm::Sha256,
        //             tbs_data: crate::ToBeSignedData {
        //                 payload: SignedDataPayload {
        //                     data: Some(Ieee1609Dot2Data {
        //                         protocol_version: Uint8(3),
        //                         content: crate::Ieee1609Dot2Content::UnsecuredData(Opaque(&[
        //                             32, 80, 2, 128, 0, 48, 1, 0, 20, 0, 6, 66, 126, 117, 69, 35,
        //                             48, 62, 190, 208, 31, 243, 73, 104, 5, 250, 153, 73, 128, 12,
        //                             2, 32, 0, 0, 0, 0, 7, 209, 0, 0, 2, 2, 126, 117, 69, 35, 190,
        //                             208, 0, 90, 179, 6, 77, 14, 40, 141, 105, 38, 174, 106, 224, 0,
        //                             52, 45, 146, 72, 34, 15, 160, 0, 152, 191, 233, 234, 111, 51,
        //                             255, 1, 255, 250, 0, 40, 51, 0,
        //                         ])),
        //                     }),
        //                     ext_data_hash: None,
        //                     omitted: None,
        //                 },
        //                 header_info: HeaderInfo {
        //                     psid: Psid(36),
        //                     generation_time: Some(Uint64(696594120508870)),
        //                     expiry_time: None,
        //                     generation_location: None,
        //                     p2pcd_learning_request: None,
        //                     missing_crl_identifier: None,
        //                     encryption_key: None,
        //                     inline_p2pcd_request: None,
        //                     requested_certificate: None,
        //                     pdu_functional_type: None,
        //                     contributed_extensions: None,
        //                 },
        //                 // raw: [
        //                 //     64, 3, 128, 84, 32, 80, 2, 128, 0, 48, 1, 0, 20, 0, 6, 66, 126, 117,
        //                 //     69, 35, 48, 62, 190, 208, 31, 243, 73, 104, 5, 250, 153, 73, 128, 12,
        //                 //     2, 32, 0, 0, 0, 0, 7, 209, 0, 0, 2, 2, 126, 117, 69, 35, 190, 208, 0,
        //                 //     90, 179, 6, 77, 14, 40, 141, 105, 38, 174, 106, 224, 0, 52, 45, 146,
        //                 //     72, 34, 15, 160, 0, 152, 191, 233, 234, 111, 51, 255, 1, 255, 250, 0,
        //                 //     40, 51, 0, 64, 1, 36, 0, 2, 121, 140, 117, 27, 5, 198,
        //                 // ],
        //             },
        //             signer: crate::SignerIdentifier::Digest(HashedId8(&[
        //                 231, 63, 7, 66, 126, 117, 69, 35,
        //             ])),
        //             signature: crate::Signature::EcdsaNistP256Signature(EcdsaP256Signature {
        //                 r_sig: crate::EccP256CurvePoint::CompressedY1(&[
        //                     111, 196, 169, 79, 176, 224, 29, 215, 102, 195, 40, 29, 253, 56, 6, 85,
        //                     168, 76, 196, 70, 200, 123, 51, 117, 109, 86, 252, 38, 8, 107, 85, 21,
        //                 ]),
        //                 s_sig: &[
        //                     172, 35, 139, 254, 209, 112, 33, 113, 110, 108, 149, 124, 110, 247,
        //                     181, 161, 95, 110, 137, 36, 252, 33, 110, 212, 143, 194, 154, 81, 148,
        //                     186, 208, 127,
        //                 ],
        //             }),
        //         })),
        //     },
        //     common: CommonHeader {
        //         next_header: crate::NextAfterCommon::BTPB,
        //         reserved_1: arbitrary_int::u4::from_u8(0),
        //         header_type_and_subtype: crate::HeaderType::TopologicallyScopedBroadcast(
        //             crate::BroadcastType::SingleHop,
        //         ),
        //         traffic_class: TrafficClass {
        //             store_carry_forward: false,
        //             channel_offload: false,
        //             traffic_class_id: 2,
        //         },
        //         flags: [true, false, false, false, false, false, false, false],
        //         payload_length: 48,
        //         maximum_hop_limit: 1,
        //         reserved_2: 0,
        //     },
        //     extended: Some(ExtendedHeader::SHB(SingleHopBroadcast {
        //         source_position_vector: LongPositionVector {
        //             gn_address: Address {
        //                 manually_configured: false,
        //                 station_type: crate::StationType::PassengerCar,
        //                 reserved: arbitrary_int::u10::from_u16(0),
        //                 address: [6, 66, 126, 117, 69, 35],
        //             },
        //             timestamp: Timestamp(809418448),
        //             latitude: 536037736,
        //             longitude: 100309321,
        //             position_accuracy: true,
        //             speed: 12,
        //             heading: 544,
        //         },
        //         media_dependent_data: [0, 0, 0, 0],
        //     })),
        // };

        // let encoded = packet.encode_to_vec().unwrap();
        // let decoded = Packet::decode(encoded.as_slice()).unwrap();
    }

    // CAM with full digest
    {
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

        // let decoded = Packet::decode(expected.as_slice()).unwrap();
        // println!("TODO: {decoded:?}");

        let decoded = Packet::decode(data).unwrap();
        // let encoded = decoded.decoded.encode_to_vec().unwrap();
        // assert_eq!(data, &encoded)

        // TODO: validate signature!
    }

    // YUNEX message
    {
        let data = "12001a02038100400380742040010000400200339f00003c00005056a2425e1680b8271c0e3f530930e52f800000001c0e5f5a0930dcf103e800000000000007d207d2020100009c3fc3000000008a321442d01704e510b405c13d1b3485a747aaef1ffffffe11dbba1f400f01e200400004800060001c73877fda083bc73850012500027927d8b339381c0e3f530930e52f100081010180030080fb9fe6571f7ce7f910830000000000297714d98400a8010280012581050401ffffff80018b81070601c04001fff8808182379e9625d2ddb44ae300f17c1c34b9afb691248a2decf4721f496e470e9886478080d7a0add885ffae3276dbed6b905d8d72bef3716bc3f983c665ffda8d16ba472ddf46a738a4d46ddb24acada60890d85bf75bf1c9e806592cfb71c623c4d98b2f81809e35a51638c0be4d457ecf50344bfe89ef37100438ec3360778647b1e59d9bc62ce3b82a24fd39ee04ac90e219996aa13700570c7c60c73072de3dc79ab73260";
        // TODO: hex to bin

        // hex

        // decoded.validate()
    }
}
