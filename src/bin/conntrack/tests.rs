use std::net::IpAddr;

use crate::{
    ConntrackAttribute, IPTuple, NetfilterMessage, Nfgenmsg, ProtoInfo, ProtoInfoTCP, ProtoTuple,
    Tuple,
};
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage};

#[test]
fn test_dump_conntrack() {
    // I got this from wireshark
    let raw: Vec<u8> = vec![
        0x14, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x03, 0xb9, 0x80, 0xc2, 0x68, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let conntrack_get_message = NetfilterMessage::ConntrackGet {
        header: (Nfgenmsg {
            nfgen_family: 0,
            version: 0,
            resource_id: 0,
        }),
        nlas: vec![],
    };

    let mut packet = NetlinkMessage::from(conntrack_get_message);

    packet.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    packet.header.sequence_number = 1757577401;

    // `finalize()` calculates the total packet length and sets the message type
    // in the header based on our `NetlinkSerializable` implementation.
    packet.finalize();

    println!("Original Packet: {:#?}", packet);

    // Serialize the packet into a byte buffer.
    let mut buf = vec![0; packet.buffer_len()];
    packet.serialize(&mut buf);

    println!("\nSerialized Bytes: {:?}", buf);

    let deserialized_packet = NetlinkMessage::<NetfilterMessage>::deserialize(&buf).unwrap();

    // Verify that the round trip was successful.
    assert_eq!(packet, deserialized_packet);

    // Now verify the library made packet against the deserialized raw packet (wireshark dump of conntrack -L)
    let deserialized_raw = NetlinkMessage::<NetfilterMessage>::deserialize(&raw).unwrap();
    assert_eq!(packet, deserialized_raw);
}

#[test]
fn test_get_conntrack() {
    // I got this from wireshark
    let raw: Vec<u8> = vec![
        0x60, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x92, 0xe5, 0xcf, 0x68, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x80, 0x14, 0x00, 0x01, 0x80, 0x08, 0x00,
        0x01, 0x00, 0x0a, 0x39, 0x61, 0x7c, 0x08, 0x00, 0x02, 0x00, 0x94, 0x71, 0x14, 0x69, 0x1c,
        0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x9a, 0xb0, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x18, 0x00, 0x04,
        0x80, 0x14, 0x00, 0x01, 0x80, 0x06, 0x00, 0x04, 0x00, 0x0a, 0x0a, 0x00, 0x00, 0x06, 0x00,
        0x05, 0x00, 0x0a, 0x0a, 0x00, 0x00,
    ];

    let src_addr = IPTuple::SourceAddress(IpAddr::V4("10.57.97.124".parse().unwrap()));
    let dst_addr = IPTuple::DestinationAddress(IpAddr::V4("148.113.20.105".parse().unwrap()));

    let proto_num = ProtoTuple::Protocol(6);
    let src_port = ProtoTuple::SourcePort(45210);
    let dst_port = ProtoTuple::DestinationPort(47873);

    let ip_tuple = Tuple::Ip(vec![src_addr, dst_addr]);
    let proto_tuple = Tuple::Proto(vec![proto_num, src_port, dst_port]);

    let proto_info = ProtoInfo::TCP(vec![
        ProtoInfoTCP::OriginalFlags(2570),
        ProtoInfoTCP::ReplyFlags(2570),
    ]);

    let nlas = vec![
        ConntrackAttribute::CtaTupleOrig(vec![ip_tuple, proto_tuple]),
        ConntrackAttribute::CtaProtoInfo(vec![proto_info]),
    ];

    let conntrack_get_message = NetfilterMessage::ConntrackGet {
        header: (Nfgenmsg {
            nfgen_family: 2,
            version: 0,
            resource_id: 0,
        }),
        nlas,
    };
    let mut packet = NetlinkMessage::from(conntrack_get_message);

    packet.header.flags = netlink_packet_core::NLM_F_REQUEST;
    packet.header.sequence_number = 1758455186;

    // `finalize()` calculates the total packet length and sets the message type
    // in the header based on our `NetlinkSerializable` implementation.
    packet.finalize();

    println!("Original Packet: {:#?}", packet);

    // Serialize the packet into a byte buffer.
    let mut buf = vec![0; packet.buffer_len()];
    packet.serialize(&mut buf);

    println!("\nSerialized Bytes: {:?}", buf);

    let deserialized_packet = NetlinkMessage::<NetfilterMessage>::deserialize(&buf).unwrap();
    // Verify that the round trip was successful.
    assert_eq!(packet, deserialized_packet);

    // Now verify the library made packet against the deserialized raw packet (wireshark dump of conntrack -G)
    let deserialized_raw = NetlinkMessage::<NetfilterMessage>::deserialize(&raw).unwrap();
    assert_eq!(packet, deserialized_raw);
}
