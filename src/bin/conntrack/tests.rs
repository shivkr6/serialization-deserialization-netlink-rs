use crate::{NetfilterMessage, Nfgenmsg};
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
