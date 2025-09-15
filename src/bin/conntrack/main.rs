use netlink_packet_core::{
    DecodeError, Emitable, NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NetlinkSerializable, Parseable, buffer, fields, getter, setter,
};

const NFGENMSG_LEN: usize = 4;

// We use the `buffer!` macro to create a safe, zero-copy wrapper around a byte slice.
// It automatically generates getter and setter methods for the fields we define.
buffer!(NfgenmsgBuffer(NFGENMSG_LEN) {
    nfgen_family: (u8, 0),
    version: (u8, 1),
    resource_id: (u16, 2..4),
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nfgenmsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub resource_id: u16,
}

// Implement `Emitable` to define how to write `Nfgenmsg` to a byte buffer.
impl Emitable for Nfgenmsg {
    fn buffer_len(&self) -> usize {
        NFGENMSG_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buf = NfgenmsgBuffer::new(buffer);
        buf.set_nfgen_family(self.nfgen_family);
        buf.set_version(self.version);
        buf.set_resource_id(self.resource_id);
    }
}

// Implement `Parseable` to define how to read `BvgGenMsg` from a byte buffer.
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NfgenmsgBuffer<&'a T>> for Nfgenmsg {
    fn parse(buf: &NfgenmsgBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Nfgenmsg {
            nfgen_family: buf.nfgen_family(),
            version: buf.version(),
            resource_id: buf.resource_id(),
        })
    }
}

// Top level message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetfilterMessage {
    ConntrackGet { header: Nfgenmsg },
}

pub const NFNL_SUBSYS_CTNETLINK: u16 = 1;
pub const IPCTNL_MSG_CT_GET: u16 = 1;
pub const NETFILTER_CONNTRACK_GET_MESSAGE_TYPE: u16 =
    NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_GET;

// for serializing
impl NetlinkSerializable for NetfilterMessage {
    fn message_type(&self) -> u16 {
        match self {
            Self::ConntrackGet { .. } => NETFILTER_CONNTRACK_GET_MESSAGE_TYPE,
        }
    }

    fn buffer_len(&self) -> usize {
        NFGENMSG_LEN
    }

    fn serialize(&self, buffer: &mut [u8]) {
        let nfgenmsg_hdr = match self {
            Self::ConntrackGet { header } => header,
        };

        // Emit the fixed-size protocol header.
        nfgenmsg_hdr.emit(&mut buffer[..NFGENMSG_LEN]);
    }
}

// for deserializing the message
impl NetlinkDeserializable for NetfilterMessage {
    type Error = DecodeError;

    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        // First, check if the payload is long enough for our generic header.
        if payload.len() < NFGENMSG_LEN {
            return Err(DecodeError::from(
                "Payload is too short for NFGENMSG header",
            ));
        }

        // Parse our fixed-size header from the start of the payload.
        let nfgen_msg_buf = NfgenmsgBuffer::new(&payload[..NFGENMSG_LEN]);
        let nfgen_header = Nfgenmsg::parse(&nfgen_msg_buf)?;

        // We use the main `nlmsghdr.message_type` to decide which enum variant
        // to construct. This is the counterpart to `message_type()` in the
        // `NetlinkSerializable` impl.
        match header.message_type {
            NETFILTER_CONNTRACK_GET_MESSAGE_TYPE => Ok(Self::ConntrackGet {
                header: nfgen_header,
            }),
            _ => Err(DecodeError::from(format!(
                "Unknown message type for Beverage protocol: {}",
                header.message_type
            ))),
        }
    }
}

// to do stuff like `NetlinkMessage::from(my_beverage_message)`.
impl From<NetfilterMessage> for NetlinkPayload<NetfilterMessage> {
    fn from(message: NetfilterMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

fn main() {
    let conntrack_get_message = NetfilterMessage::ConntrackGet {
        header: (Nfgenmsg {
            nfgen_family: 0,
            version: 0,
            resource_id: 0,
        }),
    };

    let mut packet = NetlinkMessage::from(conntrack_get_message);

    packet.header.flags = netlink_packet_core::NLM_F_REQUEST | netlink_packet_core::NLM_F_DUMP;
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
}
#[cfg(test)]
mod tests;
