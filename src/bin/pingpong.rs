use netlink_packet_core::{
    Emitable, NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NetlinkSerializable, Nla, NlaBuffer, Parseable,
};
use std::error::Error;
use std::fmt;
use std::mem::size_of;
// PingPongMessage represent the messages for the "ping-pong" netlink
// protocol. There are only two types of messages.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PingPongMessage {
    Ping(PingPongAttribute),
    Pong(PingPongAttribute),
}

// The netlink header contains a "message type" field that identifies
// the message it carries. Some values are reserved, and we
// arbitrarily decided that "ping" type is 18 and "pong" type is 20.
pub const PING_MESSAGE: u16 = 18;
pub const PONG_MESSAGE: u16 = 20;

// Types for the netlink attributes
const PING_PONG_ATTR_MSG: u16 = 1;
const PING_PONG_ATTR_COOKIE: u16 = 2;

// PingPongAttribute represents the attributes for the "ping-pong" netlink
// protocol. There are only two types of attributes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PingPongAttribute {
    Message(String),
    Cookie(u32),
}
// In order to be used as NLAs, our enum needs to implement two traits from
// netlink-packet-core: `Nla` for serialization and `Parseable` for deserialization.
impl Nla for PingPongAttribute {
    // length
    fn value_len(&self) -> usize {
        match self {
            PingPongAttribute::Message(s) => s.len() + 1, // +1 for null terminator
            PingPongAttribute::Cookie(_) => size_of::<u32>(),
        }
    }
    // type
    fn kind(&self) -> u16 {
        match self {
            PingPongAttribute::Message(_) => PING_PONG_ATTR_MSG,
            PingPongAttribute::Cookie(_) => PING_PONG_ATTR_COOKIE,
        }
    }
    // value
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            PingPongAttribute::Message(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PingPongAttribute::Cookie(n) => buffer.copy_from_slice(&n.to_ne_bytes()),
        }
    }
}

// trait for turning a Nla from bytes into a struct
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for PingPongAttribute {
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> std::result::Result<Self, netlink_packet_core::DecodeError> {
        // NlaBuffer type provides these methods on it! wow
        let payload = buf.value();
        match buf.kind() {
            PING_PONG_ATTR_MSG => {
                // The payload is a null-terminated string. We trim the null byte
                // before converting to a String.
                let s = payload
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| &payload[..p])
                    .unwrap_or(payload);
                Ok(PingPongAttribute::Message(String::from_utf8(s.to_vec())?))
            }
            PING_PONG_ATTR_COOKIE => {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(payload);

                Ok(PingPongAttribute::Cookie(u32::from_ne_bytes(bytes)))
            }
            _ => Err("Unknown attribute type".into()),
        }
    }
}

// A custom error type for when deserialization fails. This is
// required because `NetlinkDeserializable::Error` must implement
// `std::error::Error`, so a simple `String` won't cut it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeserializeError(&'static str);

impl Error for DeserializeError {
    fn description(&self) -> &str {
        self.0
    }
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// NetlinkDeserializable implementation
impl NetlinkDeserializable for PingPongMessage {
    type Error = DeserializeError;

    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> std::result::Result<Self, Self::Error> {
        // get a nla buffer from the payload
        let nla_buffer = NlaBuffer::new_checked(payload)
            .map_err(|_| DeserializeError("Invalid NLA format in payload"))?;
        // parse the attributes from the nla buffer using the parse methods previously defined for nlas
        let attributes = PingPongAttribute::parse(&nla_buffer)
            .map_err(|_| DeserializeError("Failed to parse attributes"))?;

        match header.message_type {
            PING_MESSAGE => Ok(PingPongMessage::Ping(attributes)),

            PONG_MESSAGE => Ok(PingPongMessage::Pong(attributes)),
            _ => Err(DeserializeError(
                "invalid ping-pong message: invalid message type",
            )),
        }
    }
}

// NetlinkSerializable implementation
impl NetlinkSerializable for PingPongMessage {
    fn message_type(&self) -> u16 {
        match self {
            PingPongMessage::Ping(_) => PING_MESSAGE,
            PingPongMessage::Pong(_) => PONG_MESSAGE,
        }
    }

    fn buffer_len(&self) -> usize {
        match self {
            PingPongMessage::Ping(attr) | PingPongMessage::Pong(attr) => attr.buffer_len(),
        }
    }

    fn serialize(&self, buffer: &mut [u8]) {
        match self {
            PingPongMessage::Ping(attr) | PingPongMessage::Pong(attr) => {
                attr.emit(buffer);
            }
        }
    }
}

// It can be convenient to be able to create a NetlinkMessage directly
// from a PingPongMessage. Since NetlinkMessage<T> already implements
// From<NetlinkPayload<T>>, we just need to implement
// From<NetlinkPayload<PingPongMessage>> for this to work.
impl From<PingPongMessage> for NetlinkPayload<PingPongMessage> {
    fn from(message: PingPongMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

fn main() {
    let ping_pong_message = PingPongMessage::Ping(PingPongAttribute::Cookie(129));
    let mut packet = NetlinkMessage::from(ping_pong_message);

    // Before serializing the packet, it is very important to call
    // finalize() to ensure the header of the message is consistent
    // with its payload. Otherwise, a panic may occur when calling
    // `serialize()`
    packet.finalize();

    // Prepare a buffer to serialize the packet. Note that we never
    // set explicitely `packet.header.length` above. This was done
    // automatically when we called `finalize()`
    let mut buf = vec![0; packet.header.length as usize];
    // Serialize the packet
    packet.serialize(&mut buf[..]);

    // Deserialize the packet
    let deserialized_packet = NetlinkMessage::<PingPongMessage>::deserialize(&buf)
        .expect("Failed to deserialize message");

    // Normally, the packet deserialized from the buffer should be exactly the same
    // as the original packet we serialized.
    assert_eq!(deserialized_packet, packet);

    // This should print:
    // NetlinkMessage { header: NetlinkHeader { length: 20, message_type: 18, flags: 0, sequence_number: 0, port_number: 0 }, payload: InnerMessage(Ping([0, 1, 2, 3])) }

    // In case of structure, I think we only need to mess around with the payload structure because the structure of NetlinkHeader is going to be the same for every netlink message.
    println!("{:?}", packet);
}
