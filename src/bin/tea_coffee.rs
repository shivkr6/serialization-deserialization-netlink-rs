// We're creating a fictional "beverage" protocol
// Tea and coffee example:
// - They will only have a single message called `Beverage` with a header `BvgGenMsg`.
//     1) `BeverageMessage` will have two variants:`tea` or `coffee`.
//     2) `BvgGenFamily` should be `hot` or `cold`.
//   Flags could be:
//     1) `NLM_F_SPILL` // We could spill our drink
//     2) `NLM_F_SERVE` // We could serve our drink
//     3) `NLM_F_DRINK` // We could drink our drink
//     4) `NLM_F_WASH` // We could wash our hands with the drink
// - They will have attributes. Some examples of attributes could be:
//     1) `CAFFENE_CONTENT(u32)`
//     2) `HOTNESS(u32)`
//     3) `PERSON_NAME(String)`

use core::fmt;
use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NetlinkDeserializable, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, NetlinkSerializable, Nla, NlaBuffer, NlasIterator, Parseable, buffer, emit_u32,
    fields, getter, parse_string, parse_u32, setter,
};
use std::mem::size_of;

// These are our main message types, which will go into `nlmsghdr.message_type`.
pub const TEA_MESSAGE_TYPE: u16 = 0x13;
pub const COFFEE_MESSAGE_TYPE: u16 = 0x14;

// Custom flags that can be added to `nlmsghdr.flags`.
pub const NLM_F_SPILL: u16 = 1 << 8;
pub const NLM_F_SERVE: u16 = 1 << 9;
pub const NLM_F_DRINK: u16 = 1 << 10;
pub const NLM_F_WASH: u16 = 1 << 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BvgGenFamily {
    Hot = 2,
    Cold = 10,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BvgParseError {
    invalid_value: u8,
}
impl fmt::Display for BvgParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "failed to parse BvgGenFamily: '{}' is not a valid value",
            self.invalid_value
        )
    }
}
impl std::error::Error for BvgParseError {}
impl TryFrom<u8> for BvgGenFamily {
    type Error = BvgParseError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            2 => Ok(BvgGenFamily::Hot),
            10 => Ok(BvgGenFamily::Cold),
            unknown_value => Err(BvgParseError {
                invalid_value: unknown_value,
            }),
        }
    }
}

// Protocol-Specific Generic Header `bvggenmsg`

const BVG_GEN_MSG_LEN: usize = 4;

// We use the `buffer!` macro to create a safe, zero-copy wrapper around a byte slice.
// It automatically generates getter and setter methods for the fields we define.
buffer!(BvgGenMsgBuffer(BVG_GEN_MSG_LEN) {
    family: (u8, 0),
    version: (u8, 1),
    resource_id: (u16, 2..4),
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BvgGenMsg {
    pub family: BvgGenFamily,
    pub version: u8,
    pub resource_id: u16,
}

// Implement `Emitable` to define how to write `BvgGenMsg` to a byte buffer.
impl Emitable for BvgGenMsg {
    fn buffer_len(&self) -> usize {
        BVG_GEN_MSG_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buf = BvgGenMsgBuffer::new(buffer);
        buf.set_family(self.family as u8);
        buf.set_version(self.version);
        buf.set_resource_id(self.resource_id);
    }
}

// Implement `Parseable` to define how to read `BvgGenMsg` from a byte buffer.
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<BvgGenMsgBuffer<&'a T>> for BvgGenMsg {
    fn parse(buf: &BvgGenMsgBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(BvgGenMsg {
            family: buf.family().try_into().unwrap(),
            version: buf.version(),
            resource_id: buf.resource_id(),
        })
    }
}

// Netlink Attributes
const BVG_ATTR_CAFFEINE_CONTENT: u16 = 1;
const BVG_ATTR_HOTNESS: u16 = 2;
const BVG_ATTR_PERSON_NAME: u16 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeverageAttribute {
    CaffeineContent(u32),
    Hotness(u32),
    PersonName(String),
}

// for serializiation of NLAs
impl Nla for BeverageAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::CaffeineContent(_) | Self::Hotness(_) => size_of::<u32>(),
            // Strings in netlink are typically null-terminated. We must
            // account for the extra byte.
            Self::PersonName(s) => s.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::CaffeineContent(_) => BVG_ATTR_CAFFEINE_CONTENT,
            Self::Hotness(_) => BVG_ATTR_HOTNESS,
            Self::PersonName(_) => BVG_ATTR_PERSON_NAME,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::CaffeineContent(v) | Self::Hotness(v) => emit_u32(buffer, *v).unwrap(),
            Self::PersonName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                // Don't forget the null terminator
                buffer[s.len()] = 0;
            }
        }
    }
}

// for deserialization of the NLAs
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for BeverageAttribute {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        match buf.kind() {
            BVG_ATTR_CAFFEINE_CONTENT => {
                let value = parse_u32(payload).context("invalid u32 for CaffeineContent")?;
                Ok(Self::CaffeineContent(value))
            }
            BVG_ATTR_HOTNESS => {
                let value = parse_u32(payload).context("invalid u32 for Hotness")?;
                Ok(Self::Hotness(value))
            }
            BVG_ATTR_PERSON_NAME => {
                let value = parse_string(payload).context("invalid string for PersonName")?;
                Ok(Self::PersonName(value))
            }
            kind => Err(DecodeError::from(format!(
                "Unknown NLA kind for BeverageAttribute: {}",
                kind
            ))),
        }
    }
}

// Top level message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeverageMessage {
    Tea {
        header: BvgGenMsg,
        nlas: Vec<BeverageAttribute>,
    },
    Coffee {
        header: BvgGenMsg,
        nlas: Vec<BeverageAttribute>,
    },
}

// for serializing
impl NetlinkSerializable for BeverageMessage {
    fn message_type(&self) -> u16 {
        match self {
            Self::Tea { .. } => TEA_MESSAGE_TYPE,
            Self::Coffee { .. } => COFFEE_MESSAGE_TYPE,
        }
    }

    fn buffer_len(&self) -> usize {
        let nlas_len = match self {
            Self::Tea { nlas, .. } => nlas.as_slice().buffer_len(),
            Self::Coffee { nlas, .. } => nlas.as_slice().buffer_len(),
        };
        BVG_GEN_MSG_LEN + nlas_len
    }

    fn serialize(&self, buffer: &mut [u8]) {
        let (header, nlas) = match self {
            Self::Tea { header, nlas } => (header, nlas),
            Self::Coffee { header, nlas } => (header, nlas),
        };

        // First, emit the fixed-size protocol header.
        header.emit(&mut buffer[..BVG_GEN_MSG_LEN]);

        // Then, emit all the NLAs right after it. The `Emitable` impl for
        // `&[T: Nla]` handles iterating and writing them correctly.
        nlas.as_slice().emit(&mut buffer[BVG_GEN_MSG_LEN..]);
    }
}

// for deserializing the message
impl NetlinkDeserializable for BeverageMessage {
    type Error = DecodeError;

    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        // First, check if the payload is long enough for our generic header.
        if payload.len() < BVG_GEN_MSG_LEN {
            return Err(DecodeError::from(
                "Payload is too short for BvgGenMsg header",
            ));
        }

        // Parse our fixed-size header from the start of the payload.
        let gen_msg_buf = BvgGenMsgBuffer::new(&payload[..BVG_GEN_MSG_LEN]);
        let gen_header = BvgGenMsg::parse(&gen_msg_buf)?;

        // The rest of the payload contains the NLAs.
        let nla_payload = &payload[BVG_GEN_MSG_LEN..];
        let mut nlas = Vec::new();
        for nla_buf in NlasIterator::new(nla_payload) {
            let nla_buf = nla_buf.context("Failed to iterate over beverage attributes")?;
            let parsed_nla =
                BeverageAttribute::parse(&nla_buf).context("Failed to parse beverage attribute")?;
            nlas.push(parsed_nla);
        }

        // We use the main `nlmsghdr.message_type` to decide which enum variant
        // to construct. This is the counterpart to `message_type()` in the
        // `NetlinkSerializable` impl.
        match header.message_type {
            TEA_MESSAGE_TYPE => Ok(Self::Tea {
                header: gen_header,
                nlas,
            }),
            COFFEE_MESSAGE_TYPE => Ok(Self::Coffee {
                header: gen_header,
                nlas,
            }),
            _ => Err(DecodeError::from(format!(
                "Unknown message type for Beverage protocol: {}",
                header.message_type
            ))),
        }
    }
}

// to do stuff like `NetlinkMessage::from(my_beverage_message)`.
impl From<BeverageMessage> for NetlinkPayload<BeverageMessage> {
    fn from(message: BeverageMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

fn main() {
    let tea_request = BeverageMessage::Tea {
        header: BvgGenMsg {
            family: BvgGenFamily::Hot,
            version: 1,
            resource_id: 101,
        },
        nlas: vec![
            BeverageAttribute::Hotness(95),
            BeverageAttribute::PersonName("Alice".to_string()),
            BeverageAttribute::CaffeineContent(21932130),
        ],
    };

    let mut packet = NetlinkMessage::from(tea_request.clone());

    packet.header.flags = netlink_packet_core::NLM_F_REQUEST | NLM_F_SERVE | NLM_F_DRINK;
    packet.header.sequence_number = 1;

    // `finalize()` calculates the total packet length and sets the message type
    // in the header based on our `NetlinkSerializable` implementation.
    packet.finalize();

    println!("Original Packet: {:#?}", packet);

    // Serialize the packet into a byte buffer.
    let mut buf = vec![0; packet.buffer_len()];
    packet.serialize(&mut buf);

    println!("\nSerialized Bytes: {:?}", buf);

    let deserialized_packet = NetlinkMessage::<BeverageMessage>::deserialize(&buf).unwrap();

    // Verify that the round trip was successful.
    assert_eq!(packet, deserialized_packet);
}
