use netlink_packet_core::{
    ErrorContext, NlaBuffer, NlasIterator, emit_u16, parse_ip, parse_u8, parse_u16,
};
use std::net::IpAddr;

use netlink_packet_core::{
    DecodeError, Emitable, NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NetlinkSerializable, Nla, Parseable, buffer, fields, getter, setter,
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
#[derive(PartialEq, Debug)]
pub enum NetfilterMessage {
    ConntrackGet {
        header: Nfgenmsg,
        nlas: Vec<ConntrackAttribute>,
    },
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
        match self {
            Self::ConntrackGet { header, nlas } => {
                header.buffer_len() + nlas.as_slice().buffer_len()
            }
        }
    }

    fn serialize(&self, buffer: &mut [u8]) {
        match self {
            Self::ConntrackGet { header, nlas } => {
                header.emit(&mut buffer[..NFGENMSG_LEN]);
                nlas.as_slice().emit(&mut buffer[NFGENMSG_LEN..]);
            }
        }
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

        // Parse netlink attributes
        let error_msg = "failed to parse Conntrack attributes";
        let mut conntrack_attributes = Vec::new();
        for nlas in NlasIterator::new(&payload[NFGENMSG_LEN..]) {
            let nlas = &nlas.context(error_msg)?;
            conntrack_attributes.push(ConntrackAttribute::parse(nlas)?);
        }

        // We use the main `nlmsghdr.message_type` to decide which enum variant
        // to construct. This is the counterpart to `message_type()` in the
        // `NetlinkSerializable` impl.
        match header.message_type {
            NETFILTER_CONNTRACK_GET_MESSAGE_TYPE => Ok(Self::ConntrackGet {
                header: nfgen_header,
                nlas: conntrack_attributes,
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

// -----------ConntrackAttribute stuff starts-----------------------
#[derive(PartialEq, Debug)]
pub enum ConntrackAttribute {
    CtaTupleOrig(Vec<Tuple>),
}
const CTA_TUPLE_ORIG: u16 = 1;

impl Nla for ConntrackAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::CtaTupleOrig(nlas) => nlas.iter().map(|op| op.buffer_len()).sum(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::CtaTupleOrig(_) => CTA_TUPLE_ORIG,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::CtaTupleOrig(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
        }
    }
    fn is_nested(&self) -> bool {
        matches!(self, ConntrackAttribute::CtaTupleOrig(_))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for ConntrackAttribute {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTA_TUPLE_ORIG => {
                let error_msg = "failed to parse CTA_TUPLE_ORIG";
                let mut tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    tuples.push(Tuple::parse(nlas)?);
                }
                ConntrackAttribute::CtaTupleOrig(tuples)
            }
            kind => return Err(DecodeError::from(format!("invalid NLA kind: {}", kind))),
        })
    }
}
// -----------ConntrackAttribute stuff ends-----------------------

// -----------Tuple stuff starts-----------------------
#[derive(PartialEq, Debug)]
pub enum Tuple {
    Ip(Vec<IPTuple>),
    Proto(Vec<ProtoTuple>),
}

pub const CTA_TUPLE_IP: u16 = 1;
pub const CTA_TUPLE_PROTO: u16 = 2;
impl Nla for Tuple {
    fn value_len(&self) -> usize {
        match self {
            Tuple::Ip(nlas) => nlas.iter().map(|op| op.buffer_len()).sum(),
            Tuple::Proto(nlas) => nlas.iter().map(|op| op.buffer_len()).sum(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Tuple::Ip(_) => CTA_TUPLE_IP,
            Tuple::Proto(_) => CTA_TUPLE_PROTO,
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Tuple::Ip(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            Tuple::Proto(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
        }
    }
    fn is_nested(&self) -> bool {
        matches!(self, Tuple::Ip(_) | Tuple::Proto(_))
    }
}
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Tuple {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        Ok(match buf.kind() {
            CTA_TUPLE_IP => {
                let error_msg = "failed to parse CTA_TUPLE_IP";
                let mut ip_tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    ip_tuples.push(IPTuple::parse(nlas)?);
                }
                Tuple::Ip(ip_tuples)
            }
            CTA_TUPLE_PROTO => {
                let error_msg = "failed to parse CTA_TUPLE_PROTO";
                let mut proto_tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    proto_tuples.push(ProtoTuple::parse(nlas)?);
                }
                Tuple::Proto(proto_tuples)
            }
            kind => return Err(DecodeError::from(format!("invalid NLA kind: {}", kind))),
        })
    }
}
// -----------Tuple stuff ends-----------------------

// -----------IPTuple stuff starts-----------------------
#[derive(PartialEq, Debug)]
pub enum IPTuple {
    SourceAddress(IpAddr),
    DestinationAddress(IpAddr),
}

// Constants for implementing the Nla trait
pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

pub const CTA_IP_V4_SRC: u16 = 1;
pub const CTA_IP_V6_SRC: u16 = 3;
pub const CTA_IP_V4_DST: u16 = 2;
pub const CTA_IP_V6_DST: u16 = 4;
// Helper function needed for implementing the Nla trait
pub fn emit_ip(addr: &IpAddr, buf: &mut [u8]) {
    match addr {
        IpAddr::V4(ip) => {
            buf[..IPV4_LEN].copy_from_slice(ip.octets().as_slice());
        }
        IpAddr::V6(ip) => {
            buf[..IPV6_LEN].copy_from_slice(ip.octets().as_slice());
        }
    }
}

impl Nla for IPTuple {
    fn value_len(&self) -> usize {
        match self {
            IPTuple::SourceAddress(addr) => match *addr {
                IpAddr::V4(_) => IPV4_LEN,
                IpAddr::V6(_) => IPV6_LEN,
            },
            IPTuple::DestinationAddress(addr) => match *addr {
                IpAddr::V4(_) => IPV4_LEN,
                IpAddr::V6(_) => IPV6_LEN,
            },
        }
    }

    fn kind(&self) -> u16 {
        match self {
            IPTuple::SourceAddress(addr) => match *addr {
                IpAddr::V4(_) => CTA_IP_V4_SRC,
                IpAddr::V6(_) => CTA_IP_V6_SRC,
            },
            IPTuple::DestinationAddress(addr) => match *addr {
                IpAddr::V4(_) => CTA_IP_V4_DST,
                IpAddr::V6(_) => CTA_IP_V6_DST,
            },
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            IPTuple::SourceAddress(addr) => emit_ip(addr, buffer),
            IPTuple::DestinationAddress(addr) => emit_ip(addr, buffer),
        }
    }
}
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for IPTuple {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        Ok(match buf.kind() {
            CTA_IP_V4_SRC | CTA_IP_V6_SRC => {
                Self::SourceAddress(parse_ip(payload).context("invalid SourceAddress value")?)
            }
            CTA_IP_V4_DST | CTA_IP_V6_DST => Self::DestinationAddress(
                parse_ip(payload).context("invalid DestinationAddress value")?,
            ),
            kind => return Err(DecodeError::from(format!("invalid NLA kind: {}", kind))),
        })
    }
}
// -----------IPTuple stuff ends-----------------------

// -----------ProtoTuple stuff starts-----------------------
#[derive(PartialEq, Debug)]
pub enum ProtoTuple {
    Protocol(u8),
    SourcePort(u16),
    DestinationPort(u16),
}
pub const CTA_PROTO_NUM: u16 = 1;
pub const CTA_PROTO_SRC_PORT: u16 = 2;
pub const CTA_PROTO_DST_PORT: u16 = 3;

impl Nla for ProtoTuple {
    fn value_len(&self) -> usize {
        match self {
            ProtoTuple::Protocol(v) => size_of_val(v),
            ProtoTuple::SourcePort(v) => size_of_val(v),
            ProtoTuple::DestinationPort(v) => size_of_val(v),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ProtoTuple::Protocol(_) => CTA_PROTO_NUM,
            ProtoTuple::SourcePort(_) => CTA_PROTO_SRC_PORT,
            ProtoTuple::DestinationPort(_) => CTA_PROTO_DST_PORT,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ProtoTuple::Protocol(v) => buffer[0] = *v,
            ProtoTuple::SourcePort(v) => emit_u16(buffer, *v).unwrap(),
            ProtoTuple::DestinationPort(v) => emit_u16(buffer, *v).unwrap(),
        }
    }
}
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for ProtoTuple {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        Ok(match buf.kind() {
            CTA_PROTO_NUM => {
                ProtoTuple::Protocol(parse_u8(payload).context("invalid CTA_PROTO_NUM value")?)
            }
            CTA_PROTO_SRC_PORT => ProtoTuple::SourcePort(
                parse_u16(payload).context("invalid CTA_PROTO_SRC_PORT value")?,
            ),
            CTA_PROTO_DST_PORT => ProtoTuple::DestinationPort(
                parse_u16(payload).context("invalid CTA_PROTO_DST_PORT value")?,
            ),
            kind => return Err(DecodeError::from(format!("invalid NLA kind: {}", kind))),
        })
    }
}
// -----------ProtoTuple stuff ends-----------------------

fn main() {
    let src_addr = IPTuple::SourceAddress(IpAddr::V4("10.0.42.55".parse().unwrap()));
    let dst_addr = IPTuple::DestinationAddress(IpAddr::V4("172.64.148.235".parse().unwrap()));

    let proto_num = ProtoTuple::Protocol(6);
    let src_port = ProtoTuple::SourcePort(48154);
    let dst_port = ProtoTuple::DestinationPort(443);

    let ip_tuple = Tuple::Ip(vec![src_addr, dst_addr]);
    let proto_tuple = Tuple::Proto(vec![proto_num, src_port, dst_port]);

    let nlas = vec![ConntrackAttribute::CtaTupleOrig(vec![
        ip_tuple,
        proto_tuple,
    ])];

    let conntrack_get_message = NetfilterMessage::ConntrackGet {
        header: (Nfgenmsg {
            nfgen_family: 0,
            version: 0,
            resource_id: 0,
        }),
        nlas,
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
