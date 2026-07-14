#[cfg(test)]
use std::io::Read;
use std::io::{self, Write};
use std::num::NonZeroU64;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub(super) const BROKER_PROTOCOL_VERSION: u16 = 2;
pub(super) const MAX_PAYLOAD_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct CorrelationId(NonZeroU64);

impl CorrelationId {
    pub(super) fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    pub(super) fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum LoopbackAddress {
    Ipv4([u8; 4]),
    Ipv6,
}

impl LoopbackAddress {
    pub(super) fn is_valid(self) -> bool {
        match self {
            Self::Ipv4(octets) => octets[0] == 127,
            Self::Ipv6 => true,
        }
    }

    pub(super) fn ssh_host(self) -> String {
        match self {
            Self::Ipv4(octets) => {
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            Self::Ipv6 => "[::1]".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ForwardSpec {
    pub(crate) local_address: LoopbackAddress,
    pub(crate) local_port: u16,
    pub(crate) remote_address: LoopbackAddress,
    pub(crate) remote_port: u16,
}

impl ForwardSpec {
    pub(super) fn is_valid(self) -> bool {
        self.local_port != 0
            && self.remote_port != 0
            && self.local_address.is_valid()
            && self.remote_address.is_valid()
            && self.local_address == self.remote_address
    }

    pub(super) fn ssh_value(self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.local_address.ssh_host(),
            self.local_port,
            self.remote_address.ssh_host(),
            self.remote_port
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum ClientMessage {
    Hello {
        id: CorrelationId,
        version: u16,
    },
    AssertPolicy {
        id: CorrelationId,
        enabled: bool,
    },
    Forward {
        id: CorrelationId,
        spec: ForwardSpec,
    },
    Cancel {
        id: CorrelationId,
    },
}

impl ClientMessage {
    pub(super) fn correlation_id(&self) -> CorrelationId {
        match self {
            Self::Hello { id, .. }
            | Self::AssertPolicy { id, .. }
            | Self::Forward { id, .. }
            | Self::Cancel { id } => *id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ForwardFailure {
    Disabled,
    Cancelled,
    TooManyRequests,
    AlreadyOwned,
    BindFailed,
    CommandRejected,
    CommandTimedOut,
    CapabilityClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum ServerMessage {
    HelloAcknowledged {
        id: CorrelationId,
        version: u16,
    },
    PolicyAcknowledged {
        id: CorrelationId,
        requested: bool,
        effective: bool,
        result: Result<(), ForwardFailure>,
    },
    ForwardSettled {
        id: CorrelationId,
        result: Result<(), ForwardFailure>,
    },
    Cancelled {
        id: CorrelationId,
    },
}

impl ServerMessage {
    pub(super) fn correlation_id(&self) -> CorrelationId {
        match self {
            Self::HelloAcknowledged { id, .. }
            | Self::PolicyAcknowledged { id, .. }
            | Self::ForwardSettled { id, .. }
            | Self::Cancelled { id } => *id,
        }
    }
}

pub(super) fn write_message(writer: &mut impl Write, message: &impl Serialize) -> io::Result<()> {
    let payload = encode_message(message)?;
    write_payload(writer, &payload)
}

pub(super) fn write_payload(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker frame length",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid broker frame length"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)
}

#[cfg(test)]
pub(super) fn read_payload(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    read_payload_after_header(reader, header)
}

#[cfg(test)]
pub(super) fn read_payload_after_header(
    reader: &mut impl Read,
    header: [u8; 4],
) -> io::Result<Vec<u8>> {
    let mut payload = vec![0_u8; payload_length(header)?];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

pub(super) fn payload_length(header: [u8; 4]) -> io::Result<usize> {
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid broker frame length",
        ));
    }
    Ok(length)
}

pub(super) fn encode_message(message: &impl Serialize) -> io::Result<Vec<u8>> {
    bincode::serde::encode_to_vec(message, bincode_config())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "broker message encode failed"))
}

pub(super) fn decode_message<T: DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    let (message, consumed) = bincode::serde::decode_from_slice(payload, bincode_config())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "broker message decode failed"))?;
    if consumed != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker message has trailing bytes",
        ));
    }
    Ok(message)
}

fn bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_fixed_int_encoding()
        .with_big_endian()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn forward_specs_require_the_same_exact_loopback_identity_at_both_ends() {
        let exact_ipv4 = ForwardSpec {
            local_address: LoopbackAddress::Ipv4([127, 0, 0, 42]),
            local_port: 8080,
            remote_address: LoopbackAddress::Ipv4([127, 0, 0, 42]),
            remote_port: 3000,
        };
        let exact_ipv6 = ForwardSpec {
            local_address: LoopbackAddress::Ipv6,
            local_port: 8080,
            remote_address: LoopbackAddress::Ipv6,
            remote_port: 3000,
        };

        assert!(exact_ipv4.is_valid());
        assert!(exact_ipv6.is_valid());
        assert!(!ForwardSpec {
            remote_address: LoopbackAddress::Ipv6,
            ..exact_ipv4
        }
        .is_valid());
    }

    #[test]
    fn broker_frame_accepts_the_four_kibibyte_payload_boundary() {
        let payload = vec![0x5a; MAX_PAYLOAD_BYTES];
        let mut framed = Vec::new();

        write_payload(&mut framed, &payload).expect("write boundary frame");

        assert_eq!(&framed[..4], &(MAX_PAYLOAD_BYTES as u32).to_be_bytes());
        assert_eq!(
            read_payload(&mut Cursor::new(framed)).expect("read boundary frame"),
            payload
        );
    }

    #[test]
    fn broker_frame_rejects_zero_length_oversized_and_truncated_payloads() {
        let mut empty = Cursor::new(0_u32.to_be_bytes());
        assert_eq!(
            read_payload(&mut empty).expect_err("zero length").kind(),
            std::io::ErrorKind::InvalidData
        );

        let mut oversized = Cursor::new(((MAX_PAYLOAD_BYTES + 1) as u32).to_be_bytes());
        assert_eq!(
            read_payload(&mut oversized).expect_err("oversized").kind(),
            std::io::ErrorKind::InvalidData
        );

        let mut truncated = Cursor::new([2_u32.to_be_bytes().as_slice(), &[0_u8][..]].concat());
        assert_eq!(
            read_payload(&mut truncated).expect_err("truncated").kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn broker_message_decode_rejects_trailing_bytes() {
        let message = ClientMessage::Hello {
            id: CorrelationId::new(1).expect("nonzero id"),
            version: BROKER_PROTOCOL_VERSION,
        };
        let mut payload = encode_message(&message).expect("encode message");
        payload.push(0);

        assert_eq!(
            decode_message::<ClientMessage>(&payload)
                .expect_err("trailing byte must fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}
