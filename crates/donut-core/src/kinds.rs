use serde::{Deserialize, Serialize};

/// VLESS command byte.
///
/// On the wire: 1 unsigned byte at offset `18 + addon_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Command {
    Tcp = 0x01,
    Udp = 0x02,
    /// Mux.Cool. Accepted on the wire for compatibility but we do not
    /// implement a multiplexer; inbound requests tagged Mux are rejected.
    Mux = 0x03,
}

impl Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            0x03 => Some(Self::Mux),
            _ => None,
        }
    }
}

/// VLESS flow selector carried inside `Addons.flow`.
///
/// Vision is accepted only alongside `TransportKind::RawTcp`; all other
/// transports enforce `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowKind {
    #[default]
    None,
    #[serde(rename = "xtls-rprx-vision")]
    Vision,
}

impl FlowKind {
    pub const VISION_WIRE: &'static str = "xtls-rprx-vision";

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Vision => Self::VISION_WIRE,
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "" | "none" => Some(Self::None),
            Self::VISION_WIRE => Some(Self::Vision),
            _ => None,
        }
    }
}

/// Transport carrying VLESS frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    /// Plain TCP — VLESS is the first byte after the TLS record layer.
    RawTcp,
    /// XHTTP over HTTP/1.1 or HTTP/2.
    Xhttp,
    /// XHTTP over HTTP/3 (QUIC).
    XhttpH3,
}

/// TLS layer beneath the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsKind {
    None,
    Tls,
    Reality,
}
