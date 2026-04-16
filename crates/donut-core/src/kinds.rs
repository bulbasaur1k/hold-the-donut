use serde::{Deserialize, Serialize};

/// Inner-frame command byte.
///
/// On the wire: 1 unsigned byte at offset `18 + addon_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Command {
    Tcp = 0x01,
    Udp = 0x02,
    /// Multiplexer command. Accepted on the wire for compatibility but
    /// we do not implement a multiplexer; inbound requests tagged Mux
    /// are rejected.
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

/// Flow selector carried inside the inner-frame `Addons.flow` field.
///
/// The extended variant is accepted only alongside
/// `TransportKind::RawTcp`; all other transports enforce `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowKind {
    #[default]
    None,
    /// Extended flow variant carried on the wire as the upstream
    /// "xtls-rprx-vision" identifier.
    #[serde(rename = "xtls-rprx-vision")]
    Extended,
}

impl FlowKind {
    /// On-wire identifier for the extended flow variant. Must match
    /// the upstream codepoint byte-for-byte — this is a wire constant,
    /// not a display name.
    pub const EXTENDED_WIRE: &'static str = "xtls-rprx-vision";

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Extended => Self::EXTENDED_WIRE,
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "" | "none" => Some(Self::None),
            Self::EXTENDED_WIRE => Some(Self::Extended),
            _ => None,
        }
    }
}

/// Transport carrying the inner frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    /// Plain TCP — the inner frame is the first byte after the TLS
    /// record layer.
    RawTcp,
    /// HTTP-based carrier over HTTP/1.1 or HTTP/2.
    Carrier,
    /// HTTP-based carrier over HTTP/3 (QUIC).
    CarrierQuic,
}

/// TLS layer beneath the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsKind {
    None,
    Tls,
    /// Veiled TLS: authenticated client masquerade where non-auth'd
    /// probes are forwarded to the fronted target.
    Veil,
}
