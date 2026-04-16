use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// User identifier. Wraps a 128-bit UUID, serialised on the wire as 16
/// raw bytes (VLESS header) and as hex/UUID-canonical in config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(Uuid);

impl UserId {
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for UserId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

/// REALITY `ShortID`. Exactly 8 bytes on the wire, stored in the
/// plaintext `SessionID[8..16]` of the modified ClientHello.
///
/// Config representation: hex string, 1..=16 nibbles, zero-padded on
/// the right when shorter than 16 nibbles.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ShortId([u8; 8]);

impl ShortId {
    pub const LEN: usize = 8;

    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Zero-length ShortID — valid per xray (matches any input with a
    /// single-empty entry in `shortIds`).
    pub const fn zero() -> Self {
        Self([0; 8])
    }
}

impl fmt::Debug for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ShortId")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for ShortId {
    type Err = ShortIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 16 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ShortIdParseError::Invalid);
        }
        // Zero-pad on the right to 16 nibbles, then hex-decode.
        let mut padded = [b'0'; 16];
        padded[..s.len()].copy_from_slice(s.as_bytes());
        let mut bytes = [0u8; 8];
        hex::decode_to_slice(padded, &mut bytes).map_err(|_| ShortIdParseError::Invalid)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Error)]
pub enum ShortIdParseError {
    #[error("invalid ShortID (expected 1..=16 hex characters)")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_parse_pads_right() {
        // "01" → 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        let sid: ShortId = "01".parse().unwrap();
        assert_eq!(sid.as_bytes(), &[0x01, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn short_id_full_hex() {
        let sid: ShortId = "0123456789abcdef".parse().unwrap();
        assert_eq!(
            sid.as_bytes(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        );
    }

    #[test]
    fn short_id_rejects_bad_input() {
        let empty: ShortId = "".parse().unwrap(); // empty pads to all zeros
        assert_eq!(empty.as_bytes(), &[0u8; 8]);
        assert!("zz".parse::<ShortId>().is_err());
        assert!("01234567890abcdef1".parse::<ShortId>().is_err());
    }

    #[test]
    fn user_id_round_trip() {
        let u = UserId::new_v4();
        let bytes = *u.as_bytes();
        assert_eq!(UserId::from_bytes(bytes), u);
    }
}
