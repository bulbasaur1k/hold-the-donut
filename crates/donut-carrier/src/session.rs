use std::fmt;
use std::str::FromStr;

use rand::RngCore;

use crate::error::CarrierError;

/// Per-session identifier. 16 raw bytes, hex-encoded as 32
/// lowercase characters on the wire (same shape as upstream).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub const HEX_LEN: usize = 32;

    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionId").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for SessionId {
    type Err = CarrierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != Self::HEX_LEN {
            return Err(CarrierError::InvalidSessionId);
        }
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| CarrierError::InvalidSessionId)?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hex() {
        let s = SessionId::random();
        let parsed: SessionId = s.to_hex().parse().unwrap();
        assert_eq!(s, parsed);
    }

    #[test]
    fn rejects_short_hex() {
        assert!(matches!(
            "deadbeef".parse::<SessionId>(),
            Err(CarrierError::InvalidSessionId)
        ));
    }

    #[test]
    fn rejects_bad_hex() {
        assert!("zz".repeat(16).parse::<SessionId>().is_err());
    }
}
