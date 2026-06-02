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
    /// Length of the dashed UUID form (`8-4-4-4-12`) Xray's xHTTP client
    /// puts in the path, e.g. `550e8400-e29b-41d4-a716-446655440000`.
    pub const UUID_LEN: usize = 36;

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

    /// Format as a dashed UUID (`8-4-4-4-12`). The on-wire form an
    /// Xray xHTTP client emits; kept symmetric with [`FromStr`] so a
    /// session id parsed from either shape can be re-emitted faithfully.
    pub fn to_uuid(&self) -> String {
        let h = self.to_hex();
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
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
        let mut bytes = [0u8; 16];
        match s.len() {
            // donut client: 32 lowercase hex chars.
            Self::HEX_LEN => {
                hex::decode_to_slice(s, &mut bytes).map_err(|_| CarrierError::InvalidSessionId)?;
            }
            // Xray xHTTP client: dashed UUID (`8-4-4-4-12`). Both halves
            // decode to the same 16 raw bytes, so the server can pair an
            // uplink POST and downlink GET regardless of which client
            // emitted them.
            Self::UUID_LEN => {
                let stripped: String = s.chars().filter(|&c| c != '-').collect();
                if stripped.len() != Self::HEX_LEN {
                    return Err(CarrierError::InvalidSessionId);
                }
                hex::decode_to_slice(&stripped, &mut bytes)
                    .map_err(|_| CarrierError::InvalidSessionId)?;
            }
            _ => return Err(CarrierError::InvalidSessionId),
        }
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

    #[test]
    fn parses_xray_dashed_uuid() {
        // An Xray xHTTP client puts a dashed UUID in the path; it must
        // decode to the same bytes as its dash-free hex form so uplink and
        // downlink pair.
        let s = SessionId::random();
        let dashed = s.to_uuid();
        assert_eq!(dashed.len(), SessionId::UUID_LEN);
        let parsed: SessionId = dashed.parse().unwrap();
        assert_eq!(s, parsed);
        // The hex form of the same id parses to the same value.
        let from_hex: SessionId = s.to_hex().parse().unwrap();
        assert_eq!(parsed, from_hex);
    }

    #[test]
    fn rejects_bad_uuid() {
        // Right length, wrong shape (non-hex / misplaced dashes).
        assert!("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
            .parse::<SessionId>()
            .is_err());
    }
}
