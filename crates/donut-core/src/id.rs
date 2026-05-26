use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// User identifier. Wraps a 128-bit UUID, serialised on the wire as
/// 16 raw bytes inside the inner-frame header, and as canonical UUID
/// in config files.
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

/// The set of [`UserId`]s a server accepts on the VLESS inner frame.
///
/// Membership is the proxy's actual credential check: a session whose
/// inner-frame UUID is not in this set must be rejected before any
/// upstream is dialled. An empty set authorises no one (fail-closed).
#[derive(Debug, Clone, Default)]
pub struct UserAuth {
    users: Vec<UserId>,
}

impl UserAuth {
    pub fn new(users: Vec<UserId>) -> Self {
        Self { users }
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Constant-time membership test. The candidate is compared against
    /// every configured user without short-circuiting — neither the
    /// byte at which two UUIDs diverge nor which entry matched affects
    /// the running time, so the secret UUID(s) leak no timing oracle.
    /// (The set *size* is not secret.)
    pub fn is_authorized(&self, candidate: &UserId) -> bool {
        let cand = candidate.as_bytes();
        let mut found: u8 = 0;
        for u in &self.users {
            let a = u.as_bytes();
            let mut diff: u8 = 0;
            for i in 0..16 {
                diff |= a[i] ^ cand[i];
            }
            // diff == 0 ⇒ this entry matched. Map 0→0xFF, nonzero→0x00
            // branchlessly and fold into `found`.
            found |= ((diff as u16).wrapping_sub(1) >> 8) as u8;
        }
        found != 0
    }
}

/// Veiled-TLS short identifier. Exactly 8 bytes on the wire, stored
/// in the plaintext `SessionID[8..16]` of the modified ClientHello.
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

    /// Zero-length short id — wildcard per upstream semantics
    /// (an empty-string entry in the configured list allows all).
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

    #[test]
    fn user_auth_membership() {
        let allowed = UserId::from_bytes([0xab; 16]);
        let other = UserId::from_bytes([0xcd; 16]);
        let auth = UserAuth::new(vec![allowed]);

        assert!(auth.is_authorized(&allowed));
        assert!(!auth.is_authorized(&other));
        // A near-miss (single differing byte) must still be rejected.
        let mut near = [0xab; 16];
        near[15] = 0xac;
        assert!(!auth.is_authorized(&UserId::from_bytes(near)));
    }

    #[test]
    fn user_auth_empty_rejects_all() {
        let auth = UserAuth::default();
        assert!(auth.is_empty());
        assert!(!auth.is_authorized(&UserId::new_v4()));
    }

    #[test]
    fn user_auth_multiple_entries() {
        let a = UserId::from_bytes([0x01; 16]);
        let b = UserId::from_bytes([0x02; 16]);
        let auth = UserAuth::new(vec![a, b]);
        assert!(auth.is_authorized(&a));
        assert!(auth.is_authorized(&b));
        assert!(!auth.is_authorized(&UserId::from_bytes([0x03; 16])));
    }
}
