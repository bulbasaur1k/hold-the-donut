//! Hand-written codec for the tiny `Addons` message.
//!
//! We avoid pulling `prost` / `prost-build` for a 2-field proto3
//! message. The wire format is:
//!
//! ```text
//! message Addons {
//!   string flow = 1;  // proto3; absent when empty
//!   bytes  seed = 2;  // proto3; absent when empty
//! }
//! ```
//!
//! proto3 varint + length-delimited encoding; unknown tags are
//! rejected because we only ever expect these two fields in the
//! pinned upstream.

use bytes::BufMut;

use crate::error::WireError;

const TAG_FLOW: u8 = 0x0a; // field=1, wire-type=2 (length-delimited)
const TAG_SEED: u8 = 0x12; // field=2, wire-type=2

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addons {
    pub flow: String,
    pub seed: Vec<u8>,
}

impl Addons {
    pub fn is_empty(&self) -> bool {
        self.flow.is_empty() && self.seed.is_empty()
    }

    pub fn encoded_len(&self) -> usize {
        let mut n = 0;
        if !self.flow.is_empty() {
            n += 1 + varint_len(self.flow.len() as u64) + self.flow.len();
        }
        if !self.seed.is_empty() {
            n += 1 + varint_len(self.seed.len() as u64) + self.seed.len();
        }
        n
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        if !self.flow.is_empty() {
            buf.put_u8(TAG_FLOW);
            put_varint(buf, self.flow.len() as u64);
            buf.put_slice(self.flow.as_bytes());
        }
        if !self.seed.is_empty() {
            buf.put_u8(TAG_SEED);
            put_varint(buf, self.seed.len() as u64);
            buf.put_slice(&self.seed);
        }
    }

    pub fn decode(mut bytes: &[u8]) -> Result<Self, WireError> {
        let mut me = Addons::default();
        while !bytes.is_empty() {
            let tag = bytes[0];
            bytes = &bytes[1..];
            let len = get_varint(&mut bytes)? as usize;
            if bytes.len() < len {
                return Err(WireError::BadAddonsProto);
            }
            let (value, rest) = bytes.split_at(len);
            bytes = rest;
            match tag {
                TAG_FLOW => {
                    me.flow = std::str::from_utf8(value)
                        .map_err(|_| WireError::BadAddonsProto)?
                        .to_owned();
                }
                TAG_SEED => {
                    me.seed = value.to_vec();
                }
                _ => return Err(WireError::BadAddonsProto),
            }
        }
        Ok(me)
    }
}

fn varint_len(mut n: u64) -> usize {
    let mut c = 1;
    while n >= 0x80 {
        n >>= 7;
        c += 1;
    }
    c
}

fn put_varint<B: BufMut>(buf: &mut B, mut n: u64) {
    while n >= 0x80 {
        buf.put_u8((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    buf.put_u8(n as u8);
}

fn get_varint(bytes: &mut &[u8]) -> Result<u64, WireError> {
    let mut n: u64 = 0;
    for i in 0..10u32 {
        let b = *bytes.first().ok_or(WireError::BadAddonsProto)?;
        *bytes = &bytes[1..];
        n |= ((b & 0x7f) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(n);
        }
    }
    Err(WireError::VarintOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn empty_addons_encodes_to_nothing() {
        let a = Addons::default();
        assert_eq!(a.encoded_len(), 0);
        let mut b = BytesMut::new();
        a.encode(&mut b);
        assert!(b.is_empty());
        assert_eq!(Addons::decode(&[]).unwrap(), a);
    }

    #[test]
    fn flow_only_round_trip() {
        let a = Addons {
            flow: "xtls-rprx-vision".to_owned(),
            seed: vec![],
        };
        let mut b = BytesMut::new();
        a.encode(&mut b);
        assert_eq!(b[0], TAG_FLOW);
        assert_eq!(b[1] as usize, "xtls-rprx-vision".len());
        let out = Addons::decode(&b).unwrap();
        assert_eq!(out, a);
    }

    #[test]
    fn flow_and_seed_round_trip() {
        let a = Addons {
            flow: "xtls-rprx-vision".to_owned(),
            seed: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut b = BytesMut::new();
        a.encode(&mut b);
        assert_eq!(a.encoded_len(), b.len());
        let out = Addons::decode(&b).unwrap();
        assert_eq!(out, a);
    }

    #[test]
    fn rejects_unknown_tag() {
        // tag = 0x1a (field 3, wire-type 2) — unknown.
        let bytes = [0x1au8, 0x00];
        assert_eq!(Addons::decode(&bytes), Err(WireError::BadAddonsProto));
    }

    #[test]
    fn rejects_truncated_length_prefix() {
        // TAG_FLOW then length=5 but only 2 bytes follow.
        let bytes = [TAG_FLOW, 0x05, b'a', b'b'];
        assert_eq!(Addons::decode(&bytes), Err(WireError::BadAddonsProto));
    }

    #[test]
    fn rejects_bad_utf8() {
        let bytes = [TAG_FLOW, 0x02, 0xff, 0xfe];
        assert_eq!(Addons::decode(&bytes), Err(WireError::BadAddonsProto));
    }

    #[test]
    fn varint_boundaries() {
        // 0 .. 2^14 + 1 must encode/decode faithfully.
        for n in [0u64, 1, 127, 128, 255, 256, 16383, 16384, 16385] {
            let mut b = BytesMut::new();
            put_varint(&mut b, n);
            let mut slice: &[u8] = &b;
            assert_eq!(get_varint(&mut slice).unwrap(), n);
            assert!(slice.is_empty());
        }
    }
}
