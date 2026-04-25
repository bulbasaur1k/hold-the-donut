//! Minimal byte-level reader over the serialised ClientHello body
//! (the same slice both veil hooks see). Avoids round-tripping
//! through rustls's parser since the only fields we need are the
//! 32-byte Random, the 32-byte SessionID, and the X25519 share inside
//! the `key_share` extension.

use crate::error::VeilError;

/// Layout offsets within the ClientHello handshake body.
const TYPE_LEN_HEADER: usize = 4; // type(1) + length(3)
const VERSION_LEN: usize = 2;
const RANDOM_LEN: usize = 32;
const SESSION_ID_LEN_OFFSET: usize = TYPE_LEN_HEADER + VERSION_LEN + RANDOM_LEN; // = 38
const SESSION_ID_OFFSET: usize = SESSION_ID_LEN_OFFSET + 1; // = 39
const SESSION_ID_BYTES: usize = 32;

/// TLS extension type for `key_share`.
const EXT_KEY_SHARE: u16 = 0x0033;
/// NamedGroup value for X25519.
const NAMED_GROUP_X25519: u16 = 0x001D;

/// Borrowed view over the bits of the ClientHello the veil layer
/// touches.
pub(crate) struct ClientHelloView<'a> {
    pub random: &'a [u8; 32],
    pub session_id: [u8; 32],
    pub x25519_pub: [u8; 32],
}

impl<'a> ClientHelloView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, VeilError> {
        if bytes.len() < SESSION_ID_OFFSET + SESSION_ID_BYTES {
            return Err(VeilError::ShortClientHello);
        }
        if bytes[SESSION_ID_LEN_OFFSET] as usize != SESSION_ID_BYTES {
            return Err(VeilError::BadSessionIdLength);
        }
        let random: &[u8; 32] = (&bytes[6..38]).try_into().expect("32 bytes by index math");
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&bytes[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32]);

        let x25519_pub = find_x25519_share(bytes)?;

        Ok(Self {
            random,
            session_id,
            x25519_pub,
        })
    }
}

/// Walk the ClientHello extensions, find the `key_share` extension,
/// and pull the 32-byte X25519 key out of it. Refuses anything
/// shaped wrong.
fn find_x25519_share(bytes: &[u8]) -> Result<[u8; 32], VeilError> {
    // Cursor starts after SessionID.
    let mut cur = SESSION_ID_OFFSET + SESSION_ID_BYTES;

    // cipher_suites: u16 length then that many bytes.
    cur = skip_u16_prefixed(bytes, cur)?;
    // legacy_compression_methods: u8 length then bytes.
    cur = skip_u8_prefixed(bytes, cur)?;
    // extensions: u16 length, then sequence of (type u16, length u16, bytes...).
    if cur + 2 > bytes.len() {
        return Err(VeilError::ShortClientHello);
    }
    let ext_total = u16::from_be_bytes([bytes[cur], bytes[cur + 1]]) as usize;
    cur += 2;
    let ext_end = cur + ext_total;
    if ext_end > bytes.len() {
        return Err(VeilError::ShortClientHello);
    }

    while cur + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([bytes[cur], bytes[cur + 1]]);
        let ext_len = u16::from_be_bytes([bytes[cur + 2], bytes[cur + 3]]) as usize;
        cur += 4;
        let ext_data_end = cur + ext_len;
        if ext_data_end > ext_end {
            return Err(VeilError::ShortClientHello);
        }
        if ext_type == EXT_KEY_SHARE {
            return parse_x25519_in_key_share(&bytes[cur..ext_data_end]);
        }
        cur = ext_data_end;
    }
    Err(VeilError::MissingKeyShare)
}

fn parse_x25519_in_key_share(data: &[u8]) -> Result<[u8; 32], VeilError> {
    if data.len() < 2 {
        return Err(VeilError::ShortClientHello);
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() {
        return Err(VeilError::ShortClientHello);
    }
    let list = &data[2..2 + list_len];
    let mut cur = 0;
    while cur + 4 <= list.len() {
        let group = u16::from_be_bytes([list[cur], list[cur + 1]]);
        let len = u16::from_be_bytes([list[cur + 2], list[cur + 3]]) as usize;
        cur += 4;
        let end = cur + len;
        if end > list.len() {
            return Err(VeilError::ShortClientHello);
        }
        if group == NAMED_GROUP_X25519 {
            if len != 32 {
                return Err(VeilError::NoX25519Share);
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&list[cur..end]);
            return Ok(out);
        }
        cur = end;
    }
    Err(VeilError::NoX25519Share)
}

fn skip_u16_prefixed(bytes: &[u8], cur: usize) -> Result<usize, VeilError> {
    if cur + 2 > bytes.len() {
        return Err(VeilError::ShortClientHello);
    }
    let len = u16::from_be_bytes([bytes[cur], bytes[cur + 1]]) as usize;
    let end = cur + 2 + len;
    if end > bytes.len() {
        return Err(VeilError::ShortClientHello);
    }
    Ok(end)
}

fn skip_u8_prefixed(bytes: &[u8], cur: usize) -> Result<usize, VeilError> {
    if cur >= bytes.len() {
        return Err(VeilError::ShortClientHello);
    }
    let len = bytes[cur] as usize;
    let end = cur + 1 + len;
    if end > bytes.len() {
        return Err(VeilError::ShortClientHello);
    }
    Ok(end)
}
