//! TLS ClientHello fingerprint selection (uTLS-style).
//!
//! rustls emits a ClientHello with a fixed, rustls-specific ordering of
//! cipher suites and extensions. That ordering is a stable
//! [JA3](https://github.com/salesforce/ja3)-style fingerprint that a DPI
//! box can blacklist regardless of SNI or REALITY masking. uTLS solves
//! this on the Go side by mimicking real browsers; the headline mode is
//! **`randomized`** ([`HelloRandomized`] in uTLS), which emits a random
//! but fully-supported ClientHello — a moving target with no
//! parrot-is-dead risk.
//!
//! ## What we can do here
//!
//! The [`ClientHelloMutator`](rustls::client::ClientHelloMutator) hook is
//! **length-preserving** — the callback gets a `&mut [u8]` over the
//! already-serialised handshake body and must not resize it. Within that
//! contract the faithful subset of `randomized` is to shuffle the
//! *order* of the cipher-suite list and the extension list per
//! connection. That defeats a fixed-ordering JA3 match while keeping the
//! REALITY seal intact (the seal AAD is the whole ClientHello with the
//! SessionID zeroed, which the server reconstructs from the bytes it
//! actually receives — so reordering before sealing stays consistent).
//!
//! ## What still needs a richer hook
//!
//! True uTLS `randomized` also varies the *set* of cipher suites and
//! extensions and injects GREASE values, both of which change the
//! ClientHello length. Doing that needs a mutator that can return an
//! owned, resized buffer; that is tracked as future work (see
//! `docs/FINGERPRINT.md`). The ALPN-forcing variants
//! ([`Fingerprint::RandomizedAlpn`] / [`Fingerprint::RandomizedNoAlpn`])
//! likewise require adding/removing the ALPN extension, so for now they
//! behave exactly like [`Fingerprint::Randomized`].
//!
//! [`HelloRandomized`]: https://github.com/refraction-networking/utls

use std::str::FromStr;

use rand::seq::SliceRandom;

/// Offset of the 1-byte legacy `session_id` length field inside the
/// serialised handshake body (`4` header + `2` legacy_version + `32`
/// random).
const SESSION_ID_LEN_OFFSET: usize = 38;
/// Offset of the legacy `session_id` bytes themselves.
const SESSION_ID_OFFSET: usize = 39;
/// `pre_shared_key` extension type. Its presence (a TLS 1.3 resumption
/// attempt) means the ClientHello carries binders computed before this
/// mutator runs, so we must not reorder at all — see [`randomize_order`].
const PRE_SHARED_KEY_EXT: u16 = 41;

/// Which TLS ClientHello fingerprint the client mimics.
///
/// Parse from the `outbound.reality.fingerprint` config string via
/// [`FromStr`]; an empty/absent value means [`Fingerprint::Native`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Fingerprint {
    /// Emit rustls's native ClientHello unchanged. Default.
    #[default]
    Native,
    /// uTLS `randomized`: shuffle cipher-suite and extension order per
    /// connection.
    Randomized,
    /// uTLS `randomizedalpn`. ALPN-presence forcing needs a resizing
    /// hook, so this currently behaves like [`Fingerprint::Randomized`].
    RandomizedAlpn,
    /// uTLS `randomizednoalpn`. ALPN-absence forcing needs a resizing
    /// hook, so this currently behaves like [`Fingerprint::Randomized`].
    RandomizedNoAlpn,
}

impl Fingerprint {
    /// Whether this fingerprint mutates the ClientHello order.
    pub fn randomizes(self) -> bool {
        matches!(
            self,
            Self::Randomized | Self::RandomizedAlpn | Self::RandomizedNoAlpn
        )
    }

    /// Apply this fingerprint to a serialised ClientHello handshake body
    /// — the same `&mut [u8]` the
    /// [`ClientHelloMutator`](rustls::client::ClientHelloMutator) hook
    /// receives (handshake header at offset 0, 32-byte legacy SessionID
    /// at offset 39). Length-preserving.
    ///
    /// On any structural surprise the buffer is left **untouched** (and a
    /// warning is logged) rather than risking a malformed ClientHello.
    pub fn apply(self, buf: &mut [u8]) {
        if !self.randomizes() {
            return;
        }
        if let Err(reason) = randomize_order(buf) {
            tracing::warn!("fingerprint: leaving ClientHello unshuffled: {reason}");
        }
    }
}

/// Error returned when a config string names a fingerprint we don't
/// implement.
#[derive(Debug, thiserror::Error)]
#[error(
    "unsupported TLS fingerprint {0:?}; supported: native, randomized, randomizedalpn, randomizednoalpn"
)]
pub struct UnknownFingerprint(pub String);

impl FromStr for Fingerprint {
    type Err = UnknownFingerprint;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Normalise the way upstream does: case-insensitive, ignore
        // separators (so "Randomized-ALPN", "randomizedALPN" all match).
        let norm: String = s
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        Ok(match norm.as_str() {
            "" | "native" | "unspecified" | "none" => Self::Native,
            "random" | "rand" | "randomized" => Self::Randomized,
            "randomizedalpn" => Self::RandomizedAlpn,
            "randomizednoalpn" => Self::RandomizedNoAlpn,
            _ => return Err(UnknownFingerprint(s.to_string())),
        })
    }
}

/// Read a big-endian `u16` at `off`, or `None` if out of bounds.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)?;
    let lo = *buf.get(off + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Shuffle the cipher-suite list and extension list of a serialised
/// ClientHello in place, without changing its length. The fixed fields
/// (legacy_version, random, session_id) sit before the cipher-suite list
/// and are never touched, so the REALITY seal — computed afterwards over
/// the whole buffer with the SessionID zeroed — stays valid.
///
/// Builds the reordered bytes into owned buffers first; if any bounds
/// check fails it returns `Err` having mutated nothing.
fn randomize_order(buf: &mut [u8]) -> Result<(), &'static str> {
    let sid_len = *buf
        .get(SESSION_ID_LEN_OFFSET)
        .ok_or("buffer too short for session_id length")? as usize;

    // cipher_suites: u16 length then that many bytes.
    let cs_len_off = SESSION_ID_OFFSET + sid_len;
    let cs_len = read_u16(buf, cs_len_off).ok_or("truncated cipher_suites length")? as usize;
    let cs_off = cs_len_off + 2;
    if cs_len % 2 != 0 {
        return Err("odd cipher_suites length");
    }
    let cs_end = cs_off.checked_add(cs_len).ok_or("cipher_suites overflow")?;
    if cs_end > buf.len() {
        return Err("cipher_suites out of bounds");
    }

    // legacy_compression_methods: u8 length then that many bytes.
    let comp_len_off = cs_end;
    let comp_len = *buf
        .get(comp_len_off)
        .ok_or("truncated compression_methods length")? as usize;
    let comp_end = comp_len_off + 1 + comp_len;
    if comp_end > buf.len() {
        return Err("compression_methods out of bounds");
    }

    // extensions: u16 length then that many bytes — must run to the end.
    let ext_len_off = comp_end;
    let ext_len = read_u16(buf, ext_len_off).ok_or("truncated extensions length")? as usize;
    let ext_off = ext_len_off + 2;
    let ext_end = ext_off.checked_add(ext_len).ok_or("extensions overflow")?;
    if ext_end != buf.len() {
        return Err("extensions length does not match buffer end");
    }

    // Parse the extension list into (type, owned bytes) blocks.
    let mut blocks: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut pos = ext_off;
    while pos < ext_end {
        let etype = read_u16(buf, pos).ok_or("truncated extension type")?;
        let elen = read_u16(buf, pos + 2).ok_or("truncated extension length")? as usize;
        let block_end = pos.checked_add(4 + elen).ok_or("extension overflow")?;
        if block_end > ext_end {
            return Err("extension body out of bounds");
        }
        // A pre_shared_key extension carries binders — HMACs over the
        // truncated ClientHello transcript that rustls computed *before*
        // this mutator runs. Reordering anything would invalidate them
        // (IncorrectBinder on the server), so we must leave a
        // PSK-resuming ClientHello exactly as-is. For full per-connection
        // randomization, disable TLS resumption on the client config.
        if etype == PRE_SHARED_KEY_EXT {
            return Err("pre_shared_key present; preserving binder");
        }
        blocks.push((etype, buf[pos..block_end].to_vec()));
        pos = block_end;
    }
    if pos != ext_end {
        return Err("trailing bytes after extensions");
    }

    // Snapshot the cipher suites as 2-byte entries.
    let mut suites: Vec<[u8; 2]> = buf[cs_off..cs_end]
        .chunks_exact(2)
        .map(|c| [c[0], c[1]])
        .collect();

    let mut rng = rand::thread_rng();
    suites.shuffle(&mut rng);

    // Shuffle extension order. (No pre_shared_key can be present here —
    // we bailed above — so every ordering is valid.)
    let mut order: Vec<usize> = (0..blocks.len()).collect();
    order.shuffle(&mut rng);

    // Commit cipher suites.
    for (i, suite) in suites.iter().enumerate() {
        buf[cs_off + i * 2] = suite[0];
        buf[cs_off + i * 2 + 1] = suite[1];
    }
    // Commit extensions in the new order.
    let mut w = ext_off;
    for &i in &order {
        let bytes = &blocks[i].1;
        buf[w..w + bytes.len()].copy_from_slice(bytes);
        w += bytes.len();
    }
    debug_assert_eq!(w, ext_end, "reordered extensions must refill the slot");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_matches_upstream_spellings() {
        assert_eq!("".parse::<Fingerprint>().unwrap(), Fingerprint::Native);
        assert_eq!(
            "unspecified".parse::<Fingerprint>().unwrap(),
            Fingerprint::Native
        );
        assert_eq!(
            "random".parse::<Fingerprint>().unwrap(),
            Fingerprint::Randomized
        );
        assert_eq!(
            "Randomized".parse::<Fingerprint>().unwrap(),
            Fingerprint::Randomized
        );
        assert_eq!(
            "randomizedALPN".parse::<Fingerprint>().unwrap(),
            Fingerprint::RandomizedAlpn
        );
        assert_eq!(
            "randomized-no-alpn".parse::<Fingerprint>().unwrap(),
            Fingerprint::RandomizedNoAlpn
        );
    }

    #[test]
    fn parse_rejects_unimplemented_presets() {
        assert!("chrome".parse::<Fingerprint>().is_err());
        assert!("firefox".parse::<Fingerprint>().is_err());
        assert!("bogus".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn randomizes_flags() {
        assert!(!Fingerprint::Native.randomizes());
        assert!(Fingerprint::Randomized.randomizes());
        assert!(Fingerprint::RandomizedAlpn.randomizes());
        assert!(Fingerprint::RandomizedNoAlpn.randomizes());
    }

    /// Build a syntactically valid ClientHello handshake body with the
    /// given cipher suites and `(ext_type, ext_payload)` extensions.
    fn build_client_hello(suites: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(32); // session_id length
        body.extend_from_slice(&[0x22; 32]); // session_id
        let cs_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();
        body.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&cs_bytes);
        body.extend_from_slice(&[0x01, 0x00]); // compression: 1 method, null
        let mut ext_bytes = Vec::new();
        for (ty, payload) in exts {
            ext_bytes.extend_from_slice(&ty.to_be_bytes());
            ext_bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(payload);
        }
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_bytes);

        // Prepend the 4-byte handshake header (type 0x01 + u24 length).
        let mut msg = vec![0x01];
        let len = body.len() as u32;
        msg.extend_from_slice(&len.to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    /// Re-parse a randomised ClientHello back into its cipher-suite and
    /// extension lists, asserting structural validity.
    fn parse(buf: &[u8]) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
        let sid_len = buf[SESSION_ID_LEN_OFFSET] as usize;
        let cs_len_off = SESSION_ID_OFFSET + sid_len;
        let cs_len = read_u16(buf, cs_len_off).unwrap() as usize;
        let cs_off = cs_len_off + 2;
        let suites = buf[cs_off..cs_off + cs_len]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let comp_len_off = cs_off + cs_len;
        let comp_len = buf[comp_len_off] as usize;
        let ext_len_off = comp_len_off + 1 + comp_len;
        let ext_len = read_u16(buf, ext_len_off).unwrap() as usize;
        let ext_off = ext_len_off + 2;
        let ext_end = ext_off + ext_len;
        assert_eq!(ext_end, buf.len(), "extensions must run to buffer end");
        let mut exts = Vec::new();
        let mut pos = ext_off;
        while pos < ext_end {
            let ty = read_u16(buf, pos).unwrap();
            let elen = read_u16(buf, pos + 2).unwrap() as usize;
            exts.push((ty, buf[pos + 4..pos + 4 + elen].to_vec()));
            pos += 4 + elen;
        }
        assert_eq!(pos, ext_end);
        (suites, exts)
    }

    #[test]
    fn native_is_a_no_op() {
        let original = build_client_hello(
            &[0x1301, 0x1302, 0x1303],
            &[(0, vec![1, 2, 3]), (43, vec![4, 4])],
        );
        let mut buf = original.clone();
        Fingerprint::Native.apply(&mut buf);
        assert_eq!(buf, original, "native must not touch the ClientHello");
    }

    #[test]
    fn randomized_preserves_length_and_contents() {
        let suites = [0x1301, 0x1302, 0x1303, 0xC02B, 0x00FF];
        let exts = vec![
            (0u16, vec![0xAA, 0xBB]),     // server_name-ish
            (43, vec![0x02, 0x03, 0x04]), // supported_versions-ish
            (51, vec![0xDE; 36]),         // key_share-ish
            (10, vec![0x00, 0x02, 0x00]), // supported_groups-ish
            (13, vec![0x01, 0x02]),       // signature_algorithms-ish
        ];
        let original = build_client_hello(&suites, &exts);

        for _ in 0..64 {
            let mut buf = original.clone();
            Fingerprint::Randomized.apply(&mut buf);

            assert_eq!(buf.len(), original.len(), "length must be preserved");
            // Fixed prefix (header..session_id end) is untouched.
            assert_eq!(
                buf[..SESSION_ID_OFFSET + 32],
                original[..SESSION_ID_OFFSET + 32]
            );

            let (got_suites, got_exts) = parse(&buf);
            let mut a: Vec<u16> = got_suites.clone();
            let mut b: Vec<u16> = suites.to_vec();
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b, "cipher-suite multiset must be preserved");

            let mut got_types: Vec<u16> = got_exts.iter().map(|(t, _)| *t).collect();
            let mut want_types: Vec<u16> = exts.iter().map(|(t, _)| *t).collect();
            got_types.sort_unstable();
            want_types.sort_unstable();
            assert_eq!(got_types, want_types, "extension-type multiset preserved");
        }
    }

    #[test]
    fn pre_shared_key_disables_reorder() {
        // A ClientHello carrying a pre_shared_key (type 41) — i.e. a TLS
        // 1.3 resumption attempt — must be left byte-for-byte unchanged,
        // otherwise the PSK binder (computed before the mutator) would no
        // longer validate.
        let exts = vec![
            (0u16, vec![0xAA]),
            (43, vec![0x02, 0x03]),
            (51, vec![0xDE; 36]),
            (41, vec![0x00, 0x01]), // pre_shared_key, must be last anyway
        ];
        let original = build_client_hello(&[0x1301, 0x1302, 0x1303], &exts);
        for _ in 0..16 {
            let mut buf = original.clone();
            Fingerprint::Randomized.apply(&mut buf);
            assert_eq!(
                buf, original,
                "a PSK-resuming ClientHello must not be reordered"
            );
        }
    }

    #[test]
    fn malformed_buffer_left_untouched() {
        // Too short to even hold the session_id length byte.
        let mut tiny = vec![0x01, 0x00, 0x00, 0x05, 0x03, 0x03];
        let snapshot = tiny.clone();
        Fingerprint::Randomized.apply(&mut tiny);
        assert_eq!(tiny, snapshot, "malformed input must be left as-is");
    }
}
