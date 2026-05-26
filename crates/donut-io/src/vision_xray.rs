//! Faithful XTLS-Vision (`xtls-rprx-vision`) port — byte-compatible with
//! xray-core's `proxy/proxy.go`, so our RAW transport interoperates with a
//! real Xray VLESS client/server. See `docs/VISION_PROTOCOL.md` for the
//! ground-truth spec this mirrors.
//!
//! This module is the byte-exact **core** (padding codec + TLS filter +
//! state machines). The stream orchestration that wires it into the RAW
//! transport lives alongside (`VisionStream`).

use rand::Rng;

pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub const COMMAND_PADDING_END: u8 = 0x01;
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

const TLS_SERVER_HS_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_CLIENT_HS_START: [u8; 2] = [0x16, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_HS_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HS_TYPE_SERVER_HELLO: u8 = 0x02;

/// Xray `buf.Size`: padded-block byte budget.
pub const BUF_SIZE: usize = 8192;
/// Default padding seed `{900, 500, 900, 256}`.
pub const DEFAULT_SEED: [u32; 4] = [900, 500, 900, 256];

/// TLS_AES_128_CCM_8_SHA256 — the one TLS 1.3 suite Xray refuses to splice.
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// `XtlsPadding`: build one padded block. `content` is the payload (may be
/// empty for the VLESS-header-hiding first block). `uuid_once` is consumed
/// (set to `None`) after it is prepended to the very first block. Returns
/// the wire bytes: `[uuid?][command][contentLen:2][padLen:2][content][pad]`.
pub fn xtls_padding(
    content: &[u8],
    command: u8,
    uuid_once: &mut Option<[u8; 16]>,
    long_padding: bool,
    seed: &[u32; 4],
) -> Vec<u8> {
    let content_len = content.len() as i64;
    let mut rng = rand::thread_rng();
    let mut padding_len: i64 = if content_len < seed[0] as i64 && long_padding {
        rng.gen_range(0..seed[1] as i64) + seed[2] as i64 - content_len
    } else {
        rng.gen_range(0..seed[3] as i64)
    };
    let cap = BUF_SIZE as i64 - 21 - content_len;
    if padding_len > cap {
        padding_len = cap;
    }
    if padding_len < 0 {
        padding_len = 0;
    }
    let mut out = Vec::with_capacity(16 + 5 + content.len() + padding_len as usize);
    if let Some(uuid) = uuid_once.take() {
        out.extend_from_slice(&uuid);
    }
    out.push(command);
    out.push((content_len >> 8) as u8);
    out.push(content_len as u8);
    out.push((padding_len >> 8) as u8);
    out.push(padding_len as u8);
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len as usize, 0);
    out
}

/// Per-direction unpadding state (init: all `-1`). Buffers across `push`
/// calls so it is robust to a stream delivering partial reads (the initial
/// 21-byte UUID+header detection may span chunks).
#[derive(Debug, Clone)]
pub struct Unpadder {
    user_uuid: [u8; 16],
    started: bool,
    passthrough: bool,
    pending: Vec<u8>,
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: i32,
    finished: bool,
    direct: bool,
}

impl Unpadder {
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            started: false,
            passthrough: false,
            pending: Vec::new(),
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            finished: false,
            direct: false,
        }
    }

    /// True once an End/Direct block has been seen (padding is over).
    pub fn finished(&self) -> bool {
        self.finished
    }
    /// True once a Direct block has been seen (switch to raw splice).
    pub fn direct(&self) -> bool {
        self.direct
    }

    /// `XtlsUnpadding`: feed received bytes, return the de-padded content.
    /// Trailing raw bytes after an End/Direct block (the post-Vision phase)
    /// are passed through verbatim.
    pub fn push(&mut self, input: &[u8]) -> Vec<u8> {
        // Past the final block (End/Direct) → raw passthrough.
        if self.finished {
            return input.to_vec();
        }
        // Non-padded stream detected earlier → raw passthrough.
        if self.passthrough {
            return input.to_vec();
        }
        // Initial state: buffer until we can test the 16-byte UUID + 5-byte
        // command header atomically.
        if !self.started {
            self.pending.extend_from_slice(input);
            if self.pending.len() < 21 {
                return Vec::new();
            }
            if self.pending[..16] != self.user_uuid {
                // Not a Vision-padded stream — pass everything through.
                self.passthrough = true;
                return std::mem::take(&mut self.pending);
            }
            self.started = true;
            self.remaining_command = 5;
            let rest = self.pending.split_off(16);
            self.pending.clear();
            return self.process(&rest);
        }
        self.process(input)
    }

    fn process(&mut self, input: &[u8]) -> Vec<u8> {
        let mut b: &[u8] = input;
        let mut out = Vec::with_capacity(input.len());
        while !b.is_empty() {
            if self.remaining_command > 0 {
                let data = b[0];
                b = &b[1..];
                match self.remaining_command {
                    5 => self.current_command = data as i32,
                    4 => self.remaining_content = (data as i32) << 8,
                    3 => self.remaining_content |= data as i32,
                    2 => self.remaining_padding = (data as i32) << 8,
                    1 => self.remaining_padding |= data as i32,
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let n = (self.remaining_content as usize).min(b.len());
                out.extend_from_slice(&b[..n]);
                b = &b[n..];
                self.remaining_content -= n as i32;
            } else {
                let n = (self.remaining_padding as usize).min(b.len());
                b = &b[n..];
                self.remaining_padding -= n as i32;
            }

            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == 0 {
                    self.remaining_command = 5; // next Continue block
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    self.finished = true;
                    if self.current_command == 2 {
                        self.direct = true;
                    }
                    if !b.is_empty() {
                        out.extend_from_slice(b); // post-Vision raw bytes
                    }
                    break;
                }
            }
        }
        out
    }
}

/// Global + per-direction TLS-detection state (`XtlsFilterTls`).
#[derive(Debug, Clone)]
pub struct FilterState {
    pub number_to_filter: i32,
    pub enable_xtls: bool,
    pub is_tls12_or_above: bool,
    pub is_tls: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
}

impl Default for FilterState {
    fn default() -> Self {
        Self {
            number_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: 0,
        }
    }
}

impl FilterState {
    /// `XtlsFilterTls`: inspect one buffer; detect ClientHello/ServerHello and
    /// whether the inner connection is TLS 1.3 (→ `enable_xtls`, → splice).
    pub fn filter(&mut self, b: &[u8]) {
        self.number_to_filter -= 1;
        if b.len() >= 6 {
            let starts = &b[..6];
            if starts[..3] == TLS_SERVER_HS_START && starts[5] == TLS_HS_TYPE_SERVER_HELLO {
                self.remaining_server_hello = ((starts[3] as i32) << 8 | starts[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = b[43] as usize;
                    if 43 + session_id_len + 3 <= b.len() {
                        self.cipher = (b[43 + session_id_len + 1] as u16) << 8
                            | b[43 + session_id_len + 2] as u16;
                    }
                }
            } else if starts[..2] == TLS_CLIENT_HS_START && starts[5] == TLS_HS_TYPE_CLIENT_HELLO {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i32;
            if contains(&b[..end], &TLS13_SUPPORTED_VERSIONS) {
                if self.cipher != TLS_AES_128_CCM_8_SHA256 {
                    self.enable_xtls = true;
                }
                self.number_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.number_to_filter = 0;
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Is the buffer a sequence of complete TLS app-data records (`IsCompleteRecord`)?
pub fn is_complete_record(mut b: &[u8]) -> bool {
    while !b.is_empty() {
        if b.len() < 5 {
            return false;
        }
        if b[0] != 0x17 || b[1] != 0x03 || b[2] != 0x03 {
            return false;
        }
        let rec_len = (b[3] as usize) << 8 | b[4] as usize;
        let total = 5 + rec_len;
        if b.len() < total {
            return false;
        }
        b = &b[total..];
    }
    true
}

// The server-side data-plane that wires these primitives into the `raw`
// transport — including the faithful raw-socket splice after
// `CommandPaddingDirect` — lives in `donut-server` (`vision_xray_splice`),
// because it needs the rustls server connection and the TCP socket, neither of
// which `donut-io` depends on. This module stays I/O-light: just the codec.

#[cfg(test)]
mod tests {
    use super::*;

    /// One padded block round-trips its content (with the UUID prefix).
    #[test]
    fn pad_unpad_single_block() {
        let uuid = [7u8; 16];
        let content = b"hello vision payload".to_vec();
        let mut once = Some(uuid);
        let block = xtls_padding(
            &content,
            COMMAND_PADDING_END,
            &mut once,
            true,
            &DEFAULT_SEED,
        );
        assert!(once.is_none(), "uuid consumed");
        assert_eq!(&block[..16], &uuid, "first block carries uuid");

        let mut un = Unpadder::new(uuid);
        let got = un.push(&block);
        assert_eq!(got, content);
        assert!(un.finished());
        assert!(!un.direct());
    }

    /// Continue + End across two blocks, fed byte-by-byte (fragmentation).
    #[test]
    fn pad_unpad_multi_block_fragmented() {
        let uuid = [9u8; 16];
        let mut once = Some(uuid);
        let mut wire = Vec::new();
        wire.extend(xtls_padding(
            b"first-",
            COMMAND_PADDING_CONTINUE,
            &mut once,
            true,
            &DEFAULT_SEED,
        ));
        wire.extend(xtls_padding(
            b"second",
            COMMAND_PADDING_DIRECT,
            &mut once,
            false,
            &DEFAULT_SEED,
        ));
        // trailing raw bytes after the Direct block (post-Vision splice phase)
        wire.extend_from_slice(b"RAWTAIL");

        let mut un = Unpadder::new(uuid);
        let mut got = Vec::new();
        for chunk in wire.chunks(1) {
            got.extend(un.push(chunk));
        }
        assert_eq!(got, b"first-secondRAWTAIL");
        assert!(un.finished());
        assert!(un.direct());
    }

    /// Regression for xray-core #5961 (`panic: slice bounds out of range` in
    /// XtlsPadding/Unpadding when a block header declares a content/padding
    /// length larger than the bytes actually delivered). Our [`Unpadder`]
    /// consumes `min(declared_remaining, available)` per `push`, so a lying or
    /// truncated header must never panic — it just streams what's there and
    /// waits for the rest.
    #[test]
    fn unpadder_never_panics_on_oversized_declared_lengths() {
        let uuid = [3u8; 16];
        // Hand-craft a first block: [uuid][cmd=Continue][contentLen=0xFFFF]
        // [padLen=0xFFFF] but then only a few content bytes — far fewer than
        // the header claims.
        let mut wire = Vec::new();
        wire.extend_from_slice(&uuid);
        wire.push(COMMAND_PADDING_CONTINUE);
        wire.extend_from_slice(&[0xFF, 0xFF]); // contentLen = 65535
        wire.extend_from_slice(&[0xFF, 0xFF]); // padLen = 65535
        wire.extend_from_slice(b"only-a-little"); // 13 bytes, not 65535

        let mut un = Unpadder::new(uuid);
        // Feed byte-by-byte (worst-case fragmentation): must not panic.
        let mut out = Vec::new();
        for chunk in wire.chunks(1) {
            out.extend(un.push(chunk));
        }
        // It emits exactly the content bytes that arrived, still expecting more.
        assert_eq!(out, b"only-a-little");
        assert!(!un.finished(), "block not complete — header promised more");

        // A non-Vision stream (no UUID prefix) must pass through, not panic.
        let mut un2 = Unpadder::new([1u8; 16]);
        let pass = un2.push(&[2u8; 64]); // 64 bytes, first 16 != uuid
        assert_eq!(pass, vec![2u8; 64]);
    }

    #[test]
    fn filter_detects_tls13_serverhello() {
        // Minimal-ish TLS 1.3 ServerHello with the supported_versions ext.
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x50]; // record hdr, len=0x50
        sh.push(0x02); // [5] = ServerHello handshake type
        sh.resize(43, 0x00); // pad up to session-id length byte
        sh.push(0x00); // sessionIdLen = 0
        sh.extend_from_slice(&[0x13, 0x01]); // cipher = TLS_AES_128_GCM_SHA256
        sh.extend_from_slice(&TLS13_SUPPORTED_VERSIONS); // the 1.3 marker
        sh.resize(85, 0x00);

        let mut f = FilterState::default();
        f.filter(&sh);
        assert!(f.is_tls);
        assert!(f.is_tls12_or_above);
        assert!(f.enable_xtls, "TLS 1.3 (non-CCM8) must enable xtls/splice");
    }
}
