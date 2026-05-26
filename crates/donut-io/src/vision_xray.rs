//! Faithful XTLS-Vision (`xtls-rprx-vision`) port — byte-compatible with
//! xray-core's `proxy/proxy.go`, so our RAW transport interoperates with a
//! real Xray VLESS client/server. See `docs/VISION_PROTOCOL.md` for the
//! ground-truth spec this mirrors.
//!
//! This module is the byte-exact **core** (padding codec + TLS filter +
//! state machines). The stream orchestration that wires it into the RAW
//! transport lives alongside (`VisionStream`).

#![allow(dead_code)] // wired into the raw transport in a follow-up step

use std::sync::{Arc, Mutex};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub const COMMAND_PADDING_END: u8 = 0x01;
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

const TLS_APP_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
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
                self.remaining_server_hello =
                    ((starts[3] as i32) << 8 | starts[4] as i32) + 5;
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

fn hex16(b: &[u8]) -> String {
    b.iter()
        .take(16)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
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

/// Server-side faithful Vision data-plane (RAW inbound). Bridges the
/// Vision-framed `tunnel` (donut↔Xray) to the plaintext `upstream`:
/// - **uplink** (client→server): un-pads via [`Unpadder`], filters the inner
///   ClientHello, writes plaintext to `upstream`.
/// - **downlink** (server→client): pads upstream bytes (UUID-prefixed first
///   block), filters the inner ServerHello → on inner TLS 1.3 it emits
///   `CommandPaddingDirect` and splices raw.
///
/// `uuid` is the authenticated VLESS user (`TrafficState.UserUUID`). Call
/// **after** the VLESS request is read and the VLESS response prefix written
/// (both raw, outside Vision).
pub async fn vision_server_copy<T, U>(tunnel: T, upstream: U, uuid: [u8; 16]) -> std::io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tr, mut tw) = tokio::io::split(tunnel);
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let shared = Arc::new(Mutex::new(FilterState::default()));

    // uplink: tunnel (padded by client) -> unpad + filter -> upstream
    let s_up = shared.clone();
    let uplink = async move {
        let mut unp = Unpadder::new(uuid);
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let content = unp.push(&buf[..n]);
            tracing::debug!(read = n, content = content.len(), direct = unp.direct(),
                head = %hex16(&content), "vision uplink -> upstream");
            if !content.is_empty() {
                {
                    let mut f = s_up.lock().expect("vision filter lock");
                    if f.number_to_filter > 0 {
                        f.filter(&content);
                    }
                }
                uw.write_all(&content).await?;
            }
        }
        let _ = uw.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    // downlink: upstream -> pad (UUID first) + filter (ServerHello -> Direct) -> tunnel
    let s_down = shared.clone();
    let downlink = async move {
        let mut uuid_once = Some(uuid);
        let mut is_padding = true;
        let mut direct = false;
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = ur.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            tracing::debug!(read = n, direct, head = %hex16(chunk), "vision downlink <- upstream");
            if direct {
                tw.write_all(chunk).await?;
                continue;
            }
            let (is_tls, enable_xtls) = {
                let mut f = s_down.lock().expect("vision filter lock");
                if f.number_to_filter > 0 {
                    f.filter(chunk);
                }
                (f.is_tls, f.enable_xtls)
            };
            if is_padding {
                let app_data = is_tls
                    && chunk.len() >= 6
                    && chunk.starts_with(&TLS_APP_DATA_START)
                    && is_complete_record(chunk);
                let command = if app_data {
                    is_padding = false;
                    if enable_xtls {
                        direct = true;
                        COMMAND_PADDING_DIRECT
                    } else {
                        COMMAND_PADDING_END
                    }
                } else {
                    COMMAND_PADDING_CONTINUE
                };
                let block = xtls_padding(chunk, command, &mut uuid_once, is_tls, &DEFAULT_SEED);
                tw.write_all(&block).await?;
            } else {
                tw.write_all(chunk).await?;
            }
        }
        let _ = tw.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    // join (not try_join): a half-close / error on one direction must not
    // cancel the other mid-flight, or the peer sees a premature reset.
    let (_up, _down) = tokio::join!(uplink, downlink);
    Ok(())
}

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
        wire.extend(xtls_padding(b"first-", COMMAND_PADDING_CONTINUE, &mut once, true, &DEFAULT_SEED));
        wire.extend(xtls_padding(b"second", COMMAND_PADDING_DIRECT, &mut once, false, &DEFAULT_SEED));
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
