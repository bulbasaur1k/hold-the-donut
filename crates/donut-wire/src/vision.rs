//! Vision (`xtls-rprx-vision`) padding codec.
//!
//! Byte-exact port of xray-core `proxy/proxy.go` `XtlsPadding` /
//! `XtlsUnpadding` (verified against v26.4.15 — see `docs/PROTOCOLS.md` §4).
//!
//! Wire shape of a padded frame:
//!
//! ```text
//! [UserUUID:16]   ← first frame only; the receiver keys off it to detect Vision
//! [command:1] [contentLen:2 BE] [paddingLen:2 BE] [content] [padding]
//! ```
//!
//! `command`: [`CMD_PADDING_CONTINUE`] (more frames), [`CMD_PADDING_END`] /
//! [`CMD_PADDING_DIRECT`] (last reshaped frame — everything after is copied
//! verbatim). Padding bytes are arbitrary; the receiver only skips them.
//!
//! This module is the pure codec. The TLS-handshake detection
//! (`trafficState`) that decides *when* to emit `End`/`Direct` and switch to
//! a raw splice lives in the Vision transport (M5.5).

/// More padded frames will follow.
pub const CMD_PADDING_CONTINUE: u8 = 0x00;
/// Last reshaped frame; switch to direct copy afterwards.
pub const CMD_PADDING_END: u8 = 0x01;
/// Switch the peer to direct copy immediately.
pub const CMD_PADDING_DIRECT: u8 = 0x02;

/// Max bytes of real content per frame (`contentLen` is a `u16`).
pub const MAX_CONTENT: usize = u16::MAX as usize;

/// Writer side: reshapes content into Vision padded frames. The first
/// frame produced is prefixed with the 16-byte user UUID.
#[derive(Debug, Clone)]
pub struct VisionPadder {
    uuid: [u8; 16],
    first: bool,
}

impl VisionPadder {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self { uuid, first: true }
    }

    /// Build one padded frame carrying `content` (≤ [`MAX_CONTENT`]) with
    /// `command` and `padding_len` trailing padding bytes (zeroed here; the
    /// receiver ignores their value).
    pub fn frame(&mut self, command: u8, content: &[u8], padding_len: u16) -> Vec<u8> {
        debug_assert!(content.len() <= MAX_CONTENT, "Vision content exceeds u16");
        let content_len = content.len() as u16;
        let mut out = Vec::with_capacity(16 + 5 + content.len() + padding_len as usize);
        if self.first {
            out.extend_from_slice(&self.uuid);
            self.first = false;
        }
        out.push(command);
        out.extend_from_slice(&content_len.to_be_bytes());
        out.extend_from_slice(&padding_len.to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len as usize, 0);
        out
    }
}

/// Reader side: strips Vision padding, recovering the original content.
///
/// Mirrors `XtlsUnpadding`'s per-direction state machine. Feed arbitrary
/// chunks to [`VisionUnpadder::push`]; recovered content is appended to the
/// caller's `out`. Once an `End`/`Direct` command is seen the unpadder
/// switches to verbatim passthrough.
#[derive(Debug, Clone)]
pub struct VisionUnpadder {
    uuid: [u8; 16],
    started: bool,
    direct: bool,
    reading_header: bool,
    remaining_content: usize,
    remaining_padding: usize,
    current_command: u8,
    pending: Vec<u8>,
}

impl VisionUnpadder {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            started: false,
            direct: false,
            reading_header: false,
            remaining_content: 0,
            remaining_padding: 0,
            current_command: CMD_PADDING_CONTINUE,
            pending: Vec::new(),
        }
    }

    /// `true` once the stream has switched to verbatim passthrough (an
    /// `End`/`Direct` frame was processed, or the leading bytes did not
    /// carry the Vision UUID).
    pub fn is_direct(&self) -> bool {
        self.direct
    }

    /// Process `input`, appending recovered content bytes to `out`.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) {
        if self.direct {
            out.extend_from_slice(input);
            return;
        }
        self.pending.extend_from_slice(input);

        if !self.started {
            // Need 16 (UUID) + at least the 5-byte header to commit.
            if self.pending.len() < 21 {
                return;
            }
            if self.pending[..16] == self.uuid {
                self.pending.drain(..16);
                self.started = true;
                self.reading_header = true;
            } else {
                // Not a Vision stream → verbatim passthrough.
                self.direct = true;
                out.append(&mut self.pending);
                return;
            }
        }

        let mut i = 0usize;
        loop {
            if self.reading_header {
                if self.pending.len() - i < 5 {
                    break;
                }
                let h = &self.pending[i..i + 5];
                self.current_command = h[0];
                self.remaining_content = u16::from_be_bytes([h[1], h[2]]) as usize;
                self.remaining_padding = u16::from_be_bytes([h[3], h[4]]) as usize;
                i += 5;
                self.reading_header = false;
            }

            if self.remaining_content > 0 {
                let avail = self.pending.len() - i;
                let n = self.remaining_content.min(avail);
                out.extend_from_slice(&self.pending[i..i + n]);
                i += n;
                self.remaining_content -= n;
                if self.remaining_content > 0 {
                    break; // need more input
                }
            }

            if self.remaining_padding > 0 {
                let avail = self.pending.len() - i;
                let n = self.remaining_padding.min(avail);
                i += n;
                self.remaining_padding -= n;
                if self.remaining_padding > 0 {
                    break; // need more input
                }
            }

            // Block fully consumed.
            if self.current_command == CMD_PADDING_CONTINUE {
                self.reading_header = true; // next block
            } else {
                self.direct = true;
                out.extend_from_slice(&self.pending[i..]);
                i = self.pending.len();
                break;
            }
        }
        self.pending.drain(..i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn unpad_all(frames: &[u8], chunk: usize) -> (Vec<u8>, bool) {
        let mut un = VisionUnpadder::new(UUID);
        let mut out = Vec::new();
        for c in frames.chunks(chunk.max(1)) {
            un.push(c, &mut out);
        }
        (out, un.is_direct())
    }

    #[test]
    fn first_frame_carries_uuid_then_subsequent_do_not() {
        let mut p = VisionPadder::new(UUID);
        let f1 = p.frame(CMD_PADDING_CONTINUE, b"hello", 3);
        let f2 = p.frame(CMD_PADDING_CONTINUE, b"world", 0);
        assert_eq!(&f1[..16], &UUID, "first frame is UUID-prefixed");
        // f1: 16 uuid + 5 header + 5 content + 3 padding
        assert_eq!(f1.len(), 16 + 5 + 5 + 3);
        // f2: 5 header + 5 content (no uuid, no padding)
        assert_eq!(f2.len(), 5 + 5);
        assert_eq!(f2[0], CMD_PADDING_CONTINUE);
        assert_eq!(&f2[1..3], &5u16.to_be_bytes());
    }

    #[test]
    fn round_trip_multi_block_then_end() {
        let mut p = VisionPadder::new(UUID);
        let mut wire = Vec::new();
        wire.extend(p.frame(CMD_PADDING_CONTINUE, b"alpha", 7));
        wire.extend(p.frame(CMD_PADDING_CONTINUE, b"-beta", 0));
        wire.extend(p.frame(CMD_PADDING_END, b"-gamma", 4));
        // Trailing direct bytes after the End frame.
        wire.extend_from_slice(b"DIRECTBYTES");

        for chunk in [1, 2, 3, 5, 7, 13, 1000] {
            let (out, direct) = unpad_all(&wire, chunk);
            assert_eq!(out, b"alpha-beta-gammaDIRECTBYTES", "chunk={chunk}");
            assert!(direct, "End frame must flip to direct; chunk={chunk}");
        }
    }

    #[test]
    fn wrong_uuid_is_verbatim_passthrough() {
        let mut p = VisionPadder::new([0xab; 16]); // different uuid
        let wire = p.frame(CMD_PADDING_CONTINUE, b"payload", 2);
        let (out, direct) = unpad_all(&wire, 4);
        assert!(direct, "non-matching UUID → passthrough");
        assert_eq!(out, wire, "bytes pass through unchanged");
    }

    #[test]
    fn empty_content_blocks() {
        let mut p = VisionPadder::new(UUID);
        let mut wire = Vec::new();
        wire.extend(p.frame(CMD_PADDING_CONTINUE, b"", 9)); // pure padding
        wire.extend(p.frame(CMD_PADDING_END, b"tail", 0));
        let (out, direct) = unpad_all(&wire, 3);
        assert_eq!(out, b"tail");
        assert!(direct);
    }

    #[test]
    fn direct_command_switches_immediately() {
        let mut p = VisionPadder::new(UUID);
        let mut wire = Vec::new();
        wire.extend(p.frame(CMD_PADDING_DIRECT, b"x", 0));
        wire.extend_from_slice(b"raw-after-direct");
        let (out, direct) = unpad_all(&wire, 2);
        assert_eq!(out, b"xraw-after-direct");
        assert!(direct);
    }
}
