//! XTLS-Vision-style first-packet padding for the RAW transport
//! (`FlowKind::Extended` / `"xtls-rprx-vision"`).
//!
//! The tunnel between donut-client and donut-server rides inside an outer
//! TLS 1.3 session. When the user's own traffic is TLS (HTTPS), the inner
//! handshake produces a recognizable sequence of record lengths that a
//! censor can fingerprint *through* the outer TLS ("TLS-in-TLS"
//! detection). Vision masks this by wrapping the first few application
//! writes in each direction with random-length padding, then dropping the
//! framing entirely and copying raw ("direct" mode) for the rest of the
//! connection — the same idea as Xray's `xtls-rprx-vision`.
//!
//! Frame (while padding is active):
//! ```text
//!   [u8 kind][u16 BE data_len][data ...][u16 BE pad_len][pad ...]
//! ```
//! `kind = 0` (MORE) keeps framing; `kind = 1` (END) is the last framed
//! packet — both sides switch to raw passthrough afterwards.
//!
//! This is *our* equivalent: both ends are donut, so it need not interop
//! with upstream Xray's exact `xtls-rprx-vision` wire format.

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const KIND_MORE: u8 = 0;
const KIND_END: u8 = 1;
const MAX_DATA: usize = 16 * 1024;

/// Vision padding parameters.
#[derive(Debug, Clone, Copy)]
pub struct VisionConfig {
    /// Number of leading frames to pad before switching to raw copy.
    pub pad_frames: usize,
    /// Maximum random padding length per frame (bytes).
    pub max_pad: usize,
}

impl Default for VisionConfig {
    fn default() -> Self {
        Self {
            pad_frames: 4,
            max_pad: 900,
        }
    }
}

/// Run Vision over a duplex `tunnel` (the donut↔donut stream) bridged to a
/// raw `target` (the upstream destination on the server, or the local
/// SOCKS app on the client). Symmetric: each end encodes target→tunnel and
/// decodes tunnel→target, so the same call serves both sides.
pub async fn copy_bidirectional<T, G>(
    tunnel: T,
    target: G,
    cfg: VisionConfig,
) -> std::io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
    G: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tr, mut tw) = tokio::io::split(tunnel);
    let (mut gr, mut gw) = tokio::io::split(target);
    let enc = encode_copy(&mut gr, &mut tw, cfg);
    let dec = decode_copy(&mut tr, &mut gw);
    tokio::try_join!(enc, dec)?;
    Ok(())
}

/// Copy `src` (raw) → `dst` (tunnel), wrapping the first `cfg.pad_frames`
/// chunks in padded Vision frames, then copying raw.
pub async fn encode_copy<R, W>(src: &mut R, dst: &mut W, cfg: VisionConfig) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let pad_frames = cfg.pad_frames.max(1);
    let mut buf = vec![0u8; MAX_DATA];
    let mut frames = 0usize;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            // EOF before we reached pad_frames: emit a terminal END so the
            // peer leaves framed mode, then close.
            if frames < pad_frames {
                write_frame(dst, KIND_END, &[], pad_len(&cfg)).await?;
            }
            dst.flush().await?;
            let _ = dst.shutdown().await;
            return Ok(());
        }
        frames += 1;
        let last = frames >= pad_frames;
        let kind = if last { KIND_END } else { KIND_MORE };
        write_frame(dst, kind, &buf[..n], pad_len(&cfg)).await?;
        dst.flush().await?;
        if last {
            // Raw passthrough for the remainder of this direction.
            tokio::io::copy(src, dst).await?;
            dst.flush().await?;
            let _ = dst.shutdown().await;
            return Ok(());
        }
    }
}

/// Copy `src` (tunnel) → `dst` (raw), unwrapping Vision frames until the
/// END frame, then copying raw.
pub async fn decode_copy<R, W>(src: &mut R, dst: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut hdr = [0u8; 5];
        match src.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                let _ = dst.shutdown().await;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        let kind = hdr[0];
        let data_len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        let pad_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if data_len > 0 {
            let mut data = vec![0u8; data_len];
            src.read_exact(&mut data).await?;
            dst.write_all(&data).await?;
            dst.flush().await?;
        }
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            src.read_exact(&mut pad).await?;
        }
        if kind == KIND_END {
            tokio::io::copy(src, dst).await?;
            dst.flush().await?;
            let _ = dst.shutdown().await;
            return Ok(());
        }
    }
}

fn pad_len(cfg: &VisionConfig) -> usize {
    if cfg.max_pad == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=cfg.max_pad)
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    dst: &mut W,
    kind: u8,
    data: &[u8],
    pad: usize,
) -> std::io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = kind;
    hdr[1..3].copy_from_slice(&(data.len() as u16).to_be_bytes());
    hdr[3..5].copy_from_slice(&(pad as u16).to_be_bytes());
    dst.write_all(&hdr).await?;
    if !data.is_empty() {
        dst.write_all(data).await?;
    }
    if pad > 0 {
        // Content is irrelevant (it rides inside the outer TLS); the
        // length is what masks the inner handshake's record pattern.
        let padding = vec![0u8; pad];
        dst.write_all(&padding).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full encode→decode round-trip must reproduce the byte stream
    /// regardless of padding (covers both framed and raw phases).
    #[tokio::test]
    async fn vision_roundtrip_preserves_bytes() {
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();

        // src(raw) → [encode] → pipe → [decode] → sink(raw)
        let (mut enc_dst, dec_src) = tokio::io::duplex(64 * 1024);
        let mut src = std::io::Cursor::new(payload.clone());

        let writer = tokio::spawn(async move {
            encode_copy(&mut src, &mut enc_dst, VisionConfig::default())
                .await
                .unwrap();
        });

        let mut dec_src = dec_src;
        let mut sink: Vec<u8> = Vec::new();
        decode_copy(&mut dec_src, &mut sink).await.unwrap();
        writer.await.unwrap();

        assert_eq!(sink, payload, "decoded stream must equal the original");
    }

    #[tokio::test]
    async fn vision_handles_short_stream() {
        // Fewer bytes than pad_frames frames — exercises the early END.
        let payload = b"hi".to_vec();
        let (mut enc_dst, mut dec_src) = tokio::io::duplex(4096);
        let mut src = std::io::Cursor::new(payload.clone());
        let writer = tokio::spawn(async move {
            encode_copy(&mut src, &mut enc_dst, VisionConfig::default()).await
        });
        let mut sink: Vec<u8> = Vec::new();
        decode_copy(&mut dec_src, &mut sink).await.unwrap();
        writer.await.unwrap().unwrap();
        assert_eq!(sink, payload);
    }
}
