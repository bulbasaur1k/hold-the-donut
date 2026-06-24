//! Native TLS ClientHello fragmentation — the in-process analogue of xray's
//! `freedom { fragment }`. Splits the first ClientHello into several smaller
//! TLS records so an SNI-matching DPI can't read the SNI from a single record.
//! De-throttles/unblocks SNI-throttled sites (e.g. YouTube on the RU node's
//! direct egress) without an external nfqws/NFQUEUE sidecar.
//!
//! Applied only on the freedom (direct) egress for plain-flow sessions: the
//! bytes written to the target socket start with the client app's own TLS
//! ClientHello, and we control the socket, so we can re-emit it fragmented.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Resolved fragmentation parameters (parsed from `[fragment]` config).
#[derive(Debug, Clone)]
pub struct FragmentParams {
    /// Fragment payload size range (bytes), inclusive.
    pub len: (u32, u32),
    /// Inter-fragment delay range (ms), inclusive.
    pub interval_ms: (u32, u32),
}

impl FragmentParams {
    fn pick(range: (u32, u32)) -> u32 {
        let (lo, hi) = range;
        if lo >= hi {
            lo
        } else {
            lo + (rand::random::<u32>() % (hi - lo + 1))
        }
    }
}

/// Read the first TLS record out of `prefix` followed by `reader`. Returns
/// `(record, extra)` — the complete first record (5-byte header + payload) and
/// any bytes read past it. If the stream ends early, returns whatever was read
/// as `record` with empty `extra` (the caller writes it through unfragmented).
pub async fn read_first_record<R: AsyncRead + Unpin>(
    prefix: &[u8],
    reader: &mut R,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = prefix.to_vec();
    while buf.len() < 5 {
        let mut tmp = [0u8; 2048];
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            return Ok((buf, Vec::new()));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total = 5 + rec_len;
    while buf.len() < total {
        let mut tmp = [0u8; 4096];
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if buf.len() > total {
        let extra = buf.split_off(total);
        Ok((buf, extra))
    } else {
        Ok((buf, Vec::new()))
    }
}

/// Write `record` to `w`. If it's a TLS ClientHello, re-emit its payload as
/// multiple smaller TLS records (`len`-byte chunks) with `interval` delays;
/// otherwise write it verbatim. A TLS handshake message may legally span
/// several records, so the destination reassembles it transparently.
pub async fn write_fragmented<W: AsyncWrite + Unpin>(
    w: &mut W,
    record: &[u8],
    p: &FragmentParams,
) -> io::Result<()> {
    // 0x16 = handshake record; payload[0] == 0x01 = ClientHello.
    let is_client_hello = record.len() >= 6 && record[0] == 0x16 && record[5] == 0x01;
    if !is_client_hello {
        w.write_all(record).await?;
        return Ok(());
    }

    let ver = [record[1], record[2]];
    let payload = &record[5..];
    let mut off = 0usize;
    while off < payload.len() {
        let chunk = (FragmentParams::pick(p.len) as usize).clamp(1, payload.len() - off);
        let slice = &payload[off..off + chunk];
        let hdr = [
            0x16,
            ver[0],
            ver[1],
            (slice.len() >> 8) as u8,
            (slice.len() & 0xff) as u8,
        ];
        w.write_all(&hdr).await?;
        w.write_all(slice).await?;
        w.flush().await?;
        off += chunk;
        if off < payload.len() {
            let d = FragmentParams::pick(p.interval_ms);
            if d > 0 {
                tokio::time::sleep(Duration::from_millis(d as u64)).await;
            }
        }
    }
    Ok(())
}

/// Build the fragmented form of a TLS ClientHello record synchronously: its
/// payload split into `len`-byte chunks, each re-emitted as its own TLS
/// handshake record. Non-ClientHello input is returned verbatim. (No
/// inter-fragment delay — pure record-splitting, for the streaming adapter.)
fn fragment_clienthello_to_vec(record: &[u8], p: &FragmentParams) -> Vec<u8> {
    if record.len() < 6 || record[0] != 0x16 || record[5] != 0x01 {
        return record.to_vec();
    }
    let ver = [record[1], record[2]];
    let payload = &record[5..];
    let mut out = Vec::with_capacity(record.len() + 16);
    let mut off = 0;
    while off < payload.len() {
        let chunk = (FragmentParams::pick(p.len) as usize).clamp(1, payload.len() - off);
        let slice = &payload[off..off + chunk];
        out.extend_from_slice(&[0x16, ver[0], ver[1], (slice.len() >> 8) as u8, (slice.len() & 0xff) as u8]);
        out.extend_from_slice(slice);
        off += chunk;
    }
    out
}

/// An `AsyncRead + AsyncWrite` adapter that fragments the **first** TLS
/// ClientHello written through it into several smaller TLS records, then passes
/// everything through. Wrap the freedom egress with it so the REALITY+Vision
/// data plane's de-tunnelled ClientHello (to YouTube / a throttled SNI) is
/// split in-process — a sidecar-free de-throttle. Reads are untouched.
pub struct FragmentWriter<S> {
    inner: S,
    params: FragmentParams,
    /// Accumulates the first record until it is complete or classified.
    acc: Vec<u8>,
    /// Fragmented/passthrough bytes still to drain to `inner`.
    out: Vec<u8>,
    out_pos: usize,
    /// First record handled — pure passthrough afterwards.
    done: bool,
}

impl<S> FragmentWriter<S> {
    pub fn new(inner: S, params: FragmentParams) -> Self {
        Self {
            inner,
            params,
            acc: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            done: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentWriter<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> FragmentWriter<S> {
    /// Drain `out` to `inner`; Ready(Ok) only when fully flushed.
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentWriter<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Flush any pending fragmented output before accepting more.
        if !me.out.is_empty() {
            match me.drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if me.done {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        me.acc.extend_from_slice(buf);
        let finalized: Option<Vec<u8>> = if me.acc.first() != Some(&0x16) {
            Some(std::mem::take(&mut me.acc))
        } else if me.acc.len() >= 5 {
            let total = 5 + (u16::from_be_bytes([me.acc[3], me.acc[4]]) as usize);
            if me.acc.len() >= total {
                let acc = std::mem::take(&mut me.acc);
                let mut out = fragment_clienthello_to_vec(&acc[..total], &me.params);
                out.extend_from_slice(&acc[total..]);
                Some(out)
            } else {
                None
            }
        } else {
            None
        };
        match finalized {
            Some(out) => {
                me.out = out;
                me.out_pos = 0;
                me.done = true;
                match me.drain(cx) {
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    _ => Poll::Ready(Ok(buf.len())),
                }
            }
            None => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // An incomplete first record must not be held back on flush.
        if !me.done && !me.acc.is_empty() {
            me.out = std::mem::take(&mut me.acc);
            me.out_pos = 0;
            me.done = true;
        }
        if !me.out.is_empty() {
            match me.drain(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.out.is_empty() {
            match me.drain(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fragments_clienthello_into_multiple_records() {
        // Synthetic ClientHello record: 0x16 0x03 0x01 <len> <payload(0x01...)>.
        let payload = vec![0x01u8; 300];
        let mut record = vec![0x16, 0x03, 0x01, (payload.len() >> 8) as u8, (payload.len() & 0xff) as u8];
        record.extend_from_slice(&payload);

        let p = FragmentParams {
            len: (50, 50),
            interval_ms: (0, 0),
        };
        let mut out: Vec<u8> = Vec::new();
        write_fragmented(&mut out, &record, &p).await.unwrap();

        // Reassemble the records and verify the payload survives unchanged,
        // split across more than one record.
        let mut i = 0;
        let mut reassembled = Vec::new();
        let mut records = 0;
        while i < out.len() {
            assert_eq!(out[i], 0x16, "every fragment is a handshake record");
            let l = u16::from_be_bytes([out[i + 3], out[i + 4]]) as usize;
            reassembled.extend_from_slice(&out[i + 5..i + 5 + l]);
            i += 5 + l;
            records += 1;
        }
        assert!(records > 1, "300B payload / 50B fragments must yield several records");
        assert_eq!(reassembled, payload, "fragmentation must preserve the ClientHello");
    }

    #[tokio::test]
    async fn fragment_writer_splits_first_clienthello_then_passthrough() {
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let mut fw = FragmentWriter::new(
            a,
            FragmentParams {
                len: (50, 50),
                interval_ms: (0, 0),
            },
        );

        let body = vec![0x01u8; 300];
        let mut hello = vec![0x16, 0x03, 0x01, (body.len() >> 8) as u8, (body.len() & 0xff) as u8];
        hello.extend_from_slice(&body);

        fw.write_all(&hello).await.unwrap();
        fw.write_all(b"after").await.unwrap();
        fw.flush().await.unwrap();
        drop(fw); // close the write half

        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();

        // Reassemble TLS records until the 300-byte ClientHello payload is whole.
        let mut i = 0;
        let mut records = 0;
        let mut reassembled = Vec::new();
        while reassembled.len() < body.len() {
            assert_eq!(got[i], 0x16, "fragment {records} is a handshake record");
            let l = u16::from_be_bytes([got[i + 3], got[i + 4]]) as usize;
            reassembled.extend_from_slice(&got[i + 5..i + 5 + l]);
            i += 5 + l;
            records += 1;
        }
        assert!(records > 1, "ClientHello must be split into multiple records");
        assert_eq!(reassembled, body, "fragmentation preserves the ClientHello");
        // The post-ClientHello bytes pass through verbatim.
        assert_eq!(&got[i..], b"after", "subsequent bytes are not fragmented");
    }

    #[tokio::test]
    async fn fragment_writer_passes_non_clienthello_through() {
        let (a, mut b) = tokio::io::duplex(4096);
        let mut fw = FragmentWriter::new(a, FragmentParams { len: (1, 1), interval_ms: (0, 0) });
        // App-data record (0x17) — not a ClientHello.
        fw.write_all(&[0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb]).await.unwrap();
        fw.flush().await.unwrap();
        drop(fw);
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, [0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb]);
    }

    #[tokio::test]
    async fn non_clienthello_is_written_verbatim() {
        let record = vec![0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb]; // app-data record
        let p = FragmentParams {
            len: (1, 1),
            interval_ms: (0, 0),
        };
        let mut out = Vec::new();
        write_fragmented(&mut out, &record, &p).await.unwrap();
        assert_eq!(out, record, "non-ClientHello passes through untouched");
    }
}
