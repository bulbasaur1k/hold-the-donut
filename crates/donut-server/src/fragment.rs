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
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
