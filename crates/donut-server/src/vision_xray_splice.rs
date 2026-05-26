//! Faithful XTLS-Vision splice for the `raw` transport.
//!
//! The padding codec lives in [`donut_io::vision_xray`]; this module owns the
//! *stream* side that the codec can't: the splice. After `CommandPaddingDirect`
//! a real Xray client stops using the outer TLS and reads/writes the **raw TCP**
//! socket (the inner TLS records flow as-is — "X"TLS avoids TLS-in-TLS double
//! encryption). To interoperate we must do the same: drive the outer rustls
//! session ourselves so that, at the Direct transition, we can hand the raw
//! socket to a plain copy and bypass rustls.
//!
//! The trick that makes this safe over rustls (which, unlike Go's `tls.Conn`,
//! exposes no buffered-input accessor) is to feed rustls **exactly one outer-TLS
//! record at a time**, parsed from the 5-byte plaintext record header. rustls
//! then never over-reads past the Direct record, so whatever is left in our TCP
//! buffer at the splice point is cleanly raw inner-TLS, ready to forward.

use std::io::{self, Read, Write};
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use rustls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use donut_io::vision_xray::{
    is_complete_record, xtls_padding, FilterState, Unpadder, COMMAND_PADDING_CONTINUE,
    COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, DEFAULT_SEED,
};

const TLS_APP_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const READ_CHUNK: usize = 16 * 1024;

/// A rustls server connection driven manually over a [`TcpStream`], one
/// outer-TLS record at a time, so the Vision data phase can splice to raw TCP
/// without losing bytes to rustls's internal read-ahead.
pub struct RecordTlsServer {
    tcp: TcpStream,
    conn: ServerConnection,
    /// Raw TCP bytes read but not yet consumed as complete outer-TLS records.
    inbuf: BytesMut,
}

impl RecordTlsServer {
    pub fn new(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<Self> {
        let conn = ServerConnection::new(config).map_err(io::Error::other)?;
        Ok(Self {
            tcp,
            conn,
            inbuf: BytesMut::with_capacity(READ_CHUNK),
        })
    }

    /// Pull more bytes from the socket into `inbuf`. Returns `false` on EOF.
    async fn fill(&mut self) -> io::Result<bool> {
        let mut tmp = [0u8; READ_CHUNK];
        let n = self.tcp.read(&mut tmp).await?;
        if n == 0 {
            return Ok(false);
        }
        self.inbuf.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    /// Ensure `inbuf` holds at least one complete outer-TLS record; returns its
    /// total length (5 + body). `Ok(None)` on a clean EOF at a record boundary.
    async fn ensure_one_record(&mut self) -> io::Result<Option<usize>> {
        loop {
            if self.inbuf.len() >= 5 {
                let body = ((self.inbuf[3] as usize) << 8) | self.inbuf[4] as usize;
                let total = 5 + body;
                if self.inbuf.len() >= total {
                    return Ok(Some(total));
                }
            }
            if !self.fill().await? {
                if self.inbuf.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof mid outer-TLS record",
                ));
            }
        }
    }

    /// Feed the first `total` bytes of `inbuf` (exactly one record) to rustls,
    /// then drop them from `inbuf`.
    fn feed_record(&mut self, total: usize) -> io::Result<()> {
        let mut cur = io::Cursor::new(&self.inbuf[..total]);
        while (cur.position() as usize) < total {
            let n = self.conn.read_tls(&mut cur)?;
            if n == 0 {
                break;
            }
        }
        self.inbuf.advance(total);
        Ok(())
    }

    /// Flush everything rustls wants to send out to the socket.
    async fn flush_tls(&mut self) -> io::Result<()> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut out)?;
        }
        if !out.is_empty() {
            self.tcp.write_all(&out).await?;
            self.tcp.flush().await?;
        }
        Ok(())
    }

    /// Complete the TLS handshake, feeding one record at a time.
    pub async fn handshake(&mut self) -> io::Result<()> {
        loop {
            self.flush_tls().await?;
            if !self.conn.is_handshaking() {
                return Ok(());
            }
            let total = match self.ensure_one_record().await? {
                Some(t) => t,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "eof during handshake",
                    ))
                }
            };
            self.feed_record(total)?;
            self.conn
                .process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
    }

    /// Read and decrypt exactly one outer-TLS record. Returns its plaintext
    /// (empty `Vec` on clean EOF; a CCS/handshake record may also decrypt to
    /// no application plaintext).
    pub async fn read_record(&mut self) -> io::Result<Vec<u8>> {
        let total = match self.ensure_one_record().await? {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        self.feed_record(total)?;
        let state = self
            .conn
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.flush_tls().await?;
        let want = state.plaintext_bytes_to_read();
        let mut out = vec![0u8; want];
        let mut got = 0;
        while got < want {
            let n = self.conn.reader().read(&mut out[got..])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        out.truncate(got);
        Ok(out)
    }

    /// Encrypt and send plaintext through the outer TLS (Vision padded phase).
    pub async fn write_plaintext(&mut self, data: &[u8]) -> io::Result<()> {
        self.conn.writer().write_all(data)?;
        self.flush_tls().await?;
        Ok(())
    }

    /// Raw read for the post-splice phase: drains the leftover `inbuf` first,
    /// then reads the socket directly.
    pub async fn read_raw(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.inbuf.is_empty() {
            let n = self.inbuf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.inbuf[..n]);
            self.inbuf.advance(n);
            return Ok(n);
        }
        self.tcp.read(buf).await
    }

    /// Raw write for the post-splice phase, bypassing rustls. Callers must have
    /// flushed the outer TLS first (the Direct block goes through
    /// [`write_plaintext`], which flushes).
    pub async fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.tcp.write_all(data).await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.tcp.shutdown().await
    }

    /// Consume into the raw socket plus any not-yet-forwarded inbound bytes
    /// (raw inner-TLS that arrived past the Direct record).
    pub fn into_raw(self) -> (TcpStream, BytesMut) {
        (self.tcp, self.inbuf)
    }
}

/// Plaintext bidirectional relay over a manual outer-TLS [`RecordTlsServer`]
/// — used for `flow=none` clients (no Vision/splice) and for self-stealing a
/// non-VLESS probe to the decoy. Everything stays inside the outer TLS.
/// `initial_to_target` is any plaintext already read that belongs to `target`.
pub async fn tls_plain_relay(
    mut tunnel: RecordTlsServer,
    mut target: TcpStream,
    initial_to_target: Vec<u8>,
) -> io::Result<()> {
    if !initial_to_target.is_empty() {
        target.write_all(&initial_to_target).await?;
    }
    let mut tunnel_done = false;
    let mut target_done = false;
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        tokio::select! {
            r = tunnel.read_record(), if !tunnel_done => {
                let pt = r?;
                if pt.is_empty() {
                    tunnel_done = true;
                    let _ = target.shutdown().await;
                    continue;
                }
                target.write_all(&pt).await?;
            }
            r = target.read(&mut buf), if !target_done => {
                let n = r?;
                if n == 0 {
                    target_done = true;
                    let _ = tunnel.shutdown().await;
                    continue;
                }
                tunnel.write_plaintext(&buf[..n]).await?;
            }
            else => break,
        }
        if tunnel_done && target_done {
            break;
        }
    }
    Ok(())
}

/// One uplink read, in whichever mode the tunnel is in. Kept as a single
/// future so `select!` borrows `tunnel` only once (the two modes can't be
/// separate branches — the borrow checker ignores the runtime guards).
enum UplinkRead {
    /// Padded phase: decrypted plaintext of one outer-TLS record (empty = EOF).
    Record(Vec<u8>),
    /// Spliced phase: `n` raw bytes in the shared buffer (0 = EOF).
    Raw(usize),
}

async fn read_uplink(
    tunnel: &mut RecordTlsServer,
    spliced: bool,
    rawbuf: &mut [u8],
) -> io::Result<UplinkRead> {
    if spliced {
        Ok(UplinkRead::Raw(tunnel.read_raw(rawbuf).await?))
    } else {
        Ok(UplinkRead::Record(tunnel.read_record().await?))
    }
}

/// Server-side faithful Vision data-plane over `raw`, with the real splice.
///
/// `tunnel` is the (already-handshaked) outer-TLS connection to the client,
/// driven manually so we can bypass it on splice. `leftover` is plaintext the
/// caller already decrypted past the VLESS request (the start of the first
/// Vision block). `upstream` is the plaintext target connection. `uuid` is the
/// authenticated VLESS user.
pub async fn vision_server_splice(
    mut tunnel: RecordTlsServer,
    mut upstream: TcpStream,
    leftover: Vec<u8>,
    uuid: [u8; 16],
) -> io::Result<()> {
    let mut filter = FilterState::default();

    // uplink (client -> server): unpad + filter -> upstream
    let mut unp = Unpadder::new(uuid);
    let mut uplink_spliced = false;
    let mut uplink_done = false;

    // downlink (server -> client): pad (UUID first) + filter -> tunnel
    let mut uuid_once = Some(uuid);
    let mut is_padding = true;
    let mut downlink_spliced = false;
    let mut downlink_done = false;

    // Replay the leftover plaintext through the uplink unpadder first.
    if !leftover.is_empty() {
        let content = unp.push(&leftover);
        if !content.is_empty() {
            if filter.number_to_filter > 0 {
                filter.filter(&content);
            }
            upstream.write_all(&content).await?;
        }
        if unp.direct() {
            uplink_spliced = true;
        }
    }

    let mut ubuf = vec![0u8; READ_CHUNK];
    let mut dbuf = vec![0u8; READ_CHUNK];

    loop {
        if uplink_spliced && downlink_spliced {
            break;
        }
        tokio::select! {
            // ---- uplink (client -> server): padded records, then raw ----
            r = read_uplink(&mut tunnel, uplink_spliced, &mut ubuf), if !uplink_done => {
                match r? {
                    UplinkRead::Record(pt) => {
                        if pt.is_empty() {
                            uplink_done = true;
                            let _ = upstream.shutdown().await;
                            continue;
                        }
                        let content = unp.push(&pt);
                        if !content.is_empty() {
                            if filter.number_to_filter > 0 {
                                filter.filter(&content);
                            }
                            upstream.write_all(&content).await?;
                        }
                        if unp.direct() {
                            uplink_spliced = true;
                        }
                    }
                    UplinkRead::Raw(n) => {
                        if n == 0 {
                            uplink_done = true;
                            let _ = upstream.shutdown().await;
                            continue;
                        }
                        upstream.write_all(&ubuf[..n]).await?;
                    }
                }
            }
            // ---- downlink: read from upstream ----
            r = upstream.read(&mut dbuf), if !downlink_done => {
                let n = r?;
                if n == 0 {
                    downlink_done = true;
                    let _ = tunnel.shutdown().await;
                    continue;
                }
                let chunk = &dbuf[..n];
                if downlink_spliced {
                    tunnel.write_raw(chunk).await?;
                    continue;
                }
                if filter.number_to_filter > 0 {
                    filter.filter(chunk);
                }
                if is_padding {
                    let app_data = filter.is_tls
                        && chunk.len() >= 6
                        && chunk.starts_with(&TLS_APP_DATA_START)
                        && is_complete_record(chunk);
                    let command = if app_data {
                        is_padding = false;
                        if filter.enable_xtls {
                            COMMAND_PADDING_DIRECT
                        } else {
                            COMMAND_PADDING_END
                        }
                    } else {
                        COMMAND_PADDING_CONTINUE
                    };
                    let block = xtls_padding(chunk, command, &mut uuid_once, filter.is_tls, &DEFAULT_SEED);
                    tunnel.write_plaintext(&block).await?;
                    if command == COMMAND_PADDING_DIRECT {
                        // The Direct block is flushed through rustls; everything
                        // after it goes raw to the socket.
                        downlink_spliced = true;
                    }
                } else {
                    // Past End (non-TLS-1.3 inner): keep relaying through the
                    // outer TLS, matching the client which did not splice.
                    tunnel.write_plaintext(chunk).await?;
                }
            }
            else => break,
        }

        if uplink_done && downlink_done {
            break;
        }
    }

    // Both directions spliced → raw inner-TLS flows untouched. Hand off to a
    // full-duplex raw copy (forward the not-yet-sent uplink leftover first).
    if uplink_spliced && downlink_spliced && !(uplink_done && downlink_done) {
        let (mut tcp, leftover) = tunnel.into_raw();
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await;
        let _ = tcp.shutdown().await;
        let _ = upstream.shutdown().await;
    }
    Ok(())
}
