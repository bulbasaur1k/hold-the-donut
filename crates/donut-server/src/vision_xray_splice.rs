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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use rustls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use donut_io::vision_xray::{
    is_complete_record, xtls_padding, FilterState, Unpadder, COMMAND_PADDING_CONTINUE,
    COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, DEFAULT_SEED,
};

use crate::metrics::Metrics;

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
    /// Total raw bytes ever read from the socket. Lets a handshake failure be
    /// classified: `0` means the peer reset/closed before sending a single
    /// byte (an ordinary port scan), `> 0` means it spoke some TLS first.
    read_total: u64,
}

impl RecordTlsServer {
    pub fn new(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<Self> {
        let conn = ServerConnection::new(config).map_err(io::Error::other)?;
        Ok(Self {
            tcp,
            conn,
            inbuf: BytesMut::with_capacity(READ_CHUNK),
            read_total: 0,
        })
    }

    /// Total raw bytes read from the peer so far (for failure triage).
    pub fn bytes_read(&self) -> u64 {
        self.read_total
    }

    /// Pull more bytes from the socket into `inbuf`. Returns `false` on EOF.
    async fn fill(&mut self) -> io::Result<bool> {
        let mut tmp = [0u8; READ_CHUNK];
        let n = self.tcp.read(&mut tmp).await?;
        if n == 0 {
            return Ok(false);
        }
        self.read_total += n as u64;
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

    /// Read and decrypt one outer-TLS record, distinguishing a clean EOF
    /// (`Ok(None)`) from a record that carried no application plaintext —
    /// e.g. a post-handshake KeyUpdate — which yields `Ok(Some(vec![]))`.
    ///
    /// Loops over the tunnel MUST treat only `None` as "done": treating an
    /// empty `Vec` as EOF tears the session down on a stray KeyUpdate (and,
    /// worse, spins at 100% CPU if the loop keeps re-polling a real EOF that
    /// returns instantly forever).
    pub async fn read_record_opt(&mut self) -> io::Result<Option<Vec<u8>>> {
        let total = match self.ensure_one_record().await? {
            Some(t) => t,
            None => return Ok(None),
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
        Ok(Some(out))
    }

    /// Read one outer-TLS record's plaintext; empty `Vec` on clean EOF *or* on
    /// a record with no application bytes. Prefer [`read_record_opt`] in loops
    /// where the EOF/empty distinction matters.
    pub async fn read_record(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.read_record_opt().await?.unwrap_or_default())
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
/// `metrics` counts proxied bytes when `Some` (the flow=none tunnel path);
/// pass `None` for decoy/self-steal relays so they don't inflate tunnel bytes.
pub async fn tls_plain_relay(
    mut tunnel: RecordTlsServer,
    mut target: TcpStream,
    initial_to_target: Vec<u8>,
    metrics: Option<&Metrics>,
) -> io::Result<()> {
    if !initial_to_target.is_empty() {
        target.write_all(&initial_to_target).await?;
        if let Some(m) = metrics {
            m.add_bytes(initial_to_target.len() as u64, 0);
        }
    }
    let mut tunnel_done = false;
    let mut target_done = false;
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        tokio::select! {
            r = tunnel.read_record_opt(), if !tunnel_done => {
                match r? {
                    None => {
                        tunnel_done = true;
                        let _ = target.shutdown().await;
                        continue;
                    }
                    // Empty (no-app-data) record, e.g. KeyUpdate — not EOF.
                    Some(pt) => {
                        if !pt.is_empty() {
                            target.write_all(&pt).await?;
                            if let Some(m) = metrics { m.add_bytes(pt.len() as u64, 0); }
                        }
                    }
                }
            }
            r = target.read(&mut buf), if !target_done => {
                let n = r?;
                if n == 0 {
                    target_done = true;
                    let _ = tunnel.shutdown().await;
                    continue;
                }
                tunnel.write_plaintext(&buf[..n]).await?;
                if let Some(m) = metrics { m.add_bytes(0, n as u64); }
            }
            else => break,
        }
        if tunnel_done && target_done {
            break;
        }
    }
    Ok(())
}

/// Idle timeout for a UDP association (no activity → close), matching how
/// proxies reap UDP flows so associations don't leak.
const UDP_IDLE: Duration = Duration::from_secs(120);

/// Pull one length-prefixed VLESS-UDP datagram (`[len:2 BE][payload]`) out of
/// `buf` if a complete one is buffered.
fn take_datagram(buf: &mut BytesMut) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let len = ((buf[0] as usize) << 8) | buf[1] as usize;
    if buf.len() < 2 + len {
        return None;
    }
    buf.advance(2);
    Some(buf.split_to(len).to_vec())
}

enum UdpEvent {
    Tunnel(io::Result<Option<Vec<u8>>>),
    Sock(io::Result<usize>),
}

/// Basic VLESS-UDP relay (`Command::Udp`): the inner body is length-prefixed
/// datagrams (`[len:2][payload]`) to the single `target` from the VLESS request
/// — Vision never applies to UDP, so this stays inside the outer TLS (no
/// splice). Bridges those datagrams to a connected UDP socket. `leftover` is
/// plaintext already read past the VLESS request (start of the UDP body).
pub async fn vision_udp_relay(
    mut tunnel: RecordTlsServer,
    target: SocketAddr,
    leftover: Vec<u8>,
    metrics: &Metrics,
) -> io::Result<()> {
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(target).await?;

    let mut inbuf = BytesMut::from(&leftover[..]);
    let mut udpbuf = vec![0u8; 65535];
    let mut tunnel_done = false;

    loop {
        // Flush any complete datagrams already buffered → upstream UDP.
        while let Some(dg) = take_datagram(&mut inbuf) {
            if !dg.is_empty() {
                sock.send(&dg).await?;
                metrics.add_bytes(dg.len() as u64, 0);
            }
        }
        if tunnel_done {
            break;
        }
        let ev = tokio::time::timeout(UDP_IDLE, async {
            tokio::select! {
                r = tunnel.read_record_opt() => UdpEvent::Tunnel(r),
                r = sock.recv(&mut udpbuf) => UdpEvent::Sock(r),
            }
        })
        .await;
        match ev {
            Err(_) => break, // idle timeout
            Ok(UdpEvent::Tunnel(r)) => match r? {
                // Clean EOF — client closed the tunnel; tear the relay down.
                None => tunnel_done = true,
                // Empty (no-app-data) record, e.g. KeyUpdate — not EOF.
                Some(pt) => inbuf.extend_from_slice(&pt),
            },
            Ok(UdpEvent::Sock(r)) => {
                let n = r?;
                let mut frame = Vec::with_capacity(2 + n);
                frame.push((n >> 8) as u8);
                frame.push(n as u8);
                frame.extend_from_slice(&udpbuf[..n]);
                tunnel.write_plaintext(&frame).await?;
                metrics.add_bytes(0, n as u64);
            }
        }
    }
    let _ = tunnel.shutdown().await;
    Ok(())
}

/// One uplink read, in whichever mode the tunnel is in. Kept as a single
/// future so `select!` borrows `tunnel` only once (the two modes can't be
/// separate branches — the borrow checker ignores the runtime guards).
enum UplinkRead {
    /// Padded phase: decrypted plaintext of one outer-TLS record. May be empty
    /// for a no-app-data record (e.g. KeyUpdate) — that is *not* EOF.
    Record(Vec<u8>),
    /// Spliced phase: `n` (>0) raw bytes in the shared buffer.
    Raw(usize),
    /// Clean EOF in either phase.
    Eof,
}

async fn read_uplink(
    tunnel: &mut RecordTlsServer,
    spliced: bool,
    rawbuf: &mut [u8],
) -> io::Result<UplinkRead> {
    if spliced {
        let n = tunnel.read_raw(rawbuf).await?;
        Ok(if n == 0 {
            UplinkRead::Eof
        } else {
            UplinkRead::Raw(n)
        })
    } else {
        match tunnel.read_record_opt().await? {
            None => Ok(UplinkRead::Eof),
            Some(pt) => Ok(UplinkRead::Record(pt)),
        }
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
    metrics: &Metrics,
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
            metrics.add_bytes(content.len() as u64, 0);
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
                    UplinkRead::Eof => {
                        uplink_done = true;
                        let _ = upstream.shutdown().await;
                        continue;
                    }
                    UplinkRead::Record(pt) => {
                        // `pt` is empty for a no-app-data record (KeyUpdate);
                        // feeding the unpadder nothing is a no-op, so skip it.
                        if !pt.is_empty() {
                            let content = unp.push(&pt);
                            if !content.is_empty() {
                                if filter.number_to_filter > 0 {
                                    filter.filter(&content);
                                }
                                upstream.write_all(&content).await?;
                                metrics.add_bytes(content.len() as u64, 0);
                            }
                            if unp.direct() {
                                uplink_spliced = true;
                            }
                        }
                    }
                    UplinkRead::Raw(n) => {
                        upstream.write_all(&ubuf[..n]).await?;
                        metrics.add_bytes(n as u64, 0);
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
                metrics.add_bytes(0, n as u64);
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
            metrics.add_bytes(leftover.len() as u64, 0);
        }
        if let Ok((up, down)) = tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await {
            metrics.add_bytes(up, down);
        }
        let _ = tcp.shutdown().await;
        let _ = upstream.shutdown().await;
    }
    Ok(())
}
