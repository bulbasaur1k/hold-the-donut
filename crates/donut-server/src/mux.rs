//! Mux.Cool / XUDP server — enough to carry UDP (and TCP) sub-streams that an
//! Xray client multiplexes over one `Command::Mux` VLESS connection. This is
//! what modern clients (xray, sing-box, HAPP) use for UDP when
//! `packetEncoding: "xudp"`, so QUIC/UDP tunnels.
//!
//! Frame (byte-exact with xray `common/mux/frame.go` + `writer.go`):
//! ```text
//! [meta-len: u16 BE]
//! [session-id: u16 BE][status: u8][option: u8]
//!   if New, or Keep with a UDP target:
//!     [network: u8 (TCP=1, UDP=2)][port: u16 BE][addr-type: u8][addr...]
//!   if New + UDP + OptionData: [global-id: 8]
//! if OptionData: [data-len: u16 BE][data...]   (one datagram for UDP)
//! ```
//! status: New=1, Keep=2, End=3, KeepAlive=4. option bit Data=0x01.
//! Each UDP datagram is its own frame carrying its target → full-cone.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use donut_io::vision_xray::{
    xtls_padding, Unpadder, BUF_SIZE, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_END, DEFAULT_SEED,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use donut_core::{Address, Endpoint};
use donut_routing::Router;

use crate::metrics::Metrics;
use crate::outbound::{ChainOutbound, Outbounds};
use crate::vision_xray_splice::RecordTlsServer;

/// Plaintext I/O the Mux relay needs, abstracted over the two carriers it
/// runs on: the raw/vision path drives TLS *records* manually
/// ([`RecordTlsServer`]); the xHTTP/carrier path is a plain byte stream.
/// Mux frames don't care about record boundaries — the relay just needs
/// "read some plaintext", "write some plaintext", "close" — so one relay
/// serves both. Futures are `Send` so the relay can run inside `spawn`.
pub trait MuxIo {
    /// Read the next plaintext chunk; `Ok(None)` on clean EOF.
    fn read_chunk(
        &mut self,
    ) -> impl std::future::Future<Output = io::Result<Option<Vec<u8>>>> + Send;
    /// Write a complete plaintext frame.
    fn write_chunk(
        &mut self,
        data: &[u8],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;
    /// Close the downstream half.
    fn close(&mut self) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

impl MuxIo for RecordTlsServer {
    async fn read_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.read_record_opt().await
    }
    async fn write_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_plaintext(data).await
    }
    async fn close(&mut self) -> io::Result<()> {
        self.shutdown().await
    }
}

/// [`MuxIo`] over a plain duplex byte stream (the xHTTP/carrier session).
pub struct CarrierMuxIo<S> {
    inner: S,
    buf: Box<[u8; 32 * 1024]>,
}

impl<S> CarrierMuxIo<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Box::new([0u8; 32 * 1024]),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> MuxIo for CarrierMuxIo<S> {
    async fn read_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        let n = self.inner.read(&mut self.buf[..]).await?;
        Ok((n != 0).then(|| self.buf[..n].to_vec()))
    }
    async fn write_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(data).await
    }
    async fn close(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

/// De-pad an inbound chunk: when the Mux stream rides inside Vision
/// (`flow=xtls-rprx-vision` + XUDP, e.g. HAPP), the client pads the frames, so
/// we must un-pad before parsing. Without Vision it's a pass-through.
fn devision(unp: &mut Option<Unpadder>, data: &[u8]) -> Vec<u8> {
    match unp {
        Some(u) => u.push(data),
        None => data.to_vec(),
    }
}

/// Vision-pad the **first** downlink frame, the mirror of [`devision`] on the
/// uplink. When the Mux stream rides inside Vision (`flow=xtls-rprx-vision` +
/// XUDP), the client's Vision reader treats the whole server→client stream as
/// padding-framed and validates the user UUID on the very first frame — so an
/// un-padded Mux frame is read as a bogus UUID and the session is dropped with
/// `XTLS Vision server responded unknown UUID`. We emit `[uuid][cmd][len][pad]`
/// blocks (UUID on the first block) ending with a `PaddingEnd` command, after
/// which the client switches to raw for the rest of the session — mirroring what
/// the client itself does on its uplink for a non-TLS stream. Content is split
/// into `BUF_SIZE`-bounded blocks (matching Xray's reshape) so the 16-bit length
/// field can't overflow on a jumbo datagram.
fn revision(uuid: [u8; 16], frame: &[u8]) -> Vec<u8> {
    const MAX: usize = BUF_SIZE - 21; // per-block content budget (Xray reshape)
    let mut uuid_once = Some(uuid);
    // A keep_frame always carries a datagram, but guard the empty case so the
    // UUID + End still go out.
    if frame.is_empty() {
        return xtls_padding(
            &[],
            COMMAND_PADDING_END,
            &mut uuid_once,
            false,
            &DEFAULT_SEED,
        );
    }
    let mut out = Vec::with_capacity(frame.len() + 21);
    let mut chunks = frame.chunks(MAX).peekable();
    while let Some(chunk) = chunks.next() {
        let command = if chunks.peek().is_none() {
            COMMAND_PADDING_END
        } else {
            COMMAND_PADDING_CONTINUE
        };
        out.extend_from_slice(&xtls_padding(
            chunk,
            command,
            &mut uuid_once,
            false, // non-TLS inner: short padding
            &DEFAULT_SEED,
        ));
    }
    out
}

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEPALIVE: u8 = 0x04;
const OPTION_DATA: u8 = 0x01;
const NET_UDP: u8 = 0x02;

/// A target address parsed from a frame (Mux `PortThenAddress`).
#[derive(Clone)]
enum Addr {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// Read `[port:2 BE][type:1][addr]` from `b`, advancing it. Returns `None` if
/// the buffer is too short (caller waits for more) or the type is unknown.
fn read_addr(b: &[u8]) -> Option<(Addr, usize)> {
    if b.len() < 3 {
        return None;
    }
    let port = ((b[0] as u16) << 8) | b[1] as u16;
    let ty = b[2];
    match ty {
        0x01 => {
            if b.len() < 7 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(b[3], b[4], b[5], b[6]);
            Some((Addr::Ip(SocketAddr::from((ip, port))), 7))
        }
        0x03 => {
            if b.len() < 19 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[3..19]);
            let ip = std::net::Ipv6Addr::from(o);
            Some((Addr::Ip(SocketAddr::from((ip, port))), 19))
        }
        0x02 => {
            let dlen = *b.get(3)? as usize;
            if b.len() < 4 + dlen {
                return None;
            }
            let host = String::from_utf8_lossy(&b[4..4 + dlen]).into_owned();
            Some((Addr::Domain(host, port), 4 + dlen))
        }
        _ => None,
    }
}

/// Write `[network=UDP][port:2 BE][type:1][addr]` for a response Keep frame.
fn write_addr(out: &mut Vec<u8>, src: SocketAddr) {
    out.push(NET_UDP);
    out.push((src.port() >> 8) as u8);
    out.push(src.port() as u8);
    match src.ip() {
        std::net::IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            out.push(0x03);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// One parsed frame ready to act on.
struct Frame {
    sid: u16,
    status: u8,
    target: Option<Addr>,
    data: Option<Vec<u8>>,
}

/// Try to parse one complete Mux frame from the front of `buf`. Returns
/// `Ok(Some(frame))` and consumes it, `Ok(None)` if incomplete (wait for more).
fn parse_frame(buf: &mut BytesMut) -> io::Result<Option<Frame>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let meta_len = ((buf[0] as usize) << 8) | buf[1] as usize;
    if !(4..=512).contains(&meta_len) {
        // Usually means the stream isn't actually plain Mux — most often a
        // Vision-wrapped Mux we failed to un-pad (see mux_relay vision_uuid).
        // Include a head dump so the cause is unambiguous in the logs.
        let head: String = buf
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "bad mux meta length {meta_len} (vision-wrapped Mux not un-padded?) head=[{head}]"
            ),
        ));
    }
    if buf.len() < 2 + meta_len {
        return Ok(None);
    }
    let meta = &buf[2..2 + meta_len];
    let sid = ((meta[0] as u16) << 8) | meta[1] as u16;
    let status = meta[2];
    let option = meta[3];
    let mut off = 4;
    let mut target = None;
    // New, or Keep with a UDP network flag, carries network + address.
    let has_addr =
        status == STATUS_NEW || (status == STATUS_KEEP && meta.len() > 4 && meta[4] == NET_UDP);
    if has_addr {
        if meta.len() < off + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mux meta truncated",
            ));
        }
        off += 1; // network byte
        match read_addr(&meta[off..]) {
            Some((a, used)) => {
                target = Some(a);
                off += used;
            }
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "mux addr parse")),
        }
        // New + UDP + Data carries an 8-byte GlobalID we don't need (skip).
        let _ = off; // remaining meta (global id) ignored
    }

    let mut consumed = 2 + meta_len;
    let mut data = None;
    if option & OPTION_DATA != 0 {
        if buf.len() < consumed + 2 {
            return Ok(None);
        }
        let dlen = ((buf[consumed] as usize) << 8) | buf[consumed + 1] as usize;
        if buf.len() < consumed + 2 + dlen {
            return Ok(None);
        }
        let start = consumed + 2;
        data = Some(buf[start..start + dlen].to_vec());
        consumed = start + dlen;
    }

    buf.advance(consumed);
    Ok(Some(Frame {
        sid,
        status,
        target,
        data,
    }))
}

/// Frame a UDP response back to the client: Keep + Data + source address.
fn keep_frame(sid: u16, src: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut meta = Vec::with_capacity(24);
    meta.push((sid >> 8) as u8);
    meta.push(sid as u8);
    meta.push(STATUS_KEEP);
    meta.push(OPTION_DATA);
    write_addr(&mut meta, src);

    let mut out = Vec::with_capacity(2 + meta.len() + 2 + data.len());
    out.push((meta.len() >> 8) as u8);
    out.push(meta.len() as u8);
    out.extend_from_slice(&meta);
    out.push((data.len() >> 8) as u8);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

/// Resolve a frame target to a `SocketAddr` (UDP). Domains are looked up.
async fn resolve(addr: &Addr) -> io::Result<SocketAddr> {
    match addr {
        Addr::Ip(s) => Ok(*s),
        Addr::Domain(h, p) => tokio::net::lookup_host((h.as_str(), *p))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for domain")),
    }
}

/// One XUDP sub-session's egress, decided **per target** by the routing table
/// exactly as it is for TCP: a tag selecting a chain outbound sends those
/// datagrams up the cascade so the *exit* owns the real socket; anything else
/// keeps the local socket. Before this existed every XUDP session bound a
/// local socket unconditionally, so UDP always left from the entry's own
/// address while TCP went abroad — which is what kept Telegram calls broken.
///
/// A sid is full-cone (each datagram re-states its target), so one sid can
/// legitimately hit both a chained and a local target. Both halves are
/// therefore lazy and coexist.
#[derive(Default)]
struct UdpSession {
    /// Local socket, shared by every target the router keeps on this node.
    direct: Option<DirectLink>,
    /// One cascade session per distinct chained target.
    chain: HashMap<SocketAddr, ChainLink>,
}

/// The local socket plus the task pumping its reads into the mux response
/// channel.
struct DirectLink {
    sock: Arc<UdpSocket>,
    recv_task: JoinHandle<()>,
}

impl Drop for DirectLink {
    fn drop(&mut self) {
        self.recv_task.abort();
    }
}

/// The uplink half of one cascade UDP session, plus the task pumping its
/// downlink back into the mux response channel.
struct ChainLink {
    tx: Box<dyn AsyncWrite + Unpin + Send>,
    recv_task: JoinHandle<()>,
}

impl Drop for ChainLink {
    fn drop(&mut self) {
        self.recv_task.abort();
    }
}

/// A mux frame target as the router sees it. Domains stay domains so a chained
/// target is resolved by the **exit**, not by us.
fn endpoint_of(addr: &Addr) -> Endpoint {
    match addr {
        Addr::Ip(s) => Endpoint::new(Address::Ip(s.ip()), s.port()),
        Addr::Domain(h, p) => Endpoint::new(Address::Domain(h.clone()), *p),
    }
}

/// Frame one datagram for a VLESS-UDP stream (`[len:2 BE][payload]`).
async fn write_datagram<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.push((data.len() >> 8) as u8);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    w.write_all(&out).await?;
    w.flush().await
}

/// Open one cascade UDP session for `ep` and pump its downlink into the mux
/// response channel, labelled with `label` (the source address the client is
/// told the datagrams came from).
async fn dial_chain(
    chain: &ChainOutbound,
    ep: &Endpoint,
    sid: u16,
    label: SocketAddr,
    resp_tx: &mpsc::Sender<(u16, SocketAddr, Vec<u8>)>,
) -> Option<ChainLink> {
    let up = match chain.dial_udp(ep).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(target = %ep, sid, error = %e, "mux: cascade udp dial failed");
            return None;
        }
    };
    let (mut rd, wr) = tokio::io::split(up);
    let tx = resp_tx.clone();
    let recv_task = tokio::spawn(async move {
        let mut acc = BytesMut::with_capacity(BUF_SIZE);
        let mut chunk = vec![0u8; 65535];
        loop {
            match rd.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => acc.extend_from_slice(&chunk[..n]),
            }
            while let Some(dg) = crate::vision_xray_splice::take_datagram(&mut acc) {
                if tx.send((sid, label, dg)).await.is_err() {
                    return;
                }
            }
        }
    });
    Some(ChainLink {
        tx: Box::new(wr),
        recv_task,
    })
}

/// Bind this node's own socket for a sid and pump its reads into the mux
/// response channel. One socket serves every local target on the sid.
async fn open_direct(
    sid: u16,
    ipv6: bool,
    resp_tx: &mpsc::Sender<(u16, SocketAddr, Vec<u8>)>,
) -> Option<DirectLink> {
    let sock = Arc::new(
        UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" })
            .await
            .ok()?,
    );
    let tx = resp_tx.clone();
    let rsock = sock.clone();
    let recv_task = tokio::spawn(async move {
        let mut b = vec![0u8; 65535];
        while let Ok((n, src)) = rsock.recv_from(&mut b).await {
            if tx.send((sid, src, b[..n].to_vec())).await.is_err() {
                break;
            }
        }
    });
    Some(DirectLink { sock, recv_task })
}

/// Send one datagram out of the sub-session, opening the egress the routing
/// table picks for this target on first use.
// The cascade session is dialled with async work between the lookup and the
// insert, so the Entry API doesn't fit cleanly.
#[allow(clippy::map_entry)]
async fn send_datagram(
    sess: &mut UdpSession,
    sid: u16,
    target: Option<&Addr>,
    data: &[u8],
    router: &Router,
    outbounds: &Outbounds,
    resp_tx: &mpsc::Sender<(u16, SocketAddr, Vec<u8>)>,
) {
    // A Keep that doesn't re-state its target continues the sid's existing
    // egress: the single cascade session if there is exactly one, else the
    // local socket's connected peer.
    let Some(t) = target else {
        if sess.chain.len() == 1 {
            if let Some(link) = sess.chain.values_mut().next() {
                let _ = write_datagram(&mut link.tx, data).await;
            }
        } else if let Some(d) = &sess.direct {
            let _ = d.sock.send(data).await;
        }
        return;
    };

    let ep = endpoint_of(t);
    if let Some(chain) = outbounds.get(router.route(&ep)) {
        // Chained: the exit opens the socket. Resolving here is only to label
        // the downlink frames — the exit resolves the target itself.
        let Ok(addr) = resolve(t).await else { return };
        if !sess.chain.contains_key(&addr) {
            let Some(link) = dial_chain(chain, &ep, sid, addr, resp_tx).await else {
                return;
            };
            sess.chain.insert(addr, link);
        }
        if let Some(link) = sess.chain.get_mut(&addr) {
            let _ = write_datagram(&mut link.tx, data).await;
        }
        return;
    }

    // Local egress (e.g. domestic geoip rules keeping traffic on this IP).
    let Ok(addr) = resolve(t).await else { return };
    if sess.direct.is_none() {
        sess.direct = open_direct(sid, addr.is_ipv6(), resp_tx).await;
    }
    if let Some(d) = &sess.direct {
        let _ = d.sock.send_to(data, addr).await;
    }
}

/// Server-side Mux.Cool relay for one `Command::Mux` connection: bridges
/// multiplexed UDP (XUDP) sub-sessions to their routed egress — a local socket
/// or a cascade session on the exit. `leftover` is plaintext already read past
/// the VLESS request.
pub async fn mux_relay<T: MuxIo>(
    mut tunnel: T,
    leftover: Vec<u8>,
    metrics: &Metrics,
    vision_uuid: Option<[u8; 16]>,
    idle: Duration,
    router: &Router,
    outbounds: &Outbounds,
) -> io::Result<()> {
    // When the Mux stream is Vision-wrapped (flow=vision + XUDP) the client pads
    // and reads *both* directions: we un-pad the uplink and must Vision-pad the
    // downlink (UUID on the first frame, then PaddingEnd → raw). Leaving the
    // downlink un-padded makes the client misread the first Mux frame as the
    // Vision UUID and drop the session. UDP/Mux never triggers a Vision splice
    // (no inner TLS).
    let mut unp = vision_uuid.map(Unpadder::new);
    let mut downlink_pad = vision_uuid; // Some(uuid) until the first frame is padded
    let mut inbuf = BytesMut::from(&devision(&mut unp, &leftover)[..]);
    let mut sessions: HashMap<u16, UdpSession> = HashMap::new();
    let (resp_tx, mut resp_rx) = mpsc::channel::<(u16, SocketAddr, Vec<u8>)>(512);

    loop {
        // Drain all complete frames currently buffered.
        while let Some(frame) = parse_frame(&mut inbuf)? {
            match frame.status {
                STATUS_NEW | STATUS_KEEP => {
                    // Create the sub-session on first sight (New, or a Keep we
                    // haven't seen — be lenient). The egress itself is opened
                    // lazily per target inside `send_datagram`.
                    let sess = sessions.entry(frame.sid).or_default();
                    if let Some(data) = &frame.data {
                        send_datagram(
                            sess,
                            frame.sid,
                            frame.target.as_ref(),
                            data,
                            router,
                            outbounds,
                            &resp_tx,
                        )
                        .await;
                        metrics.add_bytes(data.len() as u64, 0);
                    }
                }
                STATUS_END => {
                    sessions.remove(&frame.sid); // Drop aborts the recv task.
                }
                STATUS_KEEPALIVE => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown mux status",
                    ))
                }
            }
        }

        let ev = tokio::time::timeout(idle, async {
            tokio::select! {
                r = tunnel.read_chunk() => Some(Ev::Tunnel(r)),
                Some(p) = resp_rx.recv() => Some(Ev::Resp(p)),
            }
        })
        .await;

        match ev {
            Err(_) => break, // idle timeout
            Ok(None) => break,
            Ok(Some(Ev::Tunnel(r))) => match r? {
                // Carrier EOF: the client closed the whole Mux connection, so
                // every sub-session is gone (no further END frames will come).
                // Break and drop `sessions` — their recv tasks abort on drop.
                // Re-polling a closed tunnel here would return instantly and
                // spin the loop at 100% CPU for as long as a UDP session lived.
                None => break,
                // An outer-TLS record with no application bytes (e.g. a
                // KeyUpdate) decodes to empty — not EOF; keep relaying.
                Some(pt) => {
                    let d = devision(&mut unp, &pt);
                    inbuf.extend_from_slice(&d);
                }
            },
            Ok(Some(Ev::Resp((sid, src, data)))) => {
                let frame = keep_frame(sid, src, &data);
                // Vision-pad the first downlink frame (UUID first), raw after.
                let out = match downlink_pad.take() {
                    Some(uuid) => revision(uuid, &frame),
                    None => frame,
                };
                tunnel.write_chunk(&out).await?;
                metrics.add_bytes(0, data.len() as u64);
            }
        }
    }
    let _ = tunnel.close().await;
    Ok(())
}

enum Ev {
    Tunnel(io::Result<Option<Vec<u8>>>),
    Resp((u16, SocketAddr, Vec<u8>)),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_udp_frame_roundtrip() {
        // meta: sid=7, status=New, option=Data, network=UDP, port=53, IPv4 8.8.8.8
        let mut meta = vec![
            0x00,
            0x07,
            STATUS_NEW,
            OPTION_DATA,
            NET_UDP,
            0x00,
            0x35,
            0x01,
            8,
            8,
            8,
            8,
        ];
        // New+UDP+Data also carries an 8-byte global id
        meta.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let payload = b"hello-udp";
        let mut frame = Vec::new();
        frame.push((meta.len() >> 8) as u8);
        frame.push(meta.len() as u8);
        frame.extend_from_slice(&meta);
        frame.push((payload.len() >> 8) as u8);
        frame.push(payload.len() as u8);
        frame.extend_from_slice(payload);

        let mut buf = BytesMut::from(&frame[..]);
        let f = parse_frame(&mut buf).unwrap().unwrap();
        assert_eq!(f.sid, 7);
        assert_eq!(f.status, STATUS_NEW);
        assert!(matches!(f.target, Some(Addr::Ip(a)) if a.port() == 53));
        assert_eq!(f.data.as_deref(), Some(&payload[..]));
        assert!(buf.is_empty());
    }

    #[test]
    fn parse_incomplete_returns_none() {
        let mut buf = BytesMut::from(&[0x00, 0x0c, 0x00][..]); // says meta-len 12 but short
        assert!(parse_frame(&mut buf).unwrap().is_none());
    }

    /// End-to-end XUDP over the **carrier** byte stream (the xHTTP path):
    /// feed a NEW+UDP frame through `mux_relay` over `CarrierMuxIo` to a real
    /// local UDP echo, and read the echoed datagram back as a KEEP frame.
    /// This is the deterministic stand-in for "HAPP mux over xHTTP".
    #[tokio::test]
    async fn carrier_mux_relay_echoes_xudp_datagram() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Local UDP echo server.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, src)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], src).await;
            }
        });

        // Craft a NEW+UDP+Data Mux frame targeting the echo (IPv4 127.0.0.1).
        let port = echo_addr.port();
        let payload = b"ping-xudp";
        let mut meta = vec![
            0x00,
            0x01, // sid = 1
            STATUS_NEW,
            OPTION_DATA,
            NET_UDP,
            (port >> 8) as u8,
            port as u8,
            0x01, // addr type IPv4
            127,
            0,
            0,
            1,
        ];
        meta.extend_from_slice(&[0u8; 8]); // New+UDP+Data → 8-byte global id
        let mut frame = Vec::new();
        frame.push((meta.len() >> 8) as u8);
        frame.push(meta.len() as u8);
        frame.extend_from_slice(&meta);
        frame.push((payload.len() >> 8) as u8);
        frame.push(payload.len() as u8);
        frame.extend_from_slice(payload);

        // Drive mux_relay over a plain duplex (the carrier), feeding the frame
        // as the post-request leftover.
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let metrics = Metrics::new();
        let m = metrics.clone();
        let relay = tokio::spawn(async move {
            let _ = mux_relay(
                CarrierMuxIo::new(server),
                frame,
                &m,
                None,
                Duration::from_secs(5),
                &Router::new("freedom"),
                &Outbounds::default(),
            )
            .await;
        });

        // Read the KEEP frame carrying the echoed datagram.
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("relay response timeout")
            .expect("read");
        let mut rb = BytesMut::from(&buf[..n]);
        let f = parse_frame(&mut rb).unwrap().unwrap();
        assert_eq!(f.status, STATUS_KEEP);
        assert_eq!(f.data.as_deref(), Some(&payload[..]));

        // Closing the carrier ends the relay.
        let _ = client.shutdown().await;
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    }

    /// The same XUDP datagram, but with the router pointing at a chain: it must
    /// leave from the **exit**, not from a socket on this node.
    ///
    /// This is the path the home router takes — mihomo sends all UDP as XUDP —
    /// so without it Telegram calls from behind the router would still egress
    /// domestically even though the single-target UDP path was fixed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn xudp_egresses_from_the_cascade_exit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, src)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], src).await;
            }
        });

        // A real exit node: it owns the socket the datagram finally leaves on.
        const LINK_UUID: &str = "22222222-2222-4222-8222-222222222222";
        let veil =
            donut_veil::VeilServerConfig::new([0x22u8; 32], ["deadbeef".parse().unwrap()]).unwrap();
        let exit_pub = veil.public_key_bytes();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let exit_metrics = Metrics::new();
        let exit_addr = crate::run_veil_proxy(
            "127.0.0.1:0".parse().unwrap(),
            vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            veil,
            "127.0.0.1:9".parse().unwrap(),
            donut_core::AuthHandle::new(donut_core::UserAuth::new(vec![LINK_UUID
                .parse::<donut_core::UserId>()
                .unwrap()])),
            Arc::new(Router::new("freedom")),
            Arc::new(donut_dns::Resolver::system().unwrap()),
            Arc::new(Outbounds::default()),
            exit_metrics.clone(),
            crate::RuntimeTuning::default(),
        )
        .await
        .unwrap();

        let outbounds = Outbounds::build(
            &[donut_config::OutboundConfig {
                tag: "proxy".to_string(),
                transport: "veil".to_string(),
                server: exit_addr.to_string(),
                uuid: LINK_UUID.to_string(),
                reality: Some(donut_config::RealityClient {
                    public_key: exit_pub.iter().map(|b| format!("{b:02x}")).collect(),
                    short_id: "deadbeef".to_string(),
                    server_name: "localhost".to_string(),
                    version: [0, 0, 1],
                    fingerprint: String::new(),
                }),
            }],
            None,
        )
        .unwrap();

        // NEW+UDP+Data targeting the echo, exactly as in the direct test.
        let port = echo_addr.port();
        let payload = b"ping-xudp-cascade";
        let mut meta = vec![
            0x00,
            0x01,
            STATUS_NEW,
            OPTION_DATA,
            NET_UDP,
            (port >> 8) as u8,
            port as u8,
            0x01,
            127,
            0,
            0,
            1,
        ];
        meta.extend_from_slice(&[0u8; 8]);
        let mut frame = Vec::new();
        frame.push((meta.len() >> 8) as u8);
        frame.push(meta.len() as u8);
        frame.extend_from_slice(&meta);
        frame.push((payload.len() >> 8) as u8);
        frame.push(payload.len() as u8);
        frame.extend_from_slice(payload);

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let metrics = Metrics::new();
        let m = metrics.clone();
        let relay = tokio::spawn(async move {
            let _ = mux_relay(
                CarrierMuxIo::new(server),
                frame,
                &m,
                None,
                Duration::from_secs(5),
                &Router::new("proxy"),
                &outbounds,
            )
            .await;
        });

        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("no XUDP response came back through the cascade")
            .expect("read");
        let mut rb = BytesMut::from(&buf[..n]);
        let f = parse_frame(&mut rb).unwrap().unwrap();
        assert_eq!(f.status, STATUS_KEEP);
        assert_eq!(f.data.as_deref(), Some(&payload[..]));

        // The echo would answer either way — only the exit's gauge separates
        // "went through the cascade" from "bridged locally".
        let gauge = exit_metrics
            .render()
            .lines()
            .find(|l| l.starts_with("donut_active_sessions{kind=\"udp\"}"))
            .and_then(|l| l.split_whitespace().last()?.parse::<f64>().ok())
            .expect("exit metrics must expose the udp gauge");
        assert!(
            gauge >= 1.0,
            "the XUDP datagram must egress from the exit, not from this node"
        );

        let _ = client.shutdown().await;
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    }

    /// Regression: when the Mux stream is Vision-wrapped, the server's downlink
    /// must be Vision-padded (UUID on the first frame) — otherwise the client
    /// reads the raw Mux KEEP frame, mistakes its first 16 bytes for the Vision
    /// UUID, and drops the session ("XTLS Vision server responded unknown UUID").
    #[tokio::test]
    async fn vision_mux_relay_pads_downlink_with_uuid() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let uuid: [u8; 16] = [
            0xcf, 0x77, 0x6d, 0x70, 0xc6, 0xa8, 0x43, 0x6b, 0xa1, 0x40, 0xe9, 0xb4, 0x66, 0xc0,
            0x06, 0x63,
        ];

        // Local UDP echo server.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, src)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], src).await;
            }
        });

        // NEW+UDP+Data Mux frame targeting the echo.
        let port = echo_addr.port();
        let payload = b"vision-xudp";
        let mut meta = vec![
            0x00,
            0x01, // sid = 1
            STATUS_NEW,
            OPTION_DATA,
            NET_UDP,
            (port >> 8) as u8,
            port as u8,
            0x01, // IPv4
            127,
            0,
            0,
            1,
        ];
        meta.extend_from_slice(&[0u8; 8]); // New+UDP+Data → 8-byte global id
        let mut mux_frame = Vec::new();
        mux_frame.push((meta.len() >> 8) as u8);
        mux_frame.push(meta.len() as u8);
        mux_frame.extend_from_slice(&meta);
        mux_frame.push((payload.len() >> 8) as u8);
        mux_frame.push(payload.len() as u8);
        mux_frame.extend_from_slice(payload);

        // The client Vision-pads its uplink (UUID first, End → raw after).
        let mut up_uuid = Some(uuid);
        let padded_uplink = xtls_padding(
            &mux_frame,
            COMMAND_PADDING_END,
            &mut up_uuid,
            false,
            &DEFAULT_SEED,
        );

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let metrics = Metrics::new();
        let m = metrics.clone();
        let relay = tokio::spawn(async move {
            let _ = mux_relay(
                CarrierMuxIo::new(server),
                padded_uplink,
                &m,
                Some(uuid),
                Duration::from_secs(5),
                &Router::new("freedom"),
                &Outbounds::default(),
            )
            .await;
        });

        // The first downlink bytes MUST be a Vision frame carrying the UUID,
        // not a raw Mux frame (that was the bug).
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("relay response timeout")
            .expect("read");
        assert!(n >= 16, "downlink too short: {n}");
        assert_eq!(
            &buf[..16],
            &uuid[..],
            "first downlink frame must start with the Vision UUID"
        );

        // Un-pad as the client would; the echoed datagram is inside a KEEP frame.
        let mut unp = Unpadder::new(uuid);
        let content = unp.push(&buf[..n]);
        let mut rb = BytesMut::from(&content[..]);
        let f = parse_frame(&mut rb).unwrap().unwrap();
        assert_eq!(f.status, STATUS_KEEP);
        assert_eq!(f.data.as_deref(), Some(&payload[..]));

        let _ = client.shutdown().await;
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    }

    #[test]
    fn keep_frame_has_source_addr() {
        let src: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let f = keep_frame(9, src, b"resp");
        let meta_len = ((f[0] as usize) << 8) | f[1] as usize;
        assert_eq!(meta_len, 12); // sid2+status1+opt1+net1+port2+type1+ipv4(4)
        assert_eq!(((f[2] as u16) << 8) | f[3] as u16, 9); // sid
        assert_eq!(f[4], STATUS_KEEP);
        assert_eq!(f[5], OPTION_DATA);
        assert_eq!(f[6], NET_UDP);
        // parsing it back yields the source addr + payload
        let mut rb = BytesMut::from(&f[..]);
        let pf = parse_frame(&mut rb).unwrap().unwrap();
        assert!(matches!(pf.target, Some(Addr::Ip(a)) if a == src));
        assert_eq!(pf.data.as_deref(), Some(&b"resp"[..]));
    }
}
