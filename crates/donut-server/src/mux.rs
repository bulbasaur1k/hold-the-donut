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
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::metrics::Metrics;
use crate::vision_xray_splice::RecordTlsServer;

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEPALIVE: u8 = 0x04;
const OPTION_DATA: u8 = 0x01;
const NET_UDP: u8 = 0x02;
const MUX_IDLE: Duration = Duration::from_secs(180);

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
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad mux meta length"));
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
    let has_addr = status == STATUS_NEW
        || (status == STATUS_KEEP && meta.len() > 4 && meta[4] == NET_UDP);
    if has_addr {
        if meta.len() < off + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "mux meta truncated"));
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

struct UdpSession {
    sock: Arc<UdpSocket>,
    recv_task: JoinHandle<()>,
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.recv_task.abort();
    }
}

/// Server-side Mux.Cool relay for one `Command::Mux` connection: bridges
/// multiplexed UDP (XUDP) sub-sessions to real UDP sockets. `leftover` is
/// plaintext already read past the VLESS request.
// The session is created with async work (resolve/bind/spawn) between the
// lookup and the insert, so the Entry API doesn't fit cleanly.
#[allow(clippy::map_entry)]
pub async fn mux_relay(
    mut tunnel: RecordTlsServer,
    leftover: Vec<u8>,
    metrics: &Metrics,
) -> io::Result<()> {
    let mut inbuf = BytesMut::from(&leftover[..]);
    let mut sessions: HashMap<u16, UdpSession> = HashMap::new();
    let (resp_tx, mut resp_rx) = mpsc::channel::<(u16, SocketAddr, Vec<u8>)>(512);
    let mut tunnel_done = false;

    loop {
        // Drain all complete frames currently buffered.
        while let Some(frame) = parse_frame(&mut inbuf)? {
            match frame.status {
                STATUS_NEW | STATUS_KEEP => {
                    // Create the UDP session on first sight (New, or a Keep we
                    // haven't seen — be lenient).
                    if !sessions.contains_key(&frame.sid) {
                        if let Some(t) = &frame.target {
                            if let Ok(addr) = resolve(t).await {
                                let sock = match UdpSocket::bind(if addr.is_ipv6() {
                                    "[::]:0"
                                } else {
                                    "0.0.0.0:0"
                                })
                                .await
                                {
                                    Ok(s) => Arc::new(s),
                                    Err(_) => continue,
                                };
                                let tx = resp_tx.clone();
                                let sid = frame.sid;
                                let rsock = sock.clone();
                                let recv_task = tokio::spawn(async move {
                                    let mut b = vec![0u8; 65535];
                                    while let Ok((n, src)) = rsock.recv_from(&mut b).await {
                                        if tx.send((sid, src, b[..n].to_vec())).await.is_err() {
                                            break;
                                        }
                                    }
                                });
                                sessions.insert(frame.sid, UdpSession { sock, recv_task });
                            }
                        }
                    }
                    // Send this frame's datagram to its (per-packet) target.
                    if let (Some(sess), Some(t), Some(data)) =
                        (sessions.get(&frame.sid), &frame.target, &frame.data)
                    {
                        if let Ok(addr) = resolve(t).await {
                            let _ = sess.sock.send_to(data, addr).await;
                            metrics.add_bytes(data.len() as u64, 0);
                        }
                    } else if let (Some(sess), None, Some(data)) =
                        (sessions.get(&frame.sid), &frame.target, &frame.data)
                    {
                        // Keep without a re-stated target: send to the connected peer.
                        let _ = sess.sock.send(data).await;
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

        if tunnel_done && sessions.is_empty() {
            break;
        }

        let ev = tokio::time::timeout(MUX_IDLE, async {
            tokio::select! {
                r = tunnel.read_record() => Some(Ev::Tunnel(r)),
                Some(p) = resp_rx.recv() => Some(Ev::Resp(p)),
            }
        })
        .await;

        match ev {
            Err(_) => break, // idle timeout
            Ok(None) => break,
            Ok(Some(Ev::Tunnel(r))) => {
                let pt = r?;
                if pt.is_empty() {
                    tunnel_done = true;
                } else {
                    inbuf.extend_from_slice(&pt);
                }
            }
            Ok(Some(Ev::Resp((sid, src, data)))) => {
                let frame = keep_frame(sid, src, &data);
                tunnel.write_plaintext(&frame).await?;
                metrics.add_bytes(0, data.len() as u64);
            }
        }
    }
    let _ = tunnel.shutdown().await;
    Ok(())
}

enum Ev {
    Tunnel(io::Result<Vec<u8>>),
    Resp((u16, SocketAddr, Vec<u8>)),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_udp_frame_roundtrip() {
        // meta: sid=7, status=New, option=Data, network=UDP, port=53, IPv4 8.8.8.8
        let mut meta = vec![0x00, 0x07, STATUS_NEW, OPTION_DATA, NET_UDP, 0x00, 0x35, 0x01, 8, 8, 8, 8];
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
