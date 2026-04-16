use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};
use donut_core::{Address, Command, Endpoint, FlowKind, UserId};

use crate::addons::Addons;
use crate::error::WireError;

const VERSION: u8 = 0x00;

const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x02;
const ADDR_IPV6: u8 = 0x03;

/// Request header sent by the client as the first bytes of the tunnel
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub user: UserId,
    pub flow: FlowKind,
    pub command: Command,
    /// Destination; `None` iff `command == Command::Mux`.
    pub target: Option<Endpoint>,
    /// Seed bytes carried with the extended flow. Empty otherwise.
    pub seed: Vec<u8>,
}

impl Request {
    pub fn encoded_len(&self) -> usize {
        let addon_len = self.addons().encoded_len();
        let mut n = 1 /* version */ + 16 /* uuid */ + 1 /* L */ + addon_len + 1 /* cmd */;
        if let Some(ep) = &self.target {
            n += 2 /* port */ + 1 /* addr type */;
            n += match &ep.address {
                Address::Ip(IpAddr::V4(_)) => 4,
                Address::Ip(IpAddr::V6(_)) => 16,
                Address::Domain(d) => 1 + d.len(),
            };
        }
        n
    }

    fn addons(&self) -> Addons {
        Addons {
            flow: self.flow.as_str().to_owned(),
            seed: self.seed.clone(),
        }
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        let addons = self.addons();
        let addon_len = addons.encoded_len();
        debug_assert!(
            addon_len <= u8::MAX as usize,
            "addons exceed 255 bytes ({addon_len})",
        );

        buf.put_u8(VERSION);
        buf.put_slice(self.user.as_bytes());
        buf.put_u8(addon_len as u8);
        addons.encode(buf);
        buf.put_u8(self.command as u8);

        match (&self.target, self.command) {
            (None, Command::Mux) => {}
            (Some(ep), _) => {
                buf.put_u16(ep.port);
                match &ep.address {
                    Address::Ip(IpAddr::V4(a)) => {
                        buf.put_u8(ADDR_IPV4);
                        buf.put_slice(&a.octets());
                    }
                    Address::Ip(IpAddr::V6(a)) => {
                        buf.put_u8(ADDR_IPV6);
                        buf.put_slice(&a.octets());
                    }
                    Address::Domain(d) => {
                        buf.put_u8(ADDR_DOMAIN);
                        debug_assert!(!d.is_empty() && d.len() <= u8::MAX as usize);
                        buf.put_u8(d.len() as u8);
                        buf.put_slice(d.as_bytes());
                    }
                }
            }
            (None, cmd) => panic!("non-Mux command {cmd:?} must carry a target"),
        }
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, WireError> {
        ensure(buf, 1)?;
        let v = buf.get_u8();
        if v != VERSION {
            return Err(WireError::BadVersion(v));
        }

        ensure(buf, 16)?;
        let mut uuid = [0u8; 16];
        buf.copy_to_slice(&mut uuid);
        let user = UserId::from_bytes(uuid);

        ensure(buf, 1)?;
        let addon_len = buf.get_u8() as usize;
        ensure(buf, addon_len)?;
        let mut addon_buf = vec![0u8; addon_len];
        buf.copy_to_slice(&mut addon_buf);
        let addons = Addons::decode(&addon_buf)?;
        let flow = FlowKind::from_wire(&addons.flow).ok_or(WireError::UnknownFlow)?;

        ensure(buf, 1)?;
        let cmd_byte = buf.get_u8();
        let command = Command::from_u8(cmd_byte).ok_or(WireError::UnknownCommand(cmd_byte))?;

        let target = if matches!(command, Command::Mux) {
            None
        } else {
            ensure(buf, 3)?;
            let port = buf.get_u16();
            let atype = buf.get_u8();
            let addr = match atype {
                ADDR_IPV4 => {
                    ensure(buf, 4)?;
                    let mut b = [0u8; 4];
                    buf.copy_to_slice(&mut b);
                    Address::ipv4(Ipv4Addr::from(b))
                }
                ADDR_IPV6 => {
                    ensure(buf, 16)?;
                    let mut b = [0u8; 16];
                    buf.copy_to_slice(&mut b);
                    Address::ipv6(Ipv6Addr::from(b))
                }
                ADDR_DOMAIN => {
                    ensure(buf, 1)?;
                    let dl = buf.get_u8() as usize;
                    if dl == 0 {
                        return Err(WireError::ZeroDomain);
                    }
                    ensure(buf, dl)?;
                    let mut d = vec![0u8; dl];
                    buf.copy_to_slice(&mut d);
                    let s = String::from_utf8(d).map_err(|_| WireError::InvalidDomainUtf8)?;
                    Address::domain(s).map_err(|_| WireError::InvalidDomainUtf8)?
                }
                _ => return Err(WireError::UnknownAddressType(atype)),
            };
            Some(Endpoint::new(addr, port))
        };

        Ok(Request {
            user,
            flow,
            command,
            target,
            seed: addons.seed,
        })
    }
}

/// Response prefix sent by the server as the first bytes of the
/// returned payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    pub addons: Addons,
}

impl Response {
    pub fn encoded_len(&self) -> usize {
        1 + 1 + self.addons.encoded_len()
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(VERSION);
        let addon_len = self.addons.encoded_len();
        debug_assert!(addon_len <= u8::MAX as usize);
        buf.put_u8(addon_len as u8);
        self.addons.encode(buf);
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, WireError> {
        ensure(buf, 1)?;
        let v = buf.get_u8();
        if v != VERSION {
            return Err(WireError::BadVersion(v));
        }
        ensure(buf, 1)?;
        let addon_len = buf.get_u8() as usize;
        ensure(buf, addon_len)?;
        let mut addon_buf = vec![0u8; addon_len];
        buf.copy_to_slice(&mut addon_buf);
        let addons = Addons::decode(&addon_buf)?;
        Ok(Response { addons })
    }
}

fn ensure<B: Buf>(buf: &B, n: usize) -> Result<(), WireError> {
    if buf.remaining() < n {
        return Err(WireError::Truncated {
            want: n,
            have: buf.remaining(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    const UUID: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];

    fn sample_user() -> UserId {
        UserId::from_bytes(UUID)
    }

    fn encode(req: &Request) -> BytesMut {
        let mut b = BytesMut::with_capacity(req.encoded_len());
        req.encode(&mut b);
        assert_eq!(b.len(), req.encoded_len(), "encoded_len mismatch");
        b
    }

    #[test]
    fn round_trip_tcp_ipv4_no_flow() {
        let req = Request {
            user: sample_user(),
            flow: FlowKind::None,
            command: Command::Tcp,
            target: Some(Endpoint::new(
                Address::ipv4("1.2.3.4".parse().unwrap()),
                443,
            )),
            seed: vec![],
        };
        let b = encode(&req);

        // Byte-exact layout check.
        assert_eq!(b[0], 0x00); // version
        assert_eq!(&b[1..17], &UUID);
        assert_eq!(b[17], 0x00); // addon len
        assert_eq!(b[18], 0x01); // Tcp
        assert_eq!(&b[19..21], &[0x01, 0xbb]); // 443
        assert_eq!(b[21], ADDR_IPV4);
        assert_eq!(&b[22..26], &[1, 2, 3, 4]);
        assert_eq!(b.len(), 26);

        let mut frozen = b.freeze();
        let out = Request::decode(&mut frozen).unwrap();
        assert_eq!(out, req);
        assert_eq!(frozen.remaining(), 0);
    }

    #[test]
    fn round_trip_udp_ipv6() {
        let req = Request {
            user: sample_user(),
            flow: FlowKind::None,
            command: Command::Udp,
            target: Some(Endpoint::new(
                Address::ipv6("2606:4700:4700::1111".parse().unwrap()),
                53,
            )),
            seed: vec![],
        };
        let b = encode(&req);
        assert_eq!(b[18], 0x02); // Udp
        assert_eq!(&b[19..21], &[0x00, 0x35]); // 53
        assert_eq!(b[21], ADDR_IPV6);
        assert_eq!(b.len(), 22 + 16);

        let mut frozen = b.freeze();
        let out = Request::decode(&mut frozen).unwrap();
        assert_eq!(out, req);
    }

    #[test]
    fn round_trip_tcp_domain_extended_flow() {
        let req = Request {
            user: sample_user(),
            flow: FlowKind::Extended,
            command: Command::Tcp,
            target: Some(Endpoint::new(Address::domain("example.com").unwrap(), 443)),
            seed: vec![0xaa; 8],
        };
        let b = encode(&req);

        // addon_len > 0 because flow + seed are both set.
        let addon_len = b[17] as usize;
        assert!(addon_len > 0);

        // Command lives at offset 18 + addon_len.
        let cmd_off = 18 + addon_len;
        assert_eq!(b[cmd_off], 0x01); // Tcp
        let port_off = cmd_off + 1;
        assert_eq!(&b[port_off..port_off + 2], &[0x01, 0xbb]);
        assert_eq!(b[port_off + 2], ADDR_DOMAIN);
        assert_eq!(b[port_off + 3] as usize, "example.com".len());
        assert_eq!(
            &b[port_off + 4..port_off + 4 + "example.com".len()],
            b"example.com",
        );

        let mut frozen = b.freeze();
        let out = Request::decode(&mut frozen).unwrap();
        assert_eq!(out, req);
    }

    #[test]
    fn mux_command_has_no_target() {
        let req = Request {
            user: sample_user(),
            flow: FlowKind::None,
            command: Command::Mux,
            target: None,
            seed: vec![],
        };
        let b = encode(&req);
        // 1 + 16 + 1 + 0 + 1 = 19 bytes, no port/addr trailer.
        assert_eq!(b.len(), 19);
        let mut frozen = b.freeze();
        let out = Request::decode(&mut frozen).unwrap();
        assert_eq!(out, req);
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bad = bytes::Bytes::from_static(&[0x01]);
        assert_eq!(Request::decode(&mut bad), Err(WireError::BadVersion(0x01)));
    }

    #[test]
    fn decode_rejects_unknown_command() {
        let req = Request {
            user: sample_user(),
            flow: FlowKind::None,
            command: Command::Tcp,
            target: Some(Endpoint::new(
                Address::ipv4("1.2.3.4".parse().unwrap()),
                443,
            )),
            seed: vec![],
        };
        let mut b = encode(&req);
        // Overwrite command byte with an invalid value.
        b[18] = 0xaa;
        let mut frozen = b.freeze();
        assert_eq!(
            Request::decode(&mut frozen),
            Err(WireError::UnknownCommand(0xaa)),
        );
    }

    #[test]
    fn decode_rejects_truncated() {
        let req = Request {
            user: sample_user(),
            flow: FlowKind::None,
            command: Command::Tcp,
            target: Some(Endpoint::new(
                Address::ipv4("1.2.3.4".parse().unwrap()),
                443,
            )),
            seed: vec![],
        };
        let full = encode(&req);
        let trimmed = full.len() - 1;
        let b = full.freeze().slice(..trimmed);
        let mut buf = b.clone();
        assert!(matches!(
            Request::decode(&mut buf),
            Err(WireError::Truncated { .. }),
        ));
    }

    #[test]
    fn decode_rejects_zero_length_domain() {
        // Manually craft: version+uuid+addonlen=0+cmd=Tcp+port=443+addr_type=Domain+len=0
        let mut b = BytesMut::new();
        b.put_u8(0x00);
        b.put_slice(&UUID);
        b.put_u8(0x00);
        b.put_u8(0x01); // Tcp
        b.put_u16(443);
        b.put_u8(ADDR_DOMAIN);
        b.put_u8(0x00);
        let mut frozen = b.freeze();
        assert_eq!(Request::decode(&mut frozen), Err(WireError::ZeroDomain));
    }

    #[test]
    fn decode_rejects_unknown_flow() {
        // Build addons with flow="bogus" and hand-craft the request.
        let addons = Addons {
            flow: "bogus".to_owned(),
            seed: vec![],
        };
        let al = addons.encoded_len();
        let mut ab = BytesMut::new();
        addons.encode(&mut ab);

        let mut b = BytesMut::new();
        b.put_u8(0x00);
        b.put_slice(&UUID);
        b.put_u8(al as u8);
        b.put_slice(&ab);
        b.put_u8(0x01);
        b.put_u16(443);
        b.put_u8(ADDR_IPV4);
        b.put_slice(&[1, 2, 3, 4]);

        let mut frozen = b.freeze();
        assert_eq!(Request::decode(&mut frozen), Err(WireError::UnknownFlow));
    }

    #[test]
    fn response_round_trip_empty() {
        let r = Response::default();
        let mut b = BytesMut::with_capacity(r.encoded_len());
        r.encode(&mut b);
        assert_eq!(b.len(), 2); // version + L=0
        let mut frozen = b.freeze();
        let out = Response::decode(&mut frozen).unwrap();
        assert_eq!(out, r);
    }
}
