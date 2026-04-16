use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Target address reachable over the network.
///
/// Mirrors the three inner-frame address-type variants:
/// * `Ipv4` — 4 raw bytes.
/// * `Domain` — UTF-8 hostname, 1..=255 bytes.
/// * `Ipv6` — 16 raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}

impl Address {
    pub const MAX_DOMAIN_LEN: usize = 255;

    pub fn domain(s: impl Into<String>) -> Result<Self, AddressParseError> {
        let s = s.into();
        if s.is_empty() || s.len() > Self::MAX_DOMAIN_LEN {
            return Err(AddressParseError::DomainLen(s.len()));
        }
        Ok(Self::Domain(s))
    }

    pub fn ipv4(addr: Ipv4Addr) -> Self {
        Self::Ip(IpAddr::V4(addr))
    }

    pub fn ipv6(addr: Ipv6Addr) -> Self {
        Self::Ip(IpAddr::V6(addr))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(IpAddr::V4(a)) => write!(f, "{a}"),
            Self::Ip(IpAddr::V6(a)) => write!(f, "[{a}]"),
            Self::Domain(d) => f.write_str(d),
        }
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        // Strip [..] brackets for IPv6 literals, though bare form was tried above.
        let trimmed = s
            .strip_prefix('[')
            .and_then(|v| v.strip_suffix(']'))
            .unwrap_or(s);
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        Self::domain(s)
    }
}

/// Host + port pair. Distinct from [`std::net::SocketAddr`] because the
/// host side may be an unresolved domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: Address,
    pub port: u16,
}

impl Endpoint {
    pub fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.address {
            Address::Ip(IpAddr::V6(a)) => write!(f, "[{a}]:{}", self.port),
            other => write!(f, "{other}:{}", self.port),
        }
    }
}

impl FromStr for Endpoint {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // IPv6 literal with port: [::1]:443
        if let Some(rest) = s.strip_prefix('[') {
            let (ip, port) = rest
                .split_once("]:")
                .ok_or(AddressParseError::BadEndpoint)?;
            let ip: IpAddr = ip.parse().map_err(|_| AddressParseError::BadEndpoint)?;
            let port: u16 = port.parse().map_err(|_| AddressParseError::BadEndpoint)?;
            return Ok(Self::new(Address::Ip(ip), port));
        }
        let (host, port) = s.rsplit_once(':').ok_or(AddressParseError::BadEndpoint)?;
        let port: u16 = port.parse().map_err(|_| AddressParseError::BadEndpoint)?;
        Ok(Self::new(host.parse()?, port))
    }
}

#[derive(Debug, Error)]
pub enum AddressParseError {
    #[error("domain length out of range (1..=255): {0}")]
    DomainLen(usize),
    #[error("endpoint must be host:port or [v6]:port")]
    BadEndpoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_and_domain() {
        assert!(matches!(
            "1.2.3.4".parse::<Address>().unwrap(),
            Address::Ip(IpAddr::V4(_))
        ));
        assert!(matches!(
            "::1".parse::<Address>().unwrap(),
            Address::Ip(IpAddr::V6(_))
        ));
        assert!(matches!(
            "[::1]".parse::<Address>().unwrap(),
            Address::Ip(IpAddr::V6(_))
        ));
        assert!(matches!(
            "example.com".parse::<Address>().unwrap(),
            Address::Domain(_)
        ));
    }

    #[test]
    fn rejects_empty_and_oversized_domains() {
        assert!(Address::domain("").is_err());
        assert!(Address::domain("a".repeat(256)).is_err());
    }

    #[test]
    fn parses_endpoint_forms() {
        let v4: Endpoint = "1.2.3.4:443".parse().unwrap();
        assert_eq!(v4.port, 443);
        let v6: Endpoint = "[::1]:443".parse().unwrap();
        assert_eq!(v6.port, 443);
        let dom: Endpoint = "example.com:8443".parse().unwrap();
        assert_eq!(dom.port, 8443);
    }
}
