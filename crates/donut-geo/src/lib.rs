//! donut-geo — `.dat` parser + lookup for the v2fly-compatible geodata
//! format (both `geoip.dat` and `geosite.dat`).
//!
//! Reference schema: `common/geodata/geodat.proto` (v2fly / xray). The
//! `.dat` files are a single protobuf-encoded `GeoIPList` / `GeoSiteList`.
//! We hand-define the messages with `prost` derives (no build.rs), and
//! prost skips unknown fields, so newer `.dat` revisions still parse.
//!
//! Lookups are by country/category code (case-insensitive): a
//! [`GeoIpDb`] answers `contains(code, ip)`, a [`GeoSiteDb`] answers
//! `matches(code, host)`.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::net::IpAddr;

use ahash::AHashMap;
use prost::Message;

#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    #[error("protobuf decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid CIDR: ip is {0} bytes (expected 4 or 16)")]
    CidrLen(usize),
}

// ---- protobuf schema (geodat.proto subset) --------------------------

#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ::prost::Enumeration)]
#[repr(i32)]
enum DomainType {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, Message)]
struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    r#type: i32,
    #[prost(string, tag = "2")]
    value: String,
    // tag 3 (`attribute`) intentionally omitted — prost skips it.
}

#[derive(Clone, PartialEq, Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}

// ---- GeoIP ----------------------------------------------------------

/// One parsed network range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoCidr {
    net: IpAddr,
    prefix: u8,
}

impl GeoCidr {
    /// Construct a CIDR directly (programmatic geo databases / tests).
    pub fn new(net: IpAddr, prefix: u8) -> Self {
        Self { net, prefix }
    }

    fn from_proto(c: &Cidr) -> Result<Self, GeoError> {
        let net = match c.ip.len() {
            4 => {
                let mut o = [0u8; 4];
                o.copy_from_slice(&c.ip);
                IpAddr::from(o)
            }
            16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&c.ip);
                IpAddr::from(o)
            }
            n => return Err(GeoError::CidrLen(n)),
        };
        Ok(Self {
            net,
            prefix: c.prefix as u8,
        })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => masked_eq(
                u32::from(net) as u128,
                u32::from(*ip) as u128,
                self.prefix,
                32,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                masked_eq(u128::from(net), u128::from(*ip), self.prefix, 128)
            }
            _ => false,
        }
    }
}

fn masked_eq(net: u128, ip: u128, prefix: u8, bits: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > bits {
        return false;
    }
    let mask = (u128::MAX << (128 - prefix as u32)) >> (128 - bits as u32);
    (net & mask) == (ip & mask)
}

/// A parsed `geoip.dat`, indexed by upper-cased country code.
#[derive(Debug, Clone, Default)]
pub struct GeoIpDb {
    by_code: AHashMap<String, Vec<GeoCidr>>,
}

impl GeoIpDb {
    /// Parse a `geoip.dat` (protobuf `GeoIPList`).
    pub fn parse(data: &[u8]) -> Result<Self, GeoError> {
        let list = GeoIpList::decode(data)?;
        let mut by_code: AHashMap<String, Vec<GeoCidr>> = AHashMap::new();
        for entry in &list.entry {
            let code = entry.country_code.to_ascii_uppercase();
            let mut cidrs = Vec::with_capacity(entry.cidr.len());
            for c in &entry.cidr {
                cidrs.push(GeoCidr::from_proto(c)?);
            }
            by_code.entry(code).or_default().extend(cidrs);
        }
        Ok(Self { by_code })
    }

    /// Build a database from explicit `(code, cidrs)` entries — useful
    /// for programmatic rule sets and tests.
    pub fn from_entries<I, C>(entries: I) -> Self
    where
        I: IntoIterator<Item = (String, C)>,
        C: IntoIterator<Item = GeoCidr>,
    {
        let mut by_code: AHashMap<String, Vec<GeoCidr>> = AHashMap::new();
        for (code, cidrs) in entries {
            by_code
                .entry(code.to_ascii_uppercase())
                .or_default()
                .extend(cidrs);
        }
        Self { by_code }
    }

    /// CIDRs for a country code (case-insensitive), if present.
    pub fn cidrs(&self, code: &str) -> Option<&[GeoCidr]> {
        self.by_code
            .get(&code.to_ascii_uppercase())
            .map(Vec::as_slice)
    }

    /// Whether `ip` falls in any CIDR of the given country code.
    pub fn contains(&self, code: &str, ip: &IpAddr) -> bool {
        self.cidrs(code)
            .is_some_and(|cidrs| cidrs.iter().any(|c| c.contains(ip)))
    }

    /// Number of country codes loaded.
    pub fn len(&self) -> usize {
        self.by_code.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_code.is_empty()
    }
}

// ---- GeoSite --------------------------------------------------------

/// A parsed domain rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainRule {
    /// Exact match (`Full`).
    Full(String),
    /// Domain + subdomains (`Domain`).
    Suffix(String),
    /// Substring (`Plain`).
    Keyword(String),
    /// Regex — not evaluated (kept for completeness; never matches).
    Regex(String),
}

impl DomainRule {
    fn from_proto(d: &Domain) -> Self {
        let value = d.value.to_ascii_lowercase();
        match DomainType::try_from(d.r#type).unwrap_or(DomainType::Plain) {
            DomainType::Full => DomainRule::Full(value),
            DomainType::Domain => DomainRule::Suffix(value),
            DomainType::Plain => DomainRule::Keyword(value),
            DomainType::Regex => DomainRule::Regex(value),
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        match self {
            DomainRule::Full(v) => h == *v,
            DomainRule::Suffix(v) => h == *v || h.ends_with(&format!(".{v}")),
            DomainRule::Keyword(v) => h.contains(v.as_str()),
            DomainRule::Regex(_) => false,
        }
    }
}

/// A parsed `geosite.dat`, indexed by upper-cased category code.
#[derive(Debug, Clone, Default)]
pub struct GeoSiteDb {
    by_code: AHashMap<String, Vec<DomainRule>>,
}

impl GeoSiteDb {
    /// Parse a `geosite.dat` (protobuf `GeoSiteList`).
    pub fn parse(data: &[u8]) -> Result<Self, GeoError> {
        let list = GeoSiteList::decode(data)?;
        let mut by_code: AHashMap<String, Vec<DomainRule>> = AHashMap::new();
        for entry in &list.entry {
            let code = entry.country_code.to_ascii_uppercase();
            let rules = entry
                .domain
                .iter()
                .map(DomainRule::from_proto)
                .collect::<Vec<_>>();
            by_code.entry(code).or_default().extend(rules);
        }
        Ok(Self { by_code })
    }

    /// Build a database from explicit `(code, rules)` entries.
    pub fn from_entries<I, R>(entries: I) -> Self
    where
        I: IntoIterator<Item = (String, R)>,
        R: IntoIterator<Item = DomainRule>,
    {
        let mut by_code: AHashMap<String, Vec<DomainRule>> = AHashMap::new();
        for (code, rules) in entries {
            by_code
                .entry(code.to_ascii_uppercase())
                .or_default()
                .extend(rules);
        }
        Self { by_code }
    }

    /// Domain rules for a category code (case-insensitive), if present.
    pub fn rules(&self, code: &str) -> Option<&[DomainRule]> {
        self.by_code
            .get(&code.to_ascii_uppercase())
            .map(Vec::as_slice)
    }

    /// Whether `host` matches any rule of the given category code.
    pub fn matches(&self, code: &str, host: &str) -> bool {
        self.rules(code)
            .is_some_and(|rules| rules.iter().any(|r| r.matches(host)))
    }

    pub fn len(&self) -> usize {
        self.by_code.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_code.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(ip: &str, prefix: u32) -> Cidr {
        let bytes = match ip.parse::<IpAddr>().unwrap() {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        Cidr { ip: bytes, prefix }
    }

    #[test]
    fn geoip_roundtrip_and_contains() {
        let list = GeoIpList {
            entry: vec![
                GeoIp {
                    country_code: "CN".into(),
                    cidr: vec![cidr("10.0.0.0", 8), cidr("2001:db8::", 32)],
                    reverse_match: false,
                },
                GeoIp {
                    country_code: "us".into(),
                    cidr: vec![cidr("8.8.8.0", 24)],
                    reverse_match: false,
                },
            ],
        };
        let bytes = list.encode_to_vec();
        let db = GeoIpDb::parse(&bytes).unwrap();
        assert_eq!(db.len(), 2);
        assert!(db.contains("cn", &"10.1.2.3".parse().unwrap()));
        assert!(db.contains("CN", &"2001:db8::1".parse().unwrap()));
        assert!(!db.contains("cn", &"11.0.0.1".parse().unwrap()));
        assert!(db.contains("US", &"8.8.8.8".parse().unwrap()));
        assert!(!db.contains("us", &"8.8.9.1".parse().unwrap()));
        assert!(!db.contains("zz", &"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn geosite_roundtrip_and_matches() {
        let list = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "ADS".into(),
                domain: vec![
                    Domain {
                        r#type: DomainType::Full as i32,
                        value: "ads.example.com".into(),
                    },
                    Domain {
                        r#type: DomainType::Domain as i32,
                        value: "doubleclick.net".into(),
                    },
                    Domain {
                        r#type: DomainType::Plain as i32,
                        value: "tracker".into(),
                    },
                    Domain {
                        r#type: DomainType::Regex as i32,
                        value: ".*".into(),
                    },
                ],
            }],
        };
        let bytes = list.encode_to_vec();
        let db = GeoSiteDb::parse(&bytes).unwrap();
        assert!(db.matches("ads", "ads.example.com")); // Full
        assert!(!db.matches("ads", "x.ads.example.com")); // Full is exact
        assert!(db.matches("ADS", "a.doubleclick.net")); // Domain suffix
        assert!(db.matches("ads", "doubleclick.net"));
        assert!(db.matches("ads", "evil-tracker-host.com")); // Plain keyword
        assert!(!db.matches("ads", "clean.example.org"));
        assert!(!db.matches("missing", "anything.com"));
    }
}
