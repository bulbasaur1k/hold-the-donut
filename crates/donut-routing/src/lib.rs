//! donut-routing — match engine: domain / ip-cidr / port → outbound tag.
//!
//! A [`Router`] holds an ordered list of [`Rule`]s and a default outbound
//! tag. [`Router::route`] returns the tag of the **first** rule that
//! matches the target [`Endpoint`], or the default if none do.
//!
//! Rule semantics: a rule matches if the target satisfies **any** of its
//! conditions (OR). A rule with no conditions never matches — use the
//! router default for a catch-all. Geo (`geoip:`/`geosite:`) conditions
//! will plug in as an extra [`Condition`] variant once `donut-geo` lands.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use donut_core::{Address, Endpoint};
use donut_geo::{GeoIpDb, GeoSiteDb};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("invalid CIDR {0}")]
    Cidr(String),
    #[error("invalid port spec {0}")]
    Port(String),
    #[error("rule references {0} but no matching geo database was loaded")]
    MissingGeo(String),
}

/// How a domain string is matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainMatch {
    /// Exact, case-insensitive match.
    Full(String),
    /// Matches the domain itself and any subdomain (`example.com` matches
    /// `example.com` and `a.example.com`, not `notexample.com`).
    Suffix(String),
    /// Case-insensitive substring match.
    Keyword(String),
}

impl DomainMatch {
    fn matches(&self, host: &str) -> bool {
        match self {
            DomainMatch::Full(d) => host.eq_ignore_ascii_case(d),
            DomainMatch::Suffix(d) => {
                let d = d.trim_start_matches('.').to_ascii_lowercase();
                let h = host.to_ascii_lowercase();
                h == d || h.ends_with(&format!(".{d}"))
            }
            DomainMatch::Keyword(k) => host.to_ascii_lowercase().contains(&k.to_ascii_lowercase()),
        }
    }
}

/// An IP network in CIDR form, e.g. `10.0.0.0/8` or `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
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
    // Build the top-`prefix` mask in 128-bit space, then shift it down so
    // it lines up with addresses kept in the low `bits` bits (v4 lives in
    // the low 32 bits; v6 uses all 128, shift = 0).
    let mask = (u128::MAX << (128 - prefix as u32)) >> (128 - bits as u32);
    (net & mask) == (ip & mask)
}

impl FromStr for Cidr {
    type Err = RoutingError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (net_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| RoutingError::Cidr(s.into()))?;
        let net: IpAddr = net_str.parse().map_err(|_| RoutingError::Cidr(s.into()))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| RoutingError::Cidr(s.into()))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(RoutingError::Cidr(s.into()));
        }
        Ok(Cidr { net, prefix })
    }
}

/// One condition within a [`Rule`].
#[derive(Debug, Clone)]
pub enum Condition {
    Domain(DomainMatch),
    Cidr(Cidr),
    /// Inclusive port range `[lo, hi]`.
    Ports(u16, u16),
    /// Target IP belongs to `code` in a GeoIP database (`geoip:<code>`).
    GeoIp {
        db: Arc<GeoIpDb>,
        code: String,
    },
    /// Target domain matches `code` in a GeoSite database (`geosite:<code>`).
    GeoSite {
        db: Arc<GeoSiteDb>,
        code: String,
    },
}

impl Condition {
    fn matches(&self, target: &Endpoint) -> bool {
        match self {
            Condition::Domain(m) => match &target.address {
                Address::Domain(d) => m.matches(d),
                Address::Ip(_) => false,
            },
            Condition::Cidr(c) => match &target.address {
                Address::Ip(ip) => c.contains(ip),
                Address::Domain(_) => false,
            },
            Condition::Ports(lo, hi) => target.port >= *lo && target.port <= *hi,
            Condition::GeoIp { db, code } => match &target.address {
                Address::Ip(ip) => db.contains(code, ip),
                Address::Domain(_) => false,
            },
            Condition::GeoSite { db, code } => match &target.address {
                Address::Domain(d) => db.matches(code, d),
                Address::Ip(_) => false,
            },
        }
    }
}

/// An ordered routing rule: matches if the target satisfies any of its
/// conditions, routing to `outbound`.
#[derive(Debug, Clone)]
pub struct Rule {
    conditions: Vec<Condition>,
    outbound: String,
}

impl Rule {
    /// Start a rule routing to `outbound` (no conditions yet — add some).
    pub fn to(outbound: impl Into<String>) -> Self {
        Self {
            conditions: Vec::new(),
            outbound: outbound.into(),
        }
    }
    pub fn domain(mut self, m: DomainMatch) -> Self {
        self.conditions.push(Condition::Domain(m));
        self
    }
    pub fn cidr(mut self, c: Cidr) -> Self {
        self.conditions.push(Condition::Cidr(c));
        self
    }
    pub fn ports(mut self, lo: u16, hi: u16) -> Self {
        self.conditions.push(Condition::Ports(lo, hi));
        self
    }
    pub fn geoip(mut self, db: Arc<GeoIpDb>, code: impl Into<String>) -> Self {
        self.conditions.push(Condition::GeoIp {
            db,
            code: code.into(),
        });
        self
    }
    pub fn geosite(mut self, db: Arc<GeoSiteDb>, code: impl Into<String>) -> Self {
        self.conditions.push(Condition::GeoSite {
            db,
            code: code.into(),
        });
        self
    }
    fn matches(&self, target: &Endpoint) -> bool {
        self.conditions.iter().any(|c| c.matches(target))
    }
}

/// Ordered rule set with a default outbound tag.
#[derive(Debug, Clone)]
pub struct Router {
    rules: Vec<Rule>,
    default_outbound: String,
}

impl Router {
    pub fn new(default_outbound: impl Into<String>) -> Self {
        Self {
            rules: Vec::new(),
            default_outbound: default_outbound.into(),
        }
    }

    pub fn with_rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Tag of the first matching rule, or the default.
    pub fn route(&self, target: &Endpoint) -> &str {
        for rule in &self.rules {
            if rule.matches(target) {
                return &rule.outbound;
            }
        }
        &self.default_outbound
    }
}

// ---- config-facing form -------------------------------------------

/// Serde form of a single rule (as it appears in JSON config). `ip` are
/// CIDR strings, `port` are `"443"` or `"80-100"` specs; both are
/// compiled in [`RoutingConfig::build`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConfig {
    #[serde(default)]
    pub domain: Vec<DomainMatch>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    /// GeoIP country codes (`geoip:<code>`); needs a loaded GeoIP db.
    #[serde(default)]
    pub geoip: Vec<String>,
    /// GeoSite category codes (`geosite:<code>`); needs a loaded GeoSite db.
    #[serde(default)]
    pub geosite: Vec<String>,
    pub outbound: String,
}

/// Serde form of the routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default = "default_outbound")]
    pub default: String,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

fn default_outbound() -> String {
    "freedom".to_string()
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default: default_outbound(),
            rules: Vec::new(),
        }
    }
}

impl RoutingConfig {
    /// Compile the config form into a runtime [`Router`], parsing CIDR and
    /// port specs. Errors if any rule references `geoip:`/`geosite:` (use
    /// [`RoutingConfig::build_with_geo`] to supply the databases).
    pub fn build(&self) -> Result<Router, RoutingError> {
        self.build_with_geo(None, None)
    }

    /// Like [`build`](Self::build), but `geoip:`/`geosite:` rule conditions
    /// resolve against the supplied databases.
    pub fn build_with_geo(
        &self,
        geoip_db: Option<Arc<GeoIpDb>>,
        geosite_db: Option<Arc<GeoSiteDb>>,
    ) -> Result<Router, RoutingError> {
        let mut router = Router::new(self.default.clone());
        for rc in &self.rules {
            let mut rule = Rule::to(rc.outbound.clone());
            for d in &rc.domain {
                rule = rule.domain(d.clone());
            }
            for c in &rc.ip {
                rule = rule.cidr(c.parse()?);
            }
            for p in &rc.port {
                let (lo, hi) = parse_port_spec(p)?;
                rule = rule.ports(lo, hi);
            }
            for code in &rc.geoip {
                let db = geoip_db
                    .clone()
                    .ok_or_else(|| RoutingError::MissingGeo(format!("geoip:{code}")))?;
                rule = rule.geoip(db, code.clone());
            }
            for code in &rc.geosite {
                let db = geosite_db
                    .clone()
                    .ok_or_else(|| RoutingError::MissingGeo(format!("geosite:{code}")))?;
                rule = rule.geosite(db, code.clone());
            }
            router = router.with_rule(rule);
        }
        Ok(router)
    }
}

fn parse_port_spec(s: &str) -> Result<(u16, u16), RoutingError> {
    let s = s.trim();
    if let Some((a, b)) = s.split_once('-') {
        let lo = a.trim().parse().map_err(|_| RoutingError::Port(s.into()))?;
        let hi = b.trim().parse().map_err(|_| RoutingError::Port(s.into()))?;
        if lo > hi {
            return Err(RoutingError::Port(s.into()));
        }
        Ok((lo, hi))
    } else {
        let p = s.parse().map_err(|_| RoutingError::Port(s.into()))?;
        Ok((p, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str, port: u16) -> Endpoint {
        Endpoint::new(host.parse().unwrap(), port)
    }

    #[test]
    fn domain_suffix_matches_subdomains_only() {
        let m = DomainMatch::Suffix("example.com".into());
        assert!(m.matches("example.com"));
        assert!(m.matches("a.example.com"));
        assert!(m.matches("A.Example.Com"));
        assert!(!m.matches("notexample.com"));
        assert!(!m.matches("example.org"));
    }

    #[test]
    fn domain_full_and_keyword() {
        assert!(DomainMatch::Full("a.com".into()).matches("A.COM"));
        assert!(!DomainMatch::Full("a.com".into()).matches("x.a.com"));
        assert!(DomainMatch::Keyword("goog".into()).matches("www.google.com"));
        assert!(!DomainMatch::Keyword("goog".into()).matches("example.com"));
    }

    #[test]
    fn cidr_v4_contains() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!c.contains(&"11.0.0.1".parse().unwrap()));
        let host: Cidr = "192.168.1.0/24".parse().unwrap();
        assert!(host.contains(&"192.168.1.255".parse().unwrap()));
        assert!(!host.contains(&"192.168.2.0".parse().unwrap()));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_contains_and_cross_family() {
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!c.contains(&"2001:db9::1".parse().unwrap()));
        // v4 address never matches a v6 cidr and vice versa.
        assert!(!c.contains(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn bad_cidr_errors() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("nonsense".parse::<Cidr>().is_err());
    }

    #[test]
    fn router_first_match_wins_else_default() {
        let router = Router::new("direct")
            .with_rule(Rule::to("block").domain(DomainMatch::Suffix("ads.example".into())))
            .with_rule(Rule::to("proxy").cidr("10.0.0.0/8".parse().unwrap()))
            .with_rule(Rule::to("proxy").ports(443, 443));

        assert_eq!(router.route(&ep("ads.example", 80)), "block");
        assert_eq!(router.route(&ep("x.ads.example", 80)), "block");
        assert_eq!(router.route(&ep("10.2.3.4", 22)), "proxy");
        assert_eq!(router.route(&ep("8.8.8.8", 443)), "proxy"); // port rule
        assert_eq!(router.route(&ep("8.8.8.8", 22)), "direct"); // default
        assert_eq!(router.route(&ep("good.example", 22)), "direct");
    }

    #[test]
    fn empty_rule_never_matches() {
        let router = Router::new("direct").with_rule(Rule::to("proxy"));
        assert_eq!(router.route(&ep("anything.com", 80)), "direct");
    }

    #[test]
    fn routing_config_builds_and_routes() {
        let json = r#"{
            "default": "freedom",
            "rules": [
                { "domain": [{"suffix": "ads.com"}], "outbound": "block" },
                { "ip": ["10.0.0.0/8"], "port": ["443", "8000-8080"], "outbound": "block" }
            ]
        }"#;
        let cfg: RoutingConfig = serde_json::from_str(json).unwrap();
        let router = cfg.build().unwrap();
        assert_eq!(router.route(&ep("x.ads.com", 80)), "block");
        assert_eq!(router.route(&ep("10.1.1.1", 22)), "block");
        assert_eq!(router.route(&ep("8.8.8.8", 443)), "block");
        assert_eq!(router.route(&ep("8.8.8.8", 8050)), "block");
        assert_eq!(router.route(&ep("8.8.8.8", 22)), "freedom");
    }

    #[test]
    fn default_routing_config_is_freedom_passthrough() {
        let router = RoutingConfig::default().build().unwrap();
        assert_eq!(router.route(&ep("anything.com", 443)), "freedom");
    }

    #[test]
    fn routing_config_with_geo_conditions() {
        use donut_geo::{DomainRule, GeoCidr, GeoIpDb, GeoSiteDb};

        let ip_db = Arc::new(GeoIpDb::from_entries([(
            "CN".to_string(),
            vec![GeoCidr::new("10.0.0.0".parse().unwrap(), 8)],
        )]));
        let site_db = Arc::new(GeoSiteDb::from_entries([(
            "ADS".to_string(),
            vec![DomainRule::Suffix("ads.com".to_string())],
        )]));

        let json = r#"{
            "default": "freedom",
            "rules": [
                { "geoip": ["cn"], "outbound": "block" },
                { "geosite": ["ads"], "outbound": "block" }
            ]
        }"#;
        let cfg: RoutingConfig = serde_json::from_str(json).unwrap();

        // Geo rules without databases → build() fails.
        assert!(matches!(cfg.build(), Err(RoutingError::MissingGeo(_))));

        let router = cfg
            .build_with_geo(Some(ip_db), Some(site_db))
            .expect("build with geo");
        assert_eq!(router.route(&ep("10.5.5.5", 80)), "block"); // geoip:cn
        assert_eq!(router.route(&ep("x.ads.com", 80)), "block"); // geosite:ads
        assert_eq!(router.route(&ep("8.8.8.8", 80)), "freedom"); // default
        assert_eq!(router.route(&ep("clean.example", 80)), "freedom");
    }
}
