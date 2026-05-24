//! donut-dns — minimal async resolver: system config or DoH.
//!
//! Server-side name resolution for the freedom outbound. IP literals
//! short-circuit (no query). DoH keeps the exit node's lookups off the
//! local/system resolver. Built on `hickory-resolver`.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::net::{IpAddr, SocketAddr};

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("resolve {host}: {source}")]
    Resolve {
        host: String,
        source: hickory_resolver::error::ResolveError,
    },
    #[error("system resolver: {0}")]
    System(hickory_resolver::error::ResolveError),
    #[error("no addresses for {0}")]
    NoAddresses(String),
}

/// Async resolver. Cheaply cloneable (the inner hickory resolver is an
/// `Arc` under the hood).
#[derive(Clone)]
pub struct Resolver {
    inner: TokioAsyncResolver,
}

impl Resolver {
    /// Resolver from the system configuration (`/etc/resolv.conf` etc.).
    pub fn system() -> Result<Self, DnsError> {
        let inner = TokioAsyncResolver::tokio_from_system_conf().map_err(DnsError::System)?;
        Ok(Self { inner })
    }

    /// DNS-over-HTTPS resolver over `ips` (e.g. `1.1.1.1`), presenting
    /// `tls_name` as the TLS server name (e.g. `cloudflare-dns.com`).
    pub fn doh(ips: &[IpAddr], tls_name: &str) -> Self {
        let group = NameServerConfigGroup::from_ips_https(ips, 443, tls_name.to_string(), true);
        let config = ResolverConfig::from_parts(None, Vec::new(), group);
        Self {
            inner: TokioAsyncResolver::tokio(config, ResolverOpts::default()),
        }
    }

    /// Resolve `host` to `host:port` socket addresses. An IP literal in
    /// `host` short-circuits without a query.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|source| DnsError::Resolve {
                host: host.to_string(),
                source,
            })?;
        let addrs: Vec<SocketAddr> = lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect();
        if addrs.is_empty() {
            return Err(DnsError::NoAddresses(host.to_string()));
        }
        Ok(addrs)
    }

    /// Resolve and return the first address.
    pub async fn resolve_one(&self, host: &str, port: u16) -> Result<SocketAddr, DnsError> {
        self.resolve(host, port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| DnsError::NoAddresses(host.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ip_literal_short_circuits_without_query() {
        // `doh()` builds config without touching the network; an IP
        // literal never reaches the resolver.
        let r = Resolver::doh(&["1.1.1.1".parse().unwrap()], "cloudflare-dns.com");
        assert_eq!(
            r.resolve("93.184.216.34", 443).await.unwrap(),
            vec!["93.184.216.34:443".parse().unwrap()]
        );
        assert_eq!(
            r.resolve_one("::1", 80).await.unwrap(),
            "[::1]:80".parse().unwrap()
        );
    }
}
