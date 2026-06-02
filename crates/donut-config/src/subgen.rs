//! Client-config generation for off-the-shelf VLESS / xHTTP clients.
//!
//! Pure functions: given the public connection parameters of an xHTTP
//! inbound, emit an **Xray-format `client.json`**, a **`vless://` share
//! link**, or a **Clash-Meta (mihomo) YAML** profile. Shared by
//! `donut-tools config-gen` and the donut-server subscription endpoint so
//! both stay byte-identical.
//!
//! All three carry the same shape we validated against real xray 26.5.9:
//! xHTTP + TLS(H2) + the requested uTLS fingerprint + **XMUX** (H2
//! connection multiplexing) + pure-XUDP mux (UDP/QUIC over `Command::Mux`).

use serde_json::{json, Value};

/// Public connection parameters a client needs to reach an xHTTP inbound.
#[derive(Debug, Clone)]
pub struct XhttpParams {
    /// VLESS user UUID.
    pub uuid: String,
    /// `host:port` the client dials (your public domain + port).
    pub server_addr: String,
    /// TLS SNI / `serverName`.
    pub sni: String,
    /// xHTTP `Host` / `:authority` (pinned server-side).
    pub host: String,
    /// Secret path prefix.
    pub path: String,
    /// Framing mode (`stream-up` canonical).
    pub mode: String,
    /// uTLS ClientHello fingerprint (`firefox`, `chrome`, …).
    pub fp: String,
    /// Local SOCKS5 `host:port` the generated client opens.
    pub socks: String,
    /// Human label (share-link fragment / Clash proxy name).
    pub label: String,
}

/// Which routing table to bake into a generated full config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingProfile {
    /// `geoip:ru` + private + RU geosites → direct, ads → block, the rest →
    /// proxy. A split-tunnel that keeps Russian traffic off the tunnel.
    RuSplit,
    /// Everything → proxy; only private/loopback → direct, ads → block.
    ProxyAll,
}

impl RoutingProfile {
    /// Parse the `?profile=` query value; defaults to [`RuSplit`].
    pub fn parse(s: &str) -> Self {
        match s {
            "all" | "proxy-all" | "proxyall" => Self::ProxyAll,
            _ => Self::RuSplit,
        }
    }
}

/// Build an Xray-compatible **xHTTP** `vless://` share URI.
pub fn vless_xhttp_link(p: &XhttpParams) -> String {
    let params: Vec<(&str, &str)> = vec![
        ("type", "xhttp"),
        ("security", "tls"),
        ("encryption", "none"),
        ("sni", &p.sni),
        ("fp", &p.fp),
        ("alpn", "h2"),
        ("host", &p.host),
        ("path", &p.path),
        ("mode", &p.mode),
    ];
    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", pct(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!(
        "vless://{}@{}?{}#{}",
        p.uuid,
        p.server_addr,
        query,
        pct(&p.label)
    )
}

/// The VLESS+xHTTP+TLS proxy outbound (tag `proxy`), with XMUX + XUDP mux.
fn xray_proxy_outbound(p: &XhttpParams) -> Value {
    let (saddr, sport) = split_host_port(&p.server_addr, 443);
    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": { "vnext": [{
            "address": saddr, "port": sport,
            "users": [{ "id": p.uuid, "encryption": "none" }]
        }]},
        "streamSettings": {
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": { "serverName": p.sni, "alpn": ["h2"], "fingerprint": p.fp },
            "xhttpSettings": {
                "host": p.host, "path": p.path, "mode": p.mode,
                // XMUX — multiplex many proxy requests over one H2 connection
                // and recycle connections (RPRX-recommended ranges).
                "xmux": {
                    "maxConcurrency": "16-32",
                    "maxConnections": 0,
                    "cMaxReuseTimes": 0,
                    "hMaxRequestTimes": "600-900",
                    "hMaxReusableSecs": "1800-3000",
                    "hKeepAlivePeriod": 0
                }
            }
        },
        // pure-XUDP: TCP direct (XMUX handles it), UDP via XUDP mux.
        "mux": { "enabled": true, "concurrency": -1, "xudpConcurrency": 16, "xudpProxyUDP443": "reject" }
    })
}

/// Xray routing table for `profile`. Uses `outboundTag` (modern xray).
fn xray_routing(profile: RoutingProfile) -> Value {
    let mut rules = vec![
        // Never tunnel LAN / loopback.
        json!({ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }),
        // Drop ads/malware everywhere.
        json!({ "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" }),
    ];
    if profile == RoutingProfile::RuSplit {
        // Russian sites + IPs stay off the tunnel (split-tunnel).
        // RU domains → direct. `category-ru` is the universal RU umbrella
        // (present in v2fly/Loyalsoldier, MetaCubeX and runetfreedom dats);
        // the `.ru` regexp needs no geo data at all. We deliberately avoid
        // dat-specific subcategories (e.g. `yandex`, `vk`, `category-gov-ru`)
        // because xray rejects the WHOLE config if one is missing from the
        // client's geosite.dat.
        rules.push(json!({
            "type": "field",
            "domain": ["geosite:category-ru", "regexp:.+\\.ru$"],
            "outboundTag": "direct"
        }));
        rules.push(json!({ "type": "field", "ip": ["geoip:ru"], "outboundTag": "direct" }));
    }
    // Everything else → proxy.
    rules.push(json!({ "type": "field", "port": "0-65535", "outboundTag": "proxy" }));
    json!({ "domainStrategy": "IPIfNonMatch", "rules": rules })
}

/// XRAY-JSON **subscription** (XTLS standard, XTLS/Xray-core#3765): a JSON
/// array of full configs. Unlike a bare link, the `routing` is baked in, so
/// RU-split is **enforced** — the client can't accidentally tunnel RU traffic.
/// This is how commercial providers ship configs. Inbounds use the de-facto
/// 10808/10809 (not 1080) so HAPP's "JSON overrides app inbound" rule doesn't
/// clash with a stale :1080 holder.
pub fn xray_json_subscription(p: &XhttpParams, profile: RoutingProfile) -> Value {
    json!([{
        "remarks": p.label,
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": [
                // Resolve RU domains via a Russian resolver so they map to RU
                // IPs and the geoip:ru rule catches them (tighter RU-split).
                { "address": "77.88.8.8", "domains": ["geosite:category-ru"], "expectIPs": ["geoip:ru"] },
                "https://cloudflare-dns.com/dns-query"
            ]
        },
        "inbounds": [
            { "tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": { "udp": true } },
            { "tag": "http-in",  "listen": "127.0.0.1", "port": 10809, "protocol": "http" }
        ],
        "outbounds": [
            xray_proxy_outbound(p),
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block",  "protocol": "blackhole" }
        ],
        "routing": xray_routing(profile),
        "meta": { "serverDescription": "donut" }
    }])
}

/// A HAPP **routing profile** (the app's own `directSites`/`directIp`/… model,
/// distinct from an xray `routing` block). HAPP applies this to whatever
/// connection it manages — so a `links` subscription stays import-clean (no
/// inbound to clash on :1080) while RU-split rules still land.
fn happ_routing_profile(profile: RoutingProfile) -> Value {
    let (global, direct_sites, direct_ip) = match profile {
        RoutingProfile::RuSplit => (
            "false",
            json!(["geosite:category-ru", "geosite:private"]),
            json!(["geoip:ru", "geoip:private"]),
        ),
        // Everything tunnelled; only private stays direct.
        RoutingProfile::ProxyAll => ("true", json!(["geosite:private"]), json!(["geoip:private"])),
    };
    json!({
        "Name": "donut RU-split",
        "GlobalProxy": global,
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "RemoteDNSIP": "1.1.1.1",
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "",
        "DomesticDNSIP": "77.88.8.8",
        "Geoipurl": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
        "Geositeurl": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        "LastUpdated": "",
        "DnsHosts": {},
        "DirectSites": direct_sites,
        "DirectIp": direct_ip,
        "ProxySites": [],
        "ProxyIp": [],
        "BlockSites": ["geosite:category-ads-all"],
        "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false"
    })
}

/// HAPP routing deeplink (`happ://routing/onadd/<base64-json>`). HAPP parses
/// this from a subscription body and applies the RU-split routing profile —
/// the documented way to push routing rules into HAPP.
pub fn happ_routing_deeplink(profile: RoutingProfile) -> String {
    use base64::Engine;
    let json = serde_json::to_string(&happ_routing_profile(profile)).expect("static json");
    let b64 = base64::engine::general_purpose::STANDARD.encode(json);
    format!("happ://routing/onadd/{b64}")
}

/// HAPP subscription **body** (plain, pre-base64): the `vless://` connection
/// link plus the routing deeplink, one per line. The subscription endpoint
/// base64-wraps this; HAPP decodes it, imports the profile, and applies the
/// RU-split routing — connection + rules from a single subscription URL.
pub fn happ_subscription_body(p: &XhttpParams, profile: RoutingProfile) -> String {
    format!(
        "{}\n{}\n",
        vless_xhttp_link(p),
        happ_routing_deeplink(profile)
    )
}

/// Build a full **xray-format** `client.json` for the xHTTP transport with
/// the given routing `profile` (geoip/geosite split). The `geoip:`/
/// `geosite:` tags resolve against the client's own `geoip.dat`/
/// `geosite.dat` (HAPP and friends bundle them).
pub fn xray_client_json(p: &XhttpParams, profile: RoutingProfile) -> Value {
    let (laddr, lport) = split_host_port(&p.socks, 1080);
    json!({
        "log": { "loglevel": "warning" },
        "dns": { "servers": ["https://1.1.1.1/dns-query", "1.1.1.1", "localhost"] },
        "inbounds": [{
            "tag": "socks-in", "listen": laddr, "port": lport,
            "protocol": "socks", "settings": { "udp": true },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
        }],
        "outbounds": [
            xray_proxy_outbound(p),
            { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "UseIP" } },
            { "tag": "block", "protocol": "blackhole", "settings": { "response": { "type": "http" } } }
        ],
        "routing": xray_routing(profile)
    })
}

/// Build a **Clash-Meta (mihomo) YAML** profile for the xHTTP transport.
///
/// xHTTP support in mihomo is recent — this targets the mihomo `vless` +
/// `network: xhttp` schema. The xray `client.json` is the reference; treat
/// the Clash output as best-effort for mihomo builds that speak xHTTP.
pub fn clash_yaml(p: &XhttpParams, profile: RoutingProfile) -> String {
    let (_laddr, lport) = split_host_port(&p.socks, 1080);
    let (saddr, sport) = split_host_port(&p.server_addr, 443);
    let name = &p.label;
    let mut y = String::new();
    y.push_str("# Clash-Meta (mihomo) profile — generated by donut.\n");
    y.push_str("# Requires a mihomo build with xHTTP support.\n");
    y.push_str(&format!("mixed-port: {lport}\n"));
    y.push_str("mode: rule\n");
    y.push_str("proxies:\n");
    y.push_str(&format!("  - name: \"{name}\"\n"));
    y.push_str("    type: vless\n");
    y.push_str(&format!("    server: {saddr}\n"));
    y.push_str(&format!("    port: {sport}\n"));
    y.push_str(&format!("    uuid: {}\n", p.uuid));
    y.push_str("    udp: true\n");
    y.push_str("    tls: true\n");
    y.push_str(&format!("    servername: {}\n", p.sni));
    y.push_str(&format!("    client-fingerprint: {}\n", p.fp));
    y.push_str("    alpn: [h2]\n");
    y.push_str("    skip-cert-verify: false\n");
    y.push_str("    network: xhttp\n");
    y.push_str("    xhttp-opts:\n");
    y.push_str(&format!("      mode: {}\n", p.mode));
    y.push_str(&format!("      host: {}\n", p.host));
    y.push_str(&format!("      path: {}\n", p.path));
    // XMUX in mihomo is `xhttp-opts.reuse-settings` (RPRX-recommended ranges).
    y.push_str("      reuse-settings:\n");
    y.push_str("        max-concurrency: \"16-32\"\n");
    y.push_str("        h-max-request-times: \"600-900\"\n");
    y.push_str("        h-max-reusable-secs: \"1800-3000\"\n");
    y.push_str("proxy-groups:\n");
    y.push_str(&format!(
        "  - {{ name: PROXY, type: select, proxies: [\"{name}\", DIRECT] }}\n"
    ));
    y.push_str("rules:\n");
    y.push_str("  - GEOSITE,category-ads-all,REJECT\n");
    if profile == RoutingProfile::RuSplit {
        y.push_str("  - GEOSITE,category-ru,DIRECT\n");
        y.push_str("  - GEOIP,RU,DIRECT\n");
    }
    y.push_str("  - GEOIP,private,DIRECT,no-resolve\n");
    y.push_str("  - MATCH,PROXY\n");
    y
}

/// Split `host:port` into `(host, port)`, falling back to `default_port`.
pub fn split_host_port(addr: &str, default_port: u16) -> (String, u16) {
    match addr.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (addr.to_string(), default_port),
    }
}

/// Percent-encode an RFC 3986 query/fragment value (encode everything that
/// isn't an unreserved character).
pub fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> XhttpParams {
        XhttpParams {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            server_addr: "edge.example:443".into(),
            sni: "edge.example".into(),
            host: "edge.example".into(),
            path: "/secret".into(),
            mode: "stream-up".into(),
            fp: "firefox".into(),
            socks: "127.0.0.1:1080".into(),
            label: "donut-xhttp".into(),
        }
    }

    #[test]
    fn link_has_xhttp_wire_params() {
        let l = vless_xhttp_link(&params());
        assert!(l.starts_with("vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example:443?"));
        for kv in ["type=xhttp", "security=tls", "fp=firefox", "mode=stream-up"] {
            assert!(l.contains(kv), "link missing {kv}: {l}");
        }
        assert!(
            l.contains("path=%2Fsecret"),
            "path must be percent-encoded: {l}"
        );
    }

    #[test]
    fn xray_json_has_xmux_and_ru_split() {
        let j = xray_client_json(&params(), RoutingProfile::RuSplit);
        let ob = &j["outbounds"][0];
        assert_eq!(ob["streamSettings"]["network"], "xhttp");
        assert_eq!(
            ob["streamSettings"]["xhttpSettings"]["xmux"]["maxConcurrency"],
            "16-32"
        );
        assert_eq!(ob["mux"]["xudpConcurrency"], 16);
        // RU split-tunnel rule present.
        let rules = j["routing"]["rules"].as_array().unwrap();
        let has_ru = rules.iter().any(|r| {
            r["ip"]
                .as_array()
                .map(|a| a.iter().any(|v| v == "geoip:ru"))
                .unwrap_or(false)
        });
        assert!(has_ru, "RU geoip rule missing: {j}");
    }

    #[test]
    fn proxy_all_drops_ru_rule() {
        let j = xray_client_json(&params(), RoutingProfile::ProxyAll);
        let rules = j["routing"]["rules"].as_array().unwrap();
        let has_ru = rules.iter().any(|r| {
            r["ip"]
                .as_array()
                .map(|a| a.iter().any(|v| v == "geoip:ru"))
                .unwrap_or(false)
        });
        assert!(!has_ru, "ProxyAll must not have RU rule");
    }

    #[test]
    fn clash_yaml_is_vless_xhttp() {
        let y = clash_yaml(&params(), RoutingProfile::RuSplit);
        assert!(y.contains("type: vless"));
        assert!(y.contains("network: xhttp"));
        assert!(y.contains("client-fingerprint: firefox"));
        // XMUX = mihomo's xhttp-opts.reuse-settings.
        assert!(y.contains("reuse-settings:"));
        assert!(y.contains("max-concurrency: \"16-32\""));
        assert!(y.contains("GEOIP,RU,DIRECT"));
    }

    #[test]
    fn xray_json_subscription_is_array_with_baked_routing() {
        let v = xray_json_subscription(&params(), RoutingProfile::RuSplit);
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        let c = &arr[0];
        // Provider-style inbound on 10808 (not the clashing 1080).
        assert_eq!(c["inbounds"][0]["port"], 10808);
        // Routing baked in with the RU-direct rule → enforced split-tunnel.
        let rules = c["routing"]["rules"].as_array().unwrap();
        let has_ru = rules.iter().any(|r| {
            r["ip"]
                .as_array()
                .map(|a| a.iter().any(|v| v == "geoip:ru"))
                .unwrap_or(false)
        });
        assert!(has_ru, "JSON subscription must bake in geoip:ru → direct");
        // Standard outbound tags present.
        let tags: Vec<&str> = c["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["tag"].as_str())
            .collect();
        assert!(tags.contains(&"proxy") && tags.contains(&"direct") && tags.contains(&"block"));
    }

    #[test]
    fn happ_subscription_bundles_link_and_routing() {
        use base64::Engine;
        let body = happ_subscription_body(&params(), RoutingProfile::RuSplit);
        // Connection link present.
        assert!(body.contains("vless://"));
        assert!(body.contains("type=xhttp"));
        // Routing deeplink present and decodes to a HAPP RU-split profile.
        let line = body
            .lines()
            .find(|l| l.starts_with("happ://routing/onadd/"))
            .expect("routing deeplink");
        let b64 = line.trim_start_matches("happ://routing/onadd/");
        let json = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        let v: Value = serde_json::from_slice(&json).expect("valid json");
        assert_eq!(v["DirectIp"][0], "geoip:ru");
        assert_eq!(v["DirectSites"][0], "geosite:category-ru");
        assert_eq!(v["BlockSites"][0], "geosite:category-ads-all");
        assert_eq!(v["GlobalProxy"], "false");
    }
}
