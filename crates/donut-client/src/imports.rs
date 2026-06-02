//! `import` and `geo-update` subcommands.
//!
//! `import` turns a `vless://` share-link (from donut-server / donut-tools)
//! into a ready-to-run client config, defaulting to a Russia→direct
//! split-tunnel so domestic traffic bypasses the VPS. `geo-update` fetches the
//! geoip/geosite databases those rules need.

use anyhow::Context;
use clap::Args;
use donut_config::{
    ClientConfig, ClientInbound, ClientOutbound, DnsConfig, GeoConfig, LogConfig, RoutingConfig,
};
use donut_routing::RuleConfig;

use crate::download::https_get_to_file;
use crate::link;

const GEOIP_URL: &str = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat";
const GEOSITE_URL: &str =
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat";

#[derive(Debug, Clone, Args)]
pub struct ImportArgs {
    /// The `vless://` share-link to import.
    pub link: String,
    /// Local SOCKS5 listen address.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub socks: String,
    /// Directory holding geoip.dat/geosite.dat (for split-tunnel rules).
    #[arg(long, default_value = "~/.donut")]
    pub geo_dir: String,
    /// Output config path. Default: `~/.donut/client.toml`.
    #[arg(short, long)]
    pub out: Option<String>,
    /// Do NOT add Russia→direct split-tunnel rules (proxy everything).
    #[arg(long)]
    pub no_ru_direct: bool,
    /// Print the config to stdout instead of writing a file.
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Debug, Clone, Args)]
pub struct GeoArgs {
    /// Directory to download geoip.dat + geosite.dat into.
    #[arg(long, default_value = "~/.donut")]
    pub dir: String,
}

pub fn cmd_import(args: ImportArgs) -> anyhow::Result<()> {
    let l = link::parse(&args.link).context("parsing vless:// link")?;
    if !l.label.is_empty() {
        eprintln!("importing {:?} ({}:{})", l.label, l.host, l.port);
    }
    if l.security != "tls" && !l.security.is_empty() {
        eprintln!(
            "note: link security={:?}; donut-client speaks cert-TLS (`raw`). \
             REALITY links aren't importable yet.",
            l.security
        );
    }

    // donut-client can't yet *originate* faithful Xray Vision, so it connects
    // with plain VLESS (flow=none) — which the vision:xray server serves on its
    // flow=none path. Off-the-shelf clients use the link as-is (full Vision).
    let flow = if l.flow == "xtls-rprx-vision" {
        eprintln!(
            "note: donut-client connects with flow=none (plain VLESS over cert-TLS); \
             paste the link itself into an App Store client for full xtls-rprx-vision."
        );
        "none".to_string()
    } else {
        l.flow.clone()
    };

    let geo_dir = expand_tilde(&args.geo_dir);
    let outbound = ClientOutbound {
        server: format!("{}:{}", l.host, l.port),
        uuid: l.uuid.clone(),
        transport: "raw".to_string(),
        reality: None,
        server_name: l.server_name(),
        path: "/".to_string(),
        mode: "stream-one".to_string(),
        flow,
    };

    let routing = if args.no_ru_direct {
        RoutingConfig {
            default: "proxy".to_string(),
            rules: Vec::new(),
        }
    } else {
        RoutingConfig {
            default: "proxy".to_string(),
            rules: vec![
                RuleConfig {
                    geoip: vec!["ru".into(), "private".into()],
                    outbound: "direct".into(),
                    ..Default::default()
                },
                RuleConfig {
                    // `category-ru` is the universal RU umbrella present in every
                    // geosite.dat; dat-specific subcategories (yandex/vk/…) are
                    // avoided since a missing one rejects the whole config.
                    geosite: vec!["category-ru".into()],
                    outbound: "direct".into(),
                    ..Default::default()
                },
            ],
        }
    };

    let geo = if args.no_ru_direct {
        GeoConfig::default()
    } else {
        GeoConfig {
            geoip: Some(format!("{geo_dir}/geoip.dat")),
            geosite: Some(format!("{geo_dir}/geosite.dat")),
        }
    };

    let dns = if args.no_ru_direct {
        DnsConfig::default()
    } else {
        // Yandex DoH for client-side direct dials of RU resources.
        DnsConfig {
            doh: vec!["77.88.8.8".to_string()],
            doh_tls_name: Some("common.dot.dns.yandex.net".to_string()),
        }
    };

    let cfg = ClientConfig {
        log: LogConfig::default(),
        inbound: ClientInbound {
            socks: args.socks.clone(),
        },
        outbound,
        routing,
        geo,
        dns,
    };

    let rendered = match toml::to_string_pretty(&cfg) {
        Ok(t) => t,
        Err(_) => serde_json::to_string_pretty(&cfg)?, // fallback if TOML can't represent it
    };

    if args.stdout {
        println!("{rendered}");
        return Ok(());
    }

    let out_path = args
        .out
        .unwrap_or_else(|| format!("{}/client.toml", expand_tilde("~/.donut")));
    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out_path, &rendered).with_context(|| format!("writing {out_path}"))?;

    eprintln!("✓ wrote {out_path}");
    if !args.no_ru_direct {
        eprintln!("  Russia→direct split-tunnel is ON — run `donut-client geo-update` to fetch the geo databases.");
    }
    eprintln!("  start: donut-client --config {out_path}");
    Ok(())
}

pub async fn cmd_geo_update(args: GeoArgs) -> anyhow::Result<()> {
    let dir = expand_tilde(&args.dir);
    let targets = [
        (GEOIP_URL, format!("{dir}/geoip.dat"), "geoip.dat"),
        (GEOSITE_URL, format!("{dir}/geosite.dat"), "geosite.dat"),
    ];
    for (url, dest, name) in targets {
        eprintln!("downloading {name} …");
        let n = https_get_to_file(url, std::path::Path::new(&dest))
            .await
            .with_context(|| format!("downloading {name} from {url}"))?;
        eprintln!("✓ {name}: {n} bytes → {dest}");
    }
    eprintln!("done. point client.toml's [geo] geoip/geosite at {dir}/*.dat");
    Ok(())
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    } else if p == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    p.to_string()
}
