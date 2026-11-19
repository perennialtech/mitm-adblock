use anyhow::{Context, Result, bail};
use mitm_adblock_subscriptions::{Config as Feeds, DEFAULT_LISTS};
use regex::RegexSet;
use std::{env, net::SocketAddr, path::PathBuf};

pub const OPTIONS: &str = "\
mitm-adblock [--mode MODE[@ADDRESS:PORT]] [--listen-host IP] [--listen-port PORT]
             [--ignore-hosts REGEX] [--set NAME=VALUE]
             [--wireguard-profile HOST:PORT]

Modes: regular, transparent, tun[:interface], wireguard[:config], reverse:http3://HOST:PORT
Repeat --mode for multiple listeners. Default: regular on 127.0.0.1:8080.
confdir                           CA directory
adblock_lists                     comma-separated list URLs/paths; supplement: for secondary lists
adblock_cache_dir                 downloaded lists and ThreatFox cache
adblock_update_hours              24 (0 to disable periodic refresh)
adblock_html_limit                max bytes buffered/decoded per HTML response (33554432)
adblock_cosmetic                  true
adblock_smart_app_banners         true
adblock_log_blocked               false
adblock_threatfox_key_file        optional ThreatFox key file
adblock_threat_domains_file       optional exact host list
tls_fallback_mode                 compatible (default), strict, off
ssl_verify_upstream_trusted_ca    optional PEM trust bundle for origins
ignore_hosts                      repeatable host:port regex
http2, http3                      true";

pub struct Config {
    pub profile: Option<String>,
    pub feeds: Feeds,
    pub confdir: PathBuf,
    pub trust: Option<PathBuf>,
    pub modes: Vec<String>,
    pub host: String,
    pub port: u16,
    pub html_limit: usize,
    pub cosmetic: bool,
    pub banners: bool,
    pub log_blocked: bool,
    pub fallback: Mode,
    pub ignore: RegexSet,
    pub http2: bool,
    pub http3: bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum Mode {
    Compatible,
    Strict,
    Off,
}

pub fn path(value: &str) -> PathBuf {
    if let Some(suffix) = value.strip_prefix("~/") {
        return PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(suffix);
    }
    PathBuf::from(value)
}

impl Config {
    pub fn parse() -> Result<Self> {
        let mut cfg = Self {
            profile: None,
            feeds: Feeds {
                lists: DEFAULT_LISTS.to_owned(),
                cache_dir: env::var_os("MITM_ADBLOCK_CACHE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| path("~/.cache/mitm-adblock")),
                update_hours: 24,
                threatfox_key_file: env::var_os("ADBLOCK_THREATFOX_KEY_FILE")
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from),
                threat_domains_file: None,
            },
            confdir: env::var_os("MITM_ADBLOCK_CONFDIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| path("~/.mitmproxy")),
            trust: None,
            modes: Vec::new(),
            host: env::var("MITM_ADBLOCK_BIND").unwrap_or_else(|_| "127.0.0.1".into()),
            port: 8080,
            html_limit: 32 * 1024 * 1024,
            cosmetic: true,
            banners: true,
            log_blocked: false,
            fallback: Mode::Compatible,
            ignore: RegexSet::empty(),
            http2: true,
            http3: true,
        };
        let mut ignore = Vec::new();
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            if matches!(arg.as_str(), "--help" | "-h" | "--options") {
                println!("{OPTIONS}\n\nDefault adblock_lists={DEFAULT_LISTS}");
                std::process::exit(0);
            }
            if arg == "--version" {
                println!("mitm-adblock {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            let val = args
                .next()
                .with_context(|| format!("missing argument for {arg}"))?;
            match arg.as_str() {
                "--mode" | "-m" => cfg.modes.push(val),
                "--listen-host" => cfg.host = val,
                "--listen-port" | "-p" => cfg.port = val.parse()?,
                "--wireguard-profile" => cfg.profile = Some(val),
                "--ignore-hosts" => ignore.push(val),
                "--set" => {
                    let (key, v) = val.split_once('=').context("expected --set name=value")?;
                    let boolean = || {
                        v.to_ascii_lowercase()
                            .parse::<bool>()
                            .context("expected true or false")
                    };
                    match key {
                        "confdir" => cfg.confdir = path(v),
                        "adblock_cache_dir" => cfg.feeds.cache_dir = path(v),
                        "adblock_lists" => cfg.feeds.lists = v.into(),
                        "adblock_update_hours" => cfg.feeds.update_hours = v.parse()?,
                        "adblock_threatfox_key_file" => {
                            cfg.feeds.threatfox_key_file = (!v.is_empty()).then(|| path(v))
                        }
                        "adblock_threat_domains_file" => {
                            cfg.feeds.threat_domains_file = (!v.is_empty()).then(|| path(v))
                        }
                        "adblock_html_limit" => cfg.html_limit = v.parse()?,
                        "adblock_cosmetic" => cfg.cosmetic = boolean()?,
                        "adblock_smart_app_banners" => cfg.banners = boolean()?,
                        "adblock_log_blocked" => cfg.log_blocked = boolean()?,
                        "http2" => cfg.http2 = boolean()?,
                        "http3" => cfg.http3 = boolean()?,
                        "ssl_verify_upstream_trusted_ca" => cfg.trust = Some(path(v)),
                        "ignore_hosts" => ignore.push(v.into()),
                        "tls_fallback_mode" => {
                            cfg.fallback = match v {
                                "compatible" => Mode::Compatible,
                                "strict" => Mode::Strict,
                                "off" => Mode::Off,
                                _ => bail!("invalid tls_fallback_mode"),
                            }
                        }
                        // This proxy issues leaves from the requested name and connects lazily.
                        "upstream_cert" if !boolean()? => (),
                        "connection_strategy" if v == "lazy" => (),
                        "flow_detail" if v == "0" => (),
                        _ => bail!("unknown or unsupported option {key}"),
                    }
                }
                _ => bail!("unknown argument {arg}"),
            }
        }
        cfg.ignore = RegexSet::new(ignore)?;
        if cfg.modes.is_empty() {
            cfg.modes.push("regular".into());
        }
        Ok(cfg)
    }

    pub fn listen(&self, spec: Option<&str>, default: u16) -> Result<SocketAddr> {
        if let Some(s) = spec
            && let Ok(addr) = s.parse()
        {
            return Ok(addr);
        }
        let port = match spec {
            Some(s) => s.parse()?,
            None => default,
        };
        Ok(SocketAddr::new(
            self.host.trim_matches(['[', ']']).parse()?,
            port,
        ))
    }
}
