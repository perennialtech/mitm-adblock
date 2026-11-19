mod ca;
mod config;
mod content;
mod enrollment;
mod fallback;
mod ingress;
#[path = "http.rs"]
mod proxy_http;
mod tcp;
mod upstream;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use config::Config;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use mitm_adblock_policy::Policy;
use mitm_adblock_subscriptions::{self as feeds, Snapshot};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, pem::PemObject},
    sign::{CertifiedKey, SingleCertAndKey},
};
use std::{
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};

type Body = UnsyncBoxBody<Bytes, anyhow::Error>;
fn full(value: impl Into<Bytes>) -> Body {
    Full::new(value.into())
        .map_err(|e| match e {})
        .boxed_unsync()
}

#[derive(Clone)]
pub struct Route {
    pub scheme: &'static str,
    pub authority: String,
    pub connect: String,
}

pub fn host_port(host: &str, port: u16) -> String {
    let h = host.trim_matches(['[', ']']);
    if h.contains(':') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}
pub fn authority(host: &str, port: u16, scheme: &str) -> String {
    if (port, scheme) == (443, "https") || (port, scheme) == (80, "http") {
        let h = host.trim_matches(['[', ']']);
        if h.contains(':') {
            format!("[{h}]")
        } else {
            h.into()
        }
    } else {
        host_port(host, port)
    }
}

pub struct App {
    config: Config,
    ca: ca::Authority,
    policy: RwLock<Arc<Policy>>,
    fallback: fallback::Fallback,
    client_tls: Arc<ClientConfig>,
    upstream_pool: upstream::Pool,
}

fn client_tls(trust: Option<&Path>, h2: bool) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = trust {
        for cert in CertificateDer::pem_file_iter(path)? {
            roots.add(cert?)?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
    }
    if roots.is_empty() {
        bail!("no trusted origin certificate authorities found");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if h2 {
        config.alpn_protocols.push(b"h2".to_vec());
    }
    config.alpn_protocols.push(b"http/1.1".to_vec());
    Ok(config)
}

fn load(feeds: &feeds::Config, force: bool) -> Result<Policy> {
    let Snapshot {
        primary,
        supplemental,
        domains,
        payload_urls,
    } = feeds::load(feeds, force)?;
    if !feeds.lists.trim().is_empty() && primary.is_empty() && supplemental.is_empty() {
        if force {
            bail!("none of the configured subscriptions could be refreshed");
        }
        tracing::warn!("Subscriptions unavailable on startup; using available local indicators");
    }
    Ok(Policy::new(primary, supplemental, domains, payload_urls))
}
impl App {
    fn ignored(&self, authority: &str) -> bool {
        self.config.ignore.is_match(authority)
    }
    fn certified_key(&self, name: &str) -> Result<Arc<CertifiedKey>> {
        self.ca.certified_key(name)
    }
    fn tls_config(&self, name: &str, alpn: &[&[u8]]) -> Result<ServerConfig> {
        let resolver = Arc::new(SingleCertAndKey::from(self.certified_key(name)?));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.alpn_protocols = alpn.iter().map(|x| x.to_vec()).collect();
        Ok(config)
    }
    async fn refresh(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.feeds.update_hours.saturating_mul(3600));
        if interval.is_zero() {
            return;
        }
        loop {
            tokio::time::sleep(interval).await;
            let feeds = self.config.feeds.clone();
            match tokio::task::spawn_blocking(move || load(&feeds, true)).await {
                Ok(Ok(policy)) => {
                    *self.policy.write().unwrap() = Arc::new(policy);
                    eprintln!("subscriptions refreshed");
                }
                Ok(Err(e)) => eprintln!("retaining previous subscriptions: {e}"),
                Err(e) => eprintln!("subscription worker stopped: {e}"),
            }
        }
    }
    async fn listen(self: Arc<Self>, spec: String) -> Result<()> {
        let (mode, bind) = spec
            .rsplit_once('@')
            .map_or((spec.as_str(), None), |(m, b)| (m, Some(b)));
        match mode {
            "regular" | "transparent" => {
                tcp::listen(
                    self.clone(),
                    self.config.listen(bind, self.config.port)?,
                    mode == "transparent",
                )
                .await
            }
            "tun" => ingress::serve_tun(self, "mitm-h3").await,
            s if s.starts_with("tun:") => ingress::serve_tun(self, &s[4..]).await,
            s if s == "wireguard" || s.starts_with("wireguard:") => {
                let addr = self.config.listen(bind, 51820)?;
                let config = s
                    .strip_prefix("wireguard:")
                    .map(config::path)
                    .unwrap_or_else(|| self.config.confdir.join("wireguard.conf"));
                if s == "wireguard" {
                    enrollment::initialize(&config)?;
                }
                ingress::serve_wireguard(self, addr, &config).await
            }
            s if s.starts_with("reverse:http3://") => {
                if !self.config.http3 {
                    bail!("http3 must be enabled for reverse:http3");
                }
                let addr = self.config.listen(bind, self.config.port)?;
                let authority = s
                    .trim_start_matches("reverse:http3://")
                    .parse::<http::uri::Authority>()?;
                let target = host_port(authority.host(), authority.port_u16().unwrap_or(443));
                let dest = tokio::net::lookup_host(target)
                    .await?
                    .next()
                    .context("no origin address")?;
                ingress::serve_h3(self, addr, dest).await
            }
            _ => bail!("unsupported proxy mode {mode}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse()?;
    if let Some(endpoint) = &config.profile {
        print!(
            "{}",
            enrollment::profile(&config.confdir.join("wireguard.conf"), endpoint)?
        );
        return Ok(());
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let ca = ca::Authority::load(&config.confdir)?;
    let client_tls = Arc::new(client_tls(config.trust.as_deref(), config.http2)?);
    let mut h1_tls = (*client_tls).clone();
    h1_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let feeds = config.feeds.clone();
    let policy = tokio::task::spawn_blocking(move || load(&feeds, false)).await??;
    let modes = config.modes.clone();
    let app = Arc::new(App {
        fallback: fallback::Fallback::new(config.fallback),
        policy: RwLock::new(Arc::new(policy)),
        ca,
        upstream_pool: upstream::Pool::new(client_tls.clone(), Arc::new(h1_tls)),
        client_tls,
        config,
    });
    tokio::spawn(app.clone().refresh());
    let mut listeners = tokio::task::JoinSet::new();
    for mode in modes {
        listeners.spawn(app.clone().listen(mode));
    }
    tokio::select! {
        _=tokio::signal::ctrl_c()=>Ok(()),
        result=listeners.join_next()=> result.context("no listeners")?.map_err(anyhow::Error::from)?,
    }
}
