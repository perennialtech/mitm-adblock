use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use serde::Deserialize;
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{self, MissedTickBehavior},
};

use super::tun::serve_ip;
use crate::App;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConfig {
    private_key: String,
    peer_public_key: String,
    peer_ipv4: Option<Ipv4Addr>,
    peer_ipv6: Option<Ipv6Addr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyConfig {
    server_key: String,
    client_key: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ConfigFile {
    Native(PeerConfig),
    Legacy(LegacyConfig),
}

pub async fn serve_wireguard(app: Arc<App>, bind: SocketAddr, config_path: &Path) -> Result<()> {
    serve_wireguard_socket(app, UdpSocket::bind(bind).await?, config_path).await
}

pub(super) async fn serve_wireguard_socket(
    app: Arc<App>,
    socket: UdpSocket,
    config_path: &Path,
) -> Result<()> {
    let config: ConfigFile = serde_json::from_slice(
        &std::fs::read(config_path)
            .with_context(|| format!("read WireGuard configuration {}", config_path.display()))?,
    )
    .context("parse WireGuard configuration")?;
    let (private, public, v4, v6, dns) = match config {
        ConfigFile::Native(config) => {
            anyhow::ensure!(
                config.peer_ipv4.is_some() || config.peer_ipv6.is_some(),
                "WireGuard requires an exact tunnel IP for the enrolled peer"
            );
            (
                StaticSecret::from(decode_key(&config.private_key, "private_key")?),
                PublicKey::from(decode_key(&config.peer_public_key, "peer_public_key")?),
                config.peer_ipv4,
                config.peer_ipv6,
                None,
            )
        }
        ConfigFile::Legacy(config) => {
            let client_key = StaticSecret::from(decode_key(&config.client_key, "client_key")?);
            (
                StaticSecret::from(decode_key(&config.server_key, "server_key")?),
                PublicKey::from(&client_key),
                Some(Ipv4Addr::new(10, 0, 0, 1)),
                None,
                legacy_dns()?,
            )
        }
    };
    let tunnel = Tunn::new(private, public, None, None, 0, None);
    let (to_stack, from_peer) = mpsc::channel(128);
    let (to_peer, from_stack) = mpsc::channel(128);

    tokio::select! {
        result = run_peer(socket, tunnel, v4, v6, to_stack, from_stack) => result,
        result = serve_ip(app, 1420, from_peer, to_peer, dns) => result,
    }
}

fn legacy_dns() -> Result<Option<(SocketAddr, SocketAddr)>> {
    let config =
        std::fs::read_to_string("/etc/resolv.conf").context("read host resolver configuration")?;
    let resolver = config.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        if words.next() == Some("nameserver") {
            words.next()?.parse::<IpAddr>().ok()
        } else {
            None
        }
    });
    if resolver.is_none() {
        tracing::warn!("No host nameserver found for the WireGuard profile DNS address");
    }
    Ok(resolver.map(|resolver| {
        (
            SocketAddr::from(([10, 0, 0, 53], 53)),
            SocketAddr::new(resolver, 53),
        )
    }))
}

fn decode_key(encoded: &str, field: &str) -> Result<[u8; 32]> {
    let key = STANDARD
        .decode(encoded.trim())
        .with_context(|| format!("invalid base64 in WireGuard {field}"))?;
    key.try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard {field} must contain 32 bytes"))
}

async fn run_peer(
    socket: UdpSocket,
    mut tunnel: Tunn,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    to_stack: mpsc::Sender<Vec<u8>>,
    mut from_stack: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let mut received = vec![0; 65_535];
    let mut output = vec![0; 65_535 + 32];
    let mut endpoint = None;
    let mut timer = time::interval(Duration::from_millis(250));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            network = socket.recv_from(&mut received) => {
                let (len, source) = network?;
                if len == 0 {
                    continue;
                }
                match tunnel.decapsulate(Some(source.ip()), &received[..len], &mut output) {
                    TunnResult::WriteToTunnelV4(packet, ip) if v4 == Some(ip) => {
                        endpoint = Some(source);
                        let _ = to_stack.try_send(packet.to_vec());
                    }
                    TunnResult::WriteToTunnelV6(packet, ip) if v6 == Some(ip) => {
                        endpoint = Some(source);
                        let _ = to_stack.try_send(packet.to_vec());
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        send_udp(&socket, source, packet).await;
                        // Only flush queued traffic toward an authenticated address.
                        if endpoint == Some(source) {
                            while let TunnResult::WriteToNetwork(packet) =
                                tunnel.decapsulate(None, &[], &mut output)
                            {
                                send_udp(&socket, source, packet).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
            packet = from_stack.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                if packet.len() <= 65_475
                    && let Some(address) = endpoint
                    && let TunnResult::WriteToNetwork(packet) = tunnel.encapsulate(&packet, &mut output)
                {
                    send_udp(&socket, address, packet).await;
                }
            }
            _ = timer.tick() => {
                let result = tunnel.update_timers(&mut output);
                if let (Some(address), TunnResult::WriteToNetwork(packet)) = (endpoint, result) {
                    send_udp(&socket, address, packet).await;
                }
            }
        }
    }
}

async fn send_udp(socket: &UdpSocket, address: SocketAddr, packet: &[u8]) {
    if let Err(error) = socket.send_to(packet, address).await {
        tracing::debug!(%error, "WireGuard datagram could not be sent");
    }
}
