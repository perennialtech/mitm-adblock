use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use etherparse::{PacketBuilder, SlicedPacket};
use mitm_adblock_policy::Policy;
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};

use super::{tun::serve_ip, wireguard::serve_wireguard_socket};
use crate::{App, ca, client_tls, config, fallback};

const WAIT: Duration = Duration::from_secs(3);

fn test_app(root: &std::path::Path) -> Result<Arc<App>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = config::Config {
        profile: None,
        feeds: mitm_adblock_subscriptions::Config {
            lists: String::new(),
            cache_dir: root.into(),
            update_hours: 0,
            threatfox_key_file: None,
            threat_domains_file: None,
        },
        confdir: root.into(),
        trust: None,
        modes: Vec::new(),
        host: "127.0.0.1".into(),
        port: 8080,
        html_limit: 64 * 1024,
        cosmetic: true,
        banners: true,
        log_blocked: false,
        fallback: config::Mode::Compatible,
        ignore: regex::RegexSet::empty(),
        http2: false,
        http3: true,
    };
    let authority = ca::Authority::load(&config.confdir)?;
    let trust = config.confdir.join("mitmproxy-ca-cert.pem");
    let client_tls = Arc::new(client_tls(Some(&trust), false)?);
    Ok(Arc::new(App {
        fallback: fallback::Fallback::new(config.fallback),
        policy: RwLock::new(Arc::new(Policy::new(
            vec![],
            vec![],
            Default::default(),
            Default::default(),
        ))),
        ca: authority,
        upstream_pool: crate::upstream::Pool::new(client_tls.clone(), client_tls.clone()),
        client_tls,
        config,
    }))
}

fn datagram(peer: SocketAddr, target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    match (peer.ip(), target.ip()) {
        (IpAddr::V4(peer_ip), IpAddr::V4(target_ip)) => {
            PacketBuilder::ipv4(peer_ip.octets(), target_ip.octets(), 64)
                .udp(peer.port(), target.port())
                .write(&mut packet, data)
                .unwrap()
        }
        (IpAddr::V6(peer_ip), IpAddr::V6(target_ip)) => {
            PacketBuilder::ipv6(peer_ip.octets(), target_ip.octets(), 64)
                .udp(peer.port(), target.port())
                .write(&mut packet, data)
                .unwrap()
        }
        _ => panic!("mixed address families"),
    };
    packet
}

#[tokio::test]
async fn ip_stack_preserves_ipv4_and_ipv6_udp_endpoints() -> Result<()> {
    let root = tempfile::tempdir()?;
    let app = test_app(root.path())?;
    let (send, incoming) = mpsc::channel(4);
    let (outgoing, mut receive) = mpsc::channel(4);
    let service = tokio::spawn(serve_ip(app, 1420, incoming, outgoing, None));

    for (peer, local) in [
        ("10.0.0.1:55000", "127.0.0.1:0"),
        ("[fd00::1]:55000", "[::1]:0"),
    ] {
        let origin = UdpSocket::bind(local).await?;
        let destination = origin.local_addr()?;
        let peer = peer.parse()?;
        send.send(datagram(peer, destination, b"app request"))
            .await?;
        let mut payload = [0; 128];
        let (len, socket) = timeout(WAIT, origin.recv_from(&mut payload)).await??;
        assert_eq!(&payload[..len], b"app request");
        origin.send_to(b"app response", socket).await?;
        let response = timeout(WAIT, receive.recv())
            .await?
            .context("stack stopped")?;
        let expected = datagram(destination, peer, b"app response");
        assert_eq!(response.len(), expected.len());
        let packet = SlicedPacket::from_ip(&response)?;
        let expected = SlicedPacket::from_ip(&expected)?;
        assert_eq!(packet.transport, expected.transport);
        match (packet.net, expected.net) {
            (Some(etherparse::NetSlice::Ipv4(got)), Some(etherparse::NetSlice::Ipv4(want))) => {
                assert_eq!(got.header().source(), want.header().source());
                assert_eq!(got.header().destination(), want.header().destination());
            }
            (Some(etherparse::NetSlice::Ipv6(got)), Some(etherparse::NetSlice::Ipv6(want))) => {
                assert_eq!(got.header().source(), want.header().source());
                assert_eq!(got.header().destination(), want.header().destination());
            }
            _ => panic!("response has wrong address family"),
        }
    }

    drop(send);
    timeout(WAIT, service).await???;
    Ok(())
}

#[tokio::test]
async fn legacy_wireguard_uses_the_enrolled_peer_ip() -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;

    let root = tempfile::tempdir()?;
    let app = test_app(root.path())?;
    let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let wg_listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let bind = wg_listener.local_addr()?;
    client_socket.connect(bind).await?;

    let client_key = [11; 32];
    let server_key = [17; 32];
    let private = StaticSecret::from(client_key);
    let server = PublicKey::from(&StaticSecret::from(server_key));
    let legacy = root.path().join("wireguard.conf");
    std::fs::write(
        &legacy,
        serde_json::to_vec(&json!({
            "server_key": STANDARD.encode(server_key),
            "client_key": STANDARD.encode(client_key),
        }))?,
    )?;
    let task = tokio::spawn(async move { serve_wireguard_socket(app, wg_listener, &legacy).await });

    let mut client = Tunn::new(private, server, None, None, 0, None);
    let mut network = [0; 2048];
    let mut plaintext = [0; 2048];
    let destination = origin.local_addr()?;
    let unenrolled = SocketAddr::from(([10, 0, 0, 2], 55000));
    let enrolled = SocketAddr::from(([10, 0, 0, 1], 55000));
    let wrong_source = datagram(unenrolled, destination, b"reject this");
    let accepted = datagram(enrolled, destination, b"accept this");

    let TunnResult::WriteToNetwork(handshake) = client.encapsulate(&wrong_source, &mut network)
    else {
        anyhow::bail!("client handshake expected");
    };
    client_socket.send(handshake).await?;
    let len = timeout(WAIT, client_socket.recv(&mut network)).await??;
    let TunnResult::WriteToNetwork(keepalive) =
        client.decapsulate(None, &network[..len], &mut plaintext)
    else {
        anyhow::bail!("server handshake response expected");
    };
    client_socket.send(keepalive).await?;
    while let TunnResult::WriteToNetwork(packet) = client.decapsulate(None, &[], &mut plaintext) {
        client_socket.send(packet).await?;
    }
    let TunnResult::WriteToNetwork(packet) = client.encapsulate(&accepted, &mut network) else {
        anyhow::bail!("no encrypted UDP payload");
    };
    client_socket.send(packet).await?;

    let mut response = [0; 128];
    let (len, remote) = timeout(WAIT, origin.recv_from(&mut response)).await??;
    assert_eq!(&response[..len], b"accept this");
    origin.send_to(b"reply", remote).await?;
    let len = timeout(WAIT, client_socket.recv(&mut network)).await??;
    let TunnResult::WriteToTunnelV4(packet, ip) =
        client.decapsulate(None, &network[..len], &mut plaintext)
    else {
        anyhow::bail!("no decrypted UDP response");
    };
    assert_eq!(ip, Ipv4Addr::LOCALHOST);
    let packet = SlicedPacket::from_ip(packet)?;
    let Some(etherparse::TransportSlice::Udp(udp)) = packet.transport else {
        anyhow::bail!("expected a UDP response");
    };
    assert_eq!(udp.destination_port(), enrolled.port());
    assert_eq!(udp.payload(), b"reply");
    task.abort();
    Ok(())
}
