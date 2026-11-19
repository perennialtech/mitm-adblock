use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result};
use quinn::{
    AsyncUdpSocket, ConnectionError, Endpoint, EndpointConfig, TokioRuntime, UdpPoller,
    crypto::rustls::QuicServerConfig,
    udp::{RecvMeta, Transmit},
};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{self, Instant},
};

use super::{h3, quic::ServerCrypto};
use crate::App;

const MAX_UDP_DATAGRAM: usize = 65_535;
const MAX_PENDING_BYTES: usize = 65_536;
const MAX_FLOWS: usize = 1_024;
const RAW_IDLE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Flow {
    pub peer: SocketAddr,
    pub destination: SocketAddr,
}

pub(super) struct Datagram {
    pub flow: Flow,
    pub data: Vec<u8>,
}

pub(super) struct UdpIngress {
    app: Arc<App>,
    flows: HashMap<Flow, mpsc::Sender<Vec<u8>>>,
    responses: mpsc::Sender<Datagram>,
    tasks: JoinSet<()>,
    reverse_h3: bool,
    dns: Option<(SocketAddr, SocketAddr)>,
}

impl UdpIngress {
    pub fn new(
        app: Arc<App>,
        reverse_h3: bool,
        dns: Option<(SocketAddr, SocketAddr)>,
    ) -> (Self, mpsc::Receiver<Datagram>) {
        let (responses, packets) = mpsc::channel(256);
        (
            Self {
                app,
                responses,
                flows: HashMap::new(),
                tasks: JoinSet::new(),
                reverse_h3,
                dns,
            },
            packets,
        )
    }

    pub fn ingest(&mut self, flow: Flow, data: &[u8]) {
        while let Some(result) = self.tasks.try_join_next() {
            if let Err(error) = result {
                tracing::debug!(%error, "UDP flow task stopped");
            }
        }
        if let Some(sender) = self.flows.get(&flow)
            && !sender.is_closed()
        {
            let _ = sender.try_send(data.to_vec());
            return;
        }
        if self.flows.len() >= MAX_FLOWS {
            self.flows.retain(|_, sender| !sender.is_closed());
            if self.flows.len() >= MAX_FLOWS {
                return;
            }
        }

        let (sender, receiver) = mpsc::channel(32);
        self.flows.insert(flow, sender);
        let first = data.to_vec();
        let app = self.app.clone();
        let responses = self.responses.clone();
        let h3 = app.config.http3 && (self.reverse_h3 || flow.destination.port() == 443);
        let target = self
            .dns
            .filter(|(virtual_dns, _)| *virtual_dns == flow.destination)
            .map_or(flow.destination, |(_, resolver)| resolver);
        self.tasks.spawn(async move {
            let result = if h3 && looks_like_quic(&first) {
                handle_quic(app, flow, responses, receiver, first).await
            } else {
                relay_udp(flow, target, responses, receiver, vec![first]).await
            };
            if let Err(error) = result {
                tracing::debug!(?flow, %error, "UDP flow closed");
            }
        });
    }
}

pub async fn serve_h3(app: Arc<App>, bind: SocketAddr, destination: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    let (mut ingress, mut responses) = UdpIngress::new(app, true, None);
    let mut datagram = vec![0; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut datagram) => {
                let (len, peer) = result?;
                ingress.ingest(Flow { peer, destination }, &datagram[..len]);
            }
            Some(reply) = responses.recv() => {
                if let Err(error) = socket.send_to(&reply.data, reply.flow.peer).await {
                    tracing::debug!(%error, "UDP reply could not be sent");
                }
            }
        }
    }
}

fn looks_like_quic(data: &[u8]) -> bool {
    data.len() >= 1200 && data[0] & 0xc0 == 0xc0
}

#[derive(Clone)]
enum Choice {
    Pending,
    Intercept(Option<String>),
    Relay,
}

struct Resolver {
    app: Arc<App>,
    flow: Flow,
    choice: watch::Sender<Choice>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicCertificateResolver")
            .field("flow", &self.flow)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello
            .server_name()
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase());
        let destination = self.flow.destination.to_string();
        let relay = self.app.ignored(&destination)
            || name.as_ref().is_some_and(|sni| {
                self.app.ignored(sni)
                    || self
                        .app
                        .ignored(&format!("{sni}:{}", self.flow.destination.port()))
                    || self
                        .app
                        .fallback
                        .active(self.flow.peer.ip(), &destination, sni, true)
            });
        self.choice.send_if_modified(|choice| {
            if matches!(choice, Choice::Pending) {
                *choice = if relay {
                    Choice::Relay
                } else {
                    Choice::Intercept(name.clone())
                };
                true
            } else {
                false
            }
        });
        if matches!(*self.choice.borrow(), Choice::Relay) {
            return None;
        }

        let name = name.unwrap_or_else(|| self.flow.destination.ip().to_string());
        match self.app.certified_key(&name) {
            Ok(key) => Some(key),
            Err(error) => {
                tracing::warn!(%error, "Could not issue HTTP/3 certificate");
                None
            }
        }
    }
}

async fn handle_quic(
    app: Arc<App>,
    flow: Flow,
    responses: mpsc::Sender<Datagram>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    first: Vec<u8>,
) -> Result<()> {
    let (choice_sender, mut choice) = watch::channel(Choice::Pending);
    let resolver = Arc::new(Resolver {
        app: app.clone(),
        flow,
        choice: choice_sender.clone(),
    });
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    let authenticated = Arc::new(AtomicBool::new(false));
    let crypto = ServerCrypto::new(QuicServerConfig::try_from(tls)?, authenticated.clone());
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.migration(false).max_incoming(1);
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.supported_versions(vec![1]);

    let (to_quinn, quinn_in) = mpsc::channel(32);
    let (quinn_out, mut from_quinn) = mpsc::channel(64);
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(server_config),
        Arc::new(FlowSocket {
            flow,
            incoming: Mutex::new(quinn_in),
            outgoing: quinn_out,
        }),
        Arc::new(TokioRuntime),
    )?;
    let _ = to_quinn.try_send(first.clone());
    let mut size = first.len();
    let mut buffered = vec![first];
    let session = run_session(app, flow, &endpoint, choice.clone(), authenticated);
    tokio::pin!(session);
    let mut decided = false;

    // Hold the original Initial datagrams until rustls has reconstructed the
    // ClientHello. The only permitted early reply is version negotiation.
    loop {
        tokio::select! {
            biased;
            change = choice.changed(), if !decided => {
                change?;
                let relay = matches!(*choice.borrow_and_update(), Choice::Relay);
                if relay {
                    endpoint.close(0u32.into(), b"");
                    return relay_udp(flow, flow.destination, responses, incoming, buffered).await;
                }
                buffered.clear();
                decided = true;
            }
            result = &mut session => {
                endpoint.close(0u32.into(), b"");
                if matches!(*choice.borrow(), Choice::Relay) {
                    return relay_udp(flow, flow.destination, responses, incoming, buffered).await;
                }
                return result;
            }
            Some(packet) = from_quinn.recv() => {
                let selected = choice.borrow();
                let send = matches!(*selected, Choice::Intercept(_))
                    || matches!(*selected, Choice::Pending) && packet.get(1..5) == Some(&[0; 4]);
                if send {
                    let _ = responses.try_send(Datagram { flow, data: packet });
                }
            }
            packet = incoming.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                if !decided {
                    size += packet.len();
                    if size <= MAX_PENDING_BYTES {
                        buffered.push(packet.clone());
                    } else {
                        // Do not allow an incomplete hello to retain unbounded memory.
                        choice_sender.send_if_modified(|value| if matches!(*value, Choice::Pending) {
                            *value = Choice::Intercept(None);
                            true
                        } else {
                            false
                        });
                    }
                }
                let _ = to_quinn.try_send(packet);
            }
            _ = time::sleep(RAW_IDLE) => return Ok(()),
        }
    }
}

async fn run_session(
    app: Arc<App>,
    flow: Flow,
    endpoint: &Endpoint,
    choice: watch::Receiver<Choice>,
    authenticated: Arc<AtomicBool>,
) -> Result<()> {
    let Some(incoming) = endpoint.accept().await else {
        return Ok(());
    };
    match incoming.await {
        Ok(connection) => h3::serve_connection(app, flow.destination, connection).await,
        Err(error) => {
            if let ConnectionError::ConnectionClosed(close) = &error
                && authenticated.load(Ordering::Acquire)
                && close.frame_type.is_some()
                && let Some(alert) = u64::from(close.error_code)
                    .checked_sub(0x100)
                    .and_then(|code| u8::try_from(code).ok())
                && let Choice::Intercept(Some(sni)) = &*choice.borrow()
            {
                app.fallback.rejected(
                    flow.peer.ip(),
                    &flow.destination.to_string(),
                    sni,
                    alert,
                    true,
                );
            }
            Err(error.into())
        }
    }
}

async fn relay_udp(
    flow: Flow,
    target: SocketAddr,
    responses: mpsc::Sender<Datagram>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    buffered: Vec<Vec<u8>>,
) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddr::new(unspecified(target.ip()), 0)).await?;
    socket.connect(target).await.context("connect UDP origin")?;
    for packet in buffered {
        socket.send(&packet).await?;
    }
    let mut data = vec![0; MAX_UDP_DATAGRAM];
    let idle = time::sleep(RAW_IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            result = socket.recv(&mut data) => {
                let len = result?;
                let _ = responses.try_send(Datagram { flow, data: data[..len].to_vec() });
            }
            packet = incoming.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                socket.send(&packet).await?;
            }
            _ = &mut idle => return Ok(()),
        }
        idle.as_mut().reset(Instant::now() + RAW_IDLE);
    }
}

pub(super) fn unspecified(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    }
}

#[derive(Debug)]
struct FlowSocket {
    flow: Flow,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug)]
struct DatagramPoller;

impl UdpPoller for DatagramPoller {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for FlowSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(DatagramPoller)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // Like a UDP socket, a congested output queue can drop a datagram.
        debug_assert!(transmit.segment_size.is_none());
        let _ = self.outgoing.try_send(transmit.contents.to_vec());
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut incoming = self.incoming.lock().expect("QUIC receiver poisoned");
        loop {
            match std::task::ready!(incoming.poll_recv(cx)) {
                Some(packet) if packet.len() <= bufs[0].len() && !packet.is_empty() => {
                    let len = packet.len();
                    bufs[0][..len].copy_from_slice(&packet);
                    meta[0] = RecvMeta {
                        addr: self.flow.peer,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: Some(self.local_addr()?.ip()),
                    };
                    return Poll::Ready(Ok(1));
                }
                Some(_) => continue,
                None => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(
            unspecified(self.flow.peer.ip()),
            self.flow.destination.port(),
        ))
    }
}
