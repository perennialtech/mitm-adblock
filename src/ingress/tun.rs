use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use tokio::{net::TcpStream, sync::mpsc, task::JoinSet, time::timeout};

use super::udp::{Flow, UdpIngress};
use crate::App;

const PACKET_QUEUE: usize = 128;
const MAX_TCP_FLOWS: usize = 512;

pub async fn serve_tun(app: Arc<App>, name: &str) -> Result<()> {
    let device = tun_rs::DeviceBuilder::new()
        .name(name)
        .build_async()
        .with_context(|| format!("open TUN interface {name}"))?;
    let mtu = usize::from(device.mtu()?);
    let (packet_in, packets_from_tun) = mpsc::channel(PACKET_QUEUE);
    let (packets_to_tun, mut packet_out) = mpsc::channel(PACKET_QUEUE);
    let receive = async {
        let mut packet = vec![0; 65_535];
        loop {
            let len = device.recv(&mut packet).await?;
            if len == 0 {
                return Ok(());
            }
            packet_in
                .send(packet[..len].to_vec())
                .await
                .context("TUN stack stopped")?;
        }
    };
    let send = async {
        while let Some(packet) = packet_out.recv().await {
            let packet: Vec<u8> = packet;
            let count = device.send(&packet).await?;
            anyhow::ensure!(count == packet.len(), "short write to TUN interface");
        }
        Ok(())
    };
    tokio::select! {
        result = serve_ip(app, mtu, packets_from_tun, packets_to_tun, None) => result,
        result = receive => result,
        result = send => result,
    }
}

pub(super) async fn serve_ip(
    app: Arc<App>,
    mtu: usize,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    dns: Option<(SocketAddr, SocketAddr)>,
) -> Result<()> {
    let (stack, runner, udp, tcp) = StackBuilder::default()
        .mtu(mtu)
        .stack_buffer_size(PACKET_QUEUE)
        .tcp_buffer_size(PACKET_QUEUE)
        .udp_buffer_size(PACKET_QUEUE)
        .tcp_recv_buffer_size(64 * 1024)
        .tcp_send_buffer_size(64 * 1024)
        .enable_tcp(true)
        .enable_udp(true)
        .build()?;
    let runner = runner.context("missing IP stack runner")?;
    let (mut ip_send, mut ip_recv) = stack.split();
    let (mut udp_recv, mut udp_send) = udp.context("missing UDP stack")?.split();
    let mut tcp = tcp.context("missing TCP stack")?;
    let from_interface = async {
        while let Some(packet) = incoming.recv().await {
            match ip_send.send(packet).await {
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                    tracing::debug!(%error, "Dropping malformed IP packet");
                }
                result => result?,
            }
        }
        Ok(())
    };
    let to_interface = async {
        while let Some(packet) = ip_recv.next().await {
            outgoing
                .send(packet?)
                .await
                .context("IP interface stopped")?;
        }
        Ok(())
    };

    let (mut ingress, mut responses) = UdpIngress::new(app.clone(), false, dns);
    let receive_udp = async {
        loop {
            // The stack can report a malformed UDP packet as None before the stream ends.
            if let Some((data, peer, destination)) = udp_recv.next().await {
                ingress.ingest(Flow { peer, destination }, &data);
            }
        }
    };
    let send_udp = async {
        while let Some(reply) = responses.recv().await {
            udp_send
                .send((reply.data, reply.flow.destination, reply.flow.peer))
                .await?;
        }
        Ok(())
    };

    let receive_tcp = async {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result {
                        tracing::debug!(%error, "TUN TCP task stopped");
                    }
                }
                stream = tcp.next() => {
                    let Some((mut io, peer, destination)) = stream else { return Ok(()) };
                    if tasks.len() >= MAX_TCP_FLOWS {
                        continue;
                    }
                    let app = app.clone();
                    tasks.spawn(async move {
                        let result = if matches!(destination.port(), 80 | 443) {
                            app.serve_tcp(io, peer, Some(destination)).await
                        } else {
                            async {
                                let target = dns.filter(|(virtual_dns, _)| *virtual_dns == destination)
                                    .map_or(destination, |(_, resolver)| resolver);
                                let mut origin = timeout(Duration::from_secs(10), TcpStream::connect(target)).await??;
                                tokio::io::copy_bidirectional(&mut io, &mut origin).await?;
                                Ok(())
                            }.await
                        };
                        if let Err(error) = result {
                            tracing::debug!(%destination, %error, "TUN TCP connection closed");
                        }
                    });
                }
            }
        }
    };

    tokio::select! {
        result = runner => result.context("IP stack stopped"),
        result = from_interface => result,
        result = to_interface => result,
        result = receive_udp => result,
        result = send_udp => result,
        result = receive_tcp => result,
    }
}
