use crate::{App, Route};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    io::{self, Cursor},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// Keep the original bytes available if the client must retry against the origin directly.
struct Prefix<T> {
    head: Cursor<Vec<u8>>,
    tail: T,
    server_flight: bool,
}
impl<T: AsyncRead + Unpin> AsyncRead for Prefix<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.head.position() < self.head.get_ref().len() as u64 {
            return Pin::new(&mut self.head).poll_read(cx, buf);
        }
        Pin::new(&mut self.tail).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Prefix<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.tail).poll_write(cx, buf);
        if matches!(result,Poll::Ready(Ok(n)) if n>0) && buf.first() == Some(&22) {
            self.server_flight = true;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tail).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tail).poll_shutdown(cx)
    }
}
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type Io = Box<dyn Stream>;

async fn client_hello(io: &mut Io) -> Result<(Vec<u8>, Option<String>)> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut head = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let n = io.read(&mut buf).await?;
        if n == 0 || head.len() + n > 65536 {
            bail!("incomplete or oversized TLS client hello");
        }
        head.extend_from_slice(&buf[..n]);
        let mut data = &buf[..n];
        while !data.is_empty() {
            if acceptor.read_tls(&mut data)? == 0 {
                bail!("incomplete client hello");
            }
            if let Some(hello) = acceptor.accept().map_err(|(e, _)| anyhow!(e))? {
                return Ok((head, hello.client_hello().server_name().map(str::to_owned)));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn original_destination(io: &TcpStream) -> Result<SocketAddr> {
    use nix::sys::socket::{getsockopt, sockopt};
    use std::net::{Ipv4Addr, Ipv6Addr};
    if io.local_addr()?.is_ipv4() {
        let addr = getsockopt(io, sockopt::OriginalDst)?;
        Ok((
            Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(addr.sin_port),
        )
            .into())
    } else {
        let addr = getsockopt(io, sockopt::Ip6tOriginalDst)?;
        Ok((
            Ipv6Addr::from(addr.sin6_addr.s6_addr),
            u16::from_be(addr.sin6_port),
        )
            .into())
    }
}

pub async fn listen(app: Arc<App>, addr: SocketAddr, transparent: bool) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!(
        "listening on {} ({})",
        listener.local_addr()?,
        if transparent {
            "transparent"
        } else {
            "regular"
        }
    );
    loop {
        let (io, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let result = async {
                let dest = if transparent {
                    #[cfg(target_os = "linux")]
                    {
                        let dst = original_destination(&io)?;
                        if dst == io.local_addr()? {
                            bail!("missing redirected destination");
                        }
                        Some(dst)
                    }
                    #[cfg(not(target_os = "linux"))]
                    bail!("transparent mode requires Linux")
                } else {
                    None
                };
                app.serve_tcp(io, peer, dest).await
            }
            .await;
            if let Err(e) = result {
                eprintln!("TCP session: {e}");
            }
        });
    }
}

impl App {
    pub async fn serve_tcp(
        self: &Arc<Self>,
        io: impl Stream + 'static,
        peer: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Result<()> {
        match destination {
            None => self.clone().explicit(Box::new(io), peer).await,
            Some(dest) if dest.port() == 443 => {
                self.intercept(Box::new(io), peer, &dest.to_string()).await
            }
            Some(dest) if dest.port() == 80 => {
                self.clone()
                    .http_session(
                        Box::new(io),
                        Route {
                            scheme: "http",
                            authority: String::new(),
                            connect: dest.to_string(),
                        },
                        peer,
                    )
                    .await
            }
            Some(dest) => relay(Box::new(io), &dest.to_string()).await,
        }
    }

    pub async fn intercept(
        self: &Arc<Self>,
        mut io: Io,
        peer: SocketAddr,
        dest: &str,
    ) -> Result<()> {
        if self.ignored(dest) {
            return relay(io, dest).await;
        }
        let (head, sni) =
            tokio::time::timeout(Duration::from_secs(15), client_hello(&mut io)).await??;
        let stream = Prefix {
            head: Cursor::new(head),
            tail: io,
            server_flight: false,
        };
        let addr = dest.parse::<http::uri::Authority>()?;
        let hostname = sni
            .as_deref()
            .unwrap_or(addr.host())
            .trim_matches(['[', ']']);
        let authority = crate::authority(hostname, addr.port_u16().unwrap_or(443), "https");
        if self.ignored(&crate::host_port(hostname, addr.port_u16().unwrap_or(443)))
            || sni
                .as_ref()
                .is_some_and(|name| self.fallback.active(peer.ip(), dest, name, false))
        {
            return relay(Box::new(stream), dest).await;
        }
        let protos: &[&[u8]] = if self.config.http2 {
            &[b"h2", b"http/1.1"]
        } else {
            &[b"http/1.1"]
        };
        let accept = TlsAcceptor::from(Arc::new(self.tls_config(hostname, protos)?));
        let tls = match tokio::time::timeout(
            Duration::from_secs(20),
            accept.accept(stream).into_fallible(),
        )
        .await?
        {
            Ok(tls) => tls,
            Err((e, stream)) => {
                if stream.server_flight
                    && let Some(rustls::Error::AlertReceived(alert)) =
                        e.get_ref().and_then(|e| e.downcast_ref())
                    && let Some(name) = sni.as_deref()
                {
                    self.fallback
                        .rejected(peer.ip(), dest, name, u8::from(*alert), false);
                }
                return Err(e.into());
            }
        };
        self.clone()
            .http_session(
                Box::new(tls),
                Route {
                    scheme: "https",
                    authority,
                    connect: dest.to_owned(),
                },
                peer,
            )
            .await
    }
}

pub async fn relay(mut io: Io, dest: &str) -> Result<()> {
    let mut remote = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(dest))
        .await?
        .context("origin connect")?;
    tokio::io::copy_bidirectional(&mut io, &mut remote).await?;
    Ok(())
}
