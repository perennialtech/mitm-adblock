use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use http::uri::{Authority, PathAndQuery};
use http::{Request, Response, Uri, Version, header};
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::{
    Client,
    connect::{Connected, Connection},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::{App, Body, Route, tcp::Io};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_ORIGINS: usize = 256;
const IDLE_PER_ORIGIN: usize = 4;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

type OriginClient = Client<Connector, Body>;
type PrivateSender = AsyncMutex<Option<http1::SendRequest<Body>>>;

/// Origin sockets carrying connection-bound credentials belong to one downstream session.
#[derive(Default)]
pub(crate) struct Session {
    private: Mutex<HashMap<Origin, Arc<PrivateSender>>>,
}

impl Session {
    fn sender(&self, origin: &Origin, begin_auth: bool) -> Option<Arc<PrivateSender>> {
        let mut private = self.private.lock().unwrap();
        if begin_auth {
            Some(private.entry(origin.clone()).or_default().clone())
        } else {
            private.get(origin).cloned()
        }
    }
}

pub(crate) struct Pool {
    tls: Arc<ClientConfig>,
    http1_tls: Arc<ClientConfig>,
    origins: Mutex<HashMap<Origin, Entry>>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct Origin {
    scheme: &'static str,
    authority: Authority,
    connect: String,
    force_http1: bool,
}

struct Entry {
    used_at: Instant,
    client: OriginClient,
}

impl Pool {
    pub(crate) fn new(tls: Arc<ClientConfig>, http1_tls: Arc<ClientConfig>) -> Self {
        Self {
            tls,
            http1_tls,
            origins: Mutex::new(HashMap::new()),
        }
    }

    fn client(&self, origin: Origin) -> OriginClient {
        let mut origins = self.origins.lock().unwrap();
        let now = Instant::now();
        if let Some(entry) = origins.get_mut(&origin) {
            entry.used_at = now;
            return entry.client.clone();
        }

        if origins.len() >= MAX_ORIGINS
            && let Some(oldest) = origins
                .iter()
                .min_by_key(|(_, entry)| entry.used_at)
                .map(|(key, _)| key.clone())
        {
            origins.remove(&oldest);
        }

        let client = self.build_client(origin.clone());
        origins.insert(
            origin,
            Entry {
                used_at: now,
                client: client.clone(),
            },
        );
        client
    }

    fn build_client(&self, origin: Origin) -> OriginClient {
        let tls = if origin.force_http1 {
            self.http1_tls.clone()
        } else {
            self.tls.clone()
        };
        Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(IDLE_TIMEOUT)
            .pool_max_idle_per_host(IDLE_PER_ORIGIN)
            .build(Connector { origin, tls })
    }

    async fn send(
        &self,
        session: &Session,
        mut request: Request<Body>,
        route: &Route,
        force_http1: bool,
    ) -> Result<Response<Body>> {
        let authority: Authority = route.authority.parse()?;
        let path = request
            .uri()
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        *request.version_mut() = Version::HTTP_11;

        // Bind the client to both the masked authority and the physical route.
        let mut origin = Origin {
            scheme: route.scheme,
            authority,
            connect: route.connect.clone(),
            force_http1: true,
        };
        let mut response =
            if let Some(sender) = session.sender(&origin, connection_bound_auth(&request)) {
                *request.uri_mut() = path.into();
                request
                    .headers_mut()
                    .insert(header::HOST, origin.authority.as_str().parse()?);
                self.send_private(request, origin, &sender).await?
            } else {
                *request.uri_mut() = Uri::builder()
                    .scheme(route.scheme)
                    .authority(origin.authority.clone())
                    .path_and_query(path)
                    .build()?;
                origin.force_http1 = force_http1;
                self.client(origin).request(request).await?
            };
        response.headers_mut().remove(header::PROXY_AUTHENTICATE);
        Ok(response.map(|body| body.map_err(anyhow::Error::from).boxed_unsync()))
    }

    async fn send_private(
        &self,
        request: Request<Body>,
        origin: Origin,
        connection: &PrivateSender,
    ) -> Result<Response<hyper::body::Incoming>> {
        // Serialize requests so concurrent HTTP/2 streams use the same HTTP/1 socket.
        let mut connection = connection.lock().await;
        if let Some(sender) = connection.as_mut()
            && sender.ready().await.is_err()
        {
            *connection = None;
        }
        let sender = match connection.as_mut() {
            Some(sender) => sender,
            None => {
                let transport = Connector {
                    origin,
                    tls: self.http1_tls.clone(),
                }
                .connect()
                .await?;
                let (mut sender, driver) = http1::handshake(transport).await?;
                tokio::spawn(driver.with_upgrades());
                sender.ready().await?;
                connection.insert(sender)
            }
        };
        Ok(sender.send_request(request).await?)
    }
}

fn connection_bound_auth(request: &Request<Body>) -> bool {
    request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|value| {
            value
                .as_bytes()
                .split(u8::is_ascii_whitespace)
                .find(|scheme| !scheme.is_empty())
        })
        .any(|scheme| {
            scheme.eq_ignore_ascii_case(b"ntlm") || scheme.eq_ignore_ascii_case(b"negotiate")
        })
}

impl App {
    pub(crate) async fn upstream(
        &self,
        mut request: Request<Body>,
        route: &Route,
        wants_upgrade: bool,
    ) -> Result<Response<Body>> {
        let session = request
            .extensions_mut()
            .remove::<Arc<Session>>()
            .context("missing upstream session")?;
        self.upstream_pool
            .send(&session, request, route, wants_upgrade)
            .await
    }
}

#[derive(Clone)]
struct Connector {
    origin: Origin,
    tls: Arc<ClientConfig>,
}

impl Service<Uri> for Connector {
    type Response = Transport;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Transport>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move { connector.connect().await })
    }
}

impl Connector {
    async fn connect(self) -> io::Result<Transport> {
        let tls_name = (self.origin.scheme == "https")
            .then(|| {
                let hostname = self.origin.authority.host().trim_matches(['[', ']']);
                ServerName::try_from(hostname.to_owned())
            })
            .transpose()
            .map_err(io::Error::other)?;
        let socket = timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.origin.connect)).await??;
        socket.set_nodelay(true)?;
        let (stream, h2): (Io, bool) = if let Some(name) = tls_name {
            let stream = timeout(
                CONNECT_TIMEOUT,
                TlsConnector::from(self.tls).connect(name, socket),
            )
            .await??;
            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            (Box::new(stream), h2)
        } else {
            (Box::new(socket), false)
        };
        Ok(Transport {
            stream: TokioIo::new(stream),
            h2,
        })
    }
}

struct Transport {
    stream: TokioIo<Io>,
    h2: bool,
}

impl Connection for Transport {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if self.h2 {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl Read for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl Write for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, buffers)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicU8, Ordering};

    use http::StatusCode;

    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use tokio::net::TcpListener;

    use crate::full;

    use super::*;

    async fn serve_origin(listener: TcpListener, label: &'static str) {
        let mut accepted = 0;
        while let Ok((stream, _)) = listener.accept().await {
            accepted += 1;
            let service = service_fn(move |request: Request<hyper::body::Incoming>| async move {
                let host = request.headers()[header::HOST].to_str().unwrap();
                Ok::<_, Infallible>(Response::new(full(format!("{label}/{accepted}/{host}"))))
            });
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }

    async fn call(
        pool: &Pool,
        session: &Session,
        connect: &str,
        authority: &str,
        authorization: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::new(full(""));
        if let Some(value) = authorization {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, value.parse().unwrap());
        }
        let route = Route {
            scheme: "http",
            authority: authority.to_owned(),
            connect: connect.to_owned(),
        };
        let response = pool.send(session, request, &route, false).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn pool() -> Pool {
        let tls = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        Pool::new(tls.clone(), tls)
    }

    #[tokio::test]
    async fn pool_separates_physical_destinations_and_authorities() {
        let one = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let two = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let first = one.local_addr().unwrap().to_string();
        let second = two.local_addr().unwrap().to_string();
        tokio::spawn(serve_origin(one, "one"));
        tokio::spawn(serve_origin(two, "two"));

        let pool = pool();
        let session = Session::default();

        assert_eq!(
            call(&pool, &session, &first, "virtual.test", None).await.1,
            "one/1/virtual.test"
        );
        assert_eq!(
            call(&pool, &session, &second, "virtual.test", None).await.1,
            "two/1/virtual.test"
        );
        assert_eq!(
            call(&pool, &session, &first, "other.test", None).await.1,
            "one/2/other.test"
        );
    }

    async fn serve_auth_origin(listener: TcpListener, scheme: &'static str) {
        let mut accepted = 0;
        while let Ok((stream, _)) = listener.accept().await {
            accepted += 1;
            let phase = Arc::new(AtomicU8::new(0));
            let first = format!("{scheme} fixture-negotiate");
            let second = format!("{scheme} fixture-authenticate");
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let auth = request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                let current = phase.load(Ordering::Relaxed);
                let (next, ok) = match auth {
                    Some(value) if value == first => (1, false),
                    Some(value) if value == second && current == 1 => (2, true),
                    None if current == 2 => (2, true),
                    _ => (0, false),
                };
                phase.store(next, Ordering::Relaxed);
                let mut response = Response::new(full(accepted.to_string()));
                if !ok {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    let challenge = if next == 1 {
                        format!("{scheme} fixture-challenge")
                    } else {
                        scheme.to_owned()
                    };
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, challenge.parse().unwrap());
                }
                async move { Ok::<_, Infallible>(response) }
            });
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }

    #[tokio::test]
    async fn connection_bound_auth_is_private_throughout_the_exchange() {
        for scheme in ["NTLM", "Negotiate"] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let origin = tokio::spawn(serve_auth_origin(listener, scheme));
            let pool = pool();
            let authenticating = Session::default();
            let other = Session::default();
            let authority = "virtual.test";
            let negotiate = format!("{scheme} fixture-negotiate");
            let authenticate = format!("{scheme} fixture-authenticate");

            let anonymous = call(&pool, &authenticating, &address, authority, None).await;
            assert_eq!(anonymous.0, StatusCode::UNAUTHORIZED);
            assert_eq!(
                call(&pool, &other, &address, authority, None).await,
                anonymous
            );

            let challenged = call(
                &pool,
                &authenticating,
                &address,
                authority,
                Some(&negotiate),
            )
            .await;
            assert_eq!(challenged.0, StatusCode::UNAUTHORIZED);
            assert_ne!(challenged.1, anonymous.1);
            let granted = call(
                &pool,
                &authenticating,
                &address,
                authority,
                Some(&authenticate),
            )
            .await;
            assert_eq!(granted, (StatusCode::OK, challenged.1));
            assert_eq!(
                call(&pool, &authenticating, &address, authority, None).await,
                granted
            );

            assert_eq!(
                call(&pool, &other, &address, authority, None).await,
                anonymous
            );
            let no_challenge = call(&pool, &other, &address, authority, Some(&authenticate)).await;
            assert_eq!(no_challenge.0, StatusCode::UNAUTHORIZED);
            assert_ne!(no_challenge.1, granted.1);

            origin.abort();
        }
    }
}
