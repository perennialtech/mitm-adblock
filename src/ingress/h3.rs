use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use futures_util::stream;
use http::{Request, Response, StatusCode, Version, uri::Authority};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use tokio::{net::lookup_host, sync::OnceCell, task::JoinSet, time::timeout};

use crate::{App, Body, Route};

type ServerReceive = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type ClientReceive = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type OriginSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

pub(super) async fn serve_connection(
    app: Arc<App>,
    destination: SocketAddr,
    connection: quinn::Connection,
) -> Result<()> {
    let peer = connection.remote_address().ip();
    // Some HTTP/3 clients miss the stream end when the last frame is GREASE.
    let mut h3 = h3::server::builder()
        .send_grease(false)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    let origins = Arc::new(OriginPool::default());
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            request = h3.accept() => {
                let Some(request) = request? else { return Ok(()) };
                let app = app.clone();
                let origins = origins.clone();
                requests.spawn(async move {
                    let (request, io) = request.resolve_request().await?;
                    serve_request(app, peer, destination, origins, request, io).await
                });
            }
            Some(result) = requests.join_next(), if !requests.is_empty() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!(%error, "HTTP/3 stream closed"),
                    Err(error) => tracing::debug!(%error, "HTTP/3 request task stopped"),
                }
            }
        }
    }
}

async fn serve_request(
    app: Arc<App>,
    peer: IpAddr,
    destination: SocketAddr,
    origins: Arc<OriginPool>,
    mut request: Request<()>,
    io: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<()> {
    let (mut send, receive) = io.split();
    *request.version_mut() = Version::HTTP_3;
    request.extensions_mut().insert(peer);
    request.extensions_mut().insert(origins);
    let authority = request
        .uri()
        .authority()
        .context("missing HTTP/3 authority")?
        .to_string();
    let route = Route {
        scheme: "https",
        authority,
        connect: destination.to_string(),
    };
    let request = request.map(|_| request_body(receive));
    let response = match app.forward(request, route).await {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(%error, "HTTP/3 upstream failed");
            Response::builder().status(StatusCode::BAD_GATEWAY).body(
                Full::new(Bytes::new())
                    .map_err(|error| match error {})
                    .boxed_unsync(),
            )?
        }
    };
    let (mut headers, mut body) = response.into_parts();
    headers.version = Version::HTTP_3;
    send.send_response(Response::from_parts(headers, ()))
        .await?;
    while let Some(frame) = body.frame().await {
        match frame?.into_data() {
            Ok(data) => send.send_data(data).await?,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send.send_trailers(trailers).await?;
                    return Ok(());
                }
            }
        }
    }
    send.finish().await?;
    Ok(())
}

fn request_body(receive: ServerReceive) -> Body {
    let frames = stream::try_unfold(Some(receive), |state| async move {
        let Some(mut receive) = state else {
            return Ok(None);
        };
        if let Some(mut data) = receive.recv_data().await? {
            let data = data.copy_to_bytes(data.remaining());
            return Ok(Some((Frame::data(data), Some(receive))));
        }
        Ok(receive
            .recv_trailers()
            .await?
            .map(|trailers| (Frame::trailers(trailers), None)))
    });
    StreamBody::new(frames).boxed_unsync()
}

const MAX_ORIGINS: usize = 32;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OriginKey {
    destination: SocketAddr,
    authority: String,
}

struct Origin {
    transport: quinn::Connection,
    sender: Mutex<OriginSender>,
}

#[derive(Default)]
struct OriginPool {
    routes: Mutex<HashMap<OriginKey, Arc<OnceCell<Origin>>>>,
}

impl OriginPool {
    fn route(&self, key: &OriginKey) -> Arc<OnceCell<Origin>> {
        let mut routes = self.routes.lock().unwrap();
        if let Some(slot) = routes.get(key) {
            if slot
                .get()
                .is_none_or(|origin| origin.transport.close_reason().is_none())
            {
                return slot.clone();
            }
            routes.remove(key);
        }
        let slot = Arc::new(OnceCell::new());
        if routes.len() < MAX_ORIGINS {
            routes.insert(key.clone(), slot.clone());
        }
        slot
    }

    fn discard(&self, key: &OriginKey, slot: &Arc<OnceCell<Origin>>) {
        let mut routes = self.routes.lock().unwrap();
        if routes
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, slot))
        {
            routes.remove(key);
        }
    }
}

pub async fn send_h3(app: &App, request: Request<Body>, route: &Route) -> Result<Response<Body>> {
    let authority: Authority = route.authority.parse()?;
    let name = authority.host().trim_matches(['[', ']']);
    let destination = lookup_host(&route.connect)
        .await?
        .next()
        .context("no HTTP/3 origin address")?;
    let pool = request
        .extensions()
        .get::<Arc<OriginPool>>()
        .context("missing downstream HTTP/3 connection")?
        .clone();
    let key = OriginKey {
        destination,
        authority: authority.as_str().to_ascii_lowercase(),
    };
    let slot = pool.route(&key);
    let origin = slot
        .get_or_try_init(|| connect_origin(app, destination, name))
        .await?;
    let mut sender = origin.sender.lock().unwrap().clone();
    let (headers, mut body) = request.into_parts();
    let io = match sender.send_request(Request::from_parts(headers, ())).await {
        Ok(io) => io,
        Err(error) => {
            // A new request can reconnect. The current stream may already have
            // sent headers, so never replay it on another connection.
            pool.discard(&key, &slot);
            return Err(error.into());
        }
    };
    let (mut send, mut receive) = io.split();
    // The last request sender closes the h3 connection, even if a stream is
    // still reading or writing. Keep one sender in each stream direction.
    let upload_sender = sender.clone();
    tokio::spawn(async move {
        let _sender = upload_sender;
        let result: Result<()> = async {
            while let Some(frame) = body.frame().await {
                match frame?.into_data() {
                    Ok(data) => send.send_data(data).await?,
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            send.send_trailers(trailers).await?;
                            return Ok(());
                        }
                    }
                }
            }
            send.finish().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "HTTP/3 upstream upload stopped");
        }
    });

    let response = receive.recv_response().await?;
    Ok(response.map(|_| response_body(receive, sender)))
}

async fn connect_origin(app: &App, destination: SocketAddr, name: &str) -> Result<Origin> {
    let mut tls = (*app.client_tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = Endpoint::client(SocketAddr::new(
        super::udp::unspecified(destination.ip()),
        0,
    ))?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
    )));
    let transport = timeout(
        Duration::from_secs(10),
        endpoint.connect(destination, name)?,
    )
    .await??;
    let (mut h3, sender) = h3::client::builder()
        .send_grease(false)
        .build(h3_quinn::Connection::new(transport.clone()))
        .await?;
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let _ = h3.wait_idle().await;
    });
    Ok(Origin {
        transport,
        sender: Mutex::new(sender),
    })
}

fn response_body(receive: ClientReceive, sender: OriginSender) -> Body {
    let frames = stream::try_unfold(Some((receive, sender)), |state| async move {
        let Some((mut receive, sender)) = state else {
            return Ok(None);
        };
        if let Some(mut data) = receive.recv_data().await? {
            let data = data.copy_to_bytes(data.remaining());
            return Ok(Some((Frame::data(data), Some((receive, sender)))));
        }
        Ok(receive
            .recv_trailers()
            .await?
            .map(|trailers| (Frame::trailers(trailers), None)))
    });
    StreamBody::new(frames).boxed_unsync()
}
