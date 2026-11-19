use crate::{App, Body, Route, full, host_port, tcp::Io};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, Version, header};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service::service_fn, upgrade};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};

fn incoming(body: Incoming) -> Body {
    body.map_err(anyhow::Error::from).boxed_unsync()
}

fn error(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(full(status.canonical_reason().unwrap_or_default()))
        .unwrap()
}

async fn answer(
    f: impl Future<Output = Result<Response<Body>>>,
) -> Result<Response<Body>, Infallible> {
    Ok(f.await.unwrap_or_else(|e| {
        eprintln!("request failed: {e}");
        error(StatusCode::BAD_GATEWAY)
    }))
}

fn remove_hop_fields(headers: &mut HeaderMap, upgrading: bool) {
    let names: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(','))
        .filter_map(|s| header::HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    for name in names {
        if !(upgrading && name == header::UPGRADE) {
            headers.remove(name);
        }
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "transfer-encoding",
        "te",
    ] {
        headers.remove(name);
    }
    if upgrading {
        headers.insert(
            header::CONNECTION,
            header::HeaderValue::from_static("upgrade"),
        );
    } else {
        headers.remove(header::UPGRADE);
    }
}

fn request_authority(req: &Request<Body>) -> Option<&str> {
    req.uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| req.headers().get(header::HOST)?.to_str().ok())
}

impl App {
    pub async fn explicit(self: Arc<Self>, io: Io, peer: SocketAddr) -> Result<()> {
        let session = Arc::new(crate::upstream::Session::default());
        let serve = service_fn(move |req: Request<Incoming>| {
            let app = self.clone();
            let session = session.clone();
            answer(async move {
                let mut req = req.map(incoming);
                req.extensions_mut().insert(session);
                if req.method() == Method::CONNECT {
                    let Some(target) = req.uri().authority() else {
                        return Ok(error(StatusCode::BAD_REQUEST));
                    };
                    if target.port_u16().is_none() || target.as_str().contains('@') {
                        return Ok(error(StatusCode::BAD_REQUEST));
                    }
                    let dest = target.to_string();
                    let upgraded = upgrade::on(&mut req);
                    tokio::spawn(async move {
                        if let Ok(up) = upgraded.await
                            && let Err(e) =
                                app.intercept(Box::new(TokioIo::new(up)), peer, &dest).await
                        {
                            eprintln!("CONNECT session: {e}");
                        }
                    });
                    return Ok(Response::new(full(Bytes::new())));
                }
                if req.uri().scheme_str().is_some_and(|s| s != "http") {
                    return Ok(error(StatusCode::BAD_REQUEST));
                }
                let Some(name) = request_authority(&req) else {
                    return Ok(error(StatusCode::BAD_REQUEST));
                };
                let host = name.parse::<http::uri::Authority>()?;
                if name.contains('@') {
                    return Ok(error(StatusCode::BAD_REQUEST));
                }
                let route = Route {
                    scheme: "http",
                    authority: name.to_owned(),
                    connect: host_port(host.host(), host.port_u16().unwrap_or(80)),
                };
                app.forward(req, route).await
            })
        });
        auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(io), serve)
            .await
            .map_err(|e| anyhow!(e))
    }

    pub async fn http_session(
        self: Arc<Self>,
        io: Io,
        route: Route,
        peer: SocketAddr,
    ) -> Result<()> {
        let session = Arc::new(crate::upstream::Session::default());
        let serve = service_fn(move |req: Request<Incoming>| {
            let app = self.clone();
            let session = session.clone();
            let route = route.clone();
            answer(async move {
                let mut req = req.map(incoming);
                req.extensions_mut().insert(session);
                req.extensions_mut().insert(peer.ip());
                app.forward(req, route).await
            })
        });
        auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(io), serve)
            .await
            .map_err(|e| anyhow!(e))
    }

    pub async fn forward(
        &self,
        mut req: Request<Body>,
        mut route: Route,
    ) -> Result<Response<Body>> {
        // Keep the network destination fixed for redirected and CONNECT streams.
        let offered = request_authority(&req).map(str::to_owned);
        if route.authority.is_empty() {
            route.authority = offered.unwrap_or_else(|| route.connect.clone());
        } else if let Some(raw) = offered {
            let actual: http::uri::Authority = raw.parse()?;
            let expected: http::uri::Authority = route.authority.parse()?;
            let default = if route.scheme == "https" { 443 } else { 80 };
            if !actual
                .host()
                .trim_end_matches('.')
                .eq_ignore_ascii_case(expected.host().trim_end_matches('.'))
                || actual.port_u16().unwrap_or(default) != expected.port_u16().unwrap_or(default)
            {
                return Ok(error(StatusCode::MISDIRECTED_REQUEST));
            }
            route.authority = raw;
        }
        let host = route.authority.parse::<http::uri::Authority>()?;
        if host.as_str().contains('@') {
            return Ok(error(StatusCode::BAD_REQUEST));
        }
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let url = format!("{}://{}{}", route.scheme, route.authority, path);
        if host.host().eq_ignore_ascii_case("mitm.it") && route.scheme == "http" {
            return Ok(self.enroll(req.method(), req.uri().path()));
        }
        let method = req.method().clone();
        let headers = req.headers().clone();
        let policy = self.policy.read().unwrap().clone();
        if let Some(blocked) = policy.request(&url, method.as_str(), &headers) {
            if self.config.log_blocked {
                eprintln!("blocked {url}");
            }
            return Ok(blocked.map(full));
        }
        let h3 = req.version() == Version::HTTP_3;
        let wants_upgrade = !h3
            && req.headers().contains_key(header::UPGRADE)
            && req
                .headers()
                .get_all(header::CONNECTION)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .any(|s| s.trim().eq_ignore_ascii_case("upgrade"));
        let downstream = wants_upgrade.then(|| upgrade::on(&mut req));
        remove_hop_fields(req.headers_mut(), wants_upgrade);
        req.headers_mut()
            .insert(header::HOST, route.authority.parse()?);
        let peer = req.extensions().get::<std::net::IpAddr>().copied();
        let origin = if h3 {
            *req.uri_mut() = url.parse()?;
            crate::ingress::send_h3(self, req, &route).await
        } else {
            self.upstream(req, &route, wants_upgrade).await
        };
        let mut resp = origin.inspect_err(|_| {
            if route.scheme == "https"
                && let Some(peer) = peer
                && let Ok(name) = route.authority.parse::<http::uri::Authority>()
            {
                self.fallback.forget(peer, &route.connect, name.host());
            }
        })?;
        let switching = wants_upgrade && resp.status() == StatusCode::SWITCHING_PROTOCOLS;
        remove_hop_fields(resp.headers_mut(), switching);
        if switching && let Some(client) = downstream {
            let origin = upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let Ok((a, b)) = tokio::try_join!(client, origin) {
                    let _ =
                        tokio::io::copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b))
                            .await;
                }
            });
            return Ok(resp);
        }
        if let Some(blocked) = policy.redirect(
            &url,
            method.as_str(),
            &headers,
            resp.status(),
            resp.headers(),
        ) {
            if self.config.log_blocked {
                eprintln!("blocked navigation from {url}");
            }
            return Ok(blocked.map(full));
        }
        crate::content::rewrite(policy, &self.config, &url, &method, &headers, resp).await
    }

    fn enroll(&self, method: &Method, path: &str) -> Response<Body> {
        if method != Method::GET && method != Method::HEAD {
            return error(StatusCode::METHOD_NOT_ALLOWED);
        }
        let (mime,data):(&str,&[u8])=match path {
            "/" => ("text/html; charset=utf-8",br#"<!doctype html><title>Ad blocking certificate</title><h1>Ad blocking certificate</h1><p>Install and trust this certificate on devices enrolled in this proxy.</p><a href="/cert/pem">Download CA (PEM)</a> &middot; <a href="/cert/cer">Download CA (DER)</a>"#),
            "/cert/pem" | "/cert/android" => ("application/x-pem-file",&self.ca.public_pem),
            "/cert/cer" | "/cert/ios" | "/cert/windows" => ("application/x-x509-ca-cert",&self.ca.public_der),
            _ => return error(StatusCode::NOT_FOUND),
        };
        Response::builder()
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, data.len())
            .body(if method == Method::HEAD {
                full(Bytes::new())
            } else {
                full(Bytes::copy_from_slice(data))
            })
            .unwrap()
    }
}
