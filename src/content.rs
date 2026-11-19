use crate::{Body, Config, full};
use anyhow::Result;
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use http::{HeaderMap, Method, Response, StatusCode, header};
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::body::Frame;
use mitm_adblock_policy::Policy;
use std::{io::Read, sync::Arc};

fn decode(bytes: &[u8], encoding: &str, limit: usize) -> Option<Vec<u8>> {
    let reader: Box<dyn Read + '_> = match encoding.trim().to_ascii_lowercase().as_str() {
        "" | "identity" => return Some(bytes.to_vec()),
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(bytes)),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(bytes)),
        "br" => Box::new(brotli_decompressor::Decompressor::new(bytes, 8192)),
        "zstd" => Box::new(zstd::stream::read::Decoder::new(bytes).ok()?),
        _ => return None,
    };
    let mut out = Vec::new();
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= limit).then_some(out)
}

pub async fn rewrite(
    policy: Arc<Policy>,
    config: &Config,
    url: &str,
    method: &Method,
    headers: &HeaderMap,
    resp: Response<Body>,
) -> Result<Response<Body>> {
    let mime = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let limit = config.html_limit;
    if method == Method::HEAD
        || resp.status() != StatusCode::OK
        || !(config.banners || config.cosmetic)
        || !mime
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("text/html")
        || resp
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| {
                s.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("attachment")
            })
        || resp
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(','))
            .any(|s| s.trim().eq_ignore_ascii_case("no-transform"))
        || resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
            .is_some_and(|size| size > limit as u64)
    {
        return Ok(resp);
    }
    let charset = mime.split(';').skip(1).find_map(|field| {
        let (k, v) = field.trim().split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| v.trim().trim_matches(['"', '\'']).to_owned())
    });
    let (mut parts, mut body) = resp.into_parts();
    let mut size = 0;
    let mut frames = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        size += frame.data_ref().map_or(0, Bytes::len);
        frames.push(frame);
        if size > limit {
            break;
        }
    }
    let original = |frames: Vec<Frame<Bytes>>, body: Body| {
        StreamBody::new(stream::iter(frames.into_iter().map(Ok)).chain(BodyStream::new(body)))
            .boxed_unsync()
    };
    if size > limit {
        return Ok(Response::from_parts(parts, original(frames, body)));
    }
    let mut raw = Vec::with_capacity(size);
    for frame in &frames {
        if let Some(data) = frame.data_ref() {
            raw.extend_from_slice(data);
        }
    }
    let coding = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(bytes) = decode(&raw, coding, limit) else {
        return Ok(Response::from_parts(parts, original(frames, body)));
    };
    let (codec, bom) = encoding_rs::Encoding::for_bom(&bytes).unwrap_or_else(|| {
        (
            charset
                .as_ref()
                .and_then(|s| encoding_rs::Encoding::for_label(s.as_bytes()))
                .unwrap_or(encoding_rs::UTF_8),
            0,
        )
    });
    let (html, invalid) = codec.decode_without_bom_handling(&bytes[bom..]);
    let mut updated = parts.headers.clone();
    if !invalid
        && let Some(text) = policy.rewrite(
            url,
            method.as_str(),
            headers,
            parts.status,
            &mut updated,
            &html,
            config.cosmetic,
            config.banners,
        )
    {
        // Send edited pages as UTF-8, including pages received as UTF-16 or legacy encodings.
        updated.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/html; charset=utf-8"),
        );
        updated.remove(header::CONTENT_ENCODING);
        updated.remove(header::TRAILER);
        updated.insert(header::CONTENT_LENGTH, text.len().into());
        parts.headers = updated;
        return Ok(Response::from_parts(parts, full(text)));
    }
    Ok(Response::from_parts(parts, original(frames, body)))
}
