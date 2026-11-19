//! Run production filtering decisions over archived events from the offline replay harness.

use std::fs;
use std::io::{self, BufRead, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use mitm_adblock_policy::{BlockInfo, Policy};
use mitm_adblock_subscriptions::{self as subscriptions, Snapshot};
use serde::{Deserialize, Serialize};

type WireHeaders = Vec<(String, String)>;

#[derive(Deserialize)]
struct Event {
    url: String,
    method: String,
    request_headers: WireHeaders,
    response: Option<RecordedResponse>,
}

#[derive(Deserialize)]
struct RecordedResponse {
    status: u16,
    headers: WireHeaders,
    html: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum Outcome {
    Unchanged,
    Block {
        status: u16,
        headers: WireHeaders,
        body: String,
        rule: Option<String>,
        navigation: Option<&'static str>,
    },
    Rewrite {
        headers: WireHeaders,
        html: String,
        injected: bool,
    },
    Error,
}

fn load(input: &Path) -> Result<Policy> {
    let input = input.canonicalize()?;
    let mut sources = Vec::new();
    for entry in fs::read_dir(&input)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "txt")
            && entry.file_name() != "threat-domains.txt"
        {
            sources.push(path);
        }
    }
    sources.sort_unstable();
    let mut lists = Vec::new();
    for path in &sources {
        let path_string = path.to_str().context("Invalid replay subscription path")?;
        anyhow::ensure!(
            !path_string.contains(','),
            "Invalid replay subscription path"
        );
        if path
            .file_name()
            .is_some_and(|name| name == "adguard-base.txt")
        {
            lists.push(format!("supplement:{path_string}"));
        } else {
            lists.push(path_string.to_owned());
        }
    }
    let Snapshot {
        primary,
        supplemental,
        domains,
        payload_urls,
    } = subscriptions::load(
        &subscriptions::Config {
            lists: lists.join(","),
            cache_dir: input.clone(),
            update_hours: 0,
            threatfox_key_file: None,
            threat_domains_file: Some(input.join("threat-domains.txt")),
        },
        false,
    )?;
    Ok(Policy::new(primary, supplemental, domains, payload_urls))
}

fn decode_headers(values: WireHeaders) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(&STANDARD.decode(value)?)?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn encode_headers(headers: &HeaderMap) -> WireHeaders {
    headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), STANDARD.encode(value.as_bytes())))
        .collect()
}

fn block(response: Response<Vec<u8>>, navigation: Option<&'static str>) -> Outcome {
    let (parts, body) = response.into_parts();
    Outcome::Block {
        status: parts.status.as_u16(),
        headers: encode_headers(&parts.headers),
        body: STANDARD.encode(body),
        rule: parts
            .extensions
            .get::<BlockInfo>()
            .and_then(|info| info.rule.clone()),
        navigation,
    }
}

fn evaluate(policy: &Policy, event: Event) -> Result<Outcome> {
    let Event {
        url,
        method,
        request_headers,
        response,
    } = event;
    let request_headers = decode_headers(request_headers)?;
    let Some(recorded) = response else {
        return Ok(policy
            .request(&url, &method, &request_headers)
            .map_or(Outcome::Unchanged, |response| block(response, None)));
    };

    let status = StatusCode::from_u16(recorded.status)?;
    let mut headers = decode_headers(recorded.headers)?;
    if let Some(response) = policy.redirect(&url, &method, &request_headers, status, &headers) {
        let navigation = if status == StatusCode::OK {
            "refresh"
        } else {
            "redirect"
        };
        return Ok(block(response, Some(navigation)));
    }

    const INJECTED_STYLE: &str = "<style data-mitm-adblock>";
    if let Some(html) = recorded.html
        && let Some(rewritten) = policy.rewrite(
            &url,
            &method,
            &request_headers,
            status,
            &mut headers,
            &html,
            true,
            true,
        )
    {
        let injected =
            rewritten.matches(INJECTED_STYLE).count() > html.matches(INJECTED_STYLE).count();
        return Ok(Outcome::Rewrite {
            headers: encode_headers(&headers),
            html: rewritten,
            injected,
        });
    }
    Ok(Outcome::Unchanged)
}

fn serve() -> Result<()> {
    let input = std::env::args_os()
        .nth(1)
        .context("Missing replay directory")?;
    let policy = load(Path::new(&input))?;
    let mut output = BufWriter::new(io::stdout().lock());
    output.write_all(b"{\"ready\":true}\n")?;
    output.flush()?;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let outcome = serde_json::from_str(&line)
            .ok()
            .and_then(|event| evaluate(&policy, event).ok())
            .unwrap_or(Outcome::Error);
        serde_json::to_writer(&mut output, &outcome)?;
        writeln!(output)?;
        output.flush()?;
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    // Input files and event data stay inside the replay process and its pipe.
    if serve().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
