mod html;
mod navigation;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use adblock::cosmetic_filter_cache::ProceduralOrActionFilter;
use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, LOCATION, ORIGIN, REFERER, REFRESH,
    UPGRADE,
};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use percent_encoding::percent_decode_str;
use regex::Regex;

use html::{DocumentHead, authorize_stylesheet, selector_tokens};
pub use navigation::exact_url_key;
use navigation::{resolve, url_path};

static REFRESH_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\A[ \t]*[0-9]+(?:\.[0-9]*)?[ \t]*[;,][ \t]*url[ \t]*=[ \t]*",
        r#"(?:"([^"]+)"|'([^']+)'|([^ \t"']+))[ \t]*\z"#,
    ))
    .unwrap()
});

/// Details for the proxy's optional block logging.
#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub url: String,
    pub request_type: &'static str,
    pub rule: Option<String>,
}

pub struct Policy {
    primary: adblock::Engine,
    supplement: Option<adblock::Engine>,
    domains: HashSet<String>,
    payload_urls: HashMap<String, i64>,
}

impl Policy {
    pub fn new(
        primary: Vec<String>,
        supplemental: Vec<String>,
        domains: HashSet<String>,
        payload_urls: HashMap<String, i64>,
    ) -> Self {
        Self {
            primary: compile(primary),
            supplement: (!supplemental.is_empty()).then(|| compile(supplemental)),
            domains,
            payload_urls,
        }
    }

    /// Filter an outbound request at the destination visible to the browser.
    pub fn request(
        &self,
        url: &str,
        method: &str,
        headers: &HeaderMap,
    ) -> Option<Response<Vec<u8>>> {
        let kind = request_type(url, method, headers);
        self.block(url, source_url(url, headers, kind), method, kind, true)
    }

    /// Filter HTTP redirects and Refresh navigations before a client follows them.
    pub fn redirect(
        &self,
        url: &str,
        method: &str,
        request_headers: &HeaderMap,
        status: StatusCode,
        response_headers: &HeaderMap,
    ) -> Option<Response<Vec<u8>>> {
        let mut kind = request_type(url, method, request_headers);
        let (location, followup_method) = match status.as_u16() {
            301 | 302 | 303 | 307 | 308 => {
                let location = single_header(response_headers, LOCATION)?;
                if location.trim().is_empty() {
                    return None;
                }
                let followup_method = match (status.as_u16(), method) {
                    (301 | 302, "POST") => "GET",
                    (303, method) if method != "HEAD" => "GET",
                    _ => method,
                };
                (location, followup_method)
            }
            200 if html_document(response_headers, kind) => {
                let value = single_header(response_headers, REFRESH)?;
                let target = REFRESH_TARGET.captures(value)?;
                let location = (1..=3).find_map(|index| target.get(index))?.as_str();
                (location, "GET")
            }
            _ => return None,
        };

        let target = resolve(url, location)?;
        // Keep the original inferred destination when following a redirect.
        if kind == "other" {
            kind = request_type(&target, method, request_headers);
        }
        self.block(
            &target,
            source_url(&target, request_headers, kind),
            followup_method,
            kind,
            false,
        )
    }

    /// Compute body edits and their associated header changes for decoded HTML.
    #[allow(clippy::too_many_arguments)]
    pub fn rewrite(
        &self,
        url: &str,
        method: &str,
        request_headers: &HeaderMap,
        status: StatusCode,
        response_headers: &mut HeaderMap,
        html: &str,
        cosmetic: bool,
        smart_banners: bool,
    ) -> Option<String> {
        let kind = request_type(url, method, request_headers);
        let smart_banners = smart_banners && kind == "document";
        if status != StatusCode::OK
            || !(cosmetic || smart_banners)
            || !html_document(response_headers, kind)
            || header_tokens(response_headers, CACHE_CONTROL)
                .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
            || html.is_empty()
        {
            return None;
        }

        let head = DocumentHead::scan(html)?;
        let mut edits = Vec::new();
        if smart_banners {
            edits.extend(
                head.smart_apps
                    .into_iter()
                    .map(|range| (range, String::new())),
            );
        }
        if cosmetic
            && !head.meta_policy
            && let Some(position) = head.position
        {
            let css = self.stylesheet(url, html);
            if !css.is_empty() {
                authorize_stylesheet(response_headers, &css);
                edits.push((
                    position..position,
                    format!("<style data-mitm-adblock>{css}</style>"),
                ));
            }
        }
        if edits.is_empty() {
            return None;
        }
        edits.sort_unstable_by_key(|(range, _)| (range.start, range.end));
        let mut modified = String::with_capacity(html.len());
        let mut cursor = 0;
        for (range, replacement) in edits {
            modified.push_str(&html[cursor..range.start]);
            modified.push_str(&replacement);
            cursor = range.end;
        }
        modified.push_str(&html[cursor..]);
        for key in [
            "etag",
            "content-md5",
            "digest",
            "repr-digest",
            "content-digest",
        ] {
            response_headers.remove(key);
        }
        Some(modified)
    }

    fn block(
        &self,
        url: &str,
        source: &str,
        method: &str,
        kind: &'static str,
        allow_resource: bool,
    ) -> Option<Response<Vec<u8>>> {
        let request = Request::new(url, source, kind, method).ok()?;
        let found_host = self
            .domains
            .contains(request.hostname.trim_end_matches('.'));
        let found_payload = !self.payload_urls.is_empty()
            && exact_url_key(url)
                .and_then(|key| self.payload_urls.get(&key))
                .and_then(|expiry| u64::try_from(*expiry).ok())
                .is_some_and(|expiry| {
                    expiry > 0
                        && SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .is_ok_and(|now| expiry > now.as_secs())
                });
        let mut result = self.primary.check_network_request_subset(
            &request,
            found_host || found_payload,
            self.supplement.is_some(),
        );
        if !result.should_block()
            && result.exception.is_none()
            && let Some(supplement) = &self.supplement
        {
            result = supplement.check_network_request_subset(&request, false, false);
        }
        if !result.should_block() {
            return None;
        }

        let rule = result.filter.and_then(|rule| rule.raw_line).or_else(|| {
            if found_payload {
                Some("Exact threat payload URL".to_owned())
            } else {
                found_host.then(|| "Exact threat hostname".to_owned())
            }
        });
        let resource = result
            .redirect
            .as_deref()
            .filter(|_| allow_resource)
            .and_then(data_url);
        let mut response = if let Some((content_type, body)) = resource {
            let mut response = Response::new(body);
            response.headers_mut().insert(CONTENT_TYPE, content_type);
            response
        } else if is_document(kind) {
            let mut response =
                Response::new(blocked_page(url, rule.as_deref().unwrap_or_default()));
            *response.status_mut() = StatusCode::FORBIDDEN;
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        } else {
            let mut response = Response::new(Vec::new());
            *response.status_mut() = StatusCode::NO_CONTENT;
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        };
        response.extensions_mut().insert(BlockInfo {
            url: url.to_owned(),
            request_type: kind,
            rule,
        });
        Some(response)
    }

    fn stylesheet(&self, url: &str, html: &str) -> String {
        let primary = self.primary.url_cosmetic_resources(url);
        let mut styles = style_rules(&primary.procedural_actions);
        let mut selectors: BTreeSet<_> = primary.hide_selectors.into_iter().collect();
        let supplemental = self
            .supplement
            .as_ref()
            .map(|engine| (engine, engine.url_cosmetic_resources(url)));
        if !primary.generichide {
            let (classes, ids) = selector_tokens(html);
            if let Some((engine, extra)) = &supplemental
                && !extra.generichide
            {
                let exceptions = extra
                    .exceptions
                    .union(&primary.exceptions)
                    .cloned()
                    .collect();
                selectors.extend(engine.hidden_class_id_selectors(
                    classes.clone(),
                    ids.clone(),
                    &exceptions,
                ));
            }
            selectors.extend(self.primary.hidden_class_id_selectors(
                classes,
                ids,
                &primary.exceptions,
            ));
        }

        if let Some((_, extra)) = supplemental {
            styles.extend(
                style_rules(&extra.procedural_actions)
                    .into_iter()
                    .filter(|(selector, _)| !primary.exceptions.contains(selector)),
            );
            selectors.extend(
                extra
                    .hide_selectors
                    .into_iter()
                    .filter(|selector| !primary.exceptions.contains(selector)),
            );
        }

        let mut css = String::new();
        for selector in selectors {
            append_rule(&mut css, &selector, "display:none!important");
        }
        let mut seen = HashSet::new();
        for (selector, style) in &styles {
            if seen.insert((selector, style)) {
                append_rule(&mut css, selector, style);
            }
        }
        css.replace("\r\n", "\n").replace('\r', "\n")
    }
}

fn compile(lists: Vec<String>) -> adblock::Engine {
    // Preserve the original rule text for block pages and logging.
    let mut filters = FilterSet::new(true);
    for list in lists {
        filters.add_filter_list(list, ParseOptions::default());
    }
    adblock::Engine::new_with_filter_set(filters)
}

fn style_rules<T: AsRef<str>>(rules: impl IntoIterator<Item = T>) -> Vec<(String, String)> {
    let mut styles: Vec<_> = rules
        .into_iter()
        .filter_map(|rule| serde_json::from_str::<ProceduralOrActionFilter>(rule.as_ref()).ok())
        .filter_map(|rule| rule.as_css())
        .collect();
    styles.sort_unstable();
    styles
}

fn append_rule(css: &mut String, selector: &str, style: &str) {
    // CSS is embedded in a raw-text element.
    if selector.to_ascii_lowercase().contains("</style")
        || style.to_ascii_lowercase().contains("</style")
    {
        return;
    }
    css.push_str(selector);
    css.push('{');
    css.push_str(style);
    css.push('}');
}

fn request_type(url: &str, method: &str, headers: &HeaderMap) -> &'static str {
    if header(headers, UPGRADE).eq_ignore_ascii_case("websocket") {
        return "websocket";
    }
    if method == "POST"
        && mime_type(header(headers, CONTENT_TYPE)).eq_ignore_ascii_case("text/ping")
        && !header(headers, "ping-to").is_empty()
    {
        return "ping";
    }

    match header(headers, "sec-fetch-dest")
        .to_ascii_lowercase()
        .as_str()
    {
        "document" => return "document",
        "iframe" | "frame" | "fencedframe" => return "subdocument",
        "image" => return "image",
        "script" | "worker" | "sharedworker" | "serviceworker" | "audioworklet"
        | "paintworklet" => return "script",
        "style" => return "stylesheet",
        "font" => return "font",
        "audio" | "video" | "track" => return "media",
        "object" | "embed" => return "object",
        "empty" => return "xmlhttprequest",
        "report" => return "ping",
        "manifest" => return "other",
        _ => {}
    }

    let filename = url_path(url).rsplit('/').next().unwrap_or_default();
    if let Some((stem, extension)) = filename.rsplit_once('.')
        && stem.bytes().any(|ch| ch != b'.')
    {
        match extension.to_ascii_lowercase().as_str() {
            "js" | "mjs" => return "script",
            "css" => return "stylesheet",
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" => return "image",
            "woff" | "woff2" | "ttf" | "otf" => return "font",
            "mp4" | "webm" | "mp3" | "m3u8" => return "media",
            "html" | "htm" => return "document",
            _ => {}
        }
    }

    let accept = header(headers, ACCEPT).to_ascii_lowercase();
    if accept.starts_with("text/html") {
        "document"
    } else if accept.starts_with("image/") {
        "image"
    } else if accept.starts_with("text/css") {
        "stylesheet"
    } else {
        "other"
    }
}

fn source_url<'a>(url: &'a str, headers: &'a HeaderMap, kind: &str) -> &'a str {
    if kind == "document" {
        return url;
    }
    for name in [REFERER, ORIGIN] {
        let value = header(headers, name);
        if !value.is_empty() {
            return value;
        }
    }
    if header(headers, "sec-fetch-site").eq_ignore_ascii_case("cross-site") {
        return "";
    }
    url
}

fn header(headers: &HeaderMap, name: impl http::header::AsHeaderName) -> &str {
    headers.get(name).and_then(header_text).unwrap_or_default()
}

fn header_text(value: &HeaderValue) -> Option<&str> {
    std::str::from_utf8(value.as_bytes()).ok()
}

fn single_header(headers: &HeaderMap, name: http::header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().and_then(header_text)?;
    values.next().is_none().then_some(value)
}

fn header_tokens(
    headers: &HeaderMap,
    name: http::header::HeaderName,
) -> impl Iterator<Item = &str> {
    headers
        .get_all(name)
        .into_iter()
        .filter_map(header_text)
        .flat_map(|value| value.split(','))
}

fn mime_type(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

fn is_document(kind: &str) -> bool {
    matches!(kind, "document" | "subdocument")
}

fn html_document(headers: &HeaderMap, kind: &str) -> bool {
    is_document(kind)
        && mime_type(header(headers, CONTENT_TYPE)).eq_ignore_ascii_case("text/html")
        && !mime_type(header(headers, CONTENT_DISPOSITION)).eq_ignore_ascii_case("attachment")
}

fn data_url(value: &str) -> Option<(HeaderValue, Vec<u8>)> {
    let (content_type, data) = value.strip_prefix("data:")?.split_once(',')?;
    let (content_type, body) = if let Some(content_type) = content_type.strip_suffix(";base64") {
        let data: Vec<u8> = data
            .bytes()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect();
        (content_type, STANDARD.decode(data).ok()?)
    } else {
        (content_type, percent_decode_str(data).collect())
    };
    let content_type = if content_type.is_empty() {
        "text/plain"
    } else {
        content_type
    };
    Some((HeaderValue::from_str(content_type).ok()?, body))
}

fn blocked_page(url: &str, rule: &str) -> Vec<u8> {
    fn escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Blocked</title>\n\
         <body style=\"font:16px system-ui;margin:3em;color:#444\">\n\
         <h2>Blocked by mitmproxy adblock</h2>\n\
         <p><code>{}</code></p><p>Filter: <code>{}</code></p></body>",
        escape(url),
        escape(rule),
    )
    .into_bytes()
}
