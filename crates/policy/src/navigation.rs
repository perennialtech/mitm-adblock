use std::net::Ipv6Addr;

struct HttpUrl<'a> {
    scheme: &'static str,
    authority: &'a str,
    suffix: &'a str,
}

impl<'a> HttpUrl<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let (scheme, remainder) = value.split_once("://")?;
        let scheme = http_scheme(scheme)?;
        let (authority, suffix) = split_authority(remainder);
        (!authority.is_empty()).then_some(Self {
            scheme,
            authority,
            suffix,
        })
    }
}

fn http_scheme(value: &str) -> Option<&'static str> {
    match () {
        _ if value.eq_ignore_ascii_case("http") => Some("http"),
        _ if value.eq_ignore_ascii_case("https") => Some("https"),
        _ => None,
    }
}

fn split_authority(value: &str) -> (&str, &str) {
    value.split_at(value.find(['/', '?', '#']).unwrap_or(value.len()))
}

pub(crate) fn url_path(url: &str) -> &str {
    let suffix = HttpUrl::parse(url).map_or(url, |parts| parts.suffix);
    suffix.split(['?', '#']).next().unwrap_or_default()
}

fn host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.contains('@') {
        return None;
    }
    if let Some(literal) = authority.strip_prefix('[') {
        let (host, tail) = literal.split_once(']')?;
        let address = host.split_once('%').map_or(host, |(address, _)| address);
        let ipv_future = host.strip_prefix('v').is_some_and(|versioned| {
            versioned.split_once('.').is_some_and(|(version, name)| {
                !version.is_empty()
                    && version.bytes().all(|ch| ch.is_ascii_hexdigit())
                    && !name.is_empty()
            })
        });
        if address.parse::<Ipv6Addr>().is_err() && !ipv_future {
            return None;
        }
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':')?)
        };
        return Some((host, port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    (!host.is_empty() && !host.contains(['[', ']'])).then_some((host, port))
}

/// Canonicalize the authority while keeping the path and query byte-exact.
pub fn exact_url_key(value: &str) -> Option<String> {
    let sent_url = value.split('#').next()?;
    if sent_url
        .bytes()
        .any(|ch| ch <= b' ' || ch >= 0x7f || ch == b'\\')
    {
        return None;
    }
    let url = HttpUrl::parse(sent_url)?;
    let (host, port) = host_port(url.authority)?;
    let host = if let Some((address, zone)) = host.split_once('%') {
        format!("{}%{zone}", address.to_ascii_lowercase())
    } else {
        host.to_ascii_lowercase()
    };
    let default_port = if url.scheme == "https" { 443 } else { 80 };
    let mut key = format!("{}://", url.scheme);
    if url.authority.starts_with('[') {
        key.push('[');
        key.push_str(&host);
        key.push(']');
    } else {
        key.push_str(&host);
    }
    if let Some(port) = port.filter(|port| !port.is_empty()) {
        if !port.bytes().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        let port: u16 = port.parse().ok()?;
        if port != default_port {
            key.push(':');
            key.push_str(&port.to_string());
        }
    }
    if !url.suffix.starts_with('/') {
        key.push('/');
    }
    key.push_str(url.suffix);
    Some(key)
}

/// Resolve an HTTP navigation while preserving escaped characters and the query.
pub(crate) fn resolve(url: &str, location: &str) -> Option<String> {
    let base = HttpUrl::parse(url)?;
    let location = location.trim().replace(['\r', '\n', '\t'], "");
    let (scheme, location) = match location.split_once(':') {
        Some((scheme, remainder)) if valid_scheme(scheme) => (http_scheme(scheme)?, remainder),
        _ => (base.scheme, location.as_str()),
    };

    if let Some(network) = location.strip_prefix("//") {
        let (authority, suffix) = split_authority(network);
        if !authority.is_empty() {
            host_port(authority)?;
            return Some(format!("{scheme}://{authority}{suffix}"));
        }
    }
    if scheme != base.scheme {
        return None;
    }
    let location = location.strip_prefix("//").unwrap_or(location);
    host_port(base.authority)?;
    let (path, query, fragment) = split_suffix(location);
    let (base_path, base_query, base_fragment) = split_suffix(base.suffix);
    let mut target = format!("{scheme}://{}", base.authority);

    if path.is_empty() {
        target.push_str(base_path);
        let fragment = fragment.or_else(|| if query.is_none() { base_fragment } else { None });
        append_suffix(&mut target, query.or(base_query), fragment);
        return Some(target);
    }

    let absolute = path.starts_with('/');
    let mut segments = Vec::new();
    if !absolute {
        let directory = base_path
            .rsplit_once('/')
            .map_or("", |(directory, _)| directory);
        segments.extend(directory.split('/'));
    }
    segments.extend(path.split('/'));
    let mut resolved = Vec::new();
    let last = segments.len() - 1;
    for (index, segment) in segments.into_iter().enumerate() {
        match segment {
            ".." => {
                resolved.pop();
            }
            "." => {}
            "" if !absolute && index != 0 && index != last => {}
            _ => resolved.push(segment),
        }
    }
    if matches!(path.rsplit('/').next(), Some("." | "..")) {
        resolved.push("");
    }
    let resolved = resolved.join("/");
    if !resolved.starts_with('/') {
        target.push('/');
    }
    target.push_str(&resolved);
    append_suffix(&mut target, query, fragment);
    Some(target)
}

fn valid_scheme(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || b"+-.".contains(&ch))
}

fn split_suffix(value: &str) -> (&str, Option<&str>, Option<&str>) {
    let (sent, fragment) = value
        .split_once('#')
        .map_or((value, None), |(sent, fragment)| (sent, Some(fragment)));
    let (path, query) = sent
        .split_once('?')
        .map_or((sent, None), |(path, query)| (path, Some(query)));
    (path, query, fragment)
}

fn append_suffix(value: &mut String, query: Option<&str>, fragment: Option<&str>) {
    if let Some(query) = query {
        value.push('?');
        value.push_str(query);
    }
    if let Some(fragment) = fragment {
        value.push('#');
        value.push_str(fragment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_key_uses_exact_path_and_query() {
        for (input, expected) in [
            (
                "HTTPS://FILE.test:0443/A/%2f/../b?token=A&token=B#extra",
                Some("https://file.test/A/%2f/../b?token=A&token=B"),
            ),
            ("http://file.test:81?", Some("http://file.test:81/?")),
            (
                "https://[2001:0DB8:0000::1]:443",
                Some("https://[2001:0db8:0000::1]/"),
            ),
            ("https://user@file.test/file", None),
            ("https://file.test:99999/file", None),
            ("https://file.test:bad/file", None),
            ("https://file.test/my file", None),
            ("https://file.test/some\\file", None),
        ] {
            assert_eq!(exact_url_key(input).as_deref(), expected, "{input}");
        }
    }

    #[test]
    fn navigation_keeps_escaped_segments_and_raw_absolute_paths() {
        let base = "https://page.test/a//b?old";
        for (location, expected) in [
            (
                "../asset/./file?tag=A&tag=B",
                Some("https://page.test/asset/file?tag=A&tag=B"),
            ),
            (
                "https://other.test:443/a/%2e/../b?",
                Some("https://other.test:443/a/%2e/../b?"),
            ),
            ("//other.test/path", Some("https://other.test/path")),
            ("#section", Some("https://page.test/a//b?old#section")),
            ("?new", Some("https://page.test/a//b?new")),
            ("https://user@other.test/secret", None),
            ("about:blank", None),
        ] {
            assert_eq!(resolve(base, location).as_deref(), expected, "{location}");
        }
    }
}
