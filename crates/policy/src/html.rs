use std::collections::HashSet;
use std::ops::Range;
use std::sync::LazyLock;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::header::{CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY};
use http::{HeaderMap, HeaderValue};
use regex::{Captures, Regex};
use sha2::{Digest, Sha256};

static CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)[\t\n\f\r ]class[\t\n\f\r ]*=[\t\n\f\r ]*(?:"([^"]*)"|'([^']*)'|([^\t\n\f\r >]+))"#,
    )
    .unwrap()
});
static ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)[\t\n\f\r ]id[\t\n\f\r ]*=[\t\n\f\r ]*(?:"([^"]*)"|'([^']*)'|([^\t\n\f\r >]+))"#,
    )
    .unwrap()
});
static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([^\t\n\f\r /=<>'"]+)(?:[\t\n\f\r ]*=[\t\n\f\r ]*(?:"([^"]*)"|'([^']*)'|([^\t\n\f\r >]+)))?"#).unwrap()
});
static INLINE_SOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\A'(?:nonce-|sha(?:256|384|512)-)[a-z0-9+/_-]+=*'\z").unwrap()
});

pub(crate) fn selector_tokens(html: &str) -> (Vec<String>, Vec<String>) {
    let mut classes = HashSet::new();
    let mut ids = HashSet::new();
    for captures in CLASS.captures_iter(html) {
        let value = html_escape::decode_html_entities(capture_value(&captures, 1));
        classes.extend(
            value
                .split(is_html_space)
                .filter(|token| !token.is_empty())
                .map(str::to_owned),
        );
    }
    for captures in ID.captures_iter(html) {
        let value = html_escape::decode_html_entities(capture_value(&captures, 1));
        if !value.is_empty() {
            ids.insert(value.into_owned());
        }
    }
    (classes.into_iter().collect(), ids.into_iter().collect())
}

fn capture_value<'a>(captures: &Captures<'a>, start: usize) -> &'a str {
    (start..start + 3)
        .find_map(|index| captures.get(index).map(|value| value.as_str()))
        .unwrap_or_default()
}

fn is_html_space(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\x0c' | '\r' | ' ')
}

#[derive(Default)]
pub(crate) struct DocumentHead {
    pub(crate) position: Option<usize>,
    pub(crate) meta_policy: bool,
    pub(crate) smart_apps: Vec<Range<usize>>,
}

impl DocumentHead {
    /// Scan the head for edit positions while retaining the original HTML.
    pub(crate) fn scan(html: &str) -> Option<Self> {
        let mut head = Self::default();
        let mut cursor = 0;
        let mut templates = 0usize;
        let mut raw_tag: Option<String> = None;
        while let Some(relative) = html[cursor..].find('<') {
            let start = cursor + relative;
            cursor = start + 1;
            let after_open = &html[cursor..];

            if let Some(raw) = raw_tag.as_deref() {
                if let Some(end_tag) = after_open.strip_prefix('/') {
                    let end_tag = end_tag.trim_start_matches(is_html_space);
                    if tag_name(end_tag).eq_ignore_ascii_case(raw) {
                        cursor = start + html[start..].find('>')? + 1;
                        raw_tag = None;
                    }
                }
                continue;
            }

            if let Some(comment) = after_open.strip_prefix("!--") {
                cursor = html.len() - comment.len() + comment.find("-->")? + 3;
                continue;
            }
            if after_open.starts_with(['!', '?']) {
                cursor = tag_end(html, cursor + 1)?;
                continue;
            }

            let closing = after_open.starts_with('/');
            let tag = after_open.strip_prefix('/').unwrap_or(after_open);
            let tag = if closing {
                tag.trim_start_matches(is_html_space)
            } else {
                tag
            };
            if !tag.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) {
                continue;
            }
            let name = tag_name(tag);
            let attributes_start = html.len() - tag.len() + name.len();
            cursor = tag_end(html, attributes_start)?;
            let raw_attributes = &html[attributes_start..cursor - 1];
            let self_closing = !closing && raw_attributes.ends_with('/');
            let name = name.to_ascii_lowercase();

            if closing {
                if name == "template" && templates > 0 {
                    templates -= 1;
                }
                if name == "head" && templates == 0 {
                    head.position = Some(start);
                    break;
                }
                continue;
            }
            if !self_closing {
                if name == "template" {
                    templates += 1;
                }
                if matches!(
                    name.as_str(),
                    "title" | "noscript" | "noframes" | "script" | "style"
                ) {
                    raw_tag = Some(name.clone());
                }
            }
            if templates > 0 {
                continue;
            }

            match name.as_str() {
                "meta" => head.meta(raw_attributes, start..cursor),
                "head" => {
                    head.position = Some(if self_closing { start } else { cursor });
                    if self_closing {
                        break;
                    }
                }
                "html" | "base" | "basefont" | "bgsound" | "link" | "title" | "noscript"
                | "noframes" | "script" | "style" | "template" => {}
                _ => {
                    head.position = Some(start);
                    break;
                }
            }
        }
        Some(head)
    }

    fn meta(&mut self, attributes: &str, range: Range<usize>) {
        let mut name = None;
        let mut http_equiv = None;
        for captures in ATTRIBUTE.captures_iter(attributes) {
            let attribute = &captures[1];
            if name.is_none() && attribute.eq_ignore_ascii_case("name") {
                name = Some(capture_value(&captures, 2));
            } else if http_equiv.is_none() && attribute.eq_ignore_ascii_case("http-equiv") {
                http_equiv = Some(capture_value(&captures, 2));
            }
        }
        if let Some(equiv) = http_equiv {
            let value = html_escape::decode_html_entities(equiv);
            self.meta_policy |= value.trim().eq_ignore_ascii_case("content-security-policy");
        } else if name.is_some_and(|name| {
            html_escape::decode_html_entities(name)
                .trim()
                .eq_ignore_ascii_case("apple-itunes-app")
        }) {
            self.smart_apps.push(range);
        }
    }
}

fn tag_name(tag: &str) -> &str {
    tag.split(|ch| is_html_space(ch) || ch == '/' || ch == '>')
        .next()
        .unwrap_or_default()
}

fn tag_end(html: &str, start: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, ch) in html.as_bytes()[start..].iter().copied().enumerate() {
        match quote {
            Some(active) if active == ch => quote = None,
            Some(_) => {}
            None if matches!(ch, b'\'' | b'"') => quote = Some(ch),
            None if ch == b'>' => return Some(start + offset + 1),
            None => {}
        }
    }
    None
}

pub(crate) fn authorize_stylesheet(headers: &mut HeaderMap, css: &str) {
    let hash = STANDARD.encode(Sha256::digest(css.as_bytes()));
    let source = format!("'sha256-{hash}'");
    for key in [CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY] {
        let values: Vec<_> = headers
            .get_all(&key)
            .iter()
            .map(|original| {
                std::str::from_utf8(original.as_bytes())
                    .ok()
                    .and_then(|value| {
                        let updated = value
                            .split(',')
                            .map(|policy| authorize_style(policy, &source))
                            .collect::<Vec<_>>()
                            .join(",");
                        let mut updated = HeaderValue::from_str(&updated).ok()?;
                        updated.set_sensitive(original.is_sensitive());
                        Some(updated)
                    })
                    .unwrap_or_else(|| original.clone())
            })
            .collect();
        if !values.is_empty() {
            headers.remove(&key);
            for value in values {
                headers.append(key.clone(), value);
            }
        }
    }
}

fn authorize_style(policy: &str, source: &str) -> String {
    let mut directives: Vec<_> = policy.split(';').map(str::to_owned).collect();
    let first = |name: &str| {
        directives.iter().position(|directive| {
            directive
                .split_whitespace()
                .next()
                .is_some_and(|token| token.eq_ignore_ascii_case(name))
        })
    };

    // Style elements fall back through style-src and then default-src.
    let Some((name, index)) = ["style-src-elem", "style-src", "default-src"]
        .into_iter()
        .find_map(|name| first(name).map(|index| (name, index)))
    else {
        return policy.to_owned();
    };
    let sources: Vec<_> = directives[index].split_whitespace().skip(1).collect();
    let unsafe_inline = sources
        .iter()
        .any(|token| token.eq_ignore_ascii_case("'unsafe-inline'"));
    if (unsafe_inline && !sources.iter().any(|token| INLINE_SOURCE.is_match(token)))
        || sources.contains(&source)
    {
        return policy.to_owned();
    }
    let authorized = sources
        .iter()
        .copied()
        .filter(|token| !token.eq_ignore_ascii_case("'none'"))
        .chain([source])
        .collect::<Vec<_>>()
        .join(" ");

    if name == "default-src" {
        return format!(
            "{}; style-src-elem {authorized}",
            policy.trim_end_matches([';', ' '])
        );
    }
    // Some clients still use style-src for elements. Preserve the style
    // attribute fallback for clients that support the separate directive.
    if name == "style-src" && first("style-src-attr").is_none() {
        let original = sources.join(" ");
        directives.push(if original.is_empty() {
            " style-src-attr".to_owned()
        } else {
            format!(" style-src-attr {original}")
        });
    }
    let directive = &mut directives[index];
    let leading = directive.len() - directive.trim_start().len();
    directive.truncate(leading);
    directive.push_str(name);
    directive.push(' ');
    directive.push_str(&authorized);

    directives.join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_positions_ignore_comments_raw_text_and_templates() {
        let banner = r#"<meta content="app-id=123" name="Apple-iTunes-App" />"#;
        let html = format!(
            r#"<!doctype html><!-- <head> --><html><head data-prop=">">
<title>{banner}</title><script>const s = '{banner}';</script>
<template><meta http-equiv="content-security-policy" />{banner}</template>
{banner}<meta name="apple-itunes-app" http-equiv="refresh">
</head><body>{banner}</body>"#
        );
        let head = DocumentHead::scan(&html).unwrap();
        assert_eq!(head.position, html.find("</head>"));
        assert!(!head.meta_policy);
        assert_eq!(head.smart_apps.len(), 1);
        assert_eq!(&html[head.smart_apps[0].clone()], banner);
    }

    #[test]
    fn effective_style_fallbacks_are_preserved() {
        let source = "'sha256-example='";
        for (input, expected) in [
            ("script-src 'none'", "script-src 'none'"),
            ("style-src 'unsafe-inline'", "style-src 'unsafe-inline'"),
            (
                "default-src 'self'; script-src 'none'",
                "default-src 'self'; script-src 'none'; style-src-elem 'self' 'sha256-example='",
            ),
            (
                "style-src 'unsafe-inline' 'nonce-aa=';  script-src 'none'",
                "style-src 'unsafe-inline' 'nonce-aa=' 'sha256-example=';  script-src 'none'; style-src-attr 'unsafe-inline' 'nonce-aa='",
            ),
            (
                "style-src 'self'; style-src-elem 'none'; style-src-attr 'none'",
                "style-src 'self'; style-src-elem 'sha256-example='; style-src-attr 'none'",
            ),
            (
                "style-src-elem 'sha256-example='",
                "style-src-elem 'sha256-example='",
            ),
        ] {
            assert_eq!(authorize_style(input, source), expected, "{input}");
        }
    }
}
