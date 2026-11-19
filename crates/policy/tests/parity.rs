use std::collections::{HashMap, HashSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderValue, StatusCode};
use mitm_adblock_policy::{BlockInfo, Policy};
use sha2::{Digest, Sha256};

fn policy(primary: &str, supplement: &str) -> Policy {
    let supplement = if supplement.is_empty() {
        Vec::new()
    } else {
        vec![supplement.to_owned()]
    };
    Policy::new(
        vec![primary.to_owned()],
        supplement,
        HashSet::new(),
        HashMap::new(),
    )
}

fn headers(values: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (key, value) in values {
        headers.append(*key, HeaderValue::from_static(value));
    }
    headers
}

#[test]
fn policy_is_shareable() {
    fn shareable<T: Send + Sync>() {}
    shareable::<Policy>();
}

#[test]
fn reports_the_blocking_rule_and_leaves_query_rewrites_alone() {
    let engine = policy(
        "||badware.test^$all\n||page.test^$removeparam=utm_source",
        "",
    );
    let document = headers(&[("sec-fetch-dest", "document")]);
    let response = engine
        .request("https://badware.test/?x=1&y=<data>", "GET", &document)
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response
            .extensions()
            .get::<BlockInfo>()
            .unwrap()
            .rule
            .as_deref(),
        Some("||badware.test^$all")
    );
    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("?x=1&amp;y=&lt;data&gt;"));
    assert!(body.contains("||badware.test^$all"));
    assert!(
        engine
            .request(
                "https://page.test/?utm_source=test&tag=1&tag=2&value=%2f",
                "GET",
                &document
            )
            .is_none()
    );
}

#[test]
fn supplements_preserve_primary_blocks_and_exceptions() {
    let engine = policy(
        "||ads.test/old.js\n@@||site.test/player.js",
        "@@||ads.test/old.js\n||ads.test/old.js$badfilter\n||site.test/player.js\n\
         ||site.test/ad-sdk/\n@@||site.test/ad-sdk/player.js",
    );
    let script = headers(&[("sec-fetch-dest", "script")]);
    for (url, blocked) in [
        ("https://ads.test/old.js", true),
        ("https://site.test/player.js", false),
        ("https://site.test/ad-sdk/prebid.js", true),
        ("https://site.test/ad-sdk/player.js", false),
    ] {
        assert_eq!(
            engine
                .request(url, "GET", &script)
                .map(|response| response.status()),
            blocked.then_some(StatusCode::NO_CONTENT),
            "{url}"
        );
    }
}

#[test]
fn fetch_metadata_and_ping_classification_preserve_request_context() {
    let engine = policy(
        "||target.test/third-party.js^$script,third-party\n\
         ||target.test/scoped.js^$script,domain=publisher.test\n\
         ||target.test/link^$ping,third-party",
        "",
    );
    let script = headers(&[
        ("sec-fetch-dest", "script"),
        ("sec-fetch-site", "cross-site"),
    ]);
    assert!(
        engine
            .request("https://target.test/third-party.js", "GET", &script)
            .is_some()
    );
    assert!(
        engine
            .request("https://target.test/scoped.js", "GET", &script)
            .is_none()
    );
    let script = headers(&[
        ("sec-fetch-dest", "script"),
        ("sec-fetch-site", "same-site"),
    ]);
    assert!(
        engine
            .request("https://target.test/third-party.js", "GET", &script)
            .is_none()
    );

    let mut ping = headers(&[
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-site", "cross-site"),
        ("content-type", "text/ping; charset=utf-8"),
        ("ping-to", "https://publisher.test/"),
    ]);
    assert!(
        engine
            .request("https://target.test/link", "POST", &ping)
            .is_some()
    );
    ping.insert("content-type", HeaderValue::from_static("application/json"));
    assert!(
        engine
            .request("https://target.test/link", "POST", &ping)
            .is_none()
    );
}

#[test]
fn exact_threat_matches_respect_expiry_and_primary_exceptions() {
    let engine = Policy::new(
        vec!["@@||allow.test^$document".to_owned()],
        Vec::new(),
        HashSet::from(["known.test".to_owned(), "allow.test".to_owned()]),
        HashMap::from([
            ("https://shared.test/File?token=A".to_owned(), i64::MAX),
            ("https://shared.test/expired".to_owned(), 1),
            ("https://allow.test/File".to_owned(), i64::MAX),
        ]),
    );
    let document = headers(&[("sec-fetch-dest", "document")]);
    for (url, rule) in [
        ("https://known.test.:8443/", Some("Exact threat hostname")),
        ("https://sub.known.test/", None),
        ("https://known.test@other.test/", None),
        ("https://allow.test/File", None),
        (
            "https://SHARED.test:443/File?token=A#ignored",
            Some("Exact threat payload URL"),
        ),
        ("https://shared.test/file?token=A", None),
        ("https://shared.test/File?token=a", None),
        ("https://shared.test/File?token=A&flag", None),
        ("https://shared.test:444/File?token=A", None),
        ("https://shared.test/expired", None),
    ] {
        let response = engine.request(url, "GET", &document);
        let matched = response.as_ref().and_then(|response| {
            response
                .extensions()
                .get::<BlockInfo>()
                .unwrap()
                .rule
                .as_deref()
        });
        assert_eq!(matched, rule, "{url}");
    }
}

#[test]
fn navigations_use_the_followup_method_and_original_request_type() {
    let engine = policy(
        "||page.test/landing^$document,method=get\n||target.test/asset.html^$script",
        "",
    );
    let document = headers(&[("sec-fetch-dest", "document")]);
    let location = headers(&[("location", "/landing")]);
    for (status, method, blocked) in [
        (StatusCode::MOVED_PERMANENTLY, "POST", true),
        (StatusCode::FOUND, "POST", true),
        (StatusCode::SEE_OTHER, "POST", true),
        (StatusCode::SEE_OTHER, "HEAD", false),
        (StatusCode::TEMPORARY_REDIRECT, "POST", false),
        (StatusCode::PERMANENT_REDIRECT, "POST", false),
        (StatusCode::NOT_MODIFIED, "GET", false),
    ] {
        let response = engine.redirect(
            "https://page.test/start",
            method,
            &document,
            status,
            &location,
        );
        assert_eq!(
            response.map(|response| response.status()),
            blocked.then_some(StatusCode::FORBIDDEN)
        );
    }
    let location = headers(&[("location", "https://target.test/asset.html")]);
    let response = engine.redirect(
        "https://page.test/original.js",
        "GET",
        &HeaderMap::new(),
        StatusCode::FOUND,
        &location,
    );
    assert_eq!(response.unwrap().status(), StatusCode::NO_CONTENT);
}

#[test]
fn evaluates_only_a_single_followable_refresh_on_html_documents() {
    let engine = policy(
        "||page.test/bounce^$document,method=get\n@@||page.test/continue^$document",
        "",
    );
    for (values, destination, disposition, blocked) in [
        (&["0; URL='/bounce'"][..], "document", "inline", true),
        (&["0; URL='/bounce'"], "empty", "inline", false),
        (&["0; URL='/bounce'"], "document", "attachment", false),
        (&["5"], "document", "inline", false),
        (&["0;url=/continue"], "document", "inline", false),
        (&["0;url=about:blank"], "document", "inline", false),
        (&["0;url=/bounce", "5"], "document", "inline", false),
    ] {
        let request = headers(&[("sec-fetch-dest", destination)]);
        let mut response = headers(&[
            ("content-type", "text/html"),
            ("content-disposition", disposition),
        ]);
        for value in values {
            response.append("refresh", HeaderValue::from_static(value));
        }
        let actual = engine.redirect(
            "https://page.test/start",
            "POST",
            &request,
            StatusCode::OK,
            &response,
        );
        assert_eq!(
            actual.map(|response| response.status()),
            blocked.then_some(StatusCode::FORBIDDEN)
        );
    }
}

#[test]
fn cosmetic_rules_respect_primary_exceptions_and_authorize_one_stylesheet() {
    let engine = policy(
        "##.generic-ad\n##.data-token\n##.keep\npage.test#@#.keep\npage.test##.sponsor\n\
         page.test##.layout:style(margin: 0 !important)",
        "page.test#@#.sponsor\npage.test##.keep\npage.test##.extra",
    );
    let request = headers(&[("sec-fetch-dest", "document")]);
    let mut response = headers(&[
        ("content-type", "text/html; charset=utf-8"),
        ("etag", "\"original\""),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self', style-src 'unsafe-inline'",
        ),
        (
            "content-security-policy",
            "style-src 'self'; style-src-elem 'none'; style-src-attr 'none'",
        ),
        ("content-security-policy-report-only", "style-src 'self'"),
    ]);
    let html = concat!(
        "<!doctype html><!-- <head> -->\n<html><head data-test=\"a>b\">",
        "<meta charset=\"utf-8\"></head><body data-class=\"data-token\">",
        "<p class=\"generic&#45;ad sponsor keep\">Publisher content</p></body></html>",
    );
    let css = concat!(
        ".extra{display:none!important}.generic-ad{display:none!important}",
        ".sponsor{display:none!important}.layout{margin: 0 !important}",
    );
    let output = engine
        .rewrite(
            "https://page.test/",
            "GET",
            &request,
            StatusCode::OK,
            &mut response,
            html,
            true,
            true,
        )
        .unwrap();
    assert_eq!(
        output,
        html.replace(
            "</head>",
            &format!("<style data-mitm-adblock>{css}</style></head>")
        )
    );
    let digest = format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(css.as_bytes()))
    );
    let policies: Vec<_> = response
        .get_all("content-security-policy")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(
        policies,
        [
            format!(
                "default-src 'none'; script-src 'self'; style-src-elem {digest}, style-src 'unsafe-inline'"
            ),
            format!("style-src 'self'; style-src-elem {digest}; style-src-attr 'none'"),
        ]
    );
    assert_eq!(
        response["content-security-policy-report-only"]
            .to_str()
            .unwrap(),
        format!("style-src 'self' {digest}; style-src-attr 'self'")
    );
    assert!(!response.contains_key("etag"));
}

#[test]
fn native_relational_selectors_remain_usable() {
    let engine = policy("page.test#?#div:-abp-has(> .ad-title)", "");
    let request = headers(&[("sec-fetch-dest", "document")]);
    let mut response = headers(&[("content-type", "text/html")]);
    let html = engine
        .rewrite(
            "https://page.test/",
            "GET",
            &request,
            StatusCode::OK,
            &mut response,
            "<html><head></head><body><div><span class=ad-title>Ad</span></div>",
            true,
            false,
        )
        .unwrap();
    assert!(
        regex::Regex::new(r"div:has\(>\s*\.ad-title\)\s*\{display:")
            .unwrap()
            .is_match(&html)
    );
    assert!(!html.contains(":-abp-has"));
}

#[test]
fn smart_app_removal_preserves_meta_policy_and_markup() {
    let engine = policy("page.test##.extra", "");
    let banner = r#"<meta content="app-id=300704847" name="Apple-iTunes-App" />"#;
    let html = format!(
        r#"<!doctype html><html><head><meta charset="utf-8">{banner}<meta http-equiv="Content-Security-Policy" content="style-src 'none'"></head><body>Publisher</body></html>"#
    );
    for (destination, enabled, extra, changed) in [
        ("document", true, None, true),
        ("iframe", true, None, false),
        ("document", false, None, false),
        (
            "document",
            true,
            Some(("cache-control", "private, no-transform")),
            false,
        ),
        (
            "document",
            true,
            Some(("content-disposition", "attachment; filename=page.html")),
            false,
        ),
    ] {
        let request = headers(&[("sec-fetch-dest", destination)]);
        let mut response = headers(&[
            ("content-type", "text/html"),
            ("content-digest", "original"),
        ]);
        if let Some((key, value)) = extra {
            response.insert(key, HeaderValue::from_static(value));
        }
        let output = engine.rewrite(
            "https://page.test/",
            "GET",
            &request,
            StatusCode::OK,
            &mut response,
            &html,
            true,
            enabled,
        );
        assert_eq!(output, changed.then(|| html.replace(banner, "")));
        assert_eq!(response.contains_key("content-digest"), !changed);
    }
}
