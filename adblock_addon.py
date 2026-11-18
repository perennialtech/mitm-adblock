"""
mitmproxy ad-blocking addon, powered by Brave's adblock-rust engine.

Network blocking: every request is checked against ABP/uBO-syntax filter
lists (EasyList, EasyPrivacy, ...). Matches never leave your machine.
Cosmetic filtering: HTML pages get a <style> block that hides ad elements
(site-specific ##rules plus generic rules matched against the page's
classes/ids). CSP authorizes the exact injected stylesheet where necessary.

Install:
    pip install -r requirements.txt ./engine

Run:
    mitmdump -s adblock_addon.py
    mitmdump -s adblock_addon.py --set adblock_lists="https://easylist.to/easylist/easylist.txt,~/my-rules.txt"

Then point your browser/OS proxy at 127.0.0.1:8080 and install the
mitmproxy CA from http://mitm.it (browse there *through* the proxy).

Options (set with --set name=value):
    adblock_lists          comma-separated URLs and/or local file paths
    adblock_cache_dir      where downloaded lists are cached
    adblock_update_hours   re-download lists after this many hours
    adblock_cosmetic       true/false, enable element hiding in HTML
    adblock_smart_app_banners   true/false, remove Safari Smart App Banner tags
    adblock_log_blocked    true/false, log every blocked request
"""

from __future__ import annotations

import base64
import hashlib
from html import unescape
from html.parser import HTMLParser
import logging
import os
import re
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from mitm_adblock_engine import Engine
from mitmproxy import ctx, http

from threatfox import MAX_AGE_SECONDS, ThreatFoxSnapshot, exact_url_key, fetch_snapshot, valid_domains

log = logging.getLogger("adblock")

ANNOYANCES = "https://secure.fanboy.co.nz/fanboy-annoyance.txt"
SUPPLEMENT_PREFIX = "supplement:"
ADGUARD_BASE = "https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt"
TIF_FULL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt"
TIF_MEDIUM = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt"

DEFAULT_LISTS = ",".join(
    [
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
        SUPPLEMENT_PREFIX + ADGUARD_BASE,
        ANNOYANCES,
        TIF_FULL,
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt",
        "https://big.oisd.nl/",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext",
        "https://ublockorigin.github.io/uAssets/filters/badware.txt",
        "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-online.txt",
    ]
)

# Sec-Fetch-Dest -> adblock-rust request type
DEST_TO_TYPE = {
    "document": "document",
    "iframe": "subdocument",
    "frame": "subdocument",
    "fencedframe": "subdocument",
    "image": "image",
    "script": "script",
    "worker": "script",
    "sharedworker": "script",
    "serviceworker": "script",
    "audioworklet": "script",
    "paintworklet": "script",
    "style": "stylesheet",
    "font": "font",
    "audio": "media",
    "video": "media",
    "track": "media",
    "object": "object",
    "embed": "object",
    "empty": "xmlhttprequest",  # fetch() / XHR / beacons
    "report": "ping",
    "manifest": "other",
}

EXT_TO_TYPE = {
    ".js": "script", ".mjs": "script",
    ".css": "stylesheet",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".webp": "image", ".avif": "image", ".svg": "image", ".ico": "image",
    ".woff": "font", ".woff2": "font", ".ttf": "font", ".otf": "font",
    ".mp4": "media", ".webm": "media", ".mp3": "media", ".m3u8": "media",
    ".html": "document", ".htm": "document",
}

# Match complete attribute names and split at HTML space characters only.
ATTR_SPACE = r"[\t\n\f\r ]"
ATTR_VALUE = r"""(?:"([^"]*)"|'([^']*)'|([^\t\n\f\r >]+))"""
CLASS_RE = re.compile(rf"{ATTR_SPACE}class{ATTR_SPACE}*={ATTR_SPACE}*{ATTR_VALUE}", re.I)
ID_RE = re.compile(rf"{ATTR_SPACE}id{ATTR_SPACE}*={ATTR_SPACE}*{ATTR_VALUE}", re.I)
HTML_SPACE = re.compile(ATTR_SPACE + "+")
INLINE_SOURCE = re.compile(r"'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_-]+=*'", re.I)
FOLLOWABLE_REDIRECTS = {301, 302, 303, 307, 308}
REFRESH_TARGET = re.compile(
    r"[ \t]*[0-9]+(?:\.[0-9]*)?[ \t]*[;,][ \t]*url[ \t]*=[ \t]*"
    r"""(?:"([^"]+)"|'([^']+)'|([^ \t"']+))[ \t]*""",
    re.IGNORECASE,
)

BLOCKED_PAGE = """<!doctype html><meta charset="utf-8"><title>Blocked</title>
<body style="font:16px system-ui;margin:3em;color:#444">
<h2>Blocked by mitmproxy adblock</h2>
<p><code>{url}</code></p><p>Filter: <code>{filter}</code></p></body>"""


def _request_type(req: http.Request, url: str) -> str:
    h = req.headers
    if h.get("upgrade", "").lower() == "websocket":
        return "websocket"
    # Hyperlink auditing uses an empty Fetch destination, just like an XHR.
    if (
        req.method == "POST"
        and h.get("content-type", "").partition(";")[0].strip().lower() == "text/ping"
        and h.get("ping-to")
    ):
        return "ping"
    dest = h.get("sec-fetch-dest", "").lower()
    if dest in DEST_TO_TYPE:
        return DEST_TO_TYPE[dest]
    # No fetch metadata (old browser, curl, apps): guess from path / Accept.
    ext = os.path.splitext(urllib.parse.urlsplit(url).path)[1].lower()
    if ext in EXT_TO_TYPE:
        return EXT_TO_TYPE[ext]
    accept = h.get("accept", "").lower()
    if accept.startswith("text/html"):
        return "document"
    if accept.startswith("image/"):
        return "image"
    if accept.startswith("text/css"):
        return "stylesheet"
    return "other"


def _source_url(req: http.Request, url: str, rtype: str) -> str:
    if rtype == "document":
        return url
    source = req.headers.get("referer") or req.headers.get("origin")
    if source:
        return source
    # Fetch Metadata can establish cross-site context without identifying the source.
    if req.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return ""
    return url


def _resolve_navigation(url: str, location: str) -> str | None:
    try:
        target = urllib.parse.urljoin(url, location.strip())
        parts = urllib.parse.urlsplit(target)
        if parts.scheme in {"http", "https"} and parts.hostname and parts.username is None:
            return target
    except ValueError:
        pass
    return None


def _cached_list(cache: Path, source: str) -> Path:
    return cache / (hashlib.sha1(source.encode()).hexdigest()[:16] + ".txt")


def _attr_tokens(regex: re.Pattern, html: str, split: bool) -> set[str]:
    out: set[str] = set()
    for m in regex.finditer(html):
        val = unescape(m.group(1) or m.group(2) or m.group(3) or "")
        if split:
            out.update(token for token in HTML_SPACE.split(val) if token)
        elif val:
            out.add(val)
    return out


def _authorize_style(policy: str, source: str) -> str:
    """Allow one stylesheet while preserving script and style-attribute policy."""
    directives = policy.split(";")
    first = {}
    for index, directive in enumerate(directives):
        if tokens := directive.split():
            first.setdefault(tokens[0].lower(), (index, tokens[1:]))

    # Inline style elements fall back through style-src and default-src.
    name = next((name for name in ("style-src-elem", "style-src", "default-src")
                 if name in first), None)
    if name is None:
        return policy
    index, sources = first[name]
    if "'unsafe-inline'" in (token.lower() for token in sources) and not any(INLINE_SOURCE.fullmatch(token) for token in sources):
        return policy
    if source in sources:
        return policy

    sources = [token for token in sources if token.lower() != "'none'"] + [source]
    if name == "default-src":
        # A new element-specific directive keeps the fallback for style attributes.
        return policy.rstrip("; ") + "; style-src-elem " + " ".join(sources)
    if name == "style-src":
        # Older clients use style-src. Pin the existing style attribute fallback
        # explicitly so that new clients do not inherit the new hash for attributes.
        if "style-src-attr" not in first:
            original = " ".join(first[name][1])
            directives.append(" style-src-attr" + (f" {original}" if original else ""))
    leading = directives[index][:len(directives[index]) - len(directives[index].lstrip())]
    directives[index] = leading + name + " " + " ".join(sources)
    return ";".join(directives)


class _HeadDone(Exception):
    pass


class _DocumentHead(HTMLParser):
    HEAD_CONTENT = {"html", "base", "basefont", "bgsound", "link", "meta", "title",
                    "noscript", "noframes", "script", "style", "template"}
    RAW_CONTENT = {"title", "noscript", "noframes"}

    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.text = text
        self.position = None
        self.meta_policy = False
        self.smart_apps = []
        self.template_depth = 0
        self.raw_tag = None

    def _offset(self) -> int:
        line, column = self.getpos()
        start = 0
        for _ in range(line - 1):
            start = self.text.index("\n", start) + 1
        return start + column

    def handle_starttag(self, tag, attrs):
        if self.raw_tag is not None:
            return
        if tag in self.RAW_CONTENT:
            self.raw_tag = tag
        if tag == "template":
            self.template_depth += 1
        if self.template_depth:
            return
        if tag == "meta":
            attributes = dict(reversed(attrs))
            name = (attributes.get("name") or "").strip().lower()
            if name == "apple-itunes-app" and "http-equiv" not in attributes:
                start = self._offset()
                self.smart_apps.append((start, start + len(self.get_starttag_text())))
            self.meta_policy |= (
                (attributes.get("http-equiv") or "").strip().lower() == "content-security-policy"
            )
        elif tag == "head":
            self.position = self._offset() + len(self.get_starttag_text())
        elif tag not in self.HEAD_CONTENT:
            self.position = self._offset()
            raise _HeadDone

    def handle_endtag(self, tag):
        if self.raw_tag is not None:
            if tag == self.raw_tag:
                self.raw_tag = None
            return
        if tag == "template" and self.template_depth:
            self.template_depth -= 1
        if tag == "head" and not self.template_depth:
            self.position = self._offset()
            raise _HeadDone


def _document_head(html: str) -> _DocumentHead | None:
    head = _DocumentHead(html)
    try:
        head.feed(html)
    except _HeadDone:
        pass
    except (AssertionError, ValueError):
        return None
    return head


class FilterEngine:
    def __init__(self, compiled: Engine, payload_urls: dict[str, int],
                 supplement: Engine | None = None) -> None:
        self.compiled = compiled
        self.payload_urls = payload_urls
        self.supplement = supplement

    def matches_payload_url(self, url: str) -> bool:
        if not self.payload_urls:
            return False
        expiry = self.payload_urls.get(exact_url_key(url), 0)
        return expiry > 0 and expiry > time.time()

    def check_network_urls(self, url: str, source_url: str, rtype: str, method: str):
        primary = self.compiled.check_network_urls(
            url, source_url, rtype, method, self.matches_payload_url(url),
            check_exceptions=self.supplement is not None,
        )
        if self.supplement is None or primary.matched or primary.excepted:
            return primary
        return self.supplement.check_network_urls(url, source_url, rtype, method)


class AdBlock:
    def __init__(self) -> None:
        self.engine: FilterEngine | None = None
        self.loaded_at = 0.0
        self._lock = threading.Lock()
        self._reloading = False
        self.stats = {"blocked": 0, "pages_injected": 0, "app_banners_removed": 0}

    # ---- mitmproxy hooks -------------------------------------------------

    def load(self, loader) -> None:
        loader.add_option("adblock_lists", str, DEFAULT_LISTS,
                          "Comma-separated filter list URLs or local paths.")
        loader.add_option("adblock_cache_dir", str,
                          str(Path.home() / ".cache" / "mitm-adblock"),
                          "Directory for cached filter lists.")
        loader.add_option("adblock_update_hours", int, 24,
                          "Re-download remote lists after this many hours.")
        loader.add_option("adblock_cosmetic", bool, True,
                          "Inject element-hiding CSS into HTML pages.")
        loader.add_option("adblock_smart_app_banners", bool, True,
                          "Remove Safari Smart App Banner metadata from top-level HTML.")
        loader.add_option("adblock_log_blocked", bool, False,
                          "Log every blocked request.")
        loader.add_option("adblock_threatfox_key_file", str,
                          os.environ.get("ADBLOCK_THREATFOX_KEY_FILE", ""),
                          "File containing the ThreatFox auth key for domain and payload URL blocking.")
        loader.add_option("adblock_threat_domains_file", str, "",
                          "Local file containing additional exact threat hostnames, one per line.")

    def configure(self, updated) -> None:
        if {
            "adblock_lists", "adblock_cache_dir", "adblock_threatfox_key_file", "adblock_threat_domains_file",
        } & set(updated):
            self._build_engine()

    def request(self, flow: http.HTTPFlow) -> None:
        self._maybe_refresh()
        engine = self.engine
        if engine is None or flow.response is not None:
            return
        url = flow.request.pretty_url
        self._filter_url(flow, engine, url)

    def _filter_url(self, flow: http.HTTPFlow, engine: FilterEngine,
                    url: str, redirect_method: str | None = None) -> bool:
        try:
            rtype = _request_type(flow.request, flow.request.pretty_url)
            if redirect_method is not None and rtype == "other":
                # Redirects preserve the request destination. Use the target extension
                # only when we could not infer a more specific type from the request.
                rtype = _request_type(flow.request, url)
            res = engine.check_network_urls(
                url, _source_url(flow.request, url, rtype), rtype, redirect_method or flow.request.method,
            )
        except Exception as e:  # malformed URL etc.
            log.debug("check failed for %s: %s", url, e)
            return False
        if not res.matched:
            return False

        self.stats["blocked"] += 1
        if ctx.options.adblock_log_blocked:
            log.info("blocked [%s] %s  (%s)", rtype, url, res.filter)

        # $redirect= rules resolve to data: URLs when resources are loaded.
        if redirect_method is None and res.redirect and res.redirect.startswith("data:"):
            ctype, body = self._decode_data_url(res.redirect)
            flow.response = http.Response.make(200, body, {"content-type": ctype})
        elif rtype in ("document", "subdocument"):
            page = BLOCKED_PAGE.format(url=_esc(url), filter=_esc(res.filter or ""))
            flow.response = http.Response.make(
                403, page.encode(), {"content-type": "text/html; charset=utf-8",
                                     "cache-control": "no-store"})
        else:
            # Empty success: fewer console errors than a hard failure.
            flow.response = http.Response.make(204, b"", {"cache-control": "no-store"})
        flow.metadata["adblock"] = res.filter
        return True

    def response(self, flow: http.HTTPFlow) -> None:
        engine = self.engine
        if engine is None or "adblock" in flow.metadata or flow.response is None:
            return
        resp = flow.response
        if resp.status_code in FOLLOWABLE_REDIRECTS:
            self._filter_redirect(flow, engine)
            return
        if resp.status_code != 200:
            return
        mime = resp.headers.get("content-type", "").partition(";")[0].strip().lower()
        disposition = resp.headers.get("content-disposition", "").partition(";")[0].strip().lower()
        if mime != "text/html" or disposition == "attachment":
            return
        url = flow.request.pretty_url
        request_type = _request_type(flow.request, url)
        if request_type not in ("document", "subdocument") or self._filter_refresh(flow, engine):
            return
        smart_banners = ctx.options.adblock_smart_app_banners and request_type == "document"
        if not (smart_banners or ctx.options.adblock_cosmetic):
            return
        if any(directive.strip().lower() == "no-transform"
               for directive in resp.headers.get("cache-control", "").split(",")):
            return

        try:
            html = resp.get_text(strict=False)
        except (ValueError, UnicodeError):
            return
        if not html or (head := _document_head(html)) is None:
            return
        # Authorize CSS only through HTTP headers, leaving HTML meta policies intact.
        css = ""
        if ctx.options.adblock_cosmetic and not head.meta_policy and head.position is not None:
            css = self._stylesheet(engine, url, html)
        banners = head.smart_apps if smart_banners else []
        if not (css or banners):
            return

        edits = [(start, end, "") for start, end in banners]
        if css:
            snippet = f"<style data-mitm-adblock>{css}</style>"
            edits.append((head.position, head.position, snippet))
        for start, end, replacement in sorted(edits, reverse=True):
            html = html[:start] + replacement + html[end:]
        resp.set_text(html)
        if css:
            source = "'sha256-" + base64.b64encode(hashlib.sha256(css.encode()).digest()).decode("ascii") + "'"
            for key in ("content-security-policy", "content-security-policy-report-only"):
                values = resp.headers.get_all(key)
                if values:
                    resp.headers.set_all(key, [
                        ",".join(_authorize_style(policy, source) for policy in value.split(","))
                        for value in values
                    ])
            self.stats["pages_injected"] += 1
        self.stats["app_banners_removed"] += len(banners)
        # The origin's validators and digests no longer describe the body.
        for header in ("etag", "content-md5", "digest", "repr-digest", "content-digest"):
            if header in resp.headers:
                del resp.headers[header]

    @staticmethod
    def _stylesheet(engine: FilterEngine, url: str, html: str) -> str:
        primary = engine.compiled.url_cosmetic_resources(url)
        selectors = set(primary.hide_selectors)
        styles = list(primary.style_rules)
        supplement = engine.supplement
        extra = supplement.url_cosmetic_resources(url) if supplement is not None else None
        if extra is not None:
            selectors.update(extra.hide_selectors - primary.exceptions)
            styles.extend(rule for rule in extra.style_rules if rule[0] not in primary.exceptions)
        if not primary.generichide:
            classes = list(_attr_tokens(CLASS_RE, html, split=True))
            ids = list(_attr_tokens(ID_RE, html, split=False))
            selectors.update(engine.compiled.hidden_class_id_selectors(classes, ids, primary.exceptions))
            if extra is not None and not extra.generichide:
                selectors.update(supplement.hidden_class_id_selectors(classes, ids, extra.exceptions | primary.exceptions))

        css_parts = []
        if selectors:
            # One rule per selector: a single invalid selector would otherwise
            # void the whole combined rule.
            css_parts.extend(f"{s}{{display:none!important}}" for s in sorted(selectors))
        for selector, style in dict.fromkeys(styles):
            css_parts.append(f"{selector}{{{style}}}")
        # CSS from subscriptions is embedded in an HTML raw-text element.
        # A literal closing tag must never become active HTML.
        css = "".join(part for part in css_parts if "</style" not in part.lower())
        return css.replace("\r\n", "\n").replace("\r", "\n")

    def _filter_redirect(self, flow: http.HTTPFlow, engine: FilterEngine) -> None:
        locations = flow.response.headers.get_all("location")
        if len(locations) != 1 or not locations[0].strip():
            return
        target = _resolve_navigation(flow.request.pretty_url, locations[0])
        if target is None:
            return
        status = flow.response.status_code
        method = flow.request.method
        if (status == 303 and method != "HEAD") or (status in {301, 302} and method == "POST"):
            method = "GET"
        if self._filter_url(flow, engine, target, redirect_method=method):
            flow.metadata["adblock_redirect"] = True

    def _filter_refresh(self, flow: http.HTTPFlow, engine: FilterEngine) -> bool:
        values = flow.response.headers.get_all("refresh")
        if len(values) != 1:
            return False
        match = REFRESH_TARGET.fullmatch(values[0])
        if not match:
            return False
        location = next(value for value in match.groups() if value is not None)
        target = _resolve_navigation(flow.request.pretty_url, location)
        if target is not None and self._filter_url(flow, engine, target, redirect_method="GET"):
            flow.metadata["adblock_refresh"] = True
            return True
        return False

    def done(self) -> None:
        log.info("adblock stats: %s", self.stats)

    # ---- filter list management -----------------------------------------

    def _maybe_refresh(self) -> None:
        hours = ctx.options.adblock_update_hours
        if hours <= 0 or self._reloading:
            return
        if time.time() - self.loaded_at > hours * 3600:
            self._reloading = True
            threading.Thread(target=self._build_engine, kwargs={"force": True},
                             daemon=True).start()

    def _fetch(self, src: str, cache: Path, force: bool) -> str | None:
        src = src.strip()
        if not src:
            return None
        if not re.match(r"^https?://", src):
            p = Path(os.path.expanduser(src))
            return p.read_text(encoding="utf-8", errors="replace") if p.exists() else None

        cache.mkdir(parents=True, exist_ok=True)
        f = _cached_list(cache, src)
        max_age = ctx.options.adblock_update_hours * 3600
        fresh = f.exists() and (time.time() - f.stat().st_mtime) < max_age
        if fresh and not force:
            return f.read_text(encoding="utf-8", errors="replace")
        try:
            r = urllib.request.Request(src, headers={"User-Agent": "mitm-adblock/1.0"})
            with urllib.request.urlopen(r, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            f.write_text(text, encoding="utf-8")
            log.info("downloaded %s (%d lines)", src, text.count("\n"))
            return text
        except Exception as e:
            if f.exists():
                log.warning("download failed for %s (%s); using cached copy", src, e)
                return f.read_text(encoding="utf-8", errors="replace")
            log.error("download failed for %s: %s", src, e)
            return None

    def _threatfox(self, cache: Path, force: bool) -> ThreatFoxSnapshot:
        key_file = ctx.options.adblock_threatfox_key_file
        if not key_file:
            return ThreatFoxSnapshot()
        cached = cache / "threatfox.json"
        fallback = ThreatFoxSnapshot()
        try:
            age = time.time() - cached.stat().st_mtime
            if age <= MAX_AGE_SECONDS:
                with cached.open(encoding="ascii") as file:
                    fallback = ThreatFoxSnapshot.read(file)
                if not force and age < ctx.options.adblock_update_hours * 3600 and fallback.domains:
                    return fallback
        except (OSError, ValueError, KeyError, TypeError):
            pass

        if not fallback.domains:
            legacy = cache / "threatfox-domains.txt"
            try:
                if time.time() - legacy.stat().st_mtime <= MAX_AGE_SECONDS:
                    fallback = ThreatFoxSnapshot(valid_domains(legacy.read_text(encoding="ascii").splitlines()))
            except (OSError, UnicodeError):
                pass

        try:
            snapshot = fetch_snapshot(Path(key_file).expanduser())
        except Exception as error:
            # Error text from a server or HTTP client might include the key-bearing URL.
            log.warning("ThreatFox refresh failed (%s)%s", type(error).__name__,
                        "; using cached indicators" if fallback.domains else "")
            return fallback

        temp_path = None
        try:
            cache.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=cache, mode="w", encoding="ascii", delete=False) as file:
                temp_path = Path(file.name)
                snapshot.write(file)
            temp_path.replace(cached)
        except OSError as error:
            log.warning("Could not cache ThreatFox (%s)", type(error).__name__)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        log.info("downloaded ThreatFox (%d exact domains, %d exact payload URLs)",
                 len(snapshot.domains), len(snapshot.payload_urls))
        return snapshot

    def _build_engine(self, force: bool = False) -> None:
        try:
            cache = Path(os.path.expanduser(ctx.options.adblock_cache_dir))
            lists = []
            supplements = []
            for src in ctx.options.adblock_lists.split(","):
                src = src.strip()
                supplemental = src.startswith(SUPPLEMENT_PREFIX)
                src = src.removeprefix(SUPPLEMENT_PREFIX).strip()
                text = self._fetch(src, cache, force)
                if not text and src.strip() == TIF_FULL:
                    previous = _cached_list(cache, TIF_MEDIUM)
                    if previous.is_file():
                        text = previous.read_text(encoding="utf-8", errors="replace")
                        if text:
                            log.warning("TIF Full unavailable; using the previous TIF Medium cache")
                if text:
                    (supplements if supplemental else lists).append(text)
            threatfox = self._threatfox(cache, force)
            domains = threatfox.domains
            local_domains = ctx.options.adblock_threat_domains_file
            if local_domains:
                try:
                    with Path(local_domains).expanduser().open(encoding="ascii") as stream:
                        domains.update(valid_domains(stream))
                except (OSError, UnicodeError) as error:
                    log.warning("Could not read local threat domains (%s)", type(error).__name__)
            t0 = time.time()
            supplement = Engine(supplements) if supplements else None
            engine = FilterEngine(Engine(lists, domains), threatfox.payload_urls, supplement)
            with self._lock:
                self.engine = engine
                self.loaded_at = time.time()
            log.info("adblock engine ready: %d list(s), %d supplements, %d exact threat domains, "
                     "%d exact payload URLs, built in %.2fs",
                     len(lists), len(supplements), len(domains), len(threatfox.payload_urls), time.time() - t0)
        finally:
            self._reloading = False

    @staticmethod
    def _decode_data_url(url: str) -> tuple[str, bytes]:
        header, _, data = url[5:].partition(",")
        is_b64 = header.endswith(";base64")
        ctype = header[:-7] if is_b64 else header
        body = base64.b64decode(data) if is_b64 else urllib.parse.unquote_to_bytes(data)
        return ctype or "text/plain", body


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


addons = [AdBlock()]
