"""
mitmproxy ad-blocking addon, powered by Brave's adblock-rust engine.

Network blocking: every request is checked against ABP/uBO-syntax filter
lists (EasyList, EasyPrivacy, ...). Matches never leave your machine.
Cosmetic filtering: HTML pages get a <style> block that hides ad elements
(site-specific ##rules plus generic rules matched against the page's
classes/ids), with CSP nonces handled so the injection isn't blocked.

Install:
    pip install mitmproxy adblock

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
    adblock_log_blocked    true/false, log every blocked request
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

import adblock
from mitmproxy import ctx, http

log = logging.getLogger("adblock")

DEFAULT_LISTS = ",".join(
    [
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
        "https://big.oisd.nl/",
        str(Path(__file__).resolve().with_name("first-party.txt")),
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

CLASS_RE = re.compile(r"""\bclass\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
ID_RE = re.compile(r"""\bid\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
HEAD_RE = re.compile(r"<head\b[^>]*>", re.I)
HTML_RE = re.compile(r"<html\b[^>]*>", re.I)
FOLLOWABLE_REDIRECTS = {301, 302, 303, 307, 308}

BLOCKED_PAGE = """<!doctype html><meta charset="utf-8"><title>Blocked</title>
<body style="font:16px system-ui;margin:3em;color:#444">
<h2>Blocked by mitmproxy adblock</h2>
<p><code>{url}</code></p><p>Filter: <code>{filter}</code></p></body>"""


def _request_type(req: http.Request, url: str) -> str:
    h = req.headers
    if h.get("upgrade", "").lower() == "websocket":
        return "websocket"
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
    return req.headers.get("referer") or req.headers.get("origin") or url


def _attr_tokens(regex: re.Pattern, html: str, split: bool) -> set[str]:
    out: set[str] = set()
    for m in regex.finditer(html):
        val = m.group(1) or m.group(2) or m.group(3) or ""
        if split:
            out.update(val.split())
        elif val:
            out.add(val.strip())
    return out


def _patch_csp(value: str, nonce: str) -> str:
    """Allow our nonce'd <style>/<script> without loosening anything else.

    Only touches style-src / script-src (or default-src when those are absent)
    that lack 'unsafe-inline'. Adding a nonce to a directive that already has
    'unsafe-inline' would *disable* unsafe-inline and break the site, so those
    are left alone.
    """
    directives = [d.strip() for d in value.split(";") if d.strip()]
    names = [d.split()[0].lower() for d in directives]
    token = f"'nonce-{nonce}'"
    default = next((d for d in directives if d.split()[0].lower() == "default-src"), None)

    out = []
    for d in directives:
        name = d.split()[0].lower()
        if name in ("style-src", "script-src", "style-src-elem", "script-src-elem"):
            if "'unsafe-inline'" not in d and "'none'" not in d:
                d = f"{d} {token}"
            elif "'none'" in d:
                d = f"{name} {token}"
        out.append(d)

    # Directives that fall back to default-src need an explicit copy + nonce.
    if default and "'unsafe-inline'" not in default:
        base = " ".join(t for t in default.split()[1:] if t != "'none'")
        for want in ("style-src", "script-src"):
            if want not in names:
                out.append(f"{want} {base} {token}".replace("  ", " "))
    return "; ".join(out)


class AdBlock:
    def __init__(self) -> None:
        self.engine: adblock.Engine | None = None
        self.loaded_at = 0.0
        self._lock = threading.Lock()
        self._reloading = False
        self.stats = {"blocked": 0, "pages_injected": 0}

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
        loader.add_option("adblock_log_blocked", bool, False,
                          "Log every blocked request.")

    def configure(self, updated) -> None:
        if "adblock_lists" in updated or "adblock_cache_dir" in updated:
            self._build_engine()

    def request(self, flow: http.HTTPFlow) -> None:
        self._maybe_refresh()
        engine = self.engine
        if engine is None or flow.response is not None:
            return
        url = flow.request.pretty_url
        self._filter_url(flow, engine, url)

    def _filter_url(self, flow: http.HTTPFlow, engine: adblock.Engine,
                    url: str, redirect: bool = False) -> bool:
        try:
            rtype = _request_type(flow.request, url)
            res = engine.check_network_urls(url, _source_url(flow.request, url, rtype), rtype)
        except Exception as e:  # malformed URL etc.
            log.debug("check failed for %s: %s", url, e)
            return False
        if not res.matched:
            return False

        self.stats["blocked"] += 1
        if ctx.options.adblock_log_blocked:
            log.info("blocked [%s] %s  (%s)", rtype, url, res.filter)

        # $redirect= rules resolve to data: URLs when resources are loaded.
        if not redirect and res.redirect and res.redirect.startswith("data:"):
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
        if not ctx.options.adblock_cosmetic or resp.status_code != 200:
            return
        if "text/html" not in resp.headers.get("content-type", "").lower():
            return
        url = flow.request.pretty_url
        if _request_type(flow.request, url) not in ("document", "subdocument"):
            return

        try:
            html = resp.get_text(strict=False)
        except Exception:
            return
        if not html:
            return

        cos = engine.url_cosmetic_resources(url)
        selectors = set(cos.hide_selectors)
        if not cos.generichide:
            classes = list(_attr_tokens(CLASS_RE, html, split=True))
            ids = list(_attr_tokens(ID_RE, html, split=False))
            selectors.update(engine.hidden_class_id_selectors(classes, ids, cos.exceptions))

        css_parts = []
        if selectors:
            # One rule per selector: a single invalid selector would otherwise
            # void the whole combined rule.
            css_parts.extend(f"{s}{{display:none!important}}" for s in sorted(selectors))
        for sel, styles in (cos.style_selectors or {}).items():
            css_parts.append(f"{sel}{{{';'.join(styles)}}}")
        script = cos.injected_script or ""
        if not css_parts and not script:
            return

        nonce = secrets.token_urlsafe(16)
        snippet = f'<style nonce="{nonce}" data-mitm-adblock>{"".join(css_parts)}</style>'
        if script.strip():
            snippet += (f'<script nonce="{nonce}" data-mitm-adblock>'
                        f"(function(){{try{{{script}}}catch(e){{}}}})();</script>")

        for key in ("content-security-policy", "content-security-policy-report-only"):
            values = resp.headers.get_all(key)
            if values:
                resp.headers.set_all(key, [_patch_csp(v, nonce) for v in values])

        m = HEAD_RE.search(html) or HTML_RE.search(html)
        html = html[: m.end()] + snippet + html[m.end():] if m else snippet + html
        resp.set_text(html)
        self.stats["pages_injected"] += 1

    def _filter_redirect(self, flow: http.HTTPFlow, engine: adblock.Engine) -> None:
        locations = flow.response.headers.get_all("location")
        if len(locations) != 1 or not locations[0].strip():
            return
        try:
            target = urllib.parse.urljoin(flow.request.pretty_url, locations[0].strip())
            parts = urllib.parse.urlsplit(target)
            if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username is not None:
                return
        except ValueError:
            return
        if self._filter_url(flow, engine, target, redirect=True):
            flow.metadata["adblock_redirect"] = True

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
        f = cache / (hashlib.sha1(src.encode()).hexdigest()[:16] + ".txt")
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

    def _build_engine(self, force: bool = False) -> None:
        try:
            cache = Path(os.path.expanduser(ctx.options.adblock_cache_dir))
            fs = adblock.FilterSet(debug=True)  # debug=True keeps rule text for logs
            n = 0
            for src in ctx.options.adblock_lists.split(","):
                text = self._fetch(src, cache, force)
                if text:
                    fs.add_filter_list(text, format="standard")
                    n += 1
            t0 = time.time()
            engine = adblock.Engine(filter_set=fs, optimize=True)
            with self._lock:
                self.engine = engine
                self.loaded_at = time.time()
            log.info("adblock engine ready: %d list(s), built in %.2fs", n, time.time() - t0)
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
