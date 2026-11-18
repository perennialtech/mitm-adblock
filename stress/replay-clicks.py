"""Replay archived browser clicks with the production HTTP addon or an unfiltered baseline."""

from collections import Counter
import json
import logging
import os
import signal
import socket
import sys
import time
from urllib.parse import urlsplit

from mitmproxy import connection, http
from playwright.sync_api import Error as BrowserError, sync_playwright

sys.path.insert(0, "/replay")
from replay import INPUT, CorpusError, digest, har_flow, make_addon

MAX_CASES = 8
MAX_REPEATED_CASES = 24
WAIT_MS = 2_000
ACTION_TIMEOUT_MS = 7_500
STRIPPED_HEADERS = {
    "connection", "content-encoding", "content-length", "keep-alive", "proxy-authenticate",
    "set-cookie", "transfer-encoding", "upgrade", "clear-site-data", "alt-svc",
    "report-to", "reporting-endpoints", "nel",
}


def url_key(value):
    if not isinstance(value, str) or not 0 < len(value) <= 16384:
        raise CorpusError("Invalid URL in click replay.")
    url = urlsplit(value)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None:
        raise CorpusError("Click replay requires HTTP(S) URLs without embedded credentials.")
    return url._replace(path=url.path or "/", fragment="").geturl()


def index_capture(har):
    entries = json.loads(har.read_bytes())["log"]["entries"]
    if not isinstance(entries, list) or not 0 < len(entries) <= 10_000:
        raise CorpusError("Each browser HAR needs 1–10,000 recorded requests.")
    archive = {}
    recorded_urls = set()
    for entry in entries:
        request = entry["request"]
        method = request["method"]
        if method not in {"GET", "HEAD"} or not request["url"].startswith(("https://", "http://")):
            continue
        key = (method, url_key(request["url"]))
        if method == "GET":
            recorded_urls.add(key[1])
        response = entry["response"]
        if not 200 <= response["status"] < 600 or response["status"] == 304:
            continue
        if key in archive and (archive[key] is None or archive[key]["response"] != response):
            # Leave ambiguous exchanges unavailable. Unused duplicates need not
            # invalidate an otherwise reproducible click.
            archive[key] = None
        else:
            archive[key] = entry
    return archive, recorded_urls


def click_cases(har):
    manifest = har.with_suffix(".clicks.json")
    cases = json.loads(manifest.read_bytes())
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise CorpusError("A click sidecar needs 1–8 cases.")
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "expect", "start_url", "click", "opener_selector", "opener_url", "popup_url"
        } or case["expect"] not in ("allow", "block"):
            raise CorpusError("Invalid click sidecar fields or expectation.")
        for key in ("start_url", "opener_url", "popup_url"):
            case[key] = url_key(case[key])
        if case["popup_url"] in {case["start_url"], case["opener_url"]}:
            raise CorpusError("The popup target must differ from the opener.")
        if not all(isinstance(case[key], str) and 0 < len(case[key]) <= 512
                   for key in ("click", "opener_selector")):
            raise CorpusError("Click and opener CSS selectors must contain 1–512 characters.")
    return manifest, cases


def has_body(entry):
    return entry and "text" in entry["response"]["content"]


def archive_miss(entry, method):
    if not entry:
        return True
    status = entry["response"]["status"]
    return method == "GET" and status in range(200, 300) and status not in (204, 205) and not has_body(entry)


def respond(route, url, archived, addon, terminal):
    request = route.request
    if terminal:
        local = ("127.0.0.1", 0)
        flow = http.HTTPFlow(connection.Client(peername=local, sockname=local),
                             connection.Server(address=None))
        flow.request = http.Request.make(request.method, url)
        # Observe a document navigation without executing the landing page.
        recorded = http.Response.make(200, b"", {"content-type": "text/html"})
    else:
        flow = har_flow(archived)
        recorded, flow.response = flow.response, None
    flow.request.headers = http.Headers(
        (name.encode(), value.encode()) for name, value in request.all_headers().items()
    )
    if addon:
        addon.request(flow)
    if flow.response is None:
        flow.response = recorded
        if addon:
            addon.response(flow)
    blocked = any(key in flow.metadata for key in ("adblock", "adblock_redirect"))
    response = flow.response
    headers = {name: value for name, value in response.headers.items()
               if name.lower() not in STRIPPED_HEADERS}
    route.fulfill(status=response.status_code, headers=headers, body=response.content or b"")
    return blocked


def execute(browser, archive, case, addon):
    counters = Counter()
    critical_misses = set()
    new_pages = []
    phase = "setup"

    def route_request(route):
        request = route.request
        method = request.method
        try:
            url = url_key(request.url)
            archived = archive.get((method, url))
            navigation = request.is_navigation_request()
            terminal = url == case["popup_url"]
            if terminal and not (phase == "click" and method == "GET" and navigation):
                route.abort()
                return
            if terminal:
                counters["target_requests"] += 1
            if not terminal and archive_miss(archived, method):
                counters[f"{phase}_archive_misses"] += 1
                if phase == "click" and (navigation or request.resource_type == "script"):
                    critical_misses.add((method, url))
                route.abort()
                return
            blocked = respond(route, url, archived, addon, terminal)
            if blocked:
                if phase == "setup" and request.resource_type == "script":
                    counters["setup_script_blocks"] += 1
                if phase == "click":
                    counters["click_blocks"] += 1
                    if navigation:
                        counters["navigation_blocks"] += 1
                    if terminal:
                        counters["target_blocks"] += 1
        except Exception:
            counters["route_errors"] += 1
            route.abort()

    with browser.new_context(service_workers="block", accept_downloads=False) as context:
        context.set_default_timeout(ACTION_TIMEOUT_MS)
        context.route_web_socket("**/*", lambda socket: socket.close())
        context.route("**/*", route_request)
        page = context.new_page()
        page.on("popup", lambda _: counters.update(["opener_popups"]))
        context.on("page", lambda child: new_pages.append(child))
        try:
            page.goto(case["start_url"], wait_until="load")
            locator = page.locator("css=" + case["click"])
            locator.wait_for(state="visible")
            page.wait_for_timeout(250)
            counters["windows_before_click"] = len(new_pages)
            phase = "click"
            locator.click()
            counters["clicked"] += 1
            # Give any timer-based pop-under a bounded observation window.
            page.wait_for_timeout(WAIT_MS)
            counters["opener_ok"] = (
                not page.is_closed()
                and url_key(page.url) == case["opener_url"]
                and page.locator("css=" + case["opener_selector"]).is_visible()
            )
        except (BrowserError, CorpusError):
            counters["action_error"] += 1
        opened = new_pages[counters["windows_before_click"]:]
        counters["new_pages_after_click"] = len(opened)
        counters["target_windows"] = sum(
            child.url.partition("#")[0] == case["popup_url"] for child in opened
        )
    counters["critical_archive_misses"] = len(critical_misses)
    return counters


def baseline_matches(observed, case):
    return (
        observed["target_requests"] == observed["target_windows"] == observed["new_pages_after_click"] == 1
        and observed["clicked"] and observed["opener_ok"]
        and not observed["windows_before_click"]
        and not observed["route_errors"]
        and (case["expect"] == "allow" or not observed["critical_archive_misses"])
    )


def filtered_result(observed, case):
    if observed["route_errors"] or (case["expect"] == "block" and observed["critical_archive_misses"]):
        return "incomplete_archive"
    if not observed["clicked"] or not observed["opener_ok"] or observed["windows_before_click"]:
        return "opener_broken"
    if observed["new_pages_after_click"] > 1:
        return "unexpected_windows"
    attempted = observed["target_requests"]
    if case["expect"] == "allow":
        if (attempted == observed["target_windows"] == observed["new_pages_after_click"] == 1
                and not observed["target_blocks"]):
            return "allowed"
        return "expected_popup_missing"
    if attempted and attempted == observed["target_blocks"]:
        return "destination_blocked"
    if not attempted and observed["navigation_blocks"]:
        return "navigation_blocked_upstream"
    script_or_click_blocked = observed["setup_script_blocks"] or observed["click_blocks"]
    if not attempted and not observed["new_pages_after_click"] and script_or_click_blocked:
        return "popup_suppressed"
    if not attempted:
        return "destination_not_observed"
    return "popup_allowed"


def check_replay(browser, repeat):
    captures = sorted(INPUT.glob("*.har"))
    plans = []
    for har in captures:
        if har.with_suffix(".clicks.json").exists():
            manifest, cases = click_cases(har)
            plans.append((har, manifest, cases))
    case_count = sum(len(cases) for _, _, cases in plans)
    if not 1 <= case_count <= MAX_CASES:
        raise CorpusError("Supply 1–8 click cases across all HAR sidecars.")
    if case_count * repeat > MAX_REPEATED_CASES:
        raise CorpusError("The click workload exceeds 24 baseline and filtered case pairs.")
    addon, lists = make_addon()
    report = {"kind": "browser_clicks", "repeat": repeat, "filter_sha256": lists,
              "observation_ms": WAIT_MS, "captures": {}}
    status = 0
    for har, manifest, cases in plans:
        archive, recorded_urls = index_capture(har)
        results = []
        for index, case in enumerate(cases):
            if not has_body(archive.get(("GET", case["start_url"]))):
                raise CorpusError("The browser opener needs an archived response body.")
            if case["expect"] == "block" and case["popup_url"] not in recorded_urls:
                raise CorpusError("An unsolicited popup needs a recorded target request.")
            for _ in range(repeat):
                baseline = execute(browser, archive, case, None)
                record = {"case": index, "expect": case["expect"], "baseline": baseline}
                if not baseline_matches(baseline, case):
                    status = 2
                    record["outcome"] = "baseline_did_not_reproduce"
                else:
                    filtered = execute(browser, archive, case, addon)
                    outcome = filtered_result(filtered, case)
                    record.update(filtered=filtered, outcome=outcome)
                    if outcome not in {"allowed", "destination_blocked", "navigation_blocked_upstream",
                                       "popup_suppressed"}:
                        status = max(status, 2 if outcome == "incomplete_archive" else 1)
                results.append(record)
        report["captures"][har.name] = {"sha256": digest(har), "clicks_sha256": digest(manifest),
                                        "cases": results}
    return report, status


def main():
    logging.disable(logging.CRITICAL)
    signal.alarm(int(sys.argv[2]))
    started = time.monotonic()
    try:
        if os.geteuid() != 10001 or {name for _, name in socket.if_nameindex()} - {"lo"}:
            raise CorpusError("Browser sandbox isolation check failed.")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(ignore_default_args=["--disable-popup-blocking"])
            try:
                if "--check" in sys.argv[3:]:
                    page = browser.new_page()
                    page.goto("about:blank")
                    report, status = {"kind": "browser_clicks", "chromium": browser.version}, 0
                else:
                    report, status = check_replay(browser, int(sys.argv[1]))
            finally:
                browser.close()
        report.update(isolation_check="passed", elapsed_seconds=round(time.monotonic() - started, 3))
    except CorpusError as error:
        report, status = {"error": str(error)}, 2
    except Exception as error:
        report, status = {"error": "Browser sandbox or click replay failed.",
                          "error_type": type(error).__name__}, 2
    print(json.dumps(report, ensure_ascii=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
