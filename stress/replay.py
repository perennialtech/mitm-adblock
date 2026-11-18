"""Replay archived HTTP events as data, entirely inside the offline sandbox."""

import csv
import hashlib
import json
import logging
import os
import re
import signal
import socket
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

INPUT = Path("/replay")
MAX_OPERATIONS = 100_000
MAX_FINDINGS = 50
MAX_FAMILIES = 64
CAMPAIGN = "pushpaganda.csv"
FAMILY = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


class CorpusError(ValueError):
    pass


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def labels_for(path, entry_count):
    if not path.exists():
        return {}
    raw = json.loads(path.read_bytes())
    for ordinal, label in raw.items():
        index = int(ordinal)
        if str(index) != ordinal or not 0 <= index < entry_count:
            raise CorpusError("A label points outside the HAR.")
        if label["expect"] not in {"block", "allow", "inject"} or not FAMILY.fullmatch(label["family"]):
            raise CorpusError("Invalid expectation or family in labels.")
    return {int(index): label for index, label in raw.items()}


def captures(repeat):
    count = 0
    for path in sorted(INPUT.glob("*.har")):
        entries = json.loads(path.read_bytes())["log"]["entries"]
        if not isinstance(entries, list) or not entries:
            raise CorpusError("Each HAR must contain recorded requests.")
        count += len(entries)
        if count * repeat > MAX_OPERATIONS:
            raise CorpusError("The corpus and repeat count exceed 100,000 HAR entries per run.")
        label_path = path.with_suffix(".labels.json")
        labels = labels_for(label_path, len(entries))
        yield path.name, entries, labels, {
            "sha256": digest(path),
            **({"labels_sha256": digest(label_path)} if labels else {}),
        }


def make_addon():
    # The launcher runs Python in isolated mode. Load only the app baked into
    # the trusted image, even if an input file has a Python-looking name.
    sys.path.insert(0, "/app")
    from mitmproxy import ctx, options

    from adblock_addon import AdBlock

    addon = AdBlock()
    opts = options.Options()
    addon.load(SimpleNamespace(add_option=opts.add_option))
    ctx.options = opts
    rules = sorted(INPUT.glob("*.txt"))
    opts.update(
        adblock_lists=",".join(str(path) for path in rules),
        adblock_cache_dir="/unused",
        adblock_update_hours=0,
    )
    addon.configure({"adblock_lists", "adblock_cache_dir"})
    if addon.engine is None:
        raise CorpusError("The ad-block engine did not initialize.")
    return addon, {rule.name: digest(rule) for rule in rules}


def har_flow(entry):
    from mitmproxy.io.har import request_to_flow

    url = urlsplit(entry["request"]["url"])
    if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None:
        return None
    flow = request_to_flow(entry)
    if flow.response.status_code == 0:
        flow.response = None
    elif "content-type" not in flow.response.headers:
        mime = entry["response"]["content"].get("mimeType")
        if mime:
            flow.response.headers["content-type"] = mime
    return flow


def run_capture(addon, name, entries, labels, repeat, timings, families, findings):
    counts = Counter(entries=len(entries))
    for iteration in range(repeat):
        for index, entry in enumerate(entries):
            label = labels.get(index)
            try:
                flow = har_flow(entry)
                if flow is None:
                    counts["unsupported"] += 1
                    if label:
                        raise CorpusError("Label refers to an unsupported URL.")
                    continue
                recorded_response, flow.response = flow.response, None
                recorded_status = recorded_response.status_code if recorded_response else 0
                html = (
                    recorded_status == 200
                    and "text/html" in recorded_response.headers.get("content-type", "").lower()
                )
                has_body = html and bool(entry["response"]["content"].get("text"))
                pages_before = addon.stats["pages_injected"]
                start = time.perf_counter_ns()
                addon.request(flow)
                blocked = "adblock" in flow.metadata
                if not blocked:
                    flow.response = recorded_response
                original_body = flow.response.raw_content if flow.response else None
                if flow.response is not None:
                    addon.response(flow)
                timings.append(time.perf_counter_ns() - start)
                injected = (
                    addon.stats["pages_injected"] > pages_before
                    and flow.response.raw_content != original_body
                )
            except Exception:
                counts["errors"] += 1
                if len(findings) < MAX_FINDINGS and iteration == 0:
                    findings.append({"capture": name, "entry": index, "result": "replay_error"})
                continue

            counts["replayed"] += 1
            counts["requests_without_headers"] += not bool(entry["request"]["headers"])
            counts["blocked" if blocked else "allowed"] += 1
            if 300 <= recorded_status < 400 and recorded_status != 304:
                counts["recorded_redirects"] += 1
                counts["blocked_redirects"] += blocked
            counts["html_with_body"] += has_body
            counts["html_missing_body"] += html and not has_body
            counts["injected"] += injected
            if label:
                expected = label["expect"]
                actual = "block" if blocked else "inject" if injected else "allow"
                # A permitted page can also receive cosmetic filtering.
                matched = expected == actual or (expected == "allow" and not blocked)
                families[label["family"]]["checked"] += 1
                families[label["family"]]["missed"] += not matched
                counts["expectation_misses"] += not matched
                if not matched and len(findings) < MAX_FINDINGS and iteration == 0:
                    findings.append({"capture": name, "entry": index, "expected": expected, "result": actual})
    return dict(counts)


def probe_campaign(addon, path):
    from mitmproxy import connection, http

    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.reader(stream))
    if not 0 < len(rows) <= 1_000 or any(
        len(row) != 1 or len(row[0]) > 253 or not DOMAIN.fullmatch(row[0]) for row in rows
    ):
        raise CorpusError("Invalid campaign domain CSV.")
    domains = {row[0] for row in rows}
    blocked = 0
    for domain in sorted(domains):
        flow = http.HTTPFlow(
            connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0), timestamp_start=0),
            connection.Server(address=(domain, 443)),
        )
        flow.request = http.Request.make("GET", f"https://{domain}/", headers={"Sec-Fetch-Dest": "document"})
        addon.request(flow)
        blocked += "adblock" in flow.metadata
    return {"sha256": digest(path), "document_probes": len(domains), "blocked": blocked, "allowed": len(domains) - blocked}


def replay(repeat):
    started = time.perf_counter()
    addon, lists = make_addon()
    results = {}
    timings = []
    families = defaultdict(Counter)
    findings = []
    campaign = INPUT / CAMPAIGN
    report = {"filter_sha256": lists, "repeat": repeat, "captures": results}
    for name, entries, labels, files in captures(repeat):
        if len(families.keys() | {label["family"] for label in labels.values()}) > MAX_FAMILIES:
            raise CorpusError("The corpus exceeds 64 expectation families.")
        counts = run_capture(addon, name, entries, labels, repeat, timings, families, findings)
        results[name] = {**files, **counts}
    if campaign.exists():
        report["pushpaganda"] = probe_campaign(addon, campaign)
    timings.sort()
    report.update(
        hook_p95_us=round(timings[(95 * len(timings) - 1) // 100] / 1_000, 2) if timings else None,
        elapsed_seconds=round(time.perf_counter() - started, 3),
        expectations=families,
        findings=findings,
    )
    failed = any(
        not result.get("replayed") or result.get("errors") or result.get("expectation_misses")
        for result in results.values()
    )
    return report, int(failed)


def main():
    # Keep untrusted headers, URLs, response bodies, rule text and parser
    # exceptions out of stderr and the portable report.
    logging.disable(logging.CRITICAL)
    signal.alarm(115)
    try:
        interfaces = {name for _, name in socket.if_nameindex()}
        if os.geteuid() != 10001 or interfaces - {"lo"}:
            raise CorpusError("Sandbox preflight failed.")
        if sys.argv[2:] == ["--check"]:
            report, status = {"isolation_check": "passed", "interfaces": sorted(interfaces)}, 0
        else:
            report, status = replay(int(sys.argv[1]))
            report["isolation_check"] = "passed"
    except CorpusError as error:
        report, status = {"error": str(error)}, 2
    except Exception as error:
        # A fixed error vocabulary prevents third-party exception text from
        # sending any archived content across the boundary.
        report, status = {"error": "Sandbox preflight, corpus validation or replay failed.",
                          "error_type": type(error).__name__}, 2
    print(json.dumps(report, ensure_ascii=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
