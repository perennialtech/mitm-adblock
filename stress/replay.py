"""Replay archived HTTP events as data, entirely inside the offline sandbox."""

import atexit
from base64 import b64decode, b64encode
import csv
import hashlib
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

INPUT = Path("/replay")
MAX_OPERATIONS = 100_000
MAX_FINDINGS = 50
MAX_FAMILIES = 64
CAMPAIGNS = {
    "pushpaganda": "pushpaganda.csv",
    "trapdoor": "trapdoor.csv",
    "help_tds": "help-tds.csv",
}
MAX_CAMPAIGN_ROWS = 5_000
BADWARE = "badware.txt"
THREAT_DOMAINS = "threat-domains.txt"
FAMILY = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
INJECTED_CSS = re.compile(r"<style data-mitm-adblock>(.*?)</style>", re.DOTALL)
SHA256 = re.compile(r"[a-f0-9]{64}")
SCAN_ID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
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
        if (
            label["expect"] not in {"block", "block_redirect", "stop_redirect", "allow", "inject"}
            or not FAMILY.fullmatch(label["family"])
            or not isinstance(label.get("probe", False), bool)
        ):
            raise CorpusError("Invalid expectation or family in labels.")
        fragment = label.get("css_contains")
        if fragment is not None and (
            label["expect"] != "inject" or not isinstance(fragment, str) or not 0 < len(fragment) <= 1024
        ):
            raise CorpusError("A CSS fragment needs an inject expectation and 1–1024 characters.")
    return {int(index): label for index, label in raw.items()}


def captures(repeat):
    count = 0
    for path in sorted(INPUT.glob("*.har")):
        archive = json.loads(path.read_bytes())["log"]
        entries = archive["entries"]
        if not isinstance(entries, list) or not entries:
            raise CorpusError("Each HAR must contain recorded requests.")
        count += len(entries)
        if count * repeat > MAX_OPERATIONS:
            raise CorpusError("The corpus and repeat count exceed 100,000 HAR entries per run.")
        label_path = path.with_suffix(".labels.json")
        labels = labels_for(label_path, len(entries))
        metadata = {}
        if ranked := archive.get("_rankedScan"):
            metadata = {"ranked_scan": ranked_scan_info(ranked)}
        yield path.name, entries, labels, {
            "sha256": digest(path),
            **({"labels_sha256": digest(label_path)} if labels else {}),
            **metadata,
        }


def ranked_scan_info(source):
    if not isinstance(source, dict):
        raise CorpusError("Invalid ranked scan provenance.")
    scan = source.get("id")
    rank = source.get("rank")
    cohort = source.get("cohort")
    raw = source.get("raw_sha256")
    hashes = source.get("snapshots")
    if (
        not isinstance(scan, str) or not SCAN_ID.fullmatch(scan)
        or type(rank) is not int or not 1 <= rank <= 150_000
        or cohort not in ("adult", "piracy", "overlap")
        or not isinstance(hashes, dict) or set(hashes) != {"adult", "piracy", "ranking"}
        or not all(isinstance(value, str) and SHA256.fullmatch(value)
                   for value in [raw, *hashes.values()])
    ):
        raise CorpusError("Invalid ranked scan provenance.")
    return {"id": scan, "rank": rank, "cohort": cohort, "raw_sha256": raw, "snapshots": hashes}


class ReplayAddon:
    def __init__(self, input_path):
        self.stats = {"blocked": 0, "pages_injected": 0}
        self.process = subprocess.Popen(
            ["/usr/local/bin/replay-policy", str(input_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        try:
            if self.process.stdout.readline() != '{"ready":true}\n':
                raise CorpusError("The Rust ad-block policy did not initialize.")
        except BaseException:
            self.close()
            raise
        atexit.register(self.close)

    def close(self):
        # Closing the event stream lets the child exit its read loop.
        try:
            self.process.stdin.close()
        except BrokenPipeError:
            pass
        self.process.stdout.close()
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    @staticmethod
    def _encode_headers(headers):
        return [(name.decode("ascii"), b64encode(value).decode("ascii"))
                for name, value in headers.fields]

    @staticmethod
    def _decode_headers(values):
        from mitmproxy import http

        return http.Headers((name.encode("ascii"), b64decode(value)) for name, value in values)

    def _evaluate(self, request, response=None):
        event = {
            "url": request.pretty_url,
            "method": request.method,
            "request_headers": self._encode_headers(request.headers),
            "response": response,
        }
        try:
            self.process.stdin.write(json.dumps(event, ensure_ascii=False) + "\n")
        except UnicodeEncodeError:
            # Invalid Unicode cannot reach the Rust proxy as a valid URL.
            return {"outcome": "unchanged"}
        self.process.stdin.flush()
        result = json.loads(self.process.stdout.readline())
        if result["outcome"] == "error":
            raise CorpusError("The Rust ad-block policy could not process a replay event.")
        return result

    def _block(self, flow, result):
        from mitmproxy import http

        flow.response = http.Response.make(
            result["status"], b64decode(result["body"]), self._decode_headers(result["headers"]),
        )
        flow.metadata["adblock"] = result["rule"]
        if result["navigation"] is not None:
            flow.metadata["adblock_" + result["navigation"]] = True
        self.stats["blocked"] += 1

    def request(self, flow):
        if flow.response is None:
            result = self._evaluate(flow.request)
            if result["outcome"] == "block":
                self._block(flow, result)

    def response(self, flow):
        response = flow.response
        if response is None or "adblock" in flow.metadata:
            return
        html = None
        mime = response.headers.get("content-type", "").partition(";")[0].strip().lower()
        if response.status_code == 200 and mime == "text/html":
            try:
                html = response.get_text(strict=False)
                if html is not None:
                    html.encode("utf-8")
            except ValueError:
                html = None
        result = self._evaluate(flow.request, {
            "status": response.status_code,
            "headers": self._encode_headers(response.headers),
            "html": html,
        })
        if result["outcome"] == "block":
            self._block(flow, result)
        elif result["outcome"] == "rewrite":
            response.headers = self._decode_headers(result["headers"])
            response.set_text(result["html"])
            self.stats["pages_injected"] += result["injected"]


def make_addon():
    rules = sorted(path for path in INPUT.glob("*.txt") if path.name != THREAT_DOMAINS)
    domains = INPUT / THREAT_DOMAINS
    if domains.exists():
        rules.append(domains)
    return ReplayAddon(INPUT), {rule.name: digest(rule) for rule in rules}


def har_flow(entry, infer_resource_types=False):
    from mitmproxy.io.har import request_to_flow

    url = urlsplit(entry["request"]["url"])
    if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None:
        return None
    flow = request_to_flow(entry)
    if infer_resource_types and "sec-fetch-dest" not in flow.request.headers:
        destination = entry.get("_capturedFetchDest")
        if destination in {"document", "iframe", "script", "image", "style", "font", "video", "empty", "report"}:
            flow.request.headers["sec-fetch-dest"] = destination
    if flow.response.status_code == 0:
        flow.response = None
    else:
        recorded = entry["response"]
        if "content-type" not in flow.response.headers:
            mime = recorded["content"].get("mimeType")
            if mime:
                flow.response.headers["content-type"] = mime
        # Some archives retain the redirect target but omit the HTTP headers.
        if "location" not in flow.response.headers and recorded.get("redirectURL"):
            flow.response.headers["location"] = recorded["redirectURL"]
    return flow


def run_capture(addon, name, entries, labels, repeat, timings, families, findings,
                infer_resource_types=False):
    counts = Counter(entries=len(entries))
    for entry in entries:
        if chain := entry.get("_capturedRedirectChain"):
            if not isinstance(chain, list) or not 2 <= len(chain) <= 30:
                raise CorpusError("Invalid archived redirect chain.")
            hosts = [urlsplit(hop).hostname for hop in chain]
            if not all(hosts):
                raise CorpusError("Invalid archived redirect hop.")
            counts["published_redirect_chains"] += 1
            counts["published_redirect_hops"] += len(chain) - 1
            counts["published_cross_host_redirect_hops"] += sum(
                origin != destination for origin, destination in zip(hosts, hosts[1:])
            )
    for iteration in range(repeat):
        for index, entry in enumerate(entries):
            label = labels.get(index)
            try:
                flow = har_flow(entry, infer_resource_types)
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
                blocked_destination = "adblock_redirect" in flow.metadata
                injected = (
                    addon.stats["pages_injected"] > pages_before
                    and flow.response.raw_content != original_body
                )
                fragment = label.get("css_contains") if label else None
                css_matched = fragment is None or (injected and any(
                    fragment in match for match in
                    INJECTED_CSS.findall(flow.response.get_text(strict=False) or "")
                ))
            except Exception:
                counts["errors"] += 1
                if len(findings) < MAX_FINDINGS and iteration == 0:
                    findings.append({"capture": name, "entry": index, "result": "replay_error"})
                continue

            counts["replayed"] += 1
            counts["requests_without_headers"] += not bool(entry["request"]["headers"])
            counts["blocked" if blocked else "allowed"] += 1
            recorded_redirect = 300 <= recorded_status < 400 and recorded_status != 304
            if recorded_redirect:
                counts["recorded_redirects"] += 1
                counts["blocked_redirects"] += blocked or blocked_destination
                counts["blocked_redirect_destinations"] += blocked_destination
            counts["html_with_body"] += has_body
            counts["html_missing_body"] += html and not has_body
            counts["injected"] += injected
            if label:
                expected = label["expect"]
                if blocked:
                    actual = "block"
                elif blocked_destination:
                    actual = "block_redirect"
                else:
                    actual = "inject" if injected else "allow"
                # A permitted page can also receive cosmetic filtering.
                matched = (
                    (expected == actual and css_matched)
                    or (expected == "allow" and actual == "inject")
                    or (expected == "stop_redirect" and recorded_redirect and (blocked or blocked_destination))
                )
                families[label["family"]]["checked"] += 1
                families[label["family"]]["missed"] += not matched
                probe = label.get("probe", False)
                counts["probe_misses" if probe else "expectation_misses"] += not matched
                if not matched and len(findings) < MAX_FINDINGS and iteration == 0:
                    finding = {"capture": name, "entry": index, "expected": expected,
                               "result": "missing_css" if actual == "inject" and not css_matched else actual}
                    if probe:
                        finding["probe"] = True
                    findings.append(finding)
    return dict(counts)


def campaign_domains(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.reader(stream))
    if not 0 < len(rows) <= MAX_CAMPAIGN_ROWS:
        raise CorpusError("Invalid campaign domain CSV.")
    if path.name == CAMPAIGNS["trapdoor"]:
        if rows.pop(0) != ["C2 Domain"]:
            raise CorpusError("Invalid Trapdoor CSV header.")
    if path.name == CAMPAIGNS["help_tds"]:
        if rows.pop(0) != ["type", "indicator", "classification", "detected_date"]:
            raise CorpusError("Invalid Help TDS CSV header.")
        if any(len(row) != 4 for row in rows):
            raise CorpusError("Invalid Help TDS CSV row.")
        rows = [[indicator.replace("[.]", ".").lower()]
                for kind, indicator, classification, _ in rows
                if (kind, classification) == ("domain", "malicious")]
    if not rows or any(
        len(row) != 1 or len(row[0]) > 253 or not DOMAIN.fullmatch(row[0]) for row in rows
    ):
        raise CorpusError("Invalid campaign domain CSV.")
    return {row[0] for row in rows}


def badware_domains(path):
    domains = set()
    with path.open(encoding="utf-8-sig") as stream:
        for line in stream:
            anchor, _, suffix = line.strip().partition("^")
            domain = anchor.removeprefix("||")
            if suffix == "$all" and anchor.startswith("||") and len(domain) <= 253 and DOMAIN.fullmatch(domain):
                domains.add(domain)
    return domains


def probe_domains(addon, path, domains):
    from mitmproxy import connection, http

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


def replay(repeat, infer_resource_types=False):
    started = time.perf_counter()
    addon, lists = make_addon()
    results = {}
    timings = []
    families = defaultdict(Counter)
    findings = []
    report = {"filter_sha256": lists, "repeat": repeat, "captures": results,
              "infer_resource_types": infer_resource_types}
    for name, entries, labels, files in captures(repeat):
        if len(families.keys() | {label["family"] for label in labels.values()}) > MAX_FAMILIES:
            raise CorpusError("The corpus exceeds 64 expectation families.")
        counts = run_capture(addon, name, entries, labels, repeat, timings, families, findings, infer_resource_types)
        results[name] = {**files, **counts}
    for name, filename in CAMPAIGNS.items():
        campaign = INPUT / filename
        if campaign.exists():
            report[name] = probe_domains(addon, campaign, campaign_domains(campaign))
    badware = INPUT / BADWARE
    if badware.exists():
        report["badware_all_rules"] = probe_domains(addon, badware, badware_domains(badware))
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
    signal.alarm(int(sys.argv[2]))
    try:
        interfaces = {name for _, name in socket.if_nameindex()}
        if os.geteuid() != 10001 or interfaces - {"lo"}:
            raise CorpusError("Sandbox preflight failed.")
        if "--check" in sys.argv[3:]:
            report, status = {"isolation_check": "passed", "interfaces": sorted(interfaces)}, 0
        else:
            report, status = replay(int(sys.argv[1]), "--infer-resource-types" in sys.argv[3:])
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
