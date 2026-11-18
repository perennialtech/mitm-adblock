"""Stage request-only HARs from public scan reports selected by upstream categories."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import html
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlencode, urlsplit
import zipfile

SOURCES = {
    "adult": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "ranking": "https://tranco-list.eu/top-1m.csv.zip",
}
SCAN_ID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
DOMAIN = re.compile(r"\|\|([\w.-]+)\^", re.ASCII)
TABLE = re.compile(r'<table\b[^>]*\bid="table_transactions"[^>]*>', re.I)
ROW = re.compile(r'<tr class="request(?: [^"]*)?">')
CELL = re.compile(r'<td\b[^>]*>(.*?)</td>', re.S)
KEY_VALUE = re.compile(r"<dt>(.*?)</dt>\s*<dd>(.*?)</dd>", re.S)
CHAIN = re.compile(r"<b[^>]*>Redirect Chain</b>\s*<ul[^>]*>(.*?)</ul>", re.S)
HOP = re.compile(r"<li\b[^>]*>(.*?)</li>", re.S)
REQUEST_HEADERS = {"accept", "content-type", "origin", "referer", "sec-fetch-dest",
                   "sec-fetch-site", "sec-fetch-mode", "upgrade", "ping-to"}
RESPONSE_HEADERS = {"content-type", "location", "refresh"}
DESTINATION = {"script": "script", "image": "image", "css": "style", "stylesheet": "style",
               "font": "font", "media": "video", "fetch": "empty", "xhr": "empty",
               "ping": "report", "preflight": "empty", "eventsource": "empty"}
CANDIDATES_PER_COHORT = 16
SCANS_PER_COHORT = 8


def download(url, limit):
    with tempfile.TemporaryFile() as file:
        subprocess.run(
            ["curl", "-qfsS", "--proto", "=https", "--max-time", "30",
             *(["--location", "--proto-redir", "=https", "--max-redirs", "2"]
               if url == SOURCES["ranking"] else []), "--max-filesize", str(limit), url],
            stdout=file, stderr=subprocess.DEVNULL, check=True,
        )
        file.seek(0)
        data = file.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Empty or oversized archive response.")
    return data


def domains(data):
    return {match[1] for line in data.decode("utf-8-sig").splitlines()
            if (match := DOMAIN.match(line.lower()))}


def ranked_candidates(ranking, adult, piracy, excluded):
    cohorts = {"overlap": [], "adult": [], "piracy": []}
    with zipfile.ZipFile(io.BytesIO(ranking)) as archive:
        members = [item for item in archive.infolist() if item.filename == "top-1m.csv"]
        if len(members) != 1 or members[0].file_size > 64 * 1024 * 1024:
            raise ValueError("Unexpected ranking archive contents.")
        with archive.open(members[0]) as file:
            for index, (position, domain) in enumerate(csv.reader(io.TextIOWrapper(file)), 1):
                if index > 150_000 or all(len(group) == CANDIDATES_PER_COHORT for group in cohorts.values()):
                    break
                domain = domain.lower()
                if domain in excluded or not (domain in adult or domain in piracy):
                    continue
                if domain in adult:
                    name = "overlap" if domain in piracy else "adult"
                else:
                    name = "piracy"
                if len(cohorts[name]) < CANDIDATES_PER_COHORT:
                    cohorts[name].append((int(position), domain))
    return cohorts


def http_url(url):
    if not isinstance(url, str) or len(url) > 16384:
        return None
    try:
        target = urlsplit(url)
        if target.scheme in {"http", "https"} and target.hostname and target.username is None:
            return target
    except ValueError:
        pass
    return None


def matches_domain(url, domain):
    target = http_url(url)
    return bool(target and not target.query and (
        target.hostname == domain or target.hostname.endswith("." + domain)
    ))


def plain_markup(value):
    return " ".join(html.unescape(re.sub(r"<[^>]*>", " ", value)).split())


def fields(markup):
    return {plain_markup(key).lower(): plain_markup(value)
            for key, value in KEY_VALUE.findall(markup)}


def selected_headers(markup, section, keep):
    _, found, body = markup.partition(f"<h4>{section} headers</h4>")
    if not found:
        return {}
    return {key: value for key, value in fields(body.split("</dl>", 1)[0]).items()
            if key in keep and value}


def redirect_chain(summary_cell, url):
    match = CHAIN.search(summary_cell)
    if not match:
        return []
    urls = [plain_markup(item) for item in HOP.findall(match[1])]
    if not 2 <= len(urls) <= 30 or http_url(urls[-1]) != http_url(url):
        return []
    return urls if all(http_url(hop) for hop in urls) else []


def request_entries(report, landing_url, timestamp):
    """Read public transaction rows without running scripts or fetching their resources."""
    markup = report.decode("utf-8")
    table = TABLE.search(markup)
    if not table:
        return [], None
    entries, main = [], None
    for transaction in ROW.split(markup[table.end():])[1:]:
        cells = CELL.findall(transaction.split("</tr>", 1)[0])
        if len(cells) < 6:
            continue
        url = fields(transaction.split("<h4>Request headers</h4>", 1)[0]).get("full url")
        target = http_url(url)
        method = plain_markup(cells[0]).split()
        if not target or not method or not re.fullmatch(r"[A-Z]{3,12}", method[0]):
            continue
        status = re.match(r"[1-5]\d\d\b", plain_markup(cells[1]))
        resource = re.search(r"<span[^>]*>(.*?)</span>", cells[5], re.S)
        kind = plain_markup(resource[1]).lower() if resource else ""
        primary = target == http_url(landing_url) and bool(re.search(r">\s*Primary Request\s*<", cells[2]))
        req = selected_headers(transaction, "Request", REQUEST_HEADERS)
        resp = selected_headers(transaction, "Response", RESPONSE_HEADERS)
        mime = re.search(r"<small[^>]*>(.*?)</small>", cells[5], re.S)
        if mime:
            resp.setdefault("content-type", plain_markup(mime[1]))
        # Keep recorded headers intact. The addon handles old clients without
        # Fetch Metadata and the alternate replay can add the browser's type.
        destination = ("document" if primary else "iframe") if kind == "document" else DESTINATION.get(kind)
        request = {"url": url, "method": method[0], "httpVersion": "HTTP/1.1",
                   "headers": [{"name": k, "value": v} for k, v in req.items()],
                   "cookies": [], "queryString": [], "headersSize": -1, "bodySize": -1}
        response = {"status": int(status[0]) if status else 0, "statusText": "", "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in resp.items()],
                    "cookies": [], "redirectURL": resp.get("location", ""), "headersSize": -1,
                    "bodySize": -1, "content": {"size": 0, "mimeType": resp.get("content-type", "")}}
        entry = {"startedDateTime": timestamp, "time": 0, "request": request, "response": response,
                 "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}
        if destination:
            entry["_capturedFetchDest"] = destination
        if chain := redirect_chain(cells[2], url):
            entry["_capturedRedirectChain"] = chain
        if primary and response["status"] == 200:
            if main is not None:
                return [], None
            main = len(entries)
        entries.append(entry)
    return entries, main


def eligible_scan(scan, domain, cutoff):
    try:
        return (scan["task"]["visibility"] == "public" and scan["page"]["status"] in {200, "200"}
                and SCAN_ID.fullmatch(scan["_id"])
                and datetime.fromisoformat(scan["task"]["time"].replace("Z", "+00:00")) >= cutoff
                and 18 <= scan["stats"]["requests"] <= 3000
                and matches_domain(scan["task"]["url"], domain) and matches_domain(scan["page"]["url"], domain))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def stage_cohort(name, candidates, cutoff, output, snapshots):
    count = 0
    for rank, domain in candidates:
        query = f'task.apexDomain:"{domain}" AND page.apexDomain:"{domain}" AND page.status:200 AND date:>now-45d'
        endpoint = "https://urlscan.io/api/v1/search/?" + urlencode({"q": query, "size": 18})
        try:
            search = json.loads(download(endpoint, 2_000_000))
        except (subprocess.SubprocessError, ValueError):
            continue
        eligible = [item for item in search.get("results", []) if eligible_scan(item, domain, cutoff)]
        for scan in eligible[:3]:
            source = f"https://urlscan.io/result/{scan['_id']}/"
            try:
                raw = download(source, 18_000_000)
                entries, main = request_entries(raw, scan["page"]["url"], scan["task"]["time"])
            except (subprocess.SubprocessError, ValueError):
                continue
            if len(entries) < 18 or main is None:
                continue
            count += 1
            stem = f"ranked-{name}-{count:02}"
            log = {"version": "1.2", "creator": {"name": "Public urlscan report import", "version": "1"},
                   "_rankedScan": {"id": scan["_id"], "cohort": name, "rank": rank,
                                   "raw_sha256": hashlib.sha256(raw).hexdigest(), "snapshots": snapshots},
                   "entries": entries}
            (output / f"{stem}.har").write_text(json.dumps({"log": log}, ensure_ascii=True) + "\n")
            (output / f"{stem}.labels.json").write_text(json.dumps({
                str(main): {"expect": "allow", "family": "ranked_primary_page", "probe": True}
            }) + "\n")
            break
        if count == SCANS_PER_COHORT:
            break
    return count


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("output", type=Path, help="Existing staging directory containing tif-full.txt.")
    args = cli.parse_args()
    loaded = {key: download(url, 25_000_000 if key == "ranking" else 8_000_000)
              for key, url in SOURCES.items()}
    snapshots = {key: hashlib.sha256(data).hexdigest() for key, data in loaded.items()}
    excluded = domains((args.output / "tif-full.txt").read_bytes())
    categories = ranked_candidates(loaded["ranking"], domains(loaded["adult"]), domains(loaded["piracy"]), excluded)
    cutoff = datetime.now(timezone.utc) - timedelta(days=45)
    with ThreadPoolExecutor(max_workers=len(categories)) as executor:
        futures = {name: executor.submit(stage_cohort, name, group, cutoff, args.output, snapshots)
                   for name, group in categories.items()}
        counts = {name: future.result() for name, future in futures.items()}
    print("Ranked public reports", json.dumps(counts), flush=True)
    if not sum(counts.values()):
        cli.exit(2, "No eligible public scan reports could be staged. Check the archive service and quotas.\n")


if __name__ == "__main__":
    main()
