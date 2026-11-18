"""Read ThreatFox domain and payload URL indicators without visiting them."""

import csv
import http.client
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

HOST = "threatfox-api.abuse.ch"
MAX_EXPORT = 32 * 1024 * 1024
MAX_CSV = 192 * 1024 * 1024
MIN_CONFIDENCE = 75
MAX_AGE_SECONDS = 7 * 24 * 3600
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
INVALID_URL_CHAR = re.compile(r"[\\\x00-\x20\x7f]")
REQUIRED_COLUMNS = {
    "ioc_value", "ioc_type", "threat_type", "confidence_level", "is_compromised",
    "first_seen_utc", "last_seen_utc",
}


@dataclass
class ThreatFoxSnapshot:
    domains: set[str] = field(default_factory=set)
    payload_urls: dict[str, int] = field(default_factory=dict)

    def write(self, stream) -> None:
        json.dump({"domains": sorted(self.domains), "payload_urls": self.payload_urls}, stream)

    @classmethod
    def read(cls, stream):
        data = json.load(stream)
        domains = data["domains"]
        payload_urls = data["payload_urls"]
        if (
            not isinstance(domains, list) or not all(isinstance(host, str) for host in domains)
            or not isinstance(payload_urls, dict)
            or not all(type(expiry) is int for expiry in payload_urls.values())
        ):
            raise ValueError("Invalid ThreatFox cache")
        return cls(valid_domains(domains), payload_urls)


def exact_url_key(value: str) -> str | None:
    """Canonicalize the authority while keeping the path and query byte-exact."""
    sent_url = value.partition("#")[0]
    if not sent_url.isascii() or INVALID_URL_CHAR.search(sent_url):
        return None
    try:
        url = urlsplit(sent_url)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None:
            return None
        port = url.port
    except ValueError:
        return None
    host = url.hostname
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if url.scheme == "https" else 80):
        authority += f":{port}"
    query = "?" + url.query if "?" in sent_url else ""
    return f"{url.scheme}://{authority}{url.path or '/'}{query}"


def valid_domains(lines) -> set[str]:
    hosts = (line.strip().lower().rstrip(".") for line in lines)
    return {host for host in hosts if len(host) <= 253 and DOMAIN.fullmatch(host)}


def snapshot_from_export(data: bytes, *, now: datetime | None = None) -> ThreatFoxSnapshot:
    now = now or datetime.now(timezone.utc)
    current = int(now.timestamp())
    snapshot = ThreatFoxSnapshot()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [member for member in archive.infolist() if member.filename.endswith(".csv")]
        if len(members) != 1 or members[0].file_size > MAX_CSV:
            raise ValueError("Unexpected ThreatFox CSV size or layout")
        with archive.open(members[0]) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as stream:
            for line in stream:
                if line.startswith("#") and "first_seen_utc" in line:
                    fields = next(csv.reader([line.lstrip("# ").strip()], skipinitialspace=True))
                    break
            else:
                raise ValueError("Missing ThreatFox CSV header")
            if not REQUIRED_COLUMNS <= set(fields):
                raise ValueError("Missing ThreatFox fields")
            for row in csv.DictReader(stream, fieldnames=fields, skipinitialspace=True):
                ioc_type = row.get("ioc_type")
                threat_type = row.get("threat_type")
                if ioc_type not in {"domain", "url"} or threat_type not in {"botnet_cc", "payload_delivery"}:
                    continue
                try:
                    confidence = int(row.get("confidence_level") or 0)
                except ValueError:
                    continue
                if confidence < MIN_CONFIDENCE:
                    continue
                compromised = (row.get("is_compromised") or "").lower()
                value = row.get("ioc_value") or ""
                if ioc_type == "domain" and compromised in {"false", "0"}:
                    host = value.lower().rstrip(".")
                    if len(host) <= 253 and DOMAIN.fullmatch(host):
                        snapshot.domains.add(host)
                elif ioc_type == "url" and threat_type == "payload_delivery":
                    seen = row.get("last_seen_utc") or row.get("first_seen_utc") or ""
                    try:
                        observed = int(datetime.fromisoformat(seen).replace(tzinfo=timezone.utc).timestamp())
                    except (ValueError, OverflowError):
                        continue
                    if not 0 <= current - observed < MAX_AGE_SECONDS:
                        continue
                    url = exact_url_key(value)
                    if not url:
                        continue
                    if compromised not in {"false", "0"} and urlsplit(url).path == "/" and "?" not in url:
                        continue
                    expires = observed + MAX_AGE_SECONDS
                    snapshot.payload_urls[url] = max(expires, snapshot.payload_urls.get(url, 0))
    if not snapshot.domains:
        raise ValueError("ThreatFox export contained no eligible domains")
    return snapshot


def fetch_snapshot(key_file: Path) -> ThreatFoxSnapshot:
    with key_file.open(encoding="ascii") as stream:
        key = stream.read(257).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{12,256}", key):
        raise ValueError("Invalid ThreatFox key file")
    # The documented file export embeds the key in the HTTPS path. Use a direct
    # connection so it stays out of command arguments, redirect handlers and logs.
    connection = http.client.HTTPSConnection(HOST, timeout=30)
    try:
        path = f"/v2/files/exports/{quote(key, safe='')}/full.csv.zip"
        connection.request("GET", path, headers={"User-Agent": "mitm-adblock/1.0"})
        response = connection.getresponse()
        if response.status != 200:
            raise OSError(f"ThreatFox responded with HTTP {response.status}")
        data = response.read(MAX_EXPORT + 1)
        if len(data) > MAX_EXPORT:
            raise ValueError("ThreatFox export exceeded the download limit")
        return snapshot_from_export(data)
    finally:
        connection.close()
