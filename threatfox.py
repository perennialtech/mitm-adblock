"""Load ThreatFox's reported dedicated domains for exact-host threat blocking."""

import csv
import http.client
import io
import re
import zipfile
from pathlib import Path
from urllib.parse import quote

HOST = "threatfox-api.abuse.ch"
MAX_EXPORT = 32 * 1024 * 1024
MAX_CSV = 192 * 1024 * 1024
MIN_CONFIDENCE = 75
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
REQUIRED_COLUMNS = {"ioc_value", "ioc_type", "threat_type", "confidence_level", "is_compromised"}


def valid_domains(lines) -> set[str]:
    hosts = (line.strip().lower().rstrip(".") for line in lines)
    return {host for host in hosts if len(host) <= 253 and DOMAIN.fullmatch(host)}


def domains_from_export(data: bytes) -> set[str]:
    domains = set()
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
                if (
                    row.get("ioc_type") != "domain"
                    or row.get("threat_type") not in {"botnet_cc", "payload_delivery"}
                    or (row.get("is_compromised") or "").lower() not in {"false", "0"}
                    or int(row.get("confidence_level") or 0) < MIN_CONFIDENCE
                ):
                    continue
                host = (row.get("ioc_value") or "").lower().rstrip(".")
                if len(host) <= 253 and DOMAIN.fullmatch(host):
                    domains.add(host)
    if not domains:
        raise ValueError("ThreatFox export contained no eligible domains")
    return domains


def fetch_domains(key_file: Path) -> set[str]:
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
        return domains_from_export(data)
    finally:
        connection.close()
