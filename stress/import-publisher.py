"""Convert one checksum-verified Common Crawl HTML response to the replay format."""

import gzip
import json
import sys
from email.parser import BytesHeaderParser
from pathlib import Path

MAX_HTML = 8 * 1024 * 1024
RESPONSE_HEADERS = {
    "cache-control", "content-type", "content-security-policy",
    "content-security-policy-report-only",
}


def import_response(source: Path, destination: Path) -> None:
    with gzip.open(source, "rb") as capture:
        record = capture.read(MAX_HTML + 1)
    if len(record) > MAX_HTML:
        raise ValueError("Archived response exceeds the HTML capture limit.")
    warc_block, _, payload = record.partition(b"\r\n\r\n")
    version, _, fields = warc_block.partition(b"\r\n")
    parse = BytesHeaderParser().parsebytes
    archive = parse(fields)
    if version != b"WARC/1.0" or archive["WARC-Type"] != "response":
        raise ValueError("Expected a Common Crawl response record.")
    response_header, _, body = payload[:int(archive["Content-Length"])].partition(b"\r\n\r\n")
    status, _, fields = response_header.partition(b"\r\n")
    headers = parse(fields)
    if status.split()[:2] != [b"HTTP/1.1", b"200"] or headers.get_content_type() != "text/html":
        raise ValueError("Expected an archived HTTP 200 HTML document.")
    if len(body) != int(headers["Content-Length"]):
        raise ValueError("Archived response body does not match its recorded length.")

    entry = {
        "startedDateTime": archive["WARC-Date"],
        "time": 0,
        "request": {
            "url": archive["WARC-Target-URI"], "method": "GET", "httpVersion": "HTTP/1.1",
            # The WARC is a document response. The request headers are unavailable.
            "headers": [{"name": "Accept", "value": "text/html"}],
            "cookies": [], "queryString": [], "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "redirectURL": "",
            "headers": [{"name": name, "value": value} for name, value in headers.items()
                        if name.lower() in RESPONSE_HEADERS],
            "cookies": [], "headersSize": len(response_header), "bodySize": len(body),
            "content": {"mimeType": headers["Content-Type"], "size": len(body),
                        "text": body.decode(headers.get_content_charset() or "utf-8")},
        },
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }
    har = {"log": {"version": "1.2", "creator": {"name": "Common Crawl WARC import", "version": "1"},
                   "entries": [entry]}}
    destination.write_text(json.dumps(har, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    import_response(Path(sys.argv[1]), Path(sys.argv[2]))
