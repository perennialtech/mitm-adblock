"""Exercise the shipped Rust proxy with a loopback publisher."""
import gzip
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

PAGE = b'<html><head></head><body class="sponsor">Publisher</body></html>'


class Publisher(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.seen.append((self.path, self.client_address[1]))
        if self.path == "/socket":
            self.send_response(101)
            self.send_header("Upgrade", "echo")
            self.send_header("Connection", "upgrade")
            self.end_headers()
            self.wfile.write(self.rfile.read(4))
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path == "/jump":
            self.send_response(302)
            self.send_header("Location", "/advert.js")
            body = b""
        else:
            self.send_response(200)
            if self.path.startswith("/html"):
                body = gzip.compress(PAGE)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Security-Policy", "default-src 'none'")
                self.send_header("ETag", '"origin"')
                if self.path.endswith("unchanged"):
                    self.send_header("Cache-Control", "no-transform")
            else:
                body = self.path.encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProxyWire(unittest.TestCase):
    def setUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Publisher)
        self.seen = origin.seen = []
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(origin.server_close)
        self.addCleanup(origin.shutdown)
        self.origin = "127.0.0.1:%s" % origin.server_port
        self.proxy = self.start()

    def start(self, *extra):
        rules = self.work / "rules.txt"
        rules.write_text("/advert.js$script\n##.sponsor\n")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        log = self.enterContext((self.work / f"{port}.log").open("w+"))
        proc = subprocess.Popen(["mitm-adblock", "--listen-port", str(port), "--set",
                                 f"confdir={self.work}", "--set", f"adblock_lists={rules}", *extra],
                                stdout=log, stderr=log)
        def stop():
            proc.terminate()
            proc.wait(timeout=5)
        self.addCleanup(stop)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                log.seek(0)
                self.fail(log.read())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return port
            except OSError:
                time.sleep(0.025)
        self.fail("listener did not become ready")

    def fetch(self, path, headers=None, *, origin=None, port=None):
        conn = http.client.HTTPConnection("127.0.0.1", port or self.proxy, timeout=4)
        try:
            conn.request("GET", f"http://{origin or self.origin}{path}", headers=headers or {})
            response = conn.getresponse()
            return response.status, response.headers, response.read()
        finally:
            conn.close()

    def test_encoded_query_block_and_redirect(self):
        path = "/a%2Fb?utm_source=x&tag=1&tag=2&flag&v=%2f"
        self.assertEqual(self.fetch(path)[2], path.encode())
        headers = {"Sec-Fetch-Dest": "script"}
        self.assertEqual(self.fetch("/advert.js", headers, origin="offline.invalid")[0], 204)
        self.assertEqual(self.fetch("/jump", headers)[0], 204)

    def test_compressed_html_policy_and_no_transform(self):
        import base64
        headers = {"Sec-Fetch-Dest": "document"}
        status, response, doc = self.fetch("/html", headers)
        self.assertEqual(status, 200)
        css = b".sponsor{display:none!important}"
        self.assertIn(css, doc)
        self.assertIn(base64.b64encode(hashlib.sha256(css).digest()).decode(),
                      response["Content-Security-Policy"])
        self.assertNotIn("ETag", response)
        _, response, doc = self.fetch("/html/unchanged", headers)
        self.assertEqual(response["Content-Encoding"], "gzip")
        self.assertEqual(response["ETag"], '"origin"')
        self.assertEqual(gzip.decompress(doc), PAGE)

    def test_ca_volume_survives_restart(self):
        ca = self.fetch("/cert/pem", origin="mitm.it")[2]
        self.assertTrue(ca.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertEqual(ca, (self.work / "mitmproxy-ca-cert.pem").read_bytes())
        self.assertEqual(self.fetch("/cert/pem", origin="mitm.it", port=self.start())[2], ca)
        self.assertNotIn(b"PRIVATE", ca)

    def test_existing_mitmproxy_ca_and_cold_start_with_local_domains(self):
        from mitmproxy.certs import CertStore

        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        CertStore.from_store(self.work, "mitmproxy", 2048)
        expected = (self.work / "mitmproxy-ca-cert.pem").read_bytes()
        combined = (self.work / "mitmproxy-ca.pem").read_bytes()
        indicators = self.work / "domains"
        indicators.write_text("blocked.test\n")
        port = self.start("--set", f"adblock_lists={self.work / 'missing'}",
                          "--set", f"adblock_threat_domains_file={indicators}")
        self.assertEqual(self.fetch("/cert/pem", origin="mitm.it", port=port)[2], expected)
        self.assertEqual((self.work / "mitmproxy-ca.pem").read_bytes(), combined)
        self.assertEqual(self.fetch("/", {"Sec-Fetch-Dest": "document"}, origin="blocked.test", port=port)[0], 403)

    def test_origin_connection_is_reused(self):
        paths = ["/reuse/%2F?q=%2b&x=+", "/reuse/next"]
        for path in paths:
            self.assertEqual(self.fetch(path)[2], path.encode())
        self.assertEqual([entry[0] for entry in self.seen], paths)
        self.assertEqual(self.seen[0][1], self.seen[1][1])

    def test_upgrade_is_bidirectional(self):
        with socket.create_connection(("127.0.0.1", self.proxy), timeout=4) as sock:
            with sock.makefile("rb") as stream:
                sock.sendall((f"GET http://{self.origin}/socket HTTP/1.1\r\nHost: {self.origin}\r\n"
                              "Connection: upgrade\r\nUpgrade: echo\r\n\r\n").encode())
                self.assertIn(b" 101 ", stream.readline())
                while stream.readline() not in {b"\r\n", b""}:
                    pass
                sock.sendall(b"echo")
                self.assertEqual(stream.read(4), b"echo")
