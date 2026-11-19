"""Route only documentation addresses through a TUN in a disposable network namespace."""
import http.client
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


@unittest.skipUnless(os.environ.get("TUN_WIRE_TEST") == "1", "requires isolated Linux TUN")
class KernelTun(unittest.TestCase):
    def test_dual_stack_filtered_and_allowed_requests(self):
        self.assertEqual(os.listdir("/sys/class/net"), ["lo"])
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        rules = work / "filters"
        rules.write_text("/advert.js$script\n")
        with (work / "proxy.log").open("w+") as log:
            process = subprocess.Popen(["mitm-adblock", "--mode", "tun:adtest0",
                                        "--set", f"confdir={work}", "--set", f"adblock_lists={rules}"],
                                       stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while not Path("/sys/class/net/adtest0").exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        log.seek(0)
                        self.fail(log.read() or "TUN did not appear")
                    time.sleep(0.02)
                subprocess.run(["ip", "link", "set", "dev", "adtest0", "up"], check=True)
                for family, local, remote, mask in (
                    ("-4", "192.0.2.1", "198.51.100.2", "/32"),
                    ("-6", "2001:db8:1::1", "2001:db8:2::2", "/128"),
                ):
                    options = ["nodad"] if family == "-6" else []
                    subprocess.run(["ip", family, "addr", "add", local + mask, "dev", "adtest0", *options], check=True)
                    subprocess.run(["ip", family, "route", "add", remote + mask, "dev", "adtest0", "src", local], check=True)
                    with self.subTest(family=family):
                        conn = http.client.HTTPConnection(remote, 80, timeout=5)
                        try:
                            conn.request("GET", "/advert.js", headers={"Host": "publisher.test", "Sec-Fetch-Dest": "script"})
                            reply = conn.getresponse()
                            self.assertEqual((reply.status, reply.read()), (204, b""))
                            conn.request("GET", "/cert/pem", headers={"Host": "mitm.it"})
                            reply = conn.getresponse()
                            self.assertEqual(reply.status, 200)
                            self.assertTrue(reply.read().startswith(b"-----BEGIN CERTIFICATE-----"))
                        finally:
                            conn.close()
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_redirect_uses_original_ipv4_destination(self):
        import socket
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.assertEqual(os.listdir("/sys/class/net"), ["lo"])
        observed = []

        class Origin(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                observed.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"publisher")

        origin = ThreadingHTTPServer(("127.0.0.2", 80), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        self.addCleanup(origin.server_close)
        self.addCleanup(origin.shutdown)
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        rules = work / "list"
        rules.write_text("/advert.js$script\n")
        proxy = subprocess.Popen(["mitm-adblock", "--mode", "transparent@127.0.0.1:8083",
                                  "--set", f"confdir={work}", "--set", f"adblock_lists={rules}"])
        self.addCleanup(lambda: (proxy.terminate(), proxy.wait(timeout=5)))
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", 8083), timeout=.1):
                    break
            except OSError:
                if time.monotonic() > deadline or proxy.poll() is not None:
                    self.fail("transparent listener failed to start")
                time.sleep(.025)
        # Only the synthetic client matches. The proxy can reach the loopback origin directly.
        rule = ["OUTPUT", "-s", "127.0.0.3", "-d", "127.0.0.2", "-p", "tcp",
                "--dport", "80", "-j", "REDIRECT", "--to-ports", "8083"]
        subprocess.run(["iptables", "-t", "nat", "-A", *rule], check=True)
        self.addCleanup(subprocess.run, ["iptables", "-t", "nat", "-D", *rule], check=True)
        for path, code, body in (("/advert.js", 204, b""), ("/article", 200, b"publisher")):
            conn = http.client.HTTPConnection("127.0.0.2", 80, timeout=5,
                                              source_address=("127.0.0.3", 0))
            try:
                conn.request("GET", path, headers={"Host": "publisher.test", "Sec-Fetch-Dest": "script"})
                reply = conn.getresponse()
                self.assertEqual((reply.status, reply.read()), (code, body))
            finally:
                conn.close()
        self.assertEqual(observed, ["/article"])
