"""Loopback handshake tests for the image CI's isolated network namespace."""

import asyncio
import ipaddress
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from aioquic import tls
from aioquic.asyncio import connect, serve
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from mitmproxy.certs import CertStore

import tls_rejection_fallback


class PinMismatch(tls.Alert):
    description = tls.AlertDescription.certificate_unknown


@unittest.skipUnless(os.environ.get("FALLBACK_WIRE_TEST") == "1", "needs isolated loopback port 443")
class WireTest(unittest.IsolatedAsyncioTestCase):
    async def test_pinned_retry_and_filtering(self):
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        store = CertStore.from_store(work, "origin", 2048)
        sans = [x509.DNSName("service.test"), x509.DNSName("origin-only.test"), x509.DNSName("tcp.test"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        leaf = store.get_cert("service.test", sans)
        origin_cert = work / "origin-leaf.pem"
        origin_cert.write_bytes(leaf.cert.to_pem())
        origin_ca = work / "origin-ca-cert.pem"
        origin_key = work / "origin-ca.pem"
        tcp_config = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tcp_config.load_cert_chain(origin_cert, origin_key)
        quic_config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        quic_config.load_cert_chain(origin_cert, origin_key)

        async def respond(reader, writer):
            try:
                if await reader.read(4096):
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                    await writer.drain()
            finally:
                writer.close()

        tcp_server = await asyncio.start_server(respond, "127.0.0.1", 443, ssl=tcp_config)
        self.addCleanup(tcp_server.close)
        udp_server = await serve("127.0.0.1", 443, configuration=quic_config)
        self.addCleanup(udp_server.close)
        scripts = Path(tls_rejection_fallback.__file__).parent
        (work / "rules").write_text("/fixture-ad.js$script\n")
        log = self.enterContext((work / "proxy.log").open("w+"))
        proxy = await asyncio.create_subprocess_exec(
            "mitmdump", "--mode", "regular@127.0.0.1:18080",
            "--mode", "reverse:http3://127.0.0.1:443@127.0.0.1:18443",
            "--set", f"confdir={work}", "--set", f"adblock_lists={work}/rules",
            "--set", f"adblock_cache_dir={work}/cache", "--set", "upstream_cert=false",
            "--set", f"ssl_verify_upstream_trusted_ca={origin_ca}",
            "--set", "tls_fallback_tcp_bad_certificate=true", "--set", "tls_fallback_quic_to_tcp=true",
            "-s", str(scripts / "adblock_addon.py"), "-s", str(scripts / "tls_rejection_fallback.py"),
            stdout=log, stderr=log,
        )
        try:
            async with asyncio.timeout(10):
                while True:
                    if proxy.returncode is not None:
                        self.fail("Proxy exited during startup")
                    try:
                        _, writer = await asyncio.open_connection("127.0.0.1", 18080)
                    except OSError:
                        await asyncio.sleep(0.05)
                        continue
                    writer.close()
                    await writer.wait_closed()
                    break
            trust = work / "trust.pem"
            trust.write_bytes(origin_ca.read_bytes() + (work / "mitmproxy-ca-cert.pem").read_bytes())
            origin_pin = leaf.cert.to_cryptography().public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            verify_chain = tls.verify_certificate

            def verify_pin(**kwargs):
                verify_chain(**kwargs)
                actual = kwargs["certificate"].public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                if actual != origin_pin:
                    raise PinMismatch("unexpected server key")

            async def handshake(cafile):
                config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                           server_name="service.test", cafile=str(cafile))
                async with asyncio.timeout(5):
                    async with connect("127.0.0.1", 18443, configuration=config):
                        pass

            async def tcp_request(sni, verify_name):
                proc = await asyncio.create_subprocess_exec(
                    "openssl", "s_client", "-quiet", "-proxy", "127.0.0.1:18080",
                    "-connect", "127.0.0.1:443", "-servername", sni,
                    "-verify_hostname", verify_name, "-verify_return_error", "-CAfile", str(trust),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                request = (f"GET /fixture-ad.js HTTP/1.1\r\nHost: {sni}\r\n"
                           "Sec-Fetch-Dest: script\r\nConnection: close\r\n\r\n").encode("ascii")
                async with asyncio.timeout(5):
                    return await proc.communicate(request)

            # The untrusted CA alert from an unenrolled QUIC client must leave
            # TCP filtering in place. A pin mismatch with a trusted CA opens
            # a TCP window after QUIC finishes draining the failed handshake.
            with self.assertRaises(ConnectionError):
                await handshake(origin_ca)
            response, err = await tcp_request("service.test", "service.test")
            self.assertIn(b" 204 ", response, err)
            with patch.object(tls, "verify_certificate", verify_pin):
                with self.assertRaises(ConnectionError):
                    await handshake(trust)
                async with asyncio.timeout(5):
                    while True:
                        response, err = await tcp_request("service.test", "service.test")
                        if b" 200 OK" in response:
                            break
                        self.assertIn(b" 204 ", response, err)
                        await asyncio.sleep(0.1)
                with self.assertRaises(ConnectionError):
                    await handshake(trust)
            response, err = await tcp_request("service.test", "origin-only.test")
            self.assertIn(b" 200 OK", response, err)

            # A different hostname is still filtered. Only the origin leaf
            # has the second SAN. Test the opt-in TCP bad_certificate alert.
            response, err = await tcp_request("tcp.test", "tcp.test")
            self.assertIn(b" 204 ", response, err)
            _, err = await tcp_request("tcp.test", "origin-only.test")
            self.assertIn(b"hostname mismatch", err)
            response, err = await tcp_request("tcp.test", "origin-only.test")
            self.assertIn(b" 200 OK", response, err)
        except BaseException:
            log.seek(0)
            print(log.read())
            raise
        finally:
            if proxy.returncode is None:
                proxy.terminate()
            await proxy.wait()
