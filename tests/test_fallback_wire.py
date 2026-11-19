"""Loopback handshakes through the same addon entry point used by the image."""

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
from aioquic.quic.packet import QuicProtocolVersion
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from mitmproxy.certs import CertStore

import tls_rejection_fallback


class PinMismatch(tls.Alert):
    description = tls.AlertDescription.certificate_unknown


def public_key(cert):
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@unittest.skipUnless(os.environ.get("FALLBACK_WIRE_TEST") == "1", "needs isolated loopback port 443")
class WireTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        store = CertStore.from_store(self.work, "origin", 2048)
        sans = [x509.DNSName(name) for name in ("service.test", "origin-only.test", "tcp.test")]
        sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        leaf = store.get_cert("service.test", sans)
        self.origin_pin = public_key(leaf.cert.to_cryptography())
        origin_cert = self.work / "origin-leaf.pem"
        origin_cert.write_bytes(leaf.cert.to_pem())
        self.origin_ca = self.work / "origin-ca-cert.pem"
        origin_key = self.work / "origin-ca.pem"
        tcp_config = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tcp_config.load_cert_chain(origin_cert, origin_key)
        udp_config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        udp_config.load_cert_chain(origin_cert, origin_key)

        async def respond(reader, writer):
            try:
                if await reader.read(4096):
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                    await writer.drain()
            finally:
                writer.close()

        tcp_server = await asyncio.start_server(respond, "127.0.0.1", 443, ssl=tcp_config)
        self.addCleanup(tcp_server.close)
        udp_server = await serve("127.0.0.1", 443, configuration=udp_config)
        self.addCleanup(udp_server.close)
        (self.work / "rules").write_text("/fixture-ad.js$script\n")

    async def start_proxy(self, mode=None):
        script = Path(tls_rejection_fallback.__file__).with_name("adblock_addon.py")
        log = self.enterContext((self.work / "proxy.log").open("w+"))
        proc = await asyncio.create_subprocess_exec(
            "mitmdump", "--mode", "regular@127.0.0.1:18080",
            "--mode", "reverse:http3://127.0.0.1:443@127.0.0.1:18443",
            "--set", f"confdir={self.work}", "--set", f"adblock_lists={self.work}/rules",
            "--set", f"adblock_cache_dir={self.work}/cache", "--set", "upstream_cert=false",
            "--set", f"ssl_verify_upstream_trusted_ca={self.origin_ca}", "-s", str(script),
            *(["--set", f"tls_fallback_mode={mode}"] if mode else []), stdout=log, stderr=log,
        )

        async def stop():
            if proc.returncode is None:
                proc.terminate()
            await proc.wait()

        self.addAsyncCleanup(stop)
        async with asyncio.timeout(10):
            while True:
                if proc.returncode is not None:
                    log.seek(0)
                    self.fail(log.read())
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", 18080)
                except OSError:
                    await asyncio.sleep(0.05)
                    continue
                writer.close()
                await writer.wait_closed()
                break
        self.trust = self.work / "trust.pem"
        self.trust.write_bytes(self.origin_ca.read_bytes() + (self.work / "mitmproxy-ca-cert.pem").read_bytes())

    async def handshake(self, name="service.test", *, fragmented=False, local_port=0):
        offers = list(H3_ALPN)
        if fragmented:
            offers.extend(f"fixture-{n}-" + "x" * 180 for n in range(12))
        config = QuicConfiguration(is_client=True, alpn_protocols=offers,
                                   server_name=name, cafile=str(self.trust))
        if fragmented:
            # Exercise version negotiation before the supported, multi-packet hello.
            config.supported_versions = [0x0a0a0a0a, QuicProtocolVersion.VERSION_1]
        try:
            async with asyncio.timeout(5):
                async with connect("127.0.0.1", 18443, configuration=config, local_port=local_port) as client:
                    return public_key(client._quic.tls._peer_certificate)
        finally:
            # aioquic schedules the asyncio socket close for the next loop tick.
            await asyncio.sleep(0)

    async def tcp_request(self, name="service.test", *, cafile=None, verify_name=None):
        proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-quiet", "-proxy", "127.0.0.1:18080",
            "-connect", "127.0.0.1:443", "-servername", name,
            "-verify_hostname", verify_name or name, "-verify_return_error",
            "-CAfile", str(cafile or self.trust), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        request = (f"GET /fixture-ad.js HTTP/1.1\r\nHost: {name}\r\n"
                   "Sec-Fetch-Dest: script\r\nConnection: close\r\n\r\n").encode("ascii")
        async with asyncio.timeout(5):
            return await proc.communicate(request)

    async def test_default_recovers_pinned_http3_and_tcp(self):
        await self.start_proxy()
        verify_chain = tls.verify_certificate

        def verify_pin(**kwargs):
            verify_chain(**kwargs)
            if public_key(kwargs["certificate"]) != self.origin_pin:
                raise PinMismatch("unexpected server key")

        with patch.object(tls, "verify_certificate", verify_pin):
            with self.assertRaises(ConnectionError):
                await self.handshake()
            pin = await self.handshake(fragmented=True, local_port=15123)
            self.assertEqual(pin, self.origin_pin)
            # A new socket reusing this port can inherit the proxy's UDP flow.
            self.assertEqual(await self.handshake("tcp.test", local_port=15123), self.origin_pin)

        # A fresh UDP socket for the other hostname is still intercepted.
        self.assertNotEqual(await self.handshake("tcp.test"), self.origin_pin)
        response, err = await self.tcp_request(verify_name="origin-only.test")
        self.assertIn(b" 200 OK", response, err)
        response, err = await self.tcp_request("tcp.test")
        self.assertIn(b" 204 ", response, err)

    async def test_default_recovers_tcp_certificate_errors(self):
        await self.start_proxy()
        for sni, cafile, verify_name, error in (
            ("service.test", self.origin_ca, "service.test", b"certificate verify failed"),
            ("tcp.test", self.trust, "origin-only.test", b"hostname mismatch"),
        ):
            with self.subTest(sni=sni):
                response, err = await self.tcp_request(sni, cafile=cafile, verify_name=verify_name)
                self.assertNotIn(b" 200 ", response)
                self.assertIn(error, err)
                response, err = await self.tcp_request(sni, cafile=cafile, verify_name=verify_name)
                self.assertIn(b" 200 OK", response, err)

    async def test_strict_keeps_ambiguous_rejections_filtered(self):
        await self.start_proxy("strict")
        for _ in range(2):
            _, err = await self.tcp_request(verify_name="origin-only.test")
            self.assertIn(b"hostname mismatch", err)
        response, err = await self.tcp_request()
        self.assertIn(b" 204 ", response, err)
