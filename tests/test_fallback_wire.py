"""Loopback handshakes and HTTP/3 through the proxy executable used by the image."""

import asyncio
from datetime import datetime, timedelta, timezone
from functools import partial
import ipaddress
import os
from pathlib import Path
import ssl
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from aioquic import tls
from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class PinMismatch(tls.Alert):
    description = tls.AlertDescription.certificate_unknown


def public_key(cert):
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def origin_certificate(work):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loopback origin CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service.test")])
    now = datetime.now(timezone.utc)

    def certificate(subject, subject_key):
        return (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_name)
                .public_key(subject_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=7)))

    ca = (certificate(ca_name, ca_key)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    names = [x509.DNSName(name) for name in ("service.test", "origin-only.test", "tcp.test")]
    names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    leaf = (certificate(leaf_name, leaf_key)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    origin_ca = work / "origin-ca-cert.pem"
    origin_cert = work / "origin-leaf.pem"
    origin_key = work / "origin-leaf-key.pem"
    origin_ca.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    origin_cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    origin_key.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return leaf, origin_ca, origin_cert, origin_key


class OriginH3(QuicConnectionProtocol):
    def __init__(self, *args, observed, connections, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.observed = observed
        connections.append(self)
        self.streams = {}

    def quic_event_received(self, event):
        for frame in self.h3.handle_event(event):
            if isinstance(frame, HeadersReceived) and frame.stream_id not in self.streams:
                path = dict(frame.headers)[b":path"]
                self.observed.append(path)
                self.streams[frame.stream_id] = (path, bytearray())
            if isinstance(frame, DataReceived):
                self.streams[frame.stream_id][1].extend(frame.data)
            if isinstance(frame, (HeadersReceived, DataReceived)) and frame.stream_ended:
                path, data = self.streams.pop(frame.stream_id)
                body = bytes(data) if path == b"/echo" else b"OK"
                self.h3.send_headers(frame.stream_id, [
                    (b":status", b"200"),
                    (b"content-type", b"application/octet-stream"),
                ])
                self.h3.send_data(frame.stream_id, body, end_stream=False)
                self.h3.send_headers(frame.stream_id, [(b"x-origin-trailer", b"yes")], end_stream=True)
                self.transmit()


class ClientH3(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.responses = {}

    async def request(self, name, path, body):
        stream = self._quic.get_next_available_stream_id()
        result = asyncio.get_running_loop().create_future()
        self.responses[stream] = SimpleNamespace(headers={}, trailers={}, data=bytearray(), result=result)
        self.h3.send_headers(stream, [
            (b":method", b"POST" if body else b"GET"),
            (b":scheme", b"https"),
            (b":authority", name.encode("ascii")),
            (b":path", path.encode("ascii")),
            (b"sec-fetch-dest", b"script"),
        ], end_stream=not body)
        if body:
            self.h3.send_data(stream, body, end_stream=True)
        self.transmit()
        try:
            return await result
        finally:
            self.responses.pop(stream)

    def quic_event_received(self, event):
        for frame in self.h3.handle_event(event):
            if isinstance(frame, (HeadersReceived, DataReceived)):
                response = self.responses.get(frame.stream_id)
                if response is None or response.result.done():
                    continue
                if isinstance(frame, HeadersReceived):
                    headers = dict(frame.headers)
                    if b":status" in headers:
                        response.headers = headers
                    else:
                        response.trailers = headers
                else:
                    response.data.extend(frame.data)
                if frame.stream_ended:
                    response.result.set_result((
                        int(response.headers[b":status"]), bytes(response.data), response.trailers,
                    ))


@unittest.skipUnless(os.environ.get("FALLBACK_WIRE_TEST") == "1", "needs isolated loopback port 443")
class WireTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        leaf, self.origin_ca, origin_cert, origin_key = origin_certificate(self.work)
        self.origin_pin = public_key(leaf)
        self.observed = []
        self.origin_connections = []
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
        self.udp_config = udp_config
        udp_server = await self.start_origin_h3(443)
        self.addCleanup(udp_server.close)
        (self.work / "rules").write_text("/fixture-ad.js$script\n")

    async def start_origin_h3(self, port):
        return await serve(
            "127.0.0.1", port, configuration=self.udp_config,
            create_protocol=partial(
                OriginH3, observed=self.observed, connections=self.origin_connections,
            ),
        )

    async def start_proxy(self, mode=None, origin_port=443):
        log = self.enterContext((self.work / "proxy.log").open("w+"))
        proc = await asyncio.create_subprocess_exec(
            os.environ.get("MITM_ADBLOCK_BIN", "mitm-adblock"),
            "--mode", "regular@127.0.0.1:18080",
            "--mode", f"reverse:http3://127.0.0.1:{origin_port}@127.0.0.1:18443",
            "--set", f"confdir={self.work}", "--set", f"adblock_lists={self.work}/rules",
            "--set", f"adblock_cache_dir={self.work}/cache", "--set", "upstream_cert=false",
            "--set", f"ssl_verify_upstream_trusted_ca={self.origin_ca}",
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

    async def test_tcp_rejection_allows_http3_retry_for_same_name(self):
        await self.start_proxy()
        response, err = await self.tcp_request(cafile=self.origin_ca)
        self.assertNotIn(b" 200 ", response)
        self.assertIn(b"certificate verify failed", err)
        self.assertEqual(await self.handshake(), self.origin_pin)
        self.assertNotEqual(await self.handshake("tcp.test"), self.origin_pin)

    async def test_strict_keeps_ambiguous_rejections_filtered(self):
        await self.start_proxy("strict")
        for _ in range(2):
            _, err = await self.tcp_request(verify_name="origin-only.test")
            self.assertIn(b"hostname mismatch", err)
        response, err = await self.tcp_request()
        self.assertIn(b" 204 ", response, err)

    async def h3_request(self, path, *, name="service.test", body=b""):
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                   server_name=name, cafile=str(self.trust))
        async with asyncio.timeout(5):
            async with connect("127.0.0.1", 18443, configuration=config,
                               create_protocol=ClientH3) as client:
                return await client.request(name, path, body)

    async def test_http3_forwards_h3_only_origin_and_filters(self):
        origin = await self.start_origin_h3(0)
        self.addCleanup(origin.close)
        port = origin._transport.get_extra_info("sockname")[1]
        await self.start_proxy(origin_port=port)
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                   server_name="service.test", cafile=str(self.trust))
        async with asyncio.timeout(8):
            async with connect("127.0.0.1", 18443, configuration=config,
                               create_protocol=ClientH3) as client:
                self.assertEqual(await client.request("service.test", "/fixture-ad.js", b""),
                                 (204, b"", {}))
                self.assertEqual(self.observed, [])
                self.assertEqual(self.origin_connections, [])
                body = b"request body" * 2048
                echo, page = await asyncio.gather(
                    client.request("service.test", "/echo", body),
                    client.request("service.test", "/page", b""),
                )
                self.assertEqual(echo[0], 200)
                self.assertEqual(len(echo[1]), len(body))
                self.assertEqual(echo[1], body)
                self.assertEqual(echo[2], {b"x-origin-trailer": b"yes"})
                self.assertEqual(page, (200, b"OK", {b"x-origin-trailer": b"yes"}))
                self.assertCountEqual(self.observed, [b"/echo", b"/page"])
                self.assertEqual(len(self.origin_connections), 1)

                # Closing one origin leaves the established downstream client
                # available for its next request.
                closed = self.origin_connections[0]
                closed.close(error_code=0x100)
                await closed.wait_closed()
                self.assertEqual(await client.request("service.test", "/new", b""),
                                 (200, b"OK", {b"x-origin-trailer": b"yes"}))
                self.assertEqual(len(self.origin_connections), 2)

        self.assertEqual(await self.h3_request("/page", name="unknown-origin.test"), (502, b"", {}))
        self.assertCountEqual(self.observed, [b"/echo", b"/page", b"/new"])

    async def test_strict_never_learns_from_http3(self):
        await self.start_proxy("strict")
        verify_chain = tls.verify_certificate

        def verify_pin(**kwargs):
            verify_chain(**kwargs)
            if public_key(kwargs["certificate"]) != self.origin_pin:
                raise PinMismatch("unexpected server key")

        with patch.object(tls, "verify_certificate", verify_pin):
            for _ in range(2):
                with self.assertRaises(ConnectionError):
                    await self.handshake()
        response, err = await self.tcp_request()
        self.assertIn(b" 204 ", response, err)
