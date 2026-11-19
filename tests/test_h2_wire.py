"""Exercise TLS and multiplexed HTTP/2 on both sides of the native proxy."""

import asyncio
from contextlib import suppress
import os
from pathlib import Path
import socket
import ssl
import tempfile
import unittest

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded, StreamReset

from test_fallback_wire import origin_certificate


class Http2Wire(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        _, origin_ca, origin_cert, origin_key = origin_certificate(self.work)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.set_alpn_protocols(["h2"])
        tls.load_cert_chain(origin_cert, origin_key)
        self.origin_sni = []
        tls.set_servername_callback(lambda _ssl, name, _context: self.origin_sni.append(name))
        self.origin_requests = []
        self.origin_seen = asyncio.Event()
        origin = await asyncio.start_server(self.serve_origin, "127.0.0.1", 0, ssl=tls)
        self.addAsyncCleanup(origin.wait_closed)
        self.addCleanup(origin.close)
        self.origin_port = origin.sockets[0].getsockname()[1]
        self.proxy_port = await self.start_proxy(origin_ca)

    async def start_proxy(self, origin_ca):
        rules = self.work / "rules.txt"
        rules.write_text("/advert.js$script\n", encoding="ascii")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        log = self.enterContext((self.work / "proxy.log").open("w+", encoding="utf-8"))
        proxy = await asyncio.create_subprocess_exec(
            os.environ.get("MITM_ADBLOCK_BIN", "mitm-adblock"),
            "--mode", f"regular@127.0.0.1:{port}",
            "--set", f"confdir={self.work}",
            "--set", f"adblock_lists={rules}",
            "--set", "adblock_threatfox_key_file=",
            "--set", f"ssl_verify_upstream_trusted_ca={origin_ca}",
            stdout=log, stderr=log,
        )

        async def stop():
            if proxy.returncode is None:
                proxy.terminate()
                try:
                    await asyncio.wait_for(proxy.wait(), timeout=5)
                except TimeoutError:
                    proxy.kill()
                    await proxy.wait()

        self.addAsyncCleanup(stop)
        async with asyncio.timeout(10):
            while proxy.returncode is None:
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", port)
                except OSError:
                    await asyncio.sleep(0.025)
                    continue
                writer.close()
                await writer.wait_closed()
                return port
        log.seek(0)
        self.fail(log.read())

    async def serve_origin(self, reader, writer):
        connection = H2Connection(config=H2Configuration(client_side=False))
        alpn = writer.get_extra_info("ssl_object").selected_alpn_protocol()
        peer = writer.get_extra_info("peername")
        pending = {}
        connection.initiate_connection()
        writer.write(connection.data_to_send())
        try:
            while data := await reader.read(65535):
                for event in connection.receive_data(data):
                    if isinstance(event, RequestReceived):
                        headers = dict(event.headers)
                        pending[event.stream_id] = headers[b":path"]
                        self.origin_requests.append((alpn, peer, event.stream_id, headers))
                        self.origin_seen.set()
                # Keep the first response open until another request arrives on this connection.
                if len(pending) == 2:
                    for stream, path in pending.items():
                        connection.send_headers(stream, [(b":status", b"200")])
                        connection.send_data(stream, b"publisher " + path, end_stream=True)
                    pending.clear()
                writer.write(connection.data_to_send())
                await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()

    async def test_connect_multiplexes_allowed_streams_and_blocks_ad(self):
        async with asyncio.timeout(10):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
            self.addCleanup(writer.close)
            writer.write(
                f"CONNECT 127.0.0.1:{self.origin_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.origin_port}\r\n\r\n".encode("ascii")
            )
            await writer.drain()
            self.assertIn(b" 200 ", (await reader.readuntil(b"\r\n\r\n")).split(b"\r\n", 1)[0])

            tls = ssl.create_default_context(cafile=self.work / "mitmproxy-ca-cert.pem")
            tls.set_alpn_protocols(["h2"])
            await writer.start_tls(tls, server_hostname="service.test")
            self.assertEqual(writer.get_extra_info("ssl_object").selected_alpn_protocol(), "h2")

            connection = H2Connection()
            connection.initiate_connection()
            authority = f"service.test.:{self.origin_port}".encode("ascii")
            paths = [b"/asset/%2f?tag=A&tag=+&keep", b"/advert.js", b"/second.css"]

            def request(path, extra=()):
                stream = connection.get_next_available_stream_id()
                connection.send_headers(stream, [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", authority),
                    (b":path", path),
                    *extra,
                ], end_stream=True)
                writer.write(connection.data_to_send())
                return stream

            first = request(paths[0], [(b"authorization", b"Bearer synthetic-token")])
            blocked = request(paths[1], [(b"sec-fetch-dest", b"script")])
            await writer.drain()
            await self.origin_seen.wait()
            second = request(paths[2])
            await writer.drain()

            statuses = {}
            bodies = {stream: bytearray() for stream in (first, blocked, second)}
            ended = set()
            while len(ended) != len(bodies):
                data = await reader.read(65535)
                self.assertTrue(data, "proxy closed before sending all responses")
                for event in connection.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        statuses[event.stream_id] = dict(event.headers)[b":status"]
                    elif isinstance(event, DataReceived):
                        bodies[event.stream_id].extend(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        ended.add(event.stream_id)
                    elif isinstance(event, StreamReset):
                        self.fail(f"HTTP/2 stream {event.stream_id} reset with code {event.error_code}")
                writer.write(connection.data_to_send())
                await writer.drain()

        self.assertEqual(statuses, {first: b"200", blocked: b"204", second: b"200"})
        self.assertEqual(bodies, {first: b"publisher " + paths[0], blocked: b"", second: b"publisher " + paths[2]})
        self.assertEqual(set(self.origin_sni), {"service.test"})
        self.assertEqual(len(self.origin_requests), 2)
        one, two = self.origin_requests
        self.assertEqual([one[0], two[0]], ["h2", "h2"])
        self.assertEqual(one[1], two[1])
        self.assertNotEqual(one[2], two[2])
        self.assertEqual([observed[3][b":path"] for observed in (one, two)], [paths[0], paths[2]])
        self.assertEqual(one[3][b":authority"], authority)
        self.assertEqual(one[3][b"authorization"], b"Bearer synthetic-token")
