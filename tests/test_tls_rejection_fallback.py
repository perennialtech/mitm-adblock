import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aioquic.quic.connection import QuicConnectionState
from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.packet import QuicErrorCode, QuicFrameType
from aioquic.tls import AlertDescription, State
from mitmproxy import connection, exceptions, options, tls
from mitmproxy.addons.script import ScriptLoader
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.quic import ClientQuicLayer, QuicTlsData
from OpenSSL import SSL

import tls_rejection_fallback as fallback


def context(transport="tcp", client_ip="192.0.2.1", destination="192.0.2.2", port=443):
    client = connection.Client(peername=(client_ip, 50000), sockname=("127.0.0.1", 8080),
                               transport_protocol=transport)
    client.sni = "service.test"
    ctx = Context(client, options.Options())
    ctx.server.address = (destination, port)
    if transport == "udp":
        ClientQuicLayer(ctx, time=lambda: 0)
    return ctx


def hello(ctx, sni="service.test"):
    return tls.ClientHelloData(ctx, SimpleNamespace(sni=sni))


class FallbackTests(unittest.TestCase):
    def setUp(self):
        self.addon = fallback.CertificateRejectionFallback()
        self.options = options.Options()
        ScriptLoader().load(self.options)
        self.addon.load(self.options)
        self.enterContext(patch.object(fallback.ctx, "options", self.options, create=True))

    def mode(self, mode):
        self.options.tls_fallback_mode = mode
        self.addon.configure({"tls_fallback_mode"})

    def quic_failure(self, ctx, alert, *, state=State.SERVER_EXPECT_FINISHED,
                     frame=QuicFrameType.CRYPTO, resumed=False, reason="", draining=False):
        self.addon.quic_start_client(QuicTlsData(ctx.client, ctx))
        ctx.client.error = reason
        ctx.layers[-1].quic = SimpleNamespace(
            _state=QuicConnectionState.DRAINING if draining else QuicConnectionState.TERMINATED,
            tls=SimpleNamespace(state=state, session_resumed=resumed),
            _close_event=ConnectionTerminated(QuicErrorCode.CRYPTO_ERROR + alert, frame, reason),
        )
        if not draining:
            self.addon.tls_failed_client(QuicTlsData(ctx.client, ctx))

    def test_immediate_tcp_retry_after_received_quic_close(self):
        ctx = context("udp")
        self.quic_failure(ctx, AlertDescription.certificate_unknown, draining=True)
        self.assertFalse(self.addon.deadlines)
        retry = hello(context())
        self.addon.tls_clienthello(retry)
        self.assertTrue(retry.ignore_connection)
        self.assertFalse(self.addon.negotiating)

    def test_quic_retry_scope_expiry_and_fixed_deadline(self):
        with patch.object(fallback.time, "monotonic") as now:
            now.return_value = 10
            first = context("udp")
            self.quic_failure(first, AlertDescription.certificate_unknown, reason="pin mismatch")
            now.return_value = 129
            self.quic_failure(first, AlertDescription.access_denied)
            retry = context("tcp")
            retry.client.peername = (first.client.peername[0], 51000)
            matched = hello(retry, "Service.Test.")
            self.addon.tls_clienthello(matched)
            self.assertTrue(matched.ignore_connection)
            for other in (hello(context("udp")), hello(retry, "other.test"), hello(retry, None),
                          hello(context("tcp", client_ip="192.0.2.3")),
                          hello(context("tcp", destination="192.0.2.4")),
                          hello(context("tcp", port=8443))):
                self.addon.tls_clienthello(other)
                self.assertFalse(other.ignore_connection)
            now.return_value = 130
            self.assertFalse(self.addon._active(fallback.route(retry, "Service.Test.")))

    def test_quic_requires_certificate_stage_and_transport_close_code(self):
        ctx = context("udp")
        for alert, overrides in (
            (AlertDescription.user_canceled, {}),
            (AlertDescription.certificate_unknown, {"frame": None}),
            (AlertDescription.access_denied, {"state": State.SERVER_EXPECT_CLIENT_HELLO}),
            (AlertDescription.access_denied, {"state": State.SERVER_POST_HANDSHAKE}),
            (AlertDescription.access_denied, {"resumed": True}),
        ):
            with self.subTest(alert=alert, overrides=overrides):
                self.quic_failure(ctx, alert, reason="certificate unknown", **overrides)
                self.assertFalse(self.addon.deadlines)
        ctx.layers[-1].quic = None
        self.addon.tls_failed_client(QuicTlsData(ctx.client, ctx))
        self.addon.tls_failed_client(QuicTlsData(ctx.server, ctx))
        self.assertFalse(self.addon.deadlines)

    def test_profiles_clear_routes_and_honor_explicit_legacy_script(self):
        ctx = context("udp")
        self.assertEqual(self.options.tls_fallback_mode, "compatible")
        for profile in ("strict", "off"):
            self.mode("compatible")
            self.quic_failure(ctx, AlertDescription.bad_certificate)
            self.assertTrue(self.addon.deadlines)
            self.mode(profile)
            self.assertFalse(self.addon.deadlines)
            self.quic_failure(ctx, AlertDescription.certificate_unknown)
            self.assertFalse(self.addon.deadlines)
        with self.assertRaises(exceptions.OptionsError):
            self.mode("typo")

        self.mode("compatible")
        self.options.scripts = ["adblock_addon.py", "/conf/tls-rejection-fallback.py"]
        self.addon.configure({"scripts"})
        self.assertEqual(self.addon.mode, "off")
        self.options.scripts = ["adblock_addon.py"]
        self.addon.configure({"scripts"})
        self.assertEqual(self.addon.mode, "compatible")

    def test_upstream_failure_prevents_and_revokes_a_window(self):
        ctx = context("udp")
        self.quic_failure(ctx, AlertDescription.certificate_unknown)
        self.assertTrue(self.addon.deadlines)
        ctx.server.error = "Certificate verify failed"
        self.addon.tls_failed_server(QuicTlsData(ctx.server, ctx))
        self.quic_failure(ctx, AlertDescription.certificate_unknown)
        self.assertFalse(self.addon.deadlines)

        ctx = context()
        ctx.server.error = "Certificate verify failed"
        conn = Mock(spec=SSL.Connection)
        self.addon.tls_start_client(tls.TlsData(ctx.client, ctx, ssl_conn=conn))
        self.assertFalse(conn.method_calls)

    @unittest.skipUnless(hasattr(SSL.Connection, "set_info_callback"), "requires pyOpenSSL 25.2")
    def test_tcp_requires_inbound_fatal_alert_during_certificate_check(self):
        ctx = context()
        conn = Mock(spec=SSL.Connection)
        self.addon.tls_start_client(tls.TlsData(ctx.client, ctx, ssl_conn=conn))
        observe, = conn.set_info_callback.call_args.args
        fatal = 2 << 8
        observe(conn, SSL.SSL_CB_READ_ALERT, fatal | AlertDescription.access_denied)
        conn.get_state_string.return_value = b"SSLv3/TLS write certificate"
        observe(conn, SSL.SSL_CB_LOOP, 1)
        observe(conn, SSL.SSL_CB_WRITE_ALERT, fatal | AlertDescription.bad_certificate)
        observe(conn, SSL.SSL_CB_READ_ALERT, (1 << 8) | AlertDescription.bad_certificate)
        observe(conn, SSL.SSL_CB_READ_ALERT, fatal | AlertDescription.user_canceled)
        self.assertFalse(self.addon.deadlines)
        for alert in (AlertDescription.unknown_ca, AlertDescription.bad_certificate):
            observe(conn, SSL.SSL_CB_READ_ALERT, fatal | alert)
            self.assertTrue(self.addon.deadlines)
            self.addon.deadlines.clear()
        self.mode("strict")
        observe(conn, SSL.SSL_CB_READ_ALERT, fatal | AlertDescription.unknown_ca)
        observe(conn, SSL.SSL_CB_READ_ALERT, fatal | AlertDescription.bad_certificate)
        self.assertFalse(self.addon.deadlines)
        observe(conn, SSL.SSL_CB_READ_ALERT, fatal | AlertDescription.certificate_unknown)
        retry = hello(context())
        self.addon.tls_clienthello(retry)
        self.assertTrue(retry.ignore_connection)
        self.addon.deadlines.clear()
        self.mode("off")
        observe(conn, SSL.SSL_CB_READ_ALERT, fatal | AlertDescription.certificate_unknown)
        self.assertFalse(self.addon.deadlines)
        self.mode("compatible")
        observe(conn, SSL.SSL_CB_HANDSHAKE_DONE, 1)
        observe(conn, SSL.SSL_CB_READ_ALERT, fatal | AlertDescription.certificate_unknown)
        self.assertFalse(self.addon.deadlines)

    def test_cache_evicts_oldest_and_preserves_other_ignore_decisions(self):
        with patch.object(fallback, "MAX_ENTRIES", 2):
            for host in ("one.test", "two.test", "three.test"):
                ctx = context("udp")
                ctx.client.sni = host
                self.quic_failure(ctx, AlertDescription.access_denied)
            for host, expected in (("one.test", False), ("two.test", True), ("three.test", True)):
                self.assertEqual(self.addon._active(fallback.route(ctx, host)), expected)
            explicit = hello(ctx, "manual.test")
            explicit.ignore_connection = True
            self.addon.tls_clienthello(explicit)
            self.assertTrue(explicit.ignore_connection)
