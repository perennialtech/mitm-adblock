"""Relay fresh connections after a client explicitly rejects our certificate."""

from collections import OrderedDict
import logging
import time

from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.packet import QuicErrorCode
from aioquic.tls import AlertDescription, State
from mitmproxy import ctx, tls
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.quic import ClientQuicLayer, QuicTlsData
from OpenSSL import SSL

logger = logging.getLogger(__name__)
FALLBACK_SECONDS = 120
MAX_ENTRIES = 1024
REJECTION_ALERTS = {AlertDescription.certificate_unknown, AlertDescription.access_denied}

# Only TCP retries on destination port 443 can be relayed.
Route = tuple[str, str, str]


def route(context: Context, sni: str | None) -> Route | None:
    client, address = context.client, context.server.address
    if not client.peername or not sni or not address or address[1] != 443:
        return None
    return client.peername[0], address[0].lower().removesuffix("."), sni.lower().removesuffix(".")


def quic_rejection(data: QuicTlsData) -> int | None:
    # The failure hook exposes a free-form reason. Look up the numeric close
    # on the failing client layer, as mitmproxy itself does in receive_close.
    # Missing structured evidence on another library version means no fallback.
    layer = next((layer for layer in reversed(data.context.layers)
                  if isinstance(layer, ClientQuicLayer) and layer.conn is data.conn), None)
    quic = getattr(layer, "quic", None)
    handshake = getattr(quic, "tls", None)
    close = getattr(quic, "_close_event", None)
    if (getattr(handshake, "state", None) != State.SERVER_EXPECT_FINISHED
            or getattr(handshake, "session_resumed", True)
            or not isinstance(close, ConnectionTerminated)
            or close.frame_type is None):
        return None
    alert = close.error_code - QuicErrorCode.CRYPTO_ERROR
    return alert if alert in REJECTION_ALERTS else None


class CertificateRejectionFallback:
    def __init__(self) -> None:
        self.deadlines: OrderedDict[Route, float] = OrderedDict()

    def load(self, loader) -> None:
        loader.add_option("tls_fallback_tcp_bad_certificate", bool, False,
                          "Also relay after a TCP bad_certificate alert, which may indicate an untrusted CA.")
        loader.add_option("tls_fallback_quic_to_tcp", bool, False,
                          "Use an explicit QUIC certificate rejection to recognize a subsequent TCP retry.")

    def configure(self, updated) -> None:
        if {"tls_fallback_quic_to_tcp", "tls_fallback_tcp_bad_certificate"} & updated:
            self.deadlines.clear()

    def running(self) -> None:
        if not hasattr(SSL.Connection, "set_info_callback"):
            logger.warning("Learning from TCP certificate alerts requires pyOpenSSL >= 25.2")

    def _active(self, key: Route | None) -> bool:
        if key is None or key not in self.deadlines:
            return False
        if self.deadlines[key] > time.monotonic():
            return True
        del self.deadlines[key]
        return False

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        if (not data.context.server.error and data.context.client.transport_protocol == "tcp"
                and self._active(route(data.context, data.client_hello.sni))):
            data.ignore_connection = True

    def _remember(self, key: Route, alert: int, transport: str) -> None:
        now = time.monotonic()
        if self.deadlines.get(key, 0) > now:
            return
        self.deadlines[key] = now + FALLBACK_SECONDS
        self.deadlines.move_to_end(key)
        if len(self.deadlines) > MAX_ENTRIES:
            self.deadlines.popitem(last=False)
        logger.info("Certificate rejection fallback armed for %s (%s, alert %d, %ds)",
                    key[2], transport, alert, FALLBACK_SECONDS)

    def tls_start_client(self, data: tls.TlsData) -> None:
        key = route(data.context, data.context.client.sni)
        if (key is None or data.context.server.error or data.context.client.transport_protocol != "tcp"
                or not hasattr(SSL.Connection, "set_info_callback")):
            return
        # Script hooks run before tlsconfig. Keep its normal connection and
        # settings, then observe only alerts on this client-facing socket.
        if data.ssl_conn is None:
            ctx.master.addons.get("tlsconfig").tls_start_client(data)
        if data.ssl_conn is None:
            return
        checking_certificate = False
        server = data.context.server

        def observe(conn: SSL.Connection, where: int, value: int) -> None:
            nonlocal checking_certificate
            if where & SSL.SSL_CB_LOOP:
                state = conn.get_state_string()
                if state == b"SSLv3/TLS write certificate":
                    checking_certificate = True
                elif state == b"SSLv3/TLS read finished":
                    checking_certificate = False
            if where & SSL.SSL_CB_HANDSHAKE_DONE:
                checking_certificate = False
            received_alert = (where & SSL.SSL_CB_READ_ALERT) == SSL.SSL_CB_READ_ALERT
            if checking_certificate and received_alert and value >> 8 == 2 and not server.error:
                alert = value & 0xff
                if alert in REJECTION_ALERTS or (
                    alert == AlertDescription.bad_certificate and ctx.options.tls_fallback_tcp_bad_certificate
                ):
                    self._remember(key, alert, "tcp")

        data.ssl_conn.set_info_callback(observe)

    def tls_failed_client(self, data: tls.TlsData) -> None:
        if (not isinstance(data, QuicTlsData) or not ctx.options.tls_fallback_quic_to_tcp
                or data.context.server.error or data.conn is not data.context.client):
            return
        key = route(data.context, data.conn.sni)
        if key is not None and (alert := quic_rejection(data)) is not None:
            self._remember(key, alert, "quic")

    def tls_failed_server(self, data: tls.TlsData) -> None:
        if data.context.client.transport_protocol != "tcp" and not ctx.options.tls_fallback_quic_to_tcp:
            return
        key = route(data.context, data.context.client.sni)
        if key is not None:
            self.deadlines.pop(key, None)


addons = [CertificateRejectionFallback()]
