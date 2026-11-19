"""Relay retries to the origin after a client rejects the proxy certificate."""

from collections import OrderedDict
from collections.abc import Callable
import logging
from pathlib import Path
import time
from weakref import WeakKeyDictionary

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnectionState
from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.packet import QuicErrorCode, encode_quic_version_negotiation, pull_quic_header
from aioquic.tls import AlertDescription, State
from mitmproxy import ctx, exceptions, tls
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layer import NextLayer
from mitmproxy.proxy.layers import UDPLayer
from mitmproxy.proxy.layers.quic import (
    ClientQuicLayer,
    QuicTlsData,
    quic_parse_client_hello_from_datagrams,
)
from OpenSSL import SSL

logger = logging.getLogger(__name__)
FALLBACK_SECONDS = 120
MAX_ENTRIES = 1024
QUIC_VERSIONS = QuicConfiguration(is_client=False).supported_versions
MODES = ("compatible", "strict", "off")
STRICT_ALERTS = {AlertDescription.certificate_unknown, AlertDescription.access_denied}
CERTIFICATE_ALERTS = STRICT_ALERTS | {
    AlertDescription.bad_certificate, AlertDescription.unknown_ca,
    AlertDescription.unsupported_certificate, AlertDescription.certificate_expired,
    AlertDescription.certificate_revoked,
}

# Client IP, original destination and SNI. Only web connections to port 443 qualify.
Route = tuple[str, str, str]


def endpoint(context: Context) -> tuple[str, str] | None:
    address = context.server.address
    if not context.client.peername or not address or address[1] != 443:
        return None
    return context.client.peername[0], address[0].lower().removesuffix(".")


def route(context: Context, sni: str | None) -> Route | None:
    peer = endpoint(context)
    return (*peer, sni.lower().removesuffix(".")) if peer and sni else None


class QuicRetry(NextLayer):
    """Decide on raw UDP while the original QUIC datagrams can still be relayed."""

    def __init__(self, context: Context, active: Callable[[Route | None], bool]):
        super().__init__(context)
        self.active = active

    def _ask(self):
        incoming = [e for e in self.events if isinstance(e, events.DataReceived)
                    and e.connection is self.context.client]
        packets = [e.data for e in incoming]
        # A ClientHello may span Initial datagrams. Bound the extra inspection
        # and let mitmproxy handle incomplete or unrecognized traffic normally.
        if packets and len(packets[0]) >= 1200 and sum(map(len, packets)) <= 65536:
            try:
                header = pull_quic_header(Buffer(data=packets[0]), host_cid_length=8)
                if header.version and header.version not in QUIC_VERSIONS:
                    # The version probe contains no readable SNI. Answer like
                    # mitmproxy and keep the new, supported Initial eligible.
                    self.events.remove(incoming[0])
                    reply = encode_quic_version_negotiation(
                        source_cid=header.destination_cid, destination_cid=header.source_cid,
                        supported_versions=QUIC_VERSIONS,
                    )
                    yield commands.SendData(self.context.client, reply)
                    return
                hello = quic_parse_client_hello_from_datagrams(packets)
            except (TypeError, ValueError):
                pass
            else:
                if hello is None and len(packets) < 8:
                    return
                if hello and self.active(route(self.context, hello.sni)):
                    self.layer = UDPLayer(self.context, ignore=True)
        yield from super()._ask()


def client_quic_layer(data: QuicTlsData) -> ClientQuicLayer | None:
    return next((layer for layer in reversed(data.context.layers)
                 if isinstance(layer, ClientQuicLayer) and layer.conn is data.context.client), None)


def quic_rejection(layer: ClientQuicLayer) -> int | None:
    # Read the numeric transport close on the client-facing layer. The hook's
    # free-form reason may omit the alert or describe a different error.
    quic = layer.quic
    handshake = getattr(quic, "tls", None)
    close = getattr(quic, "_close_event", None)
    if (getattr(handshake, "state", None) != State.SERVER_EXPECT_FINISHED
            or getattr(handshake, "session_resumed", True)
            or not isinstance(close, ConnectionTerminated)
            or close.frame_type is None):
        return None
    alert = close.error_code - QuicErrorCode.CRYPTO_ERROR
    return alert if alert in CERTIFICATE_ALERTS else None


class CertificateRejectionFallback:
    # The deployed standalone script registers a different addon under its class name.
    name = "adblock-certificate-fallback"

    def __init__(self) -> None:
        self.mode = "compatible"
        self.negotiating: WeakKeyDictionary[ClientQuicLayer, Route] = WeakKeyDictionary()
        self.deadlines: OrderedDict[Route, float] = OrderedDict()

    def load(self, loader) -> None:
        loader.add_option("tls_fallback_mode", str, "compatible",
                          "Automatic certificate fallback policy.", choices=MODES)

    def configure(self, updated) -> None:
        if not {"tls_fallback_mode", "scripts"} & updated:
            return
        mode = ctx.options.tls_fallback_mode
        if mode not in MODES:
            raise exceptions.OptionsError("tls_fallback_mode must be compatible, strict or off")
        if any(Path(script).name == "tls-rejection-fallback.py" for script in ctx.options.scripts):
            logger.info("Using the configured legacy TLS fallback script. Remove its -s argument "
                        "to use tls_fallback_mode.")
            mode = "off"
        if mode != self.mode:
            self.mode = mode
            self.deadlines.clear()
            self.negotiating.clear()

    def running(self) -> None:
        if self.mode != "off" and not hasattr(SSL.Connection, "set_info_callback"):
            logger.warning("Learning from TCP certificate alerts requires pyOpenSSL >= 25.2")

    def _active(self, key: Route | None) -> bool:
        if key is None or key not in self.deadlines:
            return False
        if self.deadlines[key] > time.monotonic():
            return True
        del self.deadlines[key]
        return False

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        if self.mode == "off" or data.context.server.error or data.context.client.transport_protocol != "tcp":
            return
        key = route(data.context, data.client_hello.sni)
        if key is not None:
            self._collect_draining(key[:2])
            if self._active(key):
                data.ignore_connection = True

    def next_layer(self, data: NextLayer) -> None:
        client = data.context.client
        if (self.mode != "compatible" or client.transport_protocol != "udp" or client.tls
                or data.layer or isinstance(data, QuicRetry) or data.context.server.error
                or not data.context.options.http3):
            return
        peer = endpoint(data.context)
        if peer is None:
            return
        self._collect_draining(peer)
        now = time.monotonic()
        if any(key[:2] == peer and expiry > now for key, expiry in self.deadlines.items()):
            data.layer = QuicRetry(data.context, self._active_quic)

    def _active_quic(self, key: Route | None) -> bool:
        # Policy can change between fragments of a ClientHello.
        return self.mode == "compatible" and self._active(key)

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
        if (self.mode == "off" or key is None or data.context.server.error
                or data.context.client.transport_protocol != "tcp"
                or not hasattr(SSL.Connection, "set_info_callback")):
            return
        # Script hooks run before tlsconfig. Keep its normal socket and observe
        # only the certificate phase on the client-facing side.
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
                if (self.mode == "compatible" and alert in CERTIFICATE_ALERTS
                        or self.mode == "strict" and alert in STRICT_ALERTS):
                    self._remember(key, alert, "tcp")

        data.ssl_conn.set_info_callback(observe)

    def quic_start_client(self, data: QuicTlsData) -> None:
        if self.mode != "compatible" or data.context.server.error:
            return
        key = route(data.context, data.conn.sni)
        layer = client_quic_layer(data)
        if key and layer is not None:
            self.negotiating[layer] = key
            if len(self.negotiating) > MAX_ENTRIES:
                del self.negotiating[next(iter(self.negotiating))]

    def _finish_quic(self, layer: ClientQuicLayer) -> None:
        key = self.negotiating.pop(layer, None)
        if key is not None and not layer.context.server.error:
            alert = quic_rejection(layer)
            if alert is not None:
                self._remember(key, alert, "quic")

    def _collect_draining(self, peer: tuple[str, str]) -> None:
        # A retry may arrive after the peer's transport close but before
        # aioquic finishes draining and mitmproxy emits tls_failed_client.
        for layer, key in list(self.negotiating.items()):
            if key[:2] == peer and getattr(layer.quic, "_state", None) == QuicConnectionState.DRAINING:
                self._finish_quic(layer)

    def tls_established_client(self, data: tls.TlsData) -> None:
        if isinstance(data, QuicTlsData) and (layer := client_quic_layer(data)) is not None:
            self.negotiating.pop(layer, None)

    def tls_failed_client(self, data: tls.TlsData) -> None:
        if isinstance(data, QuicTlsData) and data.conn is data.context.client:
            layer = client_quic_layer(data)
            if layer is not None:
                self._finish_quic(layer)

    def tls_failed_server(self, data: tls.TlsData) -> None:
        if (data.context.client.transport_protocol != "tcp"
                and (self.mode != "compatible" or not isinstance(data, QuicTlsData))):
            return
        key = route(data.context, data.context.client.sni)
        if key is not None:
            self.deadlines.pop(key, None)
