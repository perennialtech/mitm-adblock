use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::BytesMut;
use quinn::{
    ConnectionId, Side,
    crypto::{
        CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, ServerConfig,
        Session, UnsupportedVersion, rustls::QuicServerConfig,
    },
};
use quinn_proto::{TransportError, transport_parameters::TransportParameters};

/// Retain which encryption level authenticated the most recent incoming packet.
/// Quinn surfaces a remote transport close without its encryption level.
pub(super) struct ServerCrypto {
    inner: Arc<QuicServerConfig>,
    pub authenticated_handshake: Arc<AtomicBool>,
}

impl ServerCrypto {
    pub fn new(inner: QuicServerConfig, authenticated_handshake: Arc<AtomicBool>) -> Self {
        Self {
            inner: Arc::new(inner),
            authenticated_handshake,
        }
    }
}

impl ServerConfig for ServerCrypto {
    fn initial_keys(&self, version: u32, dcid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        self.inner.initial_keys(version, dcid)
    }

    fn retry_tag(&self, version: u32, dcid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, dcid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        Box::new(ObservedSession {
            inner: self.inner.clone().start_session(version, params),
            authenticated_handshake: self.authenticated_handshake.clone(),
            next_keys_are_handshake: true,
        })
    }
}

struct ObservedSession {
    inner: Box<dyn Session>,
    authenticated_handshake: Arc<AtomicBool>,
    next_keys_are_handshake: bool,
}

impl ObservedSession {
    fn observe(&self, keys: Keys, handshake: bool) -> Keys {
        Keys {
            header: keys.header,
            packet: KeyPair {
                local: keys.packet.local,
                remote: Box::new(ObservedKey {
                    inner: keys.packet.remote,
                    authenticated_handshake: self.authenticated_handshake.clone(),
                    handshake,
                }),
            },
        }
    }
}

impl Session for ObservedSession {
    fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> Keys {
        self.observe(self.inner.initial_keys(dcid, side), false)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = self.inner.write_handshake(buf)?;
        let handshake = std::mem::take(&mut self.next_keys_are_handshake);
        Some(self.observe(keys, handshake))
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, dcid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(dcid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

struct ObservedKey {
    inner: Box<dyn PacketKey>,
    authenticated_handshake: Arc<AtomicBool>,
    handshake: bool,
}

impl PacketKey for ObservedKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        self.inner.encrypt(packet, buf, header_len);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        self.inner.decrypt(packet, header, payload)?;
        self.authenticated_handshake
            .store(self.handshake, Ordering::Release);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.inner.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.inner.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.inner.integrity_limit()
    }
}
