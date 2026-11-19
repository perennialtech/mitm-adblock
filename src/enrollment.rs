use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::pkey::{Id, PKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{ErrorKind, Write},
    path::Path,
};
use tempfile::NamedTempFile;

#[derive(Deserialize, Serialize)]
struct Enrollment {
    server_key: String,
    client_key: String,
}

pub fn initialize(path: &Path) -> Result<()> {
    if path.try_exists()? {
        return Ok(());
    }
    let dir = path.parent().context("invalid WireGuard config path")?;
    fs::create_dir_all(dir)?;
    let key =
        || -> Result<String> { Ok(STANDARD.encode(PKey::generate_x25519()?.raw_private_key()?)) };
    let mut file = NamedTempFile::new_in(dir)?;
    serde_json::to_writer(
        file.as_file_mut(),
        &Enrollment {
            server_key: key()?,
            client_key: key()?,
        },
    )?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => {
            fs::File::open(dir)?.sync_all()?;
            Ok(())
        }
        Err(e) if e.error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn profile(path: &Path, endpoint: &str) -> Result<String> {
    let target = endpoint
        .parse::<http::uri::Authority>()
        .context("expected a WireGuard host:port")?;
    ensure!(
        target.port_u16().is_some() && !target.as_str().contains('@'),
        "expected a WireGuard host:port"
    );
    initialize(path)?;
    let keys: Enrollment = serde_json::from_slice(&fs::read(path)?)
        .context("this configuration requires a separately managed client profile")?;
    let server = PKey::private_key_from_raw_bytes(&STANDARD.decode(keys.server_key)?, Id::X25519)?;
    ensure!(
        STANDARD.decode(&keys.client_key)?.len() == 32,
        "invalid WireGuard client key"
    );
    let public = STANDARD.encode(server.raw_public_key()?);
    Ok(format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.1/32\nDNS = 10.0.0.53\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0\n",
        keys.client_key, public, target
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_enrollment_preserves_peer_and_uses_public_server_key() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("wireguard.conf");
        let first = profile(&path, "[::1]:51820")?;
        let json = fs::read(&path)?;
        assert_eq!(profile(&path, "[::1]:51820")?, first);
        assert_eq!(fs::read(&path)?, json);
        let keys: Enrollment = serde_json::from_slice(&json)?;
        assert!(!first.contains(&keys.server_key));
        assert!(first.contains(&keys.client_key));
        assert!(profile(&path, "example.test").is_err());
        Ok(())
    }
}
