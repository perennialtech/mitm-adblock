use anyhow::{Context, Result, bail};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509Builder, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;

pub struct Authority {
    ca: X509,
    signer: PKey<Private>,
    leaf_key: PKey<Private>,
    cache: Mutex<HashMap<String, (Instant, Arc<CertifiedKey>)>>,
    pub public_pem: Vec<u8>,
    pub public_der: Vec<u8>,
}

fn key() -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

fn unsigned(name: &str, key: &PKey<Private>, days: u32) -> Result<X509Builder> {
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::ONE, false)?;
    let serial = Asn1Integer::from_bn(&serial)?;
    cert.set_serial_number(&serial)?;
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_nid(Nid::COMMONNAME, name)?;
    cert.set_subject_name(&subject.build())?;
    cert.set_pubkey(key)?;
    let start = Asn1Time::days_from_now(0)?;
    let end = Asn1Time::days_from_now(days)?;
    cert.set_not_before(&start)?;
    cert.set_not_after(&end)?;
    Ok(cert)
}

fn persist(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(dir.join(name))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

impl Authority {
    pub fn load(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let guard = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(".ca.lock"))?;
        fs2::FileExt::lock_exclusive(&guard)?;
        let path = dir.join("mitmproxy-ca.pem");
        let (ca, signer) = match fs::read(&path) {
            Ok(pem) => (X509::from_pem(&pem)?, PKey::private_key_from_pem(&pem)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if dir.join("mitmproxy-ca-cert.pem").exists() {
                    bail!(
                        "existing public CA is missing its private key in {}",
                        dir.display()
                    );
                }
                let signer = PKey::from_rsa(Rsa::generate(3072)?)?;
                let mut ca = unsigned("mitm-adblock", &signer, 3650)?;
                let mut subject = X509NameBuilder::new()?;
                subject.append_entry_by_nid(Nid::COMMONNAME, "mitm-adblock")?;
                ca.set_issuer_name(&subject.build())?;
                ca.append_extension(BasicConstraints::new().critical().ca().build()?)?;
                ca.append_extension(
                    KeyUsage::new()
                        .critical()
                        .key_cert_sign()
                        .crl_sign()
                        .build()?,
                )?;
                ca.append_extension(
                    SubjectKeyIdentifier::new().build(&ca.x509v3_context(None, None))?,
                )?;
                ca.sign(&signer, MessageDigest::sha256())?;
                let ca = ca.build();
                let mut pem = signer.private_key_to_pem_pkcs8()?;
                pem.extend(ca.to_pem()?);
                persist(dir, "mitmproxy-ca.pem", &pem)?;
                (ca, signer)
            }
            Err(e) => return Err(e.into()),
        };
        if !ca.public_key()?.public_eq(&signer) {
            bail!("CA key and certificate differ");
        }
        let public_pem = ca.to_pem()?;
        let public_der = ca.to_der()?;
        let public = dir.join("mitmproxy-ca-cert.pem");
        match fs::read(&public) {
            Ok(bytes) if X509::from_pem(&bytes)?.to_der()? != public_der => {
                bail!("public CA differs from signing CA")
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                persist(dir, "mitmproxy-ca-cert.pem", &public_pem)?
            }
            Err(e) => return Err(e.into()),
        }
        Ok(Self {
            ca,
            signer,
            leaf_key: key()?,
            cache: Mutex::default(),
            public_pem,
            public_der,
        })
    }

    pub fn certified_key(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let mut cache = self.cache.lock().unwrap();
        if let Some((renew_at, cert)) = cache.get(host)
            && *renew_at > Instant::now()
        {
            return Ok(cert.clone());
        }
        let ip = host.parse::<IpAddr>().is_ok();
        if !ip
            && (host.is_empty()
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)))
        {
            bail!("invalid certificate hostname");
        }
        let mut cert = unsigned(
            if host.len() <= 64 {
                host
            } else {
                "mitm-adblock"
            },
            &self.leaf_key,
            30,
        )?;
        cert.set_issuer_name(self.ca.subject_name())?;
        let mut san = SubjectAlternativeName::new();
        if ip {
            san.ip(host);
        } else {
            san.dns(host);
        }
        cert.append_extension(san.build(&cert.x509v3_context(Some(&self.ca), None))?)?;
        cert.append_extension(BasicConstraints::new().critical().build()?)?;
        cert.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        cert.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
        cert.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(false)
                .issuer(false)
                .build(&cert.x509v3_context(Some(&self.ca), None))?,
        )?;
        cert.sign(&self.signer, MessageDigest::sha256())?;
        let signing = rustls::crypto::ring::sign::any_supported_type(
            &PrivatePkcs8KeyDer::from(self.leaf_key.private_key_to_pkcs8()?).into(),
        )
        .context("load leaf key")?;
        let leaf = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert.build().to_der()?)],
            signing,
        ));
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(
            host.to_owned(),
            (
                Instant::now() + Duration::from_secs(7 * 24 * 3600),
                leaf.clone(),
            ),
        );
        Ok(leaf)
    }
}
