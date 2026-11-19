mod cache;
mod download;
mod threatfox;

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use curl::easy::Easy;
use sha1::{Digest, Sha1};

const SUPPLEMENT_PREFIX: &str = "supplement:";
const TIF_FULL: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt";
const TIF_MEDIUM: &str =
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt";

pub const DEFAULT_LISTS: &str = concat!(
    "https://easylist.to/easylist/easylist.txt,",
    "https://easylist.to/easylist/easyprivacy.txt,",
    "supplement:https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt,",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt,",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt,",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt,",
    "https://big.oisd.nl/,",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext,",
    "https://ublockorigin.github.io/uAssets/filters/badware.txt,",
    "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-online.txt",
);

#[derive(Clone, Debug)]
pub struct Config {
    pub lists: String,
    pub cache_dir: PathBuf,
    pub update_hours: u64,
    pub threatfox_key_file: Option<PathBuf>,
    pub threat_domains_file: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub primary: Vec<String>,
    pub supplemental: Vec<String>,
    pub domains: HashSet<String>,
    pub payload_urls: HashMap<String, i64>,
}

pub fn load(config: &Config, force: bool) -> io::Result<Snapshot> {
    let mut client: Option<Easy> = None;
    load_with(config, force, |source| {
        let client = match &mut client {
            Some(client) => client,
            None => client.insert(download::client(false)?),
        };
        download::list(client, source)
    })
}

fn load_with(
    config: &Config,
    force: bool,
    mut download_list: impl FnMut(&str) -> io::Result<Vec<u8>>,
) -> io::Result<Snapshot> {
    let cache_dir = expand_home(&config.cache_dir);
    let update_interval = Duration::from_secs(config.update_hours.saturating_mul(3600));
    let mut snapshot = Snapshot::default();

    for source in config.lists.split(',').map(str::trim) {
        let (supplemental, source) = match source.strip_prefix(SUPPLEMENT_PREFIX) {
            Some(source) => (true, source.trim()),
            None => (false, source),
        };
        if source.is_empty() {
            continue;
        }
        let text = if source.starts_with("https://") || source.starts_with("http://") {
            let cached = cached_list(&cache_dir, source);
            let fresh =
                cache::age(&cached, SystemTime::now()).is_some_and(|age| age < update_interval);
            let mut text = if fresh && !force {
                read_list(&cached)?
            } else {
                download_or_cached(source, &cached, &mut download_list)?
            };
            if source == TIF_FULL && text.as_ref().is_none_or(String::is_empty) {
                let previous = cached_list(&cache_dir, TIF_MEDIUM);
                if previous.is_file() {
                    text = read_list(&previous)?;
                    if text.as_ref().is_some_and(|list| !list.is_empty()) {
                        tracing::warn!("TIF Full unavailable; using the previous TIF Medium cache");
                    }
                }
            }
            text.filter(|text| !text.is_empty())
        } else {
            read_list(&expand_home(Path::new(source)))?
        };
        if let Some(text) = text {
            let lists = if supplemental {
                &mut snapshot.supplemental
            } else {
                &mut snapshot.primary
            };
            lists.push(text);
        }
    }

    if let Some(path) = configured_path(&config.threatfox_key_file) {
        let indicators =
            threatfox::load(&path, &cache_dir, force, update_interval, SystemTime::now());
        snapshot.domains = indicators.domains;
        snapshot.payload_urls = indicators.payload_urls;
    }
    if let Some(path) = configured_path(&config.threat_domains_file) {
        match threatfox::read_domains(&path) {
            Ok(domains) => snapshot.domains.extend(domains),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "Could not read local threat domains")
            }
        }
    }
    Ok(snapshot)
}

fn download_or_cached(
    source: &str,
    cached: &Path,
    download: &mut impl FnMut(&str) -> io::Result<Vec<u8>>,
) -> io::Result<Option<String>> {
    let uri = source.parse::<http::Uri>().ok();
    let host = uri.as_ref().and_then(http::Uri::host).unwrap_or("");
    match download(source) {
        Ok(bytes) => {
            let text = decode_list(bytes);
            if let Err(error) = cache::replace(cached, |file| file.write_all(text.as_bytes())) {
                tracing::warn!(host, kind = ?error.kind(), "Could not cache subscription");
            }
            tracing::info!(host, bytes = text.len(), "Downloaded subscription");
            Ok(Some(text))
        }
        Err(error) => {
            let fallback = read_list(cached)?;
            tracing::warn!(host, %error, using_cache = fallback.is_some(), "Subscription refresh failed");
            Ok(fallback)
        }
    }
}

fn configured_path(path: &Option<PathBuf>) -> Option<PathBuf> {
    path.as_deref()
        .filter(|path| !path.as_os_str().is_empty())
        .map(expand_home)
}

fn expand_home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(relative), Some(home)) => PathBuf::from(home).join(relative),
        _ => path.to_owned(),
    }
}

fn cached_list(cache_dir: &Path, source: &str) -> PathBuf {
    let digest = Sha1::digest(source.as_bytes());
    let mut filename = String::with_capacity(20);
    for byte in &digest[..8] {
        write!(filename, "{byte:02x}").expect("writing to a String cannot fail");
    }
    filename.push_str(".txt");
    cache_dir.join(filename)
}

fn decode_list(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

fn read_list(path: &Path) -> io::Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => {
            let text = decode_list(bytes);
            let text = if text.contains('\r') {
                text.replace("\r\n", "\n").replace('\r', "\n")
            } else {
                text
            };
            Ok(Some(text))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(cache_dir: &Path) -> Config {
        Config {
            lists: String::new(),
            cache_dir: cache_dir.to_owned(),
            update_hours: 24,
            threatfox_key_file: None,
            threat_domains_file: None,
        }
    }

    #[test]
    fn local_lists_preserve_order_and_separate_supplements() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let first = path.join("first.txt");
        let supplement = path.join("supplement.txt");
        let second = path.join("second.txt");
        let absent = path.join("absent.txt");
        let empty = path.join("empty.txt");
        let domains = path.join("domains.txt");
        fs::write(&first, "first\r\nrule\r").unwrap();
        fs::write(&supplement, b"extra\xff").unwrap();
        fs::write(&second, "second").unwrap();
        fs::write(&empty, "").unwrap();
        fs::write(&domains, "GOOD.Test...\r# comment\r_bad.test\n").unwrap();

        let mut config = config(path);
        config.lists = format!(
            " {},supplement: {}, {}, ,{},{}",
            first.display(),
            supplement.display(),
            absent.display(),
            empty.display(),
            second.display()
        );
        config.threat_domains_file = Some(domains);

        let snapshot = load(&config, false).unwrap();
        assert_eq!(snapshot.primary, ["first\nrule\n", "", "second"]);
        assert_eq!(snapshot.supplemental, ["extra\u{fffd}"]);
        assert_eq!(snapshot.domains, HashSet::from(["good.test".to_owned()]));
        assert!(snapshot.payload_urls.is_empty());
    }

    #[test]
    fn refresh_reuses_legacy_subscription_cache_names() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        config.lists = TIF_FULL.to_owned();
        let full = directory.path().join("ba7ed3a9fe2ce03c.txt");
        let medium = directory.path().join("f890b580bd23ead6.txt");
        fs::write(&full, "legacy full").unwrap();
        fs::write(&medium, "legacy medium").unwrap();

        let fresh = load_with(&config, false, |_| panic!("fresh cache")).unwrap();
        assert_eq!(fresh.primary, ["legacy full"]);

        let failed = |_: &str| Err(io::Error::other("simulated network failure"));
        let stale = load_with(&config, true, failed).unwrap();
        assert_eq!(stale.primary, ["legacy full"]);

        fs::remove_file(&full).unwrap();
        let fallback = load_with(&config, true, failed).unwrap();
        assert_eq!(fallback.primary, ["legacy medium"]);

        let refreshed = load_with(&config, true, |source| {
            assert_eq!(source, TIF_FULL);
            Ok(b"updated full".to_vec())
        })
        .unwrap();
        assert_eq!(refreshed.primary, ["updated full"]);
        assert_eq!(fs::read_to_string(&full).unwrap(), "updated full");
        assert_eq!(fs::read_to_string(&medium).unwrap(), "legacy medium");
    }
}
