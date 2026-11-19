use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, Timelike};
use csv::{ReaderBuilder, StringRecord};
use mitm_adblock_policy::exact_url_key;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use super::{cache, download};

const HOST: &str = "threatfox-api.abuse.ch";
const MAX_EXPORT: u64 = 32 * 1024 * 1024;
const MAX_CSV: u64 = 192 * 1024 * 1024;
const MIN_CONFIDENCE: i64 = 75;
const MAX_AGE_SECONDS: i64 = 7 * 24 * 3600;
const MAX_CACHE_AGE: Duration = Duration::from_secs(MAX_AGE_SECONDS as u64);

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Indicators {
    pub(super) domains: HashSet<String>,
    pub(super) payload_urls: HashMap<String, i64>,
}

#[derive(Deserialize)]
struct CachedIndicators {
    domains: Vec<String>,
    payload_urls: HashMap<String, i64>,
}

pub(super) fn load(
    key_file: &Path,
    cache_dir: &Path,
    force: bool,
    update_interval: Duration,
    now: SystemTime,
) -> Indicators {
    let cached = cache_dir.join("threatfox.json");
    let mut fallback = Indicators::default();
    if let Some(age) = cache::age(&cached, now).filter(|age| *age <= MAX_CACHE_AGE)
        && let Ok(recent) = read_cache(&cached)
    {
        if !force && age < update_interval && !recent.domains.is_empty() {
            return recent;
        }
        fallback = recent;
    }

    if fallback.domains.is_empty() {
        let legacy = cache_dir.join("threatfox-domains.txt");
        if cache::age(&legacy, now).is_some_and(|age| age <= MAX_CACHE_AGE)
            && let Ok(domains) = read_domains(&legacy)
        {
            fallback = Indicators {
                domains,
                payload_urls: HashMap::new(),
            };
        }
    }

    match fetch(key_file) {
        Ok(indicators) => {
            if let Err(error) = write_cache(&cached, &indicators) {
                tracing::warn!(kind = ?error.kind(), "Could not cache ThreatFox");
            }
            tracing::info!(
                domains = indicators.domains.len(),
                payload_urls = indicators.payload_urls.len(),
                "Downloaded ThreatFox"
            );
            indicators
        }
        Err(error) => {
            // Keep the key-bearing URL and any archive-supplied error text out of logs.
            tracing::warn!(kind = ?error.kind(), using_cache = !fallback.domains.is_empty(), "ThreatFox refresh failed");
            fallback
        }
    }
}

fn fetch(key_file: &Path) -> io::Result<Indicators> {
    let mut data = Vec::new();
    File::open(key_file)?.take(257).read_to_end(&mut data)?;
    let key = ascii(&data)?.trim_ascii();
    if !(12..=256).contains(&key.len())
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(invalid("Invalid ThreatFox key file"));
    }
    let url = format!("https://{HOST}/v2/files/exports/{key}/full.csv.zip");
    let archive = download::export(&url, MAX_EXPORT)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs() as i64;
    read_export(&archive, now)
}

fn read_cache(path: &Path) -> io::Result<Indicators> {
    let bytes = fs::read(path)?;
    let cached: CachedIndicators = serde_json::from_str(ascii(&bytes)?)?;
    Ok(Indicators {
        domains: normalize_domains(cached.domains.iter().map(String::as_str)),
        payload_urls: cached.payload_urls,
    })
}

fn write_cache(path: &Path, indicators: &Indicators) -> io::Result<()> {
    #[derive(Serialize)]
    struct CacheData<'a> {
        domains: Vec<&'a str>,
        payload_urls: &'a HashMap<String, i64>,
    }

    let mut domains = indicators
        .domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    domains.sort_unstable();
    cache::replace(path, |file| {
        serde_json::to_writer(
            file,
            &CacheData {
                domains,
                payload_urls: &indicators.payload_urls,
            },
        )
        .map_err(Into::into)
    })
}

pub(super) fn read_domains(path: &Path) -> io::Result<HashSet<String>> {
    let bytes = fs::read(path)?;
    Ok(normalize_domains(ascii(&bytes)?.split(['\r', '\n'])))
}

fn ascii(bytes: &[u8]) -> io::Result<&str> {
    if bytes.is_ascii() {
        str::from_utf8(bytes).map_err(io::Error::other)
    } else {
        Err(invalid("Expected ASCII data"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn normalize_domains<'a>(domains: impl Iterator<Item = &'a str>) -> HashSet<String> {
    domains
        .filter_map(|domain| valid_domain(domain.trim()))
        .collect()
}

fn valid_domain(value: &str) -> Option<String> {
    let host = value.trim_end_matches('.');
    let (labels, suffix) = host.rsplit_once('.')?;
    if host.len() <= 253
        && (2..=63).contains(&suffix.len())
        && suffix.bytes().all(|byte| byte.is_ascii_alphabetic())
        && labels.split('.').all(valid_label)
    {
        Some(host.to_ascii_lowercase())
    } else {
        None
    }
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn read_export(data: &[u8], now: i64) -> io::Result<Indicators> {
    let mut archive = ZipArchive::new(Cursor::new(data)).map_err(io::Error::other)?;
    if archive.has_duplicate_names() {
        return Err(invalid("Duplicate file names in ThreatFox export"));
    }
    let index = {
        let mut files = archive
            .file_names_raw()
            .enumerate()
            .filter_map(|(index, name)| name.ends_with(b".csv").then_some(index));
        let Some(index) = files.next() else {
            return Err(invalid("Missing ThreatFox CSV"));
        };
        if files.next().is_some() {
            return Err(invalid("Multiple ThreatFox CSV files"));
        }
        index
    };

    let file = archive.by_index(index).map_err(io::Error::other)?;
    if file.size() > MAX_CSV {
        return Err(invalid("Oversized ThreatFox CSV"));
    }
    let mut limited = file.take(MAX_CSV + 1);
    let indicators = read_csv(BufReader::new(&mut limited), now)?;
    if limited.limit() == 0 {
        return Err(invalid("Oversized ThreatFox CSV"));
    }
    if indicators.domains.is_empty() {
        return Err(invalid("ThreatFox export contained no eligible domains"));
    }
    Ok(indicators)
}

fn read_csv(mut stream: impl BufRead, now: i64) -> io::Result<Indicators> {
    let mut line = String::new();
    let mut first_line = true;
    let fields = loop {
        if stream.read_line(&mut line)? == 0 {
            return Err(invalid("Missing ThreatFox CSV header"));
        }
        let content = if first_line {
            line.strip_prefix('\u{feff}').unwrap_or(&line)
        } else {
            &line
        };
        if content.starts_with('#') && content.contains("first_seen_utc") {
            let header = content.trim_start_matches(['#', ' ']).trim();
            break csv_reader(header.as_bytes())
                .records()
                .next()
                .transpose()
                .map_err(io::Error::other)?
                .ok_or_else(|| invalid("Empty ThreatFox CSV header"))?;
        }
        first_line = false;
        line.clear();
    };

    let field = |name| {
        fields
            .iter()
            .enumerate()
            .filter_map(|(index, value)| (value == name).then_some(index))
            .last()
            .ok_or_else(|| invalid("Missing ThreatFox fields"))
    };
    let columns = Columns {
        ioc_type: field("ioc_type")?,
        threat_type: field("threat_type")?,
        confidence: field("confidence_level")?,
        compromised: field("is_compromised")?,
        value: field("ioc_value")?,
        last_seen: field("last_seen_utc")?,
        first_seen: field("first_seen_utc")?,
    };
    let mut indicators = Indicators::default();
    let mut records = csv_reader(stream);
    let mut record = StringRecord::new();
    while records.read_record(&mut record).map_err(io::Error::other)? {
        columns.ingest(&record, now, &mut indicators);
    }
    Ok(indicators)
}

struct Columns {
    ioc_type: usize,
    threat_type: usize,
    confidence: usize,
    compromised: usize,
    value: usize,
    last_seen: usize,
    first_seen: usize,
}

impl Columns {
    fn ingest(&self, row: &StringRecord, now: i64, indicators: &mut Indicators) {
        let value = |index| row.get(index).unwrap_or_default();
        let ioc_type = value(self.ioc_type);
        let threat_type = value(self.threat_type);
        if !matches!(ioc_type, "domain" | "url")
            || !matches!(threat_type, "botnet_cc" | "payload_delivery")
            || !value(self.confidence)
                .trim()
                .parse::<i64>()
                .is_ok_and(|confidence| confidence >= MIN_CONFIDENCE)
        {
            return;
        }

        let compromised = value(self.compromised);
        let dedicated = compromised.eq_ignore_ascii_case("false") || compromised == "0";
        let indicator = value(self.value);
        match (ioc_type, threat_type, dedicated) {
            ("domain", _, true) => {
                if let Some(host) = valid_domain(indicator) {
                    indicators.domains.insert(host);
                }
            }
            ("url", "payload_delivery", _) => {
                let mut seen = value(self.last_seen);
                if seen.is_empty() {
                    seen = value(self.first_seen);
                }
                let Some(observed) = observed_at(seen) else {
                    return;
                };
                if !(0..MAX_AGE_SECONDS).contains(&now.saturating_sub(observed)) {
                    return;
                }
                let Some(url) = exact_url_key(indicator) else {
                    return;
                };
                // The canonical URL always has a path. A shared host's root
                // without a query is too broad to identify a payload.
                if !dedicated && url.splitn(4, '/').nth(3) == Some("") {
                    return;
                }
                let expiry = observed + MAX_AGE_SECONDS;
                indicators
                    .payload_urls
                    .entry(url)
                    .and_modify(|old| *old = expiry.max(*old))
                    .or_insert(expiry);
            }
            _ => {}
        }
    }
}

fn observed_at(value: &str) -> Option<i64> {
    let timestamp = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
        .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f"))
        .or_else(|_| DateTime::parse_from_rfc3339(value).map(|time| time.naive_local()))
        .or_else(|_| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .map(|date| date.and_hms_opt(0, 0, 0).expect("midnight is valid"))
        })
        .ok()?;
    // ThreatFox columns are UTC. The legacy parser also treated offset-tagged
    // values as UTC wall-clock time.
    if !(1..=9999).contains(&timestamp.year()) || timestamp.nanosecond() >= 1_000_000_000 {
        return None;
    }
    Some(timestamp.and_utc().timestamp())
}

fn csv_reader<R: BufRead>(stream: R) -> csv::Reader<SkipInitialSpace<R>> {
    ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(SkipInitialSpace {
            stream,
            field: Field::Start,
        })
}

#[derive(Clone, Copy)]
enum Field {
    Start,
    Unquoted,
    Quoted,
    AfterQuote,
}

// ThreatFox inserts spaces before opening quotes. Remove only spaces before
// fields so the CSV parser sees their quotes and preserves exact URL values.
struct SkipInitialSpace<R> {
    stream: R,
    field: Field,
}

impl<R: BufRead> Read for SkipInitialSpace<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < output.len() {
            let input = self.stream.fill_buf()?;
            if input.is_empty() {
                break;
            }
            let mut consumed = 0;
            for &byte in input {
                consumed += 1;
                if byte == b' ' && matches!(self.field, Field::Start) {
                    continue;
                }
                self.field = match (self.field, byte) {
                    (Field::Start | Field::AfterQuote, b'"') => Field::Quoted,
                    (Field::Quoted, b'"') => Field::AfterQuote,
                    (Field::Quoted, _) => Field::Quoted,
                    (_, b',' | b'\r' | b'\n') => Field::Start,
                    _ => Field::Unquoted,
                };
                output[written] = byte;
                written += 1;
                if written == output.len() {
                    break;
                }
            }
            self.stream.consume(consumed);
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    use super::*;

    const HEADER: &str = "# \"first_seen_utc\", \"last_seen_utc\", \"ioc_value\", \"ioc_type\", \"threat_type\", \"confidence_level\", \"is_compromised\"\r\n";

    fn zip(files: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for &(name, contents) in files {
            writer.start_file(name, options).unwrap();
            writer.write_all(contents.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn export_keeps_only_eligible_exact_indicators() {
        let report = format!(
            "\u{feff}# comments\n{HEADER}{}",
            r#""2001-01-01 00:00:00", "", "Dedicated.Test.", "domain", "botnet_cc", "90", "False"
"2025-05-01 00:00:00", "", "compromised.test", "domain", "botnet_cc", "90", "True"
"2025-05-01 00:00:00", "", "weak.test", "domain", "botnet_cc", "74", "False"
"2001-01-01 00:00:00", "2025-05-01 00:00:00", "https://SHARED.test:443/File?q=A,B#fragment", "url", "payload_delivery", "90", "True"
"2025-04-25 00:00:00", "", "https://shared.test/File?q=A,B", "url", "payload_delivery", "90", "True"
"2025-05-01 00:00:00", "", "https://shared.test/", "url", "payload_delivery", "90", "True"
"2025-05-01 00:00:00", "", "https://shared.test/?", "url", "payload_delivery", "75", "True"
"2025-05-01 00:00:00", "", "https://user:pass@shared.test/secret", "url", "payload_delivery", "90", "False"
"2025-05-01 00:00:00", "", "https://shared.test/c2", "url", "botnet_cc", "90", "False"
"2025-05-01 00:00:01", "", "https://shared.test/future", "url", "payload_delivery", "90", "False"
"2025-04-24 00:00:00", "", "https://shared.test/stale", "url", "payload_delivery", "90", "False"
"2025-04-24 00:00:01", "", "https://dedicated.test/root%2f", "url", "payload_delivery", "90", "False"
"#,
        );
        let now = observed_at("2025-05-01 00:00:00").unwrap();
        let snapshot = read_export(&zip(&[("sample.csv", &report)]), now).unwrap();
        assert_eq!(
            snapshot.domains,
            HashSet::from(["dedicated.test".to_owned()])
        );
        assert_eq!(
            snapshot.payload_urls,
            HashMap::from([
                (
                    "https://shared.test/File?q=A,B".to_owned(),
                    now + MAX_AGE_SECONDS
                ),
                ("https://shared.test/?".to_owned(), now + MAX_AGE_SECONDS),
                ("https://dedicated.test/root%2f".to_owned(), now + 1),
            ])
        );
    }

    #[test]
    fn invalid_export_layout_and_empty_indicators_are_rejected() {
        for archive in [
            zip(&[]),
            zip(&[("one.csv", HEADER), ("two.csv", HEADER)]),
            zip(&[("incomplete.csv", "# first_seen_utc\n")]),
            zip(&[("no_eligible_domains.csv", HEADER)]),
        ] {
            assert!(read_export(&archive, 0).is_err());
        }
    }

    #[test]
    fn threatfox_uses_compatible_json_and_recent_legacy_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let absent_key = path.join("absent-key");
        let cache = path.join("threatfox.json");
        let legacy = path.join("threatfox-domains.txt");
        fs::write(
            &cache,
            r#"{"domains": ["Cached.Test.", "two", "non\u00e0scii.test"], "payload_urls": {"https://cached.test/Payload?x=1": 1735689601}}"#,
        )
        .unwrap();
        fs::write(&legacy, "legacy.test").unwrap();

        let now = SystemTime::now();
        let indicators = load(&absent_key, path, true, Duration::ZERO, now);
        assert_eq!(
            indicators.domains,
            HashSet::from(["cached.test".to_owned()])
        );
        assert_eq!(
            indicators.payload_urls,
            HashMap::from([("https://cached.test/Payload?x=1".to_owned(), 1735689601)])
        );
        write_cache(&cache, &indicators).unwrap();
        assert_eq!(read_cache(&cache).unwrap(), indicators);

        let stale = now - MAX_CACHE_AGE - Duration::from_secs(1);
        File::open(&cache).unwrap().set_modified(stale).unwrap();
        let indicators = load(&absent_key, path, true, Duration::ZERO, now);
        assert_eq!(
            indicators.domains,
            HashSet::from(["legacy.test".to_owned()])
        );
        assert!(indicators.payload_urls.is_empty());

        File::open(legacy).unwrap().set_modified(stale).unwrap();
        assert_eq!(
            load(&absent_key, path, true, Duration::ZERO, now),
            Indicators::default()
        );
    }
}
