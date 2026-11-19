use crate::config::Mode;
use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

struct Entry {
    peer: IpAddr,
    dest: String,
    sni: String,
    until: Instant,
}
pub struct Fallback {
    mode: Mode,
    entries: Mutex<VecDeque<Entry>>,
}

impl Fallback {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            entries: Mutex::default(),
        }
    }

    pub fn active(&self, peer: IpAddr, dest: &str, sni: &str, udp: bool) -> bool {
        if self.mode == Mode::Off || (udp && self.mode != Mode::Compatible) {
            return false;
        }
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        while entries.front().is_some_and(|e| e.until <= now) {
            entries.pop_front();
        }
        entries.iter().any(|e| {
            e.peer == peer
                && e.dest.eq_ignore_ascii_case(dest)
                && e.sni.eq_ignore_ascii_case(sni.trim_end_matches('.'))
        })
    }

    pub fn forget(&self, peer: IpAddr, dest: &str, sni: &str) {
        self.entries.lock().unwrap().retain(|entry| {
            !(entry.peer == peer
                && entry.dest.eq_ignore_ascii_case(dest)
                && entry.sni.eq_ignore_ascii_case(sni.trim_end_matches('.')))
        });
    }

    pub fn rejected(&self, peer: IpAddr, dest: &str, sni: &str, alert: u8, udp: bool) {
        if (udp && self.mode != Mode::Compatible)
            || !dest.ends_with(":443")
            || sni.is_empty()
            || !match self.mode {
                Mode::Compatible => matches!(alert, 42..=46 | 48 | 49),
                Mode::Strict => matches!(alert, 46 | 49),
                Mode::Off => false,
            }
        {
            return;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap();
        let name = sni.trim_end_matches('.');
        if entries.iter().any(|e| {
            e.until > now
                && e.peer == peer
                && e.dest.eq_ignore_ascii_case(dest)
                && e.sni.eq_ignore_ascii_case(name)
        }) {
            return;
        }
        if entries.len() == 1024 {
            entries.pop_front();
        }
        entries.push_back(Entry {
            peer,
            dest: dest.to_owned(),
            sni: name.to_owned(),
            until: now + Duration::from_secs(120),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retries_are_scoped_expire_and_can_be_revoked_on_origin_failure() {
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        let dest = "192.0.2.55:443";
        let fallback = Fallback::new(Mode::Compatible);
        fallback.rejected(peer, dest, "Service.Test.", 46, true);
        assert!(fallback.active(peer, dest, "service.test", false));
        let until = fallback.entries.lock().unwrap()[0].until;
        fallback.rejected(peer, dest, "service.test", 46, false);
        assert_eq!(fallback.entries.lock().unwrap()[0].until, until);
        assert!(!fallback.active(peer, dest, "other.test", true));
        assert!(!fallback.active("192.0.2.11".parse().unwrap(), dest, "service.test", true));
        assert!(!fallback.active(peer, "192.0.2.55:8443", "service.test", true));
        fallback.forget(peer, dest, "service.test");
        assert!(!fallback.active(peer, dest, "service.test", false));
        fallback.rejected(peer, dest, "service.test", 48, false);
        fallback.entries.lock().unwrap()[0].until = Instant::now();
        assert!(!fallback.active(peer, dest, "service.test", false));
    }
}
