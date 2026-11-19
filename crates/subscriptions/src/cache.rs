use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tempfile::NamedTempFile;

pub(super) fn age(path: &Path, now: SystemTime) -> Option<Duration> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    Some(now.duration_since(modified).unwrap_or_default())
}

pub(super) fn replace(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory)?;
    let mut file = NamedTempFile::new_in(directory)?;
    write(file.as_file_mut())?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn incomplete_update_keeps_previous_cache() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("cache");
        fs::write(&file, "old snapshot").unwrap();
        assert!(
            replace(&file, |temporary| {
                temporary.write_all(b"partial snapshot")?;
                Err(io::Error::other("simulated write failure"))
            })
            .is_err()
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), "old snapshot");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
