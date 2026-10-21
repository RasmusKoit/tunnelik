//! Keeps `plugin.log` from growing forever: once it passes a limit, it becomes `plugin.log.1`
//! and a fresh file starts, so at most two limits' worth stays on disk.

use std::fs;
use std::io;
use std::path::Path;

/// Moves `path` aside as `<path>.1` when it is larger than `limit` bytes, replacing an older
/// `.1`. A missing file is fine.
pub fn rotate(path: &Path, limit: u64) -> io::Result<()> {
    let size = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if size <= limit {
        return Ok(());
    }
    let mut aside = path.as_os_str().to_owned();
    aside.push(".1");
    fs::rename(path, aside)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_only_past_the_limit() {
        let dir = std::env::temp_dir().join(format!("tunnelik-logfile-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("plugin.log");
        let aside = dir.join("plugin.log.1");

        rotate(&log, 10).unwrap();
        assert!(!log.exists(), "a missing log is left alone");

        fs::write(&log, b"short").unwrap();
        rotate(&log, 10).unwrap();
        assert_eq!(fs::read(&log).unwrap(), b"short");
        assert!(!aside.exists());

        fs::write(&log, b"longer than ten bytes").unwrap();
        rotate(&log, 10).unwrap();
        assert!(!log.exists());
        assert_eq!(fs::read(&aside).unwrap(), b"longer than ten bytes");

        fs::write(&log, b"second time around, also long").unwrap();
        rotate(&log, 10).unwrap();
        assert_eq!(
            fs::read(&aside).unwrap(),
            b"second time around, also long",
            "an older .1 is replaced"
        );

        fs::remove_dir_all(&dir).unwrap();
    }
}
