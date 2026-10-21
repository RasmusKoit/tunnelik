//! Per-tunnel options that are not part of the WireGuard config. Nothing in here is secret, so
//! they sit in plain text as `tunnels\<name>.options` next to the encrypted config:
//!
//! ```text
//! keep-awake = true
//! ```
//!
//! A tunnel without the file has the defaults. Unknown keys are kept out of the way rather than
//! rejected, so an older version can read a file a newer one wrote.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::profile::validate_name;

const DIR: &str = "tunnels";
const EXTENSION: &str = ".options";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Hold the PC out of idle sleep while the tunnel carries traffic. The plugin decides what
    /// counts as traffic; see `BUSY_BYTES_PER_MINUTE` in `vpn`.
    pub keep_awake: bool,
}

pub fn encode(options: &Options) -> String {
    format!("keep-awake = {}\n", options.keep_awake)
}

pub fn decode(text: &str) -> Options {
    let mut options = Options::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "keep-awake" {
            options.keep_awake = value.trim() == "true";
        }
    }
    options
}

fn path(local_state: &Path, name: &str) -> Result<PathBuf, String> {
    validate_name(name)?;
    Ok(local_state.join(DIR).join(format!("{name}{EXTENSION}")))
}

/// The tunnel's options, or the defaults when it never had any set.
pub fn load(local_state: &Path, name: &str) -> Result<Options, String> {
    let path = path(local_state, name)?;
    match fs::read_to_string(&path) {
        Ok(text) => Ok(decode(&text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Options::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

pub fn save(local_state: &Path, name: &str, options: &Options) -> Result<(), String> {
    let path = path(local_state, name)?;
    fs::create_dir_all(local_state.join(DIR))
        .and_then(|()| fs::write(&path, encode(options)))
        .map_err(|e| format!("saving {}: {e}", path.display()))
}

pub fn remove(local_state: &Path, name: &str) -> Result<(), String> {
    let path = path(local_state, name)?;
    match fs::remove_file(&path) {
        Err(e) if e.kind() != ErrorKind::NotFound => {
            Err(format!("deleting {}: {e}", path.display()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for keep_awake in [false, true] {
            let options = Options { keep_awake };
            assert_eq!(decode(&encode(&options)), options);
        }
    }

    #[test]
    fn tolerates_other_files() {
        assert_eq!(decode(""), Options::default());
        assert_eq!(decode("keep-awake = yes\n"), Options::default());
        assert_eq!(
            decode("# comment\nfrom-the-future = 1\n keep-awake=true \r\n"),
            Options { keep_awake: true }
        );
    }

    #[test]
    fn load_save_remove() {
        let dir = std::env::temp_dir().join(format!("tunnelik-options-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(load(&dir, "Home").unwrap(), Options::default());
        save(&dir, "Home", &Options { keep_awake: true }).unwrap();
        assert_eq!(load(&dir, "Home").unwrap(), Options { keep_awake: true });
        remove(&dir, "Home").unwrap();
        remove(&dir, "Home").unwrap();
        assert_eq!(load(&dir, "Home").unwrap(), Options::default());
        assert!(load(&dir, "..\\evil").is_err());

        fs::remove_dir_all(&dir).unwrap();
    }
}
