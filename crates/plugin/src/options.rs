//! Per-tunnel options that are not part of the WireGuard config. Nothing in here is secret, so
//! they sit in plain text as `tunnels\<name>.options` next to the encrypted config:
//!
//! ```text
//! keep-awake = true
//! always-on = false
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
    /// A copy of the VPN profile's always-on flag, so the plugin can tell a redial by Windows
    /// from one the user asked for. The profile is the truth; the tools keep this in step.
    pub always_on: bool,
}

pub fn encode(options: &Options) -> String {
    format!(
        "keep-awake = {}\nalways-on = {}\n",
        options.keep_awake, options.always_on
    )
}

pub fn decode(text: &str) -> Options {
    let mut options = Options::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let on = value.trim() == "true";
        match key.trim() {
            "keep-awake" => options.keep_awake = on,
            "always-on" => options.always_on = on,
            _ => {}
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
            for always_on in [false, true] {
                let options = Options {
                    keep_awake,
                    always_on,
                };
                assert_eq!(decode(&encode(&options)), options);
            }
        }
    }

    #[test]
    fn tolerates_other_files() {
        assert_eq!(decode(""), Options::default());
        assert_eq!(decode("keep-awake = yes\n"), Options::default());
        assert_eq!(
            decode("# comment\nfrom-the-future = 1\n keep-awake=true \r\n"),
            Options {
                keep_awake: true,
                always_on: false
            }
        );
        // A file from before always-on existed.
        assert!(!decode("keep-awake = true\n").always_on);
    }

    #[test]
    fn load_save_remove() {
        let dir = std::env::temp_dir().join(format!("tunnelik-options-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let on = Options {
            keep_awake: true,
            always_on: false,
        };
        assert_eq!(load(&dir, "Home").unwrap(), Options::default());
        save(&dir, "Home", &on).unwrap();
        assert_eq!(load(&dir, "Home").unwrap(), on);
        remove(&dir, "Home").unwrap();
        remove(&dir, "Home").unwrap();
        assert_eq!(load(&dir, "Home").unwrap(), Options::default());
        assert!(load(&dir, "..\\evil").is_err());

        fs::remove_dir_all(&dir).unwrap();
    }
}
