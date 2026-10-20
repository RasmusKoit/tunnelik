//! Tunnel configs on disk, encrypted with DPAPI for the current Windows user.
//!
//! Each tunnel is `tunnels\<name>.conf.dpapi` in the package's LocalState folder. Both the plugin
//! (inside the package) and the tools that add tunnels (outside it) read and write that folder.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use windows::Security::Cryptography::DataProtection::DataProtectionProvider;
use windows_core::HSTRING;

use crate::profile::validate_name;
use crate::winrt::{Context, new_buffer, read_buffer};

const DIR: &str = "tunnels";
const EXTENSION: &str = ".conf.dpapi";
/// Only the same user on the same machine can decrypt.
const PROTECTION: &str = "LOCAL=user";

fn path(local_state: &Path, name: &str) -> Result<PathBuf, String> {
    validate_name(name)?;
    Ok(local_state.join(DIR).join(format!("{name}{EXTENSION}")))
}

pub fn save(local_state: &Path, name: &str, config_text: &str) -> Result<(), String> {
    let path = path(local_state, name)?;
    let provider = DataProtectionProvider::CreateOverloadExplicit(&HSTRING::from(PROTECTION))
        .context("setting up encryption")?;
    let encrypted = new_buffer(config_text.as_bytes())
        .and_then(|plain| provider.ProtectAsync(&plain))
        .and_then(|op| op.join())
        .and_then(|buffer| read_buffer(&buffer))
        .context("encrypting the config")?;

    // Write next to the target and swap it in, so a connect reading the tunnel at the same moment
    // sees either the old config or the new one, never half of one.
    let temp = path.with_extension("dpapi.tmp");
    fs::create_dir_all(local_state.join(DIR))
        .and_then(|()| fs::write(&temp, encrypted))
        .and_then(|()| fs::rename(&temp, &path))
        .map_err(|e| {
            let _ = fs::remove_file(&temp);
            format!("saving {}: {e}", path.display())
        })
}

pub fn load(local_state: &Path, name: &str) -> Result<String, String> {
    let path = path(local_state, name)?;
    let encrypted = fs::read(&path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => format!("tunnel `{name}` has no saved config; add it again"),
        _ => format!("reading {}: {e}", path.display()),
    })?;
    let plain = DataProtectionProvider::new()
        .and_then(|provider| provider.UnprotectAsync(&new_buffer(&encrypted)?))
        .and_then(|op| op.join())
        .and_then(|buffer| read_buffer(&buffer))
        .context("decrypting the config")?;
    String::from_utf8(plain).map_err(|_| format!("tunnel `{name}`'s config is not valid text"))
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

pub fn list(local_state: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(local_state.join(DIR)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|f| f.strip_suffix(EXTENSION).map(str::to_string))
        .collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tunnelik-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn save_load_list_remove() {
        let dir = temp_dir();
        let text = "[Interface]\nPrivateKey = secret\n";

        save(&dir, "Home", "old").unwrap();
        save(&dir, "Home", text).unwrap();
        save(&dir, "Office", "x").unwrap();
        assert_eq!(load(&dir, "Home").unwrap(), text);
        assert_eq!(list(&dir), vec!["Home", "Office"]);
        // Replacing a config leaves no temporary file behind.
        assert_eq!(fs::read_dir(dir.join(DIR)).unwrap().count(), 2);

        // The file on disk must not contain the key in the clear.
        let raw = fs::read(dir.join(DIR).join("Home.conf.dpapi")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"));

        remove(&dir, "Home").unwrap();
        remove(&dir, "Home").unwrap();
        assert_eq!(list(&dir), vec!["Office"]);
        assert!(load(&dir, "Home").unwrap_err().contains("add it again"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_unsafe_names() {
        assert!(save(&temp_dir(), "..\\evil", "x").is_err());
    }
}
