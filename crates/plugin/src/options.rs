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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Hold the PC out of idle sleep while the tunnel carries traffic. The plugin decides what
    /// counts as traffic; see `BUSY_BYTES_PER_MINUTE` in `vpn`.
    pub keep_awake: bool,
    /// Tunnelik's own always-on: bring the tunnel back after Windows dropped it, and at
    /// sign-in. The plugin also reads it to tell such a redial from one the user asked for.
    pub always_on: bool,
    /// Programs whose start makes Windows dial the tunnel, as full paths.
    pub app_triggers: Vec<String>,
    /// DNS suffixes a lookup under which makes Windows dial the tunnel, without a leading dot.
    pub dns_triggers: Vec<String>,
    /// Address ranges (`10.0.0.0/8`) a program's first connection into which makes Tunnelik's
    /// own watcher dial the tunnel; canonical, as `subnet::Subnet` prints them.
    pub subnet_triggers: Vec<String>,
    /// Its VPN profile is the managed, machine-wide one Windows dials on its own. Windows keeps
    /// such a profile always on itself, so the always-on task leaves it alone.
    pub managed: bool,
}

impl Options {
    /// Triggers Windows itself watches for, which take a managed profile; subnets are
    /// Tunnelik's own and need none of that.
    pub fn windows_triggers(&self) -> bool {
        !self.app_triggers.is_empty() || !self.dns_triggers.is_empty()
    }
}

pub fn encode(options: &Options) -> String {
    let mut text = format!(
        "keep-awake = {}\nalways-on = {}\n",
        options.keep_awake, options.always_on
    );
    for app in &options.app_triggers {
        text.push_str(&format!("app-trigger = {app}\n"));
    }
    for dns in &options.dns_triggers {
        text.push_str(&format!("dns-trigger = {dns}\n"));
    }
    for subnet in &options.subnet_triggers {
        text.push_str(&format!("subnet-trigger = {subnet}\n"));
    }
    if options.managed {
        text.push_str("managed = true\n");
    }
    text
}

pub fn decode(text: &str) -> Options {
    let mut options = Options::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let on = value == "true";
        match key.trim() {
            "keep-awake" => options.keep_awake = on,
            "always-on" => options.always_on = on,
            "app-trigger" if !value.is_empty() => options.app_triggers.push(value.to_string()),
            "dns-trigger" if !value.is_empty() => options.dns_triggers.push(value.to_string()),
            "subnet-trigger" if !value.is_empty() => {
                options.subnet_triggers.push(value.to_string())
            }
            "managed" => options.managed = on,
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
                    app_triggers: vec!["C:\\Program Files\\Some App\\app.exe".into()],
                    dns_triggers: vec!["corp.example".into(), "lab.example".into()],
                    subnet_triggers: vec!["10.0.0.0/8".into(), "fd00::/64".into()],
                    managed: keep_awake,
                };
                assert_eq!(decode(&encode(&options)), options);
                assert!(options.windows_triggers());
            }
        }
        assert!(!Options::default().windows_triggers());
        // Subnets are Tunnelik's own: no managed profile for them.
        let subnets_only = Options {
            subnet_triggers: vec!["10.0.0.0/8".into()],
            ..Options::default()
        };
        assert!(!subnets_only.windows_triggers());
        assert_eq!(decode(&encode(&subnets_only)), subnets_only);
    }

    #[test]
    fn tolerates_other_files() {
        assert_eq!(decode(""), Options::default());
        assert_eq!(decode("keep-awake = yes\n"), Options::default());
        assert_eq!(
            decode("# comment\nfrom-the-future = 1\n keep-awake=true \r\napp-trigger = \n"),
            Options {
                keep_awake: true,
                ..Options::default()
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
            ..Options::default()
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
