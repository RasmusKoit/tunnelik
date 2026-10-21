//! Flag files next to the tunnel configs, for passing one bit from the tools to the plugin.

use std::fs;
use std::path::{Path, PathBuf};

use crate::profile::validate_name;

const DIR: &str = "tunnels";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// The window or the `tunnelik` command is dialing the tunnel right now, as opposed to
    /// Tunnelik bringing it up on its own.
    Dialing,
    /// The user disconnected the tunnel on purpose: always-on leaves it down until the next
    /// sign-in or network change.
    Stopped,
    /// The plugin was told to disconnect, by whoever; its age says how long ago. Always-on
    /// leaves a tunnel alone for a while after that, so a switch flipped in the flyout is not
    /// undone a second later.
    Dropped,
}

impl Marker {
    fn extension(self) -> &'static str {
        match self {
            Marker::Dialing => ".dialing",
            Marker::Stopped => ".stopped",
            Marker::Dropped => ".dropped",
        }
    }
}

/// Whether the marker is there, leaving it in place.
pub fn exists(local_state: &Path, name: &str, marker: Marker) -> bool {
    path(local_state, name, marker).is_ok_and(|path| path.exists())
}

/// How long ago the marker was set, if it is there.
pub fn age(local_state: &Path, name: &str, marker: Marker) -> Option<std::time::Duration> {
    let modified = fs::metadata(path(local_state, name, marker).ok()?)
        .ok()?
        .modified()
        .ok()?;
    Some(modified.elapsed().unwrap_or_default())
}

fn path(local_state: &Path, name: &str, marker: Marker) -> Result<PathBuf, String> {
    validate_name(name)?;
    Ok(local_state
        .join(DIR)
        .join(format!("{name}{}", marker.extension())))
}

pub fn set(local_state: &Path, name: &str, marker: Marker) -> Result<(), String> {
    let path = path(local_state, name, marker)?;
    fs::create_dir_all(local_state.join(DIR))
        .and_then(|()| fs::write(&path, b""))
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Removes the marker, and says whether it was there.
pub fn take(local_state: &Path, name: &str, marker: Marker) -> bool {
    path(local_state, name, marker).is_ok_and(|path| fs::remove_file(path).is_ok())
}

/// Removes every marker a tunnel may have left behind.
pub fn clear(local_state: &Path, name: &str) {
    take(local_state, name, Marker::Dialing);
    take(local_state, name, Marker::Stopped);
    take(local_state, name, Marker::Dropped);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_take_clear() {
        let dir = std::env::temp_dir().join(format!("tunnelik-markers-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        assert!(!take(&dir, "Home", Marker::Dialing));
        set(&dir, "Home", Marker::Dialing).unwrap();
        assert!(take(&dir, "Home", Marker::Dialing), "the marker was there");
        assert!(!take(&dir, "Home", Marker::Dialing), "and take consumed it");

        set(&dir, "Home", Marker::Dialing).unwrap();
        set(&dir, "Home", Marker::Stopped).unwrap();
        assert!(exists(&dir, "Home", Marker::Stopped));
        assert!(exists(&dir, "Home", Marker::Stopped), "exists leaves it");
        clear(&dir, "Home");
        assert!(!take(&dir, "Home", Marker::Dialing));
        assert!(!exists(&dir, "Home", Marker::Stopped));

        assert_eq!(age(&dir, "Home", Marker::Dropped), None);
        set(&dir, "Home", Marker::Dropped).unwrap();
        let age = age(&dir, "Home", Marker::Dropped).expect("just set");
        assert!(age < std::time::Duration::from_secs(5), "{age:?}");

        assert!(set(&dir, "..\\evil", Marker::Dialing).is_err());
        assert!(!take(&dir, "..\\evil", Marker::Dialing));

        fs::remove_dir_all(&dir).unwrap();
    }
}
