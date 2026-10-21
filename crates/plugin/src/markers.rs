//! Flag files next to the tunnel configs, for passing one bit from the tools to the plugin.

use std::fs;
use std::path::{Path, PathBuf};

use crate::profile::validate_name;

const DIR: &str = "tunnels";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// The window or the `tunnelik` command is dialing the tunnel right now, as opposed to
    /// Windows bringing it up on its own.
    Dialing,
}

impl Marker {
    fn extension(self) -> &'static str {
        match self {
            Marker::Dialing => ".dialing",
        }
    }
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
        clear(&dir, "Home");
        assert!(!take(&dir, "Home", Marker::Dialing));

        assert!(set(&dir, "..\\evil", Marker::Dialing).is_err());
        assert!(!take(&dir, "..\\evil", Marker::Dialing));

        fs::remove_dir_all(&dir).unwrap();
    }
}
