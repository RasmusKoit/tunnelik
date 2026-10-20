//! Windows VPN plugin that carries WireGuard tunnels.
//!
//! Windows loads this DLL into its background task host when a VPN profile that uses the plugin
//! connects. `vpn` holds the Windows side; the other modules are plain Rust and tested anywhere.

pub mod profile;
pub mod settings;
pub mod tunnel;

#[cfg(windows)]
mod vpn;
