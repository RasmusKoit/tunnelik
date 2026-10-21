//! Windows VPN plugin that carries WireGuard tunnels.
//!
//! Windows loads this code into the package's host process when a VPN profile that uses the
//! plugin connects. `vpn` holds the Windows side; `profile`, `settings` and `tunnel` are plain
//! Rust and tested anywhere.

pub mod activity;
pub mod live;
pub mod markers;
pub mod notify;
pub mod options;
pub mod profile;
pub mod settings;
pub mod tunnel;

#[cfg(windows)]
mod power;
#[cfg(windows)]
pub mod store;
#[cfg(windows)]
mod vpn;
#[cfg(windows)]
mod winrt;

#[cfg(windows)]
pub use vpn::{TASK_CLASS, activation_factory, file_log};
