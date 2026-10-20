//! Managing tunnels from outside the VPN plugin, shared by the `tunnelik` command and the app.
//!
//! A tunnel is an encrypted config in the package's data folder plus a Windows VPN profile that
//! points the plugin at it. Connecting goes through Windows (`rasdial`), which starts the plugin.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

use tunnelik_plugin::{profile, settings, store};

/// Package name from package/AppxManifest.xml.
pub const PACKAGE_NAME: &str = "Tunnelik";
/// Application id of the config editor in package/AppxManifest.xml.
pub const APP_ID: &str = "App";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub name: String,
    pub connected: bool,
}

/// Checks a config the way the plugin will read it, so mistakes show up before saving.
pub fn validate(config_text: &str) -> Result<(), String> {
    let config = wgconf::parse(config_text).map_err(|e| e.to_string())?;
    settings::from_config(&config)?;
    Ok(())
}

pub fn list() -> Result<Vec<Tunnel>, String> {
    let connected = connected_names();
    Ok(store::list(&local_state()?)
        .into_iter()
        .map(|name| Tunnel {
            connected: connected.contains(&name),
            name,
        })
        .collect())
}

pub fn read(name: &str) -> Result<String, String> {
    store::load(&local_state()?, name)
}

/// Adds a tunnel or replaces its config. A connected tunnel picks up the change on its next
/// connect.
pub fn save(name: &str, config_text: &str) -> Result<(), String> {
    profile::validate_name(name)?;
    validate(config_text)?;
    let config = wgconf::parse(config_text).map_err(|e| e.to_string())?;
    let s = settings::from_config(&config)?.settings;
    let full_tunnel =
        s.ipv4_routes.iter().any(|r| r.1 == 0) || s.ipv6_routes.iter().any(|r| r.1 == 0);

    let family = package_family()?;
    store::save(&local_state()?, name, config_text)?;

    // Values travel as environment variables, so nothing in them is parsed as PowerShell.
    powershell(
        r#"
        $ErrorActionPreference = 'Stop'
        $split = $env:TUNNELIK_SPLIT -eq '1'
        if (Get-VpnConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue) {
            Set-VpnConnection -Name $env:TUNNELIK_NAME -ServerAddress $env:TUNNELIK_SERVER -SplitTunneling $split -Force -ErrorAction SilentlyContinue
        } else {
            Add-VpnConnection -Name $env:TUNNELIK_NAME -ServerAddress $env:TUNNELIK_SERVER `
                -PlugInApplicationID $env:TUNNELIK_FAMILY -CustomConfiguration ([xml]$env:TUNNELIK_PROFILE) `
                -SplitTunneling:$split -Force
        }
        "#,
        &[
            ("TUNNELIK_NAME", name),
            ("TUNNELIK_SERVER", &s.endpoint.host),
            ("TUNNELIK_FAMILY", &family),
            ("TUNNELIK_PROFILE", &profile::custom_configuration(name)),
            ("TUNNELIK_SPLIT", if full_tunnel { "0" } else { "1" }),
        ],
    )
    .map_err(|e| format!("creating the VPN connection: {e}"))?;
    Ok(())
}

pub fn remove(name: &str) -> Result<(), String> {
    profile::validate_name(name)?;
    if connected_names().iter().any(|n| n == name) {
        disconnect(name)?;
    }
    powershell(
        "Remove-VpnConnection -Name $env:TUNNELIK_NAME -Force -ErrorAction SilentlyContinue",
        &[("TUNNELIK_NAME", name)],
    )
    .map_err(|e| format!("removing the VPN connection: {e}"))?;
    store::remove(&local_state()?, name)
}

pub fn connect(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    rasdial(&[name])
}

pub fn disconnect(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    rasdial(&[name, "/disconnect"])
}

fn ensure_exists(name: &str) -> Result<(), String> {
    profile::validate_name(name)?;
    if store::list(&local_state()?).iter().any(|n| n == name) {
        Ok(())
    } else {
        Err(format!("no tunnel named `{name}`"))
    }
}

/// Opens the config editor app.
pub fn open_app() -> Result<(), String> {
    let target = format!("shell:AppsFolder\\{}!{APP_ID}", package_family()?);
    Command::new("explorer.exe")
        .arg(target)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("opening the app: {e}"))
}

/// Names of the VPN connections that are currently up.
fn connected_names() -> Vec<String> {
    use windows::Win32::NetworkManagement::Rras::{RASCONNW, RasEnumConnectionsW};

    const MAX: usize = 32;
    // SAFETY: RASCONNW is plain data, for which all zeroes is a valid value.
    let mut conns: Vec<RASCONNW> = vec![unsafe { std::mem::zeroed() }; MAX];
    for c in &mut conns {
        c.dwSize = size_of::<RASCONNW>() as u32;
    }
    let mut bytes = (MAX * size_of::<RASCONNW>()) as u32;
    let mut count = 0u32;
    // SAFETY: the buffer holds `bytes` bytes of RASCONNW entries with dwSize set.
    let err = unsafe { RasEnumConnectionsW(Some(conns.as_mut_ptr()), &mut bytes, &mut count) };
    if err != 0 {
        return Vec::new();
    }
    conns
        .iter()
        .take(count as usize)
        .map(|c| {
            // Copied out because the struct is packed.
            let name = c.szEntryName;
            let len = name.iter().position(|&ch| ch == 0).unwrap_or(name.len());
            String::from_utf16_lossy(&name[..len])
        })
        .collect()
}

fn rasdial(args: &[&str]) -> Result<(), String> {
    let out = hidden(Command::new("rasdial.exe"))
        .args(args)
        .output()
        .map_err(|e| format!("starting rasdial: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    // rasdial prints its error, e.g. "Remote Access error 628 - ...", among other lines.
    let text = String::from_utf8_lossy(&out.stdout);
    let error = text
        .lines()
        .find(|l| l.contains("error"))
        .unwrap_or(text.trim());
    Err(error.trim().to_string())
}

/// The package's family name, which VPN profiles use to find the plugin.
pub fn package_family() -> Result<String, String> {
    // Started from the package (the app, or `tunnelik` through its alias): ask Windows directly.
    if let Ok(name) = windows::ApplicationModel::Package::Current()
        .and_then(|p| p.Id())
        .and_then(|id| id.FamilyName())
    {
        return Ok(name.to_string());
    }
    let family = powershell(
        "(Get-AppxPackage -Name $env:TUNNELIK_PACKAGE).PackageFamilyName",
        &[("TUNNELIK_PACKAGE", PACKAGE_NAME)],
    )?;
    if family.is_empty() {
        return Err("the app package is not installed; run scripts\\install-dev.ps1 first".into());
    }
    Ok(family)
}

/// The package's LocalState folder, which the plugin sees as its own data folder.
fn local_state() -> Result<PathBuf, String> {
    if let Ok(path) = windows::Storage::ApplicationData::Current()
        .and_then(|data| data.LocalFolder())
        .and_then(|folder| folder.Path())
    {
        return Ok(PathBuf::from(path.to_os_string()));
    }
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(base)
        .join("Packages")
        .join(package_family()?)
        .join("LocalState"))
}

fn powershell(script: &str, env: &[(&str, &str)]) -> Result<String, String> {
    let out = hidden(Command::new("powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .envs(env.iter().copied())
        .output()
        .map_err(|e| format!("starting PowerShell: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Keeps helper processes from flashing a console window when called from the app.
fn hidden(mut command: Command) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
    command
}
