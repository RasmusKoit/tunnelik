//! Adds, removes and lists tunnels until the config editor app exists.
//!
//! Adding a tunnel saves its config encrypted in the package's data folder and creates a VPN
//! profile that points the plugin at it.

use std::process::{Command, ExitCode};

const USAGE: &str = "usage:
  wgw11 add <name> <file.conf>   add or replace a tunnel
  wgw11 remove <name>            remove a tunnel
  wgw11 list                     list tunnels";

/// Package name from package/AppxManifest.xml.
const PACKAGE_NAME: &str = "WireGuardW11";

#[cfg(windows)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["add", name, file] => add(name, file),
        ["remove", name] => remove(name),
        ["list"] => list(),
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("wgw11 only runs on Windows");
    ExitCode::FAILURE
}

#[cfg(windows)]
fn add(name: &str, file: &str) -> Result<(), String> {
    use wgw11_plugin::{profile, settings, store};

    profile::validate_name(name)?;
    let text = std::fs::read_to_string(file).map_err(|e| format!("reading {file}: {e}"))?;
    let config = wgconf::parse(&text).map_err(|e| format!("{file}: {e}"))?;
    let setup = settings::from_config(&config)?;
    let s = &setup.settings;
    let full_tunnel =
        s.ipv4_routes.iter().any(|r| r.1 == 0) || s.ipv6_routes.iter().any(|r| r.1 == 0);

    let family = package_family()?;
    store::save(&local_state(&family), name, &text)?;

    // Values travel as environment variables, so nothing in them is parsed as PowerShell.
    powershell(
        r#"
        $ErrorActionPreference = 'Stop'
        Remove-VpnConnection -Name $env:WGW11_NAME -Force -ErrorAction SilentlyContinue
        $vpn = @{
            Name                = $env:WGW11_NAME
            ServerAddress       = $env:WGW11_SERVER
            PlugInApplicationID = $env:WGW11_FAMILY
            CustomConfiguration = [xml]$env:WGW11_PROFILE
            SplitTunneling      = $env:WGW11_SPLIT -eq '1'
            Force               = $true
        }
        Add-VpnConnection @vpn
        "#,
        &[
            ("WGW11_NAME", name),
            ("WGW11_SERVER", &s.endpoint.host),
            ("WGW11_FAMILY", &family),
            ("WGW11_PROFILE", &profile::custom_configuration(name)),
            ("WGW11_SPLIT", if full_tunnel { "0" } else { "1" }),
        ],
    )
    .map_err(|e| format!("creating the VPN connection: {e}"))?;

    println!("Added `{name}`. Connect it from Settings > Network & internet > VPN.");
    Ok(())
}

#[cfg(windows)]
fn remove(name: &str) -> Result<(), String> {
    wgw11_plugin::profile::validate_name(name)?;
    powershell(
        "Remove-VpnConnection -Name $env:WGW11_NAME -Force -ErrorAction SilentlyContinue",
        &[("WGW11_NAME", name)],
    )
    .map_err(|e| format!("removing the VPN connection: {e}"))?;
    wgw11_plugin::store::remove(&local_state(&package_family()?), name)?;
    println!("Removed `{name}`.");
    Ok(())
}

#[cfg(windows)]
fn list() -> Result<(), String> {
    let names = wgw11_plugin::store::list(&local_state(&package_family()?));
    if names.is_empty() {
        println!("No tunnels yet. Add one with: wgw11 add <name> <file.conf>");
    }
    for name in names {
        println!("{name}");
    }
    Ok(())
}

/// The installed package's family name, which VPN profiles use to find the plugin.
fn package_family() -> Result<String, String> {
    let family = powershell(
        "(Get-AppxPackage -Name $env:WGW11_PACKAGE).PackageFamilyName",
        &[("WGW11_PACKAGE", PACKAGE_NAME)],
    )?;
    if family.is_empty() {
        return Err(
            "the plugin package is not installed; run scripts\\install-dev.ps1 first".into(),
        );
    }
    Ok(family)
}

/// The package's LocalState folder, which the plugin sees as its own data folder.
fn local_state(family: &str) -> std::path::PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").unwrap_or_default();
    std::path::Path::new(&base)
        .join("Packages")
        .join(family)
        .join("LocalState")
}

fn powershell(script: &str, env: &[(&str, &str)]) -> Result<String, String> {
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .envs(env.iter().copied())
        .output()
        .map_err(|e| format!("starting PowerShell: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
