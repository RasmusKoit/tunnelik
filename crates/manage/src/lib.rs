//! Managing tunnels from outside the VPN plugin, shared by the `tunnelik` command and the app.
//!
//! A tunnel is an encrypted config in the package's data folder plus a Windows VPN profile that
//! points the plugin at it. Connecting goes through Windows (`rasdial`), which starts the plugin.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

use tunnelik_plugin::{profile, settings, store};

/// Package name from package/AppxManifest.xml.
pub const PACKAGE_NAME: &str = "RasmusKoit.Tunnelik";
/// Application id of the config editor in package/AppxManifest.xml.
pub const APP_ID: &str = "App";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disconnected,
    /// Dialing, or otherwise on the way up.
    Connecting,
    Connected,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Disconnected => "disconnected",
            State::Connecting => "connecting",
            State::Connected => "connected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub name: String,
    pub state: State,
}

/// Checks a config the way the plugin will read it, so mistakes show up before saving.
pub fn validate(config_text: &str) -> Result<(), String> {
    let config = wgconf::parse(config_text).map_err(|e| e.to_string())?;
    settings::from_config(&config)?;
    Ok(())
}

pub fn list() -> Result<Vec<Tunnel>, String> {
    let connections = connections()?;
    Ok(store::list(&local_state()?)
        .into_iter()
        .map(|name| Tunnel {
            state: state_of(&connections, &name),
            name,
        })
        .collect())
}

pub fn read(name: &str) -> Result<String, String> {
    store::load(&local_state()?, name)
}

/// What the plugin last reported about a connected tunnel's peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePeer {
    pub public_key: String,
    pub last_handshake_secs_ago: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Live counters for `name`, if it is the tunnel the plugin is running right now. The plugin
/// rewrites its status every 2 seconds, so anything older belongs to a finished connection.
pub fn live(name: &str) -> Option<Vec<LivePeer>> {
    let text =
        std::fs::read_to_string(local_state().ok()?.join(tunnelik_plugin::live::FILE)).ok()?;
    let live = tunnelik_plugin::live::decode(&text)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if !live.tunnel.eq_ignore_ascii_case(name) || now.saturating_sub(live.updated) > 10 {
        return None;
    }
    Some(
        live.peers
            .into_iter()
            .map(|p| LivePeer {
                public_key: p.public_key,
                last_handshake_secs_ago: p.last_handshake.map(|t| now.saturating_sub(t)),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
            })
            .collect(),
    )
}

/// Recreates missing VPN connections for saved tunnels, and returns their names. Windows deletes
/// a VPN plugin's connections when the plugin's package is uninstalled (say, when moving from a
/// development install to the signed package), while the encrypted configs survive.
pub fn repair() -> Result<Vec<String>, String> {
    let family = package_family()?;
    let existing = powershell(
        "(Get-VpnConnection | Where-Object PlugInApplicationID -eq $env:TUNNELIK_FAMILY).Name",
        &[("TUNNELIK_FAMILY", &family)],
    )?;
    let existing: Vec<&str> = existing.lines().map(str::trim).collect();

    let mut repaired = Vec::new();
    for name in store::list(&local_state()?) {
        if !existing.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
            save(&name, &read(&name)?)?;
            repaired.push(name);
        }
    }
    Ok(repaired)
}

/// A tunnel's settings without its secrets: safe to show while browsing tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Details {
    pub public_key: String,
    pub listen_port: Option<u16>,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u16>,
    pub peers: Vec<PeerDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDetails {
    pub public_key: String,
    pub has_preshared_key: bool,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

pub fn details(name: &str) -> Result<Details, String> {
    let config = wgconf::parse(&read(name)?).map_err(|e| e.to_string())?;
    let iface = &config.interface;
    let strings = |items: &[wgconf::IpNet]| items.iter().map(ToString::to_string).collect();
    Ok(Details {
        public_key: tunnelik_plugin::tunnel::public_key(&iface.private_key).to_base64(),
        listen_port: iface.listen_port,
        addresses: strings(&iface.addresses),
        dns_servers: iface.dns_servers.iter().map(ToString::to_string).collect(),
        dns_search: iface.dns_search.clone(),
        mtu: iface.mtu,
        peers: config
            .peers
            .iter()
            .map(|p| PeerDetails {
                public_key: p.public_key.to_base64(),
                has_preshared_key: p.preshared_key.is_some(),
                allowed_ips: strings(&p.allowed_ips),
                endpoint: p.endpoint.as_ref().map(ToString::to_string),
                persistent_keepalive: p.persistent_keepalive,
            })
            .collect(),
    })
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

    // The VPN profile comes first: if the name already belongs to another VPN, nothing gets
    // saved. Values travel as environment variables, so nothing in them is parsed as PowerShell.
    let outcome = powershell(
        r#"
        $ErrorActionPreference = 'Stop'
        $split = $env:TUNNELIK_SPLIT -eq '1'
        $existing = Get-VpnConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue
        if ($existing) {
            if ($existing.PlugInApplicationID -ne $env:TUNNELIK_FAMILY) {
                [Console]::Error.WriteLine("A VPN connection named '$($env:TUNNELIK_NAME)' already exists and isn't a Tunnelik tunnel. Pick another name.")
                exit 2
            }
            if ($existing.ServerAddress -ne $env:TUNNELIK_SERVER -or $existing.SplitTunneling -ne $split) {
                try {
                    Set-VpnConnection -Name $env:TUNNELIK_NAME -ServerAddress $env:TUNNELIK_SERVER -SplitTunneling $split -Force
                } catch {
                    [Console]::Error.WriteLine("Couldn't update the VPN connection (disconnect it first?): $($_.Exception.Message)")
                    exit 1
                }
            }
            'updated'
        } else {
            Add-VpnConnection -Name $env:TUNNELIK_NAME -ServerAddress $env:TUNNELIK_SERVER `
                -PlugInApplicationID $env:TUNNELIK_FAMILY -CustomConfiguration ([xml]$env:TUNNELIK_PROFILE) `
                -SplitTunneling:$split -Force | Out-Null
            'created'
        }
        "#,
        &[
            ("TUNNELIK_NAME", name),
            // Shown in Settings; the plugin connects to every peer's endpoint itself.
            ("TUNNELIK_SERVER", &s.endpoints[0].host),
            ("TUNNELIK_FAMILY", &family),
            ("TUNNELIK_PROFILE", &profile::custom_configuration(name)),
            ("TUNNELIK_SPLIT", if full_tunnel { "0" } else { "1" }),
        ],
    )?;

    // Without its config a new profile would be a tunnel that can never connect, so take it
    // back out if saving fails.
    if let Err(e) = local_state().and_then(|dir| store::save(&dir, name, config_text)) {
        if outcome == "created" {
            let _ = remove_profile(name, &family);
        }
        return Err(e);
    }
    Ok(())
}

/// Removes one of Tunnelik's own tunnels; other VPN connections are never touched.
pub fn remove(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    if state_of(&connections()?, name) != State::Disconnected {
        disconnect(name)?;
    }
    remove_profile(name, &package_family()?)?;
    store::remove(&local_state()?, name)
}

/// Removes the VPN profile, but only if it is Tunnelik's.
fn remove_profile(name: &str, family: &str) -> Result<(), String> {
    powershell(
        r#"
        $existing = Get-VpnConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue
        if ($existing -and $existing.PlugInApplicationID -eq $env:TUNNELIK_FAMILY) {
            Remove-VpnConnection -Name $env:TUNNELIK_NAME -Force -ErrorAction Stop
        }
        "#,
        &[("TUNNELIK_NAME", name), ("TUNNELIK_FAMILY", family)],
    )
    .map(|_| ())
    .map_err(|e| format!("removing the VPN connection: {e}"))
}

/// Connects a tunnel, first disconnecting any other Tunnelik tunnel: Windows runs only one
/// connection per VPN plugin, and a second one never reaches the plugin and hangs at connecting.
pub fn connect(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    let ours = store::list(&local_state()?);
    for (other, state) in connections()? {
        let is_ours = ours.iter().any(|n| n.eq_ignore_ascii_case(&other));
        if is_ours && state != State::Disconnected && !other.eq_ignore_ascii_case(name) {
            rasdial(&[&other, "/disconnect"])?;
        }
    }
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

/// VPN connection names compare case-insensitively in Windows.
fn state_of(connections: &[(String, State)], name: &str) -> State {
    connections
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map_or(State::Disconnected, |(_, s)| *s)
}

/// All VPN connections Windows currently has open or is opening, with their state.
fn connections() -> Result<Vec<(String, State)>, String> {
    use windows::Win32::NetworkManagement::Rras::{
        RASCONNSTATUSW, RASCONNW, RASCS_Connected, RASCS_Disconnected, RasEnumConnectionsW,
        RasGetConnectStatusW,
    };
    const ERROR_BUFFER_TOO_SMALL: u32 = 603;

    let entries = |n: usize| -> Vec<RASCONNW> {
        // SAFETY: RASCONNW is plain data, for which all zeroes is a valid value.
        let mut conns: Vec<RASCONNW> = vec![unsafe { std::mem::zeroed() }; n];
        for c in &mut conns {
            c.dwSize = size_of::<RASCONNW>() as u32;
        }
        conns
    };
    let mut conns = entries(32);
    let mut bytes = (conns.len() * size_of::<RASCONNW>()) as u32;
    let mut count = 0u32;
    // SAFETY: the buffer holds `bytes` bytes of RASCONNW entries with dwSize set.
    let mut err = unsafe { RasEnumConnectionsW(Some(conns.as_mut_ptr()), &mut bytes, &mut count) };
    if err == ERROR_BUFFER_TOO_SMALL {
        // `bytes` now says how much is needed.
        conns = entries((bytes as usize).div_ceil(size_of::<RASCONNW>()));
        bytes = (conns.len() * size_of::<RASCONNW>()) as u32;
        // SAFETY: as above, with the larger buffer.
        err = unsafe { RasEnumConnectionsW(Some(conns.as_mut_ptr()), &mut bytes, &mut count) };
    }
    if err != 0 {
        return Err(format!("listing VPN connections failed: RAS error {err}"));
    }
    Ok(conns
        .iter()
        .take(count as usize)
        .map(|c| {
            // Copied out because the structs are packed.
            let (name, handle) = (c.szEntryName, c.hrasconn);
            let len = name.iter().position(|&ch| ch == 0).unwrap_or(name.len());

            // SAFETY: plain data, all zeroes is valid; dwSize is set before the call.
            let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
            status.dwSize = size_of::<RASCONNSTATUSW>() as u32;
            // SAFETY: `handle` came from RasEnumConnectionsW; `status` is a valid out pointer.
            let state = match unsafe { RasGetConnectStatusW(handle, &mut status) } {
                0 => match status.rasconnstate {
                    s if s == RASCS_Connected => State::Connected,
                    s if s == RASCS_Disconnected => State::Disconnected,
                    _ => State::Connecting,
                },
                // The connection went away between the two calls.
                _ => State::Disconnected,
            };
            (String::from_utf16_lossy(&name[..len]), state)
        })
        .collect())
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
