//! Managing tunnels from outside the VPN plugin, shared by the `tunnelik` command and the app.
//!
//! A tunnel is an encrypted config in the package's data folder plus a Windows VPN profile that
//! points the plugin at it. Profiles are owned through Windows' VPN management API, which keeps
//! them in the package's own phonebook and is also where always-on lives. That API only answers
//! a process with package identity: the app, or `tunnelik` through its alias.
//!
//! Versions before 0.3 created profiles in the user's phonebook with `Add-VpnConnection`. Those
//! still connect, and `repair` moves each one over the first time it is seen disconnected.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

use tunnelik_plugin::markers::{self, Marker};
use tunnelik_plugin::{options, profile, settings, store};
use windows::Foundation::Uri;
use windows::Networking::Vpn::{VpnManagementAgent, VpnManagementErrorStatus, VpnPlugInProfile};
use windows_core::{HSTRING, Interface};
use windows_future::IAsyncOperation;

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
    /// Whether the plugin keeps the PC awake while this tunnel is busy.
    pub keep_awake: bool,
    /// Whether Windows brings the tunnel up by itself at sign-in and after it was dropped.
    pub always_on: bool,
}

/// Checks a config the way the plugin will read it, so mistakes show up before saving.
pub fn validate(config_text: &str) -> Result<(), String> {
    let config = wgconf::parse(config_text).map_err(|e| e.to_string())?;
    settings::from_config(&config)?;
    Ok(())
}

pub fn list() -> Result<Vec<Tunnel>, String> {
    let connections = connections()?;
    let dir = local_state()?;
    let profiles = plugin_profiles().unwrap_or_default();
    Ok(store::list(&dir)
        .into_iter()
        .map(|name| Tunnel {
            state: state_of(&connections, &name),
            keep_awake: options::load(&dir, &name).is_ok_and(|o| o.keep_awake),
            always_on: find_profile(&profiles, &name)
                .is_some_and(|p| p.AlwaysOn().unwrap_or(false)),
            name,
        })
        .collect())
}

// ---- Windows' VPN management API ----

fn agent() -> Result<VpnManagementAgent, String> {
    require_identity()?;
    VpnManagementAgent::new().map_err(|e| format!("reaching Windows' VPN service: {}", e.message()))
}

/// The management API answers for the calling package only, so there is no point in asking
/// without one.
fn require_identity() -> Result<(), String> {
    windows::ApplicationModel::Package::Current().map(|_| ()).map_err(|_| {
        "tunnels can only be managed from the installed Tunnelik: the app, or `tunnelik` in a terminal"
            .to_string()
    })
}

/// Waits for one of the API's operations and turns anything but success into a message.
fn run(
    op: windows_core::Result<IAsyncOperation<VpnManagementErrorStatus>>,
    what: &str,
) -> Result<(), String> {
    match status_of(op, what)? {
        VpnManagementErrorStatus::Ok => Ok(()),
        status => Err(format!("{what} failed: {}", describe_status(status))),
    }
}

fn status_of(
    op: windows_core::Result<IAsyncOperation<VpnManagementErrorStatus>>,
    what: &str,
) -> Result<VpnManagementErrorStatus, String> {
    op.and_then(|op| op.join())
        .map_err(|e| format!("{what} failed: {}", e.message()))
}

/// Tunnelik's own VPN profiles, as the management API lists them. The list includes old-style
/// profiles from the user's phonebook, which the API can connect but not change; only
/// `ras_connections` tells the two kinds apart.
fn plugin_profiles() -> Result<Vec<VpnPlugInProfile>, String> {
    let family = package_family()?;
    let profiles = agent()?
        .GetProfilesAsync()
        .and_then(|op| op.join())
        .map_err(|e| format!("listing VPN profiles: {}", e.message()))?;
    Ok(profiles
        .into_iter()
        .filter_map(|profile| profile.cast::<VpnPlugInProfile>().ok())
        .filter(|profile| {
            profile
                .VpnPluginPackageFamilyName()
                .is_ok_and(|f| f.to_string().eq_ignore_ascii_case(&family))
        })
        .collect())
}

/// VPN profile names compare case-insensitively in Windows.
fn find_profile<'a>(profiles: &'a [VpnPlugInProfile], name: &str) -> Option<&'a VpnPlugInProfile> {
    profiles.iter().find(|p| {
        p.ProfileName()
            .is_ok_and(|n| n.to_string().eq_ignore_ascii_case(name))
    })
}

fn plugin_profile(name: &str) -> Result<VpnPlugInProfile, String> {
    let profiles = plugin_profiles()?;
    find_profile(&profiles, name)
        .cloned()
        .ok_or_else(|| format!("`{name}` has no VPN connection yet; run `tunnelik repair`"))
}

/// A fresh profile for `name`: the plugin's package, the tunnel's name as the custom
/// configuration the plugin reads back, and the first peer's host for Settings to show.
fn new_profile(name: &str, server: &str) -> Result<VpnPlugInProfile, String> {
    let family = package_family()?;
    let build = || -> windows_core::Result<VpnPlugInProfile> {
        let profile = VpnPlugInProfile::new()?;
        profile.SetProfileName(&HSTRING::from(name))?;
        profile.SetVpnPluginPackageFamilyName(&HSTRING::from(family.as_str()))?;
        profile.SetCustomConfiguration(&HSTRING::from(profile::custom_configuration(name)))?;
        profile.SetRememberCredentials(true)?;
        set_server(&profile, server)?;
        Ok(profile)
    };
    build().map_err(|e| format!("preparing the VPN connection: {}", e.message()))
}

fn set_server(profile: &VpnPlugInProfile, server: &str) -> windows_core::Result<()> {
    let uris = profile.ServerUris()?;
    uris.Clear()?;
    uris.Append(&Uri::CreateUri(&HSTRING::from(server))?)
}

fn server_of(profile: &VpnPlugInProfile) -> Option<String> {
    let uris = profile.ServerUris().ok()?;
    (uris.Size().ok()? == 1)
        .then(|| uris.GetAt(0).ok()?.RawUri().ok())??
        .to_string()
        .into()
}

/// The URI Windows shows as the connection's server. It is only a label here: the plugin
/// connects to every peer's endpoint itself.
fn server_uri(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("https://[{host}]")
    } else {
        format!("https://{host}")
    }
}

/// The management API's outcomes, in words for the user.
fn describe_status(status: VpnManagementErrorStatus) -> String {
    let words = match status {
        VpnManagementErrorStatus::Ok => "ok",
        VpnManagementErrorStatus::AccessDenied => "access denied",
        VpnManagementErrorStatus::CannotFindProfile => "the VPN connection was not found",
        VpnManagementErrorStatus::AlreadyConnected => "the tunnel is already connected",
        VpnManagementErrorStatus::AlreadyDisconnecting => "the tunnel is still disconnecting",
        VpnManagementErrorStatus::NoConnection => "there is no network connection",
        VpnManagementErrorStatus::ProfileInvalidAppId => "the connection's app id is invalid",
        VpnManagementErrorStatus::InvalidXmlSyntax => "the connection's settings are malformed",
        VpnManagementErrorStatus::ProfileNameTooLong => "the name is too long",
        VpnManagementErrorStatus::DnsNotResolvable => "the server name does not resolve",
        VpnManagementErrorStatus::ServerConnection => "the server could not be reached",
        _ => "an unexpected error",
    };
    format!("{words} (status {})", status.0)
}

// ---- Profiles from before 0.3, in the user's own phonebook ----

/// A VPN connection in the user's phonebook: Tunnelik's from before 0.3, or anyone else's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RasConnection {
    name: String,
    ours: bool,
}

fn ras_connections() -> Result<Vec<RasConnection>, String> {
    let family = package_family()?;
    let text = powershell(
        "Get-VpnConnection -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.Name)`t$($_.PlugInApplicationID)\" }",
        &[],
    )?;
    Ok(parse_ras_connections(&text, &family))
}

/// One `name<TAB>plugin package family` line per connection; the family is empty for VPNs that
/// are not plugin based.
fn parse_ras_connections(text: &str, family: &str) -> Vec<RasConnection> {
    text.lines()
        .filter_map(|line| {
            let (name, plugin) = line.split_once('\t')?;
            let name = name.trim();
            (!name.is_empty()).then(|| RasConnection {
                name: name.to_string(),
                ours: plugin.trim().eq_ignore_ascii_case(family),
            })
        })
        .collect()
}

/// Whether `name` is still on a profile from before 0.3.
fn is_legacy(ras: &[RasConnection], name: &str) -> bool {
    ras.iter()
        .any(|c| c.ours && c.name.eq_ignore_ascii_case(name))
}

/// Makes sure `name` is free for a new profile: no other VPN may have it, and an old-style
/// Tunnelik profile is removed, unless it is connected right now.
fn take_over_name(
    name: &str,
    ras: &[RasConnection],
    connections: &[(String, State)],
) -> Result<(), String> {
    let Some(existing) = ras.iter().find(|c| c.name.eq_ignore_ascii_case(name)) else {
        return Ok(());
    };
    if !existing.ours {
        return Err(format!(
            "A VPN connection named '{name}' already exists and isn't a Tunnelik tunnel. Pick another name."
        ));
    }
    if state_of(connections, name) != State::Disconnected {
        return Err(format!(
            "`{name}` is connected through its old profile; disconnect it, then save again"
        ));
    }
    remove_ras_profile(name)
}

/// Removes an old-style profile, but only if it is Tunnelik's.
fn remove_ras_profile(name: &str) -> Result<(), String> {
    powershell(
        r#"
        $existing = Get-VpnConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue
        if ($existing -and $existing.PlugInApplicationID -eq $env:TUNNELIK_FAMILY) {
            Remove-VpnConnection -Name $env:TUNNELIK_NAME -Force -ErrorAction Stop
        }
        "#,
        &[
            ("TUNNELIK_NAME", name),
            ("TUNNELIK_FAMILY", &package_family()?),
        ],
    )
    .map(|_| ())
    .map_err(|e| format!("removing the old VPN connection: {e}"))
}

// ---- Always on ----

/// Whether Windows brings `name` up by itself: at sign-in, and again after standby or a network
/// change dropped it.
pub fn always_on(name: &str) -> Result<bool, String> {
    plugin_profile(name)?
        .AlwaysOn()
        .map_err(|e| format!("reading the VPN connection: {}", e.message()))
}

/// Switches Windows' own always-on behaviour for `name`. A deliberate disconnect still sticks
/// until the next sign-in or network change, the same as for any always-on VPN.
pub fn set_always_on(name: &str, enabled: bool) -> Result<(), String> {
    ensure_exists(name)?;
    if is_legacy(&ras_connections()?, name) {
        return Err(format!(
            "`{name}` still uses its old-style VPN connection, which Windows can't switch to always on; disconnect it and run `tunnelik repair` (the window does that when it opens), then try again"
        ));
    }
    let profile = plugin_profile(name)?;
    profile
        .SetAlwaysOn(enabled)
        .map_err(|e| format!("updating the VPN connection: {}", e.message()))?;
    run(
        agent()?.UpdateProfileFromObjectAsync(&profile),
        "updating the VPN connection",
    )?;
    // The plugin reads this copy to tell a redial by Windows from one the user asked for.
    let dir = local_state()?;
    let mut options = options::load(&dir, name)?;
    options.always_on = enabled;
    options::save(&dir, name, &options)
}

/// Switches whether the plugin holds the PC out of idle sleep while `name` carries traffic. A
/// connected tunnel picks the change up within about ten seconds.
pub fn set_keep_awake(name: &str, enabled: bool) -> Result<(), String> {
    ensure_exists(name)?;
    let dir = local_state()?;
    let mut options = options::load(&dir, name)?;
    options.keep_awake = enabled;
    options::save(&dir, name, &options)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveStatus {
    /// The plugin is holding the PC awake right now because the tunnel is busy.
    pub keeping_awake: bool,
    pub peers: Vec<LivePeer>,
}

/// Live counters for `name`, if it is the tunnel the plugin is running right now. The plugin
/// rewrites its status every 2 seconds, so anything older belongs to a finished connection.
pub fn live(name: &str) -> Option<LiveStatus> {
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
    Some(LiveStatus {
        keeping_awake: live.keeping_awake,
        peers: live
            .peers
            .into_iter()
            .map(|p| LivePeer {
                public_key: p.public_key,
                last_handshake_secs_ago: p.last_handshake.map(|t| now.saturating_sub(t)),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
            })
            .collect(),
    })
}

/// Gives every saved tunnel its VPN connection, and returns the names of those it had to
/// create. Windows deletes a plugin's connections when the package is uninstalled (say, when
/// moving from a development install to the signed package), while the encrypted configs
/// survive. Tunnels still on an old-style profile are moved over here too, once they are
/// disconnected; a connected one keeps its old profile until next time.
pub fn repair() -> Result<Vec<String>, String> {
    let dir = local_state()?;
    let profiles = plugin_profiles()?;
    let legacy: Vec<String> = ras_connections()?
        .into_iter()
        .filter(|c| c.ours)
        .map(|c| c.name)
        .collect();
    let connections = connections()?;

    let mut repaired = Vec::new();
    for name in store::list(&dir) {
        let listed = find_profile(&profiles, &name).is_some();
        let native = listed && !legacy.iter().any(|l| l.eq_ignore_ascii_case(&name));
        if native || state_of(&connections, &name) != State::Disconnected {
            continue;
        }
        // Still on an old-style profile, or without one at all: `save` retires the old profile
        // and creates the new one.
        save(&name, &read(&name)?)?;
        repaired.push(name);
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
    /// Whether the plugin keeps the PC awake while the tunnel is busy.
    pub keep_awake: bool,
    /// Whether Windows brings the tunnel up by itself; see `always_on`.
    pub always_on: bool,
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
        keep_awake: options::load(&local_state()?, name)?.keep_awake,
        always_on: always_on(name).unwrap_or(false),
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
    let server = server_uri(&s.endpoints[0].host);
    let dir = local_state()?;
    let profiles = plugin_profiles()?;
    let ras = ras_connections()?;

    // The VPN profile comes first: if the name belongs to another VPN, nothing gets saved. An
    // old-style profile can't be updated in place, so it counts as not there.
    let native = find_profile(&profiles, name).filter(|_| !is_legacy(&ras, name));
    let created = match native {
        Some(existing) => {
            if server_of(existing).as_deref() != Some(server.as_str()) {
                set_server(existing, &server)
                    .map_err(|e| format!("updating the VPN connection: {}", e.message()))?;
                run(
                    agent()?.UpdateProfileFromObjectAsync(existing),
                    "updating the VPN connection",
                )?;
            }
            false
        }
        None => {
            take_over_name(name, &ras, &connections()?)?;
            let profile = new_profile(name, &server)?;
            run(
                agent()?.AddProfileFromObjectAsync(&profile),
                "adding the VPN connection",
            )?;
            true
        }
    };

    // Without its config a new profile would be a tunnel that can never connect, so take it
    // back out if saving fails.
    if let Err(e) = store::save(&dir, name, config_text) {
        if created {
            let _ = delete_profile(name);
        }
        return Err(e);
    }
    Ok(())
}

/// Removes `name`'s VPN connection, whichever phonebook it is in; other VPNs are never touched.
fn delete_profile(name: &str) -> Result<(), String> {
    if is_legacy(&ras_connections()?, name) {
        return remove_ras_profile(name);
    }
    let profiles = plugin_profiles()?;
    match find_profile(&profiles, name) {
        Some(profile) => run(
            agent()?.DeleteProfileAsync(profile),
            "removing the VPN connection",
        ),
        None => Ok(()),
    }
}

/// Removes one of Tunnelik's own tunnels; other VPN connections are never touched.
pub fn remove(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    if state_of(&connections()?, name) != State::Disconnected {
        disconnect(name)?;
    }
    delete_profile(name)?;
    let dir = local_state()?;
    store::remove(&dir, name)?;
    markers::clear(&dir, name);
    options::remove(&dir, name)
}

/// Connects a tunnel, first disconnecting any other Tunnelik tunnel: Windows runs only one
/// connection per VPN plugin, and a second one never reaches the plugin and hangs at connecting.
pub fn connect(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    let dir = local_state()?;
    let profile = plugin_profile(name)?;
    let ours = store::list(&dir);
    for (other, state) in connections()? {
        let is_ours = ours.iter().any(|n| n.eq_ignore_ascii_case(&other));
        if is_ours && state != State::Disconnected && !other.eq_ignore_ascii_case(name) {
            disconnect(&other)?;
        }
    }
    // So the plugin knows this connect was asked for, rather than Windows redialing on its own.
    markers::set(&dir, name, Marker::Dialing)?;
    let result = match status_of(agent()?.ConnectProfileAsync(&profile), "connecting")? {
        VpnManagementErrorStatus::Ok | VpnManagementErrorStatus::AlreadyConnected => Ok(()),
        status => Err(format!("connecting failed: {}", describe_status(status))),
    };
    if result.is_err() {
        markers::take(&dir, name, Marker::Dialing);
    }
    result
}

pub fn disconnect(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    if state_of(&connections()?, name) == State::Disconnected {
        return Ok(());
    }
    if is_legacy(&ras_connections()?, name) {
        return rasdial(&[name, "/disconnect"]);
    }
    let profile = plugin_profile(name)?;
    run(agent()?.DisconnectProfileAsync(&profile), "disconnecting")
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

/// All VPN connections Windows currently has open or is opening, with their state. Whichever
/// phonebook a profile lives in, its connection shows up here.
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

/// Only old-style profiles are dialed this way; the management API does not see them.
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
pub fn local_state() -> Result<PathBuf, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_statuses_the_user_can_hit() {
        for (status, words) in [
            (VpnManagementErrorStatus::Ok, "ok"),
            (VpnManagementErrorStatus::AccessDenied, "access denied"),
            (VpnManagementErrorStatus::CannotFindProfile, "not found"),
            (
                VpnManagementErrorStatus::AlreadyConnected,
                "already connected",
            ),
            (VpnManagementErrorStatus::NoConnection, "no network"),
            (VpnManagementErrorStatus::Other, "unexpected"),
            (VpnManagementErrorStatus(999), "unexpected"),
        ] {
            assert!(describe_status(status).contains(words), "{status:?}");
        }
    }

    #[test]
    fn server_uris() {
        assert_eq!(server_uri("vpn.example.com"), "https://vpn.example.com");
        assert_eq!(server_uri("203.0.113.10"), "https://203.0.113.10");
        assert_eq!(server_uri("2001:db8::1"), "https://[2001:db8::1]");
        assert_eq!(server_uri("[2001:db8::1]"), "https://[2001:db8::1]");
    }

    #[test]
    fn parses_the_phonebook_listing() {
        let family = "RasmusKoit.Tunnelik_abc";
        let text =
            "Infra\tRasmusKoit.Tunnelik_abc\nWork VPN\t\n\n  \tsomething\nOther\tVendor.App_xyz\n";
        let listed = parse_ras_connections(text, family);
        assert_eq!(
            listed,
            vec![
                RasConnection {
                    name: "Infra".into(),
                    ours: true
                },
                RasConnection {
                    name: "Work VPN".into(),
                    ours: false
                },
                RasConnection {
                    name: "Other".into(),
                    ours: false
                },
            ]
        );
        assert!(parse_ras_connections("", family).is_empty());
    }
}
