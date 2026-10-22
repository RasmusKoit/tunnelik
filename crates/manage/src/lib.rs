//! Managing tunnels from outside the VPN plugin, shared by the `tunnelik` command and the app.
//!
//! A tunnel is an encrypted config in the package's data folder plus a Windows VPN profile that
//! points the plugin at it. Connecting goes through Windows (`rasdial`), which starts the plugin.
//!
//! Profiles live in the user's own phonebook, created with `Add-VpnConnection`: that is the only
//! phonebook Settings and the network flyout list. Windows' VPN management API can create
//! profiles too, but keeps them in a phonebook of the package's own that no Windows UI shows,
//! so it is used for nothing but reading and dialing.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

mod mdm;

use tunnelik_plugin::markers::{self, Marker};
use tunnelik_plugin::{options, profile, settings, store, subnet};
use windows::ApplicationModel::Background::{
    BackgroundAccessStatus, BackgroundExecutionManager, BackgroundTaskBuilder,
    BackgroundTaskRegistration, IBackgroundTaskRegistration, SystemTrigger, SystemTriggerType,
};
use windows::Networking::Vpn::{VpnManagementAgent, VpnManagementErrorStatus, VpnPlugInProfile};
use windows_core::{HSTRING, Interface};

/// Package name from package/AppxManifest.xml.
pub const PACKAGE_NAME: &str = "dev.koit.Tunnelik";
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
    /// Whether Tunnelik brings the tunnel back by itself after Windows dropped it.
    pub always_on: bool,
    /// "WireGuard", or "AmneziaWG" with its generation; see `protocol_name`.
    pub protocol: String,
}

/// Checks a config the way the plugin will read it, so mistakes show up before saving, and
/// returns the public key of its private key, which is what the server side needs.
pub fn validate(config_text: &str) -> Result<String, String> {
    let config = wgconf::parse(config_text).map_err(|e| e.to_string())?;
    settings::from_config(&config)?;
    Ok(tunnelik_plugin::tunnel::public_key(&config.interface.private_key).to_base64())
}

/// Puts a freshly generated private key into a config being edited, and returns the new text
/// with the matching public key. An existing `PrivateKey` line in `[Interface]` is replaced;
/// otherwise one is added right after `[Interface]`, which is added itself to an empty box.
pub fn generate_key(config_text: &str) -> Result<(String, String), String> {
    let private = tunnelik_plugin::tunnel::generate_private_key()?;
    let public = tunnelik_plugin::tunnel::public_key(&private).to_base64();
    Ok((with_private_key(config_text, &private.to_base64()), public))
}

/// `config_text` with its `[Interface]` private key set to `key`. Everything else, line endings
/// included, stays as it was.
fn with_private_key(config_text: &str, key: &str) -> String {
    let newline = if config_text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let key_line = format!("PrivateKey = {key}");
    let mut out: Vec<String> = Vec::new();
    let mut section = String::new();
    let mut done = false;
    for line in config_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            // Leaving [Interface] without having seen a key: add one at its end, before the
            // blank lines that separate it from the next section.
            if section.eq_ignore_ascii_case("[interface]") && !done {
                let blanks = out.iter().rev().take_while(|l| l.trim().is_empty()).count();
                out.insert(out.len() - blanks, key_line.clone());
                done = true;
            }
            section = trimmed.to_string();
            out.push(line.to_string());
            continue;
        }
        let is_key = section.eq_ignore_ascii_case("[interface]")
            && trimmed
                .split_once('=')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("PrivateKey"));
        if is_key && !done {
            out.push(key_line.clone());
            done = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !done {
        if !section.eq_ignore_ascii_case("[interface]") {
            if !out.is_empty() && !out.last().is_some_and(|l| l.trim().is_empty()) {
                out.push(String::new());
            }
            out.push("[Interface]".to_string());
        }
        out.push(key_line);
    }
    let mut text = out.join(newline);
    if config_text.ends_with(newline) || config_text.is_empty() {
        text.push_str(newline);
    }
    text
}

/// Opens the folder with the plugin's log and status files in Explorer.
pub fn open_log_folder() -> Result<(), String> {
    let dir = local_state()?;
    Command::new("explorer.exe")
        .arg(&dir)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("opening {}: {e}", dir.display()))
}

/// The installed package's version, as `major.minor.build`.
pub fn app_version() -> Option<String> {
    let v = windows::ApplicationModel::Package::Current()
        .and_then(|p| p.Id())
        .and_then(|id| id.Version())
        .ok()?;
    Some(format_version(v.Major, v.Minor, v.Build))
}

fn format_version(major: u16, minor: u16, build: u16) -> String {
    format!("{major}.{minor}.{build}")
}

pub fn list() -> Result<Vec<Tunnel>, String> {
    let connections = connections()?;
    let dir = local_state()?;
    Ok(store::list(&dir)
        .into_iter()
        .map(|name| {
            let options = options::load(&dir, &name).unwrap_or_default();
            // A config that no longer parses is still listed, as WireGuard.
            let protocol = store::load(&dir, &name)
                .ok()
                .and_then(|text| wgconf::parse(&text).ok())
                .map_or_else(
                    || "WireGuard".to_string(),
                    |c| protocol_name(&c.interface.amnezia),
                );
            Tunnel {
                state: state_of(&connections, &name),
                keep_awake: options.keep_awake,
                always_on: options.always_on,
                protocol,
                name,
            }
        })
        .collect())
}

/// Whether Tunnelik brings `name` back by itself: at sign-in, and again after standby or a
/// network change dropped it.
pub fn always_on(name: &str) -> Result<bool, String> {
    ensure_exists(name)?;
    Ok(options::load(&local_state()?, name)?.always_on)
}

/// Switches always-on for `name`. A deliberate disconnect still sticks until the next sign-in
/// or network change, the same as for Windows' own always-on VPNs.
pub fn set_always_on(name: &str, enabled: bool) -> Result<(), String> {
    ensure_exists(name)?;
    let dir = local_state()?;
    let mut options = options::load(&dir, name)?;
    options.always_on = enabled;
    if options.managed || managed_exists(name)? {
        // Windows keeps a managed profile always on itself; the flag lives in the profile.
        rebuild_profile(name, options)?;
    } else {
        options::save(&dir, name, &options)?;
    }
    let any = store::list(&dir)
        .iter()
        .any(|n| options::load(&dir, n).is_ok_and(|o| o.always_on));
    sync_trigger_task(any)
}

/// The events Windows runs the always-on task on, with the names the registrations carry.
const TRIGGERS: [(&str, SystemTriggerType); 3] = [
    (
        "Tunnelik: network changed",
        SystemTriggerType::NetworkStateChange,
    ),
    ("Tunnelik: signed in", SystemTriggerType::SessionConnected),
    ("Tunnelik: user is back", SystemTriggerType::UserPresent),
];

/// Registers the always-on task while any tunnel is always on, and unregisters it once none
/// is. Registrations outlive the process and package updates, so missing ones are added and
/// present ones left alone.
fn sync_trigger_task(wanted: bool) -> Result<(), String> {
    let registered = trigger_registrations()?;
    if wanted {
        let access = BackgroundExecutionManager::RequestAccessAsync()
            .and_then(|op| op.join())
            .map_err(|e| {
                format!(
                    "asking Windows to run tasks in the background: {}",
                    e.message()
                )
            })?;
        if matches!(
            access,
            BackgroundAccessStatus::Denied
                | BackgroundAccessStatus::DeniedBySystemPolicy
                | BackgroundAccessStatus::DeniedByUser
        ) {
            return Err(
                "Windows does not let Tunnelik run in the background; check Settings > Apps > Tunnelik > Background apps permissions"
                    .into(),
            );
        }
        for (name, kind) in TRIGGERS {
            if registered.iter().any(|(n, _)| n == name) {
                continue;
            }
            let register = || -> windows_core::Result<()> {
                let builder = BackgroundTaskBuilder::new()?;
                builder.SetName(&HSTRING::from(name))?;
                builder.SetTaskEntryPoint(&HSTRING::from(tunnelik_plugin::trigger::CLASS))?;
                builder.SetTrigger(&SystemTrigger::Create(kind, false)?)?;
                builder.Register()?;
                Ok(())
            };
            register().map_err(|e| format!("registering `{name}`: {}", e.message()))?;
        }
    } else {
        for (name, registration) in registered {
            registration
                .Unregister(true)
                .map_err(|e| format!("unregistering `{name}`: {}", e.message()))?;
        }
    }
    Ok(())
}

fn trigger_registrations() -> Result<Vec<(String, IBackgroundTaskRegistration)>, String> {
    let all = BackgroundTaskRegistration::AllTasks()
        .map_err(|e| format!("listing background tasks: {}", e.message()))?;
    Ok(all
        .into_iter()
        .filter_map(|pair| {
            let registration = pair.Value().ok()?;
            let name = registration.Name().ok()?.to_string();
            TRIGGERS
                .iter()
                .any(|(n, _)| *n == name)
                .then_some((name, registration))
        })
        .collect())
}

/// The always-on task's registered events, for `tunnelik always-on <name>` to show.
pub fn trigger_events() -> Result<Vec<String>, String> {
    Ok(trigger_registrations()?
        .into_iter()
        .map(|(name, _)| name)
        .collect())
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

/// Recreates missing VPN connections for saved tunnels, and returns their names. Windows deletes
/// a VPN plugin's connections when the plugin's package is uninstalled (say, when moving from a
/// development install to the signed package), while the encrypted configs survive. Profiles a
/// 0.3.0 pre-release kept in the package's own phonebook are retired on the way, once they are
/// disconnected.
pub fn repair() -> Result<Vec<String>, String> {
    let family = package_family()?;
    let existing = powershell(
        "(Get-VpnConnection | Where-Object PlugInApplicationID -eq $env:TUNNELIK_FAMILY).Name",
        &[("TUNNELIK_FAMILY", &family)],
    )?;
    let existing: Vec<&str> = existing.lines().map(str::trim).collect();
    let connections = connections()?;

    let dir = local_state()?;
    let mut repaired = Vec::new();
    for name in store::list(&dir) {
        if state_of(&connections, &name) != State::Disconnected {
            continue;
        }
        let options = options::load(&dir, &name).unwrap_or_default();
        let in_phonebook = existing.iter().any(|e| e.eq_ignore_ascii_case(&name));
        if options.windows_triggers() {
            // A tunnel that starts on its own lives in a managed profile; an ordinary one in
            // its way, or a missing managed one, gets put right.
            if in_phonebook || !managed_exists(&name)? {
                retire_hidden_profile(&name)?;
                remove_profile(&name, &family)?;
                let (host, _, dns) = tunnel_server(&name)?;
                apply_managed(&name, &host, &dns, &options)?;
                repaired.push(name);
            }
        } else if !in_phonebook {
            retire_hidden_profile(&name)?;
            if managed_exists(&name)? {
                mdm::remove(&name)?;
            }
            save(&name, &read(&name)?)?;
            repaired.push(name);
        }
    }
    Ok(repaired)
}

/// Whether `name` has a managed profile in the all-users phonebook, where the service puts
/// the ones Windows dials on its own.
fn managed_exists(name: &str) -> Result<bool, String> {
    let family = package_family()?;
    let found = powershell(
        "$c = Get-VpnConnection -AllUserConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue; [bool]($c -and $c.PlugInApplicationID -eq $env:TUNNELIK_FAMILY)",
        &[("TUNNELIK_NAME", name), ("TUNNELIK_FAMILY", &family)],
    )?;
    Ok(found.eq_ignore_ascii_case("true"))
}

/// The first peer's host, shown as the connection's server, whether the config routes
/// everything into the tunnel, and the config's DNS servers.
fn tunnel_server(name: &str) -> Result<(String, bool, Vec<String>), String> {
    let config = wgconf::parse(&read(name)?).map_err(|e| e.to_string())?;
    let s = settings::from_config(&config)?.settings;
    let full_tunnel =
        s.ipv4_routes.iter().any(|r| r.1 == 0) || s.ipv6_routes.iter().any(|r| r.1 == 0);
    let dns = s.dns_servers.iter().map(ToString::to_string).collect();
    Ok((s.endpoints[0].host.clone(), full_tunnel, dns))
}

/// Has the service (re)build `name`'s managed profile from its options.
fn apply_managed(
    name: &str,
    host: &str,
    dns_servers: &[String],
    options: &options::Options,
) -> Result<(), String> {
    let xml = mdm::profile_xml(
        &package_family()?,
        host,
        &profile::custom_configuration(name),
        options.always_on,
        dns_servers,
        &options.app_triggers,
        &options.dns_triggers,
    );
    mdm::apply(name, &xml)
}

/// Rebuilds `name`'s VPN profile to match its options and saves them: with Windows triggers
/// it becomes a managed profile the service applies through Windows' MDM bridge, without any
/// it goes back to an ordinary one. Either way the profile is replaced, so a connected tunnel
/// is disconnected first and dialed again afterwards.
fn rebuild_profile(name: &str, mut options: options::Options) -> Result<(), String> {
    let dir = local_state()?;
    let was_up = state_of(&connections()?, name) != State::Disconnected;
    if was_up {
        disconnect(name)?;
        // The connection takes a moment to go away; the profile cannot be replaced before.
        for _ in 0..40 {
            if state_of(&connections()?, name) == State::Disconnected {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    let before = options::load(&dir, name)?;
    let (host, full_tunnel, dns) = tunnel_server(name)?;
    if options.windows_triggers() {
        remove_profile(name, &package_family()?)?;
        apply_managed(name, &host, &dns, &options)?;
        options.managed = true;
    } else {
        if before.managed || managed_exists(name)? {
            mdm::remove(name)?;
        }
        ensure_user_profile(name, &host, full_tunnel)?;
        options.managed = false;
    }
    options::save(&dir, name, &options)?;
    if was_up {
        connect(name)?;
    }
    Ok(())
}

/// Deletes a profile the VPN management API created for `name` in the package's own phonebook,
/// where no Windows UI can see it. Nothing happens when there is none.
fn retire_hidden_profile(name: &str) -> Result<(), String> {
    let Ok(agent) = VpnManagementAgent::new() else {
        return Ok(());
    };
    let family = package_family()?;
    let profiles = agent
        .GetProfilesAsync()
        .and_then(|op| op.join())
        .map_err(|e| format!("listing VPN profiles: {}", e.message()))?;
    for profile in profiles {
        let Ok(profile) = profile.cast::<VpnPlugInProfile>() else {
            continue;
        };
        let ours = profile
            .VpnPluginPackageFamilyName()
            .is_ok_and(|f| f.to_string().eq_ignore_ascii_case(&family));
        let same = profile
            .ProfileName()
            .is_ok_and(|n| n.to_string().eq_ignore_ascii_case(name));
        if !(ours && same) {
            continue;
        }
        let status = agent
            .DeleteProfileAsync(&profile)
            .and_then(|op| op.join())
            .map_err(|e| format!("removing the hidden VPN profile: {}", e.message()))?;
        if status != VpnManagementErrorStatus::Ok {
            return Err(format!(
                "removing the hidden VPN profile for `{name}` failed with status {}",
                status.0
            ));
        }
    }
    Ok(())
}

/// A tunnel's settings without its secrets: safe to show while browsing tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Details {
    /// "WireGuard", or "AmneziaWG" with the generation its settings need.
    pub protocol: String,
    /// The AmneziaWG settings as label and value rows; empty for WireGuard.
    pub obfuscation: Vec<(String, String)>,
    pub public_key: String,
    pub listen_port: Option<u16>,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u16>,
    /// Whether the plugin keeps the PC awake while the tunnel is busy.
    pub keep_awake: bool,
    /// Whether Tunnelik brings the tunnel back by itself; see `always_on`.
    pub always_on: bool,
    /// What makes Windows dial the tunnel on its own; see `triggers`.
    pub triggers: Triggers,
    pub peers: Vec<PeerDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDetails {
    pub public_key: String,
    pub has_preshared_key: bool,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    /// Seconds, or a range like `15–25` that AmneziaWG picks from.
    pub persistent_keepalive: Option<String>,
}

/// "WireGuard", or "AmneziaWG 3.1" and the like.
pub fn protocol_name(amnezia: &wgconf::Amnezia) -> String {
    if amnezia.is_active() {
        format!("AmneziaWG {}", amnezia.generation())
    } else {
        "WireGuard".to_string()
    }
}

pub fn details(name: &str) -> Result<Details, String> {
    let config = wgconf::parse(&read(name)?).map_err(|e| e.to_string())?;
    let iface = &config.interface;
    let strings = |items: &[wgconf::IpNet]| items.iter().map(ToString::to_string).collect();
    let options = options::load(&local_state()?, name)?;
    Ok(Details {
        protocol: protocol_name(&iface.amnezia),
        obfuscation: iface.amnezia.summary(),
        public_key: tunnelik_plugin::tunnel::public_key(&iface.private_key).to_base64(),
        listen_port: iface.listen_port,
        addresses: strings(&iface.addresses),
        dns_servers: iface.dns_servers.iter().map(ToString::to_string).collect(),
        dns_search: iface.dns_search.clone(),
        mtu: iface.mtu,
        keep_awake: options.keep_awake,
        always_on: options.always_on,
        triggers: triggers(name)?,
        peers: config
            .peers
            .iter()
            .map(|p| PeerDetails {
                public_key: p.public_key.to_base64(),
                has_preshared_key: p.preshared_key.is_some(),
                allowed_ips: strings(&p.allowed_ips),
                endpoint: p.endpoint.as_ref().map(ToString::to_string),
                persistent_keepalive: p.persistent_keepalive.map(|r| r.pretty()),
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
    let dir = local_state()?;
    let options = options::load(&dir, name)?;

    // The VPN profile comes first: if the name already belongs to another VPN, nothing gets
    // saved.
    let created = if options.windows_triggers() {
        // The managed profile only shows the server as a label; refresh it when it can be.
        if state_of(&connections()?, name) == State::Disconnected {
            let dns: Vec<String> = s.dns_servers.iter().map(ToString::to_string).collect();
            apply_managed(name, &s.endpoints[0].host, &dns, &options)?;
        }
        false
    } else {
        ensure_user_profile(name, &s.endpoints[0].host, full_tunnel)? == "created"
    };

    // Without its config a new profile would be a tunnel that can never connect, so take it
    // back out if saving fails.
    if let Err(e) = store::save(&dir, name, config_text) {
        if created {
            let _ = remove_profile(name, &package_family()?);
        }
        return Err(e);
    }
    Ok(())
}

/// Creates or updates the ordinary, per-user profile for `name`, and says which it did. Values
/// travel as environment variables, so nothing in them is parsed as PowerShell.
fn ensure_user_profile(name: &str, server: &str, full_tunnel: bool) -> Result<String, String> {
    let family = package_family()?;
    powershell(
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
            ("TUNNELIK_SERVER", server),
            ("TUNNELIK_FAMILY", &family),
            ("TUNNELIK_PROFILE", &profile::custom_configuration(name)),
            ("TUNNELIK_SPLIT", if full_tunnel { "0" } else { "1" }),
        ],
    )
}

/// Removes one of Tunnelik's own tunnels; other VPN connections are never touched.
pub fn remove(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    if state_of(&connections()?, name) != State::Disconnected {
        disconnect(name)?;
    }
    remove_profile(name, &package_family()?)?;
    retire_hidden_profile(name)?;
    if managed_exists(name)? {
        mdm::remove(name)?;
    }
    let dir = local_state()?;
    store::remove(&dir, name)?;
    markers::clear(&dir, name);
    options::remove(&dir, name)
}

/// Removes the VPN profile, but only if it is Tunnelik's.
fn remove_profile(name: &str, family: &str) -> Result<(), String> {
    powershell(
        r#"
        $existing = Get-VpnConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue
        if ($existing -and $existing.PlugInApplicationID -eq $env:TUNNELIK_FAMILY) {
            Remove-VpnConnection -Name $env:TUNNELIK_NAME -Force -ErrorAction Stop
            'removed'
        } else {
            'absent'
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
    let dir = local_state()?;
    let ours = store::list(&dir);
    for (other, state) in connections()? {
        let is_ours = ours.iter().any(|n| n.eq_ignore_ascii_case(&other));
        if is_ours && state != State::Disconnected && !other.eq_ignore_ascii_case(name) {
            disconnect(&other)?;
        }
    }
    // Connecting on purpose ends any earlier "leave it down"; the dialing marker tells the plugin
    // this connect was asked for, rather than Tunnelik bringing the tunnel back on its own.
    markers::take(&dir, name, Marker::Stopped);
    markers::set(&dir, name, Marker::Dialing)?;
    let result = rasdial(&[name]);
    if result.is_err() {
        markers::take(&dir, name, Marker::Dialing);
    }
    result
}

/// Disconnects on purpose: an always-on tunnel then stays down until the next sign-in or
/// network change, like Windows' own always-on VPNs.
pub fn disconnect(name: &str) -> Result<(), String> {
    ensure_exists(name)?;
    markers::set(&local_state()?, name, Marker::Stopped)?;
    rasdial(&[name, "/disconnect"])
}

// ---- Triggers: programs and DNS suffixes that make Windows dial the tunnel ----

/// What makes Windows bring a tunnel up on its own: starting one of these programs, or looking
/// up a name under one of these DNS suffixes. Windows watches on behalf of one profile per
/// machine, so only one tunnel can have any.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Triggers {
    /// Full paths of programs.
    pub apps: Vec<String>,
    /// DNS suffixes, lower case, without a leading dot.
    pub dns: Vec<String>,
    /// Address ranges Tunnelik's own watcher dials the tunnel for, canonical (`10.0.0.0/8`).
    pub subnets: Vec<String>,
    /// The other tunnel that holds the triggers, if one does.
    pub elsewhere: Option<String>,
    /// Whether the feature is turned on: the TunnelikMdm service is running.
    pub enabled: bool,
}

pub fn triggers(name: &str) -> Result<Triggers, String> {
    ensure_exists(name)?;
    let dir = local_state()?;
    let options = options::load(&dir, name)?;
    Ok(Triggers {
        apps: options.app_triggers,
        dns: options.dns_triggers,
        subnets: options.subnet_triggers,
        elsewhere: trigger_holder(&dir).filter(|h| !h.eq_ignore_ascii_case(name)),
        enabled: triggers_enabled(),
    })
}

/// Whether "start on its own" is turned on, which means the TunnelikMdm service is running.
pub fn triggers_enabled() -> bool {
    mdm::available()
}

/// Turns "start on its own" on or off by starting or stopping the TunnelikMdm service, which
/// takes administrator approval: Windows asks through its own prompt. The package installs
/// the service stopped and Windows keeps its start type at manual, so it runs from here until
/// turned off or the PC restarts; the profiles it applied keep working regardless, since
/// Windows itself does the dialing.
pub fn enable_triggers(enabled: bool) -> Result<(), String> {
    if enabled == triggers_enabled() {
        return Ok(());
    }
    let script = if enabled {
        "Start-Service TunnelikMdm"
    } else {
        "Stop-Service TunnelikMdm -Force"
    };
    powershell(
        r#"
        $ErrorActionPreference = 'Stop'
        try {
            $p = Start-Process powershell -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $env:TUNNELIK_SCRIPT)
        } catch {
            [Console]::Error.WriteLine('administrator approval was declined')
            exit 1
        }
        if ($p.ExitCode -ne 0) {
            [Console]::Error.WriteLine("changing the TunnelikMdm service failed (exit code $($p.ExitCode)); is Tunnelik installed from its package?")
            exit 1
        }
        "#,
        &[("TUNNELIK_SCRIPT", script)],
    )?;
    // The service takes a moment to answer on its pipe.
    for _ in 0..20 {
        if triggers_enabled() == enabled {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(if enabled {
        "the TunnelikMdm service did not come up; see C:\\ProgramData\\Tunnelik\\mdm.log".into()
    } else {
        "the TunnelikMdm service is still running".into()
    })
}

/// The tunnel that has triggers, if any.
fn trigger_holder(dir: &std::path::Path) -> Option<String> {
    store::list(dir)
        .into_iter()
        .find(|n| options::load(dir, n).is_ok_and(|o| o.windows_triggers()))
}

/// Makes starting `program` bring `name` up. The path must point at an existing `.exe`.
pub fn add_app_trigger(name: &str, program: &str) -> Result<(), String> {
    ensure_exists(name)?;
    let program = validate_program_path(program)?;
    let mut options = options::load(&local_state()?, name)?;
    if !options
        .app_triggers
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&program))
    {
        options.app_triggers.push(program);
    }
    set_triggers(name, options)
}

pub fn remove_app_trigger(name: &str, program: &str) -> Result<(), String> {
    ensure_exists(name)?;
    let mut options = options::load(&local_state()?, name)?;
    options
        .app_triggers
        .retain(|a| !a.eq_ignore_ascii_case(program.trim()));
    set_triggers(name, options)
}

/// Makes looking up any name under `suffix` bring `name` up.
pub fn add_dns_trigger(name: &str, suffix: &str) -> Result<(), String> {
    ensure_exists(name)?;
    let suffix = validate_dns_suffix(suffix)?;
    let mut options = options::load(&local_state()?, name)?;
    if !options.dns_triggers.contains(&suffix) {
        options.dns_triggers.push(suffix);
    }
    set_triggers(name, options)
}

pub fn remove_dns_trigger(name: &str, suffix: &str) -> Result<(), String> {
    ensure_exists(name)?;
    let suffix = normalize_dns_suffix(suffix);
    let mut options = options::load(&local_state()?, name)?;
    options.dns_triggers.retain(|d| *d != suffix);
    set_triggers(name, options)
}

/// Makes a program's first connection into `cidr` bring `name` up. That is Tunnelik's own
/// watcher, not Windows, so the profile stays as it is and nothing needs turning on; the
/// watcher is started right away, and by Windows at every sign-in.
pub fn add_subnet_trigger(name: &str, cidr: &str) -> Result<(), String> {
    ensure_exists(name)?;
    let subnet = subnet::Subnet::parse(cidr)?.to_string();
    let dir = local_state()?;
    let mut options = options::load(&dir, name)?;
    if !options.subnet_triggers.contains(&subnet) {
        options.subnet_triggers.push(subnet);
    }
    options::save(&dir, name, &options)?;
    ensure_watcher()
}

pub fn remove_subnet_trigger(name: &str, cidr: &str) -> Result<(), String> {
    ensure_exists(name)?;
    // Stored values are canonical; a parseable input is compared canonically, anything else
    // as typed, so whatever got stored stays removable.
    let subnet =
        subnet::Subnet::parse(cidr).map_or_else(|_| cidr.trim().to_string(), |s| s.to_string());
    let dir = local_state()?;
    let mut options = options::load(&dir, name)?;
    options.subnet_triggers.retain(|s| *s != subnet);
    options::save(&dir, name, &options)
}

/// `10.0.0.0/8` for anything that parses as a subnet, for matching against stored ones.
pub fn canonical_subnet(text: &str) -> Option<String> {
    subnet::Subnet::parse(text).ok().map(|s| s.to_string())
}

/// Starts the watcher that dials tunnels for subnet triggers, unless one is running already:
/// it holds a named mutex, and a second copy exits at once.
pub fn ensure_watcher() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateProcessW, DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
    };
    use windows_core::PWSTR;

    let exe = package_folder()?.join("tunnelik_watch.exe");
    // Without package identity (the development build of `tunnelik`), a file under WindowsApps
    // cannot be started directly; Windows' own cmdlet starts it inside the package.
    if windows::ApplicationModel::Package::Current().is_err() {
        return powershell(
            "Invoke-CommandInDesktopPackage -PackageFamilyName $env:TUNNELIK_FAMILY -AppId App -PreventBreakaway -Command $env:TUNNELIK_EXE",
            &[
                ("TUNNELIK_FAMILY", &package_family()?),
                ("TUNNELIK_EXE", &exe.to_string_lossy()),
            ],
        )
        .map(|_| ());
    }
    // Through CreateProcess with handle inheritance off: `std::process::Command` always lets a
    // child inherit the inheritable handles, so a `tunnelik` command run inside a pipeline
    // would hand the watcher its output pipe, and the pipeline would wait for the watcher.
    let mut command: Vec<u16> = std::ffi::OsStr::new(&format!("\"{}\"", exe.display()))
        .encode_wide()
        .chain(Some(0))
        .collect();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: the command line is a writable, NUL-terminated buffer, as the call requires;
    // the structs are initialised; the handles are closed right after.
    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            None,
            None,
            &startup,
            &mut process,
        )
        .map_err(|e| format!("starting {}: {}", exe.display(), e.message()))?;
        let _ = CloseHandle(process.hThread);
        let _ = CloseHandle(process.hProcess);
    }
    Ok(())
}

/// Where the package's files are: asked of Windows directly when running with package
/// identity, otherwise looked up by package name.
fn package_folder() -> Result<PathBuf, String> {
    if let Ok(path) = windows::ApplicationModel::Package::Current()
        .and_then(|p| p.InstalledLocation())
        .and_then(|f| f.Path())
    {
        return Ok(PathBuf::from(path.to_string()));
    }
    let path = powershell(
        "(Get-AppxPackage -Name $env:TUNNELIK_PACKAGE).InstallLocation",
        &[("TUNNELIK_PACKAGE", PACKAGE_NAME)],
    )?;
    if path.is_empty() {
        return Err("the app package is not installed; run scripts\\install-dev.ps1 first".into());
    }
    Ok(PathBuf::from(path))
}

/// Saves a tunnel's new trigger list and rebuilds its VPN profile to match; see
/// `rebuild_profile`.
fn set_triggers(name: &str, options: options::Options) -> Result<(), String> {
    let dir = local_state()?;
    if options.windows_triggers() && !triggers_enabled() {
        return Err(
            "turn on \"Start on its own\" first; it needs administrator approval once, because Windows keeps such profiles system-wide"
                .into(),
        );
    }
    if options.windows_triggers()
        && let Some(holder) = trigger_holder(&dir).filter(|h| !h.eq_ignore_ascii_case(name))
    {
        return Err(format!(
            "Only one tunnel can start on its own, and `{holder}` already does; remove its programs and domains first"
        ));
    }
    rebuild_profile(name, options)
}

/// A program for an app trigger: an absolute path to an existing `.exe`, with nothing in it that
/// could trip up the shell.
fn validate_program_path(program: &str) -> Result<String, String> {
    let program = program.trim();
    let path = std::path::Path::new(program);
    if program.is_empty() || program.contains(['"', '\n', '\r']) {
        return Err("the program path contains characters that are not allowed".into());
    }
    if !path.is_absolute() {
        return Err(format!(
            "`{program}` is not a full path; use one like C:\\Tools\\app.exe"
        ));
    }
    if !path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
    {
        return Err(format!("`{program}` is not a program (.exe)"));
    }
    if !path.is_file() {
        return Err(format!("`{program}` does not exist"));
    }
    Ok(program.to_string())
}

fn normalize_dns_suffix(suffix: &str) -> String {
    suffix.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A DNS suffix for a name trigger: `corp.example`, lower case, no spaces or shell characters.
/// Addresses and subnets are refused outright: Windows triggers on name lookups only, so an
/// address here would be accepted and never fire.
fn validate_dns_suffix(suffix: &str) -> Result<String, String> {
    let suffix = normalize_dns_suffix(suffix);
    if looks_like_address(&suffix) {
        return Err(format!(
            "`{suffix}` is an address; Windows can only start a tunnel for a program or a DNS name, not for an address or subnet. Use a domain like corp.example"
        ));
    }
    let ok = !suffix.is_empty()
        && suffix.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if ok {
        Ok(suffix)
    } else {
        Err(format!(
            "`{suffix}` is not a DNS suffix; use one like corp.example"
        ))
    }
}

/// An IPv4 or IPv6 address, with or without a `/prefix`.
fn looks_like_address(text: &str) -> bool {
    let host = text.split('/').next().unwrap_or("");
    host.parse::<std::net::IpAddr>().is_ok()
        || (host.split('.').count() == 4 && host.split('.').all(|l| l.parse::<u8>().is_ok()))
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
pub fn connections() -> Result<Vec<(String, State)>, String> {
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
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() {
            format!("PowerShell exited with {}", out.status)
        } else {
            err
        });
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
    fn formats_versions() {
        assert_eq!(format_version(0, 3, 3), "0.3.3");
        assert_eq!(format_version(1, 0, 0), "1.0.0");
    }

    #[test]
    fn puts_the_private_key_where_it_belongs() {
        let key = "KEY=";
        // Replaces, keeping everything else and the line endings.
        let text = "[Interface]\r\nPrivateKey = old\r\nAddress = 10.0.0.2/32\r\n\r\n[Peer]\r\nPrivateKey = not-mine\r\n";
        assert_eq!(
            with_private_key(text, key),
            "[Interface]\r\nPrivateKey = KEY=\r\nAddress = 10.0.0.2/32\r\n\r\n[Peer]\r\nPrivateKey = not-mine\r\n"
        );
        // Adds one at the end of [Interface] when it has none.
        assert_eq!(
            with_private_key(
                "[Interface]\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = p\n",
                key
            ),
            "[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = KEY=\n\n[Peer]\nPublicKey = p\n"
        );
        // [Interface] as the last section, without a trailing newline.
        assert_eq!(
            with_private_key(
                "[Peer]\nPublicKey = p\n\n[Interface]\nAddress = 10.0.0.2/32",
                key
            ),
            "[Peer]\nPublicKey = p\n\n[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = KEY="
        );
        // No [Interface] at all, and an empty box.
        assert_eq!(
            with_private_key("[Peer]\nPublicKey = p\n", key),
            "[Peer]\nPublicKey = p\n\n[Interface]\nPrivateKey = KEY=\n"
        );
        assert_eq!(
            with_private_key("", key),
            "[Interface]\nPrivateKey = KEY=\n"
        );
        // Case and spacing of the existing line don't matter.
        assert_eq!(
            with_private_key("[interface]\nprivatekey=old\n", key),
            "[interface]\nPrivateKey = KEY=\n"
        );
    }

    #[test]
    fn validates_program_paths() {
        let dir = std::env::temp_dir().join(format!("tunnelik-triggers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("Tool.EXE");
        std::fs::write(&exe, b"").unwrap();
        let bat = dir.join("tool.bat");
        std::fs::write(&bat, b"").unwrap();

        assert_eq!(
            validate_program_path(&format!(" {} ", exe.display())).unwrap(),
            exe.display().to_string()
        );
        assert!(
            validate_program_path("tool.exe")
                .unwrap_err()
                .contains("full path")
        );
        assert!(
            validate_program_path(&bat.display().to_string())
                .unwrap_err()
                .contains(".exe")
        );
        assert!(
            validate_program_path(&dir.join("missing.exe").display().to_string())
                .unwrap_err()
                .contains("exist")
        );
        assert!(
            validate_program_path("C:\\x\\\"a\".exe")
                .unwrap_err()
                .contains("not allowed")
        );
        assert!(validate_program_path("").is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validates_dns_suffixes() {
        assert_eq!(
            validate_dns_suffix(" Corp.Example. ").unwrap(),
            "corp.example"
        );
        assert_eq!(validate_dns_suffix("example").unwrap(), "example");
        assert_eq!(
            validate_dns_suffix("my-corp.example").unwrap(),
            "my-corp.example"
        );
        for bad in [
            "",
            ".",
            ".corp.example",
            "corp example",
            "corp..example",
            "$env:X",
            "a`b",
            "a\"b",
        ] {
            assert!(validate_dns_suffix(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_addresses_as_dns_suffixes() {
        for address in [
            "10.0.0.100",
            "10.0.0.0/8",
            "192.168.11.0/24",
            "fd00::1",
            "fd00::/64",
        ] {
            let err = validate_dns_suffix(address).unwrap_err();
            assert!(err.contains("is an address"), "{address}: {err}");
        }
        assert!(!looks_like_address("corp.example"));
        assert!(!looks_like_address("10.example"));
        // Whatever got stored stays removable.
        assert_eq!(normalize_dns_suffix(" 10.0.0.100. "), "10.0.0.100");
    }
}
