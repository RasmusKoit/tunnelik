//! Always on: brings a tunnel back after Windows dropped it.
//!
//! Some minutes into Modern Standby, Windows hangs up every VPN and never redials a plugin's.
//! The window or the `tunnelik` command registers this background task on network changes,
//! sign-in and the user coming back to the PC; each time it runs, it dials the first always-on
//! tunnel that is down, unless the user disconnected it on purpose. Windows' VPN management API
//! does the dialing, which it allows a plugin's package to do for its own profiles. A tunnel
//! that starts on its own lives in a managed, all-user profile the API does not list; that one
//! is dialed by name with `rasdial`, which reads both phonebooks.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use windows::ApplicationModel::Background::{
    IBackgroundTask, IBackgroundTask_Impl, IBackgroundTaskInstance,
};
use windows::ApplicationModel::Package;
use windows::Networking::Vpn::{
    VpnManagementAgent, VpnManagementConnectionStatus, VpnManagementErrorStatus, VpnPlugInProfile,
};
use windows::Win32::System::WinRT::{IActivationFactory, IActivationFactory_Impl};
use windows_core::{IInspectable, Interface, Ref, Result, implement};

use crate::markers::{self, Marker};
use crate::vpn::{file_log, local_state};
use crate::{options, store};

/// Class name the package manifest registers for this task.
pub const CLASS: &str = "Tunnelik.TriggerTask";
/// A tunnel dropped this recently is left alone: the drop itself is a network change, and a
/// switch flipped in the flyout must not be undone a second later. A tunnel Windows hung up in
/// standby is well past this by the time the user is back.
pub const GRACE: Duration = Duration::from_secs(120);

#[implement(IBackgroundTask)]
struct TriggerTask;

impl IBackgroundTask_Impl for TriggerTask_Impl {
    fn Run(&self, _task: Ref<IBackgroundTaskInstance>) -> Result<()> {
        // Windows runs this on every network change, so the quiet outcomes stay out of the log.
        match bring_back() {
            Ok(Some(outcome)) => file_log(&format!("always on: {outcome}")),
            Ok(None) => {}
            Err(e) => file_log(&format!("always on: {e}")),
        }
        Ok(())
    }
}

#[implement(IActivationFactory)]
pub struct Factory;

impl IActivationFactory_Impl for Factory_Impl {
    fn ActivateInstance(&self) -> Result<IInspectable> {
        Ok(TriggerTask.into())
    }
}

/// A tunnel the task may consider, in the order the tunnels are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub always_on: bool,
    /// The user disconnected it on purpose.
    pub stopped: bool,
    /// It was disconnected within `GRACE`.
    pub just_dropped: bool,
}

/// The tunnel to bring back, if any: the first always-on one that was neither stopped on
/// purpose nor dropped a moment ago, and only when none of Tunnelik's tunnels is up or on its
/// way, since Windows runs one at a time.
pub fn choose(candidates: &[Candidate], any_up: bool) -> Option<&str> {
    if any_up {
        return None;
    }
    candidates
        .iter()
        .find(|c| c.always_on && !c.stopped && !c.just_dropped)
        .map(|c| c.name.as_str())
}

pub fn candidates(local_state: &Path) -> Vec<Candidate> {
    store::list(local_state)
        .into_iter()
        .map(|name| Candidate {
            always_on: options::load(local_state, &name).is_ok_and(|o| o.always_on),
            stopped: markers::exists(local_state, &name, Marker::Stopped),
            just_dropped: markers::age(local_state, &name, Marker::Dropped)
                .is_some_and(|age| age < GRACE),
            name,
        })
        .collect()
}

/// Dials a tunnel if one needs it; says what it did when there is something worth logging.
fn bring_back() -> std::result::Result<Option<String>, String> {
    let dir = local_state()?;
    let candidates = candidates(&dir);
    if !candidates.iter().any(|c| c.always_on) {
        return Ok(None);
    }
    let family = Package::Current()
        .and_then(|p| p.Id())
        .and_then(|id| id.FamilyName())
        .map_err(|e| format!("reading the package name: {}", e.message()))?
        .to_string();
    let agent = VpnManagementAgent::new()
        .map_err(|e| format!("reaching Windows' VPN service: {}", e.message()))?;
    let profiles: Vec<VpnPlugInProfile> = agent
        .GetProfilesAsync()
        .and_then(|op| op.join())
        .map_err(|e| format!("listing VPN profiles: {}", e.message()))?
        .into_iter()
        .filter_map(|p| p.cast::<VpnPlugInProfile>().ok())
        .filter(|p| {
            p.VpnPluginPackageFamilyName()
                .is_ok_and(|f| f.to_string().eq_ignore_ascii_case(&family))
        })
        .collect();
    let ras_up = ras_connections();
    let any_up = profiles.iter().any(|p| {
        p.ConnectionStatus()
            .is_ok_and(|s| s != VpnManagementConnectionStatus::Disconnected)
    }) || candidates
        .iter()
        .any(|c| ras_up.iter().any(|up| up.eq_ignore_ascii_case(&c.name)));
    let Some(name) = choose(&candidates, any_up) else {
        return Ok(if any_up {
            None
        } else if candidates.iter().any(|c| c.always_on && c.just_dropped) {
            Some("leaving a tunnel that was dropped a moment ago".into())
        } else {
            Some("every always-on tunnel was stopped on purpose".into())
        });
    };
    let Some(profile) = profiles.iter().find(|p| {
        p.ProfileName()
            .is_ok_and(|n| n.to_string().eq_ignore_ascii_case(name))
    }) else {
        file_log(&format!("always on: dialing `{name}` by name"));
        return rasdial(name).map(|()| Some(format!("brought `{name}` back")));
    };
    file_log(&format!("always on: dialing `{name}`"));
    let status = agent
        .ConnectProfileAsync(profile)
        .and_then(|op| op.join())
        .map_err(|e| format!("dialing `{name}`: {}", e.message()))?;
    match status {
        VpnManagementErrorStatus::Ok => Ok(Some(format!("brought `{name}` back"))),
        VpnManagementErrorStatus::AlreadyConnected => Ok(None),
        other => Err(format!("dialing `{name}` failed with status {}", other.0)),
    }
}

/// Names of the RAS connections that are up right now, from `rasdial` with no arguments. Any
/// failure reads as nothing up, which at worst dials a tunnel Windows then reports as connected.
fn ras_connections() -> Vec<String> {
    let Ok(out) = hidden(Command::new("rasdial.exe")).output() else {
        return Vec::new();
    };
    parse_rasdial_list(&String::from_utf8_lossy(&out.stdout))
}

/// `rasdial` prints "Connected to", one name per line, then "Command completed successfully."
/// (or "No connections" when nothing is up).
fn parse_rasdial_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .skip_while(|l| !l.eq_ignore_ascii_case("connected to"))
        .skip(1)
        .take_while(|l| !l.is_empty() && !l.starts_with("Command completed"))
        .map(String::from)
        .collect()
}

/// Dials a profile by name, which reaches the all-user phonebook too.
fn rasdial(name: &str) -> std::result::Result<(), String> {
    let out = hidden(Command::new("rasdial.exe"))
        .arg(name)
        .output()
        .map_err(|e| format!("starting rasdial: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let text = String::from_utf8_lossy(&out.stdout);
        let reason = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("unknown error");
        Err(format!("dialing `{name}`: {reason}"))
    }
}

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
    fn reads_the_names_rasdial_lists() {
        assert_eq!(
            parse_rasdial_list(
                "Connected to\r\nInfra\r\nLab\r\nCommand completed successfully.\r\n"
            ),
            vec!["Infra".to_string(), "Lab".to_string()]
        );
        assert!(
            parse_rasdial_list("No connections\r\nCommand completed successfully.\r\n").is_empty()
        );
        assert!(parse_rasdial_list("").is_empty());
    }

    fn c(name: &str, always_on: bool, stopped: bool, just_dropped: bool) -> Candidate {
        Candidate {
            name: name.into(),
            always_on,
            stopped,
            just_dropped,
        }
    }

    #[test]
    fn picks_the_first_always_on_tunnel_that_was_neither_stopped_nor_just_dropped() {
        let list = [
            c("Home", false, false, false),
            c("Infra", true, true, false),
            c("Lab", true, false, true),
            c("Office", true, false, false),
            c("Other", true, false, false),
        ];
        assert_eq!(choose(&list, false), Some("Office"));
        assert_eq!(choose(&list, true), None, "one at a time");
        assert_eq!(choose(&[c("Home", false, false, false)], false), None);
        assert_eq!(choose(&[c("Infra", true, true, false)], false), None);
        assert_eq!(choose(&[c("Lab", true, false, true)], false), None);
        assert_eq!(choose(&[], false), None);
    }
}
