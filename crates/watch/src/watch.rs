//! What the watcher decides, kept free of Windows so it can be tested: which tunnel to dial for
//! which connection attempt, and when a tunnel is left alone.

use std::net::IpAddr;
use std::time::Duration;

use tunnelik_plugin::subnet::Subnet;

/// After the user disconnected a tunnel on purpose it stays down this long, so a program that
/// keeps retrying cannot undo the disconnect a second later.
pub const HOLD_OFF: Duration = Duration::from_secs(10 * 60);
/// A tunnel dropped this recently is left alone, same as always-on does: the flyout switch and
/// a drop by Windows must not be undone at once.
pub const GRACE: Duration = Duration::from_secs(120);
/// No second dial of the same tunnel within this, whatever the first one did.
pub const COOLDOWN: Duration = Duration::from_secs(30);

/// A TCP connection a program is trying to open right now (`SYN_SENT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub remote: IpAddr,
    pub pid: u32,
}

/// A tunnel with subnet triggers, in the order the tunnels are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watched {
    pub name: String,
    pub subnets: Vec<Subnet>,
    pub held_off: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit<'a> {
    pub name: &'a str,
    pub subnet: Subnet,
    pub remote: IpAddr,
    pub pid: u32,
}

/// Whether a tunnel is left alone for now, from how long ago its markers were set and when the
/// watcher last dialed it.
pub fn held_off(
    stopped: Option<Duration>,
    dropped: Option<Duration>,
    last_dial: Option<Duration>,
) -> bool {
    stopped.is_some_and(|age| age < HOLD_OFF)
        || dropped.is_some_and(|age| age < GRACE)
        || last_dial.is_some_and(|age| age < COOLDOWN)
}

/// The first watched tunnel, not held off, that one of the attempts is headed into.
pub fn decide<'a>(attempts: &[Attempt], watched: &'a [Watched]) -> Option<Hit<'a>> {
    watched.iter().filter(|w| !w.held_off).find_map(|w| {
        attempts.iter().find_map(|a| {
            w.subnets
                .iter()
                .find(|s| s.contains(&a.remote))
                .map(|s| Hit {
                    name: &w.name,
                    subnet: *s,
                    remote: a.remote,
                    pid: a.pid,
                })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(remote: &str, pid: u32) -> Attempt {
        Attempt {
            remote: remote.parse().unwrap(),
            pid,
        }
    }

    fn watched(name: &str, subnets: &[&str], held_off: bool) -> Watched {
        Watched {
            name: name.into(),
            subnets: subnets.iter().map(|s| Subnet::parse(s).unwrap()).collect(),
            held_off,
        }
    }

    #[test]
    fn holds_off_after_a_stop_a_drop_or_a_recent_dial() {
        let s = Duration::from_secs;
        assert!(!held_off(None, None, None));
        assert!(held_off(Some(s(60)), None, None), "stopped a minute ago");
        assert!(
            !held_off(Some(HOLD_OFF), None, None),
            "stopped long enough ago"
        );
        assert!(held_off(None, Some(s(30)), None), "dropped a moment ago");
        assert!(!held_off(None, Some(GRACE), None));
        assert!(held_off(None, None, Some(s(5))), "just dialed");
        assert!(!held_off(None, None, Some(COOLDOWN)));
    }

    #[test]
    fn picks_the_first_tunnel_an_attempt_is_headed_into() {
        let list = [
            watched("Home", &["192.168.11.0/24"], false),
            watched("Infra", &["10.0.0.0/8", "fd00::/64"], false),
            watched("Lab", &["10.0.0.0/8"], false),
        ];
        let hit = decide(&[attempt("1.1.1.1", 1), attempt("10.0.2.137", 42)], &list).unwrap();
        assert_eq!(hit.name, "Infra");
        assert_eq!(hit.subnet.to_string(), "10.0.0.0/8");
        assert_eq!(hit.remote, "10.0.2.137".parse::<IpAddr>().unwrap());
        assert_eq!(hit.pid, 42);
        assert_eq!(
            decide(&[attempt("fd00::9", 7)], &list).unwrap().name,
            "Infra"
        );
        assert_eq!(
            decide(&[attempt("192.168.11.9", 7)], &list).unwrap().name,
            "Home"
        );
        assert!(decide(&[attempt("8.8.8.8", 7)], &list).is_none());
        assert!(decide(&[], &list).is_none());
        assert!(decide(&[attempt("10.0.2.137", 1)], &[]).is_none());
    }

    #[test]
    fn skips_tunnels_that_are_held_off() {
        let list = [
            watched("Infra", &["10.0.0.0/8"], true),
            watched("Lab", &["10.0.0.0/8"], false),
        ];
        assert_eq!(
            decide(&[attempt("10.0.2.137", 1)], &list).unwrap().name,
            "Lab"
        );
        assert!(decide(&[attempt("10.0.2.137", 1)], &list[..1]).is_none());
    }
}
