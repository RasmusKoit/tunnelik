//! Tunnelik's watcher: starts a tunnel when a program first tries to reach one of its subnets.
//!
//! Windows has triggers for programs and DNS names but none for an address range, so this is
//! Tunnelik's own. Windows starts it at sign-in (a startup task in the package manifest) and
//! the window or the `tunnelik` command starts it when a subnet is added. Once a second it reads
//! the system's TCP table for connections a program is trying to open (`SYN_SENT`, which
//! Windows keeps retrying for about twenty seconds) and dials the first tunnel whose subnet one
//! is headed into. That attempt still fails, as Windows keeps it on the route it first chose;
//! the program's next try goes through the tunnel.
//! It only sees TCP; `ping` and UDP leave no trace. With nothing to watch for a minute it
//! exits; a second copy exits at once.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod table;
#[cfg(windows)]
mod watch;

#[cfg(windows)]
fn main() {
    use std::collections::HashMap;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime};

    use tunnelik_manage::{self as manage, State};
    use tunnelik_plugin::markers::{self, Marker};
    use tunnelik_plugin::subnet::Subnet;
    use tunnelik_plugin::{logfile, notify, options, store};
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows_core::w;

    const LOG_LIMIT: u64 = 1024 * 1024;
    const RELOAD: Duration = Duration::from_secs(10);
    const IDLE_EXIT: Duration = Duration::from_secs(60);

    struct Log(PathBuf);
    impl Log {
        fn line(&self, text: &str) {
            let _ = logfile::rotate(&self.0, LOG_LIMIT);
            let secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.0) {
                let _ = writeln!(file, "{h:02}:{m:02}:{s:02} UTC {text}");
            }
        }
    }

    /// The tunnels with subnet triggers, in list order, with their ranges parsed.
    fn watched(dir: &Path) -> Vec<(String, Vec<Subnet>)> {
        store::list(dir)
            .into_iter()
            .filter_map(|name| {
                let options = options::load(dir, &name).ok()?;
                let subnets: Vec<Subnet> = options
                    .subnet_triggers
                    .iter()
                    .filter_map(|s| Subnet::parse(s).ok())
                    .collect();
                (!subnets.is_empty()).then_some((name, subnets))
            })
            .collect()
    }

    // One watcher per session: the mutex outlives this scope on purpose.
    // SAFETY: plain API call with a static name.
    let created = unsafe { CreateMutexW(None, false, w!("Local\\Tunnelik.Watch")) };
    // SAFETY: GetLastError right after the call it belongs to.
    if created.is_err() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return;
    }
    let Ok(dir) = manage::local_state() else {
        return;
    };
    let log = Log(dir.join("watch.log"));
    log.line("started");

    let mut tunnels = Vec::new();
    let mut announced = String::new();
    let mut reloaded = Instant::now() - RELOAD;
    let mut idle_since: Option<Instant> = None;
    let mut last_dial: HashMap<String, Instant> = HashMap::new();
    loop {
        if reloaded.elapsed() >= RELOAD {
            tunnels = watched(&dir);
            reloaded = Instant::now();
            let now: Vec<String> = tunnels
                .iter()
                .map(|(name, subnets)| {
                    let list: Vec<String> = subnets.iter().map(ToString::to_string).collect();
                    format!("`{name}` for {}", list.join(", "))
                })
                .collect();
            let now = now.join("; ");
            if now != announced {
                log.line(&if now.is_empty() {
                    "nothing to watch".to_string()
                } else {
                    format!("watching {now}")
                });
                announced = now;
            }
        }
        if tunnels.is_empty() {
            let since = *idle_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= IDLE_EXIT {
                log.line("nothing to watch for a minute; exiting");
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        idle_since = None;

        // Never take a live tunnel down: Windows runs one connection per plugin.
        let ours = store::list(&dir);
        let any_up = manage::connections()
            .unwrap_or_default()
            .iter()
            .any(|(name, state)| {
                *state != State::Disconnected && ours.iter().any(|n| n.eq_ignore_ascii_case(name))
            });
        if any_up {
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        let list: Vec<watch::Watched> = tunnels
            .iter()
            .map(|(name, subnets)| watch::Watched {
                held_off: watch::held_off(
                    markers::age(&dir, name, Marker::Stopped),
                    markers::age(&dir, name, Marker::Dropped),
                    last_dial.get(name).map(Instant::elapsed),
                ),
                name: name.clone(),
                subnets: subnets.clone(),
            })
            .collect();
        if let Some(hit) = watch::decide(&table::syn_sent(), &list) {
            let program = table::process_name(hit.pid).unwrap_or_else(|| "unknown".into());
            log.line(&format!(
                "{} reached by {program} (pid {}); dialing `{}` for {}",
                hit.remote, hit.pid, hit.name, hit.subnet
            ));
            last_dial.insert(hit.name.to_string(), Instant::now());
            match manage::connect(hit.name) {
                Ok(()) => {
                    let _ = notify::show_text(
                        &format!("{} connected", hit.name),
                        &format!("{program} reached {} in {}.", hit.remote, hit.subnet),
                    );
                }
                Err(e) => log.line(&format!("dialing `{}`: {e}", hit.name)),
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(not(windows))]
fn main() {}
