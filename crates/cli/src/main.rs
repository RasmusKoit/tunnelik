//! The `tunnelik` command. With no arguments it opens the app; with arguments it manages tunnels
//! from the terminal.

use std::process::ExitCode;

const USAGE: &str = "usage:
  tunnelik                          open the app
  tunnelik add <name> <file.conf>   add a tunnel, or replace its config
  tunnelik remove <name>            remove a tunnel
  tunnelik up <name>                connect (disconnects any other Tunnelik tunnel)
  tunnelik down <name>              disconnect
  tunnelik list                     list tunnels and whether they are connected
  tunnelik keep-awake <name> on|off keep the PC awake while the tunnel is busy
  tunnelik always-on <name> on|off  bring it back after Windows drops it, and at sign-in
  tunnelik always-on <name>         show whether it is always on, and the task's events
  tunnelik trigger <name>           list the programs and DNS suffixes that start it
  tunnelik trigger <name> app <path.exe>    start it when that program runs
  tunnelik trigger <name> dns <suffix>      start it when a name under that suffix is looked up
  tunnelik trigger <name> remove <path-or-suffix>
  tunnelik repair                   recreate missing VPN connections, e.g. after a reinstall";

#[cfg(windows)]
fn main() -> ExitCode {
    use tunnelik_manage as manage;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        [] => manage::open_app(),
        ["add", name, file] => read_config(file)
            .and_then(|text| manage::save(name, &text))
            .map(|()| {
                println!(
                    "Added `{name}`. Connect it with `tunnelik up {name}` or from Settings > VPN."
                )
            }),
        ["remove", name] => manage::remove(name).map(|()| println!("Removed `{name}`.")),
        ["up", name] => manage::connect(name).map(|()| println!("Connected `{name}`.")),
        ["down", name] => manage::disconnect(name).map(|()| println!("Disconnected `{name}`.")),
        ["list"] => manage::list().map(|tunnels| {
            if tunnels.is_empty() {
                println!("No tunnels yet. Add one with: tunnelik add <name> <file.conf>");
            }
            for t in tunnels {
                let mut notes = Vec::new();
                if t.always_on {
                    notes.push("always on");
                }
                if t.keep_awake {
                    notes.push("keeps the PC awake while busy");
                }
                let note = if notes.is_empty() {
                    String::new()
                } else {
                    format!("   {}", notes.join(", "))
                };
                println!("{:<24} {}{note}", t.name, t.state.as_str());
            }
        }),
        ["always-on", name, switch @ ("on" | "off")] => {
            let enabled = *switch == "on";
            manage::set_always_on(name, enabled).map(|()| {
                if enabled {
                    println!("`{name}` is now always on: it comes back after Windows drops it, and at sign-in.");
                } else {
                    println!("`{name}` is no longer always on.");
                }
            })
        }
        ["always-on", name] => manage::always_on(name).and_then(|on| {
            let events = manage::trigger_events()?;
            println!(
                "`{name}` is {}.",
                if on { "always on" } else { "not always on" }
            );
            if events.is_empty() {
                println!("No always-on task is registered with Windows.");
            } else {
                println!("Windows runs the always-on task on: {}", events.join(", "));
            }
            Ok(())
        }),
        ["keep-awake", name, switch @ ("on" | "off")] => {
            let enabled = *switch == "on";
            manage::set_keep_awake(name, enabled).map(|()| {
                if enabled {
                    println!("`{name}` now keeps the PC awake while it is busy.");
                } else {
                    println!("`{name}` no longer keeps the PC awake.");
                }
            })
        }
        ["trigger", name] => manage::triggers(name).map(|t| {
            if t.apps.is_empty() && t.dns.is_empty() {
                println!("Nothing starts `{name}` on its own.");
            }
            for app in &t.apps {
                println!("program  {app}");
            }
            for dns in &t.dns {
                println!("dns      {dns}");
            }
        }),
        ["trigger", name, "app", program] => manage::add_app_trigger(name, program)
            .map(|()| println!("Starting `{program}` now connects `{name}`.")),
        ["trigger", name, "dns", suffix] => manage::add_dns_trigger(name, suffix)
            .map(|()| println!("Looking up a name under `{suffix}` now connects `{name}`.")),
        ["trigger", name, "remove", value] => manage::triggers(name)
            .and_then(|t| {
                if t.apps.iter().any(|a| a.eq_ignore_ascii_case(value)) {
                    manage::remove_app_trigger(name, value)
                } else if t.dns.iter().any(|d| d.eq_ignore_ascii_case(value)) {
                    manage::remove_dns_trigger(name, value)
                } else {
                    Err(format!("`{name}` has no trigger `{value}`"))
                }
            })
            .map(|()| println!("`{value}` no longer starts `{name}`.")),
        ["repair"] => manage::repair().map(|names| {
            if names.is_empty() {
                println!("Every tunnel has its VPN connection; nothing to repair.");
            } else {
                println!("Created the VPN connection for: {}", names.join(", "));
            }
        }),
        ["-h" | "--help" | "help"] => {
            println!("{USAGE}");
            Ok(())
        }
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

/// Reads a config as text. Notepad's "Unicode" encoding is UTF-16 with a byte order mark, which
/// the official app's export never uses but people re-save into.
#[cfg(windows)]
fn read_config(file: &str) -> Result<String, String> {
    let bytes = std::fs::read(file).map_err(|e| format!("reading {file}: {e}"))?;
    let utf16 = |decode: fn([u8; 2]) -> u16| {
        let (pairs, _) = bytes[2..].as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|&pair| decode(pair)).collect();
        String::from_utf16(&units).map_err(|_| format!("{file} is not valid UTF-16 text"))
    };
    match bytes[..] {
        [0xFF, 0xFE, ..] => utf16(u16::from_le_bytes),
        [0xFE, 0xFF, ..] => utf16(u16::from_be_bytes),
        _ => String::from_utf8(bytes)
            .map_err(|_| format!("{file} is not UTF-8 text; save it as UTF-8 and try again")),
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("tunnelik only runs on Windows\n{USAGE}");
    ExitCode::FAILURE
}
