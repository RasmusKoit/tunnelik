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
                let note = if t.keep_awake {
                    "   keeps the PC awake while busy"
                } else {
                    ""
                };
                println!("{:<24} {}{note}", t.name, t.state.as_str());
            }
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
        ["repair"] => manage::repair().map(|names| {
            if names.is_empty() {
                println!("Every tunnel has its VPN connection; nothing to repair.");
            } else {
                println!("Recreated the VPN connection for: {}", names.join(", "));
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
