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
  tunnelik repair                   recreate missing VPN connections, e.g. after a reinstall";

#[cfg(windows)]
fn main() -> ExitCode {
    use tunnelik_manage as manage;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        [] => manage::open_app(),
        ["add", name, file] => std::fs::read_to_string(file)
            .map_err(|e| format!("reading {file}: {e}"))
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
                println!("{:<24} {}", t.name, t.state.as_str());
            }
        }),
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

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("tunnelik only runs on Windows\n{USAGE}");
    ExitCode::FAILURE
}
