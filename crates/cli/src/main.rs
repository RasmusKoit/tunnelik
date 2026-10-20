//! The `tunnelik` command. With no arguments it opens the app; with arguments it manages tunnels
//! from the terminal.

use std::process::ExitCode;

const USAGE: &str = "usage:
  tunnelik                          open the app
  tunnelik add <name> <file.conf>   add a tunnel, or replace its config
  tunnelik remove <name>            remove a tunnel
  tunnelik up <name>                connect
  tunnelik down <name>              disconnect
  tunnelik list                     list tunnels and whether they are connected";

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
                let state = if t.connected {
                    "connected"
                } else {
                    "disconnected"
                };
                println!("{:<24} {state}", t.name);
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
