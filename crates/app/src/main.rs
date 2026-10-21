//! Tunnelik's window. The UI in `ui/` calls these commands; the work happens in tunnelik-manage,
//! the same code the `tunnelik` command uses.

#![windows_subsystem = "windows"]

#[cfg(windows)]
mod commands {
    use serde::Serialize;
    use tunnelik_manage as manage;

    #[derive(Serialize)]
    pub struct Tunnel {
        name: String,
        /// "disconnected", "connecting" or "connected".
        state: &'static str,
    }

    /// Runs slow work (PowerShell, rasdial) off the UI's event loop.
    async fn blocking<T: Send + 'static>(
        work: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        tauri::async_runtime::spawn_blocking(work)
            .await
            .map_err(|e| e.to_string())?
    }

    #[tauri::command]
    pub async fn list_tunnels() -> Result<Vec<Tunnel>, String> {
        blocking(|| {
            Ok(manage::list()?
                .into_iter()
                .map(|t| Tunnel {
                    name: t.name,
                    state: t.state.as_str(),
                })
                .collect())
        })
        .await
    }

    /// The full config, private key included. Only called when the user opens the editor.
    #[tauri::command]
    pub async fn read_tunnel(name: String) -> Result<String, String> {
        blocking(move || manage::read(&name)).await
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Details {
        public_key: String,
        listen_port: Option<u16>,
        addresses: Vec<String>,
        dns_servers: Vec<String>,
        dns_search: Vec<String>,
        mtu: Option<u16>,
        keep_awake: bool,
        always_on: bool,
        triggers: Triggers,
        peers: Vec<Peer>,
    }

    /// Programs and DNS suffixes that make Windows dial the tunnel, or the other tunnel that
    /// holds them.
    #[derive(Serialize)]
    pub struct Triggers {
        apps: Vec<String>,
        dns: Vec<String>,
        elsewhere: Option<String>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Peer {
        public_key: String,
        has_preshared_key: bool,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
        persistent_keepalive: Option<u16>,
    }

    /// What the overview shows: no private or preshared keys ever leave Rust here.
    #[tauri::command]
    pub async fn tunnel_details(name: String) -> Result<Details, String> {
        blocking(move || {
            let d = manage::details(&name)?;
            Ok(Details {
                public_key: d.public_key,
                listen_port: d.listen_port,
                addresses: d.addresses,
                dns_servers: d.dns_servers,
                dns_search: d.dns_search,
                mtu: d.mtu,
                keep_awake: d.keep_awake,
                always_on: d.always_on,
                triggers: Triggers {
                    apps: d.triggers.apps,
                    dns: d.triggers.dns,
                    elsewhere: d.triggers.elsewhere,
                },
                peers: d
                    .peers
                    .into_iter()
                    .map(|p| Peer {
                        public_key: p.public_key,
                        has_preshared_key: p.has_preshared_key,
                        allowed_ips: p.allowed_ips,
                        endpoint: p.endpoint,
                        persistent_keepalive: p.persistent_keepalive,
                    })
                    .collect(),
            })
        })
        .await
    }

    #[tauri::command]
    pub async fn save_tunnel(name: String, config: String) -> Result<(), String> {
        blocking(move || manage::save(&name, &config)).await
    }

    #[tauri::command]
    pub async fn remove_tunnel(name: String) -> Result<(), String> {
        blocking(move || manage::remove(&name)).await
    }

    /// Switches whether the plugin keeps the PC awake while `name` is busy.
    #[tauri::command]
    pub async fn set_keep_awake(name: String, enabled: bool) -> Result<(), String> {
        blocking(move || manage::set_keep_awake(&name, enabled)).await
    }

    /// Switches whether Tunnelik brings `name` back after Windows dropped it, and at sign-in.
    #[tauri::command]
    pub async fn set_always_on(name: String, enabled: bool) -> Result<(), String> {
        blocking(move || manage::set_always_on(&name, enabled)).await
    }

    /// The native "choose a program" dialog; null when the user cancels.
    #[tauri::command]
    pub async fn pick_program() -> Result<Option<String>, String> {
        blocking(|| {
            Ok(rfd::FileDialog::new()
                .set_title("Choose a program that connects this tunnel")
                .add_filter("Programs", &["exe"])
                .pick_file()
                .map(|path| path.display().to_string()))
        })
        .await
    }

    #[tauri::command]
    pub async fn add_app_trigger(name: String, program: String) -> Result<(), String> {
        blocking(move || manage::add_app_trigger(&name, &program)).await
    }

    #[tauri::command]
    pub async fn remove_app_trigger(name: String, program: String) -> Result<(), String> {
        blocking(move || manage::remove_app_trigger(&name, &program)).await
    }

    #[tauri::command]
    pub async fn add_dns_trigger(name: String, suffix: String) -> Result<(), String> {
        blocking(move || manage::add_dns_trigger(&name, &suffix)).await
    }

    #[tauri::command]
    pub async fn remove_dns_trigger(name: String, suffix: String) -> Result<(), String> {
        blocking(move || manage::remove_dns_trigger(&name, &suffix)).await
    }

    #[tauri::command]
    pub async fn connect(name: String) -> Result<(), String> {
        blocking(move || manage::connect(&name)).await
    }

    #[tauri::command]
    pub async fn disconnect(name: String) -> Result<(), String> {
        blocking(move || manage::disconnect(&name)).await
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct LivePeer {
        public_key: String,
        last_handshake_secs_ago: Option<u64>,
        rx_bytes: u64,
        tx_bytes: u64,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Live {
        keeping_awake: bool,
        peers: Vec<LivePeer>,
    }

    /// Handshake age and bytes per peer while `name` is connected, and whether the plugin is
    /// keeping the PC awake for it; null while it is not connected.
    #[tauri::command]
    pub fn tunnel_live(name: String) -> Option<Live> {
        manage::live(&name).map(|live| Live {
            keeping_awake: live.keeping_awake,
            peers: live
                .peers
                .into_iter()
                .map(|p| LivePeer {
                    public_key: p.public_key,
                    last_handshake_secs_ago: p.last_handshake_secs_ago,
                    rx_bytes: p.rx_bytes,
                    tx_bytes: p.tx_bytes,
                })
                .collect(),
        })
    }

    /// Recreates VPN connections Windows dropped, e.g. when the package was reinstalled.
    #[tauri::command]
    pub async fn repair_profiles() -> Result<Vec<String>, String> {
        blocking(manage::repair).await
    }

    /// Opens a web link in the default browser instead of inside the app's window.
    #[tauri::command]
    pub fn open_link(url: String) -> Result<(), String> {
        // Only plain web links: anything else could start arbitrary programs.
        if !url.starts_with("https://") || url.chars().any(|c| c.is_whitespace() || c == '"') {
            return Err(format!("not opening `{url}`"));
        }
        std::process::Command::new("explorer.exe")
            .arg(&url)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("opening {url}: {e}"))
    }

    /// Checks a config while it is being edited and returns its public key; fast, so it runs
    /// inline.
    #[tauri::command]
    pub fn validate(config: String) -> Result<String, String> {
        manage::validate(&config)
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Generated {
        config: String,
        public_key: String,
    }

    /// Puts a fresh private key into the config being edited. The key only ever travels as
    /// part of the config text, which the editor already holds.
    #[tauri::command]
    pub fn generate_key(config: String) -> Result<Generated, String> {
        manage::generate_key(&config).map(|(config, public_key)| Generated { config, public_key })
    }

    #[tauri::command]
    pub fn open_log_folder() -> Result<(), String> {
        manage::open_log_folder()
    }

    /// The installed version, for the window to show; null outside the package.
    #[tauri::command]
    pub fn app_version() -> Option<String> {
        manage::app_version()
    }
}

#[cfg(windows)]
fn main() {
    use commands::*;
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_tunnels,
            read_tunnel,
            tunnel_details,
            tunnel_live,
            save_tunnel,
            remove_tunnel,
            set_keep_awake,
            set_always_on,
            pick_program,
            add_app_trigger,
            remove_app_trigger,
            add_dns_trigger,
            remove_dns_trigger,
            connect,
            disconnect,
            open_link,
            repair_profiles,
            validate,
            generate_key,
            open_log_folder,
            app_version
        ])
        .run(tauri::generate_context!())
        .expect("starting Tunnelik");
}

#[cfg(not(windows))]
fn main() {}
