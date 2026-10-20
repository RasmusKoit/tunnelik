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
        connected: bool,
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
                    connected: t.connected,
                })
                .collect())
        })
        .await
    }

    #[tauri::command]
    pub async fn read_tunnel(name: String) -> Result<String, String> {
        blocking(move || manage::read(&name)).await
    }

    #[tauri::command]
    pub async fn save_tunnel(name: String, config: String) -> Result<(), String> {
        blocking(move || manage::save(&name, &config)).await
    }

    #[tauri::command]
    pub async fn remove_tunnel(name: String) -> Result<(), String> {
        blocking(move || manage::remove(&name)).await
    }

    #[tauri::command]
    pub async fn connect(name: String) -> Result<(), String> {
        blocking(move || manage::connect(&name)).await
    }

    #[tauri::command]
    pub async fn disconnect(name: String) -> Result<(), String> {
        blocking(move || manage::disconnect(&name)).await
    }

    /// Checks a config while it is being edited; fast, so it runs inline.
    #[tauri::command]
    pub fn validate(config: String) -> Result<(), String> {
        manage::validate(&config)
    }
}

#[cfg(windows)]
fn main() {
    use commands::*;
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_tunnels,
            read_tunnel,
            save_tunnel,
            remove_tunnel,
            connect,
            disconnect,
            validate
        ])
        .run(tauri::generate_context!())
        .expect("starting Tunnelik");
}

#[cfg(not(windows))]
fn main() {}
