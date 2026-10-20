# wireguard-w11

WireGuard tunnels as native Windows 11 VPN connections. Paste a WireGuard config once,
then connect and disconnect from **Settings → Network & internet → VPN** or the network flyout.

## How it works

- **App** (Tauri): editor where you paste a standard WireGuard config. Saving it creates a
  Windows VPN profile that uses our plugin.
- **VPN plugin** (Rust, `windows` crate): implements Windows' `IVpnPlugIn`. Windows calls it on
  Connect/Disconnect and hands it the tunnel's packets through `VpnChannel`. The WireGuard
  protocol itself comes from [BoringTun](https://github.com/cloudflare/boringtun).
- **Packaging**: MSIX signed with a self-signed certificate, installed with Developer Mode on.

The official WireGuard app is not used.

## Layout

| Path            | What                                    | Status  |
|-----------------|-----------------------------------------|---------|
| `crates/wgconf` | Parser for WireGuard `.conf` files      | Done    |
| `crates/plugin` | VPN plugin DLL (background task)        | Builds, not yet run in Windows |
| `app`           | Tauri config editor                     | Planned |

## Prerequisites

```
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive"
winget install --id Rustlang.Rustup
```

Turn on **Settings → System → For developers → Developer Mode**.

## Build

```
cargo test
```
