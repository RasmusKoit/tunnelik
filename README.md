# wireguard-w11

WireGuard tunnels as native Windows 11 VPN connections. Add a WireGuard config once,
then connect and disconnect from **Settings → Network & internet → VPN** or the network flyout.

## How it works

- **VPN plugin** (Rust, `windows` crate): implements Windows' `IVpnPlugIn`. Windows calls it on
  Connect/Disconnect and hands it the tunnel's packets through `VpnChannel`. The WireGuard
  protocol itself comes from [BoringTun](https://github.com/cloudflare/boringtun).
- **Tunnel storage**: each config is encrypted with DPAPI for your Windows user and saved in the
  package's data folder. The VPN profile only holds the tunnel's name.
- **Adding tunnels**: the `wgw11` command for now; a Tauri editor app is planned.
- **Packaging**: an MSIX package whose hidden "Plugin" app hosts the plugin. During development
  it is registered straight from a folder, which needs Developer Mode but no signing.

The official WireGuard app is not used.

## Layout

| Path            | What                                              | Status  |
|-----------------|---------------------------------------------------|---------|
| `crates/wgconf` | Parser for WireGuard `.conf` files                | Done    |
| `crates/plugin` | VPN plugin and encrypted tunnel store             | Works: connects, carries traffic, disconnects |
| `crates/host`   | `wgw11_host.exe`, the process Windows runs the plugin in | Builds |
| `crates/cli`    | `wgw11` command to add, remove and list tunnels   | Builds  |
| `package`       | MSIX manifest and icons                           | Validates with MakeAppx |
| `app`           | Tauri config editor                               | Planned |

## Prerequisites

```
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive"
winget install --id Rustlang.Rustup
```

Turn on **Settings → System → For developers → Developer Mode**.

## Try it

```
.\scripts\install-dev.ps1
.\target\release\wgw11.exe add Home C:\path\to\home.conf
```

Then connect **Home** from Settings → Network & internet → VPN, or with `rasdial Home`.
The plugin logs to `%LOCALAPPDATA%\Packages\WireGuardW11_<id>\LocalState\plugin.log`.

Limitations for now: one `[Peer]` per tunnel; editing a tunnel means running `add` again.

## Test

```
cargo test
```
