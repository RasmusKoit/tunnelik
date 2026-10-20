# Tunnelik

**A client for WireGuard® that lives in Windows 11's own VPN settings.** Add a WireGuard config
once, then connect and disconnect from **Settings → Network & internet → VPN**, the network
flyout, or the `tunnelik` command.

Tunnelik is an independent project. It is not affiliated with, endorsed by, or sponsored by the
WireGuard project. See [Trademarks](#trademarks).

## How it works

- **VPN plugin** (Rust, `windows` crate): implements Windows' `IVpnPlugIn`. Windows calls it on
  Connect/Disconnect and hands it the tunnel's packets through `VpnChannel`. The WireGuard
  protocol itself comes from [BoringTun](https://github.com/cloudflare/boringtun).
- **Tunnel storage**: each config is encrypted with DPAPI for your Windows user and saved in the
  package's data folder. The VPN profile only holds the tunnel's name.
- **`tunnelik` command**: adds, removes, connects and lists tunnels; a Tauri app is in progress.
- **Packaging**: an MSIX package whose hidden "Plugin" app hosts the plugin. During development
  it is registered straight from a folder, which needs Developer Mode but no signing.

The official WireGuard app is not needed.

## Layout

| Path            | What                                                         |
|-----------------|--------------------------------------------------------------|
| `crates/wgconf` | Parser for WireGuard `.conf` files                           |
| `crates/plugin` | VPN plugin and encrypted tunnel store                        |
| `crates/host`   | `tunnelik_host.exe`, the process Windows runs the plugin in  |
| `crates/manage` | Adding, removing and connecting tunnels, shared by CLI and app |
| `crates/cli`    | The `tunnelik` command                                       |
| `package`       | MSIX manifest and icons                                      |

## Prerequisites

```
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive"
winget install --id Rustlang.Rustup
```

Turn on **Settings → System → For developers → Developer Mode**.

## Try it

```
.\scripts\install-dev.ps1
.\target\release\tunnelik.exe add Home C:\path\to\home.conf
.\target\release\tunnelik.exe up Home
```

Or connect **Home** from Settings → Network & internet → VPN. The plugin logs to
`%LOCALAPPDATA%\Packages\Tunnelik_<id>\LocalState\plugin.log`.

Limitations for now: one `[Peer]` per tunnel.

## Test

```
cargo test
```

## Acknowledgements

Tunnelik builds on the work of others:

- **[WireGuard®](https://www.wireguard.com/)** by Jason A. Donenfeld: the protocol Tunnelik
  speaks, and the `.conf` format it reads.
- **[BoringTun](https://github.com/cloudflare/boringtun)** by Cloudflare (BSD-3-Clause): the
  WireGuard protocol implementation used for handshakes and encryption.
- **[windows-rs](https://github.com/microsoft/windows-rs)** by Microsoft (MIT or Apache-2.0):
  Rust bindings for the Windows APIs.
- **[UwpVpnPluginSample](https://github.com/microsoft/UwpVpnPluginSample)** by Microsoft (MIT):
  showed how a VPN plugin package is laid out.
- **[WSSHVpnPlugin](https://github.com/poizan42/WSSHVpnPlugin)** by poizan42: its notes on the
  Windows VPN platform's undocumented behaviour (IPv6 requirement, start and stop deadlocks,
  plugin instance reuse) saved a lot of debugging. No code was copied.

The licenses of all third-party crates are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Trademarks

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
Tunnelik uses the name only to describe what it is compatible with.
