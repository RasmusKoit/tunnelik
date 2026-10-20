# Tunnelik

**A client for WireGuard® that lives in Windows 11's own VPN settings.** Add a WireGuard config
once, then connect and disconnect from **Settings → Network & internet → VPN**, the network
flyout, or the `tunnelik` command.

Tunnelik is an independent project. It is not affiliated with, endorsed by, or sponsored by the
WireGuard project. See [Trademarks](#trademarks).

## How it works

- **VPN plugin** (Rust, `windows` crate): implements Windows' `IVpnPlugIn`. Windows calls it on
  Connect/Disconnect and hands it the tunnel's packets through `VpnChannel`. The WireGuard
  protocol itself comes from [BoringTun](https://github.com/cloudflare/boringtun). When the
  machine switches networks, the plugin notices within a second or two and has Windows
  reconnect the tunnel, which takes about five seconds. Pings and new connections carry on;
  connections that were open through the tunnel (SSH, rsync, downloads) are cut, since Windows
  recreates the VPN interface.
- **Tunnel storage**: each config is encrypted with DPAPI for your Windows user and saved in the
  package's data folder. The VPN profile only holds the tunnel's name.
- **`tunnelik` command and window**: the command adds, removes, connects and lists tunnels; the
  window (a Tauri app) does the same with an overview of each tunnel and live transfer stats.
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

## Build the installer

```
.\scripts\package.ps1
```

This builds `target\Tunnelik-<version>-x64.msix`, signed with a self-signed certificate that
`scripts\new-cert.ps1` creates on first use (its private key stays in your user certificate
store). Windows installs the package once that certificate is trusted, which takes one command
in an **admin** PowerShell:

```
Import-Certificate -FilePath target\Tunnelik.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
```

Then double-click the `.msix`, or run `Add-AppxPackage target\Tunnelik-<version>-x64.msix`.
Bump the version in `package\AppxManifest.xml` for each release so it installs as an update.

## Use it

Open **Tunnelik** from the Start menu, or from a terminal:

```
tunnelik add Home C:\path\to\home.conf
tunnelik up Home
tunnelik list
```

Or connect **Home** from Settings → Network & internet → VPN. Windows runs one connection per VPN
plugin, so connecting a tunnel disconnects any other Tunnelik tunnel. The plugin logs to
`%LOCALAPPDATA%\Packages\RasmusKoit.Tunnelik_<id>\LocalState\plugin.log`.

If Windows dropped the VPN connections (it does when the package is uninstalled and installed
again), `tunnelik repair` recreates them from the saved configs; the app does this when it opens.

Limitations for now: one `[Peer]` per tunnel.

## Development install

For quicker iterations, `.\scripts\install-dev.ps1` registers the build straight from
`target\appx` without signing. It needs **Settings → System → For developers → Developer Mode**.
A development install and the signed package can't replace each other: remove one with
`Remove-AppxPackage -PreserveApplicationData` before installing the other, then run
`tunnelik repair`.

## Test

```
cargo test
```

## License

Tunnelik is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
Tunnelik by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.

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
