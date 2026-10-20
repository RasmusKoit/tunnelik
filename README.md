<div align="center">

<img src="docs/logo.png" alt="Tunnelik logo" width="128" height="128">

# Tunnelik

**WireGuard® tunnels in Windows 11's own VPN settings.**

Add a tunnel once, from the same `.conf` the official apps use.<br>
From then on it is just another VPN to Windows.

[![Latest release](https://img.shields.io/github/v/release/RasmusKoit/tunnelik?include_prereleases&label=release&color=0e7490)](https://github.com/RasmusKoit/tunnelik/releases/latest) [![Downloads](https://img.shields.io/github/downloads/RasmusKoit/tunnelik/total?color=0e7490)](https://github.com/RasmusKoit/tunnelik/releases) [![License: MIT or Apache-2.0](https://img.shields.io/badge/license-MIT%20or%20Apache--2.0-blue)](#license) [![Built with Rust](https://img.shields.io/badge/built%20with-Rust-dea584?logo=rust&logoColor=white)](https://www.rust-lang.org/) [![Platform: Windows 11](https://img.shields.io/badge/platform-Windows%2011-0078D4)](#install)

[Install](#install) · [Use](#use) · [How it works](#how-it-works) · [Build](#build) · [License](#license)

<br>

![The Tunnelik window: tunnels with their switches on the left, the selected tunnel's interface and peer on the right](docs/tunnelik-window.png)

</div>

> Tunnelik is an independent project, not affiliated with or endorsed by the WireGuard project.
> See [Trademarks](#trademarks).

## Why Tunnelik?

Windows 11 already has a VPN page, a switch in the network flyout, and a place for profiles.
Tunnelik plugs WireGuard into all of that instead of adding a tray icon and a service of its
own. Toggle a tunnel from **Settings → Network & internet → VPN**, the taskbar flyout, the
Tunnelik window, or `tunnelik up <name>`. The official WireGuard app is not needed.

<table>
<tr>
<td width="33%" valign="top">

### 🪟 Native toggle
Connect and disconnect wherever Windows shows VPNs, including the network flyout in the taskbar.

</td>
<td width="33%" valign="top">

### 📄 Standard configs
Paste or import a `wg-quick` style `.conf`, with one or several peers. Nothing to convert.

</td>
<td width="33%" valign="top">

### 🔐 Secrets stay put
Configs are encrypted with DPAPI for your Windows user. The overview never shows a private key.

</td>
</tr>
<tr>
<td width="33%" valign="top">

### 🔁 Stays up
Survives sleep and lock, rekeys on schedule, and reconnects by itself within about five seconds when you switch networks.

</td>
<td width="33%" valign="top">

### 📊 Live view
Latest handshake and bytes transferred per peer, right in the window.

</td>
<td width="33%" valign="top">

### 🖥️ Window and command line
The same tunnels, managed from either. Scripts and humans get the same features.

</td>
</tr>
</table>

## Install

**1.** Grab `Tunnelik-<version>-x64.msix` and `Tunnelik.cer` from the
[latest release](https://github.com/RasmusKoit/tunnelik/releases/latest).

**2.** Trust the certificate once. The package is signed with a self-signed certificate, so from
an **administrator** PowerShell:

```powershell
Import-Certificate -FilePath .\Tunnelik.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
```

**3.** Double-click the `.msix`, or:

```powershell
Add-AppxPackage .\Tunnelik-<version>-x64.msix
```

Later versions install over it as updates.

## Use

Open **Tunnelik** from the Start menu, click **Add tunnel**, paste or import a config, and
**Save**. The tunnel now appears in Settings → VPN like any other; the switch next to its name in
Tunnelik does the same thing.

The same from a terminal:

| Command | Does |
|---|---|
| `tunnelik` | Opens the window |
| `tunnelik add <name> <file.conf>` | Adds a tunnel, or replaces its config |
| `tunnelik up <name>` / `tunnelik down <name>` | Connects / disconnects |
| `tunnelik list` | Lists tunnels and their state |
| `tunnelik remove <name>` | Removes a tunnel and its VPN profile |
| `tunnelik repair` | Recreates VPN profiles Windows dropped (see below) |

> [!NOTE]
> Windows runs **one connection per VPN plugin**, so connecting a tunnel disconnects any other
> Tunnelik tunnel.

<details>
<summary><b>Good to know</b></summary>
<br>

- When you **switch networks**, the tunnel comes back on its own, but Windows recreates the VPN
  interface to do it, which cuts connections that were open through the tunnel (SSH, rsync,
  downloads). Pings and new connections carry on.
- Windows **deletes a plugin's VPN profiles** when the package is uninstalled. The configs
  survive; `tunnelik repair` (which the window also runs when it opens) brings the profiles back.
- `PreUp`/`PostUp` scripts and `Table = off` are refused rather than ignored; everything else in
  a `wg-quick` config is understood.
- The plugin logs to `%LOCALAPPDATA%\Packages\RasmusKoit.Tunnelik_<id>\LocalState\plugin.log`.

</details>

## How it works

Windows lets a packaged app provide a VPN through `IVpnPlugIn`: Windows owns the VPN interface,
routes and DNS, and hands the plugin packets to encrypt and datagrams to decrypt. Tunnelik's
plugin does exactly that, with [BoringTun](https://github.com/cloudflare/boringtun) speaking the
WireGuard protocol and a timer thread for handshakes and keepalives.

```
 Settings / flyout / window / CLI
               │  toggle
               ▼
   Windows VPN platform  ──  owns the interface, routes and DNS
               │  IVpnPlugIn
               ▼
   tunnelik_host.exe  ──  Tunnelik plugin  ──  BoringTun (WireGuard protocol)
               │
               ▼
     encrypted tunnel store  (DPAPI, per Windows user)
```

A VPN profile in Windows holds nothing but the tunnel's name. The config itself lives, encrypted,
in the package's data folder, where only the same Windows user can read it.

<details>
<summary><b>Repository layout</b></summary>
<br>

| Path | What |
|---|---|
| `crates/wgconf` | Parser for WireGuard `.conf` files |
| `crates/plugin` | The VPN plugin: WireGuard sessions, Windows glue, the encrypted tunnel store |
| `crates/host` | `tunnelik_host.exe`, the process Windows starts the plugin in |
| `crates/manage` | Adding, removing and connecting tunnels, shared by the window and the command |
| `crates/app` | The window (Tauri, plain HTML/JS) |
| `crates/cli` | The `tunnelik` command |
| `package` | MSIX manifest and icons |
| `scripts` | Build, sign and install |

</details>

## Build

Rust and the MSVC build tools:

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive"
winget install --id Rustlang.Rustup
```

Then:

```powershell
cargo test
.\scripts\package.ps1
```

`package.ps1` builds `target\Tunnelik-<version>-x64.msix` and signs it. On first use
`scripts\new-cert.ps1` creates the self-signed certificate (its private key stays in your user
certificate store) and exports `target\Tunnelik.cer`, which is what other machines trust. Bump
the version in `package\AppxManifest.xml` for each release so it installs as an update.

<details>
<summary><b>Faster iteration with a development install</b></summary>
<br>

`.\scripts\install-dev.ps1` registers the build straight from `target\appx` without signing; it
needs **Settings → System → For developers → Developer Mode**.

> [!IMPORTANT]
> A development install and the signed package can't replace each other: remove one with
> `Remove-AppxPackage -PreserveApplicationData` before installing the other, then run
> `tunnelik repair`.

</details>

## Contributing

Issues and pull requests are welcome. `cargo test` runs the test suite; the
[Build](#build) section covers producing an installable package.

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

<div align="center">
<br>

If Tunnelik saved you a tray icon, a ⭐ on the repo helps others find it.

</div>
