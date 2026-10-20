# Builds the plugin and registers it with Windows straight from a folder, without signing.
# Needs Developer Mode (Settings > System > For developers). Run again after code changes.
#
#   .\scripts\install-dev.ps1            release build
#   .\scripts\install-dev.ps1 -Debug     debug build

param([switch]$Debug)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$profileName = if ($Debug) { 'debug' } else { 'release' }
$out = Join-Path $root 'target\appx'

$buildArgs = @('build', '--manifest-path', "$root\Cargo.toml", '-p', 'tunnelik-host', '-p', 'tunnelik-plugin', '-p', 'tunnelik-cli', '-p', 'tunnelik-app')
if (-not $Debug) { $buildArgs += '--release' }
# cargo reports progress on stderr, which Windows PowerShell would treat as an error under 'Stop'.
$ErrorActionPreference = 'Continue'
& cargo @buildArgs
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

# Update the installed package in place: copy the new files over the old ones and register again
# with a higher version. (Removing the package first collided with Windows re-registering it, e.g.
# while the Settings VPN page was open, and left the removal stuck until a reboot.) Windows runs
# the package from this folder, so it has to stay in place while installed.
Get-Process tunnelik_host, tunnelik-app -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force $out | Out-Null

# Re-registering the same version silently keeps the old registration, so every install gets a
# newer one: 0.0.<days since 2026-01-01>.<minute of the day>. Releases (package.ps1) use the
# manifest's version, which is always higher.
$now = Get-Date
$version = '0.0.{0}.{1}' -f [int][math]::Floor(($now - [datetime]'2026-01-01').TotalDays), ($now.Hour * 60 + $now.Minute)
[xml]$manifest = Get-Content "$root\package\AppxManifest.xml"
$manifest.Package.Identity.Version = $version
$manifest.Save("$out\AppxManifest.xml")
Copy-Item -Recurse -Force "$root\package\Assets" $out
foreach ($file in 'tunnelik_host.exe', 'tunnelik_plugin.dll', 'tunnelik.exe', 'tunnelik-app.exe') {
    Copy-Item -Force "$root\target\$profileName\$file" $out
}
Copy-Item -Force "$root\README.md", "$root\LICENSE-MIT", "$root\LICENSE-APACHE", "$root\THIRD_PARTY_NOTICES.md" $out -ErrorAction SilentlyContinue

# The plugin runs sandboxed and can only start if app packages may read this folder. Folders
# under the user profile don't allow that by default. S-1-15-2-1 is ALL APPLICATION PACKAGES.
icacls $out /grant '*S-1-15-2-1:(OI)(CI)(RX)' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'granting app packages access to the package folder failed' }

Add-AppxPackage -Register "$out\AppxManifest.xml" -ForceApplicationShutdown -ForceUpdateFromAnyVersion
$installed = Get-AppxPackage -Name RasmusKoit.Tunnelik
Write-Host "Installed $($installed.PackageFullName)"
Write-Host "Open Tunnelik from the Start menu, or run: tunnelik add <name> <file.conf>"
