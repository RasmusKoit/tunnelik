# Builds the plugin and registers it with Windows straight from a folder, without signing.
# Needs Developer Mode (Settings > System > For developers). Run again after code changes.
#
#   .\scripts\install-dev.ps1            release build
#   .\scripts\install-dev.ps1 -Debug     debug build

param([switch]$Debug)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$profileName = if ($Debug) { 'debug' } else { 'release' }
$out = Join-Path $root 'target\package'

$buildArgs = @('build', '--manifest-path', "$root\Cargo.toml", '-p', 'wgw11-host', '-p', 'wgw11-plugin', '-p', 'wgw11-cli')
if (-not $Debug) { $buildArgs += '--release' }
& cargo @buildArgs
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

# Windows runs the package from this folder, so it has to stay in place while installed.
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory $out | Out-Null
Copy-Item "$root\package\AppxManifest.xml" $out
Copy-Item -Recurse "$root\package\Assets" $out
Copy-Item "$root\target\$profileName\wgw11_host.exe", "$root\target\$profileName\wgw11_plugin.dll" $out

# Re-registering over an existing install can silently keep the old one, so remove it first.
# Keeping the app data keeps the saved tunnels.
$existing = Get-AppxPackage -Name WireGuardW11
if ($existing) { Remove-AppxPackage $existing.PackageFullName -PreserveApplicationData }

Add-AppxPackage -Register "$out\AppxManifest.xml"
$installed = Get-AppxPackage -Name WireGuardW11
Write-Host "Installed $($installed.PackageFullName)"
Write-Host "Add a tunnel with: $root\target\$profileName\wgw11.exe add <name> <file.conf>"
