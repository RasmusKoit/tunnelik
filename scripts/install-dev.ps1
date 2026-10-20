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
# cargo reports progress on stderr, which Windows PowerShell would treat as an error under 'Stop'.
$ErrorActionPreference = 'Continue'
& cargo @buildArgs
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

# Re-registering over an existing install can silently keep the old one, so remove it first,
# which also releases the files in the folder. Keeping the app data keeps the saved tunnels.
Get-Process wgw11_host -ErrorAction SilentlyContinue | Stop-Process -Force
$existing = Get-AppxPackage -Name WireGuardW11
if ($existing) { Remove-AppxPackage $existing.PackageFullName -PreserveApplicationData }

# Windows runs the package from this folder, so it has to stay in place while installed.
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory $out | Out-Null
Copy-Item "$root\package\AppxManifest.xml" $out
Copy-Item -Recurse "$root\package\Assets" $out
Copy-Item "$root\target\$profileName\wgw11_host.exe", "$root\target\$profileName\wgw11_plugin.dll" $out

# The plugin runs sandboxed and can only start if app packages may read this folder. Folders
# under the user profile don't allow that by default. S-1-15-2-1 is ALL APPLICATION PACKAGES.
icacls $out /grant '*S-1-15-2-1:(OI)(CI)(RX)' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'granting app packages access to the package folder failed' }

Add-AppxPackage -Register "$out\AppxManifest.xml"
$installed = Get-AppxPackage -Name WireGuardW11
Write-Host "Installed $($installed.PackageFullName)"
Write-Host "Add a tunnel with: $root\target\$profileName\wgw11.exe add <name> <file.conf>"
