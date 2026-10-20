# Builds Tunnelik and packs it into a signed installer: target\Tunnelik-<version>-x64.msix.
# The version comes from package\AppxManifest.xml; pass -Version to override it.
#
#   .\scripts\package.ps1
#
# Installing it needs the signing certificate trusted once (see new-cert.ps1), but not
# Developer Mode, and the installed app doesn't depend on this folder.

param([string]$Version)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
[xml]$manifest = Get-Content "$root\package\AppxManifest.xml"
if (-not $Version) { $Version = $manifest.Package.Identity.Version }

$sdk = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" |
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1 -ExpandProperty Directory
if (-not $sdk) { throw 'MakeAppx not found; install the Windows SDK (it comes with the VS Build Tools)' }

# cargo reports progress on stderr, which Windows PowerShell would treat as an error under 'Stop'.
$ErrorActionPreference = 'Continue'
& cargo build --release --manifest-path "$root\Cargo.toml" -p tunnelik-host -p tunnelik-plugin -p tunnelik-cli -p tunnelik-app
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

# Stage the package's contents.
$stage = "$root\target\msix"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory $stage | Out-Null
$manifest.Package.Identity.Version = $Version
$manifest.Save("$stage\AppxManifest.xml")
Copy-Item -Recurse "$root\package\Assets" $stage
foreach ($file in 'tunnelik_host.exe', 'tunnelik_plugin.dll', 'tunnelik.exe', 'tunnelik-app.exe') {
    Copy-Item "$root\target\release\$file" $stage
}
Copy-Item "$root\README.md", "$root\LICENSE-MIT", "$root\LICENSE-APACHE", "$root\THIRD_PARTY_NOTICES.md" $stage

$msix = "$root\target\Tunnelik-$Version-x64.msix"
& "$sdk\makeappx.exe" pack /o /d $stage /p $msix | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'makeappx pack failed' }

$thumbprint = & "$PSScriptRoot\new-cert.ps1" | Select-Object -Last 1
& "$sdk\signtool.exe" sign /q /fd SHA256 /sha1 $thumbprint /s My $msix
if ($LASTEXITCODE -ne 0) { throw 'signtool sign failed' }

Write-Host "Built $msix"
Write-Host "Signed with certificate $thumbprint (public part: $root\target\Tunnelik.cer)"
