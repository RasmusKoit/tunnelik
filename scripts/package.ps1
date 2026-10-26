# Builds Tunnelik and packs it into a signed installer: target\Tunnelik-<version>-x64.msix.
# The version comes from package\AppxManifest.xml; pass -Version to override it.
#
#   .\scripts\package.ps1                                     # signs with the certificate from new-cert.ps1
#   .\scripts\package.ps1 -Pfx signing.pfx -PfxPassword ...   # signs with an exported certificate (CI releases)
#   .\scripts\package.ps1 -Unsigned                           # packs only; Windows won't install the result
#
# Installing it needs the signing certificate trusted once (see new-cert.ps1), but not
# Developer Mode, and the installed app doesn't depend on this folder.

param(
    [string]$Version,
    # A PFX file holding the signing certificate and its private key, instead of the user's store.
    [string]$Pfx,
    [string]$PfxPassword,
    # Skip signing; the package is still built and packed.
    [switch]$Unsigned
)

$ErrorActionPreference = 'Stop'
if ($Unsigned -and $Pfx) { throw '-Unsigned and -Pfx exclude each other' }
$root = Split-Path $PSScriptRoot
[xml]$manifest = Get-Content "$root\package\AppxManifest.xml"
if (-not $Version) { $Version = $manifest.Package.Identity.Version }

$sdk = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" |
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1 -ExpandProperty Directory
if (-not $sdk) { throw 'MakeAppx not found; install the Windows SDK (it comes with the VS Build Tools)' }

# cargo reports progress on stderr, which Windows PowerShell would treat as an error under 'Stop'.
$ErrorActionPreference = 'Continue'
& cargo build --release --manifest-path "$root\Cargo.toml" -p tunnelik-host -p tunnelik-plugin -p tunnelik-cli -p tunnelik-app -p tunnelik-service -p tunnelik-watch
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

# Stage the package's contents.
$stage = "$root\target\msix"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory $stage | Out-Null
$manifest.Package.Identity.Version = $Version
$manifest.Save("$stage\AppxManifest.xml")
Copy-Item -Recurse "$root\package\Assets" $stage
foreach ($file in 'tunnelik_host.exe', 'tunnelik_plugin.dll', 'tunnelik.exe', 'tunnelik-app.exe', 'tunnelik_svc.exe', 'tunnelik_watch.exe') {
    Copy-Item "$root\target\release\$file" $stage
}
Copy-Item "$root\README.md", "$root\LICENSE-MIT", "$root\LICENSE-APACHE", "$root\THIRD_PARTY_NOTICES.md" $stage

$msix = "$root\target\Tunnelik-$Version-x64.msix"
& "$sdk\makeappx.exe" pack /o /d $stage /p $msix | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'makeappx pack failed' }

if ($Unsigned) {
    Write-Host "Built $msix (unsigned)"
    return
}

if ($Pfx) {
    # The key stays in the file; EphemeralKeySet keeps Windows from copying it into a key store.
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Resolve-Path $Pfx).Path, $PfxPassword, 'EphemeralKeySet')
    $thumbprint = $cert.Thumbprint
    Export-Certificate -Cert $cert -FilePath "$root\target\Tunnelik.cer" | Out-Null
    $signWith = @('/f', $Pfx)
    if ($PfxPassword) { $signWith += '/p', $PfxPassword }
} else {
    $thumbprint = & "$PSScriptRoot\new-cert.ps1" | Select-Object -Last 1
    $signWith = @('/sha1', $thumbprint, '/s', 'My')
}
# Releases are timestamped so they keep installing after the certificate expires; local
# builds skip it (no network needed, and new-cert.ps1 renews its certificate itself).
if ($Pfx) { $signWith += '/tr', 'http://timestamp.digicert.com', '/td', 'SHA256' }
& "$sdk\signtool.exe" sign /q /fd SHA256 @signWith $msix
if ($LASTEXITCODE -ne 0) { throw 'signtool sign failed' }

Write-Host "Built $msix"
Write-Host "Signed with certificate $thumbprint (public part: $root\target\Tunnelik.cer)"
