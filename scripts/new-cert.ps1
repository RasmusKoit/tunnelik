# Finds or creates the self-signed certificate that signs Tunnelik's MSIX package, and exports its
# public part to target\Tunnelik.cer. The private key stays in your user certificate store and
# never leaves this PC. Prints the certificate's thumbprint.
#
# Windows only installs the package once Tunnelik.cer is trusted. That's a one-time admin step:
#   Import-Certificate -FilePath target\Tunnelik.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot

# The certificate's subject must match the package's publisher exactly.
[xml]$manifest = Get-Content "$root\package\AppxManifest.xml"
$subject = $manifest.Package.Identity.Publisher
$codeSigning = '1.3.6.1.5.5.7.3.3'

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object {
        $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) -and
        ($_.EnhancedKeyUsageList.ObjectId -contains $codeSigning)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject $subject `
        -FriendlyName 'Tunnelik package signing' `
        -KeyUsage DigitalSignature `
        -TextExtension @("2.5.29.37={text}$codeSigning", '2.5.29.19={text}') `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(3)
    Write-Host "Created signing certificate $($cert.Thumbprint) for $subject, valid until $($cert.NotAfter.ToString('yyyy-MM-dd'))"
}

New-Item -ItemType Directory -Force "$root\target" | Out-Null
Export-Certificate -Cert $cert -FilePath "$root\target\Tunnelik.cer" | Out-Null
$cert.Thumbprint
