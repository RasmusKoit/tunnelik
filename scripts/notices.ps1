# Regenerates THIRD_PARTY_NOTICES.md from the licenses of all dependencies.
# Needs cargo-about: cargo install cargo-about --locked

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
cargo about generate --manifest-path "$root\Cargo.toml" --config "$root\about.toml" "$root\about.hbs" --output-file "$root\THIRD_PARTY_NOTICES.md"
if ($LASTEXITCODE -ne 0) { throw 'cargo about failed' }
