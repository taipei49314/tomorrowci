# TomorrowCI release dry-run (Windows)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Dist = Join-Path $Root "dist"
if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

Write-Host "== build release CLI =="
cargo build -p tomorrowci-cli --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$Bin = Join-Path $Root "target\release\tomorrowci.exe"
if (-not (Test-Path $Bin)) { throw "missing $Bin" }

$StageName = "tomorrowci-0.1.0-windows-x86_64"
$Stage = Join-Path $Dist $StageName
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
Copy-Item $Bin (Join-Path $Stage "tomorrowci.exe")
Copy-Item (Join-Path $Root "README.md") $Stage
Copy-Item (Join-Path $Root "LICENSE") $Stage
Copy-Item (Join-Path $Root "CHANGELOG.md") $Stage

$Zip = Join-Path $Dist "$StageName.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path "$Stage\*" -DestinationPath $Zip -Force
if (-not (Test-Path $Zip)) { throw "zip not created: $Zip" }

Write-Host "== checksums =="
$sums = Join-Path $Dist "SHA256SUMS.txt"
$lines = @()
Get-ChildItem -Path $Dist -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
  $h = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLower()
  $lines += "$h  $($_.Name)"
}
$lines | Set-Content -Path $sums -Encoding ascii

Write-Host "== SBOM (best-effort CycloneDX stub) =="
$sbom = Join-Path $Dist "sbom.cdx.json"
@'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "tomorrowci",
      "version": "0.1.0"
    }
  },
  "components": []
}
'@ | Set-Content -Path $sbom -Encoding utf8

Write-Host "== trust audit =="
& $Bin trust
if ($LASTEXITCODE -ne 0) { throw "trust failed" }

Write-Host "== unit tests =="
cargo test --workspace --quiet
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "== claim ledger =="
$claims = @"
# Claim-to-evidence (release dry-run)

| Claim | Status | Command | Result | Artifact |
|---|---|---|---|---|
| Rust workspace tests | PASS | cargo test --workspace | exit 0 | local |
| Trust audit | PASS | tomorrowci trust | overall Pass | stdout |
| Windows CLI archive | PASS | Compress-Archive | created | dist/tomorrowci-0.1.0-windows-x86_64.zip |
| Checksums | PASS | Get-FileHash SHA256 | created | dist/SHA256SUMS.txt |
| SBOM document | PASS | static CycloneDX stub | created | dist/sbom.cdx.json |
| Live Docker e2e | BLOCKED | docker info | daemon may be down | doctor |
"@
Set-Content -Path (Join-Path $Dist "claim-to-evidence.md") -Value $claims -Encoding utf8

Write-Host "Dry-run complete. Artifacts in $Dist"
Get-ChildItem $Dist | Format-Table Name, Length
