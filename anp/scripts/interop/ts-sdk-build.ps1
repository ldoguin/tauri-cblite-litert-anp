# Installs the official ANP TypeScript SDK into an ISOLATED folder (its own package.json and node_modules) and copies the driver
# next to it. It downloads @awiki/anp-typescript-sdk (Apache-2.0) and its dependencies from the npm registry; install scripts are
# not run (--ignore-scripts); nothing is installed globally.
#
#   pwsh scripts/interop/ts-sdk-build.ps1 [-Dir <target>\ts-sdk] [-Version 0.9.5]
param([string]$Dir = "", [string]$Version = "0.9.5")
. (Join-Path (Split-Path $PSScriptRoot) "common.ps1")
if (-not $Dir) { $Dir = Join-Path (Get-TargetDir) "ts-sdk" }
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Dir | Out-Null
Copy-Item "$PSScriptRoot\ts-sdk\driver.mjs" "$Dir\driver.mjs" -Force
Push-Location $Dir
try {
  if (-not (Test-Path package.json)) { '{"name":"anp-ts-interop","version":"0.0.0","private":true,"type":"module"}' | Set-Content package.json -Encoding ascii }
  npm install "@awiki/anp-typescript-sdk@$Version" --ignore-scripts --no-audit --no-fund 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
  Write-Host "installed @awiki/anp-typescript-sdk $Version in $Dir"
} finally { Pop-Location }