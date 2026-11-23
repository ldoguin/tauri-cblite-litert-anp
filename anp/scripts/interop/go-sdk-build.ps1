# Builds the Go SDK driver (scripts/interop/go-sdk/main.go) in an ISOLATED folder: its own module, its own module cache. It
# downloads github.com/agent-network-protocol/anp/golang (Apache-2.0) and its dependencies through the Go module proxy, once.
# The user-level Go configuration is ignored (GOENV=off) and nothing is installed system-wide.
#
#   pwsh scripts/interop/go-sdk-build.ps1 [-Dir <target>\go-sdk] [-Version v1.0.7]
param([string]$Dir = "", [string]$Version = "v1.0.7", [string]$Go = "")
. (Join-Path (Split-Path $PSScriptRoot) "common.ps1")
if (-not $Dir) { $Dir = Join-Path (Get-TargetDir) "go-sdk" }
if (-not $Go) { $Go = Get-GoExe }
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Dir | Out-Null
Copy-Item "$PSScriptRoot\go-sdk\main.go" "$Dir\main.go" -Force
Push-Location $Dir
try {
  $env:GOENV = "off"; $env:GOPROXY = "https://proxy.golang.org,direct"; $env:GOPATH = "$Dir\gopath"; $env:GOMODCACHE = "$Dir\gopath\pkg\mod"; $env:GOFLAGS = "-mod=mod"
  if (-not (Test-Path go.mod)) { & $Go mod init anp-go-interop 2>&1 | Out-Null }
  & $Go get "github.com/agent-network-protocol/anp/golang@$Version" 2>&1 | Out-Null
  & $Go build -o "$Dir\anp-go-interop.exe" .
  if ($LASTEXITCODE -ne 0) { throw "go build failed" }
  Write-Host "built $Dir\anp-go-interop.exe (anp/golang $Version)"
} finally { Pop-Location }