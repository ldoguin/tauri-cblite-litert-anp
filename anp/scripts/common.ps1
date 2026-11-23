# Paths shared by the scripts. Dot-source it from a script:   . (Join-Path $PSScriptRoot "common.ps1")
# Everything is derived from CARGO_TARGET_DIR (where `cargo build` puts the binaries), or from <repo>\target (the workspace root) when it is not set, which is
# cargo's own default. Nothing here names a drive or a user.

function Get-TargetDir {
  if ($env:CARGO_TARGET_DIR) { return $env:CARGO_TARGET_DIR }
  Join-Path (Split-Path (Split-Path $PSScriptRoot)) "target"   # anp/scripts -> the workspace root
}

function Get-ExeSuffix {
  if ([IO.Path]::DirectorySeparatorChar -eq '\') { ".exe" } else { "" }
}

# A built program: Get-Bin "anp-node" -> <target>\debug\anp-node.exe (no suffix off Windows). `-Sub` picks another folder, e.g. "debug\examples".
function Get-Bin([string]$Name, [string]$Sub = "debug") {
  Join-Path (Join-Path (Get-TargetDir) $Sub) ($Name + (Get-ExeSuffix))
}

# A scratch folder for a script's runs, next to the build output: Get-WorkDir "e2e-did" -> <target>\e2e-did
function Get-WorkDir([string]$Name) {
  Join-Path (Get-TargetDir) $Name
}

# The path of a Windows folder as WSL sees it (C:\x\y -> /mnt/c/x/y); unchanged where the path is already a POSIX one.
function ConvertTo-WslPath([string]$Path) {
  if ($Path -match '^([A-Za-z]):[\\/](.*)$') { return "/mnt/" + $Matches[1].ToLower() + "/" + ($Matches[2] -replace '\\', '/') }
  $Path -replace '\\', '/'
}

# The Go toolchain: the one on PATH, else the usual Windows install.
function Get-GoExe {
  $c = Get-Command go -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  "C:\Program Files\Go\bin\go.exe"
}
