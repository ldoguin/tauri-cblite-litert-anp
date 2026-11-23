# The node as a group host for end-to-end encrypted groups (ANP P6): this project's MLS devices (alice, bob, carol) talk to /anp/groups over HTTP with signed requests (ANP-02).
#   pwsh scripts/e2e-group-host.ps1 [-Exe <target>\debug\anp-node.exe] [-Port 18950]
param(
  [string]$Exe = "",
  [int]$Port = 18950,
  [string]$Work = ""
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Work) { $Work = Get-WorkDir "p6" }
if (-not $Exe) { $Exe = Get-Bin "anp-node" }
$ErrorActionPreference = "Continue"
Set-Location (Split-Path $PSScriptRoot)
Get-Process anp-node -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force $Work | Out-Null
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Get-TargetDir }

$env:ANP_P6_STEP = "docs"; $env:ANP_P6_DIR = $Work
cargo test -q -p anp-group-host --test node_live live_docs 2>&1 | Out-Null

$origin = "http://127.0.0.1:$Port"
$a = @("--name", "grp", "--data", "$Work\node", "--http-port", $Port, "--did-host", "groups.example", "--public-origin", $origin, "--require-auth", "--group-host")
foreach ($f in Get-ChildItem $Work -Filter *.did.json) { $a += @("--allow-caller", $f.FullName) }
$p = Start-Process $Exe -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput "$Work\node.out" -RedirectStandardError "$Work\node.err"
$fail = 0
try {
  Start-Sleep 3
  $env:ANP_P6_STEP = "run"; $env:ANP_P6_URL = $origin; $env:ANP_P6_SIGN = "1"
  $out = cargo test -q -p anp-group-host --test node_live live_ -- --nocapture --test-threads=1 2>&1 | Out-String
  if ($out -match "test result: ok. 6 passed") { "PASS  devices create/add/send/remove through the node's P6 host over signed HTTP; two devices of one DID in a group; a held pull (wait_ms) returns when a delivery arrives; the WebSocket push channel (signed upgrade, push, ack), roster/policy hashes, the member cap, the signed group state" }
  else { "FAIL  P6 host live test"; $out; "--- node log"; Get-Content "$Work\node.err" -Tail 20; $fail = 1 }
} finally { Stop-Process $p -Force -ErrorAction SilentlyContinue }


# The official Rust SDK as the third device of a group, through the node (open mailboxes: the HTTP signatures were exercised above).
# Needs the SDK driver built in WSL (scripts/interop/rust-sdk-group-build.sh).
$have = (wsl -d Ubuntu -- bash -c "test -x ~/anp-interop/rust-sdk-group/target/debug/anp-rust-group-interop && echo yes") -match "yes"
if ($have) {
  $W2 = Get-WorkDir "p6sdk"; $wsl2 = ConvertTo-WslPath $W2
  Remove-Item $W2 -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force $W2 | Out-Null
  [void](wsl -d Ubuntu -- bash -c "cd ~/anp-interop/rust-sdk-group && ./target/debug/anp-rust-group-interop kp $wsl2 sdk"); [void](wsl -d Ubuntu -- bash -c "cd ~/anp-interop/rust-sdk-group && ./target/debug/anp-rust-group-interop kp $wsl2 sdk2"); [void](wsl -d Ubuntu -- bash -c "cd ~/anp-interop/rust-sdk-group && ./target/debug/anp-rust-group-interop kpextra $wsl2 sdk sdkb")
  $env:ANP_P6_STEP = "docs"; $env:ANP_P6_DIR = $W2
  cargo test -q -p anp-group-host --test node_live live_docs 2>&1 | Out-Null
  $port2 = $Port + 1; $origin2 = "http://127.0.0.1:$port2"
  $a2 = @("--name", "grp2", "--data", "$W2\node", "--http-port", $port2, "--did-host", "groups.example", "--public-origin", $origin2, "--group-host", "--group-open-mailboxes")
  foreach ($f in Get-ChildItem $W2 -Filter *.did.json) { $a2 += @("--allow-caller", $f.FullName) }
  $p2 = Start-Process $Exe -ArgumentList $a2 -NoNewWindow -PassThru -RedirectStandardOutput "$W2\node.out" -RedirectStandardError "$W2\node.err"
  try {
    Start-Sleep 3
    $env:ANP_P6_STEP = "sdk"; $env:ANP_P6_URL = $origin2; $env:ANP_P6_SDK_WDIR = $wsl2; Remove-Item Env:\ANP_P6_SIGN -ErrorAction SilentlyContinue
    $out = cargo test -q -p anp-group-host --test node_live live_sdk_as_third_device -- --nocapture 2>&1 | Out-String
    $out -split "`n" | Where-Object { $_ -match "^\s+sdk :" } | ForEach-Object { $_.TrimEnd() }
    if ($out -match "test result: ok. 1 passed") { "PASS  the SDK is the third device of a group through the node (welcome, a commit made here, its message with its origin proof, reading ours), and the controller of another group (create, add, send signed by the SDK)" }
    else { "FAIL  SDK through the host"; $out; "--- node log"; Get-Content "$W2\node.err" -Tail 20; $fail = 1 }
  } finally { Stop-Process $p2 -Force -ErrorAction SilentlyContinue }
} else { "The SDK part is skipped (scripts/interop/rust-sdk-group-build.sh builds the SDK driver in WSL)" }
if ($fail) { "FAILED"; exit 1 } else { "ALL PASSED" }