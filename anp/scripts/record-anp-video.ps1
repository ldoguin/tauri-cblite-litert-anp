# Records the ANP field-inspection scenario (tablet, branch office, head office on DIDs, offline and back) as an mp4 with text explainers.
# Starts the three nodes (the tablet's report writer is a rule-based stand-in for the on-device model, `--agent writer`), plays the control-room
# page's own presenter story in a headless Chrome and puts intro and outro cards around it. Nothing appears on screen.
#
#   pwsh scripts/record-anp-video.ps1 [-Out recordings\anp-scenario.mp4]
#
# Needs: the node and admin tool built (cargo build -p anp-node -p anp-authz), Node 22+, Chrome or Edge, ffmpeg.
param(
  [string]$Out = "",
  [string]$Chrome = "",
  [string]$Work = ""
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Work) { $Work = Get-WorkDir "video-demo" }
if (-not $Out) { $Out = Join-Path (Split-Path $PSScriptRoot) "recordings\anp-scenario.mp4" }
$Exe = Get-Bin "anp-node"; $Admin = Get-Bin "anp-admin"
$ErrorActionPreference = "Stop"
$env:RUST_LOG = "warn"; $env:A2A_DB_KEY = "demo database password"

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
Get-Process anp-node -ErrorAction SilentlyContinue | Stop-Process -Force

function RootKey($name) { $o = (& $Admin root-keygen --out "$Work\$name.key") -join "`n"; ([regex]::Match($o, 'root public key:\s*(\S+)')).Groups[1].Value }
function Did($n) { ((& $Exe --name $n --data "$Work\$n" --did-host "$n.field.example.com" --print-did) -split '\s+')[1] }
function Issue($node, $to) { [void](& $Admin issue --root "$Work\root.key" --node $node --node-dir "$Work\$node" --did (Did $node) --inbox-to $to --out "$Work\$node.token") }
function Start-Device($name, $http, $extra) {
  Start-Process $Exe -ArgumentList (@("--name", $name, "--data", "$Work\$name", "--http-port", $http) + $extra) -NoNewWindow -PassThru -RedirectStandardOutput "$Work\$name.out.txt" -RedirectStandardError "$Work\$name.err.txt"
}
function Hard($n) { @("--did-host", "$n.field.example.com", "--e2ee", "--root-key", $rootPub, "--token", "$Work\$n.token", "--tls", "--admit", "--db-key-env", "A2A_DB_KEY") }

$rootPub = RootKey "root"
Issue "tablet" "branch,hq"; Issue "branch" "*"; Issue "hq" "*"
$procs = @()
try {
  $branch = Start-Device "branch" 18802 ((Hard "branch") + @("--agent", "reviewer")); $procs += $branch
  for ($i = 0; $i -lt 50 -and -not ((Get-Content "$Work\branch.out.txt" -ErrorAction SilentlyContinue) -match 'P2P port'); $i++) { Start-Sleep -Milliseconds 200 }
  $port = ((Get-Content "$Work\branch.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  $link = @("--pin-cert", "$Work\branch\tls.cert.pem", "--connect", "wss://127.0.0.1:$port/a2a")
  $procs += Start-Device "hq" 18803 ((Hard "hq") + @("--agent", "claims") + $link)
  $procs += Start-Device "tablet" 18801 ((Hard "tablet") + @("--agent", "writer") + $link)
  $up = $false
  for ($i = 0; $i -lt 120 -and -not $up; $i++) {
    try { $n = (Invoke-RestMethod "http://127.0.0.1:18801/agents") | ForEach-Object { $_.nodeId }; $up = ($n -contains "branch") -and ($n -contains "hq") } catch {}
    Start-Sleep -Milliseconds 500
  }
  if (-not $up) { throw "the three devices did not find each other" }
  Write-Host "mesh up: tablet sees the branch and head office"
  Start-Sleep 3
  $args = @("scripts\video\record.mjs", "--url", "http://127.0.0.1:18801/demo/all?autoplay=1", "--out", $Out)
  if ($Chrome) { $args += @("--chrome", $Chrome) }
  Push-Location (Split-Path $PSScriptRoot); node @args; $code = $LASTEXITCODE; Pop-Location
  if ($code -ne 0) { throw "the recorder exited with $code" }
}
finally { foreach ($p in $procs) { if ($p -and -not $p.HasExited) { $p.Kill() } } }
Write-Host "video: $Out"
