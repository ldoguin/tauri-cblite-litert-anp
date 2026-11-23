# The field-inspection scenario (tablet, branch office, head office) on DID identities, run on real nodes with the built-in agents
# in place of the on-device model (that part needs Linux and a model file: scripts/demo-field-inspection.sh runs it with the
# model). The same hardened setup: did:wba identities, Biscuit tokens bound to them (the tablet may only message branch and
# hq), end-to-end encrypted task text, TLS with a pinned certificate, connection admission, and a tablet that loses its signal.
#
#   pwsh scripts/e2e-field-did.ps1 -Exe <target>\debug\anp-node.exe -Admin <target>\debug\anp-admin.exe
param(
  [string]$Exe = "",
  [string]$Admin = "",
  [string]$Work = ""
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Admin) { $Admin = Get-Bin "anp-admin" }
if (-not $Work) { $Work = Get-WorkDir "e2e-field" }
if (-not $Exe) { $Exe = Get-Bin "anp-node" }
$ErrorActionPreference = "Stop"
$fail = 0
function Check($name, $cond, $detail = "") {
  if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
  else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fail++ }
}
function Rpc($port, $method, $params) {
  $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Depth 20
  Invoke-RestMethod -Uri "http://127.0.0.1:$port/" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 60
}
function Msg($text) { @{ messageId = [guid]::NewGuid().ToString(); role = "ROLE_USER"; parts = @(@{ text = $text }) } }
function TaskText($r) { (($r.result.task.artifacts | ForEach-Object { $_.parts | ForEach-Object { $_.text } }) -join "") }
function StartNode($name, $http, $extra = @()) {
  $out = "$Work\$name.out.txt"; $err = "$Work\$name.err.txt"
  $p = Start-Process $Exe -ArgumentList (@("--name", $name, "--data", "$Work\$name", "--http-port", $http) + $extra) -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  for ($i = 0; $i -lt 50; $i++) {
    if ((Test-Path $out) -and ((Get-Content $out -ErrorAction SilentlyContinue | Measure-Object).Count -ge 3)) { break }
    if ($p.HasExited) { break }
    Start-Sleep -Milliseconds 200
  }
  $p
}
function Agents($port) { try { @((Invoke-RestMethod "http://127.0.0.1:$port/agents") | ForEach-Object { $_.nodeId }) } catch { @() } }
function WaitSees($port, $name, $secs = 20) {
  for ($i = 0; $i -lt ($secs * 3); $i++) { if ((Agents $port) -contains $name) { return $true }; Start-Sleep -Milliseconds 330 }
  $false
}
function Did($name) { ((& $Exe --name $name --data "$Work\$name" --did-host "$name.field.example.com" --print-did) -split '\s+')[1] }
function RootKey($name) {
  $o = (& $Admin root-keygen --out "$Work\$name.key") -join "`n"
  ([regex]::Match($o, 'root public key:\s*(\S+)')).Groups[1].Value
}
function Issue($rootName, $node, $inboxTo) {
  [void](& $Admin issue --root "$Work\$rootName.key" --node $node --node-dir "$Work\$node" --did (Did $node) --inbox-to $inboxTo --out "$Work\$node.token")
}
function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }
function Link($up) { [void](Invoke-RestMethod -Uri "http://127.0.0.1:18801/link" -Method Post -Body (@{ up = $up } | ConvertTo-Json)) }

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:RUST_LOG = "warn"; $env:A2A_DB_KEY = "demo database password"

Write-Host "Setup: DIDs, tokens bound to them (the tablet may only message branch and hq)"
$rootPub = RootKey "root"; $fakePub = RootKey "fake"
Issue "root" "tablet" "branch,hq"; Issue "root" "branch" "*"; Issue "root" "hq" "*"; Issue "fake" "mallory" "*"
function Hard($n, $root = $rootPub) { @("--did-host", "$n.field.example.com", "--e2ee", "--root-key", $root, "--token", "$Work\$n.token", "--tls", "--admit", "--db-key-env", "A2A_DB_KEY") }

$procs = @()
try {
  $branch = StartNode "branch" 18802 ((Hard "branch") + @("--agent", "reviewer")); $procs += $branch
  $port = ((Get-Content "$Work\branch.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  $url = "wss://127.0.0.1:$port/a2a"; $pin = "$Work\branch\tls.cert.pem"
  $hq = StartNode "hq" 18803 ((Hard "hq") + @("--agent", "claims", "--pin-cert", $pin, "--connect", $url)); $procs += $hq
  $tablet = StartNode "tablet" 18801 ((Hard "tablet") + @("--agent", "echo", "--pin-cert", $pin, "--connect", $url)); $procs += $tablet
  Check "the tablet sees the branch and head office" ((WaitSees 18801 "branch") -and (WaitSees 18801 "hq"))

  Write-Host "1. Connected"
  $sec = Invoke-RestMethod "http://127.0.0.1:18801/security"
  Check "the tablet runs in did+biscuit mode with end-to-end encryption" ($sec.mode -eq "did+biscuit" -and $sec.e2ee -and $sec.did.StartsWith("did:wba:")) ($sec | ConvertTo-Json -Compress)
  Start-Sleep 3
  $disc = @(Invoke-RestMethod "http://127.0.0.1:18801/discover" | ForEach-Object { $_ })
  Check "every device is a DID, and the tablet has verified each one's signed description" ($disc.Count -eq 3 -and @($disc | Where-Object { $_.did -and $_.did.StartsWith("did:wba:") -and $_.descriptionVerified }).Count -eq 3) ($disc | ConvertTo-Json -Compress -Depth 4)
  $note = "Asset: Plant room B, boiler 3`nFindings: Feed pipe corroded near the flange, small leak at the isolation valve`nRisk: High`nAction: Replace the flange this week"
  $r = Rpc 18801 "SendMessage" @{ message = (Msg $note) }
  $report = TaskText $r
  Check "the tablet writes the report on the device" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED" -and $report.Length -gt 0)
  $rv = Rpc 18801 "SendMessage" @{ tenant = "branch"; message = (Msg $report) }
  $review = TaskText $rv
  Check "the branch reviews it (over TLS, sealed to the branch's key)" ($rv.result.task.status.state -eq "TASK_STATE_COMPLETED" -and $review -match "^REVIEW:") $review
  $hr = Rpc 18801 "SendMessage" @{ tenant = "hq"; message = (Msg ($report + "`n`n" + $review)) }
  $claim = TaskText $hr
  Check "head office answers (files it if approved)" ($claim -match "CLAIM FILED|NOT FILED") $claim

  Write-Host "2. The signal is lost"
  Link $false; Start-Sleep 2
  Check "the tablet reports its link as down" ((Invoke-RestMethod "http://127.0.0.1:18801/link").up -eq $false)
  $note2 = "Asset: Warehouse roof vent 12`nFindings: Seals look good, no water ingress`nRisk: Low`nAction: None"
  $r2 = Rpc 18801 "SendMessage" @{ message = (Msg $note2) }
  Check "offline, the tablet still writes a report on the device" ($r2.result.task.status.state -eq "TASK_STATE_COMPLETED")
  $q = Rpc 18801 "SendMessage" @{ tenant = "branch"; message = (Msg (TaskText $r2)); configuration = @{ returnImmediately = $true } }
  $qid = $q.result.task.id
  Start-Sleep 6
  $st = (Rpc 18801 "GetTask" @{ id = $qid }).result.status.state
  Check "the report for the branch waits: queued, not lost" ($st -eq "TASK_STATE_SUBMITTED") $st

  Write-Host "3. The signal returns"
  Link $true
  $done = $false
  for ($i = 0; $i -lt 60; $i++) { if ((Rpc 18801 "GetTask" @{ id = $qid }).result.status.state -eq "TASK_STATE_COMPLETED") { $done = $true; break }; Start-Sleep 1 }
  Check "the queued report is delivered and reviewed after reconnecting" $done
  $rej = 0; foreach ($pt in 18801, 18802, 18803) { $rej += @((Invoke-RestMethod "http://127.0.0.1:$pt/security").rejections).Count }
  Check "nothing was refused anywhere during normal operation (no false alarms)" ($rej -eq 0) $rej

  Write-Host "4. An unauthorised device tries to join"
  $mallory = StartNode "mallory" 18809 ((Hard "mallory" $fakePub) + @("--pin-cert", $pin, "--connect", $url)); $procs += $mallory
  Start-Sleep 10
  Check "a device with a token from another authority (bound to its own DID) sees nothing of the mesh" (-not ((Agents 18809) -contains "branch"))
  $refused = @((Invoke-RestMethod "http://127.0.0.1:18802/security").rejections) | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "mallory" }
  Check "the branch logged the refused connection" (@($refused).Count -ge 1)
  $err = $null
  try { $x = Rpc 18801 "SendMessage" @{ tenant = "nobody"; message = (Msg "x") }; $err = $x.error } catch { $err = "http error" }
  Check "the tablet cannot be used to message anyone its token does not allow" ($null -ne $err)
}
finally { foreach ($p in $procs) { Kill $p } }
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }