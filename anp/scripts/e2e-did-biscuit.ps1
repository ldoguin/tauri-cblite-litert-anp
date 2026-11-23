# End-to-end test of DID + Biscuit together on real nodes: did:wba identities, tokens bound to them (scoping, expiry,
# revocation), TLS and connection admission. No peer is pinned: the authority's tokens do the trusting.
#
#   pwsh scripts/e2e-did-biscuit.ps1 -Exe <target>\debug\anp-node.exe -Admin <target>\debug\anp-admin.exe
param(
  [string]$Exe = "",
  [string]$Admin = "",
  [string]$Work = ""
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Admin) { $Admin = Get-Bin "anp-admin" }
if (-not $Work) { $Work = Get-WorkDir "e2e-hybrid" }
if (-not $Exe) { $Exe = Get-Bin "anp-node" }
$ErrorActionPreference = "Stop"
$fail = 0
function Check($name, $cond, $detail = "") {
  if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
  else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fail++ }
}
function Rpc($port, $method, $params) {
  $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Depth 20
  Invoke-RestMethod -Uri "http://127.0.0.1:$port/" -Method Post -ContentType "application/json" -Body $body
}
function Msg($text) { @{ messageId = [guid]::NewGuid().ToString(); role = "ROLE_USER"; parts = @(@{ text = $text }) } }
function StartNode($name, $http, $extra = @(), $dir = $name) {
  $out = "$Work\$name.out.txt"; $err = "$Work\$name.err.txt"
  $p = Start-Process $Exe -ArgumentList (@("--name", $name, "--data", "$Work\$dir", "--http-port", $http) + $extra) `
        -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  for ($i = 0; $i -lt 50; $i++) {
    if ((Test-Path $out) -and ((Get-Content $out -ErrorAction SilentlyContinue | Measure-Object).Count -ge 3)) { break }
    if ($p.HasExited) { break }
    Start-Sleep -Milliseconds 200
  }
  $p
}
function Agents($port) { try { @((Invoke-RestMethod "http://127.0.0.1:$port/agents") | ForEach-Object { $_.nodeId }) } catch { @() } }
function WaitSees($port, $name, $secs = 15) {
  for ($i = 0; $i -lt ($secs * 3); $i++) { if ((Agents $port) -contains $name) { return $true }; Start-Sleep -Milliseconds 330 }
  $false
}
function Did($name, $host_, $dir = $name) { ((& $Exe --name $name --data "$Work\$dir" --did-host $host_ --print-did) -split '\s+')[1] }
function RootKey($name) {
  $o = (& $Admin root-keygen --out "$Work\$name.key") -join "`n"
  ([regex]::Match($o, 'root public key:\s*(\S+)')).Groups[1].Value
}
function Issue($rootName, $node, $did, $inboxTo, $dir = $node) {
  [void](& $Admin issue --root "$Work\$rootName.key" --node $node --node-dir "$Work\$dir" --did $did --inbox-to $inboxTo --out "$Work\$node.token")
}
function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:RUST_LOG = "warn"

Write-Host "Setup: DIDs, then tokens bound to them"
$rootPub = RootKey "root"; $fakePub = RootKey "fake"
$d = @{}
foreach ($n in @("alice", "bob", "carol", "mallory")) { $d[$n] = Did $n "$n.example.com" }
Issue "root" "alice" $d.alice "*"
Issue "root" "bob" $d.bob "*"
Issue "root" "carol" $d.carol "bob"          # carol may only message bob
Issue "fake" "mallory" $d.mallory "*"        # mallory's token comes from another authority
$ins = (& $Admin inspect --root-pub $rootPub --token "$Work\carol.token") -join "`n"
Check "the token carries the DID it is bound to" ($ins.Contains($d.carol)) $ins

function Hard($n, $root = $rootPub) { @("--did-host", "$n.example.com", "--root-key", $root, "--token", "$Work\$n.token", "--tls", "--admit") }

$procs = @()
try {
  $alice = StartNode "alice" 18801 (Hard "alice"); $procs += $alice
  $port = ((Get-Content "$Work\alice.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  $url = "wss://127.0.0.1:$port/a2a"; $pin = "$Work\alice\tls.cert.pem"
  $sec = Invoke-RestMethod "http://127.0.0.1:18801/security"
  Check "alice runs in did+biscuit mode with her DID" ($sec.mode -eq "did+biscuit" -and $sec.did -eq $d.alice) ($sec | ConvertTo-Json -Compress)

  $bob = StartNode "bob" 18802 ((Hard "bob") + @("--pin-cert", $pin, "--connect", $url)); $procs += $bob
  Check "bob joins with no pinned peers (the authority's token is the trust anchor)" (WaitSees 18802 "alice")
  Check "alice sees bob" (WaitSees 18801 "bob")
  $r = Rpc 18801 "SendMessage" @{ tenant = "bob"; message = (Msg "hello over DID + token") }
  Check "a task alice -> bob completes" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)
  Check "nothing refused during normal operation" (((Invoke-RestMethod "http://127.0.0.1:18801/security").rejections).Count -eq 0)

  Write-Host "Scoping"
  $carol = StartNode "carol" 18803 ((Hard "carol") + @("--pin-cert", $pin, "--connect", $url)); $procs += $carol
  Check "carol (token: may message bob only) joins" (WaitSees 18803 "alice")
  $r = Rpc 18803 "SendMessage" @{ tenant = "bob"; message = (Msg "carol to bob") }
  Check "carol -> bob (allowed) completes" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)
  $r = Rpc 18803 "SendMessage" @{ tenant = "alice"; message = (Msg "carol to alice, not allowed"); configuration = @{ returnImmediately = $true } }
  $tid = $r.result.task.id
  Start-Sleep -Seconds 8
  $st = (Rpc 18803 "GetTask" @{ id = $tid }).result.status.state
  Check "carol -> alice (not in her token) never completes" ($st -ne "TASK_STATE_COMPLETED") $st
  $rej = (Invoke-RestMethod "http://127.0.0.1:18801/security").rejections
  Check "alice logged the refused command" (($rej | Where-Object { $_.collection -eq "inbox" -and $_.author -eq "carol" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))

  Write-Host "Attackers"
  # 1. a valid DID, a valid token, but from another authority
  $mal = StartNode "mallory" 18804 ((Hard "mallory" $fakePub) + @("--pin-cert", $pin, "--connect", $url)); $procs += $mal
  Start-Sleep -Seconds 8
  Check "mallory (valid DID, token from another authority) never sees alice" (-not ((Agents 18804) -contains "alice"))
  $rej = (Invoke-RestMethod "http://127.0.0.1:18801/security").rejections
  Check "alice logged the refused connection" (($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "mallory" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
  Kill $mal

  # 2. a stolen token: bob's token on a node with another key (and so another DID)
  Copy-Item "$Work\bob.token" "$Work\stolen.token"
  $dFake = Did "bob" "bob.example.com" "fakebob"
  $thief = Start-Process $Exe -ArgumentList @("--name", "bob", "--data", "$Work\fakebob", "--http-port", 18805, "--did-host", "bob.example.com", "--root-key", $rootPub, "--token", "$Work\stolen.token", "--tls", "--admit", "--pin-cert", $pin, "--connect", $url) -NoNewWindow -PassThru -RedirectStandardOutput "$Work\thief.out" -RedirectStandardError "$Work\thief.err"
  $exited = $thief.WaitForExit(15000)
  Check "bob's token cannot even start a node with a different key (the token names bob's DID)" ($exited -and $thief.ExitCode -ne 0) "exited=$exited"
  if (-not $exited) { Kill $thief }
  Check "...and the error says why" ((Get-Content "$Work\thief.err" -Raw) -match 'token is not usable') ((Get-Content "$Work\thief.err" -Raw))

  # 3. a DID-bound token used by a node that proves no DID
  $nodid = Start-Process $Exe -ArgumentList @("--name", "bob", "--data", "$Work\bob2", "--http-port", 18806, "--root-key", $rootPub, "--token", "$Work\bob.token", "--tls") -NoNewWindow -PassThru -RedirectStandardOutput "$Work\nodid.out" -RedirectStandardError "$Work\nodid.err"
  $exited = $nodid.WaitForExit(15000)
  Check "a DID-bound token is useless without the DID" ($exited -and $nodid.ExitCode -ne 0)
  if (-not $exited) { Kill $nodid }

  Write-Host "Revocation"
  Kill $carol
  [void](& $Admin revoke --root "$Work\root.key" --token "$Work\carol.token" --reason "tablet lost" --out "$Work\carol-revoke.json")
  $res = Invoke-RestMethod -Uri "http://127.0.0.1:18801/security/revocations" -Method Post -ContentType "application/json" -InFile "$Work\carol-revoke.json"
  Check "the authority's revocation is accepted" ($res.revoked.Length -ge 32)
  $carol = StartNode "carol" 18803 ((Hard "carol") + @("--pin-cert", $pin, "--connect", $url)); $procs += $carol
  # (carol's database still holds alice's card from before, so /agents proves nothing: check that her task never arrives)
  $r = Rpc 18803 "SendMessage" @{ tenant = "bob"; message = (Msg "revoked carol tries again"); configuration = @{ returnImmediately = $true } }
  $ctid = $r.result.task.id
  Start-Sleep -Seconds 8
  Check "revoked carol (same DID, same key) cannot get a task out: it never reaches bob" ((Rpc 18803 "GetTask" @{ id = $ctid }).result.status.state -eq "TASK_STATE_SUBMITTED" -and (Rpc 18802 "GetTask" @{ id = $ctid }).error.code -eq -32001)
  $rej = (Invoke-RestMethod "http://127.0.0.1:18801/security").rejections
  Check "alice logged: token revoked" (($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "carol" -and $_.reason -like "*revoked*" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
  $sec2 = Invoke-RestMethod "http://127.0.0.1:18802/security"
  Check "bob learned of the revocation through replication" (@($sec2.revokedTokens).Count -ge 1) ($sec2 | ConvertTo-Json -Compress)
  $r = Rpc 18801 "SendMessage" @{ tenant = "bob"; message = (Msg "the others are unaffected") }
  Check "alice <-> bob still works" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED")
}
finally {
  foreach ($p in $procs) { Kill $p }
}
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }
