# End-to-end test of DID mode (ANP did:wba identities) on real nodes: TLS + admission by DID assertion.
#
#   pwsh scripts/e2e-did.ps1 -Exe <target>\debug\anp-node.exe
param(
  [string]$Exe = "",
  [string]$AdTool = "",
  [string]$Work = ""
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Work) { $Work = Get-WorkDir "e2e-did" }
if (-not $Exe) { $Exe = Get-Bin "anp-node" }
if (-not $AdTool) { $AdTool = Get-Bin "anp-ad" }
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
function StartNode($name, $http, $extra = @()) {
  $out = "$Work\$name.out.txt"; $err = "$Work\$name.err.txt"
  $p = Start-Process $Exe -ArgumentList (@("--name", $name, "--data", "$Work\$name", "--http-port", $http) + $extra) `
        -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  for ($i = 0; $i -lt 50; $i++) {
    if ((Test-Path $out) -and ((Get-Content $out -ErrorAction SilentlyContinue | Measure-Object).Count -ge 3)) { break }
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
# Windows PowerShell 5.1 returns application/ld+json as bytes and wraps JSON arrays: decode by hand.
function GetJson($url) { $r = Invoke-WebRequest $url -UseBasicParsing; $c = $r.Content; if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }; [pscustomobject]@{ Json = ($c | ConvertFrom-Json); Type = "$($r.Headers['Content-Type'])"; Raw = $c } }
function AdVerify([string[]]$a) { $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"; $o = (& $AdTool verify @a 2>&1 | Out-String); $c = $LASTEXITCODE; $ErrorActionPreference = $old; [pscustomobject]@{ Code = $c; Out = $o } }
function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:RUST_LOG = "warn"

Write-Host "Setup: each node creates its key and shows the DID it names"
$aliceDid = Did "alice" "alice.example.com"
$bobDid = Did "bob" "bob.example.com"
$malDid = Did "mallory" "evil.example.com"
$carolDid = Did "carol" "alice.example.com"   # a second agent on alice's domain
$fakeBobDid = Did "bob" "bob.example.com" "fakebob"   # same name and host as bob, a different key
Check "DIDs have the did:wba path form with an e1_ fingerprint" ($aliceDid -match '^did:wba:alice\.example\.com:agents:alice:e1_[A-Za-z0-9_-]{43}$') $aliceDid
Check "the same name and host with another key is a different DID" ($fakeBobDid -ne $bobDid)
Check "the DID is stable across restarts (it comes from the key)" ((Did "alice" "alice.example.com") -eq $aliceDid)

$procs = @()
try {
  function Mesh($name) { @("--did-host", "$name.example.com", "--tls", "--admit") }
  $alice = StartNode "alice" 18701 ((Mesh "alice") + @("--trust-did", $bobDid, "--trust-did", $carolDid)); $procs += $alice
  $port = ((Get-Content "$Work\alice.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  $url = "wss://127.0.0.1:$port/a2a"; $pin = "$Work\alice\tls.cert.pem"
  $sec = Invoke-RestMethod "http://127.0.0.1:18701/security"
  Check "alice reports DID mode and her DID" ($sec.mode -eq "did" -and $sec.did -eq $aliceDid) ($sec | ConvertTo-Json -Compress)

  $e1 = ($aliceDid -split ':')[-1]
  $doc = Invoke-RestMethod "http://127.0.0.1:18701/agents/alice/$e1/did.json"
  Check "alice serves her DID document at the URL did:wba resolution derives" ($doc.id -eq $aliceDid -and $doc.proof.cryptosuite -eq "eddsa-jcs-2022" -and $doc.verificationMethod[0].type -eq "Multikey") ($doc | ConvertTo-Json -Compress -Depth 5)
  $code = try { [void](Invoke-WebRequest "http://127.0.0.1:18701/agents/alice/e1_wrong/did.json" -UseBasicParsing); 200 } catch { [int]$_.Exception.Response.StatusCode }
  Check "a wrong fingerprint is a 404" ($code -eq 404) "$code"

  # ANP-07: the DID document points at an agent description, signed by the same key
  $svc = $doc.service | Where-Object { $_.type -eq "AgentDescription" }
  Check "alice's DID document advertises her agent description" ($svc -ne $null -and $svc.serviceEndpoint -eq "https://alice.example.com/agents/alice/ad.json") ($doc | ConvertTo-Json -Compress -Depth 5)
  Invoke-WebRequest "http://127.0.0.1:18701/agents/alice/$e1/did.json" -UseBasicParsing -OutFile "$Work\alice.did.json"
  Invoke-WebRequest "http://127.0.0.1:18701/agents/alice/ad.json" -UseBasicParsing -OutFile "$Work\alice.ad.json"
  $ad = Get-Content "$Work\alice.ad.json" -Raw | ConvertFrom-Json
  Check "alice serves an ANP-07 agent description (protocolType ANP, her DID, an A2A interface)" ($ad.protocolType -eq "ANP" -and $ad.type -eq "AgentDescription" -and $ad.did -eq $aliceDid -and $ad.interfaces[0].protocol -eq "A2A") ((Get-Content "$Work\alice.ad.json" -Raw))
  $v = AdVerify @("--ad", "$Work\alice.ad.json", "--did-doc", "$Work\alice.did.json", "--domain", "alice.example.com")
  Check "anp-ad verifies it against her DID document, bound to her domain" ($v.Code -eq 0) $v.Out
  $v = AdVerify @("--ad", "$Work\alice.ad.json", "--did-doc", "$Work\alice.did.json", "--domain", "evil.example.com")
  Check "...and refuses it when fetched from another domain" ($v.Code -ne 0 -and $v.Out -match "fetched from") $v.Out
  (Get-Content "$Work\alice.ad.json" -Raw).Replace('"name":"alice"','"name":"alice-the-fake"') | Set-Content "$Work\tampered.ad.json" -Encoding utf8 -NoNewline
  $v = AdVerify @("--ad", "$Work\tampered.ad.json", "--did-doc", "$Work\alice.did.json")
  Check "...and refuses a tampered description" ($v.Code -ne 0 -and ((Get-Content "$Work\tampered.ad.json" -Raw) -ne (Get-Content "$Work\alice.ad.json" -Raw))) $v.Out
  $code = try { [void](Invoke-WebRequest "http://127.0.0.1:18701/agents/bob/ad.json" -UseBasicParsing); 200 } catch { [int]$_.Exception.Response.StatusCode }
  Check "a node only describes itself (404 for another name)" ($code -eq 404) "$code"
  $bob = StartNode "bob" 18702 ((Mesh "bob") + @("--trust-did", $aliceDid, "--trust-did", $carolDid, "--pin-cert", $pin, "--connect", $url)); $procs += $bob
  Check "bob (a pinned DID, TLS) joins and sees alice" (WaitSees 18702 "alice")
  Check "alice sees bob" (WaitSees 18701 "bob")
  $r = Rpc 18701 "SendMessage" @{ tenant = "bob"; message = (Msg "hello over a DID-authenticated link") }
  Check "a task alice -> bob completes" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)
  Check "nothing was refused during normal operation" (((Invoke-RestMethod "http://127.0.0.1:18701/security").rejections).Count -eq 0)

  Write-Host "ANP-08 discovery"
  $carol = StartNode "carol" 18706 ((Mesh "alice") + @("--trust-did", $aliceDid, "--trust-did", $bobDid, "--pin-cert", $pin, "--connect", $url)); $procs += $carol
  Check "carol (another agent on alice's domain) joins" (WaitSees 18706 "alice")
  $names = @()
  for ($i = 0; $i -lt 40; $i++) {
    $wk = GetJson "http://127.0.0.1:18701/.well-known/agent-descriptions"
    $names = @(@($wk.Json.items) | ForEach-Object { $_.name })
    if ($names -contains "carol") { break }
    Start-Sleep -Milliseconds 500
  }
  $list = $wk.Json
  Check "/.well-known/agent-descriptions is a JSON-LD CollectionPage served as application/ld+json" ($list.'@type' -eq "CollectionPage" -and $wk.Type -like "application/ld+json*") $wk.Type
  Check "it lists the agents under alice's domain: alice and carol, not bob" (($names -join ",") -eq "alice,carol") ($names -join ",")
  Check "each item is an ad:AgentDescription with the URL of its description" (@($list.items | Where-Object { $_.'@type' -eq 'ad:AgentDescription' -and $_.'@id' -like 'https://alice.example.com/agents/*/ad.json' }).Count -eq 2) ($wk.Raw)
  $p2 = (GetJson "http://127.0.0.1:18701/.well-known/agent-descriptions?page=2").Json
  Check "a page past the end is empty and has no next" (@($p2.items).Count -eq 0 -and $null -eq $p2.next)
  $disc = @((GetJson "http://127.0.0.1:18701/discover").Json)
  $byName = @{}; foreach ($d in $disc) { $byName[$d.nodeId] = $d }
  Check "/discover on alice knows alice, bob and carol, every description verified" ($disc.Count -eq 3 -and @($disc | Where-Object { $_.descriptionVerified }).Count -eq 3) ((GetJson "http://127.0.0.1:18701/discover").Raw)
  Check "bob's description verified on alice with no contact with bob's domain (it replicated with his card)" ($byName["bob"].descriptionVerified -eq $true -and $byName["bob"].descriptionUrl -eq "https://bob.example.com/agents/bob/ad.json" -and $byName["bob"].did -eq $bobDid)
  # carol's card has to cross alice to reach bob: wait for it rather than race it
  for ($i = 0; $i -lt 60; $i++) {
    $discBob = @((GetJson "http://127.0.0.1:18702/discover").Json)
    if (@($discBob | Where-Object { $_.nodeId -eq "carol" -and $_.descriptionVerified }).Count -eq 1) { break }
    Start-Sleep -Milliseconds 500
  }
  Check "bob discovers carol too, through the mesh" (@($discBob | Where-Object { $_.nodeId -eq "carol" -and $_.descriptionVerified }).Count -eq 1) ((GetJson "http://127.0.0.1:18702/discover").Raw)
  $wkBob = (GetJson "http://127.0.0.1:18702/.well-known/agent-descriptions").Json
  Check "bob's own domain listing holds only bob" ((@(@($wkBob.items) | ForEach-Object { $_.name }) -join ",") -eq "bob") ($wkBob | ConvertTo-Json -Compress -Depth 4)
  $rj = (Invoke-RestMethod "http://127.0.0.1:18701/security").rejections
  Check "nothing was refused during discovery" (@($rj).Count -eq 0) ($rj | ConvertTo-Json -Compress -Depth 4)
  Write-Host "Attackers"
  # 1. a stranger with a perfectly valid DID of their own
  $mal = StartNode "mallory" 18703 ((Mesh "evil") + @("--trust-did", $aliceDid, "--pin-cert", $pin, "--connect", $url)); $procs += $mal
  Start-Sleep -Seconds 8
  Check "mallory (valid DID, nobody pinned it) never sees alice" (-not ((Agents 18703) -contains "alice"))
  $rej = (Invoke-RestMethod "http://127.0.0.1:18701/security").rejections
  Check "alice logged the refused connection: not a trusted identity" (($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "mallory" -and $_.reason -like "*not a trusted identity*" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
  Check "no mallory document ever reached alice" (-not ((Agents 18701) -contains "mallory"))
  Kill $mal

  # 2. an impersonator: same name and domain as bob, but not bob's key
  $fp =Start-Process $Exe -ArgumentList (@("--name", "bob", "--data", "$Work\fakebob", "--http-port", 18704) + (Mesh "bob") + @("--trust-did", $aliceDid, "--pin-cert", $pin, "--connect", $url)) -NoNewWindow -PassThru -RedirectStandardOutput "$Work\fakebob.out" -RedirectStandardError "$Work\fakebob.err"
  $procs += $fp
  Start-Sleep -Seconds 8
  Check "an impersonator named bob on bob's domain, with another key, is refused" (-not ((Agents 18704) -contains "alice"))
  $rej = (Invoke-RestMethod "http://127.0.0.1:18701/security").rejections
  Check "alice logged it" (($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "bob" -and $_.reason -like "*not a trusted identity*" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
  Kill $fp
  $r = Rpc 18701 "SendMessage" @{ tenant = "bob"; message = (Msg "the real bob is unaffected") }
  Check "the real bob still works afterwards" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED")

  # 3. no credentials at all
  $anon = StartNode "anon" 18705 @("--tls", "--pin-cert", $pin, "--connect", $url); $procs += $anon
  Start-Sleep -Seconds 6
  Check "a node with TLS but no DID is refused" (-not ((Agents 18705) -contains "alice"))
  Kill $anon
}
finally {
  foreach ($p in $procs) { Kill $p }
}
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }
