# End-to-end test of end-to-end encryption on real nodes: bob sends carol a task through alice, who only relays it.
# A control run without --e2ee proves the relay really can read it otherwise (so the search for plaintext means something).
#
#   pwsh scripts/e2e-e2ee.ps1 -Exe <target>\debug\anp-node.exe
param(
  [string]$Exe = "",
  [string]$Work = ""
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Work) { $Work = Get-WorkDir "e2e-e2ee" }
if (-not $Exe) { $Exe = Get-Bin "anp-node" }
$ErrorActionPreference = "Stop"
$fail = 0
$MARKER = "TOP-SECRET-MARKER-9137"
function Check($name, $cond, $detail = "") {
  if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
  else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fail++ }
}
function Rpc($port, $method, $params) {
  $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Depth 20
  Invoke-RestMethod -Uri "http://127.0.0.1:$port/" -Method Post -ContentType "application/json" -Body $body
}
function Msg($text) { @{ messageId = [guid]::NewGuid().ToString(); role = "ROLE_USER"; parts = @(@{ text = $text }) } }
function StartNode($name, $dir, $http, $extra) {
  $out = "$Work\$dir.out.txt"; $err = "$Work\$dir.err.txt"
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
function WaitSees($port, $name, $secs = 20) {
  for ($i = 0; $i -lt ($secs * 3); $i++) { if ((Agents $port) -contains $name) { return $true }; Start-Sleep -Milliseconds 330 }
  $false
}
function Did($name, $dir) { ((& $Exe --name $name --data "$Work\$dir" --did-host "$name.example.com" --print-did) -split '\s+')[1] }
function FileContains($dir, $text) {
  foreach ($f in Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue) {
    $s = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($f.FullName))
    if ($s.Contains($text)) { return $f.FullName }
  }
  $null
}
function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }
# SendMessage answers with result.task, GetTask with the task as the result.
function TaskText($t) { $task = if ($t.result.task) { $t.result.task } else { $t.result }; (($task.artifacts | ForEach-Object { $_.parts } | ForEach-Object { $_.text }) -join "") }

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:RUST_LOG = "warn"
$procs = @()

# One mesh: alice (relay), bob, carol; each pins the other two. $tag names the data directories.
function Mesh($tag, $e2ee, $port0) {
  $names = @("alice", "bob", "carol")
  $dids = @{}; foreach ($n in $names) { $dids[$n] = Did $n "$tag-$n" }
  $res = @{ Dids = $dids; Procs = @() }
  function Opts($n) {
    $o = @("--did-host", "$n.example.com", "--tls", "--admit")
    foreach ($m in $names) { if ($m -ne $n) { $o += @("--trust-did", $dids[$m]) } }
    if ($e2ee) { $o += "--e2ee" }
    $o
  }
  $res.Alice = StartNode "alice" "$tag-alice" $port0 (Opts "alice")
  $port = ((Get-Content "$Work\$tag-alice.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  $conn = @("--connect", "wss://127.0.0.1:$port/a2a", "--pin-cert", "$Work\$tag-alice\tls.cert.pem")
  $res.Bob = StartNode "bob" "$tag-bob" ($port0 + 1) ((Opts "bob") + $conn)
  $res.Carol = StartNode "carol" "$tag-carol" ($port0 + 2) ((Opts "carol") + $conn)
  $res.Conn = $conn; $res.Port0 = $port0
  $res
}

try {
  Write-Host "Encrypted mesh: bob -> carol through the relay alice"
  $m = Mesh "enc" $true 18901
  $procs += @($m.Alice, $m.Bob, $m.Carol)
  $sec = Invoke-RestMethod "http://127.0.0.1:18901/security"
  Check "nodes report end-to-end encryption on" ($sec.e2ee -eq $true) ($sec | ConvertTo-Json -Compress)
  Check "each node keeps its signed prekeys in its data directory" ((Test-Path "$Work\enc-alice\e2ee-prekeys.json") -and (Test-Path "$Work\enc-bob\e2ee-prekeys.json"))
  $e1 = ($m.Dids.alice -split ':')[-1]
  $doc = Invoke-RestMethod "http://127.0.0.1:18901/agents/alice/$e1/did.json"
  # the layout the ANP SDK uses: keyAgreement refers to an X25519KeyAgreementKey2019 verification method; a deviceManifest names the device
  $ka = @($doc.verificationMethod | Where-Object { $_.id -eq $doc.keyAgreement[0] })
  Check "the DID document publishes an X25519 key-agreement key (a verification method that keyAgreement refers to)" ($ka.Count -eq 1 -and $ka[0].type -eq "X25519KeyAgreementKey2019" -and $ka[0].publicKeyMultibase.StartsWith("z")) ($doc | ConvertTo-Json -Compress -Depth 5)
  Check "...and a deviceManifest lists the device with that key" ($doc.deviceManifest.devices[0].e2ee_key_id -eq $doc.keyAgreement[0] -and $doc.deviceManifest.devices[0].profiles -contains "anp.direct.e2ee.v2")
  Check "bob learns about carol through the relay" (WaitSees 18902 "carol")
  Check "carol learns about bob" (WaitSees 18903 "bob")
  # cards carry the prekey bundles; allow a moment for them to be read
  Start-Sleep -Seconds 3
  $r = Rpc 18902 "SendMessage" @{ tenant = "carol"; message = (Msg "please echo this: $MARKER") }
  $tid = $r.result.task.id
  Check "a task bob -> carol completes" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)
  Check "bob reads carol's result (decrypted on his side)" ((TaskText $r) -like "*$MARKER*") (TaskText $r)
  $g = Rpc 18903 "GetTask" @{ id = $tid }
  Check "carol, the executor, reads her own task back" ((TaskText $g) -like "*$MARKER*")
  Start-Sleep -Seconds 3
  $ga = Rpc 18901 "GetTask" @{ id = $tid }
  Check "alice, who relayed it, cannot read the task (not found through her API)" ($null -ne $ga.error -and $ga.error.code -eq -32001) ($ga | ConvertTo-Json -Depth 6 -Compress)
  $la = Rpc 18901 "ListTasks" @{}
  Check "...nor does it show in her task list" (-not (($la | ConvertTo-Json -Depth 10 -Compress) -like "*$MARKER*"))
  Check "no document was refused anywhere" ((@("18901", "18902", "18903") | ForEach-Object { @((Invoke-RestMethod "http://127.0.0.1:$_/security").rejections).Count } | Measure-Object -Sum).Sum -eq 0)

  Write-Host "A peer that sends plaintext"
  $dDid = Did "dave" "enc-dave"
  # alice, bob and carol learn dave's DID late; restart is avoided by pinning through a fresh node list: dave is pinned only by bob
  Kill $m.Bob
  $bobOpts = @("--did-host", "bob.example.com", "--tls", "--admit", "--e2ee", "--trust-did", $m.Dids.alice, "--trust-did", $m.Dids.carol, "--trust-did", $dDid)
  $m.Bob = StartNode "bob" "enc-bob" 18902 ($bobOpts + $m.Conn); $procs += $m.Bob
  Kill $m.Alice
  $aliceOpts = @("--did-host", "alice.example.com", "--tls", "--admit", "--e2ee", "--trust-did", $m.Dids.bob, "--trust-did", $m.Dids.carol, "--trust-did", $dDid)
  $m.Alice = StartNode "alice" "enc-alice" 18901 $aliceOpts; $procs += $m.Alice
  $port = ((Get-Content "$Work\enc-alice.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  # (alice's listener port changed: bob and carol reconnect to it)
  Kill $m.Bob; Kill $m.Carol
  $conn2 = @("--connect", "wss://127.0.0.1:$port/a2a", "--pin-cert", "$Work\enc-alice\tls.cert.pem")
  $m.Bob = StartNode "bob" "enc-bob" 18902 ($bobOpts + $conn2); $procs += $m.Bob
  $carolOpts = @("--did-host", "carol.example.com", "--tls", "--admit", "--e2ee", "--trust-did", $m.Dids.alice, "--trust-did", $m.Dids.bob)
  $m.Carol = StartNode "carol" "enc-carol" 18903 ($carolOpts + $conn2); $procs += $m.Carol
  # dave: valid DID, pinned by alice and bob, but not running end-to-end encryption
  $dave = StartNode "dave" "enc-dave" 18904 (@("--did-host", "dave.example.com", "--tls", "--admit", "--trust-did", $m.Dids.alice, "--trust-did", $m.Dids.bob) + $conn2); $procs += $dave
  Check "dave (no encryption) joins the mesh and sees bob" (WaitSees 18904 "bob")
  Check "bob sees dave" (WaitSees 18902 "dave")
  $r = Rpc 18904 "SendMessage" @{ tenant = "bob"; message = (Msg "plaintext from dave: DAVE-PLAINTEXT-9137"); configuration = @{ returnImmediately = $true } }
  $dtid = $r.result.task.id
  Start-Sleep -Seconds 8
  $st = (Rpc 18904 "GetTask" @{ id = $dtid }).result.status.state
  Check "dave's plaintext command is never executed (his task does not complete)" ($st -ne "TASK_STATE_COMPLETED") $st
  $rej = (Invoke-RestMethod "http://127.0.0.1:18902/security").rejections
  Check "bob logged the refusal: plaintext where encryption is required" (($rej | Where-Object { $_.reason -like "*plaintext*" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))

  Write-Host "At rest on the relay"
  foreach ($p in @($m.Alice, $m.Bob, $m.Carol, $dave)) { Kill $p }
  Start-Sleep -Seconds 2
  $leak = FileContains "$Work\enc-alice" $MARKER
  Check "the secret is NOT in the relay's database files" ($null -eq $leak) "$leak"
  $daveLeak = FileContains "$Work\enc-alice" "DAVE-PLAINTEXT-9137"
  Write-Host "  note  dave's plaintext message did replicate through the relay ($([bool]$daveLeak)): only bob refused to act on it. That is why dave is the weak link, not alice."
  $procs = @()

  Write-Host "Control: the same task with encryption off"
  $c = Mesh "plain" $false 18911
  $procs += @($c.Alice, $c.Bob, $c.Carol)
  [void](WaitSees 18912 "carol"); [void](WaitSees 18913 "bob"); Start-Sleep -Seconds 3
  $r = Rpc 18912 "SendMessage" @{ tenant = "carol"; message = (Msg "please echo this: $MARKER") }
  $ctid = $r.result.task.id
  Check "control: the task completes" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED")
  Start-Sleep -Seconds 4
  $ga = Rpc 18911 "GetTask" @{ id = $ctid }
  Check "CONTROL: without encryption the relay CAN read the task through its own API" ((TaskText $ga) -like "*$MARKER*") ($ga | ConvertTo-Json -Depth 6 -Compress)
  foreach ($p in $procs) { Kill $p }
  Start-Sleep -Seconds 2
  Check "CONTROL: without encryption the secret IS in the relay's database files" ($null -ne (FileContains "$Work\plain-alice" $MARKER))
  $procs = @()
}
finally {
  foreach ($p in $procs) { Kill $p }
}
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }
