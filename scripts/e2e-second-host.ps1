# The P6 group host on a REAL second machine: the node runs on another host (Linux, built there with scripts/linux-node-build.sh),
# and this project's devices (alice, bob, carol) use it over the network with signed HTTP requests (ANP-02): provision a group DID,
# fetch its document, key packages, create, add, send, receipts, mailboxes, remove. Different machine, different network path, a
# different clock: the host checks the signatures' freshness against its own, so clock skew shows up here and nowhere in a loopback test.
#
#   pwsh scripts/e2e-second-host.ps1 -RemoteHost me@box.example.net -RemoteAddr box.example.net `
#        -RemoteDir '~/anp-linux'
#
# What it needs:
#   * ssh/scp access to the remote machine without a password prompt (key or agent);
#   * the node built there (scripts/linux-node-build.sh puts it in ~/anp-linux/target/debug), the port free and reachable from here;
#   * rust/cargo here (the devices are the Rust test in crates/anp-group-host/tests/node_live.rs).
# It copies the devices' public DID documents (not keys) to the remote, starts the node there, runs the test against it, and stops it.
#
# Two parts: (1) the P6 group host, all the live tests (HTTP, the WebSocket push channel, state hashes, the member cap, two devices of one DID, a held pull);
# (2) the MESH of scripts/e2e-cross-os.ps1 with the second node on the remote host: DIDs and tokens bound to them, TLS with a pinned certificate,
#     admission, end-to-end encryption, tasks both ways, descriptions verified, scoping, an unauthorised node refused, the remote node restarted.
#     Here the node on THIS machine dials the remote one (so only the remote's ports need to be reachable: -MeshHttpPort and -MeshP2pPort).
#
# STATUS: run with the second "host" being the WSL2 VM on the same PC (a different OS, Couchbase Lite build and network stack, reached over
# its own IP). It has NOT been run against a physically separate machine.
param(
  [Parameter(Mandatory = $true)][string]$RemoteHost,   # ssh target, e.g. user@box
  [Parameter(Mandatory = $true)][string]$RemoteAddr,   # the name or address this machine reaches the node at (and which signs requests' target)
  [string]$RemoteDir = "~/anp-linux",
  [int]$Port = 18950,
  [int]$SshPort = 22,                                  # the remote's ssh port
  [string]$KnownHosts = "",                            # a known_hosts file to use instead of the default (e.g. a throwaway one for a local VM)
    [string]$Identity = "",                              # an ssh private key to use (BatchMode: it must not need a passphrase)
  [string]$Work = "",
  [string]$Exe = "",       # the node and admin tool on THIS machine, for the mesh part
  [string]$Admin = "",
  [int]$MeshHttpPort = 18802,                          # the remote mesh node's HTTP port
  [int]$MeshP2pPort = 18803,                           # and its P2P (replication) port
  [switch]$SkipMesh
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Admin) { $Admin = Get-Bin "anp-admin" }
if (-not $Work) { $Work = Get-WorkDir "p6remote" }
if (-not $Exe) { $Exe = Get-Bin "anp-node" }
$ErrorActionPreference = "Continue"
$sshOpts = @("-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new", "-p", "$SshPort"); if ($Identity) { $sshOpts += @("-i", $Identity, "-o", "IdentitiesOnly=yes") }
if ($KnownHosts) { $kh = @("-o", "UserKnownHostsFile=$KnownHosts") } else { $kh = @() }
$scpOpts = @("-q", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-P", "$SshPort"); if ($Identity) { $scpOpts += @("-i", $Identity, "-o", "IdentitiesOnly=yes") }
$sshOpts += $kh; $scpOpts += $kh
# (not named Ssh: PowerShell command names are case-insensitive, so the function would call itself)
function RemoteSh { ssh.exe @sshOpts $RemoteHost @args }
Set-Location (Split-Path $PSScriptRoot)
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Get-TargetDir }
Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force $Work | Out-Null

Write-Host "Remote: $(RemoteSh 'uname -sr; uname -m; date -u +%FT%TZ') (here: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')))"

$env:ANP_P6_STEP = "docs"; $env:ANP_P6_DIR = $Work
cargo test -q -p anp-group-host --test node_live live_docs 2>&1 | Out-Null
RemoteSh "rm -rf ~/x/p6remote && mkdir -p ~/x/p6remote/docs"
foreach ($f in Get-ChildItem $Work -Filter *.did.json) { scp.exe @scpOpts $f.FullName "${RemoteHost}:~/x/p6remote/docs/" }

$origin = "http://${RemoteAddr}:$Port"
$docs = (Get-ChildItem $Work -Filter *.did.json | ForEach-Object { "--allow-caller ~/x/p6remote/docs/$($_.Name)" }) -join " "
$start = "lib=`$(ls -d $RemoteDir/target/debug/build/couchbase_lite-*/out | head -1); export LD_LIBRARY_PATH=`$lib RUST_LOG=warn; cd $RemoteDir/target/debug; " +
  "nohup ./anp-node --name grp --data ~/x/p6remote/node --http-port $Port --did-host groups.example --public-origin $origin --require-auth --p6-host $docs > ~/x/p6remote/node.out 2> ~/x/p6remote/node.err < /dev/null & echo started"
$fail = 0
try {
  RemoteSh $start
  Start-Sleep 5
  $env:ANP_P6_STEP = "run"; $env:ANP_P6_URL = $origin; $env:ANP_P6_SIGN = "1"
  $out = cargo test -q -p anp-group-host --test node_live live_ -- --nocapture --test-threads=1 2>&1 | Out-String
  if ($out -match "test result: ok. 6 passed") { "PASS  the group host on ${RemoteHost}: create/add/send/remove over signed HTTP across the network, two devices of one DID, a held pull, the WebSocket push channel (signed upgrade, push, ack), roster/policy hashes, the member cap and the signed group state" }
  else { "FAIL  P6 host on the second machine"; $out; "--- remote node log"; RemoteSh "tail -20 ~/x/p6remote/node.err"; $fail = 1 }
} finally { RemoteSh "pkill -f '[a]np-node --name grp'" | Out-Null }

# ── part 2: the mesh, the second node on the remote host ────────────────────────────────────────────────────
if (-not $SkipMesh) {
  Write-Host "Mesh: this machine's node (alice) dials the remote node (bob)"
  $M = "$Work\mesh"; New-Item -ItemType Directory -Force $M | Out-Null
  function Check($name, $cond, $detail = "") {
    if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green } else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fail++ }
  }
  function Rpc($base, $method, $params, $timeout = 60) {
    $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Depth 20
    Invoke-RestMethod -Uri "$base/" -Method Post -ContentType "application/json" -Body $body -TimeoutSec $timeout
  }
  # a task goes through: tried until it does (the link to a node that was restarted comes back by itself, after a back-off)
  function TaskGoesThrough($secs) {
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $secs) {
      try { $r = Rpc $local "SendMessage" @{ tenant = "bob"; message = (Msg "Asset: roof`nFindings: fine`nRisk: Low`nAction: none") } 8; if ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") { return $true } } catch { }
      Start-Sleep 3
    }
    $false
  }
  function Msg($text) { @{ messageId = [guid]::NewGuid().ToString(); role = "ROLE_USER"; parts = @(@{ text = $text }) } }
  function Agents($base) { try { @((Invoke-RestMethod "$base/agents" -TimeoutSec 10) | ForEach-Object { $_.nodeId }) } catch { @() } }
  function WaitSees($base, $name, $secs = 30) {
    for ($i = 0; $i -lt ($secs * 3); $i++) { if ((Agents $base) -contains $name) { return $true }; Start-Sleep -Milliseconds 330 }
    $false
  }
  function Discover($base) { try { @(Invoke-RestMethod "$base/discover" -TimeoutSec 10 | ForEach-Object { $_ }) } catch { @() } }
  function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }
  $rlib = (RemoteSh "ls -d $RemoteDir/target/debug/build/couchbase_lite-*/out | head -1") -join ""
  $renv = "export LD_LIBRARY_PATH=$rlib RUST_LOG=warn; cd $RemoteDir/target/debug;"
  $local = "http://127.0.0.1:18801"; $remote = "http://${RemoteAddr}:$MeshHttpPort"
  $procs = @()
  try {
    RemoteSh "pkill -f '[a]np-node --name bob'; rm -rf ~/x/mesh && mkdir -p ~/x/mesh" | Out-Null
    $rootOut = (& $Admin root-keygen --out "$M\root.key") -join "`n"
    $rootPub = ([regex]::Match($rootOut, 'root public key:\s*(\S+)')).Groups[1].Value
    scp.exe @scpOpts "$M\root.key" "${RemoteHost}:~/x/mesh/root.key"      # a test root key: it goes to the remote only so the remote admin tool can issue bob's token
    $aliceDid = ((& $Exe --name alice --data "$M\alice" --did-host alice.example.com --print-did) -split '\s+')[1]
    $bobDid = (((RemoteSh "$renv ./anp-node --name bob --data ~/x/mesh/bob --did-host bob.example.com --print-did") -join " ") -split '\s+')[1]
    Check "the remote node has a DID of the same form" ($bobDid -like "did:wba:bob.example.com:agents:bob:e1_*") $bobDid
    [void](& $Admin issue --root "$M\root.key" --node alice --node-dir "$M\alice" --did $aliceDid --inbox-to bob --out "$M\alice.token")
    [void](RemoteSh "$renv ./anp-admin issue --root ~/x/mesh/root.key --node bob --node-dir ~/x/mesh/bob --did $bobDid --inbox-to alice --out ~/x/mesh/bob.token")
    scp.exe @scpOpts "${RemoteHost}:~/x/mesh/bob.token" "$M\bob.token"
    $ins = (& $Admin inspect --root-pub $rootPub --token "$M\bob.token") -join "`n"
    Check "this machine's admin tool reads the token the remote one made, bound to bob's DID" ($ins.Contains($bobDid)) $ins

    $startBob = "$renv nohup ./anp-node --name bob --data ~/x/mesh/bob --http-port $MeshHttpPort --p2p-port $MeshP2pPort --did-host bob.example.com --e2ee --agent reviewer --root-key $rootPub --token ~/x/mesh/bob.token --tls --admit > ~/x/mesh/bob.out 2> ~/x/mesh/bob.err < /dev/null & echo started"
    [void](RemoteSh $startBob)
    $ok = $false; for ($i = 0; $i -lt 60; $i++) { try { [void](Invoke-RestMethod "$remote/security" -TimeoutSec 3); $ok = $true; break } catch { Start-Sleep -Milliseconds 500 } }
    Check "the remote node answers over the network" $ok
    scp.exe @scpOpts "${RemoteHost}:~/x/mesh/bob/tls.cert.pem" "$M\bob.tls.cert.pem"
    $connect = @("--pin-cert", "$M\bob.tls.cert.pem", "--connect", "wss://${RemoteAddr}:$MeshP2pPort/a2a")
    $alice = Start-Process $Exe -ArgumentList (@("--name", "alice", "--data", "$M\alice", "--http-port", "18801", "--did-host", "alice.example.com", "--e2ee", "--agent", "echo", "--root-key", $rootPub, "--token", "$M\alice.token", "--tls", "--admit") + $connect) -NoNewWindow -PassThru -RedirectStandardOutput "$M\alice.out.txt" -RedirectStandardError "$M\alice.err.txt"
    $procs += $alice

    Write-Host "Joining across the network"
    Check "alice (here) sees bob (remote)" (WaitSees $local "bob" 40)
    Check "bob (remote) sees alice (here)" (WaitSees $remote "alice" 40)
    $sa = Invoke-RestMethod "$local/security"; $sb = Invoke-RestMethod "$remote/security"
    Check "both run in did+biscuit mode with end-to-end encryption" ($sa.mode -eq "did+biscuit" -and $sb.mode -eq "did+biscuit" -and $sa.e2ee -and $sb.e2ee) "$($sa.mode) $($sb.mode)"
    Check "bob's DID is the one the remote tool printed" ($sb.did -eq $bobDid)

    Write-Host "Tasks both ways"
    $r = Rpc $local "SendMessage" @{ tenant = "bob"; message = (Msg "Asset: boiler`nFindings: leak`nRisk: High`nAction: fix this week") }
    Check "alice -> bob: the remote node's reviewer answers" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED" -and ((($r.result.task.artifacts | ForEach-Object { $_.parts | ForEach-Object { $_.text } }) -join "") -match "REVIEW")) ($r | ConvertTo-Json -Depth 6 -Compress)
    $r = Rpc $remote "SendMessage" @{ tenant = "alice"; message = (Msg "hello from the remote node") }
    Check "bob -> alice: this machine's echo agent answers" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)
    Start-Sleep 3
    $da = Discover $local; $db = Discover $remote
    $bobSeen = $da | Where-Object { $_.nodeId -eq "bob" }; $aliceSeen = $db | Where-Object { $_.nodeId -eq "alice" }
    Check "alice verified bob's signed agent description" ($bobSeen -and $bobSeen.descriptionVerified -and $bobSeen.did -eq $bobDid) ($da | ConvertTo-Json -Compress -Depth 4)
    Check "bob verified alice's signed agent description" ($aliceSeen -and $aliceSeen.descriptionVerified -and $aliceSeen.did -eq $aliceDid) ($db | ConvertTo-Json -Compress -Depth 4)
    Check "nothing was refused on either side during normal operation" ((@((Invoke-RestMethod "$local/security").rejections).Count -eq 0) -and (@((Invoke-RestMethod "$remote/security").rejections).Count -eq 0))

    Write-Host "Scoping (alice's token lets her message bob only; bob's lets him message alice only)"
    $r = Rpc $remote "SendMessage" @{ tenant = "nobody"; message = (Msg "x") } 2>$null
    Check "bob cannot address anyone his token does not allow" ($null -ne $r.error)

    Write-Host "An unauthorised node dials the remote node"
    $fakeOut = (& $Admin root-keygen --out "$M\fake.key") -join "`n"; $fakePub = ([regex]::Match($fakeOut, 'root public key:\s*(\S+)')).Groups[1].Value
    $malDid = ((& $Exe --name mal --data "$M\mal" --did-host mal.example.com --print-did) -split '\s+')[1]
    [void](& $Admin issue --root "$M\fake.key" --node mal --node-dir "$M\mal" --did $malDid --inbox-to '*' --out "$M\mal.token")
    $mal = Start-Process $Exe -ArgumentList (@("--name", "mal", "--data", "$M\mal", "--http-port", "18809", "--did-host", "mal.example.com", "--root-key", $fakePub, "--token", "$M\mal.token", "--tls", "--admit") + $connect) -NoNewWindow -PassThru -RedirectStandardOutput "$M\mal.out.txt" -RedirectStandardError "$M\mal.err.txt"
    $procs += $mal
    Start-Sleep 10
    Check "a node with another authority's token never sees bob" (-not ((Agents "http://127.0.0.1:18809") -contains "bob"))
    Check "bob never sees it either" (-not ((Agents $remote) -contains "mal"))
    $rej = (Invoke-RestMethod "$remote/security").rejections
    Check "bob logged the refused connection" (@($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "mal" }).Count -ge 1) ($rej | ConvertTo-Json -Compress -Depth 4)
    Kill $mal

    Write-Host "The remote node restarts"
    [void](RemoteSh "pkill -f '[a]np-node --name bob'"); Start-Sleep 3
    [void](RemoteSh $startBob)
    $ok = $false; for ($i = 0; $i -lt 60; $i++) { try { [void](Invoke-RestMethod "$remote/security" -TimeoutSec 3); $ok = $true; break } catch { Start-Sleep -Milliseconds 500 } }
    Check "the remote node is back from its stored state" $ok
    # The listener keeps its TLS identity in its data folder, so a restart gives the same certificate and a dialler that pinned it can
    # reconnect by itself. (Both nodes still list each other from replicated data, so "seeing" proves nothing here: the real test is a task
    # over the link.)
    $oldPin = (Get-FileHash "$M\bob.tls.cert.pem").Hash
    scp.exe @scpOpts "${RemoteHost}:~/x/mesh/bob/tls.cert.pem" "$M\bob.tls.cert.pem"
    Check "the listener's certificate is the same after a restart" ($oldPin -eq (Get-FileHash "$M\bob.tls.cert.pem").Hash)
    $through = TaskGoesThrough 120
    if (-not $through) {
      # not wanted: the dialler should have come back on its own; restarting it tells whether anything else is wrong
      Write-Host "  note  alice's link did not come back by itself within 120 s; restarting alice" -ForegroundColor Yellow
      Kill $alice
      $alice = Start-Process $Exe -ArgumentList (@("--name", "alice", "--data", "$M\alice", "--http-port", "18801", "--did-host", "alice.example.com", "--e2ee", "--agent", "echo", "--root-key", $rootPub, "--token", "$M\alice.token", "--tls", "--admit") + $connect) -NoNewWindow -PassThru -RedirectStandardOutput "$M\alice2.out.txt" -RedirectStandardError "$M\alice2.err.txt"
      $procs += $alice
      [void](WaitSees "http://127.0.0.1:18801" "bob" 40)
      $fellBack = TaskGoesThrough 60
      Check "the link came back by itself (without restarting alice)" $false
      $through = $fellBack
    }
    Check "a task goes alice -> bob again after bob restarted (same DIDs, same tokens)" $through
    $r = Rpc $remote "SendMessage" @{ tenant = "alice"; message = (Msg "after the restart") } 20
    Check "and bob -> alice" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED")
  } catch { Write-Host "  FAIL  mesh part aborted: $_" -ForegroundColor Red; $fail++ }
  finally {
    [void](RemoteSh "pkill -f '[a]np-node --name bob'")
    foreach ($p in $procs) { Kill $p }
  }
}
if ($fail) { "FAILED"; exit 1 } else { "ALL PASSED" }
