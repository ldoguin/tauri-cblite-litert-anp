# Two independent deployments: a Windows node and a Linux node (built in WSL, see scripts/linux-node-build.sh) in one mesh, on
# different operating systems with different Couchbase Lite builds, talking over the network (the Windows host's address as WSL
# sees it, not loopback): DIDs, tokens bound to them, TLS with a pinned certificate, connection admission, end-to-end encryption.
#
#   pwsh scripts/e2e-cross-os.ps1 -Exe <target>\debug\anp-node.exe -Admin <target>\debug\anp-admin.exe
param(
  [string]$Exe = "",
  [string]$Admin = "",
  [string]$Work = "",
  [string]$LinuxDir = "~/anp-linux"      # where scripts/linux-node-build.sh built the node, inside WSL
)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Admin) { $Admin = Get-Bin "anp-admin" }
if (-not $Work) { $Work = Get-WorkDir "e2e-cross" }
if (-not $Exe) { $Exe = Get-Bin "anp-node" }
$ErrorActionPreference = "Continue"
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
function Agents($port) { try { @((Invoke-RestMethod "http://127.0.0.1:$port/agents") | ForEach-Object { $_.nodeId }) } catch { @() } }
function WaitSees($port, $name, $secs = 30) {
  for ($i = 0; $i -lt ($secs * 3); $i++) { if ((Agents $port) -contains $name) { return $true }; Start-Sleep -Milliseconds 330 }
  $false
}
function Discover($port) { try { @(Invoke-RestMethod "http://127.0.0.1:$port/discover" | ForEach-Object { $_ }) } catch { @() } }
function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }
function Lx($cmd) { (wsl -d Ubuntu -- bash -c $cmd 2>&1 | Out-String).Trim() }
$wslWork = ConvertTo-WslPath $Work

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$route = (wsl -d Ubuntu -- ip route show default) -join " "; $null = $route -match "via (\d+\.\d+\.\d+\.\d+)"; $hostIp = $Matches[1]
$lib = Lx "ls -d $LinuxDir/target/debug/build/couchbase_lite-*/out | head -1"
$linuxEnv = "export LD_LIBRARY_PATH=$lib RUST_LOG=warn; cd $LinuxDir/target/debug;"
Write-Host "The Linux node runs on: $(Lx 'uname -sr') ($(Lx 'uname -m'))"
Write-Host "Setup: DIDs and tokens (the authority is on Windows; bob's token is made by the Linux admin tool)"

$rootOut = (& $Admin root-keygen --out "$Work\root.key") -join "`n"
$rootPub = ([regex]::Match($rootOut, 'root public key:\s*(\S+)')).Groups[1].Value
$aliceDid = ((& $Exe --name alice --data "$Work\alice" --did-host alice.example.com --print-did) -split '\s+')[1]
$bobDid = ((Lx "$linuxEnv rm -rf ~/x/cross-bob; ./anp-node --name bob --data ~/x/cross-bob --did-host bob.example.com --print-did") -split '\s+')[1]
Check "the Linux node has a DID of the same form" ($bobDid -like "did:wba:bob.example.com:agents:bob:e1_*") $bobDid
[void](& $Admin issue --root "$Work\root.key" --node alice --node-dir "$Work\alice" --did $aliceDid --inbox-to bob --out "$Work\alice.token")
[void](Lx "$linuxEnv ./anp-admin issue --root $wslWork/root.key --node bob --node-dir ~/x/cross-bob --did $bobDid --inbox-to alice --out $wslWork/bob.token")
Check "both tokens exist" ((Test-Path "$Work\alice.token") -and (Test-Path "$Work\bob.token"))
$ins = (& $Admin inspect --root-pub $rootPub --token "$Work\bob.token") -join "`n"
Check "the Windows admin tool reads the token the Linux one made, bound to bob's DID" ($ins.Contains($bobDid)) $ins

$procs = @()
function StartBob($extra) {
  $a = "$linuxEnv ./anp-node --name bob --data ~/x/cross-bob --http-port 18802 --did-host bob.example.com --e2ee --agent reviewer --root-key $rootPub --token $wslWork/bob.token --tls --admit $extra"
  Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "bash", "-c", "`"$a > $wslWork/bob.out.txt 2> $wslWork/bob.err.txt`"") -NoNewWindow -PassThru
}
try {
  $alice = Start-Process $Exe -ArgumentList @("--name", "alice", "--data", "$Work\alice", "--http-port", "18801", "--did-host", "alice.example.com", "--e2ee", "--agent", "echo", "--root-key", $rootPub, "--token", "$Work\alice.token", "--tls", "--admit") -NoNewWindow -PassThru -RedirectStandardOutput "$Work\alice.out.txt" -RedirectStandardError "$Work\alice.err.txt"
  $procs += $alice
  for ($i = 0; $i -lt 50 -and -not ((Get-Content "$Work\alice.out.txt" -ErrorAction SilentlyContinue) -match 'P2P port'); $i++) { Start-Sleep -Milliseconds 200 }
  $port = ((Get-Content "$Work\alice.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  $connect = "--pin-cert $wslWork/alice/tls.cert.pem --connect wss://${hostIp}:$port/a2a"
  $bob = StartBob $connect; $procs += $bob

  Write-Host "Joining across the two systems"
  Check "alice (Windows) sees bob (Linux)" (WaitSees 18801 "bob" 40)
  Check "bob (Linux) sees alice (Windows)" (WaitSees 18802 "alice" 40)
  $sa = Invoke-RestMethod "http://127.0.0.1:18801/security"; $sb = Invoke-RestMethod "http://127.0.0.1:18802/security"
  Check "both run in did+biscuit mode with end-to-end encryption" ($sa.mode -eq "did+biscuit" -and $sb.mode -eq "did+biscuit" -and $sa.e2ee -and $sb.e2ee) "$($sa.mode) $($sb.mode)"
  Check "bob's DID is the one the Linux tool printed" ($sb.did -eq $bobDid)

  Write-Host "Tasks both ways"
  $r = Rpc 18801 "SendMessage" @{ tenant = "bob"; message = (Msg "Asset: boiler`nFindings: leak`nRisk: High`nAction: fix this week") }
  Check "alice -> bob: the Linux node's reviewer answers" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED" -and ((($r.result.task.artifacts | ForEach-Object { $_.parts | ForEach-Object { $_.text } }) -join "") -match "REVIEW")) ($r | ConvertTo-Json -Depth 6 -Compress)
  $r = Rpc 18802 "SendMessage" @{ tenant = "alice"; message = (Msg "hello from the Linux node") }
  Check "bob -> alice: the Windows node's echo agent answers" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)
  Start-Sleep 3
  $da = Discover 18801; $db = Discover 18802
  $bobSeen = $da | Where-Object { $_.nodeId -eq "bob" }; $aliceSeen = $db | Where-Object { $_.nodeId -eq "alice" }
  Check "the Windows node verified the Linux node's signed agent description" ($bobSeen -and $bobSeen.descriptionVerified -and $bobSeen.did -eq $bobDid) ($da | ConvertTo-Json -Compress -Depth 4)
  Check "the Linux node verified the Windows node's signed agent description" ($aliceSeen -and $aliceSeen.descriptionVerified -and $aliceSeen.did -eq $aliceDid) ($db | ConvertTo-Json -Compress -Depth 4)
  Check "nothing was refused on either side during normal operation" ((@((Invoke-RestMethod "http://127.0.0.1:18801/security").rejections).Count -eq 0) -and (@((Invoke-RestMethod "http://127.0.0.1:18802/security").rejections).Count -eq 0))

  Write-Host "Scoping (alice's token lets her message bob only; bob's lets him message alice only)"
  $r = Rpc 18802 "SendMessage" @{ tenant = "nobody"; message = (Msg "x") } 2>$null
  Check "bob cannot address anyone his token does not allow" ($null -ne $r.error)

  Write-Host "An unauthorised Linux node"
  $fakeOut = (& $Admin root-keygen --out "$Work\fake.key") -join "`n"; $fakePub = ([regex]::Match($fakeOut, 'root public key:\s*(\S+)')).Groups[1].Value
  $malDid = ((Lx "$linuxEnv rm -rf ~/x/cross-mal; ./anp-node --name mal --data ~/x/cross-mal --did-host mal.example.com --print-did") -split '\s+')[1]
  [void](Lx "$linuxEnv ./anp-admin issue --root $wslWork/fake.key --node mal --node-dir ~/x/cross-mal --did $malDid --inbox-to '*' --out $wslWork/mal.token")
  $mal = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "bash", "-c", "`"$linuxEnv ./anp-node --name mal --data ~/x/cross-mal --http-port 18809 --did-host mal.example.com --root-key $fakePub --token $wslWork/mal.token --tls --admit $connect > $wslWork/mal.out.txt 2> $wslWork/mal.err.txt`"") -NoNewWindow -PassThru
  Start-Sleep 10
  Check "a Linux node with another authority's token never sees alice" (-not ((Agents 18809) -contains "alice"))
  $rej = (Invoke-RestMethod "http://127.0.0.1:18801/security").rejections
  Check "alice logged the refused connection" (@($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "mal" }).Count -ge 1) ($rej | ConvertTo-Json -Compress -Depth 4)
  Lx "pkill -f '[a]np-node --name mal'" | Out-Null

  Write-Host "The Linux node restarts"
  Lx "pkill -f '[a]np-node --name bob'" | Out-Null; Start-Sleep 3
  $bob = StartBob $connect; $procs += $bob
  Check "bob rejoins from its stored state (same DID, same token)" (WaitSees 18802 "alice" 40)
  $r = Rpc 18801 "SendMessage" @{ tenant = "bob"; message = (Msg "Asset: roof`nFindings: fine`nRisk: Low`nAction: none") }
  Check "and a task still goes alice -> bob" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED")
}
finally {
  Lx "pkill -f '[a]np-node --name'" | Out-Null
  foreach ($p in $procs) { Kill $p }
}
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }