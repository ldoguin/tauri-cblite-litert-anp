# Needs a built workspace in -Target (cargo build -p anp-node -p anp-ad; cblite.dll next to the exes).
# Interoperability checks against the official ANP SDK (Python, AgentConnect). Needs WSL with python3, the SDK installed
# by scripts/interop/setup.sh, and the Windows build of this project. Everything runs locally; nothing leaves the machine
# except what setup.sh downloads.
#
#   pwsh scripts/interop/run.ps1 -Target <target>
param(
  [string]$Target = "",
  [string]$Out = "",
  [string]$HostIp = "",      # the Windows host as seen from WSL (default: WSL's default gateway)
  [switch]$SkipRust,         # skip the Rust SDK phase (it compiles the anp crate, about a minute the first time)
  [string]$GoDriver = "",   # built by go-sdk-build.ps1; the Go phase is skipped if it is missing
  [string]$TsDir = ""                           # made by ts-sdk-build.ps1; the TypeScript phase is skipped if it is missing
)
. (Join-Path (Split-Path $PSScriptRoot) "common.ps1")
if (-not $Target) { $Target = Get-TargetDir }
if (-not $Out) { $Out = Join-Path $Target "interop" }
if (-not $GoDriver) { $GoDriver = Join-Path (Join-Path $Target "go-sdk") ("anp-go-interop" + (Get-ExeSuffix)) }
if (-not $TsDir) { $TsDir = Join-Path $Target "ts-sdk" }
$ErrorActionPreference = "Continue"   # cargo and wsl write progress to stderr
$here = $PSScriptRoot
$root = Resolve-Path "$here\..\.."
$fail = 0
New-Item -ItemType Directory -Force $Out | Out-Null
$env:CARGO_TARGET_DIR = $Target
$wslOut = ConvertTo-WslPath $Out
$wslScripts = ConvertTo-WslPath $here
function Py($script, $argv = "") { wsl -d Ubuntu -- bash -c "INTEROP_OUT=$wslOut python3 -I $wslScripts/$script $argv" 2>&1 }
function Step($name, $ok) { if ($ok) { Write-Host "  PASS  $name" -ForegroundColor Green } else { Write-Host "  FAIL  $name" -ForegroundColor Red; $script:fail++ } }
function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }

Write-Host "Fixtures from this project's code"
Push-Location $root
$env:ANP_FIXTURE_OUT = "$Out\mine.p5.json"; cargo test -q -p anp-e2ee dump_interop_fixture 2>&1 | Out-Null
$env:ANP_FIXTURE_OUT = "$Out\mine.http.json"; cargo test -q -p anp-httpauth dump_signed_request 2>&1 | Out-Null
Remove-Item Env:\ANP_FIXTURE_OUT
Pop-Location
foreach ($f in @("anp-node.exe", "anp-ad.exe", "anp-search.exe", "anp-wns.exe", "anp-meta.exe", "cblite.dll")) { if (-not (Test-Path "$Target\debug\$f")) { throw "$Target\debug\$f is missing: build the workspace first (cargo build -p anp-node -p anp-ad) and copy cblite.dll next to the exe" } }
Step "fixtures written" ((Test-Path "$Out\mine.p5.json") -and (Test-Path "$Out\mine.http.json"))

Write-Host "A node's own DID document, checked by the SDK"
$W = "$Out\node"; Remove-Item $W -Recurse -Force -ErrorAction SilentlyContinue
$node = "$Target\debug\anp-node.exe"
$p = Start-Process $node -ArgumentList @("--name", "mine", "--data", $W, "--http-port", "18795", "--did-host", "mine.example.com", "--e2ee") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\node.out" -RedirectStandardError "$Out\node.err"
Start-Sleep 6
$did = ((& $node --name mine --data $W --did-host mine.example.com --print-did) -split '\s+')[1]
$e1 = ($did -split ':')[-1]
Invoke-WebRequest "http://127.0.0.1:18795/agents/mine/$e1/did.json" -UseBasicParsing -OutFile "$Out\mine.did.json"
Kill $p
$o = Py "sdk_make_did.py" "mine.did.json"
$o | ForEach-Object { Write-Host "  $_" }
Step "the SDK validates this project's DID document (e1 binding and proof)" (($o -join "`n") -match "validates mine.did.json.*True")
$o2 = (& "$Target\debug\anp-ad.exe" verify-did --did-doc "$Out\sdk.did.json" 2>&1) -join " "
Step "this project verifies a DID document the SDK created" ($o2 -match "^OK")

Write-Host "P5 v2 objects (bundle, associated data, plaintext) checked by the SDK"
$o = Py "sdk_check_p5.py"; $o | ForEach-Object { Write-Host "  $_" }
Step "all P5 checks" (-not (($o -join "`n") -cmatch "FAIL"))

Write-Host "ANP-02 request signatures, both directions"
$o = Py "sdk_http.py" "verify"; $o | ForEach-Object { Write-Host "  $_" }
Step "the SDK verifies a request this project signed" (-not (($o -join "`n") -cmatch "FAIL") -and $o)
[void](Py "sdk_http.py" "sign")
Push-Location $root
$env:ANP_SDK_REQUEST = "$Out\sdk.http.json"
$r = cargo test -p anp-httpauth a_request_signed_by_the_sdk 2>&1 | Out-String
Remove-Item Env:\ANP_SDK_REQUEST
Pop-Location
Step "this project verifies a request the SDK signed" ($r -match "1 passed")

Write-Host "The SDK's client against a node that requires signed requests"
if (-not $HostIp) { $route = (wsl -d Ubuntu -- ip route show default) -join " "; if ($route -match "via (\d+\.\d+\.\d+\.\d+)") { $HostIp = $Matches[1] } else { throw "cannot find the Windows host from WSL: pass -HostIp" } }
$base = "http://${HostIp}:18797"
[void](Py "sdk_live.py" "prep")
$W2 = "$Out\live"; Remove-Item $W2 -Recurse -Force -ErrorAction SilentlyContinue
$p = Start-Process $node -ArgumentList @("--name", "live", "--data", $W2, "--http-port", "18797", "--did-host", "live.example.com", "--require-auth", "--public-origin", $base, "--allow-caller", "$Out\sdkclient.did.json") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\live.out" -RedirectStandardError "$Out\live.err"
Start-Sleep 7
$o = Py "sdk_live.py" "run $base"; $o | ForEach-Object { Write-Host "  $_" }
Kill $p
Step "every live check" (-not (($o -join "`n") -cmatch "FAIL|Traceback"))

Write-Host "The older scheme (Authorization: DIDWba, then a Bearer token), with the SDK's client"
$W7 = "$Out\legacy"; Remove-Item $W7 -Recurse -Force -ErrorAction SilentlyContinue
$p = Start-Process $node -ArgumentList @("--name", "leg", "--data", $W7, "--http-port", "18797", "--did-host", "live.example.com", "--require-auth", "--public-origin", $base, "--allow-caller", "$Out\sdkclient.did.json") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\leg0.out" -RedirectStandardError "$Out\leg0.err"
Start-Sleep 7
$o = Py "sdk_legacy_live.py" "refused $base"; $o | ForEach-Object { Write-Host "  $_" }
Kill $p
Step "off by default: the older header is refused unless --allow-legacy-auth" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)
Remove-Item $W7 -Recurse -Force -ErrorAction SilentlyContinue
$p = Start-Process $node -ArgumentList @("--name", "leg", "--data", $W7, "--http-port", "18797", "--did-host", "live.example.com", "--require-auth", "--allow-legacy-auth", "--public-origin", $base, "--allow-caller", "$Out\sdkclient.did.json") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\leg.out" -RedirectStandardError "$Out\leg.err"
Start-Sleep 7
$o = Py "sdk_legacy_live.py" "run $base"; $o | ForEach-Object { Write-Host "  $_" }
Kill $p
Step "the SDK's client signs in with the older header, gets a token, and uses it" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)

Write-Host "Agent description and OpenRPC interface, read by the SDK's own parsers"
$W8 = "$Out\orpc"; Remove-Item $W8 -Recurse -Force -ErrorAction SilentlyContinue
$p = Start-Process $node -ArgumentList @("--name", "orpc", "--data", $W8, "--http-port", "18795", "--did-host", "orpc.example.com", "--agent", "echo") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\orpc.out" -RedirectStandardError "$Out\orpc.err"
Start-Sleep 7
$o = Py "sdk_openrpc.py" "http://${HostIp}:18795 orpc"; $o | ForEach-Object { Write-Host "  $_" }
Kill $p
Step "the SDK's parsers and header generator accept the node's description and OpenRPC document, and a call built from them works" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)

Write-Host "ANP-04 WNS handles"
$wnsExe = "$Target\debug\anp-wns.exe"
[void](Py "sdk_wns.py" "cases")
$o = (& $wnsExe validate-file "$Out\wns_cases.json" 2>&1 | Out-String).TrimEnd(); $o -split "`n" | ForEach-Object { Write-Host "  mine: $_" }
Step "this project and the SDK agree on every handle in the table (valid or not, and the normal form)" ($o -match "\b0 disagreements")
$W12 = "$Out\wns"; Remove-Item $W12 -Recurse -Force -ErrorAction SilentlyContinue
$p = Start-Process $node -ArgumentList @("--name", "wnsnode", "--data", $W12, "--http-port", "18795", "--did-host", "wns.example.com", "--handle", "agent", "--handle", "desk") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\wns.out" -RedirectStandardError "$Out\wns.err"
Start-Sleep 7
$o = Py "sdk_wns.py" "node http://${HostIp}:18795"; $o | ForEach-Object { Write-Host "  $_" }
$tsWns = $null
if (Test-Path "$TsDir\driver.mjs") { Push-Location $TsDir; $tsWns = (node driver.mjs wns http://127.0.0.1:18795 2>&1 | Out-String); Pop-Location; $tsWns.TrimEnd() -split "`n" | ForEach-Object { Write-Host "  ts  : $_" } }
Kill $p
Step "the SDK resolves and verifies the handles this node provides" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)
if ($tsWns) { Step "the TypeScript SDK resolves and verifies them too" (-not ($tsWns -cmatch "(?m)^FAIL") -and $tsWns -cmatch "PASS") }
# the other direction: this project's client against documents the SDK's own models built
# The test CA is made with 2 days of validity: a copy kept from an earlier run may have expired, so an old one is made again.
function Ensure-TestCa {
  $c = "$Out\https\server.pem"
  if ((-not (Test-Path $c)) -or (((Get-Date) - (Get-Item $c).LastWriteTime).TotalHours -gt 12)) {
    Remove-Item "$Out\https" -Recurse -Force -ErrorAction SilentlyContinue
    [void](wsl -d Ubuntu -- bash "$wslScripts/make_ca.sh" "$wslOut/https")
  }
}
Ensure-TestCa
$srv = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "bash", "-c", "`"INTEROP_OUT=$wslOut python3 -I $wslScripts/sdk_wns.py serve 18790`"") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\wnssrv.out" -RedirectStandardError "$Out\wnssrv.err"
$pxw = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "python3", "-I", "$wslScripts/tls_proxy.py", "$wslOut/https", "8443", "127.0.0.1", "18790") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\pxw.out" -RedirectStandardError "$Out\pxw.err"
Start-Sleep 6
$common = @("--base", "https://localhost:8443", "--roots", "$Out\https\ca.pem", "--allow-private")
function Wns($cmdArgs) { $r = (& $wnsExe @cmdArgs @common 2>&1 | Out-String).Trim(); Write-Host "    mine: wns $($cmdArgs -join ' ') -> $r"; $r }
$r = Wns @("resolve", "sdkbot.sdk.example.com")
Step "this project resolves a handle document the SDK's models built (generation 7)" ($r -match "ok sdkbot.sdk.example.com did:wba:sdk.example.com:agents:sdkbot:e1_\S+ active 7")
$r = Wns @("verify", "sdkbot.sdk.example.com", "--did-doc", "$Out\sdkbot.wns.did.json")
Step "...and verifies the binding both ways against the DID document the SDK built with build_handle_service_entry" ($r -match "ok sdkbot.sdk.example.com .* 7")
$r = Wns @("resolve", "ghost.sdk.example.com"); Step "an unknown handle is not-found (404)" ($r -match "not-found:")
$r = Wns @("resolve", "old.sdk.example.com"); Step "a revoked handle is gone (410)" ($r -match "gone:")
$r = Wns @("resolve", "moved.sdk.example.com"); Step "a moved handle is reported, not followed (301)" ($r -match "moved:")
$r = Wns @("resolve", "liar.sdk.example.com"); Step "a document for another handle than the one asked for is refused" ($r -match "resolution:.*mismatch")
$r = Wns @("resolve", "badgen.sdk.example.com"); Step "a non-canonical binding generation (007) is refused" ($r -match "resolution:.*binding_generation")
$r = Wns @("verify", "paused.sdk.example.com", "--did-doc", "$Out\sdkbot.wns.did.json"); Step "a suspended handle does not verify" ($r -match "binding:.*expected .active.")
$r = Wns @("verify", "foreign.sdk.example.com", "--did-doc", "$Out\sdkbot.wns.did.json"); Step "a did:wba on another domain than the handle's does not verify" ($r -match "binding:.*(domain mismatch|another DID)")
Kill $srv; wsl -d Ubuntu -- pkill -f "[t]ls_proxy.py" 2>$null | Out-Null; wsl -d Ubuntu -- pkill -f "[s]dk_wns.py" 2>$null | Out-Null

Write-Host "ANP-06 meta-protocol (the SDK's MetaProtocol with a stand-in for its language model)"
$W13 = "$Out\meta"; Remove-Item $W13 -Recurse -Force -ErrorAction SilentlyContinue
$p = Start-Process $node -ArgumentList @("--name", "metanode", "--data", $W13, "--http-port", "18795", "--did-host", "meta.example.com", "--meta-protocol", "a2a-json-rpc") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\meta.out" -RedirectStandardError "$Out\meta.err"
Start-Sleep 7
$o = Py "sdk_meta.py" "requester http://${HostIp}:18795"; $o | ForEach-Object { Write-Host "  $_" }
$wsr = (& "$Target\debug\anp-meta.exe" ask "ws://127.0.0.1:18795/anp/meta/ws" --want a2a-json-rpc --protocol a2a-json-rpc 2>&1 | Out-String).Trim(); Write-Host "    mine (WebSocket): $wsr"
$wsp = (& "$Target\debug\anp-meta.exe" ask "ws://127.0.0.1:18795/anp/meta/ws" --want pizza --protocol pizza 2>&1 | Out-String).Trim(); Write-Host "    mine (WebSocket): $wsp"
Step "this project negotiates with the node over the WebSocket binding (one binary message per frame), and gives up inside the round limit when nothing is shared" ($wsr -match "agreed a2a-json-rpc" -and $wsp -match "failed")
Kill $p
Step "the SDK, as requester, negotiates with a node: accepted, counter-proposal, codeGeneration" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)
$metaSrv = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "bash", "-c", "`"INTEROP_OUT=$wslOut python3 -I $wslScripts/sdk_meta.py provider 18791`"") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\metasrv.out" -RedirectStandardError "$Out\metasrv.err"
Start-Sleep 6
$ask = "$Target\debug\anp-meta.exe"
function Ask($want, $protos) { $a = @("ask", "http://localhost:18791/anp/meta", "--want", $want); foreach ($x in $protos) { $a += @("--protocol", $x) }; $r = (& $ask @a 2>&1 | Out-String).Trim(); Write-Host "    mine: ask --want $want ($($protos -join ', ')) -> $r"; $r }
$r = Ask "a2a-json-rpc" @("a2a-json-rpc"); Step "this project, as requester, is accepted at once by the SDK's provider and gets its codeGeneration" ($r -match "agreed a2a-json-rpc" -and $r -match "peer_ready=Some\(true\)")
$r = Ask "chat" @("chat", "json-rpc-lite"); Step "the SDK's provider counters with json-rpc-lite and this project, which has it, agrees" ($r -match "agreed json-rpc-lite round=3" -and $r -match "peer_ready=Some\(true\)")
$r = Ask "pizza" @("pizza"); Step "with nothing in common this project gives up inside the round limit" ($r -match "failed")
Kill $metaSrv; wsl -d Ubuntu -- pkill -f "[s]dk_meta.py" 2>$null | Out-Null

Write-Host "P6 group E2EE, wire layer: the binding and the RFC 9421 origin proofs, with the SDK's proof helpers"
Push-Location $root
$env:ANP_GROUP_FIXTURE_OUT = "$Out\mine.group.json"; cargo test -q -p anp-group dump_group_fixture 2>&1 | Out-Null; Remove-Item Env:\ANP_GROUP_FIXTURE_OUT
Pop-Location
$o = Py "sdk_group.py" "verify"; $o | ForEach-Object { Write-Host "  $_" }
Step "the SDK verifies the device binding and the origin proofs this project made (also the one preserved on a delivery)" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and ($o -match "^PASS").Count -ge 6)
[void](Py "sdk_group.py" "sign")
Push-Location $root
$env:ANP_GROUP_SDK_FIXTURE = "$Out\sdk.group.json"
$r = cargo test -p anp-group an_origin_proof_made_by_the_sdk 2>&1 | Out-String
Remove-Item Env:\ANP_GROUP_SDK_FIXTURE
Pop-Location
Step "this project verifies an origin proof the SDK made" ($r -match "1 passed")

Write-Host "P6 group E2EE with MLS: this project and the official Rust SDK (anp 1.0.7, openmls) as devices of the same groups"
$sdkg = wsl -d Ubuntu -- bash -c "test -x ~/anp-interop/rust-sdk-group/target/debug/anp-rust-group-interop && echo yes"
if ($sdkg -match "yes") {
  $groupDid = "did:wba:groups.example:teams:blue:e1_group"
  function SdkG([string]$cmd) { $o = (wsl -d Ubuntu -- bash -c "cd ~/anp-interop/rust-sdk-group && ./target/debug/anp-rust-group-interop $cmd" 2>&1 | Out-String); $o.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    sdk : $_" }; ($o -notmatch "FAIL|panicked|unknown command") -and ($o -match "PASS|SDK|sent|created|added") }
  function Ours([string]$stepName, [string]$dir) {
    Push-Location $root
    $env:ANP_GROUP_STEP = $stepName; $env:ANP_GROUP_DIR = $dir
    $r = cargo test -p anp-group-mls --test sdk_interop 2>&1 | Out-String
    Remove-Item Env:\ANP_GROUP_STEP, Env:\ANP_GROUP_DIR
    Pop-Location
    $good = $r -match "4 passed"
    if (-not $good) { ($r -split "`n" | Where-Object { $_ -match "panicked|error|Err|assert" } | Select-Object -First 6) | ForEach-Object { Write-Host "    mine: $_" } }
    $good
  }
  foreach ($d in "p6a", "p6b") { Remove-Item "$Out\$d" -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory "$Out\$d" | Out-Null }
  $A = "$Out\p6a"; $B = "$Out\p6b"; $wA = "$wslOut/p6a"; $wB = "$wslOut/p6b"
  # A: the SDK creates the group and adds this project
  $okA = Ours "a-kp" $A
  [IO.File]::WriteAllText("$A\group.json", "{`"group_did`": `"$groupDid`"}")
  $okA = $okA -and (SdkG "kp $wA sdk") -and (SdkG "create $wA sdk $groupDid") -and (SdkG "add $wA sdk $wA/ours.kp.json $wA/ours.did.json") -and (SdkG "encrypt $wA sdk 'hello from the SDK' msg-sdk-1 $wA/msg1.json")
  Step "the SDK creates a group and adds this project: key package with its binding, commit, welcome (every leaf checked here)" $okA
  Step "this project joins from the SDK's welcome, reads the SDK's message, and answers" (Ours "a-join" $A)
  Step "the SDK reads this project's answer and validates the sender's leaf" (SdkG "decrypt $wA sdk $wA/reply.json $wA/ours.did.json")
  # B: this project creates the group and adds the SDK
  $okB = SdkG "kp $wB sdk"
  Step "this project verifies the SDK's key package binding, creates a group, adds the SDK, and writes to it" ($okB -and (Ours "b-create" $B))
  Step "the SDK joins from this project's welcome (its own validation of every leaf)" (SdkG "welcome $wB sdk $wB/add.json $wB/ours.did.json $wB/sdk.did.json")
  Step "the SDK reads this project's message (authenticated data, sender leaf)" (SdkG "decrypt $wB sdk $wB/msgB.json $wB/ours.did.json")
  $okR = SdkG "encrypt $wB sdk 'reply from the SDK' msg-sdk-2 $wB/replyB.json"
  Step "this project reads the SDK's reply" ($okR -and (Ours "b-read" $B))
} else { Write-Host "The P6 MLS interop is skipped (scripts/interop/rust-sdk-group-build.sh builds the SDK side in WSL)" }

Write-Host "P6 group host on the node: three devices of this project over signed HTTP, then the SDK as a member and as a controller through it"
$o = (powershell -NoProfile -File "$root\scripts\e2e-p6-host.ps1" 2>&1 | Out-String)
$o -split "`n" | Where-Object { $_ -match "^\s*(sdk :|PASS|FAIL)|panicked|unexpected|called `Result|node log|error" } | ForEach-Object { Write-Host "    $($_.TrimEnd())" }
Step "the node hosts P6 groups: this project's devices over signed HTTP (mailboxes are the devices' own), receipts by the group DID's key" ($o -match "PASS  devices create")
Step "the SDK is a member of a hosted group (welcome, a commit made here, its message with its own origin proof) and the controller of another" ($o -match "PASS  the SDK is the third device")

Write-Host "A search agent (ANP-08 passive discovery): it crawls a node's domain over HTTPS, verifies and indexes; the SDK reads and verifies what it serves"
Ensure-TestCa
$W9 = "$Out\searchdemo"; Remove-Item $W9 -Recurse -Force -ErrorAction SilentlyContinue
$px1 = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "python3", "-I", "$wslScripts/tls_proxy.py", "$wslOut/https", "8443", $HostIp, "18795") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\px1.out" -RedirectStandardError "$Out\px1.err"
$px2 = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "python3", "-I", "$wslScripts/tls_proxy.py", "$wslOut/https", "8444", $HostIp, "18796") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\px2.out" -RedirectStandardError "$Out\px2.err"
$hotel = Start-Process $node -ArgumentList @("--name", "hotel", "--data", "$W9\hotel", "--http-port", "18795", "--did-host", "localhost:8443", "--agent", "echo") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\hotel.out" -RedirectStandardError "$Out\hotel.err"
$srch = Start-Process "$Target\debug\anp-search.exe" -ArgumentList @("--data", "$W9\search", "--http-port", "18796", "--did-host", "localhost:8444", "--resolver-roots", "$Out\https\ca.pem", "--resolver-allow-private") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\search.out" -RedirectStandardError "$Out\search.err"
Start-Sleep 8
$o = Py "sdk_search.py" "http://${HostIp}:18796 http://${HostIp}:18795"; $o | ForEach-Object { Write-Host "  $_" }
Kill $hotel; Kill $srch
wsl -d Ubuntu -- pkill -f tls_proxy.py 2>$null | Out-Null
Step "the search agent verifies and indexes a crawled description; the SDK parses and verifies both sides" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)

Write-Host "The search agent's rate limit"
$W11 = "$Out\searchlimit"; Remove-Item $W11 -Recurse -Force -ErrorAction SilentlyContinue
$srch2 = Start-Process "$Target\debug\anp-search.exe" -ArgumentList @("--data", $W11, "--http-port", "18796", "--did-host", "localhost:8444", "--rate-limit", "3", "--rate-seconds", "600") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\search2.out" -RedirectStandardError "$Out\search2.err"
Start-Sleep 4
$o = Py "search_limits.py" "http://${HostIp}:18796"; $o | ForEach-Object { Write-Host "  $_" }
Kill $srch2
Step "registrations and crawls are rationed per client, searching is not" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)


Write-Host "DIDs resolved over HTTPS: the node is told a domain to trust, not the callers' documents"
$tls = "$Out\https"; Remove-Item $tls -Recurse -Force -ErrorAction SilentlyContinue
$wslTls = "$wslOut/https"
[void](wsl -d Ubuntu -- bash "$wslScripts/make_ca.sh" $wslTls)
[void](Py "sdk_resolve_live.py" "prep")
Push-Location $root
$env:ANP_FIXTURE_OUT = "$Out\mine.p5.domain.json"; $env:ANP_FIXTURE_ALICE_DOMAIN = "localhost:8443"; $env:ANP_FIXTURE_ALICE_ENDPOINT = "http://127.0.0.1:18799/inbox"
cargo test -q -p anp-e2ee dump_interop_fixture 2>&1 | Out-Null
Remove-Item Env:\ANP_FIXTURE_OUT, Env:\ANP_FIXTURE_ALICE_DOMAIN, Env:\ANP_FIXTURE_ALICE_ENDPOINT
Pop-Location
$dfx = Get-Content "$Out\mine.p5.domain.json" -Raw | ConvertFrom-Json
[IO.File]::WriteAllText("$Out\alice.web.did.json", ($dfx.sender.did_document | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
$docs = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "python3", "-I", "$wslScripts/https_docs.py", $wslTls, "8443", "$wslOut/webclient.did.json", "$wslOut/alice.web.did.json") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\docs.out" -RedirectStandardError "$Out\docs.err"
Start-Sleep 3
$trust = @("--trust-domain", "localhost:8443", "--resolver-roots", "$tls\ca.pem", "--resolver-allow-private")
$W4 = "$Out\resolvenode"; Remove-Item $W4 -Recurse -Force -ErrorAction SilentlyContinue
$p = Start-Process $node -ArgumentList (@("--name", "rlive", "--data", $W4, "--http-port", "18797", "--did-host", "live.example.com", "--require-auth", "--public-origin", $base) + $trust) -NoNewWindow -PassThru -RedirectStandardOutput "$Out\rlive.out" -RedirectStandardError "$Out\rlive.err"
Start-Sleep 7
$o = Py "sdk_resolve_live.py" "run $base"; $o | ForEach-Object { Write-Host "  $_" }
Kill $p
Step "the SDK's client is accepted on the strength of its domain alone (and unpublished / other-domain DIDs are not)" (-not (($o -join "`n") -cmatch "FAIL|Traceback") -and $o)

if (-not $SkipRust) {
  Write-Host "The official Rust SDK (anp 1.0.7)"
  $b = wsl -d Ubuntu -- bash "$wslScripts/rust-sdk-build.sh" 2>&1
  Step "the Rust SDK driver builds (isolated folder in WSL)" (($b -join "`n") -match "anp-rust-interop")
  Push-Location $root
  cargo build -q -p anp-e2ee --example p5_chat --example p5_wire 2>&1 | Out-Null
  $env:ANP_FIXTURE_OUT = "$Out\mine.p5.json"; cargo test -q -p anp-e2ee dump_interop_fixture 2>&1 | Out-Null; Remove-Item Env:\ANP_FIXTURE_OUT
  Pop-Location
  $fx = "$Out\mine.p5.json"; $wfx = "$wslOut/mine.p5.json"
  $chatExe = "$Target\debug\examples\p5_chat.exe"; $wireExe = "$Target\debug\examples\p5_wire.exe"
  $script:bad = $false
  function Mine([string[]]$a) { $o = (& $chatExe @a 2>&1 | Out-String); $o.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    mine: $_" }; if ($LASTEXITCODE -ne 0 -or $o -cmatch "FAIL") { $script:bad = $true } }
  function Sdk([string]$cmd) { $pre = if ($env:P5_OPK) { "P5_OPK=1 " } else { "" }; $o = (wsl -d Ubuntu -- bash -c "cd ~/anp-interop/rust-sdk && $pre./target/debug/anp-rust-interop $cmd" 2>&1 | Out-String); $o.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    sdk : $_" }; if ($o -cmatch "FAIL|panicked") { $script:bad = $true } }
  # a conversation: init, two replies, two answers (a ratchet turn), three replies read out of order, and one more
  function Chat($title, $mineStarts, $dir) {
    Write-Host "  $title"
    $d = "$Out\$dir"; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory $d | Out-Null; $w = "$wslOut/$dir"
    $script:bad = $false
    if ($mineStarts) {
      Mine @("init", $fx, 1, "$d\A1.state", "$d\t1.json", "hello bob")
      Sdk "chat-accept $wfx 2 $w/t1.json $w/B1.state $w/t2.json 'hi alice' 'how are you'"
      Mine @("recv", $fx, 3, "$d\A1.state", "$d\t2.json", "0,1", "$d\A2.state", "$d\t3.json", "fine", "thanks")
      Sdk "chat-recv $wfx 4 $w/B1.state $w/t3.json 1,0 $w/B2.state $w/t4.json r3 r4 r5"
      Mine @("recv", $fx, 5, "$d\A2.state", "$d\t4.json", "2,0,1", "$d\A3.state", "$d\t5.json", "bye")
      Sdk "chat-recv $wfx 6 $w/B2.state $w/t5.json 0 $w/B3.state $w/t6.json"
    } else {
      Sdk "chat-init $wfx 1 $w/A1.state $w/t1.json 'hello bob'"
      Mine @("accept", $fx, 2, "$d\t1.json", "$d\B1.state", "$d\t2.json", "hi alice", "how are you")
      Sdk "chat-recv $wfx 3 $w/A1.state $w/t2.json 0,1 $w/A2.state $w/t3.json fine thanks"
      Mine @("recv", $fx, 4, "$d\B1.state", "$d\t3.json", "1,0", "$d\B2.state", "$d\t4.json", "r3", "r4", "r5")
      Sdk "chat-recv $wfx 5 $w/A2.state $w/t4.json 2,0,1 $w/A3.state $w/t5.json bye"
      Mine @("recv", $fx, 6, "$d\B2.state", "$d\t5.json", "0", "$d\B3.state", "$d\t6.json")
    }
    -not $script:bad
  }
  Step "a conversation we start, the SDK answers: init, replies, ratchet turns, out-of-order delivery both ways" (Chat "we initiate" $true "chat-a")
  Step "a conversation the SDK starts, we answer: the same" (Chat "the SDK initiates" $false "chat-b")
  $env:P5_OPK = "1"
  Step "the same with a one-time prekey, we initiate" (Chat "we initiate, with a one-time prekey" $true "chat-c")
  Step "the same with a one-time prekey, the SDK initiates" (Chat "the SDK initiates, with a one-time prekey" $false "chat-d")
  Remove-Item Env:\P5_OPK

  Write-Host "  wire objects: direct.send, publish and get prekey bundle, their results"
  & $wireExe build $fx "$Out\chat-a\t1.json" "$Out\chat-a\t3.json" "$Out\mine.wire.json"
  $o = (wsl -d Ubuntu -- bash -c "cd ~/anp-interop/rust-sdk && ./target/debug/anp-rust-interop wire $wfx $wslOut/mine.wire.json $wslOut/chat-b/t1.json $wslOut/chat-b/t3.json $wslOut/sdk.wire.json" 2>&1 | Out-String)
  $o.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    sdk : $_" }
  Step "the SDK parses every wire object this project builds" (($o -split "`n" | Where-Object { $_ -match "^PASS  the SDK parses" }).Count -eq 7 -and -not ($o -cmatch "FAIL|panicked"))
  $o = (& $wireExe check "$Out\sdk.wire.json" 2>&1 | Out-String); $o.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    mine: $_" }
  Step "this project parses every wire object the SDK builds" (($o -split "`n" | Where-Object { $_ -match "^PASS" }).Count -eq 7 -and -not ($o -cmatch "FAIL"))

  Write-Host "  the SDK's client chats with a running node (P5), then the node restarts"
  $fxj = Get-Content $fx -Raw | ConvertFrom-Json
  [IO.File]::WriteAllText("$Out\alice.did.json", ($fxj.sender.did_document | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
  $route = (wsl -d Ubuntu -- ip route show default) -join " "; $null = $route -match "via (\d+\.\d+\.\d+\.\d+)"; $hostip = $Matches[1]
  $W3 = "$Out\p5node"; Remove-Item $W3 -Recurse -Force -ErrorAction SilentlyContinue
  $nodeArgs = @("--name", "live", "--data", $W3, "--http-port", "18798", "--did-host", "live.example.com", "--e2ee", "--p5", "--p5-peer", "$($fxj.sender.did)=http://127.0.0.1:18799/inbox", "--allow-caller", "$Out\alice.did.json")
  $p = Start-Process $node -ArgumentList $nodeArgs -NoNewWindow -PassThru -RedirectStandardOutput "$Out\p5node.out" -RedirectStandardError "$Out\p5node.err"
  Start-Sleep 8
  $script:bad = $false
  Sdk "live $wfx http://${hostip}:18798 18799 live $wslOut/live.state"
  Step "the SDK's client and the node: key service, init, three messages, signed replies, refusals" (-not $script:bad)
  Kill $p; Start-Sleep 2
  $p = Start-Process $node -ArgumentList $nodeArgs -NoNewWindow -PassThru -RedirectStandardOutput "$Out\p5node2.out" -RedirectStandardError "$Out\p5node2.err"
  Start-Sleep 8
  $script:bad = $false
  Sdk "live-resume $wfx http://${hostip}:18798 18799 $wslOut/live.state"
  Step "after a restart the node still has the session (it is kept on disk)" (-not $script:bad)
  Kill $p

  Write-Host "  the SDK's client chats with a node that resolves its DID over HTTPS (no --allow-caller, no --p5-peer)"
  $W5 = "$Out\p5resolve"; Remove-Item $W5 -Recurse -Force -ErrorAction SilentlyContinue
  $p = Start-Process $node -ArgumentList (@("--name", "live", "--data", $W5, "--http-port", "18798", "--did-host", "live.example.com", "--e2ee", "--p5") + $trust) -NoNewWindow -PassThru -RedirectStandardOutput "$Out\p5resolve.out" -RedirectStandardError "$Out\p5resolve.err"
  Start-Sleep 8
  $script:bad = $false
  Sdk "live $wslOut/mine.p5.domain.json http://${hostip}:18798 18799 live $wslOut/rlive.state"
  Step "the SDK's client and the node: peer learned from its domain, reply endpoint taken from its ANPMessageService" (-not $script:bad)
  Kill $p

  Write-Host "  the node's replies while the network is down: queued, retried, delivered (the SDK's client sits behind a proxy that fails twice)"
  $W6 = "$Out\p5outbox"; Remove-Item $W6 -Recurse -Force -ErrorAction SilentlyContinue
  $px = Start-Process wsl -ArgumentList @("-d", "Ubuntu", "--", "python3", "-I", "$wslScripts/flaky_proxy.py", "18799", "18801", "2") -NoNewWindow -PassThru -RedirectStandardOutput "$Out\proxy.out" -RedirectStandardError "$Out\proxy.err"
  $nodeArgs6 = @("--name", "live", "--data", $W6, "--http-port", "18798", "--did-host", "live.example.com", "--e2ee", "--p5", "--p5-peer", "$($fxj.sender.did)=http://127.0.0.1:18799/inbox", "--allow-caller", "$Out\alice.did.json")
  $env:RUST_LOG = "info"
  $p = Start-Process $node -ArgumentList $nodeArgs6 -NoNewWindow -PassThru -RedirectStandardOutput "$Out\p5outbox.out" -RedirectStandardError "$Out\p5outbox.err"
  Start-Sleep 8
  $script:bad = $false
  Sdk "live $wfx http://${hostip}:18798 18801 live $wslOut/outbox.state"
  Step "every reply reached the SDK's client although the first attempts failed" (-not $script:bad)
  Kill $p; wsl -d Ubuntu -- pkill -f flaky_proxy.py 2>$null | Out-Null
  $log = (Get-Content "$Out\p5outbox.err" -Raw) + ""
  Step "the node logged the failed attempts and then the delivery" (($log -match "not delivered") -and ($log -match "delivered \(attempt 3\)"))
  Remove-Item Env:\RUST_LOG
}
if (Test-Path $GoDriver) {
  Write-Host "The official Go SDK (anp/golang v1.0.7)"
  function Go([string[]]$a) { $o = (& $GoDriver @a 2>&1 | Out-String); $o.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    go  : $_" }; ($LASTEXITCODE -eq 0) -and -not ($o -cmatch "FAIL|panic") }
  Step "the Go SDK validates this project's DID document (e1 binding and proof)" (Go @("didcheck", "$Out\mine.did.json"))
  Step "the Go SDK's P5 v2 checks: bundle against the DID document, init AAD, plaintext canonical form" (Go @("p5", "$Out\mine.p5.json"))
  Step "the Go SDK verifies a request this project signed" (Go @("httpverify", "$Out\mine.http.json"))
  [void](Go @("httpsign", $Out))
  $o2 = (& "$Target\debug\anp-ad.exe" verify-did --did-doc "$Out\gosdkbot.did.json" 2>&1) -join " "
  Step "this project verifies a DID document the Go SDK created" ($o2 -match "^OK")
  Push-Location $root
  $env:ANP_SDK_REQUEST = "$Out\gosdk.http.json"
  $r = cargo test -p anp-httpauth a_request_signed_by_the_sdk 2>&1 | Out-String
  Remove-Item Env:\ANP_SDK_REQUEST
  Pop-Location
  Step "this project verifies a request the Go SDK signed" ($r -match "1 passed")
  if (Test-Path "$Out\chat-a\t1.json") {
    $okw = Go @("wire", "$Out\mine.wire.json", "$Out\chat-a\t1.json", "$Out\chat-a\t3.json", "$Out\mine.p5.json", "$Out\gosdk.wire.json")
    Step "the Go SDK parses every wire object this project builds" $okw
    $o3 = (& "$Target\debug\examples\p5_wire.exe" check "$Out\gosdk.wire.json" 2>&1 | Out-String); $o3.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    mine: $_" }
    Step "this project parses every wire object the Go SDK builds" ((($o3 -split "`n" | Where-Object { $_ -match "^PASS" }).Count -eq 7) -and -not ($o3 -cmatch "FAIL"))
  }
  # P6 (group E2EE) wire objects: the Go SDK's parsers and builders
  $okg = Go @("group", "$Out\mine.group.json", "$root\testdata\anp-sdk\group_e2ee_p6_v2_wire_vectors.json", "$Out\gosdk.group.json")
  Step "the Go SDK parses the P6 requests this project built, agrees on the MLS authenticated data, and builds every request of the vectors" $okg
  Push-Location $root
  $env:ANP_GROUP_GO_FIXTURE = "$Out\gosdk.group.json"
  $r = cargo test -p anp-group requests_built_by_the_go_sdk 2>&1 | Out-String
  Remove-Item Env:\ANP_GROUP_GO_FIXTURE
  Pop-Location
  Step "this project parses every P6 request the Go SDK builds" ($r -match "1 passed")
  # the Go SDK's client against a node: RFC 9421 signatures, then the older scheme
  Write-Host "  the Go SDK's client against a node (ANP-02, then the older scheme)"
  [void](Go @("make", $Out, "localhost", "0", "goclient"))  # the SDK refuses a DID whose host is an IP address
  $gbase = "http://localhost:18797"
  foreach ($m in @(@("http", "ANP-02 signatures"), @("legacy", "the older DIDWba header and Bearer token"))) {
    $W10 = "$Out\golive"; Remove-Item $W10 -Recurse -Force -ErrorAction SilentlyContinue
    $nodeArgsG = @("--name", "golive", "--data", $W10, "--http-port", "18797", "--did-host", "live.example.com", "--require-auth", "--public-origin", $gbase, "--allow-caller", "$Out\goclient.did.json")
    if ($m[0] -eq "legacy") { $nodeArgsG += "--allow-legacy-auth" }
    $p = Start-Process $node -ArgumentList $nodeArgsG -NoNewWindow -PassThru -RedirectStandardOutput "$Out\golive.out" -RedirectStandardError "$Out\golive.err"
    Start-Sleep 7
    $okl = Go @("live", $gbase, "$Out\goclient.did.json", "$Out\goclient.key.pem", $m[0])
    Kill $p
    Step "the Go SDK's client against a node: $($m[1])" $okl
  }
} else { Write-Host "The Go SDK phase is skipped ($GoDriver is missing: scripts/interop/go-sdk-build.ps1 builds it)" }

if ((Test-Path "$TsDir\driver.mjs") -and (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host "The official TypeScript SDK (@awiki/anp-typescript-sdk 0.9.5)"
  function Ts([string[]]$a) { Push-Location $TsDir; $o = (node driver.mjs @a 2>&1 | Out-String); $code = $LASTEXITCODE; Pop-Location; $o.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    ts  : $_" }; ($code -eq 0) -and -not ($o -cmatch "FAIL") }
  Step "the TypeScript SDK validates this project's DID document (e1 binding and proof)" (Ts @("didcheck", "$Out\mine.did.json"))
  Step "the TypeScript SDK verifies a request this project signed" (Ts @("httpverify", "$Out\mine.http.json"))
  [void](Ts @("httpsign", $Out))
  $o2 = (& "$Target\debug\anp-ad.exe" verify-did --did-doc "$Out\tsbot.did.json" 2>&1) -join " "
  Step "this project verifies a DID document the TypeScript SDK created" ($o2 -match "^OK")
  Push-Location $root
  $env:ANP_SDK_REQUEST = "$Out\tssdk.http.json"
  $r = cargo test -p anp-httpauth a_request_signed_by_the_sdk 2>&1 | Out-String
  Remove-Item Env:\ANP_SDK_REQUEST
  Pop-Location
  Step "this project verifies a request the TypeScript SDK signed" ($r -match "1 passed")
  Copy-Item "$Out\wns_cases.json" "$Out\wns_cases_in.json" -Force
  [void](Ts @("cases", "$Out\wns_cases_ts.json", "$Out\wns_cases_in.json"))
  $o = (& $wnsExe validate-file "$Out\wns_cases_ts.json" 2>&1 | Out-String).TrimEnd(); $o -split "`n" | ForEach-Object { Write-Host "    mine: $_" }
  Step "this project and the TypeScript SDK agree on every handle in the table" ($o -match "\b0 disagreements")
  [void](Ts @("make", $Out, "localhost", "tsclient"))
  $tbase = "http://localhost:18797"
  foreach ($m in @(@("http", "ANP-02 signatures"), @("legacy", "the older DIDWba header and Bearer token"))) {
    $W14 = "$Out\tslive"; Remove-Item $W14 -Recurse -Force -ErrorAction SilentlyContinue
    $nodeArgsT = @("--name", "tslive", "--data", $W14, "--http-port", "18797", "--did-host", "live.example.com", "--require-auth", "--public-origin", $tbase, "--allow-caller", "$Out\tsclient.did.json")
    if ($m[0] -eq "legacy") { $nodeArgsT += "--allow-legacy-auth" }
    $p = Start-Process $node -ArgumentList $nodeArgsT -NoNewWindow -PassThru -RedirectStandardOutput "$Out\tslive.out" -RedirectStandardError "$Out\tslive.err"
    Start-Sleep 7
    $okl = Ts @("live", $tbase, "$Out\tsclient.did.json", "$Out\tsclient.key.pem", $m[0])
    Kill $p
    Step "the TypeScript SDK's client against a node: $($m[1])" $okl
  }
} else { Write-Host "The TypeScript SDK phase is skipped ($TsDir\driver.mjs is missing: scripts/interop/ts-sdk-build.ps1 installs it)" }
wsl -d Ubuntu -- pkill -f https_docs.py 2>$null | Out-Null
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }