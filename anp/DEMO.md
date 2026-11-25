# Cold-stock rescue: build it and show it live

A guide for someone who has the repository and wants to run this demo in front of an audience. It covers what to install, how to build,
what to prepare the day before, a run of show with timings and what to say, how to reset between takes, and what to do when something breaks.

The demo in one paragraph: it is the night after an attack on supermarket refrigeration. A store's freezers fail; the store's own agent
finds eight companies it has never worked with, asks them for quotes, chooses by rules, commits money only within a limit the retailer's
authority signed, asks a person when the plan costs more, and leaves a record anyone can audit offline. Behind it, every store's signed
records travel through Couchbase Lite, Sync Gateway and Couchbase Server to a head office that sees the whole fleet. Everything is a
simulation of the business (the store, the companies and their prices are fictional); the identities, signatures, tokens, encryption
and replication are real.

There is a slide deck that tells the same story (26 slides with speaker notes, in the Couchbase 2026 design). Its sources are in [`deck/`](deck/README.md), with a
script that previews it locally; to present it you need it published as a Slides artifact in Claude (the deck's README says how), or ask whoever gave you the
repository for a link to a published copy.

## 1. What you need

| | Needed for | Notes |
|---|---|---|
| Rust (stable) and a C toolchain | building | The Couchbase Lite binding generates its bindings with `bindgen`, which needs libclang (LLVM). |
| LLVM / libclang | building | On Windows, if the build cannot find standard headers, set `BINDGEN_EXTRA_CLANG_ARGS` to LLVM's clang include folder, for example `-IC:/scoop/apps/llvm/current/lib/clang/21/include` (your version number will differ). |
| Docker, with at least 4 GB for its VM | the fleet (Sync Gateway and Server) | I ran it in a VM of 3.9 GB: the whole fleet used about 2.1 GB, so 4 GB is the floor. |
| `k3d`, `kubectl`, `helm` on the PATH | the fleet | Tested with k3d 5.9, kubectl 1.34, helm 4.3. |
| Internet, once | the fleet | The first `fleet-up` pulls Couchbase Server (about a gigabyte compressed), Sync Gateway, cert-manager and the Couchbase operator. Do it the day before, never at the venue. |
| A browser (Chrome or Edge) | showing | A screen at 1920×1080 is what the pages and the recording are designed for. |
| Node 22+, ffmpeg | recording a backup video only | `--record` drives a headless browser and stitches frames with ffmpeg. |
| Free disk | everything | Keep at least 15 GB free: the build folder and the Docker images are large (a full disk stopped the work once). |

Not needed for this demo: WSL, the Tauri app, the on-device model (that is a separate, optional check, `bash scripts/linux-model.sh`).

The demo runs on one machine: about fourteen processes (the nodes) plus the Docker cluster. Close heavy applications first. Under load a company
can answer slowly; the agent waits up to 120 seconds for each answer, but the show feels slow if the machine is struggling.

### Installing the dependencies

**Windows (the route this was built and tested on).** It uses [scoop](https://scoop.sh) for the tools, the GNU flavour of Rust's Windows toolchain, and MSYS2's
MinGW compiler. The MSVC toolchain is installed on that machine too, but the demo was built with the GNU one; I have not tried it with MSVC. What I checked: the
tool list and versions below are what is installed on the build machine, and the scoop package names exist. What I did not do: replay these commands on a clean
machine, so if one fails, the check block at the end of this section says which tool is missing.

1. Install scoop if you do not have it (from a normal, non-administrator PowerShell):

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   irm get.scoop.sh | iex
   ```

2. Install the tools:

   ```powershell
   scoop install git rustup msys2 llvm cmake ninja k3d helm nodejs-lts ffmpeg
   ```

   `nodejs-lts` and `ffmpeg` are only for recording the backup video. Docker Desktop (next step) ships `kubectl`; if you run Docker some other way, add
   `kubectl` to that command.

3. Install Rust and pick the GNU toolchain:

   ```powershell
   rustup toolchain install stable-x86_64-pc-windows-gnu
   rustup default stable-x86_64-pc-windows-gnu
   ```

4. Give MinGW to the build: install the compiler with MSYS2's package manager, then put its `bin` folder on your PATH.

   ```powershell
   & "$(scoop prefix msys2)\usr\bin\bash.exe" -lc "pacman -S --noconfirm mingw-w64-x86_64-toolchain"
   [Environment]::SetEnvironmentVariable("Path", "$(scoop prefix msys2)\mingw64\bin;" + [Environment]::GetEnvironmentVariable("Path", "User"), "User")
   ```

   Open a new terminal afterwards. `gcc --version` should answer.

5. Tell `bindgen` where LLVM is. This is what a build error about a missing header or `libclang` is about. For the current terminal:

   ```powershell
   $env:LIBCLANG_PATH = "$(scoop prefix llvm)\bin"
   $clang = (Get-ChildItem "$(scoop prefix llvm)\lib\clang" | Select-Object -First 1).FullName -replace '\\','/'
   $env:BINDGEN_EXTRA_CLANG_ARGS = "-I$clang/include"
   ```

   To keep them for every terminal, set the same two variables with `[Environment]::SetEnvironmentVariable("LIBCLANG_PATH", ..., "User")`. On the machine this
   was built on, `LIBCLANG_PATH` is set permanently and `BINDGEN_EXTRA_CLANG_ARGS` is set in the terminal that builds.

6. Install Docker Desktop from <https://www.docker.com/products/docker-desktop/> (with the WSL 2 backend), start it, and give its VM at least 4 GB:
   with the WSL 2 backend that is `memory=6GB` under `[wsl2]` in `%UserProfile%\.wslconfig`, then `wsl --shutdown` and start Docker again. Check with
   `docker info --format "{{.MemTotal}}"` (it prints bytes; 4 GB is about 4300000000).

**macOS and Linux (not tested for this demo; the steps are the usual ones).**

- macOS: `brew install rustup llvm cmake k3d kubectl helm node ffmpeg`, then `rustup default stable`, Docker Desktop with at least 4 GB, and
  `export LIBCLANG_PATH="$(brew --prefix llvm)/lib"`.
- Linux (Debian or Ubuntu): `sudo apt install build-essential cmake clang libclang-dev curl git nodejs ffmpeg`, Rust from <https://rustup.rs>, Docker Engine, and
  `k3d`, `kubectl` and `helm` from their own install pages. The node builds on Linux (that is how the on-device model check runs, in WSL); the demo tasks are written in
  Rust so they run the same.

**Check everything before you build:**

```powershell
rustc --version; gcc --version; cmake --version
docker --version; k3d version; kubectl version --client; helm version --short
node --version; ffmpeg -version
```

Each should print a version. This is the setup it was built with: rustc 1.99, gcc from MSYS2 MinGW, cmake 4.4, LLVM 21.1, Docker 28.4, k3d 5.9, kubectl 1.34, helm 4.3,
Node 24 and ffmpeg 9. Newer versions are likely fine; I have not tried older ones.

## 2. Build

From the repository root:

```powershell
cargo build -p anp-node -p anp-authz -p anp-search -p xtask
```

The first build takes several minutes (Couchbase Lite is large). `cargo xtask <task>` is an alias for the project's task runner; it finds the
binaries in `target\debug` and copies `cblite.dll` next to them itself.

Check the build with a task that needs no Docker (about two minutes):

```powershell
cargo xtask e2e-rescue
```

It should end with `ALL PASSED` (44 checks). If it does, the nodes, the companies, the agent, the head office and the signatures all work on this
machine.

## 3. The day before

### 3.1 Bring up the fleet

```powershell
cargo xtask fleet-up
```

This creates a local k3d cluster named `anp-fleet` with the Couchbase Autonomous Operator, one Couchbase Server 8.0 node (bucket `fleet`,
scope `a2a`, eight collections) and Sync Gateway 4.1 (database `anp`). It ends with a self-check as two test stores and prints the memory used. The
first run takes several minutes, mostly image pulls. When the cluster already exists the command is idempotent and takes about 15 to 30 seconds.

After it, these are up on your machine:

| What | Address |
|---|---|
| Sync Gateway public API (stores replicate here) | `ws://localhost:4984/anp` |
| Sync Gateway admin API (no authentication, loopback only) | `http://127.0.0.1:4985` |
| Couchbase web console | `http://127.0.0.1:18091` (Administrator / password123: a throwaway local cluster) |

If your laptop sleeps or Docker restarts, `k3d cluster start anp-fleet` brings the cluster back, then run `cargo xtask fleet-up` again.

### 3.2 Rehearse the full demo once

```powershell
cargo xtask cold-rescue --gateway
```

Wait about a minute until it prints the addresses. Then open the two pages:

| Page | Address |
|---|---|
| The control room of store 0412 | `http://127.0.0.1:19102/demo/rescue` |
| The head office's fleet view | `http://127.0.0.1:19112/demo/fleet` |

Add `?autoplay=1` to the control room address to watch the night play with captions. Stop everything with Enter in the terminal. Do this rehearsal
on the machine and the screen you will present on.

### 3.3 Record a backup video

A live demo needs a fallback. With nothing else running:

```powershell
cargo xtask cold-rescue --gateway --record backup.mp4
```

It takes about five minutes and films the control room's autoplay (with an explainer under each caption and an intro and outro card), then the
head office's page. Keep the file on the presenting machine and on a USB stick. The videos are not committed to the repository.

### 3.4 Pre-flight checklist (an hour before)

- Docker is running; `k3d cluster list` shows `anp-fleet` with 1/1 servers.
- `cargo xtask fleet-up` ends with six `[ok]` lines.
- No leftover processes from a rehearsal: `Get-Process anp-node, anp-search -ErrorAction SilentlyContinue` shows nothing.
- Notifications are off, the battery is not the only power, the browser is full screen at 100% zoom.
- The terminal is large enough to read from the back of the room, with a tab ready to run `cargo xtask cold-rescue --gateway`.
- The backup video plays.

## 4. Show it live: run of show (about 15 minutes)

The commands below are what you type; the italic lines are what to say. The slide numbers refer to the deck.

### Before the audience is in

```powershell
cargo xtask cold-rescue --gateway
```

Wait until it prints `the control room:` and `the head office:`. Notice what it already did: it started the store you will watch (store 0412) and two
more stores, 0207 and 0933, made their freezers fail, and started their agents. Each of those two plans a €10,500 rescue, is over its €6,000
budget, and now **waits for a duty manager that nobody answers**. They are there so the head office has something to show.

Open the control room (without `?autoplay=1`) and the fleet view in two browser windows, side by side if you can share two windows.

### 0:00 Frame it (1 minute) · slides 1 to 3

*In October 2026 attackers put the refrigeration controllers of about 700 French supermarkets into defrost overnight. This is one store, at 01:50.
Four cold units, about €40,000 of stock, nobody on site. What happens next is what I'm going to show.*

### 1:00 The night (about 3 minutes) · slides 4 to 9

Load the control room with autoplay: `http://127.0.0.1:19102/demo/rescue?autoplay=1`. Keep this window in front; the page's timers slow down in a
background tab. It plays the whole night by itself with a caption at the top and an explanation under it. The beats, in order:

| Caption | What to point at |
|---|---|
| 01:50, the store is closed | The cold room and the Couchbase strip: the store's own Couchbase Lite database counts its signed documents. |
| A controller fault; fifty minutes later | The temperatures climbing; ice cream and vegetables turn **lost**. Food-safety rules, not a model, decide what is lost. |
| Then freezer 2 | €17,800 of frozen meat and fish at about 45 minutes. |
| The store's agent takes over | Eight companies found through a search agent that lists only descriptions it verified against each company's DID. |
| It asks every company at once | Encrypted direct messages; every request is signed. |
| Quotes come back | Polar Express declines (no truck before 06:00); ColdChain €5,400 beats FrostLine €9,400. In the log, **each decision names its rule**. |
| The plan costs €10,500 | The agent is over its €6,000 and **stops**. This is the point to slow down: it can only ask. |
| The duty manager approves | The budget goes to €11,000. |
| The agent accepts each offer | Each company checks the store's token itself. |
| An encrypted group | The plan is posted to a group whose host cannot read it. |
| Done | Six deals, €10,500, every one audited offline. |

Say, while it plays: *the agent reasons freely, but it can only sign what its token allows. A holder can narrow a token, never widen it.*

The head office window changes at the same time: store 0412 goes from "no rescue run" through the agent's phases to **done, 6 deals, €10,500 spent**,
while stores 0207 and 0933 stay amber, waiting for their duty managers.

### 4:30 Where Couchbase moves the data (3 minutes) · slides 10 to 13

Go to the fleet view. Point at the **Couchbase strip** under the header; it has four pieces and each box outlines in red when its number changes:

1. **Couchbase Lite**: this node's own database, with the number of signed documents per collection.
2. **Sync Gateway**: online, with its update sequence.
3. **Couchbase Server**: how many documents it holds.
4. The arrows say how they replicate and whether the link is live.

*Between companies it's the Agent Network Protocol. Inside the retailer, every store's Couchbase Lite replicates its signed documents through Sync Gateway
into Couchbase Server, and head office's Couchbase Lite pulls them out and checks every signature. Head office never asked a store anything.*

Then open the Couchbase console, `http://127.0.0.1:18091` (Administrator / password123), **Documents**, bucket `fleet`, scope `a2a`:

- `telemetry` has one document per unit per store; `rescue` has one record per run, rewritten at every step.
- Open one and show its `trust` block: the author, a signature and the DID that signed it. *Server stores it; it is not what makes it true. Every reader verifies.*

Optional, from a terminal, to show that Sync Gateway puts each store's documents in a channel of its own (the admin API has no authentication and is
loopback only; the first command is the database's state, the second lists documents with their channels):

```powershell
curl.exe -s http://127.0.0.1:4985/anp/
curl.exe -s "http://127.0.0.1:4985/anp.a2a.telemetry/_all_docs?channels=true&limit=5"
```

Each row ends with `"channels":["store.<node>"]`: a store may read and write only its own.

### 7:30 The architecture (2 minutes) · slides 14 to 17

Show the diagram slide ("How The Pieces Fit"): everything on the left is the retailer, everything on the right is outside it; red outlines are
Couchbase; the numbers are explained on the next slide. *Nothing in the middle decides for the store. The gateway only routes and keeps stores apart.*

### 9:30 Proof, live (optional, 3 minutes) · slide 25

The strongest proof is a check that tries to cheat and fails. Stop the demo first (press Enter in its terminal), because the checks use the same ports,
then run one:

```powershell
cargo xtask e2e-approval
```

It runs the whole night again with a phone as duty manager: the phone signs an approval and it reaches the store through Sync Gateway; a head office's signed
approval is logged and **ignored**; an approval for another store never leaves the phone. About two minutes, 21 checks, ending `ALL PASSED`.

Or `cargo xtask e2e-revocation` (19 checks): the authority revokes the store's spending token, the store stops signing with it, a new token is carried in, and a revoked
token carried again is refused.

### 12:30 Close · slides 24 to 26

*Four things made it possible: strangers found and verified, spending limited by a token the other side checks, a record no one can rewrite, and the fleet seen from head
office through Couchbase.* Then questions.

## 5. Variations

- **No Docker on the machine, or no time to bring up the fleet.** Run `cargo xtask cold-rescue --fleet` instead of `--gateway`. Everything works except Sync
  Gateway and Server: the stores replicate straight to the head office's Couchbase Lite over TLS, and the Couchbase strip shows that instead. Skip the console part.
- **Just the store.** `cargo xtask cold-rescue` alone starts the night's ten nodes and the control room, with no other stores and no head office.
- **Drive the night by hand.** Open the control room without `?autoplay=1` and use its buttons: *Freezer 1 + dairy fail*, *+10 min*, *+50 min*, *Freezer 2 fails*,
  *Start the agent*, *Approve (€11,000 budget)*. It is a good way to answer "what if" questions.
- **Approve a waiting store.** Stores 0207 and 0933 listen for `POST /rescue/approve` on ports 19115 and 19116 (for example
  `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:19115/rescue/approve -ContentType application/json -Body '{"budget":"11000"}'`). They will try to commit, but the first store has usually taken the best
  carrier by then, so their plans may end smaller. Use it only if you are comfortable improvising.

## 6. Between takes and at the end

- **One take per start.** The simulation keeps its state: a second autoplay on the same nodes does not replay the night (the units are already failed, the budget
  is spent). To show it again, press Enter in the terminal and run `cargo xtask cold-rescue --gateway` again (about a minute). With `--gateway` it also removes the
  previous take's documents for these store names first, so the counts start clean.
- **Stop the demo:** Enter in its terminal.
- **Pause the fleet:** `k3d cluster stop anp-fleet` (start it again with `k3d cluster start anp-fleet`).
- **Delete the fleet and its data:** `cargo xtask fleet-down`.

## 7. If something goes wrong

| Symptom | Likely cause and fix |
|---|---|
| `--gateway needs the fleet: run cargo xtask fleet-up first` | The cluster is stopped or Docker is down. `k3d cluster start anp-fleet`, then `cargo xtask fleet-up`. |
| `fleet-up` times out waiting for Server | Docker has too little memory. Give it at least 4 GB, restart Docker, run `fleet-up` again. |
| An operator or Sync Gateway pod keeps restarting | Run `cargo xtask fleet-up` again; if it keeps happening, memory is short. I saw the operator pod restart a couple of times under load. |
| A port is in use, or `cargo build` says it cannot remove `anp-node.exe` | A previous run is still alive. `Get-Process anp-node, anp-search, xtask -ErrorAction SilentlyContinue \| Stop-Process`, then retry. |
| The pages show old numbers, or captions lag | The browser window is in the background or minimized, and its timers slow down. Keep the demo window in front. |
| The bindgen build error about missing headers (Windows) | Set `BINDGEN_EXTRA_CLANG_ARGS` to LLVM's clang include folder (section 1). |
| The control room says the agent did not come up | The machine is overloaded or a stale process holds a port. Stop all nodes (above) and start again. |
| The plan ends with fewer than six deals | A company answered too slowly on a busy machine. Close other applications and run another take. |
| The page works but the Couchbase strip says Sync Gateway is "not answering" | The fleet went down mid-demo. `k3d cluster start anp-fleet`; the nodes catch up on their own. |
| Nothing works five minutes before | Play the backup video (section 3.3). |

`cargo xtask e2e-biscuit` is known to fail intermittently, and it is not part of this demo; do not run it live.

## 8. Reference

**Commands**

```text
cargo xtask fleet-up                       the fleet: k3d, operator, Server, Sync Gateway (idempotent)
cargo xtask fleet-down                     delete that cluster and its data
cargo xtask cold-rescue                    the night: ten nodes and the control room
cargo xtask cold-rescue --fleet            the same, plus two more stores and a head office, peer to peer
cargo xtask cold-rescue --gateway          the same, through Sync Gateway into Couchbase Server (needs fleet-up)
cargo xtask cold-rescue ... --record F.mp4 film it (Node 22+, Chrome or Edge, ffmpeg)
cargo xtask e2e-rescue | e2e-fleet | e2e-fleet-view | e2e-approval | e2e-revocation    the checks behind each claim
```

**Ports**

| Port | What |
|---|---|
| 19102 | store 0412: the control room at `/demo/rescue` |
| 19112 | the head office: the fleet view at `/demo/fleet` |
| 19115, 19116 | stores 0207 and 0933 |
| 19101 | the group host |
| 19103 to 19110 | the eight companies |
| 19111 | the search agent |
| 4984, 4985 | Sync Gateway (public; admin, loopback only) |
| 18091 | Couchbase web console (loopback only) |

Every node also has a local `GET /couchbase` that returns what the strip shows, and `GET /fleet` on the head office returns the fleet view as JSON; both answer only
this machine.

**Where to read more**

- `anp/README.md`: the whole project, the protocol glossary, and each task's checks.
- `anp/fleet/`: the Kubernetes manifests and the Sync Gateway sync function (`sync.js`) that keeps the stores apart.
- `anp/xtask/src/`: the tasks, one file each (`coldrescue.rs` is the demo, `fleet.rs` the cluster).
