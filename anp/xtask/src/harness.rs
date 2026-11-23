//! What an end-to-end check needs: where the binaries are, nodes to start and stop, JSON-RPC and HTTP calls, and a tally of PASS and FAIL lines.
//! The output format is the one the PowerShell scripts had (`  PASS  name`, `  FAIL  name  detail`, `ALL PASSED`), so the two read alike.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Where cargo puts the build: `CARGO_TARGET_DIR`, or `<repo>/target` (cargo's own default).
pub fn target_dir() -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => repo_root().join("target"),
    }
}

pub fn repo_root() -> PathBuf {
    // anp/xtask: the workspace root (where cargo's default target folder is) is two levels up
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).expect("xtask sits in anp/xtask").to_path_buf()
}

/// A built program: `bin("anp-node")` is `<target>/debug/anp-node` (with `.exe` on Windows).
pub fn bin(name: &str) -> PathBuf {
    target_dir().join("debug").join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// A scratch folder for a task, next to the build output.
pub fn work_dir(name: &str) -> PathBuf {
    target_dir().join(name)
}

pub fn require_bins(names: &[&str]) -> Result<(), String> {
    for n in names {
        if !bin(n).exists() {
            return Err(format!("{} is not built: run `cargo build -p anp-node -p anp-authz -p anp-ad -p anp-search -p anp-wns -p anp-meta` first", bin(n).display()));
        }
    }
    place_cblite_dll()
}

/// On Windows the programs load `cblite.dll` from their own folder, and cargo leaves it in the build script's output
/// (`debug/build/couchbase_lite-*/out`). Copy the newest one next to them when it is missing or older, so a fresh
/// target folder works without a manual step. Elsewhere the library is found through the rpath: nothing to do.
fn place_cblite_dll() -> Result<(), String> {
    if !cfg!(windows) {
        return Ok(());
    }
    let debug = target_dir().join("debug");
    let newest = std::fs::read_dir(debug.join("build"))
        .map_err(|e| format!("{}: {e}", debug.join("build").display()))?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("couchbase_lite-"))
        .map(|e| e.path().join("out").join("cblite.dll"))
        .filter_map(|p| p.metadata().and_then(|m| m.modified()).ok().map(|t| (t, p)))
        .max();
    let Some((built, src)) = newest else {
        return Err(format!("no cblite.dll under {}: build anp-node first", debug.join("build").display()));
    };
    let dst = debug.join("cblite.dll");
    let current = dst.metadata().and_then(|m| m.modified()).ok();
    if current.map_or(true, |t| t < built) {
        std::fs::copy(&src, &dst).map_err(|e| format!("copy {} to {}: {e}", src.display(), dst.display()))?;
        println!("(copied cblite.dll next to the programs, from {})", src.display());
    }
    Ok(())
}

/// The tally of a task.
#[derive(Default)]
pub struct Checks {
    pub failed: usize,
    pub passed: usize,
}

impl Checks {
    pub fn check(&mut self, name: &str, ok: bool, detail: impl AsRef<str>) {
        if ok {
            self.passed += 1;
            println!("  PASS  {name}");
        } else {
            self.failed += 1;
            println!("  FAIL  {name}  {}", detail.as_ref());
        }
    }

    pub fn note(&self, text: &str) {
        println!("  note  {text}");
    }

    /// Print the verdict; the process exit code to return.
    pub fn finish(&self) -> i32 {
        if self.failed == 0 {
            println!("\nALL PASSED");
            0
        } else {
            println!("\n{} FAILED", self.failed);
            1
        }
    }
}

/// A running `anp-node`, stopped when it goes out of scope.
pub struct Node {
    child: Option<Child>,
    out: PathBuf,
}

impl Node {
    /// Start it with `--name`, `--data <work>/<dir>`, `--http-port` and `extra`, output in `<work>/<dir>.out.txt` and `.err.txt`, and wait until it
    /// has said enough (three lines) or has exited.
    pub fn start(work: &Path, name: &str, dir: &str, http_port: u16, extra: &[String]) -> Node {
        let out = work.join(format!("{dir}.out.txt"));
        let err = work.join(format!("{dir}.err.txt"));
        let child = Command::new(bin("anp-node"))
            .args(["--name", name, "--data"])
            .arg(work.join(dir))
            .args(["--http-port", &http_port.to_string()])
            .args(extra)
            .env("RUST_LOG", "warn")
            .stdout(std::fs::File::create(&out).expect("node output file"))
            .stderr(std::fs::File::create(&err).expect("node error file"))
            .spawn()
            .unwrap_or_else(|e| panic!("start {name}: {e}"));
        let mut n = Node { child: Some(child), out };
        for _ in 0..50 {
            if std::fs::read_to_string(&n.out).map_or(0, |t| t.lines().count()) >= 3 {
                break;
            }
            if n.exited() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        n
    }

    /// Another of the project's programs (`anp-search`, ...) under the same supervision: `args` as given, output in
    /// `<work>/<dir>.out.txt` and `.err.txt`; returns once it has printed a line or exited (or after 10 s).
    pub fn start_program(work: &Path, program: &str, dir: &str, args: &[String]) -> Node {
        let out = work.join(format!("{dir}.out.txt"));
        let err = work.join(format!("{dir}.err.txt"));
        let child = Command::new(bin(program))
            .args(args)
            .env("RUST_LOG", "warn")
            .stdout(std::fs::File::create(&out).expect("program output file"))
            .stderr(std::fs::File::create(&err).expect("program error file"))
            .spawn()
            .unwrap_or_else(|e| panic!("start {program}: {e}"));
        let mut n = Node { child: Some(child), out };
        for _ in 0..50 {
            if std::fs::read_to_string(&n.out).map_or(0, |t| t.lines().count()) >= 1 || n.exited() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        n
    }

    fn exited(&mut self) -> bool {
        self.child.as_mut().map_or(true, |c| matches!(c.try_wait(), Ok(Some(_))))
    }

    /// Everything the node has printed so far.
    pub fn output(&self) -> String {
        std::fs::read_to_string(&self.out).unwrap_or_default()
    }

    /// The P2P (replication) port the node printed.
    pub fn p2p_port(&self) -> Option<u16> {
        let text = std::fs::read_to_string(&self.out).ok()?;
        let line = text.lines().find(|l| l.contains("P2P port"))?;
        line.split_whitespace().filter_map(|w| w.parse::<u16>().ok()).next()
    }

    pub fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill();
    }
}

/// `anp-node --print-did`: the DID a node of this name and data folder has, on the DID host `<name>.example.com`.
pub fn did_of(work: &Path, name: &str, dir: &str) -> String {
    did_for(work, name, &format!("{name}.example.com"), dir)
}

/// The same with a DID host of your choice (the key is made in the data folder, so the folder decides which DID it is).
pub fn did_for(work: &Path, name: &str, host: &str, dir: &str) -> String {
    let out = Command::new(bin("anp-node")).args(["--name", name, "--data"]).arg(work.join(dir)).args(["--did-host", host, "--print-did"]).output().expect("run anp-node --print-did");
    String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).unwrap_or_default().to_string()
}

/// A node that is expected to refuse to start: run it, wait up to `secs`, and say whether it exited, with what code, and what it said on stderr.
pub struct Exit {
    pub exited: bool,
    pub code: Option<i32>,
    pub stderr: String,
}

pub fn expect_exit(work: &Path, tag: &str, args: &[String], secs: u64) -> Exit {
    let err = work.join(format!("{tag}.err.txt"));
    let mut child = Command::new(bin("anp-node"))
        .args(args)
        .env("RUST_LOG", "warn")
        .stdout(std::fs::File::create(work.join(format!("{tag}.out.txt"))).expect("output file"))
        .stderr(std::fs::File::create(&err).expect("error file"))
        .spawn()
        .expect("start anp-node");
    let end = Instant::now() + Duration::from_secs(secs);
    let (mut exited, mut code) = (false, None);
    while Instant::now() < end {
        if let Ok(Some(st)) = child.try_wait() {
            exited = true;
            code = st.code();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }
    Exit { exited, code, stderr: std::fs::read_to_string(&err).unwrap_or_default() }
}

/// Run one of the project's tools (`anp-ad`, `anp-admin`) to the end: its exit code and what it printed (both streams).
pub fn run_tool(name: &str, args: &[String]) -> (i32, String) {
    let out = Command::new(bin(name)).args(args).output().unwrap_or_else(|e| panic!("run {name}: {e}"));
    (out.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

pub fn strs(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

// ── HTTP ────────────────────────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC call to a node's `/` (plain HTTP on loopback); the whole response object, error or not.
pub fn rpc(port: u16, method: &str, params: Value) -> Value {
    rpc_url(&format!("http://127.0.0.1:{port}"), method, params, 60)
}

/// The same for a node anywhere (`base` is `http://host:port`), with a time limit in seconds; `Null` if it did not answer.
pub fn rpc_url(base: &str, method: &str, params: Value, secs: u64) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    match ureq::post(&format!("{base}/")).set("content-type", "application/json").timeout(Duration::from_secs(secs)).send_string(&body) {
        Ok(r) => serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null),
        Err(ureq::Error::Status(_, r)) => serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}
pub fn get_json(url: &str) -> Value {
    match ureq::get(url).timeout(Duration::from_secs(10)).call() {
        Ok(r) => serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

pub fn msg(text: &str) -> Value {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    json!({ "messageId": format!("m-{nanos:x}-{}", N.fetch_add(1, Ordering::SeqCst)), "role": "ROLE_USER", "parts": [{ "text": text }] })
}

/// The node ids a node knows about.
pub fn agents(port: u16) -> Vec<String> {
    agents_at(&format!("http://127.0.0.1:{port}"))
}

pub fn agents_at(base: &str) -> Vec<String> {
    get_json(&format!("{base}/agents")).as_array().map(|a| a.iter().filter_map(|x| x["nodeId"].as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// Wait until the node on `port` knows `name`.
pub fn wait_sees(port: u16, name: &str, secs: u64) -> bool {
    wait_sees_at(&format!("http://127.0.0.1:{port}"), name, secs)
}

pub fn wait_sees_at(base: &str, name: &str, secs: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if agents_at(base).iter().any(|n| n == name) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(330));
    }
    false
}

pub fn sleep(secs: u64) {
    std::thread::sleep(Duration::from_secs(secs));
}

/// The text of a task's artifacts (`SendMessage` answers with `result.task`, `GetTask` with the task as the result).
pub fn task_text(t: &Value) -> String {
    let task = if t["result"]["task"].is_null() { &t["result"] } else { &t["result"]["task"] };
    task["artifacts"].as_array().into_iter().flatten().flat_map(|a| a["parts"].as_array().into_iter().flatten()).filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join("")
}

/// The first file under `dir` whose bytes contain `text`.
pub fn file_contains(dir: &Path, text: &str) -> Option<PathBuf> {
    fn walk(dir: &Path, needle: &[u8]) -> Option<PathBuf> {
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(f) = walk(&p, needle) {
                    return Some(f);
                }
            } else if let Ok(bytes) = std::fs::read(&p) {
                if !needle.is_empty() && bytes.windows(needle.len()).any(|w| w == needle) {
                    return Some(p);
                }
            }
        }
        None
    }
    walk(dir, text.as_bytes())
}

pub fn fresh_dir(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("create the work folder");
}

/// What a GET answered: the status, the content type and the body text.
pub struct Http {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl Http {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

pub fn http_get(url: &str) -> Http {
    let from = |r: ureq::Response| {
        let (status, content_type) = (r.status(), r.header("content-type").unwrap_or_default().to_string());
        Http { status, content_type, body: r.into_string().unwrap_or_default() }
    };
    match ureq::get(url).timeout(Duration::from_secs(10)).call() {
        Ok(r) => from(r),
        Err(ureq::Error::Status(_, r)) => from(r),
        Err(e) => Http { status: 0, content_type: String::new(), body: e.to_string() },
    }
}

/// POST a JSON body (the text as it is); the status and the answer.
pub fn post_json(url: &str, body: &str) -> (u16, Value) {
    match ureq::post(url).set("content-type", "application/json").timeout(Duration::from_secs(30)).send_string(body) {
        Ok(r) => (r.status(), serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null)),
        Err(ureq::Error::Status(c, r)) => (c, serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null)),
        Err(_) => (0, Value::Null),
    }
}

/// What a node has refused so far (`/security`).
pub fn rejections(port: u16) -> Vec<Value> {
    get_json(&format!("http://127.0.0.1:{port}/security"))["rejections"].as_array().cloned().unwrap_or_default()
}

/// Did a refusal like this get logged? `collection` and `doc_id` as the node records them, `reason` a fragment (or empty).
pub fn refused(port: u16, collection: &str, doc_id: &str, reason: &str) -> bool {
    rejections(port).iter().any(|r| r["collection"] == collection && r["docId"] == doc_id && r["reason"].as_str().map_or(false, |s| s.contains(reason)))
}

/// A `SendMessage` answer that completed.
pub fn completed(r: &Value) -> bool {
    r["result"]["task"]["status"]["state"] == "TASK_STATE_COMPLETED"
}

/// `anp-node --print-pubkey`: the public key of the node of this name in `<work>/<dir>` (the key is made there if it is not).
pub fn pubkey_of(work: &Path, name: &str) -> String {
    let out = Command::new(bin("anp-node")).args(["--name", name, "--data"]).arg(work.join(name)).arg("--print-pubkey").output().expect("run anp-node --print-pubkey");
    String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).unwrap_or_default().to_string()
}

/// A new authority root key `<work>/<name>.key`; its public key.
pub fn root_key(work: &Path, name: &str) -> String {
    let (_, out) = run_tool("anp-admin", &strs(&["root-keygen", "--out", &work.join(format!("{name}.key")).display().to_string()]));
    out.lines().find_map(|l| l.split_once("root public key:").map(|(_, k)| k.trim().to_string())).unwrap_or_default()
}

/// A `SendMessage` message that continues a task.
pub fn msg_for(text: &str, task_id: &Value) -> Value {
    let mut m = msg(text);
    m["taskId"] = task_id.clone();
    m
}

/// A streaming call (`SendStreamingMessage`): the events of the server-sent stream, until it ends or `secs` seconds have passed.
pub fn sse_events(port: u16, params: Value, secs: u64) -> Vec<Value> {
    use std::io::BufRead;
    let body = json!({ "jsonrpc": "2.0", "id": 7, "method": "SendStreamingMessage", "params": params }).to_string();
    let Ok(resp) = ureq::post(&format!("http://127.0.0.1:{port}/")).set("content-type", "application/json").timeout(Duration::from_secs(secs)).send_string(&body) else { return vec![] };
    let mut events = vec![];
    for line in std::io::BufReader::new(resp.into_reader()).lines() {
        let Ok(line) = line else { break };
        if let Some(data) = line.strip_prefix("data:") {
            if let Ok(v) = serde_json::from_str::<Value>(data.trim()) {
                events.push(v);
            }
        }
    }
    events
}

/// A token for `node` (its key lives in `<work>/<node_dir>`) from the authority `<work>/<root>.key`, optionally bound to a DID, allowed to send
/// inbox commands to `inbox_to`; written to `<work>/<node>.token`.
pub fn issue_token(work: &Path, root: &str, node: &str, node_dir: &str, did: Option<&str>, inbox_to: &str) {
    let mut a = strs(&["issue", "--root", &work.join(format!("{root}.key")).display().to_string(), "--node", node, "--node-dir", &work.join(node_dir).display().to_string()]);
    if let Some(d) = did {
        a.extend(strs(&["--did", d]));
    }
    a.extend(strs(&["--inbox-to", inbox_to, "--out", &work.join(format!("{node}.token")).display().to_string()]));
    let (code, out) = run_tool("anp-admin", &a);
    assert_eq!(code, 0, "anp-admin issue: {out}");
}

/// Poll `f` every `every_ms` until it holds or `tries` have passed.
pub fn poll(tries: u32, every_ms: u64, mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..tries {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(every_ms));
    }
    false
}

/// The value after `--name` in a task's arguments.
pub fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

pub fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// `cargo`, run in the repository with this build's target folder.
pub fn cargo_cmd() -> Command {
    let mut c = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    c.current_dir(repo_root()).env("CARGO_TARGET_DIR", target_dir());
    c
}