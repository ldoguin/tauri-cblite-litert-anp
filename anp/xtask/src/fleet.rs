//! `cargo xtask fleet-up` / `fleet-down`: the fleet's Couchbase Server and Sync Gateway in a local k3d cluster (step F2 of the fleet plan).
//!
//! The same steps as kubecondemo's `lib/cao.nu` `standup` and `sgw-db` (k3d, cert-manager, the Couchbase Autonomous Operator, the cluster,
//! Sync Gateway, a database), ported here so the repository needs only docker, k3d, kubectl and helm. The manifests are in `anp/fleet/`.
//! Every step is skipped when already done, so `fleet-up` also checks a running fleet and updates its sync function.
//!
//! On the host afterwards:
//! * Sync Gateway's public API, where stores replicate: `ws://localhost:4984/anp` (collections `anp.a2a.<collection>` over REST);
//! * its admin API, without authentication, so on loopback only: `http://127.0.0.1:4985`;
//! * the Couchbase web console: `http://127.0.0.1:18091` (Administrator / password123: a local test cluster).
//!
//! `fleet-up` ends with a check through the public API, as two test stores: a store writes its own documents, cannot write as another store
//! or read another store's channel, and what it wrote is in Server. Then it prints the memory the fleet takes in Docker's VM.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::harness::{flag, repo_root, sleep};

const CLUSTER: &str = "anp-fleet";
const CTX: &str = "k3d-anp-fleet";
const NODE: &str = "k3d-anp-fleet-server-0";
const NS: &str = "couchbase";
const SERVER_IMAGE: &str = "couchbase/server:enterprise-8.0.2";
const SGW_IMAGE: &str = "couchbase/sync-gateway:4.1.2-community";
const OPERATOR_CHART: &str = "2.93.0";
const DB: &str = "anp";
const BUCKET: &str = "fleet";
const SCOPE: &str = "a2a";
const COLLECTIONS: [&str; 6] = ["inbox", "tasks", "agents", "revocations", "telemetry", "rescue"];
const ADMIN: &str = "http://127.0.0.1:4985";
const PUBLIC: &str = "http://127.0.0.1:4984";
pub const CONSOLE: &str = "http://127.0.0.1:18091";
const USER: &str = "Administrator";
const PASSWORD: &str = "password123";

pub fn up(args: &[String]) -> Result<i32, String> {
    let started = Instant::now();
    // the clients only: `kubectl version` alone also asks whatever cluster the current context names
    for (tool, a) in [("docker", &["version"][..]), ("k3d", &["version"][..]), ("kubectl", &["version", "--client"][..]), ("helm", &["version", "--short"][..])] {
        run(tool, a).map_err(|e| format!("{tool} is needed: {e}"))?;
    }
    cluster()?;
    images()?;
    chart("cert-manager", "cert-manager", "jetstack", "https://charts.jetstack.io", "jetstack/cert-manager", &["--set", "crds.enabled=true"])?;
    chart(
        "couchbase",
        NS,
        "couchbase",
        "https://couchbase-partners.github.io/helm-charts",
        "couchbase/couchbase-operator",
        &["--version", OPERATOR_CHART, "--set", "install.couchbaseCluster=false"],
    )?;
    server()?;
    sync_gateway()?;
    database()?;
    let code = if flag(args, "--no-check") { 0 } else { check()? };
    memory();
    println!("\nthe fleet is up ({} s)", started.elapsed().as_secs());
    println!("  Sync Gateway   ws://localhost:4984/{DB}   (REST: {PUBLIC}/{DB}.{SCOPE}.<collection>/)");
    println!("  its admin API  {ADMIN}   (no authentication: loopback only)");
    println!("  web console    {CONSOLE}   ({USER} / {PASSWORD})");
    println!("  stop it with   cargo xtask fleet-down");
    Ok(code)
}

/// Delete the k3d cluster and everything in it (the Server's data included).
pub fn down() -> Result<i32, String> {
    if !cluster_exists()? {
        println!("no k3d cluster {CLUSTER}");
        return Ok(0);
    }
    step(&format!("Deleting k3d cluster {CLUSTER}"));
    run("k3d", &["cluster", "delete", CLUSTER])?;
    Ok(0)
}

// ------------------------------------------------------------------ steps

fn cluster() -> Result<(), String> {
    if cluster_exists()? {
        step(&format!("k3d cluster {CLUSTER} already exists"));
    } else {
        step(&format!("Creating k3d cluster {CLUSTER}"));
        run(
            "k3d",
            &[
                "cluster", "create", CLUSTER, "--servers", "1",
                "--k3s-arg", "--disable=traefik@server:0",
                "--k3s-arg", "--disable=metrics-server@server:0",
                // the public API for stores (and, later, phones on the LAN); the admin API and the console on loopback only
                "-p", "4984:30984@server:0",
                "-p", "127.0.0.1:4985:30985@server:0",
                "-p", "127.0.0.1:18091:30091@server:0",
                "--kubeconfig-update-default", "--kubeconfig-switch-context=false",
                "--wait", "--timeout", "180s",
            ],
        )?;
    }
    wait_for("the kube context", 60, 2, || {
        if run("kubectl", &["config", "get-contexts", "-o", "name"]).map(|o| o.lines().any(|l| l.trim() == CTX)).unwrap_or(false) {
            return true;
        }
        let _ = run("k3d", &["kubeconfig", "merge", CLUSTER, "--kubeconfig-merge-default", "--kubeconfig-switch-context=false"]);
        false
    })?;
    wait_for("CoreDNS", 600, 3, || {
        kjson(&["-n", "kube-system", "get", "deployment", "coredns"]).map(|d| d["status"]["readyReplicas"].as_i64().unwrap_or(0) >= 1).unwrap_or(false)
    })
}

fn cluster_exists() -> Result<bool, String> {
    let list: Value = serde_json::from_str(&run("k3d", &["cluster", "list", "-o", "json"])?).map_err(|e| e.to_string())?;
    Ok(list.as_array().map(|a| a.iter().any(|c| c["name"] == CLUSTER)).unwrap_or(false))
}

/// Pull the two big images inside the node (Docker runs in a VM here: pulling there beats copying them in through the socket).
fn images() -> Result<(), String> {
    for image in [SERVER_IMAGE, SGW_IMAGE] {
        if run("docker", &["exec", NODE, "crictl", "inspecti", image]).is_ok() {
            continue;
        }
        step(&format!("Pulling {image} into the node (Server is about 1 GB compressed; the first time takes minutes)"));
        run("docker", &["exec", NODE, "crictl", "pull", image])?;
    }
    Ok(())
}

/// A helm release, installed unless helm says it is deployed, then its deployments ready.
fn chart(release: &str, ns: &str, repo: &str, repo_url: &str, chart: &str, extra: &[&str]) -> Result<(), String> {
    let deployed = run("helm", &["status", release, "--kube-context", CTX, "-n", ns, "-o", "json"])
        .ok()
        .and_then(|o| serde_json::from_str::<Value>(&o).ok())
        .map(|s| s["info"]["status"] == "deployed")
        .unwrap_or(false);
    if deployed {
        step(&format!("{release} already installed"));
    } else {
        step(&format!("Installing {release}"));
        let _ = run("helm", &["repo", "add", repo, repo_url]);
        run("helm", &["repo", "update", repo])?;
        let mut a = vec!["upgrade", "--install", release, chart, "--kube-context", CTX, "--namespace", ns, "--create-namespace", "--timeout", "15m"];
        a.extend_from_slice(extra);
        run("helm", &a)?;
    }
    let selector = format!("app.kubernetes.io/instance={release}");
    wait_for(&format!("the {release} deployments"), 900, 5, || {
        kjson(&["-n", ns, "get", "deployments", "-l", &selector])
            .map(|d| {
                let items = d["items"].as_array().cloned().unwrap_or_default();
                !items.is_empty()
                    && items.iter().all(|i| i["status"]["readyReplicas"].as_i64().unwrap_or(0) >= i["spec"]["replicas"].as_i64().unwrap_or(1))
            })
            .unwrap_or(false)
    })
}

fn server() -> Result<(), String> {
    step("Applying the admin secret and anp/fleet/cluster.yaml");
    let secret = json!({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": { "name": "cb-admin-auth", "namespace": NS },
        "stringData": { "username": USER, "password": PASSWORD }
    });
    run_stdin("kubectl", &["--context", CTX, "apply", "-f", "-"], &secret.to_string())?;
    let manifest = repo_root().join("anp").join("fleet").join("cluster.yaml");
    run("kubectl", &["--context", CTX, "apply", "-f", &manifest.to_string_lossy()])?;
    step("Waiting for Couchbase Server (the first start takes a few minutes)");
    wait_for("the Server pod", 1200, 5, || {
        kjson(&["-n", NS, "get", "pods", "-l", "couchbase_cluster=anp-fleet"])
            .map(|p| {
                p["items"].as_array().map(|items| {
                    items.len() == 1
                        && items.iter().all(|i| {
                            i["status"]["containerStatuses"].as_array().map(|c| !c.is_empty() && c.iter().all(|s| s["ready"] == true)).unwrap_or(false)
                        })
                })
            })
            .ok()
            .flatten()
            .unwrap_or(false)
    })?;
    wait_for("the cluster Balanced and Available", 600, 5, || condition("Balanced") && condition("Available"))?;
    // the operator creates the bucket, then the scope and collections
    wait_for("the bucket's collections", 300, 3, || {
        let out = query(&format!("SELECT RAW name FROM system:keyspaces WHERE `bucket` = '{BUCKET}' AND `scope` = '{SCOPE}'"));
        out.map(|v| COLLECTIONS.iter().all(|c| v.iter().any(|n| n == c))).unwrap_or(false)
    })?;
    step(&format!("Couchbase Server ready: bucket {BUCKET}, scope {SCOPE}, {} collections", COLLECTIONS.len()));
    Ok(())
}

fn condition(kind: &str) -> bool {
    kjson(&["-n", NS, "get", "couchbasecluster", "anp-fleet"])
        .map(|c| c["status"]["conditions"].as_array().map(|a| a.iter().any(|x| x["type"] == kind && x["status"] == "True")).unwrap_or(false))
        .unwrap_or(false)
}

fn sync_gateway() -> Result<(), String> {
    step("Applying anp/fleet/sync-gateway.yaml");
    let manifest = repo_root().join("anp").join("fleet").join("sync-gateway.yaml");
    run("kubectl", &["--context", CTX, "apply", "-f", &manifest.to_string_lossy()])?;
    run("kubectl", &["--context", CTX, "-n", NS, "wait", "--for=condition=Available", "deployment/sync-gateway", "--timeout=300s"])?;
    wait_for("Sync Gateway's admin API on 127.0.0.1:4985", 180, 2, || http("GET", &format!("{ADMIN}/"), None, None).map(|(s, _)| s == 200).unwrap_or(false))
}

/// The database `anp` on the bucket, every collection of scope a2a with the sync function; created, or its config replaced.
fn database() -> Result<(), String> {
    let sync = std::fs::read_to_string(repo_root().join("anp").join("fleet").join("sync.js")).map_err(|e| format!("anp/fleet/sync.js: {e}"))?;
    // Sync Gateway 4.1 answers "Bad JSON" to a config whose sync function string holds comments: send the code alone
    let sync = sync.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    let collections: serde_json::Map<String, Value> = COLLECTIONS.iter().map(|c| (c.to_string(), json!({ "sync": sync }))).collect();
    let config = json!({
        "bucket": BUCKET,
        "num_index_replicas": 0,
        "enable_shared_bucket_access": true,
        "scopes": { SCOPE: { "collections": collections } },
    });
    let exists = http("GET", &format!("{ADMIN}/{DB}/"), None, None)?.0 == 200;
    if exists {
        step(&format!("Sync Gateway database {DB} exists: replacing its config (the sync function from anp/fleet/sync.js)"));
        let (s, b) = http("PUT", &format!("{ADMIN}/{DB}/_config"), Some(&config), None)?;
        if s >= 300 {
            return Err(format!("updating the database config: {s} {b}"));
        }
    } else {
        step(&format!("Creating Sync Gateway database {DB} on bucket {BUCKET}"));
        // can be refused while the bucket warms up: retry
        let mut last = String::new();
        let ok = wait_for("the database", 120, 3, || match http("PUT", &format!("{ADMIN}/{DB}/"), Some(&config), None) {
            Ok((s, _)) if s < 300 => true,
            Ok((s, b)) => {
                last = format!("{s} {b}");
                http("GET", &format!("{ADMIN}/{DB}/"), None, None).map(|(s, _)| s == 200).unwrap_or(false)
            }
            Err(e) => {
                last = e;
                false
            }
        });
        ok.map_err(|e| format!("{e}; last answer: {last}"))?;
    }
    wait_for("the database online", 120, 2, || {
        http("GET", &format!("{ADMIN}/{DB}/"), None, None).map(|(s, b)| s == 200 && b["state"] == "Online").unwrap_or(false)
    })
}

/// Two test stores through the public API: each writes its own documents; neither can write as the other or read the other's channel;
/// what was written is in Server. Returns 0 when every expectation holds, 1 otherwise.
fn check() -> Result<i32, String> {
    step("Checking the sync function through the public API, as two test stores");
    let stores = ["fleet-check-a", "fleet-check-b"];
    for s in stores {
        let access: serde_json::Map<String, Value> = COLLECTIONS.iter().map(|c| (c.to_string(), json!({ "admin_channels": [format!("store.{s}")] }))).collect();
        let user = json!({ "name": s, "password": "check-password", "collection_access": { SCOPE: access } });
        let (st, b) = http("PUT", &format!("{ADMIN}/{DB}/_user/{s}"), Some(&user), None)?;
        if st >= 300 {
            return Err(format!("creating test user {s}: {st} {b}"));
        }
    }
    let ks = format!("{DB}.{SCOPE}.telemetry");
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let own_id = format!("fleet-check-a::probe-{stamp}");
    let forged_id = format!("fleet-check-b::probe-{stamp}");
    let a = Some(("fleet-check-a", "check-password"));
    let b = Some(("fleet-check-b", "check-password"));
    let doc = |author: &str| json!({ "trust": { "author": author, "seq": stamp, "sig": "not-checked-by-sync-gateway" }, "unit": "probe", "readings": [] });

    let mut failures = 0;
    let mut expect = |what: &str, ok: bool, detail: String| {
        println!("  [{}] {what}{}", if ok { "ok" } else { "FAIL" }, if ok { String::new() } else { format!(": {detail}") });
        if !ok {
            failures += 1;
        }
    };
    let (s, body) = http("PUT", &format!("{PUBLIC}/{ks}/{own_id}"), Some(&doc("fleet-check-a")), a)?;
    expect("a store writes a document it authored", s == 201, format!("{s} {body}"));
    let (s, body) = http("PUT", &format!("{PUBLIC}/{ks}/{forged_id}"), Some(&doc("fleet-check-b")), a)?;
    expect("a store cannot write a document as another store", s == 403, format!("{s} {body}"));
    let (s, body) = http("GET", &format!("{PUBLIC}/{ks}/{own_id}"), None, a)?;
    expect("the store reads its own document back", s == 200, format!("{s} {body}"));
    let (s, body) = http("GET", &format!("{PUBLIC}/{ks}/{own_id}"), None, b)?;
    expect("another store cannot read it", s == 403 || s == 404, format!("{s} {body}"));
    let (s, body) = http("GET", &format!("{ADMIN}/{DB}.{SCOPE}.telemetry/{own_id}?show_exp=false"), None, None)?;
    let channels_ok = s == 200;
    expect("Sync Gateway holds it", channels_ok, format!("{s} {body}"));
    let in_server = wait_for("the document in Server", 30, 2, || {
        query(&format!("SELECT RAW META().id FROM `{BUCKET}`.`{SCOPE}`.`telemetry` USE KEYS '{own_id}'")).map(|v| v.len() == 1).unwrap_or(false)
    });
    expect("the document is in Couchbase Server (fleet.a2a.telemetry)", in_server.is_ok(), in_server.err().unwrap_or_default());
    for s in stores {
        let _ = http("DELETE", &format!("{ADMIN}/{DB}/_user/{s}"), None, None);
    }
    Ok(if failures == 0 { 0 } else { 1 })
}

/// What the fleet takes in Docker's VM: each k3d container, and the VM's memory as the node sees it.
fn memory() {
    step("Memory");
    if let Ok(out) = run("docker", &["stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}"]) {
        for l in out.lines().filter(|l| l.contains(CLUSTER)) {
            println!("  {l}");
        }
    }
    if let Ok(out) = run("docker", &["exec", NODE, "cat", "/proc/meminfo"]) {
        let kb = |key: &str| out.lines().find(|l| l.starts_with(key)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok());
        if let (Some(total), Some(avail)) = (kb("MemTotal:"), kb("MemAvailable:")) {
            println!("  Docker's VM: {} MiB of {} MiB in use, {} MiB available", (total - avail) / 1024, total / 1024, avail / 1024);
        }
    }
}

// ------------------------------------------------------------------ helpers

fn step(what: &str) {
    println!("==> {what}");
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("{cmd} {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn run_stdin(cmd: &str, args: &[&str], input: &str) -> Result<String, String> {
    let mut child = Command::new(cmd).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{cmd}: {e}"))?;
    child.stdin.take().expect("stdin").write_all(input.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("{cmd} {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn kjson(args: &[&str]) -> Result<Value, String> {
    let mut a = vec!["--context", CTX];
    a.extend_from_slice(args);
    a.extend_from_slice(&["-o", "json"]);
    serde_json::from_str(&run("kubectl", &a)?).map_err(|e| e.to_string())
}

/// A SQL++ statement run in the Server pod (its image has curl; nothing on the host needs the query port). The `results`.
fn query(statement: &str) -> Result<Vec<String>, String> {
    let out = run(
        "kubectl",
        &[
            "--context", CTX, "-n", NS, "exec", "anp-fleet-0000", "-c", "couchbase-server", "--",
            "curl", "-sS", "-u", &format!("{USER}:{PASSWORD}"), "http://localhost:8093/query/service",
            "--data-urlencode", &format!("statement={statement}"),
        ],
    )?;
    let v: Value = serde_json::from_str(&out).map_err(|e| format!("{e}: {out}"))?;
    Ok(v["results"].as_array().map(|r| r.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect()).unwrap_or_default())
}

/// An HTTP call to Sync Gateway: the status and the JSON body (Null when there is none). Only a transport error is an `Err`.
fn http(method: &str, url: &str, body: Option<&Value>, auth: Option<(&str, &str)>) -> Result<(u16, Value), String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build();
    let mut req = agent.request(method, url);
    if let Some((u, p)) = auth {
        use base64_basic::encode;
        req = req.set("Authorization", &format!("Basic {}", encode(&format!("{u}:{p}"))));
    }
    let res = match body {
        Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => req.call(),
    };
    let res = match res {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e.to_string()),
    };
    let status = res.status();
    let text = res.into_string().unwrap_or_default();
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

fn wait_for(what: &str, secs: u64, every: u64, mut f: impl FnMut() -> bool) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if f() {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("timed out after {secs} s waiting for {what}"));
        }
        sleep(every);
    }
}

/// Basic auth without another dependency.
mod base64_basic {
    pub fn encode(s: &str) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let b = s.as_bytes();
        let mut out = String::new();
        for c in b.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
        }
        out
    }
}
