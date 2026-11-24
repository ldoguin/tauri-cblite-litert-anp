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

use crate::harness::{did_for, fresh_dir, flag, get_json, poll, post_json, repo_root, require_bins, sleep, strs, work_dir, Checks, Node};

const CLUSTER: &str = "anp-fleet";
const CTX: &str = "k3d-anp-fleet";
const NODE: &str = "k3d-anp-fleet-server-0";
const NS: &str = "couchbase";
const SERVER_IMAGE: &str = "couchbase/server:enterprise-8.0.2";
const SGW_IMAGE: &str = "couchbase/sync-gateway:4.1.2-community";
const OPERATOR_CHART: &str = "2.93.0";
pub(crate) const DB: &str = "anp";
pub(crate) const BUCKET: &str = "fleet";
pub(crate) const SCOPE: &str = "a2a";
const COLLECTIONS: [&str; 8] = ["inbox", "tasks", "agents", "revocations", "telemetry", "rescue", "approvals", "tokens"];
pub(crate) const ADMIN: &str = "http://127.0.0.1:4985";
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

// ------------------------------------------------------------------ the stores through Sync Gateway (F3)

const PORTS: [u16; 3] = [18995, 18996, 18997];

/// A Sync Gateway user for a node: logged in as the node's id, reading the channels given (per collection).
pub(crate) fn put_user(name: &str, password: &str, channels: &[String]) -> Result<(), String> {
    put_user_roles(name, password, channels, &[])
}

/// A role (a name a sync function can require); made if it does not exist.
pub(crate) fn put_role(name: &str) -> Result<(), String> {
    let (s, b) = http("PUT", &format!("{ADMIN}/{DB}/_role/{name}"), Some(&json!({ "name": name })), None)?;
    if s >= 300 {
        return Err(format!("creating role {name}: {s} {b}"));
    }
    Ok(())
}

/// [`put_user`], with roles (`head-office` may write the authority's documents).
pub(crate) fn put_user_roles(name: &str, password: &str, channels: &[String], roles: &[&str]) -> Result<(), String> {
    let access: serde_json::Map<String, Value> = COLLECTIONS.iter().map(|c| (c.to_string(), json!({ "admin_channels": channels }))).collect();
    let user = json!({ "name": name, "password": password, "collection_access": { SCOPE: access }, "admin_roles": roles });
    let (s, b) = http("PUT", &format!("{ADMIN}/{DB}/_user/{name}"), Some(&user), None)?;
    if s >= 300 {
        return Err(format!("creating user {name}: {s} {b}"));
    }
    Ok(())
}

pub(crate) fn logs_at(port: u16) -> Vec<Value> {
    get_json(&format!("http://127.0.0.1:{port}/telemetry"))["logs"].as_array().cloned().unwrap_or_default()
}

/// The minute of the last reading `port` holds for the log `id`, -1 when it holds none.
fn minute_of(port: u16, id: &str) -> i64 {
    logs_at(port).iter().find(|l| l["id"] == id).and_then(|l| l["readings"].as_array().and_then(|r| r.last().cloned())).and_then(|r| r["minute"].as_i64()).unwrap_or(-1)
}

fn sim_advance(port: u16, minutes: u32) -> u16 {
    post_json(&format!("http://127.0.0.1:{port}/store/sim/advance"), &json!({ "minutes": minutes }).to_string()).0
}

fn node_link(port: u16, up: bool) -> u16 {
    post_json(&format!("http://127.0.0.1:{port}/link"), &json!({ "up": up }).to_string()).0
}

/// `cargo xtask e2e-fleet` (needs `fleet-up` first): two stores and a head office, each a node replicating with Sync Gateway only, as
/// itself. Each store's signed records arrive at the head office and in Couchbase Server; a store is given its own channel and no other, so it
/// holds nothing of the other's; a store whose link is cut keeps working and the head office catches up when it returns.
pub fn e2e() -> Result<i32, String> {
    require_bins(&["anp-node"])?;
    let alive = http("GET", &format!("{ADMIN}/{DB}/"), None, None).map(|(s, b)| s == 200 && b["state"] == "Online").unwrap_or(false);
    if !alive {
        return Err("the fleet is not up (no database anp at 127.0.0.1:4985): run `cargo xtask fleet-up` first".into());
    }
    let work = work_dir("xtask-fleet");
    fresh_dir(&work);
    let mut c = Checks::default();
    // node ids unique to this run: the documents stay in Server, and an id used before would meet its own old revisions
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) % 1_000_000;
    let (a, b, hq) = (format!("e2e{stamp}a"), format!("e2e{stamp}b"), format!("e2e{stamp}hq"));

    println!("Sync Gateway users: a channel per store");
    for (n, var) in [(&a, "ANP_FLEET_PW_A"), (&b, "ANP_FLEET_PW_B"), (&hq, "ANP_FLEET_PW_HQ")] {
        std::env::set_var(var, format!("pw-{n}"));
    }
    put_user(&a, &format!("pw-{a}"), &[format!("store.{a}")])?;
    put_user(&b, &format!("pw-{b}"), &[format!("store.{b}")])?;
    put_user(&hq, &format!("pw-{hq}"), &["*".to_string()])?;
    c.check("a user per node: each store on its own channel, the head office on all", true, "");

    println!("Two stores and a head office, each replicating with Sync Gateway only");
    let gateway = |var: &str| strs(&["--sync-gateway", &format!("ws://127.0.0.1:4984/{DB}"), "--sync-password-env", var]);
    let (did_a, did_b) = (did_for(&work, &a, &format!("{a}.test"), &a), did_for(&work, &b, &format!("{b}.test"), &b));
    let mut sa = Node::start(&work, &a, &a, PORTS[0], &[strs(&["--did-host", &format!("{a}.test"), "--store-sim", "0"]), gateway("ANP_FLEET_PW_A")].concat());
    let mut sb = Node::start(&work, &b, &b, PORTS[1], &[strs(&["--did-host", &format!("{b}.test"), "--store-sim", "0"]), gateway("ANP_FLEET_PW_B")].concat());
    let mut ho = Node::start(&work, &hq, &hq, PORTS[2], &[strs(&["--did-host", &format!("{hq}.test"), "--trust-did", &did_a, "--trust-did", &did_b]), gateway("ANP_FLEET_PW_HQ")].concat());

    let units = ["frz-1", "frz-2", "chl-1", "chl-2"];
    let all_at_hq = || units.iter().all(|u| minute_of(PORTS[2], &format!("{a}::{u}")) == 0 && minute_of(PORTS[2], &format!("{b}::{u}")) == 0);
    c.check("the head office receives both stores' temperature logs: 4 units each, through Sync Gateway", poll(90, 500, all_at_hq), format!("{} logs", logs_at(PORTS[2]).len()));
    let l = logs_at(PORTS[2]).into_iter().find(|l| l["id"] == json!(format!("{a}::frz-2"))).unwrap_or(Value::Null);
    c.check("...signed by each store's DID, and verified on arrival", l["signedBy"]["author"] == json!(a) && l["signedBy"]["did"] == json!(did_a), l["signedBy"].to_string());
    let in_server = poll(30, 1000, || {
        query(&format!("SELECT RAW COUNT(*) FROM `{BUCKET}`.`{SCOPE}`.`telemetry` WHERE META().id LIKE 'e2e{stamp}%'")).map(|v| v == ["8"]).unwrap_or(false)
    });
    c.check("all eight are documents in Couchbase Server too (fleet.a2a.telemetry)", in_server, "");

    println!("A store sees its own channel and no other");
    sleep(3);
    c.check("store A holds its own 4 logs and nothing of store B's", logs_at(PORTS[0]).len() == 4 && logs_at(PORTS[0]).iter().all(|l| l["signedBy"]["author"] == json!(a)), format!("{:?}", logs_at(PORTS[0]).iter().map(|l| l["id"].clone()).collect::<Vec<_>>()));
    c.check("store B holds its own 4 logs and nothing of store A's", logs_at(PORTS[1]).len() == 4 && logs_at(PORTS[1]).iter().all(|l| l["signedBy"]["author"] == json!(b)), format!("{:?}", logs_at(PORTS[1]).iter().map(|l| l["id"].clone()).collect::<Vec<_>>()));
    let ks = format!("{DB}.{SCOPE}.telemetry");
    let pw_b = format!("pw-{b}");
    let forged = json!({ "trust": { "author": a, "seq": 1, "sig": "x" }, "node": a, "unit": "frz-1", "readings": [] });
    let (st, body) = http("PUT", &format!("{PUBLIC}/{ks}/{a}::forged"), Some(&forged), Some((&b, &pw_b)))?;
    c.check("Sync Gateway refuses store B writing a record as store A", st == 403, format!("{st} {body}"));
    let (st, body) = http("GET", &format!("{PUBLIC}/{ks}/{a}::frz-1"), None, Some((&b, &pw_b)))?;
    c.check("...and store B reading store A's record", st == 403 || st == 404, format!("{st} {body}"));

    println!("Store A loses its link, keeps working, and the head office catches up");
    c.check("store A's link is cut", node_link(PORTS[0], false) == 200, "");
    sleep(2);
    c.check("store A's cold room advances 60 minutes on its own", sim_advance(PORTS[0], 60) == 200, "");
    c.check("store B's advances 10, linked", sim_advance(PORTS[1], 10) == 200, "");
    c.check("the head office sees store B's new readings", poll(60, 500, || minute_of(PORTS[2], &format!("{b}::frz-1")) == 10), minute_of(PORTS[2], &format!("{b}::frz-1")).to_string());
    c.check("...and nothing newer from store A, cut off", minute_of(PORTS[2], &format!("{a}::frz-1")) == 0, minute_of(PORTS[2], &format!("{a}::frz-1")).to_string());
    c.check("store A's link comes back", node_link(PORTS[0], true) == 200, "");
    c.check("the head office catches up with everything store A logged meanwhile", poll(90, 500, || minute_of(PORTS[2], &format!("{a}::frz-1")) == 60), minute_of(PORTS[2], &format!("{a}::frz-1")).to_string());
    c.check("...a reading every five minutes, none missing", logs_at(PORTS[2]).iter().find(|l| l["id"] == json!(format!("{a}::frz-1"))).map_or(0, |l| l["readings"].as_array().map_or(0, |r| r.len())) == 13, "");
    c.check("store B still holds only its own", logs_at(PORTS[1]).iter().all(|l| l["signedBy"]["author"] == json!(b)), "");
    // only this run's stores: the head office reads every channel, and refuses a document by any store it was not told to trust
    let ours = |r: &Value| [&a, &b].iter().any(|n| r["author"] == json!(n) || r["docId"].as_str().map_or(false, |d| d.starts_with(&format!("{n}::"))));
    let refused: Vec<Value> = PORTS.iter().flat_map(|p| crate::harness::rejections(*p)).filter(|r| ours(r)).collect();
    c.check("no document of either store was refused at any node", refused.is_empty(), format!("{refused:?}"));

    sa.kill();
    sb.kill();
    ho.kill();
    for n in [&a, &b, &hq] {
        let _ = http("DELETE", &format!("{ADMIN}/{DB}/_user/{n}"), None, None);
    }
    Ok(c.finish())
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
    let rev = body["rev"].as_str().unwrap_or_default().to_string();
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
    // leave nothing behind: a head office reading every channel would refuse a document by a store it does not know
    let _ = http("DELETE", &format!("{ADMIN}/{ks}/{own_id}?rev={rev}"), None, None);
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
pub(crate) fn query(statement: &str) -> Result<Vec<String>, String> {
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
pub(crate) fn http(method: &str, url: &str, body: Option<&Value>, auth: Option<(&str, &str)>) -> Result<(u16, Value), String> {
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
