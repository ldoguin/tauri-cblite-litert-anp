//! `cargo xtask e2e-did`: DID mode (ANP `did:wba` identities) on real nodes: TLS and admission by a DID assertion, the DID document and the signed
//! agent description (ANP-07) a node serves, discovery (ANP-08), and three attackers. The same checks as `scripts/e2e-did.ps1`.

use crate::harness::*;
use serde_json::{json, Value};

fn mesh(name: &str) -> Vec<String> {
    strs(&["--did-host", &format!("{name}.example.com"), "--tls", "--admit"])
}

fn joined(a: Vec<String>, b: &[&str]) -> Vec<String> {
    [a, strs(b)].concat()
}

/// `did:wba:alice.example.com:agents:alice:e1_<43 characters>`
fn did_form(did: &str, host: &str, name: &str) -> bool {
    let prefix = format!("did:wba:{host}:agents:{name}:e1_");
    did.strip_prefix(&prefix).map_or(false, |rest| rest.len() == 43 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

fn names_in(listing: &Value) -> Vec<String> {
    listing["items"].as_array().into_iter().flatten().filter_map(|i| i["name"].as_str().map(str::to_string)).collect()
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-ad"])?;
    let work = work_dir("xtask-did");
    fresh_dir(&work);
    let mut c = Checks::default();

    println!("Setup: each node creates its key and shows the DID it names");
    let alice_did = did_for(&work, "alice", "alice.example.com", "alice");
    let bob_did = did_for(&work, "bob", "bob.example.com", "bob");
    let _mal_did = did_for(&work, "mallory", "evil.example.com", "mallory");
    let carol_did = did_for(&work, "carol", "alice.example.com", "carol"); // a second agent on alice's domain
    let fake_bob_did = did_for(&work, "bob", "bob.example.com", "fakebob"); // the same name and host as bob, another key
    c.check("DIDs have the did:wba path form with an e1_ fingerprint", did_form(&alice_did, "alice.example.com", "alice"), &alice_did);
    c.check("the same name and host with another key is a different DID", fake_bob_did != bob_did, "");
    c.check("the DID is stable across restarts (it comes from the key)", did_for(&work, "alice", "alice.example.com", "alice") == alice_did, "");

    let alice = Node::start(&work, "alice", "alice", 18701, &joined(mesh("alice"), &["--trust-did", &bob_did, "--trust-did", &carol_did]));
    let port = alice.p2p_port().ok_or("alice printed no P2P port")?;
    let url = format!("wss://127.0.0.1:{port}/a2a");
    let pin = work.join("alice").join("tls.cert.pem").display().to_string();
    let sec = get_json("http://127.0.0.1:18701/security");
    c.check("alice reports DID mode and her DID", sec["mode"] == "did" && sec["did"] == json!(alice_did), sec.to_string());

    let e1 = alice_did.rsplit(':').next().unwrap_or_default().to_string();
    let doc_resp = http_get(&format!("http://127.0.0.1:18701/agents/alice/{e1}/did.json"));
    let doc = doc_resp.json();
    c.check(
        "alice serves her DID document at the URL did:wba resolution derives",
        doc["id"] == json!(alice_did) && doc["proof"]["cryptosuite"] == "eddsa-jcs-2022" && doc["verificationMethod"][0]["type"] == "Multikey",
        doc.to_string(),
    );
    let wrong = http_get("http://127.0.0.1:18701/agents/alice/e1_wrong/did.json");
    c.check("a wrong fingerprint is a 404", wrong.status == 404, wrong.status.to_string());

    // ANP-07: the DID document points at an agent description, signed by the same key
    let svc = doc["service"].as_array().into_iter().flatten().find(|s| s["type"] == "AgentDescription").cloned();
    c.check("alice's DID document advertises her agent description", svc.as_ref().map_or(false, |s| s["serviceEndpoint"] == "https://alice.example.com/agents/alice/ad.json"), doc.to_string());
    let (did_file, ad_file, tampered_file) = (work.join("alice.did.json"), work.join("alice.ad.json"), work.join("tampered.ad.json"));
    std::fs::write(&did_file, &doc_resp.body).map_err(|e| e.to_string())?;
    let ad_resp = http_get("http://127.0.0.1:18701/agents/alice/ad.json");
    std::fs::write(&ad_file, &ad_resp.body).map_err(|e| e.to_string())?;
    let ad = ad_resp.json();
    c.check(
        "alice serves an ANP-07 agent description (protocolType ANP, her DID, an A2A interface)",
        ad["protocolType"] == "ANP" && ad["type"] == "AgentDescription" && ad["did"] == json!(alice_did) && ad["interfaces"][0]["protocol"] == "A2A",
        &ad_resp.body,
    );
    let (d, a) = (did_file.display().to_string(), ad_file.display().to_string());
    let (code, out) = run_tool("anp-ad", &strs(&["verify", "--ad", &a, "--did-doc", &d, "--domain", "alice.example.com"]));
    c.check("anp-ad verifies it against her DID document, bound to her domain", code == 0, &out);
    let (code, out) = run_tool("anp-ad", &strs(&["verify", "--ad", &a, "--did-doc", &d, "--domain", "evil.example.com"]));
    c.check("...and refuses it when fetched from another domain", code != 0 && out.contains("fetched from"), &out);
    let tampered = ad_resp.body.replace("\"name\":\"alice\"", "\"name\":\"alice-the-fake\"");
    std::fs::write(&tampered_file, &tampered).map_err(|e| e.to_string())?;
    let (code, out) = run_tool("anp-ad", &strs(&["verify", "--ad", &tampered_file.display().to_string(), "--did-doc", &d]));
    c.check("...and refuses a tampered description", code != 0 && tampered != ad_resp.body, &out);
    let other = http_get("http://127.0.0.1:18701/agents/bob/ad.json");
    c.check("a node only describes itself (404 for another name)", other.status == 404, other.status.to_string());

    let connect = ["--trust-did", &alice_did, "--trust-did", &carol_did, "--pin-cert", &pin, "--connect", &url];
    let bob = Node::start(&work, "bob", "bob", 18702, &joined(mesh("bob"), &connect));
    c.check("bob (a pinned DID, TLS) joins and sees alice", wait_sees(18702, "alice", 15), "");
    c.check("alice sees bob", wait_sees(18701, "bob", 15), "");
    let r = rpc(18701, "SendMessage", json!({ "tenant": "bob", "message": msg("hello over a DID-authenticated link") }));
    c.check("a task alice -> bob completes", completed(&r), r.to_string());
    c.check("nothing was refused during normal operation", rejections(18701).is_empty(), "");

    println!("ANP-08 discovery");
    let carol = Node::start(&work, "carol", "carol", 18706, &joined(mesh("alice"), &["--trust-did", &alice_did, "--trust-did", &bob_did, "--pin-cert", &pin, "--connect", &url]));
    c.check("carol (another agent on alice's domain) joins", wait_sees(18706, "alice", 15), "");
    let mut wk = http_get("http://127.0.0.1:18701/.well-known/agent-descriptions");
    let mut names = names_in(&wk.json());
    for _ in 0..40 {
        if names.iter().any(|n| n == "carol") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        wk = http_get("http://127.0.0.1:18701/.well-known/agent-descriptions");
        names = names_in(&wk.json());
    }
    let list = wk.json();
    c.check("/.well-known/agent-descriptions is a JSON-LD CollectionPage served as application/ld+json", list["@type"] == "CollectionPage" && wk.content_type.starts_with("application/ld+json"), &wk.content_type);
    c.check("it lists the agents under alice's domain: alice and carol, not bob", names.join(",") == "alice,carol", names.join(","));
    let described = list["items"].as_array().into_iter().flatten().filter(|i| i["@type"] == "ad:AgentDescription" && i["@id"].as_str().map_or(false, |s| s.starts_with("https://alice.example.com/agents/") && s.ends_with("/ad.json"))).count();
    c.check("each item is an ad:AgentDescription with the URL of its description", described == 2, &wk.body);
    let p2 = http_get("http://127.0.0.1:18701/.well-known/agent-descriptions?page=2").json();
    c.check("a page past the end is empty and has no next", p2["items"].as_array().map_or(true, |a| a.is_empty()) && p2["next"].is_null(), p2.to_string());
    let disc_resp = http_get("http://127.0.0.1:18701/discover");
    let disc = disc_resp.json();
    let all = disc.as_array().cloned().unwrap_or_default();
    c.check("/discover on alice knows alice, bob and carol, every description verified", all.len() == 3 && all.iter().all(|d| d["descriptionVerified"] == true), &disc_resp.body);
    let bob_entry = all.iter().find(|d| d["nodeId"] == "bob").cloned().unwrap_or(Value::Null);
    c.check(
        "bob's description verified on alice with no contact with bob's domain (it replicated with his card)",
        bob_entry["descriptionVerified"] == true && bob_entry["descriptionUrl"] == "https://bob.example.com/agents/bob/ad.json" && bob_entry["did"] == json!(bob_did),
        bob_entry.to_string(),
    );
    // carol's card has to cross alice to reach bob: wait for it rather than race it
    let carol_on_bob = || http_get("http://127.0.0.1:18702/discover").json().as_array().map_or(false, |a| a.iter().any(|d| d["nodeId"] == "carol" && d["descriptionVerified"] == true));
    for _ in 0..60 {
        if carol_on_bob() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    c.check("bob discovers carol too, through the mesh", carol_on_bob(), http_get("http://127.0.0.1:18702/discover").body);
    let wk_bob = http_get("http://127.0.0.1:18702/.well-known/agent-descriptions").json();
    c.check("bob's own domain listing holds only bob", names_in(&wk_bob).join(",") == "bob", wk_bob.to_string());
    let rj = rejections(18701);
    c.check("nothing was refused during discovery", rj.is_empty(), Value::Array(rj).to_string());

    println!("Attackers");
    // 1. a stranger with a perfectly valid DID of their own
    let mut mal = Node::start(&work, "mallory", "mallory", 18703, &joined(mesh("evil"), &["--trust-did", &alice_did, "--pin-cert", &pin, "--connect", &url]));
    sleep(8);
    c.check("mallory (valid DID, nobody pinned it) never sees alice", !agents(18703).iter().any(|n| n == "alice"), "");
    c.check("alice logged the refused connection: not a trusted identity", refused(18701, "connection", "mallory", "not a trusted identity"), Value::Array(rejections(18701)).to_string());
    c.check("no mallory document ever reached alice", !agents(18701).iter().any(|n| n == "mallory"), "");
    mal.kill();

    // 2. an impersonator: the same name and domain as bob, but not bob's key
    let mut fake = Node::start(&work, "bob", "fakebob", 18704, &joined(mesh("bob"), &["--trust-did", &alice_did, "--pin-cert", &pin, "--connect", &url]));
    sleep(8);
    c.check("an impersonator named bob on bob's domain, with another key, is refused", !agents(18704).iter().any(|n| n == "alice"), "");
    c.check("alice logged it", refused(18701, "connection", "bob", "not a trusted identity"), Value::Array(rejections(18701)).to_string());
    fake.kill();
    let r = rpc(18701, "SendMessage", json!({ "tenant": "bob", "message": msg("the real bob is unaffected") }));
    c.check("the real bob still works afterwards", completed(&r), r.to_string());

    // 3. no credentials at all
    let mut anon = Node::start(&work, "anon", "anon", 18705, &strs(&["--tls", "--pin-cert", &pin, "--connect", &url]));
    sleep(6);
    c.check("a node with TLS but no DID is refused", !agents(18705).iter().any(|n| n == "alice"), "");
    anon.kill();

    drop((alice, bob, carol));
    Ok(c.finish())
}
