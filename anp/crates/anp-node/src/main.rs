//! Headless A2A node: A2A HTTP server + Couchbase Lite P2P listener/replicators.
//!
//! ```text
//! anp-node --name alice --data ./alice --http-port 8081
//! anp-node --name bob   --data ./bob   --http-port 8082 --connect ws://127.0.0.1:<alice p2p port>/a2a
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anp_cblite::{
    default_card,
    docs::Docs,
    executor::{EchoExecutor, Executor},
    hub::{Hub, LinkControl},
    p2p::{P2p, P2pSecurity},
    server,
    trust::Trust,
};
use couchbase_lite::{Database, DatabaseConfiguration};

struct Args {
    name: String,
    id: String,
    data: PathBuf,
    http_port: u16,
    p2p_port: u16,
    connect: Vec<String>,
    /// `.litertlm` model: makes this a real LLM agent (needs `--features litert`).
    model: Option<String>,
    role: String,
    persona: String,
    max_tokens: Option<i32>,
    /// Run the model on the GPU backend (some .litertlm files only load there).
    gpu: bool,
    /// Build ChatML prompts ourselves instead of using LiteRT-LM's chat-template layer.
    chatml: bool,
    /// Sign every document and only act on documents from enrolled peers.
    secure: bool,
    /// JSON file `{"nodes": {"alice": "<base64 public key>"}}` of trusted peers.
    trust_file: Option<PathBuf>,
    /// `name=<base64 public key>`, repeatable.
    trust_peers: Vec<String>,
    /// Create this node's key if needed, print `<id> <public key>` and exit.
    print_pubkey: bool,
    /// Biscuit mode: the mesh authority's public key (base64). Peers are trusted through
    /// tokens it issued (see `anp-admin`) instead of a list of keys.
    root_key: Option<String>,
    /// This node's token file (required with `--root-key`).
    token_file: Option<PathBuf>,
    /// Revoked token ids, one hex id per line.
    revoked_file: Option<PathBuf>,
    /// Built-in agent when no model is given: echo, reviewer (checks inspection reports) or claims (files them).
    agent: String,
    /// Serve P2P over TLS (wss://) and allow dialing wss:// peers.
    tls: bool,
    /// A peer's certificate (PEM) to pin when dialing.
    pin_cert: Option<PathBuf>,
    /// Biscuit mode: only nodes with a valid token may connect.
    admit: bool,
    /// Name of an environment variable holding the database encryption password.
    db_key_env: Option<String>,
    /// DID mode (ANP): this node's `did:wba` host, `host` or `host:port`.
    did_host: Option<String>,
    /// WNS handles this node provides: `<local>.<did host>` (needs `--did-host`, a host with at least two labels, no port in the handle).
    handles: Vec<String>,
    /// ANP-06: `NAME` (the built-in a2a-json-rpc) or `NAME=FILE` (the protocol text is the file); each one is a protocol this node can agree to.
    meta_protocols: Vec<String>,
    /// ANP P6: be a group host (needs `--did-host`; group DIDs are made on that domain).
    p6_host: bool,
    /// Run the P6 host without `--require-auth`: anyone who can reach it can collect any device's notifications.
    p6_open_mailboxes: bool,
    /// DIDs this node trusts (DID mode), repeatable.
    trust_dids: Vec<String>,
    /// Create this node's key, print `<id> <did>` and exit (needs `--did-host`).
    print_did: bool,
    /// End-to-end encryption of task payloads (needs `--did-host`).
    e2ee: bool,
    /// ANP-02: require HTTP Message Signatures from accepted callers on the API.
    require_auth: bool,
    /// Also accept the older `Authorization: DIDWba` header and issue Bearer tokens (needs --require-auth).
    allow_legacy_auth: bool,
    /// How callers address this node (default: `https://<did host>`).
    public_origin: Option<String>,
    /// DID documents of the callers to accept, repeatable.
    allow_callers: Vec<PathBuf>,
    /// ANP-09 P5 messaging for peers on other ANP stacks (needs `--e2ee`).
    p5: bool,
    /// `DID=URL`: where to send a peer's replies, repeatable.
    p5_peers: Vec<String>,
    /// Trust the DIDs of these domains (`host` or `host:port`): their documents are fetched over HTTPS, repeatable.
    trust_domains: Vec<String>,
    /// PEM file of extra root certificates (a private CA) for fetching those documents.
    resolver_roots: Option<PathBuf>,
    /// Allow those documents to live on private or loopback addresses (closed networks, tests).
    resolver_allow_private: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        name: "node".into(),
        id: String::new(),
        data: PathBuf::from("./a2a-data"),
        http_port: 8080,
        p2p_port: 0,
        connect: vec![],
        model: None,
        role: "assistant".into(),
        persona: "You are a concise, helpful assistant.".into(),
        max_tokens: None,
        gpu: false,
        chatml: false,
        secure: false,
        trust_file: None,
        trust_peers: vec![],
        print_pubkey: false,
        root_key: None,
        token_file: None,
        revoked_file: None,
        agent: "echo".into(),
        tls: false,
        pin_cert: None,
        admit: false,
        db_key_env: None,
        did_host: None,
        handles: vec![],
        meta_protocols: vec![],
        p6_host: false,
        p6_open_mailboxes: false,
        trust_dids: vec![],
        print_did: false,
        e2ee: false,
        require_auth: false,
        allow_legacy_auth: false,
        public_origin: None,
        allow_callers: vec![],
        p5: false,
        p5_peers: vec![],
        trust_domains: vec![],
        resolver_roots: None,
        resolver_allow_private: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().ok_or(format!("{k} needs a value"));
        match k.as_str() {
            "--name" => a.name = v()?,
            "--id" => a.id = v()?,
            "--data" => a.data = PathBuf::from(v()?),
            "--http-port" => a.http_port = v()?.parse().map_err(|e| format!("--http-port: {e}"))?,
            "--p2p-port" => a.p2p_port = v()?.parse().map_err(|e| format!("--p2p-port: {e}"))?,
            "--connect" => a.connect.push(v()?),
            "--model" => a.model = Some(v()?),
            "--role" => a.role = v()?,
            "--persona" => a.persona = v()?,
            "--template" => {
                a.chatml = match v()?.as_str() {
                    "chatml" => true,
                    "auto" => false,
                    other => return Err(format!("--template must be auto or chatml, got {other}")),
                }
            }
            "--backend" => {
                a.gpu = match v()?.as_str() {
                    "gpu" => true,
                    "cpu" => false,
                    other => return Err(format!("--backend must be cpu or gpu, got {other}")),
                }
            }
            "--max-tokens" => a.max_tokens = Some(v()?.parse().map_err(|e| format!("--max-tokens: {e}"))?),
            "--secure" => a.secure = true,
            "--trust" => {
                a.trust_file = Some(PathBuf::from(v()?));
                a.secure = true;
            }
            "--trust-peer" => {
                a.trust_peers.push(v()?);
                a.secure = true;
            }
            "--print-pubkey" => a.print_pubkey = true,
            "--root-key" => {
                a.root_key = Some(v()?);
                a.secure = true;
            }
            "--token" => a.token_file = Some(PathBuf::from(v()?)),
            "--revoked" => a.revoked_file = Some(PathBuf::from(v()?)),
            "--agent" => a.agent = v()?,
            "--tls" => a.tls = true,
            "--pin-cert" => a.pin_cert = Some(PathBuf::from(v()?)),
            "--admit" => a.admit = true,
            "--db-key-env" => a.db_key_env = Some(v()?),
            "--handle" => a.handles.push(v()?),
        "--meta-protocol" => a.meta_protocols.push(v()?),
        "--p6-host" => a.p6_host = true,
        "--p6-open-mailboxes" => a.p6_open_mailboxes = true,
        "--did-host" => {
                a.did_host = Some(v()?);
                a.secure = true;
            }
            "--trust-did" => a.trust_dids.push(v()?),
            "--print-did" => a.print_did = true,
            "--require-auth" => a.require_auth = true,
            "--allow-legacy-auth" => a.allow_legacy_auth = true,
            "--public-origin" => a.public_origin = Some(v()?),
            "--allow-caller" => a.allow_callers.push(PathBuf::from(v()?)),
            "--trust-domain" => a.trust_domains.push(v()?),
            "--resolver-roots" => a.resolver_roots = Some(PathBuf::from(v()?)),
            "--resolver-allow-private" => a.resolver_allow_private = true,
            "--p5" => a.p5 = true,
            "--p5-peer" => a.p5_peers.push(v()?),
            "--e2ee" => {
                a.e2ee = true;
                a.secure = true;
            }
            "-h" | "--help" => {
                return Err("usage: anp-node [--name N] [--id ID] [--data DIR] [--http-port P] [--p2p-port P] [--connect ws://host:port/a2a]...\n       LLM agent (build with --features litert, Linux/macOS): [--model FILE.litertlm] [--role R] [--persona TEXT] [--max-tokens N]\n       Security: [--secure] [--trust trust.json] [--trust-peer name=PUBKEY]... [--print-pubkey]\n       Biscuit:  [--root-key ROOT_PUBKEY --token FILE [--revoked FILE]]  (tokens come from anp-admin)\n       Built-in agent: [--agent echo|reviewer|claims|writer]\n       DID (ANP): [--did-host HOST[:PORT] [--trust-did DID]... [--print-did] [--e2ee] [--handle LOCAL]... [--meta-protocol NAME[=FILE]]... [--p6-host [--p6-open-mailboxes]]]\n       Domains: [--trust-domain HOST[:PORT]]... [--resolver-roots CA.pem] [--resolver-allow-private]  (DIDs of a trusted domain are fetched over HTTPS)\n       P5 (ANP-09): [--p5 [--p5-peer DID=URL]...]  (needs --e2ee; peers are the --allow-caller documents)\n       ANP-02: [--require-auth [--public-origin https://HOST[:PORT]] [--allow-caller DID_DOC.json]... [--allow-legacy-auth]]\n       Transport/at rest: [--tls] [--pin-cert PEM] [--admit] [--db-key-env VAR]".into())
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.id.is_empty() {
        a.id = a.name.to_lowercase().replace(' ', "-");
    }
    Ok(a)
}

/// A database handle moved onto the thread that owns the P2P state.
struct SendDb(Database);
// SAFETY: the handle is moved, not shared, and used on exactly one thread afterwards. `CBLDatabase` is
// internally synchronised and reference counted; `Database::clone` just retains it (see `anp_cblite::docs`).
unsafe impl Send for SendDb {}

enum LinkMsg {
    Set(bool, std::sync::mpsc::Sender<Result<(), String>>),
}

/// The HTTP side's handle on the P2P thread: cut or restore this node's outgoing connections.
struct NodeLink {
    tx: Mutex<std::sync::mpsc::Sender<LinkMsg>>,
    up: AtomicBool,
}

impl LinkControl for NodeLink {
    fn set(&self, up: bool) -> Result<(), String> {
        let (r_tx, r_rx) = std::sync::mpsc::channel();
        self.tx.lock().unwrap().send(LinkMsg::Set(up, r_tx)).map_err(|_| "the P2P thread stopped".to_string())?;
        let r = r_rx.recv_timeout(Duration::from_secs(20)).map_err(|_| "the P2P thread did not answer".to_string())?;
        if r.is_ok() {
            self.up.store(up, Ordering::SeqCst);
        }
        r
    }

    fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }
}

/// Start the P2P listener and dial `connect`, on a thread of its own that lives as long as the process
/// (the handles are not `Send`, so nothing else may touch them). Returns the link handle, the port and URLs.
fn spawn_p2p(db: Database, sec: P2pSecurity, port: u16, connect: Vec<String>) -> Result<(Arc<NodeLink>, u16, Vec<String>), String> {
    let db = SendDb(db);
    let (tx, rx) = std::sync::mpsc::channel::<LinkMsg>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(u16, Vec<String>), String>>();
    std::thread::Builder::new()
        .name("a2a-p2p".into())
        .spawn(move || {
            let db = db; // capture the whole wrapper, not just its (non-Send) field
            let mut p2p = P2p::new(db.0).with_security(sec);
            let started = p2p.listen(port).and_then(|(p, urls)| {
                for url in &connect {
                    p2p.connect(url)?;
                }
                Ok((p, urls))
            });
            let _ = ready_tx.send(started);
            while let Ok(LinkMsg::Set(up, reply)) = rx.recv() {
                let r = if up {
                    p2p.reconnect()
                } else {
                    p2p.disconnect();
                    Ok(())
                };
                let _ = reply.send(r);
            }
        })
        .map_err(|e| e.to_string())?;
    let (p, urls) = ready_rx.recv().map_err(|e| e.to_string())??;
    Ok((Arc::new(NodeLink { tx: Mutex::new(tx), up: AtomicBool::new(true) }), p, urls))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // A2A_CBL_LOG=debug|verbose turns on LiteCore's own console log (all domains).
    if let Ok(l) = std::env::var("A2A_CBL_LOG") {
        use couchbase_lite::logging::{set_console_log_sink, ConsoleLogSink, DomainMask, Level};
        let level = if l == "debug" { Level::Debug } else { Level::Verbose };
        set_console_log_sink(ConsoleLogSink { level, domains: DomainMask::ALL });
    }
    let args = parse_args().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    std::fs::create_dir_all(&args.data)?;

    // Secure mode: this node's signing key (created on first use) and the peers it trusts.
    let trust = if args.secure || args.print_pubkey || args.print_did {
        let t = Trust::load_or_create(&args.data, &args.id)?;
        // Printing a key or DID happens before a token exists (the token names them), so it never loads one.
        let printing = args.print_pubkey || args.print_did;
        // DID mode first: a DID-bound token is checked against the DID.
        let t = match args.did_host.as_deref() {
            Some(hp) => {
                let (host, port) = match hp.rsplit_once(':') {
                    Some((h, p)) => (h, Some(p.parse::<u16>().map_err(|e| format!("--did-host port: {e}"))?)),
                    None => (hp, None),
                };
                let mut extra = vec![];
                if args.p5 {
                    let origin = format!("https://{host}{}", port.map(|p| format!(":{p}")).unwrap_or_default());
                    extra.push(serde_json::json!({ "id": "#message", "type": "ANPMessageService", "serviceEndpoint": format!("{origin}/anp/p5") }));
                }
                // WNS handles this node provides: the DID document names the provider for each (the reverse half of the binding)
                for (i, local) in args.handles.iter().enumerate() {
                    let handle = anp_wns::validate_handle(&format!("{local}.{host}")).map_err(|e| format!("--handle {local}: {e}"))?;
                    if &handle.local != local {
                        return Err(format!("--handle {local}: use lowercase letters, digits and hyphens").into());
                    }
                    let frag = if i == 0 { "#handle".to_string() } else { format!("#handle-{}", i + 1) };
                    extra.push(serde_json::json!({ "id": frag, "type": anp_wns::HANDLE_SERVICE_TYPE, "serviceEndpoint": handle.resolution_url() }));
                }
                t.with_did_services(host, port, None, extra)?
            }
            None => t,
        };
        let t = match (&args.root_key, printing) {
            (Some(root), false) => {
                let f = args.token_file.as_ref().ok_or("--root-key needs this node's token: --token FILE (see anp-admin issue)")?;
                let token = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
                if args.trust_file.is_some() || !args.trust_peers.is_empty() || !args.trust_dids.is_empty() {
                    eprintln!("note: with --root-key peers are trusted through tokens; --trust / --trust-peer / --trust-did are ignored");
                }
                let t = t.with_biscuit(root, &token)?;
                if let Some(r) = &args.revoked_file {
                    t.load_revocations(r)?;
                }
                t
            }
            _ if args.did_host.is_some() => {
                for d in &args.trust_dids {
                    t.trust_did(d)?;
                }
                t
            }
            _ => {
                if let Some(f) = &args.trust_file {
                    t.load_trust_file(f)?;
                }
                for p in &args.trust_peers {
                    let (name, key) = p.split_once('=').ok_or_else(|| format!("--trust-peer wants name=PUBKEY, got {p}"))?;
                    t.enroll(name, key)?;
                }
                t
            }
        };        let t = if args.e2ee && !printing { t.with_e2ee(&args.data)? } else { t };
        Some(Arc::new(t))
    } else {
        None
    };
    if args.print_did {
        let did = trust.as_ref().and_then(|t| t.did()).ok_or("--print-did needs --did-host")?;
        println!("{} {}", args.id, did);
        return Ok(());
    }
    if args.print_pubkey {
        println!("{} {}", args.id, trust.as_ref().unwrap().public_key());
        return Ok(());
    }

    // Encrypt the database at rest with a key derived from a password held in an environment
    // variable (not on the command line, where it would show up in process listings).
    #[cfg(feature = "enterprise")]
    let encryption_key = match &args.db_key_env {
        Some(var) => {
            let pwd = std::env::var(var).map_err(|_| format!("--db-key-env: environment variable {var} is not set"))?;
            Some(
                couchbase_lite::EncryptionKey::new_from_password(couchbase_lite::EncryptionAlgorithm::AES256, &pwd)
                    .ok_or("could not derive a database encryption key")?,
            )
        }
        None => None,
    };
    #[cfg(not(feature = "enterprise"))]
    if args.db_key_env.is_some() {
        return Err("--db-key-env needs a Couchbase Lite Enterprise build".into());
    }
    let db = Database::open(
        "a2a",
        Some(DatabaseConfiguration {
            directory: &args.data,
            #[cfg(feature = "enterprise")]
            encryption_key,
        }),
    )?;

    let docs = match &trust {
        Some(t) => Docs::spawn_secure(db.clone(), t.clone())?,
        None => Docs::spawn(db.clone())?,
    };

    // Load the model before anything is advertised to peers.
    let (executor, description): (Arc<dyn Executor>, String) = match args.model.as_deref() {
        #[cfg(all(feature = "litert", not(windows)))]
        Some(path) => {
            let cache = args.data.join("litert-cache");
            let llm = anp_cblite::llm::LlmExecutor::load(
                path,
                args.role.clone(),
                args.persona.clone(),
                args.max_tokens,
                cache.to_str(),
                args.gpu,
                args.chatml,
            )?;
            let d = llm.description();
            (Arc::new(llm), d)
        }
        #[cfg(not(all(feature = "litert", not(windows))))]
        Some(_) => {
            return Err("--model needs a build with `--features litert` on Linux or macOS \
                        (Google ships no LiteRT-LM runtime for Windows)"
                .into())
        }
        None => match args.agent.as_str() {
            "echo" => (Arc::new(EchoExecutor), format!("A2A agent '{}' on Couchbase Lite (demo echo)", args.name)),
            "reviewer" => (Arc::new(anp_cblite::rules::ReviewExecutor), "Checks field inspection reports have an asset, findings, a risk level and an action".to_string()),
            "claims" => (Arc::new(anp_cblite::rules::ClaimsExecutor), "Files approved inspection reports and returns a claim number".to_string()),
        "writer" => (Arc::new(anp_cblite::rules::WriterExecutor), "Turns a rough field note into an inspection report (rule-based stand-in for an on-device model)".to_string()),
            other => return Err(format!("--agent must be echo, reviewer, claims or writer, got {other}").into()),
        },
    };

    let http = tokio::net::TcpListener::bind(("0.0.0.0", args.http_port)).await?;
    let base_url = format!("http://127.0.0.1:{}", http.local_addr()?.port());
    let card = default_card(&args.name, &description, &base_url);
    let hub: Arc<Hub> = Hub::start(docs, args.id.clone(), card, executor).await?;

    // Keep `p2p` alive for the life of the process (it stops on drop).
    let cert_path = args.data.join("tls.cert.pem");
    let sec = P2pSecurity {
        tls: args.tls,
        node_id: args.id.clone(),
        cert_out: args.tls.then(|| cert_path.clone()),
        identity_dir: args.tls.then(|| args.data.clone()),
        pinned_cert: args.pin_cert.as_ref().map(|f| std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))).transpose()?,
        trust: trust.clone(),
        admission: args.admit,
    };
    let (link, port, urls) = spawn_p2p(db, sec, args.p2p_port, args.connect.clone())?;
    hub.set_link_control(link);
    let mut peer_docs: Vec<serde_json::Value> = Vec::new();
    for f in &args.allow_callers {
        let text = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
        peer_docs.push(serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| format!("{}: {e}", f.display()))?); // Windows tools add a BOM
    }
    let domain_trust: Option<std::sync::Arc<anp_cblite::httpauth::DomainTrust>> = if args.trust_domains.is_empty() {
        None
    } else {
        let mut roots = Vec::new();
        if let Some(f) = &args.resolver_roots {
            let pem = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
            roots = anp_cblite::httpauth::pem_certificates(&pem)?;
        }
        Some(std::sync::Arc::new(anp_cblite::httpauth::DomainTrust::new(args.trust_domains.clone(), roots, args.resolver_allow_private)?))
    };
    hub.set_handles(args.handles.clone());
    if !args.meta_protocols.is_empty() {
        let mut protos = vec![];
        for spec in &args.meta_protocols {
            let (name, text) = match spec.split_once('=') {
                Some((n, f)) => (n.to_string(), std::fs::read_to_string(f).map_err(|e| format!("--meta-protocol {spec}: {e}"))?),
                None if spec == "a2a-json-rpc" => (spec.clone(), anp_cblite::meta::A2A_TEXT.to_string()),
                None => return Err(format!("--meta-protocol {spec}: give NAME=FILE (only a2a-json-rpc is built in)").into()),
            };
            protos.push(anp_meta::Protocol { name, text });
        }
        hub.set_meta(anp_cblite::meta::MetaService::new(protos));
    }
    if args.require_auth {
        let did = trust.as_ref().and_then(|t| t.did().map(str::to_string));
        let origin = match (&args.public_origin, &did) {
            (Some(o), _) => o.clone(),
            (None, Some(d)) => {
                let w = anp_did::WbaDid::parse(d)?;
                format!("https://{}{}", w.host, w.port.map(|p| format!(":{p}")).unwrap_or_default())
            }
            (None, None) => return Err("--require-auth needs --public-origin (or --did-host)".into()),
        };
        let mut auth = anp_cblite::httpauth::HttpAuth::new(&origin, peer_docs.clone())?;
        if let Some(d) = &domain_trust {
            auth = auth.with_domain_trust(d.clone());
        }
        if args.allow_legacy_auth {
            auth = auth.with_legacy();
        }
        hub.set_http_auth(auth);
    }
    if args.p6_host {
        let hostp = args.did_host.as_deref().ok_or("--p6-host needs --did-host")?;
        if !args.require_auth && !args.p6_open_mailboxes {
            return Err("--p6-host needs --require-auth (a mailbox is handed to whoever asks), or --p6-open-mailboxes if that is really what you want".into());
        }
        hub.set_p6(anp_cblite::p6::P6::new(hostp, &args.data, peer_docs.clone(), domain_trust.clone())?, args.require_auth);
    }
    if args.p5 {
        let t = trust.clone().ok_or("--p5 needs DID mode and --e2ee")?;
        let mut endpoints = std::collections::HashMap::new();
        for e in &args.p5_peers {
            let (did, url) = e.split_once('=').ok_or_else(|| format!("--p5-peer wants DID=URL, got {e}"))?;
            endpoints.insert(did.to_string(), url.to_string());
        }
        hub.set_p5(anp_cblite::p5::P5::new(t, &args.data, peer_docs.clone(), endpoints, domain_trust.clone())?);
    }
    hub.set_posture(serde_json::json!({
        "tls": args.tls,
        "pinned": args.pin_cert.is_some(),
        "admission": args.admit,
        "encryptedAtRest": args.db_key_env.is_some(),
        "e2ee": args.e2ee,
        "callerAuth": args.require_auth,
        "legacyAuth": args.require_auth && args.allow_legacy_auth,
        "p5": args.p5,
        "trustedDomains": args.trust_domains,
    }));

    println!("node      {} ({})", args.name, args.id);
    println!("A2A       {base_url}   card: {base_url}/.well-known/agent-card.json");
    match &trust {
        Some(t) if t.mode() == "biscuit" => println!("security  signed + verified; peers trusted through Biscuit tokens; public key {}", t.public_key()),
        Some(t) => println!("security  signed + verified; {} enrolled peer(s); public key {}", t.enrolled().len(), t.public_key()),
        None => println!("security  OFF (every replicated document is believed)"),
    }
    if args.tls {
        println!("transport TLS; certificate {}  ({})", cert_path.display(), if args.pin_cert.is_some() { "dialing with a pinned peer certificate" } else { "dialers accept any self-signed certificate" });
    }
    if args.admit {
        println!("admission only nodes with a valid, unrevoked token may connect");
    }
    if args.db_key_env.is_some() {
        println!("at rest   database encrypted (AES-256)");
    }
    println!("P2P port  {port}");
    for u in urls {
        println!("P2P url   {u}");
    }

    server::serve(hub, http).await?;
    Ok(())
}
