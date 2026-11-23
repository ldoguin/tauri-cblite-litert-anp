//! HTTP surface: agent card, mesh directory and the A2A 1.0 JSON-RPC endpoint.
//!
//! * `GET  /.well-known/agent-card.json`    this node's card
//! * `GET  /agents`                          every agent in the mesh (replicated cards)
//! * `GET  /agents/{node}/agent-card.json`   a peer's card, rewritten so that a
//!                                           standard client talks to *this*
//!                                           gateway with `tenant = {node}`
//! * `POST /`                                JSON-RPC 2.0

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::{wrappers::UnboundedReceiverStream, StreamExt};

use crate::hub::{diff_events, settled, Hub};
use crate::protocol::*;

const SEND_WAIT: Duration = Duration::from_secs(120);
const STREAM_MAX: Duration = Duration::from_secs(600);

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/.well-known/agent-card.json", get(own_card))
        .route("/agents", get(list_agents))
        .route("/security", get(security))
        .route("/link", get(link_status).post(link_set))
        .route("/demo", get(demo_page))
        .route("/demo/all", get(demo_all_page))
        .route("/security/revocations", post(post_revocation))
        .route("/agents/:node/agent-card.json", get(peer_card))
        .route("/agents/:name/:fingerprint/did.json", get(did_document))
        .route("/agents/:name/ad.json", get(agent_description))
        .route("/agents/:name/openrpc.json", get(openrpc_description))
        .route("/.well-known/agent-descriptions", get(well_known_descriptions))
        .route("/discover", get(discover))
        .route("/.well-known/handle/:local", get(handle_resolution))
        .route("/anp/p5", post(p5_rpc))
        .route("/anp/meta", post(meta_message))
        .route("/anp/meta/ws", get(meta_ws))
        .route("/anp/p6", post(p6_rpc))
        .route("/anp/p6/provision", post(p6_provision))
        .route("/anp/p6/ws", get(p6_ws))
        .route("/groups/:name/:fingerprint/did.json", get(p6_group_document))
        .route("/anp/meta/protocols", get(meta_protocols))
        .route("/", post(rpc))
        .layer(axum::middleware::from_fn_with_state(hub.clone(), crate::httpauth::middleware))
        .with_state(hub)
}

pub async fn serve(hub: Arc<Hub>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    axum::serve(listener, router(hub)).await
}

/// Trust status: whether documents are signed and verified, who is enrolled,
/// and every document this node refused (with how often).
async fn security(State(hub): State<Arc<Hub>>) -> Json<Value> {
    Json(match hub.docs.trust() {
        None => json!({ "secure": false, "posture": hub.posture() }),
        Some(t) => json!({
            "secure": true,
            "mode": t.mode(),
            "nodeId": t.node_id(),
            "did": t.did(),
            "e2ee": t.e2ee_enabled(),
            "httpAuth": hub.http_auth().map(|a| serde_json::json!({ "origin": a.origin, "callers": a.callers(), "trustedDomains": a.trusted_domains(), "refused": hub.http_refusals().len() })),
            "publicKey": t.public_key(),
            "enrolled": t.enrolled(),
            "revokedTokens": t.revoked_ids(),
            "posture": hub.posture(),
            "rejections": t.rejections(),
        }),
    })
}

/// This node's DID document, at the URL `did:wba` resolution derives from its DID (ANP-03):
/// `https://<host>[:<port>]/agents/<name>/<e1_fingerprint>/did.json`. Put TLS in front of it and an ANP peer can resolve us
/// the standard way; nodes on this mesh do not need to, because the document also travels with every signed document.
async fn did_document(State(hub): State<Arc<Hub>>, Path((name, fp)): Path<(String, String)>) -> Response {
    let Some(doc) = hub.docs.trust().and_then(|t| t.did_document()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let wanted = format!("/agents/{name}/{fp}/did.json");
    match doc["id"].as_str().and_then(|id| anp_did::WbaDid::parse(id).ok()) {
        Some(d) if d.document_path() == wanted => ([(axum::http::header::CONTENT_TYPE, "application/did+json")], doc.to_string()).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// This node's ANP-07 agent description (signed with its DID key), at the URL its DID document advertises as the
/// `AgentDescription` service: `https://<host>[:<port>]/agents/<name>/ad.json`.
async fn agent_description(State(hub): State<Arc<Hub>>, Path(name): Path<String>) -> Response {
    if name != hub.node_id {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(t) = hub.docs.trust() else { return StatusCode::NOT_FOUND.into_response() };
    let card = serde_json::to_value(hub.card()).unwrap_or(Value::Null);
    match t.agent_description(&card) {
        Ok(ad) => ([(axum::http::header::CONTENT_TYPE, "application/json")], ad.to_string()).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(), // not in DID mode
    }
}

/// ANP-04 WNS handle resolution: `GET /.well-known/handle/<local>` for the handles this node provides
/// (`--handle`), as `<local>.<did host>`. The binding is `did` <-> handle; the DID document carries the matching
/// `ANPHandleService` entry, so a client can check it both ways. Put TLS in front, as for the other documents.
async fn handle_resolution(State(hub): State<Arc<Hub>>, Path(local): Path<String>) -> Response {
    let local = local.to_ascii_lowercase();
    if !hub.handles().contains(&local) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(t) = hub.docs.trust() else { return StatusCode::NOT_FOUND.into_response() };
    let Some(did) = t.did().map(str::to_string) else { return StatusCode::NOT_FOUND.into_response() };
    let Some(authority) = anp_resolve::domain_of(&did) else { return StatusCode::NOT_FOUND.into_response() };
    let domain = authority.rsplit_once(':').map_or(authority.as_str(), |(h, _)| h).to_string();
    let Ok(handle) = anp_wns::validate_handle(&format!("{local}.{domain}")) else { return StatusCode::NOT_FOUND.into_response() };
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let card = serde_json::to_value(hub.card()).unwrap_or(Value::Null);
    let profile = anp_wns::profile(&did, &handle, "agent", card["name"].as_str().unwrap_or(&hub.node_id), card["description"].as_str(), &now);
    // the binding of a handle to this node's DID does not change (the DID is its key), so the generation stays 1
    let doc = anp_wns::resolution_document(&handle, &did, anp_wns::Status::Active, "1", &now, 300, Some(profile));
    ([(axum::http::header::CONTENT_TYPE, "application/json")], doc.to_string()).into_response()
}
/// ANP P6 group host (see `p6`): JSON-RPC from group devices.
async fn p6_rpc(State(hub): State<Arc<Hub>>, request: axum::http::Request<axum::body::Body>) -> Response {
    let Some((p6, require_caller)) = hub.p6() else { return StatusCode::NOT_FOUND.into_response() };
    let caller = request.extensions().get::<crate::httpauth::Caller>().map(|c| c.0.clone());
    let Ok(body) = axum::body::to_bytes(request.into_body(), 8 * 1024 * 1024).await else { return StatusCode::PAYLOAD_TOO_LARGE.into_response() };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Json(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": e.to_string() } })).into_response(),
    };
    Json(p6.handle(req, caller, require_caller).await).into_response()
}

/// Make a group DID on this node's domain: `{"name": "blue"}`. Needs a signed request when the node requires them.
async fn p6_provision(State(hub): State<Arc<Hub>>, request: axum::http::Request<axum::body::Body>) -> Response {
    let Some((p6, require_caller)) = hub.p6() else { return StatusCode::NOT_FOUND.into_response() };
    if require_caller && request.extensions().get::<crate::httpauth::Caller>().is_none() {
        return (StatusCode::UNAUTHORIZED, "sign the request\n").into_response();
    }
    let Ok(body) = axum::body::to_bytes(request.into_body(), 4096).await else { return StatusCode::PAYLOAD_TOO_LARGE.into_response() };
    let parsed = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
    let name = parsed["name"].as_str().map(str::to_string).unwrap_or_default();
    // an optional policy: `max_members` (at least 1)
    let max_members = parsed["max_members"].as_u64();
    match p6.provision(&name, max_members) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    }
}

/// The push channel of a device's mailbox: `GET /anp/p6/ws?did=DID&device=ID`, upgraded to a WebSocket. What waits for the device is sent
/// at once and what arrives later as it arrives, each as a text frame `{"id": ..., "notification": ...}` (the same objects `group.e2ee.pull`
/// returns); the device answers with `{"ack": [ids]}` and those are dropped. With `--require-auth` the signed upgrade request must be the
/// device's own DID, exactly as for a pull.
async fn p6_ws(State(hub): State<Arc<Hub>>, Query(q): Query<std::collections::HashMap<String, String>>, caller: Option<axum::Extension<crate::httpauth::Caller>>, ws: axum::extract::ws::WebSocketUpgrade) -> Response {
    use axum::extract::ws::Message;
    let Some((p6, require_caller)) = hub.p6() else { return StatusCode::NOT_FOUND.into_response() };
    let (Some(did), Some(device)) = (q.get("did").cloned(), q.get("device").cloned()) else { return (StatusCode::BAD_REQUEST, "did and device are required\n").into_response() };
    if require_caller && caller.as_ref().map(|c| c.0 .0.as_str()) != Some(did.as_str()) {
        return (StatusCode::UNAUTHORIZED, "a mailbox is read by the device's own DID (sign the request)\n").into_response();
    }
    ws.max_message_size(64 * 1024).on_upgrade(move |mut socket| async move {
        let mut sent: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            // register for the next delivery before reading the mailbox, so one that lands in between is not missed
            let wake = p6.delivery_wake();
            tokio::pin!(wake);
            wake.as_mut().enable();
            for (id, n) in p6.waiting(&did, &device) {
                if sent.insert(id.clone()) && socket.send(Message::Text(json!({ "id": id, "notification": n }).to_string())).await.is_err() {
                    return;
                }
            }
            tokio::select! {
                _ = &mut wake => {}
                // look again now and then even if nothing woke us
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                msg = socket.recv() => match msg {
                    Some(Ok(Message::Text(t))) => {
                        let ids: Vec<String> = serde_json::from_str::<Value>(&t).ok().and_then(|v| v["ack"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())).unwrap_or_default();
                        if !ids.is_empty() {
                            p6.acknowledge(&did, &device, &ids);
                            for i in &ids {
                                sent.remove(i);
                            }
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                },
            }
        }
    })
}

/// The DID document of a group this node provisioned.
async fn p6_group_document(State(hub): State<Arc<Hub>>, Path((name, fp)): Path<(String, String)>) -> Response {
    let Some((p6, _)) = hub.p6() else { return StatusCode::NOT_FOUND.into_response() };
    let _ = (&name, &fp);
    let wanted = format!("/groups/{name}/{fp}/did.json");
    // the DID of a group is `did:wba:<authority>:groups:<name>:<fp>`: look it up by the path it resolves to
    let authority = hub.docs.trust().and_then(|t| t.did().and_then(anp_resolve::domain_of)).unwrap_or_default();
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
        None => (authority.clone(), None),
    };
    let did = format!("did:wba:{}{}:groups:{name}:{fp}", host, port.map(|p| format!("%3A{p}")).unwrap_or_default());
    match p6.group_document(&did) {
        Some(doc) if anp_did::WbaDid::parse(&did).map(|d| d.document_path()).as_deref() == Ok(wanted.as_str()) => ([(axum::http::header::CONTENT_TYPE, "application/did+json")], doc.to_string()).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
/// ANP-06 meta-protocol over HTTP (see `meta`): one framed message in, the answering messages out.
async fn meta_message(State(hub): State<Arc<Hub>>, headers: axum::http::HeaderMap, body: Bytes) -> Response {
    let Some(meta) = hub.meta() else { return StatusCode::NOT_FOUND.into_response() };
    let Some(id) = headers.get("x-anp-session").and_then(|v| v.to_str().ok()).filter(|s| crate::meta::MetaService::valid_session_id(s)) else {
        return (StatusCode::BAD_REQUEST, "x-anp-session: 8 to 64 characters of A-Za-z0-9_-\n").into_response();
    };
    if body.len() > 64 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "a meta message is at most 64 KiB\n").into_response();
    }
    match meta.handle(id, &body) {
        Ok((out, state)) => {
            let mut h = axum::http::HeaderMap::new();
            h.insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/octet-stream"));
            if let Ok(v) = axum::http::HeaderValue::from_str(&state) {
                h.insert("x-anp-meta-state", v);
            }
            (StatusCode::OK, h, out).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    }
}

/// ANP-06 meta-protocol over a WebSocket (the SDK's own stream): every binary message is one framed meta message (the header byte, then
/// the payload); the answers come back as binary messages, one per frame. One connection is one session.
async fn meta_ws(State(hub): State<Arc<Hub>>, ws: axum::extract::ws::WebSocketUpgrade) -> Response {
    use axum::extract::ws::Message;
    let Some(meta) = hub.meta() else { return StatusCode::NOT_FOUND.into_response() };
    ws.max_message_size(64 * 1024).on_upgrade(move |mut socket| async move {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let id = format!("ws-{nanos:x}-{}", N.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        while let Some(Ok(msg)) = socket.recv().await {
            let bytes = match msg {
                Message::Binary(b) => b,
                Message::Close(_) => break,
                Message::Ping(p) => {
                    let _ = socket.send(Message::Pong(p)).await;
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Text(_) => {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            };
            match meta.handle(&id, &bytes) {
                Ok((out, _)) => {
                    // `out` is length-prefixed frames: one message each
                    let mut rest = &out[..];
                    while rest.len() >= 4 {
                        let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                        if rest.len() < 4 + n {
                            break;
                        }
                        if socket.send(Message::Binary(rest[4..4 + n].to_vec())).await.is_err() {
                            return;
                        }
                        rest = &rest[4 + n..];
                    }
                }
                Err(_) => {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    })
}

/// The protocols this node can speak after a negotiation.
async fn meta_protocols(State(hub): State<Arc<Hub>>) -> Response {
    let Some(meta) = hub.meta() else { return StatusCode::NOT_FOUND.into_response() };
    Json(meta.protocols().into_iter().map(|(name, text)| json!({ "name": name, "text": text })).collect::<Vec<_>>()).into_response()
}
/// The OpenRPC document the agent description points at: the node's JSON-RPC methods, for clients that learn them from it.
async fn openrpc_description(State(hub): State<Arc<Hub>>, Path(name): Path<String>) -> Response {
    if name != hub.node_id {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(t) = hub.docs.trust() else { return StatusCode::NOT_FOUND.into_response() };
    let card = serde_json::to_value(hub.card()).unwrap_or(Value::Null);
    let title = card["name"].as_str().unwrap_or("agent").to_string();
    let version = card["version"].as_str().unwrap_or("1.0").to_string();
    match t.openrpc_document(&title, &version) {
        Ok(doc) => ([(axum::http::header::CONTENT_TYPE, "application/json")], doc.to_string()).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// ANP-08 active discovery: the JSON-LD listing of the agent descriptions under this node's domain
/// (`https://<did host>/.well-known/agent-descriptions`, paged with `next`). Lists this node's own description and
/// those of mesh members that publish under the same domain, each one verified first: a description that does not
/// check out is not advertised.
async fn well_known_descriptions(State(hub): State<Arc<Hub>>, Query(q): Query<std::collections::HashMap<String, String>>) -> Response {
    let Some(did) = hub.docs.trust().and_then(|t| t.did().map(str::to_string)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(parsed) = anp_did::WbaDid::parse(&did) else { return StatusCode::NOT_FOUND.into_response() };
    let auth = match parsed.port {
        Some(p) => format!("{}:{p}", parsed.host),
        None => parsed.host.clone(),
    };
    let home = format!("https://{auth}");
    let agents = match hub.agents().await {
        Ok(a) => a,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let mut items: Vec<anp_ad::discovery::Item> = agents
        .iter()
        .filter_map(|a| a.check_description().ok())
        .filter(|c| anp_ad::discovery::origin(&c.url) == Some(home.as_str()))
        .map(|c| anp_ad::discovery::Item { name: c.name, id: c.url })
        .collect();
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let page = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let body = anp_ad::discovery::collection_page(&format!("{home}/.well-known/agent-descriptions"), &items, page, anp_ad::discovery::PAGE_SIZE);
    ([(axum::http::header::CONTENT_TYPE, "application/ld+json")], body.to_string()).into_response()
}

/// Discovery inside the mesh: every agent this node knows, its DID and whether the agent description it replicated
/// with its card verifies. This works with no network beyond the mesh itself, because the signed description and DID
/// document travel with the card.
async fn discover(State(hub): State<Arc<Hub>>) -> Response {
    let agents = match hub.agents().await {
        Ok(a) => a,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let out: Vec<Value> = agents
        .iter()
        .map(|a| {
            let check = a.check_description();
            json!({
                "nodeId": a.node_id,
                "self": a.node_id == hub.node_id,
                "online": a.node_id == hub.node_id || a.online(),
                "name": a.card.name,
                "did": check.as_ref().ok().map(|c| c.did.clone()),
                "descriptionUrl": check.as_ref().ok().map(|c| c.url.clone()),
                "descriptionVerified": check.is_ok(),
                "reason": check.as_ref().err(),
            })
        })
        .collect();
    Json(out).into_response()
}

/// ANP-09 P5 messaging: the key-service call and `direct.send` from peers on other ANP stacks (see `p5`).
async fn p5_rpc(State(hub): State<Arc<Hub>>, request: axum::http::Request<axum::body::Body>) -> Response {
    let Some(p5) = hub.p5() else { return StatusCode::NOT_FOUND.into_response() };
    let caller = request.extensions().get::<crate::httpauth::Caller>().map(|c| c.0.clone());
    let Ok(body) = axum::body::to_bytes(request.into_body(), 8 * 1024 * 1024).await else { return StatusCode::PAYLOAD_TOO_LARGE.into_response() };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Json(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": e.to_string() } })).into_response(),
    };
    Json(p5.handle(&hub, req, caller).await).into_response()
}

/// Publish a revocation (the output of `anp-admin revoke`). Only a bundle signed by the authority is accepted;
/// it is stored in the replicated `revocations` collection so the whole mesh learns of it.
async fn post_revocation(State(hub): State<Arc<Hub>>, body: Bytes) -> Response {
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match hub.publish_revocation(&v).await {
        Ok(id) => Json(json!({ "revoked": id })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

/// The field-inspection demo dashboard (see the README); served by every node, it shows that node's view.
async fn demo_page() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("demo.html"))
}

/// The control-room view: the three devices side by side with a live topology (see `demo-all.html`).
async fn demo_all_page() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("demo-all.html"))
}

/// Whether this node can cut its peer connections, and whether they are up.
async fn link_status(State(hub): State<Arc<Hub>>) -> Json<Value> {
    Json(match hub.link() {
        Some(l) => json!({ "available": true, "up": l.is_up() }),
        None => json!({ "available": false, "up": null }),
    })
}

/// `POST /link {"up": false}` cuts this node's outgoing peer connections, `true` restores them. The node
/// keeps running and keeps answering local requests while the link is down.
async fn link_set(State(hub): State<Arc<Hub>>, body: Bytes) -> Response {
    let up = match serde_json::from_slice::<Value>(&body).ok().and_then(|v| v.get("up").and_then(Value::as_bool)) {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, "expected {\"up\": true|false}").into_response(),
    };
    let Some(link) = hub.link() else {
        return (StatusCode::NOT_FOUND, "this node has no link control").into_response();
    };
    match tokio::task::spawn_blocking(move || link.set(up)).await {
        Ok(Ok(())) => Json(json!({ "available": true, "up": up })).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn own_card(State(hub): State<Arc<Hub>>) -> Json<AgentCard> {
    Json(hub.card().clone())
}

async fn list_agents(State(hub): State<Arc<Hub>>) -> Response {
    match hub.agents().await {
        Ok(a) => {
            let v: Vec<Value> = a
                .iter()
                .map(|d| {
                    json!({ "nodeId": d.node_id, "self": d.node_id == hub.node_id,
                            "online": d.node_id == hub.node_id || d.online(),
                            "lastSeen": d.ts, "card": d.card })
                })
                .collect();
            Json(v).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn peer_card(State(hub): State<Arc<Hub>>, Path(node): Path<String>) -> Response {
    match hub.agent(&node).await {
        Ok(Some(d)) => {
            let mut card = d.card;
            let base = hub.card().supported_interfaces.first().map(|i| i.url.clone()).unwrap_or_default();
            card.supported_interfaces = vec![AgentInterface {
                url: base,
                protocol_binding: "JSONRPC".into(),
                protocol_version: "1.0".into(),
                tenant: Some(node),
            }];
            Json(card).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn rpc(State(hub): State<Arc<Hub>>, body: Bytes) -> Response {
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Json(rpc_err(&Value::Null, &RpcError::new(ERR_PARSE, e.to_string()))).into_response(),
    };
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = v.get("method").and_then(Value::as_str) else {
        return Json(rpc_err(&id, &RpcError::new(ERR_INVALID_REQUEST, "missing method"))).into_response();
    };
    let params = v.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "SendStreamingMessage" => match start_send_stream(&hub, &params).await {
            Ok((prev, baseline, rx)) => sse(hub, id, prev, baseline, rx).into_response(),
            Err(e) => Json(rpc_err(&id, &e)).into_response(),
        },
        "SubscribeToTask" => match start_subscribe(&hub, &params).await {
            Ok((prev, rx)) => sse(hub, id, prev, None, rx).into_response(),
            Err(e) => Json(rpc_err(&id, &e)).into_response(),
        },
        _ => match unary(&hub, method, params).await {
            Ok(result) => Json(rpc_ok(&id, result)).into_response(),
            Err(e) => Json(rpc_err(&id, &e)).into_response(),
        },
    }
}

fn parse<T: serde::de::DeserializeOwned>(params: &Value) -> Result<T, RpcError> {
    serde_json::from_value(params.clone()).map_err(|e| RpcError::new(ERR_INVALID_PARAMS, e.to_string()))
}

async fn unary(hub: &Arc<Hub>, method: &str, params: Value) -> Result<Value, RpcError> {
    match method {
        "SendMessage" => {
            let req: SendMessageRequest = parse(&params)?;
            let cfg = req.configuration.clone().unwrap_or_default();
            let mut rx = hub.subscribe(); // before the write: miss nothing
            let (tid, baseline) = hub.send_message(&req).await?;
            let task = if cfg.return_immediately {
                hub.get_task(&tid).await
            } else {
                hub.wait_for(&tid, &mut rx, SEND_WAIT, |t| settled(t, baseline.as_deref())).await
            }
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::task_not_found(&tid))?;
            Ok(json!({ "task": task.with_history_length(cfg.history_length) }))
        }
        "GetTask" => {
            let id = params.get("id").and_then(Value::as_str).ok_or_else(|| RpcError::new(ERR_INVALID_PARAMS, "id required"))?;
            let hl = params.get("historyLength").and_then(Value::as_i64).map(|n| n as i32);
            let t = hub.get_task(id).await.map_err(RpcError::internal)?.ok_or_else(|| RpcError::task_not_found(id))?;
            Ok(serde_json::to_value(t.with_history_length(hl)).unwrap())
        }
        "ListTasks" => {
            let ctx = params.get("contextId").and_then(Value::as_str);
            let state: Option<TaskState> = match params.get("status") {
                Some(s) if !s.is_null() => Some(parse(s)?),
                _ => None,
            };
            let page_size = params.get("pageSize").and_then(Value::as_u64).unwrap_or(50).clamp(1, 100) as usize;
            let offset = params.get("pageToken").and_then(Value::as_str).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let hl = params.get("historyLength").and_then(Value::as_i64).map(|n| n as i32);
            let (tasks, total) =
                hub.list_tasks(ctx, state, page_size, offset, hl).await.map_err(RpcError::internal)?;
            let next = if offset + tasks.len() < total { (offset + tasks.len()).to_string() } else { String::new() };
            Ok(json!({ "tasks": tasks, "nextPageToken": next, "pageSize": tasks.len(), "totalSize": total }))
        }
        "CancelTask" => {
            let id = params.get("id").and_then(Value::as_str).ok_or_else(|| RpcError::new(ERR_INVALID_PARAMS, "id required"))?;
            Ok(serde_json::to_value(hub.cancel_task(id).await?).unwrap())
        }
        "GetExtendedAgentCard" => {
            Err(RpcError::new(-32007, "this agent has no extended agent card"))
        }
        m if m.contains("PushNotificationConfig") => {
            Err(RpcError::new(ERR_PUSH_UNSUPPORTED, "push notifications are not supported"))
        }
        m => Err(RpcError::new(ERR_METHOD_NOT_FOUND, format!("method not found: {m}"))),
    }
}

async fn start_send_stream(
    hub: &Arc<Hub>,
    params: &Value,
) -> Result<(Task, Option<String>, broadcast::Receiver<String>), RpcError> {
    let req: SendMessageRequest = parse(params)?;
    let rx = hub.subscribe();
    let (tid, baseline) = hub.send_message(&req).await?;
    let task = hub.get_task(&tid).await.map_err(RpcError::internal)?.ok_or_else(|| RpcError::task_not_found(&tid))?;
    Ok((task, baseline, rx))
}

async fn start_subscribe(
    hub: &Arc<Hub>,
    params: &Value,
) -> Result<(Task, broadcast::Receiver<String>), RpcError> {
    let id = params.get("id").and_then(Value::as_str).ok_or_else(|| RpcError::new(ERR_INVALID_PARAMS, "id required"))?;
    let rx = hub.subscribe();
    let task = hub.get_task(id).await.map_err(RpcError::internal)?.ok_or_else(|| RpcError::task_not_found(id))?;
    if task.status.state.is_terminal() {
        return Err(RpcError::new(ERR_UNSUPPORTED_OPERATION, "task is in a terminal state; nothing to subscribe to"));
    }
    Ok((task, rx))
}

/// Emit the initial `task`, then status/artifact updates as the (replicated)
/// task document changes, until the task is terminal or needs input.
fn sse(
    hub: Arc<Hub>,
    id: Value,
    initial: Task,
    baseline: Option<String>,
    mut rx: broadcast::Receiver<String>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let (tx, out) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        let mut prev = initial;
        if tx.send(rpc_ok(&id, json!({ "task": prev }))).is_err() {
            return;
        }
        let deadline = tokio::time::Instant::now() + STREAM_MAX;
        while !settled(&prev, baseline.as_deref()) {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await;
            let Ok(Some(cur)) = hub.get_task(&prev.id).await else { continue };
            for payload in diff_events(&prev, &cur) {
                if tx.send(rpc_ok(&id, payload)).is_err() {
                    return; // client went away
                }
            }
            prev = cur;
        }
    });
    Sse::new(UnboundedReceiverStream::new(out).map(|v| Ok(Event::default().data(v.to_string()))))
        .keep_alive(KeepAlive::default())
}
