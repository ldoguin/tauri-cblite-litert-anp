//! `anp-meta ask URL --want NAME --protocol NAME[=FILE]...`: negotiate a protocol with a node (or any agent that speaks the same
//! HTTP binding) as the requester. URL is the `/anp/meta` endpoint (plain http: put a TLS terminator in front for https).
//!
//! `--want` is the protocol to propose first; every `--protocol` is one this side implements (a bare NAME gets a one-line text,
//! NAME=FILE uses the file's text). Prints the outcome and exits 0 if both sides ended up with a protocol.

use anp_meta::{Catalog, Protocol, Session, State};
use std::process::ExitCode;

fn post(url: &str, session: &str, frame: &[u8]) -> Result<(Vec<Vec<u8>>, String), String> {
    let resp = ureq::post(url).set("x-anp-session", session).set("content-type", "application/octet-stream").timeout(std::time::Duration::from_secs(30)).send_bytes(frame).map_err(|e| e.to_string())?;
    let state = resp.header("x-anp-meta-state").unwrap_or("").to_string();
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut body).map_err(|e| e.to_string())?;
    let mut frames = vec![];
    let mut b = &body[..];
    while !b.is_empty() {
        if b.len() < 4 {
            return Err("a truncated answer".into());
        }
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if b.len() < 4 + n {
            return Err("a truncated answer".into());
        }
        frames.push(b[4..4 + n].to_vec());
        b = &b[4 + n..];
    }
    Ok((frames, state))
}

/// The WebSocket binding: each frame is one binary message; the answers are whatever arrives within a moment of each send.
fn post_ws(sock: &mut tungstenite::WebSocket<std::net::TcpStream>, frame: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    sock.send(tungstenite::Message::Binary(frame.to_vec())).map_err(|e| e.to_string())?;
    let mut frames = vec![];
    loop {
        match sock.read() {
            Ok(tungstenite::Message::Binary(b)) => frames.push(b),
            Ok(tungstenite::Message::Close(_)) => return Err("the server closed the connection".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Ok(frames),
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("ask") || args.len() < 2 {
        eprintln!("usage: anp-meta ask URL --want NAME --protocol NAME[=FILE]... [--session ID]");
        return ExitCode::from(2);
    }
    let url = &args[1];
    let mut want = None;
    let mut session_id = format!("req-{:016x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0) as u64);
    let mut protocols = vec![];
    let mut i = 2;
    while i < args.len() {
        let v = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--want" => want = Some(v),
            "--session" => session_id = v,
            "--protocol" => {
                let (name, text) = match v.split_once('=') {
                    Some((n, f)) => match std::fs::read_to_string(f) {
                        Ok(t) => (n.to_string(), t),
                        Err(e) => {
                            eprintln!("--protocol {v}: {e}");
                            return ExitCode::from(2);
                        }
                    },
                    None => (v.clone(), format!("{v}: the protocol of that name, as both sides know it.")),
                };
                protocols.push(Protocol { name, text });
            }
            o => {
                eprintln!("unknown option {o}");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }
    let Some(want) = want else {
        eprintln!("--want NAME is needed");
        return ExitCode::from(2);
    };
    let (mut s, first) = match Session::requester(Catalog(protocols), &want) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut outbox = vec![first];
    let mut last_state = String::new();
    // ws://host:port/path: the WebSocket binding; http://...: one POST per message
    let mut ws = None;
    if let Some(rest) = url.strip_prefix("ws://") {
        let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".to_string()));
        let tcp = match std::net::TcpStream::connect(host) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{host}: {e}");
                return ExitCode::from(1);
            }
        };
        let _ = tcp.set_read_timeout(Some(std::time::Duration::from_millis(1500)));
        match tungstenite::client(format!("ws://{host}{path}"), tcp) {
            Ok((sock, _)) => ws = Some(sock),
            Err(e) => {
                eprintln!("the WebSocket handshake failed: {e}");
                return ExitCode::from(1);
            }
        }
    }
    for _ in 0..40 {
        let Some(m) = (!outbox.is_empty()).then(|| outbox.remove(0)) else { break };
        let answered = match ws.as_mut() {
            Some(sock) => post_ws(sock, &m).map(|f| (f, "ws".to_string())),
            None => post(url, &session_id, &m),
        };
        match answered {
            Ok((frames, st)) => {
                last_state = st;
                for f in frames {
                    match s.receive(&f) {
                        Ok(r) => outbox.extend(r),
                        Err(e) => {
                            eprintln!("bad message from the other side: {e}");
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        }
    }
    match s.state() {
        State::Agreed(p) => {
            println!("agreed {p} round={} peer_ready={:?} server_state={last_state}", s.round(), s.peer_ready);
            ExitCode::SUCCESS
        }
        State::Failed(why) => {
            println!("failed {why}");
            ExitCode::from(1)
        }
        State::Negotiating => {
            println!("unfinished");
            ExitCode::from(1)
        }
    }
}