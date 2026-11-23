//! anp-ad: check an ANP-07 agent description against the DID document of the agent that published it.
//!
//!   anp-ad verify   --ad ad.json --did-doc did.json [--domain host[:port]]
//!   anp-ad verify-did --did-doc did.json
//!   anp-ad discover --url http://host:port/.well-known/agent-descriptions [--max-pages N]
//!
//! Both files are JSON (for example saved from `/agents/<name>/ad.json` and `/agents/<name>/<e1_fp>/did.json`).
//! The DID document is verified first (self-certifying: its key must match the DID), then the description.
//! Exit status 0 means everything checked out.

use std::process::ExitCode;

fn load(path: &str) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

fn fetch(url: &str) -> Result<serde_json::Value, String> {
    let r = ureq::get(url).timeout(std::time::Duration::from_secs(10)).call().map_err(|e| e.to_string())?;
    let text = r.into_string().map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("not JSON: {e}"))
}

/// Walk an ANP-08 listing and check the shape of every description it points to. (Verifying the signatures needs
/// each agent's DID document: use `verify` for that.)
fn discover(mut args: impl Iterator<Item = String>) -> Result<String, String> {
    let (mut url, mut max) = (None, 20usize);
    while let Some(k) = args.next() {
        let v = args.next().ok_or(format!("{k} needs a value"))?;
        match k.as_str() {
            "--url" => url = Some(v),
            "--max-pages" => max = v.parse().map_err(|e| format!("--max-pages: {e}"))?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let url = url.ok_or("--url is required")?;
    let items = anp_ad::discovery::crawl(&url, max, &mut |u| fetch(u)).map_err(|e| e.to_string())?;
    let mut lines = vec![format!("{} agent description(s) listed", items.len())];
    for i in &items {
        let status = match fetch(&i.id) {
            Ok(ad) => match anp_ad::validate(&ad) {
                Ok(()) => format!("valid, did {}, {}", ad["did"].as_str().unwrap_or("(none)"), if ad.get("proof").is_some() { "signed" } else { "UNSIGNED" }),
                Err(e) => format!("INVALID: {e}"),
            },
            Err(e) => format!("unreachable: {e}"),
        };
        lines.push(format!("  {:<16} {}  [{status}]", i.name, i.id));
    }
    Ok(lines.join("\n"))
}

fn run() -> Result<String, String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("verify") => {}
        Some("discover") => return discover(args),
        Some("verify-did") => {
            let mut path = None;
            while let Some(k) = args.next() {
                let v = args.next().ok_or(format!("{k} needs a value"))?;
                match k.as_str() {
                    "--did-doc" => path = Some(v),
                    other => return Err(format!("unknown argument {other}")),
                }
            }
            let doc = load(&path.ok_or("--did-doc is required")?)?;
            let v = anp_did::verify_document(&doc, None).map_err(|e| e.to_string())?;
            let ka = v.key_agreement().map(|(id, _)| id).unwrap_or_else(|| "none".into());
            return Ok(format!("OK: {} (key-agreement: {ka})", v.did_string));
        }
        _ => return Err("usage: anp-ad verify --ad ad.json --did-doc did.json [--domain host[:port]]\n       anp-ad discover --url http://host:port/.well-known/agent-descriptions [--max-pages N]".into()),
    }
    let (mut ad, mut did, mut domain) = (None, None, None);
    while let Some(k) = args.next() {
        let v = args.next().ok_or(format!("{k} needs a value"))?;
        match k.as_str() {
            "--ad" => ad = Some(v),
            "--did-doc" => did = Some(v),
            "--domain" => domain = Some(v),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let ad = load(&ad.ok_or("--ad is required")?)?;
    let did_doc = load(&did.ok_or("--did-doc is required")?)?;
    let verified = anp_did::verify_document(&did_doc, None).map_err(|e| e.to_string())?;
    anp_ad::verify(&ad, &verified, domain.as_deref()).map_err(|e| e.to_string())?;
    Ok(format!("OK: {} is signed by {}", ad["name"].as_str().unwrap_or("?"), verified.did_string))
}

fn main() -> ExitCode {
    match run() {
        Ok(m) => {
            println!("{m}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
