//! `anp-wns`: check handles from the command line.
//!
//!   anp-wns validate HANDLE                         is it a valid handle (or wba:// URI)? prints the normalised form
//!   anp-wns validate-file CASES.json                compare with another implementation's verdicts: {"cases":[{"input","valid","normalized"}]}
//!   anp-wns resolve HANDLE [--base URL]             the provider's resolution document (guarded https)
//!   anp-wns verify HANDLE [--base URL] [--did-doc FILE]   forward and reverse binding
//!
//! Options for resolve and verify: --roots CA.pem (a private CA), --allow-private (documents on private addresses), --base URL
//! (fetch from URL/.well-known/handle/<local> instead of https://<domain>/..., for gateways and tests).

use anp_wns::{parse, Client, WnsError};
use std::process::ExitCode;

fn fail(m: impl std::fmt::Display) -> ExitCode {
    eprintln!("{m}");
    ExitCode::from(1)
}

fn kind(e: &WnsError) -> &'static str {
    match e {
        WnsError::Invalid(_) => "invalid",
        WnsError::NotFound(_) => "not-found",
        WnsError::Gone(_) => "gone",
        WnsError::Moved(_) => "moved",
        WnsError::Resolution(_) => "resolution",
        WnsError::Binding(_) => "binding",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let flag = |name: &str| args.iter().any(|a| a == name);
    match args.first().map(String::as_str) {
        Some("validate") => match args.get(1).map(|h| parse(h)) {
            Some(Ok(h)) => {
                println!("ok {h}");
                ExitCode::SUCCESS
            }
            Some(Err(e)) => fail(format!("{}: {e}", kind(&e))),
            None => fail("usage: anp-wns validate HANDLE"),
        },
        Some("validate-file") => {
            let Some(path) = args.get(1) else { return fail("usage: anp-wns validate-file CASES.json") };
            let v: serde_json::Value = match std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string())) {
                Ok(v) => v,
                Err(e) => return fail(format!("{path}: {e}")),
            };
            let (mut n, mut bad) = (0, 0);
            for c in v["cases"].as_array().into_iter().flatten() {
                n += 1;
                let input = c["input"].as_str().unwrap_or("");
                let mine = parse(input);
                let agree = match (&mine, c["valid"].as_bool().unwrap_or(false)) {
                    (Ok(h), true) => c["normalized"].as_str().map_or(true, |x| x == h.to_string()),
                    (Err(_), false) => true,
                    _ => false,
                };
                if !agree {
                    bad += 1;
                    println!("DISAGREE {input:?}: this project says {:?}, the other says valid={} normalized={}", mine.as_ref().map(|h| h.to_string()).map_err(|e| e.to_string()), c["valid"], c["normalized"]);
                }
            }
            println!("{n} cases, {bad} disagreements");
            if bad == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        Some(cmd @ ("resolve" | "verify")) => {
            let Some(h) = args.get(1).map(|h| parse(h)) else { return fail(format!("usage: anp-wns {cmd} HANDLE")) };
            let handle = match h {
                Ok(h) => h,
                Err(e) => return fail(format!("{}: {e}", kind(&e))),
            };
            let roots = match opt("--roots") {
                Some(p) => match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|t| anp_resolve::pem_certificates(&t)) {
                    Ok(r) => r,
                    Err(e) => return fail(format!("--roots {p}: {e}")),
                },
                None => vec![],
            };
            let cfg = anp_resolve::Config { allow_private: flag("--allow-private"), extra_roots: roots, ..Default::default() };
            let mut client = match Client::new(cfg) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            if let Some(b) = opt("--base") {
                client = client.with_base(&b);
            }
            if cmd == "resolve" {
                return match client.resolve(&handle) {
                    Ok(r) => {
                        println!("ok {} {} {} {}", r.handle, r.did, r.status.as_str(), r.binding_generation);
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(format!("{}: {e}", kind(&e))),
                };
            }
            let doc = match opt("--did-doc") {
                Some(p) => match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|t| serde_json::from_str::<serde_json::Value>(&t).map_err(|e| e.to_string())) {
                    Ok(d) => Some(d),
                    Err(e) => return fail(format!("--did-doc {p}: {e}")),
                },
                None => None,
            };
            match client.verify(&handle, doc.as_ref()) {
                Ok(v) => {
                    println!("ok {} {} {}", v.handle, v.did, v.binding_generation);
                    ExitCode::SUCCESS
                }
                Err(e) => fail(format!("{}: {e}", kind(&e))),
            }
        }
        _ => fail("usage: anp-wns validate|validate-file|resolve|verify ..."),
    }
}