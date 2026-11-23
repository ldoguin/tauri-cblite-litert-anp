//! `cargo xtask <task>`: the project's end-to-end checks, in Rust, so that they run the same on Windows, Linux and macOS and need no shell.
//! Binaries come from `CARGO_TARGET_DIR` (or `<repo>/target`); build them first with
//! `cargo build -p anp-node -p anp-authz -p anp-ad -p anp-search -p anp-wns -p anp-meta`.
//!
//! The PowerShell scripts in `scripts/` are the same checks and still there; tasks move here one at a time.

mod biscuit;
mod crossos;
mod did;
mod direct;
mod e2ee;
mod fielddid;
mod group;
mod hardened;
mod harness;
mod mesh;
mod grouphost;
mod remote;
mod secondhost;

const TASKS: &[(&str, &str)] = &[
    ("e2e", "two nodes: discovery, routed tasks, streaming, cancel, errors, store-and-forward (as scripts/e2e.ps1)"),
    ("e2e-secure", "the same with signed documents and a key list, and two outsiders (scripts/e2e.ps1 -Secure)"),
    ("e2e-biscuit", "the same with Biscuit tokens: a fake authority, a scoped token, revocation (scripts/e2e.ps1 -Biscuit)"),
    ("e2e-cross-os", "a node here and a Linux node in WSL in one mesh over the network (as scripts/e2e-cross-os.ps1; needs WSL and the Linux build)"),
    ("e2e-second-host", "the P6 host and a two-node mesh against a node on another host over ssh (as scripts/e2e-second-host.ps1; needs --remote-host and --remote-addr)"),
    ("e2e-field-did", "the field-inspection scenario on DIDs: tablet, branch, head office, a lost signal, an intruder (as scripts/e2e-field-did.ps1)"),
    ("e2e-hardened", "tokens + TLS + admission + an encrypted database, one attacker per layer (as scripts/e2e-hardened.ps1)"),
    ("e2e-did", "DID mode: TLS and admission by a DID, the DID document and signed agent description, discovery, three attackers (as scripts/e2e-did.ps1)"),
    ("e2e-did-biscuit", "DID and Biscuit together: tokens bound to DIDs, scoping, stolen tokens, revocation (as scripts/e2e-did-biscuit.ps1)"),
    ("e2e-e2ee", "end-to-end encryption through a relay, with a plaintext peer and a control run (as scripts/e2e-e2ee.ps1)"),
    ("e2e-direct", "two nodes on two domains start encrypted direct conversations with each other, both ways: answers, follow-ups, a restart, the guards"),
    ("e2e-group", "three nodes of three companies in an encrypted group hosted by a fourth: create, add, write, read, a restart, a removal, what the host holds"),
    ("group-host", "the group host for end-to-end encrypted groups (ANP P6) over signed HTTP: the node_live tests against a node started here (the host part of scripts/e2e-group-host.ps1; also runs as p6-host)"),
];

fn main() {
    let all_args: Vec<String> = std::env::args().skip(1).collect();
    let task = all_args.first().cloned().unwrap_or_default();
    let args: Vec<String> = all_args.iter().skip(1).cloned().collect();
    let result = match task.as_str() {
        "e2e" => mesh::run(mesh::Mode::Plain),
        "e2e-secure" => mesh::run(mesh::Mode::Secure),
        "e2e-biscuit" => mesh::run(mesh::Mode::Biscuit),
        "e2e-cross-os" => crossos::run(&args),
        "e2e-second-host" => secondhost::run(&args),
        "e2e-field-did" => fielddid::run(),
        "e2e-hardened" => hardened::run(),
        "e2e-did" => did::run(),
        "e2e-did-biscuit" => biscuit::run(),
        "e2e-e2ee" => e2ee::run(),
        "e2e-direct" => direct::run(),
        "e2e-group" => group::run(),
        "group-host" | "p6-host" => grouphost::run(),
        "all" => {
            let mut worst = 0;
            for (name, _) in TASKS {
                // the two that need another OS or machine are run by name
                if matches!(*name, "e2e-cross-os" | "e2e-second-host") {
                    continue;
                }
                println!("== {name}");
                let r = match *name {
                    "e2e" => mesh::run(mesh::Mode::Plain),
                    "e2e-secure" => mesh::run(mesh::Mode::Secure),
                    "e2e-biscuit" => mesh::run(mesh::Mode::Biscuit),
                    "e2e-field-did" => fielddid::run(),
                    "e2e-hardened" => hardened::run(),
                    "e2e-did" => did::run(),
                    "e2e-did-biscuit" => biscuit::run(),
                    "e2e-e2ee" => e2ee::run(),
                    "e2e-direct" => direct::run(),
                    "e2e-group" => group::run(),
                    _ => grouphost::run(),
                };
                match r {
                    Ok(code) => worst = worst.max(code),
                    Err(e) => {
                        eprintln!("xtask {name}: {e}");
                        worst = 2;
                    }
                }
            }
            Ok(worst)
        }
        _ => {
            eprintln!("usage: cargo xtask <task>\n\ntasks:");
            for (n, d) in TASKS {
                eprintln!("  {n:<16} {d}");
            }
            eprintln!("  all              every task above that needs no other machine (not e2e-cross-os, e2e-second-host)");
            std::process::exit(if task.is_empty() || task == "help" { 0 } else { 2 });
        }
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("xtask {task}: {e}");
            std::process::exit(2);
        }
    }
}