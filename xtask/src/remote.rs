//! Another machine, or another operating system on this one, to run `anp-node` on: the Linux side in WSL, or a host reached over ssh (key or agent,
//! no password prompt). The same few operations either way: run a shell command there, start a long-running one, stop one by pattern, copy a file.

use std::path::Path;
use std::process::{Child, Command, Stdio};

pub enum Remote {
    Wsl { distro: String },
    Ssh { host: String, port: u16, identity: Option<String>, known_hosts: Option<String> },
}

/// A Windows path as WSL sees it (`C:\x\y` is `/mnt/c/x/y`); other paths come back with forward slashes.
pub fn wsl_path(p: &Path) -> String {
    let s = p.display().to_string();
    let b = s.as_bytes();
    if b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') && b[0].is_ascii_alphabetic() {
        return format!("/mnt/{}/{}", (b[0] as char).to_ascii_lowercase(), s[3..].replace('\\', "/"));
    }
    s.replace('\\', "/")
}

impl Remote {
    fn ssh_opts(&self) -> Vec<String> {
        let Remote::Ssh { port, identity, known_hosts, .. } = self else { return vec![] };
        let mut o: Vec<String> = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"].iter().map(|s| s.to_string()).collect();
        let _ = port;
        if let Some(i) = identity {
            o.extend(["-i".to_string(), i.clone(), "-o".into(), "IdentitiesOnly=yes".into()]);
        }
        if let Some(k) = known_hosts {
            o.extend(["-o".to_string(), format!("UserKnownHostsFile={k}")]);
        }
        o
    }

    fn command(&self, script: &str) -> Command {
        match self {
            Remote::Wsl { distro } => {
                let mut c = Command::new("wsl");
                c.args(["-d", distro, "--", "bash", "-c", script]);
                c
            }
            Remote::Ssh { host, port, .. } => {
                let mut c = Command::new("ssh");
                c.args(["-o", "ConnectTimeout=10", "-p", &port.to_string()]).args(self.ssh_opts()).arg(host).arg(script);
                c
            }
        }
    }

    /// Run a shell command there to the end: what it printed (both streams), trimmed.
    pub fn run(&self, script: &str) -> String {
        match self.command(script).stdin(Stdio::null()).output() {
            Ok(o) => format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)).trim().to_string(),
            Err(e) => format!("could not run the remote command: {e}"),
        }
    }

    /// Start a long-running command there; it lives as long as the returned child (kill it with [`Remote::pkill`] as well: the far side may linger).
    pub fn spawn(&self, script: &str) -> Child {
        self.command(script).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("start the remote command")
    }

    /// `pkill -f` for processes whose command line matches `pattern` (written so that it does not match itself: `[a]np-node --name bob`).
    pub fn pkill(&self, pattern: &str) {
        self.run(&format!("pkill -f '{pattern}'"));
    }

    /// Copy a local file to a path there.
    pub fn put(&self, local: &Path, remote: &str) {
        match self {
            Remote::Wsl { .. } => {
                self.run(&format!("cp \"{}\" {remote}", wsl_path(local)));
            }
            Remote::Ssh { host, .. } => {
                self.scp(&local.display().to_string(), &format!("{host}:{remote}"));
            }
        }
    }

    /// Copy a file from there to a local path.
    pub fn get(&self, remote: &str, local: &Path) {
        match self {
            Remote::Wsl { .. } => {
                self.run(&format!("cp {remote} \"{}\"", wsl_path(local)));
            }
            Remote::Ssh { host, .. } => {
                self.scp(&format!("{host}:{remote}"), &local.display().to_string());
            }
        }
    }

    fn scp(&self, from: &str, to: &str) {
        let Remote::Ssh { port, .. } = self else { return };
        let _ = Command::new("scp").args(["-q", "-P", &port.to_string()]).args(self.ssh_opts()).arg(from).arg(to).stdin(Stdio::null()).status();
    }

    /// The shell prefix that sets up the Linux node's environment: the Couchbase Lite library path, quiet logging, and the build folder as the
    /// working directory. `dir` is where `scripts/linux-node-build.sh` built the node (`~/anp-linux`).
    pub fn node_env(&self, dir: &str) -> String {
        let lib = self.run(&format!("ls -d {dir}/target/debug/build/couchbase_lite-*/out | head -1"));
        format!("export LD_LIBRARY_PATH={lib} RUST_LOG=warn; cd {dir}/target/debug;")
    }
}
