//! A test certificate authority and a TLS front for the nodes, so that `did:wba` DIDs resolve over HTTPS on one machine.
//!
//! A `did:wba` is resolved from `https://<its domain>/...`, and the resolver accepts nothing else. The nodes serve plain HTTP (a
//! deployment puts TLS in front), so each node gets a front here: `https://localhost:<port>` terminates TLS with a certificate for
//! `localhost` signed by a CA made for the run, and forwards the bytes to the node's own port. Every resolver is given that CA
//! (`--resolver-roots`) and allowed to reach a private address (`--resolver-allow-private`). Nothing else is relaxed.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct TestCa {
    /// The CA certificate, PEM: what the resolvers are told to trust.
    pub pem_file: PathBuf,
    server: Arc<rustls::ServerConfig>,
}

fn e(x: impl std::fmt::Display) -> String {
    x.to_string()
}

/// Make a CA and a certificate for `localhost` (and 127.0.0.1) signed by it; write the CA to `<dir>/test-ca.pem`.
pub fn test_ca(dir: &Path) -> Result<TestCa, String> {
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "ANP cold-rescue test CA");
    ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign, rcgen::KeyUsagePurpose::DigitalSignature];
    let ca_key = rcgen::KeyPair::generate().map_err(e)?;
    let ca_cert = ca.self_signed(&ca_key).map_err(e)?;

    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(e)?;
    leaf.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)));
    leaf.distinguished_name.push(rcgen::DnType::CommonName, "localhost");
    let leaf_key = rcgen::KeyPair::generate().map_err(e)?;
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).map_err(e)?;

    let pem_file = dir.join("test-ca.pem");
    std::fs::write(&pem_file, ca_cert.pem()).map_err(e)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(e)?
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))
        .map_err(e)?;
    Ok(TestCa { pem_file, server: Arc::new(server) })
}

impl TestCa {
    /// Serve `https://localhost:<port>` in front of the plain HTTP node on `backend`, for the life of the process.
    pub fn front(&self, port: u16, backend: u16) -> Result<(), String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|err| format!("TLS front on {port}: {err}"))?;
        let cfg = self.server.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let cfg = cfg.clone();
                std::thread::spawn(move || {
                    let _ = relay(conn, cfg, backend);
                });
            }
        });
        Ok(())
    }
}

fn idle(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// One connection: TLS on one side, the node's plain HTTP on the other, bytes copied both ways until either side closes.
fn relay(tcp: TcpStream, cfg: Arc<rustls::ServerConfig>, backend: u16) -> std::io::Result<()> {
    let conn = rustls::ServerConnection::new(cfg).map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let mut back = TcpStream::connect((Ipv4Addr::LOCALHOST, backend))?;
    tls.sock.set_read_timeout(Some(Duration::from_millis(10)))?;
    back.set_read_timeout(Some(Duration::from_millis(10)))?;
    let mut buf = [0u8; 16 * 1024];
    let mut quiet = 0u32;
    loop {
        let mut moved = false;
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                back.write_all(&buf[..n])?;
                moved = true;
            }
            Err(err) if idle(&err) => {}
            Err(_) => break,
        }
        match back.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                tls.write_all(&buf[..n])?;
                tls.flush()?;
                moved = true;
            }
            Err(err) if idle(&err) => {}
            Err(_) => break,
        }
        quiet = if moved { 0 } else { quiet + 1 };
        if quiet > 3_000 {
            break; // about 30 s with nothing either way
        }
    }
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}
