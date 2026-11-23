//! Resolving DIDs over HTTPS (ANP-03 §resolution): `did:wba` and `did:web`.
//!
//! A `did:wba` path DID names its own document URL (`https://host[:port]/path/did.json`, or `/.well-known/did.json`
//! without a path) and the document is self-certifying: its key must be the one the DID's `e1_` fingerprint names, and it
//! must be signed by it. A `did:web` document is not self-certifying; what vouches for it is the domain it was fetched from
//! over TLS, which is exactly why *which domains to believe* is a decision for the caller (see the node's `--trust-domain`).
//!
//! The DID reaches us from an untrusted request, so resolving it means fetching a URL somebody else chose. Guards:
//! * **HTTPS only**, with the certificate chain checked against the web PKI (plus any extra roots you configure);
//! * **no internal hosts**: addresses in loopback, private, link-local, unique-local, CGNAT, multicast and unspecified
//!   ranges are refused, in the very address list the connection then uses (so DNS rebinding cannot swap it);
//! * **no redirects** (the spec says untrusted cross-origin redirects must not be followed; same-origin ones are not needed);
//! * a **size limit** and a **timeout**;
//! * the document is **verified** before it is returned (`did:wba`: the `e1` binding and proof; both: `id` equals the DID).
//!
//! Results are cached (successes for `ttl`, failures briefly), and the cache is bounded.
//! Not done: DNS over HTTPS (the spec recommends it to limit tracking); the system resolver is used.

use anp_did::{verify_document, Verified, WbaDid};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Config {
    pub timeout: Duration,
    /// Largest document accepted, in bytes.
    pub max_bytes: usize,
    /// How long a successful resolution is reused.
    pub ttl: Duration,
    /// How long a failure is remembered (so a bad host cannot be hammered through us).
    pub negative_ttl: Duration,
    /// Allow documents on loopback and private addresses. Off by default; on only for tests and closed networks.
    pub allow_private: bool,
    /// Extra trusted root certificates, DER (a private CA). The web roots are always trusted.
    pub extra_roots: Vec<Vec<u8>>,
    /// Cache entries kept.
    pub max_cache: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config { timeout: Duration::from_secs(5), max_bytes: 64 * 1024, ttl: Duration::from_secs(300), negative_ttl: Duration::from_secs(30), allow_private: false, extra_roots: vec![], max_cache: 256 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// Not a DID this resolver handles, or malformed.
    Syntax(String),
    /// Refused by policy before or while fetching (a private address, a redirect).
    Refused(String),
    /// The fetch failed: DNS, connection, TLS, timeout.
    Fetch(String),
    /// The server answered with this HTTP status.
    Status(u16),
    TooLarge(usize),
    NotJson(String),
    /// The document was fetched but is not valid for this DID.
    Invalid(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::Syntax(s) => write!(f, "cannot resolve: {s}"),
            ResolveError::Refused(s) => write!(f, "refused: {s}"),
            ResolveError::Fetch(s) => write!(f, "fetch failed: {s}"),
            ResolveError::Status(c) => write!(f, "the server answered HTTP {c}"),
            ResolveError::TooLarge(n) => write!(f, "the document is larger than {n} bytes"),
            ResolveError::NotJson(s) => write!(f, "not a JSON document: {s}"),
            ResolveError::Invalid(s) => write!(f, "the document is not valid for this DID: {s}"),
        }
    }
}
impl std::error::Error for ResolveError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Wba,
    Web,
}

/// A resolved DID document.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub did: String,
    pub method: Method,
    pub document: Value,
    /// For `did:wba`: the verified document (the key the DID names, key agreement, services). `None` for `did:web`.
    pub verified: Option<Verified>,
    /// The URL it came from.
    pub url: String,
    /// The authority (`host` or `host:port`) it came from: what vouches for a `did:web` document.
    pub domain: String,
}

// ── names and URLs ──────────────────────────────────────────────────────────────────────────────────────

fn percent_decode_colon(s: &str) -> String {
    s.replace("%3A", ":").replace("%3a", ":")
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The authority (`host` or `host:port`, lowercase) a `did:wba` or `did:web` DID lives at, if it has a valid one.
pub fn domain_of(did: &str) -> Option<String> {
    split(did).ok().map(|(_, authority, _)| authority)
}

/// `(method, authority, path segments)` of a DID, validated.
fn split(did: &str) -> Result<(Method, String, Vec<String>), ResolveError> {
    let (method, rest) = if let Some(r) = did.strip_prefix("did:wba:") {
        (Method::Wba, r)
    } else if let Some(r) = did.strip_prefix("did:web:") {
        (Method::Web, r)
    } else {
        return Err(ResolveError::Syntax("only did:wba and did:web".into()));
    };
    let mut parts = rest.split(':');
    let authority = percent_decode_colon(parts.next().unwrap_or(""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority.as_str(), None),
    };
    if host.is_empty() || host.parse::<IpAddr>().is_ok() || host.starts_with('[') || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.')) {
        return Err(ResolveError::Syntax("the host must be a domain name".into()));
    }
    if let Some(p) = port {
        if p.parse::<u16>().map_or(true, |n| n == 0) {
            return Err(ResolveError::Syntax("bad port".into()));
        }
    }
    let segs: Vec<String> = parts.map(str::to_string).collect();
    if !segs.iter().all(|s| segment_ok(s)) {
        return Err(ResolveError::Syntax("bad path segment".into()));
    }
    Ok((method, authority.to_ascii_lowercase(), segs))
}

/// Where the document of `did` is served.
pub fn url_for(did: &str) -> Result<String, ResolveError> {
    let (_, authority, segs) = split(did)?;
    Ok(if segs.is_empty() { format!("https://{authority}/.well-known/did.json") } else { format!("https://{authority}/{}/did.json", segs.join("/")) })
}

// ── network guards ──────────────────────────────────────────────────────────────────────────────────────

fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_multicast() || v.is_broadcast() || v.is_documentation()
                || (o[0] == 100 && (64..128).contains(&o[1])) // carrier-grade NAT
                || o[0] == 0
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return is_internal(IpAddr::V4(m));
            }
            let s = v.segments();
            v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s[0] & 0xfe00) == 0xfc00 /* unique local */ || (s[0] & 0xffc0) == 0xfe80 /* link local */
        }
    }
}

/// The DNS step of every connection: only addresses that are allowed come back, and those are the ones connected to.
struct GuardedResolver {
    allow_private: bool,
}

impl ureq::Resolver for GuardedResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let all: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
        let allowed: Vec<SocketAddr> = all.iter().copied().filter(|a| self.allow_private || !is_internal(a.ip())).collect();
        if allowed.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("refused: {netloc} resolves only to internal addresses")));
        }
        Ok(allowed)
    }
}

/// Certificates from a PEM file (every `CERTIFICATE` block), as DER.
pub fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    use base64::Engine;
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + 27..];
        let end = after.find("-----END CERTIFICATE-----").ok_or("unterminated certificate block")?;
        let b64: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        out.push(base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| format!("bad certificate: {e}"))?);
        rest = &after[end + 25..];
    }
    if out.is_empty() {
        return Err("no certificate found".into());
    }
    Ok(out)
}

struct Entry {
    at: Instant,
    result: Result<Resolved, ResolveError>,
}

pub struct Resolver {
    cfg: Config,
    agent: ureq::Agent,
    cache: Mutex<HashMap<String, Entry>>,
}

impl Resolver {
    pub fn new(cfg: Config) -> Result<Resolver, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in &cfg.extra_roots {
            roots.add(rustls::pki_types::CertificateDer::from(der.clone())).map_err(|e| format!("extra root certificate: {e}"))?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let agent = ureq::AgentBuilder::new()
            .tls_config(Arc::new(tls))
            .redirects(0)
            .timeout(cfg.timeout)
            .resolver(GuardedResolver { allow_private: cfg.allow_private })
            .user_agent("anp-cblite-resolver")
            .build();
        Ok(Resolver { cfg, agent, cache: Mutex::new(HashMap::new()) })
    }

    /// A resolution already in the cache and still fresh (no network).
    pub fn cached(&self, did: &str) -> Option<Resolved> {
        let c = self.cache.lock().unwrap();
        c.get(did).filter(|e| e.at.elapsed() < self.cfg.ttl).and_then(|e| e.result.clone().ok())
    }

    pub fn forget(&self, did: &str) {
        self.cache.lock().unwrap().remove(did);
    }

    /// Resolve `did`: from the cache, or by fetching and verifying its document.
    pub fn resolve(&self, did: &str) -> Result<Resolved, ResolveError> {
        {
            let c = self.cache.lock().unwrap();
            if let Some(e) = c.get(did) {
                let age = e.at.elapsed();
                match &e.result {
                    Ok(r) if age < self.cfg.ttl => return Ok(r.clone()),
                    Err(err) if age < self.cfg.negative_ttl => return Err(err.clone()),
                    _ => {}
                }
            }
        }
        let result = self.fetch(did);
        let mut c = self.cache.lock().unwrap();
        if c.len() >= self.cfg.max_cache {
            let (ttl, neg) = (self.cfg.ttl, self.cfg.negative_ttl);
            c.retain(|_, e| e.at.elapsed() < if e.result.is_ok() { ttl } else { neg });
            while c.len() >= self.cfg.max_cache {
                let oldest = c.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => c.remove(&k),
                    None => break,
                };
            }
        }
        c.insert(did.to_string(), Entry { at: Instant::now(), result: result.clone() });
        result
    }

    /// Fetch a JSON document over HTTPS with all the guards of a DID resolution (no plain HTTP, no redirects, no internal
    /// addresses, size and time limits). Not cached and not verified: that is for the caller.
    pub fn get_json(&self, url: &str, accept: &str) -> Result<Value, ResolveError> {
        if !url.starts_with("https://") {
            return Err(ResolveError::Refused("only https URLs are fetched".into()));
        }
        let resp = match self.agent.get(url).set("accept", accept).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) if (300..400).contains(&code) => return Err(ResolveError::Refused("redirects are not followed".into())),
            Err(ureq::Error::Status(code, _)) => return Err(ResolveError::Status(code)),
            Err(ureq::Error::Transport(t)) => {
                let m = t.to_string();
                return Err(if m.contains("refused:") { ResolveError::Refused(m) } else { ResolveError::Fetch(m) });
            }
        };
        // with redirects off, ureq hands a 3xx back as an ordinary response: it is not a document
        match resp.status() {
            200 => {}
            c if (300..400).contains(&c) => return Err(ResolveError::Refused("redirects are not followed".into())),
            c => return Err(ResolveError::Status(c)),
        }
        let mut body = Vec::new();
        resp.into_reader().take(self.cfg.max_bytes as u64 + 1).read_to_end(&mut body).map_err(|e| ResolveError::Fetch(e.to_string()))?;
        if body.len() > self.cfg.max_bytes {
            return Err(ResolveError::TooLarge(self.cfg.max_bytes));
        }
        let text = String::from_utf8(body).map_err(|_| ResolveError::NotJson("not UTF-8".into()))?;
        serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| ResolveError::NotJson(e.to_string()))
    }
    fn fetch(&self, did: &str) -> Result<Resolved, ResolveError> {
        let (method, domain, _) = split(did)?;
        if method == Method::Wba {
            // only e1 path DIDs: the document must be self-certifying
            let parsed = WbaDid::parse(did).map_err(|e| ResolveError::Syntax(e.to_string()))?;
            if parsed.e1().is_none() {
                return Err(ResolveError::Syntax("only e1 path DIDs are resolved".into()));
            }
        }
        let url = url_for(did)?;
        let document = self.get_json(&url, "application/did+json, application/json")?;
        if document["id"].as_str() != Some(did) {
            return Err(ResolveError::Invalid(format!("the document is for {}, not {did}", document["id"])));
        }
        let verified = match method {
            Method::Wba => Some(verify_document(&document, Some(did)).map_err(|e| ResolveError::Invalid(e.to_string()))?),
            Method::Web => None,
        };
        Ok(Resolved { did: did.to_string(), method, document, verified, url, domain })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn urls_follow_the_spec() {
        assert_eq!(url_for("did:wba:example.com").unwrap(), "https://example.com/.well-known/did.json");
        assert_eq!(url_for(&format!("did:wba:example.com%3A3000:user:alice:e1_{FP}")).unwrap(), format!("https://example.com:3000/user/alice/e1_{FP}/did.json"));
        assert_eq!(url_for("did:web:example.com").unwrap(), "https://example.com/.well-known/did.json");
        assert_eq!(url_for("did:web:example.com:users:alice").unwrap(), "https://example.com/users/alice/did.json");
        assert_eq!(url_for("did:web:Example.COM%3A8443").unwrap(), "https://example.com:8443/.well-known/did.json");
        assert_eq!(domain_of("did:wba:Example.com%3A3000:a:b").as_deref(), Some("example.com:3000"));
        assert_eq!(domain_of("did:web:example.com").as_deref(), Some("example.com"));
    }

    #[test]
    fn dids_that_would_send_us_somewhere_odd_are_refused_before_any_network() {
        for bad in [
            "did:key:z6Mk",
            "did:wba:127.0.0.1",
            "did:web:10.0.0.1",
            "did:web:[::1]",
            "did:web:example.com%3A0",
            "did:web:example.com%3Aabc",
            "did:web:example.com:..:secret",
            "did:web:example.com:a%2Fb",
            "did:web:exa mple.com",
            "did:web:evil.com@internal",
            "did:web:",
        ] {
            assert!(url_for(bad).is_err(), "{bad}");
        }
        let r = Resolver::new(Config::default()).unwrap();
        assert!(matches!(r.resolve("did:wba:example.com:user:alice"), Err(ResolveError::Syntax(m)) if m.contains("e1")), "legacy path DIDs are not resolved");
        assert!(matches!(r.resolve("did:key:abc"), Err(ResolveError::Syntax(_))));
    }

    #[test]
    fn internal_addresses_are_recognised() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "224.0.0.1"] {
            assert!(is_internal(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "100.63.255.255", "172.32.0.1"] {
            assert!(!is_internal(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn pem_certificates_are_read() {
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_certificates(pem).unwrap(), vec![vec![1, 2, 3], vec![4, 5, 6]]);
        assert!(pem_certificates("nothing").is_err());
        assert!(pem_certificates("-----BEGIN CERTIFICATE-----\nAQID").is_err());
    }
}
