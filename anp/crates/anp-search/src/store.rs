//! Where the index is kept between runs. The ranking works on an in-memory [`crate::index::Index`]; a [`Store`] makes each change durable
//! one entry at a time (the old way was to rewrite one JSON file with everything after every change).
//!
//! * [`Cbl`]: a Couchbase Lite database, one document per entry. A change writes one document, atomically, and a crash cannot leave a
//!   half-written file. Couchbase Lite handles are not `Send` in the Rust binding, so (as in `anp-cblite`) they live on one thread of their
//!   own and the rest of the program talks to it with messages.
//! * [`JsonFile`]: the single JSON file, for a machine without the Couchbase Lite library, and for tests.

use crate::index::Entry;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex};

pub trait Store: Send + Sync {
    /// Everything kept.
    fn load(&self) -> Result<Vec<Entry>, String>;
    /// Keep (or replace) the entry for `e.url`.
    fn put(&self, e: &Entry) -> Result<(), String>;
    /// Forget the entry for `url`; not an error if there is none.
    fn remove(&self, url: &str) -> Result<(), String>;
}

// ── one JSON file ───────────────────────────────────────────────────────────────────────────────────────

pub struct JsonFile {
    path: PathBuf,
    entries: Mutex<BTreeMap<String, Entry>>,
}

impl JsonFile {
    /// Open (or start) the file at `path`.
    pub fn open(path: &Path) -> Result<JsonFile, String> {
        let mut entries = BTreeMap::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            let v: Value = serde_json::from_str(&text).map_err(|e| format!("index file: {e}"))?;
            for e in v.as_array().into_iter().flatten().filter_map(Entry::from_json) {
                entries.insert(e.url.clone(), e);
            }
        }
        Ok(JsonFile { path: path.to_path_buf(), entries: Mutex::new(entries) })
    }

    fn write(&self, m: &BTreeMap<String, Entry>) -> Result<(), String> {
        let tmp = self.path.with_extension("tmp");
        let text = Value::Array(m.values().map(Entry::to_json).collect()).to_string();
        std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, &self.path)).map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

impl Store for JsonFile {
    fn load(&self) -> Result<Vec<Entry>, String> {
        Ok(self.entries.lock().unwrap().values().cloned().collect())
    }
    fn put(&self, e: &Entry) -> Result<(), String> {
        let mut m = self.entries.lock().unwrap();
        m.insert(e.url.clone(), e.clone());
        self.write(&m)
    }
    fn remove(&self, url: &str) -> Result<(), String> {
        let mut m = self.entries.lock().unwrap();
        if m.remove(url).is_some() {
            self.write(&m)?;
        }
        Ok(())
    }
}

// ── Couchbase Lite ──────────────────────────────────────────────────────────────────────────────────────

const SCOPE: &str = "search";
const COLLECTION: &str = "entries";

enum Op {
    Load(mpsc::Sender<Result<Vec<Entry>, String>>),
    Put(String, Value, mpsc::Sender<Result<(), String>>),
    Remove(String, mpsc::Sender<Result<(), String>>),
}

/// The document id of an entry: a hash of its URL (a URL can be longer than an id may be).
fn doc_id(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(url.as_bytes());
    h.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Cbl {
    tx: Mutex<Option<mpsc::Sender<Op>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for Cbl {
    /// Close the database before the handle goes, so that it can be opened again at once.
    fn drop(&mut self) {
        self.tx.lock().unwrap().take();
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
    }
}

impl Cbl {
    /// Open (or create) the database `name` in `dir`.
    pub fn open(dir: &Path, name: &str) -> Result<Cbl, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let (tx, rx) = mpsc::channel::<Op>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (dir, name) = (dir.to_path_buf(), name.to_string());
        let handle = std::thread::Builder::new().name("search-store".into()).spawn(move || actor(dir, name, rx, ready_tx)).map_err(|e| e.to_string())?;
        ready_rx.recv().map_err(|_| "the store thread did not start".to_string())??;
        Ok(Cbl { tx: Mutex::new(Some(tx)), thread: Mutex::new(Some(handle)) })
    }

    fn ask<T>(&self, make: impl FnOnce(mpsc::Sender<Result<T, String>>) -> Op) -> Result<T, String> {
        let (rtx, rrx) = mpsc::channel();
        let guard = self.tx.lock().unwrap();
        guard.as_ref().ok_or("the store is closed")?.send(make(rtx)).map_err(|_| "the store thread is gone".to_string())?;
        drop(guard);
        rrx.recv().map_err(|_| "the store thread is gone".to_string())?
    }
}

impl Store for Cbl {
    fn load(&self) -> Result<Vec<Entry>, String> {
        self.ask(Op::Load)
    }
    fn put(&self, e: &Entry) -> Result<(), String> {
        self.ask(|r| Op::Put(doc_id(&e.url), e.to_json(), r))
    }
    fn remove(&self, url: &str) -> Result<(), String> {
        self.ask(|r| Op::Remove(doc_id(url), r))
    }
}

fn actor(dir: PathBuf, name: String, rx: mpsc::Receiver<Op>, ready: mpsc::Sender<Result<(), String>>) {
    use couchbase_lite::error::{CouchbaseLiteError, ErrorCode};
    use couchbase_lite::{Database, DatabaseConfiguration, Document, Query, QueryLanguage};
    let opened = Database::open(&name, Some(DatabaseConfiguration { directory: &dir, #[cfg(feature = "enterprise")] encryption_key: None }))
        .map_err(|e| format!("open the index database: {e}"))
        .and_then(|db| db.create_collection(COLLECTION.to_string(), SCOPE.to_string()).map(|c| (db, c)).map_err(|e| format!("index collection: {e}")));
    let (db, mut coll) = match opened {
        Ok(x) => {
            let _ = ready.send(Ok(()));
            x
        }
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let not_found = |e: &couchbase_lite::Error| e.code == ErrorCode::CouchbaseLite(CouchbaseLiteError::NotFound);
    while let Ok(op) = rx.recv() {
        match op {
            Op::Load(reply) => {
                let r = (|| {
                    let sql = format!("SELECT META().id AS id FROM {SCOPE}.{COLLECTION}");
                    let q = Query::new(&db, QueryLanguage::N1QL, &sql).map_err(|e| e.to_string())?;
                    let ids: Vec<String> = q.execute().map_err(|e| e.to_string())?.into_iter().filter_map(|row| row.get(0).as_string().map(str::to_owned)).collect();
                    let mut out = vec![];
                    for id in ids {
                        match coll.get_document(&id) {
                            Ok(d) => {
                                let v: Value = serde_json::from_str(&d.properties_as_json()).map_err(|e| e.to_string())?;
                                match Entry::from_json(&v) {
                                    Some(e) => out.push(e),
                                    None => log::warn!("index document {id} is not an entry; skipped"),
                                }
                            }
                            Err(e) if not_found(&e) => {}
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                    Ok(out)
                })();
                let _ = reply.send(r);
            }
            Op::Put(id, body, reply) => {
                let r = (|| {
                    let mut doc = match coll.get_document(&id) {
                        Ok(d) => d,
                        Err(e) if not_found(&e) => Document::new_with_id(&id),
                        Err(e) => return Err(e.to_string()),
                    };
                    doc.set_properties_as_json(&body.to_string()).map_err(|e| e.to_string())?;
                    coll.save_document(&mut doc).map_err(|e| e.to_string())
                })();
                let _ = reply.send(r);
            }
            Op::Remove(id, reply) => {
                let r = match coll.purge_document_by_id(&id) {
                    Ok(()) => Ok(()),
                    Err(e) if not_found(&e) => Ok(()),
                    Err(e) => Err(e.to_string()),
                };
                let _ = reply.send(r);
            }
        }
    }
    drop(coll);
    drop(db);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str, did: &str, name: &str) -> Entry {
        Entry { url: url.into(), did: did.into(), name: name.into(), description: format!("{name} does things"), protocols: vec!["A2A".into()], offers: vec!["rooms".into()], verified_at: 1_700_000_000 }
    }

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("anp-search-store-{tag}-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The same behaviour from both stores.
    fn exercise(open: &dyn Fn() -> Box<dyn Store>) {
        let long = format!("https://hotel.example.com/agents/{}/ad.json", "x".repeat(400));
        {
            let s = open();
            assert!(s.load().unwrap().is_empty());
            s.put(&entry("https://hotel.example.com/agents/a/ad.json", "did:a", "alpha")).unwrap();
            s.put(&entry("https://hotel.example.com/agents/b/ad.json", "did:b", "beta")).unwrap();
            s.put(&entry(&long, "did:c", "gamma")).unwrap();
            // the same URL again replaces the entry
            let mut changed = entry("https://hotel.example.com/agents/a/ad.json", "did:a", "alpha");
            changed.description = "alpha, changed".into();
            changed.verified_at += 10;
            s.put(&changed).unwrap();
            s.remove("https://hotel.example.com/agents/b/ad.json").unwrap();
            s.remove("https://never.example.com/there").unwrap();
        }
        // a new run sees exactly that
        let s = open();
        let mut got = s.load().unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["alpha", "gamma"]);
        assert_eq!(got[0].description, "alpha, changed");
        assert_eq!(got[0].verified_at, 1_700_000_010);
        assert_eq!(got[1].url, long, "a URL longer than a document id may be");
        assert_eq!(got[0].protocols, ["A2A"]);
    }

    #[test]
    fn the_json_file_keeps_entries_between_runs() {
        let dir = temp("json");
        exercise(&|| Box::new(JsonFile::open(&dir.join("index.json")).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn couchbase_lite_keeps_entries_between_runs_one_document_each() {
        let dir = temp("cbl");
        exercise(&|| Box::new(Cbl::open(&dir, "index").unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_service_on_a_database_starts_from_what_it_kept() {
        use crate::Service;
        use std::sync::Arc;
        struct Nothing;
        impl crate::Fetcher for Nothing {
            fn get_json(&self, _: &str) -> Result<Value, crate::service::FetchError> {
                Err(crate::service::FetchError::Gone)
            }
            fn did_document(&self, _: &str) -> Result<anp_did::Verified, String> {
                Err("no network".into())
            }
        }
        let dir = temp("svc");
        {
            let store: Arc<dyn Store> = Arc::new(Cbl::open(&dir, "index").unwrap());
            store.put(&entry("https://hotel.example.com/agents/a/ad.json", "did:a", "alpha")).unwrap();
        }
        let store: Arc<dyn Store> = Arc::new(Cbl::open(&dir, "index").unwrap());
        let s = Service::with_store(Arc::new(Nothing), Some(store)).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.search("alpha", None, 5)["results"][0]["did"], "did:a");
        // a withdrawn entry (its server says it is gone) is gone from the database too
        assert_eq!(s.refresh("https://hotel.example.com/agents/a/ad.json"), Ok("removed"));
        drop(s);
        let store: Arc<dyn Store> = Arc::new(Cbl::open(&dir, "index").unwrap());
        assert!(store.load().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}