//! The index: entries, ranking and persistence. No network here.

use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Entries kept at most; a registration beyond this is refused rather than evicting someone.
pub const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// Where the description lives (its identity in the index).
    pub url: String,
    pub did: String,
    pub name: String,
    pub description: String,
    /// The interface protocols (`A2A`, `openrpc`, ...).
    pub protocols: Vec<String>,
    /// Descriptions of its information and interface entries: what it offers, in its own words.
    pub offers: Vec<String>,
    /// Seconds since the epoch of the last successful verification.
    pub verified_at: i64,
}

impl Entry {
    /// What goes in the index from a description that has already been verified.
    pub fn from_ad(url: &str, ad: &Value, now: i64) -> Entry {
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let mut protocols: Vec<String> = ad["interfaces"].as_array().into_iter().flatten().map(|i| s(&i["protocol"])).filter(|p| !p.is_empty()).collect();
        protocols.sort();
        protocols.dedup();
        let offers = ad["Infomations"].as_array().into_iter().flatten().chain(ad["interfaces"].as_array().into_iter().flatten()).map(|x| s(&x["description"])).filter(|d| !d.is_empty()).collect();
        Entry { url: url.to_string(), did: s(&ad["did"]), name: s(&ad["name"]), description: s(&ad["description"]), protocols, offers, verified_at: now }
    }

    pub fn to_json(&self) -> Value {
        json!({ "url": self.url, "did": self.did, "name": self.name, "description": self.description, "protocols": self.protocols, "offers": self.offers, "verifiedAt": self.verified_at })
    }

    pub fn from_json(v: &Value) -> Option<Entry> {
        let s = |k: &str| v[k].as_str().map(str::to_string);
        let list = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>());
        Some(Entry { url: s("url")?, did: s("did")?, name: s("name")?, description: s("description").unwrap_or_default(), protocols: list("protocols")?, offers: list("offers")?, verified_at: v["verifiedAt"].as_i64()? })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub entry: Entry,
    pub score: u32,
}

impl Match {
    pub fn to_json(&self) -> Value {
        let mut v = self.entry.to_json();
        v["score"] = json!(self.score);
        v
    }
}

/// A light English stemmer: plural and verb endings, so that `claims`, `claim` and `claiming` meet. It only touches words long
/// enough that the stem stays recognisable.
fn stem(w: &str) -> String {
    let n = w.chars().count();
    let cut = |k: usize| w.chars().take(n - k).collect::<String>();
    if n > 4 && w.ends_with("ies") {
        format!("{}y", cut(3))
    } else if n > 5 && w.ends_with("ing") {
        cut(3)
    } else if n > 4 && w.ends_with("ed") {
        cut(2)
    } else if n > 4 && w.ends_with("es") && !w.ends_with("ses") {
        cut(2)
    } else if n > 3 && w.ends_with('s') && !w.ends_with("ss") {
        cut(1)
    } else {
        w.to_string()
    }
}

fn tokens(s: &str) -> Vec<String> {
    s.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|t| t.chars().count() > 1).map(stem).collect()
}

/// Edit distance (insert, delete, replace, or swap of two neighbours), stopping early above `max`.
fn distance(a: &str, b: &str, max: usize) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len().abs_diff(b.len()) > max {
        return max + 1;
    }
    let mut prev2: Vec<usize> = vec![];
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                cur[j] = cur[j].min(prev2[j - 2] + 1);
            }
        }
        prev2 = prev;
        prev = cur;
    }
    prev[b.len()]
}

/// How many typos a query word of this length is allowed: none for short words, one from five letters, two from nine.
fn typos_allowed(len: usize) -> usize {
    match len {
        0..=4 => 0,
        5..=8 => 1,
        _ => 2,
    }
}

/// Matches of a query word in a field: whole words count fully, a word that merely starts with it (three letters or more)
/// counts half, and a word within the typos allowed for the query word's length counts 0.3 (a misspelt `hotle` still finds `hotel`).
fn hits(field: &[String], q: &str) -> f64 {
    let allowed = typos_allowed(q.chars().count());
    field
        .iter()
        .map(|t| {
            if t == q {
                1.0
            } else if q.chars().count() >= 3 && t.starts_with(q) {
                0.5
            } else if allowed > 0 && distance(t, q, allowed) <= allowed {
                0.3
            } else {
                0.0
            }
        })
        .sum()
}
#[derive(Default)]
pub struct Index {
    entries: BTreeMap<String, Entry>,
}

impl Index {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add or replace the entry for a description URL. A DID may have several descriptions, but a description URL is one
    /// entry, and a different DID cannot take over a URL that another DID holds until that one is removed.
    pub fn put(&mut self, e: Entry) -> Result<bool, String> {
        match self.entries.get(&e.url) {
            Some(old) if old.did != e.did => return Err(format!("{} is held by another DID", e.url)),
            None if self.entries.len() >= MAX_ENTRIES => return Err("the index is full".into()),
            _ => {}
        }
        Ok(self.entries.insert(e.url.clone(), e).is_none())
    }

    pub fn remove(&mut self, url: &str) -> bool {
        self.entries.remove(url).is_some()
    }

    pub fn get(&self, url: &str) -> Option<&Entry> {
        self.entries.get(url)
    }

    /// Every entry of a DID (an agent may have several descriptions).
    pub fn by_did(&self, did: &str) -> Vec<&Entry> {
        self.entries.values().filter(|e| e.did == did).collect()
    }

    pub fn list(&self) -> Vec<&Entry> {
        self.entries.values().collect()
    }

    /// Entries matching the words of `query`, best first; ties by name. Words are stemmed, and a query word of three letters or
    /// more also matches words that start with it, at half weight. A match in the name counts most, then the description, then
    /// what the agent offers, and a word that few agents use counts more than one that many do (inverse document frequency, as
    /// in BM25 without length normalisation). `protocol` keeps only agents that speak it. An empty query matches nothing: use
    /// `list` for everything. The score is the weighted sum, times 100, rounded.
    pub fn search(&self, query: &str, protocol: Option<&str>, limit: usize) -> Vec<Match> {
        let mut words = tokens(query);
        words.dedup();
        if words.is_empty() {
            return vec![];
        }
        let docs: Vec<(&Entry, Vec<String>, Vec<String>, Vec<String>)> =
            self.entries.values().map(|e| (e, tokens(&e.name), tokens(&e.description), e.offers.iter().flat_map(|o| tokens(o)).collect())).collect();
        let n = docs.len() as f64;
        // how rare each query word is across everything indexed
        let idf: Vec<f64> = words
            .iter()
            .map(|w| {
                let df = docs.iter().filter(|(_, a, b, c)| hits(a, w) + hits(b, w) + hits(c, w) > 0.0).count() as f64;
                (1.0 + (n - df + 0.5) / (df + 0.5)).ln()
            })
            .collect();
        let mut out: Vec<Match> = docs
            .iter()
            .filter(|(e, ..)| protocol.map_or(true, |p| e.protocols.iter().any(|x| x.eq_ignore_ascii_case(p))))
            .filter_map(|(e, name, desc, offers)| {
                let s: f64 = words.iter().zip(&idf).map(|(w, i)| i * (6.0 * hits(name, w) + 3.0 * hits(desc, w) + hits(offers, w))).sum();
                let score = (s * 100.0).round() as u32;
                (score > 0).then(|| Match { entry: (*e).clone(), score })
            })
            .collect();
        out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.entry.name.cmp(&b.entry.name)));
        out.truncate(limit);
        out
    }
    pub fn to_json(&self) -> Value {
        Value::Array(self.entries.values().map(Entry::to_json).collect())
    }

    pub fn from_json(v: &Value) -> Index {
        let mut i = Index::default();
        for e in v.as_array().into_iter().flatten().filter_map(Entry::from_json) {
            i.entries.insert(e.url.clone(), e);
        }
        i
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str, did: &str, name: &str, desc: &str, offers: &[&str], protocols: &[&str]) -> Entry {
        Entry { url: url.into(), did: did.into(), name: name.into(), description: desc.into(), protocols: protocols.iter().map(|s| s.to_string()).collect(), offers: offers.iter().map(|s| s.to_string()).collect(), verified_at: 1 }
    }
    fn sample() -> Index {
        let mut i = Index::default();
        i.put(entry("https://a.example.com/ad.json", "did:a", "Hotel Concierge", "Books rooms and answers questions about the hotel", &["Room policies", "Booking: reserve a room"], &["A2A", "openrpc"])).unwrap();
        i.put(entry("https://b.example.com/ad.json", "did:b", "Flight Desk", "Finds flights; can also book a hotel room on request", &["Flight search"], &["A2A"])).unwrap();
        i.put(entry("https://c.example.com/ad.json", "did:c", "Claims Reviewer", "Reviews insurance claims", &["Claim triage"], &["openrpc"])).unwrap();
        i
    }

    #[test]
    fn the_best_match_comes_first_and_the_name_counts_most() {
        let r = sample().search("hotel", None, 10);
        assert_eq!(r.iter().map(|m| m.entry.name.as_str()).collect::<Vec<_>>(), ["Hotel Concierge", "Flight Desk"]);
        assert!(r[0].score > r[1].score);
    }

    #[test]
    fn words_are_stemmed_and_case_does_not_matter() {
        let i = sample();
        assert_eq!(i.search("CLAIMS", None, 10).len(), 1);
        assert_eq!(i.search("claim", None, 10).len(), 1, "claim and claims are one word");
        assert_eq!(i.search("booking", None, 10).len(), 2, "booking meets Books and book: both the concierge and the flight desk");
        assert!(i.search("", None, 10).is_empty());
        assert!(i.search("!!", None, 10).is_empty());
    }

    #[test]
    fn a_prefix_counts_half_and_a_short_one_not_at_all() {
        let i = sample();
        let whole = i.search("flight", None, 10);
        let prefix = i.search("fligh", None, 10);
        assert_eq!(prefix.len(), 1, "three letters or more also match words that start with them");
        assert!(prefix[0].score < whole[0].score, "but for less");
        assert!(i.search("fl", None, 10).is_empty(), "two letters match whole words only");
    }

    #[test]
    fn a_word_few_agents_use_counts_more_than_a_common_one() {
        let mut i = Index::default();
        for n in 0..6 {
            i.put(entry(&format!("https://c{n}.example.com/ad.json"), &format!("did:c{n}"), &format!("Agent {n}"), "handles requests", &[], &[])).unwrap();
        }
        i.put(entry("https://z.example.com/ad.json", "did:z", "Zebra", "handles requests and zoology questions", &[], &[])).unwrap();
        let common = i.search("requests", None, 20);
        let rare = i.search("zoology", None, 20);
        assert_eq!(rare.len(), 1);
        assert!(rare[0].score > common[0].score, "{} > {}", rare[0].score, common[0].score);
        assert_eq!(i.search("requests zoology", None, 20)[0].entry.name, "Zebra");
    }

    #[test]
    fn a_misspelt_word_still_finds_its_agent_for_less() {
        let i = sample();
        let exact = i.search("concierge", None, 10);
        for typo in ["concierge", "concirege", "conciege", "concierje"] {
            let r = i.search(typo, None, 10);
            assert_eq!(r.first().map(|m| m.entry.name.as_str()), Some("Hotel Concierge"), "{typo}");
        }
        assert!(i.search("concirege", None, 10)[0].score < exact[0].score, "a typo counts less than the word");
        assert!(i.search("hotl", None, 10).is_empty(), "a four-letter word is allowed no typo");
        assert!(!i.search("hotle", None, 10).is_empty(), "a five-letter word is allowed one");
        assert!(i.search("flghts", None, 10).len() == 1, "one letter missing from a six-letter word (flights)");
        assert_eq!(distance("hotel", "hotle", 2), 1, "a swap is one edit");
        assert!(i.search("zzzzzz", None, 10).is_empty());
    }

    #[test]
    fn the_stemmer_leaves_short_words_alone() {
        for (w, s) in [("claims", "claim"), ("policies", "policy"), ("booking", "book"), ("booked", "book"), ("boxes", "box"), ("is", "is"), ("bus", "bus"), ("glass", "glass"), ("rooms", "room"), ("sing", "sing")] {
            assert_eq!(stem(w), s, "{w}");
        }
    }
    #[test]
    fn a_protocol_filter_and_a_limit_apply() {
        let i = sample();
        let r = i.search("hotel", Some("openrpc"), 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].entry.did, "did:a");
        assert_eq!(i.search("hotel", None, 1).len(), 1);
        assert_eq!(i.search("hotel", Some("OPENRPC"), 10).len(), 1, "protocol names are matched without regard to case");
    }

    #[test]
    fn a_url_belongs_to_the_did_that_first_held_it() {
        let mut i = sample();
        assert!(i.put(entry("https://a.example.com/ad.json", "did:evil", "x", "", &[], &[])).is_err());
        assert_eq!(i.put(entry("https://a.example.com/ad.json", "did:a", "Hotel Concierge v2", "", &[], &[])), Ok(false), "the owner can update");
        assert_eq!(i.get("https://a.example.com/ad.json").unwrap().name, "Hotel Concierge v2");
        assert!(i.remove("https://a.example.com/ad.json"));
        assert_eq!(i.put(entry("https://a.example.com/ad.json", "did:evil", "x", "", &[], &[])), Ok(true), "free once removed");
    }

    #[test]
    fn the_index_survives_a_round_trip_and_has_a_ceiling() {
        let i = sample();
        let back = Index::from_json(&i.to_json());
        assert_eq!(back.list(), i.list());
        let mut full = Index::default();
        for n in 0..MAX_ENTRIES {
            full.put(entry(&format!("https://h.example.com/{n}"), "did:x", "n", "", &[], &[])).unwrap();
        }
        assert!(full.put(entry("https://h.example.com/one-more", "did:x", "n", "", &[], &[])).is_err());
        assert!(full.put(entry("https://h.example.com/3", "did:x", "again", "", &[], &[])).is_ok(), "updating is still fine when full");
    }
}