//! ANP-08 active discovery: the `/.well-known/agent-descriptions` listing.
//!
//! A domain publishes a JSON-LD `CollectionPage` that lists the URLs of its public agent descriptions; long lists are
//! split over pages linked by `next`, and a client follows them until there is none. This module builds those pages,
//! parses them, and crawls them through a caller-supplied fetch function (so it works over HTTP, over a replicated
//! store, or in a test).
//!
//! Passive discovery (registering with a search agent) is not here: ANP-08 leaves the registration API to each search
//! agent's own description, so there is nothing standard to implement.

use crate::AdError;
use serde_json::{json, Value};
use std::collections::HashSet;

/// How many items a page holds.
pub const PAGE_SIZE: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub name: String,
    /// URL of the agent description document.
    pub id: String,
}

/// `scheme://authority` of an http(s) URL.
pub fn origin(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let scheme_len = url.len() - rest.len();
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    (end > 0).then(|| &url[..scheme_len + end])
}

/// The URL of page `page` (1-based) of the listing at `base`.
pub fn page_url(base: &str, page: usize) -> String {
    if page <= 1 {
        base.to_string()
    } else {
        format!("{base}?page={page}")
    }
}

/// Page `page` (1-based) of `items`, as the spec's JSON-LD `CollectionPage`. A page past the end is empty and has no
/// `next`.
pub fn collection_page(base: &str, items: &[Item], page: usize, size: usize) -> Value {
    let page = page.max(1);
    let size = size.max(1);
    let start = (page - 1).saturating_mul(size);
    let slice: &[Item] = if start < items.len() { &items[start..(start + size).min(items.len())] } else { &[] };
    let mut v = json!({
        "@context": {
            "@vocab": "https://schema.org/",
            "did": "https://w3id.org/did#",
            "ad": "https://agent-network-protocol.com/ad#",
        },
        "@type": "CollectionPage",
        "url": page_url(base, page),
        "items": slice.iter().map(|i| json!({ "@type": "ad:AgentDescription", "name": i.name, "@id": i.id })).collect::<Vec<_>>(),
    });
    if start + size < items.len() {
        v["next"] = json!(page_url(base, page + 1));
    }
    v
}

/// The agent-description items of a page, and its `next` link. Items of other types are ignored; an item without a
/// usable http(s) `@id` is an error (a client could not follow it).
pub fn parse_page(v: &Value) -> Result<(Vec<Item>, Option<String>), AdError> {
    let ty = v.get("@type").and_then(Value::as_str).unwrap_or("");
    if ty != "CollectionPage" && ty != "https://schema.org/CollectionPage" {
        return Err(AdError(format!("not a CollectionPage (@type is {ty:?})")));
    }
    let arr = v.get("items").and_then(Value::as_array).ok_or_else(|| AdError("a listing needs an 'items' array".into()))?;
    let mut items = Vec::new();
    for x in arr {
        let t = x.get("@type").and_then(Value::as_str).unwrap_or("");
        if t != "ad:AgentDescription" && !t.ends_with("AgentDescription") {
            continue;
        }
        let id = x.get("@id").and_then(Value::as_str).filter(|u| origin(u).is_some()).ok_or_else(|| AdError("an item has no http(s) @id".into()))?;
        items.push(Item { name: x.get("name").and_then(Value::as_str).unwrap_or("").to_string(), id: id.to_string() });
    }
    let next = match v.get("next") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if origin(s).is_some() => Some(s.clone()),
        Some(_) => return Err(AdError("'next' must be an http(s) URL".into())),
    };
    Ok((items, next))
}

/// Fetch a listing and every page it links to. `fetch` returns the parsed JSON at a URL. Safeguards a malicious or
/// broken server cannot get around: at most `max_pages` pages, a page is never fetched twice, `next` must stay on the
/// origin the crawl started from (no being sent to internal hosts), and the same description is listed once.
pub fn crawl(start: &str, max_pages: usize, fetch: &mut dyn FnMut(&str) -> Result<Value, String>) -> Result<Vec<Item>, AdError> {
    let home = origin(start).ok_or_else(|| AdError("the start URL must be http(s)".into()))?.to_string();
    let (mut seen_pages, mut seen_items) = (HashSet::new(), HashSet::new());
    let (mut out, mut url) = (Vec::new(), Some(start.to_string()));
    while let Some(u) = url.take() {
        if seen_pages.len() >= max_pages {
            return Err(AdError(format!("more than {max_pages} pages: refusing to follow on")));
        }
        if !seen_pages.insert(u.clone()) {
            return Err(AdError(format!("the listing loops back to {u}")));
        }
        let page = fetch(&u).map_err(|e| AdError(format!("fetching {u}: {e}")))?;
        let (items, next) = parse_page(&page)?;
        for i in items {
            if seen_items.insert(i.id.clone()) {
                out.push(i);
            }
        }
        if let Some(n) = next {
            if origin(&n) != Some(home.as_str()) {
                return Err(AdError(format!("'next' leaves the origin ({n})")));
            }
            url = Some(n);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(n: usize) -> Vec<Item> {
        (0..n).map(|i| Item { name: format!("agent{i}"), id: format!("https://example.com/agents/a{i}/ad.json") }).collect()
    }
    const BASE: &str = "https://example.com/.well-known/agent-descriptions";

    #[test]
    fn a_page_has_the_shape_the_spec_shows() {
        let p = collection_page(BASE, &items(2), 1, PAGE_SIZE);
        assert_eq!(p["@type"], "CollectionPage");
        assert_eq!(p["url"], BASE);
        assert_eq!(p["@context"]["ad"], "https://agent-network-protocol.com/ad#");
        assert_eq!(p["items"][0]["@type"], "ad:AgentDescription");
        assert_eq!(p["items"][1]["@id"], "https://example.com/agents/a1/ad.json");
        assert!(p.get("next").is_none(), "a single page has no next");
    }

    #[test]
    fn long_lists_are_paged_with_next() {
        let all = items(45);
        let p1 = collection_page(BASE, &all, 1, 20);
        assert_eq!(p1["items"].as_array().unwrap().len(), 20);
        assert_eq!(p1["next"], format!("{BASE}?page=2"));
        let p3 = collection_page(BASE, &all, 3, 20);
        assert_eq!(p3["items"].as_array().unwrap().len(), 5);
        assert!(p3.get("next").is_none());
        assert_eq!(p3["url"], format!("{BASE}?page=3"));
        let past = collection_page(BASE, &all, 9, 20);
        assert!(past["items"].as_array().unwrap().is_empty() && past.get("next").is_none());
        assert_eq!(collection_page(BASE, &all, 0, 20)["url"], BASE, "page 0 is page 1");
    }

    #[test]
    fn parse_round_trips_and_skips_other_types() {
        let (got, next) = parse_page(&collection_page(BASE, &items(3), 1, 2)).unwrap();
        assert_eq!(got, items(3)[..2].to_vec());
        assert_eq!(next.as_deref(), Some(format!("{BASE}?page=2").as_str()));
        let mixed = json!({ "@type": "CollectionPage", "items": [
            { "@type": "ad:AgentDescription", "name": "a", "@id": "https://x.example/ad.json" },
            { "@type": "schema:Person", "name": "not an agent", "@id": "https://x.example/p" } ] });
        assert_eq!(parse_page(&mixed).unwrap().0.len(), 1);
    }

    #[test]
    fn malformed_listings_are_refused() {
        assert!(parse_page(&json!({ "@type": "Thing", "items": [] })).is_err());
        assert!(parse_page(&json!({ "@type": "CollectionPage" })).is_err());
        assert!(parse_page(&json!({ "@type": "CollectionPage", "items": [{ "@type": "ad:AgentDescription", "@id": "ftp://x/ad.json" }] })).is_err());
        assert!(parse_page(&json!({ "@type": "CollectionPage", "items": [{ "@type": "ad:AgentDescription", "name": "no id" }] })).is_err());
        assert!(parse_page(&json!({ "@type": "CollectionPage", "items": [], "next": 5 })).is_err());
    }

    fn server(total: usize, size: usize) -> impl FnMut(&str) -> Result<Value, String> {
        let all = items(total);
        move |url: &str| {
            let page = url.split("?page=").nth(1).and_then(|p| p.parse().ok()).unwrap_or(1);
            Ok(collection_page(BASE, &all, page, size))
        }
    }

    #[test]
    fn a_crawl_follows_next_until_there_is_none() {
        let got = crawl(BASE, 10, &mut server(45, 20)).unwrap();
        assert_eq!(got, items(45));
    }

    #[test]
    fn a_crawl_has_limits_a_hostile_server_cannot_get_around() {
        assert!(crawl(BASE, 2, &mut server(100, 20)).unwrap_err().0.contains("more than 2 pages"));
        // a listing that points back at itself
        let mut looping = |_: &str| Ok(json!({ "@type": "CollectionPage", "items": [], "next": BASE }));
        assert!(crawl(BASE, 10, &mut looping).unwrap_err().0.contains("loops"));
        // a listing that sends the client to another origin (an internal service, say)
        let mut away = |_: &str| Ok(json!({ "@type": "CollectionPage", "items": [], "next": "http://169.254.169.254/latest" }));
        assert!(crawl(BASE, 10, &mut away).unwrap_err().0.contains("leaves the origin"));
        // fetch failures and bad pages are reported, not swallowed
        let mut broken = |_: &str| Err::<Value, String>("connection refused".into());
        assert!(crawl(BASE, 10, &mut broken).unwrap_err().0.contains("connection refused"));
        assert!(crawl("file:///etc/passwd", 10, &mut server(1, 1)).is_err());
        // duplicates across pages are listed once
        let mut dupes = |u: &str| {
            Ok(if u == BASE {
                json!({ "@type": "CollectionPage", "items": [{ "@type": "ad:AgentDescription", "@id": "https://example.com/a" }], "next": format!("{BASE}?page=2") })
            } else {
                json!({ "@type": "CollectionPage", "items": [{ "@type": "ad:AgentDescription", "@id": "https://example.com/a" }] })
            })
        };
        assert_eq!(crawl(BASE, 10, &mut dupes).unwrap().len(), 1);
    }

    #[test]
    fn origins_are_parsed_strictly() {
        assert_eq!(origin("https://a.example:8800/x?y"), Some("https://a.example:8800"));
        assert_eq!(origin("http://a.example"), Some("http://a.example"));
        assert_eq!(origin("ftp://a.example/x"), None);
        assert_eq!(origin("https:///x"), None);
    }
}
