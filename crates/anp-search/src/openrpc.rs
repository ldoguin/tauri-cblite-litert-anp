//! The search agent's own interface, as OpenRPC (what its agent description points at).

use serde_json::{json, Value};

pub fn interface(rpc_url: &str) -> Value {
    let s = |t: &str| json!({ "type": t });
    json!({
        "openrpc": anp_ad::openrpc::OPENRPC_VERSION,
        "info": { "title": "ANP search agent", "version": "1.0", "description": "Register an agent description, or crawl a domain, then search what verified." },
        "servers": [{ "name": "search", "url": rpc_url }],
        "methods": [
            { "name": "register", "paramStructure": "by-name",
              "description": "Register an agent description by its URL. It is fetched over HTTPS, and indexed only if it names the URL it was fetched from, names a did:wba DID on that same domain, and carries a proof that verifies against that DID's document.",
              "params": [{ "name": "url", "required": true, "description": "https URL of the agent description (ad.json)", "schema": s("string") }],
              "result": { "name": "entry", "schema": { "type": "object", "description": "The indexed entry: url, did, name, description, protocols, offers, verifiedAt" } } },
            { "name": "crawl", "paramStructure": "by-name",
              "description": "Active discovery of a domain: read its /.well-known/agent-descriptions listing and register each description that verifies (at most 50, from that domain only).",
              "params": [{ "name": "domain", "required": true, "description": "host or host:port", "schema": s("string") }],
              "result": { "name": "report", "schema": { "type": "object", "description": "listed, registered, refused (with reasons), otherOrigin, beyondLimit" } } },
            { "name": "refresh", "paramStructure": "by-name",
              "description": "Check a registered description again: it is updated if it still verifies, removed if its server says it is gone, kept (with an error) if it cannot be fetched or no longer verifies. This is also how an agent withdraws: take the description down, then ask for a refresh.",
              "params": [{ "name": "url", "required": true, "description": "the registered description URL", "schema": s("string") }],
              "result": { "name": "outcome", "schema": { "type": "object", "properties": { "result": { "type": "string", "enum": ["updated", "removed"] } } } } },
            { "name": "search", "paramStructure": "by-name",
              "description": "Find registered agents by the words in their name, description and what they offer; best match first.",
              "params": [
                { "name": "query", "required": true, "description": "words to look for", "schema": s("string") },
                { "name": "protocol", "description": "only agents that speak this interface protocol (A2A, openrpc, ...)", "schema": s("string") },
                { "name": "limit", "description": "at most this many (1 to 100, default 10)", "schema": s("integer") } ],
              "result": { "name": "results", "schema": { "type": "object", "properties": { "query": s("string"), "results": { "type": "array", "items": { "type": "object" } } } } } },
            { "name": "search_handle", "paramStructure": "by-name",
              "description": "The registered agents of the DID a WNS handle (ANP-04, such as alice.example.com) names. The handle is resolved and the binding verified both ways (the provider says the handle is that DID, and the DID's document declares the provider); answers are cached for the provider's ttl, and a binding older than one already seen is refused.",
              "params": [
                { "name": "handle", "required": true, "description": "a handle or a wba:// URI", "schema": s("string") },
                { "name": "limit", "description": "at most this many (1 to 100, default 10)", "schema": s("integer") } ],
              "result": { "name": "results", "schema": { "type": "object", "properties": { "handle": s("string"), "did": s("string"), "results": { "type": "array", "items": { "type": "object" } } } } } },
            { "name": "list", "paramStructure": "by-name",
              "description": "Everything registered, a page at a time.",
              "params": [
                { "name": "offset", "description": "entries to skip", "schema": s("integer") },
                { "name": "limit", "description": "at most this many (1 to 100, default 50)", "schema": s("integer") } ],
              "result": { "name": "page", "schema": { "type": "object", "properties": { "total": s("integer"), "entries": { "type": "array", "items": { "type": "object" } } } } } }
        ]
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_is_a_well_formed_openrpc_document() {
        let d = super::interface("https://search.example.com/");
        anp_ad::openrpc::check(&d).unwrap();
        assert_eq!(d["methods"].as_array().unwrap().len(), 6);
    }
}