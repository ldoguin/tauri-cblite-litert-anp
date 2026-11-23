//! An OpenRPC description of the node's JSON-RPC interface, for ANP clients that discover methods from an agent description
//! (`interfaces` entries of type `StructuredInterface`, protocol `openrpc`): the SDKs read it to learn the method names,
//! their parameters and where to call them, and turn them into tools for a language model.
//!
//! The methods are the A2A ones the node serves at `POST /`: `SendMessage`, `GetTask`, `ListTasks` and `CancelTask`
//! (streaming goes over SSE, which OpenRPC cannot describe, so it is left out). Parameters are passed by name.

use serde_json::{json, Value};

pub const OPENRPC_VERSION: &str = "1.3.2";

fn schema(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

/// The OpenRPC document of the node, calling `rpc_url` (where the JSON-RPC endpoint is) and described as `title`.
pub fn a2a_interface(title: &str, version: &str, rpc_url: &str) -> Value {
    json!({
        "openrpc": OPENRPC_VERSION,
        "info": { "title": title, "version": version, "description": format!("{title}: tasks for an agent, as JSON-RPC 2.0 (A2A methods)") },
        "servers": [{ "name": "node", "url": rpc_url }],
        "methods": [
            {
                "name": "SendMessage",
                "description": "Give the agent a message. It answers when the task has settled: the result is the task, with the agent's artifacts. A message carrying a taskId continues that task.",
                "paramStructure": "by-name",
                "params": [
                    { "name": "message", "required": true, "description": "The message to send", "schema": schema("Message") },
                    { "name": "configuration", "description": "How to run it", "schema": { "type": "object", "properties": {
                        "returnImmediately": { "type": "boolean", "description": "Answer with the task as it is, without waiting for it to settle" },
                        "historyLength": { "type": "integer", "description": "How many messages of history to include" } } } }
                ],
                "result": { "name": "response", "schema": { "type": "object", "properties": { "task": schema("Task") }, "required": ["task"] } },
                "errors": [{ "code": -32602, "message": "Invalid params" }, { "code": -32001, "message": "Task not found" }]
            },
            {
                "name": "GetTask",
                "description": "Fetch a task by its id, with its status, artifacts and (optionally) history.",
                "paramStructure": "by-name",
                "params": [
                    { "name": "id", "required": true, "description": "The task id", "schema": { "type": "string" } },
                    { "name": "historyLength", "description": "How many messages of history to include", "schema": { "type": "integer" } }
                ],
                "result": { "name": "task", "schema": schema("Task") },
                "errors": [{ "code": -32001, "message": "Task not found" }]
            },
            {
                "name": "ListTasks",
                "description": "List tasks, newest first, optionally of one context or one state, a page at a time.",
                "paramStructure": "by-name",
                "params": [
                    { "name": "contextId", "description": "Only tasks of this context", "schema": { "type": "string" } },
                    { "name": "status", "description": "Only tasks in this state", "schema": { "type": "string" } },
                    { "name": "pageSize", "description": "At most this many (1 to 100, default 50)", "schema": { "type": "integer" } },
                    { "name": "pageToken", "description": "The nextPageToken of the previous page", "schema": { "type": "string" } },
                    { "name": "historyLength", "description": "How many messages of history to include", "schema": { "type": "integer" } }
                ],
                "result": { "name": "page", "schema": { "type": "object", "properties": {
                    "tasks": { "type": "array", "items": schema("Task") },
                    "nextPageToken": { "type": "string" }, "pageSize": { "type": "integer" }, "totalSize": { "type": "integer" } } } }
            },
            {
                "name": "CancelTask",
                "description": "Ask the agent to stop working on a task. Answers with the task as it is afterwards.",
                "paramStructure": "by-name",
                "params": [{ "name": "id", "required": true, "description": "The task id", "schema": { "type": "string" } }],
                "result": { "name": "task", "schema": schema("Task") },
                "errors": [{ "code": -32001, "message": "Task not found" }, { "code": -32002, "message": "Task cannot be canceled" }]
            }
        ],
        "components": { "schemas": {
            "Part": { "type": "object", "description": "A piece of content: text, or a file or data reference", "properties": { "text": { "type": "string" } } },
            "Message": { "type": "object", "required": ["messageId", "role", "parts"], "properties": {
                "messageId": { "type": "string", "description": "A unique id for this message" },
                "role": { "type": "string", "enum": ["ROLE_USER", "ROLE_AGENT"] },
                "parts": { "type": "array", "items": schema("Part") },
                "taskId": { "type": "string", "description": "Continue this task" },
                "contextId": { "type": "string" } } },
            "Task": { "type": "object", "properties": {
                "id": { "type": "string" }, "contextId": { "type": "string" },
                "status": { "type": "object", "properties": { "state": { "type": "string" }, "message": schema("Message") } },
                "artifacts": { "type": "array", "items": { "type": "object", "properties": { "artifactId": { "type": "string" }, "parts": { "type": "array", "items": schema("Part") } } } },
                "history": { "type": "array", "items": schema("Message") } } }
        } }
    })
}

/// The structural rules the SDKs rely on: a version, a server with a URL, and methods that each have a name, a description,
/// a parameter list and a result.
pub fn check(doc: &Value) -> Result<(), String> {
    if doc["openrpc"].as_str().map_or(true, str::is_empty) {
        return Err("no openrpc version".into());
    }
    let server = doc["servers"].as_array().and_then(|s| s.first()).and_then(|s| s["url"].as_str());
    if server.map_or(true, str::is_empty) {
        return Err("no server url".into());
    }
    let methods = doc["methods"].as_array().ok_or("methods must be an array")?;
    if methods.is_empty() {
        return Err("no methods".into());
    }
    for (i, m) in methods.iter().enumerate() {
        if m["name"].as_str().map_or(true, str::is_empty) {
            return Err(format!("methods[{i}] has no name"));
        }
        if m["description"].as_str().map_or(true, str::is_empty) {
            return Err(format!("methods[{i}] has no description"));
        }
        let params = m["params"].as_array().ok_or_else(|| format!("methods[{i}].params must be an array"))?;
        for (j, p) in params.iter().enumerate() {
            if p["name"].as_str().map_or(true, str::is_empty) || !p["schema"].is_object() {
                return Err(format!("methods[{i}].params[{j}] needs a name and a schema"));
            }
        }
        if !m["result"].is_object() || !m["result"]["schema"].is_object() {
            return Err(format!("methods[{i}] has no result schema"));
        }
    }
    // every $ref must point at something that is there
    let mut refs = Vec::new();
    collect_refs(doc, &mut refs);
    for r in refs {
        let path = r.strip_prefix("#/").ok_or_else(|| format!("only local $ref is supported, got {r}"))?;
        let mut cur = doc;
        for seg in path.split('/') {
            cur = cur.get(seg).ok_or_else(|| format!("$ref {r} does not resolve"))?;
        }
    }
    Ok(())
}

fn collect_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "$ref" {
                    if let Some(s) = x.as_str() {
                        out.push(s.to_string());
                    }
                } else {
                    collect_refs(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_is_well_formed_and_names_the_node_s_methods() {
        let d = a2a_interface("Node", "1.0", "https://node.example.com/");
        check(&d).unwrap();
        let names: Vec<&str> = d["methods"].as_array().unwrap().iter().filter_map(|m| m["name"].as_str()).collect();
        assert_eq!(names, ["SendMessage", "GetTask", "ListTasks", "CancelTask"]);
        assert_eq!(d["servers"][0]["url"], "https://node.example.com/");
    }

    #[test]
    fn the_check_catches_what_the_sdks_would_choke_on() {
        let good = a2a_interface("Node", "1.0", "https://node.example.com/");
        let mut d = good.clone();
        d["methods"][0].as_object_mut().unwrap().remove("description");
        assert!(check(&d).is_err());
        let mut d = good.clone();
        d["servers"] = json!([]);
        assert!(check(&d).is_err());
        let mut d = good.clone();
        d["components"]["schemas"].as_object_mut().unwrap().remove("Message");
        assert!(check(&d).unwrap_err().contains("does not resolve"));
        let mut d = good;
        d["methods"][1]["params"][0].as_object_mut().unwrap().remove("schema");
        assert!(check(&d).is_err());
    }
}