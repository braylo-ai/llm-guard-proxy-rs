#![allow(dead_code)]
use llm_guard::audit::AuditSink;
use llm_guard::proxy::{handle, Call, Deps, Env, Fetcher, Request, Response};
use llm_guard::vault::MemoryVaultStore;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub fn env() -> Env {
    Env {
        mock_upstream: Some("1".into()),
        allow_unauthenticated: Some("1".into()),
        audit_salt: Some("t".into()),
        vault_secret: Some("t".into()),
        ..Default::default()
    }
}

pub struct Rig {
    pub deps: Deps,
    pub audit: Arc<AuditSink>,
    pub calls: Arc<Mutex<Vec<Call>>>,
}

pub fn mk_deps() -> Rig {
    let (fetcher, calls) = Fetcher::recording(Fetcher::Mock);
    let audit = Arc::new(AuditSink::memory());
    let deps = Deps { fetcher: Some(fetcher), audit: audit.clone(), vault_store: Arc::new(MemoryVaultStore::new()), classifier: None };
    Rig { deps, audit, calls }
}

pub async fn post_with(path: &str, body: &Value, headers: &[(&str, &str)], env: &Env, deps: &Deps) -> (Response, Value) {
    post_raw(path, serde_json::to_vec(body).unwrap(), headers, env, deps).await
}

pub async fn post_raw(path: &str, body: Vec<u8>, headers: &[(&str, &str)], env: &Env, deps: &Deps) -> (Response, Value) {
    let mut h: HashMap<String, String> = HashMap::new();
    h.insert("content-type".into(), "application/json".into());
    for (k, v) in headers {
        h.insert(k.to_string(), v.to_string());
    }
    let res = handle(Request { method: "POST".into(), path: path.into(), headers: h, body }, env, deps).await;
    let j = res.json();
    (res, j)
}

/// Post with default env and fresh deps.
pub async fn post(path: &str, body: &Value, headers: &[(&str, &str)]) -> (Response, Value) {
    post_with(path, body, headers, &env(), &mk_deps().deps).await
}

pub fn chat(content: &str) -> Value {
    json!({ "model": "m", "messages": [{ "role": "user", "content": content }] })
}
