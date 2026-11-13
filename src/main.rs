//! llm-guard-proxy server: axum in front of `proxy::handle`.
//!
//! Env: UPSTREAM_OPENAI_URL, UPSTREAM_ANTHROPIC_URL, OPENAI_API_KEY, ANTHROPIC_API_KEY, PROXY_AUTH_TOKEN,
//! ALLOW_UNAUTHENTICATED, MOCK_UPSTREAM, AUDIT_SALT, VAULT_SECRET, POLICIES_JSON, BIND (default 127.0.0.1:8787).

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::Router;
use llm_guard::proxy::{handle, Deps, Env, Request};
use std::collections::HashMap;
use std::sync::Arc;

struct App {
    env: Env,
    deps: Deps,
}

fn var(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn internal_error() -> axum::response::Response {
    // never echo internals (could include request content)
    let mut r = axum::response::Response::new(axum::body::Body::from(r#"{"error":{"type":"guard_internal_error","message":"internal error"}}"#));
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
    r
}

async fn serve(State(app): State<Arc<App>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> axum::response::Response {
    let mut h = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            h.insert(k.as_str().to_string(), s.to_string());
        }
    }
    let req = Request { method: method.as_str().to_string(), path: uri.path().to_string(), headers: h, body: body.to_vec() };
    // run in a task so a panic becomes a generic 500, not a dropped connection
    let a = app.clone();
    let res = tokio::spawn(async move { handle(req, &a.env, &a.deps).await }).await;
    let Ok(res) = res else { return internal_error() };
    let mut out = axum::response::Response::new(axum::body::Body::from(res.body));
    *out.status_mut() = StatusCode::from_u16(res.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (k, v) in res.headers {
        if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
            out.headers_mut().append(k, v);
        }
    }
    out
}

#[tokio::main]
async fn main() {
    let key_set = var("OPENAI_API_KEY").is_some() || var("ANTHROPIC_API_KEY").is_some();
    let auth = var("PROXY_AUTH_TOKEN");
    let env = Env {
        upstream_openai_url: var("UPSTREAM_OPENAI_URL"),
        upstream_anthropic_url: var("UPSTREAM_ANTHROPIC_URL"),
        openai_api_key: var("OPENAI_API_KEY"),
        anthropic_api_key: var("ANTHROPIC_API_KEY"),
        proxy_auth_token: auth.clone(),
        allow_unauthenticated: var("ALLOW_UNAUTHENTICATED"),
        // with no upstream keys, default to the mock so local dev works out of the box
        mock_upstream: var("MOCK_UPSTREAM").or_else(|| if key_set { None } else { Some("1".into()) }),
        audit_salt: var("AUDIT_SALT"),
        vault_secret: var("VAULT_SECRET"),
        policies_json: var("POLICIES_JSON"),
    };
    if auth.is_none() && env.allow_unauthenticated.as_deref() != Some("1") {
        eprintln!("warning: PROXY_AUTH_TOKEN is not set and ALLOW_UNAUTHENTICATED is not 1: every request will get 401 (fail closed).");
    }
    let bind = var("BIND").unwrap_or_else(|| "127.0.0.1:8787".into());
    let mock = env.mock_upstream.as_deref() == Some("1");
    let app = Arc::new(App { env, deps: Deps::default() });
    let router = Router::new().fallback(serve).layer(DefaultBodyLimit::max(16 * 1024 * 1024)).with_state(app);
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {bind}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("llm-guard-proxy listening on http://{bind}  mock={mock}");
    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
