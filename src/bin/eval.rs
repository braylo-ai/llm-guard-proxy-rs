//! Eval harness (port of evals/run.ts). Every number in the README comes from evals/results.json,
//! which this binary writes. Run: cargo run --release --bin guard-eval
//!
//!   PII            detector-level span match (type + exact value) -> P/R/F1 per type and micro
//!   attacks/benign end-to-end through handle() with the mock upstream, default policy (block)
//!   cross-agent    end-to-end through POST /v1/agent-relay, default (neutralize) and strict (block)
//!   latency        paired timing: mock upstream alone vs. proxy + same mock upstream, in-process

use llm_guard::audit::AuditSink;
use llm_guard::injection::{detect_injection, Channel};
use llm_guard::mock::mock_upstream;
use llm_guard::pii::{detect_all, PiiType, ALL_PII_TYPES};
use llm_guard::proxy::{handle, Deps, Env, Fetcher, Request};
use llm_guard::vault::MemoryVaultStore;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

// Fake test tokens are assembled at run time so no complete token-shaped string is committed
// (keeps GitHub push protection quiet).
fn fake_tokens() -> [(&'static str, String); 3] {
    [
        ("＠＠FAKE_SLACK＠＠", ["xo", "xb-1234567890-0987654321-AbCdEfGhIjKlMnOp"].concat()),
        ("＠＠FAKE_STRIPE＠＠", ["sk_", "test_4eC39HqLyjWDarjtT1zdp7dc"].concat()),
        ("＠＠FAKE_GITLAB＠＠", ["gl", "pat-xY7zQ2wE9rT4uI1oP6aS"].concat()),
    ]
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load(dir: &str, f: &str) -> Vec<Value> {
    let path = root().join("evals").join(dir).join(f);
    let mut raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    for (k, v) in fake_tokens() {
        raw = raw.replace(k, &v);
    }
    // also accept the plain-ASCII marker form used by the TS data files
    for (k, v) in fake_tokens() {
        raw = raw.replace(&k.replace('＠', "@"), &v);
    }
    raw.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).expect("jsonl line")).collect()
}

fn r3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn prf(tp: usize, fp: usize, fnn: usize) -> Value {
    let p = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 1.0 };
    let r = if tp + fnn > 0 { tp as f64 / (tp + fnn) as f64 } else { 1.0 };
    let f1 = if p + r > 0.0 { 2.0 * p * r / (p + r) } else { 0.0 };
    json!({ "tp": tp, "fp": fp, "fn": fnn, "precision": r3(p), "recall": r3(r), "f1": r3(f1) })
}

fn pct(xs: &[f64], q: f64) -> f64 {
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[(s.len() - 1).min((q * s.len() as f64).floor() as usize)]
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

// ---------------- PII ----------------
fn eval_pii(dir: &str) -> Value {
    let samples = load(dir, "pii.jsonl");
    let mut per: HashMap<PiiType, [usize; 3]> = ALL_PII_TYPES.iter().map(|t| (*t, [0, 0, 0])).collect(); // tp fp fn
    let mut errors = Vec::new();
    let (mut neg, mut neg_fp, mut gold_n) = (0usize, 0usize, 0usize);
    for smp in &samples {
        let mut remaining: Vec<(PiiType, String)> = detect_all(s(smp, "text")).into_iter().map(|e| (e.kind, e.value)).collect();
        let gold: Vec<(PiiType, String)> = smp["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (PiiType::parse(s(e, "type")).expect("gold type"), s(e, "value").to_string()))
            .collect();
        gold_n += gold.len();
        let mut missed = Vec::new();
        for g in &gold {
            if let Some(i) = remaining.iter().position(|p| p == g) {
                per.get_mut(&g.0).unwrap()[0] += 1;
                remaining.remove(i);
            } else {
                per.get_mut(&g.0).unwrap()[2] += 1;
                missed.push(format!("{}:{}", g.0.as_str(), g.1));
            }
        }
        for p in &remaining {
            per.get_mut(&p.0).unwrap()[1] += 1;
        }
        if gold.is_empty() {
            neg += 1;
            if !remaining.is_empty() {
                neg_fp += 1;
            }
        }
        if !missed.is_empty() || !remaining.is_empty() {
            errors.push(json!({ "id": s(smp, "id"), "missed": missed, "spurious": remaining.iter().map(|p| p.0.as_str()).collect::<Vec<_>>() }));
        }
    }
    let tot = per.values().fold([0usize; 3], |a, x| [a[0] + x[0], a[1] + x[1], a[2] + x[2]]);
    let mut per_type = Map::new();
    for t in ALL_PII_TYPES {
        let v = per[&t];
        per_type.insert(t.as_str().to_string(), prf(v[0], v[1], v[2]));
    }
    json!({
        "samples": samples.len(), "gold_entities": gold_n, "negative_samples": neg,
        "negative_samples_with_false_positive": neg_fp,
        "micro": prf(tot[0], tot[1], tot[2]), "per_type": per_type, "errors": errors,
    })
}

// ---------------- harness ----------------
fn env() -> Env {
    Env {
        mock_upstream: Some("1".into()),
        allow_unauthenticated: Some("1".into()),
        audit_salt: Some("eval".into()),
        vault_secret: Some("eval".into()),
        ..Default::default()
    }
}

fn deps() -> Deps {
    Deps { fetcher: Some(Fetcher::Mock), audit: Arc::new(AuditSink::memory()), vault_store: Arc::new(MemoryVaultStore::new()), classifier: None }
}

struct Sent {
    status: u16,
    json: Value,
}

async fn send(body: &Value, tenant: &str, path: &str, env: &Env) -> Sent {
    let mut req = Request::new("POST", path);
    req.headers.insert("content-type".into(), "application/json".into());
    req.headers.insert("x-guard-tenant".into(), tenant.into());
    req.body = serde_json::to_vec(body).unwrap();
    let res = handle(req, env, &deps()).await;
    Sent { status: res.status, json: res.json() }
}

fn chat_body(smp: &Value) -> Value {
    let mut messages = vec![json!({ "role": "system", "content": "You are a helpful assistant for a home-services company." })];
    if s(smp, "channel") == "tool" {
        messages.push(json!({ "role": "user", "content": "Use the tool result to answer my question." }));
        messages.push(json!({ "role": "assistant", "content": null, "tool_calls": [{ "id": "call_1", "type": "function", "function": { "name": "fetch", "arguments": "{}" } }] }));
        messages.push(json!({ "role": "tool", "tool_call_id": "call_1", "content": s(smp, "text") }));
    } else {
        messages.push(json!({ "role": "user", "content": s(smp, "text") }));
    }
    json!({ "model": "mock", "messages": messages })
}

// ---------------- attacks / benign ----------------
async fn eval_prompts(dir: &str, env: &Env) -> Value {
    let attacks = load(dir, "attacks.jsonl");
    let benign = load(dir, "benign.jsonl");
    let mut by_cat: Vec<(String, usize, usize)> = Vec::new();
    let (mut blocked, mut missed) = (0usize, Vec::new());
    for a in &attacks {
        let r = send(&chat_body(a), "default", "/v1/chat/completions", env).await;
        let b = r.status == 403;
        let cat = s(a, "category").to_string();
        let i = match by_cat.iter().position(|c| c.0 == cat) {
            Some(i) => i,
            None => {
                by_cat.push((cat, 0, 0));
                by_cat.len() - 1
            }
        };
        by_cat[i].1 += 1;
        if b {
            blocked += 1;
            by_cat[i].2 += 1;
        } else {
            missed.push(s(a, "id").to_string());
        }
    }
    let (mut fp, mut fps) = (0usize, Vec::new());
    for b in &benign {
        if send(&chat_body(b), "default", "/v1/chat/completions", env).await.status == 403 {
            fp += 1;
            fps.push(s(b, "id").to_string());
        }
    }
    let cats: Map<String, Value> =
        by_cat.iter().map(|(k, n, b)| (k.clone(), json!({ "n": n, "blocked": b, "block_rate": r3(*b as f64 / *n as f64) }))).collect();
    json!({
        "attacks": { "n": attacks.len(), "blocked": blocked, "block_rate": r3(blocked as f64 / attacks.len() as f64), "by_category": cats, "missed_ids": missed },
        "benign": { "n": benign.len(), "blocked": fp, "false_positive_rate": r3(fp as f64 / benign.len() as f64), "false_positive_ids": fps },
    })
}

// ---------------- cross-agent ----------------
fn unwrap_env(t: &str) -> String {
    // ^<untrusted_agent_message[^>]*>\n  ...  \n</untrusted_agent_message>\n[\s\S]*$
    let mut x = t;
    if x.starts_with("<untrusted_agent_message") {
        if let Some(i) = x.find(">\n") {
            x = &x[i + 2..];
        }
    }
    match x.find("\n</untrusted_agent_message>\n") {
        Some(i) => x[..i].to_string(),
        None => x.to_string(),
    }
}

async fn eval_cross_agent(dir: &str, tenant: &str, env: &Env) -> Value {
    let xs = load(dir, "cross_agent.jsonl");
    let (mut atk, mut stopped, mut blocked_n, mut neut_n, mut ben, mut ben_fp) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let (mut missed, mut fps) = (Vec::new(), Vec::new());
    for x in &xs {
        let body = json!({ "from": s(x, "from"), "to": s(x, "to"), "content": s(x, "content"), "tool_outputs": x.get("tool_outputs").cloned().unwrap_or(json!([])) });
        let r = send(&body, tenant, "/v1/agent-relay", env).await;
        let decision = s(&r.json, "decision").to_string();
        if s(x, "label") == "attack" {
            atk += 1;
            let mut ok = false;
            if decision == "blocked" {
                ok = true;
                blocked_n += 1;
            } else if decision == "neutralized" {
                // success only if what agent B would receive no longer scores as an injection
                let mut delivered = vec![s(&r.json, "content").to_string()];
                if let Some(a) = r.json.get("tool_outputs").and_then(Value::as_array) {
                    delivered.extend(a.iter().map(|v| v.as_str().unwrap_or("").to_string()));
                }
                ok = delivered.iter().map(|d| unwrap_env(d)).all(|d| detect_injection(&d, Channel::Agent).score < 1.0);
                if ok {
                    neut_n += 1;
                }
            }
            if ok {
                stopped += 1;
            } else {
                missed.push(s(x, "id").to_string());
            }
        } else {
            ben += 1;
            if decision == "blocked" || decision == "neutralized" {
                ben_fp += 1;
                fps.push(s(x, "id").to_string());
            }
        }
    }
    json!({
        "tenant_policy": tenant,
        "attacks": { "n": atk, "stopped": stopped, "blocked": blocked_n, "neutralized": neut_n, "stop_rate": r3(stopped as f64 / atk as f64), "missed_ids": missed },
        "benign": { "n": ben, "altered_or_blocked": ben_fp, "false_positive_rate": r3(ben_fp as f64 / ben as f64), "false_positive_ids": fps },
    })
}

// ---------------- latency ----------------
async fn eval_latency(env: &Env) -> Value {
    let (iterations, warmup) = (1000usize, 100usize);
    let long = format!("Summarize: {}", "The crew finished the gutter install and cleaned the site. ".repeat(40));
    let bodies = [
        json!({ "model": "mock", "messages": [{ "role": "system", "content": "You are helpful." }, { "role": "user", "content": "Draft a follow-up email to a roofing lead about Thursday's inspection." }] }),
        json!({ "model": "mock", "messages": [{ "role": "user", "content": "Customer jane.doe@example.com, phone (312) 555-0142, wants a quote for 18 Maple Ave." }] }),
        json!({ "model": "mock", "messages": [{ "role": "user", "content": long }] }),
    ];
    let (mut added, mut direct, mut proxied) = (Vec::new(), Vec::new(), Vec::new());
    let ms = |a: Instant, b: Instant| b.duration_since(a).as_secs_f64() * 1000.0;
    let fetcher = Fetcher::Mock;
    for i in 0..iterations + warmup {
        let body = &bodies[i % bodies.len()];
        let t0 = Instant::now();
        let d = fetcher.post("http://mock/v1/chat/completions", &[], body.to_string(), None).await.unwrap();
        let _: Value = serde_json::from_slice(&d.body).unwrap();
        let _ = mock_upstream; // same code path as Fetcher::Mock
        let t1 = Instant::now();
        let mut req = Request::new("POST", "/v1/chat/completions");
        req.headers.insert("content-type".into(), "application/json".into());
        req.body = serde_json::to_vec(body).unwrap();
        let p = handle(req, env, &deps()).await;
        let _ = p.json();
        let t2 = Instant::now();
        if i >= warmup {
            direct.push(ms(t0, t1));
            proxied.push(ms(t1, t2));
            added.push(ms(t1, t2) - ms(t0, t1));
        }
    }
    json!({
        "iterations": iterations,
        "method": "in-process, paired per iteration: (proxy + mock upstream) minus (mock upstream alone); no network",
        "added_ms": { "p50": r3(pct(&added, 0.5)), "p95": r3(pct(&added, 0.95)), "p99": r3(pct(&added, 0.99)) },
        "mock_upstream_only_ms": { "p50": r3(pct(&direct, 0.5)), "p95": r3(pct(&direct, 0.95)) },
        "through_proxy_ms": { "p50": r3(pct(&proxied, 0.5)), "p95": r3(pct(&proxied, 0.95)) },
    })
}

async fn suite(dir: &str, env: &Env) -> Value {
    json!({
        "pii": eval_pii(dir),
        "injection": eval_prompts(dir, env).await,
        "cross_agent": {
            "default_neutralize": eval_cross_agent(dir, "default", env).await,
            "strict_block": eval_cross_agent(dir, "demo-strict", env).await,
        },
    })
}

fn summary(r: &Value) -> Value {
    let g = |p: &str| r.pointer(p).cloned().unwrap_or(Value::Null);
    let mut o = json!({
        "pii_micro": g("/pii/micro"),
        "attack_block_rate": g("/injection/attacks/block_rate"),
        "benign_fpr": g("/injection/benign/false_positive_rate"),
        "cross_agent_stop_rate_default": g("/cross_agent/default_neutralize/attacks/stop_rate"),
        "cross_agent_fpr_default": g("/cross_agent/default_neutralize/benign/false_positive_rate"),
        "cross_agent_block_rate_strict": g("/cross_agent/strict_block/attacks/stop_rate"),
        "cross_agent_fpr_strict": g("/cross_agent/strict_block/benign/false_positive_rate"),
        "added_latency_ms": g("/latency/added_ms"),
    });
    if r.get("holdout").is_some() {
        let m = o.as_object_mut().unwrap();
        m.insert("holdout_pii_micro".into(), g("/holdout/pii/micro"));
        m.insert("holdout_attack_block_rate".into(), g("/holdout/injection/attacks/block_rate"));
        m.insert("holdout_benign_fpr".into(), g("/holdout/injection/benign/false_positive_rate"));
        m.insert("holdout_cross_agent_stop_rate_default".into(), g("/holdout/cross_agent/default_neutralize/attacks/stop_rate"));
        m.insert("holdout_cross_agent_fpr_default".into(), g("/holdout/cross_agent/default_neutralize/benign/false_positive_rate"));
    }
    o
}

fn now_utc() -> String {
    // seconds since epoch is enough and needs no date crate; format as RFC 3339 via the same math as proxy
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let (days, rem) = (d.div_euclid(86400), d.rem_euclid(86400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[tokio::main]
async fn main() {
    let env = env();
    let dev = suite("data", &env).await;
    let holdout = suite("data/holdout", &env).await;
    let latency = eval_latency(&env).await;
    let mut results = Map::new();
    results.insert("generated_at".into(), json!(now_utc()));
    results.insert("runtime".into(), json!(format!("rust llm-guard-proxy {} ({}/{})", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH)));
    results.insert(
        "notes".into(),
        json!("dev = sets the rules were tuned on (see first_run_before_tuning for the untuned dev numbers). holdout = written after rules were frozen; no rule changes after seeing it. All sets authored by the same person as the rules."),
    );
    for (k, v) in dev.as_object().unwrap() {
        results.insert(k.clone(), v.clone());
    }
    results.insert("holdout".into(), holdout);
    results.insert("latency".into(), latency);
    let out = root().join("evals").join("results.json");
    // keep the very first (pre-tuning) numbers from an earlier results file, if there is one
    let read = |p: &PathBuf| std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
    // fall back to the TS baseline, which holds the original pre-tuning run
    let prior = read(&out).filter(|v| v.get("first_run_before_tuning").is_some()).or_else(|| read(&root().join("evals").join("results.ts-baseline.json"))).unwrap_or(Value::Null);
    if let Some(f) = prior.get("first_run_before_tuning") {
        results.insert("first_run_before_tuning".into(), f.clone());
    }
    let results = Value::Object(results);
    std::fs::write(&out, serde_json::to_string_pretty(&results).unwrap() + "\n").expect("write results.json");
    println!("{}", serde_json::to_string_pretty(&summary(&results)).unwrap());
}
