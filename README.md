# llm-guard-proxy (Rust)

A security proxy for LLM APIs. It sits between your app (or between two agents) and an OpenAI-compatible or Anthropic Messages API. It is a Rust port of the TypeScript Cloudflare Worker `llm-guard-proxy`. It has no npm and no JavaScript tooling.

> **Headline:** the Rust port gives the same numbers as the TypeScript original on every eval set. On the held-out set, the rules block **10 of 25 attacks (40%)** at a **5% false-positive rate**. On the set they were tuned on, they block 68 of 68. That gap is the main finding. Regex rules are a cheap first layer. They are not a full defense.

## What it does

- **Gateway:** `POST /v1/chat/completions` (OpenAI) and `POST /v1/messages` (Anthropic). Change the base URL. Change nothing else.
- **Inbound:** PII and secret redaction with reversible placeholders. Prompt-injection detection on user, tool and agent content.
- **Outbound:** leak scan (secrets, PII), canary tokens, and exfiltration-URL checks. Text and tool-call arguments are both scanned.
- **Relay:** `POST /v1/agent-relay` removes embedded instructions from agent messages before the next agent sees them.
- **Policy:** JSON per tenant. **Audit log:** no raw PII, only salted fingerprints.

`stream=true` is refused with 400. The scanners need the full response.

## Run it

```bash
cargo run --release
```

The server listens on `127.0.0.1:8787`. With no API keys set, it uses the built-in mock upstream. Set `ALLOW_UNAUTHENTICATED=1` for local tests, or set `PROXY_AUTH_TOKEN`.

```bash
ALLOW_UNAUTHENTICATED=1 cargo run --release &
curl -s localhost:8787/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"m","messages":[{"role":"user","content":"mail jane@example.com"}]}'
```

If neither `PROXY_AUTH_TOKEN` nor `ALLOW_UNAUTHENTICATED=1` is set, every request gets 401. This is on purpose (fail closed).

| Variable | Meaning |
|---|---|
| `PROXY_AUTH_TOKEN` | Client token. Send it as `x-guard-key` or `Authorization: Bearer`. |
| `ALLOW_UNAUTHENTICATED` | `1` allows requests when no token is set. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` | Upstream keys. The client's own credential is never sent upstream. |
| `UPSTREAM_OPENAI_URL`, `UPSTREAM_ANTHROPIC_URL` | Upstream base URLs. |
| `MOCK_UPSTREAM` | `1` uses the mock. It is the default when no key is set. |
| `AUDIT_SALT`, `VAULT_SECRET` | Secrets for fingerprints and placeholders. Set them in production. |
| `POLICIES_JSON` | Per-tenant overrides, merged over `policies/default.json`. |
| `BIND` | Address and port. Default `127.0.0.1:8787`. |

Request headers: `x-guard-tenant` (policy), `x-guard-session` (stable placeholders across requests), `x-guard-mode: inter-agent`. Response headers: `x-guard-request-id`, `x-guard-decision`, `x-guard-flags`.

## How it is built

| File | Job |
|---|---|
| `src/proxy.rs` | The whole pipeline: `async fn handle(Request, &Env, &Deps) -> Response`. No HTTP types, so tests need no server. |
| `src/main.rs` | axum server around `handle`. Panics become a generic 500. |
| `src/adapters.rs` | OpenAI and Anthropic wire formats as JSON-pointer segments. |
| `src/pii.rs`, `vault.rs` | Seven PII types with validators. HMAC placeholders. |
| `src/injection.rs`, `normalize.rs` | Rules in 8 families over several text views. |
| `src/outbound.rs` | Canary, leak and exfil checks. |
| `src/policy.rs`, `audit.rs`, `mock.rs`, `rx.rs` | Policy, audit, mock upstream, JS-regex translation. |
| `src/bin/eval.rs` | The eval harness. |

Upstream calls go through a `Fetcher`: `Mock`, `Http` (reqwest, rustls) or `Recording` (wraps another one, for tests).

## Results

All numbers come from [`evals/results.json`](evals/results.json). Run `cargo run --release --bin guard-eval` to write it. The TypeScript run is kept in `evals/results.ts-baseline.json`. One person wrote the rules and every eval set. Treat all numbers as optimistic.

- **dev** = the sets the rules were tuned on.
- **holdout** = written after the rules were frozen.

| Metric | TypeScript | Rust |
|---|---|---|
| PII micro F1, dev (111 samples, 88 entities) | 0.989 | 0.989 |
| PII micro F1, holdout (30 samples) | 0.974 | 0.974 |
| Attacks blocked, dev | 68 / 68 | 68 / 68 |
| Benign blocked, dev | 1 / 45 (2.2%) | 1 / 45 (2.2%) |
| **Attacks blocked, holdout** | **10 / 25 (40%)** | **10 / 25 (40%)** |
| **Benign blocked, holdout** | **1 / 20 (5%)** | **1 / 20 (5%)** |
| Relay attacks stopped, dev, default (neutralize) | 24 / 24 | 24 / 24 |
| Relay attacks stopped, dev, strict (block) | 100% | 100% |
| Relay attacks stopped, holdout, default | 5 / 8 (62.5%) | 5 / 8 (62.5%) |
| Relay attacks stopped, holdout, strict | 6 / 8 (75%) | 6 / 8 (75%) |
| Relay benign altered, all runs | 0 | 0 |
| Added latency, p50 (in-process) | 0.32 ms | 0.70 ms |
| Added latency, p95 (in-process) | 0.59 ms | 9.1 ms |

Apart from latency, every field in `results.json` (per-type PII scores, per-category block rates, every missed id) is identical to the TypeScript file. A `jq` diff shows no change.

## Honest notes

- **The holdout gap is real.** 100% on the tuning set and 40% on the holdout means the rules fit the data they were tuned on. A classifier layer is the next step. The proxy already has a hook for one.
- **Latency is worse in Rust.** The rules use look-around, so they run on `fancy-regex`. That engine is slower than V8's regex engine. On a short prompt, the detectors take about 0.4 ms. On a 2.4 KB prompt they take about 6 ms, and that case sets the p95. The number is in-process and has no network. A real upstream call takes far longer. A fix is to move the patterns without look-around to the plain `regex` crate. This is not done.
- **Regex differences.** JavaScript `\d` and `\w` are ASCII only. Rust ones are Unicode-aware. `src/rx.rs` rewrites them to ASCII. Rust `\b` keeps Unicode rules. It differs from JavaScript only next to non-ASCII letters. No eval sample or test hits this.
- **The vault is in memory.** It has a TTL and a size cap. It is lost on restart and not shared between instances. The Cloudflare KV store from the TypeScript version is not ported.
- **Classifier hook.** It is a function in `Deps` (sync) or an HTTP URL in the policy. The mock upstream returns no score, so the URL form is only tested live.
- **Same author, same bias.** Rules and eval sets share one author. A third-party benchmark would tell more.
- **Placeholders in eval data.** The fake tokens in `evals/data/pii.jsonl` are markers like `@@FAKE_SLACK@@`. The harness fills them in at run time. No complete token-shaped string is committed.

## Tests

```bash
cargo test
```

53 tests in `tests/`: PII, injection, vault, relay and proxy. They port every test of the TypeScript version, plus a few new ones (classifier fail-open and fail-closed, header validation, 404 and 405, Anthropic `tool_use` round trip).

`cargo audit` reports no known vulnerabilities in `Cargo.lock` (advisory database of 2026-11-13).

## License

MIT. See [LICENSE](LICENSE).
