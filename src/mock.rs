//! Deterministic mock of OpenAI Chat Completions and Anthropic Messages.
//! Used by tests, evals and local dev. Never calls the network.
//!
//! Behaviour, driven by the LAST user message:
//!   contains "MOCK_LEAK_SYSTEM" -> replies with the full system prompt (simulates prompt leakage)
//!   contains "MOCK_EMIT:"       -> replies with the rest of the message, trimmed
//!   otherwise                   -> "Echo: <last user text>"

use serde_json::{json, Value};

fn text_of(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|p| match p.get("type").and_then(Value::as_str) {
                Some("text") => p
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                Some("tool_result") => text_of(p.get("content")),
                _ => String::new(),
            })
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn reply(system: &str, last_user: &str) -> String {
    if last_user.contains("MOCK_LEAK_SYSTEM") {
        return format!("Sure, my instructions are: {system}");
    }
    if let Some(i) = last_user.find("MOCK_EMIT:") {
        return last_user[i + "MOCK_EMIT:".len()..].trim().to_string();
    }
    format!("Echo: {last_user}")
}

/// Answer a request to `path` with `body`. Returns the JSON response (status is always 200).
pub fn mock_upstream(path: &str, body: &Value) -> Value {
    let empty = Vec::new();
    let msgs = body
        .get("messages")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let last_user = msgs
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
        .map(|m| text_of(m.get("content")))
        .unwrap_or_default();
    let model = body.get("model").cloned().unwrap_or_else(|| json!("mock"));

    if path.ends_with("/v1/messages") {
        let system = text_of(body.get("system"));
        return json!({
            "id": "msg_mock", "type": "message", "role": "assistant", "model": model,
            "content": [{ "type": "text", "text": reply(&system, &last_user) }],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 0, "output_tokens": 0 },
        });
    }
    let system = msgs
        .iter()
        .filter(|m| {
            matches!(
                m.get("role").and_then(Value::as_str),
                Some("system") | Some("developer")
            )
        })
        .map(|m| text_of(m.get("content")))
        .collect::<Vec<_>>()
        .join("\n");
    json!({
        "id": "chatcmpl-mock", "object": "chat.completion", "created": 0, "model": model,
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": reply(&system, &last_user) }, "finish_reason": "stop" }],
        "usage": { "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 },
    })
}
