//! Wire-format adapters. Each exposes the text segments of a request or response as JSON-pointer
//! handles, so the pipeline does not care about the wire format.

use crate::injection::Channel;
use serde_json::{json, Value};

/// A text location inside a JSON document.
#[derive(Clone, Debug)]
pub struct Segment {
    pub channel: Channel,
    /// RFC 6901 JSON pointer into the document.
    pub ptr: String,
    /// True when the value at `ptr` is a JSON value (Anthropic tool_use input) shown as JSON text.
    pub json_text: bool,
}

impl Segment {
    fn text(channel: Channel, ptr: String) -> Self {
        Segment {
            channel,
            ptr,
            json_text: false,
        }
    }

    pub fn get(&self, doc: &Value) -> String {
        match doc.pointer(&self.ptr) {
            Some(v) if self.json_text => serde_json::to_string(v).unwrap_or_default(),
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    }

    /// Write a new value. For JSON-text segments the text is parsed back; invalid JSON => Err
    /// and the caller must block.
    pub fn set(&self, doc: &mut Value, v: String) -> Result<(), ()> {
        let Some(slot) = doc.pointer_mut(&self.ptr) else {
            return Err(());
        };
        if self.json_text {
            *slot = serde_json::from_str(&v).map_err(|_| ())?;
        } else {
            *slot = Value::String(v);
        }
        Ok(())
    }
}

fn text_parts(container: &Value, base: &str, key: &str, channel: Channel, out: &mut Vec<Segment>) {
    match container.get(key) {
        Some(Value::String(_)) => out.push(Segment::text(channel, format!("{base}/{key}"))),
        Some(Value::Array(parts)) => {
            for (i, part) in parts.iter().enumerate() {
                if part.get("type").and_then(Value::as_str) == Some("text")
                    && part.get("text").is_some_and(Value::is_string)
                {
                    out.push(Segment::text(channel, format!("{base}/{key}/{i}/text")));
                }
            }
        }
        _ => {}
    }
}

fn role_channel(role: Option<&str>) -> Channel {
    match role {
        Some("system") | Some("developer") => Channel::System,
        Some("assistant") => Channel::Assistant,
        Some("tool") | Some("function") => Channel::Tool,
        _ => Channel::User,
    }
}

const MSG_ERR: &str = "messages must be an array";

// ---------------- OpenAI Chat Completions ----------------

pub fn openai_request_segments(body: &Value) -> Result<Vec<Segment>, String> {
    let msgs = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(MSG_ERR)?;
    let mut out = Vec::new();
    for (i, m) in msgs.iter().enumerate() {
        if !m.is_object() {
            continue;
        }
        let ch = role_channel(m.get("role").and_then(Value::as_str));
        text_parts(m, &format!("/messages/{i}"), "content", ch, &mut out);
    }
    Ok(out)
}

pub fn openai_inject_system(body: &mut Value, text: &str) {
    let Some(msgs) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    let is_sys = |m: &Value| {
        matches!(
            m.get("role").and_then(Value::as_str),
            Some("system") | Some("developer")
        )
    };
    if let Some(sys) = msgs.iter_mut().find(|m| is_sys(m)) {
        if let Some(Value::String(c)) = sys.get_mut("content") {
            c.push_str("\n\n");
            c.push_str(text);
            return;
        }
    }
    msgs.insert(0, json!({ "role": "system", "content": text }));
}

pub fn openai_response_segments(resp: &Value) -> Vec<Segment> {
    let mut out = Vec::new();
    let Some(choices) = resp.get("choices").and_then(Value::as_array) else {
        return out;
    };
    for (ci, ch) in choices.iter().enumerate() {
        let Some(msg) = ch.get("message").filter(|m| !m.is_null()) else {
            continue;
        };
        let base = format!("/choices/{ci}/message");
        text_parts(msg, &base, "content", Channel::Assistant, &mut out);
        if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
            for (ti, tc) in tcs.iter().enumerate() {
                if tc
                    .pointer("/function/arguments")
                    .is_some_and(Value::is_string)
                {
                    out.push(Segment::text(
                        Channel::Assistant,
                        format!("{base}/tool_calls/{ti}/function/arguments"),
                    ));
                }
            }
        }
    }
    out
}

pub fn openai_blocked_response(resp: &mut Value, message: &str) {
    if let Some(choices) = resp.get_mut("choices").and_then(Value::as_array_mut) {
        for ch in choices {
            if let Some(o) = ch.as_object_mut() {
                o.insert(
                    "message".into(),
                    json!({ "role": "assistant", "content": message }),
                );
                o.insert("finish_reason".into(), json!("content_filter"));
            }
        }
    }
}

// ---------------- Anthropic Messages ----------------

pub fn anthropic_request_segments(body: &Value) -> Result<Vec<Segment>, String> {
    let mut out = Vec::new();
    if body.get("system").is_some() {
        text_parts(body, "", "system", Channel::System, &mut out);
    }
    let msgs = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(MSG_ERR)?;
    for (i, m) in msgs.iter().enumerate() {
        if !m.is_object() {
            continue;
        }
        let ch = role_channel(m.get("role").and_then(Value::as_str));
        let base = format!("/messages/{i}");
        text_parts(m, &base, "content", ch, &mut out);
        if let Some(blocks) = m.get("content").and_then(Value::as_array) {
            for (j, block) in blocks.iter().enumerate() {
                if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                    text_parts(
                        block,
                        &format!("{base}/content/{j}"),
                        "content",
                        Channel::Tool,
                        &mut out,
                    );
                }
            }
        }
    }
    Ok(out)
}

pub fn anthropic_inject_system(body: &mut Value, text: &str) {
    let Some(o) = body.as_object_mut() else {
        return;
    };
    match o.get_mut("system") {
        Some(Value::String(s)) => {
            s.push_str("\n\n");
            s.push_str(text);
        }
        Some(Value::Array(a)) => a.push(json!({ "type": "text", "text": text })),
        _ => {
            o.insert("system".into(), Value::String(text.to_string()));
        }
    }
}

pub fn anthropic_response_segments(resp: &Value) -> Vec<Segment> {
    let mut out = Vec::new();
    let Some(blocks) = resp.get("content").and_then(Value::as_array) else {
        return out;
    };
    for (i, block) in blocks.iter().enumerate() {
        match block.get("type").and_then(Value::as_str) {
            Some("text") if block.get("text").is_some_and(Value::is_string) => {
                out.push(Segment::text(
                    Channel::Assistant,
                    format!("/content/{i}/text"),
                ));
            }
            // tool input is exposed as JSON text; writes are parsed back (invalid JSON -> caller blocks)
            Some("tool_use") if block.get("input").is_some() => {
                out.push(Segment {
                    channel: Channel::Assistant,
                    ptr: format!("/content/{i}/input"),
                    json_text: true,
                });
            }
            _ => {}
        }
    }
    out
}

pub fn anthropic_blocked_response(resp: &mut Value, message: &str) {
    if let Some(o) = resp.as_object_mut() {
        o.insert(
            "content".into(),
            json!([{ "type": "text", "text": message }]),
        );
        o.insert("stop_reason".into(), json!("end_turn"));
    }
}
