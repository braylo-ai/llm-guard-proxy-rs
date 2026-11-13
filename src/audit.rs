//! Audit log of guard decisions. Contract: NO raw PII, secrets, prompts or model output ever enter
//! an audit record. Values are represented only by a salted SHA-256 fingerprint (first 12 hex chars).

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub stage: String,
    pub detector: String,
    pub label: String,
    pub action: String,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub request_id: String,
    pub tenant: String,
    pub route: String,
    pub decision: String,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    pub guard_ms: f64,
}

pub enum AuditSink {
    Console,
    Memory(Mutex<Vec<AuditRecord>>),
}

impl AuditSink {
    pub fn memory() -> Self {
        AuditSink::Memory(Mutex::new(Vec::new()))
    }
    pub fn write(&self, r: AuditRecord) {
        match self {
            AuditSink::Console => {
                let mut v = serde_json::to_value(&r).unwrap();
                v.as_object_mut().unwrap().insert("type".into(), "llm_guard_audit".into());
                println!("{v}");
            }
            AuditSink::Memory(m) => m.lock().unwrap().push(r),
        }
    }
    pub fn records(&self) -> Vec<AuditRecord> {
        match self {
            AuditSink::Memory(m) => m.lock().unwrap().clone(),
            _ => vec![],
        }
    }
}

pub fn fingerprint(value: &str, salt: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update([0u8]);
    h.update(value.as_bytes());
    let d = h.finalize();
    d[..6].iter().map(|b| format!("{b:02x}")).collect()
}
