//! Reversible placeholder vault. Placeholders look like `[[EMAIL:1b4e28ba-…]]`.
//! The UUID is HMAC-SHA256(sessionKey, type + value), so the same value maps to the same placeholder
//! for the whole session without the vault ever storing value -> uuid. Only uuid -> value is stored,
//! in a VaultStore with TTL, and only for rehydration on allowed egress.

use crate::pii::{Entity, PiiType};
use crate::policy::Rehydrate;
use crate::rx::js;
use fancy_regex::Regex;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

pub static PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| js(r"\[\[([A-Z_]+):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\]\]", false));

#[derive(Clone, Debug)]
pub struct VaultEntry {
    pub kind: PiiType,
    pub value: String,
}

/// Process-local store with TTL and a size cap. (Multi-instance deployments would swap in Redis.)
pub struct MemoryVaultStore {
    m: Mutex<HashMap<String, (VaultEntry, Instant, u64)>>,
    ttl: Duration,
    max: usize,
    seq: Mutex<u64>,
}

impl MemoryVaultStore {
    pub fn new() -> Self {
        Self { m: Mutex::new(HashMap::new()), ttl: Duration::from_secs(3600), max: 50_000, seq: Mutex::new(0) }
    }
    pub fn get(&self, session: &str, uuid: &str) -> Option<VaultEntry> {
        let k = format!("{session}:{uuid}");
        let mut m = self.m.lock().unwrap();
        match m.get(&k) {
            Some((e, exp, _)) if *exp > Instant::now() => Some(e.clone()),
            Some(_) => {
                m.remove(&k);
                None
            }
            None => None,
        }
    }
    pub fn put(&self, session: &str, uuid: &str, e: VaultEntry) {
        let mut m = self.m.lock().unwrap();
        let mut seq = self.seq.lock().unwrap();
        if m.len() >= self.max {
            if let Some(oldest) = m.iter().min_by_key(|(_, v)| v.2).map(|(k, _)| k.clone()) {
                m.remove(&oldest);
            }
        }
        *seq += 1;
        m.insert(format!("{session}:{uuid}"), (e, Instant::now() + self.ttl, *seq));
    }
}

impl Default for MemoryVaultStore {
    fn default() -> Self {
        Self::new()
    }
}

fn hmac_uuid(key: &[u8], data: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data.as_bytes());
    let sig = mac.finalize().into_bytes();
    let mut b = [0u8; 16];
    b.copy_from_slice(&sig[..16]);
    b[6] = (b[6] & 0x0f) | 0x80; // version 8 (custom, RFC 9562)
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

pub struct Vault<'a> {
    pub session: String,
    key: Vec<u8>,
    store: &'a MemoryVaultStore,
    local: HashMap<String, VaultEntry>,
}

impl<'a> Vault<'a> {
    pub fn new(session: &str, secret: &str, store: &'a MemoryVaultStore) -> Self {
        let mut key = secret.as_bytes().to_vec();
        key.push(0);
        key.extend_from_slice(session.as_bytes());
        Vault { session: session.to_string(), key, store, local: HashMap::new() }
    }

    pub fn placeholder_for(&mut self, kind: PiiType, value: &str) -> String {
        let uuid = hmac_uuid(&self.key, &format!("{}\0{}", kind.as_str(), value));
        if !self.local.contains_key(&uuid) {
            self.local.insert(uuid.clone(), VaultEntry { kind, value: value.to_string() });
            self.store.put(&self.session, &uuid, VaultEntry { kind, value: value.to_string() });
        }
        format!("[[{}:{}]]", kind.as_str(), uuid)
    }

    /// Replace entity spans with placeholders. Entities must be non-overlapping.
    pub fn redact(&mut self, text: &str, entities: &[Entity]) -> String {
        let mut out = text.to_string();
        let mut es: Vec<&Entity> = entities.iter().collect();
        es.sort_by(|a, b| b.start.cmp(&a.start));
        for e in es {
            let ph = self.placeholder_for(e.kind, &e.value);
            out.replace_range(e.start..e.end, &ph);
        }
        out
    }

    fn resolve(&mut self, uuid: &str) -> Option<VaultEntry> {
        if let Some(l) = self.local.get(uuid) {
            return Some(l.clone());
        }
        let s = self.store.get(&self.session, uuid)?;
        self.local.insert(uuid.to_string(), s.clone());
        Some(s)
    }

    /// Restore placeholders issued in THIS session, for allowed types only. Unknown or foreign
    /// placeholders are left as-is. Returns (text, restored count).
    pub fn rehydrate(&mut self, text: &str, allowed: &Rehydrate) -> (String, usize) {
        if matches!(allowed, Rehydrate::None) {
            return (text.to_string(), 0);
        }
        let caps: Vec<_> = PLACEHOLDER_RE.captures_iter(text).filter_map(|c| c.ok()).collect();
        if caps.is_empty() {
            return (text.to_string(), 0);
        }
        let mut resolved: HashMap<String, String> = HashMap::new();
        for c in &caps {
            let ph = c.get(0).unwrap().as_str().to_string();
            if resolved.contains_key(&ph) {
                continue;
            }
            let kind = &c[1];
            let uuid = c[2].to_string();
            let Some(hit) = self.resolve(&uuid) else { continue };
            if hit.kind.as_str() != kind {
                continue;
            }
            let ok = match allowed {
                Rehydrate::All => true,
                Rehydrate::Types(ts) => ts.contains(&hit.kind),
                Rehydrate::None => false,
            };
            if ok {
                resolved.insert(ph, hit.value);
            }
        }
        let mut restored = 0usize;
        let out = crate::rx::replace_all(&PLACEHOLDER_RE, text, |ph| match resolved.get(ph) {
            Some(v) => {
                restored += 1;
                v.clone()
            }
            None => ph.to_string(),
        });
        (out, restored)
    }

    pub fn size(&self) -> usize {
        self.local.len()
    }
}
