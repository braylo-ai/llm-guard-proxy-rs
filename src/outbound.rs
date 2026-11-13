//! Outbound (model -> client) scanners: secret / PII leakage, canary tokens, exfiltration URLs.

use crate::pii::{detect_pii, Entity, PiiType};
use crate::rx::{captures_all, js};
use crate::vault::PLACEHOLDER_RE;
use base64::{engine::general_purpose::STANDARD, Engine};
use fancy_regex::Regex;
use std::sync::LazyLock;

fn squash(s: &str) -> String {
    s.to_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

/// Returns the canary that appeared in `text` (plain, base64 or reversed), if any.
pub fn canary_hit(text: &str, canaries: &[String]) -> Option<String> {
    let t = squash(text);
    for c in canaries {
        let sc = squash(c);
        if sc.len() >= 8 && t.contains(&sc) {
            return Some(c.clone());
        }
        let b = STANDARD.encode(c.as_bytes());
        if text.contains(&b) || text.contains(b.trim_end_matches('=')) {
            return Some(c.clone());
        }
        let rev: String = sc.chars().rev().collect();
        if sc.len() >= 8 && t.contains(&rev) {
            return Some(c.clone());
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExfilReason {
    ImageWithQuery,
    LinkWithPlaceholder,
    LinkWithPii,
    LinkWithLongParam,
}
impl ExfilReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExfilReason::ImageWithQuery => "image_with_query",
            ExfilReason::LinkWithPlaceholder => "link_with_placeholder",
            ExfilReason::LinkWithPii => "link_with_pii",
            ExfilReason::LinkWithLongParam => "link_with_long_param",
        }
    }
}

static MD_URL: LazyLock<Regex> =
    LazyLock::new(|| js(r#"(!?)\[[^\]]*\]\(\s*(https?://[^\s)]+)\s*\)|(?<![\w(])(https?://[^\s<>"')]+)"#, false));

fn pct_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

pub fn find_exfil_urls(text: &str, allow_hosts: &[String]) -> Vec<ExfilReason> {
    let mut hits = Vec::new();
    for m in captures_all(&MD_URL, text) {
        let is_image = m.get(1).map(|x| x.as_str() == "!").unwrap_or(false);
        let Some(url) = m.get(2).or_else(|| m.get(3)).map(|x| x.as_str()) else { continue };
        let Ok(u) = url::Url::parse(url) else { continue };
        let host = u.host_str().unwrap_or("");
        if allow_hosts.iter().any(|h| host == h || host.ends_with(&format!(".{h}"))) {
            continue;
        }
        let search = u.query().map(|q| format!("?{q}")).unwrap_or_default();
        let frag = u.fragment().map(|f| format!("#{f}")).unwrap_or_default();
        let q = pct_decode(&format!("{search}{frag}"));
        let path_and_query = format!("{}{}", pct_decode(u.path()), q);
        if is_image && search.len() > 1 {
            hits.push(ExfilReason::ImageWithQuery);
            continue;
        }
        if PLACEHOLDER_RE.is_match(&path_and_query).unwrap_or(false) {
            hits.push(ExfilReason::LinkWithPlaceholder);
            continue;
        }
        let kinds = [PiiType::Email, PiiType::Phone, PiiType::Ssn, PiiType::CreditCard, PiiType::Iban, PiiType::Secret];
        if !detect_pii(&path_and_query, &kinds, &[]).is_empty() {
            hits.push(ExfilReason::LinkWithPii);
            continue;
        }
        if u.query_pairs().any(|(_, v)| v.chars().count() >= 64) {
            hits.push(ExfilReason::LinkWithLongParam);
        }
    }
    hits
}

pub struct LeakScan {
    pub secrets: Vec<Entity>,
    pub pii: Vec<Entity>,
}

/// Leak scan on raw model output (before rehydration, so placeholders are not PII).
pub fn scan_leaks(text: &str, enabled: &[PiiType], allowlist: &[String]) -> LeakScan {
    let all = detect_pii(text, enabled, allowlist);
    LeakScan {
        secrets: all.iter().filter(|e| e.kind == PiiType::Secret).cloned().collect(),
        pii: all.iter().filter(|e| e.kind != PiiType::Secret).cloned().collect(),
    }
}

pub fn mask_entities(text: &str, entities: &[Entity]) -> String {
    let mut out = text.to_string();
    let mut es: Vec<&Entity> = entities.iter().collect();
    es.sort_by(|a, b| b.start.cmp(&a.start));
    for e in es {
        out.replace_range(e.start..e.end, &format!("[REDACTED_{}]", e.kind.as_str()));
    }
    out
}
