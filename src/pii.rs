//! PII + secret detectors. Pure functions, no I/O, deterministic.
//! Overlaps are resolved by detector priority (secrets > cards > IBAN > SSN > email > phone > address).

use crate::rx::{captures_all, js};
use fancy_regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PiiType {
    Secret,
    CreditCard,
    Iban,
    Ssn,
    Email,
    Phone,
    Address,
}

pub const ALL_PII_TYPES: [PiiType; 7] =
    [PiiType::Secret, PiiType::CreditCard, PiiType::Iban, PiiType::Ssn, PiiType::Email, PiiType::Phone, PiiType::Address];

impl PiiType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PiiType::Secret => "SECRET",
            PiiType::CreditCard => "CREDIT_CARD",
            PiiType::Iban => "IBAN",
            PiiType::Ssn => "SSN",
            PiiType::Email => "EMAIL",
            PiiType::Phone => "PHONE",
            PiiType::Address => "ADDRESS",
        }
    }
    pub fn parse(s: &str) -> Option<PiiType> {
        ALL_PII_TYPES.iter().copied().find(|t| t.as_str() == s)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    pub kind: PiiType,
    pub start: usize,
    pub end: usize,
    pub value: String,
}

// ---------- validators ----------

pub fn luhn_valid(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    let mut dbl = false;
    for b in digits.bytes().rev() {
        let mut d = (b - b'0') as u32;
        if dbl {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        dbl = !dbl;
    }
    sum % 10 == 0
}

static RE_VISA: LazyLock<Regex> = LazyLock::new(|| js(r"^4", false));
static RE_MC: LazyLock<Regex> = LazyLock::new(|| js(r"^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))", false));
static RE_AMEX: LazyLock<Regex> = LazyLock::new(|| js(r"^3[47]", false));
static RE_DISC: LazyLock<Regex> = LazyLock::new(|| js(r"^(6011|65|64[4-9])", false));
static RE_JCB: LazyLock<Regex> = LazyLock::new(|| js(r"^35(2[89]|[3-8]\d)", false));
static RE_DINERS: LazyLock<Regex> = LazyLock::new(|| js(r"^3(0[0-5]|[68])", false));

fn card_prefix_ok(d: &str) -> bool {
    let n = d.len();
    let t = |r: &Regex| r.is_match(d).unwrap_or(false);
    if t(&RE_VISA) {
        return n == 13 || n == 16 || n == 19;
    }
    if t(&RE_MC) {
        return n == 16;
    }
    if t(&RE_AMEX) {
        return n == 15;
    }
    if t(&RE_DISC) {
        return (16..=19).contains(&n);
    }
    if t(&RE_JCB) {
        return (16..=19).contains(&n);
    }
    if t(&RE_DINERS) {
        return (14..=19).contains(&n);
    }
    false
}

fn iban_len(cc: &str) -> Option<usize> {
    Some(match cc {
        "AD" => 24, "AT" => 20, "BE" => 16, "CH" => 21, "CY" => 28, "CZ" => 24, "DE" => 22, "DK" => 18, "EE" => 20,
        "ES" => 24, "FI" => 18, "FR" => 27, "GB" => 22, "GR" => 27, "HR" => 21, "HU" => 28, "IE" => 22, "IS" => 26,
        "IT" => 27, "LI" => 21, "LT" => 20, "LU" => 20, "LV" => 21, "MC" => 27, "MT" => 31, "NL" => 18, "NO" => 15,
        "PL" => 28, "PT" => 25, "RO" => 24, "SE" => 24, "SI" => 19, "SK" => 24, "SM" => 27, "TR" => 26, "SA" => 24,
        "AE" => 23, "IL" => 23, "QA" => 29, "BR" => 29, "MU" => 30,
        _ => return None,
    })
}

static RE_IBAN_SHAPE: LazyLock<Regex> = LazyLock::new(|| js(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", false));

pub fn iban_valid(raw: &str) -> bool {
    let s: String = raw.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    if !RE_IBAN_SHAPE.is_match(&s).unwrap_or(false) {
        return false;
    }
    let expected = iban_len(&s[..2]);
    match expected {
        Some(e) if s.len() != e => return false,
        None if s.len() < 15 || s.len() > 34 => return false,
        _ => {}
    }
    let re = format!("{}{}", &s[4..], &s[..4]);
    let mut rem = 0u32;
    for ch in re.chars() {
        if ch.is_ascii_uppercase() {
            let v = (ch as u32 - 55).to_string();
            for c in v.chars() {
                rem = (rem * 10 + (c as u32 - 48)) % 97;
            }
        } else {
            rem = (rem * 10 + (ch as u32 - 48)) % 97;
        }
    }
    rem == 1
}

fn ssn_valid(area: &str, group: &str, serial: &str) -> bool {
    !(area == "000" || area == "666" || area.starts_with('9') || group == "00" || serial == "0000")
}

/// Shannon entropy in bits/char.
fn entropy(s: &str) -> f64 {
    let mut f: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *f.entry(c).or_insert(0) += 1;
        n += 1;
    }
    let mut h = 0.0;
    for c in f.values() {
        let p = *c as f64 / n as f64;
        h -= p * p.log2();
    }
    h
}

// ---------- detectors ----------

#[derive(Clone, Debug)]
struct Raw {
    start: usize,
    end: usize,
    value: String,
}

/// Scan with a regex; `group` selects the captured span; `keep` filters matches.
fn scan(re: &Regex, text: &str, group: usize, keep: Option<&dyn Fn(&Captures) -> bool>) -> Vec<Raw> {
    let mut out = Vec::new();
    for m in captures_all(re, text) {
        let whole = m.get(0).unwrap();
        if whole.as_str().is_empty() {
            continue;
        }
        if let Some(k) = keep {
            if !k(&m) {
                continue;
            }
        }
        let Some(g) = m.get(group) else { continue };
        let value = g.as_str().to_string();
        let off = whole.as_str().find(&value).unwrap_or(0);
        let start = whole.start() + off;
        out.push(Raw { start, end: start + value.len(), value });
    }
    out
}

static RE_PLACEHOLDER_WHOLE: LazyLock<Regex> = LazyLock::new(|| js(r"^\[\[[A-Z_]+_\d+\]\]$", false));

struct SecretPat {
    re: Regex,
    group: usize,
    kv: bool,
}

static SECRET_PATTERNS: LazyLock<Vec<SecretPat>> = LazyLock::new(|| {
    let p = |src: &str, group: usize, kv: bool, i: bool| SecretPat { re: js(src, i), group, kv };
    vec![
        p(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|$)", 0, false, false),
        p(r"\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}", 0, false, false),
        p(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, false, false),
        p(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", 0, false, false),
        p(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b", 0, false, false),
        p(r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 0, false, false),
        p(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b", 0, false, false),
        p(r"\bAIza[0-9A-Za-z_-]{35}\b", 0, false, false),
        p(r"\bglpat-[A-Za-z0-9_-]{20,}\b", 0, false, false),
        p(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", 0, false, false),
        p(r"\bBearer\s+([A-Za-z0-9._~+/-]{20,}=*)", 1, false, false),
        p(r#"\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)\b["']?\s*[:=]\s*["']?([^\s"',;]{8,})"#, 1, true, true),
    ]
});

fn detect_secrets(t: &str) -> Vec<Raw> {
    let mut out = Vec::new();
    for p in SECRET_PATTERNS.iter() {
        if p.kv {
            let keep = |m: &Captures| {
                let v = m.get(1).map(|x| x.as_str()).unwrap_or("");
                let classes = [
                    v.chars().any(|c| c.is_ascii_lowercase()),
                    v.chars().any(|c| c.is_ascii_uppercase()),
                    v.chars().any(|c| c.is_ascii_digit()),
                    v.chars().any(|c| !c.is_ascii_alphanumeric()),
                ]
                .iter()
                .filter(|b| **b)
                .count();
                entropy(v) >= 3.0 && classes >= 2 && !RE_PLACEHOLDER_WHOLE.is_match(v).unwrap_or(false)
            };
            out.extend(scan(&p.re, t, p.group, Some(&keep)));
        } else {
            out.extend(scan(&p.re, t, p.group, None));
        }
    }
    out
}

static RE_CARD: LazyLock<Regex> = LazyLock::new(|| js(r"(?<![\d.-])(?:\d[ .-]?){12,18}\d(?![\d-]|\.\d)", false));
static RE_CARD_GROUPS: LazyLock<Regex> = LazyLock::new(|| js(r"^\d{4}([ .-])\d{4,6}(\1\d{4,5}){0,3}(\1\d{1,4})?$", false));
static RE_SEPS: LazyLock<Regex> = LazyLock::new(|| js(r"[ .-]", false));

fn detect_cards(t: &str) -> Vec<Raw> {
    scan(&RE_CARD, t, 0, None)
        .into_iter()
        .filter(|r| {
            let d = RE_SEPS.replace_all(&r.value, "").into_owned();
            if d.len() < 13 || d.len() > 19 {
                return false;
            }
            if RE_SEPS.is_match(&r.value).unwrap_or(false) && !RE_CARD_GROUPS.is_match(&r.value).unwrap_or(false) {
                return false;
            }
            luhn_valid(&d) && card_prefix_ok(&d)
        })
        .collect()
}

static RE_IBAN: LazyLock<Regex> = LazyLock::new(|| js(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b", false));
fn detect_iban(t: &str) -> Vec<Raw> {
    scan(&RE_IBAN, t, 0, None).into_iter().filter(|r| iban_valid(&r.value)).collect()
}

static RE_SSN_DASHED: LazyLock<Regex> = LazyLock::new(|| js(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])", false));
static RE_SSN_KW: LazyLock<Regex> = LazyLock::new(|| js(r"\b(?:ssn|social security(?: number| no\.?| #)?|ss#)\s*(?:is|:|#)?\s*((\d{3}) ?(\d{2}) ?(\d{4}))\b", true));
fn detect_ssn(t: &str) -> Vec<Raw> {
    let k1 = |m: &Captures| ssn_valid(&m[1], &m[2], &m[3]);
    let k2 = |m: &Captures| ssn_valid(&m[2], &m[3], &m[4]);
    let mut out = scan(&RE_SSN_DASHED, t, 0, Some(&k1));
    out.extend(scan(&RE_SSN_KW, t, 1, Some(&k2)));
    out
}

static RE_EMAIL: LazyLock<Regex> =
    LazyLock::new(|| js(r"(?<![A-Za-z0-9._%+'-])[A-Za-z0-9._%+-]+(?:'[A-Za-z0-9._%+-]+)*@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b", false));
fn detect_email(t: &str) -> Vec<Raw> {
    scan(&RE_EMAIL, t, 0, None)
}

static RE_NANP: LazyLock<Regex> = LazyLock::new(|| js(r"(?<![\d\w.+-])(?:\+?1[ .-]?)?(?:\(([2-9]\d{2})\)\s?|([2-9]\d{2})[ .-])([2-9]\d{2})[ .-](\d{4})(?![\d-]|\.\d)", false));
static RE_INTL: LazyLock<Regex> = LazyLock::new(|| js(r"(?<![\w+])\+(?:[2-9]\d{0,2})(?:[ .-]?\(?\d{1,4}\)?)(?:[ .-]?\d{2,4}){2,4}(?![\d-])", false));
static RE_PHONE_KW: LazyLock<Regex> = LazyLock::new(|| js(r"\b(?:call|phone|tel|mobile|cell|text|fax|whatsapp)\b[^\d\n]{0,12}(\+?1?[2-9]\d{2}[2-9]\d{6})\b", true));
fn detect_phone(t: &str) -> Vec<Raw> {
    let mut out = scan(&RE_NANP, t, 0, None);
    out.extend(scan(&RE_INTL, t, 0, None).into_iter().filter(|r| {
        let n = r.value.chars().filter(|c| c.is_ascii_digit()).count();
        (8..=15).contains(&n)
    }));
    out.extend(scan(&RE_PHONE_KW, t, 1, None));
    out
}

const STREET_SUFFIX: &str =
    "(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Parkway|Pkwy|Circle|Cir|Highway|Hwy|Square|Sq)";
static RE_STREET: LazyLock<Regex> = LazyLock::new(|| {
    js(
        &format!(
            r"\b\d{{1,6}}[A-Z]?\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z]+\.?\s+|\d{{1,3}}(?:st|nd|rd|th)\s+){{1,4}}{STREET_SUFFIX}\b(?:,?\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\.?\s*[A-Za-z0-9-]+)?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+){{0,2}},\s*[A-Z]{{2}}(?:\s+\d{{5}}(?:-\d{{4}})?)?)?"
        ),
        false,
    )
});
static RE_POBOX: LazyLock<Regex> = LazyLock::new(|| js(r"\bP\.?\s?O\.?\s+Box\s+\d{1,6}\b", true));
fn detect_address(t: &str) -> Vec<Raw> {
    let mut out = scan(&RE_STREET, t, 0, None);
    out.extend(scan(&RE_POBOX, t, 0, None));
    out
}

type Detector = fn(&str) -> Vec<Raw>;
const ORDERED: [(PiiType, Detector); 7] = [
    (PiiType::Secret, detect_secrets),
    (PiiType::CreditCard, detect_cards),
    (PiiType::Iban, detect_iban),
    (PiiType::Ssn, detect_ssn),
    (PiiType::Email, detect_email),
    (PiiType::Phone, detect_phone),
    (PiiType::Address, detect_address),
];

/// Detect entities of the enabled types; non-overlapping, sorted by start.
pub fn detect_pii(text: &str, enabled: &[PiiType], allowlist: &[String]) -> Vec<Entity> {
    let allow: HashSet<String> = allowlist.iter().map(|a| a.to_lowercase()).collect();
    let mut taken: Vec<Entity> = Vec::new();
    for (kind, f) in ORDERED.iter() {
        if !enabled.contains(kind) {
            continue;
        }
        let mut found = f(text);
        found.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        for r in found {
            if taken.iter().any(|x| r.start < x.end && r.end > x.start) {
                continue;
            }
            if allow.contains(&r.value.to_lowercase()) || is_allowed_domain(&r.value, &allow) {
                continue;
            }
            taken.push(Entity { kind: *kind, start: r.start, end: r.end, value: r.value });
        }
    }
    taken.sort_by_key(|e| e.start);
    taken
}

pub fn detect_all(text: &str) -> Vec<Entity> {
    detect_pii(text, &ALL_PII_TYPES, &[])
}

/// Allowlist entries like "@example.com" allow every email at that domain.
fn is_allowed_domain(value: &str, allow: &HashSet<String>) -> bool {
    match value.rfind('@') {
        Some(at) if at > 0 => allow.contains(&value[at..].to_lowercase()),
        _ => false,
    }
}
