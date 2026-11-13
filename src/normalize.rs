//! De-obfuscated "views" of a text so injection rules see through common encoding tricks.

use crate::rx::{captures_all, js, replace_all};
use base64::{engine::general_purpose::STANDARD, Engine};
use fancy_regex::Regex;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewKind {
    Plain,
    Leet,
    Despaced,
    Base64,
    Hex,
    Url,
    Rot13,
    Reversed,
}

#[derive(Clone, Debug)]
pub struct View {
    pub kind: ViewKind,
    pub text: String,
}

fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}' | '\u{00AD}')
}

fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y', 'х' => 'x', 'і' => 'i', 'ј' => 'j',
        'ѕ' => 's', 'ԁ' => 'd', 'ɡ' => 'g', 'һ' => 'h', 'ӏ' => 'l', 'м' => 'm', 'т' => 't', 'к' => 'k', 'в' => 'b',
        'н' => 'h', 'А' => 'a', 'Е' => 'e', 'О' => 'o', 'Р' => 'p', 'С' => 'c', 'Т' => 't', 'Х' => 'x', 'І' => 'i',
        'ο' => 'o', 'α' => 'a', 'ε' => 'e', 'ι' => 'i', 'ν' => 'v', 'ρ' => 'p', 'τ' => 't', 'υ' => 'u',
        _ => return None,
    })
}

fn leet_char(c: char) -> Option<char> {
    Some(match c {
        '0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a', '$' => 's', '!' => 'i', '|' => 'l',
        _ => return None,
    })
}

static RE_SPACES: LazyLock<Regex> = LazyLock::new(|| js(r"[ \t]+", false));
static RE_TOKEN: LazyLock<Regex> = LazyLock::new(|| js(r"[a-z0-9@$!|]+", false));
static RE_TWO_SPACES: LazyLock<Regex> = LazyLock::new(|| js(r"[ \t]{2,}", false));
static RE_RUN: LazyLock<Regex> = LazyLock::new(|| js(r"\b(?:[a-z][ .\-_*]){2,}[a-z]\b", false));
static RE_SEP: LazyLock<Regex> = LazyLock::new(|| js(r"[ .\-_*]", false));
static RE_PIPE: LazyLock<Regex> = LazyLock::new(|| js(r" \| ", false));
static RE_MULTISPACE: LazyLock<Regex> = LazyLock::new(|| js(r" {2,}", false));
static RE_B64: LazyLock<Regex> = LazyLock::new(|| js(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{24,}", false));
static RE_HEX: LazyLock<Regex> = LazyLock::new(|| js(r"(?:(?:0x|\\x)?[0-9a-f]{2}[ :]?){8,}", true));
static RE_HEX_STRIP: LazyLock<Regex> = LazyLock::new(|| js(r"0x|\\x|[ :]", true));
static RE_PCT: LazyLock<Regex> = LazyLock::new(|| js(r"%[0-9a-f]{2}", true));
static RE_ROT: LazyLock<Regex> = LazyLock::new(|| js(r"\brot[- ]?13\b|caesar", true));
static RE_REV: LazyLock<Regex> = LazyLock::new(|| js(r"\brevers(e|ed)\b|backwards", true));
static RE_LETTERS_WS: LazyLock<Regex> = LazyLock::new(|| js(r"[a-z]{3,}\s", true));
static RE_LETTERS3: LazyLock<Regex> = LazyLock::new(|| js(r"[a-z]{3,}", true));

pub fn basic_normalize(s: &str) -> String {
    let t: String = s.nfkc().filter(|c| !is_zero_width(*c)).collect();
    let t: String = t.chars().map(|c| if c.is_ascii() { c } else { homoglyph(c).unwrap_or(c) }).collect();
    let lower = t.to_lowercase();
    RE_SPACES.replace_all(&lower, " ").into_owned()
}

fn leet(s: &str) -> String {
    replace_all(&RE_TOKEN, s, |tok| {
        if tok.chars().any(|c| c.is_ascii_lowercase()) {
            tok.chars().map(|c| leet_char(c).unwrap_or(c)).collect()
        } else {
            tok.to_string()
        }
    })
}

/// "i g n o r e  a l l" -> "ignore all"
fn despace(raw: &str) -> String {
    let s: String = raw.nfkc().filter(|c| !is_zero_width(*c)).collect::<String>().to_lowercase();
    let s = RE_TWO_SPACES.replace_all(&s, " | ").into_owned();
    let s = replace_all(&RE_RUN, &s, |run| RE_SEP.replace_all(run, "").into_owned());
    let s = RE_PIPE.replace_all(&s, " ").into_owned();
    RE_MULTISPACE.replace_all(&s, " ").into_owned()
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let b = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                (((c as u8 - b + 13) % 26) + b) as char
            } else {
                c
            }
        })
        .collect()
}

fn printable_ratio(s: &str) -> f64 {
    let n = s.chars().count();
    if n == 0 {
        return 0.0;
    }
    let ok = s.chars().filter(|c| matches!(*c, '\x20'..='\x7E' | '\n' | '\r' | '\t')).count();
    ok as f64 / n as f64
}

/// JS `atob` yields a Latin-1 string: each byte becomes one char.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

fn decode_base64_segments(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in captures_all(&RE_B64, s) {
        let seg = m.get(0).unwrap().as_str();
        let b = seg.replace('-', "+").replace('_', "/");
        let trimmed = b.trim_end_matches('=');
        let mut padded = trimmed.to_string();
        padded.push_str(&"=".repeat((4 - trimmed.len() % 4) % 4));
        if let Ok(bytes) = STANDARD.decode(padded.as_bytes()) {
            let dec = latin1(&bytes);
            if printable_ratio(&dec) > 0.9 && RE_LETTERS_WS.is_match(&dec).unwrap_or(false) {
                out.push(dec);
            }
        }
    }
    out
}

fn decode_hex_segments(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in captures_all(&RE_HEX, s) {
        let seg = m.get(0).unwrap().as_str();
        let hex = RE_HEX_STRIP.replace_all(seg, "").into_owned();
        if hex.len() % 2 == 1 {
            continue;
        }
        let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect();
        let dec = latin1(&bytes);
        if printable_ratio(&dec) > 0.9 && RE_LETTERS3.is_match(&dec).unwrap_or(false) {
            out.push(dec);
        }
    }
    out
}

pub fn views(raw: &str) -> Vec<View> {
    let plain = basic_normalize(raw);
    let mut v = vec![View { kind: ViewKind::Plain, text: plain.clone() }];
    let l = leet(&plain);
    if l != plain {
        v.push(View { kind: ViewKind::Leet, text: l.clone() });
    }
    let d = leet(&basic_normalize(&despace(raw)));
    if d != l && d != plain {
        v.push(View { kind: ViewKind::Despaced, text: d });
    }
    for dec in decode_base64_segments(raw) {
        v.push(View { kind: ViewKind::Base64, text: basic_normalize(&dec) });
    }
    for dec in decode_hex_segments(raw) {
        v.push(View { kind: ViewKind::Hex, text: basic_normalize(&dec) });
    }
    if RE_PCT.is_match(raw).unwrap_or(false) {
        if let Ok(u) = percent_encoding::percent_decode_str(raw).decode_utf8() {
            if u != raw {
                v.push(View { kind: ViewKind::Url, text: basic_normalize(&u) });
            }
        }
    }
    if RE_ROT.is_match(raw).unwrap_or(false) {
        v.push(View { kind: ViewKind::Rot13, text: basic_normalize(&rot13(raw)) });
    }
    if RE_REV.is_match(raw).unwrap_or(false) {
        v.push(View { kind: ViewKind::Reversed, text: basic_normalize(&raw.chars().rev().collect::<String>()) });
    }
    v
}
