//! JavaScript-regex -> fancy-regex translation helpers.
//! `\d` and `\w` are ASCII-only in JavaScript but Unicode-aware in Rust, so they are rewritten.
//! (`\b` keeps Rust's Unicode semantics; the difference only shows next to non-ASCII letters.)

use fancy_regex::Regex;

/// Translate a JS regex source to the Rust dialect. `i` = case-insensitive.
pub fn js(src: &str, i: bool) -> Regex {
    let mut out = String::with_capacity(src.len() + 8);
    if i {
        out.push_str("(?i)");
    }
    let mut in_class = false;
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let n = chars.next().unwrap_or('\\');
                match (n, in_class) {
                    ('d', false) => out.push_str("[0-9]"),
                    ('d', true) => out.push_str("0-9"),
                    ('w', false) => out.push_str("[A-Za-z0-9_]"),
                    ('w', true) => out.push_str("A-Za-z0-9_"),
                    ('D', false) => out.push_str("[^0-9]"),
                    ('W', false) => out.push_str("[^A-Za-z0-9_]"),
                    _ => {
                        out.push('\\');
                        out.push(n);
                    }
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                }
                // a leading ']' would close an empty class in JS; none of our patterns do this
            }
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            '[' if in_class => out.push_str("\\["), // literal '[' inside a class
            _ => out.push(c),
        }
    }
    Regex::new(&out).unwrap_or_else(|e| panic!("bad regex {src:?} -> {out:?}: {e}"))
}

/// Find iterator over (match start, match end, full captures).
pub fn captures_all<'t>(re: &Regex, text: &'t str) -> Vec<fancy_regex::Captures<'t>> {
    re.captures_iter(text).filter_map(|c| c.ok()).collect()
}

/// Replace all matches using a closure over the matched text. Matches that fail to evaluate are skipped.
pub fn replace_all(re: &Regex, text: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in re.find_iter(text).filter_map(|m| m.ok()) {
        out.push_str(&text[last..m.start()]);
        out.push_str(&f(m.as_str()));
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}
