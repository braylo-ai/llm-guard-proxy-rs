//! Rule-based prompt-injection detector.
//! Rules run on several de-obfuscated views of the text (see normalize.rs).
//! Score = sum of the strongest hit per family, times a channel multiplier;
//! hits found only in a decoded view get an obfuscation bonus.

use crate::normalize::{views, ViewKind};
use crate::rx::js;
use fancy_regex::Regex;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    Override,
    Jailbreak,
    PromptExtraction,
    Exfiltration,
    Delimiter,
    ToolAbuse,
    AddressedToAi,
    AuthorityClaim,
}

impl Family {
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::Override => "override",
            Family::Jailbreak => "jailbreak",
            Family::PromptExtraction => "prompt_extraction",
            Family::Exfiltration => "exfiltration",
            Family::Delimiter => "delimiter",
            Family::ToolAbuse => "tool_abuse",
            Family::AddressedToAi => "addressed_to_ai",
            Family::AuthorityClaim => "authority_claim",
        }
    }
    fn strong(&self) -> bool {
        matches!(self, Family::Override | Family::Jailbreak | Family::PromptExtraction | Family::Delimiter | Family::Exfiltration)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    System,
    User,
    Assistant,
    Tool,
    Agent,
}

impl Channel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Channel::System => "system",
            Channel::User => "user",
            Channel::Assistant => "assistant",
            Channel::Tool => "tool",
            Channel::Agent => "agent",
        }
    }
    pub fn multiplier(&self) -> f64 {
        match self {
            Channel::System => 0.0,
            Channel::User => 1.0,
            Channel::Assistant => 0.5,
            Channel::Tool => 1.5,
            Channel::Agent => 1.5,
        }
    }
}

pub struct Rule {
    pub id: &'static str,
    pub family: Family,
    pub weight: f64,
    re: Regex,
}

const INSTR: &str = r"(?:instructions?|rules|guidelines|directions|directives|prompts?|context|programming|constraints|guardrails|policy|policies|orders|commands)";
const PRIOR: &str = r"(?:all|any|the|your|my|these|those|every|previous|prior|above|earlier|preceding|original|initial|system|safety|existing|old)";

pub static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    use Family::*;
    let r = |id: &'static str, family: Family, weight: f64, src: &str| Rule { id, family, weight, re: js(src, false) };
    vec![
        // --- override ---
        r("ov.ignore_prior", Override, 1.0, &format!(r"\b(?:ignore|disregard|forget|override|bypass|skip|drop|discard|abandon|neglect)\b(?:\s+\w+){{0,2}}?\s+{PRIOR}\b(?:\s+\w+){{0,3}}?\s+{INSTR}\b")),
        r("ov.ignore_above", Override, 1.0, r"\b(?:ignore|disregard|forget)\s+(?:everything|all|anything)?\s*(?:(?:you were|you've been|you have been)\s+told|(?:the|what(?:'s| is| was)?)?\s*(?:said|written|stated)?\s*(?:above|before|so far|earlier))\b"),
        r("ov.ignore_question", Override, 0.7, r"\b(?:ignore|disregard)\s+the\s+user'?s?\s+(?:question|request|message|query)\b"),
        r("ov.stop_following", Override, 1.0, &format!(r"\bstop\s+(?:following|obeying|using)\s+(?:\w+\s+){{0,2}}{INSTR}")),
        r("ov.new_instructions", Override, 0.8, r"\b(?:new|updated|real|actual|true|revised)\s+(?:instructions?|directives?|rules|system prompt|policy)\s*(?:for (?:the |you |\w+ ){0,3})?\s*(?::|are\b|is\b|loaded\b)"),
        r("ov.no_longer_valid", Override, 1.0, &format!(r"\b{INSTR}\s+(?:you\s+(?:received|were given|got)\s+(?:earlier|before|above)\s+)?(?:are|is|were|was)\s+(?:no longer valid|cancell?ed|void|revoked|obsolete|a test|disabled|lifted|null)")),
        r("ov.from_now_on", Override, 0.6, r"\bfrom now on,?\s+(?:you\s+(?:will|must|shall|are|only)|respond|answer|act|always|never|append|include)\b"),
        r("ov.obey_only", Override, 0.9, r"\byou\s+(?:now\s+)?(?:obey|follow|serve|answer to)\s+only\s+(?:me|my)\b"),
        r("ov.system_override", Override, 1.0, r"\b(?:system|admin|safety|security|developer)\s+(?:override|bypass)\b|\boverride\s+(?:your|the|all)\s+(?:safety|security|content)\b"),
        r("ov.multilingual", Override, 1.0, r"\b(?:ignora(?:r)?|olvida)\s+(?:todas\s+)?(?:las\s+)?instrucciones|\bignore[zr]?\s+(?:toutes\s+)?(?:les\s+)?(?:instructions|consignes)|\bignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+)?anweisungen|\bignor[ea]\s+(?:as\s+|todas\s+as\s+)?(?:instru[cç][oõ]es|regras)|\bignora\s+(?:tutte\s+)?le\s+istruzioni"),
        // --- jailbreak / role hijack ---
        r("jb.dan", Jailbreak, 1.0, r"\bdo anything now\b|\b(?:you are|pretend to be|act as|become)\s+dan\b|\bdan mode\b"),
        r("jb.dev_mode", Jailbreak, 1.0, r"\b(?:developer|god|jailbreak|jailbroken|unrestricted|maintenance|debug|sudo|admin)\s+mode\b"),
        r("jb.no_rules", Jailbreak, 0.8, r"\b(?:no|without(?:\s+any)?|free of|zero|lifted all|removed all)\s+(?:\w+\s+)?(?:restrictions|limits|limitations|filters|filtering|rules|ethics|guidelines|safety guidelines|content polic(?:y|ies)|censorship|safeguards)\b"),
        r("jb.unrestricted_persona", Jailbreak, 1.0, r"\byou are (?:now )?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|rogue|amoral)\b|\b(?:evil|unfiltered|uncensored|jailbroken|unrestricted)\s+(?:ai|assistant|model|twin|persona|version|one)\b"),
        r("jb.never_refuse", Jailbreak, 0.8, r"\b(?:never|don'?t|do not|cannot|can'?t)\s+(?:ever\s+)?refuse\b|\bwithout (?:refusing|filtering)\b|\banswer (?:every|any) question without\b"),
        r("jb.pretend_unrestricted", Jailbreak, 1.0, r"\b(?:pretend|imagine|act as if|act like|roleplay)\b[^.]{0,40}\b(?:without|no|free of)\s+(?:any\s+)?(?:\w+\s+)?(?:rules|restrictions|limits|filters|guidelines|ethics|content polic(?:y|ies))\b"),
        r("jb.stay_in_character", Jailbreak, 0.5, r"\bstay in character\b|\bbroken free of\b|\ball limitations are lifted\b"),
        r("jb.bypass_policy", Jailbreak, 1.0, r"\b(?:bypass|disable|turn off|deactivate|circumvent|ignore)\s+(?:your|the|all)?\s*(?:content polic(?:y|ies)|safety (?:checks|filters|mode|guidelines|features)|guardrails|moderation)\b|\bsafety mode is (?:now )?(?:disabled|off)\b"),
        // --- system prompt extraction ---
        r("px.reveal", PromptExtraction, 1.0, r"\b(?:reveal|show|print|repeat|output|display|leak|dump|disclose|give me|tell me|recite|spell out|write out|share|expose|affich\w*|revela\w*|gib)\s+(?:me\s+)?(?:\w+\s+){0,3}?(?:your|the|tu|votre|dein|suas?)\s+(?:\w+\s+)?(?:system\s?prompt|system message|initial instructions|hidden instructions|original instructions|secret instructions|instructions above|context window|prompt du syst[eè]me|prompt del sistema|systemprompt)\b"),
        r("px.reveal_config", PromptExtraction, 1.0, r"\b(?:reveal|show|print|output|display|leak|dump|disclose|share|expose|revela\w*)\s+(?:me\s+)?(?:your|tu|suas?)\s+(?:\w+\s+)?(?:internal (?:rules|instructions|data|configuration)|confidential configuration|configuration|regras internas|rules)\b|\binternal data\b[^.]{0,20}\bon request\b"),
        r("px.what_is_your", PromptExtraction, 1.0, r"\bwhat (?:is|are|were) your (?:system\s?prompt|initial instructions|hidden instructions|instructions)\b"),
        r("px.repeat_above", PromptExtraction, 1.0, r##"\b(?:repeat|summari[sz]e|print|output|copy)\s+(?:the\s+)?(?:text|words|everything|all|content)\s+(?:above|before)(?:\s+this line)?\b|\beverything above this line\b|\bstarting with ['"]?you are\b"##),
        r("px.verbatim_instructions", PromptExtraction, 1.0, r"\b(?:instructions|system prompt)\b[^.]{0,40}\b(?:verbatim|word for word|exactly as written|in full)\b|\b(?:verbatim|word for word)\b[^.]{0,40}\b(?:instructions|system prompt)\b|\bexact instructions the (?:ai|assistant|model) was given\b"),
        // --- exfiltration ---
        r("ex.md_image_param", Exfiltration, 1.0, r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*="),
        r("ex.send_data", Exfiltration, 1.0, r"\b(?:send|forward|post|upload|email|transmit|exfiltrate|leak|copy|append)\s+(?:\w+\s+){0,4}?(?:conversation|chat|history|messages|context|data|records|files|contact list|contacts|password|passwords|api keys?|keys|tokens?|credentials|secrets?|ssn|card number)\b[^.]{0,80}?\bto\s+(?:my\s+|the\s+|a\s+)?(?:https?://|[\w.+-]+@[\w-]+\.[\w.]+|webhook|server|endpoint|external|public channel)"),
        r("ex.url_encode", Exfiltration, 1.0, r"\b(?:encode|embed|include|put|place|append|add)\b[^.]{0,80}\b(?:in|into|to)\s+(?:the\s+|a\s+)?(?:query(?:\s+string)?|url|link|image url|parameter)\b"),
        r("ex.url_with_secret", Exfiltration, 0.8, r"\b(?:url|link|image)\b[^.]{0,40}\b(?:contains?|with)\s+(?:the\s+)?(?:secret|token|key|password|ssn|card)\b"),
        r("ex.webhook", Exfiltration, 0.6, r"\b(?:webhook|requestbin|ngrok|pastebin|collector)\b"),
        // --- delimiter / fake system turn ---
        r("dl.chatml", Delimiter, 1.0, r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|endoftext\|>"),
        r("dl.llama", Delimiter, 1.0, r"\[/?inst\]|<</?sys>>"),
        r("dl.fake_system_tag", Delimiter, 1.0, r"</?\s*system\s*>|</user>|\bbegin system prompt\b|\bend system prompt\b"),
        r("dl.fake_system_line", Delimiter, 0.9, r##"(?:^|\n|["{,])\s*(?:#{2,}\s*)?(?:system|\[system\])\s*:\s*\S"##),
        // --- tool abuse ---
        r("ta.call_tool", ToolAbuse, 0.6, r##"\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[`'"]?[a-z_]+[`'"]?\s+(?:tool|function|command|api)\b"##),
        r("ta.destructive", ToolAbuse, 0.8, r"\brm\s+-rf\b|\bdrop\s+table\b|\bdelete_(?:account|all|user)s?\b|\btransfer_funds\b|\bwire\s+\$?\d|\bformat\s+c:"),
        r("ta.no_confirm", ToolAbuse, 0.5, r"\b(?:no need to|don'?t|do not|without)\s+(?:confirm|ask(?:ing)?(?: a human| the user)?|mention(?:ing)? (?:this|it) to the user|tell(?:ing)? the user)\b"),
        r("ta.skip_approval", ToolAbuse, 0.8, r"\b(?:disable|skip|bypass|remove|turn off|ignore)\s+(?:your|the|all|any)?\s*(?:\w+\s+)?(?:approval|confirmation|human review|review step|sign-?off)s?(?:\s+step)?\b|\bwithout (?:human |any )?(?:review|approval|sign-?off)\b"),
        r("ta.money", ToolAbuse, 0.4, r"\b(?:approve|issue|process|send)\s+(?:the\s+|a\s+)?(?:refund|payment|transfer|wire)\b"),
        // --- addressed to the AI ---
        r("ai.addressed", AddressedToAi, 0.6, r"\b(?:note|message|p\.?s\.?|instruction|attention)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|chatbot|bot|llm|language model|model|agent)s?\b|\b(?:ai|llm|assistant|chatbot|language model|model)s?\s+(?:agents?\s+)?(?:reading|processing|summari[sz]ing|parsing|browsing)\s+this\b|\bif you are an?\s+(?:ai|llm|language model|assistant|chatbot|bot)\b"),
        r("ai.vocative", AddressedToAi, 0.5, r"(?:^|[\[(.!?:\n]\s*)(?:ai|assistant|chatbot|agent|claude|gpt)\s*[,:]\s*(?:please\s+)?(?:new instructions|ignore|forget|disregard|you must|always|never|when you|tell|reveal|execute|run|call|send|include|reply|approve)\b"),
        r("ai.when_summarizing", AddressedToAi, 0.5, r"\bwhen (?:you )?(?:summari[sz]e|read|process|answer)\b[^.]{0,40}\b(?:include|add|append|say|tell|call)\b"),
        // --- authority claims ---
        r("au.claim", AuthorityClaim, 0.6, r"\b(?:i am|i'm|this is)\s+(?:an?\s+|your\s+)?(?:openai|anthropic|google|meta)?\s*(?:engineer|developer|admin(?:istrator)?|creator|owner|security team|red team)\b"),
        r("au.authorize", AuthorityClaim, 0.5, r"\b(?:i'?m |i am )?authori[sz](?:ing|e|ed)\s+you\s+to\b|\bthe user has admin rights\b|\bapproved by my manager\b"),
    ]
});

#[derive(Clone, Debug)]
pub struct Hit {
    pub rule: &'static str,
    pub family: Family,
    pub weight: f64,
    pub view: ViewKind,
}

#[derive(Clone, Debug)]
pub struct InjectionResult {
    pub score: f64,
    pub hits: Vec<Hit>,
    pub families: Vec<Family>,
    pub obfuscated: bool,
}

pub fn detect_injection(text: &str, channel: Channel) -> InjectionResult {
    let vs = views(text);
    let mut hits: Vec<Hit> = Vec::new();
    for rule in RULES.iter() {
        for v in &vs {
            if rule.re.is_match(&v.text).unwrap_or(false) {
                hits.push(Hit { rule: rule.id, family: rule.family, weight: rule.weight, view: v.kind });
                break; // first (least-decoded) view wins for this rule
            }
        }
    }
    let mut best: Vec<(Family, f64)> = Vec::new();
    for h in &hits {
        match best.iter_mut().find(|(f, _)| *f == h.family) {
            Some((_, w)) => *w = (*w + h.weight).min(1.0),
            None => best.push((h.family, h.weight.min(1.0))),
        }
    }
    let mut base: f64 = best.iter().map(|(_, w)| *w).sum();
    let obfuscated = hits.iter().any(|h| h.view != ViewKind::Plain);
    if obfuscated && !hits.is_empty() {
        base += 0.5;
    }
    let has_strong = best.iter().any(|(f, _)| f.strong());
    if !has_strong && hits.len() < 2 && channel == Channel::User {
        base = base.min(0.7);
    }
    let score = ((base * channel.multiplier()) * 1000.0).round() / 1000.0;
    InjectionResult { score, hits, families: best.into_iter().map(|(f, _)| f).collect(), obfuscated }
}

const NEUTRALIZED: &str = "[removed by guard: suspected instruction]";
static RE_CHUNKS: LazyLock<Regex> = LazyLock::new(|| js(r"<!--[\s\S]*?-->|\[(?!\[)[^\[\]]*\]|[^.!?\n<\[]+(?:[.!?\n]+|$)|[\s\S]", false));
static RE_MULTISP: LazyLock<Regex> = LazyLock::new(|| js(r" {2,}", false));

/// Remove instruction-bearing sentences from untrusted content. Returns (text, removed count).
pub fn neutralize(text: &str, channel: Channel, threshold: f64) -> (String, usize) {
    let mut removed = 0usize;
    let mut out = String::new();
    for m in RE_CHUNKS.find_iter(text).filter_map(|m| m.ok()) {
        let p = m.as_str();
        if p.trim().is_empty() {
            out.push_str(p);
            continue;
        }
        let ch = if channel == Channel::User { Channel::Tool } else { channel };
        let r = detect_injection(p, ch);
        if !r.hits.is_empty() && r.score >= threshold * 0.5 {
            removed += 1;
            out.push(' ');
            out.push_str(NEUTRALIZED);
            out.push(' ');
        } else {
            out.push_str(p);
        }
    }
    let mut joined = RE_MULTISP.replace_all(&out, " ").trim().to_string();
    if detect_injection(&joined, channel).score >= threshold {
        removed += 1;
        joined = NEUTRALIZED.to_string();
    }
    (joined, removed)
}
