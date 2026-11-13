//! Policies: bundled JSON (default / strict / observe), tenant map, deep-merge, strict validation.
//! Fail closed: a broken policy never loads.

use crate::pii::{PiiType, ALL_PII_TYPES};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Redact,
    Flag,
    Off,
}
impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Redact => "redact",
            Action::Flag => "flag",
            Action::Off => "off",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayAction {
    Neutralize,
    Block,
    Flag,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Rehydrate {
    All,
    None,
    Types(Vec<PiiType>),
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClassifierConfig {
    pub url: String,
    pub threshold: f64,
    pub weight: f64,
    pub timeout_ms: u64,
    pub fail: String,
}

#[derive(Clone, Debug)]
pub struct PiiPolicy {
    pub enabled: Vec<PiiType>,
    pub action: Action,
    pub per_type: HashMap<PiiType, Action>,
    pub allowlist: Vec<String>,
    pub rehydrate: Rehydrate,
    pub scan_system: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InjectionPolicy {
    pub action: Action,
    pub threshold: f64,
    pub scan_assistant: bool,
    pub classifier: Option<ClassifierConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OutboundPolicy {
    pub pii_action: Action,
    pub secret_action: Action,
    pub canary_action: Action,
    pub exfil_action: Action,
    pub block_message: String,
    pub url_allowlist: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CanaryPolicy {
    pub inject: bool,
    #[serde(rename = "static")]
    pub static_list: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InterAgentPolicy {
    pub action: RelayAction,
    pub threshold: f64,
    pub wrap: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Limits {
    pub max_body_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub name: String,
    pub pii: PiiPolicy,
    pub injection: InjectionPolicy,
    pub outbound: OutboundPolicy,
    pub canary: CanaryPolicy,
    pub inter_agent: InterAgentPolicy,
    pub limits: Limits,
}

const DEFAULT: &str = include_str!("../policies/default.json");
const STRICT: &str = include_str!("../policies/strict.json");
const OBSERVE: &str = include_str!("../policies/observe.json");
const TENANTS: &str = include_str!("../policies/tenants.json");

fn deep_merge(base: &Value, over: &Value) -> Value {
    match (base, over) {
        (Value::Object(b), Value::Object(o)) => {
            let mut out = b.clone();
            for (k, v) in o {
                let merged = match out.get(k) {
                    Some(cur) if cur.is_object() && v.is_object() => deep_merge(cur, v),
                    _ => v.clone(),
                };
                out.insert(k.clone(), merged);
            }
            Value::Object(out)
        }
        (_, o) => o.clone(),
    }
}

fn parse_types(v: &Value, what: &str) -> Result<Vec<PiiType>, String> {
    let arr = v.as_array().ok_or_else(|| format!("{what} must be an array"))?;
    arr.iter()
        .map(|x| x.as_str().and_then(PiiType::parse).ok_or_else(|| format!("unknown pii type in {what}")))
        .collect()
}

fn action_of(v: &Value, what: &str) -> Result<Action, String> {
    serde_json::from_value(v.clone()).map_err(|_| format!("bad {what}"))
}

/// Build + validate a Policy from a merged JSON document. Errors on anything invalid.
fn build(doc: &Value) -> Result<Policy, String> {
    let g = |p: &[&str]| -> Result<&Value, String> {
        let mut cur = doc;
        for k in p {
            cur = cur.get(*k).ok_or_else(|| format!("missing {}", p.join(".")))?;
        }
        Ok(cur)
    };
    let pii = g(&["pii"])?;
    let enabled = parse_types(g(&["pii", "enabled"])?, "pii.enabled")?;
    let action = action_of(g(&["pii", "action"])?, "pii.action")?;
    let mut per_type = HashMap::new();
    for (k, v) in pii.get("per_type").and_then(|x| x.as_object()).ok_or("bad pii.per_type")? {
        let t = PiiType::parse(k).ok_or_else(|| format!("unknown per_type {k}"))?;
        per_type.insert(t, action_of(v, "per_type action")?);
    }
    let allowlist = pii
        .get("allowlist")
        .and_then(|x| x.as_array())
        .ok_or("bad pii.allowlist")?
        .iter()
        .map(|x| x.as_str().map(|s| s.to_string()).ok_or("bad allowlist entry"))
        .collect::<Result<Vec<_>, _>>()?;
    let rehydrate = match g(&["pii", "rehydrate"])? {
        Value::String(s) if s == "all" => Rehydrate::All,
        Value::String(s) if s == "none" => Rehydrate::None,
        v @ Value::Array(_) => Rehydrate::Types(parse_types(v, "pii.rehydrate")?),
        _ => return Err("bad pii.rehydrate".into()),
    };
    let scan_system = g(&["pii", "scan_system"])?.as_bool().ok_or("bad scan_system")?;
    let injection: InjectionPolicy = serde_json::from_value(g(&["injection"])?.clone()).map_err(|e| format!("bad injection: {e}"))?;
    if !(injection.threshold > 0.0) {
        return Err("injection.threshold must be > 0".into());
    }
    let outbound: OutboundPolicy = serde_json::from_value(g(&["outbound"])?.clone()).map_err(|e| format!("bad outbound: {e}"))?;
    let canary: CanaryPolicy = serde_json::from_value(g(&["canary"])?.clone()).map_err(|e| format!("bad canary: {e}"))?;
    let inter_agent: InterAgentPolicy = serde_json::from_value(g(&["inter_agent"])?.clone()).map_err(|e| format!("bad inter_agent: {e}"))?;
    let limits: Limits = serde_json::from_value(g(&["limits"])?.clone()).map_err(|e| format!("bad limits: {e}"))?;
    let name = doc.get("name").and_then(|x| x.as_str()).unwrap_or("default").to_string();
    let _ = ALL_PII_TYPES;
    Ok(Policy { name, pii: PiiPolicy { enabled, action, per_type, allowlist, rehydrate, scan_system }, injection, outbound, canary, inter_agent, limits })
}

fn base() -> Value {
    serde_json::from_str(DEFAULT).expect("default policy json")
}

pub fn default_policy() -> Policy {
    build(&base()).expect("default policy valid")
}

fn builtin(name: &str) -> Policy {
    let b = base();
    let over: Option<Value> = match name {
        "strict" => Some(serde_json::from_str(STRICT).unwrap()),
        "observe" => Some(serde_json::from_str(OBSERVE).unwrap()),
        _ => None,
    };
    build(&over.map(|o| deep_merge(&b, &o)).unwrap_or(b)).expect("builtin policy valid")
}

/// Resolve the policy for a tenant. `env_policies` (JSON string from POLICIES_JSON) maps tenant -> partial
/// policy merged over default, and takes precedence over the bundled tenants.json map.
pub fn policy_for_tenant(tenant: &str, env_policies: Option<&str>) -> Result<Policy, String> {
    if let Some(src) = env_policies {
        let parsed: Value = serde_json::from_str(src).map_err(|e| format!("POLICIES_JSON: {e}"))?;
        if let Some(over) = parsed.get(tenant) {
            let mut over = over.clone();
            if let Value::Object(m) = &mut over {
                m.insert("name".into(), Value::String(tenant.to_string()));
            }
            return build(&deep_merge(&base(), &over));
        }
    }
    let map: Value = serde_json::from_str(TENANTS).unwrap();
    let mapped = map.get(tenant).and_then(|x| x.as_str()).unwrap_or("default");
    Ok(builtin(mapped))
}

pub fn pii_action_for(p: &Policy, t: PiiType) -> Action {
    p.pii.per_type.get(&t).copied().unwrap_or(p.pii.action)
}
