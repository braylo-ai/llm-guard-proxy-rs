use llm_guard::pii::{detect_all, PiiType};
use llm_guard::policy::Rehydrate;
use llm_guard::vault::{MemoryVaultStore, Vault, PLACEHOLDER_RE};

#[test]
fn issues_uuid_placeholders_that_are_stable_for_a_value_within_a_session() {
    let store = MemoryVaultStore::new();
    let mut v = Vault::new("s1", "k", &store);
    let a = v.placeholder_for(PiiType::Email, "a@example.com");
    let re = fancy_regex::Regex::new(r"^\[\[EMAIL:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\]\]$").unwrap();
    assert!(re.is_match(&a).unwrap(), "{a}");
    assert_eq!(v.placeholder_for(PiiType::Email, "a@example.com"), a);
    assert_ne!(v.placeholder_for(PiiType::Email, "b@example.com"), a);
}

#[test]
fn is_stable_across_requests_in_the_same_session_and_differs_across_sessions() {
    let store = MemoryVaultStore::new();
    let p1 = Vault::new("s1", "k", &store).placeholder_for(PiiType::Phone, "312-555-0142");
    let p2 = Vault::new("s1", "k", &store).placeholder_for(PiiType::Phone, "312-555-0142");
    let p3 = Vault::new("s2", "k", &store).placeholder_for(PiiType::Phone, "312-555-0142");
    assert_eq!(p1, p2);
    assert_ne!(p1, p3);
}

#[test]
fn rehydrates_only_allowed_types_and_only_placeholders_from_its_own_session() {
    let store = MemoryVaultStore::new();
    let mut v = Vault::new("s1", "k", &store);
    let text = "mail jane@example.com, ssn 512-38-4471";
    let red = v.redact(text, &detect_all(text));
    assert!(!red.contains("jane@example.com"));
    let (back, _) = Vault::new("s1", "k", &store).rehydrate(&red, &Rehydrate::Types(vec![PiiType::Email]));
    assert!(back.contains("jane@example.com"));
    assert!(!back.contains("512-38-4471"));
    let (_, restored) = Vault::new("s2", "k", &store).rehydrate(&red, &Rehydrate::All);
    assert_eq!(restored, 0);
}

#[test]
fn never_invents_a_value_for_an_unknown_placeholder() {
    let store = MemoryVaultStore::new();
    let mut v = Vault::new("s1", "k", &store);
    let fake = "[[EMAIL:00000000-0000-8000-8000-000000000000]]";
    assert_eq!(v.rehydrate(fake, &Rehydrate::All).0, fake);
}

#[test]
fn placeholder_regex_matches_issued_placeholders() {
    let store = MemoryVaultStore::new();
    let mut v = Vault::new("s", "k", &store);
    let ph = v.placeholder_for(PiiType::Iban, "GB82WEST12345698765432");
    assert_eq!(PLACEHOLDER_RE.find_iter(&ph).count(), 1);
}
