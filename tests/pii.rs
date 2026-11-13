use llm_guard::pii::{detect_all, detect_pii, iban_valid, luhn_valid, PiiType::*};

fn types(t: &str) -> Vec<llm_guard::pii::PiiType> {
    detect_all(t).iter().map(|e| e.kind).collect()
}

#[test]
fn luhn_validates_published_test_card_numbers_and_rejects_off_by_one() {
    assert!(luhn_valid("4111111111111111"));
    assert!(!luhn_valid("4111111111111112"));
}

#[test]
fn detects_cards_with_spaces_or_dashes_only_when_luhn_and_prefix_pass() {
    assert_eq!(types("card 4111-1111-1111-1111"), vec![CreditCard]);
    assert_eq!(types("invoice 1234 5678 9012 3456"), vec![]);
}

#[test]
fn validates_iban_mod97_and_country_length() {
    assert!(iban_valid("GB82WEST12345698765432"));
    assert!(!iban_valid("GB82WEST12345698765433"));
    assert!(!iban_valid("DE8937040044053201300")); // wrong length
}

#[test]
fn rejects_ssns_in_never_issued_ranges() {
    assert_eq!(types("ssn 512-38-4471"), vec![Ssn]);
    assert_eq!(types("000-12-3456 666-12-3456 912-34-5678"), vec![]);
}

#[test]
fn detects_emails_including_rfc_apostrophes() {
    assert_eq!(detect_all("to o'neil@example.com now")[0].value, "o'neil@example.com");
    assert_eq!(types("user@localhost"), vec![]);
}

#[test]
fn detects_nanp_and_international_phones_but_not_bare_numbers() {
    assert_eq!(types("call (312) 555-0142"), vec![Phone]);
    assert_eq!(types("+44 20 7946 0958"), vec![Phone]);
    assert_eq!(types("we have 3125550142 widgets"), vec![]);
    assert_eq!(types("text me 3125550142"), vec![Phone]);
}

#[test]
fn detects_vendor_secrets_and_high_entropy_assignments_not_low_entropy_ones() {
    assert_eq!(types("key AKIAIOSFODNN7EXAMPLE"), vec![Secret]);
    assert_eq!(types("client_secret: 9fK2mQ7xL4pR8vN1"), vec![Secret]);
    assert_eq!(types("password: hunter2"), vec![]);
}

#[test]
fn detects_us_street_addresses_and_po_boxes() {
    assert_eq!(detect_all("at 221 N Clark St, Chicago, IL 60601.")[0].value, "221 N Clark St, Chicago, IL 60601");
    assert_eq!(types("P.O. Box 4417"), vec![Address]);
    assert_eq!(types("I walked 5 miles"), vec![]);
}

#[test]
fn respects_allowlist_values_and_at_domain_entries() {
    let all = llm_guard::pii::ALL_PII_TYPES;
    assert!(detect_pii("ops@acme.example", &all, &["@acme.example".to_string()]).is_empty());
    assert_eq!(detect_pii("x@other.example", &all, &["@acme.example".to_string()]).len(), 1);
}

#[test]
fn resolves_overlaps_by_priority_secret_wins_over_phone_digits_inside_it() {
    assert_eq!(types("Bearer abcdefghij3125550142klmnopqrstu"), vec![Secret]);
}
