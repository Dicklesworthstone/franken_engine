//! Enrichment integration tests for `extension_host_authority_guard` module.
//!
//! Covers: ViolationKind, ExtensionHostFinding, ExtensionHostExemption,
//! ExtensionHostExemptionRegistry — Display uniqueness, serde roundtrips,
//! exemption registry matching (exact line, module-wide with line=0),
//! exemption not matching different modules/kinds, registry count, clone/eq.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::extension_host_authority_guard::*;

// ── helpers ──────────────────────────────────────────────────────────────

fn all_violation_kinds() -> Vec<ViolationKind> {
    vec![
        ViolationKind::ForbiddenPattern,
        ViolationKind::MissingCxParameter,
        ViolationKind::DirectUpstreamImport,
        ViolationKind::CanonicalTypeShadow,
    ]
}

fn sample_finding() -> ExtensionHostFinding {
    ExtensionHostFinding {
        kind: ViolationKind::DirectUpstreamImport,
        module_path: "ext_host::bridge".to_string(),
        file_path: "src/bridge.rs".to_string(),
        line: 5,
        source_line: "use franken_kernel::Cx;".to_string(),
        description: "Direct upstream import: `use franken_kernel`".to_string(),
        remediation: "Import from crate::control_plane instead".to_string(),
        exempted: false,
    }
}

fn sample_exemption(id: &str, module: &str, kind: ViolationKind, token: &str, line: usize) -> ExtensionHostExemption {
    ExtensionHostExemption {
        exemption_id: id.to_string(),
        module_path: module.to_string(),
        kind,
        matched_token: token.to_string(),
        reason: "test exemption".to_string(),
        line,
    }
}

// ── test: ViolationKind Display uniqueness ───────────────────────────────

#[test]
fn enrichment_violation_kind_display_all_unique() {
    let strs: BTreeSet<String> = all_violation_kinds().iter().map(|k| k.to_string()).collect();
    assert_eq!(strs.len(), 4);
}

// ── test: ViolationKind Display stable values ────────────────────────────

#[test]
fn enrichment_violation_kind_display_stable_values() {
    assert_eq!(ViolationKind::ForbiddenPattern.to_string(), "forbidden_pattern");
    assert_eq!(ViolationKind::MissingCxParameter.to_string(), "missing_cx_parameter");
    assert_eq!(ViolationKind::DirectUpstreamImport.to_string(), "direct_upstream_import");
    assert_eq!(ViolationKind::CanonicalTypeShadow.to_string(), "canonical_type_shadow");
}

// ── test: ViolationKind ordering ─────────────────────────────────────────

#[test]
fn enrichment_violation_kind_ordering() {
    assert!(ViolationKind::ForbiddenPattern < ViolationKind::MissingCxParameter);
    assert!(ViolationKind::MissingCxParameter < ViolationKind::DirectUpstreamImport);
    assert!(ViolationKind::DirectUpstreamImport < ViolationKind::CanonicalTypeShadow);
}

// ── test: ViolationKind serde roundtrip all variants ─────────────────────

#[test]
fn enrichment_violation_kind_serde_all_variants() {
    for kind in all_violation_kinds() {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ViolationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ── test: ViolationKind serde JSON strings distinct ──────────────────────

#[test]
fn enrichment_violation_kind_serde_json_strings_distinct() {
    let jsons: BTreeSet<String> = all_violation_kinds().iter().map(|k| serde_json::to_string(k).unwrap()).collect();
    assert_eq!(jsons.len(), 4);
}

// ── test: ViolationKind Debug distinctness ───────────────────────────────

#[test]
fn enrichment_violation_kind_debug_distinct() {
    let debugs: BTreeSet<String> = all_violation_kinds().iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

// ── test: ViolationKind Clone/Eq ─────────────────────────────────────────

#[test]
fn enrichment_violation_kind_clone_eq() {
    for kind in all_violation_kinds() {
        let cloned = kind;
        assert_eq!(kind, cloned);
    }
}

// ── test: ViolationKind Hash consistency ─────────────────────────────────

#[test]
fn enrichment_violation_kind_hash_consistent() {
    use std::hash::{Hash, Hasher};
    for kind in all_violation_kinds() {
        let h1 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            kind.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            kind.hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }
}

// ── test: ViolationKind in BTreeSet ──────────────────────────────────────

#[test]
fn enrichment_violation_kind_btreeset() {
    let mut set = BTreeSet::new();
    for kind in all_violation_kinds() {
        set.insert(kind);
    }
    assert_eq!(set.len(), 4);
    set.insert(ViolationKind::ForbiddenPattern);
    assert_eq!(set.len(), 4); // no dup
}

// ── test: ExtensionHostFinding serde roundtrip ───────────────────────────

#[test]
fn enrichment_finding_serde_roundtrip() {
    let finding = sample_finding();
    let json = serde_json::to_string(&finding).unwrap();
    let back: ExtensionHostFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

// ── test: ExtensionHostFinding serde with exempted=true ──────────────────

#[test]
fn enrichment_finding_serde_exempted_true() {
    let mut finding = sample_finding();
    finding.exempted = true;
    let json = serde_json::to_string(&finding).unwrap();
    let back: ExtensionHostFinding = serde_json::from_str(&json).unwrap();
    assert!(back.exempted);
}

// ── test: ExtensionHostFinding JSON field names ──────────────────────────

#[test]
fn enrichment_finding_json_field_names() {
    let finding = sample_finding();
    let val = serde_json::to_value(&finding).unwrap();
    let obj = val.as_object().unwrap();
    for key in ["kind", "module_path", "file_path", "line", "source_line", "description", "remediation", "exempted"] {
        assert!(obj.contains_key(key), "missing: {key}");
    }
    assert_eq!(obj.len(), 8);
}

// ── test: ExtensionHostFinding ordering ──────────────────────────────────

#[test]
fn enrichment_finding_ordering_by_kind() {
    let mut f1 = sample_finding();
    f1.kind = ViolationKind::ForbiddenPattern;
    let mut f2 = sample_finding();
    f2.kind = ViolationKind::CanonicalTypeShadow;
    assert!(f1 < f2);
}

// ── test: ExtensionHostFinding clone independence ────────────────────────

#[test]
fn enrichment_finding_clone_independence() {
    let finding = sample_finding();
    let mut cloned = finding.clone();
    cloned.line = 999;
    assert_ne!(finding.line, cloned.line);
    assert_eq!(finding.line, 5);
}

// ── test: ExtensionHostExemption serde roundtrip ─────────────────────────

#[test]
fn enrichment_exemption_serde_roundtrip() {
    let exemption = sample_exemption("e1", "mod", ViolationKind::ForbiddenPattern, "std::fs", 0);
    let json = serde_json::to_string(&exemption).unwrap();
    let back: ExtensionHostExemption = serde_json::from_str(&json).unwrap();
    assert_eq!(exemption, back);
}

// ── test: ExtensionHostExemption serde all ViolationKind variants ────────

#[test]
fn enrichment_exemption_serde_all_kinds() {
    for (i, kind) in all_violation_kinds().iter().enumerate() {
        let ex = sample_exemption(&format!("e{i}"), "m", *kind, "tok", 0);
        let json = serde_json::to_string(&ex).unwrap();
        let back: ExtensionHostExemption = serde_json::from_str(&json).unwrap();
        assert_eq!(ex, back);
    }
}

// ── test: ExtensionHostExemption JSON field names ────────────────────────

#[test]
fn enrichment_exemption_json_field_names() {
    let ex = sample_exemption("e1", "m", ViolationKind::ForbiddenPattern, "t", 5);
    let val = serde_json::to_value(&ex).unwrap();
    let obj = val.as_object().unwrap();
    for key in ["exemption_id", "module_path", "kind", "matched_token", "reason", "line"] {
        assert!(obj.contains_key(key), "missing: {key}");
    }
    assert_eq!(obj.len(), 6);
}

// ── test: ExtensionHostExemptionRegistry new is empty ────────────────────

#[test]
fn enrichment_registry_new_is_empty() {
    let reg = ExtensionHostExemptionRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    assert!(reg.entries().is_empty());
}

// ── test: registry add increments count ──────────────────────────────────

#[test]
fn enrichment_registry_add_increments_count() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "m1", ViolationKind::ForbiddenPattern, "t1", 0));
    assert_eq!(reg.len(), 1);
    assert!(!reg.is_empty());
    reg.add(sample_exemption("e2", "m2", ViolationKind::MissingCxParameter, "t2", 0));
    assert_eq!(reg.len(), 2);
}

// ── test: registry is_exempted with module-wide (line=0) ─────────────────

#[test]
fn enrichment_registry_module_wide_exemption() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "ext::boot", ViolationKind::DirectUpstreamImport, "use franken_kernel", 0));

    assert!(reg.is_exempted("ext::boot", ViolationKind::DirectUpstreamImport, "use franken_kernel", 1));
    assert!(reg.is_exempted("ext::boot", ViolationKind::DirectUpstreamImport, "use franken_kernel", 42));
    assert!(reg.is_exempted("ext::boot", ViolationKind::DirectUpstreamImport, "use franken_kernel", 999));
}

// ── test: registry is_exempted with exact line ───────────────────────────

#[test]
fn enrichment_registry_exact_line_exemption() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "ext::boot", ViolationKind::ForbiddenPattern, "std::fs", 5));

    assert!(reg.is_exempted("ext::boot", ViolationKind::ForbiddenPattern, "std::fs", 5));
    assert!(!reg.is_exempted("ext::boot", ViolationKind::ForbiddenPattern, "std::fs", 6));
    assert!(!reg.is_exempted("ext::boot", ViolationKind::ForbiddenPattern, "std::fs", 4));
}

// ── test: registry is_exempted not matching different module ─────────────

#[test]
fn enrichment_registry_different_module_not_matched() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "ext::a", ViolationKind::ForbiddenPattern, "std::fs", 0));

    assert!(!reg.is_exempted("ext::b", ViolationKind::ForbiddenPattern, "std::fs", 1));
}

// ── test: registry is_exempted not matching different kind ───────────────

#[test]
fn enrichment_registry_different_kind_not_matched() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "ext::a", ViolationKind::ForbiddenPattern, "std::fs", 0));

    assert!(!reg.is_exempted("ext::a", ViolationKind::MissingCxParameter, "std::fs", 1));
}

// ── test: registry is_exempted not matching different token ──────────────

#[test]
fn enrichment_registry_different_token_not_matched() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "ext::a", ViolationKind::ForbiddenPattern, "std::fs", 0));

    assert!(!reg.is_exempted("ext::a", ViolationKind::ForbiddenPattern, "std::net", 1));
}

// ── test: registry serde roundtrip ───────────────────────────────────────

#[test]
fn enrichment_registry_serde_roundtrip() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "m1", ViolationKind::ForbiddenPattern, "t1", 0));
    reg.add(sample_exemption("e2", "m2", ViolationKind::CanonicalTypeShadow, "t2", 5));
    let json = serde_json::to_string(&reg).unwrap();
    let back: ExtensionHostExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

// ── test: registry serde empty ───────────────────────────────────────────

#[test]
fn enrichment_registry_serde_empty() {
    let reg = ExtensionHostExemptionRegistry::new();
    let json = serde_json::to_string(&reg).unwrap();
    let back: ExtensionHostExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
    assert!(back.is_empty());
}

// ── test: registry entries returns all added ─────────────────────────────

#[test]
fn enrichment_registry_entries_returns_all() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    for i in 0..5 {
        reg.add(sample_exemption(&format!("e{i}"), &format!("m{i}"), ViolationKind::ForbiddenPattern, "t", 0));
    }
    assert_eq!(reg.entries().len(), 5);
    assert_eq!(reg.len(), 5);
}

// ── test: registry clone independence ────────────────────────────────────

#[test]
fn enrichment_registry_clone_independence() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "m", ViolationKind::ForbiddenPattern, "t", 0));
    let cloned = reg.clone();
    reg.add(sample_exemption("e2", "m2", ViolationKind::MissingCxParameter, "t2", 0));
    assert_eq!(cloned.len(), 1);
    assert_eq!(reg.len(), 2);
}

// ── test: registry Default trait ─────────────────────────────────────────

#[test]
fn enrichment_registry_default() {
    let reg = ExtensionHostExemptionRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

// ── test: ExtensionHostFinding with all ViolationKind variants serde ─────

#[test]
fn enrichment_finding_all_kinds_serde() {
    for kind in all_violation_kinds() {
        let mut finding = sample_finding();
        finding.kind = kind;
        let json = serde_json::to_string(&finding).unwrap();
        let back: ExtensionHostFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }
}

// ── test: ExtensionHostExemption clone/eq ────────────────────────────────

#[test]
fn enrichment_exemption_clone_eq() {
    let ex = sample_exemption("e1", "m", ViolationKind::ForbiddenPattern, "t", 5);
    let cloned = ex.clone();
    assert_eq!(ex, cloned);
}

// ── test: multiple exemptions for same module ────────────────────────────

#[test]
fn enrichment_multiple_exemptions_same_module() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(sample_exemption("e1", "ext::m", ViolationKind::ForbiddenPattern, "std::fs", 0));
    reg.add(sample_exemption("e2", "ext::m", ViolationKind::DirectUpstreamImport, "use franken_kernel", 0));

    assert!(reg.is_exempted("ext::m", ViolationKind::ForbiddenPattern, "std::fs", 1));
    assert!(reg.is_exempted("ext::m", ViolationKind::DirectUpstreamImport, "use franken_kernel", 10));
    assert!(!reg.is_exempted("ext::m", ViolationKind::CanonicalTypeShadow, "TraceId", 1));
}
