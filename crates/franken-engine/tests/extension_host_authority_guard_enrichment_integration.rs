#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

//! Enrichment integration tests for the `extension_host_authority_guard` module.
//!
//! Covers: serde roundtrips, Display distinctness, GuardConfig defaults and
//! customization, exemption registry operations, audit result structure,
//! source auditing edge cases, canonical type shadowing, direct import
//! detection, and deterministic behavior.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::extension_host_authority_guard::{
    ExtensionHostAuditResult, ExtensionHostExemption, ExtensionHostExemptionRegistry,
    ExtensionHostFinding, ExtensionHostGuard, GuardConfig, ViolationKind,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn standard_guard() -> ExtensionHostGuard {
    ExtensionHostGuard::standard()
}

fn cx_guard(prefix: &str) -> ExtensionHostGuard {
    let mut config = GuardConfig::default();
    config.add_cx_audited_prefix(prefix);
    ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new())
}

fn no_base_guard() -> ExtensionHostGuard {
    let config = GuardConfig {
        include_base_patterns: false,
        ..GuardConfig::default()
    };
    ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new())
}

// ===========================================================================
// ViolationKind — serde and Display
// ===========================================================================

#[test]
fn enrichment_violation_kind_serde_roundtrip_all() {
    let kinds = [
        ViolationKind::ForbiddenPattern,
        ViolationKind::MissingCxParameter,
        ViolationKind::DirectUpstreamImport,
        ViolationKind::CanonicalTypeShadow,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: ViolationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn enrichment_violation_kind_display_all_distinct() {
    let mut set = BTreeSet::new();
    set.insert(ViolationKind::ForbiddenPattern.to_string());
    set.insert(ViolationKind::MissingCxParameter.to_string());
    set.insert(ViolationKind::DirectUpstreamImport.to_string());
    set.insert(ViolationKind::CanonicalTypeShadow.to_string());
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_violation_kind_display_snake_case() {
    assert_eq!(ViolationKind::ForbiddenPattern.to_string(), "forbidden_pattern");
    assert_eq!(ViolationKind::MissingCxParameter.to_string(), "missing_cx_parameter");
    assert_eq!(ViolationKind::DirectUpstreamImport.to_string(), "direct_upstream_import");
    assert_eq!(ViolationKind::CanonicalTypeShadow.to_string(), "canonical_type_shadow");
}

#[test]
fn enrichment_violation_kind_ordering() {
    assert!(ViolationKind::ForbiddenPattern < ViolationKind::MissingCxParameter);
    assert!(ViolationKind::MissingCxParameter < ViolationKind::DirectUpstreamImport);
    assert!(ViolationKind::DirectUpstreamImport < ViolationKind::CanonicalTypeShadow);
}

#[test]
fn enrichment_violation_kind_clone_copy() {
    let k = ViolationKind::CanonicalTypeShadow;
    let k2 = k;
    assert_eq!(k, k2);
}

#[test]
fn enrichment_violation_kind_deterministic_serde() {
    let k = ViolationKind::ForbiddenPattern;
    let a = serde_json::to_string(&k).unwrap();
    let b = serde_json::to_string(&k).unwrap();
    assert_eq!(a, b);
}

// ===========================================================================
// ExtensionHostFinding — serde
// ===========================================================================

#[test]
fn enrichment_finding_serde_roundtrip() {
    let finding = ExtensionHostFinding {
        kind: ViolationKind::DirectUpstreamImport,
        module_path: "ext_host::loader".to_string(),
        file_path: "src/loader.rs".to_string(),
        line: 42,
        source_line: "use franken_kernel::something;".to_string(),
        description: "Direct upstream import".to_string(),
        remediation: "Use adapter layer".to_string(),
        exempted: false,
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: ExtensionHostFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn enrichment_finding_fields_accessible() {
    let f = ExtensionHostFinding {
        kind: ViolationKind::CanonicalTypeShadow,
        module_path: "mod".to_string(),
        file_path: "file.rs".to_string(),
        line: 10,
        source_line: "struct TraceId {}".to_string(),
        description: "desc".to_string(),
        remediation: "fix".to_string(),
        exempted: true,
    };
    assert_eq!(f.kind, ViolationKind::CanonicalTypeShadow);
    assert_eq!(f.module_path, "mod");
    assert_eq!(f.file_path, "file.rs");
    assert_eq!(f.line, 10);
    assert!(f.exempted);
}

// ===========================================================================
// ExtensionHostExemption — serde
// ===========================================================================

#[test]
fn enrichment_exemption_serde_roundtrip() {
    let ex = ExtensionHostExemption {
        exemption_id: "ex-001".to_string(),
        module_path: "ext_host::special".to_string(),
        kind: ViolationKind::ForbiddenPattern,
        matched_token: "std::fs::read".to_string(),
        reason: "Legacy code path under migration".to_string(),
        line: 55,
    };
    let json = serde_json::to_string(&ex).unwrap();
    let back: ExtensionHostExemption = serde_json::from_str(&json).unwrap();
    assert_eq!(ex, back);
}

#[test]
fn enrichment_exemption_fields_accessible() {
    let ex = ExtensionHostExemption {
        exemption_id: "ex-002".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "use franken_kernel".to_string(),
        reason: "r".to_string(),
        line: 0,
    };
    assert_eq!(ex.exemption_id, "ex-002");
    assert_eq!(ex.kind, ViolationKind::DirectUpstreamImport);
    assert_eq!(ex.line, 0);
}

// ===========================================================================
// ExtensionHostExemptionRegistry — operations
// ===========================================================================

#[test]
fn enrichment_registry_new_is_empty() {
    let r = ExtensionHostExemptionRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.entries().is_empty());
}

#[test]
fn enrichment_registry_add_increases_count() {
    let mut r = ExtensionHostExemptionRegistry::new();
    r.add(ExtensionHostExemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::ForbiddenPattern,
        matched_token: "std::fs".to_string(),
        reason: "r".to_string(),
        line: 0,
    });
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn enrichment_registry_is_exempted_exact_match() {
    let mut r = ExtensionHostExemptionRegistry::new();
    r.add(ExtensionHostExemption {
        exemption_id: "e1".to_string(),
        module_path: "ext_host::loader".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "legacy".to_string(),
        line: 10,
    });
    assert!(r.is_exempted(
        "ext_host::loader",
        ViolationKind::DirectUpstreamImport,
        "Direct upstream import: `use franken_kernel`",
        10,
    ));
}

#[test]
fn enrichment_registry_is_exempted_line_zero_matches_any_line() {
    let mut r = ExtensionHostExemptionRegistry::new();
    r.add(ExtensionHostExemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::ForbiddenPattern,
        matched_token: "desc".to_string(),
        reason: "module-wide".to_string(),
        line: 0, // module-wide
    });
    assert!(r.is_exempted("m", ViolationKind::ForbiddenPattern, "desc", 1));
    assert!(r.is_exempted("m", ViolationKind::ForbiddenPattern, "desc", 999));
}

#[test]
fn enrichment_registry_is_exempted_wrong_module_returns_false() {
    let mut r = ExtensionHostExemptionRegistry::new();
    r.add(ExtensionHostExemption {
        exemption_id: "e1".to_string(),
        module_path: "correct_module".to_string(),
        kind: ViolationKind::ForbiddenPattern,
        matched_token: "t".to_string(),
        reason: "r".to_string(),
        line: 0,
    });
    assert!(!r.is_exempted("wrong_module", ViolationKind::ForbiddenPattern, "t", 1));
}

#[test]
fn enrichment_registry_serde_roundtrip() {
    let mut r = ExtensionHostExemptionRegistry::new();
    r.add(ExtensionHostExemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::CanonicalTypeShadow,
        matched_token: "t".to_string(),
        reason: "r".to_string(),
        line: 5,
    });
    let json = serde_json::to_string(&r).unwrap();
    let back: ExtensionHostExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// GuardConfig — defaults and customization
// ===========================================================================

#[test]
fn enrichment_guard_config_default_has_forbidden_imports() {
    let cfg = GuardConfig::default();
    assert!(!cfg.forbidden_imports.is_empty());
    assert!(cfg.forbidden_imports.iter().any(|(p, _)| p.contains("franken_kernel")));
    assert!(cfg.forbidden_imports.iter().any(|(p, _)| p.contains("franken_decision")));
    assert!(cfg.forbidden_imports.iter().any(|(p, _)| p.contains("franken_evidence")));
}

#[test]
fn enrichment_guard_config_default_has_canonical_types() {
    let cfg = GuardConfig::default();
    assert!(cfg.canonical_types.contains("TraceId"));
    assert!(cfg.canonical_types.contains("DecisionId"));
    assert!(cfg.canonical_types.contains("PolicyId"));
    assert!(cfg.canonical_types.contains("Budget"));
    assert!(cfg.canonical_types.contains("Cx"));
}

#[test]
fn enrichment_guard_config_default_has_effectful_indicators() {
    let cfg = GuardConfig::default();
    assert!(cfg.effectful_indicators.iter().any(|s| s == "dispatch_hostcall"));
    assert!(cfg.effectful_indicators.iter().any(|s| s == "consume_budget"));
}

#[test]
fn enrichment_guard_config_default_include_base_patterns_true() {
    let cfg = GuardConfig::default();
    assert!(cfg.include_base_patterns);
}

#[test]
fn enrichment_guard_config_add_cx_prefix() {
    let mut cfg = GuardConfig::default();
    cfg.add_cx_audited_prefix("ext_host");
    assert!(cfg.cx_audited_module_prefixes.contains("ext_host"));
}

#[test]
fn enrichment_guard_config_add_effectful_indicator() {
    let mut cfg = GuardConfig::default();
    cfg.add_effectful_indicator("custom_effect");
    assert!(cfg.effectful_indicators.iter().any(|s| s == "custom_effect"));
}

#[test]
fn enrichment_guard_config_add_forbidden_import() {
    let mut cfg = GuardConfig::default();
    cfg.add_forbidden_import("use custom_crate", "Use adapter instead");
    assert!(cfg.forbidden_imports.iter().any(|(p, _)| p == "use custom_crate"));
}

#[test]
fn enrichment_guard_config_serde_roundtrip() {
    let cfg = GuardConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GuardConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// ExtensionHostAuditResult — serde
// ===========================================================================

#[test]
fn enrichment_audit_result_serde_roundtrip() {
    let result = ExtensionHostAuditResult {
        findings: vec![],
        violation_count: 0,
        exemption_count: 0,
        modules_audited: vec!["mod_a".to_string()],
        passed: true,
        summary_by_kind: BTreeMap::new(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ExtensionHostAuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_audit_result_fields_accessible() {
    let result = ExtensionHostAuditResult {
        findings: vec![],
        violation_count: 3,
        exemption_count: 1,
        modules_audited: vec!["a".to_string(), "b".to_string()],
        passed: false,
        summary_by_kind: {
            let mut m = BTreeMap::new();
            m.insert("forbidden_pattern".to_string(), 2);
            m.insert("missing_cx_parameter".to_string(), 1);
            m
        },
    };
    assert_eq!(result.violation_count, 3);
    assert_eq!(result.exemption_count, 1);
    assert!(!result.passed);
    assert_eq!(result.modules_audited.len(), 2);
    assert_eq!(result.summary_by_kind.len(), 2);
}

// ===========================================================================
// ExtensionHostGuard — audit_source edge cases
// ===========================================================================

#[test]
fn enrichment_empty_source_produces_no_findings() {
    let guard = standard_guard();
    let findings = guard.audit_source("mod", "file.rs", "");
    assert!(findings.is_empty());
}

#[test]
fn enrichment_comment_only_source_no_findings() {
    let guard = standard_guard();
    let source = "// This is just a comment\n// use franken_kernel::something;\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    // Comments should be skipped for direct import detection
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(import_findings.is_empty());
}

#[test]
fn enrichment_detects_direct_upstream_import_franken_kernel() {
    let guard = no_base_guard();
    let source = "use franken_kernel::core;\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    assert!(findings.iter().any(|f| f.kind == ViolationKind::DirectUpstreamImport));
}

#[test]
fn enrichment_detects_direct_upstream_import_franken_decision() {
    let guard = no_base_guard();
    let source = "use franken_decision::policy;\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    assert!(findings.iter().any(|f| f.kind == ViolationKind::DirectUpstreamImport));
}

#[test]
fn enrichment_detects_direct_upstream_import_franken_evidence() {
    let guard = no_base_guard();
    let source = "use franken_evidence::ledger;\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    assert!(findings.iter().any(|f| f.kind == ViolationKind::DirectUpstreamImport));
}

#[test]
fn enrichment_detects_canonical_type_shadow_struct() {
    let guard = no_base_guard();
    let source = "pub struct TraceId { id: String }\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    assert!(findings.iter().any(|f| f.kind == ViolationKind::CanonicalTypeShadow));
}

#[test]
fn enrichment_detects_canonical_type_shadow_enum() {
    let guard = no_base_guard();
    let source = "pub enum PolicyId { V1, V2 }\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    assert!(findings.iter().any(|f| f.kind == ViolationKind::CanonicalTypeShadow));
}

#[test]
fn enrichment_detects_canonical_type_shadow_type_alias() {
    let guard = no_base_guard();
    let source = "type Budget = u64;\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    assert!(findings.iter().any(|f| f.kind == ViolationKind::CanonicalTypeShadow));
}

#[test]
fn enrichment_no_shadow_for_non_canonical_type() {
    let guard = no_base_guard();
    let source = "pub struct MyCustomType { data: Vec<u8> }\n";
    let findings = guard.audit_source("mod", "file.rs", source);
    assert!(findings.iter().all(|f| f.kind != ViolationKind::CanonicalTypeShadow));
}

// ===========================================================================
// ExtensionHostGuard — audit_all
// ===========================================================================

#[test]
fn enrichment_audit_all_empty_sources_passes() {
    let guard = standard_guard();
    let sources: BTreeMap<(String, String), String> = BTreeMap::new();
    let result = guard.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert_eq!(result.exemption_count, 0);
    assert!(result.findings.is_empty());
}

#[test]
fn enrichment_audit_all_clean_sources_passes() {
    let guard = standard_guard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("mod_a".to_string(), "src/a.rs".to_string()),
        "fn compute(x: u64) -> u64 { x + 1 }".to_string(),
    );
    sources.insert(
        ("mod_b".to_string(), "src/b.rs".to_string()),
        "fn transform(data: &[u8]) -> Vec<u8> { data.to_vec() }".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.modules_audited.len(), 2);
}

#[test]
fn enrichment_audit_all_with_violations_fails() {
    let guard = no_base_guard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("mod_a".to_string(), "src/a.rs".to_string()),
        "use franken_kernel::core;\nstruct TraceId { id: String }".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(!result.passed);
    assert!(result.violation_count >= 2);
}

#[test]
fn enrichment_audit_all_summary_by_kind_counts_correctly() {
    let guard = no_base_guard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("mod_a".to_string(), "src/a.rs".to_string()),
        "use franken_kernel::core;\nuse franken_decision::policy;\n".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(result
        .summary_by_kind
        .get("direct_upstream_import")
        .is_some_and(|&c| c >= 2));
}

// ===========================================================================
// ExtensionHostGuard — config and exemptions accessors
// ===========================================================================

#[test]
fn enrichment_guard_config_accessor() {
    let guard = standard_guard();
    let cfg = guard.config();
    assert!(cfg.include_base_patterns);
    assert!(!cfg.forbidden_imports.is_empty());
}

#[test]
fn enrichment_guard_exemptions_accessor() {
    let guard = standard_guard();
    assert!(guard.exemptions().is_empty());
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn enrichment_audit_deterministic_same_input_same_output() {
    let guard = standard_guard();
    let source = "use franken_kernel::core;\nstruct TraceId { id: String }\n";
    let findings1 = guard.audit_source("mod", "file.rs", source);
    let findings2 = guard.audit_source("mod", "file.rs", source);
    assert_eq!(findings1, findings2);
}

#[test]
fn enrichment_audit_all_deterministic() {
    let guard = no_base_guard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("mod_a".to_string(), "src/a.rs".to_string()),
        "use franken_evidence::ledger;\n".to_string(),
    );
    let r1 = guard.audit_all(&sources);
    let r2 = guard.audit_all(&sources);
    assert_eq!(r1, r2);
}
