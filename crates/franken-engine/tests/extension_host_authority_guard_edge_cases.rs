//! Edge-case tests for `extension_host_authority_guard` module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use frankenengine_engine::extension_host_authority_guard::{
    ExtensionHostAuditResult, ExtensionHostExemption, ExtensionHostExemptionRegistry,
    ExtensionHostFinding, ExtensionHostGuard, GuardConfig, ViolationKind,
};

// =========================================================================
// Helpers
// =========================================================================

fn hash_of<T: Hash>(val: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    val.hash(&mut hasher);
    hasher.finish()
}

fn make_finding(kind: ViolationKind, line: usize, exempted: bool) -> ExtensionHostFinding {
    ExtensionHostFinding {
        kind,
        module_path: "test::mod".to_string(),
        file_path: "src/test.rs".to_string(),
        line,
        source_line: "test line".to_string(),
        description: "test description".to_string(),
        remediation: "test remediation".to_string(),
        exempted,
    }
}

fn make_exemption(
    id: &str,
    module: &str,
    kind: ViolationKind,
    token: &str,
    line: usize,
) -> ExtensionHostExemption {
    ExtensionHostExemption {
        exemption_id: id.to_string(),
        module_path: module.to_string(),
        kind,
        matched_token: token.to_string(),
        reason: "test reason".to_string(),
        line,
    }
}

fn guard_with_cx_prefix(prefix: &str) -> ExtensionHostGuard {
    let mut config = GuardConfig::default();
    config.add_cx_audited_prefix(prefix);
    ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new())
}

// =========================================================================
// ViolationKind
// =========================================================================

#[test]
fn violation_kind_copy_semantics() {
    let a = ViolationKind::ForbiddenPattern;
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn violation_kind_hash_all_four_distinct() {
    let kinds = [
        ViolationKind::ForbiddenPattern,
        ViolationKind::MissingCxParameter,
        ViolationKind::DirectUpstreamImport,
        ViolationKind::CanonicalTypeShadow,
    ];
    let hashes: BTreeSet<u64> = kinds.iter().map(hash_of).collect();
    assert_eq!(
        hashes.len(),
        4,
        "all 4 ViolationKind variants must hash distinctly"
    );
}

#[test]
fn violation_kind_serde_stable_strings() {
    // Verify the serialized representation is a quoted enum variant name
    let json = serde_json::to_string(&ViolationKind::ForbiddenPattern).unwrap();
    assert_eq!(json, "\"ForbiddenPattern\"");
    let json = serde_json::to_string(&ViolationKind::MissingCxParameter).unwrap();
    assert_eq!(json, "\"MissingCxParameter\"");
    let json = serde_json::to_string(&ViolationKind::DirectUpstreamImport).unwrap();
    assert_eq!(json, "\"DirectUpstreamImport\"");
    let json = serde_json::to_string(&ViolationKind::CanonicalTypeShadow).unwrap();
    assert_eq!(json, "\"CanonicalTypeShadow\"");
}

#[test]
fn violation_kind_display_all_four() {
    assert_eq!(
        ViolationKind::ForbiddenPattern.to_string(),
        "forbidden_pattern"
    );
    assert_eq!(
        ViolationKind::MissingCxParameter.to_string(),
        "missing_cx_parameter"
    );
    assert_eq!(
        ViolationKind::DirectUpstreamImport.to_string(),
        "direct_upstream_import"
    );
    assert_eq!(
        ViolationKind::CanonicalTypeShadow.to_string(),
        "canonical_type_shadow"
    );
}

#[test]
fn violation_kind_ordering_exhaustive() {
    let ordered = [
        ViolationKind::ForbiddenPattern,
        ViolationKind::MissingCxParameter,
        ViolationKind::DirectUpstreamImport,
        ViolationKind::CanonicalTypeShadow,
    ];
    for i in 0..ordered.len() {
        for j in (i + 1)..ordered.len() {
            assert!(
                ordered[i] < ordered[j],
                "{:?} should be < {:?}",
                ordered[i],
                ordered[j]
            );
        }
    }
}

// =========================================================================
// ExtensionHostFinding
// =========================================================================

#[test]
fn finding_serde_roundtrip_all_fields() {
    let finding = make_finding(ViolationKind::CanonicalTypeShadow, 42, true);
    let json = serde_json::to_string(&finding).unwrap();
    let restored: ExtensionHostFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, restored);
}

#[test]
fn finding_ordering_by_kind_first() {
    let a = ExtensionHostFinding {
        kind: ViolationKind::ForbiddenPattern,
        module_path: "z::mod".to_string(),
        file_path: "z.rs".to_string(),
        line: 999,
        source_line: String::new(),
        description: String::new(),
        remediation: String::new(),
        exempted: false,
    };
    let b = ExtensionHostFinding {
        kind: ViolationKind::DirectUpstreamImport,
        module_path: "a::mod".to_string(),
        file_path: "a.rs".to_string(),
        line: 1,
        source_line: String::new(),
        description: String::new(),
        remediation: String::new(),
        exempted: false,
    };
    assert!(
        a < b,
        "ForbiddenPattern < DirectUpstreamImport regardless of other fields"
    );
}

#[test]
fn finding_ordering_same_kind_by_module_path() {
    let a = ExtensionHostFinding {
        kind: ViolationKind::ForbiddenPattern,
        module_path: "a::mod".to_string(),
        file_path: "z.rs".to_string(),
        line: 99,
        source_line: String::new(),
        description: String::new(),
        remediation: String::new(),
        exempted: false,
    };
    let b = ExtensionHostFinding {
        kind: ViolationKind::ForbiddenPattern,
        module_path: "b::mod".to_string(),
        file_path: "a.rs".to_string(),
        line: 1,
        source_line: String::new(),
        description: String::new(),
        remediation: String::new(),
        exempted: false,
    };
    assert!(a < b, "same kind: ordered by module_path");
}

#[test]
fn finding_clone() {
    let f = make_finding(ViolationKind::MissingCxParameter, 10, false);
    let f2 = f.clone();
    assert_eq!(f, f2);
}

// =========================================================================
// ExtensionHostExemption
// =========================================================================

#[test]
fn exemption_serde_roundtrip() {
    let e = make_exemption(
        "ex-1",
        "m::mod",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    );
    let json = serde_json::to_string(&e).unwrap();
    let restored: ExtensionHostExemption = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn exemption_ordering() {
    let a = make_exemption("a", "a::mod", ViolationKind::ForbiddenPattern, "t", 0);
    let b = make_exemption("b", "b::mod", ViolationKind::ForbiddenPattern, "t", 0);
    assert!(a < b);
}

#[test]
fn exemption_clone() {
    let e = make_exemption("ex-1", "m", ViolationKind::DirectUpstreamImport, "tok", 5);
    let e2 = e.clone();
    assert_eq!(e, e2);
}

// =========================================================================
// ExtensionHostExemptionRegistry
// =========================================================================

#[test]
fn registry_new_is_empty() {
    let reg = ExtensionHostExemptionRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    assert!(reg.entries().is_empty());
}

#[test]
fn registry_default_is_empty() {
    let reg = ExtensionHostExemptionRegistry::default();
    assert!(reg.is_empty());
}

#[test]
fn registry_add_increments_len() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m",
        ViolationKind::ForbiddenPattern,
        "t",
        0,
    ));
    assert_eq!(reg.len(), 1);
    assert!(!reg.is_empty());
    reg.add(make_exemption(
        "e2",
        "m",
        ViolationKind::DirectUpstreamImport,
        "t",
        0,
    ));
    assert_eq!(reg.len(), 2);
}

#[test]
fn registry_entries_returns_all() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m1",
        ViolationKind::ForbiddenPattern,
        "t",
        0,
    ));
    reg.add(make_exemption(
        "e2",
        "m2",
        ViolationKind::DirectUpstreamImport,
        "t",
        0,
    ));
    assert_eq!(reg.entries().len(), 2);
    assert_eq!(reg.entries()[0].exemption_id, "e1");
    assert_eq!(reg.entries()[1].exemption_id, "e2");
}

#[test]
fn registry_is_exempted_line_zero_matches_any_line() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m",
        ViolationKind::ForbiddenPattern,
        "tok",
        0,
    ));
    // line=0 means module-wide: should match any line number
    assert!(reg.is_exempted("m", ViolationKind::ForbiddenPattern, "tok", 1));
    assert!(reg.is_exempted("m", ViolationKind::ForbiddenPattern, "tok", 42));
    assert!(reg.is_exempted("m", ViolationKind::ForbiddenPattern, "tok", 999));
}

#[test]
fn registry_is_exempted_specific_line_only_matches_that_line() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m",
        ViolationKind::ForbiddenPattern,
        "tok",
        5,
    ));
    assert!(reg.is_exempted("m", ViolationKind::ForbiddenPattern, "tok", 5));
    assert!(!reg.is_exempted("m", ViolationKind::ForbiddenPattern, "tok", 4));
    assert!(!reg.is_exempted("m", ViolationKind::ForbiddenPattern, "tok", 6));
}

#[test]
fn registry_is_exempted_wrong_module_no_match() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "tok",
        0,
    ));
    assert!(!reg.is_exempted("m::b", ViolationKind::ForbiddenPattern, "tok", 1));
}

#[test]
fn registry_is_exempted_wrong_kind_no_match() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m",
        ViolationKind::ForbiddenPattern,
        "tok",
        0,
    ));
    assert!(!reg.is_exempted("m", ViolationKind::DirectUpstreamImport, "tok", 1));
}

#[test]
fn registry_is_exempted_wrong_token_no_match() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m",
        ViolationKind::ForbiddenPattern,
        "tok_a",
        0,
    ));
    assert!(!reg.is_exempted("m", ViolationKind::ForbiddenPattern, "tok_b", 1));
}

#[test]
fn registry_serde_roundtrip() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m1",
        ViolationKind::ForbiddenPattern,
        "t1",
        0,
    ));
    reg.add(make_exemption(
        "e2",
        "m2",
        ViolationKind::CanonicalTypeShadow,
        "t2",
        10,
    ));
    let json = serde_json::to_string(&reg).unwrap();
    let restored: ExtensionHostExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, restored);
}

// =========================================================================
// GuardConfig
// =========================================================================

#[test]
fn guard_config_default_forbidden_imports_count() {
    let config = GuardConfig::default();
    // 6 entries: 3 use + 3 extern crate
    assert_eq!(config.forbidden_imports.len(), 6);
}

#[test]
fn guard_config_default_canonical_types_content() {
    let config = GuardConfig::default();
    let expected = [
        "TraceId",
        "DecisionId",
        "PolicyId",
        "SchemaVersion",
        "Budget",
        "Cx",
    ];
    assert_eq!(config.canonical_types.len(), expected.len());
    for t in &expected {
        assert!(
            config.canonical_types.contains(*t),
            "missing canonical type: {t}"
        );
    }
}

#[test]
fn guard_config_default_effectful_indicators_count() {
    let config = GuardConfig::default();
    assert_eq!(config.effectful_indicators.len(), 9);
}

#[test]
fn guard_config_default_cx_prefixes_empty() {
    let config = GuardConfig::default();
    assert!(config.cx_audited_module_prefixes.is_empty());
}

#[test]
fn guard_config_default_include_base_patterns() {
    let config = GuardConfig::default();
    assert!(config.include_base_patterns);
}

#[test]
fn guard_config_add_cx_prefix() {
    let mut config = GuardConfig::default();
    config.add_cx_audited_prefix("ext_host");
    config.add_cx_audited_prefix("ext_worker");
    assert_eq!(config.cx_audited_module_prefixes.len(), 2);
    assert!(config.cx_audited_module_prefixes.contains("ext_host"));
    assert!(config.cx_audited_module_prefixes.contains("ext_worker"));
}

#[test]
fn guard_config_add_cx_prefix_dedup() {
    let mut config = GuardConfig::default();
    config.add_cx_audited_prefix("ext_host");
    config.add_cx_audited_prefix("ext_host");
    // BTreeSet deduplicates
    assert_eq!(config.cx_audited_module_prefixes.len(), 1);
}

#[test]
fn guard_config_add_effectful_indicator() {
    let mut config = GuardConfig::default();
    let orig_count = config.effectful_indicators.len();
    config.add_effectful_indicator("custom_effect");
    assert_eq!(config.effectful_indicators.len(), orig_count + 1);
    assert!(
        config
            .effectful_indicators
            .contains(&"custom_effect".to_string())
    );
}

#[test]
fn guard_config_add_forbidden_import() {
    let mut config = GuardConfig::default();
    let orig_count = config.forbidden_imports.len();
    config.add_forbidden_import("use secret", "Use safe wrapper");
    assert_eq!(config.forbidden_imports.len(), orig_count + 1);
}

#[test]
fn guard_config_serde_roundtrip() {
    let mut config = GuardConfig::default();
    config.add_cx_audited_prefix("ext_host");
    config.add_effectful_indicator("custom_thing");
    config.add_forbidden_import("use bad_crate", "Don't do that");
    let json = serde_json::to_string(&config).unwrap();
    let restored: GuardConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn guard_config_serde_with_base_patterns_disabled() {
    let config = GuardConfig {
        include_base_patterns: false,
        ..GuardConfig::default()
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: GuardConfig = serde_json::from_str(&json).unwrap();
    assert!(!restored.include_base_patterns);
}

// =========================================================================
// ExtensionHostAuditResult
// =========================================================================

#[test]
fn audit_result_serde_roundtrip_with_findings() {
    let result = ExtensionHostAuditResult {
        findings: vec![make_finding(ViolationKind::ForbiddenPattern, 1, false)],
        violation_count: 1,
        exemption_count: 0,
        modules_audited: vec!["m".to_string()],
        passed: false,
        summary_by_kind: {
            let mut m = BTreeMap::new();
            m.insert("forbidden_pattern".to_string(), 1);
            m
        },
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ExtensionHostAuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn audit_result_empty_passes() {
    let result = ExtensionHostAuditResult {
        findings: vec![],
        violation_count: 0,
        exemption_count: 0,
        modules_audited: vec![],
        passed: true,
        summary_by_kind: BTreeMap::new(),
    };
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
}

// =========================================================================
// ExtensionHostGuard — construction
// =========================================================================

#[test]
fn guard_standard_has_default_config() {
    let guard = ExtensionHostGuard::standard();
    assert_eq!(*guard.config(), GuardConfig::default());
    assert!(guard.exemptions().is_empty());
}

#[test]
fn guard_config_accessor() {
    let mut config = GuardConfig::default();
    config.add_cx_audited_prefix("test_prefix");
    let guard = ExtensionHostGuard::new(config.clone(), ExtensionHostExemptionRegistry::new());
    assert_eq!(*guard.config(), config);
}

#[test]
fn guard_exemptions_accessor() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m",
        ViolationKind::ForbiddenPattern,
        "tok",
        0,
    ));
    let guard = ExtensionHostGuard::new(GuardConfig::default(), reg.clone());
    assert_eq!(*guard.exemptions(), reg);
}

// =========================================================================
// ExtensionHostGuard — direct upstream imports
// =========================================================================

#[test]
fn detects_all_six_forbidden_import_patterns() {
    let guard = ExtensionHostGuard::standard();
    let patterns = [
        "use franken_kernel::something;",
        "use franken_decision::something;",
        "use franken_evidence::something;",
        "extern crate franken_kernel;",
        "extern crate franken_decision;",
        "extern crate franken_evidence;",
    ];
    for pat in &patterns {
        let findings = guard.audit_source("m", "f.rs", pat);
        let import_count = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
            .count();
        assert!(
            import_count >= 1,
            "pattern `{pat}` should produce a DirectUpstreamImport finding"
        );
    }
}

#[test]
fn import_in_comment_line_not_flagged() {
    let guard = ExtensionHostGuard::standard();
    let source = "// use franken_kernel::Cx;\n/// use franken_decision::D;";
    let findings = guard.audit_source("m", "f.rs", source);
    let imports: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(imports.is_empty());
}

#[test]
fn import_finding_has_remediation_with_control_plane() {
    let guard = ExtensionHostGuard::standard();
    let source = "use franken_kernel::Cx;";
    let findings = guard.audit_source("m", "f.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(!import_findings.is_empty());
    assert!(import_findings[0].remediation.contains("control_plane"));
}

#[test]
fn import_finding_line_number_correct() {
    let guard = ExtensionHostGuard::standard();
    let source = "fn ok() {}\nuse franken_kernel::Cx;\nfn also_ok() {}";
    let findings = guard.audit_source("m", "f.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert_eq!(import_findings[0].line, 2);
}

#[test]
fn multiple_imports_on_different_lines() {
    let guard = ExtensionHostGuard::standard();
    let source = "use franken_kernel::A;\nuse franken_decision::B;\nuse franken_evidence::C;";
    let findings = guard.audit_source("m", "f.rs", source);
    let import_count = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .count();
    assert_eq!(import_count, 3);
}

// =========================================================================
// ExtensionHostGuard — canonical type shadowing
// =========================================================================

#[test]
fn all_six_canonical_types_detected_as_struct() {
    let guard = ExtensionHostGuard::standard();
    let types = [
        "TraceId",
        "DecisionId",
        "PolicyId",
        "SchemaVersion",
        "Budget",
        "Cx",
    ];
    for t in &types {
        let source = format!("pub struct {t}(u64);");
        let findings = guard.audit_source("m", "f.rs", &source);
        let shadow_count = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
            .count();
        assert!(
            shadow_count >= 1,
            "struct {t} should trigger CanonicalTypeShadow"
        );
    }
}

#[test]
fn all_six_canonical_types_detected_as_enum() {
    let guard = ExtensionHostGuard::standard();
    let types = [
        "TraceId",
        "DecisionId",
        "PolicyId",
        "SchemaVersion",
        "Budget",
        "Cx",
    ];
    for t in &types {
        let source = format!("pub enum {t} {{ A, B }}");
        let findings = guard.audit_source("m", "f.rs", &source);
        let shadow_count = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
            .count();
        assert!(
            shadow_count >= 1,
            "enum {t} should trigger CanonicalTypeShadow"
        );
    }
}

#[test]
fn all_six_canonical_types_detected_as_type_alias() {
    let guard = ExtensionHostGuard::standard();
    let types = [
        "TraceId",
        "DecisionId",
        "PolicyId",
        "SchemaVersion",
        "Budget",
        "Cx",
    ];
    for t in &types {
        let source = format!("type {t} = u64;");
        let findings = guard.audit_source("m", "f.rs", &source);
        let shadow_count = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
            .count();
        assert!(
            shadow_count >= 1,
            "type alias {t} should trigger CanonicalTypeShadow"
        );
    }
}

#[test]
fn shadow_finding_description_contains_type_name() {
    let guard = ExtensionHostGuard::standard();
    let source = "struct Budget { amount: u64 }";
    let findings = guard.audit_source("m", "f.rs", source);
    let shadow_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .collect();
    assert!(!shadow_findings.is_empty());
    assert!(shadow_findings[0].description.contains("Budget"));
}

#[test]
fn shadow_finding_remediation_mentions_control_plane() {
    let guard = ExtensionHostGuard::standard();
    let source = "struct TraceId(String);";
    let findings = guard.audit_source("m", "f.rs", source);
    let shadow_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .collect();
    assert!(!shadow_findings.is_empty());
    assert!(
        shadow_findings[0]
            .remediation
            .contains("crate::control_plane")
    );
}

#[test]
fn shadow_in_doc_comment_not_flagged() {
    let guard = ExtensionHostGuard::standard();
    let source = "/// struct TraceId(u64);\n// type Budget = f64;";
    let findings = guard.audit_source("m", "f.rs", source);
    let shadows: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .collect();
    assert!(shadows.is_empty());
}

#[test]
fn non_canonical_type_not_flagged() {
    let guard = ExtensionHostGuard::standard();
    let source = "struct MyTraceId(u64);\nenum CustomBudget { A }";
    let findings = guard.audit_source("m", "f.rs", source);
    let shadows: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .collect();
    assert!(shadows.is_empty());
}

// =========================================================================
// ExtensionHostGuard — missing Cx parameter
// =========================================================================

#[test]
fn all_nine_effectful_indicators_detected() {
    let indicators = [
        "dispatch_hostcall",
        "evaluate_policy",
        "transition_lifecycle",
        "emit_telemetry",
        "emit_metric",
        "emit_span",
        "emit_evidence",
        "send_decision",
        "consume_budget",
    ];
    for ind in &indicators {
        let guard = ExtensionHostGuard::new(
            GuardConfig::default(),
            ExtensionHostExemptionRegistry::new(),
        );
        let source = format!("fn bad_fn(data: &[u8]) {{\n    {ind}(data);\n}}");
        let findings = guard.audit_source("m", "f.rs", &source);
        let cx_count = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .count();
        assert!(
            cx_count >= 1,
            "effectful indicator `{ind}` should trigger MissingCxParameter"
        );
    }
}

#[test]
fn cx_via_context_adapter_accepted() {
    let guard = guard_with_cx_prefix("ext");
    let source = "fn ok(cx: &dyn ContextAdapter) {\n    dispatch_hostcall(cx, \"op\");\n}";
    let findings = guard.audit_source("ext::m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn cx_via_ref_cx_accepted() {
    let guard = guard_with_cx_prefix("ext");
    let source = "fn ok(cx: &Cx) {\n    emit_telemetry(cx, \"m\");\n}";
    let findings = guard.audit_source("ext::m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn cx_via_mut_cx_accepted() {
    let guard = guard_with_cx_prefix("ext");
    let source = "fn ok(cx: &mut Cx) {\n    consume_budget(cx, 10);\n}";
    let findings = guard.audit_source("ext::m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn cx_via_colon_cx_accepted() {
    let guard = guard_with_cx_prefix("ext");
    let source = "fn ok(thing: Cx) {\n    emit_metric(thing, 1);\n}";
    let findings = guard.audit_source("ext::m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn cx_via_named_cx_colon_accepted() {
    let guard = guard_with_cx_prefix("ext");
    let source = "fn ok(cx: SomeType) {\n    emit_span(cx);\n}";
    let findings = guard.audit_source("ext::m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn missing_cx_finding_description_contains_fn_name() {
    let guard = ExtensionHostGuard::new(
        GuardConfig::default(),
        ExtensionHostExemptionRegistry::new(),
    );
    let source = "fn my_effectful_fn(data: &[u8]) {\n    dispatch_hostcall(\"op\");\n}";
    let findings = guard.audit_source("m", "f.rs", source);
    let cx_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(!cx_findings.is_empty());
    assert!(cx_findings[0].description.contains("my_effectful_fn"));
}

#[test]
fn missing_cx_finding_remediation_mentions_context_adapter() {
    let guard = ExtensionHostGuard::new(
        GuardConfig::default(),
        ExtensionHostExemptionRegistry::new(),
    );
    let source = "fn bad_fn() {\n    dispatch_hostcall(\"op\");\n}";
    let findings = guard.audit_source("m", "f.rs", source);
    let cx_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(!cx_findings.is_empty());
    assert!(cx_findings[0].remediation.contains("ContextAdapter"));
}

#[test]
fn module_not_in_cx_prefix_not_checked() {
    let guard = guard_with_cx_prefix("ext_host");
    let source = "fn bad_fn() {\n    dispatch_hostcall(\"op\");\n}";
    let findings = guard.audit_source("engine::other", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn empty_cx_prefixes_checks_all_modules() {
    // Default config has empty cx_audited_module_prefixes
    let guard = ExtensionHostGuard::new(
        GuardConfig::default(),
        ExtensionHostExemptionRegistry::new(),
    );
    let source = "fn bad_fn() {\n    dispatch_hostcall(\"op\");\n}";
    let findings = guard.audit_source("any::module::path", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(!cx_violations.is_empty());
}

#[test]
fn one_finding_per_function_not_per_indicator() {
    let guard = ExtensionHostGuard::new(
        GuardConfig::default(),
        ExtensionHostExemptionRegistry::new(),
    );
    let source = "fn multi_effect() {\n    dispatch_hostcall(\"a\");\n    emit_telemetry(\"b\");\n    consume_budget(10);\n}";
    let findings = guard.audit_source("m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert_eq!(cx_violations.len(), 1);
}

#[test]
fn pure_function_no_cx_violation() {
    let guard = ExtensionHostGuard::new(
        GuardConfig::default(),
        ExtensionHostExemptionRegistry::new(),
    );
    let source = "fn pure_math(x: i64, y: i64) -> i64 {\n    x + y\n}";
    let findings = guard.audit_source("m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn trait_declaration_not_flagged_as_missing_cx() {
    let guard = ExtensionHostGuard::new(
        GuardConfig::default(),
        ExtensionHostExemptionRegistry::new(),
    );
    // Trait method ending with `;` should be skipped by extract_fn_signature
    let source = "    fn abstract_method(&self) -> bool;";
    let findings = guard.audit_source("m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

// =========================================================================
// ExtensionHostGuard — forbidden base patterns
// =========================================================================

#[test]
fn base_patterns_detect_std_fs() {
    let guard = ExtensionHostGuard::standard();
    let source = "let data = std::fs::read(\"file.txt\");";
    let findings = guard.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn base_patterns_detect_tcp_stream() {
    let guard = ExtensionHostGuard::standard();
    let source = "let s = TcpStream::connect(\"127.0.0.1:80\");";
    let findings = guard.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn base_patterns_detect_command_new() {
    let guard = ExtensionHostGuard::standard();
    let source = "let out = Command::new(\"ls\").output();";
    let findings = guard.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn base_patterns_detect_static_mut() {
    let guard = ExtensionHostGuard::standard();
    let source = "static mut COUNTER: u64 = 0;";
    let findings = guard.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn base_patterns_detect_system_time() {
    let guard = ExtensionHostGuard::standard();
    let source = "let now = SystemTime::now();";
    let findings = guard.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn base_patterns_disabled_no_forbidden_pattern_findings() {
    let config = GuardConfig {
        include_base_patterns: false,
        ..GuardConfig::default()
    };
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "let data = std::fs::read(\"file.txt\");\nstatic mut BAD: u64 = 0;";
    let findings = guard.audit_source("m", "f.rs", source);
    let base_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::ForbiddenPattern)
        .collect();
    assert!(base_findings.is_empty());
}

// =========================================================================
// ExtensionHostGuard — exemptions applied during audit
// =========================================================================

#[test]
fn exemption_marks_finding_as_exempted() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(ExtensionHostExemption {
        exemption_id: "ex-1".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "bootstrap".to_string(),
        line: 0, // module-wide
    });
    let guard = ExtensionHostGuard::new(GuardConfig::default(), reg);
    let source = "use franken_kernel::Cx;";
    let findings = guard.audit_source("m", "f.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(!import_findings.is_empty());
    assert!(import_findings[0].exempted);
}

#[test]
fn exempted_findings_not_counted_as_violations_in_audit_all() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(ExtensionHostExemption {
        exemption_id: "ex-1".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "needed".to_string(),
        line: 0,
    });
    let guard = ExtensionHostGuard::new(GuardConfig::default(), reg);
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m".to_string(), "f.rs".to_string()),
        "use franken_kernel::Cx;".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert_eq!(result.exemption_count, 1);
    // The exempted finding should NOT be in violation_count
    let import_violations = result
        .findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport && !f.exempted)
        .count();
    assert_eq!(import_violations, 0);
}

// =========================================================================
// ExtensionHostGuard — audit_all
// =========================================================================

#[test]
fn audit_all_empty_sources() {
    let guard = ExtensionHostGuard::standard();
    let sources = BTreeMap::new();
    let result = guard.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert_eq!(result.exemption_count, 0);
    assert!(result.modules_audited.is_empty());
    assert!(result.findings.is_empty());
}

#[test]
fn audit_all_multiple_clean_sources_pass() {
    let guard = ExtensionHostGuard::standard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m1".to_string(), "f1.rs".to_string()),
        "fn pure(x: i64) -> i64 { x + 1 }".to_string(),
    );
    sources.insert(
        ("m2".to_string(), "f2.rs".to_string()),
        "fn also_pure(y: bool) -> bool { !y }".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.modules_audited.len(), 2);
}

#[test]
fn audit_all_summary_by_kind_correct() {
    let guard = ExtensionHostGuard::standard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m".to_string(), "f.rs".to_string()),
        "use franken_kernel::Cx;\nuse franken_decision::D;\nstruct TraceId(u64);".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(!result.passed);
    assert!(
        result
            .summary_by_kind
            .get("direct_upstream_import")
            .copied()
            .unwrap_or(0)
            >= 2
    );
    assert!(
        result
            .summary_by_kind
            .get("canonical_type_shadow")
            .copied()
            .unwrap_or(0)
            >= 1
    );
}

#[test]
fn audit_all_exempted_not_in_summary_by_kind() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(ExtensionHostExemption {
        exemption_id: "ex-1".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::CanonicalTypeShadow,
        matched_token: "Local definition shadows canonical type `TraceId`".to_string(),
        reason: "ok".to_string(),
        line: 0,
    });
    let guard = ExtensionHostGuard::new(GuardConfig::default(), reg);
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m".to_string(), "f.rs".to_string()),
        "struct TraceId(u64);".to_string(),
    );
    let result = guard.audit_all(&sources);
    // Exempted findings are NOT counted in summary_by_kind
    assert_eq!(
        result
            .summary_by_kind
            .get("canonical_type_shadow")
            .copied()
            .unwrap_or(0),
        0
    );
}

// =========================================================================
// ExtensionHostGuard — mixed violations
// =========================================================================

#[test]
fn mixed_violations_all_kinds_detected() {
    let guard = guard_with_cx_prefix("m");
    let source = "\
use franken_kernel::Cx;
struct Budget { amount: u64 }
static mut COUNTER: u64 = 0;
fn bad_fn(data: &[u8]) {
    dispatch_hostcall(\"op\");
}";
    let findings = guard.audit_source("m::mix", "f.rs", source);
    let kinds: BTreeSet<ViolationKind> = findings.iter().map(|f| f.kind).collect();
    assert!(kinds.contains(&ViolationKind::DirectUpstreamImport));
    assert!(kinds.contains(&ViolationKind::CanonicalTypeShadow));
    assert!(kinds.contains(&ViolationKind::ForbiddenPattern));
    assert!(kinds.contains(&ViolationKind::MissingCxParameter));
}

#[test]
fn findings_sorted_deterministically() {
    let guard = ExtensionHostGuard::standard();
    let source = "\
use franken_evidence::E;
struct Cx { inner: u64 }
use franken_kernel::K;
struct TraceId(u64);
static mut BAD: u64 = 0;";
    let f1 = guard.audit_source("m", "f.rs", source);
    let f2 = guard.audit_source("m", "f.rs", source);
    assert_eq!(f1, f2);
    // Verify sorted by kind (ForbiddenPattern < DirectUpstreamImport < CanonicalTypeShadow)
    for i in 0..f1.len().saturating_sub(1) {
        assert!(f1[i] <= f1[i + 1], "findings should be sorted");
    }
}

// =========================================================================
// ExtensionHostGuard — edge cases
// =========================================================================

#[test]
fn empty_source() {
    let guard = ExtensionHostGuard::standard();
    let findings = guard.audit_source("m", "f.rs", "");
    assert!(findings.is_empty());
}

#[test]
fn whitespace_only_source() {
    let guard = ExtensionHostGuard::standard();
    let findings = guard.audit_source("m", "f.rs", "   \n  \n   ");
    assert!(findings.is_empty());
}

#[test]
fn comment_only_source() {
    let guard = ExtensionHostGuard::standard();
    let source = "// This is just a comment\n/// Doc comment\n// Another comment";
    let findings = guard.audit_source("m", "f.rs", source);
    // No direct import or shadow findings (base patterns might still scan?)
    let ext_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.kind == ViolationKind::DirectUpstreamImport
                || f.kind == ViolationKind::CanonicalTypeShadow
                || f.kind == ViolationKind::MissingCxParameter
        })
        .collect();
    assert!(ext_findings.is_empty());
}

#[test]
fn finding_module_path_and_file_path_preserved() {
    let guard = ExtensionHostGuard::standard();
    let source = "use franken_kernel::Cx;";
    let findings = guard.audit_source("my::module::path", "src/my/module/path.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(!import_findings.is_empty());
    assert_eq!(import_findings[0].module_path, "my::module::path");
    assert_eq!(import_findings[0].file_path, "src/my/module/path.rs");
}

#[test]
fn finding_source_line_trimmed() {
    let guard = ExtensionHostGuard::standard();
    let source = "    use franken_kernel::Cx;    ";
    let findings = guard.audit_source("m", "f.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(!import_findings.is_empty());
    assert_eq!(import_findings[0].source_line, "use franken_kernel::Cx;");
}

#[test]
fn custom_forbidden_import_works_in_audit() {
    let mut config = GuardConfig::default();
    config.add_forbidden_import("use evil_crate", "Use safe_wrapper instead");
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "use evil_crate::Bad;";
    let findings = guard.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    );
}

#[test]
fn custom_effectful_indicator_works_in_audit() {
    let mut config = GuardConfig::default();
    config.add_effectful_indicator("my_custom_effect");
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "fn bad_fn() {\n    my_custom_effect();\n}";
    let findings = guard.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::MissingCxParameter)
    );
}

#[test]
fn multi_line_function_signature_detects_cx() {
    let guard = guard_with_cx_prefix("ext");
    let source = "\
fn long_function(
    cx: &dyn ContextAdapter,
    data: &[u8],
    count: usize,
) {
    dispatch_hostcall(cx, \"op\");
}";
    let findings = guard.audit_source("ext::m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_violations.is_empty());
}

#[test]
fn multi_line_function_signature_detects_missing_cx() {
    let guard = guard_with_cx_prefix("ext");
    let source = "\
fn long_function(
    data: &[u8],
    count: usize,
) {
    dispatch_hostcall(\"op\");
}";
    let findings = guard.audit_source("ext::m", "f.rs", source);
    let cx_violations: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(!cx_violations.is_empty());
}

#[test]
fn remediation_messages_all_non_empty() {
    let guard = guard_with_cx_prefix("m");
    let source = "\
use franken_kernel::Cx;
struct Budget { amount: u64 }
fn bad() { dispatch_hostcall(\"op\"); }";
    let findings = guard.audit_source("m::x", "f.rs", source);
    for f in &findings {
        assert!(
            !f.remediation.is_empty(),
            "kind {:?} must have remediation",
            f.kind
        );
    }
}

// =========================================================================
// Determinism
// =========================================================================

#[test]
fn deterministic_audit_100_iterations() {
    let guard = ExtensionHostGuard::standard();
    let source = "\
use franken_kernel::Cx;
use franken_evidence::E;
struct TraceId(u64);
type Budget = f64;
static mut BAD: u64 = 0;
let _ = std::fs::read(\"x\");";

    let baseline = guard.audit_source("m", "f.rs", source);
    for _ in 0..100 {
        let run = guard.audit_source("m", "f.rs", source);
        assert_eq!(baseline, run);
    }
}

#[test]
fn deterministic_audit_all_100_iterations() {
    let guard = ExtensionHostGuard::standard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m1".to_string(), "f1.rs".to_string()),
        "use franken_kernel::Cx;\nstruct Budget(u64);".to_string(),
    );
    sources.insert(
        ("m2".to_string(), "f2.rs".to_string()),
        "use franken_evidence::E;\nstatic mut BAD: u64 = 0;".to_string(),
    );

    let baseline = guard.audit_all(&sources);
    for _ in 0..100 {
        let run = guard.audit_all(&sources);
        assert_eq!(baseline, run);
    }
}

// =========================================================================
// Integration scenarios
// =========================================================================

#[test]
fn integration_clean_extension_host_module_passes_audit() {
    let guard = guard_with_cx_prefix("ext_host");
    let source = "\
use crate::control_plane::ContextAdapter;
use crate::control_plane::TraceId;

fn process_request(cx: &dyn ContextAdapter, data: &[u8]) -> Vec<u8> {
    dispatch_hostcall(cx, \"process\");
    data.to_vec()
}

fn pure_transform(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.wrapping_add(1)).collect()
}";
    let findings = guard.audit_source("ext_host::handler", "src/handler.rs", source);
    let ext_violations: Vec<_> = findings
        .iter()
        .filter(|f| !f.exempted)
        .filter(|f| {
            f.kind == ViolationKind::DirectUpstreamImport
                || f.kind == ViolationKind::CanonicalTypeShadow
                || f.kind == ViolationKind::MissingCxParameter
        })
        .collect();
    assert!(ext_violations.is_empty());
}

#[test]
fn integration_dirty_module_fails_with_multiple_violations() {
    let guard = guard_with_cx_prefix("ext_host");
    let mut sources = BTreeMap::new();
    sources.insert(
        ("ext_host::bad".to_string(), "src/bad.rs".to_string()),
        "\
use franken_kernel::Cx;
use franken_decision::Policy;
struct TraceId(u64);
type DecisionId = String;
static mut GLOBAL: u64 = 0;
fn do_work(data: &[u8]) {
    dispatch_hostcall(\"op\");
    emit_telemetry(\"metric\", 1);
}
fn also_bad() {
    evaluate_policy(\"p\");
}"
        .to_string(),
    );

    let result = guard.audit_all(&sources);
    assert!(!result.passed);
    // Should have: 2 DirectUpstreamImport, 2 CanonicalTypeShadow, 1+ ForbiddenPattern, 2 MissingCxParameter
    assert!(result.violation_count >= 7);
    let kinds: BTreeSet<String> = result.summary_by_kind.keys().cloned().collect();
    assert!(kinds.contains("direct_upstream_import"));
    assert!(kinds.contains("canonical_type_shadow"));
    assert!(kinds.contains("forbidden_pattern"));
    assert!(kinds.contains("missing_cx_parameter"));
}

#[test]
fn integration_exemptions_allow_targeted_violations() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    // Exempt specific import for bootstrap module
    reg.add(ExtensionHostExemption {
        exemption_id: "bootstrap-kernel".to_string(),
        module_path: "ext_host::bootstrap".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "Bootstrap requires direct kernel access for initialization".to_string(),
        line: 0,
    });

    let guard = ExtensionHostGuard::new(GuardConfig::default(), reg);
    let mut sources = BTreeMap::new();
    sources.insert(
        (
            "ext_host::bootstrap".to_string(),
            "src/bootstrap.rs".to_string(),
        ),
        "use franken_kernel::init;".to_string(),
    );
    sources.insert(
        (
            "ext_host::handler".to_string(),
            "src/handler.rs".to_string(),
        ),
        "fn pure() { 1 + 1; }".to_string(),
    );

    let result = guard.audit_all(&sources);
    // The import in bootstrap is exempted, handler is clean
    assert_eq!(result.exemption_count, 1);
    // violation_count should not include the exempted finding
    let unexempted_imports = result
        .findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport && !f.exempted)
        .count();
    assert_eq!(unexempted_imports, 0);
}

#[test]
fn integration_line_specific_exemption_partial() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    // Only exempt line 1
    reg.add(ExtensionHostExemption {
        exemption_id: "line1-only".to_string(),
        module_path: "m".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "line 1 only".to_string(),
        line: 1,
    });
    let guard = ExtensionHostGuard::new(GuardConfig::default(), reg);
    let source = "use franken_kernel::A;\nuse franken_kernel::B;";
    let findings = guard.audit_source("m", "f.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert_eq!(import_findings.len(), 2);
    let exempted_count = import_findings.iter().filter(|f| f.exempted).count();
    let violation_count = import_findings.iter().filter(|f| !f.exempted).count();
    assert_eq!(exempted_count, 1);
    assert_eq!(violation_count, 1);
}
