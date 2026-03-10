#![forbid(unsafe_code)]
//! Integration tests for the `dual_backend_parser` module.
//!
//! Exercises every public type, constructor, method, error path, Display/Debug,
//! and serde round-trip from outside the crate boundary.

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

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::ast::{ParseGoal, SourceSpan, SyntaxTree};
use frankenengine_engine::dual_backend_parser::{
    BackendCapability, BackendId, BackendParseResult, BackendRegistration, BackendRequirements,
    BackendSelectionPolicy, DUAL_BACKEND_SCHEMA_VERSION, DiagnosticCategory, DiagnosticSeverity,
    DiagnosticsEnvelope, DifferentialComparisonResult, DivergenceClass, DualBackendEventKind,
    DualBackendParseEvent, DualBackendParser, DualBackendParserError, FidelityReport,
    NormalizedDiagnostic, NormalizedParseOutput, SpanMappingEntry,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_span(start: u64, end: u64) -> SourceSpan {
    SourceSpan {
        start_offset: start,
        end_offset: end,
        start_line: 1,
        start_column: start + 1,
        end_line: 1,
        end_column: end + 1,
    }
}

fn make_registration(id: BackendId, priority: u32, healthy: bool) -> BackendRegistration {
    BackendRegistration {
        backend_id: id,
        display_name: "Test Backend".into(),
        version: "1.0.0".into(),
        capabilities: BackendCapability::full(),
        priority,
        healthy,
    }
}

fn make_parser() -> DualBackendParser {
    let mut parser = DualBackendParser::new(
        "integ-parser",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    parser
        .register_backend(make_registration(BackendId::swc(), 1, true))
        .unwrap();
    parser
        .register_backend(make_registration(BackendId::oxc(), 2, true))
        .unwrap();
    parser
        .register_backend(make_registration(BackendId::franken_canonical(), 3, true))
        .unwrap();
    parser
}

fn make_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: Vec::new(),
        span: make_span(0, 100),
    }
}

fn make_output(backend: BackendId) -> NormalizedParseOutput {
    let tree = make_tree();
    let hash = tree.canonical_hash();
    NormalizedParseOutput {
        tree,
        canonical_hash: hash,
        source_map: Vec::new(),
        diagnostics: DiagnosticsEnvelope::empty(),
        backend_id: backend,
        latency_us: 500,
        normalization_verified: true,
    }
}

fn make_diag(code: &str, sev: DiagnosticSeverity, cat: DiagnosticCategory) -> NormalizedDiagnostic {
    NormalizedDiagnostic {
        code: code.into(),
        category: cat,
        severity: sev,
        message_template: format!("Diagnostic {code}"),
        span: None,
        context: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Section 1: BackendId — constructors, Display, Ord, serde
// ---------------------------------------------------------------------------

#[test]
fn backend_id_named_constructors() {
    assert_eq!(BackendId::swc().0, "swc");
    assert_eq!(BackendId::oxc().0, "oxc");
    assert_eq!(BackendId::franken_canonical().0, "franken_canonical");
}

#[test]
fn backend_id_display() {
    assert_eq!(BackendId::swc().to_string(), "swc");
    assert_eq!(BackendId::oxc().to_string(), "oxc");
    assert_eq!(
        BackendId::franken_canonical().to_string(),
        "franken_canonical"
    );
}

#[test]
fn backend_id_debug() {
    let dbg = format!("{:?}", BackendId::swc());
    assert!(dbg.contains("swc"));
}

#[test]
fn backend_id_ordering_deterministic() {
    let mut ids = [
        BackendId::oxc(),
        BackendId::swc(),
        BackendId::franken_canonical(),
    ];
    ids.sort();
    assert_eq!(ids[0], BackendId::franken_canonical());
    assert_eq!(ids[1], BackendId::oxc());
    assert_eq!(ids[2], BackendId::swc());
}

#[test]
fn backend_id_custom_string() {
    let custom = BackendId("my_backend".into());
    assert_eq!(custom.to_string(), "my_backend");
}

#[test]
fn backend_id_serde_roundtrip() {
    for id in &[
        BackendId::swc(),
        BackendId::oxc(),
        BackendId::franken_canonical(),
    ] {
        let json = serde_json::to_string(id).unwrap();
        let back: BackendId = serde_json::from_str(&json).unwrap();
        assert_eq!(*id, back);
    }
}

#[test]
fn backend_id_eq_and_clone() {
    let a = BackendId::swc();
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, BackendId::oxc());
}

// ---------------------------------------------------------------------------
// Section 2: BackendCapability — full, minimal, satisfies
// ---------------------------------------------------------------------------

#[test]
fn capability_full_fields() {
    let c = BackendCapability::full();
    assert!(c.typescript);
    assert!(c.jsx);
    assert!(c.source_maps);
    assert!(!c.incremental);
    assert!(c.comment_preservation);
    assert_eq!(c.max_source_bytes, 0);
}

#[test]
fn capability_minimal_fields() {
    let c = BackendCapability::minimal();
    assert!(!c.typescript);
    assert!(!c.jsx);
    assert!(!c.source_maps);
    assert!(!c.incremental);
    assert!(!c.comment_preservation);
    assert_eq!(c.max_source_bytes, 1_048_576);
}

#[test]
fn capability_satisfies_empty_requirements() {
    let cap = BackendCapability::minimal();
    let req = BackendRequirements::default();
    assert!(cap.satisfies(&req));
}

#[test]
fn capability_satisfies_full_requirements() {
    let cap = BackendCapability::full();
    let req = BackendRequirements {
        needs_typescript: true,
        needs_jsx: true,
        needs_source_maps: true,
        needs_incremental: false,
    };
    assert!(cap.satisfies(&req));
}

#[test]
fn capability_fails_typescript_requirement() {
    let cap = BackendCapability::minimal();
    let req = BackendRequirements {
        needs_typescript: true,
        ..Default::default()
    };
    assert!(!cap.satisfies(&req));
}

#[test]
fn capability_fails_jsx_requirement() {
    let cap = BackendCapability::minimal();
    let req = BackendRequirements {
        needs_jsx: true,
        ..Default::default()
    };
    assert!(!cap.satisfies(&req));
}

#[test]
fn capability_fails_source_maps_requirement() {
    let cap = BackendCapability::minimal();
    let req = BackendRequirements {
        needs_source_maps: true,
        ..Default::default()
    };
    assert!(!cap.satisfies(&req));
}

#[test]
fn capability_fails_incremental_requirement() {
    let cap = BackendCapability::full();
    let req = BackendRequirements {
        needs_incremental: true,
        ..Default::default()
    };
    assert!(!cap.satisfies(&req));
}

#[test]
fn capability_serde_roundtrip() {
    for cap in &[BackendCapability::full(), BackendCapability::minimal()] {
        let json = serde_json::to_string(cap).unwrap();
        let back: BackendCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(*cap, back);
    }
}

// ---------------------------------------------------------------------------
// Section 3: BackendRequirements — default, serde
// ---------------------------------------------------------------------------

#[test]
fn requirements_default_all_false() {
    let req = BackendRequirements::default();
    assert!(!req.needs_typescript);
    assert!(!req.needs_jsx);
    assert!(!req.needs_source_maps);
    assert!(!req.needs_incremental);
}

#[test]
fn requirements_serde_roundtrip() {
    let req = BackendRequirements {
        needs_typescript: true,
        needs_jsx: false,
        needs_source_maps: true,
        needs_incremental: true,
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: BackendRequirements = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

// ---------------------------------------------------------------------------
// Section 4: BackendRegistration — serde
// ---------------------------------------------------------------------------

#[test]
fn registration_serde_roundtrip() {
    let reg = make_registration(BackendId::swc(), 5, true);
    let json = serde_json::to_string(&reg).unwrap();
    let back: BackendRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

#[test]
fn registration_fields_accessible() {
    let reg = make_registration(BackendId::oxc(), 10, false);
    assert_eq!(reg.backend_id, BackendId::oxc());
    assert_eq!(reg.priority, 10);
    assert!(!reg.healthy);
    assert_eq!(reg.version, "1.0.0");
}

// ---------------------------------------------------------------------------
// Section 5: DiagnosticSeverity — Display, ordering, serde
// ---------------------------------------------------------------------------

#[test]
fn severity_display_all_variants() {
    assert_eq!(DiagnosticSeverity::Hint.to_string(), "hint");
    assert_eq!(DiagnosticSeverity::Warning.to_string(), "warning");
    assert_eq!(DiagnosticSeverity::Error.to_string(), "error");
    assert_eq!(DiagnosticSeverity::Fatal.to_string(), "fatal");
}

#[test]
fn severity_ordering() {
    assert!(DiagnosticSeverity::Hint < DiagnosticSeverity::Warning);
    assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
    assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Fatal);
}

#[test]
fn severity_display_unique() {
    let sevs = [
        DiagnosticSeverity::Hint,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Fatal,
    ];
    let set: BTreeSet<String> = sevs.iter().map(|s| s.to_string()).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn severity_serde_roundtrip() {
    for sev in &[
        DiagnosticSeverity::Hint,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Fatal,
    ] {
        let json = serde_json::to_string(sev).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, back);
    }
}

// ---------------------------------------------------------------------------
// Section 6: DiagnosticCategory — Display, serde
// ---------------------------------------------------------------------------

#[test]
fn category_display_all_variants() {
    assert_eq!(DiagnosticCategory::Syntax.to_string(), "syntax");
    assert_eq!(DiagnosticCategory::Semantic.to_string(), "semantic");
    assert_eq!(DiagnosticCategory::Type.to_string(), "type");
    assert_eq!(DiagnosticCategory::Resource.to_string(), "resource");
    assert_eq!(DiagnosticCategory::Encoding.to_string(), "encoding");
}

#[test]
fn category_display_unique() {
    let cats = [
        DiagnosticCategory::Syntax,
        DiagnosticCategory::Semantic,
        DiagnosticCategory::Type,
        DiagnosticCategory::Resource,
        DiagnosticCategory::Encoding,
    ];
    let set: BTreeSet<String> = cats.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn category_serde_roundtrip() {
    for cat in &[
        DiagnosticCategory::Syntax,
        DiagnosticCategory::Semantic,
        DiagnosticCategory::Type,
        DiagnosticCategory::Resource,
        DiagnosticCategory::Encoding,
    ] {
        let json = serde_json::to_string(cat).unwrap();
        let back: DiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

// ---------------------------------------------------------------------------
// Section 7: NormalizedDiagnostic — construction, serde, context
// ---------------------------------------------------------------------------

#[test]
fn normalized_diagnostic_with_span_and_context() {
    let mut ctx = BTreeMap::new();
    ctx.insert("token".into(), "if".into());
    ctx.insert("expected".into(), "expression".into());
    let diag = NormalizedDiagnostic {
        code: "FE-PARSE-0001".into(),
        category: DiagnosticCategory::Syntax,
        severity: DiagnosticSeverity::Error,
        message_template: "Unexpected token '{token}'".into(),
        span: Some(make_span(5, 10)),
        context: ctx,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: NormalizedDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
    assert_eq!(back.context.len(), 2);
    assert!(back.span.is_some());
}

#[test]
fn normalized_diagnostic_no_span() {
    let diag = make_diag(
        "FE-RES-0001",
        DiagnosticSeverity::Warning,
        DiagnosticCategory::Resource,
    );
    assert!(diag.span.is_none());
    let json = serde_json::to_string(&diag).unwrap();
    let back: NormalizedDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

// ---------------------------------------------------------------------------
// Section 8: DiagnosticsEnvelope — empty, from_diagnostics, has_errors, hash
// ---------------------------------------------------------------------------

#[test]
fn envelope_empty() {
    let env = DiagnosticsEnvelope::empty();
    assert!(env.is_empty());
    assert_eq!(env.len(), 0);
    assert!(!env.has_errors());
    assert_eq!(env.schema_version, DUAL_BACKEND_SCHEMA_VERSION);
    assert!(env.envelope_hash.starts_with("sha256:"));
}

#[test]
fn envelope_from_diagnostics_with_error() {
    let diag = make_diag(
        "FE-P-0001",
        DiagnosticSeverity::Error,
        DiagnosticCategory::Syntax,
    );
    let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
    assert_eq!(env.len(), 1);
    assert!(!env.is_empty());
    assert!(env.has_errors());
}

#[test]
fn envelope_from_diagnostics_warning_only() {
    let diag = make_diag(
        "FE-W-0001",
        DiagnosticSeverity::Warning,
        DiagnosticCategory::Syntax,
    );
    let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
    assert_eq!(env.len(), 1);
    assert!(!env.has_errors());
}

#[test]
fn envelope_from_diagnostics_fatal_counts_as_error() {
    let diag = make_diag(
        "FE-F-0001",
        DiagnosticSeverity::Fatal,
        DiagnosticCategory::Encoding,
    );
    let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
    assert!(env.has_errors());
}

#[test]
fn envelope_from_diagnostics_hint_no_error() {
    let diag = make_diag(
        "FE-H-0001",
        DiagnosticSeverity::Hint,
        DiagnosticCategory::Semantic,
    );
    let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
    assert!(!env.has_errors());
}

#[test]
fn envelope_hash_deterministic() {
    let d1 = make_diag(
        "FE-A",
        DiagnosticSeverity::Error,
        DiagnosticCategory::Syntax,
    );
    let d2 = d1.clone();
    let env1 = DiagnosticsEnvelope::from_diagnostics(vec![d1]);
    let env2 = DiagnosticsEnvelope::from_diagnostics(vec![d2]);
    assert_eq!(env1.envelope_hash, env2.envelope_hash);
}

#[test]
fn envelope_hash_differs_for_different_diags() {
    let d1 = make_diag(
        "FE-A",
        DiagnosticSeverity::Error,
        DiagnosticCategory::Syntax,
    );
    let d2 = make_diag(
        "FE-B",
        DiagnosticSeverity::Warning,
        DiagnosticCategory::Type,
    );
    let env1 = DiagnosticsEnvelope::from_diagnostics(vec![d1]);
    let env2 = DiagnosticsEnvelope::from_diagnostics(vec![d2]);
    assert_ne!(env1.envelope_hash, env2.envelope_hash);
}

#[test]
fn envelope_serde_roundtrip() {
    let d = make_diag(
        "FE-S",
        DiagnosticSeverity::Error,
        DiagnosticCategory::Syntax,
    );
    let env = DiagnosticsEnvelope::from_diagnostics(vec![d]);
    let json = serde_json::to_string(&env).unwrap();
    let back: DiagnosticsEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

// ---------------------------------------------------------------------------
// Section 9: SpanMappingEntry — is_exact, serde
// ---------------------------------------------------------------------------

#[test]
fn span_mapping_exact() {
    let span = make_span(0, 10);
    let entry = SpanMappingEntry {
        node_index: 0,
        canonical_span: span.clone(),
        backend_span: span,
        deviation_bytes: 0,
    };
    assert!(entry.is_exact());
}

#[test]
fn span_mapping_with_deviation() {
    let entry = SpanMappingEntry {
        node_index: 1,
        canonical_span: make_span(0, 10),
        backend_span: make_span(0, 12),
        deviation_bytes: 2,
    };
    assert!(!entry.is_exact());
}

#[test]
fn span_mapping_serde_roundtrip() {
    let entry = SpanMappingEntry {
        node_index: 42,
        canonical_span: make_span(5, 15),
        backend_span: make_span(5, 16),
        deviation_bytes: 1,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: SpanMappingEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Section 10: FidelityReport — from_mappings, thresholds, edge cases
// ---------------------------------------------------------------------------

#[test]
fn fidelity_all_exact_perfect_score() {
    let mappings = vec![
        SpanMappingEntry {
            node_index: 0,
            canonical_span: make_span(0, 5),
            backend_span: make_span(0, 5),
            deviation_bytes: 0,
        },
        SpanMappingEntry {
            node_index: 1,
            canonical_span: make_span(5, 10),
            backend_span: make_span(5, 10),
            deviation_bytes: 0,
        },
    ];
    let report = FidelityReport::from_mappings(BackendId::swc(), &mappings, 990_000);
    assert_eq!(report.fidelity_score_millionths, 1_000_000);
    assert!(report.meets_threshold);
    assert!(report.deviations.is_empty());
    assert_eq!(report.total_spans, 2);
    assert_eq!(report.exact_spans, 2);
    assert_eq!(report.max_deviation_bytes, 0);
}

#[test]
fn fidelity_half_exact_below_threshold() {
    let mappings = vec![
        SpanMappingEntry {
            node_index: 0,
            canonical_span: make_span(0, 5),
            backend_span: make_span(0, 5),
            deviation_bytes: 0,
        },
        SpanMappingEntry {
            node_index: 1,
            canonical_span: make_span(5, 10),
            backend_span: make_span(5, 11),
            deviation_bytes: 1,
        },
    ];
    let report = FidelityReport::from_mappings(BackendId::oxc(), &mappings, 990_000);
    assert_eq!(report.fidelity_score_millionths, 500_000);
    assert!(!report.meets_threshold);
    assert_eq!(report.deviations.len(), 1);
    assert_eq!(report.max_deviation_bytes, 1);
}

#[test]
fn fidelity_empty_mappings_is_perfect() {
    let report = FidelityReport::from_mappings(BackendId::swc(), &[], 1_000_000);
    assert_eq!(report.fidelity_score_millionths, 1_000_000);
    assert!(report.meets_threshold);
    assert_eq!(report.total_spans, 0);
}

#[test]
fn fidelity_all_deviant() {
    let mappings: Vec<SpanMappingEntry> = (0..4)
        .map(|i| SpanMappingEntry {
            node_index: i,
            canonical_span: make_span(i * 10, (i + 1) * 10),
            backend_span: make_span(i * 10, (i + 1) * 10 + 1),
            deviation_bytes: 1,
        })
        .collect();
    let report = FidelityReport::from_mappings(BackendId::swc(), &mappings, 0);
    assert_eq!(report.fidelity_score_millionths, 0);
    assert!(report.meets_threshold); // threshold is 0
    assert_eq!(report.deviations.len(), 4);
}

#[test]
fn fidelity_max_deviation_tracked() {
    let mappings = vec![
        SpanMappingEntry {
            node_index: 0,
            canonical_span: make_span(0, 10),
            backend_span: make_span(0, 12),
            deviation_bytes: 2,
        },
        SpanMappingEntry {
            node_index: 1,
            canonical_span: make_span(10, 20),
            backend_span: make_span(10, 30),
            deviation_bytes: 10,
        },
    ];
    let report = FidelityReport::from_mappings(BackendId::swc(), &mappings, 0);
    assert_eq!(report.max_deviation_bytes, 10);
}

#[test]
fn fidelity_report_serde_roundtrip() {
    let report = FidelityReport::from_mappings(BackendId::swc(), &[], 990_000);
    let json = serde_json::to_string(&report).unwrap();
    let back: FidelityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Section 11: BackendSelectionPolicy — constructors, select_backend, overrides
// ---------------------------------------------------------------------------

#[test]
fn policy_swc_primary_fields() {
    let p = BackendSelectionPolicy::default_swc_primary();
    assert_eq!(p.policy_id, "default-swc-primary");
    assert_eq!(p.default_backend, BackendId::swc());
    assert_eq!(p.fallback_backend, BackendId::franken_canonical());
    assert_eq!(p.min_fidelity_millionths, 990_000);
    assert!(p.verify_normalization);
    assert!(!p.differential_mode);
}

#[test]
fn policy_oxc_primary_fields() {
    let p = BackendSelectionPolicy::default_oxc_primary();
    assert_eq!(p.policy_id, "default-oxc-primary");
    assert_eq!(p.default_backend, BackendId::oxc());
    assert_eq!(p.fallback_backend, BackendId::swc());
}

#[test]
fn policy_differential_fields() {
    let p = BackendSelectionPolicy::differential();
    assert_eq!(p.policy_id, "differential-all");
    assert_eq!(p.default_backend, BackendId::franken_canonical());
    assert!(p.differential_mode);
    assert_eq!(p.min_fidelity_millionths, 1_000_000);
}

#[test]
fn policy_selects_default_when_healthy() {
    let p = BackendSelectionPolicy::default_swc_primary();
    let backends = vec![
        make_registration(BackendId::swc(), 1, true),
        make_registration(BackendId::franken_canonical(), 2, true),
    ];
    let sel = p.select_backend(ParseGoal::Module, None, &backends);
    assert_eq!(sel, BackendId::swc());
}

#[test]
fn policy_selects_fallback_when_default_unhealthy() {
    let p = BackendSelectionPolicy::default_swc_primary();
    let backends = vec![
        make_registration(BackendId::swc(), 1, false),
        make_registration(BackendId::franken_canonical(), 2, true),
    ];
    let sel = p.select_backend(ParseGoal::Module, None, &backends);
    assert_eq!(sel, BackendId::franken_canonical());
}

#[test]
fn policy_goal_override_script() {
    let mut p = BackendSelectionPolicy::default_swc_primary();
    p.goal_overrides.insert("script".into(), BackendId::oxc());
    let backends = vec![
        make_registration(BackendId::swc(), 1, true),
        make_registration(BackendId::oxc(), 2, true),
    ];
    let sel = p.select_backend(ParseGoal::Script, None, &backends);
    assert_eq!(sel, BackendId::oxc());
}

#[test]
fn policy_goal_override_module() {
    let mut p = BackendSelectionPolicy::default_swc_primary();
    p.goal_overrides
        .insert("module".into(), BackendId::franken_canonical());
    let backends = vec![
        make_registration(BackendId::swc(), 1, true),
        make_registration(BackendId::franken_canonical(), 2, true),
    ];
    let sel = p.select_backend(ParseGoal::Module, None, &backends);
    assert_eq!(sel, BackendId::franken_canonical());
}

#[test]
fn policy_extension_override_tsx() {
    let mut p = BackendSelectionPolicy::default_swc_primary();
    p.extension_overrides.insert("tsx".into(), BackendId::oxc());
    let backends = vec![
        make_registration(BackendId::swc(), 1, true),
        make_registration(BackendId::oxc(), 2, true),
    ];
    let sel = p.select_backend(ParseGoal::Module, Some("tsx"), &backends);
    assert_eq!(sel, BackendId::oxc());
}

#[test]
fn policy_extension_override_takes_priority_over_goal() {
    let mut p = BackendSelectionPolicy::default_swc_primary();
    p.extension_overrides.insert("tsx".into(), BackendId::oxc());
    p.goal_overrides
        .insert("module".into(), BackendId::franken_canonical());
    let backends = vec![
        make_registration(BackendId::swc(), 1, true),
        make_registration(BackendId::oxc(), 2, true),
        make_registration(BackendId::franken_canonical(), 3, true),
    ];
    // Extension override should win over goal override
    let sel = p.select_backend(ParseGoal::Module, Some("tsx"), &backends);
    assert_eq!(sel, BackendId::oxc());
}

#[test]
fn policy_extension_override_ignored_if_backend_unhealthy() {
    let mut p = BackendSelectionPolicy::default_swc_primary();
    p.extension_overrides.insert("tsx".into(), BackendId::oxc());
    let backends = vec![
        make_registration(BackendId::swc(), 1, true),
        make_registration(BackendId::oxc(), 2, false), // unhealthy
    ];
    // Should fall back to default since overridden backend is unhealthy
    let sel = p.select_backend(ParseGoal::Module, Some("tsx"), &backends);
    assert_eq!(sel, BackendId::swc());
}

#[test]
fn policy_serde_roundtrip() {
    let p = BackendSelectionPolicy::default_swc_primary();
    let json = serde_json::to_string(&p).unwrap();
    let back: BackendSelectionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// Section 12: DualBackendParserError — Display, std::error::Error, serde
// ---------------------------------------------------------------------------

#[test]
fn error_display_no_backends() {
    assert_eq!(
        DualBackendParserError::NoBackendsRegistered.to_string(),
        "no backends registered"
    );
}

#[test]
fn error_display_backend_not_found() {
    assert_eq!(
        DualBackendParserError::BackendNotFound("swc".into()).to_string(),
        "backend not found: swc"
    );
}

#[test]
fn error_display_backend_unhealthy() {
    assert_eq!(
        DualBackendParserError::BackendUnhealthy("oxc".into()).to_string(),
        "backend unhealthy: oxc"
    );
}

#[test]
fn error_display_all_failed() {
    let e = DualBackendParserError::AllBackendsFailed(vec!["swc".into(), "oxc".into()]);
    assert_eq!(e.to_string(), "all backends failed: swc, oxc");
}

#[test]
fn error_display_normalization_failed() {
    let e = DualBackendParserError::NormalizationVerificationFailed {
        backend_id: "swc".into(),
        expected_hash: "sha256:aaa".into(),
        actual_hash: "sha256:bbb".into(),
    };
    let s = e.to_string();
    assert!(s.contains("swc"));
    assert!(s.contains("sha256:aaa"));
    assert!(s.contains("sha256:bbb"));
}

#[test]
fn error_display_fidelity_below() {
    let e = DualBackendParserError::FidelityBelowThreshold {
        backend_id: "oxc".into(),
        fidelity_millionths: 500_000,
        threshold_millionths: 990_000,
    };
    let s = e.to_string();
    assert!(s.contains("500000"));
    assert!(s.contains("990000"));
}

#[test]
fn error_display_too_many_backends() {
    let e = DualBackendParserError::TooManyBackends { count: 9, max: 8 };
    assert_eq!(e.to_string(), "too many backends: 9 > 8");
}

#[test]
fn error_display_invalid_config() {
    let e = DualBackendParserError::InvalidConfig("bad value".into());
    assert_eq!(e.to_string(), "invalid config: bad value");
}

#[test]
fn error_all_displays_unique() {
    let errors: Vec<DualBackendParserError> = vec![
        DualBackendParserError::NoBackendsRegistered,
        DualBackendParserError::BackendNotFound("x".into()),
        DualBackendParserError::BackendUnhealthy("y".into()),
        DualBackendParserError::AllBackendsFailed(vec!["z".into()]),
        DualBackendParserError::NormalizationVerificationFailed {
            backend_id: "a".into(),
            expected_hash: "b".into(),
            actual_hash: "c".into(),
        },
        DualBackendParserError::FidelityBelowThreshold {
            backend_id: "d".into(),
            fidelity_millionths: 1,
            threshold_millionths: 2,
        },
        DualBackendParserError::TooManyBackends { count: 9, max: 8 },
        DualBackendParserError::InvalidConfig("e".into()),
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(DualBackendParserError::NoBackendsRegistered);
    assert!(!e.to_string().is_empty());
}

#[test]
fn error_serde_roundtrip() {
    let e = DualBackendParserError::NormalizationVerificationFailed {
        backend_id: "swc".into(),
        expected_hash: "sha256:aaa".into(),
        actual_hash: "sha256:bbb".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: DualBackendParserError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// Section 13: DivergenceClass — Display, ordering, serde
// ---------------------------------------------------------------------------

#[test]
fn divergence_class_display() {
    assert_eq!(DivergenceClass::AstDivergence.to_string(), "ast_divergence");
    assert_eq!(
        DivergenceClass::DiagnosticsDivergence.to_string(),
        "diagnostics_divergence"
    );
    assert_eq!(
        DivergenceClass::SpanDivergence.to_string(),
        "span_divergence"
    );
    assert_eq!(
        DivergenceClass::ErrorDivergence.to_string(),
        "error_divergence"
    );
}

#[test]
fn divergence_class_serde_roundtrip() {
    for dc in &[
        DivergenceClass::AstDivergence,
        DivergenceClass::DiagnosticsDivergence,
        DivergenceClass::SpanDivergence,
        DivergenceClass::ErrorDivergence,
    ] {
        let json = serde_json::to_string(dc).unwrap();
        let back: DivergenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*dc, back);
    }
}

// ---------------------------------------------------------------------------
// Section 14: DualBackendParser — creation, registration, health, selection
// ---------------------------------------------------------------------------

#[test]
fn parser_creation_initial_state() {
    let parser = make_parser();
    assert_eq!(parser.parser_id, "integ-parser");
    assert_eq!(parser.backend_count(), 3);
    assert_eq!(parser.healthy_backend_count(), 3);
    assert_eq!(parser.parse_count, 0);
    assert_eq!(parser.fallback_count, 0);
    assert_eq!(parser.normalization_failure_count, 0);
}

#[test]
fn parser_empty_select_fails() {
    let mut parser = DualBackendParser::new(
        "empty",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    let result = parser.select_backend(ParseGoal::Module, None);
    assert!(matches!(
        result,
        Err(DualBackendParserError::NoBackendsRegistered)
    ));
}

#[test]
fn parser_selects_swc_as_primary() {
    let mut parser = make_parser();
    let selected = parser.select_backend(ParseGoal::Module, None).unwrap();
    assert_eq!(selected, BackendId::swc());
}

#[test]
fn parser_fallback_when_primary_unhealthy() {
    let mut parser = make_parser();
    parser.set_backend_health(&BackendId::swc(), false).unwrap();
    let selected = parser.select_backend(ParseGoal::Module, None).unwrap();
    assert_eq!(selected, BackendId::franken_canonical());
    assert_eq!(parser.fallback_count, 1);
}

#[test]
fn parser_all_unhealthy_returns_error() {
    let mut parser = DualBackendParser::new(
        "all-sick",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    parser
        .register_backend(make_registration(BackendId::swc(), 1, false))
        .unwrap();
    parser
        .register_backend(make_registration(BackendId::franken_canonical(), 2, false))
        .unwrap();
    let result = parser.select_backend(ParseGoal::Module, None);
    assert!(matches!(
        result,
        Err(DualBackendParserError::AllBackendsFailed(_))
    ));
}

#[test]
fn parser_health_toggle() {
    let mut parser = make_parser();
    parser.set_backend_health(&BackendId::swc(), false).unwrap();
    assert_eq!(parser.healthy_backend_count(), 2);
    parser.set_backend_health(&BackendId::swc(), true).unwrap();
    assert_eq!(parser.healthy_backend_count(), 3);
}

#[test]
fn parser_health_unknown_backend() {
    let mut parser = make_parser();
    let result = parser.set_backend_health(&BackendId("unknown".into()), false);
    assert!(matches!(
        result,
        Err(DualBackendParserError::BackendNotFound(_))
    ));
}

#[test]
fn parser_max_backends_enforced() {
    let mut parser = DualBackendParser::new(
        "max-test",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    for i in 0..8 {
        let reg = make_registration(BackendId(format!("b{i}")), i as u32, true);
        parser.register_backend(reg).unwrap();
    }
    let extra = make_registration(BackendId("extra".into()), 99, true);
    let result = parser.register_backend(extra);
    assert!(matches!(
        result,
        Err(DualBackendParserError::TooManyBackends { count: 9, max: 8 })
    ));
}

#[test]
fn parser_duplicate_registration_updates_in_place() {
    let mut parser = make_parser();
    let updated = BackendRegistration {
        backend_id: BackendId::swc(),
        display_name: "Updated SWC".into(),
        version: "2.0.0".into(),
        capabilities: BackendCapability::full(),
        priority: 0,
        healthy: true,
    };
    parser.register_backend(updated).unwrap();
    assert_eq!(parser.backend_count(), 3); // no growth
    let swc = parser
        .backends
        .iter()
        .find(|b| b.backend_id == BackendId::swc())
        .unwrap();
    assert_eq!(swc.version, "2.0.0");
    assert_eq!(swc.display_name, "Updated SWC");
}

#[test]
fn parser_record_parse_increments_count() {
    let mut parser = make_parser();
    parser.record_parse(&BackendId::swc(), "test.js", "sha256:abc", 1_000);
    parser.record_parse(&BackendId::swc(), "test2.js", "sha256:def", 2_000);
    assert_eq!(parser.parse_count, 2);
}

#[test]
fn parser_record_failure_does_not_increment_parse_count() {
    let mut parser = make_parser();
    parser.record_failure(&BackendId::swc(), "bad.js", "syntax error");
    assert_eq!(parser.parse_count, 0);
}

#[test]
fn parser_verify_normalization_success() {
    let mut parser = make_parser();
    let output = make_output(BackendId::swc());
    assert!(parser.verify_normalization(&output).is_ok());
    assert_eq!(parser.normalization_failure_count, 0);
}

#[test]
fn parser_verify_normalization_failure() {
    let mut parser = make_parser();
    let mut output = make_output(BackendId::swc());
    output.canonical_hash = "sha256:wrong".into(); // mismatch
    let result = parser.verify_normalization(&output);
    assert!(matches!(
        result,
        Err(DualBackendParserError::NormalizationVerificationFailed { .. })
    ));
    assert_eq!(parser.normalization_failure_count, 1);
}

#[test]
fn parser_compute_fidelity_perfect() {
    let mut parser = make_parser();
    let output = make_output(BackendId::swc());
    let report = parser.compute_fidelity(&output);
    assert_eq!(report.fidelity_score_millionths, 1_000_000);
    assert!(report.meets_threshold);
}

#[test]
fn parser_events_grow_on_actions() {
    let mut parser = make_parser();
    let initial = parser.events.len();
    parser.record_parse(&BackendId::swc(), "a.js", "h1", 100);
    parser.record_failure(&BackendId::swc(), "b.js", "err");
    assert!(parser.events.len() > initial);
    assert_eq!(parser.events.len(), initial + 2);
}

#[test]
fn parser_serde_roundtrip() {
    let parser = make_parser();
    let json = serde_json::to_string(&parser).unwrap();
    let back: DualBackendParser = serde_json::from_str(&json).unwrap();
    assert_eq!(parser.parser_id, back.parser_id);
    assert_eq!(parser.backend_count(), back.backend_count());
    assert_eq!(parser.parse_count, back.parse_count);
}

// ---------------------------------------------------------------------------
// Section 15: NormalizedParseOutput — verify_hash, serde
// ---------------------------------------------------------------------------

#[test]
fn output_verify_hash_correct() {
    let output = make_output(BackendId::swc());
    assert!(output.verify_hash());
}

#[test]
fn output_verify_hash_incorrect() {
    let mut output = make_output(BackendId::swc());
    output.canonical_hash = "sha256:wrong_hash_value".into();
    assert!(!output.verify_hash());
}

#[test]
fn output_serde_roundtrip() {
    let output = make_output(BackendId::oxc());
    let json = serde_json::to_string(&output).unwrap();
    let back: NormalizedParseOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

// ---------------------------------------------------------------------------
// Section 16: DualBackendParseEvent and DualBackendEventKind — serde
// ---------------------------------------------------------------------------

#[test]
fn event_kind_all_variants_serde() {
    let kinds = vec![
        DualBackendEventKind::BackendSelected,
        DualBackendEventKind::ParseCompleted {
            latency_us: 500,
            hash: "sha256:abc".into(),
        },
        DualBackendEventKind::ParseFailed {
            error: "syntax".into(),
        },
        DualBackendEventKind::FallbackSelected,
        DualBackendEventKind::NormalizationVerified,
        DualBackendEventKind::FidelityReported {
            score_millionths: 990_000,
        },
        DualBackendEventKind::DifferentialCompleted {
            all_equivalent: true,
        },
        DualBackendEventKind::BackendRegistered,
        DualBackendEventKind::HealthChanged { healthy: false },
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: DualBackendEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn parse_event_serde_roundtrip() {
    let event = DualBackendParseEvent {
        seq: 42,
        kind: DualBackendEventKind::ParseCompleted {
            latency_us: 1_234,
            hash: "sha256:test".into(),
        },
        backend_id: Some(BackendId::swc()),
        source_label: "main.ts".into(),
        epoch: epoch(5),
        timestamp_ns: 42_000_000,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: DualBackendParseEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// Section 17: DifferentialComparisonResult and BackendParseResult — serde
// ---------------------------------------------------------------------------

#[test]
fn differential_result_with_divergence_serde() {
    let result = DifferentialComparisonResult {
        source_label: "app.tsx".into(),
        goal: "module".into(),
        backend_results: vec![
            BackendParseResult {
                backend_id: BackendId::swc(),
                canonical_hash: Some("sha256:aaa".into()),
                success: true,
                error_code: None,
                diagnostics_hash: "sha256:ddd".into(),
                latency_us: 500,
                fidelity_score_millionths: 1_000_000,
            },
            BackendParseResult {
                backend_id: BackendId::oxc(),
                canonical_hash: Some("sha256:bbb".into()),
                success: true,
                error_code: None,
                diagnostics_hash: "sha256:eee".into(),
                latency_us: 600,
                fidelity_score_millionths: 995_000,
            },
        ],
        all_equivalent: false,
        distinct_hashes: vec!["sha256:aaa".into(), "sha256:bbb".into()],
        divergence: Some(DivergenceClass::AstDivergence),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: DifferentialComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
    assert!(!back.all_equivalent);
    assert_eq!(back.distinct_hashes.len(), 2);
}

#[test]
fn differential_result_all_equivalent() {
    let result = DifferentialComparisonResult {
        source_label: "index.js".into(),
        goal: "script".into(),
        backend_results: vec![BackendParseResult {
            backend_id: BackendId::franken_canonical(),
            canonical_hash: Some("sha256:same".into()),
            success: true,
            error_code: None,
            diagnostics_hash: "sha256:dh".into(),
            latency_us: 100,
            fidelity_score_millionths: 1_000_000,
        }],
        all_equivalent: true,
        distinct_hashes: vec!["sha256:same".into()],
        divergence: None,
    };
    assert!(result.all_equivalent);
    assert!(result.divergence.is_none());
}

#[test]
fn backend_parse_result_failure() {
    let result = BackendParseResult {
        backend_id: BackendId::oxc(),
        canonical_hash: None,
        success: false,
        error_code: Some("SYNTAX_ERROR".into()),
        diagnostics_hash: "sha256:err".into(),
        latency_us: 50,
        fidelity_score_millionths: 0,
    };
    assert!(!result.success);
    assert!(result.canonical_hash.is_none());
    assert_eq!(result.error_code.as_deref(), Some("SYNTAX_ERROR"));
}

// ---------------------------------------------------------------------------
// Section 18: DUAL_BACKEND_SCHEMA_VERSION constant
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constant() {
    assert_eq!(
        DUAL_BACKEND_SCHEMA_VERSION,
        "franken-engine.dual-backend-parser.v1"
    );
}

// ---------------------------------------------------------------------------
// Section 19: Cross-concern end-to-end scenarios
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_parse_verify_fidelity() {
    let mut parser = make_parser();
    // Select backend
    let backend = parser.select_backend(ParseGoal::Module, None).unwrap();
    assert_eq!(backend, BackendId::swc());
    // Create output
    let output = make_output(backend.clone());
    // Verify normalization
    parser.verify_normalization(&output).unwrap();
    // Compute fidelity
    let report = parser.compute_fidelity(&output);
    assert!(report.meets_threshold);
    // Record parse
    parser.record_parse(
        &backend,
        "main.ts",
        &output.canonical_hash,
        output.latency_us,
    );
    assert_eq!(parser.parse_count, 1);
    // Check events were emitted
    assert!(parser.events.len() >= 4);
}

#[test]
fn end_to_end_failover_scenario() {
    let mut parser = make_parser();
    // Mark primary unhealthy
    parser.set_backend_health(&BackendId::swc(), false).unwrap();
    // Select should failover
    let backend = parser.select_backend(ParseGoal::Module, None).unwrap();
    assert_eq!(backend, BackendId::franken_canonical());
    assert_eq!(parser.fallback_count, 1);
    // Record the failure on the original backend
    parser.record_failure(&BackendId::swc(), "app.js", "backend crashed");
    // Parse with fallback
    parser.record_parse(&backend, "app.js", "sha256:ok", 2_000);
    assert_eq!(parser.parse_count, 1);
}

#[test]
fn end_to_end_multiple_parses_accumulate() {
    let mut parser = make_parser();
    for i in 0..10 {
        let label = format!("file_{i}.js");
        let hash = format!("sha256:hash_{i}");
        parser.record_parse(&BackendId::swc(), &label, &hash, (i + 1) * 100);
    }
    assert_eq!(parser.parse_count, 10);
    assert_eq!(parser.events.len() as u64, parser.event_seq);
}
