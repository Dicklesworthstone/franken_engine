//! Enrichment integration tests for `dual_backend_parser` module.
//!
//! Tests additional scenarios: backend registration, selection policy,
//! fidelity reports, diagnostics, differential comparison, error paths,
//! Display/serde coverage.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
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

fn make_reg(id: BackendId, priority: u32, healthy: bool) -> BackendRegistration {
    BackendRegistration {
        backend_id: id,
        display_name: "Test".into(),
        version: "1.0.0".into(),
        capabilities: BackendCapability::full(),
        priority,
        healthy,
    }
}

fn make_parser() -> DualBackendParser {
    let mut p = DualBackendParser::new(
        "enrich-parser",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    p.register_backend(make_reg(BackendId::swc(), 1, true))
        .unwrap();
    p.register_backend(make_reg(BackendId::oxc(), 2, true))
        .unwrap();
    p.register_backend(make_reg(BackendId::franken_canonical(), 3, true))
        .unwrap();
    p
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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_nonempty() {
    assert!(!DUAL_BACKEND_SCHEMA_VERSION.is_empty());
    assert!(DUAL_BACKEND_SCHEMA_VERSION.contains("dual-backend-parser"));
}

// ---------------------------------------------------------------------------
// BackendId
// ---------------------------------------------------------------------------

#[test]
fn backend_id_swc() {
    let id = BackendId::swc();
    assert_eq!(id.0, "swc");
    assert_eq!(id.to_string(), "swc");
}

#[test]
fn backend_id_oxc() {
    let id = BackendId::oxc();
    assert_eq!(id.0, "oxc");
}

#[test]
fn backend_id_franken_canonical() {
    let id = BackendId::franken_canonical();
    assert_eq!(id.0, "franken_canonical");
}

#[test]
fn backend_id_display_distinctness() {
    let ids = [
        BackendId::swc(),
        BackendId::oxc(),
        BackendId::franken_canonical(),
    ];
    let displays: BTreeSet<String> = ids.iter().map(|id| id.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn backend_id_serde_roundtrip() {
    let id = BackendId::swc();
    let json = serde_json::to_string(&id).unwrap();
    let back: BackendId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

// ---------------------------------------------------------------------------
// BackendCapability
// ---------------------------------------------------------------------------

#[test]
fn capability_full_defaults() {
    let c = BackendCapability::full();
    assert!(c.typescript);
    assert!(c.jsx);
    assert!(c.source_maps);
    assert!(!c.incremental);
    assert!(c.comment_preservation);
    assert_eq!(c.max_source_bytes, 0);
}

#[test]
fn capability_minimal_defaults() {
    let c = BackendCapability::minimal();
    assert!(!c.typescript);
    assert!(!c.jsx);
    assert!(!c.source_maps);
    assert_eq!(c.max_source_bytes, 1_048_576);
}

#[test]
fn capability_satisfies_basic_requirements() {
    let c = BackendCapability::full();
    let req = BackendRequirements {
        needs_typescript: true,
        needs_jsx: true,
        needs_source_maps: true,
        needs_incremental: false,
    };
    assert!(c.satisfies(&req));
}

#[test]
fn capability_fails_typescript_requirement() {
    let c = BackendCapability::minimal();
    let req = BackendRequirements {
        needs_typescript: true,
        ..BackendRequirements::default()
    };
    assert!(!c.satisfies(&req));
}

#[test]
fn capability_fails_incremental_requirement() {
    let c = BackendCapability::full();
    let req = BackendRequirements {
        needs_incremental: true,
        ..BackendRequirements::default()
    };
    assert!(!c.satisfies(&req));
}

#[test]
fn capability_serde_roundtrip() {
    let c = BackendCapability::full();
    let json = serde_json::to_string(&c).unwrap();
    let back: BackendCapability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// BackendRequirements
// ---------------------------------------------------------------------------

#[test]
fn requirements_default_all_false() {
    let r = BackendRequirements::default();
    assert!(!r.needs_typescript);
    assert!(!r.needs_jsx);
    assert!(!r.needs_source_maps);
    assert!(!r.needs_incremental);
}

#[test]
fn requirements_serde_roundtrip() {
    let r = BackendRequirements {
        needs_typescript: true,
        needs_jsx: true,
        needs_source_maps: false,
        needs_incremental: false,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: BackendRequirements = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// BackendRegistration
// ---------------------------------------------------------------------------

#[test]
fn registration_serde_roundtrip() {
    let r = make_reg(BackendId::swc(), 1, true);
    let json = serde_json::to_string(&r).unwrap();
    let back: BackendRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn severity_display_distinctness() {
    let sevs = [
        DiagnosticSeverity::Hint,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Fatal,
    ];
    let displays: BTreeSet<String> = sevs.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn severity_ordering() {
    assert!(DiagnosticSeverity::Hint < DiagnosticSeverity::Fatal);
}

#[test]
fn severity_serde_roundtrip() {
    for s in [
        DiagnosticSeverity::Hint,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Fatal,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticCategory
// ---------------------------------------------------------------------------

#[test]
fn category_display_distinctness() {
    let cats = [
        DiagnosticCategory::Syntax,
        DiagnosticCategory::Semantic,
        DiagnosticCategory::Type,
        DiagnosticCategory::Resource,
        DiagnosticCategory::Encoding,
    ];
    let displays: BTreeSet<String> = cats.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn category_serde_roundtrip() {
    for c in [
        DiagnosticCategory::Syntax,
        DiagnosticCategory::Semantic,
        DiagnosticCategory::Type,
        DiagnosticCategory::Resource,
        DiagnosticCategory::Encoding,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: DiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticsEnvelope
// ---------------------------------------------------------------------------

#[test]
fn envelope_empty_properties() {
    let e = DiagnosticsEnvelope::empty();
    assert!(e.is_empty());
    assert_eq!(e.len(), 0);
    assert!(!e.has_errors());
    assert!(!e.envelope_hash.is_empty());
}

#[test]
fn envelope_from_diagnostics_with_error() {
    let diag = NormalizedDiagnostic {
        code: "FE-PARSE-0001".into(),
        category: DiagnosticCategory::Syntax,
        severity: DiagnosticSeverity::Error,
        message_template: "unexpected token".into(),
        span: Some(make_span(0, 5)),
        context: BTreeMap::new(),
    };
    let e = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
    assert!(!e.is_empty());
    assert_eq!(e.len(), 1);
    assert!(e.has_errors());
}

#[test]
fn envelope_from_diagnostics_without_error() {
    let diag = NormalizedDiagnostic {
        code: "FE-WARN-0001".into(),
        category: DiagnosticCategory::Semantic,
        severity: DiagnosticSeverity::Warning,
        message_template: "unused var".into(),
        span: None,
        context: BTreeMap::new(),
    };
    let e = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
    assert!(!e.has_errors());
}

#[test]
fn envelope_serde_roundtrip() {
    let e = DiagnosticsEnvelope::empty();
    let json = serde_json::to_string(&e).unwrap();
    let back: DiagnosticsEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// SpanMappingEntry
// ---------------------------------------------------------------------------

#[test]
fn span_mapping_exact() {
    let entry = SpanMappingEntry {
        node_index: 0,
        canonical_span: make_span(0, 10),
        backend_span: make_span(0, 10),
        deviation_bytes: 0,
    };
    assert!(entry.is_exact());
}

#[test]
fn span_mapping_non_exact() {
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
        node_index: 5,
        canonical_span: make_span(10, 20),
        backend_span: make_span(10, 21),
        deviation_bytes: 1,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: SpanMappingEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// BackendSelectionPolicy
// ---------------------------------------------------------------------------

#[test]
fn policy_default_swc_primary() {
    let p = BackendSelectionPolicy::default_swc_primary();
    assert_eq!(p.default_backend, BackendId::swc());
    assert_eq!(p.fallback_backend, BackendId::franken_canonical());
    assert!(p.verify_normalization);
    assert!(!p.differential_mode);
}

#[test]
fn policy_default_oxc_primary() {
    let p = BackendSelectionPolicy::default_oxc_primary();
    assert_eq!(p.default_backend, BackendId::oxc());
    assert_eq!(p.fallback_backend, BackendId::swc());
}

#[test]
fn policy_differential() {
    let p = BackendSelectionPolicy::differential();
    assert!(p.differential_mode);
    assert_eq!(p.default_backend, BackendId::franken_canonical());
}

#[test]
fn policy_select_backend_default() {
    let p = BackendSelectionPolicy::default_swc_primary();
    let backends = vec![make_reg(BackendId::swc(), 1, true)];
    let selected = p.select_backend(ParseGoal::Module, None, &backends);
    assert_eq!(selected, BackendId::swc());
}

#[test]
fn policy_select_backend_fallback_when_default_unhealthy() {
    let p = BackendSelectionPolicy::default_swc_primary();
    let backends = vec![
        make_reg(BackendId::swc(), 1, false),
        make_reg(BackendId::franken_canonical(), 2, true),
    ];
    let selected = p.select_backend(ParseGoal::Module, None, &backends);
    assert_eq!(selected, BackendId::franken_canonical());
}

#[test]
fn policy_serde_roundtrip() {
    let p = BackendSelectionPolicy::default_swc_primary();
    let json = serde_json::to_string(&p).unwrap();
    let back: BackendSelectionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// FidelityReport
// ---------------------------------------------------------------------------

#[test]
fn fidelity_report_all_exact() {
    let mappings = vec![
        SpanMappingEntry {
            node_index: 0,
            canonical_span: make_span(0, 10),
            backend_span: make_span(0, 10),
            deviation_bytes: 0,
        },
        SpanMappingEntry {
            node_index: 1,
            canonical_span: make_span(10, 20),
            backend_span: make_span(10, 20),
            deviation_bytes: 0,
        },
    ];
    let r = FidelityReport::from_mappings(BackendId::swc(), &mappings, 990_000);
    assert_eq!(r.total_spans, 2);
    assert_eq!(r.exact_spans, 2);
    assert_eq!(r.max_deviation_bytes, 0);
    assert_eq!(r.fidelity_score_millionths, 1_000_000);
    assert!(r.meets_threshold);
    assert!(r.deviations.is_empty());
}

#[test]
fn fidelity_report_with_deviations() {
    let mappings = vec![
        SpanMappingEntry {
            node_index: 0,
            canonical_span: make_span(0, 10),
            backend_span: make_span(0, 10),
            deviation_bytes: 0,
        },
        SpanMappingEntry {
            node_index: 1,
            canonical_span: make_span(10, 20),
            backend_span: make_span(10, 23),
            deviation_bytes: 3,
        },
    ];
    let r = FidelityReport::from_mappings(BackendId::oxc(), &mappings, 990_000);
    assert_eq!(r.total_spans, 2);
    assert_eq!(r.exact_spans, 1);
    assert_eq!(r.max_deviation_bytes, 3);
    assert_eq!(r.fidelity_score_millionths, 500_000);
    assert!(!r.meets_threshold);
    assert_eq!(r.deviations.len(), 1);
}

#[test]
fn fidelity_report_empty_mappings() {
    let r = FidelityReport::from_mappings(BackendId::swc(), &[], 990_000);
    assert_eq!(r.fidelity_score_millionths, 1_000_000);
    assert!(r.meets_threshold);
}

#[test]
fn fidelity_report_serde_roundtrip() {
    let r = FidelityReport::from_mappings(BackendId::swc(), &[], 990_000);
    let json = serde_json::to_string(&r).unwrap();
    let back: FidelityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// DivergenceClass
// ---------------------------------------------------------------------------

#[test]
fn divergence_class_display_distinctness() {
    let classes = [
        DivergenceClass::AstDivergence,
        DivergenceClass::DiagnosticsDivergence,
        DivergenceClass::SpanDivergence,
        DivergenceClass::ErrorDivergence,
    ];
    let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn divergence_class_serde_roundtrip() {
    for c in [
        DivergenceClass::AstDivergence,
        DivergenceClass::DiagnosticsDivergence,
        DivergenceClass::SpanDivergence,
        DivergenceClass::ErrorDivergence,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: DivergenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ---------------------------------------------------------------------------
// DualBackendParserError
// ---------------------------------------------------------------------------

#[test]
fn error_display_distinctness() {
    let errors: Vec<DualBackendParserError> = vec![
        DualBackendParserError::NoBackendsRegistered,
        DualBackendParserError::BackendNotFound("test".into()),
        DualBackendParserError::BackendUnhealthy("test".into()),
        DualBackendParserError::AllBackendsFailed(vec!["a".into()]),
        DualBackendParserError::NormalizationVerificationFailed {
            backend_id: "b".into(),
            expected_hash: "h1".into(),
            actual_hash: "h2".into(),
        },
        DualBackendParserError::FidelityBelowThreshold {
            backend_id: "c".into(),
            fidelity_millionths: 500_000,
            threshold_millionths: 990_000,
        },
        DualBackendParserError::TooManyBackends { count: 9, max: 8 },
        DualBackendParserError::InvalidConfig("bad".into()),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn error_serde_roundtrip_all() {
    let errors = vec![
        DualBackendParserError::NoBackendsRegistered,
        DualBackendParserError::BackendNotFound("swc".into()),
        DualBackendParserError::TooManyBackends { count: 10, max: 8 },
        DualBackendParserError::InvalidConfig("x".into()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: DualBackendParserError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(DualBackendParserError::NoBackendsRegistered);
    assert!(!e.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// DualBackendParser — registration and selection
// ---------------------------------------------------------------------------

#[test]
fn parser_new_no_backends() {
    let p = DualBackendParser::new(
        "test",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    assert_eq!(p.backend_count(), 0);
    assert_eq!(p.healthy_backend_count(), 0);
}

#[test]
fn parser_register_backend() {
    let mut p = DualBackendParser::new(
        "test",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    p.register_backend(make_reg(BackendId::swc(), 1, true))
        .unwrap();
    assert_eq!(p.backend_count(), 1);
    assert_eq!(p.healthy_backend_count(), 1);
}

#[test]
fn parser_register_duplicate_updates() {
    let mut p = DualBackendParser::new(
        "test",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    p.register_backend(make_reg(BackendId::swc(), 1, true))
        .unwrap();
    p.register_backend(make_reg(BackendId::swc(), 2, false))
        .unwrap();
    assert_eq!(p.backend_count(), 1);
    assert_eq!(p.healthy_backend_count(), 0);
}

#[test]
fn parser_select_backend_primary() {
    let mut p = make_parser();
    let selected = p.select_backend(ParseGoal::Module, None).unwrap();
    assert_eq!(selected, BackendId::swc());
}

#[test]
fn parser_select_backend_no_backends_error() {
    let mut p = DualBackendParser::new(
        "test",
        BackendSelectionPolicy::default_swc_primary(),
        epoch(1),
    );
    let err = p.select_backend(ParseGoal::Module, None).unwrap_err();
    assert!(matches!(err, DualBackendParserError::NoBackendsRegistered));
}

#[test]
fn parser_select_backend_fallback() {
    let mut p = make_parser();
    p.set_backend_health(&BackendId::swc(), false).unwrap();
    let selected = p.select_backend(ParseGoal::Module, None).unwrap();
    assert_eq!(selected, BackendId::franken_canonical());
    assert!(p.fallback_count > 0);
}

#[test]
fn parser_set_backend_health_not_found() {
    let mut p = make_parser();
    let err = p
        .set_backend_health(&BackendId("unknown".into()), true)
        .unwrap_err();
    assert!(matches!(err, DualBackendParserError::BackendNotFound(_)));
}

// ---------------------------------------------------------------------------
// DualBackendParser — parse recording
// ---------------------------------------------------------------------------

#[test]
fn parser_record_parse() {
    let mut p = make_parser();
    p.record_parse(&BackendId::swc(), "test.js", "hash123", 100);
    assert_eq!(p.parse_count, 1);
    assert!(!p.events.is_empty());
}

#[test]
fn parser_record_failure() {
    let mut p = make_parser();
    p.record_failure(&BackendId::swc(), "test.js", "syntax error");
    assert!(!p.events.is_empty());
}

// ---------------------------------------------------------------------------
// DualBackendParser — normalization verification
// ---------------------------------------------------------------------------

#[test]
fn parser_verify_normalization_ok() {
    let mut p = make_parser();
    let output = make_output(BackendId::swc());
    assert!(p.verify_normalization(&output).is_ok());
}

#[test]
fn parser_verify_normalization_mismatch() {
    let mut p = make_parser();
    let mut output = make_output(BackendId::swc());
    output.canonical_hash = "wrong-hash".to_string();
    let err = p.verify_normalization(&output).unwrap_err();
    assert!(matches!(
        err,
        DualBackendParserError::NormalizationVerificationFailed { .. }
    ));
    assert_eq!(p.normalization_failure_count, 1);
}

// ---------------------------------------------------------------------------
// DualBackendParser — fidelity
// ---------------------------------------------------------------------------

#[test]
fn parser_compute_fidelity_empty_source_map() {
    let mut p = make_parser();
    let output = make_output(BackendId::swc());
    let report = p.compute_fidelity(&output);
    assert_eq!(report.fidelity_score_millionths, 1_000_000);
    assert!(report.meets_threshold);
}

// ---------------------------------------------------------------------------
// DifferentialComparisonResult serde
// ---------------------------------------------------------------------------

#[test]
fn differential_comparison_serde_roundtrip() {
    let r = DifferentialComparisonResult {
        source_label: "test.js".into(),
        goal: "module".into(),
        backend_results: vec![BackendParseResult {
            backend_id: BackendId::swc(),
            canonical_hash: Some("hash".into()),
            success: true,
            error_code: None,
            diagnostics_hash: "diag-hash".into(),
            latency_us: 100,
            fidelity_score_millionths: 1_000_000,
        }],
        all_equivalent: true,
        distinct_hashes: vec!["hash".into()],
        divergence: None,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DifferentialComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// DualBackendParseEvent serde
// ---------------------------------------------------------------------------

#[test]
fn parse_event_serde_roundtrip() {
    let e = DualBackendParseEvent {
        seq: 0,
        kind: DualBackendEventKind::BackendSelected,
        backend_id: Some(BackendId::swc()),
        source_label: "test.js".into(),
        epoch: epoch(1),
        timestamp_ns: 1_000_000,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: DualBackendParseEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// DualBackendEventKind serde
// ---------------------------------------------------------------------------

#[test]
fn event_kind_serde_roundtrip_all() {
    let kinds = vec![
        DualBackendEventKind::BackendSelected,
        DualBackendEventKind::ParseCompleted {
            latency_us: 100,
            hash: "h".into(),
        },
        DualBackendEventKind::ParseFailed {
            error: "err".into(),
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
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: DualBackendEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// NormalizedParseOutput
// ---------------------------------------------------------------------------

#[test]
fn normalized_output_verify_hash_ok() {
    let output = make_output(BackendId::swc());
    assert!(output.verify_hash());
}

#[test]
fn normalized_output_verify_hash_mismatch() {
    let mut output = make_output(BackendId::swc());
    output.canonical_hash = "wrong".into();
    assert!(!output.verify_hash());
}

#[test]
fn normalized_output_serde_roundtrip() {
    let output = make_output(BackendId::swc());
    let json = serde_json::to_string(&output).unwrap();
    let back: NormalizedParseOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

// ---------------------------------------------------------------------------
// NormalizedDiagnostic serde
// ---------------------------------------------------------------------------

#[test]
fn normalized_diagnostic_serde_roundtrip() {
    let d = NormalizedDiagnostic {
        code: "FE-TEST-0001".into(),
        category: DiagnosticCategory::Syntax,
        severity: DiagnosticSeverity::Error,
        message_template: "test error".into(),
        span: Some(make_span(0, 5)),
        context: BTreeMap::from([("key".into(), "val".into())]),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: NormalizedDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}
