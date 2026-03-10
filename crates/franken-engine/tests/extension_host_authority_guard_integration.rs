#![forbid(unsafe_code)]
//! Integration tests for the `extension_host_authority_guard` module.
//!
//! Exercises every public type, enum variant, method, builder, exemption
//! path, and cross-concern scenario from outside the crate boundary.

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

fn make_finding(kind: ViolationKind, module: &str, line: usize) -> ExtensionHostFinding {
    ExtensionHostFinding {
        kind,
        module_path: module.to_string(),
        file_path: format!("src/{module}.rs"),
        line,
        source_line: "source".to_string(),
        description: "desc".to_string(),
        remediation: "fix it".to_string(),
        exempted: false,
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

// ===========================================================================
// Section 1: ViolationKind
// ===========================================================================

#[test]
fn violation_kind_display_forbidden_pattern() {
    assert_eq!(
        ViolationKind::ForbiddenPattern.to_string(),
        "forbidden_pattern"
    );
}

#[test]
fn violation_kind_display_missing_cx_parameter() {
    assert_eq!(
        ViolationKind::MissingCxParameter.to_string(),
        "missing_cx_parameter"
    );
}

#[test]
fn violation_kind_display_direct_upstream_import() {
    assert_eq!(
        ViolationKind::DirectUpstreamImport.to_string(),
        "direct_upstream_import"
    );
}

#[test]
fn violation_kind_display_canonical_type_shadow() {
    assert_eq!(
        ViolationKind::CanonicalTypeShadow.to_string(),
        "canonical_type_shadow"
    );
}

#[test]
fn violation_kind_all_display_strings_are_unique() {
    let kinds = [
        ViolationKind::ForbiddenPattern,
        ViolationKind::MissingCxParameter,
        ViolationKind::DirectUpstreamImport,
        ViolationKind::CanonicalTypeShadow,
    ];
    let set: BTreeSet<_> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(set.len(), kinds.len());
}

#[test]
fn violation_kind_ordering() {
    assert!(ViolationKind::ForbiddenPattern < ViolationKind::MissingCxParameter);
    assert!(ViolationKind::MissingCxParameter < ViolationKind::DirectUpstreamImport);
    assert!(ViolationKind::DirectUpstreamImport < ViolationKind::CanonicalTypeShadow);
}

#[test]
fn violation_kind_serde_roundtrip_all_variants() {
    let kinds = [
        ViolationKind::ForbiddenPattern,
        ViolationKind::MissingCxParameter,
        ViolationKind::DirectUpstreamImport,
        ViolationKind::CanonicalTypeShadow,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: ViolationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn violation_kind_clone_and_copy() {
    let k = ViolationKind::MissingCxParameter;
    let k2 = k; // Copy
    let k3 = k; // Copy
    assert_eq!(k, k2);
    assert_eq!(k2, k3);
}

// ===========================================================================
// Section 2: ExtensionHostExemptionRegistry
// ===========================================================================

#[test]
fn empty_registry_accessors() {
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
fn registry_add_and_len() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    assert_eq!(reg.len(), 1);
    assert!(!reg.is_empty());
    reg.add(make_exemption(
        "e2",
        "m::b",
        ViolationKind::DirectUpstreamImport,
        "use franken_kernel",
        0,
    ));
    assert_eq!(reg.len(), 2);
}

#[test]
fn registry_entries_returns_all() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    reg.add(make_exemption(
        "e2",
        "m::b",
        ViolationKind::DirectUpstreamImport,
        "use franken_kernel",
        0,
    ));
    assert_eq!(reg.entries().len(), 2);
    assert_eq!(reg.entries()[0].exemption_id, "e1");
    assert_eq!(reg.entries()[1].exemption_id, "e2");
}

#[test]
fn registry_is_exempted_module_wide() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    // line=0 means module-wide, matches any line
    assert!(reg.is_exempted("m::a", ViolationKind::ForbiddenPattern, "std::fs", 1));
    assert!(reg.is_exempted("m::a", ViolationKind::ForbiddenPattern, "std::fs", 100));
    assert!(reg.is_exempted("m::a", ViolationKind::ForbiddenPattern, "std::fs", 999));
}

#[test]
fn registry_is_exempted_specific_line() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        5,
    ));
    assert!(reg.is_exempted("m::a", ViolationKind::ForbiddenPattern, "std::fs", 5));
    assert!(!reg.is_exempted("m::a", ViolationKind::ForbiddenPattern, "std::fs", 6));
    assert!(!reg.is_exempted("m::a", ViolationKind::ForbiddenPattern, "std::fs", 4));
}

#[test]
fn registry_is_exempted_wrong_module_no_match() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    assert!(!reg.is_exempted("m::b", ViolationKind::ForbiddenPattern, "std::fs", 1));
}

#[test]
fn registry_is_exempted_wrong_kind_no_match() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    assert!(!reg.is_exempted("m::a", ViolationKind::DirectUpstreamImport, "std::fs", 1));
}

#[test]
fn registry_is_exempted_wrong_token_no_match() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    assert!(!reg.is_exempted("m::a", ViolationKind::ForbiddenPattern, "std::net", 1));
}

#[test]
fn registry_serde_roundtrip() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m::a",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    reg.add(make_exemption(
        "e2",
        "m::b",
        ViolationKind::CanonicalTypeShadow,
        "TraceId",
        10,
    ));
    let json = serde_json::to_string(&reg).unwrap();
    let restored: ExtensionHostExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, restored);
}

// ===========================================================================
// Section 3: GuardConfig
// ===========================================================================

#[test]
fn guard_config_default_has_forbidden_imports() {
    let cfg = GuardConfig::default();
    assert!(!cfg.forbidden_imports.is_empty());
    // 6 entries: 3 use + 3 extern crate
    assert_eq!(cfg.forbidden_imports.len(), 6);
}

#[test]
fn guard_config_default_has_canonical_types() {
    let cfg = GuardConfig::default();
    let expected = [
        "TraceId",
        "DecisionId",
        "PolicyId",
        "SchemaVersion",
        "Budget",
        "Cx",
    ];
    assert_eq!(cfg.canonical_types.len(), expected.len());
    for t in &expected {
        assert!(cfg.canonical_types.contains(*t));
    }
}

#[test]
fn guard_config_default_has_effectful_indicators() {
    let cfg = GuardConfig::default();
    assert!(!cfg.effectful_indicators.is_empty());
    let expected_indicators = [
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
    assert_eq!(cfg.effectful_indicators.len(), expected_indicators.len());
}

#[test]
fn guard_config_default_empty_cx_prefixes() {
    let cfg = GuardConfig::default();
    assert!(cfg.cx_audited_module_prefixes.is_empty());
}

#[test]
fn guard_config_default_includes_base_patterns() {
    let cfg = GuardConfig::default();
    assert!(cfg.include_base_patterns);
}

#[test]
fn guard_config_add_cx_audited_prefix() {
    let mut cfg = GuardConfig::default();
    cfg.add_cx_audited_prefix("ext_host");
    assert!(cfg.cx_audited_module_prefixes.contains("ext_host"));
    cfg.add_cx_audited_prefix("extensions");
    assert_eq!(cfg.cx_audited_module_prefixes.len(), 2);
}

#[test]
fn guard_config_add_effectful_indicator() {
    let mut cfg = GuardConfig::default();
    let initial = cfg.effectful_indicators.len();
    cfg.add_effectful_indicator("custom_side_effect");
    assert_eq!(cfg.effectful_indicators.len(), initial + 1);
    assert!(
        cfg.effectful_indicators
            .contains(&"custom_side_effect".to_string())
    );
}

#[test]
fn guard_config_add_forbidden_import() {
    let mut cfg = GuardConfig::default();
    let initial = cfg.forbidden_imports.len();
    cfg.add_forbidden_import("use secret_crate", "use crate::safe_wrapper instead");
    assert_eq!(cfg.forbidden_imports.len(), initial + 1);
}

#[test]
fn guard_config_serde_roundtrip() {
    let mut cfg = GuardConfig::default();
    cfg.add_cx_audited_prefix("ext_host");
    cfg.add_effectful_indicator("custom_op");
    cfg.add_forbidden_import("use bad", "use good");
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: GuardConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ===========================================================================
// Section 4: ExtensionHostGuard — construction and accessors
// ===========================================================================

#[test]
fn standard_guard_has_default_config() {
    let guard = standard_guard();
    assert!(guard.config().include_base_patterns);
    assert!(!guard.config().canonical_types.is_empty());
}

#[test]
fn standard_guard_has_empty_exemptions() {
    let guard = standard_guard();
    assert!(guard.exemptions().is_empty());
}

#[test]
fn guard_with_exemptions_reports_them() {
    let mut reg = ExtensionHostExemptionRegistry::new();
    reg.add(make_exemption(
        "e1",
        "m",
        ViolationKind::ForbiddenPattern,
        "std::fs",
        0,
    ));
    let guard = ExtensionHostGuard::new(GuardConfig::default(), reg);
    assert_eq!(guard.exemptions().len(), 1);
}

// ===========================================================================
// Section 5: audit_source — clean code
// ===========================================================================

#[test]
fn clean_pure_computation_no_findings() {
    let guard = standard_guard();
    let source = "fn add(a: i64, b: i64) -> i64 { a + b }\n";
    let findings = guard.audit_source("ext_host::math", "src/math.rs", source);
    assert!(findings.is_empty());
}

#[test]
fn clean_empty_source() {
    let guard = standard_guard();
    let findings = guard.audit_source("m", "f.rs", "");
    assert!(findings.is_empty());
}

#[test]
fn clean_whitespace_only() {
    let guard = standard_guard();
    let findings = guard.audit_source("m", "f.rs", "   \n  \n   ");
    assert!(findings.is_empty());
}

#[test]
fn clean_cx_gated_effectful_function() {
    let guard = cx_guard("ext_host");
    let source = "\
fn do_work(cx: &dyn ContextAdapter, data: &[u8]) {
    dispatch_hostcall(cx, \"read_data\");
}
";
    let findings = guard.audit_source("ext_host::worker", "src/worker.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

// ===========================================================================
// Section 6: audit_source — forbidden I/O patterns (base auditor)
// ===========================================================================

#[test]
fn detects_std_fs() {
    let guard = standard_guard();
    let source = "let data = std::fs::read(\"secrets.txt\");\n";
    let findings = guard.audit_source("ext_host::io", "src/io.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn detects_tcp_stream() {
    let guard = standard_guard();
    let source = "let s = TcpStream::connect(\"evil.com:443\");\n";
    let findings = guard.audit_source("ext_host::net", "src/net.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn detects_command_new() {
    let guard = standard_guard();
    let source = "let output = Command::new(\"rm\").arg(\"-rf\").output();\n";
    let findings = guard.audit_source("ext_host::exec", "src/exec.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn detects_static_mut() {
    let guard = standard_guard();
    let source = "static mut GLOBAL: u64 = 0;\n";
    let findings = guard.audit_source("ext_host::state", "src/state.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn detects_system_time() {
    let guard = standard_guard();
    let source = "let now = SystemTime::now();\n";
    let findings = guard.audit_source("ext_host::clock", "src/clock.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    );
}

#[test]
fn no_base_guard_skips_forbidden_patterns() {
    let guard = no_base_guard();
    let source = "let _ = std::fs::read(\"x\");\nstatic mut BAD: u64 = 0;\n";
    let findings = guard.audit_source("ext_host::io", "src/io.rs", source);
    let base_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::ForbiddenPattern)
        .collect();
    assert!(base_viols.is_empty());
}

// ===========================================================================
// Section 7: audit_source — direct upstream imports
// ===========================================================================

#[test]
fn detects_use_franken_kernel() {
    let guard = standard_guard();
    let source = "use franken_kernel::Cx;\n";
    let findings = guard.audit_source("ext_host::bridge", "src/bridge.rs", source);
    let import_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(!import_viols.is_empty());
    assert!(import_viols[0].remediation.contains("crate::control_plane"));
}

#[test]
fn detects_use_franken_decision() {
    let guard = standard_guard();
    let source = "use franken_decision::DecisionContract;\n";
    let findings = guard.audit_source("ext_host::policy", "src/policy.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    );
}

#[test]
fn detects_use_franken_evidence() {
    let guard = standard_guard();
    let source = "use franken_evidence::EvidenceLedger;\n";
    let findings = guard.audit_source("ext_host::ev", "src/ev.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    );
}

#[test]
fn detects_extern_crate_franken_kernel() {
    let guard = standard_guard();
    let source = "extern crate franken_kernel;\n";
    let findings = guard.audit_source("ext_host::old", "src/old.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    );
}

#[test]
fn detects_extern_crate_franken_decision() {
    let guard = standard_guard();
    let source = "extern crate franken_decision;\n";
    let findings = guard.audit_source("ext_host::old2", "src/old2.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    );
}

#[test]
fn detects_extern_crate_franken_evidence() {
    let guard = standard_guard();
    let source = "extern crate franken_evidence;\n";
    let findings = guard.audit_source("ext_host::old3", "src/old3.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    );
}

#[test]
fn does_not_flag_control_plane_import() {
    let guard = standard_guard();
    let source = "use crate::control_plane::ContextAdapter;\nuse crate::control_plane::{TraceId, DecisionId};\n";
    let findings = guard.audit_source("ext_host::adapter", "src/adapter.rs", source);
    let import_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(import_viols.is_empty());
}

#[test]
fn does_not_flag_commented_import() {
    let guard = standard_guard();
    let source = "// use franken_kernel::Cx;\n/// use franken_decision::DecisionContract;\n";
    let findings = guard.audit_source("ext_host::docs", "src/docs.rs", source);
    let import_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(import_viols.is_empty());
}

#[test]
fn custom_forbidden_import_detected() {
    let mut config = GuardConfig::default();
    config.add_forbidden_import("use secret_crate", "Use crate::safe_wrapper instead");
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "use secret_crate::DangerousApi;\n";
    let findings = guard.audit_source("ext_host::x", "src/x.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    );
}

// ===========================================================================
// Section 8: audit_source — canonical type shadowing
// ===========================================================================

#[test]
fn detects_struct_trace_id_shadow() {
    let guard = standard_guard();
    let source = "pub struct TraceId(u64);\n";
    let findings = guard.audit_source("ext_host::types", "src/types.rs", source);
    let shadow_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .collect();
    assert!(!shadow_viols.is_empty());
    assert!(shadow_viols[0].description.contains("TraceId"));
}

#[test]
fn detects_enum_budget_shadow() {
    let guard = standard_guard();
    let source = "pub enum Budget { Limited, Unlimited }\n";
    let findings = guard.audit_source("ext_host::budget", "src/budget.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::CanonicalTypeShadow
                && f.description.contains("Budget"))
    );
}

#[test]
fn detects_type_alias_decision_id_shadow() {
    let guard = standard_guard();
    let source = "type DecisionId = u64;\n";
    let findings = guard.audit_source("ext_host::ids", "src/ids.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::CanonicalTypeShadow
                && f.description.contains("DecisionId"))
    );
}

#[test]
fn detects_struct_cx_shadow() {
    let guard = standard_guard();
    let source = "struct Cx { inner: u64 }\n";
    let findings = guard.audit_source("ext_host::ctx", "src/ctx.rs", source);
    assert!(findings.iter().any(|f| f.kind == ViolationKind::CanonicalTypeShadow && f.description.contains("`Cx`")));
}

#[test]
fn detects_struct_policy_id_shadow() {
    let guard = standard_guard();
    let source = "pub struct PolicyId(String);\n";
    let findings = guard.audit_source("ext_host::pol", "src/pol.rs", source);
    assert!(findings.iter().any(
        |f| f.kind == ViolationKind::CanonicalTypeShadow && f.description.contains("PolicyId")
    ));
}

#[test]
fn detects_struct_schema_version_shadow() {
    let guard = standard_guard();
    let source = "pub struct SchemaVersion(u32);\n";
    let findings = guard.audit_source("ext_host::schema", "src/schema.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == ViolationKind::CanonicalTypeShadow
                && f.description.contains("SchemaVersion"))
    );
}

#[test]
fn does_not_flag_non_canonical_type() {
    let guard = standard_guard();
    let source = "pub struct MyCustomType(u64);\npub enum WorkerState { Idle, Running }\n";
    let findings = guard.audit_source("ext_host::types", "src/types.rs", source);
    let shadow_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .collect();
    assert!(shadow_viols.is_empty());
}

#[test]
fn does_not_flag_commented_type_shadow() {
    let guard = standard_guard();
    let source = "// struct TraceId(u64);\n/// type Budget = f64;\n";
    let findings = guard.audit_source("ext_host::docs", "src/docs.rs", source);
    let shadow_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .collect();
    assert!(shadow_viols.is_empty());
}

#[test]
fn shadow_remediation_mentions_control_plane() {
    let guard = standard_guard();
    let source = "pub struct TraceId(u64);\n";
    let findings = guard.audit_source("ext_host::types", "src/types.rs", source);
    let shadow = findings
        .iter()
        .find(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        .unwrap();
    assert!(shadow.remediation.contains("crate::control_plane"));
}

// ===========================================================================
// Section 9: audit_source — missing Cx parameter
// ===========================================================================

#[test]
fn detects_effectful_function_without_cx() {
    let guard = cx_guard("ext_host");
    let source = "\
fn send_data(payload: &[u8]) {
    dispatch_hostcall(\"write_data\");
}
";
    let findings = guard.audit_source("ext_host::sender", "src/sender.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(!cx_viols.is_empty());
    assert!(cx_viols[0].description.contains("send_data"));
    assert!(cx_viols[0].remediation.contains("ContextAdapter"));
}

#[test]
fn effectful_with_context_adapter_passes() {
    let guard = cx_guard("ext_host");
    let source = "\
fn do_work(cx: &dyn ContextAdapter, data: &[u8]) {
    dispatch_hostcall(cx, \"process\");
}
";
    let findings = guard.audit_source("ext_host::worker", "src/worker.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

#[test]
fn effectful_with_cx_ref_passes() {
    let guard = cx_guard("ext_host");
    let source = "\
fn do_work(cx: &Cx, data: &[u8]) {
    emit_telemetry(cx, \"metric\", 42);
}
";
    let findings = guard.audit_source("ext_host::worker", "src/worker.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

#[test]
fn effectful_with_mut_cx_passes() {
    let guard = cx_guard("ext_host");
    let source = "\
fn do_work(cx: &mut Cx) {
    consume_budget(cx, 10);
}
";
    let findings = guard.audit_source("ext_host::budget", "src/budget.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

#[test]
fn effectful_with_cx_named_param_passes() {
    let guard = cx_guard("ext_host");
    let source = "\
fn do_work(cx: &mut impl ContextAdapter) {
    consume_budget(cx, 10);
}
";
    let findings = guard.audit_source("ext_host::budget", "src/budget.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

#[test]
fn non_effectful_function_not_flagged() {
    let guard = cx_guard("ext_host");
    let source = "\
fn pure_compute(x: i64, y: i64) -> i64 {
    x + y
}
";
    let findings = guard.audit_source("ext_host::math", "src/math.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

#[test]
fn cx_audited_prefix_restricts_scope() {
    let guard = cx_guard("ext_host");
    // Module is NOT under "ext_host" prefix, so Cx check skipped
    let source = "\
fn unchecked_send(payload: &[u8]) {
    dispatch_hostcall(\"write_data\");
}
";
    let findings = guard.audit_source("engine::sender", "src/sender.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

#[test]
fn empty_cx_prefixes_audits_all_modules() {
    // No prefixes configured = all modules checked
    let config = GuardConfig::default();
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "\
fn send_data(payload: &[u8]) {
    dispatch_hostcall(\"write_data\");
}
";
    let findings = guard.audit_source("any_module::sender", "src/sender.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(!cx_viols.is_empty());
}

#[test]
fn multiple_effectful_indicators_one_finding() {
    let config = GuardConfig::default();
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "\
fn bad_function(data: &[u8]) {
    dispatch_hostcall(\"read\");
    emit_telemetry(\"metric\", 1);
    consume_budget(10);
}
";
    let findings = guard.audit_source("ext::bad", "src/bad.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    // One finding per function, not per indicator
    assert_eq!(cx_viols.len(), 1);
}

#[test]
fn custom_effectful_indicator_detected() {
    let mut config = GuardConfig::default();
    config.add_effectful_indicator("custom_effect");
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "\
fn bad_fn(data: &[u8]) {
    custom_effect(data);
}
";
    let findings = guard.audit_source("ext_host::custom", "src/custom.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(!cx_viols.is_empty());
}

#[test]
fn all_effectful_indicators_detected_individually() {
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
    for indicator in &indicators {
        let config = GuardConfig::default();
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
        let source = format!("fn bad_fn() {{\n    {indicator}(\"x\");\n}}\n");
        let findings = guard.audit_source("ext::m", "src/m.rs", &source);
        let cx_viols: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(
            !cx_viols.is_empty(),
            "Expected violation for indicator: {indicator}"
        );
    }
}

// ===========================================================================
// Section 10: Exemptions applied during audit
// ===========================================================================

#[test]
fn exemption_suppresses_direct_import_finding() {
    let mut exemptions = ExtensionHostExemptionRegistry::new();
    exemptions.add(ExtensionHostExemption {
        exemption_id: "ehx-001".to_string(),
        module_path: "ext_host::bootstrap".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "Bootstrap needs direct kernel access".to_string(),
        line: 0,
    });
    let guard = ExtensionHostGuard::new(GuardConfig::default(), exemptions);
    let source = "use franken_kernel::Cx;\n";
    let findings = guard.audit_source("ext_host::bootstrap", "src/bootstrap.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(!import_findings.is_empty());
    assert!(import_findings.iter().all(|f| f.exempted));
}

#[test]
fn line_specific_exemption_only_applies_to_that_line() {
    let mut exemptions = ExtensionHostExemptionRegistry::new();
    exemptions.add(ExtensionHostExemption {
        exemption_id: "ehx-002".to_string(),
        module_path: "ext_host::mixed".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "Line 2 only".to_string(),
        line: 2,
    });
    let guard = ExtensionHostGuard::new(GuardConfig::default(), exemptions);
    let source = "// header\nuse franken_kernel::Cx;\nuse franken_kernel::Budget;";
    let findings = guard.audit_source("ext_host::mixed", "src/mixed.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    let exempted_count = import_findings.iter().filter(|f| f.exempted).count();
    let violation_count = import_findings.iter().filter(|f| !f.exempted).count();
    assert_eq!(exempted_count, 1);
    assert!(violation_count >= 1);
}

// ===========================================================================
// Section 11: audit_all — multi-file
// ===========================================================================

#[test]
fn audit_all_clean_passes() {
    let guard = standard_guard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("ext_host::pure".to_string(), "src/pure.rs".to_string()),
        "fn add(a: i64, b: i64) -> i64 { a + b }".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert_eq!(result.exemption_count, 0);
    assert_eq!(result.modules_audited.len(), 1);
    assert!(result.findings.is_empty());
}

#[test]
fn audit_all_aggregates_findings_across_files() {
    let guard = standard_guard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("ext_host::clean".to_string(), "src/clean.rs".to_string()),
        "fn ok() { 1 + 1; }".to_string(),
    );
    sources.insert(
        ("ext_host::dirty".to_string(), "src/dirty.rs".to_string()),
        "use franken_kernel::Cx;\nlet _ = std::fs::read(\"x\");".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(!result.passed);
    assert!(result.violation_count >= 2);
    assert_eq!(result.modules_audited.len(), 2);
    assert!(!result.summary_by_kind.is_empty());
}

#[test]
fn audit_all_summary_by_kind_counts_correctly() {
    let guard = standard_guard();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("ext_host::mix".to_string(), "src/mix.rs".to_string()),
        "use franken_kernel::Cx;\nlet _ = std::fs::read(\"x\");".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(
        result
            .summary_by_kind
            .get("direct_upstream_import")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    assert!(
        result
            .summary_by_kind
            .get("forbidden_pattern")
            .copied()
            .unwrap_or(0)
            >= 1
    );
}

#[test]
fn audit_all_exempted_findings_not_in_violation_count() {
    let mut exemptions = ExtensionHostExemptionRegistry::new();
    exemptions.add(ExtensionHostExemption {
        exemption_id: "ehx-all".to_string(),
        module_path: "ext_host::boot".to_string(),
        kind: ViolationKind::DirectUpstreamImport,
        matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
        reason: "allowed".to_string(),
        line: 0,
    });
    let guard = ExtensionHostGuard::new(GuardConfig::default(), exemptions);
    let mut sources = BTreeMap::new();
    sources.insert(
        ("ext_host::boot".to_string(), "src/boot.rs".to_string()),
        "use franken_kernel::Cx;\n".to_string(),
    );
    let result = guard.audit_all(&sources);
    assert!(result.exemption_count >= 1);
    // The exempted finding should not count toward violations
    let total = result.violation_count + result.exemption_count;
    assert_eq!(total, result.findings.len());
}

#[test]
fn audit_all_empty_sources_passes() {
    let guard = standard_guard();
    let sources: BTreeMap<(String, String), String> = BTreeMap::new();
    let result = guard.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert!(result.modules_audited.is_empty());
}

// ===========================================================================
// Section 12: Deterministic output and ordering
// ===========================================================================

#[test]
fn audit_source_deterministic() {
    let guard = standard_guard();
    let source = "use franken_kernel::Cx;\nlet _ = std::fs::read(\"a\");\nstruct TraceId(u64);\n";
    let f1 = guard.audit_source("ext_host::m", "f.rs", source);
    let f2 = guard.audit_source("ext_host::m", "f.rs", source);
    assert_eq!(f1, f2);
}

#[test]
fn findings_are_sorted() {
    let guard = standard_guard();
    let source = "struct TraceId(u64);\nuse franken_kernel::Cx;\nlet _ = std::fs::read(\"a\");\n";
    let findings = guard.audit_source("ext_host::m", "f.rs", source);
    // Verify findings are sorted (impl Ord)
    for window in findings.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

// ===========================================================================
// Section 13: Serde roundtrips
// ===========================================================================

#[test]
fn finding_serde_roundtrip() {
    let f = make_finding(ViolationKind::DirectUpstreamImport, "ext_host::bridge", 5);
    let json = serde_json::to_string(&f).unwrap();
    let restored: ExtensionHostFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
}

#[test]
fn exemption_serde_roundtrip() {
    let e = make_exemption(
        "ehx-001",
        "ext_host::boot",
        ViolationKind::DirectUpstreamImport,
        "use franken_kernel",
        0,
    );
    let json = serde_json::to_string(&e).unwrap();
    let restored: ExtensionHostExemption = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn audit_result_serde_roundtrip_empty() {
    let result = ExtensionHostAuditResult {
        findings: vec![],
        violation_count: 0,
        exemption_count: 0,
        modules_audited: vec!["ext_host::clean".to_string()],
        passed: true,
        summary_by_kind: BTreeMap::new(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ExtensionHostAuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn audit_result_serde_roundtrip_with_findings() {
    let f = make_finding(ViolationKind::CanonicalTypeShadow, "ext_host::m", 10);
    let mut summary = BTreeMap::new();
    summary.insert("canonical_type_shadow".to_string(), 1);
    let result = ExtensionHostAuditResult {
        findings: vec![f],
        violation_count: 1,
        exemption_count: 0,
        modules_audited: vec!["ext_host::m".to_string()],
        passed: false,
        summary_by_kind: summary,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ExtensionHostAuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ===========================================================================
// Section 14: Mixed violations and edge cases
// ===========================================================================

#[test]
fn mixed_violations_single_file() {
    let guard = standard_guard();
    let source = "\
use franken_kernel::Cx;
use franken_evidence::EvidenceLedger;
struct TraceId(u64);
let _ = std::fs::read(\"x\");
static mut BAD: u64 = 0;
";
    let findings = guard.audit_source("ext_host::mix", "src/mix.rs", source);
    let kinds: BTreeSet<ViolationKind> = findings.iter().map(|f| f.kind).collect();
    assert!(kinds.contains(&ViolationKind::DirectUpstreamImport));
    assert!(kinds.contains(&ViolationKind::CanonicalTypeShadow));
    assert!(kinds.contains(&ViolationKind::ForbiddenPattern));
}

#[test]
fn remediation_messages_are_non_empty() {
    let guard = standard_guard();
    let source = "use franken_kernel::Cx;\nstruct Budget { amount: u64 }\n";
    let findings = guard.audit_source("ext_host::bad", "src/bad.rs", source);
    for finding in &findings {
        assert!(
            !finding.remediation.is_empty(),
            "Finding {:?} has empty remediation",
            finding.kind
        );
    }
}

#[test]
fn large_file_performance() {
    let guard = standard_guard();
    let mut source = String::new();
    for i in 0..500 {
        source.push_str(&format!("fn compute_{i}(x: i64) -> i64 {{ x + {i} }}\n"));
    }
    let findings = guard.audit_source("ext_host::big", "src/big.rs", &source);
    assert!(findings.is_empty());
}

#[test]
fn finding_line_numbers_are_1_based() {
    let guard = standard_guard();
    let source = "use franken_kernel::Cx;\n";
    let findings = guard.audit_source("ext_host::m", "f.rs", source);
    let import_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .collect();
    assert!(!import_findings.is_empty());
    assert_eq!(import_findings[0].line, 1);
}

#[test]
fn finding_preserves_module_and_file_path() {
    let guard = standard_guard();
    let source = "use franken_kernel::Cx;\n";
    let findings = guard.audit_source("ext_host::bridge", "src/bridge.rs", source);
    let f = findings
        .iter()
        .find(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .unwrap();
    assert_eq!(f.module_path, "ext_host::bridge");
    assert_eq!(f.file_path, "src/bridge.rs");
}

#[test]
fn finding_ordering_by_kind() {
    let f1 = make_finding(ViolationKind::DirectUpstreamImport, "a", 1);
    let f2 = make_finding(ViolationKind::CanonicalTypeShadow, "a", 1);
    assert!(f1 < f2);
}

#[test]
fn multi_line_fn_sig_with_cx_passes() {
    let guard = cx_guard("ext_host");
    let source = "\
fn long_function(
    cx: &dyn ContextAdapter,
    data: &[u8],
) {
    dispatch_hostcall(cx, \"process\");
}
";
    let findings = guard.audit_source("ext_host::worker", "src/worker.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert!(cx_viols.is_empty());
}

#[test]
fn multiple_functions_multiple_violations() {
    let config = GuardConfig::default();
    let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());
    let source = "\
fn func_a(data: &[u8]) {
    dispatch_hostcall(\"read\");
}
fn func_b(data: &[u8]) {
    emit_telemetry(\"metric\", 1);
}
";
    let findings = guard.audit_source("ext::m", "src/m.rs", source);
    let cx_viols: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::MissingCxParameter)
        .collect();
    assert_eq!(cx_viols.len(), 2);
}
