//! Integration tests for the `ambient_authority` module.
//!
//! Tests the compile-time ambient-authority audit gate: forbidden pattern
//! detection, exemption registry, multi-file audit, and serde roundtrips.

#![forbid(unsafe_code)]
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

use frankenengine_engine::ambient_authority::{
    AuditConfig, AuditFinding, AuditResult, Exemption, ExemptionRegistry, ForbiddenCallCategory,
    ForbiddenPattern, SourceAuditor,
};

// ---------------------------------------------------------------------------
// ForbiddenCallCategory
// ---------------------------------------------------------------------------

#[test]
fn category_display_all_variants() {
    assert_eq!(ForbiddenCallCategory::FileSystem.to_string(), "filesystem");
    assert_eq!(ForbiddenCallCategory::Network.to_string(), "network");
    assert_eq!(ForbiddenCallCategory::Process.to_string(), "process");
    assert_eq!(
        ForbiddenCallCategory::GlobalMutableState.to_string(),
        "global_mutable_state"
    );
    assert_eq!(
        ForbiddenCallCategory::Environment.to_string(),
        "environment"
    );
    assert_eq!(
        ForbiddenCallCategory::RawPointerExternalState.to_string(),
        "raw_pointer_external_state"
    );
    assert_eq!(ForbiddenCallCategory::DirectTime.to_string(), "direct_time");
}

#[test]
fn category_ordering_is_deterministic() {
    assert!(ForbiddenCallCategory::FileSystem < ForbiddenCallCategory::Network);
    assert!(ForbiddenCallCategory::Network < ForbiddenCallCategory::Process);
}

// ---------------------------------------------------------------------------
// AuditConfig
// ---------------------------------------------------------------------------

#[test]
fn standard_config_has_fourteen_patterns() {
    let config = AuditConfig::standard();
    assert_eq!(config.patterns.len(), 14);
}

#[test]
fn standard_config_covers_all_categories() {
    let config = AuditConfig::standard();
    let cats: std::collections::BTreeSet<_> = config.patterns.iter().map(|p| p.category).collect();
    assert!(cats.contains(&ForbiddenCallCategory::FileSystem));
    assert!(cats.contains(&ForbiddenCallCategory::Network));
    assert!(cats.contains(&ForbiddenCallCategory::Process));
    assert!(cats.contains(&ForbiddenCallCategory::Environment));
    assert!(cats.contains(&ForbiddenCallCategory::GlobalMutableState));
    assert!(cats.contains(&ForbiddenCallCategory::DirectTime));
}

#[test]
fn audit_module_adds_to_scope() {
    let mut config = AuditConfig::standard();
    config.audit_module("engine::gc");
    config.audit_module("engine::parser");
    assert_eq!(config.audited_modules.len(), 2);
}

#[test]
fn add_custom_pattern() {
    let mut config = AuditConfig::standard();
    let initial_len = config.patterns.len();
    config.add_pattern(ForbiddenPattern {
        pattern_id: "custom".to_string(),
        category: ForbiddenCallCategory::RawPointerExternalState,
        pattern: "unsafe_fn()".to_string(),
        reason: "test".to_string(),
        suggested_alternative: "safe_fn()".to_string(),
    });
    assert_eq!(config.patterns.len(), initial_len + 1);
}

// ---------------------------------------------------------------------------
// ExemptionRegistry
// ---------------------------------------------------------------------------

#[test]
fn empty_registry() {
    let reg = ExemptionRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    assert!(!reg.is_exempted("m", "p", 1));
}

#[test]
fn module_wide_exemption() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "engine::boot".to_string(),
        pattern_id: "std_fs".to_string(),
        reason: "bootstrap".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    assert!(reg.is_exempted("engine::boot", "std_fs", 1));
    assert!(reg.is_exempted("engine::boot", "std_fs", 999));
    assert!(!reg.is_exempted("engine::boot", "other_pattern", 1));
    assert!(!reg.is_exempted("engine::other", "std_fs", 1));
}

#[test]
fn line_specific_exemption() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e2".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 42,
    });
    assert!(reg.is_exempted("m", "p", 42));
    assert!(!reg.is_exempted("m", "p", 43));
}

#[test]
fn exemptions_accessor() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "r".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    assert_eq!(reg.exemptions().len(), 1);
    assert_eq!(reg.exemptions()[0].exemption_id, "e1");
}

// ---------------------------------------------------------------------------
// SourceAuditor — clean source
// ---------------------------------------------------------------------------

fn standard_auditor() -> SourceAuditor {
    SourceAuditor::new(AuditConfig::standard(), ExemptionRegistry::new())
}

#[test]
fn clean_source_no_findings() {
    let auditor = standard_auditor();
    let source = "fn compute(x: i64) -> i64 { x * 2 + 1 }";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.is_empty());
}

// ---------------------------------------------------------------------------
// SourceAuditor — detection
// ---------------------------------------------------------------------------

#[test]
fn detects_filesystem_access() {
    let auditor = standard_auditor();
    let source = "let data = std::fs::read(\"file.txt\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ForbiddenCallCategory::FileSystem)
    );
}

#[test]
fn detects_network_access() {
    let auditor = standard_auditor();
    let source = "let stream = TcpStream::connect(\"127.0.0.1:80\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ForbiddenCallCategory::Network)
    );
}

#[test]
fn detects_udp_socket() {
    let auditor = standard_auditor();
    let source = "let sock = UdpSocket::bind(\"0.0.0.0:0\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ForbiddenCallCategory::Network)
    );
}

#[test]
fn detects_process_spawn() {
    let auditor = standard_auditor();
    let source = "let output = Command::new(\"ls\").output();";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ForbiddenCallCategory::Process)
    );
}

#[test]
fn detects_environment_access() {
    let auditor = standard_auditor();
    let source = "let val = std::env::var(\"HOME\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ForbiddenCallCategory::Environment)
    );
}

#[test]
fn detects_static_mut() {
    let auditor = standard_auditor();
    let source = "static mut COUNTER: u64 = 0;";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ForbiddenCallCategory::GlobalMutableState)
    );
}

#[test]
fn detects_system_time() {
    let auditor = standard_auditor();
    let source = "let now = SystemTime::now();";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ForbiddenCallCategory::DirectTime)
    );
}

// ---------------------------------------------------------------------------
// SourceAuditor — comments skipped
// ---------------------------------------------------------------------------

#[test]
fn comments_not_flagged() {
    let auditor = standard_auditor();
    let source = "// std::fs::read is documented here\n/// Example: TcpStream::connect\n//! Module: Command::new";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.is_empty());
}

// ---------------------------------------------------------------------------
// SourceAuditor — exemptions
// ---------------------------------------------------------------------------

#[test]
fn exempted_finding_marked() {
    let mut exemptions = ExemptionRegistry::new();
    exemptions.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "engine::boot".to_string(),
        pattern_id: "std_fs".to_string(),
        reason: "bootstrap".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    exemptions.add(Exemption {
        exemption_id: "e2".to_string(),
        module_path: "engine::boot".to_string(),
        pattern_id: "fs_read".to_string(),
        reason: "bootstrap".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
    let source = "let config = std::fs::read_to_string(\"config.toml\");";
    let findings = auditor.audit_source("engine::boot", "src/boot.rs", source);
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f.exempted));
}

// ---------------------------------------------------------------------------
// SourceAuditor — audit_all
// ---------------------------------------------------------------------------

#[test]
fn audit_all_clean_passes() {
    let auditor = standard_auditor();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("engine::pure".to_string(), "src/pure.rs".to_string()),
        "fn add(a: i64, b: i64) -> i64 { a + b }".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert_eq!(result.exemption_count, 0);
    assert_eq!(result.modules_audited.len(), 1);
}

#[test]
fn audit_all_with_violations_fails() {
    let auditor = standard_auditor();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("engine::dirty".to_string(), "src/dirty.rs".to_string()),
        "let _ = std::fs::read(\"x\");".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert!(!result.passed);
    assert!(result.violation_count >= 1);
}

#[test]
fn audit_all_multiple_modules() {
    let auditor = standard_auditor();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("engine::a".to_string(), "a.rs".to_string()),
        "fn ok() {}".to_string(),
    );
    sources.insert(
        ("engine::b".to_string(), "b.rs".to_string()),
        "fn ok() {}".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert_eq!(result.modules_audited.len(), 2);
}

#[test]
fn scoped_audit_source_skips_out_of_scope_module() {
    let mut config = AuditConfig::standard();
    config.audit_module("engine::audited");
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());

    let findings = auditor.audit_source(
        "engine::ignored",
        "src/ignored.rs",
        "let _ = std::fs::read(\"x\");",
    );

    assert!(findings.is_empty());
}

#[test]
fn scoped_audit_all_only_reports_matching_modules() {
    let mut config = AuditConfig::standard();
    config.audit_module("engine::audited");
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
    let mut sources = BTreeMap::new();
    sources.insert(
        (
            "engine::audited::worker".to_string(),
            "src/audited.rs".to_string(),
        ),
        "let _ = std::fs::read(\"audited\");".to_string(),
    );
    sources.insert(
        (
            "engine::ignored::worker".to_string(),
            "src/ignored.rs".to_string(),
        ),
        "let _ = std::fs::read(\"ignored\");".to_string(),
    );

    let result = auditor.audit_all(&sources);

    assert_eq!(
        result.modules_audited,
        vec!["engine::audited::worker".to_string()]
    );
    assert!(result.violation_count >= 1);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.module_path.starts_with("engine::audited"))
    );
}

#[test]
fn scoped_audit_does_not_match_sibling_prefix_modules() {
    let mut config = AuditConfig::standard();
    config.audit_module("engine::audit");
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
    let mut sources = BTreeMap::new();
    sources.insert(
        (
            "engine::audit::worker".to_string(),
            "src/audited.rs".to_string(),
        ),
        "let _ = std::fs::read(\"audited\");".to_string(),
    );
    sources.insert(
        (
            "engine::auditedevil::worker".to_string(),
            "src/ignored.rs".to_string(),
        ),
        "let _ = std::fs::read(\"ignored\");".to_string(),
    );

    let result = auditor.audit_all(&sources);

    assert_eq!(
        result.modules_audited,
        vec!["engine::audit::worker".to_string()]
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.module_path == "engine::audit::worker")
    );
}

// ---------------------------------------------------------------------------
// SourceAuditor — finding structure
// ---------------------------------------------------------------------------

#[test]
fn finding_contains_actionable_info() {
    let auditor = standard_auditor();
    let source = "let _ = std::fs::read(\"x\");";
    let findings = auditor.audit_source("engine::io", "src/io.rs", source);
    let f = &findings[0];
    assert_eq!(f.module_path, "engine::io");
    assert_eq!(f.file_path, "src/io.rs");
    assert_eq!(f.line, 1);
    assert!(!f.suggested_alternative.is_empty());
    assert!(!f.forbidden_api.is_empty());
    assert!(!f.exempted);
}

// ---------------------------------------------------------------------------
// SourceAuditor — deterministic output
// ---------------------------------------------------------------------------

#[test]
fn deterministic_audit_output() {
    let auditor = standard_auditor();
    let source = "let _ = std::fs::read(\"a\");\nlet _ = TcpStream::connect(\"b\");\nlet _ = Command::new(\"c\");";
    let f1 = auditor.audit_source("m", "f.rs", source);
    let f2 = auditor.audit_source("m", "f.rs", source);
    assert_eq!(f1, f2);
}

// ---------------------------------------------------------------------------
// SourceAuditor — custom pattern
// ---------------------------------------------------------------------------

#[test]
fn custom_pattern_detected() {
    let mut config = AuditConfig::standard();
    config.add_pattern(ForbiddenPattern {
        pattern_id: "custom_danger".to_string(),
        category: ForbiddenCallCategory::RawPointerExternalState,
        pattern: "dangerous_call()".to_string(),
        reason: "Custom dangerous".to_string(),
        suggested_alternative: "safe_call()".to_string(),
    });
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
    let source = "fn bad() { dangerous_call(); }";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "custom_danger"));
}

// ---------------------------------------------------------------------------
// SourceAuditor — accessors
// ---------------------------------------------------------------------------

#[test]
fn config_accessor() {
    let auditor = standard_auditor();
    assert_eq!(auditor.config().patterns.len(), 14);
}

#[test]
fn exemptions_accessor_on_auditor() {
    let auditor = standard_auditor();
    assert!(auditor.exemptions().is_empty());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn category_serde_roundtrip() {
    let cats = [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ];
    for c in &cats {
        let json = serde_json::to_string(c).unwrap();
        let restored: ForbiddenCallCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

#[test]
fn exemption_serde_roundtrip() {
    let ex = Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "r".to_string(),
        witness: "w".to_string(),
        line: 42,
    };
    let json = serde_json::to_string(&ex).unwrap();
    let restored: Exemption = serde_json::from_str(&json).unwrap();
    assert_eq!(ex, restored);
}

#[test]
fn audit_finding_serde_roundtrip() {
    let finding = AuditFinding {
        module_path: "m".to_string(),
        forbidden_api: "std::fs::read".to_string(),
        pattern_id: "std_fs".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        file_path: "f.rs".to_string(),
        line: 10,
        source_line: "let _ = std::fs::read(\"x\");".to_string(),
        suggested_alternative: "Use FileSystemCap".to_string(),
        exempted: false,
    };
    let json = serde_json::to_string(&finding).unwrap();
    let restored: AuditFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, restored);
}

#[test]
fn audit_result_serde_roundtrip() {
    let result = AuditResult {
        findings: vec![],
        violation_count: 0,
        exemption_count: 0,
        modules_audited: vec!["m".to_string()],
        passed: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn audit_config_serde_roundtrip() {
    let config = AuditConfig::standard();
    let json = serde_json::to_string(&config).unwrap();
    let restored: AuditConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn exemption_registry_serde_roundtrip() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "r".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    let json = serde_json::to_string(&reg).unwrap();
    let restored: ExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, restored);
}

// ---------------------------------------------------------------------------
// Enrichment: ExemptionRegistry — Default, is_empty, len
// ---------------------------------------------------------------------------

#[test]
fn exemption_registry_default_is_empty() {
    let reg = ExemptionRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    assert_eq!(reg.exemptions().len(), 0);
}

#[test]
fn exemption_registry_is_not_empty_after_add() {
    let mut reg = ExemptionRegistry::new();
    assert!(reg.is_empty());
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "r".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    assert!(!reg.is_empty());
    assert_eq!(reg.len(), 1);
}

#[test]
fn exemption_registry_multiple_entries() {
    let mut reg = ExemptionRegistry::new();
    for i in 0..5u64 {
        reg.add(Exemption {
            exemption_id: format!("e{i}"),
            module_path: "m".to_string(),
            pattern_id: format!("p{i}"),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
    }
    assert_eq!(reg.len(), 5);
    assert!(reg.is_exempted("m", "p0", 1));
    assert!(reg.is_exempted("m", "p4", 1));
    assert!(!reg.is_exempted("m", "p5", 1));
}

// ---------------------------------------------------------------------------
// Enrichment: Exemption — line=0 means module-wide
// ---------------------------------------------------------------------------

#[test]
fn exemption_line_zero_matches_any_line() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    assert!(reg.is_exempted("m", "p", 0));
    assert!(reg.is_exempted("m", "p", 1));
    assert!(reg.is_exempted("m", "p", 100_000));
    assert!(reg.is_exempted("m", "p", usize::MAX));
}

#[test]
fn exemption_line_usize_max_only_matches_that_line() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: usize::MAX,
    });
    assert!(reg.is_exempted("m", "p", usize::MAX));
    assert!(!reg.is_exempted("m", "p", 0));
    assert!(!reg.is_exempted("m", "p", 1));
}

#[test]
fn exemption_wrong_module_does_not_match() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "correct".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    assert!(!reg.is_exempted("wrong", "p", 1));
}

#[test]
fn exemption_wrong_pattern_id_does_not_match() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "std_fs".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    assert!(!reg.is_exempted("m", "std_net", 1));
    assert!(!reg.is_exempted("m", "fs_read", 1));
    assert!(reg.is_exempted("m", "std_fs", 1));
}

#[test]
fn exemption_empty_string_fields() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: String::new(),
        module_path: String::new(),
        pattern_id: String::new(),
        reason: String::new(),
        witness: String::new(),
        line: 0,
    });
    assert!(reg.is_exempted("", "", 1));
    assert!(!reg.is_exempted("x", "", 1));
}

// ---------------------------------------------------------------------------
// Enrichment: audit_source — empty / whitespace / edge cases
// ---------------------------------------------------------------------------

#[test]
fn audit_source_empty_source_no_findings() {
    let auditor = standard_auditor();
    let findings = auditor.audit_source("m", "f.rs", "");
    assert!(findings.is_empty());
}

#[test]
fn audit_source_whitespace_only_no_findings() {
    let auditor = standard_auditor();
    let findings = auditor.audit_source("m", "f.rs", "   \n\t\n  ");
    assert!(findings.is_empty());
}

#[test]
fn audit_source_line_numbers_are_one_indexed() {
    let auditor = standard_auditor();
    let source = "let _ = std::fs::read(\"x\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().all(|f| f.line == 1));
}

#[test]
fn audit_source_multiline_correct_line_numbers() {
    let auditor = standard_auditor();
    let source = "fn safe() {}\nlet x = std::fs::read(\"y\");\nfn also_safe() {}";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.line == 2));
    assert!(findings.iter().all(|f| f.line == 2));
}

#[test]
fn audit_source_source_line_is_trimmed() {
    let auditor = standard_auditor();
    let source = "    let _ = std::fs::read(\"x\");    ";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(!findings.is_empty());
    let f = &findings[0];
    assert_eq!(f.source_line, "let _ = std::fs::read(\"x\");");
}

#[test]
fn audit_source_very_long_module_path() {
    let auditor = standard_auditor();
    let long_path = "a::".repeat(100) + "b";
    let source = "fn pure() {}";
    let findings = auditor.audit_source(&long_path, "f.rs", source);
    assert!(findings.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: Multiple patterns matching same line
// ---------------------------------------------------------------------------

#[test]
fn multiple_patterns_match_same_line() {
    let auditor = standard_auditor();
    // Both "std::fs::" and "fs::read" patterns match here
    let source = "let _ = std::fs::read(\"x\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.len() >= 2);
    assert!(findings.iter().any(|f| f.pattern_id == "std_fs"));
    assert!(findings.iter().any(|f| f.pattern_id == "fs_read"));
}

// ---------------------------------------------------------------------------
// Enrichment: Additional pattern detection
// ---------------------------------------------------------------------------

#[test]
fn detects_fs_write() {
    let auditor = standard_auditor();
    let source = "fs::write(\"out.txt\", data);";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "fs_write"));
}

#[test]
fn detects_env_var_pattern() {
    let auditor = standard_auditor();
    let source = "let v = env::var(\"PATH\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "env_var"));
}

#[test]
fn detects_std_net_pattern() {
    let auditor = standard_auditor();
    let source = "use std::net::TcpListener;";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "std_net"));
}

#[test]
fn detects_std_process_pattern() {
    let auditor = standard_auditor();
    let source = "use std::process::exit;";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "std_process"));
}

#[test]
fn detects_std_env_pattern() {
    let auditor = standard_auditor();
    let source = "use std::env::args;";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "std_env"));
}

#[test]
fn detects_system_time_now_pattern() {
    let auditor = standard_auditor();
    let source = "let t = SystemTime::now();";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "system_time"));
}

#[test]
fn detects_static_mut_pattern() {
    let auditor = standard_auditor();
    let source = "static mut GLOBAL: i32 = 0;";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "static_mut"));
}

// ---------------------------------------------------------------------------
// Enrichment: Line-specific exemption in audit_source flow
// ---------------------------------------------------------------------------

#[test]
fn line_specific_exemption_in_audit_source() {
    let mut exemptions = ExemptionRegistry::new();
    exemptions.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "std_fs".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 2,
    });
    let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
    let source =
        "fn init() {\n    let _ = std::fs::read(\"x\");\n    let _ = std::fs::read(\"y\");\n}";
    let findings = auditor.audit_source("m", "f.rs", source);
    // Line 2 has std_fs exempted, line 3 does not
    let exempted_count = findings
        .iter()
        .filter(|f| f.exempted && f.pattern_id == "std_fs")
        .count();
    let violated_count = findings
        .iter()
        .filter(|f| !f.exempted && f.pattern_id == "std_fs")
        .count();
    assert_eq!(exempted_count, 1);
    assert!(violated_count >= 1);
}

// ---------------------------------------------------------------------------
// Enrichment: audit_all — edge cases
// ---------------------------------------------------------------------------

#[test]
fn audit_all_empty_sources_passes() {
    let auditor = standard_auditor();
    let sources = BTreeMap::new();
    let result = auditor.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert_eq!(result.exemption_count, 0);
    assert!(result.modules_audited.is_empty());
    assert!(result.findings.is_empty());
}

#[test]
fn audit_all_counts_exemptions_correctly() {
    let mut exemptions = ExemptionRegistry::new();
    exemptions.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "std_fs".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    exemptions.add(Exemption {
        exemption_id: "e2".to_string(),
        module_path: "m".to_string(),
        pattern_id: "fs_read".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m".to_string(), "f.rs".to_string()),
        "let _ = std::fs::read(\"x\");".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert!(result.exemption_count >= 2);
}

#[test]
fn audit_all_mixed_exempted_and_violated() {
    let mut exemptions = ExemptionRegistry::new();
    exemptions.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m1".to_string(),
        pattern_id: "std_fs".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    exemptions.add(Exemption {
        exemption_id: "e2".to_string(),
        module_path: "m1".to_string(),
        pattern_id: "fs_read".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m1".to_string(), "f1.rs".to_string()),
        "let _ = std::fs::read(\"x\");".to_string(),
    );
    sources.insert(
        ("m2".to_string(), "f2.rs".to_string()),
        "let s = TcpStream::connect(\"x\");".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert!(!result.passed);
    assert!(result.exemption_count >= 2);
    assert!(result.violation_count >= 1);
    assert_eq!(result.modules_audited.len(), 2);
}

#[test]
fn audit_all_same_module_different_files() {
    let auditor = standard_auditor();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("shared::m".to_string(), "a.rs".to_string()),
        "let _ = TcpStream::connect(\"x\");".to_string(),
    );
    sources.insert(
        ("shared::m".to_string(), "b.rs".to_string()),
        "let _ = Command::new(\"ls\");".to_string(),
    );
    let result = auditor.audit_all(&sources);
    // Same module reported once in modules_audited
    assert_eq!(result.modules_audited.len(), 1);
    assert_eq!(result.modules_audited[0], "shared::m");
    assert!(result.violation_count >= 2);
}

#[test]
fn audit_all_modules_sorted_in_output() {
    let auditor = standard_auditor();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("z_mod".to_string(), "z.rs".to_string()),
        "let _ = std::fs::read(\"x\");".to_string(),
    );
    sources.insert(
        ("a_mod".to_string(), "a.rs".to_string()),
        "let s = TcpStream::connect(\"x\");".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert_eq!(result.modules_audited[0], "a_mod");
    assert_eq!(result.modules_audited[1], "z_mod");
}

// ---------------------------------------------------------------------------
// Enrichment: Module scope — exact match
// ---------------------------------------------------------------------------

#[test]
fn scoped_audit_exact_module_match() {
    let mut config = AuditConfig::standard();
    config.audit_module("engine::core");
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());

    // Exact match should be in scope
    let findings = auditor.audit_source(
        "engine::core",
        "src/core.rs",
        "let _ = std::fs::read(\"x\");",
    );
    assert!(!findings.is_empty());

    // Child module should be in scope (prefixed with ::)
    let child_findings = auditor.audit_source(
        "engine::core::sub",
        "src/core/sub.rs",
        "let _ = std::fs::read(\"x\");",
    );
    assert!(!child_findings.is_empty());
}

#[test]
fn scoped_audit_empty_scope_means_everything_in_scope() {
    let config = AuditConfig::standard();
    // No modules added => everything is in scope
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
    let findings = auditor.audit_source(
        "any::module::path",
        "src/any.rs",
        "let _ = std::fs::read(\"x\");",
    );
    assert!(!findings.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: Standard config invariants
// ---------------------------------------------------------------------------

#[test]
fn standard_config_pattern_ids_unique() {
    let config = AuditConfig::standard();
    let ids: std::collections::BTreeSet<_> =
        config.patterns.iter().map(|p| &p.pattern_id).collect();
    assert_eq!(ids.len(), config.patterns.len());
}

#[test]
fn standard_config_no_raw_pointer_category() {
    let config = AuditConfig::standard();
    let cats: std::collections::BTreeSet<_> = config.patterns.iter().map(|p| p.category).collect();
    assert!(!cats.contains(&ForbiddenCallCategory::RawPointerExternalState));
}

#[test]
fn standard_config_all_patterns_have_nonempty_fields() {
    let config = AuditConfig::standard();
    for p in &config.patterns {
        assert!(!p.pattern_id.is_empty(), "pattern_id empty");
        assert!(!p.pattern.is_empty(), "pattern empty");
        assert!(!p.reason.is_empty(), "reason empty");
        assert!(
            !p.suggested_alternative.is_empty(),
            "suggested_alternative empty"
        );
    }
}

#[test]
fn standard_config_audited_modules_empty() {
    let config = AuditConfig::standard();
    assert!(config.audited_modules.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: ForbiddenCallCategory — ordering
// ---------------------------------------------------------------------------

#[test]
fn category_ordering_full_chain() {
    assert!(ForbiddenCallCategory::FileSystem < ForbiddenCallCategory::Network);
    assert!(ForbiddenCallCategory::Network < ForbiddenCallCategory::Process);
    assert!(ForbiddenCallCategory::Process < ForbiddenCallCategory::GlobalMutableState);
    assert!(ForbiddenCallCategory::GlobalMutableState < ForbiddenCallCategory::Environment);
    assert!(ForbiddenCallCategory::Environment < ForbiddenCallCategory::RawPointerExternalState);
    assert!(ForbiddenCallCategory::RawPointerExternalState < ForbiddenCallCategory::DirectTime);
}

// ---------------------------------------------------------------------------
// Enrichment: ForbiddenCallCategory — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn category_display_all_unique() {
    let categories = [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for cat in &categories {
        seen.insert(cat.to_string());
    }
    assert_eq!(seen.len(), 7);
}

// ---------------------------------------------------------------------------
// Enrichment: ForbiddenCallCategory — Copy semantics
// ---------------------------------------------------------------------------

#[test]
fn category_copy_semantics() {
    let original = ForbiddenCallCategory::Network;
    let copied = original;
    assert_eq!(original, copied);
    // Both usable independently
    assert_eq!(original.to_string(), "network");
    assert_eq!(copied.to_string(), "network");
}

// ---------------------------------------------------------------------------
// Enrichment: ForbiddenCallCategory — Hash consistency
// ---------------------------------------------------------------------------

#[test]
fn category_hash_consistent() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    for v in [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ] {
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        v.hash(&mut h1);
        v.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish(), "hash not consistent for {v:?}");
    }
}

// ---------------------------------------------------------------------------
// Enrichment: Serde — variant distinctness
// ---------------------------------------------------------------------------

#[test]
fn category_serde_all_variants_produce_distinct_json() {
    let variants = [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ];
    let mut jsons = std::collections::BTreeSet::new();
    for v in &variants {
        jsons.insert(serde_json::to_string(v).unwrap());
    }
    assert_eq!(jsons.len(), 7);
}

// ---------------------------------------------------------------------------
// Enrichment: ForbiddenPattern serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn forbidden_pattern_serde_roundtrip() {
    let pattern = ForbiddenPattern {
        pattern_id: "test_p".to_string(),
        category: ForbiddenCallCategory::Network,
        pattern: "test_pattern".to_string(),
        reason: "test reason".to_string(),
        suggested_alternative: "use safe api".to_string(),
    };
    let json = serde_json::to_string(&pattern).unwrap();
    let restored: ForbiddenPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(pattern, restored);
}

// ---------------------------------------------------------------------------
// Enrichment: AuditResult with populated findings serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn audit_result_with_findings_serde_roundtrip() {
    let result = AuditResult {
        findings: vec![AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "std::fs::read".to_string(),
            pattern_id: "std_fs".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            file_path: "f.rs".to_string(),
            line: 1,
            source_line: "std::fs::read(\"x\")".to_string(),
            suggested_alternative: "use cap".to_string(),
            exempted: false,
        }],
        violation_count: 1,
        exemption_count: 0,
        modules_audited: vec!["m".to_string()],
        passed: false,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn audit_finding_exempted_true_serde_roundtrip() {
    let f = AuditFinding {
        module_path: "m".to_string(),
        forbidden_api: "api".to_string(),
        pattern_id: "p".to_string(),
        category: ForbiddenCallCategory::DirectTime,
        file_path: "f.rs".to_string(),
        line: 99,
        source_line: "src".to_string(),
        suggested_alternative: "alt".to_string(),
        exempted: true,
    };
    let json = serde_json::to_string(&f).unwrap();
    let restored: AuditFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
    assert!(restored.exempted);
}

// ---------------------------------------------------------------------------
// Enrichment: AuditConfig with custom patterns + modules serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn audit_config_with_modules_and_custom_patterns_serde_roundtrip() {
    let mut config = AuditConfig::standard();
    config.add_pattern(ForbiddenPattern {
        pattern_id: "custom_p".to_string(),
        category: ForbiddenCallCategory::RawPointerExternalState,
        pattern: "raw_ptr_call()".to_string(),
        reason: "unsafe raw pointer".to_string(),
        suggested_alternative: "use safe abstraction".to_string(),
    });
    config.audit_module("engine::raw");
    config.audit_module("engine::io");
    let json = serde_json::to_string(&config).unwrap();
    let restored: AuditConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
    assert_eq!(restored.patterns.len(), 15);
    assert!(restored.audited_modules.contains("engine::raw"));
    assert!(restored.audited_modules.contains("engine::io"));
}

// ---------------------------------------------------------------------------
// Enrichment: ExemptionRegistry multi-entry serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn exemption_registry_multi_entry_serde_roundtrip() {
    let mut reg = ExemptionRegistry::new();
    for i in 0..5u64 {
        reg.add(Exemption {
            exemption_id: format!("e{i}"),
            module_path: format!("m{i}"),
            pattern_id: format!("p{i}"),
            reason: format!("reason {i}"),
            witness: format!("w{i}"),
            line: i as usize,
        });
    }
    let json = serde_json::to_string(&reg).unwrap();
    let restored: ExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, restored);
    assert_eq!(restored.len(), 5);
}

// ---------------------------------------------------------------------------
// Enrichment: JSON field name stability
// ---------------------------------------------------------------------------

#[test]
fn exemption_json_field_names_stable() {
    let ex = Exemption {
        exemption_id: "eid".to_string(),
        module_path: "mp".to_string(),
        pattern_id: "pid".to_string(),
        reason: "r".to_string(),
        witness: "w".to_string(),
        line: 7,
    };
    let json = serde_json::to_string(&ex).unwrap();
    assert!(json.contains("\"exemption_id\""));
    assert!(json.contains("\"module_path\""));
    assert!(json.contains("\"pattern_id\""));
    assert!(json.contains("\"reason\""));
    assert!(json.contains("\"witness\""));
    assert!(json.contains("\"line\""));
}

#[test]
fn audit_finding_json_field_names_stable() {
    let f = AuditFinding {
        module_path: "m".to_string(),
        forbidden_api: "api".to_string(),
        pattern_id: "p".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        file_path: "f.rs".to_string(),
        line: 1,
        source_line: "src".to_string(),
        suggested_alternative: "alt".to_string(),
        exempted: false,
    };
    let json = serde_json::to_string(&f).unwrap();
    assert!(json.contains("\"module_path\""));
    assert!(json.contains("\"forbidden_api\""));
    assert!(json.contains("\"pattern_id\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"file_path\""));
    assert!(json.contains("\"line\""));
    assert!(json.contains("\"source_line\""));
    assert!(json.contains("\"suggested_alternative\""));
    assert!(json.contains("\"exempted\""));
}

#[test]
fn forbidden_pattern_json_field_names_stable() {
    let p = ForbiddenPattern {
        pattern_id: "pid".to_string(),
        category: ForbiddenCallCategory::Network,
        pattern: "pat".to_string(),
        reason: "r".to_string(),
        suggested_alternative: "alt".to_string(),
    };
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("\"pattern_id\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"pattern\""));
    assert!(json.contains("\"reason\""));
    assert!(json.contains("\"suggested_alternative\""));
}

#[test]
fn audit_result_json_field_names_stable() {
    let r = AuditResult {
        findings: vec![],
        violation_count: 3,
        exemption_count: 1,
        modules_audited: vec![],
        passed: false,
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"findings\""));
    assert!(json.contains("\"violation_count\""));
    assert!(json.contains("\"exemption_count\""));
    assert!(json.contains("\"modules_audited\""));
    assert!(json.contains("\"passed\""));
}

// ---------------------------------------------------------------------------
// Enrichment: Debug trait nonempty
// ---------------------------------------------------------------------------

#[test]
fn category_debug_all_nonempty() {
    for v in [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ] {
        assert!(!format!("{v:?}").is_empty());
    }
}

#[test]
fn category_debug_all_distinct() {
    let variants = [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ];
    let mut set = std::collections::BTreeSet::new();
    for v in &variants {
        set.insert(format!("{v:?}"));
    }
    assert_eq!(set.len(), 7);
}

#[test]
fn forbidden_pattern_debug_nonempty() {
    let p = ForbiddenPattern {
        pattern_id: "p1".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        pattern: "std::fs::".to_string(),
        reason: "bad".to_string(),
        suggested_alternative: "use cap".to_string(),
    };
    assert!(!format!("{p:?}").is_empty());
}

#[test]
fn exemption_debug_nonempty() {
    let ex = Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    };
    assert!(!format!("{ex:?}").is_empty());
}

#[test]
fn audit_finding_debug_nonempty() {
    let f = AuditFinding {
        module_path: "m".to_string(),
        forbidden_api: "api".to_string(),
        pattern_id: "p".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        file_path: "f.rs".to_string(),
        line: 1,
        source_line: "src".to_string(),
        suggested_alternative: "alt".to_string(),
        exempted: false,
    };
    assert!(!format!("{f:?}").is_empty());
}

#[test]
fn audit_config_debug_nonempty() {
    let config = AuditConfig::standard();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn audit_result_debug_nonempty() {
    let r = AuditResult {
        findings: vec![],
        violation_count: 0,
        exemption_count: 0,
        modules_audited: vec![],
        passed: true,
    };
    assert!(!format!("{r:?}").is_empty());
}

#[test]
fn exemption_registry_debug_nonempty() {
    let reg = ExemptionRegistry::new();
    assert!(!format!("{reg:?}").is_empty());
}

#[test]
fn source_auditor_debug_nonempty() {
    let auditor = standard_auditor();
    assert!(!format!("{auditor:?}").is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: Clone independence
// ---------------------------------------------------------------------------

#[test]
fn exemption_clone_independence() {
    let original = Exemption {
        exemption_id: "e1".to_string(),
        module_path: "original".to_string(),
        pattern_id: "p1".to_string(),
        reason: "original reason".to_string(),
        witness: "w1".to_string(),
        line: 5,
    };
    let mut cloned = original.clone();
    cloned.module_path = "mutated".to_string();
    assert_eq!(original.module_path, "original");
}

#[test]
fn forbidden_pattern_clone_independence() {
    let original = ForbiddenPattern {
        pattern_id: "p1".to_string(),
        category: ForbiddenCallCategory::Network,
        pattern: "std::net::".to_string(),
        reason: "original".to_string(),
        suggested_alternative: "use cap".to_string(),
    };
    let mut cloned = original.clone();
    cloned.reason = "mutated".to_string();
    assert_eq!(original.reason, "original");
}

#[test]
fn audit_finding_clone_independence() {
    let original = AuditFinding {
        module_path: "m".to_string(),
        forbidden_api: "api".to_string(),
        pattern_id: "p".to_string(),
        category: ForbiddenCallCategory::Process,
        file_path: "f.rs".to_string(),
        line: 1,
        source_line: "src".to_string(),
        suggested_alternative: "alt".to_string(),
        exempted: false,
    };
    let mut cloned = original.clone();
    cloned.exempted = true;
    assert!(!original.exempted);
}

#[test]
fn audit_config_clone_independence() {
    let original = AuditConfig::standard();
    let mut cloned = original.clone();
    cloned.audit_module("extra::module");
    assert!(!original.audited_modules.contains("extra::module"));
}

#[test]
fn audit_result_clone_independence() {
    let original = AuditResult {
        findings: vec![],
        violation_count: 0,
        exemption_count: 0,
        modules_audited: vec!["m".to_string()],
        passed: true,
    };
    let mut cloned = original.clone();
    cloned.passed = false;
    assert!(original.passed);
}

#[test]
fn exemption_registry_clone_independence() {
    let mut original = ExemptionRegistry::new();
    original.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    let mut cloned = original.clone();
    cloned.add(Exemption {
        exemption_id: "e2".to_string(),
        module_path: "m2".to_string(),
        pattern_id: "p2".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    assert_eq!(original.len(), 1);
    assert_eq!(cloned.len(), 2);
}

// ---------------------------------------------------------------------------
// Enrichment: Equality and Ordering
// ---------------------------------------------------------------------------

#[test]
fn audit_finding_equality_and_inequality() {
    let f1 = AuditFinding {
        module_path: "m".to_string(),
        forbidden_api: "api".to_string(),
        pattern_id: "p".to_string(),
        category: ForbiddenCallCategory::Network,
        file_path: "f.rs".to_string(),
        line: 1,
        source_line: "src".to_string(),
        suggested_alternative: "alt".to_string(),
        exempted: false,
    };
    let f2 = f1.clone();
    let mut f3 = f1.clone();
    f3.line = 2;
    assert_eq!(f1, f2);
    assert_ne!(f1, f3);
}

#[test]
fn audit_finding_ordering_by_module_then_api() {
    let f1 = AuditFinding {
        module_path: "a::b".to_string(),
        forbidden_api: "A_api".to_string(),
        pattern_id: "p1".to_string(),
        category: ForbiddenCallCategory::Network,
        file_path: "a.rs".to_string(),
        line: 1,
        source_line: "line1".to_string(),
        suggested_alternative: "alt".to_string(),
        exempted: false,
    };
    let f2 = AuditFinding {
        module_path: "a::b".to_string(),
        forbidden_api: "B_api".to_string(),
        pattern_id: "p2".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        file_path: "a.rs".to_string(),
        line: 2,
        source_line: "line2".to_string(),
        suggested_alternative: "alt".to_string(),
        exempted: false,
    };
    assert!(f1 < f2);
    assert_eq!(f1.cmp(&f1), std::cmp::Ordering::Equal);
}

#[test]
fn forbidden_pattern_equality() {
    let p1 = ForbiddenPattern {
        pattern_id: "p".to_string(),
        category: ForbiddenCallCategory::DirectTime,
        pattern: "SystemTime::now".to_string(),
        reason: "bad".to_string(),
        suggested_alternative: "good".to_string(),
    };
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

#[test]
fn forbidden_pattern_ordering() {
    let p1 = ForbiddenPattern {
        pattern_id: "a_pattern".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        pattern: "std::fs::".to_string(),
        reason: "bad".to_string(),
        suggested_alternative: "good".to_string(),
    };
    let p2 = ForbiddenPattern {
        pattern_id: "b_pattern".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        pattern: "std::fs::".to_string(),
        reason: "bad".to_string(),
        suggested_alternative: "good".to_string(),
    };
    assert!(p1 < p2);
}

#[test]
fn exemption_equality() {
    let e1 = Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 5,
    };
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

#[test]
fn exemption_ordering() {
    let e1 = Exemption {
        exemption_id: "a_exempt".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 1,
    };
    let e2 = Exemption {
        exemption_id: "b_exempt".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 1,
    };
    assert!(e1 < e2);
}

// ---------------------------------------------------------------------------
// Enrichment: Finding suggested_alternative always nonempty for std patterns
// ---------------------------------------------------------------------------

#[test]
fn all_standard_pattern_findings_have_suggested_alternative() {
    let auditor = standard_auditor();
    let source = concat!(
        "let _ = std::fs::read(\"x\");\n",
        "let _ = fs::read(\"x\");\n",
        "let _ = fs::write(\"x\", b\"\");\n",
        "let _ = std::net::TcpStream::connect(\"x\");\n",
        "let _ = TcpStream::connect(\"x\");\n",
        "let _ = UdpSocket::bind(\"x\");\n",
        "let _ = std::process::Command::new(\"x\");\n",
        "let _ = Command::new(\"x\");\n",
        "let _ = std::env::var(\"x\");\n",
        "let _ = env::var(\"x\");\n",
        "static mut G: u32 = 0;\n",
        "let t = SystemTime::now();\n",
    );
    let findings = auditor.audit_source("m", "f.rs", source);
    for f in &findings {
        assert!(
            !f.suggested_alternative.is_empty(),
            "empty suggested_alternative for pattern_id={}",
            f.pattern_id
        );
    }
}

// ---------------------------------------------------------------------------
// Enrichment: Audit finding preserves file_path and module_path
// ---------------------------------------------------------------------------

#[test]
fn finding_preserves_paths() {
    let auditor = standard_auditor();
    let source = "let _ = std::fs::read(\"x\");";
    let findings = auditor.audit_source(
        "engine::deep::nested::module",
        "src/deep/nested/module.rs",
        source,
    );
    for f in &findings {
        assert_eq!(f.module_path, "engine::deep::nested::module");
        assert_eq!(f.file_path, "src/deep/nested/module.rs");
    }
}

// ---------------------------------------------------------------------------
// Enrichment: Comments with various prefixes are all skipped
// ---------------------------------------------------------------------------

#[test]
fn triple_slash_comments_skipped() {
    let auditor = standard_auditor();
    let source = "/// Example: std::fs::read(\"x\")";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.is_empty());
}

#[test]
fn inner_doc_comments_skipped() {
    let auditor = standard_auditor();
    let source = "//! Module docs: std::process::Command";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.is_empty());
}

#[test]
fn inline_comment_at_end_of_code_is_not_a_comment_line() {
    let auditor = standard_auditor();
    // The line starts with real code, not a comment — should be flagged
    let source = "let _ = std::fs::read(\"x\"); // read file";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(!findings.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: Duplicate exemptions
// ---------------------------------------------------------------------------

#[test]
fn duplicate_exemptions_both_counted() {
    let mut reg = ExemptionRegistry::new();
    let ex = Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    };
    reg.add(ex.clone());
    reg.add(ex);
    assert_eq!(reg.len(), 2);
    assert!(reg.is_exempted("m", "p", 1));
}

// ---------------------------------------------------------------------------
// Enrichment: Auditor with exemptions — accessors
// ---------------------------------------------------------------------------

#[test]
fn auditor_with_exemptions_accessors() {
    let mut exemptions = ExemptionRegistry::new();
    exemptions.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "p".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    let config = AuditConfig::standard();
    let auditor = SourceAuditor::new(config.clone(), exemptions);
    assert_eq!(auditor.config().patterns.len(), config.patterns.len());
    assert_eq!(auditor.exemptions().len(), 1);
    assert!(!auditor.exemptions().is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: audit_all with only exempted findings passes
// ---------------------------------------------------------------------------

#[test]
fn audit_all_fully_exempted_passes() {
    let mut exemptions = ExemptionRegistry::new();
    exemptions.add(Exemption {
        exemption_id: "e1".to_string(),
        module_path: "m".to_string(),
        pattern_id: "tcp_stream".to_string(),
        reason: "ok".to_string(),
        witness: "w".to_string(),
        line: 0,
    });
    let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
    let mut sources = BTreeMap::new();
    sources.insert(
        ("m".to_string(), "f.rs".to_string()),
        "let s = TcpStream::connect(\"x\");".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
    assert!(result.exemption_count >= 1);
    assert!(!result.findings.is_empty());
    assert!(result.findings.iter().all(|f| f.exempted));
}

// ---------------------------------------------------------------------------
// Enrichment: Multiple scoped modules
// ---------------------------------------------------------------------------

#[test]
fn scoped_audit_multiple_modules_in_scope() {
    let mut config = AuditConfig::standard();
    config.audit_module("engine::a");
    config.audit_module("engine::b");
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());

    let fa = auditor.audit_source("engine::a", "a.rs", "let _ = std::fs::read(\"x\");");
    let fb = auditor.audit_source("engine::b", "b.rs", "let _ = std::fs::read(\"x\");");
    let fc = auditor.audit_source("engine::c", "c.rs", "let _ = std::fs::read(\"x\");");

    assert!(!fa.is_empty());
    assert!(!fb.is_empty());
    assert!(fc.is_empty()); // engine::c not in scope
}

// ---------------------------------------------------------------------------
// Enrichment: Pattern on last line of multiline source
// ---------------------------------------------------------------------------

#[test]
fn finding_on_last_line_of_multiline() {
    let auditor = standard_auditor();
    let source = "fn ok() {}\nfn also_ok() {}\nlet _ = TcpStream::connect(\"x\");";
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.line == 3));
}

// ---------------------------------------------------------------------------
// Enrichment: Many violations in single file
// ---------------------------------------------------------------------------

#[test]
fn many_violations_single_file() {
    let auditor = standard_auditor();
    let mut lines = Vec::new();
    for i in 0..20 {
        lines.push(format!("let _ = std::fs::read(\"file_{i}\");"));
    }
    let source = lines.join("\n");
    let findings = auditor.audit_source("m", "f.rs", &source);
    // Each line should produce at least 2 findings (std_fs and fs_read)
    assert!(findings.len() >= 40);
}

// ---------------------------------------------------------------------------
// Enrichment: audit_all with many modules
// ---------------------------------------------------------------------------

#[test]
fn audit_all_ten_modules() {
    let auditor = standard_auditor();
    let mut sources = BTreeMap::new();
    for i in 0..10 {
        sources.insert(
            (format!("mod_{i}"), format!("f{i}.rs")),
            "fn clean() {}".to_string(),
        );
    }
    let result = auditor.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.modules_audited.len(), 10);
    assert_eq!(result.violation_count, 0);
}

// ---------------------------------------------------------------------------
// Enrichment: ExemptionRegistry new equals default
// ---------------------------------------------------------------------------

#[test]
fn exemption_registry_new_equals_default() {
    let new = ExemptionRegistry::new();
    let default = ExemptionRegistry::default();
    assert_eq!(new, default);
}

// ---------------------------------------------------------------------------
// Enrichment: AuditConfig — audit_module dedup
// ---------------------------------------------------------------------------

#[test]
fn audit_module_dedup_via_btreeset() {
    let mut config = AuditConfig::standard();
    config.audit_module("engine::core");
    config.audit_module("engine::core");
    assert_eq!(config.audited_modules.len(), 1);
}

// ---------------------------------------------------------------------------
// Enrichment: AuditResult — passed field consistency
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// New forbidden patterns: File:: and OpenOptions::
// ---------------------------------------------------------------------------

#[test]
fn detects_file_open_pattern() {
    let auditor = standard_auditor();
    let source = r#"let f = File::open("data.txt").unwrap();"#;
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings.iter().any(|f| f.pattern_id == "file_open"),
        "should detect File:: usage as forbidden ambient authority"
    );
}

#[test]
fn detects_file_create_pattern() {
    let auditor = standard_auditor();
    let source = r#"let f = File::create("output.txt").unwrap();"#;
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings.iter().any(|f| f.pattern_id == "file_open"),
        "should detect File::create as forbidden ambient authority"
    );
}

#[test]
fn detects_open_options_pattern() {
    let auditor = standard_auditor();
    let source = r#"OpenOptions::new().read(true).open("config.toml")"#;
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(
        findings.iter().any(|f| f.pattern_id == "open_options"),
        "should detect OpenOptions:: usage as forbidden ambient authority"
    );
}

#[test]
fn file_open_finding_has_correct_category() {
    let auditor = standard_auditor();
    let source = r#"let f = File::open("data.txt");"#;
    let findings = auditor.audit_source("m", "f.rs", source);
    let file_finding = findings
        .iter()
        .find(|f| f.pattern_id == "file_open")
        .expect("should find file_open violation");
    assert_eq!(file_finding.category, ForbiddenCallCategory::FileSystem);
}

#[test]
fn open_options_finding_has_correct_category() {
    let auditor = standard_auditor();
    let source = r#"OpenOptions::new().write(true).open("out.txt")"#;
    let findings = auditor.audit_source("m", "f.rs", source);
    let oo_finding = findings
        .iter()
        .find(|f| f.pattern_id == "open_options")
        .expect("should find open_options violation");
    assert_eq!(oo_finding.category, ForbiddenCallCategory::FileSystem);
}

#[test]
fn file_and_open_options_both_detected_in_same_source() {
    let auditor = standard_auditor();
    let source = r#"
        let a = File::open("input.txt").unwrap();
        let b = OpenOptions::new().append(true).open("log.txt").unwrap();
    "#;
    let findings = auditor.audit_source("m", "f.rs", source);
    assert!(findings.iter().any(|f| f.pattern_id == "file_open"));
    assert!(findings.iter().any(|f| f.pattern_id == "open_options"));
}

#[test]
fn file_pattern_exemption_marks_finding_as_exempted() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "exempt-file-open".to_string(),
        module_path: "m".to_string(),
        pattern_id: "file_open".to_string(),
        reason: "legacy code".to_string(),
        witness: "reviewer-signed".to_string(),
        line: 0,
    });
    let auditor = SourceAuditor::new(AuditConfig::standard(), reg);
    let source = r#"let f = File::open("data.txt");"#;
    let findings = auditor.audit_source("m", "f.rs", source);
    let file_finding = findings
        .iter()
        .find(|f| f.pattern_id == "file_open")
        .expect("file_open finding should still be present in findings");
    assert!(
        file_finding.exempted,
        "file_open finding should be marked as exempted"
    );
}

#[test]
fn audit_result_passed_consistency() {
    let auditor = standard_auditor();

    // No violations => passed = true
    let mut clean = BTreeMap::new();
    clean.insert(
        ("m".to_string(), "f.rs".to_string()),
        "fn ok() {}".to_string(),
    );
    let r1 = auditor.audit_all(&clean);
    assert!(r1.passed);
    assert_eq!(r1.violation_count, 0);

    // Has violations => passed = false
    let mut dirty = BTreeMap::new();
    dirty.insert(
        ("m".to_string(), "f.rs".to_string()),
        "let _ = std::fs::read(\"x\");".to_string(),
    );
    let r2 = auditor.audit_all(&dirty);
    assert!(!r2.passed);
    assert!(r2.violation_count >= 1);
}
