//! Integration tests for the `ambient_authority` module.
//!
//! Tests the compile-time ambient-authority audit gate: forbidden pattern
//! detection, exemption registry, multi-file audit, and serde roundtrips.

#![forbid(unsafe_code)]

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
fn standard_config_has_twelve_patterns() {
    let config = AuditConfig::standard();
    assert_eq!(config.patterns.len(), 12);
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
    assert_eq!(auditor.config().patterns.len(), 12);
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
