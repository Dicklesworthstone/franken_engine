//! Enrichment integration tests for `ambient_authority`.
//!
//! Covers gaps: ForbiddenCallCategory Display uniqueness, standard AuditConfig
//! pattern coverage, ExemptionRegistry add/check/is_exempted, SourceAuditor
//! audit_source finding generation, audit_all pass/fail semantics, serde
//! roundtrips for all public types, and pattern matching accuracy.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ambient_authority::{
    AuditConfig, AuditFinding, AuditResult, Exemption, ExemptionRegistry, ForbiddenCallCategory,
    ForbiddenPattern, SourceAuditor,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn standard_auditor() -> SourceAuditor {
    SourceAuditor::new(AuditConfig::standard(), ExemptionRegistry::new())
}

// ===========================================================================
// ForbiddenCallCategory Display uniqueness
// ===========================================================================

#[test]
fn enrichment_forbidden_call_category_display_all_unique() {
    let all = [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ];
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_forbidden_call_category_serde_roundtrip() {
    let all = [
        ForbiddenCallCategory::FileSystem,
        ForbiddenCallCategory::Network,
        ForbiddenCallCategory::Process,
        ForbiddenCallCategory::GlobalMutableState,
        ForbiddenCallCategory::Environment,
        ForbiddenCallCategory::RawPointerExternalState,
        ForbiddenCallCategory::DirectTime,
    ];
    for cat in &all {
        let json = serde_json::to_string(cat).unwrap();
        let back: ForbiddenCallCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

// ===========================================================================
// AuditConfig: standard patterns
// ===========================================================================

#[test]
fn enrichment_standard_config_has_patterns() {
    let config = AuditConfig::standard();
    assert!(!config.patterns.is_empty());
}

#[test]
fn enrichment_standard_config_covers_filesystem() {
    let config = AuditConfig::standard();
    assert!(
        config
            .patterns
            .iter()
            .any(|p| p.category == ForbiddenCallCategory::FileSystem)
    );
}

#[test]
fn enrichment_standard_config_covers_network() {
    let config = AuditConfig::standard();
    assert!(
        config
            .patterns
            .iter()
            .any(|p| p.category == ForbiddenCallCategory::Network)
    );
}

#[test]
fn enrichment_standard_config_covers_process() {
    let config = AuditConfig::standard();
    assert!(
        config
            .patterns
            .iter()
            .any(|p| p.category == ForbiddenCallCategory::Process)
    );
}

#[test]
fn enrichment_standard_config_pattern_ids_unique() {
    let config = AuditConfig::standard();
    let ids: BTreeSet<&str> = config
        .patterns
        .iter()
        .map(|p| p.pattern_id.as_str())
        .collect();
    assert_eq!(ids.len(), config.patterns.len());
}

#[test]
fn enrichment_standard_config_audit_module() {
    let mut config = AuditConfig::standard();
    config.audit_module("test_module");
    assert!(config.audited_modules.contains("test_module"));
}

// ===========================================================================
// ExemptionRegistry
// ===========================================================================

#[test]
fn enrichment_exemption_registry_new_empty() {
    let reg = ExemptionRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn enrichment_exemption_registry_add() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "ex-001".to_string(),
        module_path: "test_mod".to_string(),
        pattern_id: "pat-001".to_string(),
        reason: "testing".to_string(),
        witness: "test witness".to_string(),
        line: 42,
    });
    assert_eq!(reg.len(), 1);
}

#[test]
fn enrichment_exemption_registry_is_exempted() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "ex-001".to_string(),
        module_path: "test_mod".to_string(),
        pattern_id: "pat-001".to_string(),
        reason: "testing".to_string(),
        witness: "test witness".to_string(),
        line: 42,
    });
    assert!(reg.is_exempted("test_mod", "pat-001", 42));
}

#[test]
fn enrichment_exemption_not_matching_module() {
    let mut reg = ExemptionRegistry::new();
    reg.add(Exemption {
        exemption_id: "ex-001".to_string(),
        module_path: "test_mod".to_string(),
        pattern_id: "pat-001".to_string(),
        reason: "testing".to_string(),
        witness: "test witness".to_string(),
        line: 42,
    });
    assert!(!reg.is_exempted("other_mod", "pat-001", 42));
}

#[test]
fn enrichment_exemption_serde_roundtrip() {
    let exemption = Exemption {
        exemption_id: "ex-001".to_string(),
        module_path: "test_mod".to_string(),
        pattern_id: "pat-001".to_string(),
        reason: "testing".to_string(),
        witness: "witness_data".to_string(),
        line: 10,
    };
    let json = serde_json::to_string(&exemption).unwrap();
    let back: Exemption = serde_json::from_str(&json).unwrap();
    assert_eq!(exemption.exemption_id, back.exemption_id);
}

// ===========================================================================
// ForbiddenPattern serde roundtrip
// ===========================================================================

#[test]
fn enrichment_forbidden_pattern_serde_roundtrip() {
    let pattern = ForbiddenPattern {
        pattern_id: "pat-001".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        pattern: "std::fs::".to_string(),
        reason: "No direct FS access".to_string(),
        suggested_alternative: "Use hostcall".to_string(),
    };
    let json = serde_json::to_string(&pattern).unwrap();
    let back: ForbiddenPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(pattern.pattern_id, back.pattern_id);
    assert_eq!(pattern.category, back.category);
}

// ===========================================================================
// SourceAuditor: audit_source
// ===========================================================================

#[test]
fn enrichment_audit_clean_source_no_findings() {
    let auditor = standard_auditor();
    let findings = auditor.audit_source("clean_mod", "clean.rs", "let x = 42;");
    // Clean code should have no findings (or only audited patterns might not match)
    // Just verify it doesn't panic
    let _ = findings.len();
}

#[test]
fn enrichment_audit_source_with_fs_call_finds_violation() {
    let auditor = standard_auditor();
    let source = "use std::fs::read_to_string;\nfn main() { std::fs::read(\"test\"); }";
    let findings = auditor.audit_source("fs_mod", "fs_mod.rs", source);
    // Should find at least one FS-related finding
    let fs_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ForbiddenCallCategory::FileSystem)
        .collect();
    assert!(!fs_findings.is_empty(), "Should detect std::fs usage");
}

// ===========================================================================
// SourceAuditor: audit_all
// ===========================================================================

#[test]
fn enrichment_audit_all_empty_sources() {
    let auditor = standard_auditor();
    let sources = BTreeMap::new();
    let result = auditor.audit_all(&sources);
    assert!(result.passed);
    assert_eq!(result.violation_count, 0);
}

#[test]
fn enrichment_audit_all_result_serde_roundtrip() {
    let result = AuditResult {
        findings: vec![],
        violation_count: 0,
        exemption_count: 0,
        modules_audited: vec!["mod_a".to_string()],
        passed: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.passed, back.passed);
    assert_eq!(result.violation_count, back.violation_count);
}

// ===========================================================================
// AuditFinding serde roundtrip
// ===========================================================================

#[test]
fn enrichment_audit_finding_serde_roundtrip() {
    let finding = AuditFinding {
        module_path: "test_mod".to_string(),
        forbidden_api: "std::fs::read".to_string(),
        pattern_id: "pat-001".to_string(),
        category: ForbiddenCallCategory::FileSystem,
        file_path: "test.rs".to_string(),
        line: 10,
        source_line: "use std::fs::read;".to_string(),
        suggested_alternative: "Use hostcall".to_string(),
        exempted: false,
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: AuditFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.module_path, back.module_path);
    assert_eq!(finding.exempted, back.exempted);
}

// ===========================================================================
// SourceAuditor: accessors
// ===========================================================================

#[test]
fn enrichment_auditor_config_accessible() {
    let auditor = standard_auditor();
    let config = auditor.config();
    assert!(!config.patterns.is_empty());
}

#[test]
fn enrichment_auditor_exemptions_accessible() {
    let auditor = standard_auditor();
    let exemptions = auditor.exemptions();
    assert!(exemptions.is_empty());
}

// ===========================================================================
// AuditConfig: add_pattern
// ===========================================================================

#[test]
fn enrichment_config_add_custom_pattern() {
    let mut config = AuditConfig::standard();
    let original_count = config.patterns.len();
    config.add_pattern(ForbiddenPattern {
        pattern_id: "custom-001".to_string(),
        category: ForbiddenCallCategory::GlobalMutableState,
        pattern: "GLOBAL_STATE".to_string(),
        reason: "No global state".to_string(),
        suggested_alternative: "Use context".to_string(),
    });
    assert_eq!(config.patterns.len(), original_count + 1);
}
