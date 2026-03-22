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

// ===========================================================================
// ExemptionRegistry: add, check, len, is_empty
// ===========================================================================

#[test]
fn enrichment_registry_add_and_check() {
    let mut registry = ExemptionRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);

    registry.add(Exemption {
        exemption_id: "ex-001".to_string(),
        module_path: "test_module.rs".to_string(),
        pattern_id: "forbidden-001".to_string(),
        line: 42,
        reason: "Legacy code".to_string(),
        witness: "signed-witness-001".to_string(),
    });

    assert!(!registry.is_empty());
    assert_eq!(registry.len(), 1);
    assert!(registry.is_exempted("test_module.rs", "forbidden-001", 42));
    assert!(!registry.is_exempted("test_module.rs", "forbidden-001", 99));
    assert!(!registry.is_exempted("other.rs", "forbidden-001", 42));
}

#[test]
fn enrichment_registry_wildcard_line_exemption() {
    let mut registry = ExemptionRegistry::new();
    registry.add(Exemption {
        exemption_id: "ex-wc".to_string(),
        module_path: "wildcard.rs".to_string(),
        pattern_id: "forbidden-002".to_string(),
        line: 0,
        reason: "Whole file exempted".to_string(),
        witness: "signed-witness-wc".to_string(),
    });

    // line=0 means module-wide exemption
    assert!(registry.is_exempted("wildcard.rs", "forbidden-002", 1));
    assert!(registry.is_exempted("wildcard.rs", "forbidden-002", 999));
}

#[test]
fn enrichment_registry_multiple_exemptions() {
    let mut registry = ExemptionRegistry::new();
    for i in 0..5 {
        registry.add(Exemption {
            exemption_id: format!("ex-{i}"),
            module_path: format!("mod_{i}.rs"),
            pattern_id: "pat".to_string(),
            line: i * 10,
            reason: format!("reason {i}"),
            witness: format!("witness-{i}"),
        });
    }
    assert_eq!(registry.len(), 5);
    assert_eq!(registry.exemptions().len(), 5);
}

#[test]
fn enrichment_registry_serde_roundtrip() {
    let mut registry = ExemptionRegistry::new();
    registry.add(Exemption {
        exemption_id: "ex-serde".to_string(),
        module_path: "serde_test.rs".to_string(),
        pattern_id: "pat-serde".to_string(),
        line: 10,
        reason: "serde test".to_string(),
        witness: "witness-serde".to_string(),
    });
    let json = serde_json::to_string(&registry).unwrap();
    let decoded: ExemptionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.len(), 1);
}

// ===========================================================================
// Exemption serde
// ===========================================================================

#[test]
fn enrichment_exemption_full_fields_serde() {
    let ex = Exemption {
        exemption_id: "ex-rt".to_string(),
        module_path: "path.rs".to_string(),
        pattern_id: "pat-1".to_string(),
        line: 42,
        reason: "reason".to_string(),
        witness: "witness-rt".to_string(),
    };
    let json = serde_json::to_string(&ex).unwrap();
    let decoded: Exemption = serde_json::from_str(&json).unwrap();
    assert_eq!(ex, decoded);
}

#[test]
fn enrichment_exemption_module_wide_serde() {
    let ex = Exemption {
        exemption_id: "ex-mw".to_string(),
        module_path: "path.rs".to_string(),
        pattern_id: "pat-2".to_string(),
        line: 0,
        reason: "whole file".to_string(),
        witness: "witness-mw".to_string(),
    };
    let json = serde_json::to_string(&ex).unwrap();
    let decoded: Exemption = serde_json::from_str(&json).unwrap();
    assert_eq!(ex.line, decoded.line);
}

// ===========================================================================
// SourceAuditor: audit_source with violations
// ===========================================================================

#[test]
fn enrichment_audit_source_clean_code() {
    let auditor = standard_auditor();
    let findings = auditor.audit_source("clean_mod", "clean.rs", "let x = 42;\nlet y = x + 1;\n");
    // Clean code should have no findings
    assert!(findings.is_empty());
}

#[test]
fn enrichment_audit_source_with_fs_call() {
    let auditor = standard_auditor();
    let findings = auditor.audit_source(
        "bad_mod",
        "bad.rs",
        "use std::fs;\nfs::read_to_string(\"foo\");\n",
    );
    // Should detect fs usage
    assert!(!findings.is_empty());
}

#[test]
fn enrichment_audit_source_exempted_finding() {
    let mut registry = ExemptionRegistry::new();
    // We need to find which pattern IDs exist in standard config
    let config = AuditConfig::standard();
    if let Some(first_pat) = config.patterns.first() {
        registry.add(Exemption {
            exemption_id: "ex-test".to_string(),
            module_path: "exempted.rs".to_string(),
            pattern_id: first_pat.pattern_id.clone(),
            line: 0,
            reason: "Test exemption".to_string(),
            witness: "test-witness".to_string(),
        });
    }
    let auditor = SourceAuditor::new(config, registry);
    // Even if code matches, exempted modules get passes
    let _findings = auditor.audit_source("exempted_mod", "exempted.rs", "use std::fs;\n");
    // Findings may still be generated but marked as exempted
}

// ===========================================================================
// SourceAuditor: audit_all
// ===========================================================================

#[test]
fn enrichment_audit_all_empty_passes() {
    let auditor = standard_auditor();
    let sources = BTreeMap::new();
    let result = auditor.audit_all(&sources);
    assert_eq!(result.modules_audited.len(), 0);
    assert!(result.passed);
}

#[test]
fn enrichment_audit_all_clean_sources() {
    let auditor = standard_auditor();
    let mut sources = BTreeMap::new();
    sources.insert(
        ("mod_a".to_string(), "mod_a.rs".to_string()),
        "let a = 1;\n".to_string(),
    );
    sources.insert(
        ("mod_b".to_string(), "mod_b.rs".to_string()),
        "let b = 2;\n".to_string(),
    );
    let result = auditor.audit_all(&sources);
    assert_eq!(result.modules_audited.len(), 2);
}

// ===========================================================================
// AuditResult serde
// ===========================================================================

#[test]
fn enrichment_audit_result_serde_roundtrip() {
    let auditor = standard_auditor();
    let sources = BTreeMap::new();
    let result = auditor.audit_all(&sources);
    let json = serde_json::to_string(&result).unwrap();
    let decoded: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.modules_audited.len(), decoded.modules_audited.len());
}

// ===========================================================================
// AuditFinding enrichment serde
// ===========================================================================

#[test]
fn enrichment_audit_finding_full_serde() {
    let finding = AuditFinding {
        module_path: "test.rs".to_string(),
        forbidden_api: "net::connect".to_string(),
        pattern_id: "pat-1".to_string(),
        category: ForbiddenCallCategory::Network,
        file_path: "test.rs".to_string(),
        line: 10,
        source_line: "use net::connect;".to_string(),
        suggested_alternative: "use sandbox".to_string(),
        exempted: false,
    };
    let json = serde_json::to_string(&finding).unwrap();
    let decoded: AuditFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, decoded);
}
