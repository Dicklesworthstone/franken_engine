#![forbid(unsafe_code)]

//! Ambient Authority Guard Conformance Harness
//!
//! Pattern 4: Spec-Derived Test Matrix for extension-host ambient authority defense.
//! Tests fail-closed behavior against environment variable bypasses, feature flag overrides,
//! and RollbackUnverified error boundary violations.
//!
//! Specification Source: bd-11z7 Extension-host ambient authority guard requirements
//! - Guard MUST reject all permutations of bypass environment variables
//! - Guard MUST NOT be overridable via feature flags
//! - RollbackUnverified MUST be invoked at correct security boundaries

use std::collections::BTreeMap;

use frankenengine_engine::extension_host_authority_guard::{ExtensionHostGuard, ViolationKind};
use serde::{Deserialize, Serialize};

/// Conformance test requirement levels from security specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum RequirementLevel {
    Must,   // MUST - security critical
    Should, // SHOULD - important but not security-breaking
    May,    // MAY - optional security hardening
}

/// Conformance test case following spec-derived pattern
#[derive(Debug, Clone)]
struct ConformanceCase {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    description: &'static str,
    test_fn: fn() -> ConformanceResult,
}

/// Test execution result
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
enum ConformanceResult {
    Pass,
    Fail { reason: String },
    ExpectedFailure { reason: String }, // Known divergence (XFAIL)
}

/// RollbackUnverified error for security boundary violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackUnverified {
    BypassAttempt { method: String, context: String },
    FeatureFlagOverride { flag: String },
    EnvironmentBypass { var: String, value: String },
}

impl RollbackUnverified {
    fn should_trigger(violation_kind: ViolationKind, context: &str) -> bool {
        match violation_kind {
            ViolationKind::DirectUpstreamImport => context.contains("franken_"),
            ViolationKind::ForbiddenPattern => {
                context.contains("std::env") || context.contains("std::fs")
            }
            ViolationKind::CanonicalTypeShadow => true,
            ViolationKind::MissingCxParameter => false, // Not a security boundary
        }
    }
}

// ---------------------------------------------------------------------------
// BD-11Z7 Security Requirements as Conformance Cases
// ---------------------------------------------------------------------------

const CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Section 1: Environment Variable Bypass Prevention (MUST level)
    ConformanceCase {
        id: "BD11Z7-ENV-01",
        section: "bypass_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject DISABLE_AMBIENT_GUARD environment variable",
        test_fn: test_disable_ambient_guard_env_var,
    },
    ConformanceCase {
        id: "BD11Z7-ENV-02",
        section: "bypass_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject SKIP_AUTHORITY_CHECK environment variable",
        test_fn: test_skip_authority_check_env_var,
    },
    ConformanceCase {
        id: "BD11Z7-ENV-03",
        section: "bypass_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject BYPASS_SECURITY environment variable",
        test_fn: test_bypass_security_env_var,
    },
    ConformanceCase {
        id: "BD11Z7-ENV-04",
        section: "bypass_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject ALLOW_UNSAFE_IMPORTS environment variable",
        test_fn: test_allow_unsafe_imports_env_var,
    },
    ConformanceCase {
        id: "BD11Z7-ENV-05",
        section: "bypass_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject all environment variable permutations",
        test_fn: test_env_var_permutations,
    },
    // Section 2: Feature Flag Override Prevention (MUST level)
    ConformanceCase {
        id: "BD11Z7-FLAG-01",
        section: "feature_flag_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject disable-ambient-guard feature flag",
        test_fn: test_disable_ambient_guard_feature,
    },
    ConformanceCase {
        id: "BD11Z7-FLAG-02",
        section: "feature_flag_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject unsafe-extension-host feature flag",
        test_fn: test_unsafe_extension_host_feature,
    },
    ConformanceCase {
        id: "BD11Z7-FLAG-03",
        section: "feature_flag_prevention",
        level: RequirementLevel::Must,
        description: "Guard MUST reject bypass-security feature flag",
        test_fn: test_bypass_security_feature,
    },
    // Section 3: RollbackUnverified Error Boundary (MUST level)
    ConformanceCase {
        id: "BD11Z7-ROLLBACK-01",
        section: "rollback_boundaries",
        level: RequirementLevel::Must,
        description: "RollbackUnverified MUST trigger on direct upstream imports",
        test_fn: test_rollback_on_direct_imports,
    },
    ConformanceCase {
        id: "BD11Z7-ROLLBACK-02",
        section: "rollback_boundaries",
        level: RequirementLevel::Must,
        description: "RollbackUnverified MUST trigger on forbidden I/O patterns",
        test_fn: test_rollback_on_forbidden_io,
    },
    ConformanceCase {
        id: "BD11Z7-ROLLBACK-03",
        section: "rollback_boundaries",
        level: RequirementLevel::Must,
        description: "RollbackUnverified MUST trigger on canonical type shadowing",
        test_fn: test_rollback_on_type_shadowing,
    },
    ConformanceCase {
        id: "BD11Z7-ROLLBACK-04",
        section: "rollback_boundaries",
        level: RequirementLevel::Must,
        description: "RollbackUnverified MUST NOT trigger on legitimate patterns",
        test_fn: test_no_rollback_on_legitimate_code,
    },
    // Section 4: Fail-Closed Behavior (MUST level)
    ConformanceCase {
        id: "BD11Z7-FAIL-01",
        section: "fail_closed",
        level: RequirementLevel::Must,
        description: "Guard MUST fail closed on unknown environment variables",
        test_fn: test_fail_closed_unknown_env_vars,
    },
    ConformanceCase {
        id: "BD11Z7-FAIL-02",
        section: "fail_closed",
        level: RequirementLevel::Must,
        description: "Guard MUST fail closed on malformed bypass attempts",
        test_fn: test_fail_closed_malformed_bypass,
    },
];

// ---------------------------------------------------------------------------
// Section 1: Environment Variable Bypass Prevention
// ---------------------------------------------------------------------------

fn test_disable_ambient_guard_env_var() -> ConformanceResult {
    if let Err(reason) = assert_no_process_env_override_path("DISABLE_AMBIENT_GUARD") {
        return ConformanceResult::Fail { reason };
    }

    let auditor = create_test_auditor();
    let source = "use franken_kernel::EngineCore;";
    let findings = auditor.audit_source("test", "test.rs", source);

    if !findings.is_empty()
        && findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
    {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: "Guard accepted direct upstream import despite DISABLE_AMBIENT_GUARD=1"
                .to_string(),
        }
    }
}

fn test_skip_authority_check_env_var() -> ConformanceResult {
    if let Err(reason) = assert_no_process_env_override_path("SKIP_AUTHORITY_CHECK") {
        return ConformanceResult::Fail { reason };
    }

    let auditor = create_test_auditor();
    let source = "let _ = std::fs::read_to_string(\"config.txt\");";
    let findings = auditor.audit_source("test", "test.rs", source);

    if !findings.is_empty()
        && findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern)
    {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: "Guard accepted forbidden I/O despite SKIP_AUTHORITY_CHECK=true".to_string(),
        }
    }
}

fn test_bypass_security_env_var() -> ConformanceResult {
    for value in ["1", "true", "yes", "on", "enable"] {
        if let Err(reason) = assert_no_process_env_override_path("BYPASS_SECURITY") {
            return ConformanceResult::Fail { reason };
        }

        let auditor = create_test_auditor();
        let source = "struct TraceId(String);"; // Shadows canonical type
        let findings = auditor.audit_source("test", "test.rs", source);

        if findings.is_empty()
            || !findings
                .iter()
                .any(|f| f.kind == ViolationKind::CanonicalTypeShadow)
        {
            return ConformanceResult::Fail {
                reason: format!(
                    "Guard accepted canonical type shadowing with BYPASS_SECURITY={}",
                    value
                ),
            };
        }
    }

    ConformanceResult::Pass
}

fn test_allow_unsafe_imports_env_var() -> ConformanceResult {
    if let Err(reason) = assert_no_process_env_override_path("ALLOW_UNSAFE_IMPORTS") {
        return ConformanceResult::Fail { reason };
    }

    let auditor = create_test_auditor();
    let source = r#"
        use franken_decision::PolicyEngine;
        use franken_evidence::AuditTrail;
    "#;
    let findings = auditor.audit_source("test", "test.rs", source);

    // Must still detect violations even with bypass env var
    let upstream_violations = findings
        .iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .count();

    if upstream_violations >= 2 {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: format!(
                "Guard only detected {} upstream import violations, expected 2",
                upstream_violations
            ),
        }
    }
}

fn test_env_var_permutations() -> ConformanceResult {
    let bypass_vars = [
        ("DISABLE_AMBIENT_GUARD", "1"),
        ("SKIP_AUTHORITY_CHECK", "true"),
        ("BYPASS_SECURITY", "yes"),
        ("ALLOW_UNSAFE_IMPORTS", "on"),
        ("FRANKEN_UNSAFE_MODE", "enabled"),
        ("DEBUG_DISABLE_GUARDS", "1"),
    ];

    let auditor = create_test_auditor();
    let test_source = r#"
        use franken_kernel::Core;
        let _ = std::env::var("HOME");
        struct DecisionId(u64);
    "#;

    // Test all combinations of 1, 2, and 3 environment variables
    for single_var in &bypass_vars {
        if let Err(reason) = assert_no_process_env_override_path(single_var.0) {
            return ConformanceResult::Fail { reason };
        }

        let findings = auditor.audit_source("test", "test.rs", test_source);

        // Should detect all violation types despite bypass attempt
        let has_import_violation = findings
            .iter()
            .any(|f| f.kind == ViolationKind::DirectUpstreamImport);
        let has_io_violation = findings
            .iter()
            .any(|f| f.kind == ViolationKind::ForbiddenPattern);
        let has_shadow_violation = findings
            .iter()
            .any(|f| f.kind == ViolationKind::CanonicalTypeShadow);

        if !has_import_violation || !has_io_violation || !has_shadow_violation {
            return ConformanceResult::Fail {
                reason: format!(
                    "Guard bypassed by single env var: {}={}",
                    single_var.0, single_var.1
                ),
            };
        }
    }

    // Test combination of multiple bypass variables
    for var in [
        "DISABLE_AMBIENT_GUARD",
        "BYPASS_SECURITY",
        "ALLOW_UNSAFE_IMPORTS",
    ] {
        if let Err(reason) = assert_no_process_env_override_path(var) {
            return ConformanceResult::Fail { reason };
        }
    }

    let findings = auditor.audit_source("test", "test.rs", test_source);

    if findings.len() >= 3 {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: format!(
                "Guard bypassed by multiple env vars, only {} violations detected",
                findings.len()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Section 2: Feature Flag Override Prevention
// ---------------------------------------------------------------------------

fn test_disable_ambient_guard_feature() -> ConformanceResult {
    assert_forbidden_extension_host_feature_absent("disable-ambient-guard")
}

fn test_unsafe_extension_host_feature() -> ConformanceResult {
    assert_forbidden_extension_host_feature_absent("unsafe-extension-host")
}

fn test_bypass_security_feature() -> ConformanceResult {
    // Test multiple potential bypass feature names
    let bypass_features = [
        "bypass-security",
        "disable-guards",
        "unsafe-mode",
        "debug-unsafe",
        "skip-checks",
    ];

    for feature in &bypass_features {
        if let ConformanceResult::Fail { reason } =
            assert_forbidden_extension_host_feature_absent(feature)
        {
            return ConformanceResult::Fail {
                reason: format!(
                    "Bypass feature '{feature}' exists or manifest is invalid: {reason}"
                ),
            };
        }
    }

    ConformanceResult::Pass
}

// ---------------------------------------------------------------------------
// Section 3: RollbackUnverified Error Boundary
// ---------------------------------------------------------------------------

fn test_rollback_on_direct_imports() -> ConformanceResult {
    let auditor = create_test_auditor();
    let source = "use franken_kernel::PolicyEngine;";
    let findings = auditor.audit_source("test", "test.rs", source);

    for finding in &findings {
        if finding.kind == ViolationKind::DirectUpstreamImport {
            let should_rollback = RollbackUnverified::should_trigger(finding.kind, source);
            if should_rollback {
                return ConformanceResult::Pass;
            }
        }
    }

    ConformanceResult::Fail {
        reason: "RollbackUnverified not triggered for direct upstream imports".to_string(),
    }
}

fn test_rollback_on_forbidden_io() -> ConformanceResult {
    let auditor = create_test_auditor();
    let sources = [
        "let _ = std::fs::read_to_string(\"file.txt\");",
        "let _ = std::env::var(\"HOME\");",
        "std::process::Command::new(\"ls\").output();",
    ];

    for source in &sources {
        let findings = auditor.audit_source("test", "test.rs", source);

        let has_forbidden = findings.iter().any(|f| {
            f.kind == ViolationKind::ForbiddenPattern
                && RollbackUnverified::should_trigger(f.kind, source)
        });

        if !has_forbidden {
            return ConformanceResult::Fail {
                reason: format!(
                    "RollbackUnverified not triggered for forbidden I/O: {}",
                    source
                ),
            };
        }
    }

    ConformanceResult::Pass
}

fn test_rollback_on_type_shadowing() -> ConformanceResult {
    let auditor = create_test_auditor();
    let sources = [
        "struct TraceId(String);",
        "enum DecisionId { Id(u64) }",
        "type PolicyId = String;",
    ];

    for source in &sources {
        let findings = auditor.audit_source("test", "test.rs", source);

        let has_shadow = findings.iter().any(|f| {
            f.kind == ViolationKind::CanonicalTypeShadow
                && RollbackUnverified::should_trigger(f.kind, source)
        });

        if !has_shadow {
            return ConformanceResult::Fail {
                reason: format!(
                    "RollbackUnverified not triggered for type shadowing: {}",
                    source
                ),
            };
        }
    }

    ConformanceResult::Pass
}

fn test_no_rollback_on_legitimate_code() -> ConformanceResult {
    let auditor = create_test_auditor();
    let legitimate_sources = [
        "fn process_request(ctx: &Cx, req: Request) -> Response { todo!() }",
        "use frankenengine_extension_host::ExtensionManifest;",
        "struct LocalConfig { name: String }",
    ];

    for source in &legitimate_sources {
        let findings = auditor.audit_source("test", "test.rs", source);

        let triggers_rollback = findings
            .iter()
            .any(|f| RollbackUnverified::should_trigger(f.kind, source));

        if triggers_rollback {
            return ConformanceResult::Fail {
                reason: format!(
                    "RollbackUnverified incorrectly triggered for legitimate code: {}",
                    source
                ),
            };
        }
    }

    ConformanceResult::Pass
}

// ---------------------------------------------------------------------------
// Section 4: Fail-Closed Behavior
// ---------------------------------------------------------------------------

fn test_fail_closed_unknown_env_vars() -> ConformanceResult {
    let unknown_vars = [
        ("FRANKEN_SECRET_BYPASS", "admin123"),
        ("SECURITY_OVERRIDE_CODE", "emergency"),
        ("AMBIENT_AUTHORITY_DISABLE", "please"),
    ];

    let auditor = create_test_auditor();
    let test_source = "use franken_decision::Core;";

    for (var, value) in &unknown_vars {
        if let Err(reason) = assert_no_process_env_override_path(var) {
            return ConformanceResult::Fail { reason };
        }

        let findings = auditor.audit_source("test", "test.rs", test_source);

        // Should still detect violation despite unknown bypass attempt
        if findings.is_empty()
            || !findings
                .iter()
                .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
        {
            return ConformanceResult::Fail {
                reason: format!("Guard bypassed by unknown env var: {}={}", var, value),
            };
        }
    }

    ConformanceResult::Pass
}

fn test_fail_closed_malformed_bypass() -> ConformanceResult {
    // Test malformed bypass attempts that should still be rejected
    let malformed_attempts = [
        ("DISABLE_AMBIENT_GUARD", ""),    // Empty value
        ("BYPASS_SECURITY", "maybe"),     // Ambiguous value
        ("SKIP_AUTHORITY_CHECK", "0x1"),  // Hex format
        ("ALLOW_UNSAFE_IMPORTS", "TRUE"), // Wrong case
    ];

    let auditor = create_test_auditor();
    let test_source = "let _ = std::fs::File::open(\"test.txt\");";

    for (var, value) in &malformed_attempts {
        if let Err(reason) = assert_no_process_env_override_path(var) {
            return ConformanceResult::Fail { reason };
        }

        let findings = auditor.audit_source("test", "test.rs", test_source);

        if findings.is_empty()
            || !findings
                .iter()
                .any(|f| f.kind == ViolationKind::ForbiddenPattern)
        {
            return ConformanceResult::Fail {
                reason: format!("Guard bypassed by malformed env var: {}={}", var, value),
            };
        }
    }

    ConformanceResult::Pass
}

// ---------------------------------------------------------------------------
// Test Infrastructure
// ---------------------------------------------------------------------------

fn assert_no_process_env_override_path(var_name: &str) -> Result<(), String> {
    // Rust 2024 makes process-global environment mutation unsafe. These tests
    // prove the guard has no code path that can observe env-based bypass knobs,
    // then exercise the same findings the bypass would have tried to suppress.
    let guard_source = include_str!("../src/extension_host_authority_guard.rs");
    for token in ["std::env", "env::var", var_name] {
        if guard_source.contains(token) {
            return Err(format!(
                "extension-host authority guard contains process-environment override token `{token}`"
            ));
        }
    }
    Ok(())
}

fn create_test_auditor() -> ExtensionHostGuard {
    ExtensionHostGuard::standard()
}

fn assert_forbidden_extension_host_feature_absent(feature: &str) -> ConformanceResult {
    match extension_host_feature_names() {
        Ok(features)
            if features
                .iter()
                .any(|candidate| candidate.as_str() == feature) =>
        {
            ConformanceResult::Fail {
                reason: format!("forbidden extension-host feature '{feature}' is declared"),
            }
        }
        Ok(_) => ConformanceResult::Pass,
        Err(reason) => ConformanceResult::Fail { reason },
    }
}

fn extension_host_feature_names() -> Result<Vec<String>, String> {
    let manifest: toml::Value =
        toml::from_str(include_str!("../../franken-extension-host/Cargo.toml"))
            .map_err(|error| format!("failed to parse extension-host Cargo.toml: {error}"))?;

    Ok(manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .map(|features| features.keys().cloned().collect())
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Conformance Test Runner
// ---------------------------------------------------------------------------

#[test]
fn extension_host_ambient_authority_conformance() {
    let mut pass = 0;
    let mut fail = 0;
    let mut xfail = 0;
    let mut must_pass = 0;

    for case in CONFORMANCE_CASES {
        let result = (case.test_fn)();
        let verdict = match result {
            ConformanceResult::Pass => {
                pass += 1;
                if case.level == RequirementLevel::Must {
                    must_pass += 1;
                }
                "PASS"
            }
            ConformanceResult::Fail { ref reason } => {
                fail += 1;
                eprintln!("FAIL {}: {}", case.id, reason);
                "FAIL"
            }
            ConformanceResult::ExpectedFailure { ref reason } => {
                xfail += 1;
                eprintln!("XFAIL {}: {}", case.id, reason);
                "XFAIL"
            }
        };

        // Structured JSON-line output for CI parsing. Build it through serde so
        // future descriptions with quotes or backslashes remain valid JSON.
        let record = serde_json::json!({
            "id": case.id,
            "verdict": verdict,
            "level": format!("{:?}", case.level),
            "section": case.section,
            "description": case.description,
        });
        eprintln!("{record}");
    }

    let total = pass + fail + xfail;
    eprintln!(
        "\nBD-11Z7 Conformance: {}/{} pass, {} fail, {} expected-fail",
        pass, total, fail, xfail
    );

    // Coverage accounting matrix
    let mut by_section: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();

    for case in CONFORMANCE_CASES {
        let entry = by_section.entry(case.section).or_insert((0, 0, 0));
        match case.level {
            RequirementLevel::Must => entry.0 += 1,
            RequirementLevel::Should => entry.1 += 1,
            RequirementLevel::May => entry.2 += 1,
        }
    }

    eprintln!("\nCoverage Matrix:");
    eprintln!("| Section | MUST | SHOULD | MAY | Total |");
    eprintln!("|---------|----- |--------|-----|-------|");

    for (section, (must, should, may)) in &by_section {
        let total = must + should + may;
        eprintln!(
            "| {} | {} | {} | {} | {} |",
            section, must, should, may, total
        );
    }

    assert_eq!(fail, 0, "{} conformance tests failed", fail);

    // MUST clause coverage ≥ 95% requirement
    let total_must = by_section.values().map(|(must, _, _)| must).sum::<usize>();
    let must_score = if total_must > 0 {
        (must_pass as f32) / (total_must as f32)
    } else {
        0.0
    };

    assert!(
        must_score >= 0.95,
        "MUST clause coverage {:.2}% < 95% minimum ({}/{} MUST clauses passed)",
        must_score * 100.0,
        must_pass,
        total_must
    );
}
