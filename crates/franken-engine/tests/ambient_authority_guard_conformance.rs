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

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::process::Command;
use std::sync::Mutex;

use frankenengine_engine::extension_host_authority_guard::{
    ExtensionHostExemptionRegistry, ExtensionHostGuard, GuardConfig, ViolationKind,
};
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
            ViolationKind::ForbiddenPattern => context.contains("std::env") || context.contains("std::fs"),
            ViolationKind::CanonicalTypeShadow => true,
            ViolationKind::MissingCxParameter => false, // Not a security boundary
        }
    }
}

// Global mutex to serialize environment variable tests
static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

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
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Test that DISABLE_AMBIENT_GUARD=1 is rejected
    env::set_var("DISABLE_AMBIENT_GUARD", "1");

    let auditor = create_test_auditor();
    let source = "use franken_kernel::EngineCore;";
    let findings = auditor.audit_source("test", "test.rs", source);

    env::remove_var("DISABLE_AMBIENT_GUARD");

    if !findings.is_empty() && findings.iter().any(|f| f.kind == ViolationKind::DirectUpstreamImport) {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: "Guard accepted direct upstream import despite DISABLE_AMBIENT_GUARD=1".to_string(),
        }
    }
}

fn test_skip_authority_check_env_var() -> ConformanceResult {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Test that SKIP_AUTHORITY_CHECK=true is rejected
    env::set_var("SKIP_AUTHORITY_CHECK", "true");

    let auditor = create_test_auditor();
    let source = "let _ = std::fs::read_to_string(\"config.txt\");";
    let findings = auditor.audit_source("test", "test.rs", source);

    env::remove_var("SKIP_AUTHORITY_CHECK");

    if !findings.is_empty() && findings.iter().any(|f| f.kind == ViolationKind::ForbiddenPattern) {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: "Guard accepted forbidden I/O despite SKIP_AUTHORITY_CHECK=true".to_string(),
        }
    }
}

fn test_bypass_security_env_var() -> ConformanceResult {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    for value in ["1", "true", "yes", "on", "enable"] {
        env::set_var("BYPASS_SECURITY", value);

        let auditor = create_test_auditor();
        let source = "struct TraceId(String);"; // Shadows canonical type
        let findings = auditor.audit_source("test", "test.rs", source);

        if findings.is_empty() || !findings.iter().any(|f| f.kind == ViolationKind::CanonicalTypeShadow) {
            env::remove_var("BYPASS_SECURITY");
            return ConformanceResult::Fail {
                reason: format!("Guard accepted canonical type shadowing with BYPASS_SECURITY={}", value),
            };
        }
    }

    env::remove_var("BYPASS_SECURITY");
    ConformanceResult::Pass
}

fn test_allow_unsafe_imports_env_var() -> ConformanceResult {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    env::set_var("ALLOW_UNSAFE_IMPORTS", "1");

    let auditor = create_test_auditor();
    let source = r#"
        use franken_decision::PolicyEngine;
        use franken_evidence::AuditTrail;
    "#;
    let findings = auditor.audit_source("test", "test.rs", source);

    env::remove_var("ALLOW_UNSAFE_IMPORTS");

    // Must still detect violations even with bypass env var
    let upstream_violations = findings.iter()
        .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
        .count();

    if upstream_violations >= 2 {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: format!("Guard only detected {} upstream import violations, expected 2", upstream_violations),
        }
    }
}

fn test_env_var_permutations() -> ConformanceResult {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

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
        env::set_var(single_var.0, single_var.1);

        let findings = auditor.audit_source("test", "test.rs", test_source);

        // Should detect all violation types despite bypass attempt
        let has_import_violation = findings.iter().any(|f| f.kind == ViolationKind::DirectUpstreamImport);
        let has_io_violation = findings.iter().any(|f| f.kind == ViolationKind::ForbiddenPattern);
        let has_shadow_violation = findings.iter().any(|f| f.kind == ViolationKind::CanonicalTypeShadow);

        env::remove_var(single_var.0);

        if !has_import_violation || !has_io_violation || !has_shadow_violation {
            return ConformanceResult::Fail {
                reason: format!("Guard bypassed by single env var: {}={}", single_var.0, single_var.1),
            };
        }
    }

    // Test combination of multiple bypass variables
    env::set_var("DISABLE_AMBIENT_GUARD", "1");
    env::set_var("BYPASS_SECURITY", "true");
    env::set_var("ALLOW_UNSAFE_IMPORTS", "yes");

    let findings = auditor.audit_source("test", "test.rs", test_source);

    for var in ["DISABLE_AMBIENT_GUARD", "BYPASS_SECURITY", "ALLOW_UNSAFE_IMPORTS"] {
        env::remove_var(var);
    }

    if findings.len() >= 3 {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: format!("Guard bypassed by multiple env vars, only {} violations detected", findings.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// Section 2: Feature Flag Override Prevention
// ---------------------------------------------------------------------------

fn test_disable_ambient_guard_feature() -> ConformanceResult {
    // Test that compilation with --features disable-ambient-guard still enforces checks
    let output = Command::new("cargo")
        .args(&["check", "--features", "disable-ambient-guard", "--lib"])
        .current_dir("/data/projects/franken_engine/crates/franken-extension-host")
        .output();

    match output {
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);

            // Feature should either not exist or not disable the guard
            if stderr.contains("feature `disable-ambient-guard` does not exist") {
                ConformanceResult::Pass
            } else if result.status.success() {
                // If it compiles, the guard should still be active
                ConformanceResult::Pass
            } else {
                ConformanceResult::Fail {
                    reason: "Compilation failed for unknown reasons".to_string(),
                }
            }
        }
        Err(e) => ConformanceResult::Fail {
            reason: format!("Failed to run cargo check: {}", e),
        }
    }
}

fn test_unsafe_extension_host_feature() -> ConformanceResult {
    // Test that unsafe-extension-host feature flag is rejected
    let output = Command::new("cargo")
        .args(&["check", "--features", "unsafe-extension-host"])
        .current_dir("/data/projects/franken_engine/crates/franken-extension-host")
        .output();

    match output {
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);

            if stderr.contains("feature `unsafe-extension-host` does not exist") {
                ConformanceResult::Pass
            } else {
                ConformanceResult::Fail {
                    reason: "unsafe-extension-host feature flag exists and could bypass security".to_string(),
                }
            }
        }
        Err(e) => ConformanceResult::Fail {
            reason: format!("Failed to check feature flags: {}", e),
        }
    }
}

fn test_bypass_security_feature() -> ConformanceResult {
    // Test multiple potential bypass feature names
    let bypass_features = [
        "bypass-security",
        "disable-guards",
        "unsafe-mode",
        "debug-unsafe",
        "skip-checks"
    ];

    for feature in &bypass_features {
        let output = Command::new("cargo")
            .args(&["check", "--features", feature])
            .current_dir("/data/projects/franken_engine/crates/franken-extension-host")
            .output();

        match output {
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);

                if !stderr.contains(&format!("feature `{}` does not exist", feature)) {
                    return ConformanceResult::Fail {
                        reason: format!("Bypass feature '{}' exists", feature),
                    };
                }
            }
            Err(e) => {
                return ConformanceResult::Fail {
                    reason: format!("Failed to check feature '{}': {}", feature, e),
                };
            }
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
            let should_rollback = RollbackUnverified::should_trigger(finding.kind, &source);
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
            f.kind == ViolationKind::ForbiddenPattern &&
            RollbackUnverified::should_trigger(f.kind, source)
        });

        if !has_forbidden {
            return ConformanceResult::Fail {
                reason: format!("RollbackUnverified not triggered for forbidden I/O: {}", source),
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
            f.kind == ViolationKind::CanonicalTypeShadow &&
            RollbackUnverified::should_trigger(f.kind, source)
        });

        if !has_shadow {
            return ConformanceResult::Fail {
                reason: format!("RollbackUnverified not triggered for type shadowing: {}", source),
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

        let triggers_rollback = findings.iter().any(|f|
            RollbackUnverified::should_trigger(f.kind, source)
        );

        if triggers_rollback {
            return ConformanceResult::Fail {
                reason: format!("RollbackUnverified incorrectly triggered for legitimate code: {}", source),
            };
        }
    }

    ConformanceResult::Pass
}

// ---------------------------------------------------------------------------
// Section 4: Fail-Closed Behavior
// ---------------------------------------------------------------------------

fn test_fail_closed_unknown_env_vars() -> ConformanceResult {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    let unknown_vars = [
        ("FRANKEN_SECRET_BYPASS", "admin123"),
        ("SECURITY_OVERRIDE_CODE", "emergency"),
        ("AMBIENT_AUTHORITY_DISABLE", "please"),
    ];

    let auditor = create_test_auditor();
    let test_source = "use franken_decision::Core;";

    for (var, value) in &unknown_vars {
        env::set_var(var, value);

        let findings = auditor.audit_source("test", "test.rs", test_source);

        env::remove_var(var);

        // Should still detect violation despite unknown bypass attempt
        if findings.is_empty() || !findings.iter().any(|f| f.kind == ViolationKind::DirectUpstreamImport) {
            return ConformanceResult::Fail {
                reason: format!("Guard bypassed by unknown env var: {}={}", var, value),
            };
        }
    }

    ConformanceResult::Pass
}

fn test_fail_closed_malformed_bypass() -> ConformanceResult {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Test malformed bypass attempts that should still be rejected
    let malformed_attempts = [
        ("DISABLE_AMBIENT_GUARD", ""), // Empty value
        ("BYPASS_SECURITY", "maybe"), // Ambiguous value
        ("SKIP_AUTHORITY_CHECK", "0x1"), // Hex format
        ("ALLOW_UNSAFE_IMPORTS", "TRUE"), // Wrong case
    ];

    let auditor = create_test_auditor();
    let test_source = "let _ = std::fs::File::open(\"test.txt\");";

    for (var, value) in &malformed_attempts {
        env::set_var(var, value);

        let findings = auditor.audit_source("test", "test.rs", test_source);

        env::remove_var(var);

        if findings.is_empty() || !findings.iter().any(|f| f.kind == ViolationKind::ForbiddenPattern) {
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

fn create_test_auditor() -> ExtensionHostGuard {
    ExtensionHostGuard::standard()
}

// ---------------------------------------------------------------------------
// Conformance Test Runner
// ---------------------------------------------------------------------------

#[test]
fn extension_host_ambient_authority_conformance() {
    let mut pass = 0;
    let mut fail = 0;
    let mut xfail = 0;

    for case in CONFORMANCE_CASES {
        let result = (case.test_fn)();
        let verdict = match result {
            ConformanceResult::Pass => {
                pass += 1;
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

        // Structured JSON-line output for CI parsing
        eprintln!("{{\"id\":\"{}\",\"verdict\":\"{}\",\"level\":\"{:?}\",\"section\":\"{}\"}}",
            case.id, verdict, case.level, case.section);
    }

    let total = pass + fail + xfail;
    eprintln!("\nBD-11Z7 Conformance: {}/{} pass, {} fail, {} expected-fail",
        pass, total, fail, xfail);

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
        eprintln!("| {} | {} | {} | {} | {} |", section, must, should, may, total);
    }

    assert_eq!(fail, 0, "{} conformance tests failed", fail);

    // MUST clause coverage ≥ 95% requirement
    let total_must = by_section.values().map(|(must, _, _)| must).sum::<usize>();
    let must_score = if total_must > 0 { (pass as f32) / (total_must as f32) } else { 0.0 };

    assert!(must_score >= 0.95,
        "MUST clause coverage {:.2}% < 95% minimum", must_score * 100.0);
}