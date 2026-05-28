#![forbid(unsafe_code)]

//! Golden artifact tests for `PolicyBundle` deterministic serialization.
//!
//! Tests that `PolicyBundle` structures serialize to deterministic JSON
//! snapshots, ensuring no non-deterministic fields (timestamps, random IDs)
//! break reproducible builds and proof artifacts.
//!
//! Schema-shape coverage is enforced by *real* golden files in
//! `tests/golden/policy_bundle_{default,minimal,comprehensive}.golden`
//! (see [`assert_golden`]) — the substring-only asserts that used to live
//! here let silent schema renames slip through (bd-ub6x8.4); the golden
//! files are now the load-bearing check. Run
//! `UPDATE_GOLDENS=1 cargo test --test policy_bundle_golden_artifacts` to
//! refresh them when the `PolicyBundle` schema legitimately changes; the
//! diff has to be reviewed and committed.
//!
//! Uses real engine components without mocks to validate production behavior.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use frankenengine_engine::runtime_decision_theory::{
    BudgetConfig, ConformalConfig, CvarConfig, DecisionContext, DecisionContextConfig, DriftConfig,
    LaneId, PolicyBundle, RiskFactor,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Golden assertion helper (mirrors benchmark_evidence_bundle_golden.rs:24)
// ---------------------------------------------------------------------------

/// Assert golden output matches expected, with `UPDATE_GOLDENS=1` support.
/// Mirrors the canonical helper in `benchmark_evidence_bundle_golden.rs` so
/// the regen workflow (`UPDATE_GOLDENS=1`) and the `.actual` sweep behave
/// identically across goldens in `tests/golden/` (bd-ub6x8.2/bd-ub6x8.7).
fn assert_golden(test_name: &str, actual: &str) {
    let golden_path = Path::new("tests/golden").join(format!("{test_name}.golden"));

    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(
            golden_path
                .parent()
                .expect("Golden path must have parent directory"),
        )
        .expect("Failed to create golden artifacts directory");
        fs::write(&golden_path, actual).expect("Failed to write golden artifact file");
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/",
            golden_path.display()
        )
    });

    if actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual)
            .expect("Failed to write actual artifact file for comparison");
        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             Expected length: {} bytes\n\
             Actual length:   {} bytes\n\n\
             To update: UPDATE_GOLDENS=1 cargo test --test policy_bundle_golden_artifacts -- {test_name}\n\
             To review: diff {} {}",
            expected.len(),
            actual.len(),
            golden_path.display(),
            actual_path.display()
        );
    }

    let _ = fs::remove_file(golden_path.with_extension("actual"));
}

// ---------------------------------------------------------------------------
// Real golden snapshot tests (bd-ub6x8.4)
// ---------------------------------------------------------------------------

#[test]
fn golden_policy_bundle_default() {
    let bundle = create_test_policy_bundle();
    let actual = serde_json::to_string_pretty(&bundle).expect("PolicyBundle should serialize");
    assert_golden("policy_bundle_default", &actual);
}

#[test]
fn golden_policy_bundle_minimal() {
    let bundle = create_minimal_policy_bundle();
    let actual = serde_json::to_string_pretty(&bundle).expect("PolicyBundle should serialize");
    assert_golden("policy_bundle_minimal", &actual);
}

#[test]
fn golden_policy_bundle_comprehensive() {
    let bundle = create_comprehensive_policy_bundle();
    let actual = serde_json::to_string_pretty(&bundle).expect("PolicyBundle should serialize");
    assert_golden("policy_bundle_comprehensive", &actual);
}

// ---------------------------------------------------------------------------
// Orthogonal property checks (kept from the pre-bd-ub6x8.4 version)
//
// The golden tests above already cover *what* the JSON looks like. These
// remaining tests cover orthogonal properties the golden file alone can't
// prove: round-trip preservation, determinism across repeated calls, and
// the absence of platform-leaked / non-deterministic field shapes that a
// schema diff against the golden wouldn't catch on first appearance.
// ---------------------------------------------------------------------------

#[test]
fn test_policy_bundle_deterministic_serialization() {
    let bundle = create_test_policy_bundle();
    let baseline =
        serde_json::to_string_pretty(&bundle).expect("PolicyBundle should serialize to JSON");

    for iteration in 1..=5 {
        let repeated_bundle = create_test_policy_bundle();
        let repeated_json = serde_json::to_string_pretty(&repeated_bundle)
            .expect("PolicyBundle should serialize consistently");

        assert_eq!(
            baseline, repeated_json,
            "PolicyBundle serialization not deterministic on iteration {}",
            iteration
        );
    }
}

#[test]
fn test_policy_bundle_round_trip_serialization() {
    let original_bundle = create_test_policy_bundle();
    let json_string =
        serde_json::to_string(&original_bundle).expect("Should serialize PolicyBundle");
    let deserialized_bundle: PolicyBundle =
        serde_json::from_str(&json_string).expect("Should deserialize PolicyBundle from JSON");

    assert_eq!(
        original_bundle, deserialized_bundle,
        "PolicyBundle should survive JSON round-trip unchanged"
    );

    // Per-field assertions give clearer error messages on first regression.
    assert_eq!(original_bundle.version, deserialized_bundle.version);
    assert_eq!(original_bundle.epoch, deserialized_bundle.epoch);
    assert_eq!(original_bundle.lanes, deserialized_bundle.lanes);
    assert_eq!(original_bundle.cvar_config, deserialized_bundle.cvar_config);
    assert_eq!(
        original_bundle.conformal_config,
        deserialized_bundle.conformal_config
    );
    assert_eq!(
        original_bundle.drift_config,
        deserialized_bundle.drift_config
    );
    assert_eq!(
        original_bundle.budget_config,
        deserialized_bundle.budget_config
    );
    assert_eq!(
        original_bundle.risk_weights,
        deserialized_bundle.risk_weights
    );
    assert_eq!(
        original_bundle.default_action,
        deserialized_bundle.default_action
    );
    assert_eq!(
        original_bundle.fallback_action,
        deserialized_bundle.fallback_action
    );
}

#[test]
fn test_policy_bundle_with_different_configs() {
    let test_cases = vec![
        ("default_config", create_test_policy_bundle()),
        ("minimal_config", create_minimal_policy_bundle()),
        ("comprehensive_config", create_comprehensive_policy_bundle()),
    ];

    for (test_name, bundle) in &test_cases {
        let json1 = serde_json::to_string_pretty(bundle).expect("Should serialize PolicyBundle");
        let json2 = serde_json::to_string_pretty(bundle)
            .expect("Should serialize PolicyBundle consistently");

        assert_eq!(
            json1, json2,
            "PolicyBundle serialization not deterministic for config: {}",
            test_name
        );

        // Catch any non-deterministic shape leaking into the serialised form.
        assert!(!json1.contains("random"), "{} contains 'random'", test_name);
        assert!(
            !json1.contains("timestamp"),
            "{} contains 'timestamp'",
            test_name
        );
        assert!(!json1.contains("uuid"), "{} contains 'uuid'", test_name);
        assert!(!json1.contains("nonce"), "{} contains 'nonce'", test_name);
    }
}

#[test]
fn test_policy_bundle_cross_platform_determinism() {
    let bundle = create_test_policy_bundle();

    let mut json_outputs = Vec::new();
    for i in 0..10 {
        let json = serde_json::to_string(&bundle).expect("Should serialize PolicyBundle");
        json_outputs.push((i, json));
    }

    let reference_json = &json_outputs[0].1;
    for (iteration, json) in &json_outputs[1..] {
        assert_eq!(
            reference_json, json,
            "Cross-platform determinism violation at iteration {}",
            iteration
        );
    }

    // Catch platform-specific identifiers slipping into the serialized form.
    for label in &["windows", "linux", "darwin", "x86", "arm"] {
        assert!(
            !reference_json.contains(label),
            "PolicyBundle JSON contains platform label {label:?} — must be cross-platform-deterministic"
        );
    }
}

// ---------------------------------------------------------------------------
// Helper functions for creating test `PolicyBundle`s
// ---------------------------------------------------------------------------

fn create_test_policy_bundle() -> PolicyBundle {
    let config = DecisionContextConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let context = DecisionContext::new(config, epoch);
    context.policy_bundle()
}

fn create_minimal_policy_bundle() -> PolicyBundle {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig::default(),
        conformal_config: ConformalConfig::default(),
        drift_config: DriftConfig::default(),
        budget_config: BudgetConfig::default(),
        lanes: vec![LaneId::deterministic_profile()],
        risk_weights: {
            let mut weights = BTreeMap::new();
            weights.insert(RiskFactor::Compatibility, 1_000_000); // 100%
            weights
        },
    };
    let epoch = SecurityEpoch::from_raw(1);
    let context = DecisionContext::new(config, epoch);
    context.policy_bundle()
}

fn create_comprehensive_policy_bundle() -> PolicyBundle {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig::default(),
        conformal_config: ConformalConfig::default(),
        drift_config: DriftConfig::default(),
        budget_config: BudgetConfig::default(),
        lanes: vec![
            LaneId::deterministic_profile(),
            LaneId::throughput_profile(),
            LaneId("custom_experimental_lane".into()),
        ],
        risk_weights: {
            let mut weights = BTreeMap::new();
            weights.insert(RiskFactor::Compatibility, 400_000); // 40%
            weights.insert(RiskFactor::Latency, 300_000); // 30%
            weights.insert(RiskFactor::Memory, 200_000); // 20%
            weights.insert(RiskFactor::IncidentSeverity, 100_000); // 10%
            weights
        },
    };
    let epoch = SecurityEpoch::from_raw(1);
    let context = DecisionContext::new(config, epoch);
    context.policy_bundle()
}
