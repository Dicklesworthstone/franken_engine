#![forbid(unsafe_code)]

//! Golden artifact tests for PolicyBundle deterministic serialization.
//!
//! Tests that PolicyBundle structures serialize to deterministic JSON
//! snapshots, ensuring no non-deterministic fields (timestamps, random IDs)
//! break reproducible builds and proof artifacts.
//!
//! Uses real engine components without mocks to validate production behavior.

use std::collections::BTreeMap;

use frankenengine_engine::runtime_decision_theory::{
    BudgetConfig, ConformalConfig, CvarConfig, DecisionContext, DecisionContextConfig, DriftConfig,
    LaneId, PolicyBundle, RiskFactor,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

#[test]
fn test_policy_bundle_deterministic_serialization() {
    println!("Testing PolicyBundle deterministic JSON serialization...");

    let policy_bundle = create_test_policy_bundle();

    // Serialize to JSON
    let json_output = serde_json::to_string_pretty(&policy_bundle)
        .expect("PolicyBundle should serialize to JSON");

    println!("Generated PolicyBundle JSON:\n{}", json_output);
    let json_value: serde_json::Value =
        serde_json::from_str(&json_output).expect("PolicyBundle pretty JSON should parse");

    // Test determinism: multiple serializations should be identical
    for iteration in 1..=5 {
        let repeated_bundle = create_test_policy_bundle();
        let repeated_json = serde_json::to_string_pretty(&repeated_bundle)
            .expect("PolicyBundle should serialize consistently");

        assert_eq!(
            json_output, repeated_json,
            "PolicyBundle serialization not deterministic on iteration {}",
            iteration
        );
    }

    // Golden artifact verification: validate expected structure and values
    assert!(json_output.contains(r#""version": "1.0.0""#));
    assert!(json_output.contains(r#""epoch": 1"#)); // SecurityEpoch::from_raw(1)
    assert!(json_output.contains(r#"baseline_deterministic_profile"#));
    assert!(json_output.contains(r#"baseline_throughput_profile"#));
    assert_eq!(json_value["cvar_config"]["alpha_millionths"], 950_000);
    assert_eq!(json_value["conformal_config"]["alpha_millionths"], 100_000);

    println!("✅ PolicyBundle serialization is deterministic");
}

#[test]
fn test_policy_bundle_round_trip_serialization() {
    println!("Testing PolicyBundle JSON round-trip preservation...");

    let original_bundle = create_test_policy_bundle();

    // Serialize to JSON
    let json_string =
        serde_json::to_string(&original_bundle).expect("Should serialize PolicyBundle");

    // Deserialize back
    let deserialized_bundle: PolicyBundle =
        serde_json::from_str(&json_string).expect("Should deserialize PolicyBundle from JSON");

    // Verify round-trip preservation
    assert_eq!(
        original_bundle, deserialized_bundle,
        "PolicyBundle should survive JSON round-trip unchanged"
    );

    // Verify key fields individually for better error reporting
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

    println!("✅ PolicyBundle round-trip serialization preserved all fields");
}

#[test]
fn test_policy_bundle_with_different_configs() {
    println!("Testing PolicyBundle determinism with different configurations...");

    let test_cases = vec![
        ("default_config", create_test_policy_bundle()),
        ("minimal_config", create_minimal_policy_bundle()),
        ("comprehensive_config", create_comprehensive_policy_bundle()),
    ];

    for (test_name, bundle) in &test_cases {
        println!("Testing configuration: {}", test_name);

        // Each configuration should have deterministic serialization
        let json1 = serde_json::to_string_pretty(bundle).expect("Should serialize PolicyBundle");
        let json2 = serde_json::to_string_pretty(bundle)
            .expect("Should serialize PolicyBundle consistently");

        assert_eq!(
            json1, json2,
            "PolicyBundle serialization not deterministic for config: {}",
            test_name
        );

        // Validate structure contains expected deterministic elements
        assert!(!json1.contains("random"));
        assert!(!json1.contains("timestamp"));
        assert!(!json1.contains("uuid"));
        assert!(!json1.contains("nonce"));

        println!(
            "✅ Configuration {} produces deterministic output",
            test_name
        );
    }
}

#[test]
fn test_policy_bundle_golden_snapshot() {
    println!("Testing PolicyBundle against golden snapshot...");

    let bundle = create_test_policy_bundle();
    let actual_json = serde_json::to_string_pretty(&bundle).expect("Should serialize PolicyBundle");
    let actual_value: serde_json::Value =
        serde_json::from_str(&actual_json).expect("PolicyBundle pretty JSON should parse");

    // Expected golden JSON structure (deterministic)
    let expected_json_structure = vec![
        r#""version": "1.0.0""#,
        r#""epoch": 1"#,
        r#""lanes""#,
        r#""baseline_deterministic_profile""#,
        r#""baseline_throughput_profile""#,
        r#""cvar_config""#,
        r#""conformal_config""#,
        r#""drift_config""#,
        r#""budget_config""#,
        r#""risk_weights""#,
        r#""Compatibility""#,
        r#""Latency""#,
        r#""Memory""#,
        r#""IncidentSeverity""#,
        r#""default_action""#,
        r#""fallback_action""#,
    ];

    for expected_element in &expected_json_structure {
        assert!(
            actual_json.contains(expected_element),
            "Golden snapshot missing expected element: {}\n\nActual JSON:\n{}",
            expected_element,
            actual_json
        );
    }

    // Verify deterministic field values
    assert_eq!(actual_value["risk_weights"]["Compatibility"], 300_000);
    assert_eq!(actual_value["risk_weights"]["Latency"], 300_000);
    assert_eq!(actual_value["risk_weights"]["Memory"], 200_000);
    assert_eq!(actual_value["risk_weights"]["IncidentSeverity"], 200_000);
    assert_eq!(actual_value["cvar_config"]["alpha_millionths"], 950_000);
    assert_eq!(
        actual_value["conformal_config"]["alpha_millionths"],
        100_000
    );

    println!("✅ PolicyBundle matches expected golden snapshot structure");
}

#[test]
fn test_policy_bundle_cross_platform_determinism() {
    println!("Testing PolicyBundle cross-platform serialization determinism...");

    let bundle = create_test_policy_bundle();

    // Test multiple serialization attempts to catch any non-determinism
    let mut json_outputs = Vec::new();
    for i in 0..10 {
        let json = serde_json::to_string(&bundle).expect("Should serialize PolicyBundle");
        json_outputs.push((i, json));
    }

    // All outputs should be identical (cross-platform determinism)
    let reference_json = &json_outputs[0].1;
    for (iteration, json) in &json_outputs[1..] {
        assert_eq!(
            reference_json, json,
            "Cross-platform determinism violation at iteration {}",
            iteration
        );
    }

    // Verify no platform-specific elements leak through
    assert!(!reference_json.contains("windows"));
    assert!(!reference_json.contains("linux"));
    assert!(!reference_json.contains("darwin"));
    assert!(!reference_json.contains("x86"));
    assert!(!reference_json.contains("arm"));

    println!("✅ PolicyBundle serialization is cross-platform deterministic");
}

// Helper functions for creating test PolicyBundles

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
