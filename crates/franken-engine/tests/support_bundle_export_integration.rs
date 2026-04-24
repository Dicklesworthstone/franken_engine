#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::support_bundle_export::{SupportBundleInput, export_support_bundle};

fn integration_input() -> SupportBundleInput {
    SupportBundleInput {
        engine_version: "0.1.0".to_string(),
        runtime_version: "runtime-2026.04".to_string(),
        config: BTreeMap::from([
            ("policy.mode".to_string(), "safe".to_string()),
            ("scheduler.max_depth".to_string(), "64".to_string()),
        ]),
        determinism_witnesses: BTreeMap::from([
            ("canonical_seed".to_string(), "seed-hash-1".to_string()),
            ("replay_trace".to_string(), "trace-7".to_string()),
        ]),
        decision_artifact_ids: vec!["decision-z".to_string(), "decision-a".to_string()],
        diagnostics: BTreeMap::from([
            ("operator_note".to_string(), "migration blocked".to_string()),
            ("api_token".to_string(), "super-secret-token".to_string()),
        ]),
    }
}

#[test]
fn support_bundle_json_bytes_are_identical_across_two_exports() {
    let input = integration_input();
    let first = export_support_bundle(&input)
        .expect("first export")
        .to_json_bytes()
        .expect("first bytes");
    let second = export_support_bundle(&input)
        .expect("second export")
        .to_json_bytes()
        .expect("second bytes");

    assert_eq!(first, second);
    let serialized = String::from_utf8(first).expect("utf8 json");
    assert!(serialized.contains("decision_artifact_id.000"));
    assert!(!serialized.contains("super-secret-token"));
}
