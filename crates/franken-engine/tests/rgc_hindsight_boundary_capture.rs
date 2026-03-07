#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use frankenengine_engine::hindsight_boundary_capture::{
    BoundaryCaptureContract, BoundaryCaptureSession, BoundaryClass, BoundaryContext,
    ReplaySufficiency,
};

const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_hindsight_boundary_capture_v1.json");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn rgc_811a_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_HINDSIGHT_BOUNDARY_CAPTURE_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Hindsight Boundary Capture V1",
        "## Purpose",
        "## Boundary Taxonomy",
        "## Correlation Key Contract",
        "## Minimal Replay Input Rules",
        "## Privacy And Redaction",
        "## Artifact Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_811a_contract_json_matches_default_contract() {
    let actual: BoundaryCaptureContract =
        serde_json::from_str(CONTRACT_JSON).expect("contract json must parse");
    let expected = BoundaryCaptureContract::default_v1();
    assert_eq!(actual, expected);
}

#[test]
fn rgc_811a_minimal_replay_schema_covers_every_boundary_class() {
    let actual: BoundaryCaptureContract =
        serde_json::from_str(CONTRACT_JSON).expect("contract json must parse");

    let expected_classes: BTreeSet<_> = BoundaryClass::ALL.into_iter().collect();
    let actual_classes: BTreeSet<_> = actual
        .minimal_replay_input_schema
        .entries
        .iter()
        .map(|entry| entry.boundary_class)
        .collect();

    assert_eq!(actual_classes, expected_classes);
}

#[test]
fn rgc_811a_multi_boundary_scenario_emits_stable_jsonl() {
    let mut session = BoundaryCaptureSession::default_v1();

    let module_context = BoundaryContext::new(
        "trace-rgc-811a",
        "decision-rgc-811a-module",
        "policy-rgc-811a",
        "module_loader",
        20,
    );
    session
        .capture_module_resolution(
            &module_context,
            "pkg:demo/widget",
            "digest-referrer",
            "digest-resolved",
            None,
        )
        .expect("module capture succeeds");

    let scheduler_context = BoundaryContext::new(
        "trace-rgc-811a",
        "decision-rgc-811a-scheduler",
        "policy-rgc-811a",
        "scheduler",
        40,
    );
    session
        .capture_scheduling_decision(
            &scheduler_context,
            "ready",
            "task-41",
            "digest-ordering",
            None,
        )
        .expect("scheduler capture succeeds");

    let controller_context = BoundaryContext::new(
        "trace-rgc-811a",
        "decision-rgc-811a-controller",
        "policy-rgc-811a",
        "controller",
        60,
    );
    session
        .capture_controller_override(
            &controller_context,
            "router",
            "force_safe_mode",
            "digest-value",
            Some("interactive-controller-input"),
        )
        .expect("controller capture succeeds");

    let rendered = session.log().render_jsonl().expect("jsonl renders");
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines.len(), 3);

    let correlation_keys: BTreeSet<_> = session
        .log()
        .records()
        .iter()
        .map(|record| record.correlation_key.as_str())
        .collect();
    assert_eq!(correlation_keys.len(), 3);
    assert!(rendered.contains("\"boundary_class\":\"module_resolution\""));
    assert!(rendered.contains("\"boundary_class\":\"scheduling_decision\""));
    assert!(rendered.contains("\"boundary_class\":\"controller_override\""));
    assert!(
        session
            .log()
            .records()
            .iter()
            .any(|record| record.sufficiency == ReplaySufficiency::NeedsEscalation)
    );
}

#[test]
fn rgc_811a_redaction_contract_keeps_sensitive_fields_digest_only() {
    let actual: BoundaryCaptureContract =
        serde_json::from_str(CONTRACT_JSON).expect("contract json must parse");

    let digest_only_fields: BTreeSet<_> = actual
        .boundary_redaction_map
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.treatment,
                frankenengine_engine::hindsight_boundary_capture::RedactionTreatment::DigestOnly
            )
        })
        .map(|entry| (entry.boundary_class, entry.field.as_str()))
        .collect();

    assert!(digest_only_fields.contains(&(BoundaryClass::RandomnessDraw, "sample_digest")));
    assert!(digest_only_fields.contains(&(BoundaryClass::FilesystemInput, "path_digest")));
    assert!(digest_only_fields.contains(&(BoundaryClass::NetworkResponse, "response_digest")));
    assert!(digest_only_fields.contains(&(BoundaryClass::ControllerOverride, "value_digest")));
    assert!(
        digest_only_fields.contains(&(BoundaryClass::HardwareSurfaceRead, "driver_fingerprint"))
    );
}
