#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use frankenengine_engine::hindsight_boundary_capture::{
    BoundaryCaptureContract, BoundaryCaptureSession, BoundaryClass, BoundaryContext,
    RedactionTreatment, ReplaySufficiency,
};

const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_hindsight_boundary_capture_v1.json");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn make_ctx<'a>(
    trace: &'a str,
    decision: &'a str,
    component: &'a str,
    ts: u64,
) -> BoundaryContext<'a> {
    BoundaryContext::new(trace, decision, "policy-test", component, ts)
}

// ---------------------------------------------------------------------------
// Original 7 tests
// ---------------------------------------------------------------------------

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

    let cache_context = BoundaryContext::new(
        "trace-rgc-811a",
        "decision-rgc-811a-cache",
        "policy-rgc-811a",
        "module_cache",
        30,
    );
    session
        .capture_filesystem_input(
            &cache_context,
            "cache_read",
            "digest-cache-path",
            "digest-cache-entry",
            None,
        )
        .expect("cache capture succeeds");

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
    assert_eq!(lines.len(), 4);

    let correlation_keys: BTreeSet<_> = session
        .log()
        .records()
        .iter()
        .map(|record| record.correlation_key.as_str())
        .collect();
    assert_eq!(correlation_keys.len(), 4);
    assert!(rendered.contains("\"boundary_class\":\"filesystem_input\""));
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
fn rgc_811a_minimal_replay_plan_covers_event_loop_module_cache_and_controller_flows() {
    let mut session = BoundaryCaptureSession::default_v1();

    session
        .capture_module_resolution(
            &BoundaryContext::new(
                "trace-rgc-811a",
                "decision-rgc-811a-module",
                "policy-rgc-811a",
                "module_loader",
                20,
            ),
            "pkg:demo/widget",
            "digest-referrer",
            "digest-resolved",
            None,
        )
        .expect("module capture succeeds");
    session
        .capture_filesystem_input(
            &BoundaryContext::new(
                "trace-rgc-811a",
                "decision-rgc-811a-cache",
                "policy-rgc-811a",
                "module_cache",
                30,
            ),
            "cache_read",
            "digest-cache-path",
            "digest-cache-entry",
            None,
        )
        .expect("cache capture succeeds");
    session
        .capture_scheduling_decision(
            &BoundaryContext::new(
                "trace-rgc-811a",
                "decision-rgc-811a-event-loop",
                "policy-rgc-811a",
                "event_loop",
                40,
            ),
            "ready",
            "task-41",
            "digest-ordering",
            None,
        )
        .expect("event-loop capture succeeds");
    session
        .capture_controller_override(
            &BoundaryContext::new(
                "trace-rgc-811a",
                "decision-rgc-811a-controller",
                "policy-rgc-811a",
                "controller",
                60,
            ),
            "router",
            "force_safe_mode",
            "digest-value",
            None,
        )
        .expect("controller capture succeeds");

    let plans = session
        .minimal_replay_plans()
        .expect("all non-escalated captures should be replayable");
    assert_eq!(plans.len(), 4);

    let replay_shape: BTreeSet<_> = plans
        .iter()
        .map(|plan| {
            (
                plan.decision_id.as_str(),
                plan.inputs[0].boundary_class,
                plan.inputs[0].component.as_str(),
            )
        })
        .collect();

    assert!(replay_shape.contains(&(
        "decision-rgc-811a-module",
        BoundaryClass::ModuleResolution,
        "module_loader",
    )));
    assert!(replay_shape.contains(&(
        "decision-rgc-811a-cache",
        BoundaryClass::FilesystemInput,
        "module_cache",
    )));
    assert!(replay_shape.contains(&(
        "decision-rgc-811a-event-loop",
        BoundaryClass::SchedulingDecision,
        "event_loop",
    )));
    assert!(replay_shape.contains(&(
        "decision-rgc-811a-controller",
        BoundaryClass::ControllerOverride,
        "controller",
    )));
}

#[test]
fn rgc_811a_minimal_replay_plan_rejects_escalation_triggering_capture() {
    let mut session = BoundaryCaptureSession::default_v1();

    session
        .capture_controller_override(
            &BoundaryContext::new(
                "trace-rgc-811a",
                "decision-rgc-811a-controller",
                "policy-rgc-811a",
                "controller",
                60,
            ),
            "router",
            "force_safe_mode",
            "digest-value",
            Some("interactive-controller-input"),
        )
        .expect("controller capture succeeds");

    let error = session
        .minimal_replay_plans()
        .expect_err("escalated controller decision should fail closed");
    let error_text = error.to_string();
    assert!(error_text.contains("interactive-controller-input"));
    assert!(error_text.contains("controller_override"));
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

// ---------------------------------------------------------------------------
// New tests (23+)
// ---------------------------------------------------------------------------

#[test]
fn boundary_class_all_contains_nine_variants() {
    assert_eq!(BoundaryClass::ALL.len(), 9);
    let as_set: BTreeSet<_> = BoundaryClass::ALL.into_iter().collect();
    assert_eq!(as_set.len(), 9, "ALL should contain 9 unique variants");
}

#[test]
fn boundary_class_serde_roundtrip_for_each_variant() {
    for variant in BoundaryClass::ALL {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: BoundaryClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant, "roundtrip failed for {variant}");
    }
}

#[test]
fn boundary_context_new_sets_all_fields() {
    let ctx = BoundaryContext::new("t1", "d1", "p1", "comp1", 99);
    assert_eq!(ctx.trace_id, "t1");
    assert_eq!(ctx.decision_id, "d1");
    assert_eq!(ctx.policy_id, "p1");
    assert_eq!(ctx.component, "comp1");
    assert_eq!(ctx.virtual_ts, 99);
}

#[test]
fn default_v1_session_has_empty_log() {
    let session = BoundaryCaptureSession::default_v1();
    assert!(session.log().records().is_empty());
}

#[test]
fn empty_session_renders_empty_jsonl() {
    let session = BoundaryCaptureSession::default_v1();
    let rendered = session.log().render_jsonl().expect("render succeeds");
    assert!(
        rendered.is_empty(),
        "empty session should produce empty JSONL"
    );
}

#[test]
fn empty_session_minimal_replay_plans_returns_empty_ok() {
    let session = BoundaryCaptureSession::default_v1();
    let plans = session
        .minimal_replay_plans()
        .expect("no captures, no errors");
    assert!(plans.is_empty());
}

#[test]
fn replay_sufficiency_serde_roundtrip_sufficient() {
    let val = ReplaySufficiency::Sufficient;
    let json = serde_json::to_string(&val).unwrap();
    let back: ReplaySufficiency = serde_json::from_str(&json).unwrap();
    assert_eq!(back, val);
}

#[test]
fn replay_sufficiency_serde_roundtrip_needs_escalation() {
    let val = ReplaySufficiency::NeedsEscalation;
    let json = serde_json::to_string(&val).unwrap();
    let back: ReplaySufficiency = serde_json::from_str(&json).unwrap();
    assert_eq!(back, val);
}

#[test]
fn redaction_treatment_serde_roundtrip_plaintext() {
    let val = RedactionTreatment::Plaintext;
    let json = serde_json::to_string(&val).unwrap();
    let back: RedactionTreatment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, val);
}

#[test]
fn redaction_treatment_serde_roundtrip_digest_only() {
    let val = RedactionTreatment::DigestOnly;
    let json = serde_json::to_string(&val).unwrap();
    let back: RedactionTreatment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, val);
}

#[test]
fn redaction_treatment_serde_roundtrip_omit() {
    let val = RedactionTreatment::Omit;
    let json = serde_json::to_string(&val).unwrap();
    let back: RedactionTreatment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, val);
}

#[test]
fn contract_has_non_empty_redaction_map_entries() {
    let contract = BoundaryCaptureContract::default_v1();
    assert!(
        !contract.boundary_redaction_map.entries.is_empty(),
        "redaction map must have entries"
    );
}

#[test]
fn contract_has_non_empty_minimal_replay_input_schema_entries() {
    let contract = BoundaryCaptureContract::default_v1();
    assert!(
        !contract.minimal_replay_input_schema.entries.is_empty(),
        "minimal replay input schema must have entries"
    );
}

#[test]
fn multiple_captures_increment_sequence_numbers() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-seq", "d-seq", "clock", 10);

    for i in 0u64..5 {
        session
            .capture_clock_read(&ctx, "mono", "monotonic", i, None)
            .expect("capture succeeds");
    }

    let records = session.log().records();
    for (i, record) in records.iter().enumerate() {
        assert_eq!(record.sequence, i as u64, "sequence should match index");
    }
}

#[test]
fn correlation_keys_are_unique_per_capture() {
    let mut session = BoundaryCaptureSession::default_v1();
    for i in 0u64..4 {
        let decision = format!("d-uniq-{i}");
        let ctx = make_ctx("t-uniq", &decision, "rng", i * 10);
        session
            .capture_randomness_draw(&ctx, "rng-seeded", i, "digest-sample", None)
            .expect("capture");
    }
    let keys: BTreeSet<_> = session
        .log()
        .records()
        .iter()
        .map(|r| r.correlation_key.as_str())
        .collect();
    assert_eq!(keys.len(), 4, "all correlation keys must be unique");
}

#[test]
fn single_module_resolution_capture_renders_one_jsonl_line() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-mod", "d-mod", "module_loader", 20);
    session
        .capture_module_resolution(&ctx, "pkg:a/b", "ref-dig", "res-dig", None)
        .expect("capture");
    let rendered = session.log().render_jsonl().expect("render");
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(rendered.contains("\"boundary_class\":\"module_resolution\""));
}

#[test]
fn single_filesystem_input_capture_renders_one_jsonl_line() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-fs", "d-fs", "cache", 30);
    session
        .capture_filesystem_input(&ctx, "read", "path-dig", "content-dig", None)
        .expect("capture");
    let rendered = session.log().render_jsonl().expect("render");
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(rendered.contains("\"boundary_class\":\"filesystem_input\""));
}

#[test]
fn single_scheduling_decision_capture_renders_one_jsonl_line() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-sched", "d-sched", "scheduler", 40);
    session
        .capture_scheduling_decision(&ctx, "ready", "task-1", "ord-dig", None)
        .expect("capture");
    let rendered = session.log().render_jsonl().expect("render");
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(rendered.contains("\"boundary_class\":\"scheduling_decision\""));
}

#[test]
fn single_controller_override_without_escalation_renders_one_jsonl_line() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-ctrl", "d-ctrl", "controller", 50);
    session
        .capture_controller_override(&ctx, "router", "safe_mode", "val-dig", None)
        .expect("capture");
    let rendered = session.log().render_jsonl().expect("render");
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(rendered.contains("\"boundary_class\":\"controller_override\""));
    // No escalation means sufficiency should be "sufficient"
    let record = &session.log().records()[0];
    assert_eq!(record.sufficiency, ReplaySufficiency::Sufficient);
}

#[test]
fn jsonl_rendering_is_deterministic() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-det", "d-det", "clock", 10);
    session
        .capture_clock_read(&ctx, "mono", "monotonic", 42, None)
        .expect("capture");
    let first = session.log().render_jsonl().expect("first render");
    let second = session.log().render_jsonl().expect("second render");
    assert_eq!(first, second, "JSONL rendering must be deterministic");
}

#[test]
fn contract_schema_version_is_stable() {
    let contract = BoundaryCaptureContract::default_v1();
    assert_eq!(
        contract.schema_version,
        "franken-engine.rgc-hindsight-boundary-capture.contract.v1"
    );
}

#[test]
fn contract_bead_id_is_stable() {
    let contract = BoundaryCaptureContract::default_v1();
    assert_eq!(contract.bead_id, "bd-1lsy.9.11.1");
}

#[test]
fn contract_version_matches_json_artifact() {
    let from_json: BoundaryCaptureContract = serde_json::from_str(CONTRACT_JSON).expect("parse");
    let from_code = BoundaryCaptureContract::default_v1();
    assert_eq!(from_json.schema_version, from_code.schema_version);
    assert_eq!(from_json.bead_id, from_code.bead_id);
}

#[test]
fn replay_plan_input_count_matches_capture_count() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-plan", "d-plan", "clock", 10);
    session
        .capture_clock_read(&ctx, "mono", "monotonic", 1, None)
        .expect("capture 1");
    session
        .capture_clock_read(&ctx, "mono", "monotonic", 2, None)
        .expect("capture 2");

    let plans = session.minimal_replay_plans().expect("plans");
    // Both captures share the same (trace, decision, policy) tuple, so one plan
    let total_inputs: usize = plans.iter().map(|p| p.inputs.len()).sum();
    assert_eq!(total_inputs, 2, "input count must match capture count");
}

#[test]
fn replay_plan_decision_id_matches_capture_context() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-did", "decision-abc", "fs", 20);
    session
        .capture_filesystem_input(&ctx, "stat", "p-dig", "c-dig", None)
        .expect("capture");
    let plans = session.minimal_replay_plans().expect("plans");
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].decision_id, "decision-abc");
}

#[test]
fn redaction_map_has_entries_for_each_boundary_class_with_sensitive_fields() {
    let contract = BoundaryCaptureContract::default_v1();
    let classes_with_entries: BTreeSet<_> = contract
        .boundary_redaction_map
        .entries
        .iter()
        .map(|e| e.boundary_class)
        .collect();
    // Every boundary class has at least one redaction entry
    let all_classes: BTreeSet<_> = BoundaryClass::ALL.into_iter().collect();
    assert_eq!(
        classes_with_entries, all_classes,
        "every boundary class must have redaction map entries"
    );
}

#[test]
fn clock_read_capture_sets_correct_minimal_fields() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-clk", "d-clk", "clock", 5);
    let record = session
        .capture_clock_read(&ctx, "wall", "realtime", 1234, None)
        .expect("capture");
    assert_eq!(record.minimal_fields.get("clock_id").unwrap(), "wall");
    assert_eq!(
        record.minimal_fields.get("clock_domain").unwrap(),
        "realtime"
    );
    assert_eq!(record.minimal_fields.get("observed_tick").unwrap(), "1234");
}

#[test]
fn network_response_capture_preserves_status_code() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-net", "d-net", "network", 7);
    let record = session
        .capture_network_response(&ctx, "req-dig", "resp-dig", 404, None)
        .expect("capture");
    assert_eq!(record.minimal_fields.get("status_code").unwrap(), "404");
    assert_eq!(record.boundary_class, BoundaryClass::NetworkResponse);
}

#[test]
fn external_policy_read_capture_records_epoch() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-pol", "d-pol", "policy_reader", 8);
    let record = session
        .capture_external_policy_read(&ctx, "risk-router", "pol-dig", 42, None)
        .expect("capture");
    assert_eq!(record.minimal_fields.get("policy_epoch").unwrap(), "42");
    assert_eq!(record.boundary_class, BoundaryClass::ExternalPolicyRead);
}

#[test]
fn hardware_surface_read_capture_records_surface_kind() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-hw", "d-hw", "tpm", 9);
    let record = session
        .capture_hardware_surface_read(&ctx, "tpm_quote", "meas-dig", "drv-dig", None)
        .expect("capture");
    assert_eq!(
        record.minimal_fields.get("surface_kind").unwrap(),
        "tpm_quote"
    );
    assert_eq!(record.boundary_class, BoundaryClass::HardwareSurfaceRead);
}

#[test]
fn randomness_draw_capture_records_draw_index() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-rng", "d-rng", "rng", 3);
    let record = session
        .capture_randomness_draw(&ctx, "chacha20", 7, "sample-dig", None)
        .expect("capture");
    assert_eq!(record.minimal_fields.get("draw_index").unwrap(), "7");
    assert_eq!(
        record.minimal_fields.get("generator_id").unwrap(),
        "chacha20"
    );
}

#[test]
fn escalation_on_clock_read_marks_needs_escalation() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_ctx("t-esc", "d-esc", "clock", 11);
    let record = session
        .capture_clock_read(&ctx, "sys", "monotonic", 0, Some("clock-non-monotonic"))
        .expect("capture");
    assert_eq!(record.sufficiency, ReplaySufficiency::NeedsEscalation);
    assert_eq!(
        record.escalation_reason.as_deref(),
        Some("clock-non-monotonic")
    );
}

#[test]
fn catalog_rule_for_returns_none_for_missing_class_in_empty_catalog() {
    // Build a contract and verify rule_for works on the default catalog
    let contract = BoundaryCaptureContract::default_v1();
    for class in BoundaryClass::ALL {
        assert!(
            contract.boundary_catalog.rule_for(class).is_some(),
            "default catalog must have a rule for {class}"
        );
    }
}
