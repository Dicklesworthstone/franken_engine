#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::hindsight_boundary_capture::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_context<'a>() -> BoundaryContext<'a> {
    BoundaryContext::new("trace-1", "dec-1", "pol-1", "comp-a", 1000)
}

fn make_fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn clock_fields() -> BTreeMap<String, String> {
    make_fields(&[
        ("clock_id", "sys-mono"),
        ("clock_domain", "monotonic"),
        ("observed_tick", "42"),
    ])
}

// ---------------------------------------------------------------------------
// 1. Schema constant formats (5 tests)
// ---------------------------------------------------------------------------

#[test]
fn schema_contract_version_has_expected_prefix() {
    assert!(
        CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."),
        "CONTRACT_SCHEMA_VERSION should start with `franken-engine.`"
    );
    assert!(
        CONTRACT_SCHEMA_VERSION.ends_with(".v1"),
        "CONTRACT_SCHEMA_VERSION should end with `.v1`"
    );
}

#[test]
fn schema_boundary_catalog_version_format() {
    assert!(
        BOUNDARY_CATALOG_SCHEMA_VERSION.starts_with("franken-engine."),
        "BOUNDARY_CATALOG_SCHEMA_VERSION prefix mismatch"
    );
    assert!(BOUNDARY_CATALOG_SCHEMA_VERSION.contains("catalog"));
}

#[test]
fn schema_minimal_replay_input_version_format() {
    assert!(
        MINIMAL_REPLAY_INPUT_SCHEMA_VERSION.starts_with("franken-engine."),
        "MINIMAL_REPLAY_INPUT_SCHEMA_VERSION prefix mismatch"
    );
    assert!(MINIMAL_REPLAY_INPUT_SCHEMA_VERSION.contains("replay"));
}

#[test]
fn schema_boundary_redaction_map_version_format() {
    assert!(
        BOUNDARY_REDACTION_MAP_SCHEMA_VERSION.starts_with("franken-engine."),
        "BOUNDARY_REDACTION_MAP_SCHEMA_VERSION prefix mismatch"
    );
    assert!(BOUNDARY_REDACTION_MAP_SCHEMA_VERSION.contains("redaction"));
}

#[test]
fn schema_boundary_capture_event_version_format() {
    assert!(
        BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION.starts_with("franken-engine."),
        "BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION prefix mismatch"
    );
    assert!(BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION.contains("event"));
}

// ---------------------------------------------------------------------------
// 2. Enum serde round-trips (4 tests)
// ---------------------------------------------------------------------------

#[test]
fn boundary_class_serde_roundtrip() {
    for variant in BoundaryClass::ALL {
        let json = serde_json::to_string(&variant).unwrap();
        let back: BoundaryClass = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn privacy_class_serde_roundtrip() {
    let variants = [
        PrivacyClass::PublicMetadata,
        PrivacyClass::PathDigest,
        PrivacyClass::SecretDigest,
        PrivacyClass::PolicyDigest,
        PrivacyClass::HardwareFingerprint,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: PrivacyClass = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn redaction_treatment_serde_roundtrip() {
    let variants = [
        RedactionTreatment::Plaintext,
        RedactionTreatment::DigestOnly,
        RedactionTreatment::Omit,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: RedactionTreatment = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn replay_sufficiency_serde_roundtrip() {
    let variants = [
        ReplaySufficiency::Sufficient,
        ReplaySufficiency::NeedsEscalation,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ReplaySufficiency = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

// ---------------------------------------------------------------------------
// 3. BoundaryClass::ALL has 9 variants, as_str/Display consistency (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn boundary_class_all_has_nine_variants() {
    assert_eq!(BoundaryClass::ALL.len(), 9);
}

#[test]
fn boundary_class_as_str_matches_display() {
    for variant in BoundaryClass::ALL {
        assert_eq!(
            variant.as_str(),
            variant.to_string().as_str(),
            "as_str and Display should agree for {variant:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. BoundaryCatalog::default_v1() covers all classes, rule_for (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn default_catalog_covers_all_boundary_classes() {
    let catalog = BoundaryCatalog::default_v1();
    for bc in BoundaryClass::ALL {
        assert!(
            catalog.rule_for(bc).is_some(),
            "catalog should contain a rule for {bc:?}"
        );
    }
}

#[test]
fn default_catalog_rule_count_matches_boundary_class_count() {
    let catalog = BoundaryCatalog::default_v1();
    assert_eq!(catalog.rules.len(), BoundaryClass::ALL.len());
}

#[test]
fn rule_for_returns_matching_boundary_class() {
    let catalog = BoundaryCatalog::default_v1();
    for bc in BoundaryClass::ALL {
        let rule = catalog.rule_for(bc).unwrap();
        assert_eq!(rule.boundary_class, bc);
        assert!(!rule.minimal_fields.is_empty());
        assert!(!rule.escalation_cases.is_empty());
        assert!(!rule.redaction_rules.is_empty());
    }
}

// ---------------------------------------------------------------------------
// 5. MinimalReplayInputSchema::from_catalog (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn minimal_replay_input_schema_covers_all_boundary_classes() {
    let catalog = BoundaryCatalog::default_v1();
    let schema = MinimalReplayInputSchema::from_catalog(&catalog);
    assert_eq!(schema.entries.len(), BoundaryClass::ALL.len());
    let classes: Vec<_> = schema.entries.iter().map(|e| e.boundary_class).collect();
    for bc in BoundaryClass::ALL {
        assert!(
            classes.contains(&bc),
            "schema should contain entry for {bc:?}"
        );
    }
}

#[test]
fn minimal_replay_input_schema_has_correct_versions() {
    let catalog = BoundaryCatalog::default_v1();
    let schema = MinimalReplayInputSchema::from_catalog(&catalog);
    assert_eq!(schema.schema_version, MINIMAL_REPLAY_INPUT_SCHEMA_VERSION);
    assert_eq!(schema.bead_id, BEAD_ID);
}

// ---------------------------------------------------------------------------
// 6. BoundaryRedactionMap::from_catalog (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn boundary_redaction_map_from_catalog_generates_entries() {
    let catalog = BoundaryCatalog::default_v1();
    let map = BoundaryRedactionMap::from_catalog(&catalog);
    // Each rule has 3 fields * 9 rules = 27 entries
    assert_eq!(map.entries.len(), 27);
}

#[test]
fn boundary_redaction_map_schema_version_and_bead_id() {
    let catalog = BoundaryCatalog::default_v1();
    let map = BoundaryRedactionMap::from_catalog(&catalog);
    assert_eq!(map.schema_version, BOUNDARY_REDACTION_MAP_SCHEMA_VERSION);
    assert_eq!(map.bead_id, BEAD_ID);
}

// ---------------------------------------------------------------------------
// 7. BoundaryCaptureContract::default_v1() (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn default_contract_has_correct_schema_and_bead() {
    let contract = BoundaryCaptureContract::default_v1();
    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, BEAD_ID);
}

#[test]
fn default_contract_sub_schemas_match_catalog() {
    let contract = BoundaryCaptureContract::default_v1();
    let standalone_replay = MinimalReplayInputSchema::from_catalog(&contract.boundary_catalog);
    let standalone_redaction = BoundaryRedactionMap::from_catalog(&contract.boundary_catalog);
    assert_eq!(contract.minimal_replay_input_schema, standalone_replay);
    assert_eq!(contract.boundary_redaction_map, standalone_redaction);
}

// ---------------------------------------------------------------------------
// 8. Full capture session workflow (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn capture_all_nine_boundary_types_via_typed_methods() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();

    session
        .capture_clock_read(&ctx, "sys-mono", "monotonic", 42, None)
        .unwrap();
    session
        .capture_randomness_draw(&ctx, "prng-0", 0, "d1g3st", None)
        .unwrap();
    session
        .capture_filesystem_input(&ctx, "read", "path-hash", "content-hash", None)
        .unwrap();
    session
        .capture_network_response(&ctx, "req-hash", "resp-hash", 200, None)
        .unwrap();
    session
        .capture_module_resolution(&ctx, "./mod", "ref-hash", "resolved-hash", None)
        .unwrap();
    session
        .capture_scheduling_decision(&ctx, "q1", "t1", "ord-hash", None)
        .unwrap();
    session
        .capture_controller_override(&ctx, "ctrl-1", "force-route", "val-hash", None)
        .unwrap();
    session
        .capture_external_policy_read(&ctx, "csp", "pol-hash", 7, None)
        .unwrap();
    session
        .capture_hardware_surface_read(&ctx, "gpu", "meas-hash", "drv-hash", None)
        .unwrap();

    assert_eq!(session.log().records().len(), 9);
}

#[test]
fn captured_records_have_correct_boundary_classes() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();

    let r0 = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    let r1 = session
        .capture_randomness_draw(&ctx, "rng", 0, "d", None)
        .unwrap();

    assert_eq!(r0.boundary_class, BoundaryClass::ClockRead);
    assert_eq!(r1.boundary_class, BoundaryClass::RandomnessDraw);
}

#[test]
fn captured_record_fields_match_input() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();

    let record = session
        .capture_clock_read(&ctx, "sys-mono", "monotonic", 42, None)
        .unwrap();

    assert_eq!(record.trace_id, "trace-1");
    assert_eq!(record.decision_id, "dec-1");
    assert_eq!(record.policy_id, "pol-1");
    assert_eq!(record.component, "comp-a");
    assert_eq!(record.virtual_ts, 1000);
    assert_eq!(record.minimal_fields.get("clock_id").unwrap(), "sys-mono");
    assert_eq!(
        record.minimal_fields.get("clock_domain").unwrap(),
        "monotonic"
    );
    assert_eq!(record.minimal_fields.get("observed_tick").unwrap(), "42");
    assert_eq!(record.sufficiency, ReplaySufficiency::Sufficient);
    assert!(record.escalation_reason.is_none());
}

// ---------------------------------------------------------------------------
// 9. Error cases (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn error_missing_required_field() {
    let mut session = BoundaryCaptureSession::default_v1();
    // Missing "observed_tick"
    let fields = make_fields(&[("clock_id", "sys"), ("clock_domain", "mono")]);
    let request = BoundaryCaptureRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        boundary_class: BoundaryClass::ClockRead,
        virtual_ts: 1,
        minimal_fields: fields,
        escalation_reason: None,
    };
    let err = session.capture_boundary(request).unwrap_err();
    assert!(
        matches!(err, BoundaryCaptureError::MissingRequiredField { .. }),
        "expected MissingRequiredField, got {err:?}"
    );
}

#[test]
fn error_unexpected_field() {
    let mut session = BoundaryCaptureSession::default_v1();
    let mut fields = clock_fields();
    fields.insert("bogus_field".into(), "x".into());
    let request = BoundaryCaptureRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        boundary_class: BoundaryClass::ClockRead,
        virtual_ts: 1,
        minimal_fields: fields,
        escalation_reason: None,
    };
    let err = session.capture_boundary(request).unwrap_err();
    assert!(
        matches!(err, BoundaryCaptureError::UnexpectedField { .. }),
        "expected UnexpectedField, got {err:?}"
    );
}

#[test]
fn error_empty_field() {
    let mut session = BoundaryCaptureSession::default_v1();
    let fields = make_fields(&[
        ("clock_id", "sys"),
        ("clock_domain", ""),
        ("observed_tick", "42"),
    ]);
    let request = BoundaryCaptureRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        boundary_class: BoundaryClass::ClockRead,
        virtual_ts: 1,
        minimal_fields: fields,
        escalation_reason: None,
    };
    let err = session.capture_boundary(request).unwrap_err();
    assert!(
        matches!(err, BoundaryCaptureError::EmptyField { .. }),
        "expected EmptyField, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 10. Replay plans (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn replay_plan_single_trace() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    session
        .capture_randomness_draw(&ctx, "rng", 0, "d", None)
        .unwrap();

    let plans = session.minimal_replay_plans().unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].trace_id, "trace-1");
    assert_eq!(plans[0].inputs.len(), 2);
}

#[test]
fn replay_plan_multiple_traces() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx1 = BoundaryContext::new("trace-A", "dec-A", "pol-A", "comp", 100);
    let ctx2 = BoundaryContext::new("trace-B", "dec-B", "pol-B", "comp", 200);

    session
        .capture_clock_read(&ctx1, "clk", "mono", 1, None)
        .unwrap();
    session
        .capture_clock_read(&ctx2, "clk", "mono", 2, None)
        .unwrap();

    let plans = session.minimal_replay_plans().unwrap();
    assert_eq!(plans.len(), 2);

    let trace_ids: Vec<_> = plans.iter().map(|p| p.trace_id.as_str()).collect();
    assert!(trace_ids.contains(&"trace-A"));
    assert!(trace_ids.contains(&"trace-B"));
}

#[test]
fn replay_plan_escalation_blocks_replay() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    session
        .capture_clock_read(&ctx, "clk", "mono", 1, Some("non-monotonic detected"))
        .unwrap();

    let err = session.minimal_replay_plans().unwrap_err();
    assert!(
        matches!(err, BoundaryCaptureError::ReplayNeedsEscalation { .. }),
        "expected ReplayNeedsEscalation, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 11. JSONL rendering (1 test)
// ---------------------------------------------------------------------------

#[test]
fn jsonl_rendering_produces_valid_json_lines() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    session
        .capture_randomness_draw(&ctx, "rng", 0, "d", None)
        .unwrap();

    let jsonl = session.log().render_jsonl().unwrap();
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(parsed.is_object());
    }
}

// ---------------------------------------------------------------------------
// 12. Record serde round-trip (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn boundary_capture_record_serde_roundtrip() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    let record = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();

    let json = serde_json::to_string(&record).unwrap();
    let back: BoundaryCaptureRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn boundary_capture_record_with_escalation_serde_roundtrip() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    let record = session
        .capture_clock_read(&ctx, "clk", "mono", 1, Some("clock drift"))
        .unwrap();

    assert_eq!(record.sufficiency, ReplaySufficiency::NeedsEscalation);
    assert_eq!(record.escalation_reason.as_deref(), Some("clock drift"));

    let json = serde_json::to_string(&record).unwrap();
    let back: BoundaryCaptureRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ---------------------------------------------------------------------------
// 13. Correlation key stability and uniqueness (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn correlation_key_is_stable_for_same_inputs() {
    let mut s1 = BoundaryCaptureSession::default_v1();
    let mut s2 = BoundaryCaptureSession::default_v1();
    let ctx = make_context();

    let r1 = s1.capture_clock_read(&ctx, "clk", "mono", 1, None).unwrap();
    let r2 = s2.capture_clock_read(&ctx, "clk", "mono", 1, None).unwrap();

    assert_eq!(r1.correlation_key, r2.correlation_key);
}

#[test]
fn correlation_keys_are_unique_across_captures() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();

    let r1 = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    let r2 = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();

    // Different sequence numbers yield different keys even with identical fields
    assert_ne!(r1.correlation_key, r2.correlation_key);
}

// ---------------------------------------------------------------------------
// 14. Sequence numbering (1 test)
// ---------------------------------------------------------------------------

#[test]
fn sequence_numbers_increment_monotonically() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();

    for i in 0..5u64 {
        let record = session
            .capture_clock_read(&ctx, "clk", "mono", i, None)
            .unwrap();
        assert_eq!(record.sequence, i);
    }
    assert_eq!(session.log().records().len(), 5);
}

// ---------------------------------------------------------------------------
// 15. BoundaryCaptureError Display formatting (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn error_display_missing_boundary_rule() {
    let err = BoundaryCaptureError::MissingBoundaryRule {
        boundary_class: BoundaryClass::ClockRead,
    };
    let msg = err.to_string();
    assert!(msg.contains("missing boundary rule"));
    assert!(msg.contains("clock_read"));
}

#[test]
fn error_display_missing_required_field() {
    let err = BoundaryCaptureError::MissingRequiredField {
        boundary_class: BoundaryClass::RandomnessDraw,
        field: "generator_id".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("missing required field"));
    assert!(msg.contains("generator_id"));
    assert!(msg.contains("randomness_draw"));
}

#[test]
fn error_display_replay_needs_escalation() {
    let err = BoundaryCaptureError::ReplayNeedsEscalation {
        boundary_class: BoundaryClass::NetworkResponse,
        correlation_key: "bcorr_abc123".into(),
        reason: "rich body needed".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("requires escalation"));
    assert!(msg.contains("network_response"));
    assert!(msg.contains("bcorr_abc123"));
    assert!(msg.contains("rich body needed"));
}

// ---------------------------------------------------------------------------
// 16. Determinism (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn deterministic_capture_produces_identical_records() {
    let build_records = || {
        let mut session = BoundaryCaptureSession::default_v1();
        let ctx = make_context();
        session
            .capture_clock_read(&ctx, "clk", "mono", 1, None)
            .unwrap();
        session
            .capture_randomness_draw(&ctx, "rng", 0, "d", None)
            .unwrap();
        session.log().records().to_vec()
    };

    let run1 = build_records();
    let run2 = build_records();
    assert_eq!(run1, run2);
}

#[test]
fn deterministic_jsonl_rendering_across_runs() {
    let build_jsonl = || {
        let mut session = BoundaryCaptureSession::default_v1();
        let ctx = make_context();
        session
            .capture_clock_read(&ctx, "clk", "mono", 1, None)
            .unwrap();
        session.log().render_jsonl().unwrap()
    };

    let j1 = build_jsonl();
    let j2 = build_jsonl();
    assert_eq!(j1, j2);
}

// ---------------------------------------------------------------------------
// Additional coverage: struct serde round-trips and edge cases
// ---------------------------------------------------------------------------

#[test]
fn boundary_catalog_serde_roundtrip() {
    let catalog = BoundaryCatalog::default_v1();
    let json = serde_json::to_string(&catalog).unwrap();
    let back: BoundaryCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, back);
}

#[test]
fn boundary_capture_contract_serde_roundtrip() {
    let contract = BoundaryCaptureContract::default_v1();
    let json = serde_json::to_string(&contract).unwrap();
    let back: BoundaryCaptureContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn boundary_capture_log_serde_roundtrip() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    session
        .capture_filesystem_input(&ctx, "read", "ph", "ch", None)
        .unwrap();

    let log = session.log();
    let json = serde_json::to_string(log).unwrap();
    let back: BoundaryCaptureLog = serde_json::from_str(&json).unwrap();
    assert_eq!(*log, back);
}

#[test]
fn field_contract_serde_roundtrip() {
    let fc = FieldContract {
        field: "clock_id".into(),
        description: "stable clock identifier".into(),
    };
    let json = serde_json::to_string(&fc).unwrap();
    let back: FieldContract = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, back);
}

#[test]
fn escalation_case_serde_roundtrip() {
    let ec = EscalationCase {
        case_id: "clock-non-monotonic".into(),
        description: "clock moved backwards".into(),
    };
    let json = serde_json::to_string(&ec).unwrap();
    let back: EscalationCase = serde_json::from_str(&json).unwrap();
    assert_eq!(ec, back);
}

#[test]
fn field_privacy_metadata_serde_roundtrip() {
    let fpm = FieldPrivacyMetadata {
        field: "sample_digest".into(),
        privacy_class: PrivacyClass::SecretDigest,
        treatment: RedactionTreatment::DigestOnly,
    };
    let json = serde_json::to_string(&fpm).unwrap();
    let back: FieldPrivacyMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(fpm, back);
}

#[test]
fn field_redaction_value_serde_roundtrip() {
    let frv = FieldRedactionValue {
        privacy_class: PrivacyClass::HardwareFingerprint,
        treatment: RedactionTreatment::Omit,
    };
    let json = serde_json::to_string(&frv).unwrap();
    let back: FieldRedactionValue = serde_json::from_str(&json).unwrap();
    assert_eq!(frv, back);
}

#[test]
fn minimal_replay_input_schema_serde_roundtrip() {
    let catalog = BoundaryCatalog::default_v1();
    let schema = MinimalReplayInputSchema::from_catalog(&catalog);
    let json = serde_json::to_string(&schema).unwrap();
    let back: MinimalReplayInputSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

#[test]
fn boundary_redaction_map_serde_roundtrip() {
    let catalog = BoundaryCatalog::default_v1();
    let map = BoundaryRedactionMap::from_catalog(&catalog);
    let json = serde_json::to_string(&map).unwrap();
    let back: BoundaryRedactionMap = serde_json::from_str(&json).unwrap();
    assert_eq!(map, back);
}

#[test]
fn boundary_class_serde_snake_case() {
    let json = serde_json::to_string(&BoundaryClass::HardwareSurfaceRead).unwrap();
    assert_eq!(json, "\"hardware_surface_read\"");
}

#[test]
fn privacy_class_serde_snake_case() {
    let json = serde_json::to_string(&PrivacyClass::PublicMetadata).unwrap();
    assert_eq!(json, "\"public_metadata\"");
}

#[test]
fn redaction_treatment_serde_snake_case() {
    let json = serde_json::to_string(&RedactionTreatment::DigestOnly).unwrap();
    assert_eq!(json, "\"digest_only\"");
}

#[test]
fn replay_sufficiency_serde_snake_case() {
    let json = serde_json::to_string(&ReplaySufficiency::NeedsEscalation).unwrap();
    assert_eq!(json, "\"needs_escalation\"");
}

#[test]
fn session_catalog_accessor() {
    let session = BoundaryCaptureSession::default_v1();
    let catalog = session.catalog();
    assert_eq!(catalog.schema_version, BOUNDARY_CATALOG_SCHEMA_VERSION);
    assert_eq!(catalog.rules.len(), 9);
}

#[test]
fn bead_id_constant() {
    assert_eq!(BEAD_ID, "bd-1lsy.9.11.1");
}

#[test]
fn record_nondeterminism_tag_matches_rule() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    let record = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    let rule = session
        .catalog()
        .rule_for(BoundaryClass::ClockRead)
        .unwrap();
    assert_eq!(record.nondeterminism_tag, rule.nondeterminism_tag);
}

#[test]
fn record_redaction_map_matches_rule_redaction_rules() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    let record = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    let rule = session
        .catalog()
        .rule_for(BoundaryClass::ClockRead)
        .unwrap();
    assert_eq!(record.redaction.len(), rule.redaction_rules.len());
    for rr in &rule.redaction_rules {
        let frv = record.redaction.get(&rr.field).unwrap();
        assert_eq!(frv.privacy_class, rr.privacy_class);
        assert_eq!(frv.treatment, rr.treatment);
    }
}

#[test]
fn record_schema_version_matches_event_constant() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    let record = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    assert_eq!(record.schema_version, BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION);
}

#[test]
fn empty_log_produces_empty_jsonl() {
    let log = BoundaryCaptureLog::new();
    let jsonl = log.render_jsonl().unwrap();
    assert!(jsonl.is_empty());
}

#[test]
fn empty_log_produces_empty_replay_plans() {
    let session = BoundaryCaptureSession::default_v1();
    let plans = session.minimal_replay_plans().unwrap();
    assert!(plans.is_empty());
}

#[test]
fn correlation_key_starts_with_bcorr_prefix() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    let record = session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();
    assert!(
        record.correlation_key.starts_with("bcorr_"),
        "correlation key should start with `bcorr_` prefix, got: {}",
        record.correlation_key
    );
}

#[test]
fn boundary_capture_error_implements_std_error() {
    let err = BoundaryCaptureError::MissingBoundaryRule {
        boundary_class: BoundaryClass::ClockRead,
    };
    // Verify it implements std::error::Error by calling source()
    let _: &dyn std::error::Error = &err;
    assert!(err.source().is_none());
}

#[test]
fn error_display_unexpected_field_formatting() {
    let err = BoundaryCaptureError::UnexpectedField {
        boundary_class: BoundaryClass::FilesystemInput,
        field: "bogus".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("unexpected"));
    assert!(msg.contains("bogus"));
    assert!(msg.contains("filesystem_input"));
}

#[test]
fn error_display_empty_field_formatting() {
    let err = BoundaryCaptureError::EmptyField {
        boundary_class: BoundaryClass::SchedulingDecision,
        field: "queue_id".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("empty"));
    assert!(msg.contains("queue_id"));
    assert!(msg.contains("scheduling_decision"));
}

#[test]
fn replay_plan_input_records_preserve_minimal_fields() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    session
        .capture_clock_read(&ctx, "sys-mono", "monotonic", 42, None)
        .unwrap();

    let plans = session.minimal_replay_plans().unwrap();
    assert_eq!(plans.len(), 1);
    let input = &plans[0].inputs[0];
    assert_eq!(input.boundary_class, BoundaryClass::ClockRead);
    assert_eq!(input.minimal_fields.get("clock_id").unwrap(), "sys-mono");
    assert_eq!(input.virtual_ts, 1000);
}

#[test]
fn minimal_replay_plan_serde_roundtrip() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    session
        .capture_clock_read(&ctx, "clk", "mono", 1, None)
        .unwrap();

    let plans = session.minimal_replay_plans().unwrap();
    let json = serde_json::to_string(&plans).unwrap();
    let back: Vec<MinimalReplayPlan> = serde_json::from_str(&json).unwrap();
    assert_eq!(plans, back);
}

#[test]
fn minimal_replay_input_entry_has_required_fields_from_rule() {
    let catalog = BoundaryCatalog::default_v1();
    let schema = MinimalReplayInputSchema::from_catalog(&catalog);
    for entry in &schema.entries {
        let rule = catalog.rule_for(entry.boundary_class).unwrap();
        let expected: Vec<String> = rule
            .minimal_fields
            .iter()
            .map(|f| f.field.clone())
            .collect();
        assert_eq!(entry.required_fields, expected);
    }
}

#[test]
fn minimal_replay_input_entry_has_escalation_case_ids_from_rule() {
    let catalog = BoundaryCatalog::default_v1();
    let schema = MinimalReplayInputSchema::from_catalog(&catalog);
    for entry in &schema.entries {
        let rule = catalog.rule_for(entry.boundary_class).unwrap();
        let expected: Vec<String> = rule
            .escalation_cases
            .iter()
            .map(|e| e.case_id.clone())
            .collect();
        assert_eq!(entry.escalation_cases, expected);
    }
}

#[test]
fn boundary_rule_serde_roundtrip() {
    let catalog = BoundaryCatalog::default_v1();
    for rule in &catalog.rules {
        let json = serde_json::to_string(rule).unwrap();
        let back: BoundaryRule = serde_json::from_str(&json).unwrap();
        assert_eq!(*rule, back);
    }
}

#[test]
fn capture_with_escalation_sets_needs_escalation() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = make_context();
    let record = session
        .capture_randomness_draw(&ctx, "rng", 0, "d", Some("unseeded entropy"))
        .unwrap();
    assert_eq!(record.sufficiency, ReplaySufficiency::NeedsEscalation);
    assert_eq!(
        record.escalation_reason.as_deref(),
        Some("unseeded entropy")
    );
}

#[test]
fn boundary_redaction_map_entries_cover_all_rule_fields() {
    let catalog = BoundaryCatalog::default_v1();
    let map = BoundaryRedactionMap::from_catalog(&catalog);
    for rule in &catalog.rules {
        for rr in &rule.redaction_rules {
            let found = map.entries.iter().any(|e| {
                e.boundary_class == rule.boundary_class
                    && e.field == rr.field
                    && e.privacy_class == rr.privacy_class
                    && e.treatment == rr.treatment
            });
            assert!(
                found,
                "redaction map should contain entry for {:?}::{}",
                rule.boundary_class, rr.field
            );
        }
    }
}

#[test]
fn boundary_capture_log_default_is_new() {
    let log1 = BoundaryCaptureLog::new();
    let log2 = BoundaryCaptureLog::default();
    assert_eq!(log1, log2);
}

use std::error::Error;

#[test]
fn boundary_capture_error_source_is_none() {
    let variants: Vec<BoundaryCaptureError> = vec![
        BoundaryCaptureError::MissingBoundaryRule {
            boundary_class: BoundaryClass::ClockRead,
        },
        BoundaryCaptureError::MissingRequiredField {
            boundary_class: BoundaryClass::ClockRead,
            field: "f".into(),
        },
        BoundaryCaptureError::UnexpectedField {
            boundary_class: BoundaryClass::ClockRead,
            field: "f".into(),
        },
        BoundaryCaptureError::EmptyField {
            boundary_class: BoundaryClass::ClockRead,
            field: "f".into(),
        },
        BoundaryCaptureError::ReplayNeedsEscalation {
            boundary_class: BoundaryClass::ClockRead,
            correlation_key: "k".into(),
            reason: "r".into(),
        },
    ];
    for v in &variants {
        assert!(v.source().is_none());
    }
}
