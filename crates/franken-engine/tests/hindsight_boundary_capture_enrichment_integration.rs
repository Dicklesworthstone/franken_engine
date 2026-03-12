//! Enrichment integration tests for `hindsight_boundary_capture` module.
//!
//! Covers: BoundaryClass, PrivacyClass, RedactionTreatment, ReplaySufficiency,
//! FieldContract, EscalationCase, FieldPrivacyMetadata, BoundaryRule,
//! BoundaryCatalog, MinimalReplayInputSchema, BoundaryRedactionMap,
//! BoundaryCaptureContract, BoundaryContext, BoundaryCaptureRequest,
//! BoundaryCaptureRecord, BoundaryCaptureLog, BoundaryCaptureSession,
//! BoundaryCaptureError, MinimalReplayPlan — Display, serde, lifecycle, errors.

use std::collections::BTreeSet;

use frankenengine_engine::hindsight_boundary_capture::*;

// ── BoundaryClass ────────────────────────────────────────────────────────

#[test]
fn enrichment_boundary_class_all_count() {
    assert_eq!(BoundaryClass::ALL.len(), 9);
}

#[test]
fn enrichment_boundary_class_display_unique() {
    let displays: BTreeSet<String> = BoundaryClass::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 9);
}

#[test]
fn enrichment_boundary_class_as_str_matches_display() {
    for c in &BoundaryClass::ALL {
        assert_eq!(c.as_str(), c.to_string());
    }
}

#[test]
fn enrichment_boundary_class_as_str_snake_case() {
    for c in &BoundaryClass::ALL {
        let s = c.as_str();
        assert!(!s.is_empty());
        assert!(s.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'));
    }
}

#[test]
fn enrichment_boundary_class_serde_all() {
    for c in &BoundaryClass::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: BoundaryClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn enrichment_boundary_class_serde_snake_case_format() {
    let json = serde_json::to_string(&BoundaryClass::ClockRead).unwrap();
    assert!(json.contains("clock_read"));
}

// ── PrivacyClass ─────────────────────────────────────────────────────────

#[test]
fn enrichment_privacy_class_serde_all() {
    for pc in [
        PrivacyClass::PublicMetadata,
        PrivacyClass::PathDigest,
        PrivacyClass::SecretDigest,
        PrivacyClass::PolicyDigest,
        PrivacyClass::HardwareFingerprint,
    ] {
        let json = serde_json::to_string(&pc).unwrap();
        let back: PrivacyClass = serde_json::from_str(&json).unwrap();
        assert_eq!(pc, back);
    }
}

#[test]
fn enrichment_privacy_class_serde_unique_json() {
    let jsons: BTreeSet<String> = [
        PrivacyClass::PublicMetadata,
        PrivacyClass::PathDigest,
        PrivacyClass::SecretDigest,
        PrivacyClass::PolicyDigest,
        PrivacyClass::HardwareFingerprint,
    ].iter().map(|p| serde_json::to_string(p).unwrap()).collect();
    assert_eq!(jsons.len(), 5);
}

// ── RedactionTreatment ───────────────────────────────────────────────────

#[test]
fn enrichment_redaction_treatment_serde_all() {
    for rt in [
        RedactionTreatment::Plaintext,
        RedactionTreatment::DigestOnly,
        RedactionTreatment::Omit,
    ] {
        let json = serde_json::to_string(&rt).unwrap();
        let back: RedactionTreatment = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, back);
    }
}

#[test]
fn enrichment_redaction_treatment_unique_json() {
    let jsons: BTreeSet<String> = [
        RedactionTreatment::Plaintext,
        RedactionTreatment::DigestOnly,
        RedactionTreatment::Omit,
    ].iter().map(|r| serde_json::to_string(r).unwrap()).collect();
    assert_eq!(jsons.len(), 3);
}

// ── ReplaySufficiency ───────────────────────────────────────────────────

#[test]
fn enrichment_replay_sufficiency_serde_all() {
    for rs in [ReplaySufficiency::Sufficient, ReplaySufficiency::NeedsEscalation] {
        let json = serde_json::to_string(&rs).unwrap();
        let back: ReplaySufficiency = serde_json::from_str(&json).unwrap();
        assert_eq!(rs, back);
    }
}

// ── FieldContract / EscalationCase / FieldPrivacyMetadata ───────────────

#[test]
fn enrichment_field_contract_serde() {
    let fc = FieldContract {
        field: "clock_id".into(),
        description: "stable clock identifier".into(),
    };
    let json = serde_json::to_string(&fc).unwrap();
    let back: FieldContract = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, back);
}

#[test]
fn enrichment_escalation_case_serde() {
    let ec = EscalationCase {
        case_id: "clock-non-monotonic".into(),
        description: "clock moved backwards".into(),
    };
    let json = serde_json::to_string(&ec).unwrap();
    let back: EscalationCase = serde_json::from_str(&json).unwrap();
    assert_eq!(ec, back);
}

#[test]
fn enrichment_field_privacy_metadata_serde() {
    let fpm = FieldPrivacyMetadata {
        field: "sample_digest".into(),
        privacy_class: PrivacyClass::SecretDigest,
        treatment: RedactionTreatment::DigestOnly,
    };
    let json = serde_json::to_string(&fpm).unwrap();
    let back: FieldPrivacyMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(fpm, back);
}

// ── BoundaryCatalog ─────────────────────────────────────────────────────

#[test]
fn enrichment_boundary_catalog_default_v1_covers_all_classes() {
    let catalog = BoundaryCatalog::default_v1();
    let classes: Vec<_> = catalog.rules.iter().map(|r| r.boundary_class).collect();
    for c in &BoundaryClass::ALL {
        assert!(classes.contains(c), "missing class: {c}");
    }
    assert_eq!(classes.len(), 9);
}

#[test]
fn enrichment_boundary_catalog_rule_for_all() {
    let catalog = BoundaryCatalog::default_v1();
    for c in &BoundaryClass::ALL {
        assert!(catalog.rule_for(*c).is_some(), "no rule for {c}");
    }
}

#[test]
fn enrichment_boundary_catalog_rule_for_returns_none_invalid() {
    // BoundaryCatalog with empty rules
    let catalog = BoundaryCatalog {
        schema_version: "test".into(),
        bead_id: "test".into(),
        rules: vec![],
    };
    assert!(catalog.rule_for(BoundaryClass::ClockRead).is_none());
}

#[test]
fn enrichment_boundary_catalog_serde_roundtrip() {
    let catalog = BoundaryCatalog::default_v1();
    let json = serde_json::to_string(&catalog).unwrap();
    let back: BoundaryCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, back);
}

#[test]
fn enrichment_boundary_catalog_every_rule_has_fields() {
    let catalog = BoundaryCatalog::default_v1();
    for rule in &catalog.rules {
        assert!(
            !rule.minimal_fields.is_empty(),
            "rule for {:?} has no minimal fields",
            rule.boundary_class
        );
    }
}

#[test]
fn enrichment_boundary_catalog_every_rule_has_escalation() {
    let catalog = BoundaryCatalog::default_v1();
    for rule in &catalog.rules {
        assert!(
            !rule.escalation_cases.is_empty(),
            "rule for {:?} has no escalation cases",
            rule.boundary_class
        );
    }
}

#[test]
fn enrichment_boundary_catalog_every_rule_has_redaction() {
    let catalog = BoundaryCatalog::default_v1();
    for rule in &catalog.rules {
        assert!(
            !rule.redaction_rules.is_empty(),
            "rule for {:?} has no redaction rules",
            rule.boundary_class
        );
    }
}

// ── MinimalReplayInputSchema ────────────────────────────────────────────

#[test]
fn enrichment_minimal_replay_input_schema_from_catalog() {
    let catalog = BoundaryCatalog::default_v1();
    let schema = MinimalReplayInputSchema::from_catalog(&catalog);
    assert_eq!(schema.entries.len(), 9);
    for entry in &schema.entries {
        assert!(!entry.required_fields.is_empty());
        assert!(!entry.sufficiency_rule.is_empty());
    }
}

#[test]
fn enrichment_minimal_replay_input_schema_serde_roundtrip() {
    let catalog = BoundaryCatalog::default_v1();
    let schema = MinimalReplayInputSchema::from_catalog(&catalog);
    let json = serde_json::to_string(&schema).unwrap();
    let back: MinimalReplayInputSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

// ── BoundaryRedactionMap ────────────────────────────────────────────────

#[test]
fn enrichment_boundary_redaction_map_from_catalog() {
    let catalog = BoundaryCatalog::default_v1();
    let map = BoundaryRedactionMap::from_catalog(&catalog);
    // Each rule has 3 fields => 9 * 3 = 27
    assert_eq!(map.entries.len(), 27);
}

#[test]
fn enrichment_boundary_redaction_map_serde_roundtrip() {
    let catalog = BoundaryCatalog::default_v1();
    let map = BoundaryRedactionMap::from_catalog(&catalog);
    let json = serde_json::to_string(&map).unwrap();
    let back: BoundaryRedactionMap = serde_json::from_str(&json).unwrap();
    assert_eq!(map, back);
}

// ── BoundaryCaptureContract ─────────────────────────────────────────────

#[test]
fn enrichment_contract_default_v1_schema_versions() {
    let contract = BoundaryCaptureContract::default_v1();
    assert!(contract.schema_version.starts_with("franken-engine."));
    assert!(contract.boundary_catalog.schema_version.starts_with("franken-engine."));
    assert!(contract.minimal_replay_input_schema.schema_version.starts_with("franken-engine."));
    assert!(contract.boundary_redaction_map.schema_version.starts_with("franken-engine."));
}

#[test]
fn enrichment_contract_serde_roundtrip() {
    let contract = BoundaryCaptureContract::default_v1();
    let json = serde_json::to_string(&contract).unwrap();
    let back: BoundaryCaptureContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn enrichment_contract_bead_id() {
    let contract = BoundaryCaptureContract::default_v1();
    assert_eq!(contract.bead_id, BEAD_ID);
}

// ── BoundaryContext ─────────────────────────────────────────────────────

#[test]
fn enrichment_boundary_context_stores_all_fields() {
    let ctx = BoundaryContext::new("t", "d", "p", "comp", 42);
    assert_eq!(ctx.trace_id, "t");
    assert_eq!(ctx.decision_id, "d");
    assert_eq!(ctx.policy_id, "p");
    assert_eq!(ctx.component, "comp");
    assert_eq!(ctx.virtual_ts, 42);
}

// ── BoundaryCaptureSession — all 9 capture methods ──────────────────────

#[test]
fn enrichment_session_capture_clock_read() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "clock", 1);
    let record = session.capture_clock_read(&ctx, "mono", "monotonic", 100, None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::ClockRead);
    assert_eq!(record.sequence, 0);
    assert_eq!(record.sufficiency, ReplaySufficiency::Sufficient);
}

#[test]
fn enrichment_session_capture_randomness_draw() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "rng", 2);
    let record = session.capture_randomness_draw(&ctx, "seeded", 0, "digest", None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::RandomnessDraw);
}

#[test]
fn enrichment_session_capture_filesystem_input() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "fs", 3);
    let record = session.capture_filesystem_input(&ctx, "read", "path-d", "content-d", None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::FilesystemInput);
}

#[test]
fn enrichment_session_capture_network_response() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "net", 4);
    let record = session.capture_network_response(&ctx, "req-d", "resp-d", 200, None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::NetworkResponse);
}

#[test]
fn enrichment_session_capture_module_resolution() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "mod", 5);
    let record = session.capture_module_resolution(&ctx, "pkg:demo", "ref-d", "resolved-d", None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::ModuleResolution);
}

#[test]
fn enrichment_session_capture_scheduling_decision() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "sched", 6);
    let record = session.capture_scheduling_decision(&ctx, "ready", "task-1", "ord-d", None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::SchedulingDecision);
}

#[test]
fn enrichment_session_capture_controller_override() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "ctrl", 7);
    let record = session.capture_controller_override(&ctx, "router", "safe_mode", "val-d", None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::ControllerOverride);
}

#[test]
fn enrichment_session_capture_external_policy_read() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "policy", 8);
    let record = session.capture_external_policy_read(&ctx, "risk", "pol-d", 42, None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::ExternalPolicyRead);
}

#[test]
fn enrichment_session_capture_hardware_surface_read() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "hw", 9);
    let record = session.capture_hardware_surface_read(&ctx, "tpm", "meas-d", "driver-d", None).unwrap();
    assert_eq!(record.boundary_class, BoundaryClass::HardwareSurfaceRead);
}

// ── Escalation ──────────────────────────────────────────────────────────

#[test]
fn enrichment_escalation_marks_needs_escalation() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "net", 1);
    let record = session.capture_network_response(&ctx, "r", "s", 500, Some("body-needed")).unwrap();
    assert_eq!(record.sufficiency, ReplaySufficiency::NeedsEscalation);
    assert_eq!(record.escalation_reason.as_deref(), Some("body-needed"));
}

#[test]
fn enrichment_escalation_blocks_minimal_replay() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "ctrl", 1);
    session.capture_controller_override(&ctx, "r", "safe", "v", Some("interactive")).unwrap();

    let err = session.minimal_replay_plans().unwrap_err();
    assert!(matches!(err, BoundaryCaptureError::ReplayNeedsEscalation { .. }));
}

// ── Field validation ────────────────────────────────────────────────────

#[test]
fn enrichment_missing_required_field_errors() {
    let mut session = BoundaryCaptureSession::default_v1();
    let request = BoundaryCaptureRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        boundary_class: BoundaryClass::ClockRead,
        virtual_ts: 1,
        minimal_fields: [
            ("clock_domain".to_string(), "monotonic".to_string()),
            ("observed_tick".to_string(), "10".to_string()),
        ].into_iter().collect(),
        escalation_reason: None,
    };
    let err = session.capture_boundary(request).unwrap_err();
    assert!(matches!(err, BoundaryCaptureError::MissingRequiredField { field, .. } if field == "clock_id"));
}

#[test]
fn enrichment_unexpected_field_errors() {
    let mut session = BoundaryCaptureSession::default_v1();
    let request = BoundaryCaptureRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        boundary_class: BoundaryClass::ClockRead,
        virtual_ts: 1,
        minimal_fields: [
            ("clock_id".to_string(), "mono".to_string()),
            ("clock_domain".to_string(), "monotonic".to_string()),
            ("observed_tick".to_string(), "10".to_string()),
            ("extra_field".to_string(), "bad".to_string()),
        ].into_iter().collect(),
        escalation_reason: None,
    };
    let err = session.capture_boundary(request).unwrap_err();
    assert!(matches!(err, BoundaryCaptureError::UnexpectedField { field, .. } if field == "extra_field"));
}

#[test]
fn enrichment_empty_field_value_errors() {
    let mut session = BoundaryCaptureSession::default_v1();
    let request = BoundaryCaptureRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        boundary_class: BoundaryClass::ClockRead,
        virtual_ts: 1,
        minimal_fields: [
            ("clock_id".to_string(), "  ".to_string()),
            ("clock_domain".to_string(), "monotonic".to_string()),
            ("observed_tick".to_string(), "10".to_string()),
        ].into_iter().collect(),
        escalation_reason: None,
    };
    let err = session.capture_boundary(request).unwrap_err();
    assert!(matches!(err, BoundaryCaptureError::EmptyField { field, .. } if field == "clock_id"));
}

// ── BoundaryCaptureError Display ────────────────────────────────────────

#[test]
fn enrichment_error_display_unique() {
    let errors: Vec<BoundaryCaptureError> = vec![
        BoundaryCaptureError::MissingBoundaryRule { boundary_class: BoundaryClass::ClockRead },
        BoundaryCaptureError::MissingRequiredField { boundary_class: BoundaryClass::ClockRead, field: "f".into() },
        BoundaryCaptureError::UnexpectedField { boundary_class: BoundaryClass::ClockRead, field: "f".into() },
        BoundaryCaptureError::EmptyField { boundary_class: BoundaryClass::ClockRead, field: "f".into() },
        BoundaryCaptureError::ReplayNeedsEscalation {
            boundary_class: BoundaryClass::ClockRead,
            correlation_key: "k".into(),
            reason: "r".into(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_error_is_std_error() {
    let e = BoundaryCaptureError::MissingBoundaryRule { boundary_class: BoundaryClass::ClockRead };
    let _: &dyn std::error::Error = &e;
}

// ── BoundaryCaptureLog ──────────────────────────────────────────────────

#[test]
fn enrichment_log_new_empty() {
    let log = BoundaryCaptureLog::new();
    assert!(log.records().is_empty());
}

#[test]
fn enrichment_log_default_equals_new() {
    let a = BoundaryCaptureLog::new();
    let b = BoundaryCaptureLog::default();
    assert_eq!(a.records().len(), b.records().len());
}

#[test]
fn enrichment_log_sequence_monotonic() {
    let mut session = BoundaryCaptureSession::default_v1();
    for i in 0..5u64 {
        let t = format!("t-{i}");
        let d = format!("d-{i}");
        let p = format!("p-{i}");
        let ctx = BoundaryContext::new(&t, &d, &p, "clock", i);
        session.capture_clock_read(&ctx, "mono", "monotonic", i, None).unwrap();
    }
    for (i, r) in session.log().records().iter().enumerate() {
        assert_eq!(r.sequence, i as u64);
    }
}

#[test]
fn enrichment_log_render_jsonl() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "sched", 1);
    session.capture_scheduling_decision(&ctx, "ready", "task-1", "ord", None).unwrap();

    let jsonl = session.log().render_jsonl().unwrap();
    assert!(jsonl.contains("\"boundary_class\":\"scheduling_decision\""));
    assert!(jsonl.contains("\"correlation_key\":\"bcorr_"));
}

// ── Minimal replay plans ────────────────────────────────────────────────

#[test]
fn enrichment_minimal_replay_plan_success() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t1", "d1", "p1", "clock", 1);
    session.capture_clock_read(&ctx, "mono", "monotonic", 100, None).unwrap();

    let plans = session.minimal_replay_plans().unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].trace_id, "t1");
    assert_eq!(plans[0].inputs.len(), 1);
}

#[test]
fn enrichment_minimal_replay_plan_groups_by_trace() {
    let mut session = BoundaryCaptureSession::default_v1();
    // Two records with same trace/decision/policy
    let ctx1 = BoundaryContext::new("t1", "d1", "p1", "clock", 1);
    session.capture_clock_read(&ctx1, "mono", "monotonic", 100, None).unwrap();
    let ctx2 = BoundaryContext::new("t1", "d1", "p1", "rng", 2);
    session.capture_randomness_draw(&ctx2, "seeded", 0, "digest", None).unwrap();

    // One record with different trace
    let ctx3 = BoundaryContext::new("t2", "d2", "p2", "fs", 3);
    session.capture_filesystem_input(&ctx3, "read", "path", "content", None).unwrap();

    let plans = session.minimal_replay_plans().unwrap();
    assert_eq!(plans.len(), 2);
}

// ── Record redaction ────────────────────────────────────────────────────

#[test]
fn enrichment_record_redaction_populated() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "rng", 1);
    let record = session.capture_randomness_draw(&ctx, "seeded", 0, "digest", None).unwrap();

    assert!(!record.redaction.is_empty());
    // sample_digest should have SecretDigest / DigestOnly
    let sample = record.redaction.get("sample_digest").expect("sample_digest redaction");
    assert_eq!(sample.privacy_class, PrivacyClass::SecretDigest);
    assert_eq!(sample.treatment, RedactionTreatment::DigestOnly);
}

#[test]
fn enrichment_record_nondeterminism_tag_from_rule() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "clock", 1);
    let record = session.capture_clock_read(&ctx, "mono", "monotonic", 1, None).unwrap();
    assert_eq!(record.nondeterminism_tag, "clock_read");
}

// ── Correlation key ─────────────────────────────────────────────────────

#[test]
fn enrichment_correlation_key_starts_with_bcorr() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "hw", 1);
    let record = session.capture_hardware_surface_read(&ctx, "tpm", "m", "d", None).unwrap();
    assert!(record.correlation_key.starts_with("bcorr_"));
}

#[test]
fn enrichment_correlation_key_deterministic() {
    let mut s1 = BoundaryCaptureSession::default_v1();
    let mut s2 = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "clock", 1);

    let r1 = s1.capture_clock_read(&ctx, "mono", "monotonic", 1, None).unwrap();
    let r2 = s2.capture_clock_read(&ctx, "mono", "monotonic", 1, None).unwrap();
    assert_eq!(r1.correlation_key, r2.correlation_key);
}

#[test]
fn enrichment_correlation_key_unique_per_sequence() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx1 = BoundaryContext::new("t", "d", "p", "clock", 1);
    let ctx2 = BoundaryContext::new("t2", "d2", "p2", "clock", 2);
    let r1 = session.capture_clock_read(&ctx1, "mono", "monotonic", 1, None).unwrap();
    let r2 = session.capture_clock_read(&ctx2, "mono", "monotonic", 2, None).unwrap();
    assert_ne!(r1.correlation_key, r2.correlation_key);
}

// ── Session accessors ───────────────────────────────────────────────────

#[test]
fn enrichment_session_catalog_accessor() {
    let session = BoundaryCaptureSession::default_v1();
    assert_eq!(session.catalog().rules.len(), 9);
}

#[test]
fn enrichment_session_log_accessor() {
    let session = BoundaryCaptureSession::default_v1();
    assert!(session.log().records().is_empty());
}

// ── Schema version constants ────────────────────────────────────────────

#[test]
fn enrichment_schema_constants_franken_engine_prefix() {
    assert!(CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(BOUNDARY_CATALOG_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(MINIMAL_REPLAY_INPUT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(BOUNDARY_REDACTION_MAP_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_bead_id_constant() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

// ── BoundaryCaptureRecord serde ─────────────────────────────────────────

#[test]
fn enrichment_capture_record_serde_roundtrip() {
    let mut session = BoundaryCaptureSession::default_v1();
    let ctx = BoundaryContext::new("t", "d", "p", "mod", 1);
    let record = session.capture_module_resolution(&ctx, "pkg:demo", "ref", "resolved", None).unwrap();
    let json = serde_json::to_string(&record).unwrap();
    let back: BoundaryCaptureRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ── MinimalReplayInputRecord serde ──────────────────────────────────────

#[test]
fn enrichment_minimal_replay_input_record_serde() {
    let record = MinimalReplayInputRecord {
        correlation_key: "bcorr_abc".into(),
        boundary_class: BoundaryClass::ClockRead,
        component: "clock".into(),
        virtual_ts: 42,
        minimal_fields: [("clock_id".to_string(), "mono".to_string())].into_iter().collect(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: MinimalReplayInputRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ── MinimalReplayPlan serde ─────────────────────────────────────────────

#[test]
fn enrichment_minimal_replay_plan_serde() {
    let plan = MinimalReplayPlan {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        inputs: vec![],
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: MinimalReplayPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

// ── FieldRedactionValue serde ───────────────────────────────────────────

#[test]
fn enrichment_field_redaction_value_serde() {
    let frv = FieldRedactionValue {
        privacy_class: PrivacyClass::HardwareFingerprint,
        treatment: RedactionTreatment::DigestOnly,
    };
    let json = serde_json::to_string(&frv).unwrap();
    let back: FieldRedactionValue = serde_json::from_str(&json).unwrap();
    assert_eq!(frv, back);
}

// ── BoundaryRedactionEntry serde ────────────────────────────────────────

#[test]
fn enrichment_boundary_redaction_entry_serde() {
    let entry = BoundaryRedactionEntry {
        boundary_class: BoundaryClass::NetworkResponse,
        field: "request_digest".into(),
        privacy_class: PrivacyClass::SecretDigest,
        treatment: RedactionTreatment::DigestOnly,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BoundaryRedactionEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ── MinimalReplayInputEntry serde ───────────────────────────────────────

#[test]
fn enrichment_minimal_replay_input_entry_serde() {
    let entry = MinimalReplayInputEntry {
        boundary_class: BoundaryClass::FilesystemInput,
        required_fields: vec!["operation".into(), "path_digest".into()],
        sufficiency_rule: "sufficient unless escalated".into(),
        escalation_cases: vec!["fs-path-needed".into()],
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: MinimalReplayInputEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}
