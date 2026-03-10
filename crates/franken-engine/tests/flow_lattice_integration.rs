//! Integration tests for the `flow_lattice` module.
//!
//! Tests IFC flow-lattice semantics: label classes, clearance, declassification
//! obligations, Ir2FlowLattice engine, data source/sink assignment, and serde.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::flow_lattice::{
    Clearance, DataSource, DeclassificationObligation, FlowCheckResult, FlowLatticeError,
    FlowLatticeEvent, Ir2FlowLattice, LabelClass, SinkKind, assign_label, sink_clearance,
};
use frankenengine_engine::ifc_artifacts::Label;

// ---------------------------------------------------------------------------
// LabelClass — ordering, join, meet
// ---------------------------------------------------------------------------

#[test]
fn label_class_levels_are_strictly_increasing() {
    let labels = [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ];
    for pair in labels.windows(2) {
        assert!(pair[0].level() < pair[1].level());
    }
}

#[test]
fn label_join_is_commutative_exhaustive() {
    let all = [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ];
    for a in &all {
        for b in &all {
            assert_eq!(a.join(b), b.join(a));
        }
    }
}

#[test]
fn label_meet_is_commutative_exhaustive() {
    let all = [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ];
    for a in &all {
        for b in &all {
            assert_eq!(a.meet(b), b.meet(a));
        }
    }
}

#[test]
fn label_join_idempotent_exhaustive() {
    let all = [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ];
    for l in &all {
        assert_eq!(l.join(l), *l);
    }
}

#[test]
fn label_meet_idempotent_exhaustive() {
    let all = [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ];
    for l in &all {
        assert_eq!(l.meet(l), *l);
    }
}

#[test]
fn label_join_associative() {
    let a = LabelClass::Internal;
    let b = LabelClass::Secret;
    let c = LabelClass::Confidential;
    assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
}

#[test]
fn label_meet_associative() {
    let a = LabelClass::TopSecret;
    let b = LabelClass::Internal;
    let c = LabelClass::Secret;
    assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
}

#[test]
fn label_join_returns_higher_level() {
    assert_eq!(
        LabelClass::Public.join(&LabelClass::TopSecret),
        LabelClass::TopSecret
    );
    assert_eq!(
        LabelClass::Internal.join(&LabelClass::Confidential),
        LabelClass::Confidential
    );
}

#[test]
fn label_meet_returns_lower_level() {
    assert_eq!(
        LabelClass::TopSecret.meet(&LabelClass::Public),
        LabelClass::Public
    );
    assert_eq!(
        LabelClass::Secret.meet(&LabelClass::Internal),
        LabelClass::Internal
    );
}

#[test]
fn label_class_display_all_variants() {
    assert_eq!(format!("{}", LabelClass::Public), "public");
    assert_eq!(format!("{}", LabelClass::Internal), "internal");
    assert_eq!(format!("{}", LabelClass::Confidential), "confidential");
    assert_eq!(format!("{}", LabelClass::Secret), "secret");
    assert_eq!(format!("{}", LabelClass::TopSecret), "top_secret");
}

// ---------------------------------------------------------------------------
// LabelClass <-> Label conversion
// ---------------------------------------------------------------------------

#[test]
fn label_class_to_label_roundtrip_all_standard() {
    let classes = [
        (LabelClass::Public, Label::Public),
        (LabelClass::Internal, Label::Internal),
        (LabelClass::Confidential, Label::Confidential),
        (LabelClass::Secret, Label::Secret),
        (LabelClass::TopSecret, Label::TopSecret),
    ];
    for (class, expected_label) in &classes {
        let label = class.to_label();
        assert_eq!(&label, expected_label);
        let back = LabelClass::from_label(&label);
        assert_eq!(&back, class);
    }
}

#[test]
fn label_class_from_custom_label_maps_by_level() {
    let custom_0 = Label::Custom {
        level: 0,
        name: "custom_pub".to_string(),
    };
    assert_eq!(LabelClass::from_label(&custom_0), LabelClass::Public);

    let custom_3 = Label::Custom {
        level: 3,
        name: "custom_secret".to_string(),
    };
    assert_eq!(LabelClass::from_label(&custom_3), LabelClass::Secret);

    let custom_99 = Label::Custom {
        level: 99,
        name: "ultra".to_string(),
    };
    assert_eq!(LabelClass::from_label(&custom_99), LabelClass::TopSecret);
}

// ---------------------------------------------------------------------------
// Clearance — ordering, join, meet
// ---------------------------------------------------------------------------

#[test]
fn clearance_levels_strictly_increasing() {
    let all = [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ];
    for pair in all.windows(2) {
        assert!(pair[0].level() < pair[1].level());
    }
}

#[test]
fn clearance_join_commutative_exhaustive() {
    let all = [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ];
    for a in &all {
        for b in &all {
            assert_eq!(a.join(b), b.join(a));
        }
    }
}

#[test]
fn clearance_meet_commutative_exhaustive() {
    let all = [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ];
    for a in &all {
        for b in &all {
            assert_eq!(a.meet(b), b.meet(a));
        }
    }
}

#[test]
fn clearance_idempotent_all() {
    let all = [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ];
    for c in &all {
        assert_eq!(c.join(c), *c);
        assert_eq!(c.meet(c), *c);
    }
}

#[test]
fn clearance_display_all_variants() {
    assert_eq!(format!("{}", Clearance::OpenSink), "open_sink");
    assert_eq!(format!("{}", Clearance::RestrictedSink), "restricted_sink");
    assert_eq!(format!("{}", Clearance::AuditedSink), "audited_sink");
    assert_eq!(format!("{}", Clearance::SealedSink), "sealed_sink");
    assert_eq!(format!("{}", Clearance::NeverSink), "never_sink");
}

#[test]
fn clearance_max_label_level_values() {
    assert_eq!(Clearance::OpenSink.max_label_level(), 4);
    assert_eq!(Clearance::RestrictedSink.max_label_level(), 1);
    assert_eq!(Clearance::AuditedSink.max_label_level(), 2);
    assert_eq!(Clearance::SealedSink.max_label_level(), 3);
    assert_eq!(Clearance::NeverSink.max_label_level(), 0);
}

// ---------------------------------------------------------------------------
// can_flow_to — lattice legality
// ---------------------------------------------------------------------------

#[test]
fn public_can_flow_to_all_clearances() {
    let clearances = [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ];
    // NeverSink max_label_level() = 0, Public level() = 0, so 0 <= 0 is true
    for c in &clearances {
        assert!(
            LabelClass::Public.can_flow_to(c),
            "Public should flow to {c}"
        );
    }
}

#[test]
fn top_secret_can_only_flow_to_open_sink() {
    assert!(LabelClass::TopSecret.can_flow_to(&Clearance::OpenSink));
    assert!(!LabelClass::TopSecret.can_flow_to(&Clearance::RestrictedSink));
    assert!(!LabelClass::TopSecret.can_flow_to(&Clearance::AuditedSink));
    assert!(!LabelClass::TopSecret.can_flow_to(&Clearance::SealedSink));
    assert!(!LabelClass::TopSecret.can_flow_to(&Clearance::NeverSink));
}

#[test]
fn secret_can_flow_to_sealed_and_open() {
    assert!(LabelClass::Secret.can_flow_to(&Clearance::OpenSink));
    assert!(LabelClass::Secret.can_flow_to(&Clearance::SealedSink));
    assert!(!LabelClass::Secret.can_flow_to(&Clearance::AuditedSink));
    assert!(!LabelClass::Secret.can_flow_to(&Clearance::RestrictedSink));
    assert!(!LabelClass::Secret.can_flow_to(&Clearance::NeverSink));
}

#[test]
fn confidential_can_flow_to_audited_and_above() {
    assert!(LabelClass::Confidential.can_flow_to(&Clearance::OpenSink));
    assert!(LabelClass::Confidential.can_flow_to(&Clearance::AuditedSink));
    assert!(LabelClass::Confidential.can_flow_to(&Clearance::SealedSink));
    assert!(!LabelClass::Confidential.can_flow_to(&Clearance::RestrictedSink));
    assert!(!LabelClass::Confidential.can_flow_to(&Clearance::NeverSink));
}

#[test]
fn internal_can_flow_to_restricted_and_above() {
    assert!(LabelClass::Internal.can_flow_to(&Clearance::OpenSink));
    assert!(LabelClass::Internal.can_flow_to(&Clearance::RestrictedSink));
    assert!(LabelClass::Internal.can_flow_to(&Clearance::AuditedSink));
    assert!(LabelClass::Internal.can_flow_to(&Clearance::SealedSink));
    assert!(!LabelClass::Internal.can_flow_to(&Clearance::NeverSink));
}

// ---------------------------------------------------------------------------
// assign_label — data source label assignment
// ---------------------------------------------------------------------------

#[test]
fn assign_label_all_simple_sources() {
    assert_eq!(assign_label(&DataSource::Literal), LabelClass::Public);
    assert_eq!(
        assign_label(&DataSource::EnvironmentVariable),
        LabelClass::Secret
    );
    assert_eq!(
        assign_label(&DataSource::CredentialFileRead),
        LabelClass::Secret
    );
    assert_eq!(
        assign_label(&DataSource::GeneralFileRead),
        LabelClass::Internal
    );
    assert_eq!(
        assign_label(&DataSource::KeyMaterial),
        LabelClass::TopSecret
    );
    assert_eq!(
        assign_label(&DataSource::PolicyProtectedArtifact),
        LabelClass::Confidential
    );
}

#[test]
fn assign_label_hostcall_return_maps_clearance() {
    let cases = [
        (Clearance::OpenSink, LabelClass::Public),
        (Clearance::RestrictedSink, LabelClass::Internal),
        (Clearance::AuditedSink, LabelClass::Confidential),
        (Clearance::SealedSink, LabelClass::Secret),
        (Clearance::NeverSink, LabelClass::TopSecret),
    ];
    for (clearance, expected) in &cases {
        let source = DataSource::HostcallReturn {
            clearance: clearance.clone(),
        };
        assert_eq!(assign_label(&source), *expected);
    }
}

#[test]
fn assign_label_computed_joins_all_inputs() {
    let source = DataSource::Computed {
        input_labels: vec![
            LabelClass::Public,
            LabelClass::Internal,
            LabelClass::Confidential,
        ],
    };
    assert_eq!(assign_label(&source), LabelClass::Confidential);
}

#[test]
fn assign_label_computed_empty_is_public() {
    let source = DataSource::Computed {
        input_labels: vec![],
    };
    assert_eq!(assign_label(&source), LabelClass::Public);
}

#[test]
fn assign_label_declassified_always_public() {
    for original in [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ] {
        let source = DataSource::Declassified {
            original: original.clone(),
        };
        assert_eq!(assign_label(&source), LabelClass::Public);
    }
}

// ---------------------------------------------------------------------------
// sink_clearance — sink kind clearance assignment
// ---------------------------------------------------------------------------

#[test]
fn sink_clearance_all_kinds() {
    assert_eq!(
        sink_clearance(&SinkKind::NetworkEgress),
        Clearance::NeverSink
    );
    assert_eq!(
        sink_clearance(&SinkKind::SubprocessIpc),
        Clearance::NeverSink
    );
    assert_eq!(
        sink_clearance(&SinkKind::PersistenceExport),
        Clearance::SealedSink
    );
    assert_eq!(
        sink_clearance(&SinkKind::DeclassificationEndpoint),
        Clearance::SealedSink
    );
    assert_eq!(
        sink_clearance(&SinkKind::LoggingRedacted),
        Clearance::OpenSink
    );
    assert_eq!(
        sink_clearance(&SinkKind::MetricsExport),
        Clearance::RestrictedSink
    );
}

// ---------------------------------------------------------------------------
// DeclassificationObligation
// ---------------------------------------------------------------------------

fn make_obligation(id: &str, max_uses: u64, use_count: u64) -> DeclassificationObligation {
    DeclassificationObligation {
        obligation_id: id.to_string(),
        source_label: LabelClass::Secret,
        target_clearance: Clearance::NeverSink,
        decision_contract_id: "contract-1".to_string(),
        requires_operator_approval: false,
        max_uses,
        use_count,
    }
}

#[test]
fn obligation_has_remaining_uses_unlimited() {
    let ob = make_obligation("d1", 0, 1000);
    assert!(ob.has_remaining_uses());
}

#[test]
fn obligation_has_remaining_uses_limited() {
    let ob = make_obligation("d1", 5, 3);
    assert!(ob.has_remaining_uses());

    let ob_full = make_obligation("d1", 5, 5);
    assert!(!ob_full.has_remaining_uses());
}

#[test]
fn obligation_record_use_increments() {
    let mut ob = make_obligation("d1", 3, 0);
    ob.record_use().unwrap();
    assert_eq!(ob.use_count, 1);
    ob.record_use().unwrap();
    assert_eq!(ob.use_count, 2);
    ob.record_use().unwrap();
    assert_eq!(ob.use_count, 3);

    let err = ob.record_use().unwrap_err();
    assert_eq!(
        err,
        FlowLatticeError::ObligationExhausted {
            obligation_id: "d1".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// FlowCheckResult
// ---------------------------------------------------------------------------

#[test]
fn flow_check_result_is_legal() {
    assert!(FlowCheckResult::LegalByLattice.is_legal());
    assert!(!FlowCheckResult::LegalByLattice.is_blocked());
}

#[test]
fn flow_check_result_is_blocked() {
    let blocked = FlowCheckResult::Blocked {
        source: LabelClass::Secret,
        sink: Clearance::NeverSink,
    };
    assert!(blocked.is_blocked());
    assert!(!blocked.is_legal());
}

#[test]
fn flow_check_result_requires_declassification() {
    let declass = FlowCheckResult::RequiresDeclassification {
        obligation_id: "d1".to_string(),
    };
    assert!(!declass.is_legal());
    assert!(!declass.is_blocked());
}

// ---------------------------------------------------------------------------
// FlowLatticeError display
// ---------------------------------------------------------------------------

#[test]
fn flow_lattice_error_display_all_variants() {
    let errors = [
        (
            FlowLatticeError::ObligationExhausted {
                obligation_id: "d1".to_string(),
            },
            "exhausted",
        ),
        (
            FlowLatticeError::ObligationNotFound {
                obligation_id: "d2".to_string(),
            },
            "not found",
        ),
        (
            FlowLatticeError::DuplicateObligation {
                obligation_id: "d3".to_string(),
            },
            "duplicate",
        ),
        (
            FlowLatticeError::FlowBlocked {
                detail: "secret->never".to_string(),
            },
            "blocked",
        ),
    ];
    for (err, expected_substr) in &errors {
        let msg = format!("{err}");
        assert!(
            msg.contains(expected_substr),
            "'{msg}' should contain '{expected_substr}'"
        );
    }
}

#[test]
fn flow_lattice_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(FlowLatticeError::FlowBlocked {
        detail: "test".to_string(),
    });
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Ir2FlowLattice — flow checking
// ---------------------------------------------------------------------------

#[test]
fn lattice_legal_flow_by_lattice() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    let result = lattice.check_flow(&LabelClass::Public, &Clearance::RestrictedSink, "t1");
    assert_eq!(result, FlowCheckResult::LegalByLattice);
}

#[test]
fn lattice_blocked_flow_no_declassification() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    let result = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t1");
    assert!(result.is_blocked());
}

#[test]
fn lattice_requires_declassification_with_obligation() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    lattice
        .register_obligation(make_obligation("declass-1", 0, 0))
        .unwrap();
    let result = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t1");
    assert_eq!(
        result,
        FlowCheckResult::RequiresDeclassification {
            obligation_id: "declass-1".to_string()
        }
    );
}

#[test]
fn lattice_exhausted_obligation_blocks() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    lattice
        .register_obligation(make_obligation("declass-1", 1, 1))
        .unwrap();
    let result = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t1");
    assert!(result.is_blocked());
}

#[test]
fn lattice_use_declassification_success() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    lattice
        .register_obligation(make_obligation("d1", 3, 0))
        .unwrap();
    lattice.use_declassification("d1", "t1").unwrap();
    lattice.use_declassification("d1", "t2").unwrap();
    lattice.use_declassification("d1", "t3").unwrap();
    let err = lattice.use_declassification("d1", "t4").unwrap_err();
    assert_eq!(
        err,
        FlowLatticeError::ObligationExhausted {
            obligation_id: "d1".to_string()
        }
    );
}

#[test]
fn lattice_use_declassification_not_found() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    let err = lattice
        .use_declassification("nonexistent", "t1")
        .unwrap_err();
    assert_eq!(
        err,
        FlowLatticeError::ObligationNotFound {
            obligation_id: "nonexistent".to_string()
        }
    );
}

#[test]
fn lattice_duplicate_obligation_rejected() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    lattice
        .register_obligation(make_obligation("d1", 0, 0))
        .unwrap();
    let err = lattice
        .register_obligation(make_obligation("d1", 5, 0))
        .unwrap_err();
    assert_eq!(
        err,
        FlowLatticeError::DuplicateObligation {
            obligation_id: "d1".to_string()
        }
    );
}

#[test]
fn lattice_unlimited_obligation_many_uses() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    lattice
        .register_obligation(make_obligation("d1", 0, 0))
        .unwrap();
    for i in 0..100 {
        lattice
            .use_declassification("d1", &format!("t{i}"))
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Ir2FlowLattice — label propagation and source/sink assignment
// ---------------------------------------------------------------------------

#[test]
fn lattice_propagate_empty_is_public() {
    let lattice = Ir2FlowLattice::new("test-policy");
    assert_eq!(lattice.propagate_labels(&[]), LabelClass::Public);
}

#[test]
fn lattice_propagate_joins_all_labels() {
    let lattice = Ir2FlowLattice::new("test-policy");
    let result = lattice.propagate_labels(&[
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::TopSecret,
        LabelClass::Confidential,
    ]);
    assert_eq!(result, LabelClass::TopSecret);
}

#[test]
fn lattice_assign_source_label_delegates() {
    let lattice = Ir2FlowLattice::new("test-policy");
    assert_eq!(
        lattice.assign_source_label(&DataSource::KeyMaterial),
        LabelClass::TopSecret
    );
}

#[test]
fn lattice_assign_sink_clearance_delegates() {
    let lattice = Ir2FlowLattice::new("test-policy");
    assert_eq!(
        lattice.assign_sink_clearance(&SinkKind::NetworkEgress),
        Clearance::NeverSink
    );
}

// ---------------------------------------------------------------------------
// Ir2FlowLattice — events
// ---------------------------------------------------------------------------

#[test]
fn lattice_events_recorded_for_flow_checks() {
    let mut lattice = Ir2FlowLattice::new("policy-42");
    lattice.check_flow(&LabelClass::Public, &Clearance::OpenSink, "t1");
    lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t2");

    let events = lattice.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].outcome, "legal_by_lattice");
    assert_eq!(events[0].trace_id, "t1");
    assert_eq!(events[0].policy_id, "policy-42");
    assert_eq!(events[1].outcome, "blocked");
    assert_eq!(events[1].error_code.as_deref(), Some("FLOW_BLOCKED"));
}

#[test]
fn lattice_event_for_declassification_use() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    lattice
        .register_obligation(make_obligation("d1", 0, 0))
        .unwrap();
    lattice.use_declassification("d1", "trace-declass").unwrap();

    let events = lattice.events();
    assert!(
        events
            .iter()
            .any(|e| e.event == "use_declassification" && e.outcome == "ok")
    );
}

#[test]
fn lattice_obligations_accessor() {
    let mut lattice = Ir2FlowLattice::new("test-policy");
    assert!(lattice.obligations().is_empty());
    lattice
        .register_obligation(make_obligation("d1", 0, 0))
        .unwrap();
    assert_eq!(lattice.obligations().len(), 1);
    assert!(lattice.obligations().contains_key("d1"));
}

// ---------------------------------------------------------------------------
// Exfiltration scenario
// ---------------------------------------------------------------------------

#[test]
fn exfiltration_scenario_env_to_network_blocked() {
    let mut lattice = Ir2FlowLattice::new("test-policy");

    let api_key_label = lattice.assign_source_label(&DataSource::EnvironmentVariable);
    assert_eq!(api_key_label, LabelClass::Secret);

    let prefix_label = lattice.assign_source_label(&DataSource::Literal);
    assert_eq!(prefix_label, LabelClass::Public);

    let header_label = lattice.propagate_labels(&[prefix_label, api_key_label]);
    assert_eq!(header_label, LabelClass::Secret);

    let sink = lattice.assign_sink_clearance(&SinkKind::NetworkEgress);
    assert_eq!(sink, Clearance::NeverSink);

    let result = lattice.check_flow(&header_label, &sink, "exfil-check");
    assert!(result.is_blocked());
}

#[test]
fn logging_scenario_internal_to_log_allowed() {
    let mut lattice = Ir2FlowLattice::new("test-policy");

    let file_label = lattice.assign_source_label(&DataSource::GeneralFileRead);
    assert_eq!(file_label, LabelClass::Internal);

    let sink = lattice.assign_sink_clearance(&SinkKind::LoggingRedacted);
    assert_eq!(sink, Clearance::OpenSink);

    let result = lattice.check_flow(&file_label, &sink, "log-check");
    assert!(result.is_legal());
}

#[test]
fn key_material_to_metrics_blocked() {
    let mut lattice = Ir2FlowLattice::new("test-policy");

    let key_label = lattice.assign_source_label(&DataSource::KeyMaterial);
    let sink = lattice.assign_sink_clearance(&SinkKind::MetricsExport);

    let result = lattice.check_flow(&key_label, &sink, "key-metrics");
    assert!(result.is_blocked());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn label_class_serde_roundtrip_all() {
    for label in [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ] {
        let json = serde_json::to_string(&label).unwrap();
        let decoded: LabelClass = serde_json::from_str(&json).unwrap();
        assert_eq!(label, decoded);
    }
}

#[test]
fn clearance_serde_roundtrip_all() {
    for c in [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let decoded: Clearance = serde_json::from_str(&json).unwrap();
        assert_eq!(c, decoded);
    }
}

#[test]
fn data_source_serde_roundtrip() {
    let sources = vec![
        DataSource::Literal,
        DataSource::EnvironmentVariable,
        DataSource::CredentialFileRead,
        DataSource::GeneralFileRead,
        DataSource::KeyMaterial,
        DataSource::PolicyProtectedArtifact,
        DataSource::HostcallReturn {
            clearance: Clearance::SealedSink,
        },
        DataSource::Computed {
            input_labels: vec![LabelClass::Public, LabelClass::Secret],
        },
        DataSource::Declassified {
            original: LabelClass::TopSecret,
        },
    ];
    for source in &sources {
        let json = serde_json::to_string(source).unwrap();
        let decoded: DataSource = serde_json::from_str(&json).unwrap();
        assert_eq!(source, &decoded);
    }
}

#[test]
fn sink_kind_serde_roundtrip() {
    let sinks = [
        SinkKind::NetworkEgress,
        SinkKind::SubprocessIpc,
        SinkKind::PersistenceExport,
        SinkKind::DeclassificationEndpoint,
        SinkKind::LoggingRedacted,
        SinkKind::MetricsExport,
    ];
    for sink in &sinks {
        let json = serde_json::to_string(sink).unwrap();
        let decoded: SinkKind = serde_json::from_str(&json).unwrap();
        assert_eq!(sink, &decoded);
    }
}

#[test]
fn obligation_serde_roundtrip() {
    let ob = DeclassificationObligation {
        obligation_id: "d1".to_string(),
        source_label: LabelClass::Secret,
        target_clearance: Clearance::NeverSink,
        decision_contract_id: "c1".to_string(),
        requires_operator_approval: true,
        max_uses: 5,
        use_count: 2,
    };
    let json = serde_json::to_string(&ob).unwrap();
    let decoded: DeclassificationObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(ob, decoded);
}

#[test]
fn flow_check_result_serde_roundtrip() {
    let results = vec![
        FlowCheckResult::LegalByLattice,
        FlowCheckResult::RequiresDeclassification {
            obligation_id: "d1".to_string(),
        },
        FlowCheckResult::Blocked {
            source: LabelClass::Secret,
            sink: Clearance::NeverSink,
        },
    ];
    for r in &results {
        let json = serde_json::to_string(r).unwrap();
        let decoded: FlowCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, &decoded);
    }
}

#[test]
fn flow_lattice_error_serde_roundtrip() {
    let errors = vec![
        FlowLatticeError::ObligationExhausted {
            obligation_id: "d1".to_string(),
        },
        FlowLatticeError::ObligationNotFound {
            obligation_id: "d2".to_string(),
        },
        FlowLatticeError::DuplicateObligation {
            obligation_id: "d3".to_string(),
        },
        FlowLatticeError::FlowBlocked {
            detail: "reason".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: FlowLatticeError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &decoded);
    }
}

#[test]
fn flow_lattice_event_serde_roundtrip() {
    let event = FlowLatticeEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "flow_lattice".to_string(),
        event: "check_flow".to_string(),
        outcome: "legal_by_lattice".to_string(),
        error_code: Some("NONE".to_string()),
        obligation_id: None,
        decision_contract_id: None,
        receipt_id: None,
        receipt_replay_command: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: FlowLatticeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn flow_check_deterministic() {
    let run = || {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        lattice
            .register_obligation(make_obligation("d1", 5, 0))
            .unwrap();
        let r1 = lattice.check_flow(&LabelClass::Public, &Clearance::OpenSink, "t1");
        let r2 = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t2");
        let r3 = lattice.check_flow(&LabelClass::TopSecret, &Clearance::NeverSink, "t3");
        (r1, r2, r3)
    };

    let a = run();
    let b = run();
    assert_eq!(a, b);
}
