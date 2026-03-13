//! Enrichment integration tests for the `flow_lattice` module.
//!
//! Covers: lattice axiom edge cases, label-clearance flow matrix,
//! declassification obligation lifecycle, data source assignment,
//! sink kind clearance mapping, propagation rules, error Display,
//! serde roundtrips, event emission, and Debug formatting.

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

use std::collections::BTreeSet;

use frankenengine_engine::flow_lattice::{
    Clearance, DataSource, DeclassificationObligation, FlowCheckResult, FlowLatticeError,
    FlowLatticeEvent, Ir2FlowLattice, LabelClass, SinkKind, assign_label, sink_clearance,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_obligation(
    id: &str,
    source: LabelClass,
    target: Clearance,
    max_uses: u64,
) -> DeclassificationObligation {
    DeclassificationObligation {
        obligation_id: id.to_string(),
        source_label: source,
        target_clearance: target,
        decision_contract_id: format!("contract-{id}"),
        requires_operator_approval: false,
        max_uses,
        use_count: 0,
    }
}

// =========================================================================
// A. LabelClass lattice — absorption, boundary, Display
// =========================================================================

#[test]
fn enrichment_label_join_with_public_is_identity() {
    // Public is the bottom element — join with Public returns the other
    for label in [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ] {
        assert_eq!(label.join(&LabelClass::Public), label);
        assert_eq!(LabelClass::Public.join(&label), label);
    }
}

#[test]
fn enrichment_label_meet_with_top_secret_is_identity() {
    // TopSecret is the top element — meet with TopSecret returns the other
    for label in [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ] {
        assert_eq!(label.meet(&LabelClass::TopSecret), label);
        assert_eq!(LabelClass::TopSecret.meet(&label), label);
    }
}

#[test]
fn enrichment_label_join_absorption() {
    // join(a, meet(a, b)) = a
    let a = LabelClass::Confidential;
    let b = LabelClass::Secret;
    assert_eq!(a.join(&a.meet(&b)), a);
}

#[test]
fn enrichment_label_meet_absorption() {
    // meet(a, join(a, b)) = a
    let a = LabelClass::Internal;
    let b = LabelClass::TopSecret;
    assert_eq!(a.meet(&a.join(&b)), a);
}

#[test]
fn enrichment_label_display_all_distinct() {
    let variants = [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ];
    let strings: BTreeSet<_> = variants.iter().map(|l| l.to_string()).collect();
    assert_eq!(strings.len(), 5);
}

#[test]
fn enrichment_label_display_exact_values() {
    assert_eq!(LabelClass::Public.to_string(), "public");
    assert_eq!(LabelClass::Internal.to_string(), "internal");
    assert_eq!(LabelClass::Confidential.to_string(), "confidential");
    assert_eq!(LabelClass::Secret.to_string(), "secret");
    assert_eq!(LabelClass::TopSecret.to_string(), "top_secret");
}

#[test]
fn enrichment_label_serde_all_variants_roundtrip() {
    for label in [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ] {
        let json = serde_json::to_string(&label).unwrap();
        let restored: LabelClass = serde_json::from_str(&json).unwrap();
        assert_eq!(label, restored);
    }
}

#[test]
fn enrichment_label_level_monotonic() {
    let levels: Vec<u32> = [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ]
    .iter()
    .map(|l| l.level())
    .collect();
    for i in 1..levels.len() {
        assert!(levels[i] > levels[i - 1]);
    }
}

#[test]
fn enrichment_label_to_label_roundtrip() {
    for label in [
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::Confidential,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ] {
        let ifc_label = label.to_label();
        let restored = LabelClass::from_label(&ifc_label);
        assert_eq!(label, restored);
    }
}

// =========================================================================
// B. Clearance lattice — operations and Display
// =========================================================================

#[test]
fn enrichment_clearance_display_all_distinct() {
    let variants = [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ];
    let strings: BTreeSet<_> = variants.iter().map(|c| c.to_string()).collect();
    assert_eq!(strings.len(), 5);
}

#[test]
fn enrichment_clearance_display_exact_values() {
    assert_eq!(Clearance::OpenSink.to_string(), "open_sink");
    assert_eq!(Clearance::RestrictedSink.to_string(), "restricted_sink");
    assert_eq!(Clearance::AuditedSink.to_string(), "audited_sink");
    assert_eq!(Clearance::SealedSink.to_string(), "sealed_sink");
    assert_eq!(Clearance::NeverSink.to_string(), "never_sink");
}

#[test]
fn enrichment_clearance_serde_all_variants_roundtrip() {
    for c in [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let restored: Clearance = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
    }
}

#[test]
fn enrichment_clearance_level_monotonic() {
    let levels: Vec<u32> = [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ]
    .iter()
    .map(|c| c.level())
    .collect();
    for i in 1..levels.len() {
        assert!(levels[i] > levels[i - 1]);
    }
}

#[test]
fn enrichment_clearance_join_commutative() {
    let pairs = [
        (Clearance::OpenSink, Clearance::NeverSink),
        (Clearance::RestrictedSink, Clearance::SealedSink),
        (Clearance::AuditedSink, Clearance::OpenSink),
    ];
    for (a, b) in &pairs {
        assert_eq!(a.join(b), b.join(a));
    }
}

#[test]
fn enrichment_clearance_meet_commutative() {
    let pairs = [
        (Clearance::OpenSink, Clearance::NeverSink),
        (Clearance::RestrictedSink, Clearance::SealedSink),
    ];
    for (a, b) in &pairs {
        assert_eq!(a.meet(b), b.meet(a));
    }
}

#[test]
fn enrichment_clearance_max_label_level_open_sink_receives_all() {
    // OpenSink can receive everything up to level 4 (TopSecret)
    assert_eq!(Clearance::OpenSink.max_label_level(), 4);
    assert!(Clearance::OpenSink.can_receive_label(&LabelClass::TopSecret.to_label()));
}

#[test]
fn enrichment_clearance_never_sink_receives_only_public() {
    assert_eq!(Clearance::NeverSink.max_label_level(), 0);
    assert!(Clearance::NeverSink.can_receive_label(&LabelClass::Public.to_label()));
    assert!(!Clearance::NeverSink.can_receive_label(&LabelClass::Internal.to_label()));
}

// =========================================================================
// C. Flow legality matrix — systematic check
// =========================================================================

#[test]
fn enrichment_flow_matrix_public_flows_everywhere() {
    let pub_label = LabelClass::Public;
    for c in [
        Clearance::OpenSink,
        Clearance::RestrictedSink,
        Clearance::AuditedSink,
        Clearance::SealedSink,
        Clearance::NeverSink,
    ] {
        assert!(pub_label.can_flow_to(&c), "Public should flow to {c}");
    }
}

#[test]
fn enrichment_flow_matrix_top_secret_blocked_except_open() {
    let ts = LabelClass::TopSecret;
    assert!(ts.can_flow_to(&Clearance::OpenSink));
    assert!(!ts.can_flow_to(&Clearance::RestrictedSink));
    assert!(!ts.can_flow_to(&Clearance::AuditedSink));
    assert!(!ts.can_flow_to(&Clearance::SealedSink));
    assert!(!ts.can_flow_to(&Clearance::NeverSink));
}

#[test]
fn enrichment_flow_matrix_confidential_up_to_audited() {
    let conf = LabelClass::Confidential;
    assert!(conf.can_flow_to(&Clearance::OpenSink));
    assert!(!conf.can_flow_to(&Clearance::RestrictedSink));
    assert!(conf.can_flow_to(&Clearance::AuditedSink));
    assert!(conf.can_flow_to(&Clearance::SealedSink));
    assert!(!conf.can_flow_to(&Clearance::NeverSink));
}

// =========================================================================
// D. DataSource label assignment
// =========================================================================

#[test]
fn enrichment_assign_label_hostcall_return_all_clearances() {
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
fn enrichment_assign_label_computed_joins_all_inputs() {
    let source = DataSource::Computed {
        input_labels: vec![LabelClass::Public, LabelClass::Internal, LabelClass::Secret],
    };
    assert_eq!(assign_label(&source), LabelClass::Secret);
}

#[test]
fn enrichment_assign_label_computed_empty_is_public() {
    let source = DataSource::Computed {
        input_labels: vec![],
    };
    assert_eq!(assign_label(&source), LabelClass::Public);
}

#[test]
fn enrichment_assign_label_declassified_always_public() {
    let source = DataSource::Declassified {
        original: LabelClass::TopSecret,
    };
    assert_eq!(assign_label(&source), LabelClass::Public);
}

#[test]
fn enrichment_assign_label_policy_protected() {
    assert_eq!(
        assign_label(&DataSource::PolicyProtectedArtifact),
        LabelClass::Confidential
    );
}

// =========================================================================
// E. SinkKind clearance mapping
// =========================================================================

#[test]
fn enrichment_sink_clearance_all_kinds() {
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

#[test]
fn enrichment_sink_kind_serde_all_roundtrip() {
    for kind in [
        SinkKind::NetworkEgress,
        SinkKind::SubprocessIpc,
        SinkKind::PersistenceExport,
        SinkKind::DeclassificationEndpoint,
        SinkKind::LoggingRedacted,
        SinkKind::MetricsExport,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let restored: SinkKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

// =========================================================================
// F. DeclassificationObligation — lifecycle
// =========================================================================

#[test]
fn enrichment_obligation_has_remaining_uses_unlimited() {
    let ob = make_obligation("o1", LabelClass::Secret, Clearance::NeverSink, 0);
    assert!(ob.has_remaining_uses()); // max_uses=0 means unlimited
}

#[test]
fn enrichment_obligation_has_remaining_uses_limited() {
    let mut ob = make_obligation("o2", LabelClass::Secret, Clearance::NeverSink, 2);
    assert!(ob.has_remaining_uses());
    ob.record_use().unwrap();
    assert!(ob.has_remaining_uses());
    ob.record_use().unwrap();
    assert!(!ob.has_remaining_uses());
}

#[test]
fn enrichment_obligation_record_use_exhausted_error() {
    let mut ob = make_obligation("o3", LabelClass::Secret, Clearance::NeverSink, 1);
    ob.record_use().unwrap();
    let result = ob.record_use();
    assert!(matches!(
        result,
        Err(FlowLatticeError::ObligationExhausted { .. })
    ));
}

#[test]
fn enrichment_obligation_serde_roundtrip() {
    let ob = make_obligation("ob-rt", LabelClass::Confidential, Clearance::SealedSink, 5);
    let json = serde_json::to_string(&ob).unwrap();
    let restored: DeclassificationObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(ob, restored);
}

// =========================================================================
// G. Ir2FlowLattice — check_flow and use_declassification
// =========================================================================

#[test]
fn enrichment_flow_lattice_legal_by_lattice() {
    let mut lattice = Ir2FlowLattice::new("policy-1");
    let result = lattice.check_flow(&LabelClass::Public, &Clearance::NeverSink, "trace-1");
    assert!(result.is_legal());
    assert!(!result.is_blocked());
}

#[test]
fn enrichment_flow_lattice_blocked_no_obligation() {
    let mut lattice = Ir2FlowLattice::new("policy-2");
    let result = lattice.check_flow(&LabelClass::TopSecret, &Clearance::NeverSink, "trace-2");
    assert!(result.is_blocked());
    assert!(!result.is_legal());
}

#[test]
fn enrichment_flow_lattice_requires_declassification() {
    let mut lattice = Ir2FlowLattice::new("policy-3");
    let ob = make_obligation("declass-1", LabelClass::TopSecret, Clearance::NeverSink, 1);
    lattice.register_obligation(ob).unwrap();

    let result = lattice.check_flow(&LabelClass::TopSecret, &Clearance::NeverSink, "trace-3");
    assert!(matches!(
        result,
        FlowCheckResult::RequiresDeclassification { .. }
    ));
}

#[test]
fn enrichment_flow_lattice_use_declassification_success() {
    let mut lattice = Ir2FlowLattice::new("policy-4");
    let ob = make_obligation("d-1", LabelClass::Secret, Clearance::NeverSink, 1);
    lattice.register_obligation(ob).unwrap();
    lattice.use_declassification("d-1", "trace-4").unwrap();
    // Now exhausted
    let result = lattice.use_declassification("d-1", "trace-4");
    assert!(matches!(
        result,
        Err(FlowLatticeError::ObligationExhausted { .. })
    ));
}

#[test]
fn enrichment_flow_lattice_use_declassification_not_found() {
    let mut lattice = Ir2FlowLattice::new("policy-5");
    let result = lattice.use_declassification("nonexistent", "trace-5");
    assert!(matches!(
        result,
        Err(FlowLatticeError::ObligationNotFound { .. })
    ));
}

#[test]
fn enrichment_flow_lattice_duplicate_obligation_rejected() {
    let mut lattice = Ir2FlowLattice::new("policy-6");
    let ob1 = make_obligation("dup", LabelClass::Secret, Clearance::NeverSink, 1);
    let ob2 = make_obligation("dup", LabelClass::Public, Clearance::OpenSink, 1);
    lattice.register_obligation(ob1).unwrap();
    let result = lattice.register_obligation(ob2);
    assert!(matches!(
        result,
        Err(FlowLatticeError::DuplicateObligation { .. })
    ));
}

#[test]
fn enrichment_flow_lattice_events_emitted() {
    let mut lattice = Ir2FlowLattice::new("policy-7");
    lattice.check_flow(&LabelClass::Public, &Clearance::OpenSink, "t1");
    lattice.check_flow(&LabelClass::TopSecret, &Clearance::NeverSink, "t2");
    let events = lattice.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].outcome, "legal_by_lattice");
    assert_eq!(events[1].outcome, "blocked");
}

#[test]
fn enrichment_flow_lattice_obligation_accessor() {
    let mut lattice = Ir2FlowLattice::new("policy-8");
    let ob = make_obligation("ob-get", LabelClass::Internal, Clearance::RestrictedSink, 3);
    lattice.register_obligation(ob).unwrap();
    assert!(lattice.obligation("ob-get").is_some());
    assert!(lattice.obligation("nonexistent").is_none());
}

#[test]
fn enrichment_flow_lattice_obligations_map() {
    let mut lattice = Ir2FlowLattice::new("policy-9");
    assert!(lattice.obligations().is_empty());
    let ob = make_obligation("ob-map", LabelClass::Secret, Clearance::SealedSink, 1);
    lattice.register_obligation(ob).unwrap();
    assert_eq!(lattice.obligations().len(), 1);
}

// =========================================================================
// H. Ir2FlowLattice — label propagation
// =========================================================================

#[test]
fn enrichment_propagate_labels_empty_is_public() {
    let lattice = Ir2FlowLattice::new("p-1");
    assert_eq!(lattice.propagate_labels(&[]), LabelClass::Public);
}

#[test]
fn enrichment_propagate_labels_single() {
    let lattice = Ir2FlowLattice::new("p-2");
    assert_eq!(
        lattice.propagate_labels(&[LabelClass::Secret]),
        LabelClass::Secret
    );
}

#[test]
fn enrichment_propagate_labels_joins_all() {
    let lattice = Ir2FlowLattice::new("p-3");
    let result = lattice.propagate_labels(&[
        LabelClass::Public,
        LabelClass::Internal,
        LabelClass::TopSecret,
    ]);
    assert_eq!(result, LabelClass::TopSecret);
}

#[test]
fn enrichment_assign_source_label_delegates() {
    let lattice = Ir2FlowLattice::new("p-4");
    assert_eq!(
        lattice.assign_source_label(&DataSource::KeyMaterial),
        LabelClass::TopSecret
    );
}

#[test]
fn enrichment_assign_sink_clearance_delegates() {
    let lattice = Ir2FlowLattice::new("p-5");
    assert_eq!(
        lattice.assign_sink_clearance(&SinkKind::NetworkEgress),
        Clearance::NeverSink
    );
}

// =========================================================================
// I. FlowLatticeError — Display and serde
// =========================================================================

#[test]
fn enrichment_error_display_all_variants_distinct() {
    let variants = [
        FlowLatticeError::ObligationExhausted {
            obligation_id: "a".into(),
        },
        FlowLatticeError::ObligationNotFound {
            obligation_id: "b".into(),
        },
        FlowLatticeError::DuplicateObligation {
            obligation_id: "c".into(),
        },
        FlowLatticeError::FlowBlocked { detail: "d".into() },
    ];
    let strings: BTreeSet<_> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(strings.len(), 4);
}

#[test]
fn enrichment_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(FlowLatticeError::FlowBlocked {
        detail: "test".into(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_error_serde_all_variants_roundtrip() {
    for err in [
        FlowLatticeError::ObligationExhausted {
            obligation_id: "x".into(),
        },
        FlowLatticeError::ObligationNotFound {
            obligation_id: "y".into(),
        },
        FlowLatticeError::DuplicateObligation {
            obligation_id: "z".into(),
        },
        FlowLatticeError::FlowBlocked {
            detail: "blocked".into(),
        },
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let restored: FlowLatticeError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }
}

// =========================================================================
// J. FlowCheckResult — properties
// =========================================================================

#[test]
fn enrichment_flow_check_result_legal_properties() {
    let r = FlowCheckResult::LegalByLattice;
    assert!(r.is_legal());
    assert!(!r.is_blocked());
}

#[test]
fn enrichment_flow_check_result_blocked_properties() {
    let r = FlowCheckResult::Blocked {
        source: LabelClass::Secret,
        sink: Clearance::NeverSink,
    };
    assert!(r.is_blocked());
    assert!(!r.is_legal());
}

#[test]
fn enrichment_flow_check_result_requires_declass_properties() {
    let r = FlowCheckResult::RequiresDeclassification {
        obligation_id: "ob-1".into(),
    };
    assert!(!r.is_legal());
    assert!(!r.is_blocked());
}

#[test]
fn enrichment_flow_check_result_serde_roundtrip() {
    for r in [
        FlowCheckResult::LegalByLattice,
        FlowCheckResult::RequiresDeclassification {
            obligation_id: "ob-x".into(),
        },
        FlowCheckResult::Blocked {
            source: LabelClass::Secret,
            sink: Clearance::NeverSink,
        },
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let restored: FlowCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }
}

// =========================================================================
// K. FlowLatticeEvent — serde
// =========================================================================

#[test]
fn enrichment_flow_lattice_event_serde_roundtrip() {
    let event = FlowLatticeEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "flow_lattice".into(),
        event: "check_flow".into(),
        outcome: "legal_by_lattice".into(),
        error_code: None,
        obligation_id: Some("ob-1".into()),
        decision_contract_id: Some("dc-1".into()),
        receipt_id: None,
        receipt_replay_command: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: FlowLatticeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// L. DataSource serde
// =========================================================================

#[test]
fn enrichment_data_source_serde_all_variants() {
    let sources = [
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
        let restored: DataSource = serde_json::from_str(&json).unwrap();
        assert_eq!(*source, restored);
    }
}

// =========================================================================
// M. Debug formatting — all major types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", LabelClass::Public).is_empty());
    assert!(!format!("{:?}", Clearance::OpenSink).is_empty());
    assert!(!format!("{:?}", SinkKind::NetworkEgress).is_empty());
    assert!(!format!("{:?}", DataSource::Literal).is_empty());
    assert!(!format!("{:?}", FlowCheckResult::LegalByLattice).is_empty());
    assert!(!format!("{:?}", FlowLatticeError::FlowBlocked { detail: "x".into() }).is_empty());
}
