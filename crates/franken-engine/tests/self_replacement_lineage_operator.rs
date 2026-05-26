//! Integration tests for the self-replacement lineage-explorer operator
//! surface (V.6 followup — bd-cixqu.22.7). Exercises the public
//! `self_replacement_lineage_operator` API from outside the crate, mirroring
//! the verdict semantics of the V.6 shell scripts walk_lineage.sh and
//! inspect_demotion_receipt.sh: intact chain, broken-linkage, slot-mismatch,
//! unapproved-artifacts; sealed/active/demoted/voided/ILLEGAL-TRIGGER.

#![forbid(unsafe_code)]

use frankenengine_engine::self_replacement_lineage_operator::{
    ArtifactStatusView, DemotionFallbackView, DemotionInspectVerdict, DemotionTriggerKind,
    FallbackStatusView, LineageChainView, LineageExplorerPartial, LineageExplorerView,
    LineageStepView, LineageWalkVerdict, LinkageStatus, inspect_demotion, walk_lineage,
};

fn approved_artifact(name: &str) -> ArtifactStatusView {
    ArtifactStatusView {
        artifact_ref: name.to_string(),
        status: "approved".to_string(),
    }
}

fn step(id: &str, old_slot: &str, new_slot: &str, old_d: &str, new_d: &str) -> LineageStepView {
    LineageStepView {
        receipt_id: id.to_string(),
        old_slot_id: old_slot.to_string(),
        new_slot_id: new_slot.to_string(),
        old_cell_digest: old_d.to_string(),
        new_cell_digest: new_d.to_string(),
        validation_artifacts: vec![approved_artifact("proof")],
    }
}

fn chain_of(len: usize, terminal_slot: &str) -> LineageChainView {
    let mut steps = Vec::new();
    let mut prev = "GENESIS".to_string();
    for i in 0..len {
        let new_d = format!("d{}", i + 1);
        let new_slot = if i + 1 == len {
            terminal_slot.to_string()
        } else {
            format!("s{}", i + 1)
        };
        steps.push(step(
            &format!("r{}", i + 1),
            &format!("s{i}"),
            &new_slot,
            &prev,
            &new_d,
        ));
        prev = new_d;
    }
    LineageChainView {
        slot_id: terminal_slot.to_string(),
        steps,
    }
}

fn fallback(
    promotion: &str,
    status: FallbackStatusView,
    permitted: Vec<DemotionTriggerKind>,
) -> DemotionFallbackView {
    DemotionFallbackView {
        promotion_id: promotion.to_string(),
        receipt_digest: "rd".to_string(),
        sealed_at_ns: 1,
        permitted_triggers: permitted,
        status,
    }
}

// ---- lineage walk ------------------------------------------------------

#[test]
fn intact_chains_of_various_lengths_are_ok() {
    for len in 1..=6 {
        let chain = chain_of(len, "terminal");
        let r = walk_lineage(&chain);
        assert_eq!(r.verdict, LineageWalkVerdict::Ok, "len {len}");
        assert_eq!(r.rows.len(), len);
        assert_eq!(r.rows[0].linkage, LinkageStatus::ChainRoot);
        for row in &r.rows[1..] {
            assert_eq!(row.linkage, LinkageStatus::Linked);
        }
    }
}

#[test]
fn empty_chain_is_empty_verdict() {
    let r = walk_lineage(&LineageChainView::default());
    assert_eq!(r.verdict, LineageWalkVerdict::Empty);
    assert!(r.rows.is_empty());
}

#[test]
fn broken_linkage_detected_at_each_position() {
    for break_at in 1..5 {
        let mut chain = chain_of(5, "terminal");
        chain.steps[break_at].old_cell_digest = "BROKEN".to_string();
        let r = walk_lineage(&chain);
        assert_eq!(
            r.verdict,
            LineageWalkVerdict::BrokenLinkage {
                index: break_at as u32
            }
        );
        assert_eq!(r.rows[break_at].linkage, LinkageStatus::Broken);
    }
}

#[test]
fn slot_mismatch_when_queried_slot_wrong() {
    let mut chain = chain_of(3, "terminal");
    chain.slot_id = "other".to_string();
    let r = walk_lineage(&chain);
    assert_eq!(
        r.verdict,
        LineageWalkVerdict::SlotMismatch {
            queried: "other".to_string(),
            terminal: "terminal".to_string(),
        }
    );
}

#[test]
fn unapproved_artifact_detected() {
    let mut chain = chain_of(3, "terminal");
    chain.steps[2].validation_artifacts = vec![ArtifactStatusView {
        artifact_ref: "scan".to_string(),
        status: "pending".to_string(),
    }];
    let r = walk_lineage(&chain);
    assert_eq!(
        r.verdict,
        LineageWalkVerdict::UnapprovedArtifacts {
            index: 2,
            artifact_ref: "scan".to_string(),
        }
    );
}

#[test]
fn verdict_strings_match_script_vocabulary() {
    assert_eq!(
        walk_lineage(&chain_of(2, "terminal")).verdict.verdict_str(),
        "ok"
    );
    assert_eq!(
        walk_lineage(&LineageChainView::default())
            .verdict
            .verdict_str(),
        "empty"
    );
    let mut broken = chain_of(2, "terminal");
    broken.steps[1].old_cell_digest = "x".to_string();
    assert_eq!(
        walk_lineage(&broken).verdict.verdict_str(),
        "broken-linkage"
    );
    let mut mismatch = chain_of(2, "terminal");
    mismatch.slot_id = "z".to_string();
    assert_eq!(
        walk_lineage(&mismatch).verdict.verdict_str(),
        "slot-mismatch"
    );
    let mut unapproved = chain_of(2, "terminal");
    unapproved.steps[0].validation_artifacts = vec![ArtifactStatusView {
        artifact_ref: "a".to_string(),
        status: "denied".to_string(),
    }];
    assert_eq!(
        walk_lineage(&unapproved).verdict.verdict_str(),
        "unapproved-artifacts"
    );
}

#[test]
fn earliest_break_wins_over_later_breaks() {
    let mut chain = chain_of(5, "terminal");
    chain.steps[3].old_cell_digest = "X".to_string();
    chain.steps[1].old_cell_digest = "Y".to_string();
    let r = walk_lineage(&chain);
    assert_eq!(r.verdict, LineageWalkVerdict::BrokenLinkage { index: 1 });
}

#[test]
fn broken_linkage_precedence_over_slot_mismatch() {
    let mut chain = chain_of(3, "terminal");
    chain.slot_id = "wrong".to_string();
    chain.steps[1].old_cell_digest = "X".to_string();
    // Both faults present; linkage break (found during walk) wins.
    assert_eq!(
        walk_lineage(&chain).verdict,
        LineageWalkVerdict::BrokenLinkage { index: 1 }
    );
}

#[test]
fn multiple_approved_artifacts_per_step_are_ok() {
    let mut chain = chain_of(2, "terminal");
    chain.steps[0].validation_artifacts = vec![
        approved_artifact("sig"),
        approved_artifact("transparency"),
        approved_artifact("attestation"),
    ];
    assert_eq!(walk_lineage(&chain).verdict, LineageWalkVerdict::Ok);
}

#[test]
fn mixed_artifacts_with_one_unapproved_flags_step() {
    let mut chain = chain_of(2, "terminal");
    chain.steps[0].validation_artifacts = vec![
        approved_artifact("sig"),
        ArtifactStatusView {
            artifact_ref: "attestation".to_string(),
            status: "expired".to_string(),
        },
    ];
    assert_eq!(
        walk_lineage(&chain).verdict,
        LineageWalkVerdict::UnapprovedArtifacts {
            index: 0,
            artifact_ref: "attestation".to_string(),
        }
    );
}

#[test]
fn approve_and_approved_both_accepted() {
    let mut chain = chain_of(2, "terminal");
    chain.steps[0].validation_artifacts = vec![ArtifactStatusView {
        artifact_ref: "p".to_string(),
        status: "approve".to_string(),
    }];
    chain.steps[1].validation_artifacts = vec![ArtifactStatusView {
        artifact_ref: "q".to_string(),
        status: "APPROVED".to_string(),
    }];
    assert_eq!(walk_lineage(&chain).verdict, LineageWalkVerdict::Ok);
}

// ---- demotion inspect --------------------------------------------------

#[test]
fn sealed_and_active_are_non_alarm() {
    assert_eq!(
        inspect_demotion(&fallback("p", FallbackStatusView::Sealed, vec![])),
        DemotionInspectVerdict::Sealed
    );
    assert_eq!(
        inspect_demotion(&fallback("p", FallbackStatusView::Active, vec![])),
        DemotionInspectVerdict::Active
    );
}

#[test]
fn voided_carries_reason() {
    let v = inspect_demotion(&fallback(
        "p",
        FallbackStatusView::Voided {
            voided_at_ns: 3,
            reason: "succeeded".to_string(),
        },
        vec![],
    ));
    assert_eq!(
        v,
        DemotionInspectVerdict::Voided {
            reason: "succeeded".to_string()
        }
    );
}

#[test]
fn every_trigger_permitted_yields_demoted() {
    for trigger in [
        DemotionTriggerKind::DigestDrift,
        DemotionTriggerKind::SeverityThresholdCrossed,
        DemotionTriggerKind::GatekeeperRejection,
        DemotionTriggerKind::ManualOperator,
    ] {
        let v = inspect_demotion(&fallback(
            "p",
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger,
            },
            vec![trigger],
        ));
        assert_eq!(v, DemotionInspectVerdict::Demoted { trigger });
        assert!(!v.is_alarm());
    }
}

#[test]
fn every_trigger_unpermitted_yields_illegal() {
    for trigger in [
        DemotionTriggerKind::DigestDrift,
        DemotionTriggerKind::SeverityThresholdCrossed,
        DemotionTriggerKind::GatekeeperRejection,
        DemotionTriggerKind::ManualOperator,
    ] {
        let v = inspect_demotion(&fallback(
            "p",
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger,
            },
            vec![], // nothing permitted
        ));
        assert_eq!(v, DemotionInspectVerdict::IllegalTrigger { trigger });
        assert!(v.is_alarm());
        assert_eq!(v.verdict_str(), "ILLEGAL-TRIGGER");
    }
}

#[test]
fn permitted_subset_distinguishes_legal_from_illegal() {
    // Permit DigestDrift only.
    let permitted = vec![DemotionTriggerKind::DigestDrift];
    let legal = inspect_demotion(&fallback(
        "p",
        FallbackStatusView::Activated {
            activated_at_ns: 1,
            trigger: DemotionTriggerKind::DigestDrift,
        },
        permitted.clone(),
    ));
    assert!(!legal.is_alarm());
    let illegal = inspect_demotion(&fallback(
        "p",
        FallbackStatusView::Activated {
            activated_at_ns: 1,
            trigger: DemotionTriggerKind::GatekeeperRejection,
        },
        permitted,
    ));
    assert!(illegal.is_alarm());
}

#[test]
fn demotion_verdict_strings_match_script_vocabulary() {
    assert_eq!(
        inspect_demotion(&fallback("p", FallbackStatusView::Sealed, vec![])).verdict_str(),
        "sealed"
    );
    assert_eq!(
        inspect_demotion(&fallback("p", FallbackStatusView::Active, vec![])).verdict_str(),
        "active"
    );
    assert_eq!(
        inspect_demotion(&fallback(
            "p",
            FallbackStatusView::Voided {
                voided_at_ns: 1,
                reason: "r".to_string()
            },
            vec![]
        ))
        .verdict_str(),
        "voided"
    );
    assert_eq!(
        inspect_demotion(&fallback(
            "p",
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger: DemotionTriggerKind::DigestDrift
            },
            vec![DemotionTriggerKind::DigestDrift]
        ))
        .verdict_str(),
        "demoted"
    );
    assert_eq!(
        inspect_demotion(&fallback(
            "p",
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger: DemotionTriggerKind::DigestDrift
            },
            vec![]
        ))
        .verdict_str(),
        "ILLEGAL-TRIGGER"
    );
}

// ---- panel -------------------------------------------------------------

#[test]
fn panel_default_is_empty_unknown() {
    let v = LineageExplorerView::from_partial(LineageExplorerPartial::default());
    assert_eq!(v.cluster, "unknown");
    assert_eq!(v.zone, "unknown");
    assert_eq!(v.lineage_slot, "unknown");
    assert_eq!(v.lineage_verdict, "empty");
    assert!(!v.lineage_intact);
    assert!(!v.has_alerts());
}

#[test]
fn panel_intact_chain_no_alerts() {
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        cluster: "c".to_string(),
        zone: "z".to_string(),
        security_epoch: Some(2),
        generated_at_unix_ms: Some(99),
        chain: chain_of(4, "terminal"),
        fallbacks: vec![],
    });
    assert!(v.lineage_intact);
    assert_eq!(v.lineage_verdict, "ok");
    assert_eq!(v.linkage_rows.len(), 4);
    assert_eq!(v.security_epoch, 2);
    assert_eq!(v.generated_at_unix_ms, 99);
    assert!(!v.has_alerts());
}

#[test]
fn panel_broken_chain_has_alert() {
    let mut chain = chain_of(4, "terminal");
    chain.steps[2].old_cell_digest = "BROKEN".to_string();
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain,
        ..Default::default()
    });
    assert!(!v.lineage_intact);
    assert_eq!(v.lineage_verdict, "broken-linkage");
    assert!(v.alerts.iter().any(|a| a.contains("broken-linkage")));
}

#[test]
fn panel_slot_mismatch_alert() {
    let mut chain = chain_of(3, "terminal");
    chain.slot_id = "nope".to_string();
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain,
        ..Default::default()
    });
    assert_eq!(v.lineage_verdict, "slot-mismatch");
    assert!(v.alerts.iter().any(|a| a.contains("slot-mismatch")));
}

#[test]
fn panel_unapproved_artifact_alert() {
    let mut chain = chain_of(3, "terminal");
    chain.steps[1].validation_artifacts = vec![ArtifactStatusView {
        artifact_ref: "scan".to_string(),
        status: "failed".to_string(),
    }];
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain,
        ..Default::default()
    });
    assert_eq!(v.lineage_verdict, "unapproved-artifacts");
    assert!(v.alerts.iter().any(|a| a.contains("unapproved-artifacts")));
}

#[test]
fn panel_renders_all_fallback_rows() {
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain: chain_of(2, "terminal"),
        fallbacks: vec![
            fallback("p1", FallbackStatusView::Sealed, vec![]),
            fallback("p2", FallbackStatusView::Active, vec![]),
            fallback(
                "p3",
                FallbackStatusView::Voided {
                    voided_at_ns: 1,
                    reason: "ok".to_string(),
                },
                vec![],
            ),
        ],
        ..Default::default()
    });
    assert_eq!(v.demotion_rows.len(), 3);
    assert_eq!(v.demotion_rows[0].verdict, "sealed");
    assert_eq!(v.demotion_rows[1].verdict, "active");
    assert_eq!(v.demotion_rows[2].verdict, "voided");
    assert!(!v.has_alerts());
}

#[test]
fn panel_illegal_trigger_sets_alarm_row_and_alert() {
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain: chain_of(2, "terminal"),
        fallbacks: vec![fallback(
            "pX",
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger: DemotionTriggerKind::ManualOperator,
            },
            vec![DemotionTriggerKind::DigestDrift],
        )],
        ..Default::default()
    });
    assert!(v.demotion_rows[0].alarm);
    assert_eq!(v.demotion_rows[0].verdict, "ILLEGAL-TRIGGER");
    assert!(v.has_alerts());
    assert!(v.alerts.iter().any(|a| a.contains("pX")));
}

#[test]
fn panel_combines_lineage_and_demotion_alerts() {
    let mut chain = chain_of(3, "terminal");
    chain.steps[1].old_cell_digest = "BROKEN".to_string();
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain,
        fallbacks: vec![fallback(
            "pZ",
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger: DemotionTriggerKind::GatekeeperRejection,
            },
            vec![],
        )],
        ..Default::default()
    });
    assert!(v.alerts.len() >= 2);
    assert!(v.alerts.iter().any(|a| a.contains("broken-linkage")));
    assert!(v.alerts.iter().any(|a| a.starts_with("ILLEGAL-TRIGGER")));
}

#[test]
fn panel_alerts_sorted_and_deduplicated() {
    let illegal = fallback(
        "pp",
        FallbackStatusView::Activated {
            activated_at_ns: 1,
            trigger: DemotionTriggerKind::ManualOperator,
        },
        vec![],
    );
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain: chain_of(2, "terminal"),
        fallbacks: vec![illegal.clone(), illegal],
        ..Default::default()
    });
    let mut sorted = v.alerts.clone();
    sorted.sort();
    assert_eq!(v.alerts, sorted);
    assert_eq!(
        v.alerts.iter().filter(|a| a.starts_with("ILLEGAL")).count(),
        1
    );
}

#[test]
fn panel_blank_labels_normalize_to_unknown() {
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        cluster: "   ".to_string(),
        zone: "".to_string(),
        chain: chain_of(1, "terminal"),
        ..Default::default()
    });
    assert_eq!(v.cluster, "unknown");
    assert_eq!(v.zone, "unknown");
}

#[test]
fn panel_demoted_fallback_is_not_alarm() {
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        chain: chain_of(2, "terminal"),
        fallbacks: vec![fallback(
            "p",
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger: DemotionTriggerKind::DigestDrift,
            },
            vec![DemotionTriggerKind::DigestDrift],
        )],
        ..Default::default()
    });
    assert_eq!(v.demotion_rows[0].verdict, "demoted");
    assert!(!v.demotion_rows[0].alarm);
    assert!(!v.has_alerts());
}

// ---- serde / determinism ----------------------------------------------

#[test]
fn panel_serde_roundtrip() {
    let v = LineageExplorerView::from_partial(LineageExplorerPartial {
        cluster: "c".to_string(),
        zone: "z".to_string(),
        security_epoch: Some(1),
        generated_at_unix_ms: Some(2),
        chain: chain_of(3, "terminal"),
        fallbacks: vec![fallback("p", FallbackStatusView::Sealed, vec![])],
    });
    let json = serde_json::to_string(&v).unwrap();
    let back: LineageExplorerView = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn chain_view_serde_roundtrip() {
    let chain = chain_of(4, "terminal");
    let json = serde_json::to_string(&chain).unwrap();
    let back: LineageChainView = serde_json::from_str(&json).unwrap();
    assert_eq!(chain, back);
}

#[test]
fn panel_build_is_deterministic() {
    let build = || {
        LineageExplorerView::from_partial(LineageExplorerPartial {
            chain: chain_of(3, "terminal"),
            fallbacks: vec![fallback("p", FallbackStatusView::Active, vec![])],
            ..Default::default()
        })
    };
    assert_eq!(build(), build());
}

#[test]
fn fallback_status_activated_serde_roundtrip() {
    let f = fallback(
        "p",
        FallbackStatusView::Activated {
            activated_at_ns: 42,
            trigger: DemotionTriggerKind::SeverityThresholdCrossed,
        },
        vec![DemotionTriggerKind::SeverityThresholdCrossed],
    );
    let json = serde_json::to_string(&f).unwrap();
    let back: DemotionFallbackView = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn linkage_rows_carry_receipt_ids_in_order() {
    let r = walk_lineage(&chain_of(3, "terminal"));
    assert_eq!(r.rows[0].receipt_id, "r1");
    assert_eq!(r.rows[1].receipt_id, "r2");
    assert_eq!(r.rows[2].receipt_id, "r3");
    assert_eq!(r.rows[0].index, 0);
    assert_eq!(r.rows[2].index, 2);
}

#[test]
fn single_step_chain_with_genesis_root() {
    let chain = chain_of(1, "only");
    let r = walk_lineage(&chain);
    assert_eq!(r.verdict, LineageWalkVerdict::Ok);
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0].linkage, LinkageStatus::ChainRoot);
}
