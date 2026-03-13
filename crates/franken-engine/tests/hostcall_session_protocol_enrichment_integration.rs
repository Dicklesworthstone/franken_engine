//! Enrichment integration tests for the hostcall_session_protocol module.
//!
//! Covers: Display uniqueness for all enums, serde roundtrips for all types,
//! method behavior edge cases, deterministic hash behavior, anti-replay ledger
//! invariants, degraded-mode policy matrix, protocol error formatting,
//! state machine boundary conditions, key schedule derivation, corpus/runner
//! consistency, and specimen family coverage.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_session_protocol::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn test_hash() -> ContentHash {
    ContentHash::compute(b"enrichment-test-transcript")
}

fn make_state() -> SessionProtocolState {
    SessionProtocolState::new(
        "enrich-sess".into(),
        "enrich-ext".into(),
        "enrich-host".into(),
        64,
        100,
    )
}

fn make_established_state() -> SessionProtocolState {
    let mut state = make_state();
    state
        .transition(
            SessionPhaseTag::Negotiating,
            TransitionTrigger::HandshakeInitiated,
            1,
        )
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Established,
            TransitionTrigger::HandshakeCompleted,
            2,
        )
        .unwrap();
    state
}

fn make_complete_key_schedule() -> SessionKeySchedule {
    let mut ks = SessionKeySchedule::new(
        test_epoch(),
        "enrich-sess".into(),
        "enrich-ext".into(),
        "enrich-host".into(),
        test_hash(),
    );
    for purpose in KeyStagePurpose::ALL {
        ks.record_stage(
            *purpose,
            ContentHash::compute(purpose.domain_label().as_bytes()),
        );
    }
    ks
}

// ---------------------------------------------------------------------------
// 1. Display uniqueness tests for all enums
// ---------------------------------------------------------------------------

#[test]
fn enrichment_session_phase_tag_display_all_unique() {
    let displays: Vec<String> = SessionPhaseTag::ALL.iter().map(|t| t.to_string()).collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "SessionPhaseTag Display values must be unique"
    );
}

#[test]
fn enrichment_key_stage_purpose_display_all_unique() {
    let displays: Vec<String> = KeyStagePurpose::ALL.iter().map(|p| p.to_string()).collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "KeyStagePurpose Display values must be unique"
    );
}

#[test]
fn enrichment_key_stage_purpose_domain_labels_all_unique() {
    let labels: Vec<&str> = KeyStagePurpose::ALL
        .iter()
        .map(|p| p.domain_label())
        .collect();
    let unique: BTreeSet<&str> = labels.iter().copied().collect();
    assert_eq!(
        labels.len(),
        unique.len(),
        "KeyStagePurpose domain labels must be unique"
    );
}

#[test]
fn enrichment_degraded_severity_display_all_unique() {
    let severities = [
        DegradedSeverity::StaleKey,
        DegradedSeverity::PartialMacFailure,
        DegradedSeverity::IdentityCompromised,
    ];
    let displays: Vec<String> = severities.iter().map(|s| s.to_string()).collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "DegradedSeverity Display values must be unique"
    );
}

#[test]
fn enrichment_degraded_operation_kind_display_all_unique() {
    let ops = [
        DegradedOperationKind::ReadHostcall,
        DegradedOperationKind::WriteHostcall,
        DegradedOperationKind::LifecycleOperation,
        DegradedOperationKind::Close,
    ];
    let displays: Vec<String> = ops.iter().map(|o| o.to_string()).collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "DegradedOperationKind Display values must be unique"
    );
}

#[test]
fn enrichment_replay_verdict_display_all_unique() {
    let verdicts = [
        ReplayVerdict::Accept,
        ReplayVerdict::Replay,
        ReplayVerdict::BelowFloor,
        ReplayVerdict::AboveCeiling,
    ];
    let displays: Vec<String> = verdicts.iter().map(|v| v.to_string()).collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "ReplayVerdict Display values must be unique"
    );
}

#[test]
fn enrichment_hsp_specimen_family_display_all_unique() {
    let displays: Vec<String> = HspSpecimenFamily::ALL
        .iter()
        .map(|f| f.to_string())
        .collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "HspSpecimenFamily Display values must be unique"
    );
}

#[test]
fn enrichment_transition_trigger_display_all_unit_variants_unique() {
    let triggers = [
        TransitionTrigger::HandshakeInitiated,
        TransitionTrigger::HandshakeCompleted,
        TransitionTrigger::HandshakeRejected,
        TransitionTrigger::DegradedRecovery,
        TransitionTrigger::CloseInitiated,
        TransitionTrigger::DrainCompleted,
    ];
    let displays: Vec<String> = triggers.iter().map(|t| t.to_string()).collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "TransitionTrigger unit Display values must be unique"
    );
}

// ---------------------------------------------------------------------------
// 2. Serde roundtrip tests for all types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_session_phase_tag_serde_all_variants() {
    for tag in SessionPhaseTag::ALL {
        let json = serde_json::to_string(tag).unwrap();
        let back: SessionPhaseTag = serde_json::from_str(&json).unwrap();
        assert_eq!(*tag, back);
    }
}

#[test]
fn enrichment_transition_trigger_serde_with_payloads() {
    let triggers = vec![
        TransitionTrigger::HandshakeInitiated,
        TransitionTrigger::HandshakeCompleted,
        TransitionTrigger::HandshakeRejected,
        TransitionTrigger::SecurityDegradation {
            reason: "epoch_boundary".into(),
        },
        TransitionTrigger::DegradedRecovery,
        TransitionTrigger::CloseInitiated,
        TransitionTrigger::SessionExpired {
            reason: "ttl_exceeded".into(),
        },
        TransitionTrigger::DrainCompleted,
        TransitionTrigger::ReplayThresholdBreached {
            drop_count: 42,
            window_ticks: 1000,
        },
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let back: TransitionTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn enrichment_phase_transition_serde_roundtrip() {
    let pt = PhaseTransition {
        from: SessionPhaseTag::Uninit,
        to: SessionPhaseTag::Negotiating,
        trigger: TransitionTrigger::HandshakeInitiated,
    };
    let json = serde_json::to_string(&pt).unwrap();
    let back: PhaseTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(pt, back);
}

#[test]
fn enrichment_key_schedule_stage_serde_roundtrip() {
    let stage = KeyScheduleStage {
        stage: 0,
        purpose: KeyStagePurpose::MasterSecret,
        domain_label: "franken::hsp::master".into(),
        key_fingerprint: ContentHash::compute(b"fingerprint"),
        epoch: test_epoch(),
    };
    let json = serde_json::to_string(&stage).unwrap();
    let back: KeyScheduleStage = serde_json::from_str(&json).unwrap();
    assert_eq!(stage, back);
}

#[test]
fn enrichment_session_key_schedule_serde_roundtrip() {
    let ks = make_complete_key_schedule();
    let json = serde_json::to_string(&ks).unwrap();
    let back: SessionKeySchedule = serde_json::from_str(&json).unwrap();
    assert_eq!(ks.session_id, back.session_id);
    assert_eq!(ks.extension_id, back.extension_id);
    assert_eq!(ks.host_id, back.host_id);
    assert_eq!(ks.epoch, back.epoch);
    assert_eq!(ks.derived_stages.len(), back.derived_stages.len());
    assert_eq!(ks.handshake_transcript_hash, back.handshake_transcript_hash);
}

#[test]
fn enrichment_replay_verdict_serde_all() {
    let verdicts = [
        ReplayVerdict::Accept,
        ReplayVerdict::Replay,
        ReplayVerdict::BelowFloor,
        ReplayVerdict::AboveCeiling,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: ReplayVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_replay_ledger_entry_serde_roundtrip() {
    let entry = ReplayLedgerEntry {
        session_id: "s1".into(),
        sequence: 42,
        envelope_hash: ContentHash::compute(b"envelope"),
        accepted_at_tick: 999,
        mac: frankenengine_engine::hash_tiers::AuthenticityHash::compute_keyed(b"key", b"data"),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ReplayLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_replay_audit_entry_serde_roundtrip() {
    let entry = ReplayAuditEntry {
        sequence: 7,
        verdict: ReplayVerdict::Accept,
        checked_at_tick: 100,
        envelope_hash: Some(ContentHash::compute(b"env")),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ReplayAuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_replay_audit_entry_serde_none_hash() {
    let entry = ReplayAuditEntry {
        sequence: 3,
        verdict: ReplayVerdict::BelowFloor,
        checked_at_tick: 50,
        envelope_hash: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ReplayAuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_anti_replay_ledger_serde_roundtrip() {
    let mut ledger = AntiReplayLedger::new("rl-sess".into(), 32, 50);
    for seq in 1..=5 {
        ledger.check_and_record(seq, seq * 10, None);
    }
    let json = serde_json::to_string(&ledger).unwrap();
    let back: AntiReplayLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_accepted(), 5);
    assert_eq!(back.session_id(), "rl-sess");
    assert_eq!(back.window_ceiling(), 5);
}

#[test]
fn enrichment_degraded_mode_policy_serde_all_severities() {
    let severities = [
        DegradedSeverity::StaleKey,
        DegradedSeverity::PartialMacFailure,
        DegradedSeverity::IdentityCompromised,
    ];
    for sev in &severities {
        let policy = DegradedModePolicy::for_severity(*sev);
        let json = serde_json::to_string(&policy).unwrap();
        let back: DegradedModePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}

#[test]
fn enrichment_protocol_error_serde_all_variants() {
    let errors = vec![
        ProtocolError::IllegalTransition {
            from: SessionPhaseTag::Uninit,
            to: SessionPhaseTag::Closed,
        },
        ProtocolError::EpochMismatch {
            schedule_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(5),
        },
        ProtocolError::IncompleteKeySchedule { stages_derived: 2 },
        ProtocolError::ReplayRejected {
            sequence: 99,
            verdict: ReplayVerdict::BelowFloor,
        },
        ProtocolError::DegradedModeBlocked {
            operation: DegradedOperationKind::WriteHostcall,
            severity: DegradedSeverity::PartialMacFailure,
        },
        ProtocolError::DegradedBudgetExhausted {
            messages_used: 100,
            messages_limit: 100,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ProtocolError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn enrichment_transition_record_serde_roundtrip() {
    let record = TransitionRecord {
        from: SessionPhaseTag::Uninit,
        to: SessionPhaseTag::Negotiating,
        trigger: TransitionTrigger::HandshakeInitiated,
        tick: 42,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn enrichment_session_protocol_state_serde_roundtrip() {
    let mut state = make_established_state();
    let ks = make_complete_key_schedule();
    state.attach_key_schedule(ks).unwrap();
    state.check_replay(1, 10, None).unwrap();
    let json = serde_json::to_string(&state).unwrap();
    let back: SessionProtocolState = serde_json::from_str(&json).unwrap();
    assert_eq!(back.phase, SessionPhaseTag::Established);
    assert_eq!(back.session_id, "enrich-sess");
    assert!(back.key_schedule.is_some());
    assert_eq!(back.transition_history.len(), 2);
}

#[test]
fn enrichment_hsp_specimen_family_serde_all() {
    for fam in HspSpecimenFamily::ALL {
        let json = serde_json::to_string(fam).unwrap();
        let back: HspSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*fam, back);
    }
}

#[test]
fn enrichment_hsp_runner_result_serde_roundtrip() {
    let result = run_hsp_corpus();
    let json = serde_json::to_string(&result).unwrap();
    let back: HspRunnerResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.specimen_count, back.specimen_count);
    assert_eq!(result.all_clean, back.all_clean);
    assert_eq!(result.terminal_count, back.terminal_count);
    assert_eq!(result.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// 3. SessionPhaseTag method behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_phase_tag_is_terminal_only_closed() {
    for tag in SessionPhaseTag::ALL {
        if *tag == SessionPhaseTag::Closed {
            assert!(tag.is_terminal());
        } else {
            assert!(!tag.is_terminal(), "{} should not be terminal", tag);
        }
    }
}

#[test]
fn enrichment_phase_tag_permits_data_only_established_and_degraded() {
    for tag in SessionPhaseTag::ALL {
        let expected = matches!(
            tag,
            SessionPhaseTag::Established | SessionPhaseTag::DegradedOpen
        );
        assert_eq!(
            tag.permits_data(),
            expected,
            "permits_data mismatch for {}",
            tag
        );
    }
}

#[test]
fn enrichment_phase_tag_all_count_is_six() {
    assert_eq!(SessionPhaseTag::ALL.len(), 6);
}

#[test]
fn enrichment_phase_tag_ordering() {
    // Uninit < Negotiating < Established < DegradedOpen < Closing < Closed
    assert!(SessionPhaseTag::Uninit < SessionPhaseTag::Negotiating);
    assert!(SessionPhaseTag::Negotiating < SessionPhaseTag::Established);
    assert!(SessionPhaseTag::Established < SessionPhaseTag::DegradedOpen);
    assert!(SessionPhaseTag::DegradedOpen < SessionPhaseTag::Closing);
    assert!(SessionPhaseTag::Closing < SessionPhaseTag::Closed);
}

// ---------------------------------------------------------------------------
// 4. Transition table completeness and edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_valid_transitions_table_has_at_least_twelve_entries() {
    let table = valid_transitions();
    assert!(
        table.len() >= 12,
        "Transition table should have at least 12 entries, got {}",
        table.len()
    );
}

#[test]
fn enrichment_no_self_loop_transitions_valid() {
    for tag in SessionPhaseTag::ALL {
        assert!(
            !is_valid_transition(*tag, *tag),
            "Self-loop should be invalid for {}",
            tag
        );
    }
}

#[test]
fn enrichment_closed_has_no_outgoing_transitions() {
    for tag in SessionPhaseTag::ALL {
        assert!(
            !is_valid_transition(SessionPhaseTag::Closed, *tag),
            "Closed should have no outgoing transition to {}",
            tag
        );
    }
}

#[test]
fn enrichment_uninit_only_transitions_to_negotiating() {
    for tag in SessionPhaseTag::ALL {
        if *tag == SessionPhaseTag::Negotiating {
            assert!(is_valid_transition(SessionPhaseTag::Uninit, *tag));
        } else {
            assert!(
                !is_valid_transition(SessionPhaseTag::Uninit, *tag),
                "Uninit should not transition to {}",
                tag
            );
        }
    }
}

#[test]
fn enrichment_negotiating_transitions_to_established_or_closed() {
    assert!(is_valid_transition(
        SessionPhaseTag::Negotiating,
        SessionPhaseTag::Established
    ));
    assert!(is_valid_transition(
        SessionPhaseTag::Negotiating,
        SessionPhaseTag::Closed
    ));
    assert!(!is_valid_transition(
        SessionPhaseTag::Negotiating,
        SessionPhaseTag::DegradedOpen
    ));
    assert!(!is_valid_transition(
        SessionPhaseTag::Negotiating,
        SessionPhaseTag::Closing
    ));
    assert!(!is_valid_transition(
        SessionPhaseTag::Negotiating,
        SessionPhaseTag::Uninit
    ));
}

#[test]
fn enrichment_established_transitions_to_degraded_closing_or_closed() {
    assert!(is_valid_transition(
        SessionPhaseTag::Established,
        SessionPhaseTag::DegradedOpen
    ));
    assert!(is_valid_transition(
        SessionPhaseTag::Established,
        SessionPhaseTag::Closing
    ));
    assert!(is_valid_transition(
        SessionPhaseTag::Established,
        SessionPhaseTag::Closed
    ));
    assert!(!is_valid_transition(
        SessionPhaseTag::Established,
        SessionPhaseTag::Uninit
    ));
    assert!(!is_valid_transition(
        SessionPhaseTag::Established,
        SessionPhaseTag::Negotiating
    ));
}

#[test]
fn enrichment_degraded_transitions_to_established_closing_or_closed() {
    assert!(is_valid_transition(
        SessionPhaseTag::DegradedOpen,
        SessionPhaseTag::Established
    ));
    assert!(is_valid_transition(
        SessionPhaseTag::DegradedOpen,
        SessionPhaseTag::Closing
    ));
    assert!(is_valid_transition(
        SessionPhaseTag::DegradedOpen,
        SessionPhaseTag::Closed
    ));
    assert!(!is_valid_transition(
        SessionPhaseTag::DegradedOpen,
        SessionPhaseTag::Uninit
    ));
    assert!(!is_valid_transition(
        SessionPhaseTag::DegradedOpen,
        SessionPhaseTag::Negotiating
    ));
}

#[test]
fn enrichment_closing_only_transitions_to_closed() {
    for tag in SessionPhaseTag::ALL {
        if *tag == SessionPhaseTag::Closed {
            assert!(is_valid_transition(SessionPhaseTag::Closing, *tag));
        } else {
            assert!(
                !is_valid_transition(SessionPhaseTag::Closing, *tag),
                "Closing should only transition to Closed, not {}",
                tag
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Key schedule tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_key_schedule_empty_is_incomplete() {
    let ks = SessionKeySchedule::new(
        test_epoch(),
        "s".into(),
        "e".into(),
        "h".into(),
        test_hash(),
    );
    assert!(!ks.is_complete());
    assert_eq!(ks.derived_stages.len(), 0);
}

#[test]
fn enrichment_key_schedule_partial_is_incomplete() {
    let mut ks = SessionKeySchedule::new(
        test_epoch(),
        "s".into(),
        "e".into(),
        "h".into(),
        test_hash(),
    );
    ks.record_stage(
        KeyStagePurpose::MasterSecret,
        ContentHash::compute(b"master"),
    );
    ks.record_stage(KeyStagePurpose::DataPlaneMac, ContentHash::compute(b"mac"));
    assert!(!ks.is_complete());
    assert_eq!(ks.derived_stages.len(), 2);
}

#[test]
fn enrichment_key_schedule_complete_after_all_four_stages() {
    let ks = make_complete_key_schedule();
    assert!(ks.is_complete());
    assert_eq!(ks.derived_stages.len(), 4);
}

#[test]
fn enrichment_key_schedule_stage_numbers_match_enum_discriminant() {
    let ks = make_complete_key_schedule();
    for stage in &ks.derived_stages {
        assert_eq!(
            stage.stage, stage.purpose as u32,
            "Stage number should match purpose discriminant for {:?}",
            stage.purpose
        );
    }
}

#[test]
fn enrichment_key_schedule_stage_domain_labels_match_purpose() {
    let ks = make_complete_key_schedule();
    for stage in &ks.derived_stages {
        assert_eq!(
            stage.domain_label,
            stage.purpose.domain_label(),
            "Domain label mismatch for {:?}",
            stage.purpose
        );
    }
}

#[test]
fn enrichment_key_schedule_epoch_validation_matches() {
    let ks = make_complete_key_schedule();
    assert!(ks.is_valid_for_epoch(test_epoch()));
}

#[test]
fn enrichment_key_schedule_epoch_validation_mismatches() {
    let ks = make_complete_key_schedule();
    assert!(!ks.is_valid_for_epoch(SecurityEpoch::from_raw(999)));
}

#[test]
fn enrichment_key_schedule_binding_hash_deterministic() {
    let ks1 = make_complete_key_schedule();
    let ks2 = make_complete_key_schedule();
    assert_eq!(ks1.binding_hash(), ks2.binding_hash());
}

#[test]
fn enrichment_key_schedule_binding_hash_varies_with_extension_id() {
    let ks1 = make_complete_key_schedule();
    let mut ks2 = make_complete_key_schedule();
    ks2.extension_id = "different-ext".into();
    assert_ne!(ks1.binding_hash(), ks2.binding_hash());
}

#[test]
fn enrichment_key_schedule_binding_hash_varies_with_host_id() {
    let ks1 = make_complete_key_schedule();
    let mut ks2 = make_complete_key_schedule();
    ks2.host_id = "different-host".into();
    assert_ne!(ks1.binding_hash(), ks2.binding_hash());
}

#[test]
fn enrichment_key_schedule_binding_hash_varies_with_epoch() {
    let ks1 = make_complete_key_schedule();
    let mut ks2 = SessionKeySchedule::new(
        SecurityEpoch::from_raw(99),
        "enrich-sess".into(),
        "enrich-ext".into(),
        "enrich-host".into(),
        test_hash(),
    );
    for purpose in KeyStagePurpose::ALL {
        ks2.record_stage(
            *purpose,
            ContentHash::compute(purpose.domain_label().as_bytes()),
        );
    }
    assert_ne!(ks1.binding_hash(), ks2.binding_hash());
}

#[test]
fn enrichment_key_schedule_binding_hash_varies_with_transcript() {
    let mut ks1 = SessionKeySchedule::new(
        test_epoch(),
        "s".into(),
        "e".into(),
        "h".into(),
        ContentHash::compute(b"transcript-a"),
    );
    let mut ks2 = SessionKeySchedule::new(
        test_epoch(),
        "s".into(),
        "e".into(),
        "h".into(),
        ContentHash::compute(b"transcript-b"),
    );
    for purpose in KeyStagePurpose::ALL {
        let fp = ContentHash::compute(purpose.domain_label().as_bytes());
        ks1.record_stage(*purpose, fp.clone());
        ks2.record_stage(*purpose, fp);
    }
    assert_ne!(ks1.binding_hash(), ks2.binding_hash());
}

// ---------------------------------------------------------------------------
// 6. Anti-replay ledger edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ledger_sequence_zero_accepted() {
    let mut ledger = AntiReplayLedger::new("s".into(), 64, 100);
    let v = ledger.check_and_record(0, 1, None);
    assert_eq!(v, ReplayVerdict::Accept);
    assert_eq!(ledger.total_accepted(), 1);
}

#[test]
fn enrichment_ledger_window_width_clamped_to_one() {
    let mut ledger = AntiReplayLedger::new("s".into(), 0, 100);
    // Window width 0 should be clamped to 1.
    let v = ledger.check_and_record(0, 1, None);
    assert_eq!(v, ReplayVerdict::Accept);
}

#[test]
fn enrichment_ledger_multiple_replays_counted() {
    let mut ledger = AntiReplayLedger::new("s".into(), 64, 100);
    ledger.check_and_record(1, 1, None);
    ledger.check_and_record(1, 2, None); // replay 1
    ledger.check_and_record(1, 3, None); // replay 2
    ledger.check_and_record(1, 4, None); // replay 3
    assert_eq!(ledger.total_replays(), 3);
    assert_eq!(ledger.total_accepted(), 1);
    assert_eq!(ledger.total_checked(), 4);
}

#[test]
fn enrichment_ledger_out_of_order_acceptance() {
    let mut ledger = AntiReplayLedger::new("s".into(), 64, 100);
    assert_eq!(ledger.check_and_record(10, 1, None), ReplayVerdict::Accept);
    assert_eq!(ledger.check_and_record(5, 2, None), ReplayVerdict::Accept);
    assert_eq!(ledger.check_and_record(8, 3, None), ReplayVerdict::Accept);
    assert_eq!(ledger.check_and_record(3, 4, None), ReplayVerdict::Accept);
    assert_eq!(ledger.total_accepted(), 4);
    assert_eq!(ledger.window_ceiling(), 10);
}

#[test]
fn enrichment_ledger_window_floor_advances_correctly() {
    let mut ledger = AntiReplayLedger::new("s".into(), 4, 100);
    for seq in 1..=10 {
        ledger.check_and_record(seq, seq, None);
    }
    // ceiling=10, width=4 => floor should be 6
    assert_eq!(ledger.window_floor(), 6);
    assert_eq!(ledger.window_ceiling(), 10);
}

#[test]
fn enrichment_ledger_eviction_removes_below_floor() {
    let mut ledger = AntiReplayLedger::new("s".into(), 4, 100);
    for seq in 1..=10 {
        ledger.check_and_record(seq, seq, None);
    }
    // Sequences 1..6 should have been evicted from the accepted_sequences map.
    assert!(ledger.window_size() <= 5);
}

#[test]
fn enrichment_ledger_below_floor_after_eviction() {
    let mut ledger = AntiReplayLedger::new("s".into(), 4, 100);
    for seq in 1..=10 {
        ledger.check_and_record(seq, seq, None);
    }
    let v = ledger.check_and_record(2, 100, None);
    assert_eq!(v, ReplayVerdict::BelowFloor);
    assert_eq!(ledger.total_below_floor(), 1);
}

#[test]
fn enrichment_ledger_above_ceiling_far_sequence() {
    let mut ledger = AntiReplayLedger::new("s".into(), 4, 100);
    ledger.check_and_record(1, 1, None);
    // ceiling=1, width=4, so max acceptable is 1 + 4 = 5
    let v = ledger.check_and_record(100, 2, None);
    assert_eq!(v, ReplayVerdict::AboveCeiling);
}

#[test]
fn enrichment_ledger_audit_trail_records_all_decisions() {
    let mut ledger = AntiReplayLedger::new("s".into(), 64, 100);
    ledger.check_and_record(1, 10, None);
    ledger.check_and_record(1, 20, None); // replay
    ledger.check_and_record(2, 30, Some(ContentHash::compute(b"env")));
    let trail = ledger.audit_trail();
    assert_eq!(trail.len(), 3);
    assert_eq!(trail[0].verdict, ReplayVerdict::Accept);
    assert_eq!(trail[1].verdict, ReplayVerdict::Replay);
    assert_eq!(trail[2].verdict, ReplayVerdict::Accept);
    assert!(trail[2].envelope_hash.is_some());
}

#[test]
fn enrichment_ledger_audit_trail_bounded_by_max_entries() {
    let mut ledger = AntiReplayLedger::new("s".into(), 1000, 3);
    for seq in 1..=10 {
        ledger.check_and_record(seq, seq, None);
    }
    assert_eq!(ledger.audit_trail().len(), 3);
    // The most recent entries should be preserved.
    assert_eq!(ledger.audit_trail()[2].sequence, 10);
}

#[test]
fn enrichment_ledger_state_hash_deterministic_same_operations() {
    let mut l1 = AntiReplayLedger::new("s".into(), 32, 100);
    let mut l2 = AntiReplayLedger::new("s".into(), 32, 100);
    for seq in [3, 1, 7, 2, 5] {
        l1.check_and_record(seq, seq, None);
        l2.check_and_record(seq, seq, None);
    }
    assert_eq!(l1.state_hash(), l2.state_hash());
}

#[test]
fn enrichment_ledger_state_hash_differs_for_different_sessions() {
    let mut l1 = AntiReplayLedger::new("session-a".into(), 32, 100);
    let mut l2 = AntiReplayLedger::new("session-b".into(), 32, 100);
    l1.check_and_record(1, 1, None);
    l2.check_and_record(1, 1, None);
    assert_ne!(l1.state_hash(), l2.state_hash());
}

#[test]
fn enrichment_ledger_state_hash_differs_for_different_sequences() {
    let mut l1 = AntiReplayLedger::new("s".into(), 64, 100);
    let mut l2 = AntiReplayLedger::new("s".into(), 64, 100);
    l1.check_and_record(1, 1, None);
    l2.check_and_record(2, 1, None);
    assert_ne!(l1.state_hash(), l2.state_hash());
}

// ---------------------------------------------------------------------------
// 7. Degraded-mode policy tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strict_policy_blocks_all_except_close() {
    let p = DegradedModePolicy::strict(DegradedSeverity::IdentityCompromised);
    assert!(!p.allow_readonly_hostcalls);
    assert!(!p.allow_write_hostcalls);
    assert!(!p.allow_lifecycle_operations);
    assert!(!p.permits_any_data());
    assert!(p.emit_evidence);
    assert_eq!(p.max_degraded_messages, 0);
    assert_eq!(p.max_degraded_ticks, 0);
    assert!(!p.auto_rekey);
    // Close is always allowed
    assert!(p.is_operation_allowed(DegradedOperationKind::Close));
    assert!(!p.is_operation_allowed(DegradedOperationKind::ReadHostcall));
    assert!(!p.is_operation_allowed(DegradedOperationKind::WriteHostcall));
    assert!(!p.is_operation_allowed(DegradedOperationKind::LifecycleOperation));
}

#[test]
fn enrichment_permissive_policy_allows_reads_blocks_writes() {
    let p = DegradedModePolicy::permissive(DegradedSeverity::PartialMacFailure);
    assert!(p.allow_readonly_hostcalls);
    assert!(!p.allow_write_hostcalls);
    assert!(!p.allow_lifecycle_operations);
    assert!(p.permits_any_data());
    assert_eq!(p.max_degraded_messages, 100);
    assert_eq!(p.max_degraded_ticks, 5_000);
    assert!(p.auto_rekey);
    assert!(p.emit_evidence);
}

#[test]
fn enrichment_stale_key_policy_allows_reads_and_writes() {
    let p = DegradedModePolicy::for_severity(DegradedSeverity::StaleKey);
    assert!(p.allow_readonly_hostcalls);
    assert!(p.allow_write_hostcalls);
    assert!(!p.allow_lifecycle_operations);
    assert!(p.permits_any_data());
    assert_eq!(p.max_degraded_messages, 1_000);
    assert_eq!(p.max_degraded_ticks, 10_000);
    assert!(p.auto_rekey);
}

#[test]
fn enrichment_partial_mac_failure_uses_permissive() {
    let p = DegradedModePolicy::for_severity(DegradedSeverity::PartialMacFailure);
    let perm = DegradedModePolicy::permissive(DegradedSeverity::PartialMacFailure);
    assert_eq!(p, perm);
}

#[test]
fn enrichment_identity_compromised_uses_strict() {
    let p = DegradedModePolicy::for_severity(DegradedSeverity::IdentityCompromised);
    let strict = DegradedModePolicy::strict(DegradedSeverity::IdentityCompromised);
    assert_eq!(p, strict);
}

#[test]
fn enrichment_degraded_severity_ordering_total() {
    assert!(DegradedSeverity::StaleKey < DegradedSeverity::PartialMacFailure);
    assert!(DegradedSeverity::PartialMacFailure < DegradedSeverity::IdentityCompromised);
    assert!(DegradedSeverity::StaleKey < DegradedSeverity::IdentityCompromised);
}

#[test]
fn enrichment_close_always_allowed_in_all_policies() {
    let severities = [
        DegradedSeverity::StaleKey,
        DegradedSeverity::PartialMacFailure,
        DegradedSeverity::IdentityCompromised,
    ];
    for sev in &severities {
        let strict = DegradedModePolicy::strict(*sev);
        let permissive = DegradedModePolicy::permissive(*sev);
        let default = DegradedModePolicy::for_severity(*sev);
        assert!(strict.is_operation_allowed(DegradedOperationKind::Close));
        assert!(permissive.is_operation_allowed(DegradedOperationKind::Close));
        assert!(default.is_operation_allowed(DegradedOperationKind::Close));
    }
}

// ---------------------------------------------------------------------------
// 8. Protocol error Display tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_protocol_error_illegal_transition_display() {
    let e = ProtocolError::IllegalTransition {
        from: SessionPhaseTag::Uninit,
        to: SessionPhaseTag::Established,
    };
    let s = e.to_string();
    assert!(s.contains("illegal"), "should contain 'illegal': {}", s);
    assert!(s.contains("uninit"), "should contain 'uninit': {}", s);
    assert!(
        s.contains("established"),
        "should contain 'established': {}",
        s
    );
}

#[test]
fn enrichment_protocol_error_epoch_mismatch_display() {
    let e = ProtocolError::EpochMismatch {
        schedule_epoch: SecurityEpoch::from_raw(3),
        current_epoch: SecurityEpoch::from_raw(7),
    };
    let s = e.to_string();
    assert!(s.contains("3"), "should contain schedule epoch: {}", s);
    assert!(s.contains("7"), "should contain current epoch: {}", s);
}

#[test]
fn enrichment_protocol_error_incomplete_key_schedule_display() {
    let e = ProtocolError::IncompleteKeySchedule { stages_derived: 2 };
    let s = e.to_string();
    assert!(s.contains("2"), "should contain stages count: {}", s);
    assert!(s.contains("4"), "should contain total stages: {}", s);
}

#[test]
fn enrichment_protocol_error_replay_rejected_display() {
    let e = ProtocolError::ReplayRejected {
        sequence: 42,
        verdict: ReplayVerdict::Replay,
    };
    let s = e.to_string();
    assert!(s.contains("42"), "should contain sequence: {}", s);
    assert!(s.contains("replay"), "should contain verdict: {}", s);
}

#[test]
fn enrichment_protocol_error_degraded_blocked_display() {
    let e = ProtocolError::DegradedModeBlocked {
        operation: DegradedOperationKind::WriteHostcall,
        severity: DegradedSeverity::IdentityCompromised,
    };
    let s = e.to_string();
    assert!(
        s.contains("write_hostcall"),
        "should contain operation: {}",
        s
    );
    assert!(
        s.contains("identity_compromised"),
        "should contain severity: {}",
        s
    );
}

#[test]
fn enrichment_protocol_error_budget_exhausted_display() {
    let e = ProtocolError::DegradedBudgetExhausted {
        messages_used: 100,
        messages_limit: 100,
    };
    let s = e.to_string();
    assert!(s.contains("100"), "should contain count: {}", s);
    assert!(s.contains("budget"), "should contain 'budget': {}", s);
}

#[test]
fn enrichment_protocol_error_implements_std_error() {
    let e = ProtocolError::IncompleteKeySchedule { stages_derived: 1 };
    let _: &dyn std::error::Error = &e;
}

// ---------------------------------------------------------------------------
// 9. State machine behavior edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_state_machine_initial_phase_is_uninit() {
    let state = make_state();
    assert_eq!(state.phase, SessionPhaseTag::Uninit);
    assert!(state.key_schedule.is_none());
    assert!(state.degraded_policy.is_none());
    assert_eq!(state.degraded_messages, 0);
    assert!(state.degraded_entered_tick.is_none());
    assert!(state.transition_history.is_empty());
}

#[test]
fn enrichment_state_machine_transition_records_history() {
    let mut state = make_state();
    state
        .transition(
            SessionPhaseTag::Negotiating,
            TransitionTrigger::HandshakeInitiated,
            42,
        )
        .unwrap();
    assert_eq!(state.transition_history.len(), 1);
    let rec = &state.transition_history[0];
    assert_eq!(rec.from, SessionPhaseTag::Uninit);
    assert_eq!(rec.to, SessionPhaseTag::Negotiating);
    assert_eq!(rec.tick, 42);
}

#[test]
fn enrichment_state_machine_recovery_clears_degraded_state() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::StaleKey, "stale".into(), 10)
        .unwrap();
    assert!(state.degraded_policy.is_some());
    assert!(state.degraded_entered_tick.is_some());
    state.record_degraded_message();
    assert_eq!(state.degraded_messages, 1);

    state
        .transition(
            SessionPhaseTag::Established,
            TransitionTrigger::DegradedRecovery,
            20,
        )
        .unwrap();
    assert!(state.degraded_policy.is_none());
    assert_eq!(state.degraded_messages, 0);
    assert!(state.degraded_entered_tick.is_none());
}

#[test]
fn enrichment_state_machine_attach_incomplete_key_schedule_rejected() {
    let mut state = make_state();
    let mut ks = SessionKeySchedule::new(
        test_epoch(),
        "s".into(),
        "e".into(),
        "h".into(),
        test_hash(),
    );
    ks.record_stage(KeyStagePurpose::MasterSecret, ContentHash::compute(b"m"));
    let result = state.attach_key_schedule(ks);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProtocolError::IncompleteKeySchedule { stages_derived } => {
            assert_eq!(stages_derived, 1);
        }
        other => panic!("Expected IncompleteKeySchedule, got {:?}", other),
    }
}

#[test]
fn enrichment_state_machine_attach_complete_key_schedule_accepted() {
    let mut state = make_state();
    let ks = make_complete_key_schedule();
    state.attach_key_schedule(ks).unwrap();
    assert!(state.key_schedule.is_some());
}

#[test]
fn enrichment_state_machine_validate_epoch_no_schedule_ok() {
    let state = make_state();
    // No key schedule attached, so epoch validation should pass.
    assert!(state.validate_epoch(SecurityEpoch::from_raw(999)).is_ok());
}

#[test]
fn enrichment_state_machine_validate_epoch_matching() {
    let mut state = make_state();
    state
        .attach_key_schedule(make_complete_key_schedule())
        .unwrap();
    assert!(state.validate_epoch(test_epoch()).is_ok());
}

#[test]
fn enrichment_state_machine_validate_epoch_mismatch() {
    let mut state = make_state();
    state
        .attach_key_schedule(make_complete_key_schedule())
        .unwrap();
    let err = state
        .validate_epoch(SecurityEpoch::from_raw(99))
        .unwrap_err();
    match err {
        ProtocolError::EpochMismatch {
            schedule_epoch,
            current_epoch,
        } => {
            assert_eq!(schedule_epoch, test_epoch());
            assert_eq!(current_epoch, SecurityEpoch::from_raw(99));
        }
        other => panic!("Expected EpochMismatch, got {:?}", other),
    }
}

#[test]
fn enrichment_state_machine_check_operation_in_uninit_fails() {
    let state = make_state();
    let result = state.check_operation(DegradedOperationKind::ReadHostcall, 1);
    assert!(result.is_err());
}

#[test]
fn enrichment_state_machine_check_operation_in_negotiating_fails() {
    let mut state = make_state();
    state
        .transition(
            SessionPhaseTag::Negotiating,
            TransitionTrigger::HandshakeInitiated,
            1,
        )
        .unwrap();
    let result = state.check_operation(DegradedOperationKind::ReadHostcall, 2);
    assert!(result.is_err());
}

#[test]
fn enrichment_state_machine_check_operation_established_allows_all() {
    let state = make_established_state();
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 10)
            .is_ok()
    );
    assert!(
        state
            .check_operation(DegradedOperationKind::WriteHostcall, 10)
            .is_ok()
    );
    assert!(
        state
            .check_operation(DegradedOperationKind::LifecycleOperation, 10)
            .is_ok()
    );
    assert!(
        state
            .check_operation(DegradedOperationKind::Close, 10)
            .is_ok()
    );
}

#[test]
fn enrichment_state_machine_degraded_close_bypasses_budget() {
    let mut state = make_established_state();
    state
        .enter_degraded(
            DegradedSeverity::IdentityCompromised,
            "compromised".into(),
            10,
        )
        .unwrap();
    // IdentityCompromised strict policy: max_degraded_messages = 0
    // Close should still work.
    assert!(
        state
            .check_operation(DegradedOperationKind::Close, 20)
            .is_ok()
    );
}

#[test]
fn enrichment_state_machine_degraded_message_budget_enforcement() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::PartialMacFailure, "mac".into(), 10)
        .unwrap();
    let limit = state
        .degraded_policy
        .as_ref()
        .unwrap()
        .max_degraded_messages;
    // Within budget
    for _ in 0..(limit - 1) {
        state.record_degraded_message();
    }
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 11)
            .is_ok()
    );
    // At budget
    state.record_degraded_message();
    let result = state.check_operation(DegradedOperationKind::ReadHostcall, 12);
    assert!(result.is_err());
}

#[test]
fn enrichment_state_machine_degraded_time_budget_at_boundary() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::StaleKey, "stale".into(), 100)
        .unwrap();
    let max_ticks = state.degraded_policy.as_ref().unwrap().max_degraded_ticks;
    // Exactly at the boundary tick: 100 + max_ticks
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 100 + max_ticks)
            .is_ok()
    );
    // One tick past the boundary
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 100 + max_ticks + 1)
            .is_err()
    );
}

#[test]
fn enrichment_state_machine_record_degraded_message_only_in_degraded() {
    let mut state = make_established_state();
    state.record_degraded_message();
    // Not in degraded mode, so counter should not increment.
    assert_eq!(state.degraded_messages, 0);
}

#[test]
fn enrichment_state_machine_check_replay_integration() {
    let mut state = make_state();
    assert!(state.check_replay(1, 10, None).is_ok());
    assert!(state.check_replay(2, 20, None).is_ok());
    let err = state.check_replay(1, 30, None).unwrap_err();
    match err {
        ProtocolError::ReplayRejected { sequence, verdict } => {
            assert_eq!(sequence, 1);
            assert_eq!(verdict, ReplayVerdict::Replay);
        }
        other => panic!("Expected ReplayRejected, got {:?}", other),
    }
}

#[test]
fn enrichment_state_machine_full_lifecycle_happy_path() {
    let mut state = make_state();
    state
        .transition(
            SessionPhaseTag::Negotiating,
            TransitionTrigger::HandshakeInitiated,
            1,
        )
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Established,
            TransitionTrigger::HandshakeCompleted,
            2,
        )
        .unwrap();
    state
        .attach_key_schedule(make_complete_key_schedule())
        .unwrap();
    state.check_replay(1, 10, None).unwrap();
    state.check_replay(2, 20, None).unwrap();
    state
        .transition(
            SessionPhaseTag::Closing,
            TransitionTrigger::CloseInitiated,
            50,
        )
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Closed,
            TransitionTrigger::DrainCompleted,
            60,
        )
        .unwrap();
    assert!(state.phase.is_terminal());
    assert_eq!(state.transition_history.len(), 4);
}

#[test]
fn enrichment_state_machine_degraded_then_close_lifecycle() {
    let mut state = make_established_state();
    state
        .enter_degraded(
            DegradedSeverity::IdentityCompromised,
            "compromised".into(),
            10,
        )
        .unwrap();
    assert_eq!(state.phase, SessionPhaseTag::DegradedOpen);
    state
        .transition(
            SessionPhaseTag::Closing,
            TransitionTrigger::CloseInitiated,
            20,
        )
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Closed,
            TransitionTrigger::DrainCompleted,
            30,
        )
        .unwrap();
    assert!(state.phase.is_terminal());
}

#[test]
fn enrichment_state_machine_expiry_from_established() {
    let mut state = make_established_state();
    state
        .transition(
            SessionPhaseTag::Closed,
            TransitionTrigger::SessionExpired {
                reason: "ttl".into(),
            },
            100,
        )
        .unwrap();
    assert!(state.phase.is_terminal());
}

#[test]
fn enrichment_state_machine_expiry_from_degraded() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::StaleKey, "stale".into(), 10)
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Closed,
            TransitionTrigger::SessionExpired {
                reason: "ttl".into(),
            },
            100,
        )
        .unwrap();
    assert!(state.phase.is_terminal());
}

#[test]
fn enrichment_state_machine_replay_threshold_breach_from_established() {
    let mut state = make_established_state();
    state
        .transition(
            SessionPhaseTag::Closed,
            TransitionTrigger::ReplayThresholdBreached {
                drop_count: 50,
                window_ticks: 100,
            },
            100,
        )
        .unwrap();
    assert!(state.phase.is_terminal());
}

// ---------------------------------------------------------------------------
// 10. Corpus and runner tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_not_empty() {
    let corpus = hsp_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn enrichment_corpus_has_at_least_twelve_specimens() {
    let corpus = hsp_corpus();
    assert!(
        corpus.len() >= 12,
        "Corpus should have at least 12 specimens, got {}",
        corpus.len()
    );
}

#[test]
fn enrichment_corpus_specimen_names_unique() {
    let corpus = hsp_corpus();
    let names: BTreeSet<&str> = corpus.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names.len(), corpus.len(), "Specimen names must be unique");
}

#[test]
fn enrichment_corpus_covers_all_families() {
    let corpus = hsp_corpus();
    let families: BTreeSet<HspSpecimenFamily> = corpus.iter().map(|s| s.family).collect();
    for fam in HspSpecimenFamily::ALL {
        assert!(families.contains(fam), "Corpus missing family {}", fam);
    }
}

#[test]
fn enrichment_corpus_content_hashes_unique() {
    let corpus = hsp_corpus();
    let hashes: BTreeSet<Vec<u8>> = corpus
        .iter()
        .map(|s| s.content_hash.as_bytes().to_vec())
        .collect();
    assert_eq!(
        hashes.len(),
        corpus.len(),
        "Specimen content hashes must be unique"
    );
}

#[test]
fn enrichment_corpus_deterministic() {
    let c1 = hsp_corpus();
    let c2 = hsp_corpus();
    assert_eq!(c1.len(), c2.len());
    for (s1, s2) in c1.iter().zip(c2.iter()) {
        assert_eq!(s1.name, s2.name);
        assert_eq!(s1.family, s2.family);
        assert_eq!(s1.transition_count, s2.transition_count);
        assert_eq!(s1.clean_completion, s2.clean_completion);
        assert_eq!(s1.content_hash, s2.content_hash);
    }
}

#[test]
fn enrichment_runner_result_specimen_count_matches_corpus() {
    let corpus = hsp_corpus();
    let result = run_hsp_corpus();
    assert_eq!(result.specimen_count, corpus.len());
}

#[test]
fn enrichment_runner_result_families_covered_matches_corpus() {
    let result = run_hsp_corpus();
    let families: BTreeSet<HspSpecimenFamily> = result.families_covered.iter().copied().collect();
    for fam in HspSpecimenFamily::ALL {
        assert!(
            families.contains(fam),
            "Runner result missing family {}",
            fam
        );
    }
}

#[test]
fn enrichment_runner_result_deterministic() {
    let r1 = run_hsp_corpus();
    let r2 = run_hsp_corpus();
    assert_eq!(r1.specimen_count, r2.specimen_count);
    assert_eq!(r1.all_clean, r2.all_clean);
    assert_eq!(r1.terminal_count, r2.terminal_count);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_runner_result_has_terminal_specimens() {
    let result = run_hsp_corpus();
    assert!(
        result.terminal_count > 0,
        "Should have at least one terminal specimen"
    );
}

#[test]
fn enrichment_evidence_bundle_writes_files() {
    let dir = std::env::temp_dir().join("hsp_enrichment_evidence_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_hsp_evidence_bundle(&dir).unwrap();
    assert!(dir.join("hsp_inventory.json").exists());
    assert!(dir.join("hsp_manifest.json").exists());
    assert!(dir.join("hsp_events.jsonl").exists());
    assert!(dir.join("hsp_commands.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 11. TransitionTrigger Display tests with payloads
// ---------------------------------------------------------------------------

#[test]
fn enrichment_trigger_security_degradation_display_includes_reason() {
    let t = TransitionTrigger::SecurityDegradation {
        reason: "epoch_advanced".into(),
    };
    let s = t.to_string();
    assert!(
        s.contains("security_degradation"),
        "should contain 'security_degradation': {}",
        s
    );
    assert!(s.contains("epoch_advanced"), "should contain reason: {}", s);
}

#[test]
fn enrichment_trigger_session_expired_display_includes_reason() {
    let t = TransitionTrigger::SessionExpired {
        reason: "ttl_exceeded".into(),
    };
    let s = t.to_string();
    assert!(
        s.contains("session_expired"),
        "should contain 'session_expired': {}",
        s
    );
    assert!(s.contains("ttl_exceeded"), "should contain reason: {}", s);
}

#[test]
fn enrichment_trigger_replay_threshold_display_includes_counts() {
    let t = TransitionTrigger::ReplayThresholdBreached {
        drop_count: 42,
        window_ticks: 1000,
    };
    let s = t.to_string();
    assert!(s.contains("42"), "should contain drop_count: {}", s);
    assert!(s.contains("1000"), "should contain window_ticks: {}", s);
}

// ---------------------------------------------------------------------------
// 12. HspSpecimenFamily ALL constant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hsp_specimen_family_all_count() {
    assert_eq!(HspSpecimenFamily::ALL.len(), 8);
}

#[test]
fn enrichment_key_stage_purpose_all_count() {
    assert_eq!(KeyStagePurpose::ALL.len(), 4);
}

// ---------------------------------------------------------------------------
// 13. Additional deterministic hash and clone behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_key_schedule_clone_preserves_binding_hash() {
    let ks = make_complete_key_schedule();
    let ks_clone = ks.clone();
    assert_eq!(ks.binding_hash(), ks_clone.binding_hash());
}

#[test]
fn enrichment_ledger_clone_preserves_state_hash() {
    let mut ledger = AntiReplayLedger::new("s".into(), 32, 100);
    for seq in 1..=5 {
        ledger.check_and_record(seq, seq, None);
    }
    let ledger_clone = ledger.clone();
    assert_eq!(ledger.state_hash(), ledger_clone.state_hash());
}

#[test]
fn enrichment_phase_transition_valid_transitions_have_distinct_from_to() {
    let table = valid_transitions();
    for pt in &table {
        assert_ne!(
            pt.from, pt.to,
            "Transition table entry should not be a self-loop"
        );
    }
}

#[test]
fn enrichment_phase_transition_no_outgoing_from_closed_in_table() {
    let table = valid_transitions();
    for pt in &table {
        assert_ne!(
            pt.from,
            SessionPhaseTag::Closed,
            "Closed should have no outgoing transitions in the table"
        );
    }
}
