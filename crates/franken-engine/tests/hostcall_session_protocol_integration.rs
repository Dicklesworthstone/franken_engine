//! Integration tests for the hostcall session protocol module.
//!
//! Covers: corpus invariants, runner/inventory, evidence hashes, serde roundtrips,
//! typestate machine, key schedule, anti-replay ledger, degraded-mode policy,
//! protocol errors, specimen families, and bundle writer.

use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::hostcall_session_protocol::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn test_hash() -> ContentHash {
    ContentHash::compute(b"integration-test")
}

fn make_state() -> SessionProtocolState {
    SessionProtocolState::new(
        "int-sess".into(),
        "int-ext".into(),
        "int-host".into(),
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

fn make_key_schedule(session_id: &str) -> SessionKeySchedule {
    let mut ks = SessionKeySchedule::new(
        test_epoch(),
        session_id.into(),
        "int-ext".into(),
        "int-host".into(),
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
// Corpus invariant tests
// ---------------------------------------------------------------------------

#[test]
fn corpus_is_nonempty() {
    let corpus = hsp_corpus();
    assert!(corpus.len() >= 10);
}

#[test]
fn corpus_specimen_names_unique() {
    let corpus = hsp_corpus();
    let names: std::collections::BTreeSet<&str> = corpus.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names.len(), corpus.len());
}

#[test]
fn corpus_specimen_hashes_unique() {
    let corpus = hsp_corpus();
    let hashes: std::collections::BTreeSet<String> = corpus
        .iter()
        .map(|s| format!("{:?}", s.content_hash))
        .collect();
    assert_eq!(hashes.len(), corpus.len());
}

#[test]
fn corpus_covers_all_families() {
    let corpus = hsp_corpus();
    let families: std::collections::BTreeSet<HspSpecimenFamily> =
        corpus.iter().map(|s| s.family).collect();
    for fam in HspSpecimenFamily::ALL {
        assert!(families.contains(fam), "family {fam} not covered in corpus");
    }
}

#[test]
fn corpus_deterministic() {
    let c1 = hsp_corpus();
    let c2 = hsp_corpus();
    assert_eq!(c1.len(), c2.len());
    for (a, b) in c1.iter().zip(c2.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.content_hash, b.content_hash);
        assert_eq!(a.transition_count, b.transition_count);
    }
}

#[test]
fn corpus_all_specimens_have_clean_completion() {
    let corpus = hsp_corpus();
    for spec in &corpus {
        assert!(
            spec.clean_completion,
            "specimen {} has clean_completion=false",
            spec.name
        );
    }
}

// ---------------------------------------------------------------------------
// Runner tests
// ---------------------------------------------------------------------------

#[test]
fn runner_result_matches_corpus() {
    let result = run_hsp_corpus();
    let corpus = hsp_corpus();
    assert_eq!(result.specimen_count, corpus.len());
}

#[test]
fn runner_covers_all_families() {
    let result = run_hsp_corpus();
    assert_eq!(result.families_covered.len(), HspSpecimenFamily::ALL.len());
}

#[test]
fn runner_all_clean() {
    let result = run_hsp_corpus();
    assert!(result.all_clean);
}

#[test]
fn runner_terminal_count_positive() {
    let result = run_hsp_corpus();
    assert!(result.terminal_count > 0);
}

#[test]
fn runner_hash_deterministic() {
    let r1 = run_hsp_corpus();
    let r2 = run_hsp_corpus();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn runner_serde_roundtrip() {
    let result = run_hsp_corpus();
    let json = serde_json::to_string(&result).unwrap();
    let back: HspRunnerResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.specimen_count, back.specimen_count);
    assert_eq!(result.all_clean, back.all_clean);
    assert_eq!(result.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// SessionPhaseTag tests
// ---------------------------------------------------------------------------

#[test]
fn phase_tag_all_has_six_variants() {
    assert_eq!(SessionPhaseTag::ALL.len(), 6);
}

#[test]
fn phase_tag_terminal_only_closed() {
    for tag in SessionPhaseTag::ALL {
        if *tag == SessionPhaseTag::Closed {
            assert!(tag.is_terminal());
        } else {
            assert!(!tag.is_terminal());
        }
    }
}

#[test]
fn phase_tag_data_only_established_and_degraded() {
    for tag in SessionPhaseTag::ALL {
        let expected = matches!(
            tag,
            SessionPhaseTag::Established | SessionPhaseTag::DegradedOpen
        );
        assert_eq!(tag.permits_data(), expected, "wrong for {tag}");
    }
}

#[test]
fn phase_tag_display_roundtrip_stable() {
    let displays: Vec<String> = SessionPhaseTag::ALL.iter().map(|t| t.to_string()).collect();
    let expected = vec![
        "uninit",
        "negotiating",
        "established",
        "degraded_open",
        "closing",
        "closed",
    ];
    assert_eq!(displays, expected);
}

#[test]
fn phase_tag_serde_all_variants() {
    for tag in SessionPhaseTag::ALL {
        let json = serde_json::to_string(tag).unwrap();
        let back: SessionPhaseTag = serde_json::from_str(&json).unwrap();
        assert_eq!(*tag, back);
    }
}

#[test]
fn phase_tag_ord_consistent() {
    assert!(SessionPhaseTag::Uninit < SessionPhaseTag::Negotiating);
    assert!(SessionPhaseTag::Negotiating < SessionPhaseTag::Established);
}

// ---------------------------------------------------------------------------
// Transition table tests
// ---------------------------------------------------------------------------

#[test]
fn transition_table_nonempty() {
    let table = valid_transitions();
    assert!(table.len() >= 10);
}

#[test]
fn transition_table_no_self_loops() {
    let table = valid_transitions();
    for t in &table {
        assert_ne!(t.from, t.to, "self-loop in transition table");
    }
}

#[test]
fn transition_table_no_exits_from_closed() {
    let table = valid_transitions();
    for t in &table {
        assert_ne!(
            t.from,
            SessionPhaseTag::Closed,
            "transition from Closed found"
        );
    }
}

#[test]
fn is_valid_transition_symmetric_with_table() {
    for from in SessionPhaseTag::ALL {
        for to in SessionPhaseTag::ALL {
            let table_says = valid_transitions()
                .iter()
                .any(|t| t.from == *from && t.to == *to);
            if *from == *to || *from == SessionPhaseTag::Closed {
                assert!(!is_valid_transition(*from, *to));
            } else {
                assert_eq!(
                    is_valid_transition(*from, *to),
                    table_says,
                    "mismatch for {from} -> {to}"
                );
            }
        }
    }
}

#[test]
fn transition_trigger_display_all_variants() {
    let triggers = vec![
        TransitionTrigger::HandshakeInitiated,
        TransitionTrigger::HandshakeCompleted,
        TransitionTrigger::HandshakeRejected,
        TransitionTrigger::SecurityDegradation {
            reason: "test".into(),
        },
        TransitionTrigger::DegradedRecovery,
        TransitionTrigger::CloseInitiated,
        TransitionTrigger::SessionExpired {
            reason: "ttl".into(),
        },
        TransitionTrigger::DrainCompleted,
        TransitionTrigger::ReplayThresholdBreached {
            drop_count: 5,
            window_ticks: 10,
        },
    ];
    for t in &triggers {
        let s = t.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn transition_trigger_serde_roundtrip() {
    let triggers = vec![
        TransitionTrigger::HandshakeInitiated,
        TransitionTrigger::HandshakeCompleted,
        TransitionTrigger::SecurityDegradation {
            reason: "epoch".into(),
        },
        TransitionTrigger::SessionExpired {
            reason: "budget".into(),
        },
        TransitionTrigger::ReplayThresholdBreached {
            drop_count: 10,
            window_ticks: 100,
        },
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let back: TransitionTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ---------------------------------------------------------------------------
// Key schedule tests
// ---------------------------------------------------------------------------

#[test]
fn key_schedule_new_incomplete() {
    let ks = SessionKeySchedule::new(
        test_epoch(),
        "s".into(),
        "e".into(),
        "h".into(),
        test_hash(),
    );
    assert!(!ks.is_complete());
    assert!(ks.derived_stages.is_empty());
}

#[test]
fn key_schedule_all_stages_makes_complete() {
    let ks = make_key_schedule("s1");
    assert!(ks.is_complete());
    assert_eq!(ks.derived_stages.len(), 4);
}

#[test]
fn key_schedule_epoch_validation() {
    let ks = make_key_schedule("s1");
    assert!(ks.is_valid_for_epoch(test_epoch()));
    assert!(!ks.is_valid_for_epoch(SecurityEpoch::from_raw(999)));
}

#[test]
fn key_schedule_binding_hash_deterministic() {
    let h1 = make_key_schedule("s1").binding_hash();
    let h2 = make_key_schedule("s1").binding_hash();
    assert_eq!(h1, h2);
}

#[test]
fn key_schedule_binding_hash_session_sensitive() {
    let h1 = make_key_schedule("s1").binding_hash();
    let h2 = make_key_schedule("s2").binding_hash();
    assert_ne!(h1, h2);
}

#[test]
fn key_schedule_serde_roundtrip() {
    let ks = make_key_schedule("serde-test");
    let json = serde_json::to_string(&ks).unwrap();
    let back: SessionKeySchedule = serde_json::from_str(&json).unwrap();
    assert_eq!(ks.session_id, back.session_id);
    assert_eq!(ks.derived_stages.len(), back.derived_stages.len());
    assert_eq!(ks.epoch, back.epoch);
}

#[test]
fn key_stage_purpose_all_has_four() {
    assert_eq!(KeyStagePurpose::ALL.len(), 4);
}

#[test]
fn key_stage_purpose_domain_labels_unique() {
    let labels: std::collections::BTreeSet<&str> = KeyStagePurpose::ALL
        .iter()
        .map(|p| p.domain_label())
        .collect();
    assert_eq!(labels.len(), 4);
}

#[test]
fn key_stage_purpose_domain_labels_prefixed() {
    for p in KeyStagePurpose::ALL {
        assert!(p.domain_label().starts_with("franken::hsp::"));
    }
}

#[test]
fn key_stage_purpose_display() {
    assert_eq!(KeyStagePurpose::MasterSecret.to_string(), "master_secret");
    assert_eq!(KeyStagePurpose::DataPlaneMac.to_string(), "data_plane_mac");
    assert_eq!(
        KeyStagePurpose::DataPlaneEncrypt.to_string(),
        "data_plane_encrypt"
    );
    assert_eq!(
        KeyStagePurpose::BackpressureSign.to_string(),
        "backpressure_sign"
    );
}

// ---------------------------------------------------------------------------
// Anti-replay ledger tests
// ---------------------------------------------------------------------------

#[test]
fn ledger_accepts_first() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 64, 100);
    assert_eq!(ledger.check_and_record(1, 1, None), ReplayVerdict::Accept);
    assert_eq!(ledger.total_accepted(), 1);
}

#[test]
fn ledger_rejects_replay() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 64, 100);
    ledger.check_and_record(1, 1, None);
    assert_eq!(ledger.check_and_record(1, 2, None), ReplayVerdict::Replay);
    assert_eq!(ledger.total_replays(), 1);
}

#[test]
fn ledger_monotonic_accepts() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 64, 100);
    for seq in 1..=20 {
        assert_eq!(
            ledger.check_and_record(seq, seq, None),
            ReplayVerdict::Accept
        );
    }
    assert_eq!(ledger.total_accepted(), 20);
}

#[test]
fn ledger_out_of_order_within_window() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 64, 100);
    ledger.check_and_record(10, 1, None);
    assert_eq!(ledger.check_and_record(5, 2, None), ReplayVerdict::Accept);
    assert_eq!(ledger.check_and_record(8, 3, None), ReplayVerdict::Accept);
}

#[test]
fn ledger_below_floor_rejected() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 4, 100);
    for seq in 1..=10 {
        ledger.check_and_record(seq, seq, None);
    }
    assert_eq!(
        ledger.check_and_record(1, 11, None),
        ReplayVerdict::BelowFloor
    );
    assert_eq!(ledger.total_below_floor(), 1);
}

#[test]
fn ledger_above_ceiling_rejected() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 4, 100);
    ledger.check_and_record(1, 1, None);
    assert_eq!(
        ledger.check_and_record(100, 2, None),
        ReplayVerdict::AboveCeiling
    );
}

#[test]
fn ledger_window_advances_correctly() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 4, 100);
    for seq in 1..=10 {
        ledger.check_and_record(seq, seq, None);
    }
    assert!(ledger.window_floor() >= 6);
    assert_eq!(ledger.window_ceiling(), 10);
}

#[test]
fn ledger_window_size_bounded() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 4, 100);
    for seq in 1..=20 {
        ledger.check_and_record(seq, seq, None);
    }
    assert!(ledger.window_size() <= 5);
}

#[test]
fn ledger_audit_trail_bounded() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 1000, 5);
    for seq in 1..=20 {
        ledger.check_and_record(seq, seq, None);
    }
    assert!(ledger.audit_trail().len() <= 5);
}

#[test]
fn ledger_total_checked_counts_all() {
    let mut ledger = AntiReplayLedger::new("l1".into(), 64, 100);
    ledger.check_and_record(1, 1, None);
    ledger.check_and_record(1, 2, None); // replay
    ledger.check_and_record(2, 3, None);
    assert_eq!(ledger.total_checked(), 3);
}

#[test]
fn ledger_state_hash_deterministic() {
    let mut l1 = AntiReplayLedger::new("l".into(), 64, 100);
    let mut l2 = AntiReplayLedger::new("l".into(), 64, 100);
    for seq in 1..=5 {
        l1.check_and_record(seq, seq, None);
        l2.check_and_record(seq, seq, None);
    }
    assert_eq!(l1.state_hash(), l2.state_hash());
}

#[test]
fn ledger_state_hash_divergence() {
    let mut l1 = AntiReplayLedger::new("l".into(), 64, 100);
    let mut l2 = AntiReplayLedger::new("l".into(), 64, 100);
    l1.check_and_record(1, 1, None);
    l2.check_and_record(2, 1, None);
    assert_ne!(l1.state_hash(), l2.state_hash());
}

#[test]
fn ledger_serde_roundtrip() {
    let mut ledger = AntiReplayLedger::new("l".into(), 64, 100);
    ledger.check_and_record(1, 1, None);
    ledger.check_and_record(2, 2, None);
    let json = serde_json::to_string(&ledger).unwrap();
    let back: AntiReplayLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_accepted(), 2);
    assert_eq!(back.session_id(), "l");
}

#[test]
fn ledger_session_id_accessor() {
    let ledger = AntiReplayLedger::new("my-session".into(), 64, 100);
    assert_eq!(ledger.session_id(), "my-session");
}

#[test]
fn ledger_envelope_hash_preserved() {
    let mut ledger = AntiReplayLedger::new("l".into(), 64, 100);
    let h = ContentHash::compute(b"envelope-data");
    ledger.check_and_record(1, 1, Some(h.clone()));
    let trail = ledger.audit_trail();
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].envelope_hash, Some(h));
}

// ---------------------------------------------------------------------------
// ReplayVerdict tests
// ---------------------------------------------------------------------------

#[test]
fn replay_verdict_display() {
    assert_eq!(ReplayVerdict::Accept.to_string(), "accept");
    assert_eq!(ReplayVerdict::Replay.to_string(), "replay");
    assert_eq!(ReplayVerdict::BelowFloor.to_string(), "below_floor");
    assert_eq!(ReplayVerdict::AboveCeiling.to_string(), "above_ceiling");
}

#[test]
fn replay_verdict_serde_all() {
    for v in &[
        ReplayVerdict::Accept,
        ReplayVerdict::Replay,
        ReplayVerdict::BelowFloor,
        ReplayVerdict::AboveCeiling,
    ] {
        let json = serde_json::to_string(v).unwrap();
        let back: ReplayVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// DegradedModePolicy tests
// ---------------------------------------------------------------------------

#[test]
fn strict_policy_blocks_everything() {
    let p = DegradedModePolicy::strict(DegradedSeverity::IdentityCompromised);
    assert!(!p.permits_any_data());
    assert!(!p.is_operation_allowed(DegradedOperationKind::ReadHostcall));
    assert!(!p.is_operation_allowed(DegradedOperationKind::WriteHostcall));
    assert!(!p.is_operation_allowed(DegradedOperationKind::LifecycleOperation));
    assert!(p.is_operation_allowed(DegradedOperationKind::Close));
}

#[test]
fn permissive_policy_allows_reads_blocks_writes() {
    let p = DegradedModePolicy::permissive(DegradedSeverity::PartialMacFailure);
    assert!(p.permits_any_data());
    assert!(p.is_operation_allowed(DegradedOperationKind::ReadHostcall));
    assert!(!p.is_operation_allowed(DegradedOperationKind::WriteHostcall));
    assert!(p.is_operation_allowed(DegradedOperationKind::Close));
}

#[test]
fn stale_key_default_allows_writes_and_rekey() {
    let p = DegradedModePolicy::for_severity(DegradedSeverity::StaleKey);
    assert!(p.allow_write_hostcalls);
    assert!(p.auto_rekey);
    assert!(p.max_degraded_messages > 0);
}

#[test]
fn identity_compromised_default_is_strict() {
    let p = DegradedModePolicy::for_severity(DegradedSeverity::IdentityCompromised);
    assert!(!p.permits_any_data());
    assert!(!p.auto_rekey);
}

#[test]
fn degraded_severity_ordering() {
    assert!(DegradedSeverity::StaleKey < DegradedSeverity::PartialMacFailure);
    assert!(DegradedSeverity::PartialMacFailure < DegradedSeverity::IdentityCompromised);
}

#[test]
fn degraded_severity_display() {
    assert_eq!(DegradedSeverity::StaleKey.to_string(), "stale_key");
    assert_eq!(
        DegradedSeverity::PartialMacFailure.to_string(),
        "partial_mac_failure"
    );
    assert_eq!(
        DegradedSeverity::IdentityCompromised.to_string(),
        "identity_compromised"
    );
}

#[test]
fn degraded_operation_kind_display() {
    assert_eq!(
        DegradedOperationKind::ReadHostcall.to_string(),
        "read_hostcall"
    );
    assert_eq!(
        DegradedOperationKind::WriteHostcall.to_string(),
        "write_hostcall"
    );
    assert_eq!(
        DegradedOperationKind::LifecycleOperation.to_string(),
        "lifecycle_operation"
    );
    assert_eq!(DegradedOperationKind::Close.to_string(), "close");
}

#[test]
fn degraded_policy_serde_roundtrip() {
    let p = DegradedModePolicy::for_severity(DegradedSeverity::StaleKey);
    let json = serde_json::to_string(&p).unwrap();
    let back: DegradedModePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p.severity, back.severity);
    assert_eq!(p.allow_readonly_hostcalls, back.allow_readonly_hostcalls);
    assert_eq!(p.allow_write_hostcalls, back.allow_write_hostcalls);
    assert_eq!(p.max_degraded_messages, back.max_degraded_messages);
}

// ---------------------------------------------------------------------------
// ProtocolError tests
// ---------------------------------------------------------------------------

#[test]
fn protocol_error_illegal_transition_display() {
    let e = ProtocolError::IllegalTransition {
        from: SessionPhaseTag::Uninit,
        to: SessionPhaseTag::Established,
    };
    let s = e.to_string();
    assert!(s.contains("illegal"));
    assert!(s.contains("uninit"));
    assert!(s.contains("established"));
}

#[test]
fn protocol_error_epoch_mismatch_display() {
    let e = ProtocolError::EpochMismatch {
        schedule_epoch: SecurityEpoch::from_raw(1),
        current_epoch: SecurityEpoch::from_raw(5),
    };
    assert!(e.to_string().contains("epoch"));
}

#[test]
fn protocol_error_incomplete_schedule_display() {
    let e = ProtocolError::IncompleteKeySchedule { stages_derived: 2 };
    assert!(e.to_string().contains("2/4"));
}

#[test]
fn protocol_error_replay_display() {
    let e = ProtocolError::ReplayRejected {
        sequence: 42,
        verdict: ReplayVerdict::Replay,
    };
    assert!(e.to_string().contains("42"));
}

#[test]
fn protocol_error_degraded_blocked_display() {
    let e = ProtocolError::DegradedModeBlocked {
        operation: DegradedOperationKind::WriteHostcall,
        severity: DegradedSeverity::PartialMacFailure,
    };
    assert!(e.to_string().contains("write_hostcall"));
}

#[test]
fn protocol_error_budget_display() {
    let e = ProtocolError::DegradedBudgetExhausted {
        messages_used: 100,
        messages_limit: 100,
    };
    assert!(e.to_string().contains("100/100"));
}

#[test]
fn protocol_error_serde_roundtrip() {
    let errors = vec![
        ProtocolError::IllegalTransition {
            from: SessionPhaseTag::Uninit,
            to: SessionPhaseTag::Closed,
        },
        ProtocolError::EpochMismatch {
            schedule_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        },
        ProtocolError::IncompleteKeySchedule { stages_derived: 3 },
        ProtocolError::ReplayRejected {
            sequence: 99,
            verdict: ReplayVerdict::BelowFloor,
        },
        ProtocolError::DegradedModeBlocked {
            operation: DegradedOperationKind::LifecycleOperation,
            severity: DegradedSeverity::IdentityCompromised,
        },
        ProtocolError::DegradedBudgetExhausted {
            messages_used: 50,
            messages_limit: 50,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ProtocolError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// SessionProtocolState tests
// ---------------------------------------------------------------------------

#[test]
fn state_initial_is_uninit() {
    let state = make_state();
    assert_eq!(state.phase, SessionPhaseTag::Uninit);
    assert!(state.key_schedule.is_none());
    assert!(state.degraded_policy.is_none());
    assert!(state.transition_history.is_empty());
}

#[test]
fn state_full_happy_path() {
    let mut state = make_established_state();
    state
        .transition(
            SessionPhaseTag::Closing,
            TransitionTrigger::CloseInitiated,
            3,
        )
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Closed,
            TransitionTrigger::DrainCompleted,
            4,
        )
        .unwrap();
    assert!(state.phase.is_terminal());
    assert_eq!(state.transition_history.len(), 4);
}

#[test]
fn state_invalid_transition_rejected() {
    let mut state = make_state();
    let err = state.transition(
        SessionPhaseTag::Established,
        TransitionTrigger::HandshakeCompleted,
        1,
    );
    assert!(err.is_err());
    assert_eq!(state.phase, SessionPhaseTag::Uninit);
}

#[test]
fn state_no_exit_from_closed() {
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
            SessionPhaseTag::Closed,
            TransitionTrigger::HandshakeRejected,
            2,
        )
        .unwrap();
    let err = state.transition(
        SessionPhaseTag::Negotiating,
        TransitionTrigger::HandshakeInitiated,
        3,
    );
    assert!(err.is_err());
}

#[test]
fn state_attach_complete_key_schedule() {
    let mut state = make_state();
    let ks = make_key_schedule("int-sess");
    state.attach_key_schedule(ks).unwrap();
    assert!(state.key_schedule.is_some());
}

#[test]
fn state_reject_incomplete_key_schedule() {
    let mut state = make_state();
    let ks = SessionKeySchedule::new(
        test_epoch(),
        "s".into(),
        "e".into(),
        "h".into(),
        test_hash(),
    );
    assert!(state.attach_key_schedule(ks).is_err());
}

#[test]
fn state_epoch_validation_pass() {
    let mut state = make_state();
    let ks = make_key_schedule("int-sess");
    state.attach_key_schedule(ks).unwrap();
    assert!(state.validate_epoch(test_epoch()).is_ok());
}

#[test]
fn state_epoch_validation_fail() {
    let mut state = make_state();
    let ks = make_key_schedule("int-sess");
    state.attach_key_schedule(ks).unwrap();
    assert!(state.validate_epoch(SecurityEpoch::from_raw(99)).is_err());
}

#[test]
fn state_degraded_entry_and_recovery() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::StaleKey, "stale".into(), 10)
        .unwrap();
    assert_eq!(state.phase, SessionPhaseTag::DegradedOpen);
    assert!(state.degraded_policy.is_some());
    assert_eq!(state.degraded_entered_tick, Some(10));

    state
        .transition(
            SessionPhaseTag::Established,
            TransitionTrigger::DegradedRecovery,
            20,
        )
        .unwrap();
    assert_eq!(state.phase, SessionPhaseTag::Established);
    assert!(state.degraded_policy.is_none());
    assert_eq!(state.degraded_messages, 0);
}

#[test]
fn state_check_operation_established_allows_all() {
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
            .check_operation(DegradedOperationKind::Close, 10)
            .is_ok()
    );
}

#[test]
fn state_check_operation_degraded_identity_blocks_data() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::IdentityCompromised, "bad".into(), 10)
        .unwrap();
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 11)
            .is_err()
    );
    assert!(
        state
            .check_operation(DegradedOperationKind::WriteHostcall, 11)
            .is_err()
    );
    assert!(
        state
            .check_operation(DegradedOperationKind::Close, 11)
            .is_ok()
    );
}

#[test]
fn state_degraded_message_budget_exhaustion() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::PartialMacFailure, "mac".into(), 10)
        .unwrap();
    let limit = state
        .degraded_policy
        .as_ref()
        .unwrap()
        .max_degraded_messages;
    for _ in 0..limit {
        state.record_degraded_message();
    }
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 11)
            .is_err()
    );
}

#[test]
fn state_degraded_time_budget_exhaustion() {
    let mut state = make_established_state();
    state
        .enter_degraded(DegradedSeverity::StaleKey, "stale".into(), 100)
        .unwrap();
    let max_ticks = state.degraded_policy.as_ref().unwrap().max_degraded_ticks;
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 100 + max_ticks)
            .is_ok()
    );
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 100 + max_ticks + 1)
            .is_err()
    );
}

#[test]
fn state_replay_integration() {
    let mut state = make_state();
    assert!(state.check_replay(1, 1, None).is_ok());
    assert!(state.check_replay(2, 2, None).is_ok());
    assert!(state.check_replay(1, 3, None).is_err()); // replay
}

#[test]
fn state_record_degraded_only_in_degraded_phase() {
    let mut state = make_established_state();
    state.record_degraded_message();
    assert_eq!(state.degraded_messages, 0); // not in degraded mode

    state
        .enter_degraded(DegradedSeverity::StaleKey, "test".into(), 10)
        .unwrap();
    state.record_degraded_message();
    assert_eq!(state.degraded_messages, 1);
}

#[test]
fn state_transition_history_recorded() {
    let state = make_established_state();
    assert_eq!(state.transition_history.len(), 2);
    assert_eq!(state.transition_history[0].from, SessionPhaseTag::Uninit);
    assert_eq!(state.transition_history[0].to, SessionPhaseTag::Negotiating);
    assert_eq!(
        state.transition_history[1].from,
        SessionPhaseTag::Negotiating
    );
    assert_eq!(state.transition_history[1].to, SessionPhaseTag::Established);
}

#[test]
fn state_serde_roundtrip() {
    let state = make_established_state();
    let json = serde_json::to_string(&state).unwrap();
    let back: SessionProtocolState = serde_json::from_str(&json).unwrap();
    assert_eq!(state.phase, back.phase);
    assert_eq!(state.session_id, back.session_id);
    assert_eq!(
        state.transition_history.len(),
        back.transition_history.len()
    );
}

#[test]
fn state_check_operation_uninit_rejected() {
    let state = make_state();
    assert!(
        state
            .check_operation(DegradedOperationKind::ReadHostcall, 1)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// HspSpecimen tests
// ---------------------------------------------------------------------------

#[test]
fn specimen_serde_roundtrip() {
    let corpus = hsp_corpus();
    for spec in &corpus {
        let json = serde_json::to_string(spec).unwrap();
        let back: HspSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(spec.name, back.name);
        assert_eq!(spec.family, back.family);
        assert_eq!(spec.transition_count, back.transition_count);
        assert_eq!(spec.content_hash, back.content_hash);
    }
}

#[test]
fn specimen_family_display_all() {
    for fam in HspSpecimenFamily::ALL {
        let s = fam.to_string();
        assert!(!s.is_empty());
        assert!(!s.contains(char::is_uppercase));
    }
}

#[test]
fn specimen_family_all_has_eight() {
    assert_eq!(HspSpecimenFamily::ALL.len(), 8);
}

#[test]
fn specimen_family_serde_roundtrip() {
    for fam in HspSpecimenFamily::ALL {
        let json = serde_json::to_string(fam).unwrap();
        let back: HspSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*fam, back);
    }
}

// ---------------------------------------------------------------------------
// Evidence bundle tests
// ---------------------------------------------------------------------------

#[test]
fn evidence_bundle_creates_four_files() {
    let dir = std::env::temp_dir().join("hsp_bundle_test_files");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    write_hsp_evidence_bundle(&dir).unwrap();

    assert!(dir.join("hsp_inventory.json").exists());
    assert!(dir.join("hsp_manifest.json").exists());
    assert!(dir.join("hsp_events.jsonl").exists());
    assert!(dir.join("hsp_commands.txt").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn evidence_bundle_inventory_valid_json() {
    let dir = std::env::temp_dir().join("hsp_bundle_test_inv");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    write_hsp_evidence_bundle(&dir).unwrap();

    let inv = std::fs::read_to_string(dir.join("hsp_inventory.json")).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&inv).unwrap();
    assert_eq!(parsed.len(), hsp_corpus().len());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn evidence_bundle_manifest_has_schema() {
    let dir = std::env::temp_dir().join("hsp_bundle_test_man");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    write_hsp_evidence_bundle(&dir).unwrap();

    let man = std::fs::read_to_string(dir.join("hsp_manifest.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&man).unwrap();
    assert_eq!(
        parsed["schema"].as_str().unwrap(),
        "hostcall_session_protocol_evidence_v1"
    );
    assert!(parsed["specimen_count"].as_u64().unwrap() >= 10);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn evidence_bundle_events_valid_jsonl() {
    let dir = std::env::temp_dir().join("hsp_bundle_test_ev");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    write_hsp_evidence_bundle(&dir).unwrap();

    let events = std::fs::read_to_string(dir.join("hsp_events.jsonl")).unwrap();
    let lines: Vec<&str> = events.lines().collect();
    assert_eq!(lines.len(), hsp_corpus().len());
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn evidence_bundle_commands_has_cargo_test() {
    let dir = std::env::temp_dir().join("hsp_bundle_test_cmd");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    write_hsp_evidence_bundle(&dir).unwrap();

    let cmds = std::fs::read_to_string(dir.join("hsp_commands.txt")).unwrap();
    assert!(cmds.contains("cargo test"));
    assert!(cmds.contains("hostcall_session_protocol"));

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// TransitionRecord tests
// ---------------------------------------------------------------------------

#[test]
fn transition_record_serde_roundtrip() {
    let rec = TransitionRecord {
        from: SessionPhaseTag::Uninit,
        to: SessionPhaseTag::Negotiating,
        trigger: TransitionTrigger::HandshakeInitiated,
        tick: 42,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

// ---------------------------------------------------------------------------
// ReplayLedgerEntry tests
// ---------------------------------------------------------------------------

#[test]
fn replay_ledger_entry_serde_roundtrip() {
    let entry = ReplayLedgerEntry {
        session_id: "s".into(),
        sequence: 7,
        envelope_hash: ContentHash::compute(b"data"),
        accepted_at_tick: 100,
        mac: AuthenticityHash::compute_keyed(b"key", b"data"),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ReplayLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry.session_id, back.session_id);
    assert_eq!(entry.sequence, back.sequence);
}

// ---------------------------------------------------------------------------
// ReplayAuditEntry tests
// ---------------------------------------------------------------------------

#[test]
fn replay_audit_entry_serde_roundtrip() {
    let entry = ReplayAuditEntry {
        sequence: 5,
        verdict: ReplayVerdict::Accept,
        checked_at_tick: 99,
        envelope_hash: Some(ContentHash::compute(b"env")),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ReplayAuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// PhaseTransition tests
// ---------------------------------------------------------------------------

#[test]
fn phase_transition_serde_roundtrip() {
    let pt = PhaseTransition {
        from: SessionPhaseTag::Established,
        to: SessionPhaseTag::Closing,
        trigger: TransitionTrigger::CloseInitiated,
    };
    let json = serde_json::to_string(&pt).unwrap();
    let back: PhaseTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(pt, back);
}
