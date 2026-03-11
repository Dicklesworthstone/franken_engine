//! Integration tests for `certified_optimization_governance` module.
//!
//! Validates public API, serde contracts, determinism, governance evaluation,
//! rollback handling, forensic entries, certificate lifecycle, and report
//! generation.

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

use std::collections::BTreeMap;

use frankenengine_engine::certified_optimization_governance::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn make_cert(id: &str, function_id: &str, tier: OptimizationTier) -> OptimizationCertificate {
    OptimizationCertificate {
        cert_id: id.to_string(),
        tier,
        function_id: function_id.to_string(),
        rewrite_count: 5,
        proof_hash: ContentHash::compute(b"proof"),
        issued_epoch: SecurityEpoch::from_raw(90),
        expiry_epoch: SecurityEpoch::from_raw(200),
        translation_receipt_valid: true,
        status: CertificateStatus::Valid,
    }
}

fn make_expired_cert(id: &str, function_id: &str) -> OptimizationCertificate {
    OptimizationCertificate {
        cert_id: id.to_string(),
        tier: OptimizationTier::Aggressive,
        function_id: function_id.to_string(),
        rewrite_count: 3,
        proof_hash: ContentHash::compute(b"expired-proof"),
        issued_epoch: SecurityEpoch::from_raw(10),
        expiry_epoch: SecurityEpoch::from_raw(50),
        translation_receipt_valid: true,
        status: CertificateStatus::Valid,
    }
}

fn make_rollback(id: &str, function_id: &str, trigger: RollbackTrigger) -> RollbackRecord {
    RollbackRecord {
        record_id: id.to_string(),
        function_id: function_id.to_string(),
        trigger,
        from_tier: OptimizationTier::Speculative,
        to_tier: OptimizationTier::Baseline,
        epoch: epoch(),
        reason: "test rollback".to_string(),
        elapsed_steps: 1000,
    }
}

fn make_forensic(id: &str, function_id: &str, surface: ForensicSurface) -> ForensicEntry {
    ForensicEntry {
        entry_id: id.to_string(),
        surface,
        function_id: function_id.to_string(),
        tier: OptimizationTier::Aggressive,
        description: "test forensic entry".to_string(),
        artifact_hash: ContentHash::compute(b"artifact"),
        epoch: epoch(),
    }
}

// ---------------------------------------------------------------------------
// OptimizationTier integration
// ---------------------------------------------------------------------------

#[test]
fn tier_enum_covers_all_variants() {
    assert_eq!(OptimizationTier::ALL.len(), 4);
    for t in OptimizationTier::ALL {
        let s = t.as_str();
        assert!(!s.is_empty());
        let display = format!("{t}");
        assert_eq!(s, display);
    }
}

#[test]
fn tier_serde_json_roundtrip() {
    for t in OptimizationTier::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: OptimizationTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn tier_rank_is_monotonic() {
    let ranks: Vec<u32> = OptimizationTier::ALL.iter().map(|t| t.rank()).collect();
    for w in ranks.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn tier_requires_cert_only_for_aggressive_and_speculative() {
    assert!(!OptimizationTier::Baseline.requires_certificate());
    assert!(!OptimizationTier::Standard.requires_certificate());
    assert!(OptimizationTier::Aggressive.requires_certificate());
    assert!(OptimizationTier::Speculative.requires_certificate());
}

// ---------------------------------------------------------------------------
// CertificateStatus integration
// ---------------------------------------------------------------------------

#[test]
fn status_enum_covers_all_variants() {
    assert_eq!(CertificateStatus::ALL.len(), 5);
    for s in CertificateStatus::ALL {
        assert!(!s.as_str().is_empty());
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn status_only_valid_allows_optimization() {
    for s in CertificateStatus::ALL {
        assert_eq!(s.allows_optimization(), *s == CertificateStatus::Valid);
    }
}

#[test]
fn status_serde_roundtrip() {
    for s in CertificateStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: CertificateStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// RollbackTrigger integration
// ---------------------------------------------------------------------------

#[test]
fn trigger_enum_covers_all_variants() {
    assert_eq!(RollbackTrigger::ALL.len(), 6);
    for t in RollbackTrigger::ALL {
        assert!(!t.as_str().is_empty());
        assert_eq!(format!("{t}"), t.as_str());
    }
}

#[test]
fn trigger_serde_roundtrip() {
    for t in RollbackTrigger::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ---------------------------------------------------------------------------
// ForensicSurface integration
// ---------------------------------------------------------------------------

#[test]
fn forensic_surface_covers_all_variants() {
    assert_eq!(ForensicSurface::ALL.len(), 6);
    for s in ForensicSurface::ALL {
        assert!(!s.as_str().is_empty());
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn forensic_surface_serde_roundtrip() {
    for s in ForensicSurface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: ForensicSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// OptimizationCertificate integration
// ---------------------------------------------------------------------------

#[test]
fn cert_validity_window() {
    let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    assert!(cert.is_valid_at(SecurityEpoch::from_raw(90)));
    assert!(cert.is_valid_at(SecurityEpoch::from_raw(150)));
    assert!(cert.is_valid_at(SecurityEpoch::from_raw(199)));
    assert!(!cert.is_valid_at(SecurityEpoch::from_raw(200)));
    assert!(!cert.is_valid_at(SecurityEpoch::from_raw(89)));
}

#[test]
fn cert_revoked_not_valid() {
    let mut cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    cert.status = CertificateStatus::Revoked;
    assert!(!cert.is_valid_at(epoch()));
}

#[test]
fn cert_pending_not_valid() {
    let mut cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    cert.status = CertificateStatus::Pending;
    assert!(!cert.is_valid_at(epoch()));
}

#[test]
fn cert_remaining_epochs_computes_correctly() {
    let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(100)), 100);
    assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(190)), 10);
    assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(200)), 0);
    assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(999)), 0);
}

#[test]
fn cert_meets_min_validity_boundary() {
    let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    // remaining = 100 at epoch 100
    assert!(cert.meets_min_validity(SecurityEpoch::from_raw(100), 100));
    assert!(!cert.meets_min_validity(SecurityEpoch::from_raw(100), 101));
}

#[test]
fn cert_content_hash_deterministic() {
    let c1 = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    let c2 = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    assert_eq!(c1.content_hash(), c2.content_hash());
}

#[test]
fn cert_content_hash_varies_with_tier() {
    let c1 = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    let c2 = make_cert("c1", "fn1", OptimizationTier::Speculative);
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn cert_serde_roundtrip() {
    let cert = make_cert("c-int", "fn-int", OptimizationTier::Speculative);
    let json = serde_json::to_string(&cert).unwrap();
    let back: OptimizationCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// RollbackRecord integration
// ---------------------------------------------------------------------------

#[test]
fn rollback_content_hash_deterministic() {
    let r1 = make_rollback("r1", "fn1", RollbackTrigger::ProofFailure);
    let r2 = make_rollback("r1", "fn1", RollbackTrigger::ProofFailure);
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn rollback_content_hash_varies_with_id() {
    let r1 = make_rollback("r1", "fn1", RollbackTrigger::ProofFailure);
    let r2 = make_rollback("r2", "fn1", RollbackTrigger::ProofFailure);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn rollback_serde_roundtrip() {
    let r = make_rollback("r-int", "fn1", RollbackTrigger::TimeoutExceeded);
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// ForensicEntry integration
// ---------------------------------------------------------------------------

#[test]
fn forensic_entry_content_hash_deterministic() {
    let f1 = make_forensic("f1", "fn1", ForensicSurface::SourceMapping);
    let f2 = make_forensic("f1", "fn1", ForensicSurface::SourceMapping);
    assert_eq!(f1.content_hash(), f2.content_hash());
}

#[test]
fn forensic_entry_content_hash_varies_with_surface() {
    let f1 = make_forensic("f1", "fn1", ForensicSurface::SourceMapping);
    let f2 = make_forensic("f1", "fn1", ForensicSurface::DiffBaseline);
    assert_ne!(f1.content_hash(), f2.content_hash());
}

#[test]
fn forensic_entry_serde_roundtrip() {
    let f = make_forensic("f-int", "fn1", ForensicSurface::ProofArtifact);
    let json = serde_json::to_string(&f).unwrap();
    let back: ForensicEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// GovernanceConfig integration
// ---------------------------------------------------------------------------

#[test]
fn config_default_serde_roundtrip() {
    let cfg = GovernanceConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn config_permissive_serde_roundtrip() {
    let cfg = GovernanceConfig::permissive();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn config_default_trait_eq() {
    let cfg: GovernanceConfig = Default::default();
    assert_eq!(cfg, GovernanceConfig::default_config());
}

// ---------------------------------------------------------------------------
// GovernanceState lifecycle
// ---------------------------------------------------------------------------

#[test]
fn state_fresh_is_empty() {
    let state = GovernanceState::new(epoch());
    assert!(state.certificates.is_empty());
    assert!(state.rollbacks.is_empty());
    assert!(state.forensic_entries.is_empty());
    assert!(state.active_tiers.is_empty());
    assert_eq!(state.epoch, epoch());
}

#[test]
fn state_add_multiple_certificates() {
    let mut state = GovernanceState::new(epoch());
    for i in 0..5 {
        state.add_certificate(make_cert(
            &format!("c{i}"),
            &format!("fn{i}"),
            OptimizationTier::Aggressive,
        ));
    }
    assert_eq!(state.certificates.len(), 5);
}

#[test]
fn state_revoke_success() {
    let mut state = GovernanceState::new(epoch());
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    assert!(
        state
            .revoke_certificate("c1", "revoke reason", epoch())
            .is_ok()
    );
    assert_eq!(state.certificates[0].status, CertificateStatus::Revoked);
    assert!(!state.certificates[0].is_valid_at(epoch()));
}

#[test]
fn state_revoke_not_found() {
    let mut state = GovernanceState::new(epoch());
    let result = state.revoke_certificate("ghost", "reason", epoch());
    assert!(matches!(
        result,
        Err(GovernanceError::CertificateNotFound { .. })
    ));
}

#[test]
fn state_record_rollback_demotes() {
    let mut state = GovernanceState::new(epoch());
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Speculative);
    state.record_rollback(make_rollback(
        "r1",
        "fn1",
        RollbackTrigger::RegressionDetected,
    ));
    assert_eq!(state.active_tiers["fn1"], OptimizationTier::Baseline);
}

#[test]
fn state_multiple_rollbacks_accumulate() {
    let mut state = GovernanceState::new(epoch());
    for i in 0..4 {
        state.record_rollback(make_rollback(
            &format!("r{i}"),
            &format!("fn{i}"),
            RollbackTrigger::OperatorCommand,
        ));
    }
    assert_eq!(state.rollbacks.len(), 4);
}

#[test]
fn state_forensic_entries_accumulate() {
    let mut state = GovernanceState::new(epoch());
    for (i, surface) in ForensicSurface::ALL.iter().enumerate() {
        state.add_forensic_entry(make_forensic(&format!("f{i}"), "fn1", *surface));
    }
    assert_eq!(state.forensic_entries.len(), 6);
}

#[test]
fn state_promote_baseline_ok_without_cert() {
    let mut state = GovernanceState::new(epoch());
    assert!(
        state
            .promote_tier("fn1", OptimizationTier::Baseline, None)
            .is_ok()
    );
    assert_eq!(
        state.active_tiers.get("fn1"),
        Some(&OptimizationTier::Baseline)
    );
}

#[test]
fn state_promote_standard_ok_without_cert() {
    let mut state = GovernanceState::new(epoch());
    assert!(
        state
            .promote_tier("fn1", OptimizationTier::Standard, None)
            .is_ok()
    );
}

#[test]
fn state_promote_aggressive_requires_cert() {
    let mut state = GovernanceState::new(epoch());
    let err = state
        .promote_tier("fn1", OptimizationTier::Aggressive, None)
        .unwrap_err();
    assert!(matches!(err, GovernanceError::UncertifiedTier { .. }));
}

#[test]
fn state_promote_speculative_requires_cert() {
    let mut state = GovernanceState::new(epoch());
    let err = state
        .promote_tier("fn1", OptimizationTier::Speculative, None)
        .unwrap_err();
    assert!(matches!(err, GovernanceError::UncertifiedTier { .. }));
}

#[test]
fn state_promote_aggressive_with_valid_cert_ok() {
    let mut state = GovernanceState::new(epoch());
    let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
    assert!(
        state
            .promote_tier("fn1", OptimizationTier::Aggressive, Some(&cert))
            .is_ok()
    );
    assert_eq!(state.active_tiers["fn1"], OptimizationTier::Aggressive);
}

#[test]
fn state_promote_with_expired_cert_fails() {
    let mut state = GovernanceState::new(epoch());
    let cert = make_expired_cert("c-exp", "fn1");
    let err = state
        .promote_tier("fn1", OptimizationTier::Aggressive, Some(&cert))
        .unwrap_err();
    assert!(matches!(err, GovernanceError::CertificateExpired { .. }));
}

#[test]
fn state_active_certificates_filters_expired() {
    let mut state = GovernanceState::new(epoch());
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    state.add_certificate(make_expired_cert("c2", "fn2"));
    let active = state.active_certificates();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].cert_id, "c1");
}

#[test]
fn state_active_certificates_filters_revoked() {
    let mut state = GovernanceState::new(epoch());
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    state.revoke_certificate("c1", "revoke", epoch()).unwrap();
    assert!(state.active_certificates().is_empty());
}

#[test]
fn state_rollbacks_in_epoch_filters() {
    let mut state = GovernanceState::new(epoch());
    state.record_rollback(make_rollback("r1", "fn1", RollbackTrigger::ProofFailure));
    let mut r2 = make_rollback("r2", "fn2", RollbackTrigger::DebugRequest);
    r2.epoch = SecurityEpoch::from_raw(500);
    state.record_rollback(r2);
    assert_eq!(state.rollbacks_in_epoch(epoch()).len(), 1);
    assert_eq!(
        state.rollbacks_in_epoch(SecurityEpoch::from_raw(500)).len(),
        1
    );
    assert_eq!(
        state.rollbacks_in_epoch(SecurityEpoch::from_raw(999)).len(),
        0
    );
}

#[test]
fn state_forensics_for_function_filters() {
    let mut state = GovernanceState::new(epoch());
    state.add_forensic_entry(make_forensic("f1", "fn-a", ForensicSurface::SourceMapping));
    state.add_forensic_entry(make_forensic("f2", "fn-b", ForensicSurface::OperatorLog));
    state.add_forensic_entry(make_forensic("f3", "fn-a", ForensicSurface::RewriteChain));
    assert_eq!(state.forensics_for_function("fn-a").len(), 2);
    assert_eq!(state.forensics_for_function("fn-b").len(), 1);
    assert_eq!(state.forensics_for_function("fn-c").len(), 0);
}

// ---------------------------------------------------------------------------
// Governance evaluation
// ---------------------------------------------------------------------------

#[test]
fn evaluate_empty_state_passes() {
    let state = GovernanceState::new(epoch());
    let verdict = state.evaluate(&GovernanceConfig::default_config());
    assert!(verdict.is_pass());
}

#[test]
fn evaluate_too_many_rollbacks() {
    let mut state = GovernanceState::new(epoch());
    for i in 0..6 {
        state.record_rollback(make_rollback(
            &format!("r{i}"),
            &format!("fn{i}"),
            RollbackTrigger::ProofFailure,
        ));
    }
    let verdict = state.evaluate(&GovernanceConfig::default_config());
    assert!(verdict.is_fail());
}

#[test]
fn evaluate_speculative_without_cert() {
    let mut state = GovernanceState::new(epoch());
    for i in 0..3 {
        state
            .active_tiers
            .insert(format!("fn{i}"), OptimizationTier::Speculative);
    }
    let verdict = state.evaluate(&GovernanceConfig::default_config());
    assert!(verdict.is_fail());
}

#[test]
fn evaluate_aggressive_without_cert_when_required() {
    let mut state = GovernanceState::new(epoch());
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Aggressive);
    let verdict = state.evaluate(&GovernanceConfig::default_config());
    assert!(verdict.is_fail());
}

#[test]
fn evaluate_aggressive_without_cert_permissive_passes() {
    let mut state = GovernanceState::new(epoch());
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Aggressive);
    let verdict = state.evaluate(&GovernanceConfig::permissive());
    assert!(verdict.is_pass());
}

#[test]
fn evaluate_with_valid_aggressive_cert_passes() {
    let mut state = GovernanceState::new(epoch());
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Aggressive);
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    let verdict = state.evaluate(&GovernanceConfig::default_config());
    assert!(verdict.is_pass());
}

#[test]
fn evaluate_too_many_speculative_fails() {
    let mut state = GovernanceState::new(epoch());
    for i in 0..10 {
        state
            .active_tiers
            .insert(format!("fn{i}"), OptimizationTier::Speculative);
        state.add_certificate(make_cert(
            &format!("c{i}"),
            &format!("fn{i}"),
            OptimizationTier::Speculative,
        ));
    }
    let mut config = GovernanceConfig::default_config();
    config.max_speculative_without_cert = 100;
    let verdict = state.evaluate(&config);
    assert!(verdict.is_fail()); // 10 > 8 max_active_speculative
}

#[test]
fn evaluate_cert_near_expiry_fails() {
    let mut state = GovernanceState::new(SecurityEpoch::from_raw(195));
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Aggressive);
    let verdict = state.evaluate(&GovernanceConfig::default_config());
    // 5 epochs remaining < 10 min
    assert!(verdict.is_fail());
}

#[test]
fn evaluate_stale_forensic_entry_fails() {
    let mut state = GovernanceState::new(SecurityEpoch::from_raw(200));
    let mut entry = make_forensic("f-old", "fn1", ForensicSurface::SourceMapping);
    entry.epoch = SecurityEpoch::from_raw(5);
    state.add_forensic_entry(entry);
    let mut config = GovernanceConfig::default_config();
    config.min_verification_epoch = SecurityEpoch::from_raw(50);
    let verdict = state.evaluate(&config);
    assert!(verdict.is_fail());
}

#[test]
fn evaluate_permissive_always_passes() {
    let mut state = GovernanceState::new(epoch());
    for i in 0..20 {
        state
            .active_tiers
            .insert(format!("fn{i}"), OptimizationTier::Speculative);
        state.record_rollback(make_rollback(
            &format!("r{i}"),
            &format!("fn-rb{i}"),
            RollbackTrigger::ProofFailure,
        ));
    }
    let verdict = state.evaluate(&GovernanceConfig::permissive());
    assert!(verdict.is_pass());
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

#[test]
fn report_empty_state() {
    let state = GovernanceState::new(epoch());
    let report = state.report(&GovernanceConfig::default_config());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.epoch, epoch());
    assert_eq!(report.total_certificates, 0);
    assert_eq!(report.valid_certificates, 0);
    assert_eq!(report.total_rollbacks, 0);
    assert_eq!(report.active_speculative, 0);
    assert_eq!(report.forensic_entry_count, 0);
    assert!(report.verdict.is_pass());
}

#[test]
fn report_with_data() {
    let mut state = GovernanceState::new(epoch());
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    state.add_certificate(make_expired_cert("c2", "fn2"));
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Aggressive);
    state.add_forensic_entry(make_forensic("f1", "fn1", ForensicSurface::SourceMapping));
    state.record_rollback(make_rollback("r1", "fn-rb", RollbackTrigger::ProofFailure));
    let report = state.report(&GovernanceConfig::default_config());
    assert_eq!(report.total_certificates, 2);
    assert_eq!(report.valid_certificates, 1);
    assert_eq!(report.total_rollbacks, 1);
    assert_eq!(report.forensic_entry_count, 1);
    assert!(report.verdict.is_pass());
}

#[test]
fn report_hash_deterministic() {
    let state = GovernanceState::new(epoch());
    let r1 = state.report(&GovernanceConfig::default_config());
    let r2 = state.report(&GovernanceConfig::default_config());
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn report_serde_roundtrip() {
    let state = GovernanceState::new(epoch());
    let report = state.report(&GovernanceConfig::default_config());
    let json = serde_json::to_string(&report).unwrap();
    let back: GovernanceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// GovernanceVerdict integration
// ---------------------------------------------------------------------------

#[test]
fn verdict_pass_tag_and_display() {
    let v = GovernanceVerdict::Pass {
        active_certs: 3,
        rollback_count: 1,
    };
    assert_eq!(v.tag(), "pass");
    assert!(format!("{v}").contains("PASS"));
}

#[test]
fn verdict_fail_tag_and_display() {
    let v = GovernanceVerdict::Fail {
        reasons: vec!["r1".into(), "r2".into()],
    };
    assert_eq!(v.tag(), "fail");
    assert!(format!("{v}").contains("FAIL"));
    assert!(format!("{v}").contains("2"));
}

#[test]
fn verdict_inconclusive_tag() {
    let v = GovernanceVerdict::Inconclusive {
        reasons: vec!["unknown".into()],
    };
    assert_eq!(v.tag(), "inconclusive");
    assert!(v.is_inconclusive());
}

#[test]
fn verdict_serde_roundtrip() {
    let v = GovernanceVerdict::Fail {
        reasons: vec!["reason-a".into()],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// GovernanceError integration
// ---------------------------------------------------------------------------

#[test]
fn error_tag_coverage() {
    let tags = vec![
        GovernanceError::CertificateNotFound {
            cert_id: "c".into(),
        },
        GovernanceError::CertificateExpired {
            cert_id: "c".into(),
        },
        GovernanceError::UncertifiedTier {
            function_id: "f".into(),
            tier: OptimizationTier::Aggressive,
        },
        GovernanceError::TooManyRollbacks { count: 10, max: 5 },
        GovernanceError::InvalidConfig {
            reason: "bad".into(),
        },
        GovernanceError::StaleEvidence {
            epoch: SecurityEpoch::from_raw(1),
            min: SecurityEpoch::from_raw(10),
        },
    ];
    let expected = [
        "certificate_not_found",
        "certificate_expired",
        "uncertified_tier",
        "too_many_rollbacks",
        "invalid_config",
        "stale_evidence",
    ];
    for (e, tag) in tags.iter().zip(expected.iter()) {
        assert_eq!(e.tag(), *tag);
    }
}

#[test]
fn error_display_contains_details() {
    let e = GovernanceError::StaleEvidence {
        epoch: SecurityEpoch::from_raw(5),
        min: SecurityEpoch::from_raw(50),
    };
    let s = format!("{e}");
    assert!(s.contains("5"));
    assert!(s.contains("50"));
}

#[test]
fn error_serde_roundtrip() {
    let e = GovernanceError::TooManyRollbacks { count: 7, max: 3 };
    let json = serde_json::to_string(&e).unwrap();
    let back: GovernanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_consistent() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.7.3");
    assert_eq!(POLICY_ID, "RGC-607C");
    assert_eq!(MILLIONTHS, 1_000_000);
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
}

// ---------------------------------------------------------------------------
// Complex scenarios
// ---------------------------------------------------------------------------

#[test]
fn scenario_full_lifecycle() {
    let mut state = GovernanceState::new(epoch());

    // Add certificate and promote
    let cert = make_cert("c1", "fn-hot", OptimizationTier::Aggressive);
    state.add_certificate(cert.clone());
    state
        .promote_tier("fn-hot", OptimizationTier::Aggressive, Some(&cert))
        .unwrap();

    // Add forensic evidence
    state.add_forensic_entry(make_forensic("f1", "fn-hot", ForensicSurface::RewriteChain));
    state.add_forensic_entry(make_forensic(
        "f2",
        "fn-hot",
        ForensicSurface::ProofArtifact,
    ));

    // Verify passes
    let config = GovernanceConfig::default_config();
    let verdict = state.evaluate(&config);
    assert!(verdict.is_pass());

    // Record rollback
    let rb = RollbackRecord {
        record_id: "r1".into(),
        function_id: "fn-hot".into(),
        trigger: RollbackTrigger::RegressionDetected,
        from_tier: OptimizationTier::Aggressive,
        to_tier: OptimizationTier::Baseline,
        epoch: epoch(),
        reason: "p99 latency spike".into(),
        elapsed_steps: 50_000,
    };
    state.record_rollback(rb);

    // Verify still passes (1 rollback < 5 max)
    assert!(state.evaluate(&config).is_pass());
    assert_eq!(state.active_tiers["fn-hot"], OptimizationTier::Baseline);

    // Forensics for function
    assert_eq!(state.forensics_for_function("fn-hot").len(), 2);
}

#[test]
fn scenario_speculative_with_mixed_certs() {
    let mut state = GovernanceState::new(epoch());

    // 2 speculative with certs, 1 without
    for i in 0..2 {
        let cert = make_cert(
            &format!("c{i}"),
            &format!("fn{i}"),
            OptimizationTier::Speculative,
        );
        state.add_certificate(cert.clone());
        state
            .promote_tier(
                &format!("fn{i}"),
                OptimizationTier::Speculative,
                Some(&cert),
            )
            .unwrap();
    }
    state
        .active_tiers
        .insert("fn-uncerted".to_string(), OptimizationTier::Speculative);

    // 1 uncerted speculative <= 2 max -> pass
    let config = GovernanceConfig::default_config();
    let verdict = state.evaluate(&config);
    assert!(verdict.is_pass());
}

#[test]
fn scenario_revoke_then_evaluate() {
    let mut state = GovernanceState::new(epoch());
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Aggressive);

    // Passes before revoke
    assert!(
        state
            .evaluate(&GovernanceConfig::default_config())
            .is_pass()
    );

    // Revoke
    state
        .revoke_certificate("c1", "security issue", epoch())
        .unwrap();

    // Now aggressive without cert -> fails with require_proof_for_aggressive
    let verdict = state.evaluate(&GovernanceConfig::default_config());
    assert!(verdict.is_fail());
}

#[test]
fn state_serde_roundtrip() {
    let mut state = GovernanceState::new(epoch());
    state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
    state
        .active_tiers
        .insert("fn1".to_string(), OptimizationTier::Aggressive);
    state.record_rollback(make_rollback("r1", "fn2", RollbackTrigger::DebugRequest));
    state.add_forensic_entry(make_forensic("f1", "fn1", ForensicSurface::DiffBaseline));
    let json = serde_json::to_string(&state).unwrap();
    let back: GovernanceState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}
