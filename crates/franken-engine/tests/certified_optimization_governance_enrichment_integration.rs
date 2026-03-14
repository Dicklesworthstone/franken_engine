#![forbid(unsafe_code)]

//! Enrichment integration tests for the `certified_optimization_governance` module.

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

use frankenengine_engine::certified_optimization_governance::{
    BEAD_ID, COMPONENT, CertificateStatus, DEFAULT_FORENSIC_RETENTION_EPOCHS,
    DEFAULT_MAX_ACTIVE_SPECULATIVE, DEFAULT_MAX_ROLLBACKS_PER_EPOCH,
    DEFAULT_MAX_SPECULATIVE_WITHOUT_CERT, DEFAULT_MIN_CERT_VALIDITY_EPOCHS, ForensicEntry,
    ForensicSurface, GovernanceConfig, GovernanceError, GovernanceState, GovernanceVerdict,
    OptimizationCertificate, OptimizationTier, POLICY_ID, RollbackRecord, RollbackTrigger,
    SCHEMA_VERSION,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_cert(id: &str, tier: OptimizationTier) -> OptimizationCertificate {
    OptimizationCertificate {
        cert_id: id.to_string(),
        tier,
        function_id: format!("fn-{id}"),
        rewrite_count: 5,
        proof_hash: ContentHash::compute(id.as_bytes()),
        issued_epoch: SecurityEpoch::from_raw(40),
        expiry_epoch: SecurityEpoch::from_raw(100),
        translation_receipt_valid: true,
        status: CertificateStatus::Valid,
    }
}

fn make_rollback(id: &str, trigger: RollbackTrigger) -> RollbackRecord {
    RollbackRecord {
        record_id: id.to_string(),
        function_id: format!("fn-{id}"),
        trigger,
        from_tier: OptimizationTier::Aggressive,
        to_tier: OptimizationTier::Baseline,
        epoch: epoch(),
        reason: "test rollback".to_string(),
        elapsed_steps: 100,
    }
}

fn make_forensic(id: &str, surface: ForensicSurface) -> ForensicEntry {
    ForensicEntry {
        entry_id: id.to_string(),
        surface,
        function_id: format!("fn-{id}"),
        tier: OptimizationTier::Standard,
        description: "test forensic entry".to_string(),
        artifact_hash: ContentHash::compute(id.as_bytes()),
        epoch: epoch(),
    }
}

// ===========================================================================
// OptimizationTier — Copy, BTreeSet, Debug/Display unique, as_str, methods
// ===========================================================================

#[test]
fn enrichment_optimization_tier_copy_semantics() {
    let a = OptimizationTier::Aggressive;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_optimization_tier_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for v in OptimizationTier::ALL {
        set.insert(*v);
    }
    set.insert(OptimizationTier::Baseline);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_optimization_tier_debug_all_unique() {
    let strs: BTreeSet<String> = OptimizationTier::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_optimization_tier_display_all_unique() {
    let strs: BTreeSet<String> = OptimizationTier::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_optimization_tier_as_str_matches_display() {
    for v in OptimizationTier::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_optimization_tier_requires_certificate_exactly_two() {
    let requiring: Vec<_> = OptimizationTier::ALL
        .iter()
        .filter(|v| v.requires_certificate())
        .collect();
    assert_eq!(requiring.len(), 2);
    assert!(OptimizationTier::Aggressive.requires_certificate());
    assert!(OptimizationTier::Speculative.requires_certificate());
    assert!(!OptimizationTier::Baseline.requires_certificate());
    assert!(!OptimizationTier::Standard.requires_certificate());
}

#[test]
fn enrichment_optimization_tier_rank_ascending() {
    let ranks: Vec<u32> = OptimizationTier::ALL.iter().map(|v| v.rank()).collect();
    for i in 1..ranks.len() {
        assert!(ranks[i] > ranks[i - 1], "rank should be ascending");
    }
}

// ===========================================================================
// CertificateStatus — Copy, BTreeSet, Debug/Display unique, allows_optimization
// ===========================================================================

#[test]
fn enrichment_certificate_status_copy_semantics() {
    let a = CertificateStatus::Valid;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_certificate_status_btreeset_dedup_5() {
    let mut set = BTreeSet::new();
    for v in CertificateStatus::ALL {
        set.insert(*v);
    }
    set.insert(CertificateStatus::Valid);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_certificate_status_debug_all_unique() {
    let strs: BTreeSet<String> = CertificateStatus::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_certificate_status_display_all_unique() {
    let strs: BTreeSet<String> = CertificateStatus::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_certificate_status_as_str_matches_display() {
    for v in CertificateStatus::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_certificate_status_allows_optimization_exactly_one() {
    let allowing: Vec<_> = CertificateStatus::ALL
        .iter()
        .filter(|v| v.allows_optimization())
        .collect();
    assert_eq!(allowing.len(), 1);
    assert!(CertificateStatus::Valid.allows_optimization());
}

// ===========================================================================
// RollbackTrigger — Copy, BTreeSet, Debug/Display unique, as_str
// ===========================================================================

#[test]
fn enrichment_rollback_trigger_copy_semantics() {
    let a = RollbackTrigger::ProofFailure;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_rollback_trigger_btreeset_dedup_6() {
    let mut set = BTreeSet::new();
    for v in RollbackTrigger::ALL {
        set.insert(*v);
    }
    set.insert(RollbackTrigger::ProofFailure);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_rollback_trigger_debug_all_unique() {
    let strs: BTreeSet<String> = RollbackTrigger::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_rollback_trigger_display_all_unique() {
    let strs: BTreeSet<String> = RollbackTrigger::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_rollback_trigger_as_str_matches_display() {
    for v in RollbackTrigger::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

// ===========================================================================
// ForensicSurface — Copy, BTreeSet, Debug/Display unique, as_str
// ===========================================================================

#[test]
fn enrichment_forensic_surface_copy_semantics() {
    let a = ForensicSurface::SourceMapping;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_forensic_surface_btreeset_dedup_6() {
    let mut set = BTreeSet::new();
    for v in ForensicSurface::ALL {
        set.insert(*v);
    }
    set.insert(ForensicSurface::SourceMapping);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_forensic_surface_debug_all_unique() {
    let strs: BTreeSet<String> = ForensicSurface::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_forensic_surface_display_all_unique() {
    let strs: BTreeSet<String> = ForensicSurface::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_forensic_surface_as_str_matches_display() {
    for v in ForensicSurface::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

// ===========================================================================
// OptimizationCertificate — Clone, Debug, JSON fields, methods
// ===========================================================================

#[test]
fn enrichment_optimization_certificate_clone_independence() {
    let a = make_cert("c1", OptimizationTier::Aggressive);
    let mut b = a.clone();
    b.rewrite_count = 999;
    assert_ne!(a.rewrite_count, b.rewrite_count);
}

#[test]
fn enrichment_optimization_certificate_debug_nonempty() {
    let cert = make_cert("c2", OptimizationTier::Speculative);
    let dbg = format!("{cert:?}");
    assert!(dbg.contains("OptimizationCertificate"));
}

#[test]
fn enrichment_optimization_certificate_json_field_names() {
    let cert = make_cert("c3", OptimizationTier::Standard);
    let json = serde_json::to_string(&cert).unwrap();
    for field in &[
        "cert_id",
        "tier",
        "function_id",
        "rewrite_count",
        "proof_hash",
        "issued_epoch",
        "expiry_epoch",
        "translation_receipt_valid",
        "status",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_optimization_certificate_valid_at_epoch() {
    let cert = make_cert("c4", OptimizationTier::Aggressive);
    assert!(cert.is_valid_at(epoch())); // 42 is between 40 and 100
    assert!(!cert.is_valid_at(SecurityEpoch::from_raw(39)));
    assert!(!cert.is_valid_at(SecurityEpoch::from_raw(101)));
}

#[test]
fn enrichment_optimization_certificate_remaining_epochs() {
    let cert = make_cert("c5", OptimizationTier::Aggressive);
    assert_eq!(cert.remaining_epochs(epoch()), 100 - 42);
    assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(100)), 0);
}

#[test]
fn enrichment_optimization_certificate_content_hash_deterministic() {
    let cert1 = make_cert("c6", OptimizationTier::Aggressive);
    let cert2 = make_cert("c6", OptimizationTier::Aggressive);
    assert_eq!(cert1.content_hash(), cert2.content_hash());
}

#[test]
fn enrichment_optimization_certificate_serde_roundtrip() {
    let cert = make_cert("c7", OptimizationTier::Speculative);
    let json = serde_json::to_string(&cert).unwrap();
    let back: OptimizationCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ===========================================================================
// RollbackRecord — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_rollback_record_clone_independence() {
    let a = make_rollback("r1", RollbackTrigger::ProofFailure);
    let mut b = a.clone();
    b.elapsed_steps = 999;
    assert_ne!(a.elapsed_steps, b.elapsed_steps);
}

#[test]
fn enrichment_rollback_record_debug_nonempty() {
    let r = make_rollback("r2", RollbackTrigger::RegressionDetected);
    let dbg = format!("{r:?}");
    assert!(dbg.contains("RollbackRecord"));
}

#[test]
fn enrichment_rollback_record_json_field_names() {
    let r = make_rollback("r3", RollbackTrigger::OperatorCommand);
    let json = serde_json::to_string(&r).unwrap();
    for field in &[
        "record_id",
        "function_id",
        "trigger",
        "from_tier",
        "to_tier",
        "epoch",
        "reason",
        "elapsed_steps",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_rollback_record_serde_roundtrip() {
    let r = make_rollback("r4", RollbackTrigger::TimeoutExceeded);
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// ForensicEntry — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_forensic_entry_clone_independence() {
    let a = make_forensic("f1", ForensicSurface::SourceMapping);
    let mut b = a.clone();
    b.description = "changed".to_string();
    assert_ne!(a.description, b.description);
}

#[test]
fn enrichment_forensic_entry_debug_nonempty() {
    let f = make_forensic("f2", ForensicSurface::RewriteChain);
    let dbg = format!("{f:?}");
    assert!(dbg.contains("ForensicEntry"));
}

#[test]
fn enrichment_forensic_entry_json_field_names() {
    let f = make_forensic("f3", ForensicSurface::ProofArtifact);
    let json = serde_json::to_string(&f).unwrap();
    for field in &[
        "entry_id",
        "surface",
        "function_id",
        "tier",
        "description",
        "artifact_hash",
        "epoch",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_forensic_entry_serde_roundtrip() {
    let f = make_forensic("f4", ForensicSurface::RegretTrace);
    let json = serde_json::to_string(&f).unwrap();
    let back: ForensicEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ===========================================================================
// GovernanceConfig — Clone, Debug, JSON fields, default/permissive
// ===========================================================================

#[test]
fn enrichment_governance_config_clone_independence() {
    let mut a = GovernanceConfig::default();
    let b = a.clone();
    a.max_rollbacks_per_epoch = 999;
    assert_ne!(a.max_rollbacks_per_epoch, b.max_rollbacks_per_epoch);
}

#[test]
fn enrichment_governance_config_debug_nonempty() {
    let cfg = GovernanceConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("GovernanceConfig"));
}

#[test]
fn enrichment_governance_config_json_field_names() {
    let cfg = GovernanceConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    for field in &[
        "max_speculative_without_cert",
        "max_rollbacks_per_epoch",
        "require_proof_for_aggressive",
        "min_cert_validity_epochs",
        "forensic_retention_epochs",
        "max_active_speculative",
        "min_verification_epoch",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_governance_config_default_matches_constants() {
    let cfg = GovernanceConfig::default();
    assert_eq!(
        cfg.max_speculative_without_cert,
        DEFAULT_MAX_SPECULATIVE_WITHOUT_CERT
    );
    assert_eq!(cfg.max_rollbacks_per_epoch, DEFAULT_MAX_ROLLBACKS_PER_EPOCH);
    assert_eq!(
        cfg.min_cert_validity_epochs,
        DEFAULT_MIN_CERT_VALIDITY_EPOCHS
    );
    assert_eq!(
        cfg.forensic_retention_epochs,
        DEFAULT_FORENSIC_RETENTION_EPOCHS
    );
    assert_eq!(cfg.max_active_speculative, DEFAULT_MAX_ACTIVE_SPECULATIVE);
}

#[test]
fn enrichment_governance_config_permissive_looser() {
    let def = GovernanceConfig::default();
    let perm = GovernanceConfig::permissive();
    assert!(perm.max_rollbacks_per_epoch >= def.max_rollbacks_per_epoch);
    assert!(perm.max_active_speculative >= def.max_active_speculative);
}

#[test]
fn enrichment_governance_config_serde_roundtrip() {
    let cfg = GovernanceConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// GovernanceError — Clone, Debug, Display unique, tag unique
// ===========================================================================

#[test]
fn enrichment_governance_error_display_all_unique() {
    let variants: Vec<GovernanceError> = vec![
        GovernanceError::CertificateNotFound {
            cert_id: "c1".to_string(),
        },
        GovernanceError::CertificateExpired {
            cert_id: "c2".to_string(),
        },
        GovernanceError::UncertifiedTier {
            function_id: "fn1".to_string(),
            tier: OptimizationTier::Aggressive,
        },
        GovernanceError::TooManyRollbacks { count: 10, max: 5 },
        GovernanceError::InvalidConfig {
            reason: "bad".to_string(),
        },
        GovernanceError::StaleEvidence {
            epoch: epoch(),
            min: SecurityEpoch::from_raw(100),
        },
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_governance_error_tag_all_unique() {
    let variants: Vec<GovernanceError> = vec![
        GovernanceError::CertificateNotFound {
            cert_id: "c1".to_string(),
        },
        GovernanceError::CertificateExpired {
            cert_id: "c2".to_string(),
        },
        GovernanceError::UncertifiedTier {
            function_id: "fn1".to_string(),
            tier: OptimizationTier::Aggressive,
        },
        GovernanceError::TooManyRollbacks { count: 10, max: 5 },
        GovernanceError::InvalidConfig {
            reason: "bad".to_string(),
        },
        GovernanceError::StaleEvidence {
            epoch: epoch(),
            min: SecurityEpoch::from_raw(100),
        },
    ];
    let tags: BTreeSet<&str> = variants.iter().map(|v| v.tag()).collect();
    assert_eq!(tags.len(), 6);
}

#[test]
fn enrichment_governance_error_serde_all() {
    let variants: Vec<GovernanceError> = vec![
        GovernanceError::CertificateNotFound {
            cert_id: "c1".to_string(),
        },
        GovernanceError::CertificateExpired {
            cert_id: "c2".to_string(),
        },
        GovernanceError::UncertifiedTier {
            function_id: "fn1".to_string(),
            tier: OptimizationTier::Aggressive,
        },
        GovernanceError::TooManyRollbacks { count: 10, max: 5 },
        GovernanceError::InvalidConfig {
            reason: "bad".to_string(),
        },
        GovernanceError::StaleEvidence {
            epoch: epoch(),
            min: SecurityEpoch::from_raw(100),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// GovernanceVerdict — Clone, Debug, Display, methods
// ===========================================================================

#[test]
fn enrichment_governance_verdict_pass_methods() {
    let v = GovernanceVerdict::Pass {
        active_certs: 3,
        rollback_count: 1,
    };
    assert!(v.is_pass());
    assert!(!v.is_fail());
    assert!(!v.is_inconclusive());
    assert_eq!(v.tag(), "pass");
}

#[test]
fn enrichment_governance_verdict_fail_methods() {
    let v = GovernanceVerdict::Fail {
        reasons: vec!["bad".to_string()],
    };
    assert!(!v.is_pass());
    assert!(v.is_fail());
    assert!(!v.is_inconclusive());
    assert_eq!(v.tag(), "fail");
}

#[test]
fn enrichment_governance_verdict_inconclusive_methods() {
    let v = GovernanceVerdict::Inconclusive {
        reasons: vec!["unclear".to_string()],
    };
    assert!(!v.is_pass());
    assert!(!v.is_fail());
    assert!(v.is_inconclusive());
    assert_eq!(v.tag(), "inconclusive");
}

#[test]
fn enrichment_governance_verdict_display_nonempty() {
    let v = GovernanceVerdict::Pass {
        active_certs: 2,
        rollback_count: 0,
    };
    let disp = format!("{v}");
    assert!(!disp.is_empty());
}

// ===========================================================================
// GovernanceState — lifecycle, evaluate, report
// ===========================================================================

#[test]
fn enrichment_governance_state_new_empty() {
    let state = GovernanceState::new(epoch());
    assert!(state.certificates.is_empty());
    assert!(state.rollbacks.is_empty());
    assert!(state.forensic_entries.is_empty());
    assert!(state.active_tiers.is_empty());
}

#[test]
fn enrichment_governance_state_add_certificate() {
    let mut state = GovernanceState::new(epoch());
    let cert = make_cert("add-1", OptimizationTier::Aggressive);
    state.add_certificate(cert);
    assert_eq!(state.certificates.len(), 1);
}

#[test]
fn enrichment_governance_state_record_rollback() {
    let mut state = GovernanceState::new(epoch());
    state.record_rollback(make_rollback("rb-1", RollbackTrigger::ProofFailure));
    assert_eq!(state.rollbacks.len(), 1);
}

#[test]
fn enrichment_governance_state_add_forensic_entry() {
    let mut state = GovernanceState::new(epoch());
    state.add_forensic_entry(make_forensic("fe-1", ForensicSurface::SourceMapping));
    assert_eq!(state.forensic_entries.len(), 1);
}

#[test]
fn enrichment_governance_state_evaluate_empty_passes() {
    let state = GovernanceState::new(epoch());
    let cfg = GovernanceConfig::permissive();
    let verdict = state.evaluate(&cfg);
    assert!(verdict.is_pass());
}

#[test]
fn enrichment_governance_state_report_has_fields() {
    let state = GovernanceState::new(epoch());
    let cfg = GovernanceConfig::default();
    let report = state.report(&cfg);
    let json = serde_json::to_string(&report).unwrap();
    for field in &[
        "schema_version",
        "epoch",
        "total_certificates",
        "valid_certificates",
        "total_rollbacks",
        "active_speculative",
        "forensic_entry_count",
        "verdict",
        "report_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_governance_state_serde_roundtrip() {
    let mut state = GovernanceState::new(epoch());
    state.add_certificate(make_cert("sr-1", OptimizationTier::Aggressive));
    let json = serde_json::to_string(&state).unwrap();
    let back: GovernanceState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

// ===========================================================================
// 5-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_report() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let mut state = GovernanceState::new(epoch());
            state.add_certificate(make_cert("det-1", OptimizationTier::Aggressive));
            let report = state.report(&GovernanceConfig::default());
            report.report_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_cert_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| make_cert("det-2", OptimizationTier::Speculative).content_hash())
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

// ===========================================================================
// Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stability() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.certified-optimization-governance.v1"
    );
    assert_eq!(COMPONENT, "certified_optimization_governance");
    assert_eq!(BEAD_ID, "bd-1lsy.7.7.3");
    assert_eq!(POLICY_ID, "RGC-607C");
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_cross_cutting_revoke_nonexistent_errors() {
    let mut state = GovernanceState::new(epoch());
    let result = state.revoke_certificate("nonexistent", "reason", epoch());
    assert!(result.is_err());
}

#[test]
fn enrichment_cross_cutting_promote_baseline_no_cert_needed() {
    let mut state = GovernanceState::new(epoch());
    let result = state.promote_tier("fn-1", OptimizationTier::Baseline, None);
    assert!(result.is_ok());
}

#[test]
fn enrichment_cross_cutting_rollbacks_in_epoch() {
    let mut state = GovernanceState::new(epoch());
    state.record_rollback(make_rollback("rb-e1", RollbackTrigger::ProofFailure));
    state.record_rollback(make_rollback("rb-e2", RollbackTrigger::OperatorCommand));
    let rbs = state.rollbacks_in_epoch(epoch());
    assert_eq!(rbs.len(), 2);
}

#[test]
fn enrichment_cross_cutting_forensics_for_function() {
    let mut state = GovernanceState::new(epoch());
    state.add_forensic_entry(make_forensic("ff-1", ForensicSurface::SourceMapping));
    let entries = state.forensics_for_function("fn-ff-1");
    assert_eq!(entries.len(), 1);
}
