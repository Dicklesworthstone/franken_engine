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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::tee_attestation_policy::{
    AttestationFreshnessWindow, AttestationQuote, DecisionImpact, DecisionReceiptEmitter,
    MeasurementAlgorithm, MeasurementDigest, PlatformTrustRoot, PolicyGovernanceEvent,
    RevocationFallback, RevocationProbeStatus, RevocationSource, RevocationSourceType,
    SignedTrustRootOverrideArtifact, TeeAttestationPolicy, TeeAttestationPolicyError,
    TeeAttestationPolicyStore, TeePlatform, TemporaryTrustRootOverride,
    TrustRootOverrideArtifactInput, TrustRootPinning, TrustRootSource,
};

fn digest_hex(byte: u8, bytes: usize) -> String {
    let mut out = String::with_capacity(bytes * 2);
    for _ in 0..bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sample_policy(epoch: u64) -> TeeAttestationPolicy {
    let mut approved = BTreeMap::new();
    approved.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48),
        }],
    );
    approved.insert(
        TeePlatform::ArmTrustZone,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x22, 32),
        }],
    );
    approved.insert(
        TeePlatform::ArmCca,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x44, 32),
        }],
    );
    approved.insert(
        TeePlatform::AmdSev,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x33, 48),
        }],
    );

    TeeAttestationPolicy {
        schema_version: 1,
        policy_epoch: SecurityEpoch::from_raw(epoch),
        approved_measurements: approved,
        freshness_window: AttestationFreshnessWindow {
            standard_max_age_secs: 300,
            high_impact_max_age_secs: 60,
        },
        revocation_sources: vec![
            RevocationSource {
                source_id: "intel_pcs".to_string(),
                source_type: RevocationSourceType::IntelPcs,
                endpoint: "https://intel.example/pcs".to_string(),
                on_unavailable: RevocationFallback::TryNextSource,
            },
            RevocationSource {
                source_id: "internal_ledger".to_string(),
                source_type: RevocationSourceType::InternalLedger,
                endpoint: "sqlite://revocations".to_string(),
                on_unavailable: RevocationFallback::FailClosed,
            },
        ],
        platform_trust_roots: vec![
            PlatformTrustRoot {
                root_id: "sgx-root-a".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----SGX-A".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "tz-root-a".to_string(),
                platform: TeePlatform::ArmTrustZone,
                trust_anchor_pem: "-----BEGIN CERT-----TZ-A".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "cca-root-a".to_string(),
                platform: TeePlatform::ArmCca,
                trust_anchor_pem: "-----BEGIN CERT-----CCA-A".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "sev-root-a".to_string(),
                platform: TeePlatform::AmdSev,
                trust_anchor_pem: "-----BEGIN CERT-----SEV-A".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
        ],
    }
}

fn sgx_quote(trust_root_id: &str) -> AttestationQuote {
    let mut rev = BTreeMap::new();
    rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

    AttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48),
        },
        quote_age_secs: 8,
        trust_root_id: trust_root_id.to_string(),
        revocation_observations: rev,
    }
}

#[test]
fn policy_epoch_transition_requires_pickup_within_one_epoch_boundary() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(10), "trace-load-1", "decision-load-1")
        .expect("load epoch 10");

    let mut emitter = DecisionReceiptEmitter::new("emitter-a");
    emitter.sync_policy(&store).expect("initial sync");

    store
        .load_policy(sample_policy(11), "trace-load-2", "decision-load-2")
        .expect("load epoch 11");
    emitter
        .can_emit(SecurityEpoch::from_raw(11), &store)
        .expect("one-epoch lag is allowed");

    store
        .load_policy(sample_policy(12), "trace-load-3", "decision-load-3")
        .expect("load epoch 12");
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(12), &store)
        .expect_err("two-epoch lag must be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterPolicyStale { .. }
    ));

    emitter.sync_policy(&store).expect("resync to epoch 12");
    emitter
        .can_emit(SecurityEpoch::from_raw(12), &store)
        .expect("resynced emitter should pass");
}

#[test]
fn parse_failure_halts_emission_fail_closed() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(2), "trace-load-ok", "decision-load-ok")
        .expect("valid baseline");

    let mut emitter = DecisionReceiptEmitter::new("emitter-b");
    emitter.sync_policy(&store).expect("sync baseline");
    emitter
        .can_emit(SecurityEpoch::from_raw(2), &store)
        .expect("baseline emit allowed");

    let err = store
        .load_policy_json(
            "{\"schema_version\":\"broken\"}",
            "trace-fail",
            "decision-fail",
        )
        .expect_err("parse should fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
    assert!(store.receipt_emission_halted());

    let err = emitter
        .can_emit(SecurityEpoch::from_raw(2), &store)
        .expect_err("emit blocked");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
}

#[test]
fn temporary_override_enables_new_root_for_quote_validation() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(20), "trace-load-ovr", "decision-load-ovr")
        .expect("load epoch 20");

    let signer = SigningKey::from_bytes([19u8; 32]);
    let verifier = signer.verification_key();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "operator-tee".to_string(),
            justification: "temporary SGX root during cert rollover".to_string(),
            evidence_refs: vec!["evidence-123".to_string()],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-root-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(20),
            expires_epoch: SecurityEpoch::from_raw(22),
        },
    )
    .expect("signed override artifact");

    let request = TemporaryTrustRootOverride {
        override_id: "ovr-tee-1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-root-temp".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(20),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };

    store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(20),
            "trace-apply-ovr",
            "decision-apply-ovr",
        )
        .expect("override apply");

    store
        .evaluate_quote(
            &sgx_quote("sgx-root-temp"),
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(20),
            "trace-quote-ovr",
            "decision-quote-ovr",
        )
        .expect("new temporary root should verify");

    let events: &[PolicyGovernanceEvent] = store.governance_ledger();
    let has_override_event = events
        .iter()
        .any(|entry| entry.event == "temporary_trust_root_override_applied");
    assert!(has_override_event);
}

// ────────────────────────────────────────────────────────────
// Enrichment: quote evaluation, revocation, governance events,
// cross-platform, error paths
// ────────────────────────────────────────────────────────────

fn arm_cca_quote(trust_root_id: &str) -> AttestationQuote {
    let mut rev = BTreeMap::new();
    rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

    AttestationQuote {
        platform: TeePlatform::ArmCca,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x44, 32),
        },
        quote_age_secs: 5,
        trust_root_id: trust_root_id.to_string(),
        revocation_observations: rev,
    }
}

fn amd_sev_quote(trust_root_id: &str) -> AttestationQuote {
    let mut rev = BTreeMap::new();
    rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

    AttestationQuote {
        platform: TeePlatform::AmdSev,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x33, 48),
        },
        quote_age_secs: 3,
        trust_root_id: trust_root_id.to_string(),
        revocation_observations: rev,
    }
}

#[test]
fn store_default_state_is_halted_with_no_active_policy() {
    let store = TeeAttestationPolicyStore::default();
    assert!(store.receipt_emission_halted());
    assert!(store.active_policy().is_none());
    assert_eq!(store.last_error_code(), Some("policy_not_loaded"));
    assert!(store.governance_ledger().is_empty());
}

#[test]
fn emitter_cannot_sync_when_store_is_in_default_halted_state() {
    let store = TeeAttestationPolicyStore::default();
    let mut emitter = DecisionReceiptEmitter::new("emitter-halted");
    let err = emitter
        .sync_policy(&store)
        .expect_err("sync on halted store should fail");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
}

#[test]
fn load_policy_clears_halted_state_and_appends_governance_event() {
    let mut store = TeeAttestationPolicyStore::default();
    assert!(store.receipt_emission_halted());

    let policy_id = store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load should succeed");
    assert!(!store.receipt_emission_halted());
    assert!(store.last_error_code().is_none());
    assert!(store.active_policy().is_some());
    assert!(!policy_id.to_hex().is_empty());

    let events = store.governance_ledger();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "policy_loaded");
    assert_eq!(events[0].outcome, "allow");
    assert_eq!(events[0].component, "tee_attestation_policy");
    assert_eq!(events[0].trace_id, "trace-load");
    assert_eq!(events[0].decision_id, "decision-load");
}

#[test]
fn policy_epoch_regression_is_rejected_and_halts_emission() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(10), "trace-1", "decision-1")
        .expect("load epoch 10");
    assert!(!store.receipt_emission_halted());

    let err = store
        .load_policy(sample_policy(5), "trace-2", "decision-2")
        .expect_err("epoch regression should fail");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::PolicyEpochRegression { .. }
    ));
    assert!(store.receipt_emission_halted());
    assert_eq!(store.last_error_code(), Some("tee_policy_epoch_regression"));

    let events = store.governance_ledger();
    let fail_event = events
        .iter()
        .find(|e| e.event == "policy_load_failed")
        .expect("failure event should exist");
    assert_eq!(fail_event.outcome, "deny");
}

#[test]
fn quote_evaluation_passes_for_valid_sgx_quote() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(5), "trace-load", "decision-load")
        .expect("load policy");

    store
        .evaluate_quote(
            &sgx_quote("sgx-root-a"),
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "trace-eval",
            "decision-eval",
        )
        .expect("valid SGX quote should pass");

    let events = store.governance_ledger();
    let accepted = events
        .iter()
        .find(|e| e.event == "quote_accepted")
        .expect("accepted event should exist");
    assert_eq!(accepted.outcome, "allow");
    assert_eq!(accepted.metadata.get("platform").unwrap(), "intel_sgx");
    assert_eq!(
        accepted.metadata.get("trust_root_id").unwrap(),
        "sgx-root-a"
    );
}

#[test]
fn quote_evaluation_passes_for_arm_cca_and_amd_sev() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    store
        .evaluate_quote(
            &arm_cca_quote("cca-root-a"),
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-cca",
            "decision-cca",
        )
        .expect("valid CCA quote should pass");

    store
        .evaluate_quote(
            &amd_sev_quote("sev-root-a"),
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-sev",
            "decision-sev",
        )
        .expect("valid SEV quote should pass");

    let accepted_count = store
        .governance_ledger()
        .iter()
        .filter(|e| e.event == "quote_accepted")
        .count();
    assert_eq!(accepted_count, 2);
}

#[test]
fn stale_quote_is_rejected_for_standard_impact() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    let mut stale = sgx_quote("sgx-root-a");
    stale.quote_age_secs = 999;

    let err = store
        .evaluate_quote(
            &stale,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-stale",
            "decision-stale",
        )
        .expect_err("stale quote should be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale {
            quote_age_secs: 999,
            max_age_secs: 300,
        }
    ));
}

#[test]
fn high_impact_has_stricter_freshness_than_standard() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    let mut borderline = sgx_quote("sgx-root-a");
    borderline.quote_age_secs = 100;

    store
        .evaluate_quote(
            &borderline,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-std",
            "decision-std",
        )
        .expect("100s is within standard 300s window");

    let err = store
        .evaluate_quote(
            &borderline,
            DecisionImpact::HighImpact,
            SecurityEpoch::from_raw(1),
            "trace-high",
            "decision-high",
        )
        .expect_err("100s exceeds high-impact 60s window");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale {
            max_age_secs: 60,
            ..
        }
    ));
}

#[test]
fn unknown_measurement_digest_is_rejected() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    let mut bad_quote = sgx_quote("sgx-root-a");
    bad_quote.measurement.digest_hex = digest_hex(0xFF, 48);

    let err = store
        .evaluate_quote(
            &bad_quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-bad-meas",
            "decision-bad-meas",
        )
        .expect_err("unknown measurement should be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::UnknownMeasurementDigest { .. }
    ));

    let rejected = store
        .governance_ledger()
        .iter()
        .find(|e| e.event == "quote_rejected")
        .expect("rejection event should exist");
    assert_eq!(rejected.outcome, "deny");
    assert_eq!(rejected.error_code, "tee_policy_measurement_not_approved");
}

#[test]
fn unknown_trust_root_id_is_rejected() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    let err = store
        .evaluate_quote(
            &sgx_quote("sgx-root-nonexistent"),
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-bad-root",
            "decision-bad-root",
        )
        .expect_err("unknown trust root should be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::UnknownTrustRoot { .. }
    ));
}

#[test]
fn revoked_source_rejects_quote_immediately() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    let mut revoked_quote = sgx_quote("sgx-root-a");
    revoked_quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Revoked);

    let err = store
        .evaluate_quote(
            &revoked_quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-revoked",
            "decision-revoked",
        )
        .expect_err("revoked quote should be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevokedBySource { .. }
    ));
    assert_eq!(err.error_code(), "tee_policy_revoked");
}

#[test]
fn fail_closed_revocation_source_unavailable_blocks_emission() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    let mut all_unavailable_quote = sgx_quote("sgx-root-a");
    all_unavailable_quote.revocation_observations.clear();
    all_unavailable_quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    all_unavailable_quote.revocation_observations.insert(
        "internal_ledger".to_string(),
        RevocationProbeStatus::Unavailable,
    );

    let err = store
        .evaluate_quote(
            &all_unavailable_quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-unavail",
            "decision-unavail",
        )
        .expect_err("fail-closed source unavailable should block");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
    ));
}

#[test]
fn override_with_expired_artifact_is_rejected() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(30), "trace-load", "decision-load")
        .expect("load policy");

    let signer = SigningKey::from_bytes([77u8; 32]);
    let verifier = signer.verification_key();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "operator-expire".to_string(),
            justification: "testing expiration".to_string(),
            evidence_refs: vec!["ev-1".to_string()],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-root-expired".to_string(),
            issued_epoch: SecurityEpoch::from_raw(20),
            expires_epoch: SecurityEpoch::from_raw(25),
        },
    )
    .expect("create override artifact");

    let request = TemporaryTrustRootOverride {
        override_id: "ovr-expired-1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-root-expired".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-EXP".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(20),
            valid_until_epoch: Some(SecurityEpoch::from_raw(25)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };

    let err = store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(30),
            "trace-ovr-exp",
            "decision-ovr-exp",
        )
        .expect_err("expired override should be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideExpired { .. }
    ));
}

#[test]
fn override_target_mismatch_is_rejected() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(20), "trace-load", "decision-load")
        .expect("load policy");

    let signer = SigningKey::from_bytes([88u8; 32]);
    let verifier = signer.verification_key();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "operator-mismatch".to_string(),
            justification: "testing mismatch".to_string(),
            evidence_refs: vec!["ev-mm".to_string()],
            target_platform: TeePlatform::AmdSev,
            target_root_id: "sev-root-new".to_string(),
            issued_epoch: SecurityEpoch::from_raw(20),
            expires_epoch: SecurityEpoch::from_raw(25),
        },
    )
    .expect("create artifact targeting AmdSev");

    let request = TemporaryTrustRootOverride {
        override_id: "ovr-mismatch-1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-root-wrong".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-WRONG".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(20),
            valid_until_epoch: Some(SecurityEpoch::from_raw(25)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };

    let err = store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(20),
            "trace-ovr-mm",
            "decision-ovr-mm",
        )
        .expect_err("platform mismatch should be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideTargetMismatch { .. }
    ));
}

#[test]
fn governance_ledger_accumulates_across_operations() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-1", "dec-1")
        .expect("load");

    store
        .evaluate_quote(
            &sgx_quote("sgx-root-a"),
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-2",
            "dec-2",
        )
        .expect("accept quote");

    store
        .load_policy(sample_policy(2), "trace-3", "dec-3")
        .expect("policy upgrade");

    let events = store.governance_ledger();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event, "policy_loaded");
    assert_eq!(events[1].event, "quote_accepted");
    assert_eq!(events[2].event, "policy_loaded");

    for event in events {
        assert_eq!(event.component, "tee_attestation_policy");
    }
}

#[test]
fn policy_serde_roundtrip_preserves_all_fields() {
    let policy = sample_policy(42);
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: TeeAttestationPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, recovered);
}

#[test]
fn policy_derive_id_is_deterministic() {
    let policy_a = sample_policy(7);
    let policy_b = sample_policy(7);
    let id_a = policy_a.derive_policy_id().expect("derive a");
    let id_b = policy_b.derive_policy_id().expect("derive b");
    assert_eq!(id_a, id_b);
}

#[test]
fn emitter_not_synced_cannot_emit() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-load", "decision-load")
        .expect("load policy");

    let emitter = DecisionReceiptEmitter::new("emitter-unsync");
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(1), &store)
        .expect_err("unsync emitter should fail");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterNotSynced { .. }
    ));
    assert_eq!(err.error_code(), "tee_policy_emitter_not_synced");
}

#[test]
fn store_serde_roundtrip_preserves_halted_state() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(5), "trace-serde", "decision-serde")
        .expect("load");
    assert!(!store.receipt_emission_halted());

    let json = serde_json::to_string(&store).expect("serialize store");
    let recovered: TeeAttestationPolicyStore =
        serde_json::from_str(&json).expect("deserialize store");
    assert!(!recovered.receipt_emission_halted());
    assert!(recovered.active_policy().is_some());
    assert_eq!(
        recovered.active_policy().unwrap().policy_epoch,
        SecurityEpoch::from_raw(5)
    );
    assert_eq!(recovered.governance_ledger().len(), 1);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 8: enum serde, error Display, constants
// ────────────────────────────────────────────────────────────

#[test]
fn tee_platform_serde_round_trip() {
    for platform in TeePlatform::ALL {
        let json = serde_json::to_string(&platform).expect("serialize");
        let recovered: TeePlatform = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(platform, recovered);
    }
}

#[test]
fn tee_platform_all_has_four_elements() {
    assert_eq!(TeePlatform::ALL.len(), 4);
}

#[test]
fn measurement_algorithm_serde_round_trip() {
    for algo in [MeasurementAlgorithm::Sha256, MeasurementAlgorithm::Sha384] {
        let json = serde_json::to_string(&algo).expect("serialize");
        let recovered: MeasurementAlgorithm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(algo, recovered);
    }
}

#[test]
fn decision_impact_serde_round_trip() {
    for impact in [DecisionImpact::Standard, DecisionImpact::HighImpact] {
        let json = serde_json::to_string(&impact).expect("serialize");
        let recovered: DecisionImpact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(impact, recovered);
    }
}

#[test]
fn revocation_source_type_serde_round_trip() {
    for src_type in [
        RevocationSourceType::IntelPcs,
        RevocationSourceType::InternalLedger,
    ] {
        let json = serde_json::to_string(&src_type).expect("serialize");
        let recovered: RevocationSourceType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(src_type, recovered);
    }
}

#[test]
fn revocation_fallback_serde_round_trip() {
    for fallback in [
        RevocationFallback::TryNextSource,
        RevocationFallback::FailClosed,
    ] {
        let json = serde_json::to_string(&fallback).expect("serialize");
        let recovered: RevocationFallback = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(fallback, recovered);
    }
}

#[test]
fn revocation_probe_status_serde_round_trip() {
    for status in [
        RevocationProbeStatus::Good,
        RevocationProbeStatus::Revoked,
        RevocationProbeStatus::Unavailable,
    ] {
        let json = serde_json::to_string(&status).expect("serialize");
        let recovered: RevocationProbeStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, recovered);
    }
}

#[test]
fn trust_root_pinning_serde_round_trip() {
    let pinned = TrustRootPinning::Pinned;
    let rotating = TrustRootPinning::Rotating {
        rotation_group: "group-a".to_string(),
    };
    for pinning in [pinned, rotating] {
        let json = serde_json::to_string(&pinning).expect("serialize");
        let recovered: TrustRootPinning = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pinning, recovered);
    }
}

#[test]
fn trust_root_source_serde_round_trip() {
    let sources = [
        TrustRootSource::Policy,
        TrustRootSource::TemporaryOverride {
            override_id: "ovr-1".to_string(),
            justification_artifact_id: "art-1".to_string(),
        },
    ];
    for source in sources {
        let json = serde_json::to_string(&source).expect("serialize");
        let recovered: TrustRootSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(source, recovered);
    }
}

#[test]
fn tee_attestation_policy_error_error_codes_all_unique() {
    use std::collections::BTreeSet;
    let errors: Vec<TeeAttestationPolicyError> = vec![
        TeeAttestationPolicyError::ReceiptEmissionHalted,
        TeeAttestationPolicyError::EmitterNotSynced {
            emitter_id: "e".to_string(),
        },
        TeeAttestationPolicyError::EmitterPolicyStale {
            emitter_id: "e".to_string(),
            synced_epoch: SecurityEpoch::from_raw(1),
            required_epoch: SecurityEpoch::from_raw(3),
        },
        TeeAttestationPolicyError::PolicyEpochRegression {
            current: SecurityEpoch::from_raw(5),
            attempted: SecurityEpoch::from_raw(3),
        },
        TeeAttestationPolicyError::AttestationStale {
            quote_age_secs: 999,
            max_age_secs: 300,
        },
        TeeAttestationPolicyError::UnknownMeasurementDigest {
            platform: TeePlatform::IntelSgx,
            digest: "abc".to_string(),
        },
        TeeAttestationPolicyError::UnknownTrustRoot {
            platform: TeePlatform::IntelSgx,
            root_id: "r".to_string(),
        },
        TeeAttestationPolicyError::RevokedBySource {
            source_id: "s".to_string(),
        },
        TeeAttestationPolicyError::RevocationSourceUnavailable {
            source_id: "s".to_string(),
        },
    ];
    let codes: BTreeSet<String> = errors.iter().map(|e| e.error_code().to_string()).collect();
    assert_eq!(
        codes.len(),
        errors.len(),
        "each error variant should have a unique code"
    );
}

#[test]
fn tee_attestation_policy_error_is_std_error() {
    let err: Box<dyn std::error::Error> =
        Box::new(TeeAttestationPolicyError::ReceiptEmissionHalted);
    assert!(!err.to_string().is_empty());
}

#[test]
fn measurement_digest_serde_round_trip() {
    let digest = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha256,
        digest_hex: digest_hex(0xAA, 32),
    };
    let json = serde_json::to_string(&digest).expect("serialize");
    let recovered: MeasurementDigest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(digest, recovered);
}

#[test]
fn attestation_quote_serde_round_trip() {
    let quote = sgx_quote("sgx-root-a");
    let json = serde_json::to_string(&quote).expect("serialize");
    let recovered: AttestationQuote = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(quote, recovered);
}

#[test]
fn governance_event_serde_round_trip() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "trace-serde-ev", "decision-serde-ev")
        .expect("load");
    let event = &store.governance_ledger()[0];
    let json = serde_json::to_string(event).expect("serialize");
    let recovered: PolicyGovernanceEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*event, recovered);
}
