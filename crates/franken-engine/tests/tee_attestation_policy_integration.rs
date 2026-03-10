//! Integration tests for the `tee_attestation_policy` module.
//!
//! Bead: bd-1t5w

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
    MeasurementAlgorithm, MeasurementDigest, PlatformTrustRoot, RevocationFallback,
    RevocationProbeStatus, RevocationSource, RevocationSourceType, SignedTrustRootOverrideArtifact,
    TeeAttestationPolicy, TeeAttestationPolicyError, TeeAttestationPolicyStore, TeePlatform,
    TemporaryTrustRootOverride, TrustRootOverrideArtifactInput, TrustRootPinning, TrustRootSource,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn digest_hex(byte: u8, bytes: usize) -> String {
    (0..bytes).map(|_| format!("{byte:02x}")).collect()
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
                source_id: "manufacturer_crl".to_string(),
                source_type: RevocationSourceType::ManufacturerCrl,
                endpoint: "https://manufacturer.example/crl".to_string(),
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

fn sgx_quote() -> AttestationQuote {
    let mut rev = BTreeMap::new();
    rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    rev.insert(
        "manufacturer_crl".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

    AttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48),
        },
        quote_age_secs: 12,
        trust_root_id: "sgx-root-a".to_string(),
        revocation_observations: rev,
    }
}

fn sk() -> SigningKey {
    SigningKey::from_bytes([7u8; 32])
}

fn loaded_store(epoch: u64) -> TeeAttestationPolicyStore {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(epoch), "trace-init", "decision-init")
        .expect("load");
    store
}

// ---------------------------------------------------------------------------
// TeePlatform Display and ALL
// ---------------------------------------------------------------------------

#[test]
fn tee_platform_display_all_variants() {
    assert_eq!(TeePlatform::IntelSgx.to_string(), "intel_sgx");
    assert_eq!(TeePlatform::ArmTrustZone.to_string(), "arm_trustzone");
    assert_eq!(TeePlatform::ArmCca.to_string(), "arm_cca");
    assert_eq!(TeePlatform::AmdSev.to_string(), "amd_sev");
}

#[test]
fn tee_platform_all_contains_four_variants() {
    assert_eq!(TeePlatform::ALL.len(), 4);
}

// ---------------------------------------------------------------------------
// MeasurementAlgorithm Display
// ---------------------------------------------------------------------------

#[test]
fn measurement_algorithm_display() {
    assert_eq!(MeasurementAlgorithm::Sha256.to_string(), "sha256");
    assert_eq!(MeasurementAlgorithm::Sha384.to_string(), "sha384");
    assert_eq!(MeasurementAlgorithm::Sha512.to_string(), "sha512");
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn tee_platform_serde_roundtrip() {
    for platform in TeePlatform::ALL {
        let json = serde_json::to_string(&platform).unwrap();
        let back: TeePlatform = serde_json::from_str(&json).unwrap();
        assert_eq!(platform, back);
    }
}

#[test]
fn measurement_algorithm_serde_roundtrip() {
    for algo in [
        MeasurementAlgorithm::Sha256,
        MeasurementAlgorithm::Sha384,
        MeasurementAlgorithm::Sha512,
    ] {
        let json = serde_json::to_string(&algo).unwrap();
        let back: MeasurementAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(algo, back);
    }
}

#[test]
fn decision_impact_serde_roundtrip() {
    for impact in [DecisionImpact::Standard, DecisionImpact::HighImpact] {
        let json = serde_json::to_string(&impact).unwrap();
        let back: DecisionImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, back);
    }
}

#[test]
fn revocation_probe_status_serde_roundtrip() {
    for status in [
        RevocationProbeStatus::Good,
        RevocationProbeStatus::Revoked,
        RevocationProbeStatus::Unavailable,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: RevocationProbeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn revocation_fallback_serde_roundtrip() {
    for fb in [
        RevocationFallback::TryNextSource,
        RevocationFallback::FailClosed,
    ] {
        let json = serde_json::to_string(&fb).unwrap();
        let back: RevocationFallback = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
    }
}

#[test]
fn tee_attestation_policy_error_serde_roundtrip() {
    let err = TeeAttestationPolicyError::AttestationStale {
        quote_age_secs: 99,
        max_age_secs: 60,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TeeAttestationPolicyError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ---------------------------------------------------------------------------
// TeeAttestationPolicy — from_json / to_canonical_json / derive_policy_id
// ---------------------------------------------------------------------------

#[test]
fn policy_canonical_json_roundtrip() {
    let policy = sample_policy(7);
    let json = policy.to_canonical_json().expect("serialize");
    let parsed = TeeAttestationPolicy::from_json(&json).expect("parse");
    assert_eq!(policy, parsed);
}

#[test]
fn policy_id_is_deterministic() {
    let id1 = sample_policy(3).derive_policy_id().unwrap();
    let id2 = sample_policy(3).derive_policy_id().unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn policy_id_changes_with_epoch() {
    let id1 = sample_policy(1).derive_policy_id().unwrap();
    let id2 = sample_policy(2).derive_policy_id().unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn from_json_fails_on_invalid_json() {
    let err = TeeAttestationPolicy::from_json("not json").expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

// ---------------------------------------------------------------------------
// Policy validation errors
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_missing_platform_measurements() {
    let mut policy = sample_policy(1);
    policy.approved_measurements.remove(&TeePlatform::AmdSev);
    let err = policy.validate().expect_err("must fail");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::AmdSev
        }
    ));
}

#[test]
fn validate_rejects_empty_measurements_for_platform() {
    let mut policy = sample_policy(1);
    policy
        .approved_measurements
        .insert(TeePlatform::IntelSgx, vec![]);
    let err = policy.validate().expect_err("must fail");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx
        }
    ));
}

#[test]
fn validate_rejects_invalid_digest_length() {
    let mut policy = sample_policy(1);
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: "abcd".to_string(), // too short for sha384 (needs 96 hex chars)
        }],
    );
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_measurement_digest");
}

#[test]
fn validate_rejects_non_hex_digest() {
    let mut policy = sample_policy(1);
    let bad_digest = "g".repeat(96); // 'g' is not hex
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: bad_digest,
        }],
    );
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_measurement_digest");
}

#[test]
fn validate_rejects_duplicate_measurement_digest() {
    let mut policy = sample_policy(1);
    let dup = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha384,
        digest_hex: digest_hex(0x11, 48),
    };
    policy
        .approved_measurements
        .insert(TeePlatform::IntelSgx, vec![dup.clone(), dup]);
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_duplicate_measurement_digest");
}

#[test]
fn validate_rejects_inverted_freshness_window() {
    let mut policy = sample_policy(1);
    policy.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 10,
        high_impact_max_age_secs: 20, // high impact > standard is invalid
    };
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_freshness_window");
}

#[test]
fn validate_rejects_zero_freshness_window() {
    let mut policy = sample_policy(1);
    policy.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 0,
        high_impact_max_age_secs: 0,
    };
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_freshness_window");
}

#[test]
fn validate_rejects_empty_revocation_sources() {
    let mut policy = sample_policy(1);
    policy.revocation_sources.clear();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_empty_revocation_sources");
}

#[test]
fn validate_rejects_revocation_source_with_empty_id() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].source_id = "".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_revocation_source");
}

#[test]
fn validate_rejects_revocation_source_with_empty_endpoint() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].endpoint = "".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_revocation_source");
}

#[test]
fn validate_rejects_duplicate_revocation_source() {
    let mut policy = sample_policy(1);
    let dup = policy.revocation_sources[0].clone();
    policy.revocation_sources.push(dup);
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_duplicate_revocation_source");
}

#[test]
fn validate_rejects_no_fail_closed_revocation_source() {
    let mut policy = sample_policy(1);
    for source in &mut policy.revocation_sources {
        source.on_unavailable = RevocationFallback::TryNextSource;
    }
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_revocation_bypass_config");
}

#[test]
fn validate_rejects_empty_trust_roots() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots.clear();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_missing_trust_roots");
}

#[test]
fn validate_rejects_trust_root_with_empty_id() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].root_id = "".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn validate_rejects_trust_root_with_empty_pem() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].trust_anchor_pem = "".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn validate_rejects_trust_root_with_inverted_epoch_range() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_from_epoch = SecurityEpoch::from_raw(10);
    policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(5));
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn validate_rejects_rotating_root_without_expiry() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].pinning = TrustRootPinning::Rotating {
        rotation_group: "group-a".to_string(),
    };
    policy.platform_trust_roots[0].valid_until_epoch = None;
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn validate_rejects_rotating_root_with_empty_group() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].pinning = TrustRootPinning::Rotating {
        rotation_group: "".to_string(),
    };
    policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(100));
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn validate_rejects_duplicate_trust_root() {
    let mut policy = sample_policy(1);
    let dup = policy.platform_trust_roots[0].clone();
    policy.platform_trust_roots.push(dup);
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_duplicate_trust_root");
}

#[test]
fn validate_rejects_missing_pinned_root_for_platform() {
    let mut policy = sample_policy(1);
    // Make SGX root inactive at policy epoch by setting valid_from in future
    policy.platform_trust_roots[0].valid_from_epoch = SecurityEpoch::from_raw(999);
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_missing_pinned_trust_root");
}

// ---------------------------------------------------------------------------
// evaluate_quote — success
// ---------------------------------------------------------------------------

#[test]
fn evaluate_quote_succeeds_for_approved_sgx_quote() {
    let policy = sample_policy(1);
    let quote = sgx_quote();
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect("should pass");
}

#[test]
fn evaluate_quote_succeeds_for_high_impact_within_freshness() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 59; // under 60s limit
    policy
        .evaluate_quote(
            &quote,
            DecisionImpact::HighImpact,
            SecurityEpoch::from_raw(1),
        )
        .expect("should pass");
}

// ---------------------------------------------------------------------------
// evaluate_quote — failures
// ---------------------------------------------------------------------------

#[test]
fn evaluate_quote_rejects_unknown_measurement() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.measurement.digest_hex = digest_hex(0xff, 48);
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_measurement_not_approved");
}

#[test]
fn evaluate_quote_rejects_stale_standard_attestation() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 301; // over 300s limit
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_attestation_stale");
}

#[test]
fn evaluate_quote_rejects_stale_high_impact_attestation() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 61; // over 60s limit
    let err = policy
        .evaluate_quote(
            &quote,
            DecisionImpact::HighImpact,
            SecurityEpoch::from_raw(1),
        )
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_attestation_stale");
}

#[test]
fn evaluate_quote_rejects_unknown_trust_root() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.trust_root_id = "nonexistent-root".to_string();
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_unknown_trust_root");
}

#[test]
fn evaluate_quote_rejects_expired_trust_root() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(2));
    let quote = sgx_quote();
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(3))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_expired_trust_root");
}

#[test]
fn evaluate_quote_rejects_revoked_by_source() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Revoked);
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_revoked");
}

#[test]
fn evaluate_quote_rejects_fail_closed_source_unavailable() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    // All sources unavailable — internal_ledger is fail-closed
    quote.revocation_observations.insert(
        "internal_ledger".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_revocation_source_unavailable");
}

#[test]
fn evaluate_quote_uses_revocation_fallback_chain() {
    let policy = sample_policy(1);
    let quote = sgx_quote();
    // intel_pcs and manufacturer_crl are unavailable (TryNextSource),
    // internal_ledger returns Good → overall pass
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect("fallback should reach Good source");
}

// ---------------------------------------------------------------------------
// TeeAttestationPolicyStore — lifecycle
// ---------------------------------------------------------------------------

#[test]
fn store_default_is_halted_with_policy_not_loaded() {
    let store = TeeAttestationPolicyStore::default();
    assert!(store.receipt_emission_halted());
    assert_eq!(store.last_error_code(), Some("policy_not_loaded"));
    assert!(store.active_policy().is_none());
    assert!(store.governance_ledger().is_empty());
}

#[test]
fn store_load_policy_succeeds_and_unhalts() {
    let store = loaded_store(5);
    assert!(!store.receipt_emission_halted());
    assert!(store.last_error_code().is_none());
    assert!(store.active_policy().is_some());
    assert_eq!(
        store.active_policy().unwrap().policy_epoch,
        SecurityEpoch::from_raw(5)
    );
}

#[test]
fn store_load_policy_json_succeeds() {
    let mut store = TeeAttestationPolicyStore::default();
    let json = sample_policy(3).to_canonical_json().unwrap();
    let id = store
        .load_policy_json(&json, "trace-1", "decision-1")
        .expect("load");
    assert!(!store.receipt_emission_halted());
    assert!(!id.to_hex().is_empty());
}

#[test]
fn store_load_policy_json_fails_on_bad_json() {
    let mut store = TeeAttestationPolicyStore::default();
    let err = store
        .load_policy_json("{bad}", "trace-bad", "decision-bad")
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
    assert!(store.receipt_emission_halted());
}

#[test]
fn store_rejects_policy_epoch_regression() {
    let mut store = loaded_store(10);
    let err = store
        .load_policy(sample_policy(5), "trace-reg", "decision-reg")
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_epoch_regression");
    assert!(store.receipt_emission_halted());
}

#[test]
fn store_allows_same_epoch_reload() {
    let mut store = loaded_store(5);
    store
        .load_policy(sample_policy(5), "trace-same", "decision-same")
        .expect("same epoch should be ok");
    assert!(!store.receipt_emission_halted());
}

#[test]
fn store_allows_epoch_advancement() {
    let mut store = loaded_store(5);
    store
        .load_policy(sample_policy(10), "trace-adv", "decision-adv")
        .expect("higher epoch ok");
    assert_eq!(
        store.active_policy().unwrap().policy_epoch,
        SecurityEpoch::from_raw(10)
    );
}

// ---------------------------------------------------------------------------
// Store — evaluate_quote
// ---------------------------------------------------------------------------

#[test]
fn store_evaluate_quote_succeeds_when_loaded() {
    let mut store = loaded_store(5);
    let quote = sgx_quote();
    store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "trace-q1",
            "decision-q1",
        )
        .expect("should pass");

    let events = store.governance_ledger();
    let last = events.last().unwrap();
    assert_eq!(last.event, "quote_accepted");
    assert_eq!(last.outcome, "allow");
}

#[test]
fn store_evaluate_quote_fails_when_halted() {
    let mut store = TeeAttestationPolicyStore::default();
    let quote = sgx_quote();
    let err = store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-halt",
            "decision-halt",
        )
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_emission_halted");
}

#[test]
fn store_evaluate_quote_records_rejection_event() {
    let mut store = loaded_store(5);
    let mut quote = sgx_quote();
    quote.measurement.digest_hex = digest_hex(0xff, 48);
    let _err = store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "trace-rej",
            "decision-rej",
        )
        .expect_err("must fail");

    let events = store.governance_ledger();
    let last = events.last().unwrap();
    assert_eq!(last.event, "quote_rejected");
    assert_eq!(last.outcome, "deny");
}

// ---------------------------------------------------------------------------
// SignedTrustRootOverrideArtifact
// ---------------------------------------------------------------------------

#[test]
fn override_artifact_create_signed_and_verify() {
    let signer = sk();
    let verifier = signer.verification_key();

    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "operator-1".to_string(),
            justification: "emergency rotation".to_string(),
            evidence_refs: vec!["ref-b".to_string(), "ref-a".to_string()],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp-root".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(15),
        },
    )
    .expect("create");

    assert!(!artifact.artifact_id.is_empty());
    artifact
        .verify(&verifier, SecurityEpoch::from_raw(12))
        .expect("should verify");
}

#[test]
fn override_artifact_verify_rejects_expired() {
    let signer = sk();
    let verifier = signer.verification_key();

    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::AmdSev,
            target_root_id: "sev-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
    )
    .expect("create");

    let err = artifact
        .verify(&verifier, SecurityEpoch::from_raw(6))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_expired");
}

#[test]
fn override_artifact_verify_rejects_tampered_justification() {
    let signer = sk();
    let verifier = signer.verification_key();

    let mut artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "legit".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(10),
        },
    )
    .expect("create");

    artifact.justification = "tampered".to_string();
    let err = artifact
        .verify(&verifier, SecurityEpoch::from_raw(5))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_signature_invalid");
}

#[test]
fn override_artifact_rejects_empty_actor() {
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk(),
        TrustRootOverrideArtifactInput {
            actor: "".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
    )
    .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_artifact_invalid");
}

#[test]
fn override_artifact_rejects_empty_justification() {
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk(),
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
    )
    .expect_err("must fail");
    assert_eq!(
        err.error_code(),
        "tee_policy_override_justification_missing"
    );
}

#[test]
fn override_artifact_rejects_expires_before_issued() {
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk(),
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
    )
    .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_artifact_invalid");
}

// ---------------------------------------------------------------------------
// Store — apply_temporary_trust_root_override
// ---------------------------------------------------------------------------

#[test]
fn store_apply_override_adds_temporary_root() {
    let mut store = loaded_store(10);
    let signer = sk();
    let verifier = signer.verification_key();

    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "incident response".to_string(),
            evidence_refs: vec!["ev-1".to_string()],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp-root".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(15),
        },
    )
    .expect("create artifact");

    let request = TemporaryTrustRootOverride {
        override_id: "ovr-1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp-root".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----TEMP".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(20)),
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
            SecurityEpoch::from_raw(10),
            "trace-ovr",
            "decision-ovr",
        )
        .expect("apply override");

    let active = store.active_policy().unwrap();
    let temp_root = active
        .platform_trust_roots
        .iter()
        .find(|r| r.root_id == "sgx-temp-root")
        .expect("temp root should exist");
    assert!(matches!(
        temp_root.source,
        TrustRootSource::TemporaryOverride { .. }
    ));
    // Expiry capped to artifact's expires_epoch (15) since it's less than root's (20)
    assert_eq!(
        temp_root.valid_until_epoch,
        Some(SecurityEpoch::from_raw(15))
    );
}

#[test]
fn store_apply_override_fails_with_no_active_policy() {
    let mut store = TeeAttestationPolicyStore::default();
    let signer = sk();
    let verifier = signer.verification_key();

    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
    )
    .expect("create artifact");

    let request = TemporaryTrustRootOverride {
        override_id: "ovr-no-policy".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "cert".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "grp".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };

    let err = store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(2),
            "trace",
            "decision",
        )
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_not_loaded");
}

// ---------------------------------------------------------------------------
// DecisionReceiptEmitter
// ---------------------------------------------------------------------------

#[test]
fn emitter_new_has_no_synced_epoch() {
    let emitter = DecisionReceiptEmitter::new("emitter-1");
    assert_eq!(emitter.emitter_id, "emitter-1");
    assert!(emitter.last_synced_policy_epoch.is_none());
}

#[test]
fn emitter_sync_policy_succeeds_when_store_loaded() {
    let store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("emitter-2");
    let epoch = emitter.sync_policy(&store).expect("sync");
    assert_eq!(epoch, SecurityEpoch::from_raw(5));
    assert_eq!(
        emitter.last_synced_policy_epoch,
        Some(SecurityEpoch::from_raw(5))
    );
}

#[test]
fn emitter_sync_policy_fails_when_halted() {
    let store = TeeAttestationPolicyStore::default();
    let mut emitter = DecisionReceiptEmitter::new("emitter-3");
    let err = emitter.sync_policy(&store).expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_emission_halted");
}

#[test]
fn emitter_can_emit_succeeds_when_synced_and_current() {
    let store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("emitter-4");
    emitter.sync_policy(&store).unwrap();
    emitter
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .expect("should pass");
}

#[test]
fn emitter_can_emit_allows_one_epoch_behind() {
    let store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("emitter-5");
    emitter.sync_policy(&store).unwrap();
    // Synced at epoch 5, runtime at epoch 6 — one behind is ok
    emitter
        .can_emit(SecurityEpoch::from_raw(6), &store)
        .expect("should pass");
}

#[test]
fn emitter_can_emit_rejects_two_epochs_behind() {
    let store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("emitter-6");
    emitter.sync_policy(&store).unwrap();
    // Synced at epoch 5, runtime at epoch 7 — two behind is stale
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(7), &store)
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_emitter_stale");
}

#[test]
fn emitter_can_emit_rejects_unsynced() {
    let store = loaded_store(5);
    let emitter = DecisionReceiptEmitter::new("emitter-7");
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_emitter_not_synced");
}

#[test]
fn emitter_can_emit_rejects_when_store_halted() {
    let store = TeeAttestationPolicyStore::default();
    let emitter = DecisionReceiptEmitter::new("emitter-8");
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(1), &store)
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_emission_halted");
}

// ---------------------------------------------------------------------------
// TeeAttestationPolicyError — Display and error_code
// ---------------------------------------------------------------------------

#[test]
fn error_display_is_nonempty_for_all_code_paths() {
    let errors: Vec<TeeAttestationPolicyError> = vec![
        TeeAttestationPolicyError::ParseFailed {
            detail: "bad json".into(),
        },
        TeeAttestationPolicyError::SerializationFailed {
            detail: "encode failed".into(),
        },
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx,
        },
        TeeAttestationPolicyError::InvalidMeasurementDigest {
            platform: TeePlatform::AmdSev,
            digest: "abc".into(),
            expected_hex_len: 96,
        },
        TeeAttestationPolicyError::DuplicateMeasurementDigest {
            platform: TeePlatform::ArmCca,
            digest: "dup".into(),
        },
        TeeAttestationPolicyError::InvalidFreshnessWindow {
            standard_max_age_secs: 10,
            high_impact_max_age_secs: 20,
        },
        TeeAttestationPolicyError::EmptyRevocationSources,
        TeeAttestationPolicyError::InvalidRevocationSource {
            reason: "bad".into(),
        },
        TeeAttestationPolicyError::DuplicateRevocationSource {
            source_id: "dup".into(),
        },
        TeeAttestationPolicyError::RevocationFallbackBypass,
        TeeAttestationPolicyError::MissingTrustRoots,
        TeeAttestationPolicyError::InvalidTrustRoot {
            root_id: "root".into(),
            reason: "bad".into(),
        },
        TeeAttestationPolicyError::DuplicateTrustRoot {
            platform: TeePlatform::IntelSgx,
            root_id: "dup".into(),
        },
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::ArmTrustZone,
        },
        TeeAttestationPolicyError::PolicyEpochRegression {
            current: SecurityEpoch::from_raw(10),
            attempted: SecurityEpoch::from_raw(5),
        },
        TeeAttestationPolicyError::IdDerivationFailed {
            detail: "hash fail".into(),
        },
        TeeAttestationPolicyError::ReceiptEmissionHalted,
        TeeAttestationPolicyError::NoActivePolicy,
        TeeAttestationPolicyError::UnknownMeasurementDigest {
            platform: TeePlatform::IntelSgx,
            digest: "unknown".into(),
        },
        TeeAttestationPolicyError::AttestationStale {
            quote_age_secs: 999,
            max_age_secs: 60,
        },
        TeeAttestationPolicyError::UnknownTrustRoot {
            platform: TeePlatform::AmdSev,
            root_id: "miss".into(),
        },
        TeeAttestationPolicyError::ExpiredTrustRoot {
            root_id: "old".into(),
            runtime_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
        },
        TeeAttestationPolicyError::RevokedBySource {
            source_id: "pcs".into(),
        },
        TeeAttestationPolicyError::RevocationSourceUnavailable {
            source_id: "ledger".into(),
        },
        TeeAttestationPolicyError::RevocationEvidenceUnavailable,
        TeeAttestationPolicyError::InvalidOverrideArtifact {
            reason: "bad".into(),
        },
        TeeAttestationPolicyError::OverrideJustificationMissing,
        TeeAttestationPolicyError::OverrideExpired {
            current_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
        TeeAttestationPolicyError::OverrideSignatureInvalid {
            detail: "mismatch".into(),
        },
        TeeAttestationPolicyError::OverrideTargetMismatch {
            expected_platform: TeePlatform::IntelSgx,
            expected_root_id: "a".into(),
            actual_platform: TeePlatform::AmdSev,
            actual_root_id: "b".into(),
        },
        TeeAttestationPolicyError::EmitterNotSynced {
            emitter_id: "em-1".into(),
        },
        TeeAttestationPolicyError::EmitterPolicyStale {
            emitter_id: "em-2".into(),
            synced_epoch: SecurityEpoch::from_raw(1),
            required_epoch: SecurityEpoch::from_raw(5),
        },
    ];

    for err in &errors {
        let display = err.to_string();
        assert!(!display.is_empty(), "empty Display for {err:?}");
        let code = err.error_code();
        assert!(!code.is_empty(), "empty error_code for {err:?}");
        assert!(
            code.starts_with("tee_policy_"),
            "error_code should start with tee_policy_: got {code}"
        );
    }
}

// ---------------------------------------------------------------------------
// Governance ledger events
// ---------------------------------------------------------------------------

#[test]
fn governance_ledger_accumulates_events_across_operations() {
    let mut store = loaded_store(5);
    let quote = sgx_quote();
    store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "trace-led-1",
            "decision-led-1",
        )
        .unwrap();
    store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "trace-led-2",
            "decision-led-2",
        )
        .unwrap();

    // 1 load event + 2 quote events
    assert!(store.governance_ledger().len() >= 3);
    for event in store.governance_ledger() {
        assert_eq!(event.component, "tee_attestation_policy");
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
    }
}

#[test]
fn governance_ledger_records_load_failure() {
    let mut store = TeeAttestationPolicyStore::default();
    let _ = store.load_policy_json("{}", "trace-fail", "decision-fail");
    let events = store.governance_ledger();
    assert!(!events.is_empty());
    let last = events.last().unwrap();
    assert_eq!(last.event, "policy_load_failed");
    assert_eq!(last.outcome, "deny");
}

// ---------------------------------------------------------------------------
// Revocation source type Other variant
// ---------------------------------------------------------------------------

#[test]
fn revocation_source_type_other_with_empty_name_fails_validation() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].source_type = RevocationSourceType::Other("".to_string());
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_revocation_source");
}

#[test]
fn revocation_source_type_other_with_valid_name_passes() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].source_type =
        RevocationSourceType::Other("custom-checker".to_string());
    policy.validate().expect("should pass");
}

// ---------------------------------------------------------------------------
// Temporary override target mismatch
// ---------------------------------------------------------------------------

#[test]
fn override_target_mismatch_detected() {
    let mut store = loaded_store(10);
    let signer = sk();
    let verifier = signer.verification_key();

    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::AmdSev, // artifact targets AMD SEV
            target_root_id: "sev-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(15),
        },
    )
    .expect("create");

    let request = TemporaryTrustRootOverride {
        override_id: "ovr-mismatch".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp".to_string(), // root is SGX — mismatch!
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "cert".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(15)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "grp".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };

    let err = store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(10),
            "trace",
            "decision",
        )
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_target_mismatch");
}

// ---------------------------------------------------------------------------
// Trust root with TemporaryOverride source validation
// ---------------------------------------------------------------------------

#[test]
fn temporary_override_source_requires_valid_until_epoch() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots.push(PlatformTrustRoot {
        root_id: "sgx-temp-extra".to_string(),
        platform: TeePlatform::IntelSgx,
        trust_anchor_pem: "cert".to_string(),
        valid_from_epoch: SecurityEpoch::from_raw(0),
        valid_until_epoch: None, // missing — required for temporary override
        pinning: TrustRootPinning::Pinned,
        source: TrustRootSource::TemporaryOverride {
            override_id: "ovr-1".to_string(),
            justification_artifact_id: "art-1".to_string(),
        },
    });
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}
