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

// ===========================================================================
// Enrichment tests — TEE attestation policy enforcement, edge cases,
// attestation validation, error handling, policy composition and conflict
// ===========================================================================

// ---------------------------------------------------------------------------
// Policy validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_sha256_digest_wrong_length_rejected() {
    let mut policy = sample_policy(1);
    // SHA-256 requires 64 hex chars (32 bytes); give 63
    let bad_digest = digest_hex(0xaa, 32);
    let truncated = bad_digest[..63].to_string();
    policy.approved_measurements.insert(
        TeePlatform::ArmTrustZone,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: truncated,
        }],
    );
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_measurement_digest");
}

#[test]
fn enrichment_validate_sha512_digest_correct_length_accepted() {
    let mut policy = sample_policy(1);
    // SHA-512 requires 128 hex chars (64 bytes)
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha512,
            digest_hex: digest_hex(0xcc, 64),
        }],
    );
    policy.validate().expect("sha512 with correct length should pass");
}

#[test]
fn enrichment_validate_sha512_digest_wrong_length_rejected() {
    let mut policy = sample_policy(1);
    // SHA-512 expects 128 hex chars; give 96 (sha384 size)
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha512,
            digest_hex: digest_hex(0xcc, 48),
        }],
    );
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_measurement_digest");
}

#[test]
fn enrichment_validate_non_hex_characters_in_digest_rejected() {
    let mut policy = sample_policy(1);
    let mut bad = digest_hex(0xaa, 48);
    bad.replace_range(0..2, "zz"); // 'z' is not hex
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: bad,
        }],
    );
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_measurement_digest");
}

#[test]
fn enrichment_validate_uppercase_hex_canonicalized_and_accepted() {
    let mut policy = sample_policy(1);
    let upper = digest_hex(0xab, 48).to_ascii_uppercase();
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: upper,
        }],
    );
    // from_json / validate canonicalizes to lowercase
    let json = policy.to_canonical_json().unwrap();
    let reparsed = TeeAttestationPolicy::from_json(&json).expect("should canonicalize and pass");
    let sgx_measurements = reparsed
        .approved_measurements
        .get(&TeePlatform::IntelSgx)
        .unwrap();
    assert!(sgx_measurements[0].digest_hex.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
}

#[test]
fn enrichment_validate_multiple_measurements_same_platform_accepted() {
    let mut policy = sample_policy(1);
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![
            MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x11, 48),
            },
            MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0xaa, 48),
            },
            MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0xbb, 32),
            },
        ],
    );
    policy.validate().expect("multiple different measurements should pass");
}

#[test]
fn enrichment_validate_duplicate_measurement_same_algo_rejected() {
    let mut policy = sample_policy(1);
    let dup_digest = digest_hex(0x11, 48);
    policy.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![
            MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: dup_digest.clone(),
            },
            MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: dup_digest,
            },
        ],
    );
    // canonicalize_in_place deduplicates, so from_json + validate may pass.
    // But direct validate without canonicalize should detect duplicates.
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_duplicate_measurement_digest");
}

#[test]
fn enrichment_validate_missing_measurements_for_one_platform() {
    let mut policy = sample_policy(1);
    policy.approved_measurements.remove(&TeePlatform::ArmCca);
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_missing_measurements");
}

#[test]
fn enrichment_validate_empty_measurements_vec_for_platform_rejected() {
    let mut policy = sample_policy(1);
    policy
        .approved_measurements
        .insert(TeePlatform::AmdSev, vec![]);
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_missing_measurements");
}

#[test]
fn enrichment_validate_freshness_window_zero_standard_rejected() {
    let mut policy = sample_policy(1);
    policy.freshness_window.standard_max_age_secs = 0;
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_freshness_window");
}

#[test]
fn enrichment_validate_freshness_window_zero_high_impact_rejected() {
    let mut policy = sample_policy(1);
    policy.freshness_window.high_impact_max_age_secs = 0;
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_freshness_window");
}

#[test]
fn enrichment_validate_freshness_high_impact_greater_than_standard_rejected() {
    let mut policy = sample_policy(1);
    policy.freshness_window.standard_max_age_secs = 100;
    policy.freshness_window.high_impact_max_age_secs = 200;
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_freshness_window");
}

#[test]
fn enrichment_validate_freshness_equal_windows_accepted() {
    let mut policy = sample_policy(1);
    policy.freshness_window.standard_max_age_secs = 120;
    policy.freshness_window.high_impact_max_age_secs = 120;
    policy.validate().expect("equal freshness windows should pass");
}

#[test]
fn enrichment_validate_whitespace_only_source_id_rejected() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].source_id = "   ".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_revocation_source");
}

#[test]
fn enrichment_validate_whitespace_only_endpoint_rejected() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].endpoint = " \t ".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_revocation_source");
}

#[test]
fn enrichment_validate_whitespace_only_root_id_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].root_id = "  ".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn enrichment_validate_whitespace_only_pem_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].trust_anchor_pem = " \n ".to_string();
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn enrichment_validate_trust_root_valid_from_equals_valid_until_accepted() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_from_epoch = SecurityEpoch::from_raw(5);
    policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(5));
    // Still need pinned root active at policy epoch 1, so set policy_epoch = 5
    policy.policy_epoch = SecurityEpoch::from_raw(5);
    policy.validate().expect("from == until should be valid");
}

#[test]
fn enrichment_validate_rotating_root_whitespace_group_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].pinning = TrustRootPinning::Rotating {
        rotation_group: "   ".to_string(),
    };
    policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(100));
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn enrichment_validate_temporary_override_empty_override_id_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots.push(PlatformTrustRoot {
        root_id: "sgx-temp-x".to_string(),
        platform: TeePlatform::IntelSgx,
        trust_anchor_pem: "cert-data".to_string(),
        valid_from_epoch: SecurityEpoch::from_raw(0),
        valid_until_epoch: Some(SecurityEpoch::from_raw(10)),
        pinning: TrustRootPinning::Pinned,
        source: TrustRootSource::TemporaryOverride {
            override_id: "".to_string(),
            justification_artifact_id: "art-1".to_string(),
        },
    });
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

#[test]
fn enrichment_validate_temporary_override_empty_artifact_id_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots.push(PlatformTrustRoot {
        root_id: "sgx-temp-y".to_string(),
        platform: TeePlatform::IntelSgx,
        trust_anchor_pem: "cert-data".to_string(),
        valid_from_epoch: SecurityEpoch::from_raw(0),
        valid_until_epoch: Some(SecurityEpoch::from_raw(10)),
        pinning: TrustRootPinning::Pinned,
        source: TrustRootSource::TemporaryOverride {
            override_id: "ovr-2".to_string(),
            justification_artifact_id: "".to_string(),
        },
    });
    let err = policy.validate().expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
}

// ---------------------------------------------------------------------------
// Quote evaluation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_quote_at_exact_standard_freshness_boundary_accepted() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 300; // exactly at the 300s limit
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect("boundary value should pass");
}

#[test]
fn enrichment_evaluate_quote_at_exact_high_impact_freshness_boundary_accepted() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 60; // exactly at the 60s limit
    policy
        .evaluate_quote(&quote, DecisionImpact::HighImpact, SecurityEpoch::from_raw(1))
        .expect("boundary value should pass");
}

#[test]
fn enrichment_evaluate_quote_one_second_over_standard_limit_rejected() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 301;
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_attestation_stale");
}

#[test]
fn enrichment_evaluate_quote_one_second_over_high_impact_limit_rejected() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 61;
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::HighImpact, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_attestation_stale");
}

#[test]
fn enrichment_evaluate_quote_zero_age_accepted() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = 0;
    policy
        .evaluate_quote(&quote, DecisionImpact::HighImpact, SecurityEpoch::from_raw(1))
        .expect("zero age should pass");
}

#[test]
fn enrichment_evaluate_quote_for_amd_sev_platform() {
    let policy = sample_policy(1);
    let mut rev = BTreeMap::new();
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
    let quote = AttestationQuote {
        platform: TeePlatform::AmdSev,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x33, 48),
        },
        quote_age_secs: 10,
        trust_root_id: "sev-root-a".to_string(),
        revocation_observations: rev,
    };
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect("AMD SEV quote should pass");
}

#[test]
fn enrichment_evaluate_quote_for_arm_trustzone_platform() {
    let policy = sample_policy(1);
    let mut rev = BTreeMap::new();
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
    let quote = AttestationQuote {
        platform: TeePlatform::ArmTrustZone,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x22, 32),
        },
        quote_age_secs: 5,
        trust_root_id: "tz-root-a".to_string(),
        revocation_observations: rev,
    };
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect("ARM TrustZone quote should pass");
}

#[test]
fn enrichment_evaluate_quote_for_arm_cca_platform() {
    let policy = sample_policy(1);
    let mut rev = BTreeMap::new();
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
    let quote = AttestationQuote {
        platform: TeePlatform::ArmCca,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x44, 32),
        },
        quote_age_secs: 15,
        trust_root_id: "cca-root-a".to_string(),
        revocation_observations: rev,
    };
    policy
        .evaluate_quote(&quote, DecisionImpact::HighImpact, SecurityEpoch::from_raw(1))
        .expect("ARM CCA quote should pass");
}

#[test]
fn enrichment_evaluate_quote_wrong_algorithm_for_platform_rejected() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    // SGX has sha384 approved; try sha256 with same byte
    quote.measurement = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha256,
        digest_hex: digest_hex(0x11, 32),
    };
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("wrong algorithm should fail");
    assert_eq!(err.error_code(), "tee_policy_measurement_not_approved");
}

#[test]
fn enrichment_evaluate_quote_trust_root_not_yet_active_rejected() {
    let mut policy = sample_policy(10);
    // Make SGX root valid only from epoch 20
    for root in &mut policy.platform_trust_roots {
        if root.platform == TeePlatform::IntelSgx {
            root.valid_from_epoch = SecurityEpoch::from_raw(0);
            // Keep it pinned and active at policy_epoch for validation
        }
    }
    // Add a second SGX root that starts at epoch 20
    policy.platform_trust_roots.push(PlatformTrustRoot {
        root_id: "sgx-root-future".to_string(),
        platform: TeePlatform::IntelSgx,
        trust_anchor_pem: "-----BEGIN CERT-----SGX-FUTURE".to_string(),
        valid_from_epoch: SecurityEpoch::from_raw(20),
        valid_until_epoch: None,
        pinning: TrustRootPinning::Pinned,
        source: TrustRootSource::Policy,
    });
    let mut quote = sgx_quote();
    quote.trust_root_id = "sgx-root-future".to_string();
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(10))
        .expect_err("future root should fail");
    assert_eq!(err.error_code(), "tee_policy_expired_trust_root");
}

#[test]
fn enrichment_evaluate_quote_trust_root_exactly_at_expiry_epoch_accepted() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(5));
    let quote = sgx_quote();
    // Runtime epoch exactly equals valid_until — should be in range
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(5))
        .expect("at exact expiry epoch should pass (inclusive)");
}

#[test]
fn enrichment_evaluate_quote_revocation_first_source_revoked_stops_chain() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    // First source revoked
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Revoked);
    // Even though internal_ledger is Good, revocation takes priority
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_revoked");
}

#[test]
fn enrichment_evaluate_quote_middle_source_revoked_stops_chain() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    quote.revocation_observations.insert(
        "manufacturer_crl".to_string(),
        RevocationProbeStatus::Revoked,
    );
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_revoked");
}

#[test]
fn enrichment_evaluate_quote_all_sources_good() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    quote
        .revocation_observations
        .insert("manufacturer_crl".to_string(), RevocationProbeStatus::Good);
    quote
        .revocation_observations
        .insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect("all good sources should pass");
}

#[test]
fn enrichment_evaluate_quote_no_revocation_observations_fail_closed_source_fails() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.revocation_observations.clear();
    // internal_ledger is fail-closed and will be Unavailable by default
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail with fail-closed source unavailable");
    assert_eq!(err.error_code(), "tee_policy_revocation_source_unavailable");
}

#[test]
fn enrichment_evaluate_quote_try_next_sources_unavailable_failclosed_good_passes() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    // intel_pcs and manufacturer_crl unavailable (TryNextSource), internal_ledger Good
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    quote.revocation_observations.insert(
        "manufacturer_crl".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    quote
        .revocation_observations
        .insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect("fallback chain should reach good source");
}

// ---------------------------------------------------------------------------
// Policy JSON parsing edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_from_json_empty_string_rejected() {
    let err = TeeAttestationPolicy::from_json("").expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

#[test]
fn enrichment_from_json_null_literal_rejected() {
    let err = TeeAttestationPolicy::from_json("null").expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

#[test]
fn enrichment_from_json_array_rejected() {
    let err = TeeAttestationPolicy::from_json("[]").expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

#[test]
fn enrichment_from_json_invalid_json_rejected() {
    let err = TeeAttestationPolicy::from_json("{not: json}").expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

#[test]
fn enrichment_canonical_json_roundtrip_deterministic() {
    let policy = sample_policy(5);
    let json1 = policy.to_canonical_json().unwrap();
    let json2 = policy.to_canonical_json().unwrap();
    assert_eq!(json1, json2, "canonical JSON must be deterministic");
}

#[test]
fn enrichment_canonical_json_roundtrip_preserves_policy() {
    let policy = sample_policy(5);
    let json = policy.to_canonical_json().unwrap();
    let reparsed = TeeAttestationPolicy::from_json(&json).unwrap();
    assert_eq!(policy.schema_version, reparsed.schema_version);
    assert_eq!(policy.policy_epoch, reparsed.policy_epoch);
    assert_eq!(
        policy.freshness_window.standard_max_age_secs,
        reparsed.freshness_window.standard_max_age_secs
    );
    assert_eq!(
        policy.freshness_window.high_impact_max_age_secs,
        reparsed.freshness_window.high_impact_max_age_secs
    );
}

#[test]
fn enrichment_derive_policy_id_deterministic() {
    let policy = sample_policy(5);
    let id1 = policy.derive_policy_id().unwrap();
    let id2 = policy.derive_policy_id().unwrap();
    assert_eq!(id1, id2, "policy ID must be deterministic");
}

#[test]
fn enrichment_derive_policy_id_differs_for_different_epochs() {
    let p1 = sample_policy(1);
    let p2 = sample_policy(2);
    let id1 = p1.derive_policy_id().unwrap();
    let id2 = p2.derive_policy_id().unwrap();
    assert_ne!(id1, id2, "different epochs should produce different IDs");
}

// ---------------------------------------------------------------------------
// Store lifecycle edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_store_load_policy_records_governance_event() {
    let store = loaded_store(5);
    let events = store.governance_ledger();
    assert!(!events.is_empty());
    let load_event = events.last().unwrap();
    assert_eq!(load_event.event, "policy_loaded");
    assert_eq!(load_event.outcome, "allow");
    assert_eq!(load_event.error_code, "ok");
    assert_eq!(load_event.component, "tee_attestation_policy");
    assert!(load_event.metadata.contains_key("policy_epoch"));
    assert!(load_event.metadata.contains_key("schema_version"));
}

#[test]
fn enrichment_store_epoch_regression_halts_and_records_event() {
    let mut store = loaded_store(10);
    let _err = store
        .load_policy(sample_policy(5), "trace-reg2", "decision-reg2")
        .expect_err("must fail");
    assert!(store.receipt_emission_halted());
    let events = store.governance_ledger();
    let last = events.last().unwrap();
    assert_eq!(last.event, "policy_load_failed");
    assert_eq!(last.outcome, "deny");
    assert_eq!(last.error_code, "tee_policy_epoch_regression");
}

#[test]
fn enrichment_store_load_json_records_failure_event_with_metadata() {
    let mut store = TeeAttestationPolicyStore::default();
    let _err = store.load_policy_json("{invalid", "trace-bad2", "decision-bad2");
    let events = store.governance_ledger();
    let last = events.last().unwrap();
    assert_eq!(last.event, "policy_load_failed");
    assert_eq!(last.trace_id, "trace-bad2");
    assert_eq!(last.decision_id, "decision-bad2");
    assert!(last.metadata.contains_key("reason"));
}

#[test]
fn enrichment_store_successive_loads_each_append_event() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(1), "t1", "d1")
        .expect("load 1");
    store
        .load_policy(sample_policy(2), "t2", "d2")
        .expect("load 2");
    store
        .load_policy(sample_policy(3), "t3", "d3")
        .expect("load 3");
    assert!(store.governance_ledger().len() >= 3);
    // Each event should have a different trace_id
    let trace_ids: Vec<&str> = store
        .governance_ledger()
        .iter()
        .map(|e| e.trace_id.as_str())
        .collect();
    assert!(trace_ids.contains(&"t1"));
    assert!(trace_ids.contains(&"t2"));
    assert!(trace_ids.contains(&"t3"));
}

#[test]
fn enrichment_store_evaluate_quote_events_contain_platform_metadata() {
    let mut store = loaded_store(5);
    let quote = sgx_quote();
    store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "trace-meta",
            "decision-meta",
        )
        .unwrap();
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.metadata.get("platform").unwrap(), "intel_sgx");
    assert_eq!(last.metadata.get("trust_root_id").unwrap(), "sgx-root-a");
}

#[test]
fn enrichment_store_evaluate_rejected_event_has_reason_metadata() {
    let mut store = loaded_store(5);
    let mut quote = sgx_quote();
    quote.measurement.digest_hex = digest_hex(0xff, 48);
    let _err = store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "trace-reason",
            "decision-reason",
        )
        .expect_err("must fail");
    let last = store.governance_ledger().last().unwrap();
    assert!(last.metadata.contains_key("reason"));
    assert!(last.metadata.get("reason").unwrap().contains("not approved"));
}

#[test]
fn enrichment_store_halted_evaluate_records_event() {
    let mut store = TeeAttestationPolicyStore::default();
    let quote = sgx_quote();
    let _err = store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "trace-halted",
            "decision-halted",
        )
        .expect_err("must fail");
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "quote_evaluation_failed");
    assert_eq!(last.outcome, "deny");
    assert_eq!(last.policy_id, "policy-unavailable");
}

// ---------------------------------------------------------------------------
// Override artifact edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_override_artifact_empty_target_root_id_rejected() {
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk(),
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
    )
    .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_artifact_invalid");
}

#[test]
fn enrichment_override_artifact_whitespace_actor_rejected() {
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk(),
        TrustRootOverrideArtifactInput {
            actor: "   ".to_string(),
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
fn enrichment_override_artifact_whitespace_justification_rejected() {
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk(),
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "  \t  ".to_string(),
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
fn enrichment_override_artifact_same_epoch_issued_and_expires_rejected() {
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk(),
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(5),
            expires_epoch: SecurityEpoch::from_raw(5), // same as issued
        },
    )
    .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_artifact_invalid");
}

#[test]
fn enrichment_override_artifact_evidence_refs_deduplicated_and_sorted() {
    let signer = sk();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "incident".to_string(),
            evidence_refs: vec![
                "ref-c".to_string(),
                "ref-a".to_string(),
                "ref-b".to_string(),
                "ref-a".to_string(), // duplicate
            ],
            target_platform: TeePlatform::AmdSev,
            target_root_id: "sev-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(10),
        },
    )
    .expect("create");
    assert_eq!(artifact.evidence_refs, vec!["ref-a", "ref-b", "ref-c"]);
}

#[test]
fn enrichment_override_artifact_empty_evidence_refs_accepted() {
    let signer = sk();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "emergency".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
    )
    .expect("empty evidence_refs should be ok");
    assert!(artifact.evidence_refs.is_empty());
}

#[test]
fn enrichment_override_artifact_id_nonempty_and_deterministic() {
    let signer = sk();
    let input = TrustRootOverrideArtifactInput {
        actor: "op".to_string(),
        justification: "test".to_string(),
        evidence_refs: vec!["ref-1".to_string()],
        target_platform: TeePlatform::IntelSgx,
        target_root_id: "sgx-temp".to_string(),
        issued_epoch: SecurityEpoch::from_raw(1),
        expires_epoch: SecurityEpoch::from_raw(5),
    };
    let a1 = SignedTrustRootOverrideArtifact::create_signed(&signer, input.clone()).unwrap();
    let a2 = SignedTrustRootOverrideArtifact::create_signed(&signer, input).unwrap();
    assert!(!a1.artifact_id.is_empty());
    assert_eq!(a1.artifact_id, a2.artifact_id);
}

#[test]
fn enrichment_override_verify_at_exact_expiry_epoch_rejected() {
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
    .unwrap();
    // current_epoch == expires_epoch: should be rejected (>= check)
    let err = artifact
        .verify(&verifier, SecurityEpoch::from_raw(5))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_expired");
}

#[test]
fn enrichment_override_verify_one_epoch_before_expiry_accepted() {
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
    .unwrap();
    artifact
        .verify(&verifier, SecurityEpoch::from_raw(4))
        .expect("one before expiry should pass");
}

#[test]
fn enrichment_override_verify_tampered_actor_rejected() {
    let signer = sk();
    let verifier = signer.verification_key();
    let mut artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "operator-1".to_string(),
            justification: "legit reason".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(10),
        },
    )
    .unwrap();
    artifact.actor = "attacker".to_string();
    let err = artifact
        .verify(&verifier, SecurityEpoch::from_raw(5))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_signature_invalid");
}

#[test]
fn enrichment_override_verify_tampered_target_root_id_rejected() {
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
    .unwrap();
    artifact.target_root_id = "sgx-malicious".to_string();
    let err = artifact
        .verify(&verifier, SecurityEpoch::from_raw(5))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_signature_invalid");
}

#[test]
fn enrichment_override_verify_wrong_key_rejected() {
    let signer = sk();
    let wrong_signer = SigningKey::from_bytes([99u8; 32]);
    let wrong_verifier = wrong_signer.verification_key();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(10),
        },
    )
    .unwrap();
    let err = artifact
        .verify(&wrong_verifier, SecurityEpoch::from_raw(5))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_signature_invalid");
}

// ---------------------------------------------------------------------------
// Store temporary trust-root override edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_store_override_empty_override_id_rejected() {
    let mut store = loaded_store(10);
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
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(15),
        },
    )
    .unwrap();
    let request = TemporaryTrustRootOverride {
        override_id: "".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp".to_string(),
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
            "t",
            "d",
        )
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_override_artifact_invalid");
}

#[test]
fn enrichment_store_override_records_governance_event() {
    let mut store = loaded_store(10);
    let signer = sk();
    let verifier = signer.verification_key();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "incident response".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-temp-gov".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(15),
        },
    )
    .unwrap();
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-gov".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp-gov".to_string(),
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
    store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(10),
            "trace-gov",
            "decision-gov",
        )
        .unwrap();
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "temporary_trust_root_override_applied");
    assert_eq!(last.outcome, "allow");
    assert!(last.metadata.contains_key("override_id"));
    assert!(last.metadata.contains_key("justification_artifact_id"));
}

#[test]
fn enrichment_store_override_caps_expiry_to_artifact() {
    let mut store = loaded_store(10);
    let signer = sk();
    let verifier = signer.verification_key();
    // Artifact expires at epoch 12, trust root says epoch 20
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "capped test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-capped".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(12),
        },
    )
    .unwrap();
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-cap".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-capped".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "cert".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(20)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "grp".to_string(),
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
            "t",
            "d",
        )
        .unwrap();
    let root = store
        .active_policy()
        .unwrap()
        .platform_trust_roots
        .iter()
        .find(|r| r.root_id == "sgx-capped")
        .unwrap();
    assert_eq!(root.valid_until_epoch, Some(SecurityEpoch::from_raw(12)));
}

#[test]
fn enrichment_store_override_replaces_existing_root_with_same_id() {
    let mut store = loaded_store(10);
    let signer = sk();
    let verifier = signer.verification_key();
    // First override
    let artifact1 = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "first override".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-replace-test".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(15),
        },
    )
    .unwrap();
    let request1 = TemporaryTrustRootOverride {
        override_id: "ovr-r1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-replace-test".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "cert-v1".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(15)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "grp".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact: artifact1,
    };
    store
        .apply_temporary_trust_root_override(
            request1,
            &verifier,
            SecurityEpoch::from_raw(10),
            "t1",
            "d1",
        )
        .unwrap();
    // Second override with same root_id
    let artifact2 = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "second override".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-replace-test".to_string(),
            issued_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(14),
        },
    )
    .unwrap();
    let request2 = TemporaryTrustRootOverride {
        override_id: "ovr-r2".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-replace-test".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "cert-v2".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(14)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "grp".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact: artifact2,
    };
    store
        .apply_temporary_trust_root_override(
            request2,
            &verifier,
            SecurityEpoch::from_raw(10),
            "t2",
            "d2",
        )
        .unwrap();
    // Should have replaced, not duplicated
    let count = store
        .active_policy()
        .unwrap()
        .platform_trust_roots
        .iter()
        .filter(|r| r.root_id == "sgx-replace-test")
        .count();
    assert_eq!(count, 1, "duplicate root should be replaced");
    let root = store
        .active_policy()
        .unwrap()
        .platform_trust_roots
        .iter()
        .find(|r| r.root_id == "sgx-replace-test")
        .unwrap();
    assert_eq!(root.trust_anchor_pem, "cert-v2");
}

// ---------------------------------------------------------------------------
// Emitter edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_emitter_sync_updates_epoch_on_policy_advance() {
    let mut store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("em-adv");
    emitter.sync_policy(&store).unwrap();
    assert_eq!(
        emitter.last_synced_policy_epoch,
        Some(SecurityEpoch::from_raw(5))
    );
    store
        .load_policy(sample_policy(10), "t", "d")
        .unwrap();
    emitter.sync_policy(&store).unwrap();
    assert_eq!(
        emitter.last_synced_policy_epoch,
        Some(SecurityEpoch::from_raw(10))
    );
}

#[test]
fn enrichment_emitter_can_emit_at_synced_epoch_passes() {
    let store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("em-eq");
    emitter.sync_policy(&store).unwrap();
    emitter
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .expect("synced epoch == runtime epoch should pass");
}

#[test]
fn enrichment_emitter_can_emit_at_zero_runtime_with_zero_policy() {
    let store = loaded_store(0);
    let mut emitter = DecisionReceiptEmitter::new("em-zero");
    emitter.sync_policy(&store).unwrap();
    emitter
        .can_emit(SecurityEpoch::from_raw(0), &store)
        .expect("epoch 0 should pass");
}

#[test]
fn enrichment_emitter_stale_after_policy_advances_two() {
    let mut store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("em-stale2");
    emitter.sync_policy(&store).unwrap();
    store
        .load_policy(sample_policy(8), "t", "d")
        .unwrap();
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(8), &store)
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_emitter_stale");
}

#[test]
fn enrichment_emitter_can_emit_one_behind_active_epoch() {
    let mut store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("em-one-behind");
    emitter.sync_policy(&store).unwrap();
    store
        .load_policy(sample_policy(6), "t", "d")
        .unwrap();
    // Synced at 5, active is 6 — one behind is ok
    emitter
        .can_emit(SecurityEpoch::from_raw(6), &store)
        .expect("one epoch behind should pass");
}

#[test]
fn enrichment_emitter_multiple_instances_independent() {
    let store = loaded_store(5);
    let mut em1 = DecisionReceiptEmitter::new("em-ind-1");
    let em2 = DecisionReceiptEmitter::new("em-ind-2");
    em1.sync_policy(&store).unwrap();
    // em1 is synced, em2 is not
    em1.can_emit(SecurityEpoch::from_raw(5), &store)
        .expect("em1 synced should pass");
    let err = em2
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .expect_err("em2 not synced must fail");
    assert_eq!(err.error_code(), "tee_policy_emitter_not_synced");
}

// ---------------------------------------------------------------------------
// Error variant coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_code_prefix_consistent_for_all_variants() {
    let codes = vec![
        TeeAttestationPolicyError::ParseFailed { detail: "x".into() },
        TeeAttestationPolicyError::SerializationFailed { detail: "x".into() },
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx,
        },
        TeeAttestationPolicyError::InvalidMeasurementDigest {
            platform: TeePlatform::IntelSgx,
            digest: "x".into(),
            expected_hex_len: 64,
        },
        TeeAttestationPolicyError::EmptyRevocationSources,
        TeeAttestationPolicyError::MissingTrustRoots,
        TeeAttestationPolicyError::ReceiptEmissionHalted,
        TeeAttestationPolicyError::NoActivePolicy,
        TeeAttestationPolicyError::RevocationEvidenceUnavailable,
        TeeAttestationPolicyError::RevocationFallbackBypass,
        TeeAttestationPolicyError::OverrideJustificationMissing,
    ];
    for err in &codes {
        assert!(
            err.error_code().starts_with("tee_policy_"),
            "error code '{}' missing prefix",
            err.error_code()
        );
    }
}

#[test]
fn enrichment_error_display_contains_useful_context() {
    let err = TeeAttestationPolicyError::AttestationStale {
        quote_age_secs: 500,
        max_age_secs: 300,
    };
    let display = err.to_string();
    assert!(display.contains("500"), "should contain quote_age_secs");
    assert!(display.contains("300"), "should contain max_age_secs");
}

#[test]
fn enrichment_error_display_expired_trust_root_contains_root_id() {
    let err = TeeAttestationPolicyError::ExpiredTrustRoot {
        root_id: "test-root-42".to_string(),
        runtime_epoch: SecurityEpoch::from_raw(10),
        valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
    };
    let display = err.to_string();
    assert!(display.contains("test-root-42"));
}

#[test]
fn enrichment_error_display_override_target_mismatch_shows_both_sides() {
    let err = TeeAttestationPolicyError::OverrideTargetMismatch {
        expected_platform: TeePlatform::IntelSgx,
        expected_root_id: "expected-root".to_string(),
        actual_platform: TeePlatform::AmdSev,
        actual_root_id: "actual-root".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("expected-root"));
    assert!(display.contains("actual-root"));
}

#[test]
fn enrichment_error_display_emitter_stale_shows_epochs() {
    let err = TeeAttestationPolicyError::EmitterPolicyStale {
        emitter_id: "em-42".to_string(),
        synced_epoch: SecurityEpoch::from_raw(3),
        required_epoch: SecurityEpoch::from_raw(7),
    };
    let display = err.to_string();
    assert!(display.contains("em-42"));
}

// ---------------------------------------------------------------------------
// Serde round-trip edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_revocation_source_type_other_roundtrip() {
    let src = RevocationSourceType::Other("custom-oracle".to_string());
    let json = serde_json::to_string(&src).unwrap();
    let back: RevocationSourceType = serde_json::from_str(&json).unwrap();
    assert_eq!(src, back);
}

#[test]
fn enrichment_serde_trust_root_pinning_rotating_roundtrip() {
    let pin = TrustRootPinning::Rotating {
        rotation_group: "group-alpha".to_string(),
    };
    let json = serde_json::to_string(&pin).unwrap();
    let back: TrustRootPinning = serde_json::from_str(&json).unwrap();
    assert_eq!(pin, back);
}

#[test]
fn enrichment_serde_trust_root_pinning_pinned_roundtrip() {
    let pin = TrustRootPinning::Pinned;
    let json = serde_json::to_string(&pin).unwrap();
    let back: TrustRootPinning = serde_json::from_str(&json).unwrap();
    assert_eq!(pin, back);
}

#[test]
fn enrichment_serde_trust_root_source_temporary_override_roundtrip() {
    let src = TrustRootSource::TemporaryOverride {
        override_id: "ovr-1".to_string(),
        justification_artifact_id: "art-1".to_string(),
    };
    let json = serde_json::to_string(&src).unwrap();
    let back: TrustRootSource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, back);
}

#[test]
fn enrichment_serde_revocation_probe_status_roundtrip() {
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
fn enrichment_serde_attestation_quote_roundtrip() {
    let quote = sgx_quote();
    let json = serde_json::to_string(&quote).unwrap();
    let back: AttestationQuote = serde_json::from_str(&json).unwrap();
    assert_eq!(quote, back);
}

#[test]
fn enrichment_serde_governance_event_has_all_fields() {
    let store = loaded_store(5);
    let event = &store.governance_ledger()[0];
    let json = serde_json::to_string(event).unwrap();
    let back: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(back.get("trace_id").is_some());
    assert!(back.get("decision_id").is_some());
    assert!(back.get("policy_id").is_some());
    assert!(back.get("component").is_some());
    assert!(back.get("event").is_some());
    assert!(back.get("outcome").is_some());
    assert!(back.get("error_code").is_some());
    assert!(back.get("metadata").is_some());
}

#[test]
fn enrichment_serde_policy_store_roundtrip() {
    let store = loaded_store(5);
    let json = serde_json::to_string(&store).unwrap();
    let back: TeeAttestationPolicyStore = serde_json::from_str(&json).unwrap();
    assert_eq!(store.receipt_emission_halted(), back.receipt_emission_halted());
    assert_eq!(store.last_error_code(), back.last_error_code());
    assert_eq!(
        store.active_policy().unwrap().policy_epoch,
        back.active_policy().unwrap().policy_epoch
    );
}

// ---------------------------------------------------------------------------
// Policy composition and conflict resolution
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_canonicalize_trims_root_id_whitespace() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].root_id = "  sgx-root-a  ".to_string();
    let json = policy.to_canonical_json().unwrap();
    let reparsed = TeeAttestationPolicy::from_json(&json).unwrap();
    let sgx_root = reparsed
        .platform_trust_roots
        .iter()
        .find(|r| r.platform == TeePlatform::IntelSgx && r.root_id == "sgx-root-a")
        .expect("trimmed root should exist");
    assert_eq!(sgx_root.root_id, "sgx-root-a");
}

#[test]
fn enrichment_policy_canonicalize_sorts_trust_roots_by_platform_then_id() {
    let mut policy = sample_policy(1);
    // Reverse the order
    policy.platform_trust_roots.reverse();
    let json = policy.to_canonical_json().unwrap();
    let reparsed = TeeAttestationPolicy::from_json(&json).unwrap();
    // Check they are sorted: AmdSev < ArmCca < ArmTrustZone < IntelSgx (by variant order)
    let platforms: Vec<TeePlatform> = reparsed
        .platform_trust_roots
        .iter()
        .map(|r| r.platform)
        .collect();
    for window in platforms.windows(2) {
        assert!(window[0] <= window[1], "trust roots should be sorted by platform");
    }
}

#[test]
fn enrichment_store_policy_reload_with_different_measurements_changes_active() {
    let mut store = loaded_store(5);
    let mut policy2 = sample_policy(6);
    // Change SGX measurement
    policy2.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0xee, 48),
        }],
    );
    store
        .load_policy(policy2, "t-new", "d-new")
        .unwrap();
    // Old SGX quote should now fail
    let quote = sgx_quote(); // uses 0x11 digest
    let err = store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(6),
            "t-fail",
            "d-fail",
        )
        .expect_err("old measurement should be rejected");
    assert_eq!(err.error_code(), "tee_policy_measurement_not_approved");
}

#[test]
fn enrichment_store_policy_reload_with_new_freshness_enforced() {
    let mut store = loaded_store(5);
    let mut policy2 = sample_policy(6);
    policy2.freshness_window.standard_max_age_secs = 100;
    policy2.freshness_window.high_impact_max_age_secs = 30;
    store
        .load_policy(policy2, "t", "d")
        .unwrap();
    let mut quote = sgx_quote();
    quote.quote_age_secs = 150; // was OK with 300, now exceeds 100
    let err = store
        .evaluate_quote(
            &quote,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(6),
            "t2",
            "d2",
        )
        .expect_err("tighter freshness should reject");
    assert_eq!(err.error_code(), "tee_policy_attestation_stale");
}

#[test]
fn enrichment_store_policy_load_then_fail_then_reload_recovers() {
    let mut store = loaded_store(5);
    assert!(!store.receipt_emission_halted());
    // Force a halt via epoch regression
    let _err = store.load_policy(sample_policy(3), "t-reg", "d-reg");
    assert!(store.receipt_emission_halted());
    // Now load with epoch >= current
    store
        .load_policy(sample_policy(10), "t-recover", "d-recover")
        .unwrap();
    assert!(!store.receipt_emission_halted());
    assert!(store.last_error_code().is_none());
}

#[test]
fn enrichment_tee_platform_ord_consistent_with_all_array() {
    // Verify that TeePlatform::ALL is in order
    let all = TeePlatform::ALL;
    for window in all.windows(2) {
        assert!(window[0] < window[1], "ALL array should be in Ord order");
    }
}

#[test]
fn enrichment_revocation_fallback_serde_roundtrip() {
    for fb in [RevocationFallback::TryNextSource, RevocationFallback::FailClosed] {
        let json = serde_json::to_string(&fb).unwrap();
        let back: RevocationFallback = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
    }
}

#[test]
fn enrichment_measurement_digest_clone_is_independent() {
    let d1 = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha384,
        digest_hex: digest_hex(0xab, 48),
    };
    let mut d2 = d1.clone();
    d2.digest_hex = digest_hex(0xcd, 48);
    assert_ne!(d1.digest_hex, d2.digest_hex);
}

#[test]
fn enrichment_store_default_governance_ledger_empty() {
    let store = TeeAttestationPolicyStore::default();
    assert!(store.governance_ledger().is_empty());
}

#[test]
fn enrichment_store_default_active_policy_none() {
    let store = TeeAttestationPolicyStore::default();
    assert!(store.active_policy().is_none());
}

#[test]
fn enrichment_evaluate_quote_max_u64_age_rejected() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote();
    quote.quote_age_secs = u64::MAX;
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .expect_err("must fail");
    assert_eq!(err.error_code(), "tee_policy_attestation_stale");
}
