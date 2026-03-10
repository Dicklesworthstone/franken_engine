//! Edge-case integration tests for `tee_attestation_policy` module.

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

// ---------------------------------------------------------------------------
// Helpers (mirror inline test helpers)
// ---------------------------------------------------------------------------

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

fn quote_for_sgx() -> AttestationQuote {
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

fn make_signing_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn make_override_input(root_id: &str, epoch: u64) -> TrustRootOverrideArtifactInput {
    TrustRootOverrideArtifactInput {
        actor: "operator-test".to_string(),
        justification: "incident response override".to_string(),
        evidence_refs: vec!["ev-1".to_string()],
        target_platform: TeePlatform::IntelSgx,
        target_root_id: root_id.to_string(),
        issued_epoch: SecurityEpoch::from_raw(epoch),
        expires_epoch: SecurityEpoch::from_raw(epoch + 5),
    }
}

// =========================================================================
// TeePlatform
// =========================================================================

#[test]
fn tee_platform_copy_semantics() {
    let a = TeePlatform::IntelSgx;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn tee_platform_hash_four_distinct() {
    use std::collections::HashSet;
    let set: HashSet<TeePlatform> = TeePlatform::ALL.into_iter().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn tee_platform_all_constant_length() {
    assert_eq!(TeePlatform::ALL.len(), 4);
}

#[test]
fn tee_platform_display_all_variants() {
    assert_eq!(TeePlatform::IntelSgx.to_string(), "intel_sgx");
    assert_eq!(TeePlatform::ArmTrustZone.to_string(), "arm_trustzone");
    assert_eq!(TeePlatform::ArmCca.to_string(), "arm_cca");
    assert_eq!(TeePlatform::AmdSev.to_string(), "amd_sev");
}

#[test]
fn tee_platform_serde_snake_case_strings() {
    for platform in TeePlatform::ALL {
        let json = serde_json::to_string(&platform).unwrap();
        assert!(json.contains('_') || json == "\"arm_cca\"");
        let parsed: TeePlatform = serde_json::from_str(&json).unwrap();
        assert_eq!(platform, parsed);
    }
}

#[test]
fn tee_platform_ord_is_deterministic() {
    let mut sorted = [
        TeePlatform::AmdSev,
        TeePlatform::ArmCca,
        TeePlatform::IntelSgx,
        TeePlatform::ArmTrustZone,
    ];
    sorted.sort();
    // Ord on enum follows discriminant order
    assert_eq!(sorted[0], TeePlatform::IntelSgx);
    assert_eq!(sorted[3], TeePlatform::AmdSev);
}

// =========================================================================
// MeasurementAlgorithm
// =========================================================================

#[test]
fn measurement_algorithm_copy_semantics() {
    let a = MeasurementAlgorithm::Sha256;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn measurement_algorithm_hash_three_distinct() {
    use std::collections::HashSet;
    let set: HashSet<MeasurementAlgorithm> = [
        MeasurementAlgorithm::Sha256,
        MeasurementAlgorithm::Sha384,
        MeasurementAlgorithm::Sha512,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn measurement_algorithm_display_all() {
    assert_eq!(MeasurementAlgorithm::Sha256.to_string(), "sha256");
    assert_eq!(MeasurementAlgorithm::Sha384.to_string(), "sha384");
    assert_eq!(MeasurementAlgorithm::Sha512.to_string(), "sha512");
}

#[test]
fn measurement_algorithm_serde_stable() {
    let json = serde_json::to_string(&MeasurementAlgorithm::Sha384).unwrap();
    assert_eq!(json, "\"sha384\"");
}

// =========================================================================
// MeasurementDigest
// =========================================================================

#[test]
fn measurement_digest_serde_roundtrip() {
    let d = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha256,
        digest_hex: digest_hex(0xab, 32),
    };
    let json = serde_json::to_string(&d).unwrap();
    let parsed: MeasurementDigest = serde_json::from_str(&json).unwrap();
    assert_eq!(d, parsed);
}

#[test]
fn measurement_digest_clone_independent() {
    let d = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha512,
        digest_hex: digest_hex(0xff, 64),
    };
    let mut d2 = d.clone();
    d2.digest_hex = "changed".to_string();
    assert_ne!(d.digest_hex, d2.digest_hex);
}

#[test]
fn measurement_digest_ord_sorts_by_algorithm_then_hex() {
    let a = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha256,
        digest_hex: digest_hex(0xaa, 32),
    };
    let b = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha256,
        digest_hex: digest_hex(0xbb, 32),
    };
    assert!(a < b);
}

// =========================================================================
// AttestationFreshnessWindow
// =========================================================================

#[test]
fn freshness_window_serde_roundtrip() {
    let w = AttestationFreshnessWindow {
        standard_max_age_secs: 600,
        high_impact_max_age_secs: 120,
    };
    let json = serde_json::to_string(&w).unwrap();
    let parsed: AttestationFreshnessWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(w, parsed);
}

#[test]
fn freshness_window_clone_independent() {
    let w = AttestationFreshnessWindow {
        standard_max_age_secs: 100,
        high_impact_max_age_secs: 50,
    };
    let mut w2 = w.clone();
    w2.standard_max_age_secs = 999;
    assert_ne!(w.standard_max_age_secs, w2.standard_max_age_secs);
}

// =========================================================================
// RevocationSourceType
// =========================================================================

#[test]
fn revocation_source_type_other_preserves_name() {
    let t = RevocationSourceType::Other("custom-checker".to_string());
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("custom-checker"));
    let parsed: RevocationSourceType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, parsed);
}

#[test]
fn revocation_source_type_ord_deterministic() {
    let mut types = [
        RevocationSourceType::Other("zzz".to_string()),
        RevocationSourceType::IntelPcs,
        RevocationSourceType::InternalLedger,
        RevocationSourceType::ManufacturerCrl,
    ];
    types.sort();
    assert_eq!(types[0], RevocationSourceType::IntelPcs);
}

// =========================================================================
// RevocationFallback
// =========================================================================

#[test]
fn revocation_fallback_copy_semantics() {
    let a = RevocationFallback::FailClosed;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn revocation_fallback_serde_stable_strings() {
    let fc = serde_json::to_string(&RevocationFallback::FailClosed).unwrap();
    assert_eq!(fc, "\"fail_closed\"");
    let tn = serde_json::to_string(&RevocationFallback::TryNextSource).unwrap();
    assert_eq!(tn, "\"try_next_source\"");
}

// =========================================================================
// RevocationSource
// =========================================================================

#[test]
fn revocation_source_serde_roundtrip() {
    let s = RevocationSource {
        source_id: "src-1".to_string(),
        source_type: RevocationSourceType::IntelPcs,
        endpoint: "https://example.com/pcs".to_string(),
        on_unavailable: RevocationFallback::FailClosed,
    };
    let json = serde_json::to_string(&s).unwrap();
    let parsed: RevocationSource = serde_json::from_str(&json).unwrap();
    assert_eq!(s, parsed);
}

// =========================================================================
// TrustRootPinning
// =========================================================================

#[test]
fn trust_root_pinning_clone_deep() {
    let p = TrustRootPinning::Rotating {
        rotation_group: "grp-a".to_string(),
    };
    let p2 = p.clone();
    assert_eq!(p, p2);
}

#[test]
fn trust_root_pinning_ord_pinned_before_rotating() {
    let pinned = TrustRootPinning::Pinned;
    let rotating = TrustRootPinning::Rotating {
        rotation_group: "g".to_string(),
    };
    assert!(pinned < rotating);
}

// =========================================================================
// TrustRootSource
// =========================================================================

#[test]
fn trust_root_source_serde_roundtrip_policy() {
    let s = TrustRootSource::Policy;
    let json = serde_json::to_string(&s).unwrap();
    let parsed: TrustRootSource = serde_json::from_str(&json).unwrap();
    assert_eq!(s, parsed);
}

#[test]
fn trust_root_source_serde_roundtrip_temporary() {
    let s = TrustRootSource::TemporaryOverride {
        override_id: "ovr-99".to_string(),
        justification_artifact_id: "art-99".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let parsed: TrustRootSource = serde_json::from_str(&json).unwrap();
    assert_eq!(s, parsed);
}

#[test]
fn trust_root_source_ord_policy_before_override() {
    let policy = TrustRootSource::Policy;
    let temp = TrustRootSource::TemporaryOverride {
        override_id: "a".to_string(),
        justification_artifact_id: "b".to_string(),
    };
    assert!(policy < temp);
}

// =========================================================================
// PlatformTrustRoot
// =========================================================================

#[test]
fn platform_trust_root_serde_roundtrip() {
    let r = PlatformTrustRoot {
        root_id: "root-test".to_string(),
        platform: TeePlatform::ArmCca,
        trust_anchor_pem: "-----BEGIN CERT-----TEST".to_string(),
        valid_from_epoch: SecurityEpoch::from_raw(1),
        valid_until_epoch: Some(SecurityEpoch::from_raw(100)),
        pinning: TrustRootPinning::Pinned,
        source: TrustRootSource::Policy,
    };
    let json = serde_json::to_string(&r).unwrap();
    let parsed: PlatformTrustRoot = serde_json::from_str(&json).unwrap();
    assert_eq!(r, parsed);
}

#[test]
fn platform_trust_root_clone_independent() {
    let r = PlatformTrustRoot {
        root_id: "root-c".to_string(),
        platform: TeePlatform::IntelSgx,
        trust_anchor_pem: "PEM".to_string(),
        valid_from_epoch: SecurityEpoch::from_raw(0),
        valid_until_epoch: None,
        pinning: TrustRootPinning::Pinned,
        source: TrustRootSource::Policy,
    };
    let mut r2 = r.clone();
    r2.root_id = "changed".to_string();
    assert_ne!(r.root_id, r2.root_id);
}

// =========================================================================
// DecisionImpact
// =========================================================================

#[test]
fn decision_impact_copy_semantics() {
    let a = DecisionImpact::HighImpact;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn decision_impact_ord_standard_before_high() {
    assert!(DecisionImpact::Standard < DecisionImpact::HighImpact);
}

#[test]
fn decision_impact_serde_snake_case() {
    let json = serde_json::to_string(&DecisionImpact::HighImpact).unwrap();
    assert_eq!(json, "\"high_impact\"");
}

// =========================================================================
// RevocationProbeStatus
// =========================================================================

#[test]
fn revocation_probe_status_copy_semantics() {
    let a = RevocationProbeStatus::Good;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn revocation_probe_status_serde_snake_case() {
    let json = serde_json::to_string(&RevocationProbeStatus::Unavailable).unwrap();
    assert_eq!(json, "\"unavailable\"");
}

#[test]
fn revocation_probe_status_ord() {
    assert!(RevocationProbeStatus::Good < RevocationProbeStatus::Revoked);
    assert!(RevocationProbeStatus::Revoked < RevocationProbeStatus::Unavailable);
}

// =========================================================================
// AttestationQuote
// =========================================================================

#[test]
fn attestation_quote_serde_roundtrip() {
    let q = quote_for_sgx();
    let json = serde_json::to_string(&q).unwrap();
    let parsed: AttestationQuote = serde_json::from_str(&json).unwrap();
    assert_eq!(q, parsed);
}

#[test]
fn attestation_quote_clone_independent() {
    let q = quote_for_sgx();
    let mut q2 = q.clone();
    q2.quote_age_secs = 9999;
    assert_ne!(q.quote_age_secs, q2.quote_age_secs);
}

// =========================================================================
// PolicyGovernanceEvent
// =========================================================================

#[test]
fn policy_governance_event_serde_roundtrip_with_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key1".to_string(), "val1".to_string());
    metadata.insert("key2".to_string(), "val2".to_string());
    let e = PolicyGovernanceEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "tee_attestation_policy".to_string(),
        event: "policy_loaded".to_string(),
        outcome: "allow".to_string(),
        error_code: "ok".to_string(),
        metadata,
    };
    let json = serde_json::to_string(&e).unwrap();
    let parsed: PolicyGovernanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, parsed);
}

#[test]
fn policy_governance_event_clone_independent() {
    let e = PolicyGovernanceEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: "ec".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut e2 = e.clone();
    e2.event = "changed".to_string();
    assert_ne!(e.event, e2.event);
}

// =========================================================================
// TeeAttestationPolicy — from_json / to_canonical_json
// =========================================================================

#[test]
fn policy_from_json_valid_roundtrip() {
    let p = sample_policy(5);
    let json = p.to_canonical_json().unwrap();
    let parsed = TeeAttestationPolicy::from_json(&json).unwrap();
    assert_eq!(p, parsed);
}

#[test]
fn policy_from_json_bad_json_returns_parse_error() {
    let err = TeeAttestationPolicy::from_json("not json").unwrap_err();
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

#[test]
fn policy_from_json_schema_but_invalid_returns_validation_error() {
    // Create a policy with missing AmdSev measurements, serialize, then parse
    let mut p = sample_policy(1);
    // Manually remove AmdSev measurements by modifying the policy before serializing
    p.approved_measurements.remove(&TeePlatform::AmdSev);
    let bad_json = serde_json::to_string(&p).unwrap();
    let err = TeeAttestationPolicy::from_json(&bad_json).unwrap_err();
    assert_eq!(err.error_code(), "tee_policy_missing_measurements");
}

#[test]
fn policy_to_canonical_json_deterministic() {
    let p = sample_policy(10);
    let json1 = p.to_canonical_json().unwrap();
    let json2 = p.to_canonical_json().unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn policy_canonical_json_lowercases_digests() {
    let mut p = sample_policy(1);
    // Use a byte with alphabetic hex chars so uppercase differs from lowercase
    let lower = digest_hex(0xab, 48);
    let upper = lower.to_uppercase();
    assert_ne!(lower, upper, "test precondition: hex strings must differ");
    p.approved_measurements
        .get_mut(&TeePlatform::IntelSgx)
        .unwrap()[0]
        .digest_hex = upper.clone();
    p.approved_measurements
        .get_mut(&TeePlatform::IntelSgx)
        .unwrap()[0]
        .algorithm = MeasurementAlgorithm::Sha384;
    let json = p.to_canonical_json().unwrap();
    // Canonical form should be lowercase
    assert!(!json.contains(&upper));
    assert!(json.contains(&lower));
}

// =========================================================================
// TeeAttestationPolicy — derive_policy_id
// =========================================================================

#[test]
fn policy_id_deterministic_same_epoch() {
    let p = sample_policy(7);
    let id1 = p.derive_policy_id().unwrap();
    let id2 = p.derive_policy_id().unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn policy_id_differs_across_epochs() {
    let p1 = sample_policy(1);
    let p2 = sample_policy(2);
    assert_ne!(
        p1.derive_policy_id().unwrap(),
        p2.derive_policy_id().unwrap()
    );
}

#[test]
fn policy_id_differs_with_different_schema_version() {
    let p1 = sample_policy(1);
    let mut p2 = sample_policy(1);
    p2.schema_version = 2;
    assert_ne!(
        p1.derive_policy_id().unwrap(),
        p2.derive_policy_id().unwrap()
    );
}

// =========================================================================
// TeeAttestationPolicy — validate edge cases
// =========================================================================

#[test]
fn validate_sample_policy_passes() {
    sample_policy(1).validate().unwrap();
}

#[test]
fn validate_rejects_missing_platform_measurements() {
    let mut p = sample_policy(1);
    p.approved_measurements.remove(&TeePlatform::ArmCca);
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::ArmCca
        }
    ));
}

#[test]
fn validate_rejects_empty_measurement_list_for_platform() {
    let mut p = sample_policy(1);
    p.approved_measurements
        .insert(TeePlatform::IntelSgx, vec![]);
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx
        }
    ));
}

#[test]
fn validate_rejects_duplicate_measurement_digest() {
    let mut p = sample_policy(1);
    let dup = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha384,
        digest_hex: digest_hex(0x11, 48),
    };
    p.approved_measurements
        .insert(TeePlatform::IntelSgx, vec![dup.clone(), dup]);
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::DuplicateMeasurementDigest { .. }
    ));
}

#[test]
fn validate_rejects_invalid_measurement_length() {
    let mut p = sample_policy(1);
    p.approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: "aabb".to_string(), // too short
        }],
    );
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidMeasurementDigest { .. }
    ));
}

#[test]
fn validate_rejects_inverted_freshness_window() {
    let mut p = sample_policy(1);
    p.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 10,
        high_impact_max_age_secs: 20,
    };
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
    ));
}

#[test]
fn validate_accepts_equal_freshness_window() {
    let mut p = sample_policy(1);
    p.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 100,
        high_impact_max_age_secs: 100,
    };
    p.validate().unwrap();
}

#[test]
fn validate_rejects_zero_freshness_high_impact() {
    let mut p = sample_policy(1);
    p.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 300,
        high_impact_max_age_secs: 0,
    };
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
    ));
}

#[test]
fn validate_rejects_empty_revocation_sources() {
    let mut p = sample_policy(1);
    p.revocation_sources.clear();
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmptyRevocationSources
    ));
}

#[test]
fn validate_rejects_no_fail_closed_revocation() {
    let mut p = sample_policy(1);
    for s in &mut p.revocation_sources {
        s.on_unavailable = RevocationFallback::TryNextSource;
    }
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationFallbackBypass
    ));
}

#[test]
fn validate_rejects_duplicate_revocation_source_id() {
    let mut p = sample_policy(1);
    let dup = p.revocation_sources[0].clone();
    p.revocation_sources.push(dup);
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::DuplicateRevocationSource { .. }
    ));
}

#[test]
fn validate_rejects_empty_trust_roots() {
    let mut p = sample_policy(1);
    p.platform_trust_roots.clear();
    let err = p.validate().unwrap_err();
    assert!(matches!(err, TeeAttestationPolicyError::MissingTrustRoots));
}

#[test]
fn validate_rejects_duplicate_trust_root() {
    let mut p = sample_policy(1);
    let dup = p.platform_trust_roots[0].clone();
    p.platform_trust_roots.push(dup);
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::DuplicateTrustRoot { .. }
    ));
}

#[test]
fn validate_rejects_missing_pinned_root_for_platform() {
    let mut p = sample_policy(1);
    // Change SGX root to rotating (needs valid_until_epoch)
    p.platform_trust_roots[0].pinning = TrustRootPinning::Rotating {
        rotation_group: "grp".to_string(),
    };
    p.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(100));
    let err = p.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::IntelSgx
        }
    ));
}

#[test]
fn validate_rejects_pinned_root_not_active_at_policy_epoch() {
    let mut p = sample_policy(10);
    // SGX root only valid from epoch 0 to 5 — not active at epoch 10
    p.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(5));
    let err = p.validate().unwrap_err();
    // Should fail because no pinned root active at policy_epoch=10 for IntelSgx
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::IntelSgx
        }
    ));
}

// =========================================================================
// TeeAttestationPolicy — evaluate_quote edge cases
// =========================================================================

#[test]
fn evaluate_quote_passes_for_valid_sgx() {
    let p = sample_policy(1);
    let q = quote_for_sgx();
    p.evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap();
}

#[test]
fn evaluate_quote_at_exact_standard_max_age_passes() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.quote_age_secs = 300; // exactly standard_max_age_secs
    p.evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap();
}

#[test]
fn evaluate_quote_one_over_standard_max_age_fails() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.quote_age_secs = 301;
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale {
            quote_age_secs: 301,
            max_age_secs: 300,
        }
    ));
}

#[test]
fn evaluate_quote_high_impact_at_exact_boundary_passes() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.quote_age_secs = 60; // exactly high_impact_max_age_secs
    p.evaluate_quote(&q, DecisionImpact::HighImpact, SecurityEpoch::from_raw(1))
        .unwrap();
}

#[test]
fn evaluate_quote_high_impact_one_over_fails() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.quote_age_secs = 61;
    let err = p
        .evaluate_quote(&q, DecisionImpact::HighImpact, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale {
            quote_age_secs: 61,
            max_age_secs: 60,
        }
    ));
}

#[test]
fn evaluate_quote_unknown_measurement_digest() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.measurement.digest_hex = digest_hex(0xff, 48);
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::UnknownMeasurementDigest { .. }
    ));
}

#[test]
fn evaluate_quote_unknown_trust_root_id() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.trust_root_id = "nonexistent".to_string();
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::UnknownTrustRoot { .. }
    ));
}

#[test]
fn evaluate_quote_expired_trust_root() {
    let mut p = sample_policy(1);
    p.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(5));
    let q = quote_for_sgx();
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(6))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ExpiredTrustRoot { .. }
    ));
}

#[test]
fn evaluate_quote_trust_root_at_exact_until_epoch_passes() {
    let mut p = sample_policy(1);
    p.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(5));
    let q = quote_for_sgx();
    // At epoch 5 exactly, root is still active
    p.evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(5))
        .unwrap();
}

#[test]
fn evaluate_quote_revoked_by_source() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Revoked);
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevokedBySource { .. }
    ));
}

#[test]
fn evaluate_quote_fail_closed_source_unavailable() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    // internal_ledger is fail_closed; make it unavailable
    q.revocation_observations.insert(
        "internal_ledger".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
    ));
}

#[test]
fn evaluate_quote_all_sources_unavailable_try_next_reaches_fail_closed() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    // All unavailable — intel_pcs and manufacturer_crl are TryNextSource,
    // internal_ledger is FailClosed
    q.revocation_observations.clear();
    q.revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    q.revocation_observations.insert(
        "manufacturer_crl".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    q.revocation_observations.insert(
        "internal_ledger".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
    ));
}

#[test]
fn evaluate_quote_first_source_good_short_circuits() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    // First source good → immediate success (no need to check others)
    q.revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    p.evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap();
}

#[test]
fn evaluate_quote_no_revocation_observations_uses_unavailable_default() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.revocation_observations.clear();
    // With no observations, all sources default to Unavailable.
    // intel_pcs=TryNext, manufacturer_crl=TryNext, internal_ledger=FailClosed → error
    let err = p
        .evaluate_quote(&q, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
    ));
}

#[test]
fn evaluate_quote_zero_age_passes() {
    let p = sample_policy(1);
    let mut q = quote_for_sgx();
    q.quote_age_secs = 0;
    p.evaluate_quote(&q, DecisionImpact::HighImpact, SecurityEpoch::from_raw(1))
        .unwrap();
}

// =========================================================================
// TeeAttestationPolicy serde roundtrip
// =========================================================================

#[test]
fn policy_serde_full_roundtrip() {
    let p = sample_policy(42);
    let json = serde_json::to_string(&p).unwrap();
    let parsed: TeeAttestationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, parsed);
}

// =========================================================================
// SignedTrustRootOverrideArtifact
// =========================================================================

#[test]
fn override_artifact_create_and_verify_roundtrip() {
    let key = make_signing_key();
    let verifier = key.verification_key();
    let input = make_override_input("root-test", 5);
    let artifact = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap();
    artifact
        .verify(&verifier, SecurityEpoch::from_raw(5))
        .unwrap();
}

#[test]
fn override_artifact_serde_roundtrip() {
    let key = make_signing_key();
    let input = make_override_input("root-serde", 1);
    let artifact = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap();
    let json = serde_json::to_string(&artifact).unwrap();
    let parsed: SignedTrustRootOverrideArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, parsed);
}

#[test]
fn override_artifact_deterministic_id() {
    let key = make_signing_key();
    let input1 = make_override_input("root-det", 3);
    let input2 = make_override_input("root-det", 3);
    let a1 = SignedTrustRootOverrideArtifact::create_signed(&key, input1).unwrap();
    let a2 = SignedTrustRootOverrideArtifact::create_signed(&key, input2).unwrap();
    assert_eq!(a1.artifact_id, a2.artifact_id);
}

#[test]
fn override_artifact_empty_actor_rejected() {
    let key = make_signing_key();
    let mut input = make_override_input("r", 1);
    input.actor = "".to_string();
    let err = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn override_artifact_whitespace_actor_rejected() {
    let key = make_signing_key();
    let mut input = make_override_input("r", 1);
    input.actor = "   ".to_string();
    let err = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn override_artifact_empty_justification_rejected() {
    let key = make_signing_key();
    let mut input = make_override_input("r", 1);
    input.justification = "".to_string();
    let err = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideJustificationMissing
    ));
}

#[test]
fn override_artifact_empty_target_root_id_rejected() {
    let key = make_signing_key();
    let mut input = make_override_input("", 1);
    input.target_root_id = "  ".to_string();
    let err = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn override_artifact_equal_epochs_rejected() {
    let key = make_signing_key();
    let mut input = make_override_input("r", 5);
    input.expires_epoch = SecurityEpoch::from_raw(5);
    let err = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn override_artifact_expires_before_issued_rejected() {
    let key = make_signing_key();
    let mut input = make_override_input("r", 10);
    input.expires_epoch = SecurityEpoch::from_raw(5);
    let err = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn override_artifact_evidence_refs_sorted_and_deduped() {
    let key = make_signing_key();
    let mut input = make_override_input("r", 1);
    input.evidence_refs = vec![
        "c".to_string(),
        "a".to_string(),
        "b".to_string(),
        "a".to_string(),
    ];
    let artifact = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap();
    assert_eq!(artifact.evidence_refs, vec!["a", "b", "c"]);
}

#[test]
fn override_artifact_verify_expired_epoch_rejected() {
    let key = make_signing_key();
    let verifier = key.verification_key();
    let input = make_override_input("r", 1);
    let artifact = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap();
    // expires at epoch 6, verify at epoch 7
    let err = artifact
        .verify(&verifier, SecurityEpoch::from_raw(7))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideExpired { .. }
    ));
}

#[test]
fn override_artifact_verify_at_exact_expiry_passes() {
    let key = make_signing_key();
    let verifier = key.verification_key();
    let input = make_override_input("r", 1);
    let artifact = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap();
    // expires at epoch 6, verify at epoch 6 (at expiry is OK: > not >=)
    artifact
        .verify(&verifier, SecurityEpoch::from_raw(6))
        .unwrap();
}

#[test]
fn override_artifact_tampered_justification_fails_verify() {
    let key = make_signing_key();
    let verifier = key.verification_key();
    let input = make_override_input("r", 1);
    let mut artifact = SignedTrustRootOverrideArtifact::create_signed(&key, input).unwrap();
    artifact.justification = "tampered".to_string();
    let err = artifact
        .verify(&verifier, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideSignatureInvalid { .. }
    ));
}

#[test]
fn override_artifact_wrong_key_fails_verify() {
    let key1 = SigningKey::from_bytes([10u8; 32]);
    let key2 = SigningKey::from_bytes([20u8; 32]);
    let verifier2 = key2.verification_key();
    let input = make_override_input("r", 1);
    let artifact = SignedTrustRootOverrideArtifact::create_signed(&key1, input).unwrap();
    let err = artifact
        .verify(&verifier2, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideSignatureInvalid { .. }
    ));
}

// =========================================================================
// TeeAttestationPolicyStore
// =========================================================================

#[test]
fn store_default_is_halted() {
    let store = TeeAttestationPolicyStore::default();
    assert!(store.receipt_emission_halted());
    assert_eq!(store.last_error_code(), Some("policy_not_loaded"));
    assert!(store.active_policy().is_none());
    assert!(store.governance_ledger().is_empty());
}

#[test]
fn store_load_policy_success_clears_halt() {
    let mut store = TeeAttestationPolicyStore::default();
    let policy_id = store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    assert!(!store.receipt_emission_halted());
    assert!(store.last_error_code().is_none());
    assert!(store.active_policy().is_some());
    assert!(!policy_id.to_hex().is_empty());
}

#[test]
fn store_load_policy_json_success() {
    let mut store = TeeAttestationPolicyStore::default();
    let json = sample_policy(3).to_canonical_json().unwrap();
    store.load_policy_json(&json, "t-1", "d-1").unwrap();
    assert!(!store.receipt_emission_halted());
    assert_eq!(store.active_policy().unwrap().policy_epoch.as_u64(), 3);
}

#[test]
fn store_load_policy_json_bad_json_halts() {
    let mut store = TeeAttestationPolicyStore::default();
    let err = store
        .load_policy_json("not json", "t-1", "d-1")
        .unwrap_err();
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
    assert!(store.receipt_emission_halted());
    assert_eq!(store.last_error_code(), Some("tee_policy_parse_failed"));
}

#[test]
fn store_load_policy_epoch_regression_halts() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(10), "t-1", "d-1").unwrap();
    let err = store
        .load_policy(sample_policy(5), "t-2", "d-2")
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::PolicyEpochRegression { .. }
    ));
    assert!(store.receipt_emission_halted());
}

#[test]
fn store_load_policy_same_epoch_succeeds() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    // Same epoch is not a regression
    store.load_policy(sample_policy(5), "t-2", "d-2").unwrap();
    assert!(!store.receipt_emission_halted());
}

#[test]
fn store_load_policy_successive_epochs() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(1), "t-1", "d-1").unwrap();
    store.load_policy(sample_policy(2), "t-2", "d-2").unwrap();
    store.load_policy(sample_policy(3), "t-3", "d-3").unwrap();
    assert_eq!(store.active_policy().unwrap().policy_epoch.as_u64(), 3);
    // Should have 3 governance events
    assert_eq!(store.governance_ledger().len(), 3);
}

#[test]
fn store_evaluate_quote_when_halted_fails() {
    let mut store = TeeAttestationPolicyStore::default();
    let q = quote_for_sgx();
    let err = store
        .evaluate_quote(
            &q,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "t-1",
            "d-1",
        )
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
    // Event should still be recorded
    assert_eq!(store.governance_ledger().len(), 1);
}

#[test]
fn store_evaluate_quote_success_appends_accept_event() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(5), "t-load", "d-load")
        .unwrap();
    let q = quote_for_sgx();
    store
        .evaluate_quote(
            &q,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "t-eval",
            "d-eval",
        )
        .unwrap();
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "quote_accepted");
    assert_eq!(last.outcome, "allow");
    assert_eq!(last.error_code, "ok");
    assert_eq!(last.trace_id, "t-eval");
    assert_eq!(last.decision_id, "d-eval");
}

#[test]
fn store_evaluate_quote_rejection_appends_deny_event() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(5), "t-load", "d-load")
        .unwrap();
    let mut q = quote_for_sgx();
    q.quote_age_secs = 999;
    let err = store
        .evaluate_quote(
            &q,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "t-eval",
            "d-eval",
        )
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale { .. }
    ));
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "quote_rejected");
    assert_eq!(last.outcome, "deny");
}

#[test]
fn store_evaluate_quote_event_has_platform_metadata() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(1), "t-l", "d-l").unwrap();
    let q = quote_for_sgx();
    store
        .evaluate_quote(
            &q,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(1),
            "t-e",
            "d-e",
        )
        .unwrap();
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.metadata.get("platform").unwrap(), "intel_sgx");
    assert_eq!(last.metadata.get("trust_root_id").unwrap(), "sgx-root-a");
}

#[test]
fn store_apply_temporary_override_no_active_policy_fails() {
    let mut store = TeeAttestationPolicyStore::default();
    let key = make_signing_key();
    let verifier = key.verification_key();
    let artifact =
        SignedTrustRootOverrideArtifact::create_signed(&key, make_override_input("sgx-temp", 1))
            .unwrap();
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "g".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    let err = store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(1),
            "t-1",
            "d-1",
        )
        .unwrap_err();
    assert!(matches!(err, TeeAttestationPolicyError::NoActivePolicy));
}

#[test]
fn store_apply_temporary_override_appends_event() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(10), "t-l", "d-l").unwrap();

    let key = make_signing_key();
    let verifier = key.verification_key();
    let artifact =
        SignedTrustRootOverrideArtifact::create_signed(&key, make_override_input("sgx-temp", 10))
            .unwrap();
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----TEMP".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "rollover".to_string(),
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
            "t-ovr",
            "d-ovr",
        )
        .unwrap();
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "temporary_trust_root_override_applied");
    assert_eq!(last.outcome, "allow");
    assert!(last.metadata.contains_key("override_id"));
}

#[test]
fn store_apply_override_sets_temporary_source_on_root() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(10), "t-l", "d-l").unwrap();

    let key = make_signing_key();
    let verifier = key.verification_key();
    let artifact =
        SignedTrustRootOverrideArtifact::create_signed(&key, make_override_input("sgx-temp2", 10))
            .unwrap();
    let artifact_id = artifact.artifact_id.clone();
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-2".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp2".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----TEMP2".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "rollover".to_string(),
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
            "t-2",
            "d-2",
        )
        .unwrap();

    let active = store.active_policy().unwrap();
    let temp_root = active
        .platform_trust_roots
        .iter()
        .find(|r| r.root_id == "sgx-temp2")
        .unwrap();
    match &temp_root.source {
        TrustRootSource::TemporaryOverride {
            override_id,
            justification_artifact_id,
        } => {
            assert_eq!(override_id, "ovr-2");
            assert_eq!(justification_artifact_id, &artifact_id);
        }
        _ => panic!("expected TemporaryOverride source"),
    }
}

#[test]
fn store_serde_roundtrip() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    let json = serde_json::to_string(&store).unwrap();
    let parsed: TeeAttestationPolicyStore = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.active_policy().unwrap().policy_epoch.as_u64(), 5);
    assert!(!parsed.receipt_emission_halted());
}

// =========================================================================
// DecisionReceiptEmitter
// =========================================================================

#[test]
fn emitter_new_has_no_synced_epoch() {
    let e = DecisionReceiptEmitter::new("e-1");
    assert_eq!(e.emitter_id, "e-1");
    assert!(e.last_synced_policy_epoch.is_none());
}

#[test]
fn emitter_serde_roundtrip() {
    let mut e = DecisionReceiptEmitter::new("e-serde");
    e.last_synced_policy_epoch = Some(SecurityEpoch::from_raw(7));
    let json = serde_json::to_string(&e).unwrap();
    let parsed: DecisionReceiptEmitter = serde_json::from_str(&json).unwrap();
    assert_eq!(e, parsed);
}

#[test]
fn emitter_sync_when_halted_fails() {
    let mut emitter = DecisionReceiptEmitter::new("e-1");
    let store = TeeAttestationPolicyStore::default();
    let err = emitter.sync_policy(&store).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
}

#[test]
fn emitter_sync_sets_epoch_from_store() {
    let mut emitter = DecisionReceiptEmitter::new("e-1");
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(7), "t-1", "d-1").unwrap();
    let epoch = emitter.sync_policy(&store).unwrap();
    assert_eq!(epoch, SecurityEpoch::from_raw(7));
    assert_eq!(
        emitter.last_synced_policy_epoch,
        Some(SecurityEpoch::from_raw(7))
    );
}

#[test]
fn emitter_can_emit_not_synced_fails() {
    let emitter = DecisionReceiptEmitter::new("e-1");
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterNotSynced { .. }
    ));
}

#[test]
fn emitter_can_emit_when_synced_succeeds() {
    let mut emitter = DecisionReceiptEmitter::new("e-1");
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    emitter.sync_policy(&store).unwrap();
    emitter
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .unwrap();
}

#[test]
fn emitter_can_emit_one_epoch_behind_ok() {
    let mut emitter = DecisionReceiptEmitter::new("e-1");
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    emitter.sync_policy(&store).unwrap();
    store.load_policy(sample_policy(6), "t-2", "d-2").unwrap();
    // Synced at 5, active is 6 — one behind is OK
    emitter
        .can_emit(SecurityEpoch::from_raw(6), &store)
        .unwrap();
}

#[test]
fn emitter_can_emit_two_epochs_behind_fails() {
    let mut emitter = DecisionReceiptEmitter::new("e-1");
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    emitter.sync_policy(&store).unwrap();
    store.load_policy(sample_policy(10), "t-2", "d-2").unwrap();
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(10), &store)
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterPolicyStale { .. }
    ));
}

#[test]
fn emitter_can_emit_when_halted_fails() {
    let mut emitter = DecisionReceiptEmitter::new("e-1");
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    emitter.sync_policy(&store).unwrap();
    // Force halt via epoch regression
    let _ = store.load_policy(sample_policy(1), "t-2", "d-2");
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
}

#[test]
fn emitter_can_emit_runtime_epoch_too_far_ahead() {
    let mut emitter = DecisionReceiptEmitter::new("e-1");
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
    emitter.sync_policy(&store).unwrap();
    // Runtime epoch 8 is 3 ahead of synced epoch 5 — too far
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(8), &store)
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterPolicyStale { .. }
    ));
}

// =========================================================================
// TeeAttestationPolicyError
// =========================================================================

#[test]
fn error_all_codes_unique() {
    use std::collections::HashSet;
    let variants: Vec<TeeAttestationPolicyError> = vec![
        TeeAttestationPolicyError::ParseFailed {
            detail: "x".to_string(),
        },
        TeeAttestationPolicyError::SerializationFailed {
            detail: "x".to_string(),
        },
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx,
        },
        TeeAttestationPolicyError::InvalidMeasurementDigest {
            platform: TeePlatform::IntelSgx,
            digest: "x".to_string(),
            expected_hex_len: 64,
        },
        TeeAttestationPolicyError::DuplicateMeasurementDigest {
            platform: TeePlatform::IntelSgx,
            digest: "x".to_string(),
        },
        TeeAttestationPolicyError::InvalidFreshnessWindow {
            standard_max_age_secs: 0,
            high_impact_max_age_secs: 0,
        },
        TeeAttestationPolicyError::EmptyRevocationSources,
        TeeAttestationPolicyError::InvalidRevocationSource {
            reason: "x".to_string(),
        },
        TeeAttestationPolicyError::DuplicateRevocationSource {
            source_id: "x".to_string(),
        },
        TeeAttestationPolicyError::RevocationFallbackBypass,
        TeeAttestationPolicyError::MissingTrustRoots,
        TeeAttestationPolicyError::InvalidTrustRoot {
            root_id: "x".to_string(),
            reason: "x".to_string(),
        },
        TeeAttestationPolicyError::DuplicateTrustRoot {
            platform: TeePlatform::IntelSgx,
            root_id: "x".to_string(),
        },
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::IntelSgx,
        },
        TeeAttestationPolicyError::PolicyEpochRegression {
            current: SecurityEpoch::from_raw(5),
            attempted: SecurityEpoch::from_raw(3),
        },
        TeeAttestationPolicyError::IdDerivationFailed {
            detail: "x".to_string(),
        },
        TeeAttestationPolicyError::ReceiptEmissionHalted,
        TeeAttestationPolicyError::NoActivePolicy,
        TeeAttestationPolicyError::UnknownMeasurementDigest {
            platform: TeePlatform::IntelSgx,
            digest: "x".to_string(),
        },
        TeeAttestationPolicyError::AttestationStale {
            quote_age_secs: 500,
            max_age_secs: 300,
        },
        TeeAttestationPolicyError::UnknownTrustRoot {
            platform: TeePlatform::IntelSgx,
            root_id: "x".to_string(),
        },
        TeeAttestationPolicyError::ExpiredTrustRoot {
            root_id: "x".to_string(),
            runtime_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
        },
        TeeAttestationPolicyError::RevokedBySource {
            source_id: "x".to_string(),
        },
        TeeAttestationPolicyError::RevocationSourceUnavailable {
            source_id: "x".to_string(),
        },
        TeeAttestationPolicyError::RevocationEvidenceUnavailable,
        TeeAttestationPolicyError::InvalidOverrideArtifact {
            reason: "x".to_string(),
        },
        TeeAttestationPolicyError::OverrideJustificationMissing,
        TeeAttestationPolicyError::OverrideExpired {
            current_epoch: SecurityEpoch::from_raw(10),
            expires_epoch: SecurityEpoch::from_raw(5),
        },
        TeeAttestationPolicyError::OverrideSignatureInvalid {
            detail: "x".to_string(),
        },
        TeeAttestationPolicyError::OverrideTargetMismatch {
            expected_platform: TeePlatform::IntelSgx,
            expected_root_id: "x".to_string(),
            actual_platform: TeePlatform::AmdSev,
            actual_root_id: "y".to_string(),
        },
        TeeAttestationPolicyError::EmitterNotSynced {
            emitter_id: "x".to_string(),
        },
        TeeAttestationPolicyError::EmitterPolicyStale {
            emitter_id: "x".to_string(),
            synced_epoch: SecurityEpoch::from_raw(3),
            required_epoch: SecurityEpoch::from_raw(5),
        },
    ];
    let codes: Vec<&str> = variants.iter().map(|v| v.error_code()).collect();
    let unique: HashSet<&str> = codes.iter().copied().collect();
    assert_eq!(codes.len(), unique.len(), "some error codes are not unique");
}

#[test]
fn error_all_display_non_empty() {
    let variants: Vec<TeeAttestationPolicyError> = vec![
        TeeAttestationPolicyError::ParseFailed {
            detail: "test".to_string(),
        },
        TeeAttestationPolicyError::EmptyRevocationSources,
        TeeAttestationPolicyError::RevocationFallbackBypass,
        TeeAttestationPolicyError::MissingTrustRoots,
        TeeAttestationPolicyError::ReceiptEmissionHalted,
        TeeAttestationPolicyError::NoActivePolicy,
        TeeAttestationPolicyError::RevocationEvidenceUnavailable,
        TeeAttestationPolicyError::OverrideJustificationMissing,
    ];
    for v in &variants {
        assert!(!v.to_string().is_empty(), "empty display for {:?}", v);
    }
}

#[test]
fn error_implements_std_error() {
    let err = TeeAttestationPolicyError::ReceiptEmissionHalted;
    let as_std: &dyn std::error::Error = &err;
    assert!(as_std.source().is_none());
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let variants = [
        TeeAttestationPolicyError::ParseFailed {
            detail: "d".to_string(),
        },
        TeeAttestationPolicyError::EmptyRevocationSources,
        TeeAttestationPolicyError::ReceiptEmissionHalted,
        TeeAttestationPolicyError::OverrideJustificationMissing,
        TeeAttestationPolicyError::RevocationEvidenceUnavailable,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let parsed: TeeAttestationPolicyError = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &parsed);
    }
}

#[test]
fn error_specific_codes_stable() {
    assert_eq!(
        TeeAttestationPolicyError::ParseFailed {
            detail: "x".to_string()
        }
        .error_code(),
        "tee_policy_parse_failed"
    );
    assert_eq!(
        TeeAttestationPolicyError::ReceiptEmissionHalted.error_code(),
        "tee_policy_emission_halted"
    );
    assert_eq!(
        TeeAttestationPolicyError::NoActivePolicy.error_code(),
        "tee_policy_not_loaded"
    );
    assert_eq!(
        TeeAttestationPolicyError::RevocationFallbackBypass.error_code(),
        "tee_policy_revocation_bypass_config"
    );
}

// =========================================================================
// Determinism
// =========================================================================

#[test]
fn determinism_policy_id_100_iterations() {
    let p = sample_policy(99);
    let id = p.derive_policy_id().unwrap();
    for _ in 0..100 {
        assert_eq!(p.derive_policy_id().unwrap(), id);
    }
}

#[test]
fn determinism_canonical_json_100_iterations() {
    let p = sample_policy(42);
    let json = p.to_canonical_json().unwrap();
    for _ in 0..100 {
        assert_eq!(p.to_canonical_json().unwrap(), json);
    }
}

// =========================================================================
// Integration — full lifecycle
// =========================================================================

#[test]
fn integration_full_lifecycle() {
    // 1. Create store and load policy
    let mut store = TeeAttestationPolicyStore::default();
    assert!(store.receipt_emission_halted());

    store
        .load_policy(sample_policy(5), "t-load", "d-load")
        .unwrap();
    assert!(!store.receipt_emission_halted());

    // 2. Evaluate passing quote
    let q = quote_for_sgx();
    store
        .evaluate_quote(
            &q,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "t-eval-1",
            "d-eval-1",
        )
        .unwrap();

    // 3. Evaluate stale quote (rejected)
    let mut stale = quote_for_sgx();
    stale.quote_age_secs = 999;
    let err = store
        .evaluate_quote(
            &stale,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "t-eval-2",
            "d-eval-2",
        )
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale { .. }
    ));

    // 4. Apply temporary override
    let key = make_signing_key();
    let verifier = key.verification_key();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &key,
        make_override_input("sgx-override-root", 5),
    )
    .unwrap();
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-lifecycle".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-override-root".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----OVERRIDE".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(5),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(5),
            "t-ovr",
            "d-ovr",
        )
        .unwrap();

    // 5. Evaluate quote using the overridden root
    let mut q_override = quote_for_sgx();
    q_override.trust_root_id = "sgx-override-root".to_string();
    store
        .evaluate_quote(
            &q_override,
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(5),
            "t-eval-3",
            "d-eval-3",
        )
        .unwrap();

    // 6. Sync emitter
    let mut emitter = DecisionReceiptEmitter::new("emitter-lifecycle");
    emitter.sync_policy(&store).unwrap();
    emitter
        .can_emit(SecurityEpoch::from_raw(5), &store)
        .unwrap();

    // 7. Verify governance ledger accumulated
    assert!(store.governance_ledger().len() >= 5);
}

#[test]
fn integration_epoch_regression_then_recovery() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(10), "t-1", "d-1").unwrap();

    // Regression halts
    let _ = store.load_policy(sample_policy(5), "t-2", "d-2");
    assert!(store.receipt_emission_halted());

    // Recovery with higher epoch
    store.load_policy(sample_policy(15), "t-3", "d-3").unwrap();
    assert!(!store.receipt_emission_halted());
    assert_eq!(store.active_policy().unwrap().policy_epoch.as_u64(), 15);
}

#[test]
fn integration_emitter_resync_after_policy_advance() {
    let mut store = TeeAttestationPolicyStore::default();
    store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();

    let mut emitter = DecisionReceiptEmitter::new("e-1");
    emitter.sync_policy(&store).unwrap();

    // Advance policy by 2 epochs
    store.load_policy(sample_policy(7), "t-2", "d-2").unwrap();

    // Stale: synced at 5, active at 7 (2 behind)
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(7), &store)
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterPolicyStale { .. }
    ));

    // Re-sync fixes it
    emitter.sync_policy(&store).unwrap();
    emitter
        .can_emit(SecurityEpoch::from_raw(7), &store)
        .unwrap();
}
