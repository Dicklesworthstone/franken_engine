//! Enrichment integration tests for `tee_attestation_policy`.
//!
//! Covers all public types, enum variants, Display impls, serde round-trips,
//! validation edge cases, governance event workflows, override artifact
//! signing/verification, emitter sync semantics, and determinism properties.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
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
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn digest_hex(byte: u8, bytes: usize) -> String {
    let mut out = String::with_capacity(bytes * 2);
    for _ in 0..bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sample_policy(ep: u64) -> TeeAttestationPolicy {
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
        policy_epoch: epoch(ep),
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
                valid_from_epoch: epoch(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "tz-root-a".to_string(),
                platform: TeePlatform::ArmTrustZone,
                trust_anchor_pem: "-----BEGIN CERT-----TZ-A".to_string(),
                valid_from_epoch: epoch(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "cca-root-a".to_string(),
                platform: TeePlatform::ArmCca,
                trust_anchor_pem: "-----BEGIN CERT-----CCA-A".to_string(),
                valid_from_epoch: epoch(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "sev-root-a".to_string(),
                platform: TeePlatform::AmdSev,
                trust_anchor_pem: "-----BEGIN CERT-----SEV-A".to_string(),
                valid_from_epoch: epoch(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
        ],
    }
}

fn quote_for_platform(
    platform: TeePlatform,
    algorithm: MeasurementAlgorithm,
    digest_byte: u8,
    digest_len: usize,
    root_id: &str,
    age: u64,
) -> AttestationQuote {
    let mut rev = BTreeMap::new();
    rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    rev.insert(
        "manufacturer_crl".to_string(),
        RevocationProbeStatus::Good,
    );
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
    AttestationQuote {
        platform,
        measurement: MeasurementDigest {
            algorithm,
            digest_hex: digest_hex(digest_byte, digest_len),
        },
        quote_age_secs: age,
        trust_root_id: root_id.to_string(),
        revocation_observations: rev,
    }
}

fn sgx_quote(age: u64) -> AttestationQuote {
    quote_for_platform(
        TeePlatform::IntelSgx,
        MeasurementAlgorithm::Sha384,
        0x11,
        48,
        "sgx-root-a",
        age,
    )
}

fn make_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_override_artifact(
    signing_key: &SigningKey,
    platform: TeePlatform,
    root_id: &str,
    issued: u64,
    expires: u64,
) -> SignedTrustRootOverrideArtifact {
    SignedTrustRootOverrideArtifact::create_signed(
        signing_key,
        TrustRootOverrideArtifactInput {
            actor: "test-operator".to_string(),
            justification: "enrichment test justification".to_string(),
            evidence_refs: vec!["evidence-a".to_string()],
            target_platform: platform,
            target_root_id: root_id.to_string(),
            issued_epoch: epoch(issued),
            expires_epoch: epoch(expires),
        },
    )
    .expect("artifact creation should succeed")
}

fn loaded_store(ep: u64) -> TeeAttestationPolicyStore {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(ep), "trace-init", "decision-init")
        .expect("policy load");
    store
}

// =========================================================================
// TeePlatform
// =========================================================================

#[test]
fn enrichment_tee_platform_all_has_four_variants() {
    assert_eq!(TeePlatform::ALL.len(), 4);
    let set: BTreeSet<TeePlatform> = TeePlatform::ALL.into_iter().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_tee_platform_display_intel_sgx() {
    assert_eq!(TeePlatform::IntelSgx.to_string(), "intel_sgx");
}

#[test]
fn enrichment_tee_platform_display_arm_trustzone() {
    assert_eq!(TeePlatform::ArmTrustZone.to_string(), "arm_trustzone");
}

#[test]
fn enrichment_tee_platform_display_arm_cca() {
    assert_eq!(TeePlatform::ArmCca.to_string(), "arm_cca");
}

#[test]
fn enrichment_tee_platform_display_amd_sev() {
    assert_eq!(TeePlatform::AmdSev.to_string(), "amd_sev");
}

#[test]
fn enrichment_tee_platform_serde_roundtrip_all_variants() {
    for platform in TeePlatform::ALL {
        let json = serde_json::to_string(&platform).unwrap();
        let parsed: TeePlatform = serde_json::from_str(&json).unwrap();
        assert_eq!(platform, parsed);
    }
}

#[test]
fn enrichment_tee_platform_ord_is_deterministic() {
    let mut platforms = TeePlatform::ALL.to_vec();
    platforms.sort();
    let mut second = platforms.clone();
    second.sort();
    assert_eq!(platforms, second);
}

#[test]
fn enrichment_tee_platform_clone_eq() {
    let p = TeePlatform::ArmCca;
    let cloned = p.clone();
    assert_eq!(p, cloned);
}

// =========================================================================
// MeasurementAlgorithm
// =========================================================================

#[test]
fn enrichment_measurement_algorithm_display_sha256() {
    assert_eq!(MeasurementAlgorithm::Sha256.to_string(), "sha256");
}

#[test]
fn enrichment_measurement_algorithm_display_sha384() {
    assert_eq!(MeasurementAlgorithm::Sha384.to_string(), "sha384");
}

#[test]
fn enrichment_measurement_algorithm_display_sha512() {
    assert_eq!(MeasurementAlgorithm::Sha512.to_string(), "sha512");
}

#[test]
fn enrichment_measurement_algorithm_serde_roundtrip() {
    for alg in [
        MeasurementAlgorithm::Sha256,
        MeasurementAlgorithm::Sha384,
        MeasurementAlgorithm::Sha512,
    ] {
        let json = serde_json::to_string(&alg).unwrap();
        let parsed: MeasurementAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(alg, parsed);
    }
}

#[test]
fn enrichment_measurement_algorithm_ord_consistent() {
    let a = MeasurementAlgorithm::Sha256;
    let b = MeasurementAlgorithm::Sha512;
    assert!(a <= b || b <= a);
}

// =========================================================================
// MeasurementDigest serde
// =========================================================================

#[test]
fn enrichment_measurement_digest_serde_sha256() {
    let digest = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha256,
        digest_hex: digest_hex(0xaa, 32),
    };
    let json = serde_json::to_string(&digest).unwrap();
    let parsed: MeasurementDigest = serde_json::from_str(&json).unwrap();
    assert_eq!(digest, parsed);
}

#[test]
fn enrichment_measurement_digest_serde_sha384() {
    let digest = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha384,
        digest_hex: digest_hex(0xbb, 48),
    };
    let json = serde_json::to_string(&digest).unwrap();
    let parsed: MeasurementDigest = serde_json::from_str(&json).unwrap();
    assert_eq!(digest, parsed);
}

#[test]
fn enrichment_measurement_digest_serde_sha512() {
    let digest = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha512,
        digest_hex: digest_hex(0xcc, 64),
    };
    let json = serde_json::to_string(&digest).unwrap();
    let parsed: MeasurementDigest = serde_json::from_str(&json).unwrap();
    assert_eq!(digest, parsed);
}

// =========================================================================
// AttestationFreshnessWindow
// =========================================================================

#[test]
fn enrichment_freshness_window_serde_roundtrip() {
    let window = AttestationFreshnessWindow {
        standard_max_age_secs: 600,
        high_impact_max_age_secs: 120,
    };
    let json = serde_json::to_string(&window).unwrap();
    let parsed: AttestationFreshnessWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(window, parsed);
}

#[test]
fn enrichment_freshness_window_equal_values_are_valid() {
    let policy = {
        let mut p = sample_policy(1);
        p.freshness_window = AttestationFreshnessWindow {
            standard_max_age_secs: 100,
            high_impact_max_age_secs: 100,
        };
        p
    };
    policy.validate().unwrap();
}

#[test]
fn enrichment_freshness_window_high_impact_greater_than_standard_rejected() {
    let mut policy = sample_policy(1);
    policy.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 50,
        high_impact_max_age_secs: 100,
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
    ));
}

#[test]
fn enrichment_freshness_window_zero_standard_rejected() {
    let mut policy = sample_policy(1);
    policy.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 0,
        high_impact_max_age_secs: 0,
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
    ));
}

#[test]
fn enrichment_freshness_window_zero_high_impact_only_rejected() {
    let mut policy = sample_policy(1);
    policy.freshness_window = AttestationFreshnessWindow {
        standard_max_age_secs: 300,
        high_impact_max_age_secs: 0,
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
    ));
}

// =========================================================================
// DecisionImpact
// =========================================================================

#[test]
fn enrichment_decision_impact_serde_standard() {
    let impact = DecisionImpact::Standard;
    let json = serde_json::to_string(&impact).unwrap();
    let parsed: DecisionImpact = serde_json::from_str(&json).unwrap();
    assert_eq!(impact, parsed);
}

#[test]
fn enrichment_decision_impact_serde_high_impact() {
    let impact = DecisionImpact::HighImpact;
    let json = serde_json::to_string(&impact).unwrap();
    let parsed: DecisionImpact = serde_json::from_str(&json).unwrap();
    assert_eq!(impact, parsed);
}

#[test]
fn enrichment_decision_impact_ord() {
    assert!(DecisionImpact::Standard <= DecisionImpact::HighImpact);
}

// =========================================================================
// RevocationProbeStatus
// =========================================================================

#[test]
fn enrichment_revocation_probe_status_serde_all() {
    for status in [
        RevocationProbeStatus::Good,
        RevocationProbeStatus::Revoked,
        RevocationProbeStatus::Unavailable,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let parsed: RevocationProbeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }
}

#[test]
fn enrichment_revocation_probe_status_clone_eq() {
    let s = RevocationProbeStatus::Good;
    assert_eq!(s, s.clone());
}

// =========================================================================
// RevocationFallback
// =========================================================================

#[test]
fn enrichment_revocation_fallback_serde_try_next() {
    let fb = RevocationFallback::TryNextSource;
    let json = serde_json::to_string(&fb).unwrap();
    let parsed: RevocationFallback = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, parsed);
}

#[test]
fn enrichment_revocation_fallback_serde_fail_closed() {
    let fb = RevocationFallback::FailClosed;
    let json = serde_json::to_string(&fb).unwrap();
    let parsed: RevocationFallback = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, parsed);
}

// =========================================================================
// RevocationSourceType
// =========================================================================

#[test]
fn enrichment_revocation_source_type_serde_all_variants() {
    for st in [
        RevocationSourceType::IntelPcs,
        RevocationSourceType::ManufacturerCrl,
        RevocationSourceType::InternalLedger,
        RevocationSourceType::Other("custom-provider".to_string()),
    ] {
        let json = serde_json::to_string(&st).unwrap();
        let parsed: RevocationSourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(st, parsed);
    }
}

#[test]
fn enrichment_revocation_source_type_other_preserves_name() {
    let st = RevocationSourceType::Other("my-revocation-db".to_string());
    let json = serde_json::to_string(&st).unwrap();
    assert!(json.contains("my-revocation-db"));
}

// =========================================================================
// RevocationSource
// =========================================================================

#[test]
fn enrichment_revocation_source_serde_roundtrip() {
    let source = RevocationSource {
        source_id: "src-custom".to_string(),
        source_type: RevocationSourceType::Other("vendor-x".to_string()),
        endpoint: "https://vendor.example/crl".to_string(),
        on_unavailable: RevocationFallback::TryNextSource,
    };
    let json = serde_json::to_string(&source).unwrap();
    let parsed: RevocationSource = serde_json::from_str(&json).unwrap();
    assert_eq!(source, parsed);
}

#[test]
fn enrichment_revocation_source_whitespace_only_source_id_rejected() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].source_id = "   ".to_string();
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidRevocationSource { .. }
    ));
}

#[test]
fn enrichment_revocation_source_whitespace_only_endpoint_rejected() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].endpoint = "   ".to_string();
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidRevocationSource { .. }
    ));
}

#[test]
fn enrichment_revocation_source_other_whitespace_name_rejected() {
    let mut policy = sample_policy(1);
    policy.revocation_sources[0].source_type = RevocationSourceType::Other("  ".to_string());
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidRevocationSource { .. }
    ));
}

// =========================================================================
// TrustRootPinning
// =========================================================================

#[test]
fn enrichment_trust_root_pinning_serde_pinned() {
    let pinning = TrustRootPinning::Pinned;
    let json = serde_json::to_string(&pinning).unwrap();
    let parsed: TrustRootPinning = serde_json::from_str(&json).unwrap();
    assert_eq!(pinning, parsed);
}

#[test]
fn enrichment_trust_root_pinning_serde_rotating() {
    let pinning = TrustRootPinning::Rotating {
        rotation_group: "grp-alpha".to_string(),
    };
    let json = serde_json::to_string(&pinning).unwrap();
    let parsed: TrustRootPinning = serde_json::from_str(&json).unwrap();
    assert_eq!(pinning, parsed);
}

// =========================================================================
// TrustRootSource
// =========================================================================

#[test]
fn enrichment_trust_root_source_serde_policy() {
    let src = TrustRootSource::Policy;
    let json = serde_json::to_string(&src).unwrap();
    let parsed: TrustRootSource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, parsed);
}

#[test]
fn enrichment_trust_root_source_serde_temporary_override() {
    let src = TrustRootSource::TemporaryOverride {
        override_id: "ovr-99".to_string(),
        justification_artifact_id: "art-99".to_string(),
    };
    let json = serde_json::to_string(&src).unwrap();
    let parsed: TrustRootSource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, parsed);
}

// =========================================================================
// PlatformTrustRoot
// =========================================================================

#[test]
fn enrichment_platform_trust_root_serde_roundtrip() {
    let root = PlatformTrustRoot {
        root_id: "sev-root-99".to_string(),
        platform: TeePlatform::AmdSev,
        trust_anchor_pem: "-----BEGIN CERT-----SEV99".to_string(),
        valid_from_epoch: epoch(5),
        valid_until_epoch: Some(epoch(100)),
        pinning: TrustRootPinning::Rotating {
            rotation_group: "sev-grp".to_string(),
        },
        source: TrustRootSource::TemporaryOverride {
            override_id: "ovr-sev".to_string(),
            justification_artifact_id: "art-sev".to_string(),
        },
    };
    let json = serde_json::to_string(&root).unwrap();
    let parsed: PlatformTrustRoot = serde_json::from_str(&json).unwrap();
    assert_eq!(root, parsed);
}

#[test]
fn enrichment_trust_root_empty_root_id_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].root_id = "  ".to_string();
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

#[test]
fn enrichment_trust_root_empty_pem_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].trust_anchor_pem = "  ".to_string();
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

#[test]
fn enrichment_trust_root_inverted_epochs_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_from_epoch = epoch(100);
    policy.platform_trust_roots[0].valid_until_epoch = Some(epoch(10));
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

#[test]
fn enrichment_trust_root_rotating_empty_group_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = Some(epoch(1000));
    policy.platform_trust_roots[0].pinning = TrustRootPinning::Rotating {
        rotation_group: "".to_string(),
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

#[test]
fn enrichment_trust_root_rotating_without_until_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = None;
    policy.platform_trust_roots[0].pinning = TrustRootPinning::Rotating {
        rotation_group: "grp".to_string(),
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

#[test]
fn enrichment_trust_root_temp_override_empty_override_id_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = Some(epoch(1000));
    policy.platform_trust_roots[0].source = TrustRootSource::TemporaryOverride {
        override_id: "".to_string(),
        justification_artifact_id: "art-1".to_string(),
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

#[test]
fn enrichment_trust_root_temp_override_empty_artifact_id_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = Some(epoch(1000));
    policy.platform_trust_roots[0].source = TrustRootSource::TemporaryOverride {
        override_id: "ovr-1".to_string(),
        justification_artifact_id: "".to_string(),
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

#[test]
fn enrichment_trust_root_temp_override_without_until_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = None;
    policy.platform_trust_roots[0].source = TrustRootSource::TemporaryOverride {
        override_id: "ovr-1".to_string(),
        justification_artifact_id: "art-1".to_string(),
    };
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidTrustRoot { .. }
    ));
}

// =========================================================================
// AttestationQuote serde
// =========================================================================

#[test]
fn enrichment_attestation_quote_serde_roundtrip() {
    let quote = sgx_quote(10);
    let json = serde_json::to_string(&quote).unwrap();
    let parsed: AttestationQuote = serde_json::from_str(&json).unwrap();
    assert_eq!(quote, parsed);
}

#[test]
fn enrichment_attestation_quote_serde_with_all_platforms() {
    for platform in TeePlatform::ALL {
        let quote = AttestationQuote {
            platform,
            measurement: MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0xab, 32),
            },
            quote_age_secs: 42,
            trust_root_id: "root-x".to_string(),
            revocation_observations: BTreeMap::new(),
        };
        let json = serde_json::to_string(&quote).unwrap();
        let parsed: AttestationQuote = serde_json::from_str(&json).unwrap();
        assert_eq!(quote, parsed);
    }
}

// =========================================================================
// PolicyGovernanceEvent
// =========================================================================

#[test]
fn enrichment_policy_governance_event_serde_roundtrip() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key1".to_string(), "value1".to_string());
    metadata.insert("key2".to_string(), "value2".to_string());
    let event = PolicyGovernanceEvent {
        trace_id: "trace-abc".to_string(),
        decision_id: "decision-xyz".to_string(),
        policy_id: "policy-123".to_string(),
        component: "tee_attestation_policy".to_string(),
        event: "policy_loaded".to_string(),
        outcome: "allow".to_string(),
        error_code: "ok".to_string(),
        metadata,
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: PolicyGovernanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn enrichment_policy_governance_event_empty_metadata_roundtrip() {
    let event = PolicyGovernanceEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "deny".to_string(),
        error_code: "err".to_string(),
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: PolicyGovernanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

// =========================================================================
// TeeAttestationPolicy -- from_json / to_canonical_json
// =========================================================================

#[test]
fn enrichment_policy_json_roundtrip() {
    let policy = sample_policy(7);
    let json = policy.to_canonical_json().expect("serialize");
    let parsed = TeeAttestationPolicy::from_json(&json).expect("parse");
    assert_eq!(policy, parsed);
}

#[test]
fn enrichment_policy_from_json_invalid_json() {
    let err = TeeAttestationPolicy::from_json("{not valid json").unwrap_err();
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

#[test]
fn enrichment_policy_from_json_wrong_type() {
    let err = TeeAttestationPolicy::from_json(r#"{"schema_version":"bad"}"#).unwrap_err();
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
}

// =========================================================================
// TeeAttestationPolicy -- derive_policy_id determinism
// =========================================================================

#[test]
fn enrichment_policy_id_deterministic() {
    let p1 = sample_policy(42);
    let p2 = sample_policy(42);
    assert_eq!(
        p1.derive_policy_id().unwrap(),
        p2.derive_policy_id().unwrap()
    );
}

#[test]
fn enrichment_policy_id_differs_for_different_epochs() {
    let p1 = sample_policy(1);
    let p2 = sample_policy(2);
    assert_ne!(
        p1.derive_policy_id().unwrap(),
        p2.derive_policy_id().unwrap()
    );
}

#[test]
fn enrichment_policy_id_differs_for_different_schema_version() {
    let mut p1 = sample_policy(1);
    let mut p2 = sample_policy(1);
    p1.schema_version = 1;
    p2.schema_version = 2;
    assert_ne!(
        p1.derive_policy_id().unwrap(),
        p2.derive_policy_id().unwrap()
    );
}

#[test]
fn enrichment_policy_id_hex_length() {
    let policy = sample_policy(1);
    let id = policy.derive_policy_id().unwrap();
    let hex = id.to_hex();
    assert!(!hex.is_empty());
    assert!(hex.len() > 10);
}

// =========================================================================
// TeeAttestationPolicy -- validate edge cases
// =========================================================================

#[test]
fn enrichment_policy_missing_measurements_for_sgx() {
    let mut policy = sample_policy(1);
    policy.approved_measurements.remove(&TeePlatform::IntelSgx);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx
        }
    ));
}

#[test]
fn enrichment_policy_missing_measurements_for_arm_trustzone() {
    let mut policy = sample_policy(1);
    policy
        .approved_measurements
        .remove(&TeePlatform::ArmTrustZone);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform { .. }
    ));
}

#[test]
fn enrichment_policy_missing_measurements_for_arm_cca() {
    let mut policy = sample_policy(1);
    policy.approved_measurements.remove(&TeePlatform::ArmCca);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform { .. }
    ));
}

#[test]
fn enrichment_policy_missing_measurements_for_amd_sev() {
    let mut policy = sample_policy(1);
    policy.approved_measurements.remove(&TeePlatform::AmdSev);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::AmdSev
        }
    ));
}

#[test]
fn enrichment_policy_empty_measurement_list_for_platform() {
    let mut policy = sample_policy(1);
    policy
        .approved_measurements
        .insert(TeePlatform::IntelSgx, vec![]);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx
        }
    ));
}

#[test]
fn enrichment_policy_duplicate_measurement_rejected() {
    let mut policy = sample_policy(1);
    let dup = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha384,
        digest_hex: digest_hex(0x11, 48),
    };
    policy
        .approved_measurements
        .insert(TeePlatform::IntelSgx, vec![dup.clone(), dup]);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::DuplicateMeasurementDigest { .. }
    ));
}

#[test]
fn enrichment_policy_invalid_measurement_digest_wrong_length() {
    let mut policy = sample_policy(1);
    policy
        .approved_measurements
        .insert(
            TeePlatform::IntelSgx,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: "aabb".to_string(), // Too short
            }],
        );
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidMeasurementDigest { .. }
    ));
}

#[test]
fn enrichment_policy_invalid_measurement_digest_non_hex() {
    let mut policy = sample_policy(1);
    policy
        .approved_measurements
        .insert(
            TeePlatform::IntelSgx,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: "zz".repeat(48),
            }],
        );
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidMeasurementDigest { .. }
    ));
}

#[test]
fn enrichment_policy_empty_revocation_sources_rejected() {
    let mut policy = sample_policy(1);
    policy.revocation_sources.clear();
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmptyRevocationSources
    ));
}

#[test]
fn enrichment_policy_duplicate_revocation_source_rejected() {
    let mut policy = sample_policy(1);
    let dup = policy.revocation_sources[0].clone();
    policy.revocation_sources.push(dup);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::DuplicateRevocationSource { .. }
    ));
}

#[test]
fn enrichment_policy_no_fail_closed_revocation_rejected() {
    let mut policy = sample_policy(1);
    for source in &mut policy.revocation_sources {
        source.on_unavailable = RevocationFallback::TryNextSource;
    }
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationFallbackBypass
    ));
}

#[test]
fn enrichment_policy_empty_trust_roots_rejected() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots.clear();
    let err = policy.validate().unwrap_err();
    assert!(matches!(err, TeeAttestationPolicyError::MissingTrustRoots));
}

#[test]
fn enrichment_policy_duplicate_trust_root_rejected() {
    let mut policy = sample_policy(1);
    let dup = policy.platform_trust_roots[0].clone();
    policy.platform_trust_roots.push(dup);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::DuplicateTrustRoot { .. }
    ));
}

#[test]
fn enrichment_policy_missing_pinned_trust_root_rejected() {
    let mut policy = sample_policy(1);
    // Replace SGX pinned root with a rotating one
    policy
        .platform_trust_roots
        .retain(|r| r.platform != TeePlatform::IntelSgx);
    policy.platform_trust_roots.push(PlatformTrustRoot {
        root_id: "sgx-rotating".to_string(),
        platform: TeePlatform::IntelSgx,
        trust_anchor_pem: "-----BEGIN CERT-----SGX-ROT".to_string(),
        valid_from_epoch: epoch(0),
        valid_until_epoch: Some(epoch(1000)),
        pinning: TrustRootPinning::Rotating {
            rotation_group: "sgx-grp".to_string(),
        },
        source: TrustRootSource::Policy,
    });
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::IntelSgx
        }
    ));
}

// =========================================================================
// TeeAttestationPolicy -- canonicalize
// =========================================================================

#[test]
fn enrichment_canonicalize_lowercases_digests() {
    let mut policy = sample_policy(1);
    let upper_digest = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha384,
        digest_hex: digest_hex(0x11, 48).to_uppercase(),
    };
    policy
        .approved_measurements
        .get_mut(&TeePlatform::IntelSgx)
        .unwrap()
        .push(upper_digest);
    // After canonicalize via to_canonical_json, uppercase deduped
    let json = policy.to_canonical_json().unwrap();
    let parsed = TeeAttestationPolicy::from_json(&json).unwrap();
    assert_eq!(
        parsed.approved_measurements[&TeePlatform::IntelSgx].len(),
        1
    );
}

#[test]
fn enrichment_canonicalize_trims_root_ids() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].root_id = "  sgx-root-a  ".to_string();
    let json = policy.to_canonical_json().unwrap();
    let parsed = TeeAttestationPolicy::from_json(&json).unwrap();
    let sgx_root = parsed
        .platform_trust_roots
        .iter()
        .find(|r| r.platform == TeePlatform::IntelSgx)
        .unwrap();
    assert_eq!(sgx_root.root_id, "sgx-root-a");
}

#[test]
fn enrichment_canonicalize_sorts_trust_roots() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots.reverse();
    let json = policy.to_canonical_json().unwrap();
    let parsed = TeeAttestationPolicy::from_json(&json).unwrap();
    // Roots should be sorted by (platform, root_id)
    for i in 1..parsed.platform_trust_roots.len() {
        let prev = &parsed.platform_trust_roots[i - 1];
        let curr = &parsed.platform_trust_roots[i];
        assert!(
            (prev.platform, prev.root_id.as_str()) <= (curr.platform, curr.root_id.as_str())
        );
    }
}

// =========================================================================
// TeeAttestationPolicy -- evaluate_quote
// =========================================================================

#[test]
fn enrichment_evaluate_quote_sgx_passes() {
    let policy = sample_policy(1);
    let quote = sgx_quote(10);
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_arm_trustzone_passes() {
    let policy = sample_policy(1);
    let quote = quote_for_platform(
        TeePlatform::ArmTrustZone,
        MeasurementAlgorithm::Sha256,
        0x22,
        32,
        "tz-root-a",
        5,
    );
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_arm_cca_passes() {
    let policy = sample_policy(1);
    let quote = quote_for_platform(
        TeePlatform::ArmCca,
        MeasurementAlgorithm::Sha256,
        0x44,
        32,
        "cca-root-a",
        5,
    );
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_amd_sev_passes() {
    let policy = sample_policy(1);
    let quote = quote_for_platform(
        TeePlatform::AmdSev,
        MeasurementAlgorithm::Sha384,
        0x33,
        48,
        "sev-root-a",
        5,
    );
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_unknown_measurement_rejected() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote(10);
    quote.measurement.digest_hex = digest_hex(0xff, 48);
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::UnknownMeasurementDigest { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_stale_standard() {
    let policy = sample_policy(1);
    let quote = sgx_quote(301); // > 300
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_at_exact_standard_max_passes() {
    let policy = sample_policy(1);
    let quote = sgx_quote(300);
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_stale_high_impact() {
    let policy = sample_policy(1);
    let quote = sgx_quote(61); // > 60
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::HighImpact, epoch(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_at_exact_high_impact_max_passes() {
    let policy = sample_policy(1);
    let quote = sgx_quote(60);
    policy
        .evaluate_quote(&quote, DecisionImpact::HighImpact, epoch(1))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_unknown_trust_root() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote(10);
    quote.trust_root_id = "nonexistent-root".to_string();
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::UnknownTrustRoot { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_expired_trust_root() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = Some(epoch(5));
    let quote = sgx_quote(10);
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(6))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ExpiredTrustRoot { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_trust_root_active_at_boundary() {
    let mut policy = sample_policy(1);
    policy.platform_trust_roots[0].valid_until_epoch = Some(epoch(10));
    let quote = sgx_quote(5);
    // At exactly the until boundary -- should pass
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(10))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_revoked_by_first_source() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote(10);
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Revoked);
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevokedBySource { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_revoked_by_second_source() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote(10);
    quote
        .revocation_observations
        .insert("manufacturer_crl".to_string(), RevocationProbeStatus::Revoked);
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevokedBySource { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_fail_closed_source_unavailable() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote(10);
    // internal_ledger is fail-closed; mark it unavailable
    quote
        .revocation_observations
        .insert(
            "internal_ledger".to_string(),
            RevocationProbeStatus::Unavailable,
        );
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_try_next_source_fallback_works() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote(10);
    // First two are TryNextSource, set them unavailable.
    // internal_ledger (FailClosed) is Good.
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    quote
        .revocation_observations
        .insert(
            "manufacturer_crl".to_string(),
            RevocationProbeStatus::Unavailable,
        );
    quote
        .revocation_observations
        .insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
    policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap();
}

#[test]
fn enrichment_evaluate_quote_all_unavailable_evidence_unavailable() {
    let policy = sample_policy(1);
    let mut quote = sgx_quote(10);
    // All TryNextSource are unavailable, FailClosed source also unavailable
    quote
        .revocation_observations
        .insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    quote
        .revocation_observations
        .insert(
            "manufacturer_crl".to_string(),
            RevocationProbeStatus::Unavailable,
        );
    quote
        .revocation_observations
        .insert(
            "internal_ledger".to_string(),
            RevocationProbeStatus::Unavailable,
        );
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    // The FailClosed source hits first
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
    ));
}

#[test]
fn enrichment_evaluate_quote_missing_observations_default_unavailable() {
    let policy = sample_policy(1);
    // Empty revocation_observations -- all sources default to Unavailable
    let quote = AttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48),
        },
        quote_age_secs: 10,
        trust_root_id: "sgx-root-a".to_string(),
        revocation_observations: BTreeMap::new(),
    };
    let err = policy
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1))
        .unwrap_err();
    // The fail-closed internal_ledger source defaults to Unavailable
    assert!(matches!(
        err,
        TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
    ));
}

// =========================================================================
// TeeAttestationPolicyStore
// =========================================================================

#[test]
fn enrichment_store_default_halts_emission() {
    let store = TeeAttestationPolicyStore::default();
    assert!(store.receipt_emission_halted());
    assert_eq!(store.last_error_code(), Some("policy_not_loaded"));
    assert!(store.active_policy().is_none());
    assert!(store.governance_ledger().is_empty());
}

#[test]
fn enrichment_store_load_policy_success() {
    let mut store = TeeAttestationPolicyStore::default();
    let policy_id = store
        .load_policy(sample_policy(5), "trace-1", "decision-1")
        .unwrap();
    assert!(!store.receipt_emission_halted());
    assert!(store.last_error_code().is_none());
    assert!(store.active_policy().is_some());
    assert_eq!(store.active_policy().unwrap().policy_epoch, epoch(5));
    // Governance event emitted
    let events = store.governance_ledger();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "policy_loaded");
    assert_eq!(events[0].outcome, "allow");
    assert_eq!(events[0].error_code, "ok");
    assert_eq!(events[0].policy_id, policy_id.to_hex());
}

#[test]
fn enrichment_store_load_policy_json_success() {
    let mut store = TeeAttestationPolicyStore::default();
    let policy = sample_policy(20);
    let json = policy.to_canonical_json().unwrap();
    let policy_id = store
        .load_policy_json(&json, "trace-json", "decision-json")
        .unwrap();
    assert!(!store.receipt_emission_halted());
    assert_eq!(policy_id, policy.derive_policy_id().unwrap());
}

#[test]
fn enrichment_store_load_policy_json_invalid_halts() {
    let mut store = TeeAttestationPolicyStore::default();
    let err = store
        .load_policy_json("{bad", "trace-bad", "decision-bad")
        .unwrap_err();
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
    assert!(store.receipt_emission_halted());
    assert_eq!(
        store.last_error_code(),
        Some("tee_policy_parse_failed")
    );
    // Governance event for failure
    let events = store.governance_ledger();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "policy_load_failed");
    assert_eq!(events[0].outcome, "deny");
}

#[test]
fn enrichment_store_load_policy_epoch_regression_rejected() {
    let mut store = loaded_store(10);
    let err = store
        .load_policy(sample_policy(5), "trace-reg", "decision-reg")
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::PolicyEpochRegression { .. }
    ));
    assert!(store.receipt_emission_halted());
    assert_eq!(
        store.last_error_code(),
        Some("tee_policy_epoch_regression")
    );
}

#[test]
fn enrichment_store_load_policy_same_epoch_allowed() {
    let mut store = loaded_store(10);
    let result = store.load_policy(sample_policy(10), "trace-same", "decision-same");
    assert!(result.is_ok());
}

#[test]
fn enrichment_store_load_policy_higher_epoch_allowed() {
    let mut store = loaded_store(10);
    let result = store.load_policy(sample_policy(15), "trace-up", "decision-up");
    assert!(result.is_ok());
    assert_eq!(store.active_policy().unwrap().policy_epoch, epoch(15));
}

#[test]
fn enrichment_store_evaluate_quote_when_halted() {
    let mut store = TeeAttestationPolicyStore::default();
    let quote = sgx_quote(10);
    let err = store
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(1), "t-1", "d-1")
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
    assert_eq!(store.governance_ledger().len(), 1);
    assert_eq!(store.governance_ledger()[0].event, "quote_evaluation_failed");
}

#[test]
fn enrichment_store_evaluate_quote_success_emits_allow() {
    let mut store = loaded_store(5);
    let quote = sgx_quote(10);
    store
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(5), "t-eval", "d-eval")
        .unwrap();
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "quote_accepted");
    assert_eq!(last.outcome, "allow");
    assert_eq!(last.error_code, "ok");
    assert_eq!(last.trace_id, "t-eval");
    assert_eq!(last.decision_id, "d-eval");
    assert!(last.metadata.contains_key("platform"));
    assert!(last.metadata.contains_key("trust_root_id"));
}

#[test]
fn enrichment_store_evaluate_quote_rejection_emits_deny() {
    let mut store = loaded_store(5);
    let quote = sgx_quote(999); // stale
    let err = store
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(5), "t-rej", "d-rej")
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::AttestationStale { .. }
    ));
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "quote_rejected");
    assert_eq!(last.outcome, "deny");
    assert!(last.metadata.contains_key("reason"));
}

#[test]
fn enrichment_store_governance_ledger_accumulates() {
    let mut store = loaded_store(5);
    let initial_len = store.governance_ledger().len();
    let quote = sgx_quote(10);
    store
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(5), "t1", "d1")
        .unwrap();
    store
        .evaluate_quote(&quote, DecisionImpact::HighImpact, epoch(5), "t2", "d2")
        .unwrap();
    assert_eq!(store.governance_ledger().len(), initial_len + 2);
}

#[test]
fn enrichment_store_component_field_is_tee_attestation_policy() {
    let mut store = loaded_store(5);
    let quote = sgx_quote(10);
    store
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(5), "t1", "d1")
        .unwrap();
    for event in store.governance_ledger() {
        assert_eq!(event.component, "tee_attestation_policy");
    }
}

// =========================================================================
// SignedTrustRootOverrideArtifact
// =========================================================================

#[test]
fn enrichment_override_artifact_create_and_verify() {
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-temp", 10, 20);
    artifact.verify(&vk, epoch(15)).unwrap();
}

#[test]
fn enrichment_override_artifact_id_is_deterministic() {
    let sk = make_signing_key(7);
    let a1 = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-temp", 10, 20);
    let a2 = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-temp", 10, 20);
    assert_eq!(a1.artifact_id, a2.artifact_id);
}

#[test]
fn enrichment_override_artifact_id_differs_for_different_platform() {
    let sk = make_signing_key(7);
    let a1 = make_override_artifact(&sk, TeePlatform::IntelSgx, "root-temp", 10, 20);
    let a2 = make_override_artifact(&sk, TeePlatform::AmdSev, "root-temp", 10, 20);
    assert_ne!(a1.artifact_id, a2.artifact_id);
}

#[test]
fn enrichment_override_artifact_empty_actor_rejected() {
    let sk = make_signing_key(7);
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "root-1".to_string(),
            issued_epoch: epoch(1),
            expires_epoch: epoch(5),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn enrichment_override_artifact_whitespace_actor_rejected() {
    let sk = make_signing_key(7);
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "   ".to_string(),
            justification: "test".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "root-1".to_string(),
            issued_epoch: epoch(1),
            expires_epoch: epoch(5),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn enrichment_override_artifact_empty_justification_rejected() {
    let sk = make_signing_key(7);
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "operator".to_string(),
            justification: "".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "root-1".to_string(),
            issued_epoch: epoch(1),
            expires_epoch: epoch(5),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideJustificationMissing
    ));
}

#[test]
fn enrichment_override_artifact_whitespace_justification_rejected() {
    let sk = make_signing_key(7);
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "operator".to_string(),
            justification: "   ".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "root-1".to_string(),
            issued_epoch: epoch(1),
            expires_epoch: epoch(5),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideJustificationMissing
    ));
}

#[test]
fn enrichment_override_artifact_empty_target_root_id_rejected() {
    let sk = make_signing_key(7);
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "operator".to_string(),
            justification: "fix".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "".to_string(),
            issued_epoch: epoch(1),
            expires_epoch: epoch(5),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn enrichment_override_artifact_expires_before_issued_rejected() {
    let sk = make_signing_key(7);
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "operator".to_string(),
            justification: "fix".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "root-1".to_string(),
            issued_epoch: epoch(10),
            expires_epoch: epoch(5),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn enrichment_override_artifact_expires_equal_issued_rejected() {
    let sk = make_signing_key(7);
    let err = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "operator".to_string(),
            justification: "fix".to_string(),
            evidence_refs: vec![],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "root-1".to_string(),
            issued_epoch: epoch(10),
            expires_epoch: epoch(10),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn enrichment_override_artifact_evidence_refs_sorted_and_deduped() {
    let sk = make_signing_key(7);
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &sk,
        TrustRootOverrideArtifactInput {
            actor: "operator".to_string(),
            justification: "test dedup".to_string(),
            evidence_refs: vec![
                "z-ref".to_string(),
                "a-ref".to_string(),
                "z-ref".to_string(),
                "m-ref".to_string(),
            ],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "root-1".to_string(),
            issued_epoch: epoch(1),
            expires_epoch: epoch(5),
        },
    )
    .unwrap();
    assert_eq!(artifact.evidence_refs, vec!["a-ref", "m-ref", "z-ref"]);
}

#[test]
fn enrichment_override_artifact_verify_expired() {
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "root-1", 1, 5);
    let err = artifact.verify(&vk, epoch(6)).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideExpired { .. }
    ));
}

#[test]
fn enrichment_override_artifact_verify_at_exact_expiry_rejected() {
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "root-1", 1, 5);
    let err = artifact.verify(&vk, epoch(5)).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideExpired { .. }
    ));
}

#[test]
fn enrichment_override_artifact_verify_tampered_rejected() {
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let mut artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "root-1", 1, 5);
    artifact.justification = "tampered".to_string();
    let err = artifact.verify(&vk, epoch(2)).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideSignatureInvalid { .. }
    ));
}

#[test]
fn enrichment_override_artifact_verify_wrong_key_rejected() {
    let sk = make_signing_key(7);
    let wrong_sk = make_signing_key(8);
    let wrong_vk = wrong_sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "root-1", 1, 5);
    let err = artifact.verify(&wrong_vk, epoch(2)).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideSignatureInvalid { .. }
    ));
}

#[test]
fn enrichment_override_artifact_serde_roundtrip() {
    let sk = make_signing_key(7);
    let artifact = make_override_artifact(&sk, TeePlatform::ArmCca, "cca-temp", 1, 10);
    let json = serde_json::to_string(&artifact).unwrap();
    let parsed: SignedTrustRootOverrideArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, parsed);
}

// =========================================================================
// TemporaryTrustRootOverride
// =========================================================================

#[test]
fn enrichment_temp_override_serde_roundtrip() {
    let sk = make_signing_key(7);
    let artifact = make_override_artifact(&sk, TeePlatform::ArmCca, "cca-temp", 1, 10);
    let req = TemporaryTrustRootOverride {
        override_id: "ovr-serde-test".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "cca-temp".to_string(),
            platform: TeePlatform::ArmCca,
            trust_anchor_pem: "-----BEGIN CERT-----CCA-TEMP".to_string(),
            valid_from_epoch: epoch(1),
            valid_until_epoch: Some(epoch(10)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "cca-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: TemporaryTrustRootOverride = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

// =========================================================================
// Store -- apply_temporary_trust_root_override
// =========================================================================

#[test]
fn enrichment_store_apply_override_success() {
    let mut store = loaded_store(10);
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-temp-ovr", 10, 20);
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-apply".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp-ovr".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP-OVR".to_string(),
            valid_from_epoch: epoch(10),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    let policy_id = store
        .apply_temporary_trust_root_override(request, &vk, epoch(10), "t-ovr", "d-ovr")
        .unwrap();
    assert!(!store.receipt_emission_halted());
    let active = store.active_policy().unwrap();
    let temp_root = active
        .platform_trust_roots
        .iter()
        .find(|r| r.root_id == "sgx-temp-ovr")
        .unwrap();
    assert!(matches!(
        temp_root.source,
        TrustRootSource::TemporaryOverride { .. }
    ));
    // Expiry should be capped
    assert!(temp_root.valid_until_epoch.is_some());
    // Governance event emitted
    let last = store.governance_ledger().last().unwrap();
    assert_eq!(last.event, "temporary_trust_root_override_applied");
    assert_eq!(last.outcome, "allow");
    assert_eq!(last.policy_id, policy_id.to_hex());
}

#[test]
fn enrichment_store_apply_override_no_active_policy_rejected() {
    let mut store = TeeAttestationPolicyStore::default();
    // Manually unset halted but leave no policy
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-root-1", 1, 5);
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-nop".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-root-1".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----".to_string(),
            valid_from_epoch: epoch(1),
            valid_until_epoch: Some(epoch(5)),
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    let err = store
        .apply_temporary_trust_root_override(request, &vk, epoch(1), "t-nop", "d-nop")
        .unwrap_err();
    assert!(matches!(err, TeeAttestationPolicyError::NoActivePolicy));
}

#[test]
fn enrichment_store_apply_override_empty_override_id_rejected() {
    let mut store = loaded_store(10);
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-temp-eid", 10, 20);
    let request = TemporaryTrustRootOverride {
        override_id: "".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp-eid".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----".to_string(),
            valid_from_epoch: epoch(10),
            valid_until_epoch: Some(epoch(20)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    let err = store
        .apply_temporary_trust_root_override(request, &vk, epoch(10), "t-eid", "d-eid")
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
    ));
}

#[test]
fn enrichment_store_apply_override_target_mismatch_rejected() {
    let mut store = loaded_store(10);
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    // Artifact targets AmdSev, trust_root is IntelSgx
    let artifact = make_override_artifact(&sk, TeePlatform::AmdSev, "sev-temp", 10, 20);
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-mm".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----".to_string(),
            valid_from_epoch: epoch(10),
            valid_until_epoch: Some(epoch(20)),
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    let err = store
        .apply_temporary_trust_root_override(request, &vk, epoch(10), "t-mm", "d-mm")
        .unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::OverrideTargetMismatch { .. }
    ));
}

#[test]
fn enrichment_store_apply_override_replaces_existing_root() {
    let mut store = loaded_store(10);
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    // Override the existing sgx-root-a (which is pinned)
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-root-a", 10, 20);
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-replace".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-root-a".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-REPLACED".to_string(),
            valid_from_epoch: epoch(0),
            valid_until_epoch: Some(epoch(20)),
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    store
        .apply_temporary_trust_root_override(request, &vk, epoch(10), "t-rep", "d-rep")
        .unwrap();
    let active = store.active_policy().unwrap();
    let sgx_roots: Vec<_> = active
        .platform_trust_roots
        .iter()
        .filter(|r| r.platform == TeePlatform::IntelSgx && r.root_id == "sgx-root-a")
        .collect();
    assert_eq!(sgx_roots.len(), 1);
    assert!(matches!(
        sgx_roots[0].source,
        TrustRootSource::TemporaryOverride { .. }
    ));
}

#[test]
fn enrichment_store_apply_override_caps_expiry_to_artifact_expires() {
    let mut store = loaded_store(10);
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    // Artifact expires at 15, trust root says valid_until 25 -- should cap to 15
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-capped", 10, 15);
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-cap".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-capped".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-CAPPED".to_string(),
            valid_from_epoch: epoch(10),
            valid_until_epoch: Some(epoch(25)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    store
        .apply_temporary_trust_root_override(request, &vk, epoch(10), "t-cap", "d-cap")
        .unwrap();
    let active = store.active_policy().unwrap();
    let capped_root = active
        .platform_trust_roots
        .iter()
        .find(|r| r.root_id == "sgx-capped")
        .unwrap();
    assert_eq!(capped_root.valid_until_epoch, Some(epoch(15)));
}

// =========================================================================
// DecisionReceiptEmitter
// =========================================================================

#[test]
fn enrichment_emitter_new_no_synced_epoch() {
    let emitter = DecisionReceiptEmitter::new("emitter-test");
    assert_eq!(emitter.emitter_id, "emitter-test");
    assert!(emitter.last_synced_policy_epoch.is_none());
}

#[test]
fn enrichment_emitter_serde_roundtrip() {
    let mut emitter = DecisionReceiptEmitter::new("e-serde");
    emitter.last_synced_policy_epoch = Some(epoch(42));
    let json = serde_json::to_string(&emitter).unwrap();
    let parsed: DecisionReceiptEmitter = serde_json::from_str(&json).unwrap();
    assert_eq!(emitter, parsed);
}

#[test]
fn enrichment_emitter_serde_roundtrip_no_epoch() {
    let emitter = DecisionReceiptEmitter::new("e-none");
    let json = serde_json::to_string(&emitter).unwrap();
    let parsed: DecisionReceiptEmitter = serde_json::from_str(&json).unwrap();
    assert_eq!(emitter, parsed);
}

#[test]
fn enrichment_emitter_sync_when_halted_fails() {
    let mut emitter = DecisionReceiptEmitter::new("e-halt");
    let store = TeeAttestationPolicyStore::default();
    let err = emitter.sync_policy(&store).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
}

#[test]
fn enrichment_emitter_sync_sets_epoch() {
    let mut emitter = DecisionReceiptEmitter::new("e-sync");
    let store = loaded_store(7);
    let synced_epoch = emitter.sync_policy(&store).unwrap();
    assert_eq!(synced_epoch, epoch(7));
    assert_eq!(emitter.last_synced_policy_epoch, Some(epoch(7)));
}

#[test]
fn enrichment_emitter_sync_updates_epoch_on_policy_upgrade() {
    let mut emitter = DecisionReceiptEmitter::new("e-upgrade");
    let mut store = loaded_store(5);
    emitter.sync_policy(&store).unwrap();
    assert_eq!(emitter.last_synced_policy_epoch, Some(epoch(5)));
    store
        .load_policy(sample_policy(10), "t-up", "d-up")
        .unwrap();
    let new_epoch = emitter.sync_policy(&store).unwrap();
    assert_eq!(new_epoch, epoch(10));
    assert_eq!(emitter.last_synced_policy_epoch, Some(epoch(10)));
}

#[test]
fn enrichment_emitter_can_emit_not_synced_fails() {
    let emitter = DecisionReceiptEmitter::new("e-notsync");
    let store = loaded_store(5);
    let err = emitter.can_emit(epoch(5), &store).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterNotSynced { .. }
    ));
}

#[test]
fn enrichment_emitter_can_emit_same_epoch_passes() {
    let mut emitter = DecisionReceiptEmitter::new("e-same");
    let store = loaded_store(5);
    emitter.sync_policy(&store).unwrap();
    emitter.can_emit(epoch(5), &store).unwrap();
}

#[test]
fn enrichment_emitter_can_emit_one_behind_passes() {
    let mut emitter = DecisionReceiptEmitter::new("e-behind");
    let mut store = loaded_store(5);
    emitter.sync_policy(&store).unwrap();
    store
        .load_policy(sample_policy(6), "t-6", "d-6")
        .unwrap();
    // Synced at 5, active is 6 -- one behind is OK
    emitter.can_emit(epoch(6), &store).unwrap();
}

#[test]
fn enrichment_emitter_can_emit_two_behind_fails() {
    let mut emitter = DecisionReceiptEmitter::new("e-stale");
    let mut store = loaded_store(5);
    emitter.sync_policy(&store).unwrap();
    store
        .load_policy(sample_policy(10), "t-10", "d-10")
        .unwrap();
    let err = emitter.can_emit(epoch(10), &store).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterPolicyStale { .. }
    ));
}

#[test]
fn enrichment_emitter_can_emit_runtime_epoch_too_far_ahead() {
    let mut emitter = DecisionReceiptEmitter::new("e-rt");
    let store = loaded_store(5);
    emitter.sync_policy(&store).unwrap();
    // Runtime epoch is 2 ahead of synced (5) -> fail
    let err = emitter.can_emit(epoch(7), &store).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterPolicyStale { .. }
    ));
}

#[test]
fn enrichment_emitter_can_emit_when_halted_fails() {
    let mut emitter = DecisionReceiptEmitter::new("e-halt");
    emitter.last_synced_policy_epoch = Some(epoch(5));
    let store = TeeAttestationPolicyStore::default(); // halted
    let err = emitter.can_emit(epoch(5), &store).unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
}

// =========================================================================
// TeeAttestationPolicyError -- error_code + Display
// =========================================================================

#[test]
fn enrichment_error_code_parse_failed() {
    let err = TeeAttestationPolicyError::ParseFailed {
        detail: "bad json".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
    assert!(err.to_string().contains("parse failed"));
}

#[test]
fn enrichment_error_code_serialization_failed() {
    let err = TeeAttestationPolicyError::SerializationFailed {
        detail: "encode error".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_serialize_failed");
    assert!(err.to_string().contains("serialization failed"));
}

#[test]
fn enrichment_error_code_missing_measurements() {
    let err = TeeAttestationPolicyError::MissingMeasurementsForPlatform {
        platform: TeePlatform::ArmCca,
    };
    assert_eq!(err.error_code(), "tee_policy_missing_measurements");
    assert!(err.to_string().contains("arm_cca"));
}

#[test]
fn enrichment_error_code_invalid_measurement_digest() {
    let err = TeeAttestationPolicyError::InvalidMeasurementDigest {
        platform: TeePlatform::AmdSev,
        digest: "abc".to_string(),
        expected_hex_len: 96,
    };
    assert_eq!(err.error_code(), "tee_policy_invalid_measurement_digest");
    assert!(err.to_string().contains("abc"));
}

#[test]
fn enrichment_error_code_duplicate_measurement_digest() {
    let err = TeeAttestationPolicyError::DuplicateMeasurementDigest {
        platform: TeePlatform::IntelSgx,
        digest: "dd".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_duplicate_measurement_digest");
}

#[test]
fn enrichment_error_code_invalid_freshness_window() {
    let err = TeeAttestationPolicyError::InvalidFreshnessWindow {
        standard_max_age_secs: 0,
        high_impact_max_age_secs: 0,
    };
    assert_eq!(err.error_code(), "tee_policy_invalid_freshness_window");
}

#[test]
fn enrichment_error_code_empty_revocation_sources() {
    let err = TeeAttestationPolicyError::EmptyRevocationSources;
    assert_eq!(err.error_code(), "tee_policy_empty_revocation_sources");
    assert!(err.to_string().contains("empty"));
}

#[test]
fn enrichment_error_code_invalid_revocation_source() {
    let err = TeeAttestationPolicyError::InvalidRevocationSource {
        reason: "test reason".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_invalid_revocation_source");
    assert!(err.to_string().contains("test reason"));
}

#[test]
fn enrichment_error_code_duplicate_revocation_source() {
    let err = TeeAttestationPolicyError::DuplicateRevocationSource {
        source_id: "src-dup".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_duplicate_revocation_source");
    assert!(err.to_string().contains("src-dup"));
}

#[test]
fn enrichment_error_code_revocation_fallback_bypass() {
    let err = TeeAttestationPolicyError::RevocationFallbackBypass;
    assert_eq!(err.error_code(), "tee_policy_revocation_bypass_config");
    assert!(err.to_string().contains("no fail-closed"));
}

#[test]
fn enrichment_error_code_missing_trust_roots() {
    let err = TeeAttestationPolicyError::MissingTrustRoots;
    assert_eq!(err.error_code(), "tee_policy_missing_trust_roots");
}

#[test]
fn enrichment_error_code_invalid_trust_root() {
    let err = TeeAttestationPolicyError::InvalidTrustRoot {
        root_id: "root-x".to_string(),
        reason: "empty pem".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_invalid_trust_root");
    assert!(err.to_string().contains("root-x"));
}

#[test]
fn enrichment_error_code_duplicate_trust_root() {
    let err = TeeAttestationPolicyError::DuplicateTrustRoot {
        platform: TeePlatform::IntelSgx,
        root_id: "dup-root".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_duplicate_trust_root");
}

#[test]
fn enrichment_error_code_missing_pinned_trust_root() {
    let err = TeeAttestationPolicyError::MissingPinnedTrustRoot {
        platform: TeePlatform::ArmTrustZone,
    };
    assert_eq!(err.error_code(), "tee_policy_missing_pinned_trust_root");
    assert!(err.to_string().contains("arm_trustzone"));
}

#[test]
fn enrichment_error_code_policy_epoch_regression() {
    let err = TeeAttestationPolicyError::PolicyEpochRegression {
        current: epoch(10),
        attempted: epoch(5),
    };
    assert_eq!(err.error_code(), "tee_policy_epoch_regression");
    assert!(err.to_string().contains("regression"));
}

#[test]
fn enrichment_error_code_receipt_emission_halted() {
    let err = TeeAttestationPolicyError::ReceiptEmissionHalted;
    assert_eq!(err.error_code(), "tee_policy_emission_halted");
    assert!(err.to_string().contains("fail-closed"));
}

#[test]
fn enrichment_error_code_no_active_policy() {
    let err = TeeAttestationPolicyError::NoActivePolicy;
    assert_eq!(err.error_code(), "tee_policy_not_loaded");
}

#[test]
fn enrichment_error_code_unknown_measurement_digest() {
    let err = TeeAttestationPolicyError::UnknownMeasurementDigest {
        platform: TeePlatform::IntelSgx,
        digest: "dd".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_measurement_not_approved");
}

#[test]
fn enrichment_error_code_attestation_stale() {
    let err = TeeAttestationPolicyError::AttestationStale {
        quote_age_secs: 500,
        max_age_secs: 300,
    };
    assert_eq!(err.error_code(), "tee_policy_attestation_stale");
    assert!(err.to_string().contains("500"));
    assert!(err.to_string().contains("300"));
}

#[test]
fn enrichment_error_code_unknown_trust_root() {
    let err = TeeAttestationPolicyError::UnknownTrustRoot {
        platform: TeePlatform::AmdSev,
        root_id: "unknown-root".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_unknown_trust_root");
    assert!(err.to_string().contains("unknown-root"));
}

#[test]
fn enrichment_error_code_expired_trust_root() {
    let err = TeeAttestationPolicyError::ExpiredTrustRoot {
        root_id: "expired-root".to_string(),
        runtime_epoch: epoch(10),
        valid_until_epoch: Some(epoch(5)),
    };
    assert_eq!(err.error_code(), "tee_policy_expired_trust_root");
    assert!(err.to_string().contains("expired-root"));
}

#[test]
fn enrichment_error_code_revoked_by_source() {
    let err = TeeAttestationPolicyError::RevokedBySource {
        source_id: "revoked-src".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_revoked");
    assert!(err.to_string().contains("revoked-src"));
}

#[test]
fn enrichment_error_code_revocation_source_unavailable() {
    let err = TeeAttestationPolicyError::RevocationSourceUnavailable {
        source_id: "unavail-src".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_revocation_source_unavailable");
}

#[test]
fn enrichment_error_code_revocation_evidence_unavailable() {
    let err = TeeAttestationPolicyError::RevocationEvidenceUnavailable;
    assert_eq!(err.error_code(), "tee_policy_revocation_evidence_unavailable");
    assert!(err.to_string().contains("fallback chain"));
}

#[test]
fn enrichment_error_code_invalid_override_artifact() {
    let err = TeeAttestationPolicyError::InvalidOverrideArtifact {
        reason: "actor is empty".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_override_artifact_invalid");
}

#[test]
fn enrichment_error_code_override_justification_missing() {
    let err = TeeAttestationPolicyError::OverrideJustificationMissing;
    assert_eq!(err.error_code(), "tee_policy_override_justification_missing");
}

#[test]
fn enrichment_error_code_override_expired() {
    let err = TeeAttestationPolicyError::OverrideExpired {
        current_epoch: epoch(10),
        expires_epoch: epoch(5),
    };
    assert_eq!(err.error_code(), "tee_policy_override_expired");
}

#[test]
fn enrichment_error_code_override_signature_invalid() {
    let err = TeeAttestationPolicyError::OverrideSignatureInvalid {
        detail: "bad sig".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_override_signature_invalid");
}

#[test]
fn enrichment_error_code_override_target_mismatch() {
    let err = TeeAttestationPolicyError::OverrideTargetMismatch {
        expected_platform: TeePlatform::IntelSgx,
        expected_root_id: "r1".to_string(),
        actual_platform: TeePlatform::AmdSev,
        actual_root_id: "r2".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_override_target_mismatch");
    assert!(err.to_string().contains("intel_sgx"));
    assert!(err.to_string().contains("amd_sev"));
}

#[test]
fn enrichment_error_code_emitter_not_synced() {
    let err = TeeAttestationPolicyError::EmitterNotSynced {
        emitter_id: "e-unsync".to_string(),
    };
    assert_eq!(err.error_code(), "tee_policy_emitter_not_synced");
    assert!(err.to_string().contains("e-unsync"));
}

#[test]
fn enrichment_error_code_emitter_policy_stale() {
    let err = TeeAttestationPolicyError::EmitterPolicyStale {
        emitter_id: "e-old".to_string(),
        synced_epoch: epoch(3),
        required_epoch: epoch(5),
    };
    assert_eq!(err.error_code(), "tee_policy_emitter_stale");
    assert!(err.to_string().contains("e-old"));
}

#[test]
fn enrichment_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(TeeAttestationPolicyError::NoActivePolicy);
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_error_serde_roundtrip_all_variants() {
    let variants: Vec<TeeAttestationPolicyError> = vec![
        TeeAttestationPolicyError::ParseFailed {
            detail: "bad".to_string(),
        },
        TeeAttestationPolicyError::SerializationFailed {
            detail: "err".to_string(),
        },
        TeeAttestationPolicyError::MissingMeasurementsForPlatform {
            platform: TeePlatform::IntelSgx,
        },
        TeeAttestationPolicyError::InvalidMeasurementDigest {
            platform: TeePlatform::ArmCca,
            digest: "abc".to_string(),
            expected_hex_len: 64,
        },
        TeeAttestationPolicyError::DuplicateMeasurementDigest {
            platform: TeePlatform::AmdSev,
            digest: "dd".to_string(),
        },
        TeeAttestationPolicyError::InvalidFreshnessWindow {
            standard_max_age_secs: 0,
            high_impact_max_age_secs: 0,
        },
        TeeAttestationPolicyError::EmptyRevocationSources,
        TeeAttestationPolicyError::InvalidRevocationSource {
            reason: "test".to_string(),
        },
        TeeAttestationPolicyError::DuplicateRevocationSource {
            source_id: "s".to_string(),
        },
        TeeAttestationPolicyError::RevocationFallbackBypass,
        TeeAttestationPolicyError::MissingTrustRoots,
        TeeAttestationPolicyError::InvalidTrustRoot {
            root_id: "r".to_string(),
            reason: "bad".to_string(),
        },
        TeeAttestationPolicyError::DuplicateTrustRoot {
            platform: TeePlatform::IntelSgx,
            root_id: "r".to_string(),
        },
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::IntelSgx,
        },
        TeeAttestationPolicyError::PolicyEpochRegression {
            current: epoch(5),
            attempted: epoch(3),
        },
        TeeAttestationPolicyError::IdDerivationFailed {
            detail: "fail".to_string(),
        },
        TeeAttestationPolicyError::ReceiptEmissionHalted,
        TeeAttestationPolicyError::NoActivePolicy,
        TeeAttestationPolicyError::UnknownMeasurementDigest {
            platform: TeePlatform::IntelSgx,
            digest: "dd".to_string(),
        },
        TeeAttestationPolicyError::AttestationStale {
            quote_age_secs: 500,
            max_age_secs: 300,
        },
        TeeAttestationPolicyError::UnknownTrustRoot {
            platform: TeePlatform::IntelSgx,
            root_id: "r".to_string(),
        },
        TeeAttestationPolicyError::ExpiredTrustRoot {
            root_id: "r".to_string(),
            runtime_epoch: epoch(10),
            valid_until_epoch: Some(epoch(5)),
        },
        TeeAttestationPolicyError::RevokedBySource {
            source_id: "s".to_string(),
        },
        TeeAttestationPolicyError::RevocationSourceUnavailable {
            source_id: "s".to_string(),
        },
        TeeAttestationPolicyError::RevocationEvidenceUnavailable,
        TeeAttestationPolicyError::InvalidOverrideArtifact {
            reason: "bad".to_string(),
        },
        TeeAttestationPolicyError::OverrideJustificationMissing,
        TeeAttestationPolicyError::OverrideExpired {
            current_epoch: epoch(10),
            expires_epoch: epoch(5),
        },
        TeeAttestationPolicyError::OverrideSignatureInvalid {
            detail: "bad".to_string(),
        },
        TeeAttestationPolicyError::OverrideTargetMismatch {
            expected_platform: TeePlatform::IntelSgx,
            expected_root_id: "r1".to_string(),
            actual_platform: TeePlatform::AmdSev,
            actual_root_id: "r2".to_string(),
        },
        TeeAttestationPolicyError::EmitterNotSynced {
            emitter_id: "e".to_string(),
        },
        TeeAttestationPolicyError::EmitterPolicyStale {
            emitter_id: "e".to_string(),
            synced_epoch: epoch(3),
            required_epoch: epoch(5),
        },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let parsed: TeeAttestationPolicyError = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, &parsed);
        assert!(!variant.error_code().is_empty());
        assert!(!variant.to_string().is_empty());
    }
}

// =========================================================================
// ContentHash integration
// =========================================================================

#[test]
fn enrichment_policy_canonical_json_content_hash_deterministic() {
    let policy = sample_policy(42);
    let json1 = policy.to_canonical_json().unwrap();
    let json2 = policy.to_canonical_json().unwrap();
    assert_eq!(json1, json2);
    let hash1 = ContentHash::compute(json1.as_bytes());
    let hash2 = ContentHash::compute(json2.as_bytes());
    assert_eq!(hash1, hash2);
}

#[test]
fn enrichment_policy_canonical_json_hash_differs_for_different_policies() {
    let p1 = sample_policy(1);
    let p2 = sample_policy(2);
    let hash1 = ContentHash::compute(p1.to_canonical_json().unwrap().as_bytes());
    let hash2 = ContentHash::compute(p2.to_canonical_json().unwrap().as_bytes());
    assert_ne!(hash1, hash2);
}

// =========================================================================
// Workflow: full lifecycle
// =========================================================================

#[test]
fn enrichment_full_lifecycle_load_evaluate_override_evaluate() {
    let mut store = TeeAttestationPolicyStore::default();

    // Step 1: load policy
    let policy_id = store
        .load_policy(sample_policy(10), "trace-lc-1", "decision-lc-1")
        .unwrap();
    assert!(!store.receipt_emission_halted());
    assert_eq!(store.governance_ledger().len(), 1);
    assert_eq!(store.governance_ledger()[0].event, "policy_loaded");

    // Step 2: evaluate a valid quote
    let quote = sgx_quote(5);
    store
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(10), "trace-lc-2", "decision-lc-2")
        .unwrap();
    assert_eq!(store.governance_ledger().len(), 2);
    assert_eq!(store.governance_ledger()[1].event, "quote_accepted");

    // Step 3: apply temporary override
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-temp-lc", 10, 20);
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-lc".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-temp-lc".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP-LC".to_string(),
            valid_from_epoch: epoch(10),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-lc-grp".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    let new_policy_id = store
        .apply_temporary_trust_root_override(request, &vk, epoch(10), "trace-lc-3", "decision-lc-3")
        .unwrap();
    assert_ne!(policy_id, new_policy_id);
    assert_eq!(store.governance_ledger().len(), 3);
    assert_eq!(
        store.governance_ledger()[2].event,
        "temporary_trust_root_override_applied"
    );

    // Step 4: evaluate a quote against the temp root
    let temp_quote = quote_for_platform(
        TeePlatform::IntelSgx,
        MeasurementAlgorithm::Sha384,
        0x11,
        48,
        "sgx-temp-lc",
        5,
    );
    store
        .evaluate_quote(
            &temp_quote,
            DecisionImpact::HighImpact,
            epoch(10),
            "trace-lc-4",
            "decision-lc-4",
        )
        .unwrap();
    assert_eq!(store.governance_ledger().len(), 4);
    assert_eq!(store.governance_ledger()[3].event, "quote_accepted");
}

#[test]
fn enrichment_lifecycle_emitter_sync_and_emit() {
    let mut store = loaded_store(5);
    let mut emitter = DecisionReceiptEmitter::new("emitter-lc");

    // Cannot emit before sync
    assert!(emitter.can_emit(epoch(5), &store).is_err());

    // Sync
    emitter.sync_policy(&store).unwrap();
    emitter.can_emit(epoch(5), &store).unwrap();

    // Upgrade policy
    store
        .load_policy(sample_policy(6), "t-6", "d-6")
        .unwrap();
    // Still OK -- one behind
    emitter.can_emit(epoch(6), &store).unwrap();

    // Upgrade again -- now two behind
    store
        .load_policy(sample_policy(7), "t-7", "d-7")
        .unwrap();
    assert!(emitter.can_emit(epoch(7), &store).is_err());

    // Re-sync fixes it
    emitter.sync_policy(&store).unwrap();
    emitter.can_emit(epoch(7), &store).unwrap();
}

// =========================================================================
// Multiple measurements per platform
// =========================================================================

#[test]
fn enrichment_policy_multiple_measurements_per_platform() {
    let mut policy = sample_policy(1);
    let extra_digest = MeasurementDigest {
        algorithm: MeasurementAlgorithm::Sha256,
        digest_hex: digest_hex(0x55, 32),
    };
    policy
        .approved_measurements
        .get_mut(&TeePlatform::IntelSgx)
        .unwrap()
        .push(extra_digest);
    policy.validate().unwrap();

    // Original measurement still passes
    let quote1 = sgx_quote(10);
    policy
        .evaluate_quote(&quote1, DecisionImpact::Standard, epoch(1))
        .unwrap();

    // New measurement also passes
    let quote2 = quote_for_platform(
        TeePlatform::IntelSgx,
        MeasurementAlgorithm::Sha256,
        0x55,
        32,
        "sgx-root-a",
        10,
    );
    policy
        .evaluate_quote(&quote2, DecisionImpact::Standard, epoch(1))
        .unwrap();
}

// =========================================================================
// Store serde
// =========================================================================

#[test]
fn enrichment_store_serde_roundtrip() {
    let mut store = loaded_store(3);
    let quote = sgx_quote(10);
    store
        .evaluate_quote(&quote, DecisionImpact::Standard, epoch(3), "t-s", "d-s")
        .unwrap();
    let json = serde_json::to_string(&store).unwrap();
    let parsed: TeeAttestationPolicyStore = serde_json::from_str(&json).unwrap();
    assert_eq!(
        store.receipt_emission_halted(),
        parsed.receipt_emission_halted()
    );
    assert_eq!(store.last_error_code(), parsed.last_error_code());
    assert_eq!(
        store.governance_ledger().len(),
        parsed.governance_ledger().len()
    );
    assert_eq!(
        store.active_policy().unwrap().policy_epoch,
        parsed.active_policy().unwrap().policy_epoch
    );
}

// =========================================================================
// Fixed-point / determinism validation
// =========================================================================

#[test]
fn enrichment_fixed_point_millionths_freshness_arithmetic() {
    let window = AttestationFreshnessWindow {
        standard_max_age_secs: 1_000_000, // 1.0 in fixed-point millionths
        high_impact_max_age_secs: 500_000,
    };
    let mut policy = sample_policy(1);
    policy.freshness_window = window;
    policy.validate().unwrap();
}

#[test]
fn enrichment_policy_id_reproducible_across_clones() {
    let policy = sample_policy(99);
    let clone1 = policy.clone();
    let clone2 = policy.clone();
    let id1 = clone1.derive_policy_id().unwrap();
    let id2 = clone2.derive_policy_id().unwrap();
    assert_eq!(id1, id2);
}

// =========================================================================
// Edge case: pinned root not active at policy epoch
// =========================================================================

#[test]
fn enrichment_pinned_root_not_active_at_policy_epoch_rejected() {
    let mut policy = sample_policy(10);
    // Set SGX root valid_from after policy epoch
    policy
        .platform_trust_roots
        .iter_mut()
        .find(|r| r.platform == TeePlatform::IntelSgx)
        .unwrap()
        .valid_from_epoch = epoch(20);
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::IntelSgx
        }
    ));
}

#[test]
fn enrichment_pinned_root_expired_before_policy_epoch_rejected() {
    let mut policy = sample_policy(10);
    let sgx_root = policy
        .platform_trust_roots
        .iter_mut()
        .find(|r| r.platform == TeePlatform::IntelSgx)
        .unwrap();
    sgx_root.valid_until_epoch = Some(epoch(5));
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        TeeAttestationPolicyError::MissingPinnedTrustRoot {
            platform: TeePlatform::IntelSgx
        }
    ));
}

// =========================================================================
// Governance events metadata
// =========================================================================

#[test]
fn enrichment_governance_event_load_contains_policy_epoch_metadata() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(42), "t-meta", "d-meta")
        .unwrap();
    let event = &store.governance_ledger()[0];
    assert_eq!(event.metadata.get("policy_epoch").unwrap(), "42");
    assert_eq!(event.metadata.get("schema_version").unwrap(), "1");
}

#[test]
fn enrichment_governance_event_override_contains_override_metadata() {
    let mut store = loaded_store(10);
    let sk = make_signing_key(7);
    let vk = sk.verification_key();
    let artifact = make_override_artifact(&sk, TeePlatform::IntelSgx, "sgx-meta-ovr", 10, 20);
    let request = TemporaryTrustRootOverride {
        override_id: "ovr-meta".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-meta-ovr".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----META".to_string(),
            valid_from_epoch: epoch(10),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "meta-grp".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };
    store
        .apply_temporary_trust_root_override(request, &vk, epoch(10), "t-meta-ovr", "d-meta-ovr")
        .unwrap();
    let last = store.governance_ledger().last().unwrap();
    assert!(last.metadata.contains_key("override_id"));
    assert!(last.metadata.contains_key("justification_artifact_id"));
    assert!(last.metadata.contains_key("expires_epoch"));
}

#[test]
fn enrichment_governance_event_failure_contains_reason() {
    let mut store = TeeAttestationPolicyStore::default();
    let _ = store.load_policy_json("{bad", "t-fail", "d-fail");
    let event = &store.governance_ledger()[0];
    assert!(event.metadata.contains_key("reason"));
    assert!(!event.metadata["reason"].is_empty());
}
