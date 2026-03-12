//! Integration tests for `attested_execution_cell` — edge cases and gaps
//! not covered by inline unit tests.

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

use frankenengine_engine::attested_execution_cell::{
    AttestationQuote, CellError, CellEvent, CellEventType, CellFunction, CellLifecycle,
    CellRegistry, CreateCellInput, ExecutionCell, FallbackPolicy, LifecycleReceipt,
    MeasurementDigest, PlatformKind, SoftwareTrustRoot, TrustLevel, TrustRootBackend,
    VerificationResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_root(key_id: &str, seed: u64) -> SoftwareTrustRoot {
    SoftwareTrustRoot::new(key_id, seed)
}

fn auth(caps: &[&str]) -> BTreeSet<String> {
    caps.iter().map(|s| s.to_string()).collect()
}

fn cell_input(label: &str, func: CellFunction, zone: &str, ep: SecurityEpoch) -> CreateCellInput {
    CreateCellInput {
        label: label.to_string(),
        function: func,
        zone: zone.to_string(),
        epoch: ep,
        trust_level: TrustLevel::SoftwareOnly,
        authority_envelope: auth(&["sign", "emit"]),
    }
}

fn measure(root: &SoftwareTrustRoot) -> MeasurementDigest {
    root.measure(
        b"code-v1",
        b"config-v1",
        b"policy-v1",
        b"schema-v1",
        "1.0.0",
    )
}

fn quote_at(
    root: &SoftwareTrustRoot,
    measurement: &MeasurementDigest,
    nonce: [u8; 32],
    issued_at_ns: u64,
    validity_window_ns: u64,
) -> AttestationQuote {
    root.attest(measurement, nonce, validity_window_ns, issued_at_ns)
}

/// Drive a cell from Provisioning all the way to Active and return its string id.
fn activate_cell(
    reg: &mut CellRegistry,
    root: &SoftwareTrustRoot,
    label: &str,
    func: CellFunction,
    zone: &str,
    ep: SecurityEpoch,
    base_ts: u64,
) -> String {
    let id = reg
        .create_cell(cell_input(label, func, zone, ep), base_ts)
        .unwrap();
    let cid = format!("{id}");
    let m = measure(root);
    reg.measure_cell(&cid, m.clone(), base_ts + 1, ep).unwrap();
    let q = quote_at(root, &m, [7u8; 32], base_ts + 1, 10_000_000);
    reg.attest_cell(&cid, q, base_ts + 2, ep).unwrap();
    reg.activate_cell(&cid, base_ts + 3, ep).unwrap();
    cid
}

// ===========================================================================
// CellLifecycle — serde all variants, ordering, hash stability
// ===========================================================================

#[test]
fn lifecycle_serde_all_variants() {
    let variants = [
        CellLifecycle::Provisioning,
        CellLifecycle::Measured,
        CellLifecycle::Attested,
        CellLifecycle::Active,
        CellLifecycle::Suspended,
        CellLifecycle::Decommissioned,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: CellLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn lifecycle_ordering_matches_discriminants() {
    assert!(CellLifecycle::Provisioning < CellLifecycle::Measured);
    assert!(CellLifecycle::Measured < CellLifecycle::Attested);
    assert!(CellLifecycle::Attested < CellLifecycle::Active);
    assert!(CellLifecycle::Active < CellLifecycle::Suspended);
    assert!(CellLifecycle::Suspended < CellLifecycle::Decommissioned);
}

#[test]
fn lifecycle_hash_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    CellLifecycle::Active.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    CellLifecycle::Active.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn lifecycle_clone_eq() {
    let a = CellLifecycle::Suspended;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// TrustLevel — serde, ordering, hash
// ===========================================================================

#[test]
fn trust_level_serde_all_variants() {
    for v in &[
        TrustLevel::SoftwareOnly,
        TrustLevel::Hybrid,
        TrustLevel::Hardware,
    ] {
        let json = serde_json::to_string(v).unwrap();
        let restored: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn trust_level_ordering() {
    assert!(TrustLevel::SoftwareOnly < TrustLevel::Hybrid);
    assert!(TrustLevel::Hybrid < TrustLevel::Hardware);
}

#[test]
fn trust_level_hash_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    TrustLevel::Hardware.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    TrustLevel::Hardware.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

// ===========================================================================
// PlatformKind — serde, ordering, hash
// ===========================================================================

#[test]
fn platform_kind_serde_all_variants() {
    for v in &[
        PlatformKind::IntelSgx,
        PlatformKind::ArmCca,
        PlatformKind::AmdSevSnp,
        PlatformKind::Software,
    ] {
        let json = serde_json::to_string(v).unwrap();
        let restored: PlatformKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn platform_kind_display_all() {
    assert_eq!(PlatformKind::IntelSgx.to_string(), "intel-sgx");
    assert_eq!(PlatformKind::ArmCca.to_string(), "arm-cca");
    assert_eq!(PlatformKind::AmdSevSnp.to_string(), "amd-sev-snp");
    assert_eq!(PlatformKind::Software.to_string(), "software");
}

#[test]
fn platform_kind_ordering() {
    // Enum derives Ord, so variants are ordered by declaration.
    assert!(PlatformKind::IntelSgx < PlatformKind::ArmCca);
    assert!(PlatformKind::ArmCca < PlatformKind::AmdSevSnp);
    assert!(PlatformKind::AmdSevSnp < PlatformKind::Software);
}

// ===========================================================================
// MeasurementDigest — canonical_bytes platform byte encoding, derive_id
// ===========================================================================

#[test]
fn measurement_canonical_bytes_includes_platform_byte() {
    let root = make_root("k1", 1);
    let m = root.measure(b"code", b"cfg", b"pol", b"sch", "v1");
    let bytes = m.canonical_bytes();
    // Last byte should be the platform discriminant (Software = 3).
    assert_eq!(*bytes.last().unwrap(), PlatformKind::Software as u8);
}

#[test]
fn measurement_canonical_bytes_differ_by_runtime_version() {
    let root = make_root("k1", 1);
    let m1 = root.measure(b"code", b"cfg", b"pol", b"sch", "1.0");
    let m2 = root.measure(b"code", b"cfg", b"pol", b"sch", "2.0");
    assert_ne!(m1.canonical_bytes(), m2.canonical_bytes());
    assert_ne!(m1.composite_hash(), m2.composite_hash());
}

#[test]
fn measurement_composite_hash_deterministic() {
    let root = make_root("k1", 1);
    let m = root.measure(b"code", b"cfg", b"pol", b"sch", "v1");
    let h1 = m.composite_hash();
    let h2 = m.composite_hash();
    assert_eq!(h1, h2);
}

#[test]
fn measurement_derive_id_same_zone_deterministic() {
    let root = make_root("k1", 1);
    let m = root.measure(b"code", b"cfg", b"pol", b"sch", "v1");
    let id1 = m.derive_id("zone-a").unwrap();
    let id2 = m.derive_id("zone-a").unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn measurement_canonical_bytes_empty_runtime_version() {
    let root = make_root("k1", 1);
    let m = root.measure(b"code", b"cfg", b"pol", b"sch", "");
    // Should still produce valid bytes — no panic.
    let bytes = m.canonical_bytes();
    assert!(!bytes.is_empty());
    let _ = m.composite_hash(); // no panic
}

// ===========================================================================
// AttestationQuote — freshness boundary, u64::MAX overflow
// ===========================================================================

#[test]
fn quote_freshness_at_exact_boundary() {
    let root = make_root("k1", 1);
    let m = measure(&root);
    let q = quote_at(&root, &m, [1u8; 32], 1000, 100);
    // Boundary: issued_at + validity = 1100.
    assert!(q.is_fresh_at(1100));
    assert!(!q.is_fresh_at(1101));
}

#[test]
fn quote_freshness_u64_max_no_overflow_panic() {
    let root = make_root("k1", 1);
    let m = measure(&root);
    let q = quote_at(&root, &m, [1u8; 32], u64::MAX, u64::MAX);
    // saturating_add should prevent panic.
    assert!(q.is_fresh_at(u64::MAX));
    assert!(!q.is_expired_at(u64::MAX));
}

#[test]
fn quote_freshness_zero_validity_window() {
    let root = make_root("k1", 1);
    let m = measure(&root);
    let q = quote_at(&root, &m, [1u8; 32], 100, 0);
    assert!(q.is_fresh_at(100)); // exactly at issued_at
    assert!(!q.is_fresh_at(101)); // one past
}

#[test]
fn quote_serde_preserves_all_fields() {
    let root = make_root("k1", 1);
    let m = measure(&root);
    let q = quote_at(&root, &m, [42u8; 32], 999, 5_000_000);
    let json = serde_json::to_string(&q).unwrap();
    let restored: AttestationQuote = serde_json::from_str(&json).unwrap();
    assert_eq!(q.nonce, restored.nonce);
    assert_eq!(q.issued_at_ns, restored.issued_at_ns);
    assert_eq!(q.validity_window_ns, restored.validity_window_ns);
    assert_eq!(q.trust_level, restored.trust_level);
    assert_eq!(q.platform, restored.platform);
    assert_eq!(q.signature_bytes, restored.signature_bytes);
    assert_eq!(q.signer_key_id, restored.signer_key_id);
    assert_eq!(q.measurement, restored.measurement);
}

// ===========================================================================
// VerificationResult — serde all variants, display all
// ===========================================================================

#[test]
fn verification_result_serde_all_variants() {
    let expected_hash = ContentHash::compute(b"expected");
    let actual_hash = ContentHash::compute(b"actual");
    let variants: Vec<VerificationResult> = vec![
        VerificationResult::Valid,
        VerificationResult::MeasurementMismatch {
            expected: expected_hash,
            actual: actual_hash,
        },
        VerificationResult::SignatureInvalid,
        VerificationResult::Expired {
            issued_at_ns: 10,
            validity_window_ns: 20,
            checked_at_ns: 50,
        },
        VerificationResult::NonceMismatch,
        VerificationResult::SignerRevoked {
            key_id: "revoked-key".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn verification_result_display_all() {
    let expected_hash = ContentHash::compute(b"expected");
    let actual_hash = ContentHash::compute(b"actual");
    assert_eq!(VerificationResult::Valid.to_string(), "valid");
    assert_eq!(
        VerificationResult::MeasurementMismatch {
            expected: expected_hash,
            actual: actual_hash,
        }
        .to_string(),
        "measurement-mismatch"
    );
    assert_eq!(
        VerificationResult::SignatureInvalid.to_string(),
        "signature-invalid"
    );
    assert_eq!(
        VerificationResult::Expired {
            issued_at_ns: 10,
            validity_window_ns: 20,
            checked_at_ns: 50,
        }
        .to_string(),
        "expired"
    );
    assert_eq!(
        VerificationResult::NonceMismatch.to_string(),
        "nonce-mismatch"
    );
    assert_eq!(
        VerificationResult::SignerRevoked {
            key_id: "k1".to_string(),
        }
        .to_string(),
        "signer-revoked(k1)"
    );
}

#[test]
fn verification_result_is_valid_false_for_all_non_valid() {
    assert!(!VerificationResult::SignatureInvalid.is_valid());
    assert!(!VerificationResult::NonceMismatch.is_valid());
    assert!(!VerificationResult::Expired {
        issued_at_ns: 0,
        validity_window_ns: 0,
        checked_at_ns: 1,
    }
    .is_valid());
    assert!(!VerificationResult::SignerRevoked {
        key_id: "k".to_string(),
    }
    .is_valid());
    assert!(!VerificationResult::MeasurementMismatch {
        expected: ContentHash::compute(b"a"),
        actual: ContentHash::compute(b"b"),
    }
    .is_valid());
}

// ===========================================================================
// SoftwareTrustRoot — determinism, different seeds, key revocation
// ===========================================================================

#[test]
fn software_trust_root_deterministic_key_derivation() {
    let r1 = make_root("k1", 42);
    let r2 = make_root("k1", 42);
    assert_eq!(r1.secret_key_bytes, r2.secret_key_bytes);
    assert_eq!(r1.key_id, r2.key_id);
}

#[test]
fn software_trust_root_different_seeds_differ() {
    let r1 = make_root("k1", 1);
    let r2 = make_root("k1", 2);
    assert_ne!(r1.secret_key_bytes, r2.secret_key_bytes);
}

#[test]
fn software_trust_root_different_keys_different_signatures() {
    let r1 = make_root("k1", 1);
    let r2 = make_root("k2", 2);
    let m = r1.measure(b"code", b"cfg", b"pol", b"sch", "v1");
    let q1 = r1.attest(&m, [1u8; 32], 1_000_000, 100);
    let q2 = r2.attest(&m, [1u8; 32], 1_000_000, 100);
    assert_ne!(q1.signature_bytes, q2.signature_bytes);
}

#[test]
fn software_trust_root_revoke_multiple_keys() {
    let mut root = make_root("k1", 1);
    root.revoke_key("k1");
    root.revoke_key("k2");
    assert!(root.revoked_keys.contains("k1"));
    assert!(root.revoked_keys.contains("k2"));
    assert!(!root.revoked_keys.contains("k3"));
}

#[test]
fn software_trust_root_revoke_idempotent() {
    let mut root = make_root("k1", 1);
    root.revoke_key("k1");
    root.revoke_key("k1");
    assert_eq!(root.revoked_keys.len(), 1);
}

#[test]
fn software_trust_root_verify_checks_revocation_before_other() {
    // Even if nonce/measurement/signature all match, revocation takes priority.
    let mut root = make_root("k1", 1);
    let m = measure(&root);
    let nonce = [1u8; 32];
    let q = quote_at(&root, &m, nonce, 100, 10_000_000);
    root.revoke_key("k1");
    let result = root.verify(&q, &m, &nonce, 200);
    assert!(matches!(result, VerificationResult::SignerRevoked { .. }));
}

#[test]
fn software_trust_root_serde_with_revoked_keys() {
    let mut root = make_root("k1", 1);
    root.revoke_key("revoked-1");
    root.revoke_key("revoked-2");
    let json = serde_json::to_string(&root).unwrap();
    let restored: SoftwareTrustRoot = serde_json::from_str(&json).unwrap();
    assert_eq!(root.key_id, restored.key_id);
    assert_eq!(root.secret_key_bytes, restored.secret_key_bytes);
    assert_eq!(root.revoked_keys, restored.revoked_keys);
}

// ===========================================================================
// CellFunction — serde, ordering, hash
// ===========================================================================

#[test]
fn cell_function_serde_all_variants() {
    let variants = [
        CellFunction::DecisionReceiptSigner,
        CellFunction::EvidenceAccumulator,
        CellFunction::PolicyEvaluator,
        CellFunction::ProofValidator,
        CellFunction::ExtensionRuntime,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: CellFunction = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn cell_function_ordering() {
    assert!(CellFunction::DecisionReceiptSigner < CellFunction::EvidenceAccumulator);
    assert!(CellFunction::EvidenceAccumulator < CellFunction::PolicyEvaluator);
    assert!(CellFunction::PolicyEvaluator < CellFunction::ProofValidator);
    assert!(CellFunction::ProofValidator < CellFunction::ExtensionRuntime);
}

// ===========================================================================
// CellError — serde all variants, display, std::error::Error
// ===========================================================================

#[test]
fn cell_error_serde_all_variants() {
    let errors: Vec<CellError> = vec![
        CellError::IdDerivation("test-id-err".to_string()),
        CellError::NotFound {
            cell_id: "cell-99".to_string(),
        },
        CellError::Duplicate {
            cell_id: "cell-dup".to_string(),
        },
        CellError::InvalidTransition {
            from: CellLifecycle::Provisioning,
            to: CellLifecycle::Active,
        },
        CellError::NotOperational {
            lifecycle: CellLifecycle::Measured,
        },
        CellError::AttestationFailed {
            reason: "expired quote".to_string(),
        },
        CellError::NotMeasured,
        CellError::TrustRootRevoked {
            key_id: "key-revoked".to_string(),
        },
        CellError::EmptyLabel,
        CellError::EmptyZone,
        CellError::EmptyAuthority,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: CellError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

#[test]
fn cell_error_display_content() {
    assert!(CellError::IdDerivation("bad".to_string())
        .to_string()
        .contains("bad"));
    assert!(CellError::NotFound {
        cell_id: "c1".to_string()
    }
    .to_string()
    .contains("c1"));
    assert!(CellError::InvalidTransition {
        from: CellLifecycle::Active,
        to: CellLifecycle::Provisioning,
    }
    .to_string()
    .contains("active"));
    assert!(CellError::NotOperational {
        lifecycle: CellLifecycle::Suspended
    }
    .to_string()
    .contains("suspended"));
    assert!(CellError::AttestationFailed {
        reason: "expired".to_string()
    }
    .to_string()
    .contains("expired"));
    assert!(CellError::NotMeasured.to_string().contains("measured"));
    assert!(CellError::TrustRootRevoked {
        key_id: "k1".to_string()
    }
    .to_string()
    .contains("k1"));
    assert!(CellError::EmptyLabel.to_string().contains("label"));
    assert!(CellError::EmptyZone.to_string().contains("zone"));
    assert!(CellError::EmptyAuthority.to_string().contains("authority"));
}

#[test]
fn cell_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(CellError::NotMeasured);
    assert!(!e.to_string().is_empty());
}

// ===========================================================================
// CellEventType — serde all variants
// ===========================================================================

#[test]
fn cell_event_type_serde_all_variants() {
    let variants: Vec<CellEventType> = vec![
        CellEventType::Created,
        CellEventType::Measured,
        CellEventType::Attested,
        CellEventType::Activated,
        CellEventType::Suspended {
            reason: "policy violation".to_string(),
        },
        CellEventType::Decommissioned {
            reason: "end of life".to_string(),
        },
        CellEventType::FallbackActivated {
            reason: "attestation timeout".to_string(),
        },
        CellEventType::ReattestationSucceeded,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: CellEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// CellEvent — serde
// ===========================================================================

#[test]
fn cell_event_serde_all_event_types() {
    for et in [
        CellEventType::Created,
        CellEventType::Measured,
        CellEventType::Attested,
        CellEventType::Activated,
        CellEventType::ReattestationSucceeded,
    ] {
        let ev = CellEvent {
            seq: 42,
            timestamp_ns: 100_000,
            epoch: epoch(10),
            cell_id: "cell-x".to_string(),
            event_type: et.clone(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: CellEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }
}

// ===========================================================================
// ExecutionCell — serde with measurement + attestation
// ===========================================================================

#[test]
fn execution_cell_serde_full() {
    let root = make_root("k1", 1);
    let m = measure(&root);
    let q = quote_at(&root, &m, [5u8; 32], 500, 10_000_000);

    let cell = ExecutionCell {
        cell_id: m.derive_id("zone-a").unwrap(),
        label: "test-cell".to_string(),
        function: CellFunction::ProofValidator,
        lifecycle: CellLifecycle::Active,
        epoch: epoch(7),
        zone: "zone-a".to_string(),
        measurement: Some(m),
        attestation: Some(q),
        trust_level: TrustLevel::SoftwareOnly,
        transition_receipts: vec![LifecycleReceipt {
            from_state: CellLifecycle::Attested,
            to_state: CellLifecycle::Active,
            timestamp_ns: 600,
            epoch: epoch(7),
            reason: "activated".to_string(),
            signature_bytes: vec![1, 2, 3],
        }],
        authority_envelope: auth(&["sign", "verify"]),
    };
    let json = serde_json::to_string(&cell).unwrap();
    let restored: ExecutionCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, restored);
}

// ===========================================================================
// LifecycleReceipt — serde
// ===========================================================================

#[test]
fn lifecycle_receipt_serde_roundtrip() {
    let receipt = LifecycleReceipt {
        from_state: CellLifecycle::Provisioning,
        to_state: CellLifecycle::Measured,
        timestamp_ns: 12345,
        epoch: epoch(3),
        reason: "initial measurement".to_string(),
        signature_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: LifecycleReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

// ===========================================================================
// FallbackPolicy — custom config, serde
// ===========================================================================

#[test]
fn fallback_policy_custom_config_serde() {
    let mut actions = BTreeSet::new();
    actions.insert("deploy".to_string());
    actions.insert("rollback".to_string());
    actions.insert("revoke".to_string());
    let fp = FallbackPolicy {
        auto_fallback: false,
        challenge_on_fallback: false,
        sandbox_on_fallback: false,
        high_impact_actions: actions,
    };
    let json = serde_json::to_string(&fp).unwrap();
    let restored: FallbackPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, restored);
}

#[test]
fn fallback_policy_default_values() {
    let fp = FallbackPolicy::default();
    assert!(fp.auto_fallback);
    assert!(fp.challenge_on_fallback);
    assert!(fp.sandbox_on_fallback);
    assert!(fp.high_impact_actions.is_empty());
}

// ===========================================================================
// CellRegistry — creation edge cases
// ===========================================================================

#[test]
fn registry_default_is_empty() {
    let reg = CellRegistry::default();
    assert_eq!(reg.cell_count(), 0);
    assert!(reg.events().is_empty());
    assert!(reg.active_cells().is_empty());
}

#[test]
fn registry_create_whitespace_only_label_rejected() {
    let mut reg = CellRegistry::new();
    let input = CreateCellInput {
        label: "   \t  ".to_string(),
        function: CellFunction::PolicyEvaluator,
        zone: "prod".to_string(),
        epoch: epoch(1),
        trust_level: TrustLevel::SoftwareOnly,
        authority_envelope: auth(&["eval"]),
    };
    assert!(matches!(
        reg.create_cell(input, 1000),
        Err(CellError::EmptyLabel)
    ));
}

#[test]
fn registry_create_whitespace_only_zone_rejected() {
    let mut reg = CellRegistry::new();
    let input = CreateCellInput {
        label: "valid-label".to_string(),
        function: CellFunction::PolicyEvaluator,
        zone: "  ".to_string(),
        epoch: epoch(1),
        trust_level: TrustLevel::SoftwareOnly,
        authority_envelope: auth(&["eval"]),
    };
    assert!(matches!(
        reg.create_cell(input, 1000),
        Err(CellError::EmptyZone)
    ));
}

// ===========================================================================
// CellRegistry — multiple cells, zone/function indexes
// ===========================================================================

#[test]
fn registry_multiple_cells_different_functions() {
    let mut reg = CellRegistry::new();
    let ep = epoch(1);

    let functions = [
        CellFunction::DecisionReceiptSigner,
        CellFunction::EvidenceAccumulator,
        CellFunction::PolicyEvaluator,
        CellFunction::ProofValidator,
        CellFunction::ExtensionRuntime,
    ];

    for (i, func) in functions.iter().enumerate() {
        let input = cell_input(&format!("cell-{i}"), *func, "prod", ep);
        reg.create_cell(input, i as u64 * 1000).unwrap();
    }

    assert_eq!(reg.cell_count(), 5);
    for func in &functions {
        assert_eq!(reg.cells_by_function(*func).len(), 1);
    }
}

#[test]
fn registry_multiple_cells_same_zone() {
    let mut reg = CellRegistry::new();
    let ep = epoch(1);

    for i in 0..3 {
        let input = cell_input(
            &format!("cell-{i}"),
            CellFunction::ExtensionRuntime,
            "shared-zone",
            ep,
        );
        reg.create_cell(input, i * 1000).unwrap();
    }

    assert_eq!(reg.cells_in_zone("shared-zone").len(), 3);
    assert_eq!(reg.cells_in_zone("other-zone").len(), 0);
}

#[test]
fn registry_multiple_cells_multiple_zones() {
    let mut reg = CellRegistry::new();
    let ep = epoch(1);

    let zones = ["zone-a", "zone-b", "zone-c"];
    for (i, zone) in zones.iter().enumerate() {
        let input = cell_input(&format!("cell-{i}"), CellFunction::ProofValidator, zone, ep);
        reg.create_cell(input, i as u64 * 1000).unwrap();
    }

    for zone in &zones {
        assert_eq!(reg.cells_in_zone(zone).len(), 1);
    }
}

// ===========================================================================
// CellRegistry — lifecycle transitions, receipts, events
// ===========================================================================

#[test]
fn registry_measure_wrong_state_fails() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );
    // Cell is Active — cannot measure.
    let result = reg.measure_cell(&cid, measure(&root), 5000, ep);
    assert!(matches!(result, Err(CellError::InvalidTransition { .. })));
}

#[test]
fn registry_attest_from_provisioning_fails() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let id = reg
        .create_cell(
            cell_input("cell-1", CellFunction::ProofValidator, "prod", ep),
            1000,
        )
        .unwrap();
    let cid = format!("{id}");
    let m = measure(&root);
    let q = quote_at(&root, &m, [1u8; 32], 1000, 10_000_000);
    // Still in Provisioning — cannot attest.
    let result = reg.attest_cell(&cid, q, 2000, ep);
    assert!(matches!(result, Err(CellError::InvalidTransition { .. })));
}

#[test]
fn registry_activate_from_measured_fails() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let id = reg
        .create_cell(
            cell_input("cell-1", CellFunction::ProofValidator, "prod", ep),
            1000,
        )
        .unwrap();
    let cid = format!("{id}");
    reg.measure_cell(&cid, measure(&root), 2000, ep).unwrap();
    // Measured — cannot activate without attest.
    let result = reg.activate_cell(&cid, 3000, ep);
    assert!(matches!(result, Err(CellError::InvalidTransition { .. })));
}

#[test]
fn registry_suspend_from_provisioning_fails() {
    let mut reg = CellRegistry::new();
    let ep = epoch(1);
    let id = reg
        .create_cell(
            cell_input("cell-1", CellFunction::ProofValidator, "prod", ep),
            1000,
        )
        .unwrap();
    let cid = format!("{id}");
    let result = reg.suspend_cell(&cid, "test", 2000, ep);
    assert!(matches!(result, Err(CellError::InvalidTransition { .. })));
}

#[test]
fn registry_decommission_from_provisioning_fails() {
    let mut reg = CellRegistry::new();
    let ep = epoch(1);
    let id = reg
        .create_cell(
            cell_input("cell-1", CellFunction::ProofValidator, "prod", ep),
            1000,
        )
        .unwrap();
    let cid = format!("{id}");
    let result = reg.decommission_cell(&cid, "test", 2000, ep);
    assert!(matches!(result, Err(CellError::InvalidTransition { .. })));
}

#[test]
fn registry_lifecycle_receipts_accumulate() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );

    let cell = reg.get(&cid).unwrap();
    // Provisioning→Measured, Measured→Attested, Attested→Active = 3 receipts.
    assert_eq!(cell.transition_receipts.len(), 3);
    assert_eq!(
        cell.transition_receipts[0].from_state,
        CellLifecycle::Provisioning
    );
    assert_eq!(
        cell.transition_receipts[0].to_state,
        CellLifecycle::Measured
    );
    assert_eq!(
        cell.transition_receipts[1].from_state,
        CellLifecycle::Measured
    );
    assert_eq!(
        cell.transition_receipts[1].to_state,
        CellLifecycle::Attested
    );
    assert_eq!(
        cell.transition_receipts[2].from_state,
        CellLifecycle::Attested
    );
    assert_eq!(cell.transition_receipts[2].to_state, CellLifecycle::Active);
}

#[test]
fn registry_events_seq_monotonic() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let _ = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );

    let events = reg.events();
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.seq, i as u64);
    }
}

#[test]
fn registry_events_contain_cell_id() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );

    for ev in reg.events() {
        assert_eq!(ev.cell_id, cid);
    }
}

// ===========================================================================
// CellRegistry — revoke_trust_root
// ===========================================================================

#[test]
fn registry_revoke_trust_root_mixed_cells() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);

    // Activate two cells with same key.
    let cid1 = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );
    let cid2 = activate_cell(
        &mut reg,
        &root,
        "cell-2",
        CellFunction::EvidenceAccumulator,
        "prod",
        ep,
        2000,
    );

    // Create a third cell that stays in Provisioning.
    let _ = reg
        .create_cell(
            cell_input("cell-3", CellFunction::ExtensionRuntime, "prod", ep),
            3000,
        )
        .unwrap();

    let suspended = reg.revoke_trust_root("k1", 4000, ep);
    assert_eq!(suspended.len(), 2);
    assert_eq!(reg.get(&cid1).unwrap().lifecycle, CellLifecycle::Suspended);
    assert_eq!(reg.get(&cid2).unwrap().lifecycle, CellLifecycle::Suspended);
    // Provisioning cell unaffected.
    assert_eq!(reg.cell_count(), 3);
}

#[test]
fn registry_revoke_nonexistent_key_no_effect() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );

    let suspended = reg.revoke_trust_root("nonexistent-key", 5000, ep);
    assert!(suspended.is_empty());
    assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Active);
}

// ===========================================================================
// CellRegistry — active_cells, lookups after state changes
// ===========================================================================

#[test]
fn registry_active_cells_updates_after_suspend() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );

    assert_eq!(reg.active_cells().len(), 1);
    reg.suspend_cell(&cid, "testing", 5000, ep).unwrap();
    assert_eq!(reg.active_cells().len(), 0);
}

#[test]
fn registry_active_cells_updates_after_decommission() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );

    assert_eq!(reg.active_cells().len(), 1);
    reg.decommission_cell(&cid, "end of life", 5000, ep)
        .unwrap();
    assert_eq!(reg.active_cells().len(), 0);
}

#[test]
fn registry_get_nonexistent_returns_none() {
    let reg = CellRegistry::new();
    assert!(reg.get("nonexistent").is_none());
}

#[test]
fn registry_cells_by_function_empty_for_unused() {
    let reg = CellRegistry::new();
    assert!(reg
        .cells_by_function(CellFunction::PolicyEvaluator)
        .is_empty());
}

// ===========================================================================
// CellRegistry — serde after complex state
// ===========================================================================

#[test]
fn registry_serde_after_full_lifecycle() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);

    let cid1 = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "zone-a",
        ep,
        1000,
    );
    let _ = activate_cell(
        &mut reg,
        &root,
        "cell-2",
        CellFunction::EvidenceAccumulator,
        "zone-b",
        ep,
        2000,
    );
    reg.suspend_cell(&cid1, "test suspend", 5000, ep).unwrap();

    let json = serde_json::to_string(&reg).unwrap();
    let restored: CellRegistry = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.cell_count(), 2);
    assert_eq!(
        restored.get(&cid1).unwrap().lifecycle,
        CellLifecycle::Suspended
    );
    assert_eq!(restored.active_cells().len(), 1);
    assert_eq!(restored.cells_in_zone("zone-a").len(), 1);
    assert_eq!(restored.cells_in_zone("zone-b").len(), 1);
}

#[test]
fn registry_serde_preserves_events() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);
    let _ = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::ProofValidator,
        "prod",
        ep,
        1000,
    );
    let event_count = reg.events().len();

    let json = serde_json::to_string(&reg).unwrap();
    let restored: CellRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.events().len(), event_count);
}

// ===========================================================================
// CellRegistry — not-found errors on all operations
// ===========================================================================

#[test]
fn registry_measure_not_found() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let result = reg.measure_cell("ghost", measure(&root), 1000, epoch(1));
    assert!(matches!(result, Err(CellError::NotFound { .. })));
}

#[test]
fn registry_attest_not_found() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let m = measure(&root);
    let q = root.attest(&m, [1u8; 32], 1_000_000, 0);
    let result = reg.attest_cell("ghost", q, 1000, epoch(1));
    assert!(matches!(result, Err(CellError::NotFound { .. })));
}

#[test]
fn registry_activate_not_found() {
    let mut reg = CellRegistry::new();
    let result = reg.activate_cell("ghost", 1000, epoch(1));
    assert!(matches!(result, Err(CellError::NotFound { .. })));
}

#[test]
fn registry_suspend_not_found() {
    let mut reg = CellRegistry::new();
    let result = reg.suspend_cell("ghost", "reason", 1000, epoch(1));
    assert!(matches!(result, Err(CellError::NotFound { .. })));
}

#[test]
fn registry_decommission_not_found() {
    let mut reg = CellRegistry::new();
    let result = reg.decommission_cell("ghost", "reason", 1000, epoch(1));
    assert!(matches!(result, Err(CellError::NotFound { .. })));
}

// ===========================================================================
// Integration — full lifecycle with re-attestation
// ===========================================================================

#[test]
fn integration_full_lifecycle_with_reattestation() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);

    // Create → Measure → Attest → Activate.
    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::DecisionReceiptSigner,
        "prod",
        ep,
        1000,
    );
    assert!(reg.get(&cid).unwrap().lifecycle.is_operational());

    // Suspend.
    reg.suspend_cell(&cid, "key rotation", 5000, ep).unwrap();
    assert!(!reg.get(&cid).unwrap().lifecycle.is_operational());
    assert!(reg.get(&cid).unwrap().lifecycle.allows_reattestation());

    // Re-attest from Suspended.
    let m = measure(&root);
    let q2 = quote_at(&root, &m, [99u8; 32], 5000, 10_000_000);
    reg.attest_cell(&cid, q2, 6000, ep).unwrap();
    assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Attested);

    // Re-activate.
    reg.activate_cell(&cid, 7000, ep).unwrap();
    assert!(reg.get(&cid).unwrap().lifecycle.is_operational());

    // Receipts: Prov→Meas, Meas→Att, Att→Act, Act→Susp, Susp→Att, Att→Act = 6.
    assert_eq!(reg.get(&cid).unwrap().transition_receipts.len(), 6);

    // Events: Created, Measured, Attested, Activated, Suspended, ReattestationSucceeded, Activated = 7.
    assert_eq!(reg.events().len(), 7);
    assert!(matches!(
        reg.events()[5].event_type,
        CellEventType::ReattestationSucceeded
    ));
}

#[test]
fn integration_decommission_from_suspended() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);

    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::PolicyEvaluator,
        "staging",
        ep,
        1000,
    );
    reg.suspend_cell(&cid, "maintenance", 5000, ep).unwrap();
    reg.decommission_cell(&cid, "retired", 6000, ep).unwrap();
    assert_eq!(
        reg.get(&cid).unwrap().lifecycle,
        CellLifecycle::Decommissioned
    );
    assert!(!reg.get(&cid).unwrap().lifecycle.is_operational());
    assert!(!reg.get(&cid).unwrap().lifecycle.allows_reattestation());
}

#[test]
fn integration_revoke_then_reattest_and_reactivate() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);
    let ep = epoch(1);

    let cid = activate_cell(
        &mut reg,
        &root,
        "cell-1",
        CellFunction::EvidenceAccumulator,
        "prod",
        ep,
        1000,
    );

    // Revoke trust root — suspends the cell.
    let suspended = reg.revoke_trust_root("k1", 5000, ep);
    assert_eq!(suspended.len(), 1);
    assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Suspended);

    // Re-attest with new quote.
    let m = measure(&root);
    let q = quote_at(&root, &m, [50u8; 32], 5000, 10_000_000);
    reg.attest_cell(&cid, q, 6000, ep).unwrap();
    reg.activate_cell(&cid, 7000, ep).unwrap();
    assert!(reg.get(&cid).unwrap().lifecycle.is_operational());
}

#[test]
fn integration_multiple_cells_different_epochs() {
    let mut reg = CellRegistry::new();
    let root = make_root("k1", 1);

    let cid1 = activate_cell(
        &mut reg,
        &root,
        "epoch1-cell",
        CellFunction::DecisionReceiptSigner,
        "prod",
        epoch(1),
        1000,
    );
    let cid2 = activate_cell(
        &mut reg,
        &root,
        "epoch2-cell",
        CellFunction::ProofValidator,
        "prod",
        epoch(2),
        2000,
    );

    assert_eq!(reg.get(&cid1).unwrap().epoch, epoch(1));
    assert_eq!(reg.get(&cid2).unwrap().epoch, epoch(2));
    assert_eq!(reg.active_cells().len(), 2);
    assert_eq!(reg.cells_in_zone("prod").len(), 2);
}

#[test]
fn integration_cell_id_deterministic_across_registries() {
    let ep = epoch(1);
    let input = cell_input(
        "deterministic-cell",
        CellFunction::PolicyEvaluator,
        "zone-x",
        ep,
    );

    let mut reg1 = CellRegistry::new();
    let id1 = reg1.create_cell(input.clone(), 1000).unwrap();

    let mut reg2 = CellRegistry::new();
    let id2 = reg2.create_cell(input, 2000).unwrap();

    assert_eq!(format!("{id1}"), format!("{id2}"));
}
