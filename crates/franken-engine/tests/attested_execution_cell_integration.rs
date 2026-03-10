#![forbid(unsafe_code)]
//! Comprehensive integration tests for the `attested_execution_cell` module.
//!
//! Covers: CellLifecycle, TrustLevel, PlatformKind, MeasurementDigest,
//! AttestationQuote, VerificationResult, SoftwareTrustRoot (TrustRootBackend),
//! CellFunction, ExecutionCell, LifecycleReceipt, CellError, CreateCellInput,
//! CellRegistry (CRUD, lifecycle transitions, revocation, indices, events),
//! and FallbackPolicy.

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

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn root(key_id: &str, seed: u64) -> SoftwareTrustRoot {
    SoftwareTrustRoot::new(key_id, seed)
}

fn auth(caps: &[&str]) -> BTreeSet<String> {
    caps.iter().map(|s| s.to_string()).collect()
}

fn input(label: &str, func: CellFunction, zone: &str) -> CreateCellInput {
    CreateCellInput {
        label: label.to_string(),
        function: func,
        zone: zone.to_string(),
        epoch: ep(1),
        trust_level: TrustLevel::SoftwareOnly,
        authority_envelope: auth(&["sign", "emit"]),
    }
}

fn meas(tr: &SoftwareTrustRoot) -> MeasurementDigest {
    tr.measure(
        b"code-v1",
        b"config-v1",
        b"policy-v1",
        b"schema-v1",
        "1.0.0",
    )
}

fn fresh_quote(tr: &SoftwareTrustRoot, m: &MeasurementDigest, nonce: [u8; 32]) -> AttestationQuote {
    let mut q = tr.attest(m, nonce, 1_000_000_000);
    q.issued_at_ns = 1_000;
    q
}

/// Drive a cell all the way to Active, returning its string ID.
fn drive_to_active(
    reg: &mut CellRegistry,
    tr: &SoftwareTrustRoot,
    label: &str,
    func: CellFunction,
    zone: &str,
) -> String {
    let cid = reg.create_cell(input(label, func, zone), 100).unwrap();
    let cid_s = format!("{cid}");
    let m = meas(tr);
    reg.measure_cell(&cid_s, m.clone(), 200, ep(1)).unwrap();
    let q = fresh_quote(tr, &m, [1u8; 32]);
    reg.attest_cell(&cid_s, q, 300, ep(1)).unwrap();
    reg.activate_cell(&cid_s, 400, ep(1)).unwrap();
    cid_s
}

// ===========================================================================
// Section 1: CellLifecycle enum
// ===========================================================================

#[test]
fn lifecycle_is_operational_only_for_active() {
    let states = [
        CellLifecycle::Provisioning,
        CellLifecycle::Measured,
        CellLifecycle::Attested,
        CellLifecycle::Active,
        CellLifecycle::Suspended,
        CellLifecycle::Decommissioned,
    ];
    for s in &states {
        assert_eq!(s.is_operational(), *s == CellLifecycle::Active);
    }
}

#[test]
fn lifecycle_allows_reattestation_only_suspended_and_measured() {
    assert!(!CellLifecycle::Provisioning.allows_reattestation());
    assert!(CellLifecycle::Measured.allows_reattestation());
    assert!(!CellLifecycle::Attested.allows_reattestation());
    assert!(!CellLifecycle::Active.allows_reattestation());
    assert!(CellLifecycle::Suspended.allows_reattestation());
    assert!(!CellLifecycle::Decommissioned.allows_reattestation());
}

#[test]
fn lifecycle_display_all_variants() {
    assert_eq!(CellLifecycle::Provisioning.to_string(), "provisioning");
    assert_eq!(CellLifecycle::Measured.to_string(), "measured");
    assert_eq!(CellLifecycle::Attested.to_string(), "attested");
    assert_eq!(CellLifecycle::Active.to_string(), "active");
    assert_eq!(CellLifecycle::Suspended.to_string(), "suspended");
    assert_eq!(CellLifecycle::Decommissioned.to_string(), "decommissioned");
}

#[test]
fn lifecycle_ordering_monotone() {
    let states = [
        CellLifecycle::Provisioning,
        CellLifecycle::Measured,
        CellLifecycle::Attested,
        CellLifecycle::Active,
        CellLifecycle::Suspended,
        CellLifecycle::Decommissioned,
    ];
    for w in states.windows(2) {
        assert!(w[0] < w[1], "{:?} should be < {:?}", w[0], w[1]);
    }
}

#[test]
fn lifecycle_clone_and_eq() {
    let a = CellLifecycle::Active;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Section 2: TrustLevel
// ===========================================================================

#[test]
fn trust_level_display_and_ordering() {
    assert_eq!(TrustLevel::SoftwareOnly.to_string(), "software-only");
    assert_eq!(TrustLevel::Hybrid.to_string(), "hybrid");
    assert_eq!(TrustLevel::Hardware.to_string(), "hardware");
    assert!(TrustLevel::SoftwareOnly < TrustLevel::Hybrid);
    assert!(TrustLevel::Hybrid < TrustLevel::Hardware);
}

// ===========================================================================
// Section 3: PlatformKind
// ===========================================================================

#[test]
fn platform_kind_display_and_ordering() {
    assert_eq!(PlatformKind::IntelSgx.to_string(), "intel-sgx");
    assert_eq!(PlatformKind::ArmCca.to_string(), "arm-cca");
    assert_eq!(PlatformKind::AmdSevSnp.to_string(), "amd-sev-snp");
    assert_eq!(PlatformKind::Software.to_string(), "software");
    assert!(PlatformKind::IntelSgx < PlatformKind::ArmCca);
    assert!(PlatformKind::ArmCca < PlatformKind::AmdSevSnp);
    assert!(PlatformKind::AmdSevSnp < PlatformKind::Software);
}

// ===========================================================================
// Section 4: MeasurementDigest
// ===========================================================================

#[test]
fn measurement_deterministic_across_calls() {
    let tr = root("k1", 42);
    let m1 = meas(&tr);
    let m2 = meas(&tr);
    assert_eq!(m1, m2);
    assert_eq!(m1.canonical_bytes(), m2.canonical_bytes());
    assert_eq!(m1.composite_hash(), m2.composite_hash());
}

#[test]
fn measurement_different_code_yields_different_hash() {
    let tr = root("k1", 42);
    let m1 = tr.measure(b"code-a", b"cfg", b"pol", b"sch", "1.0");
    let m2 = tr.measure(b"code-b", b"cfg", b"pol", b"sch", "1.0");
    assert_ne!(m1.composite_hash(), m2.composite_hash());
}

#[test]
fn measurement_different_config_yields_different_hash() {
    let tr = root("k1", 42);
    let m1 = tr.measure(b"code", b"cfg-a", b"pol", b"sch", "1.0");
    let m2 = tr.measure(b"code", b"cfg-b", b"pol", b"sch", "1.0");
    assert_ne!(m1.composite_hash(), m2.composite_hash());
}

#[test]
fn measurement_different_policy_yields_different_hash() {
    let tr = root("k1", 42);
    let m1 = tr.measure(b"code", b"cfg", b"pol-a", b"sch", "1.0");
    let m2 = tr.measure(b"code", b"cfg", b"pol-b", b"sch", "1.0");
    assert_ne!(m1.composite_hash(), m2.composite_hash());
}

#[test]
fn measurement_different_schema_yields_different_hash() {
    let tr = root("k1", 42);
    let m1 = tr.measure(b"code", b"cfg", b"pol", b"sch-a", "1.0");
    let m2 = tr.measure(b"code", b"cfg", b"pol", b"sch-b", "1.0");
    assert_ne!(m1.composite_hash(), m2.composite_hash());
}

#[test]
fn measurement_different_version_yields_different_hash() {
    let tr = root("k1", 42);
    let m1 = tr.measure(b"code", b"cfg", b"pol", b"sch", "1.0");
    let m2 = tr.measure(b"code", b"cfg", b"pol", b"sch", "2.0");
    assert_ne!(m1.composite_hash(), m2.composite_hash());
}

#[test]
fn measurement_derive_id_deterministic() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let id1 = m.derive_id("zone-a").unwrap();
    let id2 = m.derive_id("zone-a").unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn measurement_derive_id_zone_sensitive() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let id1 = m.derive_id("zone-a").unwrap();
    let id2 = m.derive_id("zone-b").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn measurement_serde_roundtrip() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let json = serde_json::to_string(&m).unwrap();
    let restored: MeasurementDigest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

#[test]
fn measurement_canonical_bytes_non_empty() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    assert!(!m.canonical_bytes().is_empty());
}

// ===========================================================================
// Section 5: AttestationQuote
// ===========================================================================

#[test]
fn quote_is_fresh_at_boundary() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let mut q = tr.attest(&m, [0u8; 32], 100);
    q.issued_at_ns = 1000;
    // Exactly at boundary: issued_at + validity = 1100
    assert!(q.is_fresh_at(1100));
    assert!(!q.is_fresh_at(1101));
}

#[test]
fn quote_fresh_at_issuance_time() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let mut q = tr.attest(&m, [0u8; 32], 500);
    q.issued_at_ns = 200;
    assert!(q.is_fresh_at(200));
}

#[test]
fn quote_expired_inverse_of_fresh() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let mut q = tr.attest(&m, [0u8; 32], 100);
    q.issued_at_ns = 1000;
    for ts in [999, 1000, 1050, 1100, 1101, 2000] {
        assert_eq!(q.is_expired_at(ts), !q.is_fresh_at(ts));
    }
}

#[test]
fn quote_zero_validity_window() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let mut q = tr.attest(&m, [0u8; 32], 0);
    q.issued_at_ns = 500;
    assert!(q.is_fresh_at(500));
    assert!(!q.is_fresh_at(501));
}

#[test]
fn quote_serde_roundtrip() {
    let tr = root("k1", 42);
    let m = meas(&tr);
    let q = fresh_quote(&tr, &m, [7u8; 32]);
    let json = serde_json::to_string(&q).unwrap();
    let restored: AttestationQuote = serde_json::from_str(&json).unwrap();
    assert_eq!(q, restored);
}

// ===========================================================================
// Section 6: VerificationResult
// ===========================================================================

#[test]
fn verification_result_is_valid_only_for_valid() {
    assert!(VerificationResult::Valid.is_valid());
    assert!(!VerificationResult::SignatureInvalid.is_valid());
    assert!(!VerificationResult::NonceMismatch.is_valid());
    let mm = VerificationResult::MeasurementMismatch {
        expected: ContentHash::compute(b"a"),
        actual: ContentHash::compute(b"b"),
    };
    assert!(!mm.is_valid());
    let exp = VerificationResult::Expired {
        issued_at_ns: 0,
        validity_window_ns: 0,
        checked_at_ns: 1,
    };
    assert!(!exp.is_valid());
    let rev = VerificationResult::SignerRevoked {
        key_id: "x".to_string(),
    };
    assert!(!rev.is_valid());
}

#[test]
fn verification_result_display_all_variants() {
    assert_eq!(VerificationResult::Valid.to_string(), "valid");
    let mm = VerificationResult::MeasurementMismatch {
        expected: ContentHash::compute(b"a"),
        actual: ContentHash::compute(b"b"),
    };
    assert_eq!(mm.to_string(), "measurement-mismatch");
    assert_eq!(
        VerificationResult::SignatureInvalid.to_string(),
        "signature-invalid"
    );
    let exp = VerificationResult::Expired {
        issued_at_ns: 10,
        validity_window_ns: 5,
        checked_at_ns: 20,
    };
    assert_eq!(exp.to_string(), "expired");
    assert_eq!(
        VerificationResult::NonceMismatch.to_string(),
        "nonce-mismatch"
    );
    let rev = VerificationResult::SignerRevoked {
        key_id: "mykey".to_string(),
    };
    assert_eq!(rev.to_string(), "signer-revoked(mykey)");
}

#[test]
fn verification_result_serde_all_variants() {
    let variants: Vec<VerificationResult> = vec![
        VerificationResult::Valid,
        VerificationResult::SignatureInvalid,
        VerificationResult::NonceMismatch,
        VerificationResult::MeasurementMismatch {
            expected: ContentHash::compute(b"e"),
            actual: ContentHash::compute(b"a"),
        },
        VerificationResult::Expired {
            issued_at_ns: 1,
            validity_window_ns: 2,
            checked_at_ns: 4,
        },
        VerificationResult::SignerRevoked {
            key_id: "k".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// Section 7: SoftwareTrustRoot / TrustRootBackend
// ===========================================================================

#[test]
fn software_root_trust_level_and_platform() {
    let tr = root("k1", 1);
    assert_eq!(tr.trust_level(), TrustLevel::SoftwareOnly);
    assert_eq!(tr.platform(), PlatformKind::Software);
}

#[test]
fn software_root_deterministic_key_derivation() {
    let a = root("k", 99);
    let b = root("k", 99);
    assert_eq!(a.secret_key_bytes, b.secret_key_bytes);
}

#[test]
fn software_root_different_seed_different_keys() {
    let a = root("k", 1);
    let b = root("k", 2);
    assert_ne!(a.secret_key_bytes, b.secret_key_bytes);
}

#[test]
fn software_root_verify_happy_path() {
    let tr = root("k1", 10);
    let m = meas(&tr);
    let nonce = [42u8; 32];
    let q = fresh_quote(&tr, &m, nonce);
    let result = tr.verify(&q, &m, &nonce, 500);
    assert_eq!(result, VerificationResult::Valid);
}

#[test]
fn software_root_verify_expired_quote() {
    let tr = root("k1", 10);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let mut q = tr.attest(&m, nonce, 100);
    q.issued_at_ns = 1000;
    let result = tr.verify(&q, &m, &nonce, 1200);
    assert!(matches!(result, VerificationResult::Expired { .. }));
}

#[test]
fn software_root_verify_nonce_mismatch() {
    let tr = root("k1", 10);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let wrong = [2u8; 32];
    let q = fresh_quote(&tr, &m, nonce);
    let result = tr.verify(&q, &m, &wrong, 500);
    assert_eq!(result, VerificationResult::NonceMismatch);
}

#[test]
fn software_root_verify_measurement_mismatch() {
    let tr = root("k1", 10);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let q = fresh_quote(&tr, &m, nonce);
    let other = tr.measure(b"other-code", b"cfg", b"pol", b"sch", "2.0");
    let result = tr.verify(&q, &other, &nonce, 500);
    assert!(matches!(
        result,
        VerificationResult::MeasurementMismatch { .. }
    ));
}

#[test]
fn software_root_verify_tampered_signature() {
    let tr = root("k1", 10);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let mut q = fresh_quote(&tr, &m, nonce);
    if let Some(b) = q.signature_bytes.first_mut() {
        *b ^= 0xFF;
    }
    let result = tr.verify(&q, &m, &nonce, 500);
    assert_eq!(result, VerificationResult::SignatureInvalid);
}

#[test]
fn software_root_verify_revoked_key() {
    let mut tr = root("k1", 10);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let q = fresh_quote(&tr, &m, nonce);
    tr.revoke_key("k1");
    let result = tr.verify(&q, &m, &nonce, 500);
    assert!(matches!(result, VerificationResult::SignerRevoked { .. }));
}

#[test]
fn software_root_revoke_key_idempotent() {
    let mut tr = root("k1", 10);
    tr.revoke_key("k1");
    tr.revoke_key("k1");
    assert_eq!(tr.revoked_keys.len(), 1);
}

#[test]
fn software_root_serde_roundtrip() {
    let mut tr = root("k1", 42);
    tr.revoke_key("old-key");
    let json = serde_json::to_string(&tr).unwrap();
    let restored: SoftwareTrustRoot = serde_json::from_str(&json).unwrap();
    assert_eq!(tr.key_id, restored.key_id);
    assert_eq!(tr.secret_key_bytes, restored.secret_key_bytes);
    assert_eq!(tr.revoked_keys, restored.revoked_keys);
}

#[test]
fn software_root_verification_priority_revocation_over_expiry() {
    // When the key is revoked AND the quote is expired, revocation is reported.
    let mut tr = root("k1", 10);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let mut q = tr.attest(&m, nonce, 10);
    q.issued_at_ns = 100;
    tr.revoke_key("k1");
    let result = tr.verify(&q, &m, &nonce, 200);
    assert!(matches!(result, VerificationResult::SignerRevoked { .. }));
}

// ===========================================================================
// Section 8: CellFunction
// ===========================================================================

#[test]
fn cell_function_display_all() {
    assert_eq!(
        CellFunction::DecisionReceiptSigner.to_string(),
        "decision-receipt-signer"
    );
    assert_eq!(
        CellFunction::EvidenceAccumulator.to_string(),
        "evidence-accumulator"
    );
    assert_eq!(
        CellFunction::PolicyEvaluator.to_string(),
        "policy-evaluator"
    );
    assert_eq!(CellFunction::ProofValidator.to_string(), "proof-validator");
    assert_eq!(
        CellFunction::ExtensionRuntime.to_string(),
        "extension-runtime"
    );
}

// ===========================================================================
// Section 9: CellError
// ===========================================================================

#[test]
fn cell_error_display_all_variants() {
    let errors: Vec<CellError> = vec![
        CellError::IdDerivation("bad id".to_string()),
        CellError::NotFound {
            cell_id: "c1".to_string(),
        },
        CellError::Duplicate {
            cell_id: "c2".to_string(),
        },
        CellError::InvalidTransition {
            from: CellLifecycle::Active,
            to: CellLifecycle::Provisioning,
        },
        CellError::NotOperational {
            lifecycle: CellLifecycle::Suspended,
        },
        CellError::AttestationFailed {
            reason: "expired".to_string(),
        },
        CellError::NotMeasured,
        CellError::TrustRootRevoked {
            key_id: "k".to_string(),
        },
        CellError::EmptyLabel,
        CellError::EmptyZone,
        CellError::EmptyAuthority,
    ];
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn cell_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(CellError::NotMeasured);
    assert!(!e.to_string().is_empty());
}

#[test]
fn cell_error_serde_roundtrip() {
    let e = CellError::InvalidTransition {
        from: CellLifecycle::Provisioning,
        to: CellLifecycle::Active,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: CellError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

// ===========================================================================
// Section 10: CellRegistry — creation and validation
// ===========================================================================

#[test]
fn registry_new_is_empty() {
    let reg = CellRegistry::new();
    assert_eq!(reg.cell_count(), 0);
    assert!(reg.events().is_empty());
    assert!(reg.active_cells().is_empty());
}

#[test]
fn registry_default_is_empty() {
    let reg = CellRegistry::default();
    assert_eq!(reg.cell_count(), 0);
}

#[test]
fn create_cell_happy_path() {
    let mut reg = CellRegistry::new();
    let cid = reg
        .create_cell(
            input("signer-1", CellFunction::DecisionReceiptSigner, "prod"),
            100,
        )
        .unwrap();
    let cid_s = format!("{cid}");
    assert_eq!(reg.cell_count(), 1);
    let cell = reg.get(&cid_s).unwrap();
    assert_eq!(cell.lifecycle, CellLifecycle::Provisioning);
    assert_eq!(cell.function, CellFunction::DecisionReceiptSigner);
    assert_eq!(cell.zone, "prod");
    assert!(cell.measurement.is_none());
    assert!(cell.attestation.is_none());
    assert!(cell.transition_receipts.is_empty());
}

#[test]
fn create_cell_rejects_empty_label() {
    let mut reg = CellRegistry::new();
    let mut inp = input("", CellFunction::PolicyEvaluator, "zone");
    inp.label = "   ".to_string();
    assert!(matches!(
        reg.create_cell(inp, 100),
        Err(CellError::EmptyLabel)
    ));
}

#[test]
fn create_cell_rejects_empty_zone() {
    let mut reg = CellRegistry::new();
    let inp = input("label", CellFunction::PolicyEvaluator, "");
    assert!(matches!(
        reg.create_cell(inp, 100),
        Err(CellError::EmptyZone)
    ));
}

#[test]
fn create_cell_rejects_empty_authority() {
    let mut reg = CellRegistry::new();
    let mut inp = input("label", CellFunction::PolicyEvaluator, "zone");
    inp.authority_envelope = BTreeSet::new();
    assert!(matches!(
        reg.create_cell(inp, 100),
        Err(CellError::EmptyAuthority)
    ));
}

#[test]
fn create_cell_rejects_duplicate() {
    let mut reg = CellRegistry::new();
    reg.create_cell(input("dup", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let result = reg.create_cell(input("dup", CellFunction::PolicyEvaluator, "z"), 200);
    assert!(matches!(result, Err(CellError::Duplicate { .. })));
}

#[test]
fn create_cell_deterministic_id() {
    let mut r1 = CellRegistry::new();
    let mut r2 = CellRegistry::new();
    let id1 = r1
        .create_cell(input("c", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let id2 = r2
        .create_cell(input("c", CellFunction::PolicyEvaluator, "z"), 999)
        .unwrap();
    assert_eq!(id1, id2);
}

// ===========================================================================
// Section 11: CellRegistry — full lifecycle transitions
// ===========================================================================

#[test]
fn full_lifecycle_provisioning_to_decommissioned() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid = reg
        .create_cell(
            input("cell-a", CellFunction::EvidenceAccumulator, "prod"),
            100,
        )
        .unwrap();
    let cid_s = format!("{cid}");

    // Provisioning -> Measured
    let m = meas(&tr);
    reg.measure_cell(&cid_s, m.clone(), 200, ep(1)).unwrap();
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Measured);
    assert!(reg.get(&cid_s).unwrap().measurement.is_some());

    // Measured -> Attested
    let q = fresh_quote(&tr, &m, [5u8; 32]);
    reg.attest_cell(&cid_s, q, 300, ep(1)).unwrap();
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Attested);
    assert!(reg.get(&cid_s).unwrap().attestation.is_some());

    // Attested -> Active
    reg.activate_cell(&cid_s, 400, ep(1)).unwrap();
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Active);
    assert!(reg.get(&cid_s).unwrap().lifecycle.is_operational());

    // Active -> Decommissioned
    reg.decommission_cell(&cid_s, "end-of-life", 500, ep(1))
        .unwrap();
    assert_eq!(
        reg.get(&cid_s).unwrap().lifecycle,
        CellLifecycle::Decommissioned
    );
    assert_eq!(reg.get(&cid_s).unwrap().transition_receipts.len(), 4);
}

#[test]
fn suspend_and_reattest_then_reactivate() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(
        &mut reg,
        &tr,
        "cell-s",
        CellFunction::ProofValidator,
        "prod",
    );

    // Active -> Suspended
    reg.suspend_cell(&cid_s, "revocation", 500, ep(2)).unwrap();
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Suspended);

    // Suspended -> Attested (re-attest)
    let m = meas(&tr);
    let mut q2 = tr.attest(&m, [9u8; 32], 1_000_000_000);
    q2.issued_at_ns = 600;
    reg.attest_cell(&cid_s, q2, 700, ep(2)).unwrap();
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Attested);

    // Attested -> Active
    reg.activate_cell(&cid_s, 800, ep(2)).unwrap();
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Active);
}

#[test]
fn decommission_from_suspended() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(
        &mut reg,
        &tr,
        "cell-d",
        CellFunction::ExtensionRuntime,
        "prod",
    );
    reg.suspend_cell(&cid_s, "maint", 500, ep(1)).unwrap();
    reg.decommission_cell(&cid_s, "permanent", 600, ep(1))
        .unwrap();
    assert_eq!(
        reg.get(&cid_s).unwrap().lifecycle,
        CellLifecycle::Decommissioned
    );
}

// ===========================================================================
// Section 12: CellRegistry — invalid transitions
// ===========================================================================

#[test]
fn invalid_transition_provisioning_to_active() {
    let mut reg = CellRegistry::new();
    let cid = reg
        .create_cell(input("x", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");
    assert!(matches!(
        reg.activate_cell(&s, 200, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
}

#[test]
fn invalid_transition_provisioning_to_suspended() {
    let mut reg = CellRegistry::new();
    let cid = reg
        .create_cell(input("x", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");
    assert!(matches!(
        reg.suspend_cell(&s, "r", 200, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
}

#[test]
fn invalid_transition_provisioning_to_decommissioned() {
    let mut reg = CellRegistry::new();
    let cid = reg
        .create_cell(input("x", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");
    assert!(matches!(
        reg.decommission_cell(&s, "r", 200, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
}

#[test]
fn invalid_transition_measured_to_active() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid = reg
        .create_cell(input("x", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");
    reg.measure_cell(&s, meas(&tr), 200, ep(1)).unwrap();
    assert!(matches!(
        reg.activate_cell(&s, 300, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
}

#[test]
fn invalid_transition_attested_to_suspended() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid = reg
        .create_cell(input("x", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");
    let m = meas(&tr);
    reg.measure_cell(&s, m.clone(), 200, ep(1)).unwrap();
    let q = fresh_quote(&tr, &m, [1u8; 32]);
    reg.attest_cell(&s, q, 300, ep(1)).unwrap();
    assert!(matches!(
        reg.suspend_cell(&s, "r", 400, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
}

#[test]
fn invalid_transition_decommissioned_to_anything() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(&mut reg, &tr, "cell-x", CellFunction::PolicyEvaluator, "z");
    reg.decommission_cell(&cid_s, "done", 500, ep(1)).unwrap();

    // Cannot measure
    assert!(matches!(
        reg.measure_cell(&cid_s, meas(&tr), 600, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
    // Cannot attest
    let m = meas(&tr);
    let q = fresh_quote(&tr, &m, [1u8; 32]);
    assert!(matches!(
        reg.attest_cell(&cid_s, q, 700, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
    // Cannot activate
    assert!(matches!(
        reg.activate_cell(&cid_s, 800, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
    // Cannot suspend
    assert!(matches!(
        reg.suspend_cell(&cid_s, "r", 900, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
    // Cannot decommission again
    assert!(matches!(
        reg.decommission_cell(&cid_s, "r", 1000, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
}

#[test]
fn not_found_errors_for_missing_cell() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let m = meas(&tr);
    let q = fresh_quote(&tr, &m, [1u8; 32]);
    assert!(matches!(
        reg.measure_cell("bogus", m.clone(), 100, ep(1)),
        Err(CellError::NotFound { .. })
    ));
    assert!(matches!(
        reg.attest_cell("bogus", q, 100, ep(1)),
        Err(CellError::NotFound { .. })
    ));
    assert!(matches!(
        reg.activate_cell("bogus", 100, ep(1)),
        Err(CellError::NotFound { .. })
    ));
    assert!(matches!(
        reg.suspend_cell("bogus", "r", 100, ep(1)),
        Err(CellError::NotFound { .. })
    ));
    assert!(matches!(
        reg.decommission_cell("bogus", "r", 100, ep(1)),
        Err(CellError::NotFound { .. })
    ));
}

// ===========================================================================
// Section 13: CellRegistry — trust root revocation
// ===========================================================================

#[test]
fn revoke_trust_root_suspends_active_cells() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(
        &mut reg,
        &tr,
        "cell-r",
        CellFunction::PolicyEvaluator,
        "prod",
    );

    let suspended = reg.revoke_trust_root("k1", 500, ep(2));
    assert_eq!(suspended.len(), 1);
    assert!(suspended.contains(&cid_s));
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Suspended);
}

#[test]
fn revoke_trust_root_ignores_non_matching_key() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(
        &mut reg,
        &tr,
        "cell-r2",
        CellFunction::PolicyEvaluator,
        "prod",
    );

    let suspended = reg.revoke_trust_root("other-key", 500, ep(2));
    assert!(suspended.is_empty());
    assert_eq!(reg.get(&cid_s).unwrap().lifecycle, CellLifecycle::Active);
}

#[test]
fn revoke_trust_root_ignores_non_active_cells() {
    let mut reg = CellRegistry::new();
    // Create cell but leave in Provisioning (no attestation with any key)
    let cid = reg
        .create_cell(input("prov", CellFunction::PolicyEvaluator, "prod"), 100)
        .unwrap();
    let _cid_s = format!("{cid}");

    let suspended = reg.revoke_trust_root("k1", 500, ep(2));
    assert!(suspended.is_empty());
}

#[test]
fn revoke_trust_root_suspends_multiple_matching_cells() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    drive_to_active(
        &mut reg,
        &tr,
        "cell-1",
        CellFunction::PolicyEvaluator,
        "prod",
    );
    drive_to_active(
        &mut reg,
        &tr,
        "cell-2",
        CellFunction::ProofValidator,
        "prod",
    );
    drive_to_active(
        &mut reg,
        &tr,
        "cell-3",
        CellFunction::EvidenceAccumulator,
        "prod",
    );

    let suspended = reg.revoke_trust_root("k1", 500, ep(2));
    assert_eq!(suspended.len(), 3);
    assert_eq!(reg.active_cells().len(), 0);
}

// ===========================================================================
// Section 14: CellRegistry — lookup indices
// ===========================================================================

#[test]
fn cells_by_function_returns_correct_subset() {
    let mut reg = CellRegistry::new();
    reg.create_cell(
        input("signer", CellFunction::DecisionReceiptSigner, "prod"),
        100,
    )
    .unwrap();
    reg.create_cell(
        input("evidence", CellFunction::EvidenceAccumulator, "prod"),
        200,
    )
    .unwrap();
    reg.create_cell(
        input("evaluator", CellFunction::PolicyEvaluator, "prod"),
        300,
    )
    .unwrap();

    assert_eq!(
        reg.cells_by_function(CellFunction::DecisionReceiptSigner)
            .len(),
        1
    );
    assert_eq!(
        reg.cells_by_function(CellFunction::EvidenceAccumulator)
            .len(),
        1
    );
    assert_eq!(reg.cells_by_function(CellFunction::ProofValidator).len(), 0);
}

#[test]
fn cells_in_zone_returns_correct_subset() {
    let mut reg = CellRegistry::new();
    reg.create_cell(
        input(
            "prod-cell",
            CellFunction::DecisionReceiptSigner,
            "production",
        ),
        100,
    )
    .unwrap();
    reg.create_cell(
        input("staging-cell", CellFunction::EvidenceAccumulator, "staging"),
        200,
    )
    .unwrap();

    assert_eq!(reg.cells_in_zone("production").len(), 1);
    assert_eq!(reg.cells_in_zone("staging").len(), 1);
    assert_eq!(reg.cells_in_zone("dev").len(), 0);
}

#[test]
fn active_cells_only_returns_active() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    drive_to_active(
        &mut reg,
        &tr,
        "active-1",
        CellFunction::PolicyEvaluator,
        "z",
    );
    // Leave another in Provisioning
    reg.create_cell(input("prov-1", CellFunction::ProofValidator, "z"), 500)
        .unwrap();

    assert_eq!(reg.active_cells().len(), 1);
    assert_eq!(reg.cell_count(), 2);
}

#[test]
fn get_returns_none_for_unknown_id() {
    let reg = CellRegistry::new();
    assert!(reg.get("nonexistent").is_none());
}

// ===========================================================================
// Section 15: CellRegistry — events and audit trail
// ===========================================================================

#[test]
fn events_sequential_seq_numbers() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let _cid_s = drive_to_active(&mut reg, &tr, "ev", CellFunction::PolicyEvaluator, "z");

    let events = reg.events();
    assert_eq!(events.len(), 4); // Created, Measured, Attested, Activated
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.seq, i as u64);
    }
}

#[test]
fn events_correct_types_for_full_lifecycle() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(&mut reg, &tr, "ev2", CellFunction::PolicyEvaluator, "z");
    reg.suspend_cell(&cid_s, "test", 500, ep(1)).unwrap();
    reg.decommission_cell(&cid_s, "done", 600, ep(1)).unwrap();

    let types: Vec<_> = reg.events().iter().map(|e| &e.event_type).collect();
    assert!(matches!(types[0], CellEventType::Created));
    assert!(matches!(types[1], CellEventType::Measured));
    assert!(matches!(types[2], CellEventType::Attested));
    assert!(matches!(types[3], CellEventType::Activated));
    assert!(matches!(types[4], CellEventType::Suspended { .. }));
    assert!(matches!(types[5], CellEventType::Decommissioned { .. }));
}

#[test]
fn reattestation_event_emitted_on_suspended_to_attested() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(&mut reg, &tr, "re", CellFunction::PolicyEvaluator, "z");
    reg.suspend_cell(&cid_s, "rev", 500, ep(1)).unwrap();

    let m = meas(&tr);
    let mut q2 = tr.attest(&m, [9u8; 32], 1_000_000_000);
    q2.issued_at_ns = 600;
    reg.attest_cell(&cid_s, q2, 700, ep(1)).unwrap();

    let last = reg.events().last().unwrap();
    assert!(matches!(
        last.event_type,
        CellEventType::ReattestationSucceeded
    ));
}

#[test]
fn events_have_correct_cell_id_and_epoch() {
    let mut reg = CellRegistry::new();
    let cid = reg
        .create_cell(input("ev3", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let cid_s = format!("{cid}");

    let ev = &reg.events()[0];
    assert_eq!(ev.cell_id, cid_s);
    assert_eq!(ev.epoch, ep(1));
}

// ===========================================================================
// Section 16: CellRegistry — serde roundtrip
// ===========================================================================

#[test]
fn registry_serde_roundtrip_preserves_cells() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    drive_to_active(&mut reg, &tr, "ser1", CellFunction::PolicyEvaluator, "z");
    reg.create_cell(input("ser2", CellFunction::ProofValidator, "z"), 500)
        .unwrap();

    let json = serde_json::to_string(&reg).unwrap();
    let restored: CellRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.cell_count(), 2);
}

#[test]
fn execution_cell_serde_roundtrip() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(
        &mut reg,
        &tr,
        "cell-serde",
        CellFunction::PolicyEvaluator,
        "z",
    );
    let cell = reg.get(&cid_s).unwrap();

    let json = serde_json::to_string(cell).unwrap();
    let restored: ExecutionCell = serde_json::from_str(&json).unwrap();
    assert_eq!(*cell, restored);
}

// ===========================================================================
// Section 17: LifecycleReceipt
// ===========================================================================

#[test]
fn lifecycle_receipts_accumulated_through_transitions() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid_s = drive_to_active(&mut reg, &tr, "rec", CellFunction::PolicyEvaluator, "z");

    let receipts = &reg.get(&cid_s).unwrap().transition_receipts;
    assert_eq!(receipts.len(), 3); // Prov->Meas, Meas->Att, Att->Active
    assert_eq!(receipts[0].from_state, CellLifecycle::Provisioning);
    assert_eq!(receipts[0].to_state, CellLifecycle::Measured);
    assert_eq!(receipts[1].from_state, CellLifecycle::Measured);
    assert_eq!(receipts[1].to_state, CellLifecycle::Attested);
    assert_eq!(receipts[2].from_state, CellLifecycle::Attested);
    assert_eq!(receipts[2].to_state, CellLifecycle::Active);
}

#[test]
fn lifecycle_receipt_serde_roundtrip() {
    let receipt = LifecycleReceipt {
        from_state: CellLifecycle::Active,
        to_state: CellLifecycle::Suspended,
        timestamp_ns: 12345,
        epoch: ep(3),
        reason: "trust root rotation".to_string(),
        signature_bytes: vec![1, 2, 3, 4],
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: LifecycleReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

// ===========================================================================
// Section 18: FallbackPolicy
// ===========================================================================

#[test]
fn fallback_policy_defaults() {
    let fp = FallbackPolicy::default();
    assert!(fp.auto_fallback);
    assert!(fp.challenge_on_fallback);
    assert!(fp.sandbox_on_fallback);
    assert!(fp.high_impact_actions.is_empty());
}

#[test]
fn fallback_policy_serde_roundtrip() {
    let mut fp = FallbackPolicy::default();
    fp.high_impact_actions.insert("deploy".to_string());
    fp.high_impact_actions.insert("promote".to_string());
    fp.auto_fallback = false;
    let json = serde_json::to_string(&fp).unwrap();
    let restored: FallbackPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, restored);
}

// ===========================================================================
// Section 19: CellEvent / CellEventType
// ===========================================================================

#[test]
fn cell_event_serde_roundtrip() {
    let event = CellEvent {
        seq: 42,
        timestamp_ns: 1_000_000,
        epoch: ep(5),
        cell_id: "test-cell-99".to_string(),
        event_type: CellEventType::FallbackActivated {
            reason: "attestation expired".to_string(),
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: CellEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn cell_event_type_serde_all_variants() {
    let types: Vec<CellEventType> = vec![
        CellEventType::Created,
        CellEventType::Measured,
        CellEventType::Attested,
        CellEventType::Activated,
        CellEventType::Suspended {
            reason: "r".to_string(),
        },
        CellEventType::Decommissioned {
            reason: "d".to_string(),
        },
        CellEventType::FallbackActivated {
            reason: "f".to_string(),
        },
        CellEventType::ReattestationSucceeded,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let restored: CellEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, restored);
    }
}

// ===========================================================================
// Section 20: Multi-cell registry scenarios
// ===========================================================================

#[test]
fn registry_manages_many_cells_across_zones_and_functions() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);

    drive_to_active(
        &mut reg,
        &tr,
        "prod-signer",
        CellFunction::DecisionReceiptSigner,
        "prod",
    );
    drive_to_active(
        &mut reg,
        &tr,
        "prod-evidence",
        CellFunction::EvidenceAccumulator,
        "prod",
    );
    drive_to_active(
        &mut reg,
        &tr,
        "staging-eval",
        CellFunction::PolicyEvaluator,
        "staging",
    );
    reg.create_cell(input("dev-ext", CellFunction::ExtensionRuntime, "dev"), 900)
        .unwrap();

    assert_eq!(reg.cell_count(), 4);
    assert_eq!(reg.active_cells().len(), 3);
    assert_eq!(reg.cells_in_zone("prod").len(), 2);
    assert_eq!(reg.cells_in_zone("staging").len(), 1);
    assert_eq!(reg.cells_in_zone("dev").len(), 1);
    assert_eq!(
        reg.cells_by_function(CellFunction::DecisionReceiptSigner)
            .len(),
        1
    );
    assert_eq!(
        reg.cells_by_function(CellFunction::ExtensionRuntime).len(),
        1
    );
}

#[test]
fn epoch_updates_on_transitions() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid = reg
        .create_cell(input("ep-test", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");

    assert_eq!(reg.get(&s).unwrap().epoch, ep(1));

    let m = meas(&tr);
    reg.measure_cell(&s, m.clone(), 200, ep(2)).unwrap();
    assert_eq!(reg.get(&s).unwrap().epoch, ep(2));

    let q = fresh_quote(&tr, &m, [1u8; 32]);
    reg.attest_cell(&s, q, 300, ep(3)).unwrap();
    assert_eq!(reg.get(&s).unwrap().epoch, ep(3));

    reg.activate_cell(&s, 400, ep(4)).unwrap();
    assert_eq!(reg.get(&s).unwrap().epoch, ep(4));

    reg.suspend_cell(&s, "test", 500, ep(5)).unwrap();
    assert_eq!(reg.get(&s).unwrap().epoch, ep(5));
}

#[test]
fn measurement_records_on_cell() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid = reg
        .create_cell(input("meas-test", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");

    let m = meas(&tr);
    reg.measure_cell(&s, m.clone(), 200, ep(1)).unwrap();

    let cell = reg.get(&s).unwrap();
    assert_eq!(cell.measurement.as_ref().unwrap(), &m);
}

#[test]
fn attestation_records_on_cell() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid = reg
        .create_cell(input("att-test", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");

    let m = meas(&tr);
    reg.measure_cell(&s, m.clone(), 200, ep(1)).unwrap();
    let q = fresh_quote(&tr, &m, [7u8; 32]);
    reg.attest_cell(&s, q.clone(), 300, ep(1)).unwrap();

    let cell = reg.get(&s).unwrap();
    assert_eq!(cell.attestation.as_ref().unwrap(), &q);
}

#[test]
fn cannot_measure_twice_from_measured_state() {
    let mut reg = CellRegistry::new();
    let tr = root("k1", 10);
    let cid = reg
        .create_cell(input("twice", CellFunction::PolicyEvaluator, "z"), 100)
        .unwrap();
    let s = format!("{cid}");
    reg.measure_cell(&s, meas(&tr), 200, ep(1)).unwrap();
    // Second measure should fail (cell is now Measured, not Provisioning)
    assert!(matches!(
        reg.measure_cell(&s, meas(&tr), 300, ep(1)),
        Err(CellError::InvalidTransition { .. })
    ));
}

#[test]
fn quote_saturating_add_handles_u64_max() {
    let tr = root("k1", 10);
    let m = meas(&tr);
    let mut q = tr.attest(&m, [0u8; 32], u64::MAX);
    q.issued_at_ns = u64::MAX;
    // Should not panic due to overflow; saturating_add wraps at u64::MAX
    assert!(q.is_fresh_at(u64::MAX));
}
