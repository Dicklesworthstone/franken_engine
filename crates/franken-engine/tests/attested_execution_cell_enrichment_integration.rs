//! Enrichment integration tests for `attested_execution_cell`.
//!
//! Covers: CellLifecycle Display/serde, TrustLevel Display/serde,
//! PlatformKind Display/serde, CellFunction Display/serde,
//! MeasurementDigest lifecycle, AttestationQuote freshness,
//! SoftwareTrustRoot measure/attest/verify, CellRegistry CRUD,
//! lifecycle transitions, revocation, FallbackPolicy, CellError Display,
//! CellEvent auditing, VerificationResult, and deterministic hashing.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::attested_execution_cell::{
    AttestationQuote, CellError, CellFunction, CellLifecycle,
    CellRegistry, CreateCellInput, FallbackPolicy,
    MeasurementDigest, PlatformKind, SoftwareTrustRoot, TrustLevel, TrustRootBackend,
    VerificationResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

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
    tr.measure(b"code-v1", b"config-v1", b"policy-v1", b"schema-v1", "1.0.0")
}

fn fresh_quote(tr: &SoftwareTrustRoot, m: &MeasurementDigest, nonce: [u8; 32]) -> AttestationQuote {
    tr.attest(m, nonce, 1_000_000_000, 1_000)
}

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
// CellLifecycle Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_cell_lifecycle_display_all_unique() {
    let all = [
        CellLifecycle::Provisioning,
        CellLifecycle::Measured,
        CellLifecycle::Attested,
        CellLifecycle::Active,
        CellLifecycle::Suspended,
        CellLifecycle::Decommissioned,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_cell_lifecycle_serde_roundtrip() {
    let all = [
        CellLifecycle::Provisioning,
        CellLifecycle::Measured,
        CellLifecycle::Attested,
        CellLifecycle::Active,
        CellLifecycle::Suspended,
        CellLifecycle::Decommissioned,
    ];
    for state in &all {
        let json = serde_json::to_string(state).unwrap();
        let back: CellLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

#[test]
fn enrichment_cell_lifecycle_is_operational() {
    assert!(!CellLifecycle::Provisioning.is_operational());
    assert!(!CellLifecycle::Measured.is_operational());
    assert!(!CellLifecycle::Attested.is_operational());
    assert!(CellLifecycle::Active.is_operational());
    assert!(!CellLifecycle::Suspended.is_operational());
    assert!(!CellLifecycle::Decommissioned.is_operational());
}

#[test]
fn enrichment_cell_lifecycle_allows_reattestation() {
    assert!(!CellLifecycle::Provisioning.allows_reattestation());
    assert!(CellLifecycle::Measured.allows_reattestation());
    assert!(!CellLifecycle::Attested.allows_reattestation());
    assert!(!CellLifecycle::Active.allows_reattestation());
    assert!(CellLifecycle::Suspended.allows_reattestation());
    assert!(!CellLifecycle::Decommissioned.allows_reattestation());
}

// ===========================================================================
// TrustLevel Display and serde
// ===========================================================================

#[test]
fn enrichment_trust_level_display_all_unique() {
    let all = [TrustLevel::SoftwareOnly, TrustLevel::Hybrid, TrustLevel::Hardware];
    let displays: BTreeSet<String> = all.iter().map(|t| t.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_trust_level_serde_roundtrip() {
    let all = [TrustLevel::SoftwareOnly, TrustLevel::Hybrid, TrustLevel::Hardware];
    for level in &all {
        let json = serde_json::to_string(level).unwrap();
        let back: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*level, back);
    }
}

#[test]
fn enrichment_trust_level_ordering() {
    assert!(TrustLevel::SoftwareOnly < TrustLevel::Hybrid);
    assert!(TrustLevel::Hybrid < TrustLevel::Hardware);
}

// ===========================================================================
// PlatformKind Display and serde
// ===========================================================================

#[test]
fn enrichment_platform_kind_display_all_unique() {
    let all = [PlatformKind::IntelSgx, PlatformKind::ArmCca, PlatformKind::AmdSevSnp, PlatformKind::Software];
    let displays: BTreeSet<String> = all.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_platform_kind_serde_roundtrip() {
    let all = [PlatformKind::IntelSgx, PlatformKind::ArmCca, PlatformKind::AmdSevSnp, PlatformKind::Software];
    for platform in &all {
        let json = serde_json::to_string(platform).unwrap();
        let back: PlatformKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*platform, back);
    }
}

// ===========================================================================
// CellFunction Display and serde
// ===========================================================================

#[test]
fn enrichment_cell_function_display_all_unique() {
    let all = [
        CellFunction::DecisionReceiptSigner,
        CellFunction::EvidenceAccumulator,
        CellFunction::PolicyEvaluator,
        CellFunction::ProofValidator,
        CellFunction::ExtensionRuntime,
    ];
    let displays: BTreeSet<String> = all.iter().map(|f| f.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_cell_function_serde_roundtrip() {
    let all = [
        CellFunction::DecisionReceiptSigner,
        CellFunction::EvidenceAccumulator,
        CellFunction::PolicyEvaluator,
        CellFunction::ProofValidator,
        CellFunction::ExtensionRuntime,
    ];
    for func in &all {
        let json = serde_json::to_string(func).unwrap();
        let back: CellFunction = serde_json::from_str(&json).unwrap();
        assert_eq!(*func, back);
    }
}

// ===========================================================================
// SoftwareTrustRoot lifecycle
// ===========================================================================

#[test]
fn enrichment_software_trust_root_trust_level() {
    let tr = root("key-1", 42);
    assert_eq!(tr.trust_level(), TrustLevel::SoftwareOnly);
}

#[test]
fn enrichment_software_trust_root_platform() {
    let tr = root("key-1", 42);
    assert_eq!(tr.platform(), PlatformKind::Software);
}

#[test]
fn enrichment_software_trust_root_measure_deterministic() {
    let tr = root("key-1", 42);
    let m1 = tr.measure(b"code", b"cfg", b"pol", b"sch", "1.0");
    let m2 = tr.measure(b"code", b"cfg", b"pol", b"sch", "1.0");
    assert_eq!(m1, m2);
}

#[test]
fn enrichment_software_trust_root_measure_different_inputs() {
    let tr = root("key-1", 42);
    let m1 = tr.measure(b"code-a", b"cfg", b"pol", b"sch", "1.0");
    let m2 = tr.measure(b"code-b", b"cfg", b"pol", b"sch", "1.0");
    assert_ne!(m1.code_hash, m2.code_hash);
}

#[test]
fn enrichment_software_trust_root_verify_valid() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let q = tr.attest(&m, nonce, 1_000_000_000, 1_000);
    let result = tr.verify(&q, &m, &nonce, 500_000);
    assert!(result.is_valid());
}

#[test]
fn enrichment_software_trust_root_verify_expired() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let q = tr.attest(&m, nonce, 100, 1_000); // validity=100ns, issued_at=1000
    let result = tr.verify(&q, &m, &nonce, 2_000); // checked_at=2000, well past expiry
    assert!(!result.is_valid());
    assert!(matches!(result, VerificationResult::Expired { .. }));
}

#[test]
fn enrichment_software_trust_root_verify_nonce_mismatch() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let q = tr.attest(&m, nonce, 1_000_000_000, 1_000);
    let wrong_nonce = [2u8; 32];
    let result = tr.verify(&q, &m, &wrong_nonce, 500_000);
    assert!(!result.is_valid());
    assert!(matches!(result, VerificationResult::NonceMismatch));
}

#[test]
fn enrichment_software_trust_root_verify_measurement_mismatch() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let q = tr.attest(&m, nonce, 1_000_000_000, 1_000);
    let different_m = tr.measure(b"different-code", b"cfg", b"pol", b"sch", "2.0");
    let result = tr.verify(&q, &different_m, &nonce, 500_000);
    assert!(!result.is_valid());
    assert!(matches!(result, VerificationResult::MeasurementMismatch { .. }));
}

#[test]
fn enrichment_software_trust_root_revoke_key() {
    let mut tr = root("key-1", 42);
    let m = meas(&tr);
    let nonce = [1u8; 32];
    let q = tr.attest(&m, nonce, 1_000_000_000, 1_000);
    tr.revoke_key("key-1");
    let result = tr.verify(&q, &m, &nonce, 500_000);
    assert!(!result.is_valid());
    assert!(matches!(result, VerificationResult::SignerRevoked { .. }));
}

// ===========================================================================
// MeasurementDigest
// ===========================================================================

#[test]
fn enrichment_measurement_digest_canonical_bytes_deterministic() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let bytes1 = m.canonical_bytes();
    let bytes2 = m.canonical_bytes();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn enrichment_measurement_digest_composite_hash_deterministic() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let h1 = m.composite_hash();
    let h2 = m.composite_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_measurement_digest_serde_roundtrip() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let json = serde_json::to_string(&m).unwrap();
    let back: MeasurementDigest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ===========================================================================
// AttestationQuote freshness
// ===========================================================================

#[test]
fn enrichment_attestation_quote_fresh_within_window() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let q = tr.attest(&m, [1u8; 32], 1_000_000, 100);
    assert!(q.is_fresh_at(500_000));
    assert!(!q.is_expired_at(500_000));
}

#[test]
fn enrichment_attestation_quote_expired_beyond_window() {
    let tr = root("key-1", 42);
    let m = meas(&tr);
    let q = tr.attest(&m, [1u8; 32], 100, 100);
    assert!(q.is_expired_at(500));
    assert!(!q.is_fresh_at(500));
}

// ===========================================================================
// VerificationResult Display
// ===========================================================================

#[test]
fn enrichment_verification_result_display_all_unique() {
    let all = [
        VerificationResult::Valid,
        VerificationResult::MeasurementMismatch {
            expected: ContentHash::compute(b"a"),
            actual: ContentHash::compute(b"b"),
        },
        VerificationResult::SignatureInvalid,
        VerificationResult::Expired { issued_at_ns: 100, validity_window_ns: 50, checked_at_ns: 200 },
        VerificationResult::NonceMismatch,
        VerificationResult::SignerRevoked { key_id: "test-key".to_string() },
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

// ===========================================================================
// CellRegistry CRUD and lifecycle
// ===========================================================================

#[test]
fn enrichment_registry_create_cell() {
    let mut reg = CellRegistry::new();
    let cid = reg.create_cell(input("cell-1", CellFunction::DecisionReceiptSigner, "zone-a"), 100);
    assert!(cid.is_ok());
    assert_eq!(reg.cell_count(), 1);
}

#[test]
fn enrichment_registry_create_duplicate_error() {
    let mut reg = CellRegistry::new();
    let _ = reg.create_cell(input("cell-1", CellFunction::DecisionReceiptSigner, "zone-a"), 100).unwrap();
    let result = reg.create_cell(input("cell-1", CellFunction::DecisionReceiptSigner, "zone-a"), 200);
    assert!(matches!(result, Err(CellError::Duplicate { .. })));
}

#[test]
fn enrichment_registry_empty_label_error() {
    let mut reg = CellRegistry::new();
    let result = reg.create_cell(input("", CellFunction::DecisionReceiptSigner, "zone-a"), 100);
    assert!(matches!(result, Err(CellError::EmptyLabel)));
}

#[test]
fn enrichment_registry_empty_zone_error() {
    let mut reg = CellRegistry::new();
    let result = reg.create_cell(input("cell-1", CellFunction::DecisionReceiptSigner, ""), 100);
    assert!(matches!(result, Err(CellError::EmptyZone)));
}

#[test]
fn enrichment_registry_empty_authority_error() {
    let mut reg = CellRegistry::new();
    let inp = CreateCellInput {
        label: "cell-1".to_string(),
        function: CellFunction::DecisionReceiptSigner,
        zone: "zone-a".to_string(),
        epoch: ep(1),
        trust_level: TrustLevel::SoftwareOnly,
        authority_envelope: BTreeSet::new(),
    };
    let result = reg.create_cell(inp, 100);
    assert!(matches!(result, Err(CellError::EmptyAuthority)));
}

#[test]
fn enrichment_registry_full_lifecycle() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    let cid = drive_to_active(&mut reg, &tr, "lifecycle-cell", CellFunction::EvidenceAccumulator, "zone-b");

    let cell = reg.get(&cid).unwrap();
    assert_eq!(cell.lifecycle, CellLifecycle::Active);
    assert!(cell.lifecycle.is_operational());

    // Suspend
    reg.suspend_cell(&cid, "maintenance", 500, ep(2)).unwrap();
    let cell = reg.get(&cid).unwrap();
    assert_eq!(cell.lifecycle, CellLifecycle::Suspended);

    // Decommission from suspended
    reg.decommission_cell(&cid, "end of life", 600, ep(3)).unwrap();
    let cell = reg.get(&cid).unwrap();
    assert_eq!(cell.lifecycle, CellLifecycle::Decommissioned);
}

#[test]
fn enrichment_registry_invalid_transition_error() {
    let mut reg = CellRegistry::new();
    let cid = reg.create_cell(input("trans-cell", CellFunction::PolicyEvaluator, "zone-c"), 100).unwrap();
    let cid_s = format!("{cid}");
    // Cannot activate a provisioning cell
    let result = reg.activate_cell(&cid_s, 200, ep(1));
    assert!(matches!(result, Err(CellError::InvalidTransition { .. })));
}

// ===========================================================================
// CellRegistry lookups
// ===========================================================================

#[test]
fn enrichment_registry_cells_by_function() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    drive_to_active(&mut reg, &tr, "signer-1", CellFunction::DecisionReceiptSigner, "zone-a");
    drive_to_active(&mut reg, &tr, "eval-1", CellFunction::PolicyEvaluator, "zone-a");
    let signers = reg.cells_by_function(CellFunction::DecisionReceiptSigner);
    assert_eq!(signers.len(), 1);
}

#[test]
fn enrichment_registry_active_cells() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    drive_to_active(&mut reg, &tr, "active-1", CellFunction::EvidenceAccumulator, "zone-a");
    let _ = reg.create_cell(input("inactive-1", CellFunction::ProofValidator, "zone-a"), 100);
    let active = reg.active_cells();
    assert_eq!(active.len(), 1);
}

#[test]
fn enrichment_registry_cells_in_zone() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    drive_to_active(&mut reg, &tr, "zone-test-1", CellFunction::ExtensionRuntime, "prod");
    drive_to_active(&mut reg, &tr, "zone-test-2", CellFunction::PolicyEvaluator, "staging");
    let prod_cells = reg.cells_in_zone("prod");
    assert_eq!(prod_cells.len(), 1);
}

#[test]
fn enrichment_registry_not_found_error() {
    let reg = CellRegistry::new();
    assert!(reg.get("nonexistent").is_none());
}

// ===========================================================================
// CellRegistry revocation
// ===========================================================================

#[test]
fn enrichment_registry_revoke_trust_root_suspends_active() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    let cid = drive_to_active(&mut reg, &tr, "revoke-cell", CellFunction::DecisionReceiptSigner, "zone-a");
    let suspended = reg.revoke_trust_root("key-1", 500, ep(2));
    assert_eq!(suspended.len(), 1);
    assert_eq!(suspended[0], cid);
    let cell = reg.get(&cid).unwrap();
    assert_eq!(cell.lifecycle, CellLifecycle::Suspended);
}

#[test]
fn enrichment_registry_revoke_trust_root_ignores_non_matching() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    drive_to_active(&mut reg, &tr, "safe-cell", CellFunction::EvidenceAccumulator, "zone-a");
    let suspended = reg.revoke_trust_root("different-key", 500, ep(2));
    assert!(suspended.is_empty());
}

// ===========================================================================
// CellEvent auditing
// ===========================================================================

#[test]
fn enrichment_registry_events_accumulate() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    drive_to_active(&mut reg, &tr, "event-cell", CellFunction::ProofValidator, "zone-a");
    // create, measure, attest, activate = 4 events
    assert_eq!(reg.events().len(), 4);
}

#[test]
fn enrichment_registry_event_seq_monotonic() {
    let mut reg = CellRegistry::new();
    let tr = root("key-1", 42);
    drive_to_active(&mut reg, &tr, "seq-cell", CellFunction::ExtensionRuntime, "zone-a");
    for window in reg.events().windows(2) {
        assert!(window[0].seq < window[1].seq);
    }
}

// ===========================================================================
// FallbackPolicy
// ===========================================================================

#[test]
fn enrichment_fallback_policy_default() {
    let policy = FallbackPolicy::default();
    assert!(policy.auto_fallback);
    assert!(policy.challenge_on_fallback);
    assert!(policy.sandbox_on_fallback);
    assert!(policy.high_impact_actions.is_empty());
}

#[test]
fn enrichment_fallback_policy_serde_roundtrip() {
    let mut policy = FallbackPolicy::default();
    policy.high_impact_actions.insert("deploy".to_string());
    let json = serde_json::to_string(&policy).unwrap();
    let back: FallbackPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ===========================================================================
// CellError Display
// ===========================================================================

#[test]
fn enrichment_cell_error_display_all_unique() {
    let errors: Vec<CellError> = vec![
        CellError::IdDerivation("test".to_string()),
        CellError::NotFound { cell_id: "abc".to_string() },
        CellError::Duplicate { cell_id: "def".to_string() },
        CellError::InvalidTransition { from: CellLifecycle::Provisioning, to: CellLifecycle::Active },
        CellError::NotOperational { lifecycle: CellLifecycle::Suspended },
        CellError::AttestationFailed { reason: "expired".to_string() },
        CellError::NotMeasured,
        CellError::TrustRootRevoked { key_id: "key-1".to_string() },
        CellError::EmptyLabel,
        CellError::EmptyZone,
        CellError::EmptyAuthority,
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_cell_error_serde_roundtrip() {
    let errors = [
        CellError::NotMeasured,
        CellError::EmptyLabel,
        CellError::EmptyZone,
        CellError::EmptyAuthority,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CellError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// CellRegistry Default
// ===========================================================================

#[test]
fn enrichment_registry_default_empty() {
    let reg = CellRegistry::default();
    assert_eq!(reg.cell_count(), 0);
    assert!(reg.events().is_empty());
    assert!(reg.active_cells().is_empty());
}
