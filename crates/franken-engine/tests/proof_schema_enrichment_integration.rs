#![forbid(unsafe_code)]

//! Enrichment integration tests for the `proof_schema` module.
//!
//! Covers Clone independence, BTreeSet ordering, Debug/Default, serde
//! field-name stability, std::error::Error, determinism, and edge cases
//! not covered by the existing proof_schema_integration.rs.

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

use frankenengine_engine::control_plane::SchemaVersion;
use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::proof_schema::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tee_attestation_policy::DecisionImpact;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const TEST_KEY: &[u8] = b"enrichment-signing-key-material!";

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn signer_key_id() -> EngineObjectId {
    let schema = SchemaId::from_definition(b"enrich-signer-key");
    derive_id(
        ObjectDomain::CapabilityToken,
        "enrich-zone",
        &schema,
        b"key-e",
    )
    .expect("derive id")
}

fn make_invariance_digest() -> InvarianceDigest {
    InvarianceDigest {
        schema_version: proof_schema_version_current(),
        golden_corpus_hash: ContentHash::compute(b"golden-corpus-enrich"),
        trace_comparison_methodology: TraceComparisonMethodology::DeterministicReplay,
        equivalence_verdict: EquivalenceVerdict::Equivalent,
        witness_chain_root: ContentHash::compute(b"witness-chain-enrich"),
    }
}

fn make_attestation_bindings() -> ReceiptAttestationBindings {
    ReceiptAttestationBindings {
        quote_digest: ContentHash::compute(b"quote-enrich"),
        measurement_id: derive_id(
            ObjectDomain::Attestation,
            "enrich-zone",
            &SchemaId::from_definition(b"measurement-enrich"),
            b"measurement-v1",
        )
        .expect("measurement id"),
        attested_signer_key_id: signer_key_id(),
        nonce: [11u8; 32],
        validity_window: AttestationValidityWindow {
            start_timestamp_ticks: 900,
            end_timestamp_ticks: 1200,
        },
    }
}

fn unsigned_receipt() -> OptReceipt {
    let digest = make_invariance_digest();
    OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: "opt-enr-001".to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline-ir-enrich"),
        candidate_ir_hash: ContentHash::compute(b"candidate-ir-enrich"),
        translation_witness_hash: ContentHash::compute(b"witness-enrich"),
        invariance_digest: digest.content_hash(),
        rollback_token_id: "rtk-enr-001".to_string(),
        replay_compatibility: BTreeMap::from([
            ("engine_version".to_string(), "0.1.0".to_string()),
            ("target_arch".to_string(), "x86_64".to_string()),
        ]),
        policy_epoch: epoch(5),
        timestamp_ticks: 1000,
        signer_key_id: signer_key_id(),
        correlation_id: "corr-enr-001".to_string(),
        decision_impact: DecisionImpact::Standard,
        attestation_bindings: None,
        signature: AuthenticityHash::compute(b"placeholder"),
    }
}

fn signed_receipt() -> OptReceipt {
    unsigned_receipt().sign(TEST_KEY)
}

fn unsigned_rollback() -> RollbackToken {
    RollbackToken {
        schema_version: proof_schema_version_current(),
        token_id: "rtk-enr-001".to_string(),
        optimization_id: "opt-enr-001".to_string(),
        baseline_snapshot_hash: ContentHash::compute(b"baseline-snapshot-enrich"),
        activation_stage: ActivationStage::Shadow,
        expiry_epoch: epoch(20),
        issuer_key_id: signer_key_id(),
        issuer_signature: AuthenticityHash::compute(b"placeholder"),
    }
}

fn signed_rollback() -> RollbackToken {
    unsigned_rollback().sign(TEST_KEY)
}

// ===========================================================================
// Copy semantics (ActivationStage, SignerRole have Copy)
// ===========================================================================

#[test]
fn enrichment_activation_stage_copy() {
    let a = ActivationStage::Shadow;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_signer_role_copy() {
    let a = SignerRole::OptimizerSubsystem;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn enrichment_invariance_digest_clone_independence() {
    let original = make_invariance_digest();
    let mut cloned = original.clone();
    cloned.golden_corpus_hash = ContentHash::compute(b"mutated");
    assert_ne!(original.golden_corpus_hash, cloned.golden_corpus_hash);
    assert_eq!(
        original.golden_corpus_hash,
        ContentHash::compute(b"golden-corpus-enrich")
    );
}

#[test]
fn enrichment_opt_receipt_clone_independence() {
    let original = signed_receipt();
    let mut cloned = original.clone();
    cloned.optimization_id = "mutated-id".to_string();
    assert_eq!(original.optimization_id, "opt-enr-001");
    assert_ne!(original.optimization_id, cloned.optimization_id);
}

#[test]
fn enrichment_rollback_token_clone_independence() {
    let original = signed_rollback();
    let mut cloned = original.clone();
    cloned.token_id = "mutated-token".to_string();
    assert_eq!(original.token_id, "rtk-enr-001");
    assert_ne!(original.token_id, cloned.token_id);
}

#[test]
fn enrichment_signer_key_id_clone_independence() {
    let original = SignerKeyId {
        key_id: signer_key_id(),
        role: SignerRole::OptimizerSubsystem,
        bound_epoch: epoch(1),
    };
    let cloned = original.clone();
    assert_eq!(original.role, cloned.role);
    assert_eq!(original.bound_epoch, cloned.bound_epoch);
}

#[test]
fn enrichment_attestation_bindings_clone_independence() {
    let original = make_attestation_bindings();
    let mut cloned = original.clone();
    cloned.nonce = [99u8; 32];
    assert_eq!(original.nonce, [11u8; 32]);
    assert_ne!(original.nonce, cloned.nonce);
}

#[test]
fn enrichment_attestation_validity_window_clone_independence() {
    let original = AttestationValidityWindow {
        start_timestamp_ticks: 100,
        end_timestamp_ticks: 200,
    };
    let cloned = original.clone();
    assert_eq!(cloned.start_timestamp_ticks, 100);
    assert_eq!(cloned.end_timestamp_ticks, 200);
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_attestation_requirement_policy_clone_independence() {
    let original = AttestationRequirementPolicy::default();
    let mut cloned = original.clone();
    cloned.allow_legacy_receipts_without_attestation = false;
    assert!(original.allow_legacy_receipts_without_attestation);
    assert!(!cloned.allow_legacy_receipts_without_attestation);
}

#[test]
fn enrichment_nonce_registry_clone_independence() {
    let mut original = ReceiptNonceRegistry::new();
    let key_id = signer_key_id();
    original
        .check_and_record(&key_id, [1u8; 32])
        .expect("first nonce");
    let mut cloned = original.clone();
    // Cloned registry should also reject same nonce (it has the same state)
    assert!(cloned.check_and_record(&key_id, [1u8; 32]).is_err());
    // But accept a new nonce
    assert!(cloned.check_and_record(&key_id, [2u8; 32]).is_ok());
}

#[test]
fn enrichment_proof_schema_error_clone_independence() {
    let original = ProofSchemaError::MissingField {
        field: "test_field".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ===========================================================================
// BTreeSet ordering
// ===========================================================================

#[test]
fn enrichment_optimization_class_btreeset_ordering() {
    let variants: BTreeSet<OptimizationClass> = [
        OptimizationClass::DevirtualizedHostcallFastPath,
        OptimizationClass::Superinstruction,
        OptimizationClass::TraceSpecialization,
        OptimizationClass::LayoutSpecialization,
    ]
    .into_iter()
    .collect();
    assert_eq!(variants.len(), 4);
    // Ord is derived so order is declaration order
    let ordered: Vec<_> = variants.into_iter().collect();
    assert_eq!(ordered[0], OptimizationClass::Superinstruction);
}

#[test]
fn enrichment_activation_stage_btreeset_ordering() {
    let variants: BTreeSet<ActivationStage> = [
        ActivationStage::Default,
        ActivationStage::Shadow,
        ActivationStage::Ramp,
        ActivationStage::Canary,
    ]
    .into_iter()
    .collect();
    assert_eq!(variants.len(), 4);
    let ordered: Vec<_> = variants.into_iter().collect();
    assert_eq!(ordered[0], ActivationStage::Shadow);
}

#[test]
fn enrichment_signer_role_btreeset_ordering() {
    let variants: BTreeSet<SignerRole> = [
        SignerRole::AttestationCell,
        SignerRole::OptimizerSubsystem,
        SignerRole::PolicyPlane,
    ]
    .into_iter()
    .collect();
    assert_eq!(variants.len(), 3);
    let ordered: Vec<_> = variants.into_iter().collect();
    assert_eq!(ordered[0], SignerRole::OptimizerSubsystem);
}

#[test]
fn enrichment_signer_key_id_btreeset_ordering() {
    let a = SignerKeyId {
        key_id: signer_key_id(),
        role: SignerRole::OptimizerSubsystem,
        bound_epoch: epoch(1),
    };
    let b = SignerKeyId {
        key_id: signer_key_id(),
        role: SignerRole::PolicyPlane,
        bound_epoch: epoch(1),
    };
    let set: BTreeSet<_> = [b.clone(), a.clone()].into_iter().collect();
    assert_eq!(set.len(), 2);
    let first = set.iter().next().unwrap();
    assert_eq!(first.role, SignerRole::OptimizerSubsystem);
}

// ===========================================================================
// Debug nonempty
// ===========================================================================

#[test]
fn enrichment_optimization_class_debug() {
    let dbg = format!("{:?}", OptimizationClass::Superinstruction);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Superinstruction"));
}

#[test]
fn enrichment_activation_stage_debug() {
    let dbg = format!("{:?}", ActivationStage::Canary);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Canary"));
}

#[test]
fn enrichment_signer_role_debug() {
    let dbg = format!("{:?}", SignerRole::PolicyPlane);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("PolicyPlane"));
}

#[test]
fn enrichment_invariance_digest_debug() {
    let dbg = format!("{:?}", make_invariance_digest());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("InvarianceDigest"));
}

#[test]
fn enrichment_opt_receipt_debug() {
    let dbg = format!("{:?}", signed_receipt());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("OptReceipt"));
}

#[test]
fn enrichment_rollback_token_debug() {
    let dbg = format!("{:?}", signed_rollback());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("RollbackToken"));
}

#[test]
fn enrichment_proof_schema_error_debug() {
    let dbg = format!(
        "{:?}",
        ProofSchemaError::MissingField {
            field: "x".to_string()
        }
    );
    assert!(!dbg.is_empty());
    assert!(dbg.contains("MissingField"));
}

#[test]
fn enrichment_signer_key_id_debug() {
    let sk = SignerKeyId {
        key_id: signer_key_id(),
        role: SignerRole::OptimizerSubsystem,
        bound_epoch: epoch(1),
    };
    let dbg = format!("{:?}", sk);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SignerKeyId"));
}

#[test]
fn enrichment_attestation_validity_window_debug() {
    let w = AttestationValidityWindow {
        start_timestamp_ticks: 100,
        end_timestamp_ticks: 200,
    };
    let dbg = format!("{:?}", w);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("AttestationValidityWindow"));
}

#[test]
fn enrichment_attestation_requirement_policy_debug() {
    let p = AttestationRequirementPolicy::default();
    let dbg = format!("{:?}", p);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("AttestationRequirementPolicy"));
}

#[test]
fn enrichment_nonce_registry_debug() {
    let r = ReceiptNonceRegistry::new();
    let dbg = format!("{:?}", r);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ReceiptNonceRegistry"));
}

// ===========================================================================
// Default
// ===========================================================================

#[test]
fn enrichment_attestation_requirement_policy_default() {
    let p = AttestationRequirementPolicy::default();
    assert_eq!(p.require_at_or_above, DecisionImpact::HighImpact);
    assert!(p.allow_legacy_receipts_without_attestation);
}

#[test]
fn enrichment_nonce_registry_default() {
    let r = ReceiptNonceRegistry::default();
    let r2 = ReceiptNonceRegistry::new();
    // Both should accept the same nonce
    let json_r = serde_json::to_string(&r).unwrap();
    let json_r2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(json_r, json_r2);
}

// ===========================================================================
// Display coverage — all variants unique
// ===========================================================================

#[test]
fn enrichment_optimization_class_display_all_unique() {
    let displays: BTreeSet<String> = [
        OptimizationClass::Superinstruction,
        OptimizationClass::TraceSpecialization,
        OptimizationClass::LayoutSpecialization,
        OptimizationClass::DevirtualizedHostcallFastPath,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_activation_stage_display_all_unique() {
    let displays: BTreeSet<String> = [
        ActivationStage::Shadow,
        ActivationStage::Canary,
        ActivationStage::Ramp,
        ActivationStage::Default,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_signer_role_display_all_unique() {
    let displays: BTreeSet<String> = [
        SignerRole::OptimizerSubsystem,
        SignerRole::PolicyPlane,
        SignerRole::AttestationCell,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_proof_schema_error_display_all_variants_unique() {
    let errors: Vec<ProofSchemaError> = vec![
        ProofSchemaError::InvalidSignature {
            artifact: "x".to_string(),
        },
        ProofSchemaError::IncompatibleVersion {
            expected_major: 1,
            actual: SchemaVersion::new(2, 0, 0),
        },
        ProofSchemaError::TokenExpired {
            token_id: "t".to_string(),
            expiry_epoch: 1,
            current_epoch: 2,
        },
        ProofSchemaError::MissingField {
            field: "f".to_string(),
        },
        ProofSchemaError::NonEquivalent {
            reason: "r".to_string(),
        },
        ProofSchemaError::UnauthorizedSigner {
            role: SignerRole::AttestationCell,
            artifact: "a".to_string(),
        },
        ProofSchemaError::EpochMismatch {
            receipt_epoch: 1,
            current_epoch: 2,
        },
        ProofSchemaError::MissingAttestationBindings {
            impact: DecisionImpact::HighImpact,
        },
        ProofSchemaError::UnexpectedAttestationBindingsForVersion {
            schema_version: SchemaVersion::new(1, 0, 0),
        },
        ProofSchemaError::InvalidAttestationBindings {
            reason: "bad".to_string(),
        },
        ProofSchemaError::NonceReplay {
            attested_signer_key_id: signer_key_id(),
            nonce_hex: "aabb".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// ===========================================================================
// std::error::Error
// ===========================================================================

#[test]
fn enrichment_proof_schema_error_is_std_error() {
    let e = ProofSchemaError::MissingField {
        field: "test".to_string(),
    };
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

// ===========================================================================
// JSON field-name stability
// ===========================================================================

#[test]
fn enrichment_opt_receipt_json_field_names() {
    let r = signed_receipt();
    let json = serde_json::to_value(&r).unwrap();
    let obj = json.as_object().unwrap();
    let expected_fields = [
        "schema_version",
        "optimization_id",
        "optimization_class",
        "baseline_ir_hash",
        "candidate_ir_hash",
        "translation_witness_hash",
        "invariance_digest",
        "rollback_token_id",
        "replay_compatibility",
        "policy_epoch",
        "timestamp_ticks",
        "signer_key_id",
        "correlation_id",
        "decision_impact",
        "signature",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
}

#[test]
fn enrichment_rollback_token_json_field_names() {
    let t = signed_rollback();
    let json = serde_json::to_value(&t).unwrap();
    let obj = json.as_object().unwrap();
    let expected_fields = [
        "schema_version",
        "token_id",
        "optimization_id",
        "baseline_snapshot_hash",
        "activation_stage",
        "expiry_epoch",
        "issuer_key_id",
        "issuer_signature",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
}

#[test]
fn enrichment_invariance_digest_json_field_names() {
    let d = make_invariance_digest();
    let json = serde_json::to_value(&d).unwrap();
    let obj = json.as_object().unwrap();
    let expected_fields = [
        "schema_version",
        "golden_corpus_hash",
        "trace_comparison_methodology",
        "equivalence_verdict",
        "witness_chain_root",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
}

#[test]
fn enrichment_signer_key_id_json_field_names() {
    let sk = SignerKeyId {
        key_id: signer_key_id(),
        role: SignerRole::OptimizerSubsystem,
        bound_epoch: epoch(1),
    };
    let json = serde_json::to_value(&sk).unwrap();
    let obj = json.as_object().unwrap();
    for field in ["key_id", "role", "bound_epoch"] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_attestation_bindings_json_field_names() {
    let b = make_attestation_bindings();
    let json = serde_json::to_value(&b).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "quote_digest",
        "measurement_id",
        "attested_signer_key_id",
        "nonce",
        "validity_window",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_attestation_validity_window_json_field_names() {
    let w = AttestationValidityWindow {
        start_timestamp_ticks: 100,
        end_timestamp_ticks: 200,
    };
    let json = serde_json::to_value(&w).unwrap();
    let obj = json.as_object().unwrap();
    for field in ["start_timestamp_ticks", "end_timestamp_ticks"] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

// ===========================================================================
// Serde roundtrips (enrichment — cover types not already tested)
// ===========================================================================

#[test]
fn enrichment_signer_key_id_serde_roundtrip() {
    let sk = SignerKeyId {
        key_id: signer_key_id(),
        role: SignerRole::OptimizerSubsystem,
        bound_epoch: epoch(1),
    };
    let json = serde_json::to_string(&sk).unwrap();
    let back: SignerKeyId = serde_json::from_str(&json).unwrap();
    assert_eq!(sk, back);
}

#[test]
fn enrichment_attestation_validity_window_serde_roundtrip() {
    let w = AttestationValidityWindow {
        start_timestamp_ticks: 100,
        end_timestamp_ticks: 200,
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: AttestationValidityWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn enrichment_attestation_requirement_policy_serde_roundtrip() {
    let p = AttestationRequirementPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let back: AttestationRequirementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn enrichment_nonce_registry_serde_roundtrip() {
    let mut r = ReceiptNonceRegistry::new();
    let key_id = signer_key_id();
    r.check_and_record(&key_id, [3u8; 32]).unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: ReceiptNonceRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_equivalence_verdict_serde_all_variants() {
    let variants: Vec<EquivalenceVerdict> = vec![
        EquivalenceVerdict::Equivalent,
        EquivalenceVerdict::NonEquivalent {
            reason: "diverged".to_string(),
        },
        EquivalenceVerdict::Inconclusive {
            reason: "timeout".to_string(),
        },
    ];
    let jsons: BTreeSet<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(jsons.len(), 3);
    for json in &jsons {
        let _back: EquivalenceVerdict = serde_json::from_str(json).unwrap();
    }
}

#[test]
fn enrichment_trace_comparison_methodology_serde_all_variants() {
    let variants: Vec<TraceComparisonMethodology> = vec![
        TraceComparisonMethodology::DeterministicReplay,
        TraceComparisonMethodology::SymbolicEquivalence,
        TraceComparisonMethodology::StatisticalCorpus { corpus_size: 5000 },
    ];
    let jsons: BTreeSet<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(jsons.len(), 3);
    for json in &jsons {
        let _back: TraceComparisonMethodology = serde_json::from_str(json).unwrap();
    }
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn enrichment_receipt_sign_determinism_20_runs() {
    let mut sigs = BTreeSet::new();
    for _ in 0..20 {
        let r = unsigned_receipt().sign(TEST_KEY);
        sigs.insert(format!("{:?}", r.signature));
    }
    assert_eq!(sigs.len(), 1, "signing must be deterministic");
}

#[test]
fn enrichment_rollback_sign_determinism_20_runs() {
    let mut sigs = BTreeSet::new();
    for _ in 0..20 {
        let t = unsigned_rollback().sign(TEST_KEY);
        sigs.insert(format!("{:?}", t.issuer_signature));
    }
    assert_eq!(sigs.len(), 1, "signing must be deterministic");
}

#[test]
fn enrichment_invariance_digest_hash_determinism_20_runs() {
    let mut hashes = BTreeSet::new();
    for _ in 0..20 {
        let d = make_invariance_digest();
        hashes.insert(format!("{:?}", d.content_hash()));
    }
    assert_eq!(hashes.len(), 1, "content_hash must be deterministic");
}

#[test]
fn enrichment_receipt_object_id_determinism_20_runs() {
    let mut ids = BTreeSet::new();
    for _ in 0..20 {
        let r = signed_receipt();
        let oid = r.object_id("det-zone").unwrap();
        ids.insert(format!("{:?}", oid));
    }
    assert_eq!(ids.len(), 1, "object_id must be deterministic");
}

// ===========================================================================
// Schema version edge cases
// ===========================================================================

#[test]
fn enrichment_schema_version_self_compatible() {
    let v = proof_schema_version_current();
    assert!(v.is_compatible_with(&v));
}

#[test]
fn enrichment_schema_v1_0_returns_correct_version() {
    let v = proof_schema_version_v1_0();
    assert_eq!(v.major_val(), 1);
    assert_eq!(v.minor_val(), 0);
}

#[test]
fn enrichment_schema_v1_1_returns_correct_version() {
    let v = proof_schema_version_v1_1();
    assert_eq!(v.major_val(), 1);
    assert_eq!(v.minor_val(), 1);
}

#[test]
fn enrichment_schema_attestation_binding_intro_is_v1_1() {
    let intro = proof_schema_attestation_binding_intro();
    assert_eq!(intro.major_val(), 1);
    assert_eq!(intro.minor_val(), 1);
}

// ===========================================================================
// InvarianceDigest edge cases
// ===========================================================================

#[test]
fn enrichment_invariance_digest_symbolic_equivalence_hash() {
    let mut d = make_invariance_digest();
    d.trace_comparison_methodology = TraceComparisonMethodology::SymbolicEquivalence;
    let h1 = d.content_hash();
    // Verify determinism
    d.trace_comparison_methodology = TraceComparisonMethodology::SymbolicEquivalence;
    let h2 = d.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_invariance_digest_statistical_corpus_sizes_differ() {
    let mut d1 = make_invariance_digest();
    d1.trace_comparison_methodology =
        TraceComparisonMethodology::StatisticalCorpus { corpus_size: 100 };
    let mut d2 = make_invariance_digest();
    d2.trace_comparison_methodology =
        TraceComparisonMethodology::StatisticalCorpus { corpus_size: 200 };
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn enrichment_invariance_digest_non_equivalent_reason_matters() {
    let mut d1 = make_invariance_digest();
    d1.equivalence_verdict = EquivalenceVerdict::NonEquivalent {
        reason: "reason_a".to_string(),
    };
    let mut d2 = make_invariance_digest();
    d2.equivalence_verdict = EquivalenceVerdict::NonEquivalent {
        reason: "reason_b".to_string(),
    };
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn enrichment_invariance_digest_inconclusive_reason_matters() {
    let mut d1 = make_invariance_digest();
    d1.equivalence_verdict = EquivalenceVerdict::Inconclusive {
        reason: "timeout".to_string(),
    };
    let mut d2 = make_invariance_digest();
    d2.equivalence_verdict = EquivalenceVerdict::Inconclusive {
        reason: "corpus_too_small".to_string(),
    };
    assert_ne!(d1.content_hash(), d2.content_hash());
}

// ===========================================================================
// Signer authorization edge cases
// ===========================================================================

#[test]
fn enrichment_attestation_cell_authorized_for_nothing_standard() {
    // AttestationCell should not be authorized for any of the standard artifacts
    assert!(check_signer_authorization(SignerRole::AttestationCell, "OptReceipt").is_err());
    assert!(check_signer_authorization(SignerRole::AttestationCell, "RollbackToken").is_err());
    assert!(check_signer_authorization(SignerRole::AttestationCell, "InvarianceDigest").is_err());
}

#[test]
fn enrichment_policy_plane_authorized_for_rollback_only() {
    assert!(check_signer_authorization(SignerRole::PolicyPlane, "OptReceipt").is_err());
    assert!(check_signer_authorization(SignerRole::PolicyPlane, "RollbackToken").is_ok());
    assert!(check_signer_authorization(SignerRole::PolicyPlane, "InvarianceDigest").is_err());
}

#[test]
fn enrichment_optimizer_subsystem_authorized_for_all_three() {
    assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "OptReceipt").is_ok());
    assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "RollbackToken").is_ok());
    assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "InvarianceDigest").is_ok());
}

#[test]
fn enrichment_signer_authorization_unknown_artifact() {
    let err =
        check_signer_authorization(SignerRole::OptimizerSubsystem, "UnknownThing").unwrap_err();
    match err {
        ProofSchemaError::UnauthorizedSigner { role, artifact } => {
            assert_eq!(role, SignerRole::OptimizerSubsystem);
            assert_eq!(artifact, "UnknownThing");
        }
        other => panic!("expected UnauthorizedSigner, got: {other:?}"),
    }
}

// ===========================================================================
// Receipt validation edge cases
// ===========================================================================

#[test]
fn enrichment_validate_receipt_attestation_timestamp_outside_window() {
    let mut r = unsigned_receipt();
    r.schema_version = proof_schema_version_v1_1();
    r.decision_impact = DecisionImpact::HighImpact;
    let mut bindings = make_attestation_bindings();
    // Timestamp 1000, but window [900, 999] — outside
    bindings.validity_window.end_timestamp_ticks = 999;
    r.attestation_bindings = Some(bindings);
    r.timestamp_ticks = 1000;
    let r = r.sign(TEST_KEY);

    let policy = AttestationRequirementPolicy {
        require_at_or_above: DecisionImpact::HighImpact,
        allow_legacy_receipts_without_attestation: false,
    };
    let result = validate_receipt_with_policy(&r, TEST_KEY, epoch(5), &policy, None);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProofSchemaError::InvalidAttestationBindings { reason } => {
            assert!(reason.contains("outside"));
        }
        other => panic!("expected InvalidAttestationBindings, got: {other:?}"),
    }
}

#[test]
fn enrichment_validate_receipt_attestation_zero_nonce() {
    let mut r = unsigned_receipt();
    r.schema_version = proof_schema_version_v1_1();
    r.decision_impact = DecisionImpact::HighImpact;
    let mut bindings = make_attestation_bindings();
    bindings.nonce = [0u8; 32]; // all zeros
    r.attestation_bindings = Some(bindings);
    let r = r.sign(TEST_KEY);

    let policy = AttestationRequirementPolicy {
        require_at_or_above: DecisionImpact::HighImpact,
        allow_legacy_receipts_without_attestation: false,
    };
    let result = validate_receipt_with_policy(&r, TEST_KEY, epoch(5), &policy, None);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProofSchemaError::InvalidAttestationBindings { reason } => {
            assert!(reason.contains("nonce"));
        }
        other => panic!("expected InvalidAttestationBindings, got: {other:?}"),
    }
}

#[test]
fn enrichment_validate_receipt_attestation_signer_mismatch() {
    let mut r = unsigned_receipt();
    r.schema_version = proof_schema_version_v1_1();
    r.decision_impact = DecisionImpact::HighImpact;
    let mut bindings = make_attestation_bindings();
    // Make attested_signer_key_id different from receipt's signer_key_id
    bindings.attested_signer_key_id = derive_id(
        ObjectDomain::CapabilityToken,
        "other-zone",
        &SchemaId::from_definition(b"other-key"),
        b"other",
    )
    .expect("derive");
    r.attestation_bindings = Some(bindings);
    let r = r.sign(TEST_KEY);

    let policy = AttestationRequirementPolicy {
        require_at_or_above: DecisionImpact::HighImpact,
        allow_legacy_receipts_without_attestation: false,
    };
    let result = validate_receipt_with_policy(&r, TEST_KEY, epoch(5), &policy, None);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProofSchemaError::InvalidAttestationBindings { reason } => {
            assert!(reason.contains("signer_key_id"));
        }
        other => panic!("expected InvalidAttestationBindings, got: {other:?}"),
    }
}

#[test]
fn enrichment_validate_receipt_standard_impact_no_attestation_passes() {
    // Standard impact should not require attestation bindings
    let r = signed_receipt(); // Standard impact, no attestation
    let policy = AttestationRequirementPolicy {
        require_at_or_above: DecisionImpact::HighImpact,
        allow_legacy_receipts_without_attestation: false,
    };
    assert!(validate_receipt_with_policy(&r, TEST_KEY, epoch(5), &policy, None).is_ok());
}

// ===========================================================================
// RollbackToken edge cases
// ===========================================================================

#[test]
fn enrichment_rollback_token_different_optimization_id_different_preimage() {
    let t1 = unsigned_rollback();
    let mut t2 = unsigned_rollback();
    t2.optimization_id = "opt-different".to_string();
    assert_ne!(t1.signing_preimage(), t2.signing_preimage());
}

#[test]
fn enrichment_rollback_token_all_stages_different_preimages() {
    let stages = [
        ActivationStage::Shadow,
        ActivationStage::Canary,
        ActivationStage::Ramp,
        ActivationStage::Default,
    ];
    let preimages: BTreeSet<Vec<u8>> = stages
        .iter()
        .map(|s| {
            let mut t = unsigned_rollback();
            t.activation_stage = *s;
            t.signing_preimage()
        })
        .collect();
    assert_eq!(preimages.len(), 4);
}

#[test]
fn enrichment_rollback_token_object_id_differs_by_content() {
    let t1 = unsigned_rollback();
    let mut t2 = unsigned_rollback();
    t2.token_id = "different-token".to_string();
    let oid1 = t1.object_id("zone").unwrap();
    let oid2 = t2.object_id("zone").unwrap();
    assert_ne!(oid1, oid2);
}

// ===========================================================================
// ReceiptNonceRegistry edge cases
// ===========================================================================

#[test]
fn enrichment_nonce_registry_replay_error_contains_hex() {
    let mut registry = ReceiptNonceRegistry::new();
    let key_id = signer_key_id();
    let nonce = [0xABu8; 32];
    registry.check_and_record(&key_id, nonce).unwrap();
    let err = registry.check_and_record(&key_id, nonce).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("nonce replay"));
    assert!(msg.contains("ab")); // hex representation
}

#[test]
fn enrichment_nonce_registry_many_unique_nonces() {
    let mut registry = ReceiptNonceRegistry::new();
    let key_id = signer_key_id();
    for i in 0u8..50 {
        let mut nonce = [0u8; 32];
        nonce[0] = i;
        assert!(registry.check_and_record(&key_id, nonce).is_ok());
    }
}

// ===========================================================================
// Receipt with all optimization classes
// ===========================================================================

#[test]
fn enrichment_receipt_all_optimization_classes_sign_verify() {
    let classes = [
        OptimizationClass::Superinstruction,
        OptimizationClass::TraceSpecialization,
        OptimizationClass::LayoutSpecialization,
        OptimizationClass::DevirtualizedHostcallFastPath,
    ];
    let mut sigs = BTreeSet::new();
    for class in &classes {
        let mut r = unsigned_receipt();
        r.optimization_class = class.clone();
        let r = r.sign(TEST_KEY);
        assert!(r.verify_signature(TEST_KEY));
        sigs.insert(format!("{:?}", r.signature));
    }
    // Different optimization classes should produce different signatures
    assert_eq!(sigs.len(), 4);
}

// ===========================================================================
// Receipt with all activation stages in replay_compatibility
// ===========================================================================

#[test]
fn enrichment_receipt_empty_replay_compatibility() {
    let mut r = unsigned_receipt();
    r.replay_compatibility = BTreeMap::new();
    let r = r.sign(TEST_KEY);
    assert!(r.verify_signature(TEST_KEY));
}

#[test]
fn enrichment_receipt_large_replay_compatibility() {
    let mut r = unsigned_receipt();
    for i in 0..20 {
        r.replay_compatibility
            .insert(format!("key_{i}"), format!("val_{i}"));
    }
    let r = r.sign(TEST_KEY);
    assert!(r.verify_signature(TEST_KEY));
}

// ===========================================================================
// Receipt v1.0 vs v1.1 behavior
// ===========================================================================

#[test]
fn enrichment_receipt_v1_0_no_attestation_fields_in_preimage() {
    let mut r1 = unsigned_receipt();
    r1.schema_version = proof_schema_version_v1_0();
    let mut r2 = unsigned_receipt();
    r2.schema_version = proof_schema_version_v1_0();
    r2.decision_impact = DecisionImpact::HighImpact; // would change preimage on v1.1
    // On v1.0, decision_impact should NOT affect preimage
    assert_eq!(r1.signing_preimage(), r2.signing_preimage());
}

#[test]
fn enrichment_receipt_v1_1_decision_impact_in_preimage() {
    let mut r1 = unsigned_receipt();
    r1.schema_version = proof_schema_version_v1_1();
    let mut r2 = unsigned_receipt();
    r2.schema_version = proof_schema_version_v1_1();
    r2.decision_impact = DecisionImpact::HighImpact;
    // On v1.1, decision_impact SHOULD affect preimage
    assert_ne!(r1.signing_preimage(), r2.signing_preimage());
}
