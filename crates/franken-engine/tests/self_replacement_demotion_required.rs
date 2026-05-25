#![forbid(unsafe_code)]
//! Negative coverage for the V.5 pre-signed demotion fallback requirement.

#![allow(clippy::too_many_arguments)]

use frankenengine_engine::demotion_rollback::{
    CreateDemotionReceiptInput, DemotionEvidenceItem, DemotionReason, DemotionReceipt,
    DemotionSeverity,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::pre_signed_demotion_fallback::{
    DemotionTrigger, FallbackError, FallbackStatus, PreSignedFallbackStore, PromotionId,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    CreateManifestInput, CreateReceiptInput, DelegateCellManifest, DelegateType, MonitoringHook,
    ReplacementLifecycle, ReplacementReceipt, SandboxConfiguration, SelfReplacementError,
    ValidationArtifactKind, ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

fn emit_event(test_name: &str, outcome: &str) {
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "self_replacement_demotion_required",
            "test_name": test_name,
            "outcome": outcome,
        })
    );
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(22)
}

fn slot(name: &str) -> SlotId {
    SlotId::new(name).expect("valid slot id")
}

fn operator_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32]).expect("valid operator key")
}

fn other_key() -> SigningKey {
    SigningKey::from_bytes([99u8; 32]).expect("valid alternate key")
}

fn envelope() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
        ],
    }
}

fn sandbox() -> SandboxConfiguration {
    SandboxConfiguration {
        max_heap_bytes: 32 * 1024 * 1024,
        max_execution_ns: 2_000_000_000,
        max_hostcalls: 5_000,
        network_egress_allowed: false,
        filesystem_access_allowed: false,
    }
}

fn hooks() -> Vec<MonitoringHook> {
    vec![MonitoringHook {
        hook_id: "promotion-monitor".to_string(),
        trigger_event: "promotion-applied".to_string(),
        blocking: false,
    }]
}

fn manifest(slot_id: &SlotId) -> DelegateCellManifest {
    let key = operator_key();
    let env = envelope();
    let sb = sandbox();
    let hook_set = hooks();
    let behavior_hash = [0xAB; 32];
    DelegateCellManifest::create_signed(
        &key,
        CreateManifestInput {
            slot_id,
            delegate_type: DelegateType::QuickJsBacked,
            capability_envelope: &env,
            sandbox: &sb,
            monitoring_hooks: &hook_set,
            expected_behavior_hash: &behavior_hash,
            zone: "zone-v",
        },
    )
    .expect("manifest signs")
}

fn lifecycle(slot_id: &SlotId) -> ReplacementLifecycle {
    ReplacementLifecycle::new(slot_id.clone(), manifest(slot_id))
}

fn validation_artifacts(passed: bool) -> Vec<ValidationArtifactRef> {
    vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "equiv-v5".to_string(),
            passed,
            summary: "equivalence gate result".to_string(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::CapabilityPreservation,
            artifact_digest: "cap-v5".to_string(),
            passed,
            summary: "capability preservation result".to_string(),
        },
    ]
}

fn receipt_for(
    slot_id: &SlotId,
    old_digest: &str,
    new_digest: &str,
    timestamp_ns: u64,
    passed: bool,
) -> ReplacementReceipt {
    let artifacts = validation_artifacts(passed);
    ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id,
        old_slot_id: slot_id,
        new_slot_id: slot_id,
        old_cell_digest: old_digest,
        new_cell_digest: new_digest,
        translation_validation_proof_ref: "test-validation-proof",
        content_hash_chain_into_lineage: "test-content-hash-chain",
        validation_artifacts: &artifacts,
        rollback_token: "rollback-old-cell",
        promotion_rationale: "V.5 negative-test fixture",
        timestamp_ns,
        epoch: epoch(),
        zone: "zone-v",
        required_signatures: 0,
    })
    .expect("replacement receipt")
}

fn demotion_evidence() -> Vec<DemotionEvidenceItem> {
    vec![DemotionEvidenceItem {
        artifact_hash: ContentHash::compute(b"demotion-evidence-v5"),
        category: "divergence_trace".to_string(),
        collected_at_ns: 2_000_000_000,
        summary: "post-promotion divergence".to_string(),
    }]
}

fn demotion_receipt_for(receipt: &ReplacementReceipt, signing_key: &SigningKey) -> DemotionReceipt {
    let evidence = demotion_evidence();
    DemotionReceipt::create_signed(
        signing_key,
        CreateDemotionReceiptInput {
            slot_id: &receipt.slot_id,
            demoted_cell_digest: &receipt.new_cell_digest,
            restored_cell_digest: &receipt.old_cell_digest,
            rollback_token_used: &receipt.rollback_token,
            demotion_reason: &DemotionReason::SemanticDivergence {
                divergence_count: 1,
                first_divergence_artifact: ContentHash::compute(b"first-divergence-v5"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &evidence,
            timestamp_ns: receipt.timestamp_ns + 1,
            epoch: receipt.epoch,
            zone: &receipt.zone,
        },
    )
    .expect("demotion receipt signs")
}

fn triggers() -> Vec<DemotionTrigger> {
    vec![
        DemotionTrigger::DigestDrift,
        DemotionTrigger::SeverityThresholdCrossed,
        DemotionTrigger::GatekeeperRejection,
    ]
}

fn seal_verified(
    store: &mut PreSignedFallbackStore,
    receipt: &ReplacementReceipt,
    demotion_receipt: &DemotionReceipt,
    key: &SigningKey,
) -> PromotionId {
    let promotion_id = receipt.promotion_id().expect("promotion id");
    store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            demotion_receipt,
            &key.verification_key(),
            receipt.timestamp_ns - 1,
            receipt.epoch,
            triggers(),
        )
        .expect("verified fallback seals");
    promotion_id
}

fn assert_missing_fallback(err: SelfReplacementError, promotion_id: &PromotionId) {
    assert_eq!(
        err,
        SelfReplacementError::MissingFallbackReceipt {
            promotion_id: promotion_id.to_string(),
        }
    );
}

#[test]
fn promotion_without_fallback_rejects_missing_fallback() {
    let slot_id = slot("v5-missing");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut lifecycle = lifecycle(&slot_id);
    let mut store = PreSignedFallbackStore::new();

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect_err("promotion must reject missing fallback");

    assert_missing_fallback(err, &promotion_id);
    assert!(lifecycle.receipts.is_empty());
    emit_event(
        "promotion_without_fallback_rejects_missing_fallback",
        "pass",
    );
}

#[test]
fn missing_fallback_error_display_mentions_promotion() {
    let err = SelfReplacementError::MissingFallbackReceipt {
        promotion_id: "promotion-display".to_string(),
    };

    assert!(err.to_string().contains("promotion-display"));
    assert!(
        err.to_string()
            .contains("missing pre-signed demotion fallback")
    );
    emit_event("missing_fallback_error_display_mentions_promotion", "pass");
}

#[test]
fn missing_fallback_error_serde_roundtrip() {
    let err = SelfReplacementError::MissingFallbackReceipt {
        promotion_id: "promotion-serde".to_string(),
    };

    let json = serde_json::to_string(&err).expect("serialize error");
    let restored: SelfReplacementError = serde_json::from_str(&json).expect("deserialize error");

    assert_eq!(restored, err);
    emit_event("missing_fallback_error_serde_roundtrip", "pass");
}

#[test]
fn fallback_for_different_promotion_rejected() {
    let slot_id = slot("v5-wrong-promotion");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let other = receipt_for(&slot_id, "old-a", "new-b", 1_000_000_100, true);
    let demotion = demotion_receipt_for(&other, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    seal_verified(&mut store, &other, &demotion, &operator_key());
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut lifecycle = lifecycle(&slot_id);

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect_err("wrong fallback must not authorize promotion");

    assert_missing_fallback(err, &promotion_id);
    assert!(lifecycle.receipts.is_empty());
    emit_event("fallback_for_different_promotion_rejected", "pass");
}

#[test]
fn active_fallback_rejected_for_promotion_attempt() {
    let slot_id = slot("v5-active");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    store
        .mark_promotion_applied(&promotion_id)
        .expect("mark active");
    let mut lifecycle = lifecycle(&slot_id);

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect_err("active fallback is no longer sealed");

    assert_missing_fallback(err, &promotion_id);
    emit_event("active_fallback_rejected_for_promotion_attempt", "pass");
}

#[test]
fn activated_fallback_rejected_for_promotion_attempt() {
    let slot_id = slot("v5-activated");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    store
        .mark_promotion_applied(&promotion_id)
        .expect("mark active");
    store
        .activate(&promotion_id, DemotionTrigger::DigestDrift, 1_000_000_010)
        .expect("activate fallback");
    let mut lifecycle = lifecycle(&slot_id);

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect_err("activated fallback is terminal");

    assert_missing_fallback(err, &promotion_id);
    emit_event("activated_fallback_rejected_for_promotion_attempt", "pass");
}

#[test]
fn voided_fallback_rejected_for_promotion_attempt() {
    let slot_id = slot("v5-voided");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    store
        .mark_promotion_applied(&promotion_id)
        .expect("mark active");
    store
        .void(&promotion_id, "promotion retired cleanly", 1_000_000_010)
        .expect("void fallback");
    let mut lifecycle = lifecycle(&slot_id);

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect_err("voided fallback is terminal");

    assert_missing_fallback(err, &promotion_id);
    emit_event("voided_fallback_rejected_for_promotion_attempt", "pass");
}

#[test]
fn valid_fallback_allows_shadow_transition() {
    let slot_id = slot("v5-valid-shadow");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);

    lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect("valid fallback allows promotion");

    assert_eq!(lifecycle.receipts.len(), 1);
    assert_eq!(lifecycle.completed_stages(), 1);
    emit_event("valid_fallback_allows_shadow_transition", "pass");
}

#[test]
fn valid_fallback_marks_store_active() {
    let slot_id = slot("v5-valid-active");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);

    lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect("valid fallback allows promotion");

    assert!(
        store
            .get(&promotion_id)
            .expect("fallback")
            .status
            .is_active()
    );
    assert!(!store.has_sealed_fallback_for(&promotion_id));
    emit_event("valid_fallback_marks_store_active", "pass");
}

#[test]
fn promotion_id_derivation_is_deterministic() {
    let slot_id = slot("v5-promotion-id-stable");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);

    assert_eq!(
        receipt.promotion_id().expect("first"),
        receipt.promotion_id().expect("second")
    );
    emit_event("promotion_id_derivation_is_deterministic", "pass");
}

#[test]
fn promotion_id_changes_when_receipt_timestamp_changes() {
    let slot_id = slot("v5-promotion-id-timestamp");
    let first = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let second = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_001, true);

    assert_ne!(
        first.promotion_id().expect("first"),
        second.promotion_id().expect("second")
    );
    emit_event(
        "promotion_id_changes_when_receipt_timestamp_changes",
        "pass",
    );
}

#[test]
fn failed_validation_does_not_consume_sealed_fallback() {
    let slot_id = slot("v5-validation-failed");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, false);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect_err("failed validation rejects promotion");

    assert!(matches!(err, SelfReplacementError::ValidationFailed { .. }));
    assert!(store.has_sealed_fallback_for(&promotion_id));
    assert!(lifecycle.receipts.is_empty());
    emit_event("failed_validation_does_not_consume_sealed_fallback", "pass");
}

#[test]
fn slot_mismatch_does_not_consume_sealed_fallback() {
    let expected_slot = slot("v5-slot-expected");
    let receipt_slot = slot("v5-slot-receipt");
    let receipt = receipt_for(&receipt_slot, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&expected_slot);

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect_err("slot mismatch rejects promotion");

    assert!(matches!(err, SelfReplacementError::SlotMismatch { .. }));
    assert!(store.has_sealed_fallback_for(&promotion_id));
    assert!(lifecycle.receipts.is_empty());
    emit_event("slot_mismatch_does_not_consume_sealed_fallback", "pass");
}

#[test]
fn unsigned_demotion_receipt_refuses_seal() {
    let slot_id = slot("v5-unsigned");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let mut demotion = demotion_receipt_for(&receipt, &operator_key());
    demotion.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut store = PreSignedFallbackStore::new();

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            &demotion,
            &operator_key().verification_key(),
            999_999_999,
            epoch(),
            triggers(),
        )
        .expect_err("unsigned receipt must not seal");

    assert_eq!(
        err,
        FallbackError::InvalidDemotionReceiptSignature { promotion_id }
    );
    assert!(store.is_empty());
    emit_event("unsigned_demotion_receipt_refuses_seal", "pass");
}

#[test]
fn wrong_operator_key_refuses_seal() {
    let slot_id = slot("v5-wrong-key");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut store = PreSignedFallbackStore::new();

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            &demotion,
            &other_key().verification_key(),
            999_999_999,
            epoch(),
            triggers(),
        )
        .expect_err("wrong key must not seal");

    assert_eq!(
        err,
        FallbackError::InvalidDemotionReceiptSignature { promotion_id }
    );
    assert!(store.is_empty());
    emit_event("wrong_operator_key_refuses_seal", "pass");
}

#[test]
fn demotion_receipt_signed_by_wrong_key_refuses_seal() {
    let slot_id = slot("v5-signed-wrong-key");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &other_key());
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut store = PreSignedFallbackStore::new();

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            &demotion,
            &operator_key().verification_key(),
            999_999_999,
            epoch(),
            triggers(),
        )
        .expect_err("receipt signed by wrong key must not seal");

    assert_eq!(
        err,
        FallbackError::InvalidDemotionReceiptSignature { promotion_id }
    );
    emit_event("demotion_receipt_signed_by_wrong_key_refuses_seal", "pass");
}

#[test]
fn tampered_demoted_digest_refuses_seal() {
    let slot_id = slot("v5-tamper-demoted");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let mut demotion = demotion_receipt_for(&receipt, &operator_key());
    demotion.demoted_cell_digest = "tampered-native".to_string();
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut store = PreSignedFallbackStore::new();

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            &demotion,
            &operator_key().verification_key(),
            999_999_999,
            epoch(),
            triggers(),
        )
        .expect_err("tampered receipt must not seal");

    assert_eq!(
        err,
        FallbackError::InvalidDemotionReceiptSignature { promotion_id }
    );
    emit_event("tampered_demoted_digest_refuses_seal", "pass");
}

#[test]
fn tampered_restored_digest_refuses_seal() {
    let slot_id = slot("v5-tamper-restored");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let mut demotion = demotion_receipt_for(&receipt, &operator_key());
    demotion.restored_cell_digest = "tampered-delegate".to_string();
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut store = PreSignedFallbackStore::new();

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            &demotion,
            &operator_key().verification_key(),
            999_999_999,
            epoch(),
            triggers(),
        )
        .expect_err("tampered receipt must not seal");

    assert_eq!(
        err,
        FallbackError::InvalidDemotionReceiptSignature { promotion_id }
    );
    emit_event("tampered_restored_digest_refuses_seal", "pass");
}

#[test]
fn tampered_rollback_token_refuses_seal() {
    let slot_id = slot("v5-tamper-rollback");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let mut demotion = demotion_receipt_for(&receipt, &operator_key());
    demotion.rollback_token_used = "tampered-rollback".to_string();
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut store = PreSignedFallbackStore::new();

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            &demotion,
            &operator_key().verification_key(),
            999_999_999,
            epoch(),
            triggers(),
        )
        .expect_err("tampered receipt must not seal");

    assert_eq!(
        err,
        FallbackError::InvalidDemotionReceiptSignature { promotion_id }
    );
    emit_event("tampered_rollback_token_refuses_seal", "pass");
}

#[test]
fn valid_signed_receipt_seals_store() {
    let slot_id = slot("v5-valid-seal");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());

    assert!(store.has_sealed_fallback_for(&promotion_id));
    assert_eq!(store.len(), 1);
    assert_eq!(
        store.get(&promotion_id).expect("fallback").receipt_digest,
        demotion.content_hash()
    );
    emit_event("valid_signed_receipt_seals_store", "pass");
}

#[test]
fn seal_verified_rejects_empty_trigger_list() {
    let slot_id = slot("v5-empty-triggers");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let promotion_id = receipt.promotion_id().expect("promotion id");
    let mut store = PreSignedFallbackStore::new();

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id,
            &demotion,
            &operator_key().verification_key(),
            999_999_999,
            epoch(),
            Vec::new(),
        )
        .expect_err("empty trigger list must not seal");

    assert_eq!(err, FallbackError::NoPermittedTriggers);
    assert!(store.is_empty());
    emit_event("seal_verified_rejects_empty_trigger_list", "pass");
}

#[test]
fn duplicate_verified_seal_rejected() {
    let slot_id = slot("v5-duplicate");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());

    let err = store
        .seal_verified_demotion_receipt(
            promotion_id.clone(),
            &demotion,
            &operator_key().verification_key(),
            999_999_998,
            epoch(),
            triggers(),
        )
        .expect_err("duplicate seal must be rejected");

    assert_eq!(err, FallbackError::AlreadySealed { promotion_id });
    emit_event("duplicate_verified_seal_rejected", "pass");
}

#[test]
fn activated_digest_matches_presigned_receipt() {
    let slot_id = slot("v5-activate-digest");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let expected_digest = demotion.content_hash();
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);
    lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect("promotion records");

    let activated = store
        .activate(&promotion_id, DemotionTrigger::DigestDrift, 1_000_000_010)
        .expect("fallback activates");

    assert_eq!(activated.receipt_digest, expected_digest);
    assert!(matches!(
        &activated.status,
        FallbackStatus::Activated { .. }
    ));
    emit_event("activated_digest_matches_presigned_receipt", "pass");
}

#[test]
fn disallowed_demotion_trigger_not_published() {
    let slot_id = slot("v5-disallowed-trigger");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);
    lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect("promotion records");

    let err = store
        .activate(
            &promotion_id,
            DemotionTrigger::ManualOperator,
            1_000_000_010,
        )
        .expect_err("manual operator was not pre-authorized");

    assert_eq!(err, FallbackError::TriggerNotPermitted { promotion_id });
    emit_event("disallowed_demotion_trigger_not_published", "pass");
}

#[test]
fn activation_before_promotion_is_refused() {
    let slot_id = slot("v5-activation-before-promotion");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());

    let err = store
        .activate(&promotion_id, DemotionTrigger::DigestDrift, 1_000_000_010)
        .expect_err("sealed fallback is not armed yet");

    assert_eq!(err, FallbackError::ActivationBeforeArmed { promotion_id });
    emit_event("activation_before_promotion_is_refused", "pass");
}

#[test]
fn valid_flow_can_void_after_promotion() {
    let slot_id = slot("v5-void-after-promotion");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);
    lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect("promotion records");

    store
        .void(&promotion_id, "monitoring window clean", 1_000_000_010)
        .expect("active fallback can be voided");

    assert!(matches!(
        &store.get(&promotion_id).expect("fallback").status,
        FallbackStatus::Voided { .. }
    ));
    emit_event("valid_flow_can_void_after_promotion", "pass");
}

#[test]
fn second_promotion_requires_second_fallback() {
    let slot_id = slot("v5-second-promotion");
    let first = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let second = receipt_for(&slot_id, "new-a", "new-b", 1_000_000_100, true);
    let demotion = demotion_receipt_for(&first, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    seal_verified(&mut store, &first, &demotion, &operator_key());
    let second_promotion_id = second.promotion_id().expect("second promotion id");
    let mut lifecycle = lifecycle(&slot_id);
    lifecycle
        .record_receipt_requiring_demotion_fallback(first, &mut store)
        .expect("first promotion records");

    let err = lifecycle
        .record_receipt_requiring_demotion_fallback(second, &mut store)
        .expect_err("second promotion needs its own fallback");

    assert_missing_fallback(err, &second_promotion_id);
    assert_eq!(lifecycle.receipts.len(), 1);
    emit_event("second_promotion_requires_second_fallback", "pass");
}

#[test]
fn separate_promotions_do_not_conflict() {
    let slot_id = slot("v5-independent-promotions");
    let first = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let second = receipt_for(&slot_id, "new-a", "new-b", 1_000_000_100, true);
    let first_demotion = demotion_receipt_for(&first, &operator_key());
    let second_demotion = demotion_receipt_for(&second, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    seal_verified(&mut store, &first, &first_demotion, &operator_key());
    seal_verified(&mut store, &second, &second_demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);

    lifecycle
        .record_receipt_requiring_demotion_fallback(first, &mut store)
        .expect("first promotion records");
    lifecycle
        .record_receipt_requiring_demotion_fallback(second, &mut store)
        .expect("second promotion records");

    assert_eq!(lifecycle.receipts.len(), 2);
    assert_eq!(store.len(), 2);
    emit_event("separate_promotions_do_not_conflict", "pass");
}

#[test]
fn fallback_store_roundtrip_preserves_sealed_state() {
    let slot_id = slot("v5-store-serde-sealed");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());

    let json = serde_json::to_string(&store).expect("serialize store");
    let restored: PreSignedFallbackStore = serde_json::from_str(&json).expect("deserialize store");

    assert!(restored.has_sealed_fallback_for(&promotion_id));
    emit_event("fallback_store_roundtrip_preserves_sealed_state", "pass");
}

#[test]
fn fallback_store_roundtrip_preserves_active_state() {
    let slot_id = slot("v5-store-serde-active");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    let promotion_id = seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);
    lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect("promotion records");

    let json = serde_json::to_string(&store).expect("serialize store");
    let restored: PreSignedFallbackStore = serde_json::from_str(&json).expect("deserialize store");

    assert!(matches!(
        &restored.get(&promotion_id).expect("fallback").status,
        FallbackStatus::Active
    ));
    emit_event("fallback_store_roundtrip_preserves_active_state", "pass");
}

#[test]
fn lifecycle_roundtrip_preserves_recorded_receipt() {
    let slot_id = slot("v5-lifecycle-serde");
    let receipt = receipt_for(&slot_id, "old-a", "new-a", 1_000_000_000, true);
    let demotion = demotion_receipt_for(&receipt, &operator_key());
    let mut store = PreSignedFallbackStore::new();
    seal_verified(&mut store, &receipt, &demotion, &operator_key());
    let mut lifecycle = lifecycle(&slot_id);
    lifecycle
        .record_receipt_requiring_demotion_fallback(receipt, &mut store)
        .expect("promotion records");

    let json = serde_json::to_string(&lifecycle).expect("serialize lifecycle");
    let restored: ReplacementLifecycle =
        serde_json::from_str(&json).expect("deserialize lifecycle");

    assert_eq!(restored.receipts.len(), 1);
    assert_eq!(restored.completed_stages(), 1);
    emit_event("lifecycle_roundtrip_preserves_recorded_receipt", "pass");
}
