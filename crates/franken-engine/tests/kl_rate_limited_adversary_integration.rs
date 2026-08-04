//! Integration tests for the KL-rate-limited adversary model (bd-cixqu.37.1).

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::kl_rate_limited_adversary::{
    AttackClass, COMPONENT, KLBudget, KLBudgetError, KLBudgetParameterization,
};

fn key() -> &'static [u8] {
    b"kl-rate-limited-adversary-integration-key"
}

fn budget() -> KLBudget {
    let mut budget = KLBudget::try_new("integration-budget", 1_000, 100).unwrap();
    budget.allocate(AttackClass::PromptInjection, 250).unwrap();
    budget.allocate(AttackClass::CapabilityProbe, 250).unwrap();
    budget
        .allocate(AttackClass::PrototypePollution, 250)
        .unwrap();
    budget
        .allocate(AttackClass::SupplyChainBackdoor, 250)
        .unwrap();
    budget
}

#[test]
fn integration_01_budget_starts_unsaturated() {
    assert!(!budget().is_saturated());
}

#[test]
fn integration_02_saturation_check_receipt_hash_valid() {
    let receipt = budget().saturation_check(1);
    assert!(receipt.has_valid_content_hash());
}

#[test]
fn integration_03_saturation_check_receipt_signs() {
    let receipt = budget().saturation_check(1).sign(key());
    assert!(receipt.verify_signature(key()));
}

#[test]
fn integration_04_depletion_receipt_signs() {
    let mut budget = budget();
    let receipt = budget
        .deplete(AttackClass::PromptInjection, 25, 2)
        .unwrap()
        .sign(key());
    assert!(receipt.verify_signature(key()));
}

#[test]
fn integration_05_wrong_key_rejected() {
    let mut budget = budget();
    let receipt = budget
        .deplete(AttackClass::PromptInjection, 25, 2)
        .unwrap()
        .sign(key());
    assert!(!receipt.verify_signature(b"wrong-key"));
}

#[test]
fn integration_06_budget_never_negative_on_global_over_depletion() {
    let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
    budget.allocate(AttackClass::PromptInjection, 100).unwrap();
    let receipt = budget
        .deplete(AttackClass::PromptInjection, 10_000, 3)
        .unwrap();
    assert_eq!(budget.remaining_budget_microln, 0);
    assert_eq!(receipt.remaining_after_microln, 0);
}

#[test]
fn integration_07_budget_never_negative_on_repeated_over_depletion() {
    let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
    budget.allocate(AttackClass::PromptInjection, 100).unwrap();
    budget
        .deplete(AttackClass::PromptInjection, 10_000, 3)
        .unwrap();
    let receipt = budget
        .deplete(AttackClass::PromptInjection, 10_000, 4)
        .unwrap();
    assert_eq!(receipt.applied_depletion_microln, 0);
    assert_eq!(receipt.remaining_after_microln, 0);
}

#[test]
fn integration_08_class_allocation_never_negative() {
    let mut budget = budget();
    budget
        .deplete(AttackClass::PromptInjection, 10_000, 3)
        .unwrap();
    assert_eq!(
        budget.class_remaining_microln(AttackClass::PromptInjection),
        0
    );
}

#[test]
fn integration_09_class_truncation_flag_set() {
    let mut budget = budget();
    let receipt = budget
        .deplete(AttackClass::PromptInjection, 10_000, 3)
        .unwrap();
    assert!(receipt.truncated_by_class_allocation);
}

#[test]
fn integration_10_global_truncation_flag_set() {
    let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
    budget.allocate(AttackClass::PromptInjection, 100).unwrap();
    let receipt = budget
        .deplete(AttackClass::PromptInjection, 10_000, 3)
        .unwrap();
    assert!(receipt.truncated_by_global_budget);
}

#[test]
fn integration_11_threshold_receipt_saturated_at_equal_threshold() {
    let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
    budget.allocate(AttackClass::PromptInjection, 90).unwrap();
    let receipt = budget.deplete(AttackClass::PromptInjection, 90, 3).unwrap();
    assert!(receipt.saturated);
}

#[test]
fn integration_12_threshold_receipt_not_saturated_above_threshold() {
    let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
    budget.allocate(AttackClass::PromptInjection, 89).unwrap();
    let receipt = budget.deplete(AttackClass::PromptInjection, 89, 3).unwrap();
    assert!(!receipt.saturated);
}

#[test]
fn integration_13_saturation_check_reports_saturated_after_depletion() {
    let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
    budget.allocate(AttackClass::PromptInjection, 90).unwrap();
    budget.deplete(AttackClass::PromptInjection, 90, 3).unwrap();
    assert!(budget.saturation_check(4).saturated);
}

#[test]
fn integration_14_receipt_hash_changes_when_event_changes() {
    let receipt_a = budget().saturation_check(4);
    let receipt_b = budget().saturation_check(5);
    assert_ne!(receipt_a.content_hash, receipt_b.content_hash);
}

#[test]
fn integration_15_receipt_hash_changes_when_attack_class_changes() {
    let mut budget_a = budget();
    let mut budget_b = budget();
    let a = budget_a
        .deplete(AttackClass::PromptInjection, 10, 4)
        .unwrap();
    let b = budget_b
        .deplete(AttackClass::CapabilityProbe, 10, 4)
        .unwrap();
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn integration_16_signed_receipt_rejects_tampered_remaining() {
    let mut budget = budget();
    let mut receipt = budget
        .deplete(AttackClass::PromptInjection, 10, 4)
        .unwrap()
        .sign(key());
    receipt.remaining_after_microln += 1;
    assert!(!receipt.verify_signature(key()));
}

#[test]
fn integration_17_signed_receipt_rejects_tampered_hash() {
    let mut budget = budget();
    let mut receipt = budget
        .deplete(AttackClass::PromptInjection, 10, 4)
        .unwrap()
        .sign(key());
    receipt.content_hash = ContentHash::compute(b"tampered");
    assert!(!receipt.verify_signature(key()));
}

#[test]
fn integration_18_structured_log_fields_are_stable() {
    let receipt = budget().saturation_check(4);
    let fields = receipt.structured_log_fields();
    assert_eq!(fields["component"], COMPONENT);
    assert_eq!(fields["operation"], "saturation_check");
}

#[test]
fn integration_19_structured_log_records_none_attack_class_for_check() {
    let receipt = budget().saturation_check(4);
    assert_eq!(receipt.structured_log_fields()["attack_class"], "none");
}

#[test]
fn integration_20_structured_log_records_attack_class_for_depletion() {
    let mut budget = budget();
    let receipt = budget.deplete(AttackClass::PromptInjection, 10, 4).unwrap();
    assert_eq!(
        receipt.structured_log_fields()["attack_class"],
        "prompt_injection"
    );
}

#[test]
fn integration_21_default_parameterization_allocates_budget() {
    let budget = KLBudgetParameterization::default_v1()
        .allocate_all("default-budget")
        .unwrap();
    assert_eq!(budget.allocations_microln.len(), AttackClass::ALL.len());
}

#[test]
fn integration_22_parameterization_hash_is_stable_for_clone() {
    let parameterization = KLBudgetParameterization::default_v1();
    assert_eq!(
        parameterization.content_hash(),
        parameterization.clone().content_hash()
    );
}

#[test]
fn integration_23_parameterization_rejects_zero_rate() {
    let mut rates = KLBudgetParameterization::default_v1().depletion_rates_microln;
    rates.insert(AttackClass::PromptInjection, 0);
    let err = KLBudgetParameterization::try_new("p", 1_000, 100, rates).unwrap_err();
    assert_eq!(
        err,
        KLBudgetError::ZeroDepletionRate {
            attack_class: AttackClass::PromptInjection
        }
    );
}

#[test]
fn integration_24_all_attack_classes_have_string_ids() {
    for attack_class in AttackClass::ALL {
        assert!(!attack_class.as_str().is_empty());
        assert_eq!(attack_class.to_string(), attack_class.as_str());
    }
}

#[test]
fn integration_25_depletion_order_changes_receipt_hashes() {
    let mut budget_a = budget();
    let mut budget_b = budget();
    let a = budget_a
        .deplete(AttackClass::PromptInjection, 10, 1)
        .unwrap();
    budget_b
        .deplete(AttackClass::PromptInjection, 10, 1)
        .unwrap();
    let b = budget_b
        .deplete(AttackClass::PromptInjection, 10, 2)
        .unwrap();
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn integration_26_spent_total_tracks_applied_depletion() {
    let mut budget = budget();
    budget.deplete(AttackClass::PromptInjection, 10, 1).unwrap();
    budget.deplete(AttackClass::CapabilityProbe, 20, 2).unwrap();
    assert_eq!(budget.spent_total_microln(), 30);
}

#[test]
fn integration_27_remaining_plus_spent_matches_initial_without_truncation() {
    let mut budget = budget();
    budget.deplete(AttackClass::PromptInjection, 10, 1).unwrap();
    budget.deplete(AttackClass::CapabilityProbe, 20, 2).unwrap();
    assert_eq!(
        budget.remaining_budget_microln + budget.spent_total_microln(),
        1_000
    );
}

#[test]
fn integration_28_unallocated_class_fails_closed() {
    let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
    let err = budget
        .deplete(AttackClass::PromptInjection, 10, 1)
        .unwrap_err();
    assert!(matches!(err, KLBudgetError::UnallocatedAttackClass { .. }));
}

#[test]
fn integration_29_zero_depletion_fails_closed() {
    let mut budget = budget();
    let err = budget
        .deplete(AttackClass::PromptInjection, 0, 1)
        .unwrap_err();
    assert!(matches!(err, KLBudgetError::ZeroDepletion { .. }));
}

#[test]
fn integration_30_signed_saturation_check_rejects_wrong_key() {
    let receipt = budget().saturation_check(4).sign(key());
    assert!(!receipt.verify_signature(b"wrong-key"));
}

#[test]
fn integration_31_budget_can_exhaust_exactly_to_zero() {
    let mut budget = KLBudget::try_new("b", 100, 0).unwrap();
    budget.allocate(AttackClass::PromptInjection, 100).unwrap();
    let receipt = budget
        .deplete(AttackClass::PromptInjection, 100, 1)
        .unwrap();
    assert_eq!(receipt.remaining_after_microln, 0);
    assert!(receipt.saturated);
}

#[test]
fn integration_32_receipt_signing_preimage_includes_budget_id() {
    let receipt_a = budget().saturation_check(4);
    let receipt_b = KLBudget::try_new("other-budget", 1_000, 100)
        .unwrap()
        .saturation_check(4);
    assert_ne!(receipt_a.signing_preimage(), receipt_b.signing_preimage());
}
