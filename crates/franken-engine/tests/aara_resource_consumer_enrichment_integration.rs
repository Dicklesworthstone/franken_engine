//! Enrichment integration tests for `aara_resource_consumer`.
//!
//! Covers: Subsystem Display/serde, BudgetDecision Display/serde,
//! DenialReason Display/serde, SubsystemRequirement factories,
//! ResourceConsumer lifecycle, ConsumptionReceipt auditing,
//! ConsumptionSummary generation, ConsumptionManifest creation,
//! deterministic content hashing, and edge cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::aara_resource_certificate::{
    AbstentionPoint, AbstentionReason, CertificateInput, CertificateVerdict, EffectEntry,
    EffectKind, EffectSummary, ResourceBound, ResourceCertificate, ResourceDimension,
};
use frankenengine_engine::aara_resource_consumer::{
    BEAD_ID, BudgetDecision, COMPONENT, ConsumptionManifest, ConsumptionSummary, DenialReason,
    POLICY_ID, ResourceConsumer, SCHEMA_VERSION, Subsystem, SubsystemRequirement,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_bounds() -> Vec<ResourceBound> {
    ResourceDimension::ALL
        .iter()
        .map(|dim| ResourceBound {
            dimension: *dim,
            upper_bound_millionths: 500_000,
            is_tight: true,
            confidence_millionths: 900_000,
        })
        .collect()
}

fn make_effect_summary(entries: Vec<EffectEntry>) -> EffectSummary {
    EffectSummary::build("test-region", entries, vec![])
}

fn good_certificate() -> ResourceCertificate {
    let bounds = make_bounds();
    let effect_summary = make_effect_summary(vec![EffectEntry {
        kind: EffectKind::Allocation,
        program_point: "main:1".to_string(),
        worst_case_count_millionths: 10_000_000,
        is_exact: true,
    }]);
    let input = CertificateInput {
        certificate_id: "test-cert-001".to_string(),
        region_id: "main".to_string(),
        epoch: ep(42),
        bounds,
        effect_summary,
        assumptions: vec![],
        abstention_points: vec![],
        potentials: vec![],
    };
    ResourceCertificate::new(input)
}

fn uncertified_certificate() -> ResourceCertificate {
    let input = CertificateInput {
        certificate_id: "test-uncertified".to_string(),
        region_id: "main".to_string(),
        epoch: ep(42),
        bounds: vec![],
        effect_summary: make_effect_summary(vec![]),
        assumptions: vec![],
        abstention_points: vec![AbstentionPoint {
            program_point: "unknown:0".to_string(),
            reason: AbstentionReason::DynamicDispatch,
            detail: "test abstention".to_string(),
        }],
        potentials: vec![],
    };
    ResourceCertificate::new(input)
}

// ===========================================================================
// Subsystem Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_subsystem_display_all_unique() {
    let all = [
        Subsystem::Scheduler,
        Subsystem::GarbageCollector,
        Subsystem::ModuleLoader,
        Subsystem::Specializer,
        Subsystem::HostcallGate,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_subsystem_serde_roundtrip() {
    let all = [
        Subsystem::Scheduler,
        Subsystem::GarbageCollector,
        Subsystem::ModuleLoader,
        Subsystem::Specializer,
        Subsystem::HostcallGate,
    ];
    for s in &all {
        let json = serde_json::to_string(s).unwrap();
        let back: Subsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// BudgetDecision Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_budget_decision_display_all_unique() {
    let all = [
        BudgetDecision::FullBudget,
        BudgetDecision::ReducedBudget,
        BudgetDecision::Denied,
        BudgetDecision::Abstain,
    ];
    let displays: BTreeSet<String> = all.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_budget_decision_serde_roundtrip() {
    let all = [
        BudgetDecision::FullBudget,
        BudgetDecision::ReducedBudget,
        BudgetDecision::Denied,
        BudgetDecision::Abstain,
    ];
    for d in &all {
        let json = serde_json::to_string(d).unwrap();
        let back: BudgetDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn enrichment_budget_decision_is_granted() {
    assert!(BudgetDecision::FullBudget.is_granted());
    assert!(BudgetDecision::ReducedBudget.is_granted());
    assert!(!BudgetDecision::Denied.is_granted());
    assert!(!BudgetDecision::Abstain.is_granted());
}

// ===========================================================================
// DenialReason Display and serde
// ===========================================================================

#[test]
fn enrichment_denial_reason_display_variants() {
    let reasons = [
        DenialReason::MissingDimension {
            dimension: ResourceDimension::Time,
        },
        DenialReason::BoundTooLow {
            dimension: ResourceDimension::HeapMemory,
            bound_millionths: 100,
            required_millionths: 500,
        },
        DenialReason::CertificateNotCertified {
            verdict: CertificateVerdict::Abstained,
        },
        DenialReason::ForbiddenEffect {
            effect: EffectKind::DynamicCodeGen,
        },
        DenialReason::LowBoundConfidence {
            dimension: ResourceDimension::StackDepth,
            confidence_millionths: 400_000,
            required_millionths: 800_000,
        },
        DenialReason::CriticalAssumptions,
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), reasons.len());
}

#[test]
fn enrichment_denial_reason_serde_roundtrip() {
    let reason = DenialReason::MissingDimension {
        dimension: ResourceDimension::Time,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: DenialReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, back);
}

// ===========================================================================
// SubsystemRequirement factories
// ===========================================================================

#[test]
fn enrichment_requirement_scheduler_has_time_bound() {
    let req = SubsystemRequirement::scheduler();
    assert_eq!(req.subsystem, Subsystem::Scheduler);
    assert!(req.min_bounds.contains_key(&ResourceDimension::Time));
}

#[test]
fn enrichment_requirement_gc_has_heap_memory() {
    let req = SubsystemRequirement::garbage_collector();
    assert_eq!(req.subsystem, Subsystem::GarbageCollector);
    assert!(req.min_bounds.contains_key(&ResourceDimension::HeapMemory));
}

#[test]
fn enrichment_requirement_module_loader_has_io() {
    let req = SubsystemRequirement::module_loader();
    assert_eq!(req.subsystem, Subsystem::ModuleLoader);
    assert!(
        req.min_bounds
            .contains_key(&ResourceDimension::IoOperationCount)
    );
}

#[test]
fn enrichment_requirement_specializer_forbids_dynamic_code_gen() {
    let req = SubsystemRequirement::specializer();
    assert_eq!(req.subsystem, Subsystem::Specializer);
    assert!(req.forbidden_effects.contains(&EffectKind::DynamicCodeGen));
    assert!(req.reject_critical_assumptions);
}

#[test]
fn enrichment_requirement_hostcall_gate_has_hostcall_count() {
    let req = SubsystemRequirement::hostcall_gate();
    assert_eq!(req.subsystem, Subsystem::HostcallGate);
    assert!(
        req.min_bounds
            .contains_key(&ResourceDimension::HostcallCount)
    );
}

// ===========================================================================
// ResourceConsumer lifecycle
// ===========================================================================

#[test]
fn enrichment_consumer_with_defaults_has_5_requirements() {
    let consumer = ResourceConsumer::with_defaults(ep(1));
    assert_eq!(consumer.requirements.len(), 5);
}

#[test]
fn enrichment_consumer_consume_good_certificate() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    let cert = good_certificate();
    let decisions = consumer.consume(&cert);
    assert_eq!(decisions.len(), 5);
    // At least some should be granted
    assert!(decisions.iter().any(|d| d.is_granted()));
}

#[test]
fn enrichment_consumer_consume_uncertified_all_denied() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    let cert = uncertified_certificate();
    let decisions = consumer.consume(&cert);
    assert_eq!(decisions.len(), 5);
    for d in &decisions {
        assert_eq!(*d, BudgetDecision::Denied);
    }
}

#[test]
fn enrichment_consumer_receipts_accumulate() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    let cert = good_certificate();
    consumer.consume(&cert);
    assert_eq!(consumer.receipts().len(), 5);
    consumer.consume(&cert);
    assert_eq!(consumer.receipts().len(), 10);
}

#[test]
fn enrichment_consumer_receipts_for_subsystem() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    let cert = good_certificate();
    consumer.consume(&cert);
    let scheduler_receipts = consumer.receipts_for(Subsystem::Scheduler);
    assert_eq!(scheduler_receipts.len(), 1);
}

#[test]
fn enrichment_consumer_last_receipt_for() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    let cert = good_certificate();
    consumer.consume(&cert);
    let last = consumer.last_receipt_for(Subsystem::Scheduler);
    assert!(last.is_some());
    assert_eq!(last.unwrap().subsystem, Subsystem::Scheduler);
}

// ===========================================================================
// ConsumptionSummary
// ===========================================================================

#[test]
fn enrichment_consumption_summary_after_good_cert() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    consumer.consume(&good_certificate());
    let summary = consumer.summary();
    assert_eq!(summary.total_decisions, 5);
    assert!(summary.grant_rate_millionths >= 0);
}

#[test]
fn enrichment_consumption_summary_serde_roundtrip() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    consumer.consume(&good_certificate());
    let summary = consumer.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: ConsumptionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ===========================================================================
// ConsumptionManifest
// ===========================================================================

#[test]
fn enrichment_consumption_manifest_from_consumer() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    assert_eq!(manifest.bead_id, BEAD_ID);
    assert_eq!(manifest.component, COMPONENT);
    assert_eq!(manifest.policy_id, POLICY_ID);
    assert_eq!(manifest.receipts.len(), 5);
}

#[test]
fn enrichment_consumption_manifest_serde_roundtrip() {
    let mut consumer = ResourceConsumer::with_defaults(ep(1));
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ConsumptionManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn enrichment_bead_id_prefix() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-625B");
}

// ===========================================================================
// Custom consumer
// ===========================================================================

#[test]
fn enrichment_custom_consumer_empty_requirements() {
    let mut consumer = ResourceConsumer::new(vec![], ep(1));
    let cert = good_certificate();
    let decisions = consumer.consume(&cert);
    assert!(decisions.is_empty());
    assert!(consumer.receipts().is_empty());
}

#[test]
fn enrichment_custom_consumer_single_requirement() {
    let mut consumer = ResourceConsumer::new(vec![SubsystemRequirement::scheduler()], ep(1));
    let cert = good_certificate();
    let decisions = consumer.consume(&cert);
    assert_eq!(decisions.len(), 1);
}
