//! Integration tests for AARA resource certificate consumer (RGC-625B).

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

use frankenengine_engine::aara_resource_certificate::{
    AbstentionPoint, AbstentionReason, AssumptionKind, CertificateAssumption, CertificateInput,
    CertificateVerdict, EffectEntry, EffectKind, EffectSummary, ResourceBound, ResourceCertificate,
    ResourceDimension,
};
use frankenengine_engine::aara_resource_consumer::{
    BEAD_ID, BudgetDecision, COMPONENT, ConsumptionManifest, ConsumptionSummary, DenialReason,
    POLICY_ID, ResourceConsumer, SCHEMA_VERSION, Subsystem, SubsystemRequirement,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
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
        epoch: epoch(),
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
        epoch: epoch(),
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

fn low_bound_certificate() -> ResourceCertificate {
    let mut bounds = make_bounds();
    if let Some(b) = bounds
        .iter_mut()
        .find(|b| b.dimension == ResourceDimension::Time)
    {
        b.upper_bound_millionths = 10_000;
    }
    let input = CertificateInput {
        certificate_id: "test-low-bound".to_string(),
        region_id: "main".to_string(),
        epoch: epoch(),
        bounds,
        effect_summary: make_effect_summary(vec![]),
        assumptions: vec![],
        abstention_points: vec![],
        potentials: vec![],
    };
    ResourceCertificate::new(input)
}

fn dynamic_code_gen_certificate() -> ResourceCertificate {
    let bounds = make_bounds();
    let effect_summary = make_effect_summary(vec![EffectEntry {
        kind: EffectKind::DynamicCodeGen,
        program_point: "eval_block:1".to_string(),
        worst_case_count_millionths: 1_000_000,
        is_exact: false,
    }]);
    let input = CertificateInput {
        certificate_id: "test-dyncodegen".to_string(),
        region_id: "eval_block".to_string(),
        epoch: epoch(),
        bounds,
        effect_summary,
        assumptions: vec![],
        abstention_points: vec![],
        potentials: vec![],
    };
    ResourceCertificate::new(input)
}

fn low_confidence_certificate() -> ResourceCertificate {
    let bounds: Vec<ResourceBound> = ResourceDimension::ALL
        .iter()
        .map(|dim| ResourceBound {
            dimension: *dim,
            upper_bound_millionths: 500_000,
            is_tight: false,
            confidence_millionths: 300_000,
        })
        .collect();
    let input = CertificateInput {
        certificate_id: "test-low-conf".to_string(),
        region_id: "main".to_string(),
        epoch: epoch(),
        bounds,
        effect_summary: make_effect_summary(vec![]),
        assumptions: vec![],
        abstention_points: vec![],
        potentials: vec![],
    };
    ResourceCertificate::new(input)
}

fn partial_dimension_certificate() -> ResourceCertificate {
    let bounds: Vec<ResourceBound> = [ResourceDimension::Time, ResourceDimension::HeapMemory]
        .iter()
        .map(|dim| ResourceBound {
            dimension: *dim,
            upper_bound_millionths: 500_000,
            is_tight: true,
            confidence_millionths: 900_000,
        })
        .collect();
    let input = CertificateInput {
        certificate_id: "test-partial".to_string(),
        region_id: "main".to_string(),
        epoch: epoch(),
        bounds,
        effect_summary: make_effect_summary(vec![]),
        assumptions: vec![],
        abstention_points: vec![],
        potentials: vec![],
    };
    ResourceCertificate::new(input)
}

fn critical_assumption_certificate() -> ResourceCertificate {
    let bounds = make_bounds();
    let input = CertificateInput {
        certificate_id: "test-crit-assume".to_string(),
        region_id: "main".to_string(),
        epoch: epoch(),
        bounds,
        effect_summary: make_effect_summary(vec![]),
        assumptions: vec![CertificateAssumption {
            key: "bounded-loop-1".to_string(),
            kind: AssumptionKind::BoundedIteration,
            description: "loop is bounded".to_string(),
            is_critical: true,
        }],
        abstention_points: vec![],
        potentials: vec![],
    };
    ResourceCertificate::new(input)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("aara_resource_consumer"));
}

#[test]
fn test_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "aara_resource_consumer");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-625B");
}

// ---------------------------------------------------------------------------
// Subsystem enum
// ---------------------------------------------------------------------------

#[test]
fn test_subsystem_display_scheduler() {
    assert_eq!(Subsystem::Scheduler.to_string(), "scheduler");
}

#[test]
fn test_subsystem_display_gc() {
    assert_eq!(Subsystem::GarbageCollector.to_string(), "gc");
}

#[test]
fn test_subsystem_display_module_loader() {
    assert_eq!(Subsystem::ModuleLoader.to_string(), "module_loader");
}

#[test]
fn test_subsystem_display_specializer() {
    assert_eq!(Subsystem::Specializer.to_string(), "specializer");
}

#[test]
fn test_subsystem_display_hostcall() {
    assert_eq!(Subsystem::HostcallGate.to_string(), "hostcall_gate");
}

#[test]
fn test_subsystem_ordering() {
    assert!(Subsystem::Scheduler < Subsystem::GarbageCollector);
}

#[test]
fn test_subsystem_serde_roundtrip_all() {
    for s in [
        Subsystem::Scheduler,
        Subsystem::GarbageCollector,
        Subsystem::ModuleLoader,
        Subsystem::Specializer,
        Subsystem::HostcallGate,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: Subsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// BudgetDecision enum
// ---------------------------------------------------------------------------

#[test]
fn test_budget_decision_full_granted() {
    assert!(BudgetDecision::FullBudget.is_granted());
}

#[test]
fn test_budget_decision_reduced_granted() {
    assert!(BudgetDecision::ReducedBudget.is_granted());
}

#[test]
fn test_budget_decision_denied_not_granted() {
    assert!(!BudgetDecision::Denied.is_granted());
}

#[test]
fn test_budget_decision_abstain_not_granted() {
    assert!(!BudgetDecision::Abstain.is_granted());
}

#[test]
fn test_budget_decision_display_full() {
    assert_eq!(BudgetDecision::FullBudget.to_string(), "full_budget");
}

#[test]
fn test_budget_decision_display_reduced() {
    assert_eq!(BudgetDecision::ReducedBudget.to_string(), "reduced_budget");
}

#[test]
fn test_budget_decision_display_denied() {
    assert_eq!(BudgetDecision::Denied.to_string(), "denied");
}

#[test]
fn test_budget_decision_display_abstain() {
    assert_eq!(BudgetDecision::Abstain.to_string(), "abstain");
}

#[test]
fn test_budget_decision_serde_roundtrip_all() {
    for d in [
        BudgetDecision::FullBudget,
        BudgetDecision::ReducedBudget,
        BudgetDecision::Denied,
        BudgetDecision::Abstain,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: BudgetDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ---------------------------------------------------------------------------
// DenialReason
// ---------------------------------------------------------------------------

#[test]
fn test_denial_reason_missing_dimension_display() {
    let r = DenialReason::MissingDimension {
        dimension: ResourceDimension::Time,
    };
    let s = format!("{r}");
    assert!(s.contains("missing dimension"));
}

#[test]
fn test_denial_reason_bound_too_low_display() {
    let r = DenialReason::BoundTooLow {
        dimension: ResourceDimension::HeapMemory,
        bound_millionths: 10_000,
        required_millionths: 100_000,
    };
    let s = format!("{r}");
    assert!(s.contains("bound too low"));
    assert!(s.contains("10000"));
}

#[test]
fn test_denial_reason_not_certified_display() {
    let r = DenialReason::CertificateNotCertified {
        verdict: CertificateVerdict::Abstained,
    };
    let s = format!("{r}");
    assert!(s.contains("certificate not certified"));
}

#[test]
fn test_denial_reason_forbidden_effect_display() {
    let r = DenialReason::ForbiddenEffect {
        effect: EffectKind::DynamicCodeGen,
    };
    let s = format!("{r}");
    assert!(s.contains("forbidden effect"));
}

#[test]
fn test_denial_reason_low_confidence_display() {
    let r = DenialReason::LowBoundConfidence {
        dimension: ResourceDimension::Time,
        confidence_millionths: 300_000,
        required_millionths: 800_000,
    };
    let s = format!("{r}");
    assert!(s.contains("low confidence"));
}

#[test]
fn test_denial_reason_critical_assumptions_display() {
    let r = DenialReason::CriticalAssumptions;
    let s = format!("{r}");
    assert!(s.contains("critical assumptions"));
}

#[test]
fn test_denial_reason_serde_roundtrip() {
    let r = DenialReason::BoundTooLow {
        dimension: ResourceDimension::HeapMemory,
        bound_millionths: 10_000,
        required_millionths: 100_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DenialReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// SubsystemRequirement factories
// ---------------------------------------------------------------------------

#[test]
fn test_scheduler_requirement_subsystem() {
    let req = SubsystemRequirement::scheduler();
    assert_eq!(req.subsystem, Subsystem::Scheduler);
}

#[test]
fn test_scheduler_requirement_needs_time() {
    let req = SubsystemRequirement::scheduler();
    assert!(req.min_bounds.contains_key(&ResourceDimension::Time));
}

#[test]
fn test_scheduler_requirement_needs_stack_depth() {
    let req = SubsystemRequirement::scheduler();
    assert!(req.min_bounds.contains_key(&ResourceDimension::StackDepth));
}

#[test]
fn test_scheduler_no_critical_assumptions_rejection() {
    let req = SubsystemRequirement::scheduler();
    assert!(!req.reject_critical_assumptions);
}

#[test]
fn test_gc_requirement_subsystem() {
    let req = SubsystemRequirement::garbage_collector();
    assert_eq!(req.subsystem, Subsystem::GarbageCollector);
}

#[test]
fn test_gc_requirement_needs_heap_memory() {
    let req = SubsystemRequirement::garbage_collector();
    assert!(req.min_bounds.contains_key(&ResourceDimension::HeapMemory));
}

#[test]
fn test_gc_requirement_needs_gc_pressure() {
    let req = SubsystemRequirement::garbage_collector();
    assert!(req.min_bounds.contains_key(&ResourceDimension::GcPressure));
}

#[test]
fn test_module_loader_requirement_subsystem() {
    let req = SubsystemRequirement::module_loader();
    assert_eq!(req.subsystem, Subsystem::ModuleLoader);
}

#[test]
fn test_module_loader_needs_module_load_count() {
    let req = SubsystemRequirement::module_loader();
    assert!(
        req.min_bounds
            .contains_key(&ResourceDimension::ModuleLoadCount)
    );
}

#[test]
fn test_module_loader_needs_io_op_count() {
    let req = SubsystemRequirement::module_loader();
    assert!(
        req.min_bounds
            .contains_key(&ResourceDimension::IoOperationCount)
    );
}

#[test]
fn test_specializer_requirement_subsystem() {
    let req = SubsystemRequirement::specializer();
    assert_eq!(req.subsystem, Subsystem::Specializer);
}

#[test]
fn test_specializer_forbids_dynamic_code_gen() {
    let req = SubsystemRequirement::specializer();
    assert!(req.forbidden_effects.contains(&EffectKind::DynamicCodeGen));
}

#[test]
fn test_specializer_rejects_critical_assumptions() {
    let req = SubsystemRequirement::specializer();
    assert!(req.reject_critical_assumptions);
}

#[test]
fn test_specializer_high_confidence_threshold() {
    let req = SubsystemRequirement::specializer();
    assert_eq!(req.min_confidence_millionths, 800_000);
}

#[test]
fn test_hostcall_gate_requirement_subsystem() {
    let req = SubsystemRequirement::hostcall_gate();
    assert_eq!(req.subsystem, Subsystem::HostcallGate);
}

#[test]
fn test_hostcall_gate_needs_hostcall_count() {
    let req = SubsystemRequirement::hostcall_gate();
    assert!(
        req.min_bounds
            .contains_key(&ResourceDimension::HostcallCount)
    );
}

#[test]
fn test_requirement_serde_roundtrip() {
    let req = SubsystemRequirement::specializer();
    let json = serde_json::to_string(&req).unwrap();
    let back: SubsystemRequirement = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

// ---------------------------------------------------------------------------
// ResourceConsumer — construction
// ---------------------------------------------------------------------------

#[test]
fn test_with_defaults_five_requirements() {
    let consumer = ResourceConsumer::with_defaults(epoch());
    assert_eq!(consumer.requirements.len(), 5);
}

#[test]
fn test_with_defaults_empty_receipts() {
    let consumer = ResourceConsumer::with_defaults(epoch());
    assert!(consumer.receipts().is_empty());
}

#[test]
fn test_custom_requirements() {
    let req = SubsystemRequirement::scheduler();
    let consumer = ResourceConsumer::new(vec![req], epoch());
    assert_eq!(consumer.requirements.len(), 1);
}

#[test]
fn test_custom_empty_requirements() {
    let consumer = ResourceConsumer::new(vec![], epoch());
    assert_eq!(consumer.requirements.len(), 0);
}

// ---------------------------------------------------------------------------
// Consumer — good certificate (all subsystems get budget)
// ---------------------------------------------------------------------------

#[test]
fn test_good_cert_produces_five_decisions() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    let decisions = consumer.consume(&good_certificate());
    assert_eq!(decisions.len(), 5);
}

#[test]
fn test_good_cert_scheduler_full_budget() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
    assert!(r.denial_reasons.is_empty());
}

#[test]
fn test_good_cert_gc_full_budget() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let r = consumer
        .last_receipt_for(Subsystem::GarbageCollector)
        .unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
}

#[test]
fn test_good_cert_module_loader_full_budget() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let r = consumer.last_receipt_for(Subsystem::ModuleLoader).unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
}

#[test]
fn test_good_cert_hostcall_full_budget() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let r = consumer.last_receipt_for(Subsystem::HostcallGate).unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
}

#[test]
fn test_good_cert_allocated_budgets_present() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert!(!r.allocated_budgets.is_empty());
}

#[test]
fn test_good_cert_certificate_id_recorded() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r.certificate_id, "test-cert-001");
}

// ---------------------------------------------------------------------------
// Consumer — uncertified certificate (all denied)
// ---------------------------------------------------------------------------

#[test]
fn test_uncertified_all_denied() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    let decisions = consumer.consume(&uncertified_certificate());
    for d in &decisions {
        assert_eq!(*d, BudgetDecision::Denied);
    }
}

#[test]
fn test_uncertified_denial_reason_present() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&uncertified_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert!(
        r.denial_reasons
            .iter()
            .any(|r| matches!(r, DenialReason::CertificateNotCertified { .. }))
    );
}

#[test]
fn test_uncertified_allocated_budgets_empty() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&uncertified_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert!(r.allocated_budgets.is_empty());
}

// ---------------------------------------------------------------------------
// Consumer — low bound certificate
// ---------------------------------------------------------------------------

#[test]
fn test_low_bound_scheduler_has_denial_reasons() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&low_bound_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert!(!r.denial_reasons.is_empty());
    assert!(
        r.denial_reasons
            .iter()
            .any(|r| matches!(r, DenialReason::BoundTooLow { .. }))
    );
}

#[test]
fn test_low_bound_specializer_has_denial_reasons() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&low_bound_certificate());
    let r = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
    assert!(!r.denial_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// Consumer — dynamic code gen certificate
// ---------------------------------------------------------------------------

#[test]
fn test_dyncodegen_blocks_specializer() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&dynamic_code_gen_certificate());
    let r = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
    assert_eq!(r.decision, BudgetDecision::Denied);
    assert!(r.denial_reasons.iter().any(|r| matches!(
        r,
        DenialReason::ForbiddenEffect {
            effect: EffectKind::DynamicCodeGen
        }
    )));
}

#[test]
fn test_dyncodegen_does_not_block_scheduler() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&dynamic_code_gen_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
}

#[test]
fn test_dyncodegen_does_not_block_gc() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&dynamic_code_gen_certificate());
    let r = consumer
        .last_receipt_for(Subsystem::GarbageCollector)
        .unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
}

#[test]
fn test_dyncodegen_does_not_block_hostcall() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&dynamic_code_gen_certificate());
    let r = consumer.last_receipt_for(Subsystem::HostcallGate).unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
}

// ---------------------------------------------------------------------------
// Consumer — low confidence certificate
// ---------------------------------------------------------------------------

#[test]
fn test_low_confidence_cert_is_provisional() {
    // Low confidence (300k) < MIN_CERTIFICATE_CONFIDENCE (900k),
    // so verdict is Provisional, not Certified. All subsystems get Denied
    // with CertificateNotCertified reason — LowBoundConfidence is never reached.
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    let decisions = consumer.consume(&low_confidence_certificate());
    for d in &decisions {
        assert_eq!(*d, BudgetDecision::Denied);
    }
}

#[test]
fn test_low_confidence_denial_reason_is_not_certified() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&low_confidence_certificate());
    let r = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
    assert!(r.denial_reasons.iter().any(|r| matches!(
        r,
        DenialReason::CertificateNotCertified {
            verdict: CertificateVerdict::Provisional
        }
    )));
}

// ---------------------------------------------------------------------------
// Consumer — partial dimension certificate (causes Abstain)
// ---------------------------------------------------------------------------

#[test]
fn test_partial_dims_module_loader_abstains() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&partial_dimension_certificate());
    let r = consumer.last_receipt_for(Subsystem::ModuleLoader).unwrap();
    assert_eq!(r.decision, BudgetDecision::Abstain);
}

#[test]
fn test_partial_dims_hostcall_abstains() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&partial_dimension_certificate());
    let r = consumer.last_receipt_for(Subsystem::HostcallGate).unwrap();
    assert_eq!(r.decision, BudgetDecision::Abstain);
}

#[test]
fn test_partial_dims_scheduler_abstains() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&partial_dimension_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r.decision, BudgetDecision::Abstain);
}

#[test]
fn test_partial_dims_missing_dimension_reason() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&partial_dimension_certificate());
    let r = consumer.last_receipt_for(Subsystem::ModuleLoader).unwrap();
    assert!(
        r.denial_reasons
            .iter()
            .any(|r| matches!(r, DenialReason::MissingDimension { .. }))
    );
}

// ---------------------------------------------------------------------------
// Consumer — critical assumption certificate
// ---------------------------------------------------------------------------

#[test]
fn test_critical_assumption_blocks_specializer() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&critical_assumption_certificate());
    let r = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
    assert_eq!(r.decision, BudgetDecision::Denied);
    assert!(
        r.denial_reasons
            .iter()
            .any(|r| matches!(r, DenialReason::CriticalAssumptions))
    );
}

#[test]
fn test_critical_assumption_does_not_block_scheduler() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&critical_assumption_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r.decision, BudgetDecision::FullBudget);
}

// ---------------------------------------------------------------------------
// Consumer — custom single requirement
// ---------------------------------------------------------------------------

#[test]
fn test_custom_single_req_good_cert() {
    let mut min_bounds = BTreeMap::new();
    min_bounds.insert(ResourceDimension::Time, 100_000);
    let req = SubsystemRequirement {
        subsystem: Subsystem::Scheduler,
        min_bounds,
        forbidden_effects: BTreeSet::new(),
        min_confidence_millionths: 500_000,
        reject_critical_assumptions: false,
    };
    let mut consumer = ResourceConsumer::new(vec![req], epoch());
    let decisions = consumer.consume(&good_certificate());
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0], BudgetDecision::FullBudget);
}

#[test]
fn test_custom_no_requirements_empty_decisions() {
    let mut consumer = ResourceConsumer::new(vec![], epoch());
    let decisions = consumer.consume(&good_certificate());
    assert!(decisions.is_empty());
}

// ---------------------------------------------------------------------------
// Receipt counter and identification
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_counter_increments() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    assert_eq!(consumer.receipts().len(), 5);
    assert_eq!(consumer.receipts()[0].receipt_id, "rc-rcpt-1");
    assert_eq!(consumer.receipts()[4].receipt_id, "rc-rcpt-5");
}

#[test]
fn test_receipt_counter_continues_across_certificates() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    consumer.consume(&good_certificate());
    assert_eq!(consumer.receipts().len(), 10);
    assert_eq!(consumer.receipts()[5].receipt_id, "rc-rcpt-6");
    assert_eq!(consumer.receipts()[9].receipt_id, "rc-rcpt-10");
}

#[test]
fn test_receipts_for_subsystem_filter() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    consumer.consume(&good_certificate());
    let sched_receipts = consumer.receipts_for(Subsystem::Scheduler);
    assert_eq!(sched_receipts.len(), 2);
    for r in &sched_receipts {
        assert_eq!(r.subsystem, Subsystem::Scheduler);
    }
}

#[test]
fn test_last_receipt_for_returns_latest() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    consumer.consume(&uncertified_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r.decision, BudgetDecision::Denied);
}

#[test]
fn test_last_receipt_for_nonexistent_returns_none() {
    let consumer = ResourceConsumer::with_defaults(epoch());
    assert!(consumer.last_receipt_for(Subsystem::Scheduler).is_none());
}

#[test]
fn test_receipt_epoch_matches_consumer() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let r = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r.epoch, epoch());
}

// ---------------------------------------------------------------------------
// Receipt hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic() {
    let mut c1 = ResourceConsumer::with_defaults(epoch());
    let mut c2 = ResourceConsumer::with_defaults(epoch());
    let cert = good_certificate();
    c1.consume(&cert);
    c2.consume(&cert);
    let r1 = c1.last_receipt_for(Subsystem::Scheduler).unwrap();
    let r2 = c2.last_receipt_for(Subsystem::Scheduler).unwrap();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_different_subsystem_different_receipt_hash() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let sched = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
    let gc = consumer
        .last_receipt_for(Subsystem::GarbageCollector)
        .unwrap();
    assert_ne!(sched.receipt_hash, gc.receipt_hash);
}

// ---------------------------------------------------------------------------
// ConsumptionSummary
// ---------------------------------------------------------------------------

#[test]
fn test_empty_summary_zero_decisions() {
    let consumer = ResourceConsumer::with_defaults(epoch());
    let summary = consumer.summary();
    assert_eq!(summary.total_decisions, 0);
    assert_eq!(summary.full_budget_count, 0);
    assert_eq!(summary.reduced_count, 0);
    assert_eq!(summary.denied_count, 0);
    assert_eq!(summary.abstain_count, 0);
    assert_eq!(summary.grant_rate_millionths, 0);
}

#[test]
fn test_summary_after_good_cert() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let summary = consumer.summary();
    assert_eq!(summary.total_decisions, 5);
    assert!(summary.full_budget_count > 0);
}

#[test]
fn test_summary_after_uncertified_cert() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&uncertified_certificate());
    let summary = consumer.summary();
    assert_eq!(summary.total_decisions, 5);
    assert_eq!(summary.denied_count, 5);
    assert_eq!(summary.full_budget_count, 0);
}

#[test]
fn test_summary_grant_rate_mixed() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    consumer.consume(&uncertified_certificate());
    let summary = consumer.summary();
    assert_eq!(summary.total_decisions, 10);
    assert!(summary.grant_rate_millionths > 0);
    assert!(summary.grant_rate_millionths < 1_000_000);
}

#[test]
fn test_summary_denial_reason_counts() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&uncertified_certificate());
    let summary = consumer.summary();
    assert!(!summary.denial_reason_counts.is_empty());
}

#[test]
fn test_summary_epoch_matches() {
    let consumer = ResourceConsumer::with_defaults(epoch());
    let summary = consumer.summary();
    assert_eq!(summary.epoch, epoch());
}

#[test]
fn test_summary_hash_deterministic() {
    let mut c1 = ResourceConsumer::with_defaults(epoch());
    let mut c2 = ResourceConsumer::with_defaults(epoch());
    let cert = good_certificate();
    c1.consume(&cert);
    c2.consume(&cert);
    let s1 = c1.summary();
    let s2 = c2.summary();
    assert_eq!(s1.summary_hash, s2.summary_hash);
}

#[test]
fn test_summary_serde_roundtrip() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let summary = consumer.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: ConsumptionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.total_decisions, back.total_decisions);
    assert_eq!(summary.summary_hash, back.summary_hash);
}

// ---------------------------------------------------------------------------
// ConsumptionManifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_schema_version() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
}

#[test]
fn test_manifest_bead_id() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    assert_eq!(manifest.bead_id, BEAD_ID);
}

#[test]
fn test_manifest_component() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    assert_eq!(manifest.component, COMPONENT);
}

#[test]
fn test_manifest_policy_id() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    assert_eq!(manifest.policy_id, POLICY_ID);
}

#[test]
fn test_manifest_receipts_count() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    assert_eq!(manifest.receipts.len(), 5);
}

#[test]
fn test_manifest_hash_deterministic() {
    let mut c1 = ResourceConsumer::with_defaults(epoch());
    let mut c2 = ResourceConsumer::with_defaults(epoch());
    let cert = good_certificate();
    c1.consume(&cert);
    c2.consume(&cert);
    let m1 = ConsumptionManifest::from_consumer(&c1);
    let m2 = ConsumptionManifest::from_consumer(&c2);
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn test_manifest_serde_roundtrip() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let manifest = ConsumptionManifest::from_consumer(&consumer);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ConsumptionManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.schema_version, back.schema_version);
    assert_eq!(manifest.manifest_hash, back.manifest_hash);
    assert_eq!(manifest.receipts.len(), back.receipts.len());
}

// ---------------------------------------------------------------------------
// Consumer serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_consumer_serde_roundtrip() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    let json = serde_json::to_string(&consumer).unwrap();
    let back: ResourceConsumer = serde_json::from_str(&json).unwrap();
    assert_eq!(back.receipts().len(), consumer.receipts().len());
    assert_eq!(back.requirements.len(), consumer.requirements.len());
}

// ---------------------------------------------------------------------------
// Multiple certificates
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_good_certs_accumulate_receipts() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    consumer.consume(&good_certificate());
    consumer.consume(&good_certificate());
    assert_eq!(consumer.receipts().len(), 15);
}

#[test]
fn test_mixed_certs_grant_rate() {
    let mut consumer = ResourceConsumer::with_defaults(epoch());
    consumer.consume(&good_certificate());
    consumer.consume(&uncertified_certificate());
    consumer.consume(&dynamic_code_gen_certificate());
    let summary = consumer.summary();
    assert_eq!(summary.total_decisions, 15);
    assert!(summary.grant_rate_millionths > 0);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_empty_consumer_no_receipts() {
    let consumer = ResourceConsumer::with_defaults(epoch());
    assert!(consumer.receipts().is_empty());
    assert!(consumer.last_receipt_for(Subsystem::Scheduler).is_none());
}

#[test]
fn test_consumer_epoch_preserved() {
    let e = SecurityEpoch::from_raw(99);
    let consumer = ResourceConsumer::with_defaults(e);
    assert_eq!(consumer.epoch, e);
}
