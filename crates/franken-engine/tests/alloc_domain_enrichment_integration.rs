//! Enrichment integration tests for `alloc_domain`.
//!
//! Covers gaps: AllocationDomain Display uniqueness, LifetimeClass Display
//! uniqueness, DomainBudget utilization math, DomainRegistry registration,
//! allocation/release lifecycle, budget enforcement, serde roundtrips,
//! error Display, standard domain factory, reset semantics, and
//! allocation sequence numbering.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::alloc_domain::{
    AllocDomainError, AllocationDomain, DomainBudget, DomainRegistry, LifetimeClass,
};

// ===========================================================================
// AllocationDomain Display uniqueness
// ===========================================================================

#[test]
fn enrichment_allocation_domain_display_all_unique() {
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    let displays: BTreeSet<String> = all.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_allocation_domain_serde_roundtrip() {
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for domain in &all {
        let json = serde_json::to_string(domain).unwrap();
        let back: AllocationDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*domain, back);
    }
}

// ===========================================================================
// LifetimeClass Display uniqueness
// ===========================================================================

#[test]
fn enrichment_lifetime_class_display_all_unique() {
    let all = [
        LifetimeClass::RequestScoped,
        LifetimeClass::SessionScoped,
        LifetimeClass::Global,
        LifetimeClass::Arena,
    ];
    let displays: BTreeSet<String> = all.iter().map(|l| l.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_lifetime_class_serde_roundtrip() {
    let all = [
        LifetimeClass::RequestScoped,
        LifetimeClass::SessionScoped,
        LifetimeClass::Global,
        LifetimeClass::Arena,
    ];
    for lc in &all {
        let json = serde_json::to_string(lc).unwrap();
        let back: LifetimeClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*lc, back);
    }
}

// ===========================================================================
// DomainBudget
// ===========================================================================

#[test]
fn enrichment_budget_new_all_remaining() {
    let budget = DomainBudget::new(1024);
    assert_eq!(budget.remaining(), 1024);
}

#[test]
fn enrichment_budget_try_reserve_within_bounds() {
    let mut budget = DomainBudget::new(1024);
    assert!(budget.try_reserve(512).is_ok());
    assert_eq!(budget.remaining(), 512);
}

#[test]
fn enrichment_budget_try_reserve_exceeds_bounds() {
    let mut budget = DomainBudget::new(100);
    let result = budget.try_reserve(200);
    assert!(result.is_err());
}

#[test]
fn enrichment_budget_release_restores_capacity() {
    let mut budget = DomainBudget::new(1024);
    budget.try_reserve(512).unwrap();
    budget.release(256);
    assert_eq!(budget.remaining(), 768);
}

#[test]
fn enrichment_budget_utilization_zero_initially() {
    let budget = DomainBudget::new(1024);
    assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn enrichment_budget_utilization_half() {
    let mut budget = DomainBudget::new(1000);
    budget.try_reserve(500).unwrap();
    let util = budget.utilization();
    assert!((util - 0.5).abs() < 0.01, "Expected ~0.5, got {util}");
}

#[test]
fn enrichment_budget_utilization_full() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(100).unwrap();
    assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn enrichment_budget_serde_roundtrip() {
    let budget = DomainBudget::new(2048);
    let json = serde_json::to_string(&budget).unwrap();
    let back: DomainBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget.remaining(), back.remaining());
}

// ===========================================================================
// DomainRegistry: registration
// ===========================================================================

#[test]
fn enrichment_registry_new_empty() {
    let reg = DomainRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn enrichment_registry_register_domain() {
    let mut reg = DomainRegistry::new();
    let result = reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        4096,
    );
    assert!(result.is_ok());
    assert_eq!(reg.len(), 1);
}

#[test]
fn enrichment_registry_register_duplicate_fails() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        4096,
    )
    .unwrap();
    let result = reg.register(AllocationDomain::ExtensionHeap, LifetimeClass::Global, 8192);
    assert!(result.is_err());
}

#[test]
fn enrichment_registry_get_registered_domain() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 2048)
        .unwrap();
    let config = reg.get(&AllocationDomain::IrArena);
    assert!(config.is_some());
    assert_eq!(config.unwrap().domain, AllocationDomain::IrArena);
}

#[test]
fn enrichment_registry_get_unregistered_returns_none() {
    let reg = DomainRegistry::new();
    assert!(reg.get(&AllocationDomain::ScratchBuffer).is_none());
}

// ===========================================================================
// DomainRegistry: allocation/release
// ===========================================================================

#[test]
fn enrichment_registry_allocate_returns_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 4096)
        .unwrap();
    let seq = reg.allocate(AllocationDomain::RuntimeHeap, 100).unwrap();
    assert!(seq > 0);
}

#[test]
fn enrichment_registry_allocate_increments_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 4096)
        .unwrap();
    let s1 = reg.allocate(AllocationDomain::RuntimeHeap, 100).unwrap();
    let s2 = reg.allocate(AllocationDomain::RuntimeHeap, 200).unwrap();
    assert!(s2 > s1);
}

#[test]
fn enrichment_registry_allocate_exceeds_budget() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        100,
    )
    .unwrap();
    let result = reg.allocate(AllocationDomain::ScratchBuffer, 200);
    assert!(result.is_err());
}

#[test]
fn enrichment_registry_allocate_unknown_domain_fails() {
    let mut reg = DomainRegistry::new();
    let result = reg.allocate(AllocationDomain::ExtensionHeap, 100);
    assert!(result.is_err());
}

#[test]
fn enrichment_registry_release_frees_budget() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 1000)
        .unwrap();
    reg.allocate(AllocationDomain::RuntimeHeap, 500).unwrap();
    reg.release(AllocationDomain::RuntimeHeap, 300).unwrap();
    let config = reg.get(&AllocationDomain::RuntimeHeap).unwrap();
    assert_eq!(config.budget.remaining(), 800);
}

// ===========================================================================
// DomainRegistry: totals
// ===========================================================================

#[test]
fn enrichment_registry_total_used_empty() {
    let reg = DomainRegistry::new();
    assert_eq!(reg.total_used(), 0);
}

#[test]
fn enrichment_registry_total_used_after_allocations() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 4096)
        .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 2048)
        .unwrap();
    reg.allocate(AllocationDomain::RuntimeHeap, 100).unwrap();
    reg.allocate(AllocationDomain::IrArena, 50).unwrap();
    assert_eq!(reg.total_used(), 150);
}

#[test]
fn enrichment_registry_total_capacity() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 4096)
        .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 2048)
        .unwrap();
    assert_eq!(reg.total_capacity(), 6144);
}

// ===========================================================================
// DomainRegistry: reset
// ===========================================================================

#[test]
fn enrichment_registry_reset_domain_clears_usage() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        1000,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ScratchBuffer, 500).unwrap();
    reg.reset_domain(AllocationDomain::ScratchBuffer).unwrap();
    let config = reg.get(&AllocationDomain::ScratchBuffer).unwrap();
    assert_eq!(config.budget.remaining(), 1000);
}

#[test]
fn enrichment_registry_reset_unknown_domain_fails() {
    let mut reg = DomainRegistry::new();
    let result = reg.reset_domain(AllocationDomain::ExtensionHeap);
    assert!(result.is_err());
}

// ===========================================================================
// DomainRegistry: standard factory
// ===========================================================================

#[test]
fn enrichment_standard_domains_has_five_entries() {
    let reg = DomainRegistry::with_standard_domains(1024 * 1024);
    assert_eq!(reg.len(), 5);
}

#[test]
fn enrichment_standard_domains_all_registered() {
    let reg = DomainRegistry::with_standard_domains(1024 * 1024);
    assert!(reg.get(&AllocationDomain::ExtensionHeap).is_some());
    assert!(reg.get(&AllocationDomain::RuntimeHeap).is_some());
    assert!(reg.get(&AllocationDomain::IrArena).is_some());
    assert!(reg.get(&AllocationDomain::EvidenceArena).is_some());
    assert!(reg.get(&AllocationDomain::ScratchBuffer).is_some());
}

// ===========================================================================
// AllocDomainError Display
// ===========================================================================

#[test]
fn enrichment_error_display_budget_exceeded() {
    let err = AllocDomainError::BudgetExceeded {
        requested: 200,
        remaining: 100,
        domain: Some(AllocationDomain::ExtensionHeap),
    };
    let display = err.to_string();
    assert!(!display.is_empty());
}

#[test]
fn enrichment_error_display_duplicate_domain() {
    let err = AllocDomainError::DuplicateDomain {
        domain: AllocationDomain::RuntimeHeap,
    };
    let display = err.to_string();
    assert!(!display.is_empty());
}

#[test]
fn enrichment_error_serde_roundtrip() {
    let errors = [
        AllocDomainError::BudgetExceeded {
            requested: 500,
            remaining: 100,
            domain: Some(AllocationDomain::ExtensionHeap),
        },
        AllocDomainError::BudgetOverflow,
        AllocDomainError::DomainNotFound {
            domain: AllocationDomain::IrArena,
        },
        AllocDomainError::DuplicateDomain {
            domain: AllocationDomain::RuntimeHeap,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: AllocDomainError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// DomainRegistry: allocation_sequence
// ===========================================================================

#[test]
fn enrichment_allocation_sequence_starts_at_zero() {
    let reg = DomainRegistry::new();
    assert_eq!(reg.allocation_sequence(), 0);
}

#[test]
fn enrichment_allocation_sequence_increments() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 10000)
        .unwrap();
    reg.allocate(AllocationDomain::RuntimeHeap, 10).unwrap();
    reg.allocate(AllocationDomain::RuntimeHeap, 20).unwrap();
    reg.allocate(AllocationDomain::RuntimeHeap, 30).unwrap();
    assert_eq!(reg.allocation_sequence(), 3);
}
