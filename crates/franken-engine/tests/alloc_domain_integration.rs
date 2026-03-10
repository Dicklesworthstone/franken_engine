//! Integration tests for the `alloc_domain` module.
//!
//! Tests allocation domain taxonomy, budget enforcement, domain registry,
//! deterministic sequencing, and serde roundtrips.

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

use frankenengine_engine::alloc_domain::{
    AllocDomainError, AllocationDomain, DomainBudget, DomainConfig, DomainRegistry, LifetimeClass,
};

// ---------------------------------------------------------------------------
// AllocationDomain display
// ---------------------------------------------------------------------------

#[test]
fn allocation_domain_display_all_variants() {
    assert_eq!(
        AllocationDomain::ExtensionHeap.to_string(),
        "extension-heap"
    );
    assert_eq!(AllocationDomain::RuntimeHeap.to_string(), "runtime-heap");
    assert_eq!(AllocationDomain::IrArena.to_string(), "ir-arena");
    assert_eq!(
        AllocationDomain::EvidenceArena.to_string(),
        "evidence-arena"
    );
    assert_eq!(
        AllocationDomain::ScratchBuffer.to_string(),
        "scratch-buffer"
    );
}

#[test]
fn allocation_domain_ordering() {
    assert!(AllocationDomain::ExtensionHeap < AllocationDomain::RuntimeHeap);
    assert!(AllocationDomain::RuntimeHeap < AllocationDomain::IrArena);
    assert!(AllocationDomain::IrArena < AllocationDomain::EvidenceArena);
    assert!(AllocationDomain::EvidenceArena < AllocationDomain::ScratchBuffer);
}

// ---------------------------------------------------------------------------
// LifetimeClass display
// ---------------------------------------------------------------------------

#[test]
fn lifetime_class_display_all_variants() {
    assert_eq!(LifetimeClass::RequestScoped.to_string(), "request-scoped");
    assert_eq!(LifetimeClass::SessionScoped.to_string(), "session-scoped");
    assert_eq!(LifetimeClass::Global.to_string(), "global");
    assert_eq!(LifetimeClass::Arena.to_string(), "arena");
}

// ---------------------------------------------------------------------------
// DomainBudget
// ---------------------------------------------------------------------------

#[test]
fn budget_new_starts_at_zero() {
    let budget = DomainBudget::new(1024);
    assert_eq!(budget.max_bytes, 1024);
    assert_eq!(budget.used_bytes, 0);
    assert_eq!(budget.remaining(), 1024);
}

#[test]
fn budget_reserve_success() {
    let mut budget = DomainBudget::new(1000);
    budget.try_reserve(400).unwrap();
    assert_eq!(budget.used_bytes, 400);
    assert_eq!(budget.remaining(), 600);
}

#[test]
fn budget_reserve_exact_capacity() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(100).unwrap();
    assert_eq!(budget.remaining(), 0);
}

#[test]
fn budget_reserve_exceeds_capacity() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(60).unwrap();
    let err = budget.try_reserve(50).unwrap_err();
    assert!(matches!(
        err,
        AllocDomainError::BudgetExceeded {
            requested: 50,
            remaining: 40,
            ..
        }
    ));
    // Used bytes unchanged on failure.
    assert_eq!(budget.used_bytes, 60);
}

#[test]
fn budget_overflow_detection() {
    let mut budget = DomainBudget::new(u64::MAX);
    budget.try_reserve(u64::MAX).unwrap();
    let err = budget.try_reserve(1).unwrap_err();
    assert!(matches!(err, AllocDomainError::BudgetOverflow));
}

#[test]
fn budget_release_frees_space() {
    let mut budget = DomainBudget::new(200);
    budget.try_reserve(150).unwrap();
    budget.release(50);
    assert_eq!(budget.used_bytes, 100);
    assert_eq!(budget.remaining(), 100);
}

#[test]
fn budget_release_saturates_at_zero() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(10).unwrap();
    budget.release(1000);
    assert_eq!(budget.used_bytes, 0);
}

#[test]
fn budget_utilization_zero() {
    let budget = DomainBudget::new(100);
    assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn budget_utilization_half() {
    let mut budget = DomainBudget::new(200);
    budget.try_reserve(100).unwrap();
    assert!((budget.utilization() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn budget_utilization_full() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(100).unwrap();
    assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn budget_utilization_zero_capacity() {
    let budget = DomainBudget::new(0);
    assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// DomainRegistry — registration
// ---------------------------------------------------------------------------

#[test]
fn registry_new_is_empty() {
    let reg = DomainRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    assert_eq!(reg.allocation_sequence(), 0);
}

#[test]
fn registry_default_is_empty() {
    let reg = DomainRegistry::default();
    assert!(reg.is_empty());
}

#[test]
fn registry_register_and_get() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        1024,
    )
    .unwrap();
    let config = reg.get(&AllocationDomain::ExtensionHeap).unwrap();
    assert_eq!(config.domain, AllocationDomain::ExtensionHeap);
    assert_eq!(config.lifetime, LifetimeClass::SessionScoped);
    assert_eq!(config.budget.max_bytes, 1024);
}

#[test]
fn registry_duplicate_registration_rejected() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1024)
        .unwrap();
    let err = reg
        .register(AllocationDomain::IrArena, LifetimeClass::Arena, 2048)
        .unwrap_err();
    assert!(matches!(
        err,
        AllocDomainError::DuplicateDomain {
            domain: AllocationDomain::IrArena
        }
    ));
}

#[test]
fn registry_get_nonexistent_returns_none() {
    let reg = DomainRegistry::new();
    assert!(reg.get(&AllocationDomain::ScratchBuffer).is_none());
}

// ---------------------------------------------------------------------------
// DomainRegistry — allocation
// ---------------------------------------------------------------------------

#[test]
fn registry_allocate_returns_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        1024,
    )
    .unwrap();
    let seq = reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
    assert_eq!(seq, 1);
}

#[test]
fn registry_allocate_unregistered_domain_fails() {
    let mut reg = DomainRegistry::new();
    let err = reg
        .allocate(AllocationDomain::ScratchBuffer, 10)
        .unwrap_err();
    assert!(matches!(
        err,
        AllocDomainError::DomainNotFound {
            domain: AllocationDomain::ScratchBuffer
        }
    ));
}

#[test]
fn registry_allocate_exceeds_budget_includes_domain() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 80).unwrap();
    let err = reg
        .allocate(AllocationDomain::ExtensionHeap, 30)
        .unwrap_err();
    assert!(matches!(
        err,
        AllocDomainError::BudgetExceeded {
            domain: Some(AllocationDomain::ExtensionHeap),
            ..
        }
    ));
}

#[test]
fn registry_allocation_sequence_increments() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        10000,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 10000)
        .unwrap();
    let s1 = reg.allocate(AllocationDomain::ExtensionHeap, 10).unwrap();
    let s2 = reg.allocate(AllocationDomain::IrArena, 20).unwrap();
    let s3 = reg.allocate(AllocationDomain::ExtensionHeap, 30).unwrap();
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(s3, 3);
    assert_eq!(reg.allocation_sequence(), 3);
}

// ---------------------------------------------------------------------------
// DomainRegistry — release and reset
// ---------------------------------------------------------------------------

#[test]
fn registry_release_frees_budget() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        100,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ScratchBuffer, 80).unwrap();
    reg.release(AllocationDomain::ScratchBuffer, 80).unwrap();
    let config = reg.get(&AllocationDomain::ScratchBuffer).unwrap();
    assert_eq!(config.budget.used_bytes, 0);
}

#[test]
fn registry_release_unregistered_fails() {
    let mut reg = DomainRegistry::new();
    let err = reg.release(AllocationDomain::IrArena, 10).unwrap_err();
    assert!(matches!(err, AllocDomainError::DomainNotFound { .. }));
}

#[test]
fn registry_reset_domain_clears_usage() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1024)
        .unwrap();
    reg.allocate(AllocationDomain::IrArena, 500).unwrap();
    reg.reset_domain(AllocationDomain::IrArena).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::IrArena)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
}

#[test]
fn registry_reset_unregistered_fails() {
    let mut reg = DomainRegistry::new();
    let err = reg
        .reset_domain(AllocationDomain::EvidenceArena)
        .unwrap_err();
    assert!(matches!(err, AllocDomainError::DomainNotFound { .. }));
}

// ---------------------------------------------------------------------------
// DomainRegistry — totals and iteration
// ---------------------------------------------------------------------------

#[test]
fn registry_total_used_and_capacity() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        500,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 300)
        .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
    reg.allocate(AllocationDomain::IrArena, 50).unwrap();
    assert_eq!(reg.total_used(), 150);
    assert_eq!(reg.total_capacity(), 800);
}

#[test]
fn registry_iter_deterministic_order() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        100,
    )
    .unwrap();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
        .unwrap();
    let domains: Vec<AllocationDomain> = reg.iter().map(|(d, _)| *d).collect();
    // BTreeMap sorts by enum discriminant.
    assert_eq!(
        domains,
        vec![
            AllocationDomain::ExtensionHeap,
            AllocationDomain::IrArena,
            AllocationDomain::ScratchBuffer,
        ]
    );
}

#[test]
fn registry_domain_isolation() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
        .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
    // IR arena still fully available.
    reg.allocate(AllocationDomain::IrArena, 100).unwrap();
    assert_eq!(reg.total_used(), 200);
}

// ---------------------------------------------------------------------------
// with_standard_domains
// ---------------------------------------------------------------------------

#[test]
fn standard_domains_creates_five() {
    let reg = DomainRegistry::with_standard_domains(128 * 1024 * 1024);
    assert_eq!(reg.len(), 5);
    assert!(reg.get(&AllocationDomain::ExtensionHeap).is_some());
    assert!(reg.get(&AllocationDomain::RuntimeHeap).is_some());
    assert!(reg.get(&AllocationDomain::IrArena).is_some());
    assert!(reg.get(&AllocationDomain::EvidenceArena).is_some());
    assert!(reg.get(&AllocationDomain::ScratchBuffer).is_some());
}

#[test]
fn standard_domains_extension_heap_budget() {
    let reg = DomainRegistry::with_standard_domains(256);
    let config = reg.get(&AllocationDomain::ExtensionHeap).unwrap();
    assert_eq!(config.budget.max_bytes, 256);
    assert_eq!(config.lifetime, LifetimeClass::SessionScoped);
}

#[test]
fn standard_domains_ir_arena_budget() {
    let reg = DomainRegistry::with_standard_domains(1024);
    let config = reg.get(&AllocationDomain::IrArena).unwrap();
    assert_eq!(config.budget.max_bytes, 512 * 1024 * 1024);
    assert_eq!(config.lifetime, LifetimeClass::Arena);
}

// ---------------------------------------------------------------------------
// AllocDomainError display
// ---------------------------------------------------------------------------

#[test]
fn error_budget_exceeded_display_with_domain() {
    let err = AllocDomainError::BudgetExceeded {
        requested: 100,
        remaining: 50,
        domain: Some(AllocationDomain::ExtensionHeap),
    };
    let s = err.to_string();
    assert!(s.contains("extension-heap"));
    assert!(s.contains("100"));
    assert!(s.contains("50"));
}

#[test]
fn error_budget_exceeded_display_without_domain() {
    let err = AllocDomainError::BudgetExceeded {
        requested: 100,
        remaining: 50,
        domain: None,
    };
    let s = err.to_string();
    assert!(s.contains("100"));
    assert!(s.contains("50"));
}

#[test]
fn error_budget_overflow_display() {
    assert_eq!(
        AllocDomainError::BudgetOverflow.to_string(),
        "budget arithmetic overflow"
    );
}

#[test]
fn error_domain_not_found_display() {
    let err = AllocDomainError::DomainNotFound {
        domain: AllocationDomain::IrArena,
    };
    assert!(err.to_string().contains("ir-arena"));
}

#[test]
fn error_duplicate_domain_display() {
    let err = AllocDomainError::DuplicateDomain {
        domain: AllocationDomain::ScratchBuffer,
    };
    assert!(err.to_string().contains("scratch-buffer"));
}

#[test]
fn error_is_std_error() {
    let err = AllocDomainError::BudgetOverflow;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn allocation_domain_serde_roundtrip() {
    let domains = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for d in &domains {
        let json = serde_json::to_string(d).unwrap();
        let restored: AllocationDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, restored);
    }
}

#[test]
fn lifetime_class_serde_roundtrip() {
    let classes = [
        LifetimeClass::RequestScoped,
        LifetimeClass::SessionScoped,
        LifetimeClass::Global,
        LifetimeClass::Arena,
    ];
    for c in &classes {
        let json = serde_json::to_string(c).unwrap();
        let restored: LifetimeClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

#[test]
fn domain_budget_serde_roundtrip() {
    let mut budget = DomainBudget::new(1024);
    budget.try_reserve(256).unwrap();
    let json = serde_json::to_string(&budget).unwrap();
    let restored: DomainBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, restored);
}

#[test]
fn domain_config_serde_roundtrip() {
    let config = DomainConfig {
        domain: AllocationDomain::ExtensionHeap,
        lifetime: LifetimeClass::SessionScoped,
        budget: DomainBudget::new(2048),
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: DomainConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn alloc_domain_error_serde_roundtrip() {
    let errors = [
        AllocDomainError::BudgetExceeded {
            requested: 100,
            remaining: 50,
            domain: Some(AllocationDomain::IrArena),
        },
        AllocDomainError::BudgetExceeded {
            requested: 100,
            remaining: 50,
            domain: None,
        },
        AllocDomainError::BudgetOverflow,
        AllocDomainError::DomainNotFound {
            domain: AllocationDomain::ScratchBuffer,
        },
        AllocDomainError::DuplicateDomain {
            domain: AllocationDomain::ExtensionHeap,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: AllocDomainError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn domain_registry_serde_roundtrip() {
    let mut reg = DomainRegistry::with_standard_domains(1024);
    reg.allocate(AllocationDomain::ExtensionHeap, 256).unwrap();
    let json = serde_json::to_string(&reg).unwrap();
    let restored: DomainRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg.len(), restored.len());
    assert_eq!(reg.allocation_sequence(), restored.allocation_sequence());
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        restored
            .get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
    );
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_allocation_sequence() {
    let run = || -> (u64, u64) {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            10000,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 10000)
            .unwrap();
        let a = reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
        let b = reg.allocate(AllocationDomain::IrArena, 200).unwrap();
        (a, b)
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_allocate_release_reallocate() {
    let mut reg = DomainRegistry::with_standard_domains(1024);
    reg.allocate(AllocationDomain::ExtensionHeap, 512).unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 512).unwrap();
    // Full.
    assert!(reg.allocate(AllocationDomain::ExtensionHeap, 1).is_err());
    // Release and reallocate.
    reg.release(AllocationDomain::ExtensionHeap, 256).unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 256).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        1024
    );
}
