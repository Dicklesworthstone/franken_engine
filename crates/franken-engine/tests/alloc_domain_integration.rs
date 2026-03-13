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

// ===========================================================================
// Enrichment tests — appended 2026-03-12
// ===========================================================================

// ---------------------------------------------------------------------------
// AllocationDomain — Clone, Debug, PartialEq, Copy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_allocation_domain_clone_eq() {
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for d in &all {
        let cloned = d.clone();
        assert_eq!(*d, cloned);
    }
}

#[test]
fn enrichment_allocation_domain_debug_contains_variant_name() {
    assert!(format!("{:?}", AllocationDomain::ExtensionHeap).contains("ExtensionHeap"));
    assert!(format!("{:?}", AllocationDomain::RuntimeHeap).contains("RuntimeHeap"));
    assert!(format!("{:?}", AllocationDomain::IrArena).contains("IrArena"));
    assert!(format!("{:?}", AllocationDomain::EvidenceArena).contains("EvidenceArena"));
    assert!(format!("{:?}", AllocationDomain::ScratchBuffer).contains("ScratchBuffer"));
}

#[test]
fn enrichment_allocation_domain_ne_across_variants() {
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn enrichment_allocation_domain_copy_semantics() {
    let a = AllocationDomain::IrArena;
    let b = a; // Copy
    assert_eq!(a, b); // original still usable
}

#[test]
fn enrichment_allocation_domain_ord_is_total() {
    // Verify ordering is total and anti-symmetric.
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for a in &all {
        for b in &all {
            // Exactly one of <, ==, > must hold.
            let lt = a < b;
            let eq = a == b;
            let gt = a > b;
            assert_eq!(lt as u8 + eq as u8 + gt as u8, 1);
        }
    }
}

#[test]
fn enrichment_allocation_domain_display_no_uppercase() {
    // Display strings are kebab-case, never PascalCase.
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for d in &all {
        let s = d.to_string();
        assert_eq!(s, s.to_lowercase(), "Display must be lowercase kebab-case");
    }
}

// ---------------------------------------------------------------------------
// AllocationDomain — serde canonical JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_allocation_domain_serde_json_string_form() {
    // Each variant serializes as a JSON string (not an integer).
    let all = [
        (AllocationDomain::ExtensionHeap, "\"ExtensionHeap\""),
        (AllocationDomain::RuntimeHeap, "\"RuntimeHeap\""),
        (AllocationDomain::IrArena, "\"IrArena\""),
        (AllocationDomain::EvidenceArena, "\"EvidenceArena\""),
        (AllocationDomain::ScratchBuffer, "\"ScratchBuffer\""),
    ];
    for (variant, expected) in &all {
        let json = serde_json::to_string(variant).unwrap();
        assert_eq!(&json, *expected);
    }
}

#[test]
fn enrichment_allocation_domain_deserialize_rejects_unknown() {
    let result = serde_json::from_str::<AllocationDomain>("\"Nonexistent\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_allocation_domain_deserialize_rejects_integer() {
    let result = serde_json::from_str::<AllocationDomain>("0");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// LifetimeClass — Clone, Debug, PartialEq, Copy, Ord
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifetime_class_clone_eq() {
    let all = [
        LifetimeClass::RequestScoped,
        LifetimeClass::SessionScoped,
        LifetimeClass::Global,
        LifetimeClass::Arena,
    ];
    for c in &all {
        assert_eq!(*c, c.clone());
    }
}

#[test]
fn enrichment_lifetime_class_debug_contains_variant_name() {
    assert!(format!("{:?}", LifetimeClass::RequestScoped).contains("RequestScoped"));
    assert!(format!("{:?}", LifetimeClass::SessionScoped).contains("SessionScoped"));
    assert!(format!("{:?}", LifetimeClass::Global).contains("Global"));
    assert!(format!("{:?}", LifetimeClass::Arena).contains("Arena"));
}

#[test]
fn enrichment_lifetime_class_ne_across_variants() {
    let all = [
        LifetimeClass::RequestScoped,
        LifetimeClass::SessionScoped,
        LifetimeClass::Global,
        LifetimeClass::Arena,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn enrichment_lifetime_class_ordering() {
    assert!(LifetimeClass::RequestScoped < LifetimeClass::SessionScoped);
    assert!(LifetimeClass::SessionScoped < LifetimeClass::Global);
    assert!(LifetimeClass::Global < LifetimeClass::Arena);
}

#[test]
fn enrichment_lifetime_class_copy_semantics() {
    let a = LifetimeClass::Global;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_lifetime_class_serde_json_string_form() {
    let all = [
        (LifetimeClass::RequestScoped, "\"RequestScoped\""),
        (LifetimeClass::SessionScoped, "\"SessionScoped\""),
        (LifetimeClass::Global, "\"Global\""),
        (LifetimeClass::Arena, "\"Arena\""),
    ];
    for (variant, expected) in &all {
        let json = serde_json::to_string(variant).unwrap();
        assert_eq!(&json, *expected);
    }
}

#[test]
fn enrichment_lifetime_class_deserialize_rejects_unknown() {
    let result = serde_json::from_str::<LifetimeClass>("\"Ephemeral\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_lifetime_class_display_no_uppercase() {
    let all = [
        LifetimeClass::RequestScoped,
        LifetimeClass::SessionScoped,
        LifetimeClass::Global,
        LifetimeClass::Arena,
    ];
    for c in &all {
        let s = c.to_string();
        assert_eq!(s, s.to_lowercase());
    }
}

// ---------------------------------------------------------------------------
// DomainBudget — edge cases and properties
// ---------------------------------------------------------------------------

#[test]
fn enrichment_budget_new_zero_capacity() {
    let budget = DomainBudget::new(0);
    assert_eq!(budget.max_bytes, 0);
    assert_eq!(budget.used_bytes, 0);
    assert_eq!(budget.remaining(), 0);
}

#[test]
fn enrichment_budget_reserve_zero_bytes_succeeds() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(0).unwrap();
    assert_eq!(budget.used_bytes, 0);
    assert_eq!(budget.remaining(), 100);
}

#[test]
fn enrichment_budget_reserve_zero_bytes_on_zero_capacity_succeeds() {
    let mut budget = DomainBudget::new(0);
    budget.try_reserve(0).unwrap();
    assert_eq!(budget.used_bytes, 0);
}

#[test]
fn enrichment_budget_reserve_one_on_zero_capacity_fails() {
    let mut budget = DomainBudget::new(0);
    let err = budget.try_reserve(1).unwrap_err();
    assert!(matches!(
        err,
        AllocDomainError::BudgetExceeded {
            requested: 1,
            remaining: 0,
            ..
        }
    ));
}

#[test]
fn enrichment_budget_reserve_u64_max_on_fresh_budget() {
    let mut budget = DomainBudget::new(u64::MAX);
    budget.try_reserve(u64::MAX).unwrap();
    assert_eq!(budget.used_bytes, u64::MAX);
    assert_eq!(budget.remaining(), 0);
}

#[test]
fn enrichment_budget_multiple_small_reserves() {
    let mut budget = DomainBudget::new(100);
    for _ in 0..100 {
        budget.try_reserve(1).unwrap();
    }
    assert_eq!(budget.used_bytes, 100);
    assert_eq!(budget.remaining(), 0);
    assert!(budget.try_reserve(1).is_err());
}

#[test]
fn enrichment_budget_release_zero_bytes_is_noop() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(50).unwrap();
    budget.release(0);
    assert_eq!(budget.used_bytes, 50);
}

#[test]
fn enrichment_budget_release_u64_max_saturates() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(50).unwrap();
    budget.release(u64::MAX);
    assert_eq!(budget.used_bytes, 0);
}

#[test]
fn enrichment_budget_remaining_invariant() {
    // remaining() == max_bytes - used_bytes (clamped to 0)
    let mut budget = DomainBudget::new(500);
    for step in [0u64, 100, 200, 150, 50] {
        budget.try_reserve(step).unwrap();
        assert_eq!(
            budget.remaining(),
            budget.max_bytes.saturating_sub(budget.used_bytes)
        );
    }
}

#[test]
fn enrichment_budget_utilization_quarter() {
    let mut budget = DomainBudget::new(400);
    budget.try_reserve(100).unwrap();
    assert!((budget.utilization() - 0.25).abs() < f64::EPSILON);
}

#[test]
fn enrichment_budget_utilization_three_quarters() {
    let mut budget = DomainBudget::new(400);
    budget.try_reserve(300).unwrap();
    assert!((budget.utilization() - 0.75).abs() < f64::EPSILON);
}

#[test]
fn enrichment_budget_utilization_after_release() {
    let mut budget = DomainBudget::new(200);
    budget.try_reserve(200).unwrap();
    assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
    budget.release(100);
    assert!((budget.utilization() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn enrichment_budget_clone_independence() {
    let mut budget = DomainBudget::new(1000);
    budget.try_reserve(400).unwrap();
    let mut cloned = budget.clone();
    cloned.try_reserve(200).unwrap();
    assert_eq!(budget.used_bytes, 400);
    assert_eq!(cloned.used_bytes, 600);
}

#[test]
fn enrichment_budget_debug_contains_fields() {
    let budget = DomainBudget::new(1024);
    let dbg = format!("{:?}", budget);
    assert!(dbg.contains("max_bytes"));
    assert!(dbg.contains("used_bytes"));
    assert!(dbg.contains("1024"));
    assert!(dbg.contains("0"));
}

#[test]
fn enrichment_budget_serde_json_field_names() {
    let budget = DomainBudget::new(512);
    let json = serde_json::to_string(&budget).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("max_bytes"));
    assert!(obj.contains_key("used_bytes"));
    assert_eq!(obj.len(), 2);
}

#[test]
fn enrichment_budget_serde_preserves_used_bytes() {
    let mut budget = DomainBudget::new(1000);
    budget.try_reserve(777).unwrap();
    let json = serde_json::to_string(&budget).unwrap();
    let restored: DomainBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.used_bytes, 777);
    assert_eq!(restored.max_bytes, 1000);
    assert_eq!(restored.remaining(), 223);
}

#[test]
fn enrichment_budget_failed_reserve_does_not_mutate() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(50).unwrap();
    let snapshot_used = budget.used_bytes;
    let _ = budget.try_reserve(60); // fails
    assert_eq!(budget.used_bytes, snapshot_used);
}

#[test]
fn enrichment_budget_overflow_near_u64_max() {
    let mut budget = DomainBudget::new(u64::MAX);
    budget.try_reserve(u64::MAX - 1).unwrap();
    // Reserve 2 more: (MAX-1)+2 overflows u64
    let err = budget.try_reserve(2).unwrap_err();
    assert!(matches!(err, AllocDomainError::BudgetOverflow));
}

// ---------------------------------------------------------------------------
// DomainConfig — struct construction, serde, Debug, Clone
// ---------------------------------------------------------------------------

#[test]
fn enrichment_domain_config_debug_contains_all_fields() {
    let config = DomainConfig {
        domain: AllocationDomain::RuntimeHeap,
        lifetime: LifetimeClass::Global,
        budget: DomainBudget::new(4096),
    };
    let dbg = format!("{:?}", config);
    assert!(dbg.contains("RuntimeHeap"));
    assert!(dbg.contains("Global"));
    assert!(dbg.contains("4096"));
}

#[test]
fn enrichment_domain_config_clone_independence() {
    let config = DomainConfig {
        domain: AllocationDomain::ScratchBuffer,
        lifetime: LifetimeClass::RequestScoped,
        budget: DomainBudget::new(256),
    };
    let mut cloned = config.clone();
    cloned.budget.try_reserve(128).unwrap();
    assert_eq!(config.budget.used_bytes, 0);
    assert_eq!(cloned.budget.used_bytes, 128);
}

#[test]
fn enrichment_domain_config_serde_json_field_names() {
    let config = DomainConfig {
        domain: AllocationDomain::EvidenceArena,
        lifetime: LifetimeClass::SessionScoped,
        budget: DomainBudget::new(2048),
    };
    let json = serde_json::to_string(&config).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("domain"));
    assert!(obj.contains_key("lifetime"));
    assert!(obj.contains_key("budget"));
    assert_eq!(obj.len(), 3);
}

#[test]
fn enrichment_domain_config_eq_different_budgets() {
    let a = DomainConfig {
        domain: AllocationDomain::IrArena,
        lifetime: LifetimeClass::Arena,
        budget: DomainBudget::new(1024),
    };
    let b = DomainConfig {
        domain: AllocationDomain::IrArena,
        lifetime: LifetimeClass::Arena,
        budget: DomainBudget::new(2048),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_domain_config_eq_different_lifetimes() {
    let a = DomainConfig {
        domain: AllocationDomain::ExtensionHeap,
        lifetime: LifetimeClass::SessionScoped,
        budget: DomainBudget::new(1024),
    };
    let b = DomainConfig {
        domain: AllocationDomain::ExtensionHeap,
        lifetime: LifetimeClass::Global,
        budget: DomainBudget::new(1024),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_domain_config_serde_roundtrip_all_variants() {
    let all_domains = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    let all_lifetimes = [
        LifetimeClass::RequestScoped,
        LifetimeClass::SessionScoped,
        LifetimeClass::Global,
        LifetimeClass::Arena,
    ];
    for domain in &all_domains {
        for lifetime in &all_lifetimes {
            let config = DomainConfig {
                domain: *domain,
                lifetime: *lifetime,
                budget: DomainBudget::new(42),
            };
            let json = serde_json::to_string(&config).unwrap();
            let restored: DomainConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(config, restored);
        }
    }
}

// ---------------------------------------------------------------------------
// AllocDomainError — exhaustive Display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_budget_exceeded_display_format_with_domain() {
    let err = AllocDomainError::BudgetExceeded {
        requested: 999,
        remaining: 1,
        domain: Some(AllocationDomain::RuntimeHeap),
    };
    let s = err.to_string();
    assert_eq!(
        s,
        "budget exceeded in runtime-heap: requested 999 bytes, 1 remaining"
    );
}

#[test]
fn enrichment_error_budget_exceeded_display_format_without_domain() {
    let err = AllocDomainError::BudgetExceeded {
        requested: 42,
        remaining: 10,
        domain: None,
    };
    let s = err.to_string();
    assert_eq!(s, "budget exceeded: requested 42 bytes, 10 remaining");
}

#[test]
fn enrichment_error_domain_not_found_display_exact() {
    let err = AllocDomainError::DomainNotFound {
        domain: AllocationDomain::EvidenceArena,
    };
    assert_eq!(err.to_string(), "domain 'evidence-arena' not registered");
}

#[test]
fn enrichment_error_duplicate_domain_display_exact() {
    let err = AllocDomainError::DuplicateDomain {
        domain: AllocationDomain::RuntimeHeap,
    };
    assert_eq!(err.to_string(), "domain 'runtime-heap' already registered");
}

#[test]
fn enrichment_error_clone_eq() {
    let err = AllocDomainError::BudgetExceeded {
        requested: 50,
        remaining: 25,
        domain: Some(AllocationDomain::IrArena),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn enrichment_error_ne_across_variants() {
    let a = AllocDomainError::BudgetOverflow;
    let b = AllocDomainError::DomainNotFound {
        domain: AllocationDomain::IrArena,
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_error_debug_contains_variant() {
    let err = AllocDomainError::BudgetOverflow;
    assert!(format!("{:?}", err).contains("BudgetOverflow"));

    let err2 = AllocDomainError::DomainNotFound {
        domain: AllocationDomain::ScratchBuffer,
    };
    let dbg2 = format!("{:?}", err2);
    assert!(dbg2.contains("DomainNotFound"));
    assert!(dbg2.contains("ScratchBuffer"));
}

#[test]
fn enrichment_error_serde_budget_exceeded_all_domains() {
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for domain in &all {
        let err = AllocDomainError::BudgetExceeded {
            requested: 100,
            remaining: 0,
            domain: Some(*domain),
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: AllocDomainError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }
}

#[test]
fn enrichment_error_serde_domain_not_found_all_domains() {
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for domain in &all {
        let err = AllocDomainError::DomainNotFound { domain: *domain };
        let json = serde_json::to_string(&err).unwrap();
        let restored: AllocDomainError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }
}

#[test]
fn enrichment_error_serde_duplicate_domain_all_domains() {
    let all = [
        AllocationDomain::ExtensionHeap,
        AllocationDomain::RuntimeHeap,
        AllocationDomain::IrArena,
        AllocationDomain::EvidenceArena,
        AllocationDomain::ScratchBuffer,
    ];
    for domain in &all {
        let err = AllocDomainError::DuplicateDomain { domain: *domain };
        let json = serde_json::to_string(&err).unwrap();
        let restored: AllocDomainError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }
}

#[test]
fn enrichment_error_is_std_error_all_variants() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(AllocDomainError::BudgetExceeded {
            requested: 1,
            remaining: 0,
            domain: None,
        }),
        Box::new(AllocDomainError::BudgetOverflow),
        Box::new(AllocDomainError::DomainNotFound {
            domain: AllocationDomain::IrArena,
        }),
        Box::new(AllocDomainError::DuplicateDomain {
            domain: AllocationDomain::ExtensionHeap,
        }),
    ];
    for e in &errors {
        // Verify Display is accessible through dyn Error
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// DomainRegistry — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_registry_allocate_zero_bytes_succeeds() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
        .unwrap();
    let seq = reg.allocate(AllocationDomain::IrArena, 0).unwrap();
    assert_eq!(seq, 1);
    assert_eq!(
        reg.get(&AllocationDomain::IrArena)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
}

#[test]
fn enrichment_registry_allocate_zero_bytes_still_increments_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    let s1 = reg.allocate(AllocationDomain::ExtensionHeap, 0).unwrap();
    let s2 = reg.allocate(AllocationDomain::ExtensionHeap, 0).unwrap();
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
}

#[test]
fn enrichment_registry_register_all_five_domains() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 200)
        .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 300)
        .unwrap();
    reg.register(
        AllocationDomain::EvidenceArena,
        LifetimeClass::SessionScoped,
        400,
    )
    .unwrap();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        500,
    )
    .unwrap();
    assert_eq!(reg.len(), 5);
    assert!(!reg.is_empty());
}

#[test]
fn enrichment_registry_total_used_empty() {
    let reg = DomainRegistry::new();
    assert_eq!(reg.total_used(), 0);
}

#[test]
fn enrichment_registry_total_capacity_empty() {
    let reg = DomainRegistry::new();
    assert_eq!(reg.total_capacity(), 0);
}

#[test]
fn enrichment_registry_iter_empty() {
    let reg = DomainRegistry::new();
    assert_eq!(reg.iter().count(), 0);
}

#[test]
fn enrichment_registry_release_more_than_allocated() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        200,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ScratchBuffer, 50).unwrap();
    // Release more than what was allocated - saturates at zero.
    reg.release(AllocationDomain::ScratchBuffer, 100).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::ScratchBuffer)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
}

#[test]
fn enrichment_registry_reset_allows_full_reallocation() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
        .unwrap();
    reg.allocate(AllocationDomain::IrArena, 100).unwrap();
    assert!(reg.allocate(AllocationDomain::IrArena, 1).is_err());
    reg.reset_domain(AllocationDomain::IrArena).unwrap();
    reg.allocate(AllocationDomain::IrArena, 100).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::IrArena)
            .unwrap()
            .budget
            .used_bytes,
        100
    );
}

#[test]
fn enrichment_registry_reset_does_not_change_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1000)
        .unwrap();
    reg.allocate(AllocationDomain::IrArena, 100).unwrap();
    let seq_before = reg.allocation_sequence();
    reg.reset_domain(AllocationDomain::IrArena).unwrap();
    assert_eq!(reg.allocation_sequence(), seq_before);
}

#[test]
fn enrichment_registry_release_does_not_change_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        1000,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 500).unwrap();
    let seq_before = reg.allocation_sequence();
    reg.release(AllocationDomain::ExtensionHeap, 200).unwrap();
    assert_eq!(reg.allocation_sequence(), seq_before);
}

#[test]
fn enrichment_registry_failed_allocate_does_not_change_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 80).unwrap();
    let seq_before = reg.allocation_sequence();
    let _ = reg.allocate(AllocationDomain::ExtensionHeap, 30); // fails
    assert_eq!(reg.allocation_sequence(), seq_before);
}

// ---------------------------------------------------------------------------
// with_standard_domains — detailed verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_standard_domains_runtime_heap_budget() {
    let reg = DomainRegistry::with_standard_domains(1024);
    let config = reg.get(&AllocationDomain::RuntimeHeap).unwrap();
    assert_eq!(config.budget.max_bytes, u64::MAX);
    assert_eq!(config.lifetime, LifetimeClass::Global);
}

#[test]
fn enrichment_standard_domains_evidence_arena_budget() {
    let reg = DomainRegistry::with_standard_domains(1024);
    let config = reg.get(&AllocationDomain::EvidenceArena).unwrap();
    assert_eq!(config.budget.max_bytes, 128 * 1024 * 1024);
    assert_eq!(config.lifetime, LifetimeClass::SessionScoped);
}

#[test]
fn enrichment_standard_domains_scratch_buffer_budget() {
    let reg = DomainRegistry::with_standard_domains(1024);
    let config = reg.get(&AllocationDomain::ScratchBuffer).unwrap();
    assert_eq!(config.budget.max_bytes, 64 * 1024 * 1024);
    assert_eq!(config.lifetime, LifetimeClass::RequestScoped);
}

#[test]
fn enrichment_standard_domains_all_start_at_zero_used() {
    let reg = DomainRegistry::with_standard_domains(1024);
    for (_domain, config) in reg.iter() {
        assert_eq!(config.budget.used_bytes, 0);
    }
}

#[test]
fn enrichment_standard_domains_allocation_sequence_starts_at_zero() {
    let reg = DomainRegistry::with_standard_domains(1024);
    assert_eq!(reg.allocation_sequence(), 0);
}

#[test]
fn enrichment_standard_domains_iter_deterministic_order() {
    let reg = DomainRegistry::with_standard_domains(1024);
    let domains: Vec<AllocationDomain> = reg.iter().map(|(d, _)| *d).collect();
    assert_eq!(
        domains,
        vec![
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ]
    );
}

#[test]
fn enrichment_standard_domains_with_zero_extension_heap() {
    let reg = DomainRegistry::with_standard_domains(0);
    let config = reg.get(&AllocationDomain::ExtensionHeap).unwrap();
    assert_eq!(config.budget.max_bytes, 0);
}

// ---------------------------------------------------------------------------
// DomainRegistry — clone, Debug, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_registry_clone_independence() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        1000,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 200).unwrap();
    let mut cloned = reg.clone();
    cloned
        .allocate(AllocationDomain::ExtensionHeap, 300)
        .unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        200
    );
    assert_eq!(
        cloned
            .get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        500
    );
}

#[test]
fn enrichment_registry_clone_preserves_sequence() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 10000)
        .unwrap();
    reg.allocate(AllocationDomain::IrArena, 100).unwrap();
    reg.allocate(AllocationDomain::IrArena, 200).unwrap();
    let cloned = reg.clone();
    assert_eq!(cloned.allocation_sequence(), 2);
}

#[test]
fn enrichment_registry_debug_contains_domains() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 512)
        .unwrap();
    let dbg = format!("{:?}", reg);
    assert!(dbg.contains("IrArena"));
    assert!(dbg.contains("512"));
}

#[test]
fn enrichment_registry_serde_json_field_names() {
    let reg = DomainRegistry::new();
    let json = serde_json::to_string(&reg).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("domains"));
    assert!(obj.contains_key("allocation_sequence"));
}

#[test]
fn enrichment_registry_serde_empty_roundtrip() {
    let reg = DomainRegistry::new();
    let json = serde_json::to_string(&reg).unwrap();
    let restored: DomainRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.len(), 0);
    assert_eq!(restored.allocation_sequence(), 0);
}

#[test]
fn enrichment_registry_serde_preserves_all_domains() {
    let mut reg = DomainRegistry::with_standard_domains(2048);
    reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
    reg.allocate(AllocationDomain::IrArena, 200).unwrap();
    reg.allocate(AllocationDomain::ScratchBuffer, 50).unwrap();
    let json = serde_json::to_string(&reg).unwrap();
    let restored: DomainRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.len(), 5);
    assert_eq!(restored.allocation_sequence(), 3);
    assert_eq!(
        restored
            .get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        100
    );
    assert_eq!(
        restored
            .get(&AllocationDomain::IrArena)
            .unwrap()
            .budget
            .used_bytes,
        200
    );
    assert_eq!(
        restored
            .get(&AllocationDomain::ScratchBuffer)
            .unwrap()
            .budget
            .used_bytes,
        50
    );
    assert_eq!(
        restored
            .get(&AllocationDomain::RuntimeHeap)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
    assert_eq!(
        restored
            .get(&AllocationDomain::EvidenceArena)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
}

// ---------------------------------------------------------------------------
// Determinism — same inputs same outputs across runs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_budget_operations() {
    let run = || {
        let mut budget = DomainBudget::new(500);
        budget.try_reserve(100).unwrap();
        budget.try_reserve(200).unwrap();
        budget.release(50);
        budget.try_reserve(100).unwrap();
        (budget.used_bytes, budget.remaining(), budget.utilization())
    };
    let (u1, r1, util1) = run();
    let (u2, r2, util2) = run();
    assert_eq!(u1, u2);
    assert_eq!(r1, r2);
    assert!((util1 - util2).abs() < f64::EPSILON);
}

#[test]
fn enrichment_determinism_registry_full_lifecycle() {
    let run = || {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            5000,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 5000)
            .unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 300).unwrap();
        reg.allocate(AllocationDomain::IrArena, 100).unwrap();
        reg.release(AllocationDomain::ExtensionHeap, 100).unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 50).unwrap();
        reg.reset_domain(AllocationDomain::IrArena).unwrap();
        (
            reg.allocation_sequence(),
            reg.total_used(),
            reg.total_capacity(),
            reg.get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes,
            reg.get(&AllocationDomain::IrArena)
                .unwrap()
                .budget
                .used_bytes,
        )
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_determinism_allocation_sequence_across_domains() {
    let run = || {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            10000,
        )
        .unwrap();
        reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 10000)
            .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 10000)
            .unwrap();
        let s1 = reg.allocate(AllocationDomain::IrArena, 10).unwrap();
        let s2 = reg.allocate(AllocationDomain::ExtensionHeap, 20).unwrap();
        let s3 = reg.allocate(AllocationDomain::RuntimeHeap, 30).unwrap();
        let s4 = reg.allocate(AllocationDomain::IrArena, 40).unwrap();
        (s1, s2, s3, s4)
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_determinism_serde_json_stable() {
    let make = || {
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
        serde_json::to_string(&reg).unwrap()
    };
    assert_eq!(make(), make());
}

// ---------------------------------------------------------------------------
// Cross-domain isolation and budget arithmetic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_registry_exhaustion_one_domain_does_not_affect_others() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 200)
        .unwrap();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        300,
    )
    .unwrap();
    // Exhaust extension heap.
    reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
    assert!(reg.allocate(AllocationDomain::ExtensionHeap, 1).is_err());
    // Others still work.
    reg.allocate(AllocationDomain::IrArena, 200).unwrap();
    reg.allocate(AllocationDomain::ScratchBuffer, 300).unwrap();
}

#[test]
fn enrichment_registry_total_used_tracks_releases() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        1000,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1000)
        .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 400).unwrap();
    reg.allocate(AllocationDomain::IrArena, 300).unwrap();
    assert_eq!(reg.total_used(), 700);
    reg.release(AllocationDomain::ExtensionHeap, 100).unwrap();
    assert_eq!(reg.total_used(), 600);
    reg.reset_domain(AllocationDomain::IrArena).unwrap();
    assert_eq!(reg.total_used(), 300);
}

#[test]
fn enrichment_registry_total_capacity_unchanged_by_allocations() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        500,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 300)
        .unwrap();
    let cap_before = reg.total_capacity();
    reg.allocate(AllocationDomain::ExtensionHeap, 200).unwrap();
    reg.allocate(AllocationDomain::IrArena, 100).unwrap();
    assert_eq!(reg.total_capacity(), cap_before);
}

// ---------------------------------------------------------------------------
// Multi-step lifecycle patterns
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_allocate_release_repeat() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        100,
    )
    .unwrap();
    for i in 0..10 {
        let seq = reg.allocate(AllocationDomain::ScratchBuffer, 100).unwrap();
        assert_eq!(seq, (i * 2 + 1) as u64);
        reg.release(AllocationDomain::ScratchBuffer, 100).unwrap();
        // Allocate zero bytes to verify sequence increments.
        let seq2 = reg.allocate(AllocationDomain::ScratchBuffer, 0).unwrap();
        assert_eq!(seq2, (i * 2 + 2) as u64);
    }
    assert_eq!(reg.allocation_sequence(), 20);
}

#[test]
fn enrichment_lifecycle_reset_then_reuse() {
    let mut reg = DomainRegistry::with_standard_domains(512);
    // Use up all extension heap.
    reg.allocate(AllocationDomain::ExtensionHeap, 512).unwrap();
    assert!(reg.allocate(AllocationDomain::ExtensionHeap, 1).is_err());
    // Reset simulates session teardown.
    reg.reset_domain(AllocationDomain::ExtensionHeap).unwrap();
    // Can allocate again.
    reg.allocate(AllocationDomain::ExtensionHeap, 256).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        256
    );
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .remaining(),
        256
    );
}

#[test]
fn enrichment_lifecycle_partial_releases() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::EvidenceArena,
        LifetimeClass::SessionScoped,
        1000,
    )
    .unwrap();
    reg.allocate(AllocationDomain::EvidenceArena, 500).unwrap();
    reg.release(AllocationDomain::EvidenceArena, 100).unwrap();
    reg.release(AllocationDomain::EvidenceArena, 100).unwrap();
    reg.release(AllocationDomain::EvidenceArena, 100).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::EvidenceArena)
            .unwrap()
            .budget
            .used_bytes,
        200
    );
    // Can allocate up to 800 more.
    reg.allocate(AllocationDomain::EvidenceArena, 800).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::EvidenceArena)
            .unwrap()
            .budget
            .used_bytes,
        1000
    );
}

// ---------------------------------------------------------------------------
// Error path: budget exceeded carries exact remaining value
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_budget_exceeded_remaining_is_exact() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.allocate(AllocationDomain::ExtensionHeap, 73).unwrap();
    let err = reg
        .allocate(AllocationDomain::ExtensionHeap, 28)
        .unwrap_err();
    match err {
        AllocDomainError::BudgetExceeded {
            requested,
            remaining,
            domain,
        } => {
            assert_eq!(requested, 28);
            assert_eq!(remaining, 27);
            assert_eq!(domain, Some(AllocationDomain::ExtensionHeap));
        }
        other => panic!("expected BudgetExceeded, got {:?}", other),
    }
}

#[test]
fn enrichment_error_budget_exceeded_at_exact_boundary() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
        .unwrap();
    reg.allocate(AllocationDomain::IrArena, 100).unwrap();
    let err = reg.allocate(AllocationDomain::IrArena, 1).unwrap_err();
    match err {
        AllocDomainError::BudgetExceeded {
            requested,
            remaining,
            domain,
        } => {
            assert_eq!(requested, 1);
            assert_eq!(remaining, 0);
            assert_eq!(domain, Some(AllocationDomain::IrArena));
        }
        other => panic!("expected BudgetExceeded, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Property: reserve-then-release returns to original state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_property_reserve_release_returns_to_original() {
    let amounts = [1u64, 100, 1024, 65536, 1_000_000];
    for amount in amounts {
        let mut budget = DomainBudget::new(amount * 2);
        let before = budget.used_bytes;
        budget.try_reserve(amount).unwrap();
        budget.release(amount);
        assert_eq!(budget.used_bytes, before);
    }
}

#[test]
fn enrichment_property_utilization_in_range() {
    // For any valid budget state, utilization is in [0.0, 1.0].
    let test_cases: Vec<(u64, u64)> = vec![
        (0, 0),
        (100, 0),
        (100, 50),
        (100, 100),
        (u64::MAX, 0),
        (u64::MAX, u64::MAX),
        (1, 1),
    ];
    for (max, used) in test_cases {
        let mut budget = DomainBudget::new(max);
        if used > 0 && max > 0 {
            budget.try_reserve(used).unwrap_or_default();
            // Force used_bytes for edge cases that might not fit.
            budget.used_bytes = used;
        }
        let u = budget.utilization();
        assert!(u >= 0.0, "utilization should be >= 0.0, got {}", u);
        assert!(
            u <= 1.0 || max == 0,
            "utilization should be <= 1.0 for max > 0, got {}",
            u
        );
    }
}

#[test]
fn enrichment_property_remaining_never_exceeds_max() {
    let mut budget = DomainBudget::new(500);
    budget.try_reserve(200).unwrap();
    budget.release(300); // saturates, used becomes 0
    assert!(budget.remaining() <= budget.max_bytes);
}

// ---------------------------------------------------------------------------
// Default trait
// ---------------------------------------------------------------------------

#[test]
fn enrichment_registry_default_equals_new() {
    let a = DomainRegistry::new();
    let b = DomainRegistry::default();
    assert_eq!(a.len(), b.len());
    assert_eq!(a.allocation_sequence(), b.allocation_sequence());
    assert_eq!(a.total_used(), b.total_used());
    assert_eq!(a.total_capacity(), b.total_capacity());
}

// ---------------------------------------------------------------------------
// Boundary: large allocations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_registry_large_budget_standard_domains() {
    let reg = DomainRegistry::with_standard_domains(u64::MAX);
    let config = reg.get(&AllocationDomain::ExtensionHeap).unwrap();
    assert_eq!(config.budget.max_bytes, u64::MAX);
}

#[test]
fn enrichment_budget_reserve_one_below_max() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(99).unwrap();
    assert_eq!(budget.remaining(), 1);
    budget.try_reserve(1).unwrap();
    assert_eq!(budget.remaining(), 0);
}

#[test]
fn enrichment_budget_reserve_one_above_remaining_fails() {
    let mut budget = DomainBudget::new(100);
    budget.try_reserve(99).unwrap();
    let err = budget.try_reserve(2).unwrap_err();
    assert!(matches!(
        err,
        AllocDomainError::BudgetExceeded {
            requested: 2,
            remaining: 1,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Sequence monotonicity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sequence_strictly_monotonic() {
    let mut reg = DomainRegistry::with_standard_domains(100_000);
    let mut prev = 0u64;
    for _ in 0..20 {
        let seq = reg.allocate(AllocationDomain::ExtensionHeap, 1).unwrap();
        assert!(
            seq > prev,
            "sequence must be strictly increasing: {} <= {}",
            seq,
            prev
        );
        prev = seq;
    }
}

// ---------------------------------------------------------------------------
// Iter yields correct configs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_iter_yields_matching_domain_and_config() {
    let mut reg = DomainRegistry::new();
    reg.register(AllocationDomain::RuntimeHeap, LifetimeClass::Global, 999)
        .unwrap();
    reg.register(
        AllocationDomain::ScratchBuffer,
        LifetimeClass::RequestScoped,
        111,
    )
    .unwrap();
    for (domain, config) in reg.iter() {
        assert_eq!(*domain, config.domain, "iter key must match config.domain");
    }
}

#[test]
fn enrichment_iter_count_matches_len() {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        100,
    )
    .unwrap();
    reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 200)
        .unwrap();
    reg.register(
        AllocationDomain::EvidenceArena,
        LifetimeClass::SessionScoped,
        300,
    )
    .unwrap();
    assert_eq!(reg.iter().count(), reg.len());
}
