//! Allocation domain taxonomy and lifetime class hierarchy.
//!
//! Defines how memory is organized, tracked, and reclaimed across the
//! FrankenEngine runtime.  Each allocation belongs to exactly one domain
//! and lifetime class, enabling per-extension budget enforcement, domain
//! isolation (security), and deterministic allocation patterns (replay).
//!
//! Plan references: Section 10.3 item 1, 9A.8 (per-extension budgets),
//! 9B.1 (arena allocation for IR nodes), 9B.4 (allocator strategy).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AllocationDomain — where memory lives
// ---------------------------------------------------------------------------

/// Identifies a logical memory region with isolation guarantees.
///
/// Domain isolation ensures that one extension's allocations cannot corrupt
/// another's — a hard security requirement for untrusted code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AllocationDomain {
    /// Per-extension managed heap — isolated per extension/session.
    ExtensionHeap,
    /// Shared runtime heap — used by engine internals.
    RuntimeHeap,
    /// IR compilation arena — used during parse/lower/optimize passes.
    IrArena,
    /// Evidence and witness arena — stores decision/replay artifacts.
    EvidenceArena,
    /// Temporary scratch buffers — short-lived, reusable.
    ScratchBuffer,
}

impl fmt::Display for AllocationDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ExtensionHeap => "extension-heap",
            Self::RuntimeHeap => "runtime-heap",
            Self::IrArena => "ir-arena",
            Self::EvidenceArena => "evidence-arena",
            Self::ScratchBuffer => "scratch-buffer",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// LifetimeClass — how long memory lives
// ---------------------------------------------------------------------------

/// Describes the expected duration of an allocation, informing GC strategy
/// and resource accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LifetimeClass {
    /// Single hostcall or operation — freed when the call returns.
    RequestScoped,
    /// Extension session — freed when the extension/session terminates.
    SessionScoped,
    /// Runtime lifetime — freed only at engine shutdown.
    Global,
    /// Compilation unit — freed when the compilation arena is dropped.
    Arena,
}

impl fmt::Display for LifetimeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::RequestScoped => "request-scoped",
            Self::SessionScoped => "session-scoped",
            Self::Global => "global",
            Self::Arena => "arena",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// DomainBudget — size limits per domain
// ---------------------------------------------------------------------------

/// Configurable size limits for an allocation domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainBudget {
    /// Maximum bytes permitted in this domain.
    pub max_bytes: u64,
    /// Current bytes allocated.
    pub used_bytes: u64,
}

impl DomainBudget {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            used_bytes: 0,
        }
    }

    /// Remaining bytes available.
    pub fn remaining(&self) -> u64 {
        self.max_bytes.saturating_sub(self.used_bytes)
    }

    /// Try to reserve `bytes`.  Returns `Ok(())` if budget allows,
    /// `Err` if it would exceed the limit.
    pub fn try_reserve(&mut self, bytes: u64) -> Result<(), AllocDomainError> {
        let new_used = self
            .used_bytes
            .checked_add(bytes)
            .ok_or(AllocDomainError::BudgetOverflow)?;
        if new_used > self.max_bytes {
            return Err(AllocDomainError::BudgetExceeded {
                requested: bytes,
                remaining: self.remaining(),
                domain: None,
            });
        }
        self.used_bytes = new_used;
        Ok(())
    }

    /// Release `bytes` back to the budget.
    pub fn release(&mut self, bytes: u64) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }

    /// Utilization ratio (0.0–1.0).
    pub fn utilization(&self) -> f64 {
        if self.max_bytes == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / self.max_bytes as f64
    }
}

// ---------------------------------------------------------------------------
// DomainConfig — per-domain configuration
// ---------------------------------------------------------------------------

/// Configuration for a single allocation domain instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainConfig {
    pub domain: AllocationDomain,
    pub lifetime: LifetimeClass,
    pub budget: DomainBudget,
}

// ---------------------------------------------------------------------------
// AllocDomainError — typed error contract
// ---------------------------------------------------------------------------

/// Errors from allocation domain operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocDomainError {
    /// Allocation would exceed domain budget.
    BudgetExceeded {
        requested: u64,
        remaining: u64,
        domain: Option<AllocationDomain>,
    },
    /// Arithmetic overflow in budget tracking.
    BudgetOverflow,
    /// Domain not found in registry.
    DomainNotFound { domain: AllocationDomain },
    /// Duplicate domain registration.
    DuplicateDomain { domain: AllocationDomain },
}

impl fmt::Display for AllocDomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExceeded {
                requested,
                remaining,
                domain,
            } => {
                if let Some(d) = domain {
                    write!(
                        f,
                        "budget exceeded in {}: requested {} bytes, {} remaining",
                        d, requested, remaining
                    )
                } else {
                    write!(
                        f,
                        "budget exceeded: requested {} bytes, {} remaining",
                        requested, remaining
                    )
                }
            }
            Self::BudgetOverflow => write!(f, "budget arithmetic overflow"),
            Self::DomainNotFound { domain } => write!(f, "domain '{}' not registered", domain),
            Self::DuplicateDomain { domain } => {
                write!(f, "domain '{}' already registered", domain)
            }
        }
    }
}

impl std::error::Error for AllocDomainError {}

// ---------------------------------------------------------------------------
// DomainRegistry — tracks all allocation domains
// ---------------------------------------------------------------------------

/// Registry of allocation domains with budget tracking.
///
/// Uses `BTreeMap` for deterministic iteration order (replay requirement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegistry {
    domains: BTreeMap<AllocationDomain, DomainConfig>,
    /// Total allocation events tracked (for determinism auditing).
    allocation_sequence: u64,
}

impl DomainRegistry {
    pub fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
            allocation_sequence: 0,
        }
    }

    /// Register a new allocation domain with its lifetime class and budget.
    pub fn register(
        &mut self,
        domain: AllocationDomain,
        lifetime: LifetimeClass,
        max_bytes: u64,
    ) -> Result<(), AllocDomainError> {
        if self.domains.contains_key(&domain) {
            return Err(AllocDomainError::DuplicateDomain { domain });
        }
        self.domains.insert(
            domain,
            DomainConfig {
                domain,
                lifetime,
                budget: DomainBudget::new(max_bytes),
            },
        );
        Ok(())
    }

    /// Try to allocate `bytes` from the specified domain.
    pub fn allocate(
        &mut self,
        domain: AllocationDomain,
        bytes: u64,
    ) -> Result<u64, AllocDomainError> {
        let config = self
            .domains
            .get_mut(&domain)
            .ok_or(AllocDomainError::DomainNotFound { domain })?;
        config.budget.try_reserve(bytes).map_err(|e| match e {
            AllocDomainError::BudgetExceeded {
                requested,
                remaining,
                ..
            } => AllocDomainError::BudgetExceeded {
                requested,
                remaining,
                domain: Some(domain),
            },
            other => other,
        })?;
        self.allocation_sequence = self.allocation_sequence.saturating_add(1);
        Ok(self.allocation_sequence)
    }

    /// Release `bytes` back to the specified domain.
    pub fn release(
        &mut self,
        domain: AllocationDomain,
        bytes: u64,
    ) -> Result<(), AllocDomainError> {
        let config = self
            .domains
            .get_mut(&domain)
            .ok_or(AllocDomainError::DomainNotFound { domain })?;
        config.budget.release(bytes);
        Ok(())
    }

    /// Get the current configuration and budget state for a domain.
    pub fn get(&self, domain: &AllocationDomain) -> Option<&DomainConfig> {
        self.domains.get(domain)
    }

    /// Iterate domains in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&AllocationDomain, &DomainConfig)> {
        self.domains.iter()
    }

    /// Total bytes used across all domains (saturating to avoid wrap).
    pub fn total_used(&self) -> u64 {
        self.domains
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.budget.used_bytes))
    }

    /// Total budget capacity across all domains (saturating to avoid wrap).
    pub fn total_capacity(&self) -> u64 {
        self.domains
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.budget.max_bytes))
    }

    /// Number of registered domains.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Current allocation sequence number (for determinism auditing).
    pub fn allocation_sequence(&self) -> u64 {
        self.allocation_sequence
    }

    /// Reset a domain's used bytes to zero (for lifetime-class transitions).
    pub fn reset_domain(&mut self, domain: AllocationDomain) -> Result<(), AllocDomainError> {
        let config = self
            .domains
            .get_mut(&domain)
            .ok_or(AllocDomainError::DomainNotFound { domain })?;
        config.budget.used_bytes = 0;
        Ok(())
    }

    /// Create a standard runtime domain set with configurable budgets.
    pub fn with_standard_domains(extension_heap_bytes: u64) -> Self {
        let mut reg = Self::new();
        // These are safe to unwrap because we know there are no duplicates.
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            extension_heap_bytes,
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::RuntimeHeap,
            LifetimeClass::Global,
            u64::MAX, // runtime heap is bounded externally
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::IrArena,
            LifetimeClass::Arena,
            512 * 1024 * 1024, // 512 MB default for IR arena
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::EvidenceArena,
            LifetimeClass::SessionScoped,
            128 * 1024 * 1024, // 128 MB default for evidence
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            64 * 1024 * 1024, // 64 MB default for scratch
        )
        .expect("no duplicate");
        reg
    }
}

impl Default for DomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DomainBudget --

    #[test]
    fn budget_reserves_within_limit() {
        let mut budget = DomainBudget::new(1024);
        assert!(budget.try_reserve(512).is_ok());
        assert_eq!(budget.used_bytes, 512);
        assert_eq!(budget.remaining(), 512);
    }

    #[test]
    fn budget_rejects_over_limit() {
        let mut budget = DomainBudget::new(100);
        budget.try_reserve(60).unwrap();
        assert!(matches!(
            budget.try_reserve(50),
            Err(AllocDomainError::BudgetExceeded { .. })
        ));
        // Used bytes unchanged on failure.
        assert_eq!(budget.used_bytes, 60);
    }

    #[test]
    fn budget_release_frees_space() {
        let mut budget = DomainBudget::new(100);
        budget.try_reserve(80).unwrap();
        budget.release(30);
        assert_eq!(budget.used_bytes, 50);
        assert_eq!(budget.remaining(), 50);
    }

    #[test]
    fn budget_release_saturates_at_zero() {
        let mut budget = DomainBudget::new(100);
        budget.try_reserve(10).unwrap();
        budget.release(100); // release more than used
        assert_eq!(budget.used_bytes, 0);
    }

    #[test]
    fn budget_utilization_calculation() {
        let mut budget = DomainBudget::new(200);
        assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
        budget.try_reserve(100).unwrap();
        assert!((budget.utilization() - 0.5).abs() < f64::EPSILON);
        budget.try_reserve(100).unwrap();
        assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn budget_zero_capacity_utilization() {
        let budget = DomainBudget::new(0);
        assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
    }

    // -- DomainRegistry --

    #[test]
    fn register_and_allocate() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            1024,
        )
        .unwrap();
        let seq = reg.allocate(AllocationDomain::ExtensionHeap, 256).unwrap();
        assert_eq!(seq, 1);
        let config = reg.get(&AllocationDomain::ExtensionHeap).unwrap();
        assert_eq!(config.budget.used_bytes, 256);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = DomainRegistry::new();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1024)
            .unwrap();
        assert!(matches!(
            reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 2048),
            Err(AllocDomainError::DuplicateDomain { .. })
        ));
    }

    #[test]
    fn allocate_from_unregistered_domain_fails() {
        let mut reg = DomainRegistry::new();
        assert!(matches!(
            reg.allocate(AllocationDomain::ScratchBuffer, 10),
            Err(AllocDomainError::DomainNotFound { .. })
        ));
    }

    #[test]
    fn budget_enforcement_across_allocations() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 60).unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 30).unwrap();
        // Next allocation would exceed
        assert!(matches!(
            reg.allocate(AllocationDomain::ExtensionHeap, 20),
            Err(AllocDomainError::BudgetExceeded {
                domain: Some(AllocationDomain::ExtensionHeap),
                ..
            })
        ));
    }

    #[test]
    fn release_and_reallocate() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            100,
        )
        .unwrap();
        reg.allocate(AllocationDomain::ScratchBuffer, 80).unwrap();
        reg.release(AllocationDomain::ScratchBuffer, 80).unwrap();
        // Should be able to allocate again.
        reg.allocate(AllocationDomain::ScratchBuffer, 90).unwrap();
        assert_eq!(
            reg.get(&AllocationDomain::ScratchBuffer)
                .unwrap()
                .budget
                .used_bytes,
            90
        );
    }

    #[test]
    fn reset_domain_clears_usage() {
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
    fn allocation_sequence_increments_deterministically() {
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

    #[test]
    fn domains_iterate_in_deterministic_order() {
        let mut reg = DomainRegistry::new();
        // Register in non-sorted order.
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
        // BTreeMap sorts by enum discriminant order.
        assert_eq!(
            domains,
            vec![
                AllocationDomain::ExtensionHeap,
                AllocationDomain::RuntimeHeap, // not registered, won't appear
                AllocationDomain::IrArena,
                AllocationDomain::ScratchBuffer,
            ]
            .into_iter()
            .filter(|d| reg.get(d).is_some())
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn standard_domains_creates_five_domains() {
        let reg = DomainRegistry::with_standard_domains(128 * 1024 * 1024);
        assert_eq!(reg.len(), 5);
        assert!(reg.get(&AllocationDomain::ExtensionHeap).is_some());
        assert!(reg.get(&AllocationDomain::RuntimeHeap).is_some());
        assert!(reg.get(&AllocationDomain::IrArena).is_some());
        assert!(reg.get(&AllocationDomain::EvidenceArena).is_some());
        assert!(reg.get(&AllocationDomain::ScratchBuffer).is_some());
    }

    #[test]
    fn domain_isolation_separate_budgets() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
            .unwrap();

        // Fill extension heap to capacity.
        reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();

        // IR arena should still be fully available.
        reg.allocate(AllocationDomain::IrArena, 100).unwrap();

        assert_eq!(reg.total_used(), 200);
        assert_eq!(reg.total_capacity(), 200);
    }

    #[test]
    fn total_used_and_capacity() {
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

    // -- Serialization --

    #[test]
    fn domain_registry_serialization_round_trip() {
        let mut reg = DomainRegistry::with_standard_domains(1024);
        reg.allocate(AllocationDomain::ExtensionHeap, 256).unwrap();

        let json = serde_json::to_string(&reg).expect("serialize");
        let roundtrip: DomainRegistry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(reg.len(), roundtrip.len());
        assert_eq!(reg.allocation_sequence(), roundtrip.allocation_sequence());
        assert_eq!(
            reg.get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes,
            roundtrip
                .get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display impls
    // -----------------------------------------------------------------------

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
    fn lifetime_class_display_all_variants() {
        assert_eq!(LifetimeClass::RequestScoped.to_string(), "request-scoped");
        assert_eq!(LifetimeClass::SessionScoped.to_string(), "session-scoped");
        assert_eq!(LifetimeClass::Global.to_string(), "global");
        assert_eq!(LifetimeClass::Arena.to_string(), "arena");
    }

    #[test]
    fn alloc_domain_error_display_all_variants() {
        let e1 = AllocDomainError::BudgetExceeded {
            requested: 500,
            remaining: 100,
            domain: Some(AllocationDomain::ExtensionHeap),
        };
        let s1 = e1.to_string();
        assert!(s1.contains("budget exceeded in extension-heap"));
        assert!(s1.contains("500"));
        assert!(s1.contains("100"));

        let e2 = AllocDomainError::BudgetExceeded {
            requested: 200,
            remaining: 50,
            domain: None,
        };
        let s2 = e2.to_string();
        assert!(s2.contains("budget exceeded:"));
        assert!(!s2.contains("in "));

        let e3 = AllocDomainError::BudgetOverflow;
        assert_eq!(e3.to_string(), "budget arithmetic overflow");

        let e4 = AllocDomainError::DomainNotFound {
            domain: AllocationDomain::IrArena,
        };
        assert!(e4.to_string().contains("ir-arena"));
        assert!(e4.to_string().contains("not registered"));

        let e5 = AllocDomainError::DuplicateDomain {
            domain: AllocationDomain::ScratchBuffer,
        };
        assert!(e5.to_string().contains("scratch-buffer"));
        assert!(e5.to_string().contains("already registered"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for leaf types
    // -----------------------------------------------------------------------

    #[test]
    fn allocation_domain_serde_all_variants() {
        let variants = [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let restored: AllocationDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn lifetime_class_serde_all_variants() {
        let variants = [
            LifetimeClass::RequestScoped,
            LifetimeClass::SessionScoped,
            LifetimeClass::Global,
            LifetimeClass::Arena,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let restored: LifetimeClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn alloc_domain_error_serde_all_variants() {
        let variants: Vec<AllocDomainError> = vec![
            AllocDomainError::BudgetExceeded {
                requested: 100,
                remaining: 50,
                domain: Some(AllocationDomain::RuntimeHeap),
            },
            AllocDomainError::BudgetExceeded {
                requested: 100,
                remaining: 50,
                domain: None,
            },
            AllocDomainError::BudgetOverflow,
            AllocDomainError::DomainNotFound {
                domain: AllocationDomain::IrArena,
            },
            AllocDomainError::DuplicateDomain {
                domain: AllocationDomain::EvidenceArena,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let restored: AllocDomainError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
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
            domain: AllocationDomain::EvidenceArena,
            lifetime: LifetimeClass::SessionScoped,
            budget: DomainBudget::new(512),
        };
        let json = serde_json::to_string(&config).unwrap();
        let restored: DomainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DomainBudget edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn budget_new_initial_state() {
        let b = DomainBudget::new(1000);
        assert_eq!(b.max_bytes, 1000);
        assert_eq!(b.used_bytes, 0);
        assert_eq!(b.remaining(), 1000);
    }

    #[test]
    fn budget_overflow_on_checked_add() {
        let mut b = DomainBudget::new(u64::MAX);
        b.try_reserve(u64::MAX).unwrap();
        let err = b.try_reserve(1).unwrap_err();
        assert!(matches!(err, AllocDomainError::BudgetOverflow));
    }

    #[test]
    fn budget_try_reserve_exact_limit() {
        let mut b = DomainBudget::new(100);
        b.try_reserve(100).unwrap();
        assert_eq!(b.used_bytes, 100);
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn budget_try_reserve_zero_bytes() {
        let mut b = DomainBudget::new(100);
        b.try_reserve(0).unwrap();
        assert_eq!(b.used_bytes, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DomainRegistry edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_registry_accessors() {
        let reg = DomainRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.total_used(), 0);
        assert_eq!(reg.total_capacity(), 0);
        assert_eq!(reg.allocation_sequence(), 0);
    }

    #[test]
    fn registry_default_is_empty() {
        let reg = DomainRegistry::default();
        assert!(reg.is_empty());
    }

    #[test]
    fn release_from_unregistered_domain_fails() {
        let mut reg = DomainRegistry::new();
        let err = reg
            .release(AllocationDomain::EvidenceArena, 10)
            .unwrap_err();
        assert!(matches!(err, AllocDomainError::DomainNotFound { .. }));
    }

    #[test]
    fn reset_unregistered_domain_fails() {
        let mut reg = DomainRegistry::new();
        let err = reg.reset_domain(AllocationDomain::IrArena).unwrap_err();
        assert!(matches!(err, AllocDomainError::DomainNotFound { .. }));
    }

    #[test]
    fn get_unregistered_domain_returns_none() {
        let reg = DomainRegistry::new();
        assert!(reg.get(&AllocationDomain::RuntimeHeap).is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: standard domains configuration
    // -----------------------------------------------------------------------

    #[test]
    fn standard_domains_lifetime_classes() {
        let reg = DomainRegistry::with_standard_domains(1024);
        let ext = reg.get(&AllocationDomain::ExtensionHeap).unwrap();
        assert_eq!(ext.lifetime, LifetimeClass::SessionScoped);
        assert_eq!(ext.budget.max_bytes, 1024);

        let rt = reg.get(&AllocationDomain::RuntimeHeap).unwrap();
        assert_eq!(rt.lifetime, LifetimeClass::Global);
        assert_eq!(rt.budget.max_bytes, u64::MAX);

        let ir = reg.get(&AllocationDomain::IrArena).unwrap();
        assert_eq!(ir.lifetime, LifetimeClass::Arena);
        assert_eq!(ir.budget.max_bytes, 512 * 1024 * 1024);

        let ev = reg.get(&AllocationDomain::EvidenceArena).unwrap();
        assert_eq!(ev.lifetime, LifetimeClass::SessionScoped);
        assert_eq!(ev.budget.max_bytes, 128 * 1024 * 1024);

        let sc = reg.get(&AllocationDomain::ScratchBuffer).unwrap();
        assert_eq!(sc.lifetime, LifetimeClass::RequestScoped);
        assert_eq!(sc.budget.max_bytes, 64 * 1024 * 1024);
    }

    // -----------------------------------------------------------------------
    // Enrichment: allocation fills domain in budget error
    // -----------------------------------------------------------------------

    #[test]
    fn allocate_over_budget_includes_domain_in_error() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();
        let err = reg
            .allocate(AllocationDomain::ExtensionHeap, 200)
            .unwrap_err();
        match err {
            AllocDomainError::BudgetExceeded { domain, .. } => {
                assert_eq!(domain, Some(AllocationDomain::ExtensionHeap));
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: allocation sequence after release/reset
    // -----------------------------------------------------------------------

    #[test]
    fn allocation_sequence_not_affected_by_release() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            1000,
        )
        .unwrap();
        let s1 = reg.allocate(AllocationDomain::ScratchBuffer, 10).unwrap();
        reg.release(AllocationDomain::ScratchBuffer, 10).unwrap();
        let s2 = reg.allocate(AllocationDomain::ScratchBuffer, 10).unwrap();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2); // sequence keeps incrementing
    }

    // -- Enrichment: std::error --

    #[test]
    fn alloc_domain_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(AllocDomainError::BudgetExceeded {
                requested: 100,
                remaining: 50,
                domain: Some(AllocationDomain::ExtensionHeap),
            }),
            Box::new(AllocDomainError::BudgetOverflow),
            Box::new(AllocDomainError::DomainNotFound {
                domain: AllocationDomain::IrArena,
            }),
            Box::new(AllocDomainError::DuplicateDomain {
                domain: AllocationDomain::ScratchBuffer,
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(displays.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: edge cases, Display uniqueness, determinism
    // -----------------------------------------------------------------------

    #[test]
    fn allocation_domain_display_uniqueness_btreeset() {
        let displays: std::collections::BTreeSet<String> = [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ]
        .iter()
        .map(|d| d.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            5,
            "all 5 domain variants must have unique Display"
        );
    }

    #[test]
    fn lifetime_class_display_uniqueness_btreeset() {
        let displays: std::collections::BTreeSet<String> = [
            LifetimeClass::RequestScoped,
            LifetimeClass::SessionScoped,
            LifetimeClass::Global,
            LifetimeClass::Arena,
        ]
        .iter()
        .map(|l| l.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 lifetime variants must have unique Display"
        );
    }

    #[test]
    fn budget_reserve_then_release_then_reserve_cycle() {
        let mut budget = DomainBudget::new(100);
        budget.try_reserve(100).unwrap();
        assert_eq!(budget.remaining(), 0);
        budget.release(50);
        assert_eq!(budget.remaining(), 50);
        budget.try_reserve(50).unwrap();
        assert_eq!(budget.remaining(), 0);
        assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn registry_with_standard_domains_allocate_all() {
        let mut reg = DomainRegistry::with_standard_domains(1024);
        // Allocate 1 byte from each domain
        for domain in [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ] {
            let seq = reg.allocate(domain, 1).unwrap();
            assert!(seq > 0);
        }
        assert_eq!(reg.allocation_sequence(), 5);
        assert_eq!(reg.total_used(), 5);
    }

    #[test]
    fn reset_domain_preserves_allocation_sequence() {
        let mut reg = DomainRegistry::new();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1024)
            .unwrap();
        reg.allocate(AllocationDomain::IrArena, 500).unwrap();
        let seq_before = reg.allocation_sequence();
        reg.reset_domain(AllocationDomain::IrArena).unwrap();
        assert_eq!(
            reg.allocation_sequence(),
            seq_before,
            "reset must not change sequence"
        );
        assert_eq!(
            reg.get(&AllocationDomain::IrArena)
                .unwrap()
                .budget
                .used_bytes,
            0
        );
    }

    #[test]
    fn domain_config_preserves_lifetime_class() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::EvidenceArena,
            LifetimeClass::SessionScoped,
            256,
        )
        .unwrap();
        let config = reg.get(&AllocationDomain::EvidenceArena).unwrap();
        assert_eq!(config.lifetime, LifetimeClass::SessionScoped);
        assert_eq!(config.domain, AllocationDomain::EvidenceArena);
    }

    #[test]
    fn registry_serde_preserves_used_bytes_across_domains() {
        let mut reg = DomainRegistry::with_standard_domains(4096);
        reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
        reg.allocate(AllocationDomain::IrArena, 200).unwrap();
        reg.allocate(AllocationDomain::ScratchBuffer, 300).unwrap();

        let json = serde_json::to_string(&reg).unwrap();
        let restored: DomainRegistry = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.total_used(), 600);
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
            300
        );
    }

    #[test]
    fn budget_try_reserve_one_over_limit_exact_boundary() {
        let mut b = DomainBudget::new(100);
        b.try_reserve(99).unwrap();
        // Exactly one byte remaining
        assert_eq!(b.remaining(), 1);
        b.try_reserve(1).unwrap();
        assert_eq!(b.remaining(), 0);
        // Now even 1 byte fails
        let err = b.try_reserve(1).unwrap_err();
        match err {
            AllocDomainError::BudgetExceeded {
                requested,
                remaining,
                ..
            } => {
                assert_eq!(requested, 1);
                assert_eq!(remaining, 0);
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone, ordering, JSON fields, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn domain_budget_clone_equality() {
        let mut b = DomainBudget::new(500);
        b.try_reserve(123).unwrap();
        let cloned = b.clone();
        assert_eq!(b, cloned);
    }

    #[test]
    fn domain_config_clone_equality() {
        let cfg = DomainConfig {
            domain: AllocationDomain::IrArena,
            lifetime: LifetimeClass::Arena,
            budget: DomainBudget::new(4096),
        };
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }

    #[test]
    fn alloc_domain_error_clone_equality() {
        let variants = vec![
            AllocDomainError::BudgetExceeded {
                requested: 42,
                remaining: 7,
                domain: Some(AllocationDomain::ScratchBuffer),
            },
            AllocDomainError::BudgetOverflow,
            AllocDomainError::DomainNotFound {
                domain: AllocationDomain::RuntimeHeap,
            },
            AllocDomainError::DuplicateDomain {
                domain: AllocationDomain::EvidenceArena,
            },
        ];
        for v in &variants {
            let cloned = v.clone();
            assert_eq!(*v, cloned);
        }
    }

    #[test]
    fn allocation_domain_ord_deterministic() {
        let mut domains = vec![
            AllocationDomain::ScratchBuffer,
            AllocationDomain::ExtensionHeap,
            AllocationDomain::EvidenceArena,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
        ];
        domains.sort();
        // Ord follows discriminant order
        assert_eq!(domains[0], AllocationDomain::ExtensionHeap);
        assert_eq!(domains[4], AllocationDomain::ScratchBuffer);
        // Sorting twice gives same result
        let first_sort = domains.clone();
        domains.sort();
        assert_eq!(domains, first_sort);
    }

    #[test]
    fn lifetime_class_ord_deterministic() {
        let mut classes = vec![
            LifetimeClass::Arena,
            LifetimeClass::Global,
            LifetimeClass::RequestScoped,
            LifetimeClass::SessionScoped,
        ];
        classes.sort();
        assert_eq!(classes[0], LifetimeClass::RequestScoped);
        assert_eq!(classes[3], LifetimeClass::Arena);
        let first_sort = classes.clone();
        classes.sort();
        assert_eq!(classes, first_sort);
    }

    #[test]
    fn domain_budget_json_field_presence() {
        let mut b = DomainBudget::new(1024);
        b.try_reserve(256).unwrap();
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("\"max_bytes\""));
        assert!(json.contains("\"used_bytes\""));
        assert!(json.contains("1024"));
        assert!(json.contains("256"));
    }

    #[test]
    fn domain_config_json_field_presence() {
        let cfg = DomainConfig {
            domain: AllocationDomain::EvidenceArena,
            lifetime: LifetimeClass::SessionScoped,
            budget: DomainBudget::new(512),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"domain\""));
        assert!(json.contains("\"lifetime\""));
        assert!(json.contains("\"budget\""));
        assert!(json.contains("EvidenceArena"));
        assert!(json.contains("SessionScoped"));
    }

    #[test]
    fn budget_zero_max_reserve_one_fails() {
        let mut b = DomainBudget::new(0);
        let err = b.try_reserve(1).unwrap_err();
        assert!(matches!(err, AllocDomainError::BudgetExceeded { .. }));
        assert_eq!(b.used_bytes, 0);
    }

    #[test]
    fn registry_allocate_zero_bytes_increments_sequence() {
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
    fn registry_total_used_after_partial_release() {
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
        reg.release(AllocationDomain::ExtensionHeap, 150).unwrap();
        assert_eq!(reg.total_used(), 550);
    }

    #[test]
    fn registry_iter_count_matches_len() {
        let reg = DomainRegistry::with_standard_domains(1024);
        assert_eq!(reg.iter().count(), reg.len());
        assert_eq!(reg.iter().count(), 5);
    }

    #[test]
    fn budget_multiple_sequential_releases_saturate() {
        let mut b = DomainBudget::new(100);
        b.try_reserve(50).unwrap();
        b.release(20);
        assert_eq!(b.used_bytes, 30);
        b.release(20);
        assert_eq!(b.used_bytes, 10);
        b.release(20); // saturates at 0 since 10 - 20 < 0
        assert_eq!(b.used_bytes, 0);
    }

    #[test]
    fn registry_clone_preserves_state() {
        let mut reg = DomainRegistry::with_standard_domains(2048);
        reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
        reg.allocate(AllocationDomain::IrArena, 200).unwrap();
        let cloned = reg.clone();
        assert_eq!(cloned.len(), reg.len());
        assert_eq!(cloned.total_used(), reg.total_used());
        assert_eq!(cloned.allocation_sequence(), reg.allocation_sequence());
        assert_eq!(
            cloned
                .get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes,
            100
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: deep coverage, stress, clone-independence, replay
    // -----------------------------------------------------------------------

    #[test]
    fn domain_budget_clone_independence_enrichment() {
        let mut original = DomainBudget::new(1000);
        original.try_reserve(200).unwrap();
        let mut cloned = original.clone();
        // Mutate the original
        original.try_reserve(300).unwrap();
        // Clone must remain at 200
        assert_eq!(cloned.used_bytes, 200);
        assert_eq!(original.used_bytes, 500);
        // Mutate the clone
        cloned.release(100);
        assert_eq!(cloned.used_bytes, 100);
        assert_eq!(original.used_bytes, 500);
    }

    #[test]
    fn domain_config_clone_independence_enrichment() {
        let mut original = DomainConfig {
            domain: AllocationDomain::ExtensionHeap,
            lifetime: LifetimeClass::SessionScoped,
            budget: DomainBudget::new(2048),
        };
        original.budget.try_reserve(500).unwrap();
        let cloned = original.clone();
        original.budget.try_reserve(300).unwrap();
        assert_eq!(original.budget.used_bytes, 800);
        assert_eq!(cloned.budget.used_bytes, 500);
    }

    #[test]
    fn registry_clone_independence_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            5000,
        )
        .unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
        let mut cloned = reg.clone();
        // Allocate more on original
        reg.allocate(AllocationDomain::ExtensionHeap, 200).unwrap();
        // Clone must still be at 100
        assert_eq!(
            cloned
                .get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes,
            100
        );
        assert_eq!(cloned.allocation_sequence(), 1);
        // Allocate on clone
        cloned
            .allocate(AllocationDomain::ExtensionHeap, 50)
            .unwrap();
        assert_eq!(cloned.allocation_sequence(), 2);
        assert_eq!(reg.allocation_sequence(), 2);
    }

    #[test]
    fn allocation_domain_btreeset_insertion_enrichment() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(AllocationDomain::ScratchBuffer);
        set.insert(AllocationDomain::ExtensionHeap);
        set.insert(AllocationDomain::IrArena);
        set.insert(AllocationDomain::RuntimeHeap);
        set.insert(AllocationDomain::EvidenceArena);
        // Duplicates are absorbed
        set.insert(AllocationDomain::IrArena);
        assert_eq!(set.len(), 5);
        // First element should be ExtensionHeap (smallest discriminant)
        assert_eq!(*set.iter().next().unwrap(), AllocationDomain::ExtensionHeap);
    }

    #[test]
    fn lifetime_class_btreeset_insertion_enrichment() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(LifetimeClass::Arena);
        set.insert(LifetimeClass::Global);
        set.insert(LifetimeClass::RequestScoped);
        set.insert(LifetimeClass::SessionScoped);
        set.insert(LifetimeClass::Arena); // duplicate
        assert_eq!(set.len(), 4);
        assert_eq!(*set.iter().next().unwrap(), LifetimeClass::RequestScoped);
    }

    #[test]
    fn allocation_domain_btreemap_as_key_enrichment() {
        let mut map = BTreeMap::new();
        map.insert(AllocationDomain::ScratchBuffer, "scratch");
        map.insert(AllocationDomain::ExtensionHeap, "ext");
        map.insert(AllocationDomain::RuntimeHeap, "rt");
        assert_eq!(map.len(), 3);
        assert_eq!(map[&AllocationDomain::ScratchBuffer], "scratch");
        // Iteration is deterministic by Ord
        let keys: Vec<_> = map.keys().collect();
        assert_eq!(*keys[0], AllocationDomain::ExtensionHeap);
    }

    #[test]
    fn lifetime_class_btreemap_as_key_enrichment() {
        let mut map = BTreeMap::new();
        map.insert(LifetimeClass::Global, 10u64);
        map.insert(LifetimeClass::RequestScoped, 20);
        map.insert(LifetimeClass::Arena, 30);
        assert_eq!(map.len(), 3);
        // RequestScoped < Global < Arena in Ord
        let keys: Vec<_> = map.keys().collect();
        assert_eq!(*keys[0], LifetimeClass::RequestScoped);
    }

    #[test]
    fn allocation_domain_debug_contains_variant_name_enrichment() {
        let dbg = format!("{:?}", AllocationDomain::ExtensionHeap);
        assert!(dbg.contains("ExtensionHeap"));
        let dbg2 = format!("{:?}", AllocationDomain::ScratchBuffer);
        assert!(dbg2.contains("ScratchBuffer"));
    }

    #[test]
    fn lifetime_class_debug_contains_variant_name_enrichment() {
        let dbg = format!("{:?}", LifetimeClass::RequestScoped);
        assert!(dbg.contains("RequestScoped"));
        let dbg2 = format!("{:?}", LifetimeClass::Arena);
        assert!(dbg2.contains("Arena"));
    }

    #[test]
    fn alloc_domain_error_debug_enrichment() {
        let err = AllocDomainError::BudgetExceeded {
            requested: 999,
            remaining: 1,
            domain: Some(AllocationDomain::IrArena),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("BudgetExceeded"));
        assert!(dbg.contains("999"));
        assert!(dbg.contains("IrArena"));
    }

    #[test]
    fn budget_exceeded_display_without_domain_enrichment() {
        let err = AllocDomainError::BudgetExceeded {
            requested: 1000,
            remaining: 0,
            domain: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("budget exceeded:"));
        assert!(msg.contains("1000 bytes"));
        assert!(msg.contains("0 remaining"));
        // Must NOT contain "in " since domain is None
        assert!(!msg.contains("in "));
    }

    #[test]
    fn budget_exceeded_display_with_domain_enrichment() {
        let err = AllocDomainError::BudgetExceeded {
            requested: 512,
            remaining: 256,
            domain: Some(AllocationDomain::ScratchBuffer),
        };
        let msg = err.to_string();
        assert!(msg.contains("budget exceeded in scratch-buffer"));
        assert!(msg.contains("512"));
        assert!(msg.contains("256"));
    }

    #[test]
    fn domain_not_found_display_all_domains_enrichment() {
        for domain in [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ] {
            let err = AllocDomainError::DomainNotFound { domain };
            let msg = err.to_string();
            assert!(msg.contains(&domain.to_string()));
            assert!(msg.contains("not registered"));
        }
    }

    #[test]
    fn duplicate_domain_display_all_domains_enrichment() {
        for domain in [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ] {
            let err = AllocDomainError::DuplicateDomain { domain };
            let msg = err.to_string();
            assert!(msg.contains(&domain.to_string()));
            assert!(msg.contains("already registered"));
        }
    }

    #[test]
    fn budget_serde_zero_capacity_enrichment() {
        let b = DomainBudget::new(0);
        let json = serde_json::to_string(&b).unwrap();
        let restored: DomainBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.max_bytes, 0);
        assert_eq!(restored.used_bytes, 0);
    }

    #[test]
    fn budget_serde_max_u64_capacity_enrichment() {
        let mut b = DomainBudget::new(u64::MAX);
        b.try_reserve(1).unwrap();
        let json = serde_json::to_string(&b).unwrap();
        let restored: DomainBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.max_bytes, u64::MAX);
        assert_eq!(restored.used_bytes, 1);
    }

    #[test]
    fn registry_serde_empty_enrichment() {
        let reg = DomainRegistry::new();
        let json = serde_json::to_string(&reg).unwrap();
        let restored: DomainRegistry = serde_json::from_str(&json).unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.allocation_sequence(), 0);
    }

    #[test]
    fn registry_serde_after_reset_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 5000)
            .unwrap();
        reg.allocate(AllocationDomain::IrArena, 3000).unwrap();
        reg.reset_domain(AllocationDomain::IrArena).unwrap();

        let json = serde_json::to_string(&reg).unwrap();
        let restored: DomainRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored
                .get(&AllocationDomain::IrArena)
                .unwrap()
                .budget
                .used_bytes,
            0
        );
        assert_eq!(restored.allocation_sequence(), 1);
    }

    #[test]
    fn deterministic_replay_same_sequence_enrichment() {
        // Two registries with identical operations must produce identical state.
        let ops = vec![
            (AllocationDomain::ExtensionHeap, 100u64),
            (AllocationDomain::IrArena, 200),
            (AllocationDomain::ExtensionHeap, 50),
            (AllocationDomain::ScratchBuffer, 300),
            (AllocationDomain::IrArena, 100),
        ];

        let mut reg1 = DomainRegistry::new();
        let mut reg2 = DomainRegistry::new();
        for reg in [&mut reg1, &mut reg2] {
            reg.register(
                AllocationDomain::ExtensionHeap,
                LifetimeClass::SessionScoped,
                10000,
            )
            .unwrap();
            reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 10000)
                .unwrap();
            reg.register(
                AllocationDomain::ScratchBuffer,
                LifetimeClass::RequestScoped,
                10000,
            )
            .unwrap();
        }

        let mut seqs1 = Vec::new();
        let mut seqs2 = Vec::new();
        for (domain, bytes) in &ops {
            seqs1.push(reg1.allocate(*domain, *bytes).unwrap());
            seqs2.push(reg2.allocate(*domain, *bytes).unwrap());
        }
        assert_eq!(seqs1, seqs2);
        assert_eq!(reg1.total_used(), reg2.total_used());
        assert_eq!(reg1.allocation_sequence(), reg2.allocation_sequence());
    }

    #[test]
    fn deterministic_replay_serde_equivalence_enrichment() {
        let mut reg = DomainRegistry::with_standard_domains(10000);
        reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
        reg.allocate(AllocationDomain::IrArena, 200).unwrap();
        reg.allocate(AllocationDomain::ScratchBuffer, 50).unwrap();

        // Serialize twice independently
        let json1 = serde_json::to_string(&reg).unwrap();
        let json2 = serde_json::to_string(&reg).unwrap();
        assert_eq!(json1, json2, "deterministic serialization");
    }

    #[test]
    fn stress_many_allocations_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            1_000_000,
        )
        .unwrap();
        for i in 0..1000 {
            let seq = reg.allocate(AllocationDomain::ScratchBuffer, 1).unwrap();
            assert_eq!(seq, (i + 1) as u64);
        }
        assert_eq!(
            reg.get(&AllocationDomain::ScratchBuffer)
                .unwrap()
                .budget
                .used_bytes,
            1000
        );
        assert_eq!(reg.allocation_sequence(), 1000);
    }

    #[test]
    fn stress_allocate_release_cycles_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
            .unwrap();
        // 500 cycles of allocate-then-release
        for _ in 0..500 {
            reg.allocate(AllocationDomain::IrArena, 100).unwrap();
            reg.release(AllocationDomain::IrArena, 100).unwrap();
        }
        assert_eq!(
            reg.get(&AllocationDomain::IrArena)
                .unwrap()
                .budget
                .used_bytes,
            0
        );
        assert_eq!(reg.allocation_sequence(), 500);
    }

    #[test]
    fn stress_interleaved_multi_domain_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            50000,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 50000)
            .unwrap();
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            50000,
        )
        .unwrap();

        let domains = [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::IrArena,
            AllocationDomain::ScratchBuffer,
        ];
        for i in 0u64..300 {
            let domain = domains[(i as usize) % 3];
            reg.allocate(domain, 10).unwrap();
        }
        assert_eq!(reg.allocation_sequence(), 300);
        // Each domain got 100 allocations of 10 bytes
        assert_eq!(reg.total_used(), 3000);
        for domain in &domains {
            assert_eq!(reg.get(domain).unwrap().budget.used_bytes, 1000);
        }
    }

    #[test]
    fn budget_utilization_midpoint_enrichment() {
        let mut b = DomainBudget::new(200);
        b.try_reserve(50).unwrap();
        assert!((b.utilization() - 0.25).abs() < f64::EPSILON);
        b.try_reserve(50).unwrap();
        assert!((b.utilization() - 0.50).abs() < f64::EPSILON);
        b.try_reserve(50).unwrap();
        assert!((b.utilization() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn budget_remaining_after_exact_fill_enrichment() {
        let mut b = DomainBudget::new(u64::MAX);
        b.try_reserve(u64::MAX).unwrap();
        assert_eq!(b.remaining(), 0);
        assert!((b.utilization() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn budget_release_zero_is_noop_enrichment() {
        let mut b = DomainBudget::new(100);
        b.try_reserve(50).unwrap();
        b.release(0);
        assert_eq!(b.used_bytes, 50);
    }

    #[test]
    fn registry_reset_then_reuse_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::EvidenceArena,
            LifetimeClass::SessionScoped,
            500,
        )
        .unwrap();
        reg.allocate(AllocationDomain::EvidenceArena, 500).unwrap();
        // Full — cannot allocate more
        assert!(reg.allocate(AllocationDomain::EvidenceArena, 1).is_err());
        // Reset and reallocate
        reg.reset_domain(AllocationDomain::EvidenceArena).unwrap();
        reg.allocate(AllocationDomain::EvidenceArena, 250).unwrap();
        assert_eq!(
            reg.get(&AllocationDomain::EvidenceArena)
                .unwrap()
                .budget
                .used_bytes,
            250
        );
    }

    #[test]
    fn standard_domains_extension_heap_param_propagates_enrichment() {
        // The extension_heap_bytes parameter must set ExtensionHeap max_bytes exactly
        for size in [0u64, 1, 1024, 1_000_000, u64::MAX / 2] {
            let reg = DomainRegistry::with_standard_domains(size);
            assert_eq!(
                reg.get(&AllocationDomain::ExtensionHeap)
                    .unwrap()
                    .budget
                    .max_bytes,
                size
            );
        }
    }

    #[test]
    fn error_serde_budget_exceeded_boundary_values_enrichment() {
        let errors = vec![
            AllocDomainError::BudgetExceeded {
                requested: 0,
                remaining: 0,
                domain: None,
            },
            AllocDomainError::BudgetExceeded {
                requested: u64::MAX,
                remaining: u64::MAX,
                domain: Some(AllocationDomain::RuntimeHeap),
            },
            AllocDomainError::BudgetExceeded {
                requested: 1,
                remaining: u64::MAX,
                domain: Some(AllocationDomain::ExtensionHeap),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: AllocDomainError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn allocation_domain_copy_semantics_enrichment() {
        let a = AllocationDomain::IrArena;
        let b = a; // Copy
        assert_eq!(a, b);
        // Both still usable (Copy, not moved)
        let _ = format!("{a}");
        let _ = format!("{b}");
    }

    #[test]
    fn lifetime_class_copy_semantics_enrichment() {
        let a = LifetimeClass::Global;
        let b = a; // Copy
        assert_eq!(a, b);
        let _ = format!("{a}");
        let _ = format!("{b}");
    }

    #[test]
    fn allocation_domain_hash_consistency_enrichment() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let d = AllocationDomain::EvidenceArena;
        let mut h1 = DefaultHasher::new();
        d.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        d.hash(&mut h2);
        let hash2 = h2.finish();

        assert_eq!(hash1, hash2, "same value must produce same hash");
    }

    #[test]
    fn lifetime_class_hash_consistency_enrichment() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let l = LifetimeClass::SessionScoped;
        let mut h1 = DefaultHasher::new();
        l.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        l.hash(&mut h2);
        let hash2 = h2.finish();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn domain_registry_debug_output_enrichment() {
        let reg = DomainRegistry::new();
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("DomainRegistry"));
        assert!(dbg.contains("allocation_sequence"));
    }

    #[test]
    fn budget_exceeded_error_fields_correct_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 70).unwrap();
        let err = reg
            .allocate(AllocationDomain::ExtensionHeap, 50)
            .unwrap_err();
        match err {
            AllocDomainError::BudgetExceeded {
                requested,
                remaining,
                domain,
            } => {
                assert_eq!(requested, 50);
                assert_eq!(remaining, 30);
                assert_eq!(domain, Some(AllocationDomain::ExtensionHeap));
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
    }

    #[test]
    fn registry_total_capacity_unchanged_by_allocations_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            1000,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 2000)
            .unwrap();
        let cap_before = reg.total_capacity();
        reg.allocate(AllocationDomain::ExtensionHeap, 500).unwrap();
        reg.allocate(AllocationDomain::IrArena, 1000).unwrap();
        assert_eq!(
            reg.total_capacity(),
            cap_before,
            "capacity must not change from allocations"
        );
    }

    #[test]
    fn registry_release_more_than_used_saturates_enrichment() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            1000,
        )
        .unwrap();
        reg.allocate(AllocationDomain::ScratchBuffer, 10).unwrap();
        // Release more than allocated
        reg.release(AllocationDomain::ScratchBuffer, 999).unwrap();
        assert_eq!(
            reg.get(&AllocationDomain::ScratchBuffer)
                .unwrap()
                .budget
                .used_bytes,
            0
        );
    }

    #[test]
    fn domain_config_all_combinations_serde_enrichment() {
        let domains = [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ];
        let lifetimes = [
            LifetimeClass::RequestScoped,
            LifetimeClass::SessionScoped,
            LifetimeClass::Global,
            LifetimeClass::Arena,
        ];
        for d in &domains {
            for l in &lifetimes {
                let cfg = DomainConfig {
                    domain: *d,
                    lifetime: *l,
                    budget: DomainBudget::new(42),
                };
                let json = serde_json::to_string(&cfg).unwrap();
                let restored: DomainConfig = serde_json::from_str(&json).unwrap();
                assert_eq!(cfg, restored);
            }
        }
    }

    #[test]
    fn allocation_domain_ne_pairwise_enrichment() {
        let variants = [
            AllocationDomain::ExtensionHeap,
            AllocationDomain::RuntimeHeap,
            AllocationDomain::IrArena,
            AllocationDomain::EvidenceArena,
            AllocationDomain::ScratchBuffer,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "{a:?} should != {b:?}");
                }
            }
        }
    }

    #[test]
    fn lifetime_class_ne_pairwise_enrichment() {
        let variants = [
            LifetimeClass::RequestScoped,
            LifetimeClass::SessionScoped,
            LifetimeClass::Global,
            LifetimeClass::Arena,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "{a:?} should != {b:?}");
                }
            }
        }
    }
}
