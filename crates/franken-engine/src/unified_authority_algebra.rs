// Unified Authority Algebra — product lattice contract for bd-cixqu.26.1.
//
// The unified authority of an evaluation context is the triple
// `(ifc_label, capability_set, budget_envelope)`. Each axis is its own
// lattice; the product lattice combines them with component-wise
// join (least upper bound) and meet (greatest lower bound).
//
// Axes:
//   * IFC: `LabelClass` from `flow_lattice` — a totally-ordered 5-level
//     lattice (`Public < Internal < Confidential < Secret < TopSecret`).
//   * Capability: a `BTreeSet<CapabilityKind>` — the powerset lattice
//     under subset ordering (`join = union`, `meet = intersection`).
//   * Budget: per-dimension `i64` millionths under
//     `join = max`, `meet = min`. Higher numbers mean MORE authority
//     (a larger budget). `Top` is the maximum representable budget;
//     `Bottom` is zero.
//
// `AuthorityLattice` is the product. `subsumes(a, b)` is the natural
// preorder: `a` subsumes `b` iff `a` dominates `b` on every axis. The
// preorder is also expressible as `a.join(b) == a`.
//
// This module is contract-first: it defines the algebra and proves
// its key laws (commutativity, associativity, idempotency, absorption,
// the join/subsumes equivalence) via unit tests. Wiring into the
// existing static-authority analyzer / capability-narrowing pipeline
// is intentionally out of scope here — that lands under bd-cixqu.26.2
// once the unified join/meet/subsumption proofs are signed off.

use crate::flow_lattice::LabelClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// CapabilityKind — the capability axis
// ---------------------------------------------------------------------------

/// Canonical capability identifiers used by the authority lattice.
///
/// This mirrors the high-level capability taxonomy used by extension
/// manifests; it is deliberately a closed enum (not a free-form
/// string) so the lattice is finite and total. Manifests that need to
/// reference capabilities outside this set should extend the enum
/// rather than introducing a parallel string-based axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    FsRead,
    FsWrite,
    NetConnect,
    NetListen,
    ProcSpawn,
    EnvRead,
    EnvWrite,
    PolicyRequest,
    Eval,
    Global,
    ClockRead,
    RandomRead,
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetConnect => "net_connect",
            Self::NetListen => "net_listen",
            Self::ProcSpawn => "proc_spawn",
            Self::EnvRead => "env_read",
            Self::EnvWrite => "env_write",
            Self::PolicyRequest => "policy_request",
            Self::Eval => "eval",
            Self::Global => "global",
            Self::ClockRead => "clock_read",
            Self::RandomRead => "random_read",
        };
        f.write_str(name)
    }
}

/// Powerset lattice over `CapabilityKind`.
///
/// `join = union`, `meet = intersection`, `bottom = empty`,
/// `top = all known kinds`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    capabilities: BTreeSet<CapabilityKind>,
}

impl CapabilitySet {
    /// Empty capability set (lattice bottom).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Capability set containing every known kind (lattice top).
    pub fn all() -> Self {
        let mut set = BTreeSet::new();
        for kind in [
            CapabilityKind::FsRead,
            CapabilityKind::FsWrite,
            CapabilityKind::NetConnect,
            CapabilityKind::NetListen,
            CapabilityKind::ProcSpawn,
            CapabilityKind::EnvRead,
            CapabilityKind::EnvWrite,
            CapabilityKind::PolicyRequest,
            CapabilityKind::Eval,
            CapabilityKind::Global,
            CapabilityKind::ClockRead,
            CapabilityKind::RandomRead,
        ] {
            set.insert(kind);
        }
        Self { capabilities: set }
    }

    /// Build a capability set from any iterable.
    pub fn from_iter<I: IntoIterator<Item = CapabilityKind>>(iter: I) -> Self {
        let mut set = BTreeSet::new();
        for kind in iter {
            set.insert(kind);
        }
        Self { capabilities: set }
    }

    /// Whether this capability set contains the given kind.
    pub fn contains(&self, kind: &CapabilityKind) -> bool {
        self.capabilities.contains(kind)
    }

    /// Add a capability; returns whether the set was modified.
    pub fn insert(&mut self, kind: CapabilityKind) -> bool {
        self.capabilities.insert(kind)
    }

    /// Iterate over the contained capabilities in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = &CapabilityKind> {
        self.capabilities.iter()
    }

    /// Cardinality of the capability set.
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Whether the set is empty (lattice bottom).
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Powerset-lattice join: set union.
    pub fn join(&self, other: &Self) -> Self {
        let capabilities = self
            .capabilities
            .union(&other.capabilities)
            .copied()
            .collect();
        Self { capabilities }
    }

    /// Powerset-lattice meet: set intersection.
    pub fn meet(&self, other: &Self) -> Self {
        let capabilities = self
            .capabilities
            .intersection(&other.capabilities)
            .copied()
            .collect();
        Self { capabilities }
    }

    /// Subset preorder. `self` subsumes `other` iff every cap in `other`
    /// is also in `self` (i.e. `self ⊇ other`).
    pub fn subsumes(&self, other: &Self) -> bool {
        other.capabilities.is_subset(&self.capabilities)
    }
}

// ---------------------------------------------------------------------------
// BudgetEnvelope — the budget axis
// ---------------------------------------------------------------------------

/// Resource-budget envelope used as the budget-lattice element.
///
/// Each field is in fixed-point millionths (1_000_000 = 1.0 unit).
/// Higher values mean MORE authority on that dimension (a larger
/// budget). `join = component-wise max`, `meet = component-wise min`.
/// `Top` is `i64::MAX` on every dimension; `Bottom` is zero.
///
/// Negative values are forbidden by `try_new` (budgets cannot be
/// negative); callers that need "no budget" use `Self::bottom()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEnvelope {
    /// CPU budget in millionths-of-a-CPU-second.
    pub cpu_millionths: i64,
    /// Memory budget in millionths-of-a-byte (i.e. micro-bytes).
    pub memory_millionths: i64,
    /// Wall-time budget in millionths-of-a-second.
    pub wall_time_millionths: i64,
    /// I/O budget in millionths-of-a-byte-transferred.
    pub io_millionths: i64,
}

impl BudgetEnvelope {
    /// Bottom of the budget lattice — zero on every dimension.
    pub fn bottom() -> Self {
        Self {
            cpu_millionths: 0,
            memory_millionths: 0,
            wall_time_millionths: 0,
            io_millionths: 0,
        }
    }

    /// Top of the budget lattice — `i64::MAX` on every dimension.
    pub fn top() -> Self {
        Self {
            cpu_millionths: i64::MAX,
            memory_millionths: i64::MAX,
            wall_time_millionths: i64::MAX,
            io_millionths: i64::MAX,
        }
    }

    /// Build a `BudgetEnvelope`; rejects negative components.
    pub fn try_new(
        cpu_millionths: i64,
        memory_millionths: i64,
        wall_time_millionths: i64,
        io_millionths: i64,
    ) -> Result<Self, AuthorityLatticeError> {
        if cpu_millionths < 0
            || memory_millionths < 0
            || wall_time_millionths < 0
            || io_millionths < 0
        {
            return Err(AuthorityLatticeError::NegativeBudget);
        }
        Ok(Self {
            cpu_millionths,
            memory_millionths,
            wall_time_millionths,
            io_millionths,
        })
    }

    /// Component-wise max — budget-lattice join.
    pub fn join(&self, other: &Self) -> Self {
        Self {
            cpu_millionths: self.cpu_millionths.max(other.cpu_millionths),
            memory_millionths: self.memory_millionths.max(other.memory_millionths),
            wall_time_millionths: self.wall_time_millionths.max(other.wall_time_millionths),
            io_millionths: self.io_millionths.max(other.io_millionths),
        }
    }

    /// Component-wise min — budget-lattice meet.
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            cpu_millionths: self.cpu_millionths.min(other.cpu_millionths),
            memory_millionths: self.memory_millionths.min(other.memory_millionths),
            wall_time_millionths: self.wall_time_millionths.min(other.wall_time_millionths),
            io_millionths: self.io_millionths.min(other.io_millionths),
        }
    }

    /// Subsumes preorder: `self` dominates `other` iff every component
    /// of `self` is `>=` the corresponding component of `other`.
    pub fn subsumes(&self, other: &Self) -> bool {
        self.cpu_millionths >= other.cpu_millionths
            && self.memory_millionths >= other.memory_millionths
            && self.wall_time_millionths >= other.wall_time_millionths
            && self.io_millionths >= other.io_millionths
    }
}

// ---------------------------------------------------------------------------
// IFC axis — `LabelClass::join` and `::meet` already exist; we provide
// a small adapter so the same `Lattice` semantics are visible on this
// axis from the product type's perspective.
// ---------------------------------------------------------------------------

fn label_subsumes(a: &LabelClass, b: &LabelClass) -> bool {
    a.level() >= b.level()
}

// ---------------------------------------------------------------------------
// AuthorityLattice — the product of all three axes
// ---------------------------------------------------------------------------

/// Unified authority: `(ifc_label, capability_set, budget_envelope)`.
///
/// Join, meet, and `subsumes` are component-wise. The product lattice
/// inherits associativity, commutativity, idempotency, and absorption
/// from each axis (proven via unit tests in this module).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLattice {
    pub ifc_label: LabelClass,
    pub capability_set: CapabilitySet,
    pub budget_envelope: BudgetEnvelope,
}

impl AuthorityLattice {
    /// Construct an authority element.
    pub fn new(
        ifc_label: LabelClass,
        capability_set: CapabilitySet,
        budget_envelope: BudgetEnvelope,
    ) -> Self {
        Self {
            ifc_label,
            capability_set,
            budget_envelope,
        }
    }

    /// Lattice bottom: most-restrictive label, no capabilities, zero budget.
    pub fn bottom() -> Self {
        Self {
            ifc_label: LabelClass::Public,
            capability_set: CapabilitySet::empty(),
            budget_envelope: BudgetEnvelope::bottom(),
        }
    }

    /// Lattice top: most-permissive label, all capabilities, max budget.
    pub fn top() -> Self {
        Self {
            ifc_label: LabelClass::TopSecret,
            capability_set: CapabilitySet::all(),
            budget_envelope: BudgetEnvelope::top(),
        }
    }

    /// Component-wise join (least upper bound).
    pub fn join(&self, other: &Self) -> Self {
        Self {
            ifc_label: self.ifc_label.join(&other.ifc_label),
            capability_set: self.capability_set.join(&other.capability_set),
            budget_envelope: self.budget_envelope.join(&other.budget_envelope),
        }
    }

    /// Component-wise meet (greatest lower bound).
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            ifc_label: self.ifc_label.meet(&other.ifc_label),
            capability_set: self.capability_set.meet(&other.capability_set),
            budget_envelope: self.budget_envelope.meet(&other.budget_envelope),
        }
    }

    /// Subsumption preorder: `self` dominates `other` on every axis.
    ///
    /// Equivalent to `self.join(other) == *self`.
    pub fn subsumes(&self, other: &Self) -> bool {
        label_subsumes(&self.ifc_label, &other.ifc_label)
            && self.capability_set.subsumes(&other.capability_set)
            && self.budget_envelope.subsumes(&other.budget_envelope)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityLatticeError {
    /// `BudgetEnvelope::try_new` was called with a negative component.
    NegativeBudget,
}

impl fmt::Display for AuthorityLatticeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeBudget => f.write_str("budget components must be non-negative"),
        }
    }
}

impl std::error::Error for AuthorityLatticeError {}

// ---------------------------------------------------------------------------
// Tests — algebraic laws for the product lattice
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_a() -> CapabilitySet {
        CapabilitySet::from_iter([CapabilityKind::FsRead, CapabilityKind::NetConnect])
    }

    fn cap_b() -> CapabilitySet {
        CapabilitySet::from_iter([CapabilityKind::NetConnect, CapabilityKind::ProcSpawn])
    }

    fn budget_a() -> BudgetEnvelope {
        BudgetEnvelope::try_new(10, 20, 30, 40).unwrap()
    }

    fn budget_b() -> BudgetEnvelope {
        BudgetEnvelope::try_new(15, 5, 30, 100).unwrap()
    }

    fn lat_a() -> AuthorityLattice {
        AuthorityLattice::new(LabelClass::Internal, cap_a(), budget_a())
    }

    fn lat_b() -> AuthorityLattice {
        AuthorityLattice::new(LabelClass::Confidential, cap_b(), budget_b())
    }

    // ----- CapabilitySet -----

    #[test]
    fn capability_set_empty_is_bottom() {
        let bottom = CapabilitySet::empty();
        assert!(bottom.is_empty());
        assert_eq!(bottom.len(), 0);
    }

    #[test]
    fn capability_set_all_contains_every_kind() {
        let top = CapabilitySet::all();
        assert!(top.contains(&CapabilityKind::FsRead));
        assert!(top.contains(&CapabilityKind::RandomRead));
        // 12 known kinds.
        assert_eq!(top.len(), 12);
    }

    #[test]
    fn capability_join_is_union() {
        let joined = cap_a().join(&cap_b());
        assert!(joined.contains(&CapabilityKind::FsRead));
        assert!(joined.contains(&CapabilityKind::NetConnect));
        assert!(joined.contains(&CapabilityKind::ProcSpawn));
        assert_eq!(joined.len(), 3);
    }

    #[test]
    fn capability_meet_is_intersection() {
        let met = cap_a().meet(&cap_b());
        assert!(met.contains(&CapabilityKind::NetConnect));
        assert_eq!(met.len(), 1);
    }

    #[test]
    fn capability_subsumes_iff_superset() {
        let all = CapabilitySet::all();
        let some = cap_a();
        assert!(all.subsumes(&some));
        assert!(!some.subsumes(&all));
        assert!(some.subsumes(&CapabilitySet::empty()));
    }

    #[test]
    fn capability_join_commutative() {
        assert_eq!(cap_a().join(&cap_b()), cap_b().join(&cap_a()));
    }

    #[test]
    fn capability_join_idempotent() {
        assert_eq!(cap_a().join(&cap_a()), cap_a());
    }

    #[test]
    fn capability_meet_idempotent() {
        assert_eq!(cap_a().meet(&cap_a()), cap_a());
    }

    #[test]
    fn capability_absorption_laws() {
        // a ⊔ (a ⊓ b) = a ; a ⊓ (a ⊔ b) = a
        let lhs1 = cap_a().join(&cap_a().meet(&cap_b()));
        let lhs2 = cap_a().meet(&cap_a().join(&cap_b()));
        assert_eq!(lhs1, cap_a());
        assert_eq!(lhs2, cap_a());
    }

    // ----- BudgetEnvelope -----

    #[test]
    fn budget_try_new_rejects_negative() {
        let r = BudgetEnvelope::try_new(-1, 0, 0, 0);
        assert_eq!(r, Err(AuthorityLatticeError::NegativeBudget));
    }

    #[test]
    fn budget_bottom_is_all_zero() {
        let b = BudgetEnvelope::bottom();
        assert_eq!(b.cpu_millionths, 0);
        assert_eq!(b.memory_millionths, 0);
        assert_eq!(b.wall_time_millionths, 0);
        assert_eq!(b.io_millionths, 0);
    }

    #[test]
    fn budget_top_is_all_max() {
        let t = BudgetEnvelope::top();
        assert_eq!(t.cpu_millionths, i64::MAX);
        assert_eq!(t.io_millionths, i64::MAX);
    }

    #[test]
    fn budget_join_is_componentwise_max() {
        let j = budget_a().join(&budget_b());
        // a = (10,20,30,40); b = (15,5,30,100)
        assert_eq!(j.cpu_millionths, 15);
        assert_eq!(j.memory_millionths, 20);
        assert_eq!(j.wall_time_millionths, 30);
        assert_eq!(j.io_millionths, 100);
    }

    #[test]
    fn budget_meet_is_componentwise_min() {
        let m = budget_a().meet(&budget_b());
        assert_eq!(m.cpu_millionths, 10);
        assert_eq!(m.memory_millionths, 5);
        assert_eq!(m.wall_time_millionths, 30);
        assert_eq!(m.io_millionths, 40);
    }

    #[test]
    fn budget_subsumes_iff_all_components_dominate() {
        let larger = BudgetEnvelope::try_new(100, 100, 100, 100).unwrap();
        let smaller = BudgetEnvelope::try_new(50, 50, 50, 50).unwrap();
        assert!(larger.subsumes(&smaller));
        assert!(!smaller.subsumes(&larger));
        // Mixed dominance: neither subsumes.
        assert!(!budget_a().subsumes(&budget_b()));
        assert!(!budget_b().subsumes(&budget_a()));
    }

    // ----- AuthorityLattice (product) -----

    #[test]
    fn product_join_is_componentwise() {
        let j = lat_a().join(&lat_b());
        assert_eq!(j.ifc_label, LabelClass::Confidential);
        assert_eq!(j.capability_set, cap_a().join(&cap_b()));
        assert_eq!(j.budget_envelope, budget_a().join(&budget_b()));
    }

    #[test]
    fn product_meet_is_componentwise() {
        let m = lat_a().meet(&lat_b());
        assert_eq!(m.ifc_label, LabelClass::Internal);
        assert_eq!(m.capability_set, cap_a().meet(&cap_b()));
        assert_eq!(m.budget_envelope, budget_a().meet(&budget_b()));
    }

    #[test]
    fn product_join_commutative() {
        assert_eq!(lat_a().join(&lat_b()), lat_b().join(&lat_a()));
    }

    #[test]
    fn product_meet_commutative() {
        assert_eq!(lat_a().meet(&lat_b()), lat_b().meet(&lat_a()));
    }

    #[test]
    fn product_join_associative() {
        let c = AuthorityLattice::new(
            LabelClass::Secret,
            CapabilitySet::from_iter([CapabilityKind::Eval]),
            BudgetEnvelope::try_new(7, 11, 13, 17).unwrap(),
        );
        let lhs = lat_a().join(&lat_b()).join(&c);
        let rhs = lat_a().join(&lat_b().join(&c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn product_meet_associative() {
        let c = AuthorityLattice::new(
            LabelClass::Secret,
            CapabilitySet::from_iter([CapabilityKind::Eval]),
            BudgetEnvelope::try_new(7, 11, 13, 17).unwrap(),
        );
        let lhs = lat_a().meet(&lat_b()).meet(&c);
        let rhs = lat_a().meet(&lat_b().meet(&c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn product_join_idempotent() {
        assert_eq!(lat_a().join(&lat_a()), lat_a());
    }

    #[test]
    fn product_meet_idempotent() {
        assert_eq!(lat_a().meet(&lat_a()), lat_a());
    }

    #[test]
    fn product_absorption_join_meet() {
        // a ⊔ (a ⊓ b) = a
        let result = lat_a().join(&lat_a().meet(&lat_b()));
        assert_eq!(result, lat_a());
    }

    #[test]
    fn product_absorption_meet_join() {
        // a ⊓ (a ⊔ b) = a
        let result = lat_a().meet(&lat_a().join(&lat_b()));
        assert_eq!(result, lat_a());
    }

    #[test]
    fn product_bottom_is_identity_for_join() {
        let bot = AuthorityLattice::bottom();
        assert_eq!(lat_a().join(&bot), lat_a());
        assert_eq!(bot.join(&lat_a()), lat_a());
    }

    #[test]
    fn product_top_is_identity_for_meet() {
        let top = AuthorityLattice::top();
        assert_eq!(lat_a().meet(&top), lat_a());
        assert_eq!(top.meet(&lat_a()), lat_a());
    }

    #[test]
    fn product_bottom_join_top_is_top() {
        let top = AuthorityLattice::top();
        let bot = AuthorityLattice::bottom();
        assert_eq!(bot.join(&top), top);
    }

    #[test]
    fn product_top_meet_bottom_is_bottom() {
        let top = AuthorityLattice::top();
        let bot = AuthorityLattice::bottom();
        assert_eq!(top.meet(&bot), bot);
    }

    #[test]
    fn product_subsumes_top_dominates_all() {
        let top = AuthorityLattice::top();
        assert!(top.subsumes(&lat_a()));
        assert!(top.subsumes(&AuthorityLattice::bottom()));
    }

    #[test]
    fn product_subsumes_iff_join_is_self() {
        let big = AuthorityLattice::new(
            LabelClass::TopSecret,
            CapabilitySet::all(),
            BudgetEnvelope::try_new(1_000, 1_000, 1_000, 1_000).unwrap(),
        );
        let small = lat_a();
        // big.subsumes(small) iff big.join(small) == big
        assert!(big.subsumes(&small));
        assert_eq!(big.join(&small), big);

        // negation: lat_a does not subsume big (lower label, fewer caps, smaller budget)
        assert!(!small.subsumes(&big));
        assert_ne!(small.join(&big), small);
    }

    #[test]
    fn product_subsumes_partial_axes_does_not_imply_subsumes_overall() {
        // c dominates lat_a on label but not on capabilities.
        let c = AuthorityLattice::new(
            LabelClass::TopSecret,
            CapabilitySet::empty(),
            BudgetEnvelope::bottom(),
        );
        assert!(label_subsumes(&c.ifc_label, &lat_a().ifc_label));
        assert!(!c.subsumes(&lat_a()));
    }

    #[test]
    fn product_serde_round_trip() {
        let original = lat_a();
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: AuthorityLattice = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
    }

    #[test]
    fn capability_kind_display_is_snake_case() {
        assert_eq!(format!("{}", CapabilityKind::FsRead), "fs_read");
        assert_eq!(
            format!("{}", CapabilityKind::PolicyRequest),
            "policy_request"
        );
    }

    #[test]
    fn error_display_message() {
        let err = AuthorityLatticeError::NegativeBudget;
        assert!(format!("{err}").contains("non-negative"));
    }

    // -----------------------------------------------------------------------
    // bd-cixqu.26.2 — unified join/meet/subsumption proofs over the product
    //
    // The tests above prove the algebraic laws on a single representative
    // pair (lat_a, lat_b). The tests below extend the proofs to:
    //   * deterministic sweeps over a fixture matrix of triples (covers
    //     distributivity and the lattice axioms across more combinations);
    //   * partial-order laws for the `subsumes` preorder (reflexivity,
    //     transitivity, antisymmetry);
    //   * cross-axis interaction laws (a join b is the unique LUB; a meet b
    //     is the unique GLB; subsumes is the natural preorder).
    //
    // These tests treat per-axis lattices as corollaries of the product
    // lattice proofs: every law verified on the product is also verified
    // on the underlying axes (because the product's components ARE the
    // axes' elements).
    // -----------------------------------------------------------------------

    fn fixture_matrix() -> Vec<AuthorityLattice> {
        vec![
            AuthorityLattice::bottom(),
            AuthorityLattice::new(
                LabelClass::Public,
                CapabilitySet::from_iter([CapabilityKind::FsRead]),
                BudgetEnvelope::try_new(1, 2, 3, 4).unwrap(),
            ),
            lat_a(),
            lat_b(),
            AuthorityLattice::new(
                LabelClass::Confidential,
                CapabilitySet::from_iter([
                    CapabilityKind::FsRead,
                    CapabilityKind::ClockRead,
                    CapabilityKind::RandomRead,
                ]),
                BudgetEnvelope::try_new(50, 60, 70, 80).unwrap(),
            ),
            AuthorityLattice::new(
                LabelClass::Secret,
                CapabilitySet::from_iter([CapabilityKind::Eval, CapabilityKind::PolicyRequest]),
                BudgetEnvelope::try_new(0, 100, 200, 0).unwrap(),
            ),
            AuthorityLattice::new(
                LabelClass::TopSecret,
                CapabilitySet::all(),
                BudgetEnvelope::try_new(1_000, 1_000, 1_000, 1_000).unwrap(),
            ),
            AuthorityLattice::top(),
        ]
    }

    // ----- Subsumes preorder laws -----

    #[test]
    fn subsumes_is_reflexive_for_all_fixtures() {
        for x in &fixture_matrix() {
            assert!(x.subsumes(x), "subsumes failed reflexivity on {:?}", x);
        }
    }

    #[test]
    fn subsumes_is_transitive_for_all_triples() {
        let fixtures = fixture_matrix();
        for (i, a) in fixtures.iter().enumerate() {
            for (j, b) in fixtures.iter().enumerate() {
                for (k, c) in fixtures.iter().enumerate() {
                    if a.subsumes(b) && b.subsumes(c) {
                        assert!(
                            a.subsumes(c),
                            "transitivity violated at indices ({}, {}, {})",
                            i,
                            j,
                            k
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn subsumes_is_antisymmetric_for_all_pairs() {
        let fixtures = fixture_matrix();
        for (i, a) in fixtures.iter().enumerate() {
            for (j, b) in fixtures.iter().enumerate() {
                if a.subsumes(b) && b.subsumes(a) {
                    assert_eq!(
                        a, b,
                        "antisymmetry violated at indices ({}, {}); a={:?}, b={:?}",
                        i, j, a, b
                    );
                }
            }
        }
    }

    // ----- Join/meet equivalence laws -----

    #[test]
    fn subsumes_iff_join_is_self_across_all_pairs() {
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                let subsumes_holds = a.subsumes(b);
                let join_is_self = a.join(b) == *a;
                assert_eq!(
                    subsumes_holds, join_is_self,
                    "subsumes vs. join-is-self diverged for a={:?}, b={:?}",
                    a, b
                );
            }
        }
    }

    #[test]
    fn subsumes_iff_meet_is_other_across_all_pairs() {
        // Dual law: a.subsumes(b) iff a.meet(b) == b
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                let subsumes_holds = a.subsumes(b);
                let meet_is_other = a.meet(b) == *b;
                assert_eq!(
                    subsumes_holds, meet_is_other,
                    "subsumes vs. meet-is-other diverged for a={:?}, b={:?}",
                    a, b
                );
            }
        }
    }

    // ----- Bounded-lattice laws across the matrix -----

    #[test]
    fn bottom_subsumed_by_everything() {
        let bot = AuthorityLattice::bottom();
        for a in &fixture_matrix() {
            assert!(a.subsumes(&bot), "{:?} should subsume bottom", a);
        }
    }

    #[test]
    fn top_subsumes_everything() {
        let top = AuthorityLattice::top();
        for a in &fixture_matrix() {
            assert!(top.subsumes(a), "top should subsume {:?}", a);
        }
    }

    // ----- Commutativity / associativity / idempotency across the matrix -----

    #[test]
    fn join_commutative_across_matrix() {
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                assert_eq!(a.join(b), b.join(a));
            }
        }
    }

    #[test]
    fn meet_commutative_across_matrix() {
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                assert_eq!(a.meet(b), b.meet(a));
            }
        }
    }

    #[test]
    fn join_associative_across_matrix() {
        let fixtures = fixture_matrix();
        for a in &fixtures {
            for b in &fixtures {
                for c in &fixtures {
                    assert_eq!(a.join(b).join(c), a.join(&b.join(c)));
                }
            }
        }
    }

    #[test]
    fn meet_associative_across_matrix() {
        let fixtures = fixture_matrix();
        for a in &fixtures {
            for b in &fixtures {
                for c in &fixtures {
                    assert_eq!(a.meet(b).meet(c), a.meet(&b.meet(c)));
                }
            }
        }
    }

    #[test]
    fn join_idempotent_across_matrix() {
        for a in &fixture_matrix() {
            assert_eq!(a.join(a), *a);
        }
    }

    #[test]
    fn meet_idempotent_across_matrix() {
        for a in &fixture_matrix() {
            assert_eq!(a.meet(a), *a);
        }
    }

    // ----- Absorption across the matrix -----

    #[test]
    fn absorption_join_meet_across_matrix() {
        // a ⊔ (a ⊓ b) = a
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                assert_eq!(a.join(&a.meet(b)), *a);
            }
        }
    }

    #[test]
    fn absorption_meet_join_across_matrix() {
        // a ⊓ (a ⊔ b) = a
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                assert_eq!(a.meet(&a.join(b)), *a);
            }
        }
    }

    // ----- Distributivity -----
    //
    // The product lattice is distributive iff each component lattice is
    // distributive. LabelClass is a chain (totally ordered) — chains are
    // always distributive. CapabilitySet is a powerset under ⊆ — powersets
    // are always distributive. BudgetEnvelope is a product of chains
    // (max/min on i64) — also distributive. So the product is distributive.

    #[test]
    fn join_distributes_over_meet_across_matrix() {
        // a ⊔ (b ⊓ c) = (a ⊔ b) ⊓ (a ⊔ c)
        let fixtures = fixture_matrix();
        for a in &fixtures {
            for b in &fixtures {
                for c in &fixtures {
                    let lhs = a.join(&b.meet(c));
                    let rhs = a.join(b).meet(&a.join(c));
                    assert_eq!(
                        lhs, rhs,
                        "join-over-meet distributivity violated for a={:?} b={:?} c={:?}",
                        a, b, c
                    );
                }
            }
        }
    }

    #[test]
    fn meet_distributes_over_join_across_matrix() {
        // a ⊓ (b ⊔ c) = (a ⊓ b) ⊔ (a ⊓ c)
        let fixtures = fixture_matrix();
        for a in &fixtures {
            for b in &fixtures {
                for c in &fixtures {
                    let lhs = a.meet(&b.join(c));
                    let rhs = a.meet(b).join(&a.meet(c));
                    assert_eq!(
                        lhs, rhs,
                        "meet-over-join distributivity violated for a={:?} b={:?} c={:?}",
                        a, b, c
                    );
                }
            }
        }
    }

    // ----- LUB / GLB universal properties -----

    #[test]
    fn join_is_upper_bound_across_matrix() {
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                let j = a.join(b);
                assert!(j.subsumes(a), "join not upper bound of a");
                assert!(j.subsumes(b), "join not upper bound of b");
            }
        }
    }

    #[test]
    fn join_is_least_upper_bound_across_matrix() {
        // For every upper bound u of {a, b}, u must subsume the join.
        let fixtures = fixture_matrix();
        for a in &fixtures {
            for b in &fixtures {
                let j = a.join(b);
                for u in &fixtures {
                    if u.subsumes(a) && u.subsumes(b) {
                        assert!(
                            u.subsumes(&j),
                            "join is not LEAST upper bound: {:?} upper-bounds both but not the join",
                            u
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn meet_is_lower_bound_across_matrix() {
        for a in &fixture_matrix() {
            for b in &fixture_matrix() {
                let m = a.meet(b);
                assert!(a.subsumes(&m), "meet not lower bound of a");
                assert!(b.subsumes(&m), "meet not lower bound of b");
            }
        }
    }

    #[test]
    fn meet_is_greatest_lower_bound_across_matrix() {
        // For every lower bound l of {a, b}, the meet must subsume l.
        let fixtures = fixture_matrix();
        for a in &fixtures {
            for b in &fixtures {
                let m = a.meet(b);
                for l in &fixtures {
                    if a.subsumes(l) && b.subsumes(l) {
                        assert!(
                            m.subsumes(l),
                            "meet is not GREATEST lower bound: {:?} lower-bounds both but the meet doesn't subsume it",
                            l
                        );
                    }
                }
            }
        }
    }

    // ----- Per-axis corollary checks -----
    //
    // Per-axis laws are now derivable as projections of the product laws,
    // but we keep direct checks as smoke tests for the axis types in
    // isolation.

    #[test]
    fn ifc_axis_is_chain_lattice() {
        // LabelClass is totally ordered; for any two labels, one subsumes
        // the other.
        let labels = [
            LabelClass::Public,
            LabelClass::Internal,
            LabelClass::Confidential,
            LabelClass::Secret,
            LabelClass::TopSecret,
        ];
        for a in &labels {
            for b in &labels {
                assert!(label_subsumes(a, b) || label_subsumes(b, a));
            }
        }
    }

    #[test]
    fn capability_axis_subsumes_is_partial_order() {
        let sets = [
            CapabilitySet::empty(),
            CapabilitySet::from_iter([CapabilityKind::FsRead]),
            CapabilitySet::from_iter([CapabilityKind::FsRead, CapabilityKind::NetConnect]),
            CapabilitySet::all(),
        ];
        for a in &sets {
            // reflexivity
            assert!(a.subsumes(a));
        }
        // antisymmetry: a ⊆ b ∧ b ⊆ a ⟹ a == b
        for a in &sets {
            for b in &sets {
                if a.subsumes(b) && b.subsumes(a) {
                    assert_eq!(a, b);
                }
            }
        }
    }

    #[test]
    fn budget_axis_subsumes_is_partial_order() {
        let envelopes = [
            BudgetEnvelope::bottom(),
            BudgetEnvelope::try_new(10, 20, 30, 40).unwrap(),
            BudgetEnvelope::try_new(50, 50, 50, 50).unwrap(),
            BudgetEnvelope::top(),
        ];
        for a in &envelopes {
            assert!(a.subsumes(a));
        }
        for a in &envelopes {
            for b in &envelopes {
                if a.subsumes(b) && b.subsumes(a) {
                    assert_eq!(a, b);
                }
            }
        }
    }
}
