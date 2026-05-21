#![forbid(unsafe_code)]

//! Typed effect-set annotation for IR2 function/method nodes.
//!
//! This module is the FE-CLAIM-006 (Track C) contract surface for capability-
//! narrowing. Every function and method node in IR2 is annotated with the
//! typed [`EffectSet`] it requires. The lowering pipeline computes the set
//! at IR2-lowering time using the declared closure-inheritance policy:
//! a closure inherits the calling scope's `EffectSet` unless an explicit
//! `declare_capability` annotation widens or restricts it.
//!
//! Determinism rules:
//! - Effects are a small finite enum ([`EffectKind`]) — there is no open
//!   string namespace; a new effect requires a code change so the typing
//!   stays under static review.
//! - The set is backed by `BTreeSet<EffectKind>` to give deterministic
//!   iteration order in canonical-bytes encoding.
//! - Canonical bytes are length-prefixed: a u32 BE count of effects, then
//!   one byte per effect (its discriminant), in sorted order. Two sets
//!   with the same effects produce byte-identical canonical bytes.
//!
//! Bead: bd-cixqu.3.1 (FE-CLAIM-006, Track C).
//!
//! This module defines the type contract and exercises it with unit tests.
//! Wiring `EffectSet` into IR2 function/method descriptors at lowering
//! time (and the integration with the red-team scenario corpus) is the
//! scope of the follow-up beads bd-cixqu.3.2 (lowering-side rejection)
//! and bd-cixqu.3.4 (gate script + replay wrapper). Landing the type here
//! first lets those follow-ups depend on a stable contract.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Canonical effects the runtime distinguishes for capability narrowing.
///
/// The discriminant is part of the canonical-bytes contract: changes here
/// are schema-evolution events and must increment the IR2 schema version.
/// Additions go at the end of the enum to keep older discriminants stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum EffectKind {
    /// Read access to the host filesystem (`fs.read`).
    FsRead = 0,
    /// Write access to the host filesystem (`fs.write`).
    FsWrite = 1,
    /// Outbound network connection (`net.connect`).
    NetConnect = 2,
    /// Inbound network bind / listen (`net.listen`).
    NetListen = 3,
    /// Spawn a subprocess (`proc.spawn`).
    ProcSpawn = 4,
    /// Read ambient host environment (`env.read`).
    EnvRead = 5,
    /// Mutate ambient host environment (`env.write`).
    EnvWrite = 6,
    /// Submit a policy-decision request (`policy.request`).
    PolicyRequest = 7,
    /// Runtime-compile attacker-supplied source (`runtime.eval`).
    Eval = 8,
    /// Reach the global object as ambient authority (`runtime.global`).
    Global = 9,
    /// Read the wall clock or monotonic timer (`clock.read`).
    ClockRead = 10,
    /// Read or seed the host CSPRNG (`random.read`).
    RandomRead = 11,
}

impl EffectKind {
    /// All variants in declaration order. New variants append at the end —
    /// schema bumps required.
    pub const ALL: [Self; 12] = [
        Self::FsRead,
        Self::FsWrite,
        Self::NetConnect,
        Self::NetListen,
        Self::ProcSpawn,
        Self::EnvRead,
        Self::EnvWrite,
        Self::PolicyRequest,
        Self::Eval,
        Self::Global,
        Self::ClockRead,
        Self::RandomRead,
    ];

    /// Stable string id used in claim-to-proof matrix entries and
    /// diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::NetConnect => "net.connect",
            Self::NetListen => "net.listen",
            Self::ProcSpawn => "proc.spawn",
            Self::EnvRead => "env.read",
            Self::EnvWrite => "env.write",
            Self::PolicyRequest => "policy.request",
            Self::Eval => "runtime.eval",
            Self::Global => "runtime.global",
            Self::ClockRead => "clock.read",
            Self::RandomRead => "random.read",
        }
    }

    /// Discriminant as the canonical single-byte encoding.
    pub const fn discriminant(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for EffectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a function node's effect set is derived at IR2-lowering time.
///
/// The policy is recorded alongside the resolved [`EffectSet`] so a future
/// audit can tell whether a function's authority was wider than its
/// declarator intended (e.g. an `Inherited` policy that ends up empty
/// because the calling scope was empty, vs. an explicitly empty
/// `Declared`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectPolicy {
    /// The function has no declared capabilities and was assigned an empty
    /// effect set at lowering time. The default for top-level scripts that
    /// do not opt into any capability surface.
    Empty,
    /// The function inherits its calling scope's effect set. The default
    /// for closures whose declarator does not explicitly narrow or widen.
    Inherited,
    /// The function declared its effect set explicitly via a manifest /
    /// in-source annotation. The set may be empty (narrow declaration) or
    /// non-empty (positive opt-in).
    Declared,
}

impl EffectPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Inherited => "inherited",
            Self::Declared => "declared",
        }
    }
}

impl fmt::Display for EffectPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Set of typed effects a function/method requires.
///
/// Backed by `BTreeSet<EffectKind>` for deterministic iteration order
/// (avoids the documented HashMap/HashSet hazard for content-hashed
/// outputs). The canonical-bytes encoding is `u32` BE count + one byte
/// per effect (discriminant), in sorted order.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EffectSet {
    effects: BTreeSet<EffectKind>,
}

impl EffectSet {
    /// Construct the empty effect set (no required capabilities).
    pub const fn new() -> Self {
        Self {
            effects: BTreeSet::new(),
        }
    }

    /// Construct from an iterator of effects. Duplicates are deduplicated by
    /// the underlying BTreeSet.
    pub fn from_iter_of<I: IntoIterator<Item = EffectKind>>(iter: I) -> Self {
        let mut set = Self::new();
        for effect in iter {
            set.insert(effect);
        }
        set
    }

    /// Insert an effect; returns `true` if the set did not already contain it.
    pub fn insert(&mut self, effect: EffectKind) -> bool {
        self.effects.insert(effect)
    }

    /// Whether the set contains the given effect.
    pub fn contains(&self, effect: EffectKind) -> bool {
        self.effects.contains(&effect)
    }

    /// Number of distinct effects.
    pub fn len(&self) -> usize {
        self.effects.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// Iterate effects in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = EffectKind> + '_ {
        self.effects.iter().copied()
    }

    /// Set union; the result contains every effect appearing in either side.
    pub fn union(&self, other: &Self) -> Self {
        Self {
            effects: self.effects.union(&other.effects).copied().collect(),
        }
    }

    /// Set intersection.
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            effects: self.effects.intersection(&other.effects).copied().collect(),
        }
    }

    /// Whether `self` is a subset of `other` — i.e. `other` is wide enough
    /// to satisfy `self`. Used by the lowering pass: a callee's required
    /// effects must be a subset of the calling scope's declared effects.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.effects.is_subset(&other.effects)
    }

    /// Whether `self` strictly widens over `other` (proper superset).
    /// Used by the lowering pass: a callee whose effect set strictly
    /// widens its caller's declared set is the canonical fail-closed case.
    pub fn widens(&self, other: &Self) -> bool {
        other.effects.is_subset(&self.effects) && self.effects != other.effects
    }

    /// Canonical-bytes encoding: `u32` BE count, then one byte per effect
    /// (discriminant) in sorted order. Two sets with the same effects
    /// produce byte-identical output.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let count = u32::try_from(self.effects.len()).unwrap_or(u32::MAX);
        let mut buf = Vec::with_capacity(4 + self.effects.len());
        buf.extend_from_slice(&count.to_be_bytes());
        for effect in &self.effects {
            buf.push(effect.discriminant());
        }
        buf
    }
}

impl fmt::Display for EffectSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "∅")
        } else {
            write!(f, "{{")?;
            let mut first = true;
            for effect in self.iter() {
                if !first {
                    write!(f, ", ")?;
                }
                write!(f, "{}", effect)?;
                first = false;
            }
            write!(f, "}}")
        }
    }
}

/// Function/method node's resolved effect annotation. Pairs the
/// [`EffectSet`] computed at IR2-lowering time with the [`EffectPolicy`]
/// that produced it.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EffectAnnotation {
    pub policy: EffectPolicy,
    pub effects: EffectSet,
}

impl EffectAnnotation {
    /// Empty declaration: explicit opt-out from any capability surface.
    pub const fn empty() -> Self {
        Self {
            policy: EffectPolicy::Empty,
            effects: EffectSet::new(),
        }
    }

    /// Inherited from the calling scope. Default for closures whose
    /// declarator does not narrow.
    pub fn inherited(caller: &EffectSet) -> Self {
        Self {
            policy: EffectPolicy::Inherited,
            effects: caller.clone(),
        }
    }

    /// Declared explicitly by manifest / in-source annotation.
    pub fn declared(effects: EffectSet) -> Self {
        Self {
            policy: EffectPolicy::Declared,
            effects,
        }
    }

    /// Canonical-bytes encoding: one byte for the policy discriminant,
    /// then the underlying [`EffectSet`] canonical bytes (length-prefixed).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + self.effects.len());
        buf.push(self.policy as u8);
        buf.extend_from_slice(&self.effects.canonical_bytes());
        buf
    }
}

impl Default for EffectPolicy {
    fn default() -> Self {
        Self::Empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== EffectKind =====

    #[test]
    fn effect_kind_all_count_matches_variants() {
        assert_eq!(EffectKind::ALL.len(), 12);
    }

    #[test]
    fn effect_kind_discriminants_are_unique_and_dense() {
        let mut seen = BTreeSet::new();
        for effect in EffectKind::ALL {
            let d = effect.discriminant();
            assert!(seen.insert(d), "duplicate discriminant {d} for {effect:?}");
            assert!(d < EffectKind::ALL.len() as u8);
        }
    }

    #[test]
    fn effect_kind_as_str_values_are_unique_and_namespaced() {
        let mut seen = BTreeSet::new();
        for effect in EffectKind::ALL {
            let s = effect.as_str();
            assert!(s.contains('.'), "{effect:?} as_str should be namespaced");
            assert!(seen.insert(s), "duplicate as_str {s}");
        }
    }

    #[test]
    fn effect_kind_serde_round_trip_is_snake_case() {
        let json = serde_json::to_string(&EffectKind::ProcSpawn).unwrap();
        assert_eq!(json, "\"proc_spawn\"");
        let back: EffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, EffectKind::ProcSpawn);
    }

    // ===== EffectSet — basics =====

    #[test]
    fn empty_effect_set_is_empty() {
        let s = EffectSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.contains(EffectKind::FsRead));
    }

    #[test]
    fn insert_returns_true_on_new_effect_and_false_on_duplicate() {
        let mut s = EffectSet::new();
        assert!(s.insert(EffectKind::FsRead));
        assert!(!s.insert(EffectKind::FsRead));
        assert!(s.contains(EffectKind::FsRead));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn from_iter_of_deduplicates() {
        let s = EffectSet::from_iter_of([
            EffectKind::FsRead,
            EffectKind::FsRead,
            EffectKind::NetConnect,
        ]);
        assert_eq!(s.len(), 2);
        assert!(s.contains(EffectKind::FsRead));
        assert!(s.contains(EffectKind::NetConnect));
    }

    #[test]
    fn iter_yields_effects_in_sorted_order() {
        let s =
            EffectSet::from_iter_of([EffectKind::Eval, EffectKind::FsRead, EffectKind::NetConnect]);
        let collected: Vec<_> = s.iter().collect();
        // EffectKind derives Ord; FsRead (0) < NetConnect (2) < Eval (8).
        assert_eq!(
            collected,
            vec![EffectKind::FsRead, EffectKind::NetConnect, EffectKind::Eval]
        );
    }

    // ===== EffectSet — set algebra =====

    #[test]
    fn union_combines_distinct_effects() {
        let a = EffectSet::from_iter_of([EffectKind::FsRead]);
        let b = EffectSet::from_iter_of([EffectKind::NetConnect]);
        let u = a.union(&b);
        assert_eq!(u.len(), 2);
        assert!(u.contains(EffectKind::FsRead));
        assert!(u.contains(EffectKind::NetConnect));
    }

    #[test]
    fn union_with_self_is_identity() {
        let a = EffectSet::from_iter_of([EffectKind::FsRead, EffectKind::NetConnect]);
        assert_eq!(a.union(&a), a);
    }

    #[test]
    fn intersection_keeps_only_common_effects() {
        let a = EffectSet::from_iter_of([EffectKind::FsRead, EffectKind::Eval]);
        let b = EffectSet::from_iter_of([EffectKind::Eval, EffectKind::ProcSpawn]);
        let i = a.intersection(&b);
        assert_eq!(i.len(), 1);
        assert!(i.contains(EffectKind::Eval));
    }

    #[test]
    fn is_subset_holds_for_empty_against_any() {
        let any = EffectSet::from_iter_of([EffectKind::FsRead]);
        assert!(EffectSet::new().is_subset(&any));
    }

    #[test]
    fn is_subset_holds_for_equal_sets() {
        let a = EffectSet::from_iter_of([EffectKind::FsRead, EffectKind::NetConnect]);
        let b = a.clone();
        assert!(a.is_subset(&b));
        assert!(b.is_subset(&a));
    }

    #[test]
    fn is_subset_rejects_when_callee_widens_caller() {
        let caller = EffectSet::from_iter_of([EffectKind::FsRead]);
        let callee = EffectSet::from_iter_of([EffectKind::FsRead, EffectKind::Eval]);
        assert!(!callee.is_subset(&caller));
    }

    #[test]
    fn widens_detects_proper_superset_only() {
        let narrow = EffectSet::from_iter_of([EffectKind::FsRead]);
        let wide = EffectSet::from_iter_of([EffectKind::FsRead, EffectKind::Eval]);
        assert!(wide.widens(&narrow));
        assert!(!narrow.widens(&wide));
        // Equal sets do not widen.
        assert!(!narrow.widens(&narrow));
    }

    // ===== EffectSet — canonical bytes =====

    #[test]
    fn canonical_bytes_for_empty_set_is_four_zero_bytes() {
        let bytes = EffectSet::new().canonical_bytes();
        assert_eq!(bytes, vec![0, 0, 0, 0]);
    }

    #[test]
    fn canonical_bytes_includes_u32_be_count_prefix() {
        let s = EffectSet::from_iter_of([EffectKind::FsRead]);
        let bytes = s.canonical_bytes();
        assert_eq!(&bytes[..4], &1u32.to_be_bytes());
        assert_eq!(bytes[4], EffectKind::FsRead.discriminant());
    }

    #[test]
    fn canonical_bytes_is_deterministic_under_insertion_reorder() {
        let a =
            EffectSet::from_iter_of([EffectKind::Eval, EffectKind::FsRead, EffectKind::NetConnect]);
        let b =
            EffectSet::from_iter_of([EffectKind::NetConnect, EffectKind::Eval, EffectKind::FsRead]);
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_differ_when_effects_differ() {
        let a = EffectSet::from_iter_of([EffectKind::FsRead]);
        let b = EffectSet::from_iter_of([EffectKind::FsWrite]);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    // ===== EffectSet — serde =====

    #[test]
    fn effect_set_serde_round_trip() {
        let s = EffectSet::from_iter_of([EffectKind::FsRead, EffectKind::Eval]);
        let json = serde_json::to_string(&s).unwrap();
        let back: EffectSet = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ===== EffectAnnotation =====

    #[test]
    fn empty_annotation_is_empty_policy_and_empty_set() {
        let ann = EffectAnnotation::empty();
        assert_eq!(ann.policy, EffectPolicy::Empty);
        assert!(ann.effects.is_empty());
    }

    #[test]
    fn inherited_annotation_clones_caller_set() {
        let caller = EffectSet::from_iter_of([EffectKind::FsRead, EffectKind::Eval]);
        let ann = EffectAnnotation::inherited(&caller);
        assert_eq!(ann.policy, EffectPolicy::Inherited);
        assert_eq!(ann.effects, caller);
    }

    #[test]
    fn declared_annotation_preserves_explicit_effects() {
        let effects = EffectSet::from_iter_of([EffectKind::PolicyRequest]);
        let ann = EffectAnnotation::declared(effects.clone());
        assert_eq!(ann.policy, EffectPolicy::Declared);
        assert_eq!(ann.effects, effects);
    }

    #[test]
    fn declared_annotation_with_empty_set_is_distinguishable_from_empty_policy() {
        // Both have an empty effect set, but the *policy* differs: one was
        // explicitly opted-out, the other declared narrowness positively.
        // Canonical bytes must distinguish them so audit can tell which
        // declarator produced the set.
        let opt_out = EffectAnnotation::empty();
        let narrow = EffectAnnotation::declared(EffectSet::new());
        assert_ne!(opt_out.canonical_bytes(), narrow.canonical_bytes());
    }

    #[test]
    fn annotation_canonical_bytes_round_trip_through_serde() {
        let ann = EffectAnnotation::declared(EffectSet::from_iter_of([
            EffectKind::NetConnect,
            EffectKind::FsWrite,
        ]));
        let json = serde_json::to_string(&ann).unwrap();
        let back: EffectAnnotation = serde_json::from_str(&json).unwrap();
        assert_eq!(ann, back);
        assert_eq!(ann.canonical_bytes(), back.canonical_bytes());
    }

    // ===== Policy strings =====

    #[test]
    fn effect_policy_as_str_matches_snake_case_variants() {
        assert_eq!(EffectPolicy::Empty.as_str(), "empty");
        assert_eq!(EffectPolicy::Inherited.as_str(), "inherited");
        assert_eq!(EffectPolicy::Declared.as_str(), "declared");
    }

    #[test]
    fn effect_policy_display_matches_as_str() {
        for policy in [
            EffectPolicy::Empty,
            EffectPolicy::Inherited,
            EffectPolicy::Declared,
        ] {
            assert_eq!(format!("{policy}"), policy.as_str());
        }
    }
}
