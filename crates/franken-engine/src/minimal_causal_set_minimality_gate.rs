//! Minimal-causal-set minimality verification gate — Track FF.5 (bd-cixqu.32.5).
//!
//! [`MinimalCausalSet`](crate::minimal_causal_set_inference::MinimalCausalSet)
//! (FF.1) carries the forensic *claim* that it is minimal — "removing any
//! element would change the decision outcome". That set is produced by a greedy
//! heuristic at decision time; nothing re-checks the claim once the set is
//! serialized, replayed, or handed to a forensic operator. A tampered or
//! hand-built set could assert minimality it does not possess.
//!
//! This gate **proves or refuses** the minimality claim of a causal set without
//! trusting its producer. It offers two verification modes:
//!
//! * **Structural** ([`verify_structural_minimality`]) — the single-cover
//!   invariant that FF.1's greedy minimizer is contractually required to
//!   produce: every influenced [`DecisionFactor`] is covered by exactly one
//!   retained atom. If a factor is covered by two or more atoms, none of them is
//!   individually necessary for that factor's coverage, so at least one is
//!   redundant and the set is not minimal. Also enforces the structural
//!   consistency / tamper invariants (declared size, considered-count bound, and
//!   the content-hash binding over the dependency vector).
//!
//! * **Counterfactual** ([`verify_minimality_with_oracle`]) — the literal
//!   definition: with a leave-one-out re-decision oracle, removing any atom must
//!   change the recorded outcome. An atom whose removal leaves the outcome
//!   unchanged is not necessary, so the set is not minimal.
//!
//! Both modes are fail-closed: any violation is reported as an ordered,
//! specific [`MinimalityViolation`] rather than silently accepted. A successful
//! verification returns a content-addressed [`MinimalityProof`].
//!
//! Plan reference: bd-cixqu.32.5 (FF.5), bd-cixqu.32 (Track FF parent).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::minimal_causal_set_inference::{CausalDependency, DecisionFactor, MinimalCausalSet};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for minimality verification proofs.
pub const MINIMALITY_GATE_SCHEMA_VERSION: &str = "franken-engine.causal-set-minimality.v1";
/// Component name for evidence linkage.
pub const MINIMALITY_GATE_COMPONENT: &str = "minimal_causal_set_minimality_gate";
/// Policy ID binding for this gate.
pub const MINIMALITY_GATE_POLICY_ID: &str = "FF-5";
/// Domain separator for minimality proof hashes.
pub const MINIMALITY_PROOF_DOMAIN: &str = "franken-engine.causal-set-minimality.proof.v1";

// ---------------------------------------------------------------------------
// Verification mode
// ---------------------------------------------------------------------------

/// Which definition of minimality a [`MinimalityProof`] was established under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Single-cover structural invariant (FF.1 greedy contract).
    Structural,
    /// Counterfactual leave-one-out re-decision oracle.
    Counterfactual,
}

impl fmt::Display for VerificationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Structural => "structural",
            Self::Counterfactual => "counterfactual",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Violations — fail-closed, ordered refusal reasons
// ---------------------------------------------------------------------------

/// Reasons a causal set's minimality claim is refused.
///
/// Checks are applied in a fixed order so that, when multiple invariants are
/// violated, the reported reason is deterministic. The order is:
/// [`SizeMismatch`](MinimalityViolation::SizeMismatch) →
/// [`OversizedClaim`](MinimalityViolation::OversizedClaim) →
/// [`ContentHashMismatch`](MinimalityViolation::ContentHashMismatch) →
/// [`RedundantAtom`](MinimalityViolation::RedundantAtom) /
/// [`AtomNotNecessary`](MinimalityViolation::AtomNotNecessary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinimalityViolation {
    /// The declared `minimal_set_size` disagrees with the actual dependency count.
    SizeMismatch {
        /// The size the set claims to have.
        declared: u64,
        /// The number of dependencies actually present.
        actual: u64,
    },
    /// The minimal set claims more atoms than were ever considered.
    OversizedClaim {
        /// Declared minimal-set size.
        minimal_set_size: u64,
        /// Total evidence atoms considered before minimization.
        total_considered: u64,
    },
    /// The stored `causal_set_hash` does not match the dependency vector,
    /// indicating tampering or an inconsistent producer.
    ContentHashMismatch {
        /// The hash recorded on the set.
        declared: ContentHash,
        /// The hash recomputed from the dependency vector.
        recomputed: ContentHash,
    },
    /// A decision factor is covered by more than one retained atom, so no single
    /// atom is necessary for that factor's coverage (structural mode).
    RedundantAtom {
        /// The over-covered decision factor.
        factor: DecisionFactor,
        /// How many retained atoms cover this factor (>= 2).
        cover_count: u64,
    },
    /// Removing this atom left the decision outcome unchanged, so it was not
    /// necessary to the recorded outcome (counterfactual mode).
    AtomNotNecessary {
        /// The evidence atom whose removal did not change the outcome.
        evidence_atom_id: String,
        /// The factor that atom influenced.
        factor: DecisionFactor,
    },
}

impl fmt::Display for MinimalityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeMismatch { declared, actual } => write!(
                f,
                "declared minimal_set_size {declared} != actual dependency count {actual}"
            ),
            Self::OversizedClaim {
                minimal_set_size,
                total_considered,
            } => write!(
                f,
                "minimal_set_size {minimal_set_size} exceeds total atoms considered {total_considered}"
            ),
            Self::ContentHashMismatch {
                declared,
                recomputed,
            } => write!(
                f,
                "causal_set_hash mismatch: declared {declared:?} != recomputed {recomputed:?}"
            ),
            Self::RedundantAtom {
                factor,
                cover_count,
            } => write!(
                f,
                "factor {factor} is covered by {cover_count} atoms; minimality requires exactly one"
            ),
            Self::AtomNotNecessary {
                evidence_atom_id,
                factor,
            } => write!(
                f,
                "removing atom {evidence_atom_id} (factor {factor}) did not change the outcome"
            ),
        }
    }
}

impl std::error::Error for MinimalityViolation {}

// ---------------------------------------------------------------------------
// Proof — content-addressed minimality certificate
// ---------------------------------------------------------------------------

/// A certificate that a [`MinimalCausalSet`] is minimal under [`VerificationMode`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalityProof {
    /// Schema version this proof was emitted under.
    pub schema_version: String,
    /// The causal-set identifier the proof applies to.
    pub causal_set_id: String,
    /// The decision identifier the causal set explains.
    pub decision_id: String,
    /// The definition of minimality that was verified.
    pub verification_mode: VerificationMode,
    /// Number of atoms retained in the verified minimal set.
    pub verified_atom_count: u64,
    /// The set of decision factors the minimal set covers (sorted, deduplicated).
    pub covered_factors: BTreeSet<DecisionFactor>,
    /// The content hash of the dependency vector that was verified (binds the
    /// proof to the exact set contents).
    pub verified_set_hash: ContentHash,
    /// Content-addressed hash certifying this proof.
    pub proof_hash: ContentHash,
}

impl MinimalityProof {
    /// Construct a proof and compute its content-addressed hash.
    fn new(
        set: &MinimalCausalSet,
        mode: VerificationMode,
        covered_factors: BTreeSet<DecisionFactor>,
    ) -> Self {
        let mut proof = Self {
            schema_version: MINIMALITY_GATE_SCHEMA_VERSION.to_string(),
            causal_set_id: set.causal_set_id.clone(),
            decision_id: set.decision_id.clone(),
            verification_mode: mode,
            verified_atom_count: set.dependencies.len() as u64,
            covered_factors,
            verified_set_hash: set.causal_set_hash,
            proof_hash: ContentHash::from_bytes([0u8; 32]),
        };
        proof.proof_hash = proof.compute_proof_hash();
        proof
    }

    /// Compute the content-addressed hash binding the proof's claims.
    ///
    /// The preimage is a domain-separated, deterministic serialization of every
    /// field except `proof_hash` itself, so the hash is stable across platforms
    /// and re-derivable by any verifier.
    fn compute_proof_hash(&self) -> ContentHash {
        let mut preimage = Vec::new();
        push_field(&mut preimage, MINIMALITY_PROOF_DOMAIN.as_bytes());
        push_field(&mut preimage, self.schema_version.as_bytes());
        push_field(&mut preimage, self.causal_set_id.as_bytes());
        push_field(&mut preimage, self.decision_id.as_bytes());
        push_field(&mut preimage, self.verification_mode.to_string().as_bytes());
        push_field(&mut preimage, &self.verified_atom_count.to_be_bytes());
        for factor in &self.covered_factors {
            push_field(&mut preimage, factor.to_string().as_bytes());
        }
        push_field(&mut preimage, self.verified_set_hash.as_bytes());
        ContentHash::compute(&preimage)
    }

    /// Re-verify this proof's content-addressed hash against its own fields.
    pub fn verify_self_hash(&self) -> bool {
        self.proof_hash == self.compute_proof_hash()
    }
}

/// Append a length-prefixed field to a signing/hashing preimage so that
/// concatenations are unambiguous (prefix-free framing).
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// Structural invariants shared by both modes
// ---------------------------------------------------------------------------

/// Recompute the content hash of a dependency vector the same way
/// [`MinimalCausalSet::new`] does, for tamper detection.
fn recompute_set_hash(dependencies: &[CausalDependency]) -> ContentHash {
    let serialized =
        serde_json::to_vec(dependencies).expect("causal dependencies serialization should succeed");
    ContentHash::compute(&serialized)
}

/// Run the producer-independent consistency / tamper checks that must hold
/// before any minimality definition can be evaluated.
fn check_consistency(set: &MinimalCausalSet) -> Result<(), MinimalityViolation> {
    let actual = set.dependencies.len() as u64;
    if set.minimal_set_size != actual {
        return Err(MinimalityViolation::SizeMismatch {
            declared: set.minimal_set_size,
            actual,
        });
    }
    if set.minimal_set_size > set.total_evidence_atoms_considered {
        return Err(MinimalityViolation::OversizedClaim {
            minimal_set_size: set.minimal_set_size,
            total_considered: set.total_evidence_atoms_considered,
        });
    }
    let recomputed = recompute_set_hash(&set.dependencies);
    if set.causal_set_hash != recomputed {
        return Err(MinimalityViolation::ContentHashMismatch {
            declared: set.causal_set_hash,
            recomputed,
        });
    }
    Ok(())
}

/// Map each covered [`DecisionFactor`] to the number of retained atoms covering
/// it, in deterministic factor order.
fn factor_cover_counts(set: &MinimalCausalSet) -> BTreeMap<DecisionFactor, u64> {
    let mut counts: BTreeMap<DecisionFactor, u64> = BTreeMap::new();
    for dep in &set.dependencies {
        *counts.entry(dep.influenced_factor).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Structural minimality
// ---------------------------------------------------------------------------

/// Verify the **structural** minimality of a causal set: the consistency/tamper
/// invariants plus the single-cover invariant (each influenced factor is
/// covered by exactly one retained atom).
///
/// Returns a [`MinimalityProof`] in [`VerificationMode::Structural`] on success,
/// or the first violated invariant in the documented order.
///
/// An empty set (no dependencies) is vacuously minimal and verifies, provided it
/// also claims to have considered no atoms it then discarded inconsistently;
/// the consistency checks still apply.
pub fn verify_structural_minimality(
    set: &MinimalCausalSet,
) -> Result<MinimalityProof, MinimalityViolation> {
    check_consistency(set)?;

    let counts = factor_cover_counts(set);
    // Deterministic: BTreeMap iterates in factor order, so the first over-covered
    // factor reported is stable.
    for (factor, count) in &counts {
        if *count >= 2 {
            return Err(MinimalityViolation::RedundantAtom {
                factor: *factor,
                cover_count: *count,
            });
        }
    }

    let covered_factors: BTreeSet<DecisionFactor> = counts.into_keys().collect();
    Ok(MinimalityProof::new(
        set,
        VerificationMode::Structural,
        covered_factors,
    ))
}

/// Fail-closed publish gate: a causal set may only be published / accepted into
/// a forensic artifact if its structural minimality claim verifies.
///
/// This is the entry point for callers that want a single yes/no gate; it is an
/// alias for [`verify_structural_minimality`].
pub fn gate_minimal_causal_set(
    set: &MinimalCausalSet,
) -> Result<MinimalityProof, MinimalityViolation> {
    verify_structural_minimality(set)
}

// ---------------------------------------------------------------------------
// Counterfactual minimality (oracle-based)
// ---------------------------------------------------------------------------

/// Verify the **counterfactual** minimality of a causal set against a
/// leave-one-out re-decision oracle.
///
/// The `oracle` is called with each leave-one-out subset of the dependency
/// vector and must return the decision outcome that subset would produce. For
/// the set to be minimal, every leave-one-out outcome must differ from
/// `recorded_outcome` — i.e., each atom is necessary. The outcome type `O` only
/// needs to be comparable for equality.
///
/// The consistency/tamper checks are applied first, so a structurally
/// inconsistent set is refused before the (potentially expensive) oracle is
/// invoked.
pub fn verify_minimality_with_oracle<O, F>(
    set: &MinimalCausalSet,
    recorded_outcome: &O,
    mut oracle: F,
) -> Result<MinimalityProof, MinimalityViolation>
where
    O: PartialEq,
    F: FnMut(&[CausalDependency]) -> O,
{
    check_consistency(set)?;

    let deps = &set.dependencies;
    for (i, removed) in deps.iter().enumerate() {
        let subset: Vec<CausalDependency> = deps
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, dep)| dep.clone())
            .collect();
        let outcome = oracle(&subset);
        if outcome == *recorded_outcome {
            return Err(MinimalityViolation::AtomNotNecessary {
                evidence_atom_id: removed.evidence_atom_id.clone(),
                factor: removed.influenced_factor,
            });
        }
    }

    let covered_factors: BTreeSet<DecisionFactor> =
        deps.iter().map(|dep| dep.influenced_factor).collect();
    Ok(MinimalityProof::new(
        set,
        VerificationMode::Counterfactual,
        covered_factors,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minimal_causal_set_inference::CausalTracker;
    use crate::security_epoch::SecurityEpoch;

    fn hash_of(label: &str) -> ContentHash {
        ContentHash::compute(label.as_bytes())
    }

    fn dep(atom: &str, factor: DecisionFactor, magnitude: i64) -> CausalDependency {
        CausalDependency::new(atom, "sensor_reading", factor, magnitude, hash_of(atom))
    }

    /// Build a set with a correct hash/size by going through the canonical
    /// constructor, then optionally override `total_evidence_atoms_considered`.
    fn make_set(deps: Vec<CausalDependency>, considered: u64) -> MinimalCausalSet {
        MinimalCausalSet::new(
            "causal-test",
            "decision-test",
            SecurityEpoch::from_raw(7),
            1_000,
            deps,
            considered,
        )
    }

    // --- positive: structural -------------------------------------------------

    #[test]
    fn single_cover_per_factor_verifies() {
        let set = make_set(
            vec![
                dep("a", DecisionFactor::PosteriorProbability, 800_000),
                dep("b", DecisionFactor::LossMatrix, 600_000),
                dep("c", DecisionFactor::GuardrailActivation, 400_000),
            ],
            10,
        );
        let proof = verify_structural_minimality(&set).expect("should be minimal");
        assert_eq!(proof.verification_mode, VerificationMode::Structural);
        assert_eq!(proof.verified_atom_count, 3);
        assert_eq!(proof.covered_factors.len(), 3);
        assert!(proof.verify_self_hash());
    }

    #[test]
    fn single_atom_verifies() {
        let set = make_set(vec![dep("a", DecisionFactor::ActionFiltering, 500_000)], 4);
        let proof = verify_structural_minimality(&set).expect("single atom is minimal");
        assert_eq!(proof.verified_atom_count, 1);
        assert!(
            proof
                .covered_factors
                .contains(&DecisionFactor::ActionFiltering)
        );
    }

    #[test]
    fn empty_set_is_vacuously_minimal() {
        let set = make_set(vec![], 0);
        let proof = verify_structural_minimality(&set).expect("empty set is vacuously minimal");
        assert_eq!(proof.verified_atom_count, 0);
        assert!(proof.covered_factors.is_empty());
    }

    #[test]
    fn greedy_compute_minimal_set_passes_gate() {
        // Tie FF.5 to FF.1's real producer: a greedy minimal set keeps one atom
        // per factor and must therefore pass the structural gate.
        let mut tracker = CausalTracker::new();
        tracker.record_dependency(dep("a", DecisionFactor::PosteriorProbability, 900_000));
        tracker.record_dependency(dep("a2", DecisionFactor::PosteriorProbability, 100_000));
        tracker.record_dependency(dep("b", DecisionFactor::LossMatrix, 500_000));
        let set = tracker.compute_minimal_set("decision-x", SecurityEpoch::from_raw(1), 2_000);
        let proof = gate_minimal_causal_set(&set).expect("greedy set must be minimal");
        assert_eq!(proof.covered_factors.len(), 2);
    }

    #[test]
    fn proof_hash_is_deterministic() {
        let set = make_set(
            vec![dep("a", DecisionFactor::PosteriorProbability, 800_000)],
            3,
        );
        let p1 = verify_structural_minimality(&set).unwrap();
        let p2 = verify_structural_minimality(&set).unwrap();
        assert_eq!(p1.proof_hash, p2.proof_hash);
        assert_eq!(p1, p2);
    }

    #[test]
    fn proof_self_hash_detects_field_tampering() {
        let set = make_set(
            vec![dep("a", DecisionFactor::PosteriorProbability, 800_000)],
            3,
        );
        let mut proof = verify_structural_minimality(&set).unwrap();
        assert!(proof.verify_self_hash());
        proof.verified_atom_count = 99;
        assert!(!proof.verify_self_hash());
    }

    // --- negative: consistency / tamper --------------------------------------

    #[test]
    fn declared_size_mismatch_is_refused() {
        let mut set = make_set(
            vec![dep("a", DecisionFactor::PosteriorProbability, 800_000)],
            3,
        );
        set.minimal_set_size = 5; // lie about the size
        let err = verify_structural_minimality(&set).unwrap_err();
        assert_eq!(
            err,
            MinimalityViolation::SizeMismatch {
                declared: 5,
                actual: 1
            }
        );
    }

    #[test]
    fn oversized_claim_is_refused() {
        // minimal_set_size (2) > total considered (1) is impossible.
        let set = make_set(
            vec![
                dep("a", DecisionFactor::PosteriorProbability, 800_000),
                dep("b", DecisionFactor::LossMatrix, 600_000),
            ],
            1,
        );
        let err = verify_structural_minimality(&set).unwrap_err();
        assert_eq!(
            err,
            MinimalityViolation::OversizedClaim {
                minimal_set_size: 2,
                total_considered: 1
            }
        );
    }

    #[test]
    fn content_hash_mismatch_is_refused() {
        let mut set = make_set(
            vec![dep("a", DecisionFactor::PosteriorProbability, 800_000)],
            3,
        );
        // Mutate a dependency without recomputing the stored hash -> tamper.
        set.dependencies[0].influence_magnitude_millionths = 1;
        let err = verify_structural_minimality(&set).unwrap_err();
        assert!(matches!(
            err,
            MinimalityViolation::ContentHashMismatch { .. }
        ));
    }

    // --- negative: structural minimality -------------------------------------

    #[test]
    fn redundant_atom_same_factor_is_refused() {
        let set = make_set(
            vec![
                dep("a", DecisionFactor::PosteriorProbability, 800_000),
                dep("b", DecisionFactor::PosteriorProbability, 700_000),
            ],
            5,
        );
        let err = verify_structural_minimality(&set).unwrap_err();
        assert_eq!(
            err,
            MinimalityViolation::RedundantAtom {
                factor: DecisionFactor::PosteriorProbability,
                cover_count: 2
            }
        );
    }

    #[test]
    fn one_atom_covering_two_factors_is_not_redundant() {
        // Same evidence atom id influencing two *distinct* factors is legitimate:
        // each factor is still single-covered.
        let set = make_set(
            vec![
                dep("shared", DecisionFactor::PosteriorProbability, 800_000),
                dep("shared", DecisionFactor::LossMatrix, 600_000),
            ],
            5,
        );
        let proof = verify_structural_minimality(&set).expect("distinct factors are minimal");
        assert_eq!(proof.covered_factors.len(), 2);
    }

    // --- ordering ------------------------------------------------------------

    #[test]
    fn consistency_checks_precede_minimality() {
        // A set that is BOTH size-inconsistent AND has a redundant atom must
        // report the earlier (size) violation deterministically.
        let mut set = make_set(
            vec![
                dep("a", DecisionFactor::PosteriorProbability, 800_000),
                dep("b", DecisionFactor::PosteriorProbability, 700_000),
            ],
            5,
        );
        set.minimal_set_size = 99;
        let err = verify_structural_minimality(&set).unwrap_err();
        assert!(matches!(err, MinimalityViolation::SizeMismatch { .. }));
    }

    #[test]
    fn hash_check_precedes_minimality() {
        let mut set = make_set(
            vec![
                dep("a", DecisionFactor::PosteriorProbability, 800_000),
                dep("b", DecisionFactor::PosteriorProbability, 700_000),
            ],
            5,
        );
        // Tamper a dependency: hash mismatch must fire before redundancy.
        set.dependencies[0].influence_magnitude_millionths = 42;
        let err = verify_structural_minimality(&set).unwrap_err();
        assert!(matches!(
            err,
            MinimalityViolation::ContentHashMismatch { .. }
        ));
    }

    // --- counterfactual oracle -----------------------------------------------

    #[test]
    fn oracle_all_atoms_necessary_verifies() {
        let set = make_set(
            vec![
                dep("a", DecisionFactor::PosteriorProbability, 800_000),
                dep("b", DecisionFactor::LossMatrix, 600_000),
            ],
            5,
        );
        let recorded = "suspend".to_string();
        // Oracle: only the full set yields "suspend"; any leave-one-out yields
        // "allow". Since verify passes leave-one-out subsets (always strictly
        // smaller), every call returns "allow" != "suspend".
        let proof = verify_minimality_with_oracle(&set, &recorded, |subset| {
            if subset.len() == 2 {
                "suspend".to_string()
            } else {
                "allow".to_string()
            }
        })
        .expect("all atoms necessary");
        assert_eq!(proof.verification_mode, VerificationMode::Counterfactual);
        assert_eq!(proof.covered_factors.len(), 2);
    }

    #[test]
    fn oracle_unnecessary_atom_is_refused() {
        let set = make_set(
            vec![
                dep("keystone", DecisionFactor::PosteriorProbability, 800_000),
                dep("filler", DecisionFactor::LossMatrix, 600_000),
            ],
            5,
        );
        let recorded = "suspend".to_string();
        // Oracle: the outcome is "suspend" as long as "keystone" is present,
        // regardless of "filler" -> removing "filler" leaves the outcome
        // unchanged -> "filler" is not necessary -> refuse.
        let err = verify_minimality_with_oracle(&set, &recorded, |subset| {
            if subset.iter().any(|d| d.evidence_atom_id == "keystone") {
                "suspend".to_string()
            } else {
                "allow".to_string()
            }
        })
        .unwrap_err();
        assert_eq!(
            err,
            MinimalityViolation::AtomNotNecessary {
                evidence_atom_id: "filler".to_string(),
                factor: DecisionFactor::LossMatrix,
            }
        );
    }

    #[test]
    fn oracle_consistency_failure_short_circuits_before_oracle() {
        let mut set = make_set(
            vec![dep("a", DecisionFactor::PosteriorProbability, 800_000)],
            3,
        );
        set.minimal_set_size = 7;
        let mut oracle_calls = 0;
        let recorded = "x".to_string();
        let err = verify_minimality_with_oracle(&set, &recorded, |_subset| {
            oracle_calls += 1;
            "x".to_string()
        })
        .unwrap_err();
        assert!(matches!(err, MinimalityViolation::SizeMismatch { .. }));
        assert_eq!(oracle_calls, 0, "oracle must not run on inconsistent set");
    }

    #[test]
    fn oracle_empty_set_verifies_without_calls() {
        let set = make_set(vec![], 0);
        let mut oracle_calls = 0;
        let recorded = "x".to_string();
        let proof = verify_minimality_with_oracle(&set, &recorded, |_subset| {
            oracle_calls += 1;
            "y".to_string()
        })
        .expect("empty set vacuously minimal");
        assert_eq!(oracle_calls, 0);
        assert_eq!(proof.verified_atom_count, 0);
    }

    // --- violation display ---------------------------------------------------

    #[test]
    fn violation_display_is_descriptive() {
        let v = MinimalityViolation::RedundantAtom {
            factor: DecisionFactor::PosteriorProbability,
            cover_count: 3,
        };
        let s = v.to_string();
        assert!(s.contains("posterior_probability"));
        assert!(s.contains('3'));
    }

    #[test]
    fn proof_hash_changes_with_mode() {
        // Same set, the two modes must yield distinct proof hashes because the
        // mode is part of the preimage.
        let set = make_set(
            vec![dep("a", DecisionFactor::PosteriorProbability, 800_000)],
            3,
        );
        let structural = verify_structural_minimality(&set).unwrap();
        let recorded = "z".to_string();
        let counterfactual = verify_minimality_with_oracle(&set, &recorded, |subset| {
            if subset.is_empty() {
                "other".to_string()
            } else {
                "z".to_string()
            }
        })
        .unwrap();
        assert_ne!(structural.proof_hash, counterfactual.proof_hash);
    }
}
