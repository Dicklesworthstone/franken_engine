// Proof Chain Composition — algebraic composition of translation-validation
// proofs (bd-cixqu.31.1).
//
// A `PassProof` carries the witness that a single optimization /
// lowering pass preserved semantics — `(precondition_hash,
// postcondition_hash, proof_artifact_ref)`. Two passes whose
// boundary states match (`left.postcondition_hash ==
// right.precondition_hash`) compose into a single proof spanning both
// passes. The composition is associative; the chain of N passes has
// the same observational meaning as a single proof from the first
// pass's precondition to the last pass's postcondition.
//
// This is the structural / algebraic contract. It does NOT recompute
// the underlying SMT proof — the witness is the postcondition hash
// plus the chain of artifact references. A downstream verifier
// (Track G) replays each step's artifact against the recorded pre/post
// hashes. The EE.2 memoization cache below stores the derived chain by
// `(pre-state hash, optimization id)` so repeated derivations are a
// `BTreeMap` lookup rather than a full chain walk.
//
// Anchoring beads:
//   * bd-cixqu.7.6 (G.4) — Translation validation pilot (CLOSED).
//     The pilot's per-pass artifact shape is what `proof_artifact_ref`
//     points at.
//   * bd-cixqu.31.2 (EE.2) — memoization cache; consumes
//     keyed by `(pre-state hash, optimization id)` and invalidated on
//     optimization-pack version bump.
//
// Non-goals for this bead:
//   * Cross-pass cost re-aggregation (proof_cost_manifest lives in
//     proof_artifact.rs).

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// PassProof — one pass's translation-validation witness
// ---------------------------------------------------------------------------

/// Single optimization / lowering pass's translation-validation
/// witness. The pass takes a program in some IR level / shape with
/// `precondition_hash` and produces an equivalent program in
/// `postcondition_hash`. The proof artifact at `proof_artifact_ref`
/// is the SMT / proof-carrying-code witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassProof {
    /// Stable pass identifier (e.g. "ir0_to_ir1", "ir1_constant_fold").
    pub pass_id: String,
    /// Content-addressed hash of the input-side IR state.
    pub precondition_hash: ContentHash,
    /// Content-addressed hash of the output-side IR state.
    pub postcondition_hash: ContentHash,
    /// Content-addressed reference to the proof artifact.
    pub proof_artifact_ref: ContentHash,
    /// Security epoch at proof emission time.
    pub epoch: SecurityEpoch,
}

impl PassProof {
    /// Whether this pass's postcondition matches the supplied
    /// successor's precondition. The fundamental composition predicate.
    pub fn matches_successor(&self, successor: &PassProof) -> bool {
        self.postcondition_hash == successor.precondition_hash
    }
}

// ---------------------------------------------------------------------------
// ProofChain — an associative composition of N pass proofs
// ---------------------------------------------------------------------------

/// Ordered chain of `PassProof`s. Constructed by repeatedly appending
/// pass proofs whose `precondition_hash` matches the chain's running
/// `postcondition`. The chain's content hash collapses to a single
/// `(start_precondition, end_postcondition, ordered_artifact_digests)`
/// commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofChain {
    passes: Vec<PassProof>,
}

impl ProofChain {
    /// Empty chain. `current_postcondition` returns `None` until the
    /// first pass is appended.
    pub fn empty() -> Self {
        Self { passes: Vec::new() }
    }

    /// Chain seeded with a single pass.
    pub fn single(pass: PassProof) -> Self {
        Self { passes: vec![pass] }
    }

    /// Construct from a vec of passes, validating composition. Returns
    /// `ChainError::BoundaryMismatch` on the first boundary that does
    /// not chain.
    pub fn try_from_passes(passes: Vec<PassProof>) -> Result<Self, ChainError> {
        let mut chain = Self::empty();
        for pass in passes {
            chain.push(pass)?;
        }
        Ok(chain)
    }

    /// Number of passes in the chain.
    pub fn len(&self) -> usize {
        self.passes.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    /// Read-only access to the underlying passes.
    pub fn passes(&self) -> &[PassProof] {
        &self.passes
    }

    /// The chain's overall precondition (start IR), if non-empty.
    pub fn start_precondition(&self) -> Option<&ContentHash> {
        self.passes.first().map(|p| &p.precondition_hash)
    }

    /// The chain's overall postcondition (end IR), if non-empty.
    pub fn end_postcondition(&self) -> Option<&ContentHash> {
        self.passes.last().map(|p| &p.postcondition_hash)
    }

    /// The current running postcondition — the hash a successor's
    /// `precondition_hash` must match for `push` to succeed. `None`
    /// only for the empty chain.
    pub fn current_postcondition(&self) -> Option<&ContentHash> {
        self.end_postcondition()
    }

    /// Append a single pass. Returns `ChainError::BoundaryMismatch` if
    /// the new pass's precondition does not match the chain's running
    /// postcondition (when the chain is non-empty).
    pub fn push(&mut self, pass: PassProof) -> Result<(), ChainError> {
        if let Some(prev_post) = self.current_postcondition() {
            if *prev_post != pass.precondition_hash {
                return Err(ChainError::BoundaryMismatch {
                    expected_precondition: *prev_post,
                    found_precondition: pass.precondition_hash,
                    pass_id: pass.pass_id,
                });
            }
        }
        self.passes.push(pass);
        Ok(())
    }

    /// Compose two chains. Returns `ChainError::BoundaryMismatch` if
    /// the left's end-postcondition does not match the right's
    /// start-precondition. Composing with an empty chain returns the
    /// other chain (identity).
    pub fn compose(&self, other: &ProofChain) -> Result<ProofChain, ChainError> {
        match (self.is_empty(), other.is_empty()) {
            (true, _) => Ok(other.clone()),
            (_, true) => Ok(self.clone()),
            (false, false) => {
                let left_end = self.end_postcondition().expect("non-empty");
                let right_start = other.start_precondition().expect("non-empty");
                if left_end != right_start {
                    return Err(ChainError::BoundaryMismatch {
                        expected_precondition: *left_end,
                        found_precondition: *right_start,
                        pass_id: other.passes[0].pass_id.clone(),
                    });
                }
                let mut combined = self.passes.clone();
                combined.extend(other.passes.iter().cloned());
                Ok(ProofChain { passes: combined })
            }
        }
    }

    /// Re-verify the chain's structural invariants — every adjacent
    /// pair must chain. Returns the first boundary that fails, or
    /// `Ok(())` if every boundary matches. (A fresh `ProofChain` built
    /// via `push` always satisfies this — `verify` exists for
    /// post-deserialization checks.)
    pub fn verify(&self) -> Result<(), ChainError> {
        for window in self.passes.windows(2) {
            let (left, right) = (&window[0], &window[1]);
            if !left.matches_successor(right) {
                return Err(ChainError::BoundaryMismatch {
                    expected_precondition: left.postcondition_hash,
                    found_precondition: right.precondition_hash,
                    pass_id: right.pass_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Deterministic content hash of the chain. Commits to the start
    /// precondition, the end postcondition, and the ordered sequence
    /// of `(pass_id, proof_artifact_ref)` pairs. Two chains hash
    /// identically iff they have the same passes in the same order.
    pub fn content_hash(&self) -> ContentHash {
        // The empty chain hashes to ContentHash::compute(b"").
        if self.passes.is_empty() {
            return ContentHash::compute(b"");
        }
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"proof_chain_v1");
        buf.push(0);
        buf.extend_from_slice(
            self.start_precondition()
                .expect("non-empty start")
                .as_bytes(),
        );
        buf.push(0);
        buf.extend_from_slice(self.end_postcondition().expect("non-empty end").as_bytes());
        buf.push(0);
        for pass in &self.passes {
            // Length-prefix each pass_id for canonical encoding.
            let id_bytes = pass.pass_id.as_bytes();
            buf.extend_from_slice(&(id_bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(id_bytes);
            buf.extend_from_slice(pass.proof_artifact_ref.as_bytes());
            buf.push(0);
        }
        ContentHash::compute(&buf)
    }
}

impl Default for ProofChain {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainError {
    /// Adjacent passes' postcondition / precondition hashes did not
    /// match.
    BoundaryMismatch {
        expected_precondition: ContentHash,
        found_precondition: ContentHash,
        pass_id: String,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryMismatch {
                expected_precondition,
                found_precondition,
                pass_id,
            } => write!(
                f,
                "proof chain boundary mismatch at pass {pass_id}: expected precondition \
                 {expected_precondition}, found {found_precondition}",
            ),
        }
    }
}

impl std::error::Error for ChainError {}

// ---------------------------------------------------------------------------
// ProofDerivationCache — EE.2 content-hashed memoization
// ---------------------------------------------------------------------------

/// Cache key for memoized proof-chain derivations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofDerivationCacheKey {
    /// Hash of the pre-optimization state.
    pub pre_state_hash: ContentHash,
    /// Stable optimization identifier within the active optimization pack.
    pub optimization_id: String,
}

impl ProofDerivationCacheKey {
    /// Construct a cache key.
    pub fn new(pre_state_hash: ContentHash, optimization_id: impl Into<String>) -> Self {
        Self {
            pre_state_hash,
            optimization_id: optimization_id.into(),
        }
    }
}

/// Memoized derivation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoizedProofDerivation {
    /// Cache key for this entry.
    pub key: ProofDerivationCacheKey,
    /// Optimization-pack version active when the entry was written.
    pub optimization_pack_version: String,
    /// Hash of the composed proof chain.
    pub proof_chain_hash: ContentHash,
    /// Hash of the post-optimization state.
    pub post_state_hash: ContentHash,
    /// Number of pass proofs represented by the chain.
    pub pass_count: usize,
    /// Cached composed proof chain.
    pub proof_chain: ProofChain,
}

/// Content-hashed memoization cache for proof-chain derivations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofDerivationCache {
    optimization_pack_version: String,
    entries: BTreeMap<ProofDerivationCacheKey, MemoizedProofDerivation>,
}

impl ProofDerivationCache {
    /// Create an empty cache for an optimization-pack version.
    pub fn new(optimization_pack_version: impl Into<String>) -> Self {
        Self {
            optimization_pack_version: optimization_pack_version.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Active optimization-pack version.
    pub fn optimization_pack_version(&self) -> &str {
        &self.optimization_pack_version
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop all entries without changing the active pack version.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Ensure the active optimization-pack version. A changed version
    /// invalidates every cached derivation and returns `true`.
    pub fn invalidate_on_pack_version_bump(
        &mut self,
        new_optimization_pack_version: impl Into<String>,
    ) -> bool {
        let new_version = new_optimization_pack_version.into();
        if self.optimization_pack_version == new_version {
            return false;
        }
        self.optimization_pack_version = new_version;
        self.clear();
        true
    }

    /// Insert a composed proof chain for the supplied optimization id.
    pub fn insert_chain(
        &mut self,
        optimization_id: impl Into<String>,
        proof_chain: ProofChain,
    ) -> Result<MemoizedProofDerivation, ProofDerivationCacheError> {
        let optimization_id = optimization_id.into();
        if optimization_id.trim().is_empty() {
            return Err(ProofDerivationCacheError::EmptyOptimizationId);
        }
        proof_chain.verify()?;
        let pre_state_hash = *proof_chain
            .start_precondition()
            .ok_or(ProofDerivationCacheError::EmptyProofChain)?;
        let post_state_hash = *proof_chain
            .end_postcondition()
            .ok_or(ProofDerivationCacheError::EmptyProofChain)?;
        let key = ProofDerivationCacheKey::new(pre_state_hash, optimization_id);
        let entry = MemoizedProofDerivation {
            key: key.clone(),
            optimization_pack_version: self.optimization_pack_version.clone(),
            proof_chain_hash: proof_chain.content_hash(),
            post_state_hash,
            pass_count: proof_chain.len(),
            proof_chain,
        };
        self.entries.insert(key, entry.clone());
        Ok(entry)
    }

    /// Lookup a derivation by `(pre-state hash, optimization id)`.
    pub fn get(
        &self,
        pre_state_hash: &ContentHash,
        optimization_id: &str,
    ) -> Option<&MemoizedProofDerivation> {
        self.entries.get(&ProofDerivationCacheKey::new(
            *pre_state_hash,
            optimization_id.to_string(),
        ))
    }

    /// Whether the cache contains a derivation key.
    pub fn contains_key(&self, pre_state_hash: &ContentHash, optimization_id: &str) -> bool {
        self.get(pre_state_hash, optimization_id).is_some()
    }
}

impl Default for ProofDerivationCache {
    fn default() -> Self {
        Self::new("unversioned")
    }
}

/// Errors from proof-derivation cache insertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDerivationCacheError {
    /// A cache entry cannot be built from an empty proof chain.
    EmptyProofChain,
    /// Optimization identifiers must be stable and non-empty.
    EmptyOptimizationId,
    /// The proof chain itself is structurally invalid.
    Chain(ChainError),
}

impl From<ChainError> for ProofDerivationCacheError {
    fn from(value: ChainError) -> Self {
        Self::Chain(value)
    }
}

impl fmt::Display for ProofDerivationCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProofChain => f.write_str("cannot memoize an empty proof chain"),
            Self::EmptyOptimizationId => f.write_str("optimization id must be non-empty"),
            Self::Chain(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ProofDerivationCacheError {}

// ---------------------------------------------------------------------------
// Tests — composition is associative and the chain is a category
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn hash(tag: &str) -> ContentHash {
        ContentHash::compute(tag.as_bytes())
    }

    fn pass(id: &str, pre: ContentHash, post: ContentHash) -> PassProof {
        PassProof {
            pass_id: id.to_string(),
            precondition_hash: pre,
            postcondition_hash: post,
            proof_artifact_ref: hash(&format!("{id}-artifact")),
            epoch: epoch(),
        }
    }

    // ----- Empty / single-pass chain -----

    #[test]
    fn empty_chain_is_empty() {
        let c = ProofChain::empty();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.start_precondition(), None);
        assert_eq!(c.end_postcondition(), None);
        assert_eq!(c.current_postcondition(), None);
    }

    #[test]
    fn default_chain_is_empty() {
        assert_eq!(ProofChain::default(), ProofChain::empty());
    }

    #[test]
    fn single_pass_chain_exposes_boundaries() {
        let p = pass("p1", hash("a"), hash("b"));
        let c = ProofChain::single(p.clone());
        assert_eq!(c.len(), 1);
        assert_eq!(c.start_precondition(), Some(&hash("a")));
        assert_eq!(c.end_postcondition(), Some(&hash("b")));
        assert_eq!(c.current_postcondition(), Some(&hash("b")));
        assert_eq!(c.passes(), &[p]);
    }

    // ----- Push: boundary matching -----

    #[test]
    fn push_accepts_matching_boundary() {
        let mut c = ProofChain::single(pass("p1", hash("a"), hash("b")));
        c.push(pass("p2", hash("b"), hash("c"))).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c.end_postcondition(), Some(&hash("c")));
    }

    #[test]
    fn push_rejects_mismatching_boundary() {
        let mut c = ProofChain::single(pass("p1", hash("a"), hash("b")));
        let err = c.push(pass("p2", hash("x"), hash("c"))).unwrap_err();
        match err {
            ChainError::BoundaryMismatch {
                expected_precondition,
                found_precondition,
                pass_id,
            } => {
                assert_eq!(expected_precondition, hash("b"));
                assert_eq!(found_precondition, hash("x"));
                assert_eq!(pass_id, "p2");
            }
        }
        // Failed push must NOT mutate the chain.
        assert_eq!(c.len(), 1);
        assert_eq!(c.end_postcondition(), Some(&hash("b")));
    }

    #[test]
    fn push_on_empty_chain_accepts_any_precondition() {
        let mut c = ProofChain::empty();
        c.push(pass("p1", hash("anything"), hash("b"))).unwrap();
        assert_eq!(c.start_precondition(), Some(&hash("anything")));
    }

    // ----- try_from_passes -----

    #[test]
    fn try_from_passes_builds_valid_chain() {
        let chain = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("c")),
            pass("p3", hash("c"), hash("d")),
        ])
        .unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.start_precondition(), Some(&hash("a")));
        assert_eq!(chain.end_postcondition(), Some(&hash("d")));
    }

    #[test]
    fn try_from_passes_rejects_first_invalid_boundary() {
        let err = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("WRONG"), hash("c")),
        ])
        .unwrap_err();
        match err {
            ChainError::BoundaryMismatch { pass_id, .. } => assert_eq!(pass_id, "p2"),
        }
    }

    // ----- Compose -----

    #[test]
    fn compose_two_chains_with_matching_boundary() {
        let left = ProofChain::try_from_passes(vec![pass("p1", hash("a"), hash("b"))]).unwrap();
        let right = ProofChain::try_from_passes(vec![pass("p2", hash("b"), hash("c"))]).unwrap();
        let composed = left.compose(&right).unwrap();
        assert_eq!(composed.len(), 2);
        assert_eq!(composed.start_precondition(), Some(&hash("a")));
        assert_eq!(composed.end_postcondition(), Some(&hash("c")));
    }

    #[test]
    fn compose_rejects_mismatched_boundary() {
        let left = ProofChain::try_from_passes(vec![pass("p1", hash("a"), hash("b"))]).unwrap();
        let right = ProofChain::try_from_passes(vec![pass("p2", hash("X"), hash("c"))]).unwrap();
        assert!(left.compose(&right).is_err());
    }

    #[test]
    fn compose_with_empty_left_is_identity() {
        let right = ProofChain::try_from_passes(vec![pass("p1", hash("a"), hash("b"))]).unwrap();
        let composed = ProofChain::empty().compose(&right).unwrap();
        assert_eq!(composed, right);
    }

    #[test]
    fn compose_with_empty_right_is_identity() {
        let left = ProofChain::try_from_passes(vec![pass("p1", hash("a"), hash("b"))]).unwrap();
        let composed = left.compose(&ProofChain::empty()).unwrap();
        assert_eq!(composed, left);
    }

    #[test]
    fn compose_empty_with_empty_is_empty() {
        let c = ProofChain::empty().compose(&ProofChain::empty()).unwrap();
        assert!(c.is_empty());
    }

    // ----- Associativity: the central algebraic property -----

    #[test]
    fn composition_is_associative() {
        let a = ProofChain::single(pass("p1", hash("a"), hash("b")));
        let b = ProofChain::single(pass("p2", hash("b"), hash("c")));
        let c = ProofChain::single(pass("p3", hash("c"), hash("d")));
        let left = a.compose(&b).unwrap().compose(&c).unwrap();
        let right = a.compose(&b.compose(&c).unwrap()).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.len(), 3);
        assert_eq!(left.start_precondition(), Some(&hash("a")));
        assert_eq!(left.end_postcondition(), Some(&hash("d")));
    }

    #[test]
    fn composition_associative_for_multi_pass_chains() {
        let a = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("c")),
        ])
        .unwrap();
        let b = ProofChain::try_from_passes(vec![
            pass("p3", hash("c"), hash("d")),
            pass("p4", hash("d"), hash("e")),
        ])
        .unwrap();
        let c = ProofChain::try_from_passes(vec![
            pass("p5", hash("e"), hash("f")),
            pass("p6", hash("f"), hash("g")),
        ])
        .unwrap();
        let left = a.compose(&b).unwrap().compose(&c).unwrap();
        let right = a.compose(&b.compose(&c).unwrap()).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.len(), 6);
    }

    // ----- 12-pass chain per the bead title -----

    #[test]
    fn twelve_pass_chain_composes_cleanly() {
        // pass-1 + ... + pass-12 -> pass-12 proof.
        let labels = [
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12",
        ];
        let mut passes = Vec::new();
        for i in 0..12 {
            passes.push(pass(
                &format!("p{}", i + 1),
                hash(labels[i]),
                hash(labels[i + 1]),
            ));
        }
        let chain = ProofChain::try_from_passes(passes).unwrap();
        assert_eq!(chain.len(), 12);
        assert_eq!(chain.start_precondition(), Some(&hash("s0")));
        assert_eq!(chain.end_postcondition(), Some(&hash("s12")));
        chain.verify().unwrap();
    }

    // ----- verify() -----

    #[test]
    fn verify_passes_for_valid_chain() {
        let chain = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("c")),
        ])
        .unwrap();
        chain.verify().unwrap();
    }

    #[test]
    fn verify_catches_post_deserialization_corruption() {
        // Simulate corruption by hand-building a bad chain via direct
        // field assignment (try_from_passes would reject it).
        let chain = ProofChain {
            passes: vec![
                pass("p1", hash("a"), hash("b")),
                pass("p2", hash("CORRUPT"), hash("c")),
            ],
        };
        assert!(chain.verify().is_err());
    }

    // ----- Content hash determinism -----

    #[test]
    fn content_hash_is_deterministic_for_same_chain() {
        let c1 = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("c")),
        ])
        .unwrap();
        let c2 = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("c")),
        ])
        .unwrap();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn content_hash_distinguishes_pass_order() {
        // Two chains with the same start/end but different intermediate
        // pass orders must hash differently.
        let c1 = ProofChain::try_from_passes(vec![
            pass("constant_fold", hash("a"), hash("b")),
            pass("inline", hash("b"), hash("c")),
        ])
        .unwrap();
        let c2 = ProofChain::try_from_passes(vec![
            pass("inline", hash("a"), hash("b")),
            pass("constant_fold", hash("b"), hash("c")),
        ])
        .unwrap();
        assert_ne!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn content_hash_distinguishes_chain_length() {
        let short = ProofChain::single(pass("p1", hash("a"), hash("z")));
        let long = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("z")),
        ])
        .unwrap();
        assert_eq!(short.start_precondition(), long.start_precondition());
        assert_eq!(short.end_postcondition(), long.end_postcondition());
        assert_ne!(short.content_hash(), long.content_hash());
    }

    #[test]
    fn empty_chain_has_stable_hash() {
        let h1 = ProofChain::empty().content_hash();
        let h2 = ProofChain::empty().content_hash();
        assert_eq!(h1, h2);
    }

    // ----- matches_successor predicate -----

    #[test]
    fn matches_successor_predicate() {
        let p1 = pass("p1", hash("a"), hash("b"));
        let p2 = pass("p2", hash("b"), hash("c"));
        let p_bad = pass("px", hash("X"), hash("y"));
        assert!(p1.matches_successor(&p2));
        assert!(!p1.matches_successor(&p_bad));
    }

    // ----- EE.2 proof-derivation memoization cache -----

    #[test]
    fn proof_derivation_cache_keys_by_pre_state_and_optimization_id() {
        let chain = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("c")),
        ])
        .unwrap();
        let mut cache = ProofDerivationCache::new("pack-v1");
        let entry = cache
            .insert_chain("constant_fold", chain.clone())
            .expect("valid chain memoizes");

        assert_eq!(entry.key.pre_state_hash, hash("a"));
        assert_eq!(entry.key.optimization_id, "constant_fold");
        assert_eq!(entry.post_state_hash, hash("c"));
        assert_eq!(entry.pass_count, 2);
        assert_eq!(entry.proof_chain_hash, chain.content_hash());
        assert_eq!(
            cache
                .get(&hash("a"), "constant_fold")
                .expect("entry should be present")
                .proof_chain,
            chain
        );
        assert!(cache.get(&hash("b"), "constant_fold").is_none());
        assert!(cache.get(&hash("a"), "inline").is_none());
    }

    #[test]
    fn proof_derivation_cache_separates_same_pre_state_by_optimization_id() {
        let mut cache = ProofDerivationCache::new("pack-v1");
        let inline = ProofChain::try_from_passes(vec![pass("inline", hash("a"), hash("b"))])
            .expect("valid inline chain");
        let fold = ProofChain::try_from_passes(vec![pass("fold", hash("a"), hash("c"))])
            .expect("valid fold chain");

        cache.insert_chain("inline", inline.clone()).unwrap();
        cache.insert_chain("constant_fold", fold.clone()).unwrap();

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&hash("a"), "inline").unwrap().proof_chain, inline);
        assert_eq!(
            cache.get(&hash("a"), "constant_fold").unwrap().proof_chain,
            fold
        );
    }

    #[test]
    fn proof_derivation_cache_version_bump_invalidates_entries() {
        let mut cache = ProofDerivationCache::new("pack-v1");
        cache
            .insert_chain(
                "inline",
                ProofChain::try_from_passes(vec![pass("inline", hash("a"), hash("b"))]).unwrap(),
            )
            .unwrap();

        assert!(!cache.invalidate_on_pack_version_bump("pack-v1"));
        assert_eq!(cache.len(), 1);
        assert!(cache.invalidate_on_pack_version_bump("pack-v2"));
        assert_eq!(cache.optimization_pack_version(), "pack-v2");
        assert!(cache.is_empty());
        assert!(!cache.contains_key(&hash("a"), "inline"));
    }

    #[test]
    fn proof_derivation_cache_rejects_empty_chain_and_empty_optimization_id() {
        let mut cache = ProofDerivationCache::new("pack-v1");
        let empty_chain_err = cache
            .insert_chain("inline", ProofChain::empty())
            .expect_err("empty chain should not memoize");
        assert_eq!(empty_chain_err, ProofDerivationCacheError::EmptyProofChain);

        let empty_id_err = cache
            .insert_chain(
                " ",
                ProofChain::try_from_passes(vec![pass("inline", hash("a"), hash("b"))]).unwrap(),
            )
            .expect_err("empty optimization id should not memoize");
        assert_eq!(empty_id_err, ProofDerivationCacheError::EmptyOptimizationId);
    }

    #[test]
    fn proof_derivation_cache_serde_round_trip_preserves_lookup() {
        let mut cache = ProofDerivationCache::new("pack-v1");
        cache
            .insert_chain(
                "inline",
                ProofChain::try_from_passes(vec![pass("inline", hash("a"), hash("b"))]).unwrap(),
            )
            .unwrap();

        let json = serde_json::to_string(&cache).expect("serialize cache");
        let restored: ProofDerivationCache =
            serde_json::from_str(&json).expect("deserialize cache");

        assert_eq!(cache, restored);
        assert_eq!(restored.optimization_pack_version(), "pack-v1");
        assert!(restored.contains_key(&hash("a"), "inline"));
    }

    // ----- Serde -----

    #[test]
    fn chain_serde_round_trip() {
        let original = ProofChain::try_from_passes(vec![
            pass("p1", hash("a"), hash("b")),
            pass("p2", hash("b"), hash("c")),
        ])
        .unwrap();
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: ProofChain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
        assert_eq!(original.content_hash(), restored.content_hash());
    }

    #[test]
    fn pass_serde_round_trip() {
        let p = pass("constant_fold", hash("a"), hash("b"));
        let json = serde_json::to_string(&p).unwrap();
        let restored: PassProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, restored);
    }

    // ----- Error Display -----

    #[test]
    fn error_display_mentions_pass_id() {
        let err = ChainError::BoundaryMismatch {
            expected_precondition: hash("expected"),
            found_precondition: hash("found"),
            pass_id: "the_failing_pass".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("the_failing_pass"));
        assert!(s.contains("boundary mismatch"));
    }
}
