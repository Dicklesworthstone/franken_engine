//! Cross-architecture reproducibility and deterministic replay contracts.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Schema marker for cross-architecture reproducibility contract artifacts.
pub const CROSS_ARCH_REPRODUCIBILITY_SCHEMA_VERSION: &str =
    "franken-engine.cross-arch-reproducibility.v1";

/// Required invariant: all architectures must replay to the same content hash.
pub const INVARIANT_CONTENT_HASH_EQUIVALENCE: &str = "content_hash_equivalence";

/// Required invariant: floating-point observations must use a deterministic total ordering.
pub const INVARIANT_DETERMINISTIC_FLOAT_ORDERING: &str = "deterministic_float_ordering";

/// Required invariant: replay serialization must normalize endianness.
pub const INVARIANT_ENDIANNESS: &str = "endianness";

const ARCH_AARCH64: &str = "aarch64";
const ARCH_X86_64: &str = "x86_64";
const FLOAT_ORDERING_TOTAL_BITS: &str = "total_order_bits";
const LITTLE_ENDIAN: &str = "little";

/// Architecture identity captured for replay comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchFingerprint {
    /// Canonical architecture name such as `x86_64` or `aarch64`.
    pub arch: String,
    /// CPU feature flags observed for this architecture.
    pub cpu_features: BTreeSet<String>,
}

impl ArchFingerprint {
    /// Build a fingerprint with normalized architecture and feature strings.
    #[must_use]
    pub fn new(arch: impl Into<String>, cpu_features: impl IntoIterator<Item = String>) -> Self {
        let cpu_features = cpu_features
            .into_iter()
            .map(|feature| normalize_token(&feature))
            .filter(|feature| !feature.is_empty())
            .collect::<BTreeSet<_>>();
        Self {
            arch: normalize_arch(&arch.into()),
            cpu_features,
        }
    }

    /// Return true for architectures covered by the cross-arch contract.
    #[must_use]
    pub fn is_contract_arch(&self) -> bool {
        matches!(self.arch.as_str(), ARCH_X86_64 | ARCH_AARCH64)
    }
}

/// Replay hash comparison result for one architecture or replay lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayVerdict {
    /// Expected content hash from the canonical replay artifact.
    pub expected_hash: String,
    /// Observed content hash from the architecture-specific replay.
    pub observed_hash: String,
    /// Whether expected and observed hashes were byte-identical after normalization.
    pub matched: bool,
}

impl ReplayVerdict {
    /// Build a verdict from expected and observed hashes.
    #[must_use]
    pub fn new(expected_hash: impl Into<String>, observed_hash: impl Into<String>) -> Self {
        let expected_hash = normalize_hash(&expected_hash.into());
        let observed_hash = normalize_hash(&observed_hash.into());
        let matched = expected_hash == observed_hash;
        Self {
            expected_hash,
            observed_hash,
            matched,
        }
    }
}

/// Deterministic replay contract for comparing artifacts across architectures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityContract {
    /// Schema marker for serialized contract artifacts.
    pub schema_version: String,
    /// Architecture fingerprints keyed by canonical architecture name.
    pub arch_fingerprints: BTreeMap<String, ArchFingerprint>,
    /// Required invariants keyed by stable invariant ID.
    pub required_invariants: BTreeMap<String, String>,
    /// Expected content hashes keyed by canonical architecture name.
    pub expected_hashes: BTreeMap<String, String>,
    /// Observed content hashes keyed by canonical architecture name.
    pub observed_hashes: BTreeMap<String, String>,
    /// Replay verdicts keyed by canonical architecture name.
    pub replay_verdicts: BTreeMap<String, ReplayVerdict>,
    /// Serialization endianness observed by architecture.
    pub endianness_by_arch: BTreeMap<String, String>,
    /// Floating-point ordering strategy observed by architecture.
    pub float_ordering_by_arch: BTreeMap<String, String>,
}

impl ReproducibilityContract {
    /// Build the strict x86_64/aarch64 replay contract.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            schema_version: CROSS_ARCH_REPRODUCIBILITY_SCHEMA_VERSION.to_string(),
            arch_fingerprints: BTreeMap::new(),
            required_invariants: required_invariants(),
            expected_hashes: BTreeMap::new(),
            observed_hashes: BTreeMap::new(),
            replay_verdicts: BTreeMap::new(),
            endianness_by_arch: BTreeMap::new(),
            float_ordering_by_arch: BTreeMap::new(),
        }
    }

    /// Add or replace an architecture fingerprint.
    pub fn record_arch_fingerprint(&mut self, fingerprint: ArchFingerprint) {
        self.arch_fingerprints
            .insert(fingerprint.arch.clone(), fingerprint);
    }

    /// Record architecture-specific serialization endianness.
    pub fn record_endianness(&mut self, arch: &str, endianness: &str) {
        self.endianness_by_arch
            .insert(normalize_arch(arch), normalize_token(endianness));
    }

    /// Record architecture-specific deterministic float ordering.
    pub fn record_float_ordering(&mut self, arch: &str, ordering: &str) {
        self.float_ordering_by_arch
            .insert(normalize_arch(arch), normalize_token(ordering));
    }

    /// Record a replay observation and store its verdict.
    pub fn record_replay_verdict(
        &mut self,
        arch: &str,
        expected_hash: &str,
        observed_hash: &str,
    ) -> ReplayVerdict {
        let arch = normalize_arch(arch);
        let verdict = ReplayVerdict::new(expected_hash, observed_hash);
        self.expected_hashes
            .insert(arch.clone(), verdict.expected_hash.clone());
        self.observed_hashes
            .insert(arch.clone(), verdict.observed_hash.clone());
        self.replay_verdicts.insert(arch, verdict.clone());
        verdict
    }

    /// Return true when both required target architectures are present.
    #[must_use]
    pub fn required_arches_present(&self) -> bool {
        [ARCH_X86_64, ARCH_AARCH64]
            .iter()
            .all(|arch| self.arch_fingerprints.contains_key(*arch))
    }

    /// Return true when every recorded replay hash matched its expectation.
    #[must_use]
    pub fn all_replays_matched(&self) -> bool {
        [ARCH_X86_64, ARCH_AARCH64].iter().all(|arch| {
            self.replay_verdicts
                .get(*arch)
                .is_some_and(|verdict| verdict.matched)
        })
    }

    /// Return true when all observed architecture hashes are equivalent.
    #[must_use]
    pub fn content_hashes_equivalent(&self) -> bool {
        if !self.required_arches_present() {
            return false;
        }
        let Some(x86_64_hash) = self.observed_hashes.get(ARCH_X86_64) else {
            return false;
        };
        self.observed_hashes
            .get(ARCH_AARCH64)
            .is_some_and(|aarch64_hash| aarch64_hash == x86_64_hash)
    }

    /// Return true when every required architecture records little-endian serialization.
    #[must_use]
    pub fn deterministic_endianness(&self) -> bool {
        [ARCH_X86_64, ARCH_AARCH64].iter().all(|arch| {
            self.endianness_by_arch
                .get(*arch)
                .is_some_and(|endianness| endianness == LITTLE_ENDIAN)
        })
    }

    /// Return true when every required architecture records deterministic total float ordering.
    #[must_use]
    pub fn deterministic_float_ordering(&self) -> bool {
        [ARCH_X86_64, ARCH_AARCH64].iter().all(|arch| {
            self.float_ordering_by_arch
                .get(*arch)
                .is_some_and(|ordering| ordering == FLOAT_ORDERING_TOTAL_BITS)
        })
    }

    /// Evaluate every required invariant into a stable verdict map.
    #[must_use]
    pub fn invariant_verdicts(&self) -> BTreeMap<String, bool> {
        BTreeMap::from([
            (
                INVARIANT_CONTENT_HASH_EQUIVALENCE.to_string(),
                self.content_hashes_equivalent() && self.all_replays_matched(),
            ),
            (
                INVARIANT_DETERMINISTIC_FLOAT_ORDERING.to_string(),
                self.deterministic_float_ordering(),
            ),
            (
                INVARIANT_ENDIANNESS.to_string(),
                self.deterministic_endianness(),
            ),
        ])
    }

    /// Return true only when every strict invariant passes.
    #[must_use]
    pub fn passes(&self) -> bool {
        self.required_arches_present()
            && self
                .invariant_verdicts()
                .values()
                .all(|invariant_passed| *invariant_passed)
    }
}

impl Default for ReproducibilityContract {
    fn default() -> Self {
        Self::strict()
    }
}

fn required_invariants() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            INVARIANT_CONTENT_HASH_EQUIVALENCE.to_string(),
            "x86_64 and aarch64 replay artifacts must resolve to the same content hash".to_string(),
        ),
        (
            INVARIANT_DETERMINISTIC_FLOAT_ORDERING.to_string(),
            "floating-point observations must be ordered with total_order_bits".to_string(),
        ),
        (
            INVARIANT_ENDIANNESS.to_string(),
            "serialized replay material must be normalized to little-endian".to_string(),
        ),
    ])
}

fn normalize_arch(value: &str) -> String {
    normalize_token(value).replace('-', "_")
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_hash(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(arch: &str) -> ArchFingerprint {
        ArchFingerprint::new(arch, vec!["sse2".to_string(), "sha".to_string()])
    }

    fn passing_contract() -> ReproducibilityContract {
        let mut contract = ReproducibilityContract::strict();
        contract.record_arch_fingerprint(fingerprint(ARCH_X86_64));
        contract.record_arch_fingerprint(ArchFingerprint::new(
            ARCH_AARCH64,
            vec!["neon".to_string(), "sha".to_string()],
        ));
        contract.record_endianness(ARCH_X86_64, LITTLE_ENDIAN);
        contract.record_endianness(ARCH_AARCH64, LITTLE_ENDIAN);
        contract.record_float_ordering(ARCH_X86_64, FLOAT_ORDERING_TOTAL_BITS);
        contract.record_float_ordering(ARCH_AARCH64, FLOAT_ORDERING_TOTAL_BITS);
        contract.record_replay_verdict(ARCH_X86_64, "sha256:abc", "sha256:abc");
        contract.record_replay_verdict(ARCH_AARCH64, "sha256:abc", "sha256:abc");
        contract
    }

    #[test]
    fn arch_fingerprint_sorts_features() {
        let fingerprint = ArchFingerprint::new(
            "x86_64",
            vec!["sha".to_string(), "sse2".to_string(), "aes".to_string()],
        );
        let features = fingerprint.cpu_features.into_iter().collect::<Vec<_>>();
        assert_eq!(features, vec!["aes", "sha", "sse2"]);
    }

    #[test]
    fn arch_fingerprint_deduplicates_features() {
        let fingerprint =
            ArchFingerprint::new("x86_64", vec!["sha".to_string(), "sha".to_string()]);
        assert_eq!(fingerprint.cpu_features.len(), 1);
    }

    #[test]
    fn arch_fingerprint_trims_and_normalizes_features() {
        let fingerprint = ArchFingerprint::new("x86_64", vec![" SHA ".to_string()]);
        assert!(fingerprint.cpu_features.contains("sha"));
    }

    #[test]
    fn arch_fingerprint_normalizes_arch_dash_to_underscore() {
        let fingerprint = ArchFingerprint::new("X86-64", Vec::<String>::new());
        assert_eq!(fingerprint.arch, "x86_64");
    }

    #[test]
    fn arch_fingerprint_identifies_contract_arches() {
        assert!(fingerprint(ARCH_X86_64).is_contract_arch());
        assert!(fingerprint(ARCH_AARCH64).is_contract_arch());
        assert!(!fingerprint("wasm32").is_contract_arch());
    }

    #[test]
    fn strict_contract_has_schema_version() {
        assert_eq!(
            ReproducibilityContract::strict().schema_version,
            CROSS_ARCH_REPRODUCIBILITY_SCHEMA_VERSION
        );
    }

    #[test]
    fn strict_contract_requires_three_invariants() {
        let contract = ReproducibilityContract::strict();
        assert_eq!(contract.required_invariants.len(), 3);
        assert!(
            contract
                .required_invariants
                .contains_key(INVARIANT_CONTENT_HASH_EQUIVALENCE)
        );
        assert!(
            contract
                .required_invariants
                .contains_key(INVARIANT_DETERMINISTIC_FLOAT_ORDERING)
        );
        assert!(
            contract
                .required_invariants
                .contains_key(INVARIANT_ENDIANNESS)
        );
    }

    #[test]
    fn strict_contract_invariant_order_is_stable() {
        let keys = ReproducibilityContract::strict()
            .required_invariants
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                INVARIANT_CONTENT_HASH_EQUIVALENCE,
                INVARIANT_DETERMINISTIC_FLOAT_ORDERING,
                INVARIANT_ENDIANNESS,
            ]
        );
    }

    #[test]
    fn record_arch_fingerprint_stores_by_canonical_arch() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_arch_fingerprint(fingerprint("X86-64"));
        assert!(contract.arch_fingerprints.contains_key(ARCH_X86_64));
    }

    #[test]
    fn record_arch_fingerprint_replaces_same_arch() {
        let mut contract = ReproducibilityContract::strict();
        contract
            .record_arch_fingerprint(ArchFingerprint::new(ARCH_X86_64, vec!["sse2".to_string()]));
        contract
            .record_arch_fingerprint(ArchFingerprint::new(ARCH_X86_64, vec!["avx2".to_string()]));
        assert!(
            contract
                .arch_fingerprints
                .get(ARCH_X86_64)
                .expect("x86 fingerprint")
                .cpu_features
                .contains("avx2")
        );
    }

    #[test]
    fn replay_verdict_matches_equal_hashes() {
        let verdict = ReplayVerdict::new("sha256:abc", "sha256:abc");
        assert!(verdict.matched);
    }

    #[test]
    fn replay_verdict_rejects_different_hashes() {
        let verdict = ReplayVerdict::new("sha256:abc", "sha256:def");
        assert!(!verdict.matched);
    }

    #[test]
    fn replay_verdict_normalizes_hash_case_and_whitespace() {
        let verdict = ReplayVerdict::new(" SHA256:ABC ", "sha256:abc");
        assert!(verdict.matched);
        assert_eq!(verdict.expected_hash, "sha256:abc");
    }

    #[test]
    fn record_replay_verdict_stores_expected_hash() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_replay_verdict(ARCH_X86_64, "sha256:abc", "sha256:abc");
        assert_eq!(
            contract.expected_hashes.get(ARCH_X86_64),
            Some(&"sha256:abc".to_string())
        );
    }

    #[test]
    fn record_replay_verdict_stores_observed_hash() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_replay_verdict(ARCH_X86_64, "sha256:abc", "sha256:def");
        assert_eq!(
            contract.observed_hashes.get(ARCH_X86_64),
            Some(&"sha256:def".to_string())
        );
    }

    #[test]
    fn record_replay_verdict_keys_by_normalized_arch() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_replay_verdict("X86-64", "sha256:abc", "sha256:abc");
        assert!(contract.replay_verdicts.contains_key(ARCH_X86_64));
    }

    #[test]
    fn required_arches_present_requires_both_targets() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_arch_fingerprint(fingerprint(ARCH_X86_64));
        assert!(!contract.required_arches_present());
        contract.record_arch_fingerprint(fingerprint(ARCH_AARCH64));
        assert!(contract.required_arches_present());
    }

    #[test]
    fn all_replays_matched_is_false_when_empty() {
        assert!(!ReproducibilityContract::strict().all_replays_matched());
    }

    #[test]
    fn all_replays_matched_requires_required_arch_verdicts() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_replay_verdict(ARCH_X86_64, "sha256:abc", "sha256:abc");
        contract.record_replay_verdict("wasm32", "sha256:abc", "sha256:abc");
        assert!(!contract.all_replays_matched());
    }

    #[test]
    fn all_replays_matched_detects_mismatch() {
        let mut contract = passing_contract();
        contract.record_replay_verdict(ARCH_AARCH64, "sha256:abc", "sha256:def");
        assert!(!contract.all_replays_matched());
    }

    #[test]
    fn content_hashes_equivalent_requires_both_arches() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_arch_fingerprint(fingerprint(ARCH_X86_64));
        contract.record_replay_verdict(ARCH_X86_64, "sha256:abc", "sha256:abc");
        assert!(!contract.content_hashes_equivalent());
    }

    #[test]
    fn content_hashes_equivalent_requires_both_required_observations() {
        let mut contract = ReproducibilityContract::strict();
        contract.record_arch_fingerprint(fingerprint(ARCH_X86_64));
        contract.record_arch_fingerprint(fingerprint(ARCH_AARCH64));
        contract.record_replay_verdict(ARCH_X86_64, "sha256:abc", "sha256:abc");
        contract.record_replay_verdict("wasm32", "sha256:abc", "sha256:abc");
        assert!(!contract.content_hashes_equivalent());
    }

    #[test]
    fn content_hashes_equivalent_accepts_same_hash_across_arches() {
        assert!(passing_contract().content_hashes_equivalent());
    }

    #[test]
    fn content_hashes_equivalent_rejects_different_hashes() {
        let mut contract = passing_contract();
        contract.record_replay_verdict(ARCH_AARCH64, "sha256:def", "sha256:def");
        assert!(!contract.content_hashes_equivalent());
    }

    #[test]
    fn deterministic_endianness_requires_little_endian() {
        assert!(passing_contract().deterministic_endianness());
    }

    #[test]
    fn deterministic_endianness_rejects_big_endian() {
        let mut contract = passing_contract();
        contract.record_endianness(ARCH_AARCH64, "big");
        assert!(!contract.deterministic_endianness());
    }

    #[test]
    fn deterministic_float_ordering_requires_total_bits() {
        assert!(passing_contract().deterministic_float_ordering());
    }

    #[test]
    fn deterministic_float_ordering_rejects_partial_ordering() {
        let mut contract = passing_contract();
        contract.record_float_ordering(ARCH_X86_64, "native_partial_cmp");
        assert!(!contract.deterministic_float_ordering());
    }

    #[test]
    fn invariant_verdicts_include_all_required_invariants() {
        let verdicts = passing_contract().invariant_verdicts();
        assert_eq!(verdicts.len(), 3);
        assert_eq!(
            verdicts.get(INVARIANT_CONTENT_HASH_EQUIVALENCE),
            Some(&true)
        );
        assert_eq!(
            verdicts.get(INVARIANT_DETERMINISTIC_FLOAT_ORDERING),
            Some(&true)
        );
        assert_eq!(verdicts.get(INVARIANT_ENDIANNESS), Some(&true));
    }

    #[test]
    fn passes_requires_all_invariants() {
        assert!(passing_contract().passes());
    }

    #[test]
    fn passes_fails_when_replay_hash_differs() {
        let mut contract = passing_contract();
        contract.record_replay_verdict(ARCH_X86_64, "sha256:abc", "sha256:def");
        assert!(!contract.passes());
    }

    #[test]
    fn contract_serializes_with_btree_maps() {
        let json = serde_json::to_string(&passing_contract()).expect("serialize contract");
        assert!(json.contains("\"arch_fingerprints\""));
        assert!(json.contains("\"required_invariants\""));
        assert!(json.contains("\"replay_verdicts\""));
    }

    #[test]
    fn contract_serde_round_trip_preserves_state() {
        let contract = passing_contract();
        let json = serde_json::to_string(&contract).expect("serialize contract");
        let restored: ReproducibilityContract =
            serde_json::from_str(&json).expect("deserialize contract");
        assert_eq!(contract, restored);
    }

    #[test]
    fn replay_verdict_serde_round_trip_preserves_matched_flag() {
        let verdict = ReplayVerdict::new("sha256:abc", "sha256:abc");
        let json = serde_json::to_string(&verdict).expect("serialize verdict");
        let restored: ReplayVerdict = serde_json::from_str(&json).expect("deserialize verdict");
        assert_eq!(verdict, restored);
        assert!(restored.matched);
    }

    #[test]
    fn arch_fingerprint_serde_round_trip_preserves_features() {
        let fingerprint = fingerprint(ARCH_X86_64);
        let json = serde_json::to_string(&fingerprint).expect("serialize fingerprint");
        let restored: ArchFingerprint =
            serde_json::from_str(&json).expect("deserialize fingerprint");
        assert_eq!(fingerprint, restored);
    }
}
