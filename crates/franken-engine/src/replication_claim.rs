#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Deterministic digest for a witness artifact used by external replication.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ContentDigest(pub [u8; 32]);

impl ContentDigest {
    /// Build a digest from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Deterministic test and fixture helper.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let mut bytes = [0_u8; 32];
        for (idx, byte) in label.as_bytes().iter().enumerate() {
            let slot = idx % bytes.len();
            bytes[slot] = bytes[slot].wrapping_add(*byte).wrapping_add(idx as u8);
        }
        Self(bytes)
    }
}

/// Externally replicated claim with exact expected witness matching.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ReplicationClaim {
    /// Stable claim identifier.
    pub claim_id: String,
    /// Witness digests expected from a successful independent replication.
    pub expected_witnesses: BTreeSet<ContentDigest>,
    /// Number of replication observations recorded.
    pub attempts: u64,
    /// Number of observations that exactly matched the expected witnesses.
    pub successes: u64,
}

impl ReplicationClaim {
    /// Create a claim with no recorded observations.
    #[must_use]
    pub fn new(claim_id: impl Into<String>, expected_witnesses: BTreeSet<ContentDigest>) -> Self {
        Self {
            claim_id: claim_id.into(),
            expected_witnesses,
            attempts: 0,
            successes: 0,
        }
    }

    /// Record one external observation and return whether it matched exactly.
    pub fn record_observation(&mut self, observed: &BTreeSet<ContentDigest>) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        let matched = observed == &self.expected_witnesses;
        if matched {
            self.successes = self.successes.saturating_add(1);
        }
        matched
    }

    /// Success ratio in fixed-point millionths.
    #[must_use]
    pub fn confidence_millionths(&self) -> u32 {
        if self.attempts == 0 {
            return 0;
        }
        let bounded_successes = self.successes.min(self.attempts);
        let scaled = u128::from(bounded_successes) * 1_000_000_u128 / u128::from(self.attempts);
        scaled as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> ContentDigest {
        ContentDigest::from_label(label)
    }

    fn set(labels: &[&str]) -> BTreeSet<ContentDigest> {
        labels.iter().map(|label| digest(label)).collect()
    }

    fn claim() -> ReplicationClaim {
        ReplicationClaim::new("throughput-3x", set(&["node-baseline", "franken-run"]))
    }

    #[test]
    fn content_digest_new_preserves_bytes() {
        let digest = ContentDigest::new([7_u8; 32]);
        assert_eq!(digest.0, [7_u8; 32]);
    }

    #[test]
    fn content_digest_from_label_is_deterministic() {
        assert_eq!(digest("witness-a"), digest("witness-a"));
    }

    #[test]
    fn content_digest_from_label_distinguishes_labels() {
        assert_ne!(digest("witness-a"), digest("witness-b"));
    }

    #[test]
    fn content_digest_orders_in_btree_set() {
        let witnesses = set(&["c", "a", "b"]);
        let ordered: Vec<_> = witnesses.into_iter().collect();
        let mut sorted = ordered.clone();
        sorted.sort();
        assert_eq!(ordered, sorted);
    }

    #[test]
    fn new_claim_stores_claim_id() {
        let claim = claim();
        assert_eq!(claim.claim_id, "throughput-3x");
    }

    #[test]
    fn new_claim_stores_expected_witnesses() {
        let expected = set(&["a", "b"]);
        let claim = ReplicationClaim::new("claim", expected.clone());
        assert_eq!(claim.expected_witnesses, expected);
    }

    #[test]
    fn new_claim_starts_with_zero_attempts() {
        assert_eq!(claim().attempts, 0);
    }

    #[test]
    fn new_claim_starts_with_zero_successes() {
        assert_eq!(claim().successes, 0);
    }

    #[test]
    fn confidence_is_zero_before_observations() {
        assert_eq!(claim().confidence_millionths(), 0);
    }

    #[test]
    fn exact_observation_matches() {
        let mut claim = claim();
        let observed = set(&["franken-run", "node-baseline"]);
        assert!(claim.record_observation(&observed));
    }

    #[test]
    fn exact_observation_increments_attempts() {
        let mut claim = claim();
        let observed = set(&["franken-run", "node-baseline"]);
        claim.record_observation(&observed);
        assert_eq!(claim.attempts, 1);
    }

    #[test]
    fn exact_observation_increments_successes() {
        let mut claim = claim();
        let observed = set(&["franken-run", "node-baseline"]);
        claim.record_observation(&observed);
        assert_eq!(claim.successes, 1);
    }

    #[test]
    fn missing_witness_does_not_match() {
        let mut claim = claim();
        let observed = set(&["node-baseline"]);
        assert!(!claim.record_observation(&observed));
    }

    #[test]
    fn extra_witness_does_not_match() {
        let mut claim = claim();
        let observed = set(&["node-baseline", "franken-run", "extra"]);
        assert!(!claim.record_observation(&observed));
    }

    #[test]
    fn different_witness_does_not_match() {
        let mut claim = claim();
        let observed = set(&["node-baseline", "other-run"]);
        assert!(!claim.record_observation(&observed));
    }

    #[test]
    fn failed_observation_increments_attempts_only() {
        let mut claim = claim();
        let observed = set(&["node-baseline"]);
        claim.record_observation(&observed);
        assert_eq!(claim.attempts, 1);
        assert_eq!(claim.successes, 0);
    }

    #[test]
    fn confidence_is_one_million_for_all_successes() {
        let mut claim = claim();
        let observed = set(&["node-baseline", "franken-run"]);
        claim.record_observation(&observed);
        claim.record_observation(&observed);
        assert_eq!(claim.confidence_millionths(), 1_000_000);
    }

    #[test]
    fn confidence_is_half_for_one_of_two_successes() {
        let mut claim = claim();
        claim.record_observation(&set(&["node-baseline", "franken-run"]));
        claim.record_observation(&set(&["node-baseline"]));
        assert_eq!(claim.confidence_millionths(), 500_000);
    }

    #[test]
    fn confidence_truncates_fractional_millionths() {
        let mut claim = claim();
        claim.record_observation(&set(&["node-baseline", "franken-run"]));
        claim.record_observation(&set(&["node-baseline"]));
        claim.record_observation(&set(&["node-baseline"]));
        assert_eq!(claim.confidence_millionths(), 333_333);
    }

    #[test]
    fn empty_expected_matches_empty_observed() {
        let mut claim = ReplicationClaim::new("empty-control", BTreeSet::new());
        assert!(claim.record_observation(&BTreeSet::new()));
    }

    #[test]
    fn empty_expected_rejects_non_empty_observed() {
        let mut claim = ReplicationClaim::new("empty-control", BTreeSet::new());
        assert!(!claim.record_observation(&set(&["unexpected"])));
    }

    #[test]
    fn duplicate_observed_labels_collapse_before_comparison() {
        let mut claim = ReplicationClaim::new("single", set(&["a"]));
        let observed = ["a", "a"].into_iter().map(digest).collect();
        assert!(claim.record_observation(&observed));
    }

    #[test]
    fn cloned_claim_preserves_counters() {
        let mut claim = claim();
        claim.record_observation(&set(&["node-baseline", "franken-run"]));
        assert_eq!(claim.clone(), claim);
    }

    #[test]
    fn claim_ordering_is_deterministic() {
        let mut claims = [
            ReplicationClaim::new("b-claim", set(&["witness"])),
            ReplicationClaim::new("a-claim", set(&["witness"])),
        ];

        claims.sort();

        assert_eq!(claims[0].claim_id, "a-claim");
        assert_eq!(claims[1].claim_id, "b-claim");
    }

    #[test]
    fn serde_roundtrip_preserves_claim() {
        let mut claim = claim();
        claim.record_observation(&set(&["node-baseline", "franken-run"]));
        let json = serde_json::to_string(&claim).expect("claim should serialize");
        let restored: ReplicationClaim =
            serde_json::from_str(&json).expect("claim should deserialize");
        assert_eq!(restored, claim);
    }

    #[test]
    fn serde_roundtrip_preserves_digest() {
        let digest = digest("replication-witness");
        let json = serde_json::to_string(&digest).expect("digest should serialize");
        let restored: ContentDigest =
            serde_json::from_str(&json).expect("digest should deserialize");
        assert_eq!(restored, digest);
    }

    #[test]
    fn saturated_attempt_counter_does_not_wrap() {
        let mut claim = claim();
        claim.attempts = u64::MAX;
        claim.record_observation(&set(&["node-baseline"]));
        assert_eq!(claim.attempts, u64::MAX);
    }

    #[test]
    fn saturated_success_counter_does_not_wrap() {
        let mut claim = claim();
        claim.attempts = u64::MAX;
        claim.successes = u64::MAX;
        claim.record_observation(&set(&["node-baseline", "franken-run"]));
        assert_eq!(claim.successes, u64::MAX);
        assert_eq!(claim.confidence_millionths(), 1_000_000);
    }

    #[test]
    fn failed_observation_still_lowers_confidence_above_u32_capacity() {
        let mut claim = claim();
        claim.attempts = u64::from(u32::MAX);
        claim.successes = u64::from(u32::MAX);
        claim.record_observation(&set(&["node-baseline"]));
        assert_eq!(claim.attempts, u64::from(u32::MAX) + 1);
        assert_eq!(claim.successes, u64::from(u32::MAX));
        assert_eq!(claim.confidence_millionths(), 999_999);
    }

    #[test]
    fn confidence_clamps_successes_above_attempts_to_full_confidence() {
        let mut claim = claim();
        claim.attempts = 3;
        claim.successes = 5;
        assert_eq!(claim.confidence_millionths(), 1_000_000);
    }
}
