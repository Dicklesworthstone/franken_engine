//! Signed N-counterfactual fleet-replay report schema (Track S / `bd-cixqu.19.2`).
//!
//! Schema id: `franken-engine.fleet-counterfactual-report.v1`.
//!
//! A [`FleetCounterfactualReport`] records the outcome of replaying N fleet
//! traces under a substituted policy (Track S.1 counterfactual replay): the
//! original and substituted policy identities, per-node decision deltas, the
//! aggregate delta, the evidence hash-chain root the replay was anchored to,
//! and a detached [`SignatureBundle`] over the report's canonical preimage.
//!
//! Determinism contract:
//! - Fractional quantities are fixed-point millionths (`1_000_000 == 1.0`).
//! - Field ordering is `BTreeMap`/`Vec`-stable; canonical encoding routes
//!   through [`deterministic_serde`] (length-prefixed).
//! - The [`SchemaId`] is derived from the schema *definition* (not a mutable
//!   label), so identical definitions yield identical ids.
//! - The signing preimage is `schema_id || u32_be(len) || canonical(unsigned)`,
//!   i.e. signatures cover everything **except** the signature bundle itself.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::engine_object_id::SchemaId;
use crate::hash_tiers::ContentHash;

/// Human-readable schema name (also the first line of the schema definition).
pub const SCHEMA_NAME: &str = "franken-engine.fleet-counterfactual-report.v1";

/// Schema definition bytes from which the stable [`SchemaId`] is derived.
///
/// Changing any field shape here changes the `SchemaId`, which is the intended
/// behavior: consumers bind to a specific layout.
pub const SCHEMA_DEFINITION: &[u8] = b"\
franken-engine.fleet-counterfactual-report.v1
original_policy_id:hash32
substituted_policy_id:hash32
per_node_decisions:[node_id:u64,original_decision:tag,substituted_decision:tag,delta_millionths:i64]
aggregate_decision_delta:{changed_nodes:u64,total_nodes:u64,net_delta_millionths:i64}
evidence_hash_chain_root:hash32
signature_bundle:[signer_key_id:hash32,signature:bytes]";

/// The decision a guardplane node reached for a trace, under a given policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CounterfactualDecision {
    /// The action was permitted.
    Approved,
    /// The action was denied.
    Rejected,
    /// The decision was deferred (e.g. escalated).
    Deferred,
    /// No determination could be made.
    Inconclusive,
}

impl CounterfactualDecision {
    /// Stable lowercase tag used in the canonical encoding. Never reorder or
    /// rename without bumping the schema version.
    pub fn tag(self) -> &'static str {
        match self {
            CounterfactualDecision::Approved => "approved",
            CounterfactualDecision::Rejected => "rejected",
            CounterfactualDecision::Deferred => "deferred",
            CounterfactualDecision::Inconclusive => "inconclusive",
        }
    }

    /// Inverse of [`tag`](Self::tag).
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "approved" => Some(CounterfactualDecision::Approved),
            "rejected" => Some(CounterfactualDecision::Rejected),
            "deferred" => Some(CounterfactualDecision::Deferred),
            "inconclusive" => Some(CounterfactualDecision::Inconclusive),
            _ => None,
        }
    }
}

/// One node's decision change between the original and substituted policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDecisionDelta {
    /// Fleet-local node identifier.
    pub node_id: u64,
    /// Decision the node reached under the original policy.
    pub original_decision: CounterfactualDecision,
    /// Decision the node reached under the substituted policy.
    pub substituted_decision: CounterfactualDecision,
    /// Change in the node's decision score, fixed-point millionths (signed).
    pub delta_millionths: i64,
}

impl NodeDecisionDelta {
    /// Whether the substituted policy changed this node's decision.
    pub fn changed(&self) -> bool {
        self.original_decision != self.substituted_decision
    }

    fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(BTreeMap::from([
            ("node_id".to_string(), CanonicalValue::U64(self.node_id)),
            (
                "original_decision".to_string(),
                CanonicalValue::String(self.original_decision.tag().to_string()),
            ),
            (
                "substituted_decision".to_string(),
                CanonicalValue::String(self.substituted_decision.tag().to_string()),
            ),
            (
                "delta_millionths".to_string(),
                CanonicalValue::I64(self.delta_millionths),
            ),
        ]))
    }
}

/// Fleet-wide summary of the counterfactual substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateDecisionDelta {
    /// Number of nodes whose decision changed.
    pub changed_nodes: u64,
    /// Total number of nodes replayed.
    pub total_nodes: u64,
    /// Net aggregate score change across the fleet, fixed-point millionths.
    pub net_delta_millionths: i64,
}

impl AggregateDecisionDelta {
    /// Fraction of nodes whose decision changed, in millionths (`0..=1_000_000`).
    /// Returns `0` for an empty fleet.
    pub fn changed_fraction_millionths(&self) -> u64 {
        if self.total_nodes == 0 {
            return 0;
        }
        // u128 to avoid overflow; result is bounded by 1_000_000 since
        // changed_nodes <= total_nodes (see `is_consistent`).
        ((self.changed_nodes as u128 * 1_000_000) / self.total_nodes as u128) as u64
    }

    fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(BTreeMap::from([
            (
                "changed_nodes".to_string(),
                CanonicalValue::U64(self.changed_nodes),
            ),
            (
                "total_nodes".to_string(),
                CanonicalValue::U64(self.total_nodes),
            ),
            (
                "net_delta_millionths".to_string(),
                CanonicalValue::I64(self.net_delta_millionths),
            ),
        ]))
    }
}

/// One detached signature over a report's signing preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSignature {
    /// Content identity of the signer's public key.
    pub signer_key_id: ContentHash,
    /// Detached signature bytes (e.g. a 64-byte ed25519 signature).
    pub signature: Vec<u8>,
}

/// Bundle of detached signatures attesting to a report (≥1 for a signed report).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// Signatures, in signer order.
    pub signatures: Vec<ReportSignature>,
}

impl SignatureBundle {
    /// A bundle is present iff it carries at least one signature.
    pub fn is_signed(&self) -> bool {
        !self.signatures.is_empty()
    }
}

/// The `franken-engine.fleet-counterfactual-report.v1` report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetCounterfactualReport {
    /// Content identity of the original (baseline) policy snapshot.
    pub original_policy_id: ContentHash,
    /// Content identity of the substituted (counterfactual) policy snapshot.
    pub substituted_policy_id: ContentHash,
    /// Per-node decision deltas, in node order.
    pub per_node_decisions: Vec<NodeDecisionDelta>,
    /// Fleet-wide aggregate delta.
    pub aggregate_decision_delta: AggregateDecisionDelta,
    /// Root of the evidence hash chain the replay was anchored to.
    pub evidence_hash_chain_root: ContentHash,
    /// Detached signatures over [`signing_preimage`](Self::signing_preimage).
    pub signature_bundle: SignatureBundle,
}

impl FleetCounterfactualReport {
    /// Stable schema id derived from [`SCHEMA_DEFINITION`].
    pub fn schema_id() -> SchemaId {
        SchemaId::from_definition(SCHEMA_DEFINITION)
    }

    /// Canonical value of everything the signature covers (i.e. excluding the
    /// signature bundle). This is the preimage body.
    pub fn unsigned_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(BTreeMap::from([
            (
                "schema".to_string(),
                CanonicalValue::String(SCHEMA_NAME.to_string()),
            ),
            (
                "original_policy_id".to_string(),
                CanonicalValue::Bytes(self.original_policy_id.as_bytes().to_vec()),
            ),
            (
                "substituted_policy_id".to_string(),
                CanonicalValue::Bytes(self.substituted_policy_id.as_bytes().to_vec()),
            ),
            (
                "per_node_decisions".to_string(),
                CanonicalValue::Array(
                    self.per_node_decisions
                        .iter()
                        .map(NodeDecisionDelta::canonical_value)
                        .collect(),
                ),
            ),
            (
                "aggregate_decision_delta".to_string(),
                self.aggregate_decision_delta.canonical_value(),
            ),
            (
                "evidence_hash_chain_root".to_string(),
                CanonicalValue::Bytes(self.evidence_hash_chain_root.as_bytes().to_vec()),
            ),
        ]))
    }

    /// Length-prefixed signing preimage: `schema_id || u32_be(len) || canonical`.
    ///
    /// The schema-id prefix binds the signature to this exact layout; the
    /// length prefix enforces the project's canonical-framing discipline so the
    /// preimage cannot be confused with a differently-sized one.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let canonical = encode_value(&self.unsigned_canonical_value());
        let len = canonical.len().min(u32::MAX as usize) as u32;
        let mut buf = Vec::with_capacity(self.schema_id_len() + 4 + canonical.len());
        buf.extend_from_slice(Self::schema_id().as_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&canonical[..len as usize]);
        buf
    }

    fn schema_id_len(&self) -> usize {
        Self::schema_id().as_bytes().len()
    }

    /// SHA-256 digest of the [`signing_preimage`](Self::signing_preimage); this
    /// is what each [`ReportSignature`] signs.
    pub fn signing_digest(&self) -> ContentHash {
        ContentHash::compute(&self.signing_preimage())
    }

    /// Structural consistency: `changed_nodes <= total_nodes` and the count of
    /// per-node deltas that actually changed equals `changed_nodes`.
    pub fn is_consistent(&self) -> bool {
        if self.aggregate_decision_delta.changed_nodes > self.aggregate_decision_delta.total_nodes {
            return false;
        }
        let observed_changed = self
            .per_node_decisions
            .iter()
            .filter(|d| d.changed())
            .count() as u64;
        observed_changed == self.aggregate_decision_delta.changed_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> ContentHash {
        ContentHash::from_bytes([seed; 32])
    }

    fn sample(changed: u64, total: u64) -> FleetCounterfactualReport {
        let per_node_decisions: Vec<NodeDecisionDelta> = (0..total)
            .map(|i| {
                let did_change = i < changed;
                NodeDecisionDelta {
                    node_id: i,
                    original_decision: CounterfactualDecision::Approved,
                    substituted_decision: if did_change {
                        CounterfactualDecision::Rejected
                    } else {
                        CounterfactualDecision::Approved
                    },
                    delta_millionths: if did_change { -250_000 } else { 0 },
                }
            })
            .collect();
        FleetCounterfactualReport {
            original_policy_id: h(1),
            substituted_policy_id: h(2),
            per_node_decisions,
            aggregate_decision_delta: AggregateDecisionDelta {
                changed_nodes: changed,
                total_nodes: total,
                net_delta_millionths: -(changed as i64) * 250_000,
            },
            evidence_hash_chain_root: h(3),
            signature_bundle: SignatureBundle::default(),
        }
    }

    #[test]
    fn schema_id_is_deterministic() {
        assert_eq!(
            FleetCounterfactualReport::schema_id(),
            FleetCounterfactualReport::schema_id()
        );
        assert_eq!(
            FleetCounterfactualReport::schema_id(),
            SchemaId::from_definition(SCHEMA_DEFINITION)
        );
    }

    #[test]
    fn schema_id_is_nonzero() {
        assert_ne!(
            FleetCounterfactualReport::schema_id().as_bytes(),
            &[0u8; 32]
        );
    }

    #[test]
    fn schema_name_is_first_line_of_definition() {
        let first = SCHEMA_DEFINITION.split(|&b| b == b'\n').next().unwrap();
        assert_eq!(first, SCHEMA_NAME.as_bytes());
    }

    #[test]
    fn report_serde_round_trip() {
        let r = sample(2, 5);
        let json = serde_json::to_string(&r).expect("serialize");
        let back: FleetCounterfactualReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn node_delta_serde_round_trip() {
        let d = NodeDecisionDelta {
            node_id: 7,
            original_decision: CounterfactualDecision::Deferred,
            substituted_decision: CounterfactualDecision::Inconclusive,
            delta_millionths: i64::MIN,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(d, serde_json::from_str(&json).unwrap());
    }

    #[test]
    fn aggregate_serde_round_trip() {
        let a = AggregateDecisionDelta {
            changed_nodes: 3,
            total_nodes: 9,
            net_delta_millionths: i64::MAX,
        };
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(a, serde_json::from_str(&json).unwrap());
    }

    #[test]
    fn decision_tag_round_trips_all_variants() {
        for d in [
            CounterfactualDecision::Approved,
            CounterfactualDecision::Rejected,
            CounterfactualDecision::Deferred,
            CounterfactualDecision::Inconclusive,
        ] {
            assert_eq!(CounterfactualDecision::from_tag(d.tag()), Some(d));
        }
        assert_eq!(CounterfactualDecision::from_tag("bogus"), None);
    }

    #[test]
    fn decision_tags_are_distinct() {
        let tags = [
            CounterfactualDecision::Approved.tag(),
            CounterfactualDecision::Rejected.tag(),
            CounterfactualDecision::Deferred.tag(),
            CounterfactualDecision::Inconclusive.tag(),
        ];
        let mut sorted = tags.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len());
    }

    #[test]
    fn node_delta_changed_flag() {
        let mut d = NodeDecisionDelta {
            node_id: 0,
            original_decision: CounterfactualDecision::Approved,
            substituted_decision: CounterfactualDecision::Approved,
            delta_millionths: 0,
        };
        assert!(!d.changed());
        d.substituted_decision = CounterfactualDecision::Rejected;
        assert!(d.changed());
    }

    #[test]
    fn signing_preimage_starts_with_schema_id() {
        let r = sample(1, 3);
        let pre = r.signing_preimage();
        assert!(pre.starts_with(FleetCounterfactualReport::schema_id().as_bytes()));
    }

    #[test]
    fn signing_preimage_has_length_prefix() {
        let r = sample(1, 3);
        let pre = r.signing_preimage();
        let canonical = encode_value(&r.unsigned_canonical_value());
        let off = FleetCounterfactualReport::schema_id().as_bytes().len();
        let len_bytes: [u8; 4] = pre[off..off + 4].try_into().unwrap();
        assert_eq!(u32::from_be_bytes(len_bytes) as usize, canonical.len());
    }

    #[test]
    fn signing_preimage_excludes_signatures() {
        let mut a = sample(1, 3);
        let mut b = sample(1, 3);
        a.signature_bundle = SignatureBundle::default();
        b.signature_bundle = SignatureBundle {
            signatures: vec![ReportSignature {
                signer_key_id: h(9),
                signature: vec![0xAB; 64],
            }],
        };
        // Differ only in the signature bundle => identical signing preimage/digest.
        assert_eq!(a.signing_preimage(), b.signing_preimage());
        assert_eq!(a.signing_digest(), b.signing_digest());
    }

    #[test]
    fn signing_digest_is_deterministic() {
        let r = sample(2, 4);
        assert_eq!(r.signing_digest(), r.signing_digest());
    }

    #[test]
    fn signing_digest_changes_with_original_policy() {
        let r = sample(2, 4);
        let mut r2 = r.clone();
        r2.original_policy_id = h(42);
        assert_ne!(r.signing_digest(), r2.signing_digest());
    }

    #[test]
    fn signing_digest_changes_with_substituted_policy() {
        let r = sample(2, 4);
        let mut r2 = r.clone();
        r2.substituted_policy_id = h(43);
        assert_ne!(r.signing_digest(), r2.signing_digest());
    }

    #[test]
    fn signing_digest_changes_with_evidence_root() {
        let r = sample(2, 4);
        let mut r2 = r.clone();
        r2.evidence_hash_chain_root = h(44);
        assert_ne!(r.signing_digest(), r2.signing_digest());
    }

    #[test]
    fn signing_digest_changes_with_node_decision() {
        let r = sample(2, 4);
        let mut r2 = r.clone();
        r2.per_node_decisions[0].delta_millionths += 1;
        assert_ne!(r.signing_digest(), r2.signing_digest());
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let r = sample(3, 6);
        assert_eq!(
            encode_value(&r.unsigned_canonical_value()),
            encode_value(&r.unsigned_canonical_value())
        );
    }

    #[test]
    fn unsigned_value_is_a_map() {
        let r = sample(1, 2);
        assert!(matches!(
            r.unsigned_canonical_value(),
            CanonicalValue::Map(_)
        ));
    }

    #[test]
    fn changed_fraction_empty_fleet_is_zero() {
        let a = AggregateDecisionDelta {
            changed_nodes: 0,
            total_nodes: 0,
            net_delta_millionths: 0,
        };
        assert_eq!(a.changed_fraction_millionths(), 0);
    }

    #[test]
    fn changed_fraction_half() {
        let a = AggregateDecisionDelta {
            changed_nodes: 1,
            total_nodes: 2,
            net_delta_millionths: 0,
        };
        assert_eq!(a.changed_fraction_millionths(), 500_000);
    }

    #[test]
    fn changed_fraction_all() {
        let a = AggregateDecisionDelta {
            changed_nodes: 25,
            total_nodes: 25,
            net_delta_millionths: 0,
        };
        assert_eq!(a.changed_fraction_millionths(), 1_000_000);
    }

    #[test]
    fn changed_fraction_no_overflow_large() {
        let a = AggregateDecisionDelta {
            changed_nodes: u64::MAX / 2,
            total_nodes: u64::MAX,
            net_delta_millionths: 0,
        };
        // ~0.5 of the fleet changed; result must stay within [0, 1_000_000].
        assert!(a.changed_fraction_millionths() <= 1_000_000);
    }

    #[test]
    fn consistency_accepts_matching_counts() {
        let r = sample(2, 5);
        assert!(r.is_consistent());
    }

    #[test]
    fn consistency_rejects_changed_exceeding_total() {
        let mut r = sample(2, 5);
        r.aggregate_decision_delta.changed_nodes = 99;
        assert!(!r.is_consistent());
    }

    #[test]
    fn consistency_rejects_count_mismatch() {
        let mut r = sample(2, 5);
        // Claim 4 changed but only 2 nodes actually differ.
        r.aggregate_decision_delta.changed_nodes = 4;
        assert!(!r.is_consistent());
    }

    #[test]
    fn empty_fleet_report_is_consistent_and_encodes() {
        let r = sample(0, 0);
        assert!(r.is_consistent());
        assert!(!r.signing_preimage().is_empty());
    }

    #[test]
    fn signature_bundle_is_signed_flag() {
        let mut b = SignatureBundle::default();
        assert!(!b.is_signed());
        b.signatures.push(ReportSignature {
            signer_key_id: h(1),
            signature: vec![1, 2, 3],
        });
        assert!(b.is_signed());
    }

    #[test]
    fn large_fleet_round_trips_and_is_consistent() {
        let r = sample(40, 100);
        assert!(r.is_consistent());
        let json = serde_json::to_string(&r).unwrap();
        let back: FleetCounterfactualReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert_eq!(back.signing_digest(), r.signing_digest());
    }
}
