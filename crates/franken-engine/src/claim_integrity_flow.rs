//! Over-promotion as an information-flow (Biba integrity) violation
//! (CEI track H.3, bead `bd-sde5e.8.3`).
//!
//! # The unification
//!
//! The runtime already enforces an information-flow algebra on *guest data*
//! ([`crate::flow_lattice`]): data carries a confidentiality label, sinks carry a
//! clearance, and a flow is legal only when the lattice permits it — otherwise it
//! is blocked unless an explicit, signed declassification receipt authorizes it.
//!
//! CEI track H.3 observes that **claim honesty is the same problem, dualized**.
//! Read the project's claims through the *integrity* (Biba) reading of the same
//! finite lattice:
//!
//! * a claim's committed evidence is *data* whose **integrity** is its evidence
//!   tier ([`EvidenceTier`]): `Unbacked` is the lowest integrity, an
//!   `AdversariallyVerified` bundle the highest;
//! * the claim's asserted state ([`ClaimAssertionState`]) is a *sink* whose
//!   **required integrity** is how much trust the wording demands: `Hypothesis`
//!   demands nothing, `Observed` prose demands high-integrity evidence.
//!
//! A claim assertion is then a flow `evidence ⟶ prose`. By Biba's "no write-up"
//! rule, low-integrity evidence may not flow into high-integrity prose. An
//! **over-promotion** — asserting `Observed` on `Unbacked` evidence — is exactly a
//! Biba integrity violation, caught by the same `≤`-algebra the runtime enforces
//! on guest data. The only sanctioned escape is an explicit
//! [`EvidencePromotionReceipt`] — the integrity dual of a declassification
//! receipt — that endorses one specific (claim, tier→state) promotion.
//!
//! # Soundness: equivalent to the A.1 predicate
//!
//! The integrity mapping is calibrated so the flow verdict is **provably
//! equivalent** to the Track A.1 soundness predicate `state ≤ ceiling(tier)`
//! (proven exhaustively over all 3×5 state/tier pairs by [`tests`]):
//!
//! ```text
//! flow_legal(state, tier)  ⟺  required_integrity(state) ≤ evidence_integrity(tier)
//!                          ⟺  state ≤ ceiling(tier)            (A.1 soundness)
//! ```
//!
//! So this module does not invent a second, possibly-divergent honesty check: it
//! re-expresses the *same* soundness condition in the runtime's own IFC vocabulary,
//! and adds the receipt-mediated endorsement path that the lattice framing makes
//! natural.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim_evidence_lattice::{
    ClaimAssertionState, EvidenceTier, IntegrityError, score_matrix_file,
};
use crate::flow_lattice::LabelClass;

/// Domain tag mixed into a promotion-receipt content hash (injectivity).
pub const PROMOTION_RECEIPT_DOMAIN: &str = "franken-engine.evidence-promotion-receipt.v1";

// ---------------------------------------------------------------------------
// The integrity reading of the runtime's confidentiality lattice
// ---------------------------------------------------------------------------

/// The integrity level of a claim's committed evidence, expressed in the runtime's
/// own [`LabelClass`] carrier (`Public < Internal < Confidential < Secret <
/// TopSecret`). This is the **Biba dual** of the runtime's confidentiality use of
/// the same five-element chain: here a *higher* level means *higher integrity*
/// (more trustworthy evidence), and the forbidden direction is low-integrity
/// evidence flowing into high-integrity prose.
///
/// The map is an order-isomorphism `EvidenceTier ≅ LabelClass` (both are 5-chains).
#[must_use]
pub fn evidence_integrity(tier: EvidenceTier) -> LabelClass {
    match tier {
        EvidenceTier::Unbacked => LabelClass::Public,
        EvidenceTier::Asserted => LabelClass::Internal,
        EvidenceTier::Exercised => LabelClass::Confidential,
        EvidenceTier::Reproduced => LabelClass::Secret,
        EvidenceTier::AdversariallyVerified => LabelClass::TopSecret,
    }
}

/// The minimum evidence integrity a given asserted state may legally flow from.
///
/// Calibrated to make the flow verdict equivalent to `state ≤ ceiling(tier)`:
/// `Hypothesis` requires nothing (`Public`), `Target` requires at least an
/// `Asserted` artifact (`Internal`), and `Observed` requires at least a
/// `Reproduced` bundle (`Secret`). Proven equivalent in [`tests`].
#[must_use]
pub fn required_integrity(state: ClaimAssertionState) -> LabelClass {
    match state {
        ClaimAssertionState::Hypothesis => LabelClass::Public,
        ClaimAssertionState::Target => LabelClass::Internal,
        ClaimAssertionState::Observed => LabelClass::Secret,
    }
}

/// Whether a claim asserted at `state` may legally flow from evidence at `tier`
/// under the Biba integrity rule (evidence integrity ≥ required integrity).
#[must_use]
pub fn flow_legal(state: ClaimAssertionState, tier: EvidenceTier) -> bool {
    evidence_integrity(tier).level() >= required_integrity(state).level()
}

// ---------------------------------------------------------------------------
// Evidence-promotion receipt (the integrity dual of a declassification receipt)
// ---------------------------------------------------------------------------

/// An explicit, content-addressed endorsement that authorizes one specific
/// over-promotion — the integrity-lattice dual of a declassification receipt.
///
/// Without such a receipt, asserting a state above the evidence ceiling is an
/// integrity violation. A receipt names exactly which `(claim_id, from_tier,
/// to_state)` promotion it endorses, who authorized it, and why; it endorses
/// nothing else. An empty authorizer or justification makes the receipt invalid
/// (a receipt must record real accountability, not a rubber stamp).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePromotionReceipt {
    /// The claim this receipt endorses a promotion for.
    pub claim_id: String,
    /// The evidence tier actually committed (the source integrity).
    pub from_tier: EvidenceTier,
    /// The asserted state this receipt authorizes despite `from_tier`.
    pub to_state: ClaimAssertionState,
    /// Key id / operator identity that authorized the promotion (must be non-empty).
    pub authorized_by: String,
    /// Human-readable justification for the endorsement (must be non-empty).
    pub justification: String,
}

impl EvidencePromotionReceipt {
    /// A receipt is structurally valid only when it records real accountability.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.claim_id.trim().is_empty()
            && !self.authorized_by.trim().is_empty()
            && !self.justification.trim().is_empty()
    }

    /// Whether this (valid) receipt authorizes the given over-promotion exactly.
    #[must_use]
    pub fn authorizes(
        &self,
        claim_id: &str,
        asserted_state: ClaimAssertionState,
        evidence_tier: EvidenceTier,
    ) -> bool {
        self.is_valid()
            && self.claim_id == claim_id
            && self.from_tier == evidence_tier
            && self.to_state == asserted_state
    }

    /// Content-addressed receipt identity (length-prefixed, domain-separated).
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        push_len_prefixed(&mut buf, PROMOTION_RECEIPT_DOMAIN.as_bytes());
        push_len_prefixed(&mut buf, self.claim_id.as_bytes());
        buf.push(self.from_tier.rank());
        buf.push(self.to_state.rank());
        push_len_prefixed(&mut buf, self.authorized_by.as_bytes());
        push_len_prefixed(&mut buf, self.justification.as_bytes());
        hex::encode(Sha256::digest(&buf))
    }
}

/// Append `bytes` with a fixed-width `u64` little-endian length prefix.
fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// Per-claim verdict
// ---------------------------------------------------------------------------

/// The information-flow verdict for one claim assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ClaimFlowVerdict {
    /// The flow is legal under the lattice (evidence integrity ≥ required).
    Legal,
    /// Over-promotion, but a valid matching receipt endorses it.
    EndorsedByReceipt {
        /// Content-addressed id of the authorizing receipt.
        receipt_id: String,
    },
    /// Over-promotion with no authorizing receipt — an integrity violation.
    Violation {
        /// The integrity the asserted state demands.
        required: String,
        /// The integrity the committed evidence actually has.
        evidence: String,
    },
}

impl ClaimFlowVerdict {
    /// Whether this verdict represents an unauthorized integrity violation.
    #[must_use]
    pub fn is_violation(&self) -> bool {
        matches!(self, Self::Violation { .. })
    }
}

impl fmt::Display for ClaimFlowVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legal => write!(f, "legal"),
            Self::EndorsedByReceipt { receipt_id } => {
                write!(f, "endorsed_by_receipt({receipt_id})")
            }
            Self::Violation { required, evidence } => {
                write!(f, "VIOLATION(requires {required}, evidence {evidence})")
            }
        }
    }
}

/// Decide the information-flow verdict for a single claim assertion.
///
/// Legal when the lattice permits the flow; otherwise an endorsement by a valid,
/// exactly-matching [`EvidencePromotionReceipt`] downgrades the violation to
/// `EndorsedByReceipt`; with no such receipt it is a `Violation`.
#[must_use]
pub fn check_claim_flow(
    claim_id: &str,
    asserted_state: ClaimAssertionState,
    evidence_tier: EvidenceTier,
    receipts: &[EvidencePromotionReceipt],
) -> ClaimFlowVerdict {
    if flow_legal(asserted_state, evidence_tier) {
        return ClaimFlowVerdict::Legal;
    }
    if let Some(receipt) = receipts
        .iter()
        .find(|r| r.authorizes(claim_id, asserted_state, evidence_tier))
    {
        return ClaimFlowVerdict::EndorsedByReceipt {
            receipt_id: receipt.content_hash_hex(),
        };
    }
    ClaimFlowVerdict::Violation {
        required: required_integrity(asserted_state).to_string(),
        evidence: evidence_integrity(evidence_tier).to_string(),
    }
}

// ---------------------------------------------------------------------------
// Whole-matrix scan
// ---------------------------------------------------------------------------

/// One claim's flow verdict, keyed for reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimFlowRecord {
    pub claim_id: String,
    pub asserted_state: ClaimAssertionState,
    pub evidence_tier: EvidenceTier,
    pub verdict: ClaimFlowVerdict,
}

/// The whole-matrix information-flow report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowReport {
    /// Per-claim records, sorted by claim id (deterministic).
    pub records: Vec<ClaimFlowRecord>,
    /// Number of claims whose assertion is an unauthorized integrity violation.
    pub violations: u64,
    /// Number of claims whose over-promotion is endorsed by a receipt.
    pub endorsed: u64,
}

impl FlowReport {
    /// Whether every claim's assertion is either legal or receipt-endorsed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.violations == 0
    }

    /// The claim ids that are unauthorized integrity violations.
    #[must_use]
    pub fn violating_claims(&self) -> Vec<&str> {
        self.records
            .iter()
            .filter(|r| r.verdict.is_violation())
            .map(|r| r.claim_id.as_str())
            .collect()
    }
}

/// Scan the live claim-to-proof matrix and committed evidence, returning the
/// information-flow report. Reuses the A.1 scorer for (asserted state, evidence
/// tier) per claim, then applies the integrity-flow check with the supplied
/// endorsement receipts.
pub fn scan_claim_integrity_flows(
    matrix_path: &Path,
    repo_root: &Path,
    now_unix: i64,
    max_freshness_days: Option<u64>,
    receipts: &[EvidencePromotionReceipt],
) -> Result<FlowReport, IntegrityError> {
    let report = score_matrix_file(matrix_path, repo_root, now_unix, max_freshness_days)?;
    let mut records = Vec::with_capacity(report.verdicts.len());
    let mut violations: u64 = 0;
    let mut endorsed: u64 = 0;
    for (claim_id, verdict) in &report.verdicts {
        let flow = check_claim_flow(
            claim_id,
            verdict.asserted_state,
            verdict.evidence_tier,
            receipts,
        );
        match &flow {
            ClaimFlowVerdict::Violation { .. } => violations += 1,
            ClaimFlowVerdict::EndorsedByReceipt { .. } => endorsed += 1,
            ClaimFlowVerdict::Legal => {}
        }
        records.push(ClaimFlowRecord {
            claim_id: claim_id.clone(),
            asserted_state: verdict.asserted_state,
            evidence_tier: verdict.evidence_tier,
            verdict: flow,
        });
    }
    Ok(FlowReport {
        records,
        violations,
        endorsed,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim_evidence_lattice::ceiling;

    #[test]
    fn integrity_flow_is_equivalent_to_a1_soundness() {
        // The whole point: the IFC verdict must agree with `state ≤ ceiling(tier)`
        // for every one of the 3×5 state/tier pairs.
        for state in ClaimAssertionState::all() {
            for tier in EvidenceTier::all() {
                let a1_sound = state <= ceiling(tier);
                let flow = flow_legal(state, tier);
                assert_eq!(
                    a1_sound, flow,
                    "IFC flow verdict diverges from A.1 soundness at state={state} tier={tier}"
                );
            }
        }
    }

    #[test]
    fn observed_on_unbacked_is_a_violation_without_a_receipt() {
        let v = check_claim_flow(
            "FE-CLAIM-999",
            ClaimAssertionState::Observed,
            EvidenceTier::Unbacked,
            &[],
        );
        assert!(
            v.is_violation(),
            "observed prose on unbacked evidence must violate"
        );
    }

    #[test]
    fn legal_flow_needs_no_receipt() {
        // Observed on Reproduced is lattice-legal.
        let v = check_claim_flow(
            "FE-CLAIM-001",
            ClaimAssertionState::Observed,
            EvidenceTier::Reproduced,
            &[],
        );
        assert_eq!(v, ClaimFlowVerdict::Legal);
    }

    #[test]
    fn matching_receipt_endorses_the_exact_over_promotion() {
        let receipt = EvidencePromotionReceipt {
            claim_id: "FE-CLAIM-022".into(),
            from_tier: EvidenceTier::Asserted,
            to_state: ClaimAssertionState::Observed,
            authorized_by: "operator:release-captain".into(),
            justification: "CI matrix verifies on real Node/multi-platform; waived on this host"
                .into(),
        };
        let v = check_claim_flow(
            "FE-CLAIM-022",
            ClaimAssertionState::Observed,
            EvidenceTier::Asserted,
            std::slice::from_ref(&receipt),
        );
        match v {
            ClaimFlowVerdict::EndorsedByReceipt { receipt_id } => {
                assert_eq!(receipt_id, receipt.content_hash_hex());
            }
            other => panic!("expected endorsement, got {other}"),
        }
    }

    #[test]
    fn receipt_for_a_different_promotion_does_not_endorse() {
        // A receipt that names a different tier/state/claim must NOT authorize.
        let receipt = EvidencePromotionReceipt {
            claim_id: "FE-CLAIM-022".into(),
            from_tier: EvidenceTier::Asserted,
            to_state: ClaimAssertionState::Target, // endorses Target, not Observed
            authorized_by: "operator".into(),
            justification: "scoped to target".into(),
        };
        let v = check_claim_flow(
            "FE-CLAIM-022",
            ClaimAssertionState::Observed,
            EvidenceTier::Asserted,
            std::slice::from_ref(&receipt),
        );
        assert!(
            v.is_violation(),
            "a receipt for a different promotion must not endorse"
        );

        // Wrong claim id likewise.
        let wrong_claim = check_claim_flow(
            "FE-CLAIM-023",
            ClaimAssertionState::Observed,
            EvidenceTier::Asserted,
            &[EvidencePromotionReceipt {
                to_state: ClaimAssertionState::Observed,
                ..receipt.clone()
            }],
        );
        assert!(wrong_claim.is_violation());
    }

    #[test]
    fn receipt_without_accountability_is_invalid() {
        let rubber_stamp = EvidencePromotionReceipt {
            claim_id: "FE-CLAIM-022".into(),
            from_tier: EvidenceTier::Asserted,
            to_state: ClaimAssertionState::Observed,
            authorized_by: "   ".into(),  // blank authorizer
            justification: String::new(), // blank justification
        };
        assert!(!rubber_stamp.is_valid());
        let v = check_claim_flow(
            "FE-CLAIM-022",
            ClaimAssertionState::Observed,
            EvidenceTier::Asserted,
            std::slice::from_ref(&rubber_stamp),
        );
        assert!(
            v.is_violation(),
            "a receipt with no accountability cannot endorse"
        );
    }

    #[test]
    fn receipt_content_hash_is_injective_over_fields() {
        let base = EvidencePromotionReceipt {
            claim_id: "FE-CLAIM-022".into(),
            from_tier: EvidenceTier::Asserted,
            to_state: ClaimAssertionState::Observed,
            authorized_by: "op".into(),
            justification: "why".into(),
        };
        let h = base.content_hash_hex();
        let mut a = base.clone();
        a.from_tier = EvidenceTier::Exercised;
        assert_ne!(h, a.content_hash_hex());
        let mut b = base.clone();
        b.authorized_by = "op2".into();
        assert_ne!(h, b.content_hash_hex());
    }
}
