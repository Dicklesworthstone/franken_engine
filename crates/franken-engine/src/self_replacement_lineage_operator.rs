#![forbid(unsafe_code)]

//! Self-replacement lineage-explorer operator surface (V.6 followup —
//! bd-cixqu.22.7).
//!
//! Rust counterpart of the V.6 operator scripts `walk_lineage.sh` and
//! `inspect_demotion_receipt.sh`. Those scripts (bash+python) consume the JSON
//! reports the engine emits — `franken-engine.self-replacement-lineage.v1` and
//! `franken-engine.demotion-fallback.v1` — and render an operator verdict. This
//! module provides the *same verdict semantics in Rust* plus a frankentui
//! "lineage explorer" panel ([`LineageExplorerView`]) analogous to the M.4
//! sibling-repo health dashboard, so the operator surface is exercised by the
//! crate's own test suite rather than only by shell self-tests.
//!
//! The view types mirror — by documented correspondence, not by import, so the
//! operator surface stays a self-contained, replay-deterministic checker — the
//! fields the scripts read:
//!
//!   * [`LineageStepView`] ↔ `self_replacement::ReplacementReceipt`
//!     (`receipt_id`, `old_slot_id`, `new_slot_id`, `old_cell_digest`,
//!     `new_cell_digest`, `validation_artifacts`).
//!   * [`DemotionFallbackView`] ↔
//!     `pre_signed_demotion_fallback::PreSignedDemotionFallback`
//!     (`promotion_id`, `receipt_digest`, `sealed_at_ns`, `permitted_triggers`,
//!     `status`).
//!
//! ## Lineage-walk verdicts (mirror `walk_lineage.sh`)
//!
//! A chain of promotion steps is intact iff every step's `old_cell_digest`
//! equals the previous step's `new_cell_digest` (head-to-tail linkage), the
//! queried slot equals the chain's terminal `new_slot_id`, and every step's
//! validation artifacts are approved:
//!
//!   * [`LineageWalkVerdict::Ok`] — intact chain.
//!   * [`LineageWalkVerdict::Empty`] — no steps.
//!   * [`LineageWalkVerdict::BrokenLinkage`] — a digest break.
//!   * [`LineageWalkVerdict::SlotMismatch`] — queried slot ≠ terminal slot.
//!   * [`LineageWalkVerdict::UnapprovedArtifacts`] — a non-approved artifact.
//!
//! ## Demotion-inspect verdicts (mirror `inspect_demotion_receipt.sh`)
//!
//!   * [`DemotionInspectVerdict::Sealed`] / [`Active`](DemotionInspectVerdict::Active)
//!     — armed, no demotion fired.
//!   * [`DemotionInspectVerdict::Demoted`] — an *permitted* trigger fired
//!     (expected rollback).
//!   * [`DemotionInspectVerdict::Voided`] — promotion succeeded, fallback
//!     retired.
//!   * [`DemotionInspectVerdict::IllegalTrigger`] — fail-closed: a trigger
//!     fired that was **not** in `permitted_triggers`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Lineage chain model (mirror of self_replacement::ReplacementReceipt)
// ---------------------------------------------------------------------------

/// Approval state of one validation artifact attached to a promotion step.
/// Mirrors the `status` field the scripts test against `("approved",
/// "approve")`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactStatusView {
    /// Reference/name of the validation artifact.
    pub artifact_ref: String,
    /// Raw status string as recorded in the receipt.
    pub status: String,
}

impl ArtifactStatusView {
    /// Whether this artifact counts as approved (the script accepts `approved`
    /// or `approve`, case-insensitively).
    pub fn is_approved(&self) -> bool {
        let s = self.status.trim().to_ascii_lowercase();
        s == "approved" || s == "approve"
    }
}

/// One promotion step in a self-replacement lineage chain. Mirrors the fields
/// of `self_replacement::ReplacementReceipt` that the lineage walk reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageStepView {
    /// Identifies this promotion step.
    pub receipt_id: String,
    /// Source slot.
    pub old_slot_id: String,
    /// Target slot (the chain's terminal slot is the last step's `new_slot_id`).
    pub new_slot_id: String,
    /// HEAD linkage: must equal the previous step's `new_cell_digest`.
    pub old_cell_digest: String,
    /// TAIL linkage: becomes the next step's `old_cell_digest`.
    pub new_cell_digest: String,
    /// Validation artifacts attached to this step.
    pub validation_artifacts: Vec<ArtifactStatusView>,
}

impl LineageStepView {
    /// Whether every validation artifact on this step is approved. An empty
    /// artifact set is vacuously approved (mirrors the script, which only flags
    /// a step when it *has* a non-approved artifact).
    pub fn all_artifacts_approved(&self) -> bool {
        self.validation_artifacts
            .iter()
            .all(ArtifactStatusView::is_approved)
    }

    /// The first non-approved artifact reference, if any.
    pub fn first_unapproved(&self) -> Option<&str> {
        self.validation_artifacts
            .iter()
            .find(|a| !a.is_approved())
            .map(|a| a.artifact_ref.as_str())
    }
}

/// A lineage chain queried at a terminal `slot_id`. Mirrors the
/// `franken-engine.self-replacement-lineage.v1` report shape
/// (`{ slot_id, entries: [{ receipt }] }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LineageChainView {
    /// The slot the lineage was queried for.
    pub slot_id: String,
    /// Promotion steps, root-first.
    pub steps: Vec<LineageStepView>,
}

/// Per-step linkage classification (mirror of the script's `linkage` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageStatus {
    /// First step — no predecessor to link to.
    ChainRoot,
    /// `old_cell_digest` matched the previous step's `new_cell_digest`.
    Linked,
    /// `old_cell_digest` did not match the previous step's `new_cell_digest`.
    Broken,
}

/// One row of the walked lineage chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageRowView {
    /// Zero-based position in the chain.
    pub index: u32,
    pub receipt_id: String,
    pub new_slot_id: String,
    pub linkage: LinkageStatus,
    /// Whether every artifact on this step is approved.
    pub artifacts_approved: bool,
}

/// Operator verdict for a lineage walk (mirror of `walk_lineage.sh`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageWalkVerdict {
    /// Intact chain: linked, slot-matched, all artifacts approved.
    Ok,
    /// No steps in the chain.
    Empty,
    /// A head-to-tail digest break at `index` (the step whose
    /// `old_cell_digest` ≠ the previous `new_cell_digest`).
    BrokenLinkage { index: u32 },
    /// The queried slot does not equal the chain's terminal `new_slot_id`.
    SlotMismatch { queried: String, terminal: String },
    /// A step carries a non-approved validation artifact.
    UnapprovedArtifacts { index: u32, artifact_ref: String },
}

impl LineageWalkVerdict {
    /// The stable operator string this verdict renders as (matches the shell
    /// script's emitted verdict vocabulary).
    pub fn verdict_str(&self) -> &'static str {
        match self {
            LineageWalkVerdict::Ok => "ok",
            LineageWalkVerdict::Empty => "empty",
            LineageWalkVerdict::BrokenLinkage { .. } => "broken-linkage",
            LineageWalkVerdict::SlotMismatch { .. } => "slot-mismatch",
            LineageWalkVerdict::UnapprovedArtifacts { .. } => "unapproved-artifacts",
        }
    }

    /// Whether this verdict is the healthy / intact one.
    pub fn is_ok(&self) -> bool {
        matches!(self, LineageWalkVerdict::Ok)
    }
}

/// Result of walking a lineage chain: the verdict plus per-step rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageWalkResult {
    pub verdict: LineageWalkVerdict,
    pub rows: Vec<LinkageRowView>,
}

/// Walk a lineage chain and produce the operator verdict + per-step rows,
/// mirroring `walk_lineage.sh`.
///
/// Verdict precedence matches the script: linkage breaks and unapproved
/// artifacts are detected during the forward walk (earliest step wins); a
/// terminal slot mismatch is reported only for an otherwise-intact chain.
pub fn walk_lineage(chain: &LineageChainView) -> LineageWalkResult {
    let mut rows = Vec::with_capacity(chain.steps.len());
    let mut verdict: Option<LineageWalkVerdict> = None;

    if chain.steps.is_empty() {
        return LineageWalkResult {
            verdict: LineageWalkVerdict::Empty,
            rows,
        };
    }

    let mut prev_new_digest: Option<&str> = None;
    for (idx, step) in chain.steps.iter().enumerate() {
        let index = idx as u32;
        let linkage = match prev_new_digest {
            None => LinkageStatus::ChainRoot,
            Some(prev) if prev == step.old_cell_digest => LinkageStatus::Linked,
            Some(_) => LinkageStatus::Broken,
        };
        let artifacts_approved = step.all_artifacts_approved();

        rows.push(LinkageRowView {
            index,
            receipt_id: step.receipt_id.clone(),
            new_slot_id: step.new_slot_id.clone(),
            linkage,
            artifacts_approved,
        });

        if verdict.is_none() {
            if linkage == LinkageStatus::Broken {
                verdict = Some(LineageWalkVerdict::BrokenLinkage { index });
            } else if let Some(artifact_ref) = step.first_unapproved() {
                verdict = Some(LineageWalkVerdict::UnapprovedArtifacts {
                    index,
                    artifact_ref: artifact_ref.to_string(),
                });
            }
        }

        prev_new_digest = Some(&step.new_cell_digest);
    }

    // Terminal-slot check only matters for an otherwise-intact chain.
    let verdict = verdict.unwrap_or_else(|| {
        let terminal = chain
            .steps
            .last()
            .map(|s| s.new_slot_id.clone())
            .unwrap_or_default();
        if terminal == chain.slot_id {
            LineageWalkVerdict::Ok
        } else {
            LineageWalkVerdict::SlotMismatch {
                queried: chain.slot_id.clone(),
                terminal,
            }
        }
    });

    LineageWalkResult { verdict, rows }
}

// ---------------------------------------------------------------------------
// Demotion fallback model (mirror of pre_signed_demotion_fallback)
// ---------------------------------------------------------------------------

/// Why a demotion fired. Mirror of
/// `pre_signed_demotion_fallback::DemotionTrigger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DemotionTriggerKind {
    DigestDrift,
    SeverityThresholdCrossed,
    GatekeeperRejection,
    ManualOperator,
}

/// Fallback lifecycle state. Mirror of
/// `pre_signed_demotion_fallback::FallbackStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackStatusView {
    /// Signed, promotion not yet applied.
    Sealed,
    /// Promotion live, fallback armed.
    Active,
    /// A trigger fired and the demotion was published.
    Activated {
        activated_at_ns: u64,
        trigger: DemotionTriggerKind,
    },
    /// Promotion succeeded; fallback retired.
    Voided { voided_at_ns: u64, reason: String },
}

/// A pre-signed demotion fallback as the operator surface sees it. Mirrors the
/// `franken-engine.demotion-fallback.v1` report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionFallbackView {
    pub promotion_id: String,
    pub receipt_digest: String,
    pub sealed_at_ns: u64,
    /// Trigger kinds this fallback is permitted to fire on.
    pub permitted_triggers: Vec<DemotionTriggerKind>,
    pub status: FallbackStatusView,
}

impl DemotionFallbackView {
    fn permits(&self, trigger: DemotionTriggerKind) -> bool {
        self.permitted_triggers.contains(&trigger)
    }
}

/// Operator verdict for a demotion fallback (mirror of
/// `inspect_demotion_receipt.sh`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemotionInspectVerdict {
    /// Sealed, no demotion fired yet.
    Sealed,
    /// Promotion live, fallback armed.
    Active,
    /// A permitted trigger fired — expected, authorized rollback.
    Demoted { trigger: DemotionTriggerKind },
    /// Promotion completed successfully, fallback retired.
    Voided { reason: String },
    /// Fail-closed alarm: a trigger fired that was NOT permitted.
    IllegalTrigger { trigger: DemotionTriggerKind },
}

impl DemotionInspectVerdict {
    /// Stable operator string (matches the shell script's vocabulary).
    pub fn verdict_str(&self) -> &'static str {
        match self {
            DemotionInspectVerdict::Sealed => "sealed",
            DemotionInspectVerdict::Active => "active",
            DemotionInspectVerdict::Demoted { .. } => "demoted",
            DemotionInspectVerdict::Voided { .. } => "voided",
            DemotionInspectVerdict::IllegalTrigger { .. } => "ILLEGAL-TRIGGER",
        }
    }

    /// Whether this verdict is a fail-closed alarm requiring operator action.
    pub fn is_alarm(&self) -> bool {
        matches!(self, DemotionInspectVerdict::IllegalTrigger { .. })
    }
}

/// Inspect a demotion fallback and produce the operator verdict, mirroring
/// `inspect_demotion_receipt.sh`. An `Activated` status whose fired trigger is
/// not in `permitted_triggers` is the fail-closed [`IllegalTrigger`] case.
///
/// [`IllegalTrigger`]: DemotionInspectVerdict::IllegalTrigger
pub fn inspect_demotion(fallback: &DemotionFallbackView) -> DemotionInspectVerdict {
    match &fallback.status {
        FallbackStatusView::Sealed => DemotionInspectVerdict::Sealed,
        FallbackStatusView::Active => DemotionInspectVerdict::Active,
        FallbackStatusView::Voided { reason, .. } => DemotionInspectVerdict::Voided {
            reason: reason.clone(),
        },
        FallbackStatusView::Activated { trigger, .. } => {
            if fallback.permits(*trigger) {
                DemotionInspectVerdict::Demoted { trigger: *trigger }
            } else {
                DemotionInspectVerdict::IllegalTrigger { trigger: *trigger }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// frankentui "lineage explorer" panel
// ---------------------------------------------------------------------------

/// One demotion-fallback row in the panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionRowView {
    pub promotion_id: String,
    pub verdict: String,
    /// `true` for the fail-closed `ILLEGAL-TRIGGER` case.
    pub alarm: bool,
}

/// frankentui lineage-explorer panel — per-slot lineage chain visualization +
/// demotion-trigger replay. Follows the `*View` / `*Partial` / `from_partial`
/// convention of the M.4 sibling-repo health dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageExplorerView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    /// The slot whose lineage is shown.
    pub lineage_slot: String,
    /// Operator verdict string for the lineage chain.
    pub lineage_verdict: String,
    /// Whether the lineage chain is intact.
    pub lineage_intact: bool,
    /// Per-step linkage rows, root-first.
    pub linkage_rows: Vec<LinkageRowView>,
    /// Per-fallback demotion rows.
    pub demotion_rows: Vec<DemotionRowView>,
    /// Human-readable alerts (broken linkage, slot mismatch, unapproved
    /// artifacts, illegal triggers), sorted + de-duplicated.
    pub alerts: Vec<String>,
}

/// Partial input for [`LineageExplorerView::from_partial`]. Optional header
/// fields default to `unknown` / `0`; collections default to empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LineageExplorerPartial {
    #[serde(default)]
    pub cluster: String,
    #[serde(default)]
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    /// The lineage chain to walk (defaults to an empty chain).
    #[serde(default)]
    pub chain: LineageChainView,
    /// Demotion fallbacks to inspect.
    #[serde(default)]
    pub fallbacks: Vec<DemotionFallbackView>,
}

fn normalize_label(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

impl LineageExplorerView {
    /// Build the panel from a partial: walks the lineage chain, inspects each
    /// fallback, derives the verdicts, and collects sorted alerts. Normalizes
    /// missing header fields to `unknown` / `0`.
    pub fn from_partial(input: LineageExplorerPartial) -> Self {
        let walk = walk_lineage(&input.chain);

        let mut alerts: BTreeSet<String> = BTreeSet::new();
        match &walk.verdict {
            LineageWalkVerdict::Ok | LineageWalkVerdict::Empty => {}
            LineageWalkVerdict::BrokenLinkage { index } => {
                alerts.insert(format!("broken-linkage at step {index}"));
            }
            LineageWalkVerdict::SlotMismatch { queried, terminal } => {
                alerts.insert(format!(
                    "slot-mismatch: queried {queried} != terminal {terminal}"
                ));
            }
            LineageWalkVerdict::UnapprovedArtifacts {
                index,
                artifact_ref,
            } => {
                alerts.insert(format!(
                    "unapproved-artifacts at step {index}: {artifact_ref}"
                ));
            }
        }

        let demotion_rows: Vec<DemotionRowView> = input
            .fallbacks
            .iter()
            .map(|f| {
                let verdict = inspect_demotion(f);
                if let DemotionInspectVerdict::IllegalTrigger { trigger } = &verdict {
                    alerts.insert(format!(
                        "ILLEGAL-TRIGGER on {}: {trigger:?}",
                        f.promotion_id
                    ));
                }
                DemotionRowView {
                    promotion_id: f.promotion_id.clone(),
                    verdict: verdict.verdict_str().to_string(),
                    alarm: verdict.is_alarm(),
                }
            })
            .collect();

        Self {
            cluster: normalize_label(input.cluster),
            zone: normalize_label(input.zone),
            security_epoch: input.security_epoch.unwrap_or(0),
            generated_at_unix_ms: input.generated_at_unix_ms.unwrap_or(0),
            lineage_slot: normalize_label(input.chain.slot_id.clone()),
            lineage_verdict: walk.verdict.verdict_str().to_string(),
            lineage_intact: walk.verdict.is_ok(),
            linkage_rows: walk.rows,
            demotion_rows,
            alerts: alerts.into_iter().collect(),
        }
    }

    /// Whether the panel surfaces any operator alert.
    pub fn has_alerts(&self) -> bool {
        !self.alerts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(name: &str, status: &str) -> ArtifactStatusView {
        ArtifactStatusView {
            artifact_ref: name.to_string(),
            status: status.to_string(),
        }
    }

    fn step(id: &str, old_slot: &str, new_slot: &str, old_d: &str, new_d: &str) -> LineageStepView {
        LineageStepView {
            receipt_id: id.to_string(),
            old_slot_id: old_slot.to_string(),
            new_slot_id: new_slot.to_string(),
            old_cell_digest: old_d.to_string(),
            new_cell_digest: new_d.to_string(),
            validation_artifacts: vec![artifact("proof", "approved")],
        }
    }

    /// An intact 3-step chain terminating at slot "s3".
    fn intact_chain() -> LineageChainView {
        LineageChainView {
            slot_id: "s3".to_string(),
            steps: vec![
                step("r1", "s0", "s1", "GENESIS", "d1"),
                step("r2", "s1", "s2", "d1", "d2"),
                step("r3", "s2", "s3", "d2", "d3"),
            ],
        }
    }

    fn fallback(
        status: FallbackStatusView,
        permitted: Vec<DemotionTriggerKind>,
    ) -> DemotionFallbackView {
        DemotionFallbackView {
            promotion_id: "p1".to_string(),
            receipt_digest: "rd".to_string(),
            sealed_at_ns: 1,
            permitted_triggers: permitted,
            status,
        }
    }

    // ---- artifact approval ----------------------------------------------

    #[test]
    fn artifact_approval_accepts_approve_and_approved_case_insensitive() {
        assert!(artifact("a", "approved").is_approved());
        assert!(artifact("a", "approve").is_approved());
        assert!(artifact("a", "APPROVED").is_approved());
        assert!(artifact("a", " Approve ").is_approved());
        assert!(!artifact("a", "rejected").is_approved());
        assert!(!artifact("a", "pending").is_approved());
    }

    // ---- lineage walk verdicts ------------------------------------------

    #[test]
    fn walk_intact_chain_is_ok() {
        let r = walk_lineage(&intact_chain());
        assert_eq!(r.verdict, LineageWalkVerdict::Ok);
        assert_eq!(r.verdict.verdict_str(), "ok");
        assert!(r.verdict.is_ok());
        assert_eq!(r.rows.len(), 3);
        assert_eq!(r.rows[0].linkage, LinkageStatus::ChainRoot);
        assert_eq!(r.rows[1].linkage, LinkageStatus::Linked);
        assert_eq!(r.rows[2].linkage, LinkageStatus::Linked);
    }

    #[test]
    fn walk_empty_chain_is_empty() {
        let r = walk_lineage(&LineageChainView::default());
        assert_eq!(r.verdict, LineageWalkVerdict::Empty);
        assert_eq!(r.verdict.verdict_str(), "empty");
        assert!(r.rows.is_empty());
    }

    #[test]
    fn walk_single_step_is_chain_root() {
        let chain = LineageChainView {
            slot_id: "s1".to_string(),
            steps: vec![step("r1", "s0", "s1", "GENESIS", "d1")],
        };
        let r = walk_lineage(&chain);
        assert_eq!(r.verdict, LineageWalkVerdict::Ok);
        assert_eq!(r.rows[0].linkage, LinkageStatus::ChainRoot);
    }

    #[test]
    fn walk_detects_broken_linkage() {
        let mut chain = intact_chain();
        // Break step 2's head linkage.
        chain.steps[2].old_cell_digest = "WRONG".to_string();
        let r = walk_lineage(&chain);
        assert_eq!(r.verdict, LineageWalkVerdict::BrokenLinkage { index: 2 });
        assert_eq!(r.verdict.verdict_str(), "broken-linkage");
        assert_eq!(r.rows[2].linkage, LinkageStatus::Broken);
    }

    #[test]
    fn walk_detects_earliest_broken_linkage() {
        let mut chain = intact_chain();
        chain.steps[1].old_cell_digest = "WRONG".to_string();
        chain.steps[2].old_cell_digest = "ALSO_WRONG".to_string();
        let r = walk_lineage(&chain);
        // Earliest break wins.
        assert_eq!(r.verdict, LineageWalkVerdict::BrokenLinkage { index: 1 });
    }

    #[test]
    fn walk_detects_slot_mismatch() {
        let mut chain = intact_chain();
        chain.slot_id = "WRONG_SLOT".to_string();
        let r = walk_lineage(&chain);
        assert_eq!(
            r.verdict,
            LineageWalkVerdict::SlotMismatch {
                queried: "WRONG_SLOT".to_string(),
                terminal: "s3".to_string(),
            }
        );
        assert_eq!(r.verdict.verdict_str(), "slot-mismatch");
    }

    #[test]
    fn walk_detects_unapproved_artifacts() {
        let mut chain = intact_chain();
        chain.steps[1].validation_artifacts = vec![artifact("scan", "rejected")];
        let r = walk_lineage(&chain);
        assert_eq!(
            r.verdict,
            LineageWalkVerdict::UnapprovedArtifacts {
                index: 1,
                artifact_ref: "scan".to_string(),
            }
        );
        assert_eq!(r.verdict.verdict_str(), "unapproved-artifacts");
        assert!(!r.rows[1].artifacts_approved);
    }

    #[test]
    fn walk_broken_linkage_takes_precedence_over_unapproved() {
        // Step 1 has both a broken link and an unapproved artifact; the
        // linkage break (checked first) wins.
        let mut chain = intact_chain();
        chain.steps[1].old_cell_digest = "WRONG".to_string();
        chain.steps[1].validation_artifacts = vec![artifact("scan", "rejected")];
        let r = walk_lineage(&chain);
        assert_eq!(r.verdict, LineageWalkVerdict::BrokenLinkage { index: 1 });
    }

    #[test]
    fn walk_empty_artifacts_is_vacuously_approved() {
        let mut chain = intact_chain();
        chain.steps[0].validation_artifacts.clear();
        let r = walk_lineage(&chain);
        assert_eq!(r.verdict, LineageWalkVerdict::Ok);
        assert!(r.rows[0].artifacts_approved);
    }

    // ---- demotion inspect verdicts --------------------------------------

    #[test]
    fn inspect_sealed() {
        let v = inspect_demotion(&fallback(FallbackStatusView::Sealed, vec![]));
        assert_eq!(v, DemotionInspectVerdict::Sealed);
        assert_eq!(v.verdict_str(), "sealed");
        assert!(!v.is_alarm());
    }

    #[test]
    fn inspect_active() {
        let v = inspect_demotion(&fallback(FallbackStatusView::Active, vec![]));
        assert_eq!(v, DemotionInspectVerdict::Active);
        assert_eq!(v.verdict_str(), "active");
    }

    #[test]
    fn inspect_voided() {
        let v = inspect_demotion(&fallback(
            FallbackStatusView::Voided {
                voided_at_ns: 5,
                reason: "promotion-succeeded".to_string(),
            },
            vec![],
        ));
        assert_eq!(
            v,
            DemotionInspectVerdict::Voided {
                reason: "promotion-succeeded".to_string()
            }
        );
        assert_eq!(v.verdict_str(), "voided");
    }

    #[test]
    fn inspect_demoted_for_permitted_trigger() {
        let v = inspect_demotion(&fallback(
            FallbackStatusView::Activated {
                activated_at_ns: 9,
                trigger: DemotionTriggerKind::DigestDrift,
            },
            vec![DemotionTriggerKind::DigestDrift],
        ));
        assert_eq!(
            v,
            DemotionInspectVerdict::Demoted {
                trigger: DemotionTriggerKind::DigestDrift
            }
        );
        assert_eq!(v.verdict_str(), "demoted");
        assert!(!v.is_alarm());
    }

    #[test]
    fn inspect_illegal_trigger_for_unpermitted() {
        let v = inspect_demotion(&fallback(
            FallbackStatusView::Activated {
                activated_at_ns: 9,
                trigger: DemotionTriggerKind::ManualOperator,
            },
            vec![DemotionTriggerKind::DigestDrift],
        ));
        assert_eq!(
            v,
            DemotionInspectVerdict::IllegalTrigger {
                trigger: DemotionTriggerKind::ManualOperator
            }
        );
        assert_eq!(v.verdict_str(), "ILLEGAL-TRIGGER");
        assert!(v.is_alarm());
    }

    #[test]
    fn inspect_illegal_trigger_when_permitted_set_empty() {
        let v = inspect_demotion(&fallback(
            FallbackStatusView::Activated {
                activated_at_ns: 9,
                trigger: DemotionTriggerKind::GatekeeperRejection,
            },
            vec![],
        ));
        assert!(v.is_alarm());
    }

    #[test]
    fn inspect_each_trigger_kind_permitted_is_demoted() {
        for trigger in [
            DemotionTriggerKind::DigestDrift,
            DemotionTriggerKind::SeverityThresholdCrossed,
            DemotionTriggerKind::GatekeeperRejection,
            DemotionTriggerKind::ManualOperator,
        ] {
            let v = inspect_demotion(&fallback(
                FallbackStatusView::Activated {
                    activated_at_ns: 1,
                    trigger,
                },
                vec![trigger],
            ));
            assert_eq!(v, DemotionInspectVerdict::Demoted { trigger });
        }
    }

    // ---- panel ----------------------------------------------------------

    #[test]
    fn panel_from_default_partial_normalizes_unknowns() {
        let v = LineageExplorerView::from_partial(LineageExplorerPartial::default());
        assert_eq!(v.cluster, "unknown");
        assert_eq!(v.zone, "unknown");
        assert_eq!(v.security_epoch, 0);
        assert_eq!(v.lineage_slot, "unknown");
        assert_eq!(v.lineage_verdict, "empty");
        assert!(!v.lineage_intact);
        assert!(!v.has_alerts());
    }

    #[test]
    fn panel_renders_intact_chain_without_alerts() {
        let v = LineageExplorerView::from_partial(LineageExplorerPartial {
            cluster: "prod".to_string(),
            zone: "us".to_string(),
            security_epoch: Some(4),
            generated_at_unix_ms: Some(1000),
            chain: intact_chain(),
            fallbacks: vec![],
        });
        assert_eq!(v.lineage_verdict, "ok");
        assert!(v.lineage_intact);
        assert_eq!(v.linkage_rows.len(), 3);
        assert!(!v.has_alerts());
    }

    #[test]
    fn panel_surfaces_broken_linkage_alert() {
        let mut chain = intact_chain();
        chain.steps[2].old_cell_digest = "WRONG".to_string();
        let v = LineageExplorerView::from_partial(LineageExplorerPartial {
            chain,
            ..Default::default()
        });
        assert_eq!(v.lineage_verdict, "broken-linkage");
        assert!(v.has_alerts());
        assert!(
            v.alerts
                .iter()
                .any(|a| a.contains("broken-linkage at step 2"))
        );
    }

    #[test]
    fn panel_surfaces_illegal_trigger_alarm() {
        let v = LineageExplorerView::from_partial(LineageExplorerPartial {
            chain: intact_chain(),
            fallbacks: vec![fallback(
                FallbackStatusView::Activated {
                    activated_at_ns: 1,
                    trigger: DemotionTriggerKind::ManualOperator,
                },
                vec![DemotionTriggerKind::DigestDrift],
            )],
            ..Default::default()
        });
        assert_eq!(v.demotion_rows.len(), 1);
        assert_eq!(v.demotion_rows[0].verdict, "ILLEGAL-TRIGGER");
        assert!(v.demotion_rows[0].alarm);
        assert!(v.has_alerts());
        assert!(v.alerts.iter().any(|a| a.starts_with("ILLEGAL-TRIGGER")));
    }

    #[test]
    fn panel_alerts_are_sorted_and_deduplicated() {
        // Two fallbacks with the same illegal trigger + a broken chain.
        let mut chain = intact_chain();
        chain.steps[1].old_cell_digest = "WRONG".to_string();
        let illegal = fallback(
            FallbackStatusView::Activated {
                activated_at_ns: 1,
                trigger: DemotionTriggerKind::ManualOperator,
            },
            vec![DemotionTriggerKind::DigestDrift],
        );
        let v = LineageExplorerView::from_partial(LineageExplorerPartial {
            chain,
            fallbacks: vec![illegal.clone(), illegal],
            ..Default::default()
        });
        // Sorted (BTreeSet) and de-duplicated.
        let mut sorted = v.alerts.clone();
        sorted.sort();
        assert_eq!(v.alerts, sorted);
        // The two identical illegal triggers collapse to one alert line.
        let illegal_lines = v.alerts.iter().filter(|a| a.starts_with("ILLEGAL")).count();
        assert_eq!(illegal_lines, 1);
    }

    #[test]
    fn panel_multiple_fallbacks_render_each_row() {
        let v = LineageExplorerView::from_partial(LineageExplorerPartial {
            chain: intact_chain(),
            fallbacks: vec![
                fallback(FallbackStatusView::Sealed, vec![]),
                fallback(FallbackStatusView::Active, vec![]),
            ],
            ..Default::default()
        });
        assert_eq!(v.demotion_rows.len(), 2);
        assert_eq!(v.demotion_rows[0].verdict, "sealed");
        assert_eq!(v.demotion_rows[1].verdict, "active");
        assert!(!v.has_alerts());
    }

    // ---- serde ----------------------------------------------------------

    #[test]
    fn walk_result_serde_roundtrip() {
        let r = walk_lineage(&intact_chain());
        let json = serde_json::to_string(&r).unwrap();
        let back: LineageWalkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn panel_serde_roundtrip() {
        let v = LineageExplorerView::from_partial(LineageExplorerPartial {
            chain: intact_chain(),
            fallbacks: vec![fallback(FallbackStatusView::Sealed, vec![])],
            ..Default::default()
        });
        let json = serde_json::to_string(&v).unwrap();
        let back: LineageExplorerView = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn demotion_view_serde_roundtrip() {
        let f = fallback(
            FallbackStatusView::Voided {
                voided_at_ns: 7,
                reason: "ok".to_string(),
            },
            vec![DemotionTriggerKind::DigestDrift],
        );
        let json = serde_json::to_string(&f).unwrap();
        let back: DemotionFallbackView = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}
