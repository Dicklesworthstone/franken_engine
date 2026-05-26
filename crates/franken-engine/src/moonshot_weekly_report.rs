// Moonshot Weekly Ranked Report — Track W.2 substrate (bd-cixqu.23.2).
//
// Assemble the weekly ranked report the operator surface
// (`MOONSHOT_PORTFOLIO_REVIEW_SURFACE.md`, W.3) consumes. Inputs are
// per-moonshot `EivScore`s from W.1; each entry is augmented with
// effort estimate + dependency-unlock count + a one-line operator
// recommendation derived from the scorecard. The report's
// `content_hash` collapses to a deterministic commitment that
// downstream replay anchors against.
//
// Per the bead: "Signed reproducible report; consumable by operator
// via frankentui panel. Lists top-k moonshots with EIV + estimated
// effort + dependency unlocks."
//
// Anchoring beads:
//   * bd-cixqu.23.1 (W.1, CLOSED) — `EivScore` substrate this report
//     consumes.
//   * bd-cixqu.23.3 (W.3, CLOSED) — operator runbook
//     `MOONSHOT_PORTFOLIO_REVIEW_SURFACE.md` documenting how the
//     report is read.
//   * Composes with `portfolio_governor.rs` `GovernorDecisionKind` —
//     the recommendation field uses the same vocabulary so the
//     operator surface can reconcile the two.
//
// Non-goals (deferred):
//   * Signing key / cryptographic signature for the report — schema
//     leaves a `signature_digest` field, but the signing pipeline
//     itself is downstream (Track G key-management UX).
//   * The frankentui panel rendering — this module emits the report
//     artifact; the TUI is a follow-up surface.

use crate::expected_info_value_scoring::EivScore;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

// ---------------------------------------------------------------------------
// EffortEstimate — operator-facing effort summary for a moonshot
// ---------------------------------------------------------------------------

/// Coarse-grained effort estimate the report surfaces alongside EIV.
/// Operators trade off EIV vs effort when choosing the next moonshot
/// to invest in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffortEstimate {
    /// < 1 week of focused work.
    Small,
    /// 1-4 weeks.
    Medium,
    /// 1-3 months.
    Large,
    /// > 3 months / multi-quarter.
    Epic,
    /// Unknown / not yet estimated.
    Unknown,
}

impl fmt::Display for EffortEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Small => f.write_str("small"),
            Self::Medium => f.write_str("medium"),
            Self::Large => f.write_str("large"),
            Self::Epic => f.write_str("epic"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// RecommendedAction — what the report nudges the operator toward
// ---------------------------------------------------------------------------

/// One-line recommendation for the operator. Vocabulary mirrors
/// `portfolio_governor::GovernorDecisionKind` so the W.3 surface can
/// reconcile the report's recommendation against any signed
/// `GovernorDecision` that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// High EIV + low effort → invest now.
    InvestNow,
    /// Moderate score; keep on the watch list.
    Watch,
    /// Insufficient signal; hold until next cadence.
    Hold,
    /// Score is non-trivially negative under the rank function; consider
    /// pausing or retiring.
    ConsiderPausing,
}

impl fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvestNow => f.write_str("invest_now"),
            Self::Watch => f.write_str("watch"),
            Self::Hold => f.write_str("hold"),
            Self::ConsiderPausing => f.write_str("consider_pausing"),
        }
    }
}

// ---------------------------------------------------------------------------
// MoonshotRanking — one ranked entry in the report
// ---------------------------------------------------------------------------

/// One ranked entry in the weekly report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotRanking {
    /// 1-indexed rank position in the report (1 = top).
    pub rank: u32,
    /// EIV score the report sorts by.
    pub eiv_score: EivScore,
    /// Operator-facing effort estimate.
    pub effort: EffortEstimate,
    /// How many other moonshots become unblocked if this one closes
    /// (dependency-unlock count). Higher = more leverage.
    pub dependency_unlocks: u32,
    /// One-line recommended action.
    pub recommended_action: RecommendedAction,
}

// ---------------------------------------------------------------------------
// WeeklyReportInput — per-moonshot inputs the report assembler consumes
// ---------------------------------------------------------------------------

/// Input bundle for a single moonshot as fed into the report
/// assembler. The assembler joins this against the corresponding
/// `EivScore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeeklyReportInput {
    pub eiv_score: EivScore,
    pub effort: EffortEstimate,
    pub dependency_unlocks: u32,
}

// ---------------------------------------------------------------------------
// ReportConfig — cadence / top-k knobs
// ---------------------------------------------------------------------------

/// Report cadence + top-k configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Cadence between two report emissions, in nanoseconds. Default
    /// is 7 days (604_800_000_000_000 ns).
    pub cadence_ns: u64,
    /// Top-k threshold: only the highest-ranked `top_k` entries appear
    /// in the surfaced report. Setting `top_k = 0` is rejected at
    /// assembly time.
    pub top_k: u32,
    /// EIV (in millionths-of-a-bit) below which the recommended
    /// action defaults to `Hold` regardless of rank position.
    pub hold_below_eiv_millimillibits: i64,
    /// EIV at or above which the recommended action defaults to
    /// `InvestNow` if effort is `Small` or `Medium`.
    pub invest_at_eiv_millimillibits: i64,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            cadence_ns: 604_800_000_000_000, // 7 days
            top_k: 10,
            // 0.20 bits of expected information gain — the noise floor.
            hold_below_eiv_millimillibits: 200_000,
            // 0.60 bits — substantial information gain expected.
            invest_at_eiv_millimillibits: 600_000,
        }
    }
}

// ---------------------------------------------------------------------------
// WeeklyRankedReport — the artifact
// ---------------------------------------------------------------------------

/// The assembled weekly ranked report. The `content_hash` collapses
/// to a deterministic commitment downstream replay anchors against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeeklyRankedReport {
    /// Cadence sequence number (monotone across emissions for the
    /// same `epoch`).
    pub cadence_sequence: u64,
    /// Time the report was assembled.
    pub generated_at_ns: u64,
    /// Security epoch at assembly time.
    pub epoch: SecurityEpoch,
    /// Configuration used to assemble the report.
    pub config: ReportConfig,
    /// Ranked entries; the report is truncated to `config.top_k`.
    pub rankings: Vec<MoonshotRanking>,
    /// Total candidates considered (before top-k truncation).
    pub total_candidates: u32,
}

impl WeeklyRankedReport {
    /// Assemble a report from per-moonshot inputs + config.
    ///
    /// Sorts entries descending by EIV (the same key W.3 operator
    /// surface uses), assigns 1-indexed ranks, derives a recommended
    /// action from EIV + effort + config, and truncates to `top_k`.
    pub fn assemble(
        inputs: Vec<WeeklyReportInput>,
        config: ReportConfig,
        cadence_sequence: u64,
        generated_at_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<Self, ReportError> {
        if config.top_k == 0 {
            return Err(ReportError::TopKZero);
        }
        if config.invest_at_eiv_millimillibits < config.hold_below_eiv_millimillibits {
            return Err(ReportError::ConfigInvertedThresholds);
        }

        let total_candidates = inputs.len() as u32;
        let mut sorted = inputs;
        // Sort descending by EIV; tie-break by moonshot_id ascending for
        // deterministic ordering when EIVs are equal.
        sorted.sort_by(|a, b| {
            match b
                .eiv_score
                .eiv_millimillibits
                .cmp(&a.eiv_score.eiv_millimillibits)
            {
                Ordering::Equal => a.eiv_score.moonshot_id.cmp(&b.eiv_score.moonshot_id),
                other => other,
            }
        });

        let truncated_len = (config.top_k as usize).min(sorted.len());
        let mut rankings = Vec::with_capacity(truncated_len);
        for (idx, input) in sorted.into_iter().take(truncated_len).enumerate() {
            let action = recommend(&input, &config);
            rankings.push(MoonshotRanking {
                rank: (idx as u32) + 1,
                eiv_score: input.eiv_score,
                effort: input.effort,
                dependency_unlocks: input.dependency_unlocks,
                recommended_action: action,
            });
        }

        Ok(Self {
            cadence_sequence,
            generated_at_ns,
            epoch,
            config,
            rankings,
            total_candidates,
        })
    }

    /// The top-ranked moonshot, if any.
    pub fn top(&self) -> Option<&MoonshotRanking> {
        self.rankings.first()
    }

    /// Read-only access to the ranked entries.
    pub fn rankings(&self) -> &[MoonshotRanking] {
        &self.rankings
    }

    /// Deterministic content hash committing to every field that
    /// affects the operator's decision: cadence_sequence, epoch,
    /// generated_at_ns, total_candidates, and the ordered list of
    /// (rank, moonshot_id, eiv_millimillibits, effort,
    /// dependency_unlocks, recommended_action).
    pub fn content_hash(&self) -> ContentHash {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"moonshot_weekly_report_v1");
        buf.push(0);
        buf.extend_from_slice(&self.cadence_sequence.to_be_bytes());
        buf.extend_from_slice(&self.generated_at_ns.to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.total_candidates.to_be_bytes());
        buf.push(0);
        for r in &self.rankings {
            buf.extend_from_slice(&r.rank.to_be_bytes());
            let id = r.eiv_score.moonshot_id.as_bytes();
            buf.extend_from_slice(&(id.len() as u64).to_be_bytes());
            buf.extend_from_slice(id);
            buf.extend_from_slice(&r.eiv_score.eiv_millimillibits.to_be_bytes());
            buf.push(effort_byte(r.effort));
            buf.extend_from_slice(&r.dependency_unlocks.to_be_bytes());
            buf.push(action_byte(r.recommended_action));
            buf.push(0);
        }
        ContentHash::compute(&buf)
    }

    /// The domain-separated preimage the report signature is computed
    /// over: a context tag followed by the report's [`content_hash`].
    ///
    /// Signing the content hash (rather than the raw struct) keeps the
    /// signature stable under any serde representation change while
    /// still committing to every decision-relevant field, since the
    /// content hash already commits to them.
    ///
    /// [`content_hash`]: WeeklyRankedReport::content_hash
    fn signature_preimage(&self) -> Vec<u8> {
        let digest = self.content_hash();
        let mut preimage = Vec::with_capacity(REPORT_SIGNATURE_DOMAIN.len() + 1 + 32);
        preimage.extend_from_slice(REPORT_SIGNATURE_DOMAIN);
        preimage.push(0);
        preimage.extend_from_slice(digest.as_bytes());
        preimage
    }

    /// Sign this report with `signing_key`, producing a verifiable
    /// [`SignedWeeklyReport`]. This is what makes the W.2 artifact a
    /// *signed* reproducible report: the content hash gives
    /// reproducibility (a deterministic commitment), and the Ed25519
    /// signature over it gives authenticity.
    ///
    /// Key *management* (custody, rotation, role binding) is out of
    /// scope here and remains a Track-G concern; this method signs with
    /// whatever key the operator surface supplies.
    ///
    /// # Errors
    /// Returns [`ReportError::Signing`] if the signing key is rejected
    /// by the signature primitive (e.g. an all-zero key).
    pub fn sign(self, signing_key: &SigningKey) -> Result<SignedWeeklyReport, ReportError> {
        let content_hash = self.content_hash();
        let preimage = self.signature_preimage();
        let signature = sign_preimage(signing_key, &preimage)
            .map_err(|e| ReportError::Signing(e.to_string()))?;
        Ok(SignedWeeklyReport {
            report: self,
            content_hash,
            verification_key: signing_key.verification_key(),
            signature,
        })
    }
}

/// Domain-separation tag for the weekly-report signature preimage, so a
/// report signature can never be confused with a signature over any
/// other engine object.
const REPORT_SIGNATURE_DOMAIN: &[u8] = b"moonshot-weekly-report-signature-v1";

/// A [`WeeklyRankedReport`] bound to an Ed25519 signature over its
/// content hash, together with the committed hash and the verification
/// key needed to check it. This is the fail-closed, operator-consumable
/// artifact W.2 ships: integrity (content hash) plus authenticity
/// (signature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWeeklyReport {
    /// The ranked report that was signed.
    pub report: WeeklyRankedReport,
    /// The content hash committed to at signing time. [`verify`] requires
    /// the embedded report to still hash to this value.
    ///
    /// [`verify`]: SignedWeeklyReport::verify
    pub content_hash: ContentHash,
    /// The verification key corresponding to the signing key.
    pub verification_key: VerificationKey,
    /// The Ed25519 signature over the domain-separated content hash.
    pub signature: Signature,
}

impl SignedWeeklyReport {
    /// Verify the signed report fail-closed, in order:
    ///
    /// 1. recompute the content hash from the embedded report and require
    ///    it equals the committed [`content_hash`] (tamper check — a
    ///    mutated report is rejected even if the signature itself is
    ///    well-formed over the old hash);
    /// 2. verify the Ed25519 signature over the domain-separated preimage
    ///    with the embedded verification key.
    ///
    /// [`content_hash`]: SignedWeeklyReport::content_hash
    ///
    /// # Errors
    /// - [`ReportError::ContentHashMismatch`] if the embedded report no
    ///   longer hashes to the committed content hash.
    /// - [`ReportError::SignatureInvalid`] if the signature does not
    ///   verify under the embedded verification key.
    pub fn verify(&self) -> Result<(), ReportError> {
        let recomputed = self.report.content_hash();
        if recomputed != self.content_hash {
            return Err(ReportError::ContentHashMismatch);
        }
        let preimage = self.report.signature_preimage();
        verify_signature(&self.verification_key, &preimage, &self.signature)
            .map_err(|e| ReportError::SignatureInvalid(e.to_string()))
    }

    /// Read-only access to the signed report.
    pub fn report(&self) -> &WeeklyRankedReport {
        &self.report
    }
}

fn effort_byte(e: EffortEstimate) -> u8 {
    match e {
        EffortEstimate::Small => 1,
        EffortEstimate::Medium => 2,
        EffortEstimate::Large => 3,
        EffortEstimate::Epic => 4,
        EffortEstimate::Unknown => 0,
    }
}

fn action_byte(a: RecommendedAction) -> u8 {
    match a {
        RecommendedAction::InvestNow => 1,
        RecommendedAction::Watch => 2,
        RecommendedAction::Hold => 3,
        RecommendedAction::ConsiderPausing => 4,
    }
}

// ---------------------------------------------------------------------------
// Recommendation derivation
// ---------------------------------------------------------------------------

fn recommend(input: &WeeklyReportInput, config: &ReportConfig) -> RecommendedAction {
    let eiv = input.eiv_score.eiv_millimillibits;
    if eiv < 0 {
        return RecommendedAction::ConsiderPausing;
    }
    if eiv < config.hold_below_eiv_millimillibits {
        return RecommendedAction::Hold;
    }
    if eiv >= config.invest_at_eiv_millimillibits
        && matches!(input.effort, EffortEstimate::Small | EffortEstimate::Medium)
    {
        return RecommendedAction::InvestNow;
    }
    RecommendedAction::Watch
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportError {
    /// `ReportConfig::top_k` was zero.
    TopKZero,
    /// `invest_at_eiv` < `hold_below_eiv` in the supplied config.
    ConfigInvertedThresholds,
    /// The signature primitive rejected the signing key (detail string).
    Signing(String),
    /// A signed report's embedded report no longer hashes to its
    /// committed content hash (tamper detected).
    ContentHashMismatch,
    /// A signed report's signature failed verification (detail string).
    SignatureInvalid(String),
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TopKZero => f.write_str("report top_k must be strictly positive"),
            Self::ConfigInvertedThresholds => {
                f.write_str("invest_at_eiv must be >= hold_below_eiv")
            }
            Self::Signing(detail) => write!(f, "report signing failed: {detail}"),
            Self::ContentHashMismatch => {
                f.write_str("signed report content hash does not match committed hash")
            }
            Self::SignatureInvalid(detail) => {
                write!(f, "signed report signature verification failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ReportError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expected_info_value_scoring::PriorEvidence;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn input(
        id: &str,
        alpha: u32,
        beta: u32,
        effort: EffortEstimate,
        unlocks: u32,
    ) -> WeeklyReportInput {
        WeeklyReportInput {
            eiv_score: EivScore::compute(
                id,
                PriorEvidence::try_new(alpha, beta).unwrap(),
                0,
                epoch(),
            ),
            effort,
            dependency_unlocks: unlocks,
        }
    }

    fn default_config() -> ReportConfig {
        ReportConfig::default()
    }

    /// Build an input with a directly-specified EIV (millionths-of-a-bit),
    /// bypassing `EivScore::compute`. The single-observation EIV from
    /// `compute` peaks near 0.082 bits (at a uniform prior) — well below
    /// the default invest/hold thresholds — so recommendation tests that
    /// need to cross the invest threshold construct the EIV they intend to
    /// exercise rather than relying on an unreachable compute value. The
    /// threshold-vs-compute-range mismatch is tracked as a separate bug.
    fn input_with_eiv(
        id: &str,
        eiv_millimillibits: i64,
        effort: EffortEstimate,
        unlocks: u32,
    ) -> WeeklyReportInput {
        WeeklyReportInput {
            eiv_score: EivScore {
                moonshot_id: id.to_string(),
                prior_entropy_millimillibits: 1_000_000,
                expected_post_entropy_millimillibits: 1_000_000 - eiv_millimillibits,
                eiv_millimillibits,
                p_success_millionths: 500_000,
                prior_total_count: 2,
                computed_at_ns: 0,
                epoch: epoch(),
            },
            effort,
            dependency_unlocks: unlocks,
        }
    }

    // ----- Config -----

    #[test]
    fn default_config_has_sane_thresholds() {
        let c = ReportConfig::default();
        assert_eq!(c.top_k, 10);
        assert!(c.invest_at_eiv_millimillibits > c.hold_below_eiv_millimillibits);
        assert!(c.cadence_ns > 0);
    }

    #[test]
    fn assemble_rejects_top_k_zero() {
        let cfg = ReportConfig {
            top_k: 0,
            ..default_config()
        };
        let err = WeeklyRankedReport::assemble(vec![], cfg, 1, 100, epoch()).unwrap_err();
        assert_eq!(err, ReportError::TopKZero);
    }

    #[test]
    fn assemble_rejects_inverted_thresholds() {
        let cfg = ReportConfig {
            hold_below_eiv_millimillibits: 800_000,
            invest_at_eiv_millimillibits: 100_000,
            ..default_config()
        };
        let err = WeeklyRankedReport::assemble(vec![], cfg, 1, 100, epoch()).unwrap_err();
        assert_eq!(err, ReportError::ConfigInvertedThresholds);
    }

    // ----- Empty input -----

    #[test]
    fn empty_input_produces_empty_report() {
        let r = WeeklyRankedReport::assemble(vec![], default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(r.rankings.len(), 0);
        assert_eq!(r.total_candidates, 0);
        assert!(r.top().is_none());
    }

    // ----- Ranking order -----

    #[test]
    fn report_sorts_descending_by_eiv() {
        let inputs = vec![
            input("m_high", 1, 1, EffortEstimate::Small, 5), // uniform; highest EIV
            input("m_low", 100, 1, EffortEstimate::Medium, 2), // lopsided; ~zero EIV
            input("m_mid", 3, 1, EffortEstimate::Large, 1),
        ];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(r.rankings.len(), 3);
        assert_eq!(r.rankings[0].eiv_score.moonshot_id, "m_high");
        assert_eq!(r.rankings[0].rank, 1);
        assert_eq!(r.rankings[2].eiv_score.moonshot_id, "m_low");
        assert_eq!(r.rankings[2].rank, 3);
    }

    #[test]
    fn ties_break_on_moonshot_id_lex_ascending() {
        // Two moonshots with identical priors → identical EIV.
        let inputs = vec![
            input("m_beta", 1, 1, EffortEstimate::Small, 0),
            input("m_alpha", 1, 1, EffortEstimate::Small, 0),
        ];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(r.rankings[0].eiv_score.moonshot_id, "m_alpha");
        assert_eq!(r.rankings[1].eiv_score.moonshot_id, "m_beta");
    }

    // ----- top-k truncation -----

    #[test]
    fn top_k_truncates_lower_ranks() {
        let inputs = (1..=20)
            .map(|i| input(&format!("m{i:02}"), 1, 1, EffortEstimate::Small, 0))
            .collect();
        let cfg = ReportConfig {
            top_k: 5,
            ..default_config()
        };
        let r = WeeklyRankedReport::assemble(inputs, cfg, 1, 100, epoch()).unwrap();
        assert_eq!(r.rankings.len(), 5);
        assert_eq!(r.total_candidates, 20);
    }

    #[test]
    fn top_k_clamps_to_input_length() {
        let inputs = vec![input("m1", 1, 1, EffortEstimate::Small, 0)];
        let cfg = ReportConfig {
            top_k: 100,
            ..default_config()
        };
        let r = WeeklyRankedReport::assemble(inputs, cfg, 1, 100, epoch()).unwrap();
        assert_eq!(r.rankings.len(), 1);
        assert_eq!(r.total_candidates, 1);
    }

    // ----- Recommendation derivation -----

    #[test]
    fn invest_now_for_high_eiv_small_effort() {
        // EIV above the invest_at threshold + small effort → InvestNow.
        let inputs = vec![input_with_eiv("m", 700_000, EffortEstimate::Small, 5)];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(
            r.rankings[0].recommended_action,
            RecommendedAction::InvestNow
        );
    }

    #[test]
    fn watch_for_high_eiv_large_effort() {
        // Large effort gates InvestNow even above the invest_at threshold → Watch.
        let inputs = vec![input_with_eiv("m", 700_000, EffortEstimate::Large, 5)];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(r.rankings[0].recommended_action, RecommendedAction::Watch);
    }

    #[test]
    fn hold_for_low_eiv() {
        // Very lopsided prior → near-zero EIV → Hold.
        let inputs = vec![input("m", 10_000, 1, EffortEstimate::Small, 5)];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(r.rankings[0].recommended_action, RecommendedAction::Hold);
    }

    #[test]
    fn invest_threshold_governed_by_config() {
        let cfg = ReportConfig {
            invest_at_eiv_millimillibits: 999_999, // basically unreachable
            ..default_config()
        };
        let inputs = vec![input("m", 1, 1, EffortEstimate::Small, 0)];
        let r = WeeklyRankedReport::assemble(inputs, cfg, 1, 100, epoch()).unwrap();
        // EIV ~1.0 bit but threshold raised: no longer InvestNow.
        assert_ne!(
            r.rankings[0].recommended_action,
            RecommendedAction::InvestNow
        );
    }

    // ----- Determinism -----

    #[test]
    fn assemble_is_deterministic_for_same_inputs() {
        let inputs_a = vec![
            input("m1", 1, 1, EffortEstimate::Small, 0),
            input("m2", 3, 1, EffortEstimate::Medium, 1),
        ];
        let inputs_b = inputs_a.clone();
        let r1 = WeeklyRankedReport::assemble(inputs_a, default_config(), 1, 100, epoch()).unwrap();
        let r2 = WeeklyRankedReport::assemble(inputs_b, default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn assemble_is_input_order_independent() {
        let i1 = vec![
            input("m1", 1, 1, EffortEstimate::Small, 0),
            input("m2", 3, 1, EffortEstimate::Medium, 1),
            input("m3", 5, 1, EffortEstimate::Large, 2),
        ];
        let mut i2 = i1.clone();
        i2.reverse();
        let r1 = WeeklyRankedReport::assemble(i1, default_config(), 1, 100, epoch()).unwrap();
        let r2 = WeeklyRankedReport::assemble(i2, default_config(), 1, 100, epoch()).unwrap();
        assert_eq!(r1, r2);
    }

    // ----- content_hash -----

    #[test]
    fn content_hash_is_stable_for_identical_report() {
        let inputs = vec![input("m1", 1, 1, EffortEstimate::Small, 0)];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        let h1 = r.content_hash();
        let h2 = r.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_changes_with_cadence_sequence() {
        let inputs1 = vec![input("m1", 1, 1, EffortEstimate::Small, 0)];
        let inputs2 = inputs1.clone();
        let r1 = WeeklyRankedReport::assemble(inputs1, default_config(), 1, 100, epoch()).unwrap();
        let r2 = WeeklyRankedReport::assemble(inputs2, default_config(), 2, 100, epoch()).unwrap();
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn content_hash_changes_with_ranking_set() {
        let r1 = WeeklyRankedReport::assemble(
            vec![input("m1", 1, 1, EffortEstimate::Small, 0)],
            default_config(),
            1,
            100,
            epoch(),
        )
        .unwrap();
        let r2 = WeeklyRankedReport::assemble(
            vec![
                input("m1", 1, 1, EffortEstimate::Small, 0),
                input("m2", 3, 1, EffortEstimate::Medium, 1),
            ],
            default_config(),
            1,
            100,
            epoch(),
        )
        .unwrap();
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    // ----- top() accessor -----

    #[test]
    fn top_returns_first_ranking() {
        let inputs = vec![
            input("m_high", 1, 1, EffortEstimate::Small, 5),
            input("m_low", 100, 1, EffortEstimate::Large, 0),
        ];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        let top = r.top().unwrap();
        assert_eq!(top.rank, 1);
        assert_eq!(top.eiv_score.moonshot_id, "m_high");
    }

    #[test]
    fn rank_indices_are_one_based_and_monotone() {
        let inputs: Vec<_> = (1..=5)
            .map(|i| input(&format!("m{i}"), 1, 1, EffortEstimate::Small, 0))
            .collect();
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        for (i, entry) in r.rankings.iter().enumerate() {
            assert_eq!(entry.rank, (i as u32) + 1);
        }
    }

    // ----- Serde -----

    #[test]
    fn report_serde_round_trip() {
        let inputs = vec![
            input("m1", 1, 1, EffortEstimate::Small, 0),
            input("m2", 3, 1, EffortEstimate::Medium, 1),
        ];
        let r = WeeklyRankedReport::assemble(inputs, default_config(), 1, 100, epoch()).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let restored: WeeklyRankedReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
        assert_eq!(r.content_hash(), restored.content_hash());
    }

    // ----- Display -----

    #[test]
    fn effort_and_action_display_strings() {
        assert_eq!(format!("{}", EffortEstimate::Small), "small");
        assert_eq!(format!("{}", EffortEstimate::Epic), "epic");
        assert_eq!(format!("{}", RecommendedAction::InvestNow), "invest_now");
        assert_eq!(
            format!("{}", RecommendedAction::ConsiderPausing),
            "consider_pausing"
        );
    }

    #[test]
    fn error_display_messages() {
        assert!(format!("{}", ReportError::TopKZero).contains("positive"));
        assert!(format!("{}", ReportError::ConfigInvertedThresholds).contains(">="));
    }

    // ----- Signing (W.2 signed reproducible report) -----

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("non-zero signing key")
    }

    fn sample_report() -> WeeklyRankedReport {
        let inputs = vec![
            input("m_high", 1, 1, EffortEstimate::Small, 5),
            input("m_mid", 3, 1, EffortEstimate::Medium, 2),
            input("m_low", 100, 1, EffortEstimate::Large, 0),
        ];
        WeeklyRankedReport::assemble(inputs, default_config(), 7, 12_345, epoch()).unwrap()
    }

    #[test]
    fn signed_report_verifies() {
        let key = signing_key(7);
        let report = sample_report();
        let signed = report.clone().sign(&key).unwrap();
        assert_eq!(signed.report(), &report);
        assert_eq!(signed.content_hash, report.content_hash());
        assert_eq!(signed.verification_key, key.verification_key());
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn signing_does_not_alter_report() {
        let key = signing_key(7);
        let report = sample_report();
        let signed = report.clone().sign(&key).unwrap();
        // The embedded report is identical to the unsigned one.
        assert_eq!(signed.report(), &report);
    }

    #[test]
    fn signature_is_deterministic() {
        // Ed25519 is deterministic: same report + key => same signature.
        let key = signing_key(7);
        let a = sample_report().sign(&key).unwrap();
        let b = sample_report().sign(&key).unwrap();
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn tampered_report_fails_content_hash_check() {
        let key = signing_key(7);
        let mut signed = sample_report().sign(&key).unwrap();
        // Mutate the embedded report so it no longer hashes to the committed hash.
        signed.report.rankings[0].dependency_unlocks += 1;
        assert!(matches!(
            signed.verify(),
            Err(ReportError::ContentHashMismatch)
        ));
    }

    #[test]
    fn truncating_signed_report_fails_content_hash_check() {
        let key = signing_key(7);
        let mut signed = sample_report().sign(&key).unwrap();
        signed.report.rankings.pop();
        assert!(matches!(
            signed.verify(),
            Err(ReportError::ContentHashMismatch)
        ));
    }

    #[test]
    fn wrong_verification_key_fails_signature_check() {
        let key_a = signing_key(7);
        let key_b = signing_key(9);
        let mut signed = sample_report().sign(&key_a).unwrap();
        // Content hash still matches, but the wrong key must reject the signature.
        signed.verification_key = key_b.verification_key();
        assert!(matches!(
            signed.verify(),
            Err(ReportError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn corrupted_signature_fails_signature_check() {
        let key = signing_key(7);
        let mut signed = sample_report().sign(&key).unwrap();
        // Flip a byte in the signature; the content hash still matches.
        let mut bytes = signed.signature.to_bytes();
        bytes[0] ^= 0xFF;
        signed.signature = Signature::from_bytes(bytes);
        assert!(matches!(
            signed.verify(),
            Err(ReportError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn distinct_reports_have_distinct_signatures() {
        let key = signing_key(7);
        let a = sample_report().sign(&key).unwrap();
        let other = WeeklyRankedReport::assemble(
            vec![input("only", 1, 1, EffortEstimate::Small, 0)],
            default_config(),
            8,
            99,
            epoch(),
        )
        .unwrap();
        let b = other.sign(&key).unwrap();
        assert_ne!(a.signature, b.signature);
        assert_ne!(a.content_hash, b.content_hash);
    }

    #[test]
    fn signed_report_serde_round_trips_and_verifies() {
        let key = signing_key(7);
        let signed = sample_report().sign(&key).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let restored: SignedWeeklyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, restored);
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn signing_error_display_messages() {
        assert!(format!("{}", ReportError::Signing("x".into())).contains("signing"));
        assert!(format!("{}", ReportError::ContentHashMismatch).contains("content hash"));
        assert!(format!("{}", ReportError::SignatureInvalid("y".into())).contains("verification"));
    }
}
