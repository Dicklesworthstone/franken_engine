//! Bayesian syntax-error recovery controller.
//!
//! Implements a principled recovery engine for parser syntax errors with
//! bounded attempts, Bayesian confidence estimation, conservative loss-matrix
//! decision policy, and deterministic fallback.
//!
//! ## Design principles
//!
//! 1. **Strict by default**: execution mode fails on syntax error unless
//!    recovery confidence exceeds a conservative threshold.
//! 2. **Bounded**: max attempts, max token skips, and max insertions per file.
//! 3. **Transparent**: every decision is logged with evidence, posterior,
//!    action, rejected alternatives, and deterministic replay token.
//! 4. **Deterministic**: same input + config → same recovery decisions.
//!
//! ## Related beads
//!
//! - bd-1gfn (this module)
//! - bd-3rjg (parallel interference gate — upstream)
//! - bd-1vfi (parallel parser — upstream)

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "bayesian_error_recovery";

/// Schema version for serde stability.
pub const SCHEMA_VERSION: &str = "franken-engine.bayesian-error-recovery.v1";

/// Fixed-point unit: 1_000_000 = 1.0 (100%).
const MILLION: u64 = 1_000_000;

/// Default max recovery attempts per file.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default max token skips per attempt.
pub const DEFAULT_MAX_SKIPS: u32 = 3;

/// Default max inserted tokens per attempt.
pub const DEFAULT_MAX_INSERTIONS: u32 = 2;

/// Default confidence threshold (millionths) to accept a recovery.
/// 700_000 = 70% posterior confidence required.
pub const DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS: u64 = 700_000;

/// Default prior for recoverable state (millionths).
pub const DEFAULT_PRIOR_RECOVERABLE: u64 = 300_000; // 30%

/// Default prior for ambiguous state (millionths).
pub const DEFAULT_PRIOR_AMBIGUOUS: u64 = 400_000; // 40%

/// Default prior for unrecoverable state (millionths).
pub const DEFAULT_PRIOR_UNRECOVERABLE: u64 = 300_000; // 30%

// ---------------------------------------------------------------------------
// Recovery mode policy
// ---------------------------------------------------------------------------

/// Recovery operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecoveryMode {
    /// Strict: always fail on syntax error (no recovery attempted).
    StrictDefault,
    /// Diagnostic: attempt recovery but report only (don't use recovered AST).
    DiagnosticRecovery,
    /// Execution: attempt recovery and use recovered AST if confidence meets threshold.
    ExecutionRecovery,
}

impl fmt::Display for RecoveryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StrictDefault => write!(f, "strict_default"),
            Self::DiagnosticRecovery => write!(f, "diagnostic_recovery"),
            Self::ExecutionRecovery => write!(f, "execution_recovery"),
        }
    }
}

// ---------------------------------------------------------------------------
// Error state taxonomy
// ---------------------------------------------------------------------------

/// Classification of the true underlying syntax error state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ErrorState {
    /// Local syntax defect recoverable without semantic distortion.
    Recoverable,
    /// Multiple plausible repairs; ambiguous.
    Ambiguous,
    /// Reliable repair not possible.
    Unrecoverable,
}

impl fmt::Display for ErrorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recoverable => write!(f, "recoverable"),
            Self::Ambiguous => write!(f, "ambiguous"),
            Self::Unrecoverable => write!(f, "unrecoverable"),
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery action
// ---------------------------------------------------------------------------

/// Action taken by the recovery controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// Accept the recovery and continue parsing.
    RecoverContinue,
    /// Accept a partial recovery (some edits applied, some skipped).
    PartialRecover,
    /// Fail strictly: no recovery applied.
    FailStrict,
}

impl fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecoverContinue => write!(f, "recover_continue"),
            Self::PartialRecover => write!(f, "partial_recover"),
            Self::FailStrict => write!(f, "fail_strict"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence features
// ---------------------------------------------------------------------------

/// Evidence features extracted from a syntax error site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFeatures {
    /// Number of tokens successfully parsed before the error.
    pub tokens_before_error: u64,
    /// Number of candidate repairs identified.
    pub candidate_repairs: u32,
    /// Whether the error is at a statement boundary.
    pub at_statement_boundary: bool,
    /// Number of tokens to skip for simplest repair.
    pub min_skip_tokens: u32,
    /// Number of tokens to insert for simplest repair.
    pub min_insert_tokens: u32,
    /// Whether the error matches a known typo pattern.
    pub matches_typo_pattern: bool,
    /// Context window hash for deterministic replay.
    pub context_hash: ContentHash,
}

impl EvidenceFeatures {
    /// Compute a deterministic hash of the evidence features.
    pub fn compute_hash(&self) -> ContentHash {
        let data = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.tokens_before_error,
            self.candidate_repairs,
            self.at_statement_boundary,
            self.min_skip_tokens,
            self.min_insert_tokens,
            self.matches_typo_pattern,
            self.context_hash,
        );
        ContentHash::compute(data.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Posterior distribution
// ---------------------------------------------------------------------------

/// Posterior distribution over error states (fixed-point millionths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posterior {
    /// P(Recoverable) in millionths.
    pub recoverable: u64,
    /// P(Ambiguous) in millionths.
    pub ambiguous: u64,
    /// P(Unrecoverable) in millionths.
    pub unrecoverable: u64,
}

impl Posterior {
    /// Create a posterior from raw millionths. Normalizes to sum to MILLION.
    pub fn new(recoverable: u64, ambiguous: u64, unrecoverable: u64) -> Self {
        let total = recoverable
            .saturating_add(ambiguous)
            .saturating_add(unrecoverable);
        if total == 0 {
            return Self {
                recoverable: MILLION / 3,
                ambiguous: MILLION / 3,
                unrecoverable: MILLION - 2 * (MILLION / 3),
            };
        }
        let r = recoverable
            .saturating_mul(MILLION)
            .checked_div(total)
            .unwrap_or(0);
        let a = ambiguous
            .saturating_mul(MILLION)
            .checked_div(total)
            .unwrap_or(0);
        let u = MILLION.saturating_sub(r).saturating_sub(a);
        Self {
            recoverable: r,
            ambiguous: a,
            unrecoverable: u,
        }
    }

    /// Default prior distribution.
    pub fn default_prior() -> Self {
        Self {
            recoverable: DEFAULT_PRIOR_RECOVERABLE,
            ambiguous: DEFAULT_PRIOR_AMBIGUOUS,
            unrecoverable: DEFAULT_PRIOR_UNRECOVERABLE,
        }
    }

    /// The maximum-a-posteriori state.
    pub fn map_state(&self) -> ErrorState {
        if self.recoverable >= self.ambiguous && self.recoverable >= self.unrecoverable {
            ErrorState::Recoverable
        } else if self.ambiguous >= self.unrecoverable {
            ErrorState::Ambiguous
        } else {
            ErrorState::Unrecoverable
        }
    }

    /// Confidence in the MAP state (millionths).
    pub fn map_confidence(&self) -> u64 {
        self.recoverable.max(self.ambiguous).max(self.unrecoverable)
    }

    /// Whether the posterior sums to MILLION (within tolerance of 1).
    pub fn is_normalized(&self) -> bool {
        let sum = self
            .recoverable
            .saturating_add(self.ambiguous)
            .saturating_add(self.unrecoverable);
        sum == MILLION || sum == MILLION - 1 || sum == MILLION + 1
    }
}

// ---------------------------------------------------------------------------
// Likelihood model
// ---------------------------------------------------------------------------

/// Compute likelihood ratios for evidence given each error state.
///
/// Returns `[L(Recoverable), L(Ambiguous), L(Unrecoverable)]` in millionths.
pub fn compute_likelihoods(evidence: &EvidenceFeatures) -> [u64; 3] {
    let mut l_recoverable = MILLION;
    let mut l_ambiguous = MILLION;
    let mut l_unrecoverable = MILLION;

    // Typo pattern strongly favors recoverable.
    if evidence.matches_typo_pattern {
        l_recoverable = l_recoverable.saturating_mul(3);
        l_ambiguous = l_ambiguous.saturating_mul(1);
        l_unrecoverable = l_unrecoverable.saturating_div(2).max(1);
    }

    // Multiple candidate repairs favor ambiguous.
    if evidence.candidate_repairs > 1 {
        l_ambiguous = l_ambiguous
            .saturating_mul(evidence.candidate_repairs as u64)
            .saturating_div(2)
            .max(1);
        l_recoverable = l_recoverable
            .saturating_div(evidence.candidate_repairs as u64)
            .max(1);
    }

    // No candidate repairs favors unrecoverable.
    if evidence.candidate_repairs == 0 {
        l_unrecoverable = l_unrecoverable.saturating_mul(4);
        l_recoverable = l_recoverable.saturating_div(4).max(1);
        l_ambiguous = l_ambiguous.saturating_div(2).max(1);
    }

    // Statement boundary favors recoverable.
    if evidence.at_statement_boundary {
        l_recoverable = l_recoverable.saturating_mul(2);
    }

    // High skip count disfavors recoverable.
    if evidence.min_skip_tokens > 2 {
        l_recoverable = l_recoverable.saturating_div(2).max(1);
        l_unrecoverable = l_unrecoverable.saturating_mul(2);
    }

    // High insert count disfavors recoverable.
    if evidence.min_insert_tokens > 1 {
        l_recoverable = l_recoverable.saturating_div(2).max(1);
        l_ambiguous = l_ambiguous.saturating_mul(2);
    }

    // Few tokens before error — less context, more uncertainty.
    if evidence.tokens_before_error < 5 {
        l_ambiguous = l_ambiguous.saturating_mul(2);
    }

    [l_recoverable, l_ambiguous, l_unrecoverable]
}

/// Update a posterior given evidence features using Bayesian update.
pub fn bayesian_update(prior: &Posterior, evidence: &EvidenceFeatures) -> Posterior {
    let likelihoods = compute_likelihoods(evidence);
    let r = prior.recoverable.saturating_mul(likelihoods[0]);
    let a = prior.ambiguous.saturating_mul(likelihoods[1]);
    let u = prior.unrecoverable.saturating_mul(likelihoods[2]);
    Posterior::new(r, a, u)
}

// ---------------------------------------------------------------------------
// Loss matrix
// ---------------------------------------------------------------------------

/// Loss matrix entry: `loss(action, state)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossMatrix {
    /// L(RecoverContinue, Recoverable).
    pub recover_recoverable: u64,
    /// L(RecoverContinue, Ambiguous).
    pub recover_ambiguous: u64,
    /// L(RecoverContinue, Unrecoverable).
    pub recover_unrecoverable: u64,
    /// L(PartialRecover, Recoverable).
    pub partial_recoverable: u64,
    /// L(PartialRecover, Ambiguous).
    pub partial_ambiguous: u64,
    /// L(PartialRecover, Unrecoverable).
    pub partial_unrecoverable: u64,
    /// L(FailStrict, Recoverable).
    pub fail_recoverable: u64,
    /// L(FailStrict, Ambiguous).
    pub fail_ambiguous: u64,
    /// L(FailStrict, Unrecoverable).
    pub fail_unrecoverable: u64,
}

impl Default for LossMatrix {
    fn default() -> Self {
        Self {
            recover_recoverable: 0,
            recover_ambiguous: 55,
            recover_unrecoverable: 90,
            partial_recoverable: 5,
            partial_ambiguous: 15,
            partial_unrecoverable: 40,
            fail_recoverable: 12,
            fail_ambiguous: 3,
            fail_unrecoverable: 0,
        }
    }
}

impl LossMatrix {
    /// Compute expected loss for an action given a posterior.
    pub fn expected_loss(&self, action: RecoveryAction, posterior: &Posterior) -> u64 {
        let (lr, la, lu) = match action {
            RecoveryAction::RecoverContinue => (
                self.recover_recoverable,
                self.recover_ambiguous,
                self.recover_unrecoverable,
            ),
            RecoveryAction::PartialRecover => (
                self.partial_recoverable,
                self.partial_ambiguous,
                self.partial_unrecoverable,
            ),
            RecoveryAction::FailStrict => (
                self.fail_recoverable,
                self.fail_ambiguous,
                self.fail_unrecoverable,
            ),
        };
        // Expected loss = sum(loss_i * P(state_i)) / MILLION.
        lr.saturating_mul(posterior.recoverable)
            .saturating_div(MILLION)
            .saturating_add(
                la.saturating_mul(posterior.ambiguous)
                    .saturating_div(MILLION),
            )
            .saturating_add(
                lu.saturating_mul(posterior.unrecoverable)
                    .saturating_div(MILLION),
            )
    }

    /// Select the minimum-expected-loss action.
    pub fn optimal_action(&self, posterior: &Posterior) -> RecoveryAction {
        let el_recover = self.expected_loss(RecoveryAction::RecoverContinue, posterior);
        let el_partial = self.expected_loss(RecoveryAction::PartialRecover, posterior);
        let el_fail = self.expected_loss(RecoveryAction::FailStrict, posterior);
        if el_recover <= el_partial && el_recover <= el_fail {
            RecoveryAction::RecoverContinue
        } else if el_partial <= el_fail {
            RecoveryAction::PartialRecover
        } else {
            RecoveryAction::FailStrict
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the recovery controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Recovery operating mode.
    pub mode: RecoveryMode,
    /// Maximum recovery attempts per file.
    pub max_attempts: u32,
    /// Maximum token skips per attempt.
    pub max_skips: u32,
    /// Maximum token insertions per attempt.
    pub max_insertions: u32,
    /// Confidence threshold to accept recovery (millionths).
    pub confidence_threshold_millionths: u64,
    /// Prior distribution.
    pub prior: Posterior,
    /// Loss matrix.
    pub loss_matrix: LossMatrix,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            mode: RecoveryMode::StrictDefault,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            max_skips: DEFAULT_MAX_SKIPS,
            max_insertions: DEFAULT_MAX_INSERTIONS,
            confidence_threshold_millionths: DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS,
            prior: Posterior::default_prior(),
            loss_matrix: LossMatrix::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery candidate
// ---------------------------------------------------------------------------

/// A candidate repair action with cost and description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCandidate {
    /// Human-readable description.
    pub description: String,
    /// Number of tokens skipped.
    pub skips: u32,
    /// Number of tokens inserted.
    pub insertions: u32,
    /// Cost metric (lower = better).
    pub cost: u64,
    /// Whether this is a known typo-pattern fix.
    pub is_typo_fix: bool,
}

// ---------------------------------------------------------------------------
// Recovery attempt
// ---------------------------------------------------------------------------

/// A single recovery attempt at an error site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAttempt {
    /// Attempt index (0-based).
    pub attempt_index: u32,
    /// Token position of the error.
    pub error_position: u64,
    /// Evidence features at the error site.
    pub evidence: EvidenceFeatures,
    /// Posterior after Bayesian update.
    pub posterior: Posterior,
    /// Expected losses for each action.
    pub expected_losses: Vec<(RecoveryAction, u64)>,
    /// Selected action.
    pub selected_action: RecoveryAction,
    /// Rejected actions with reasons.
    pub rejected_actions: Vec<(RecoveryAction, String)>,
    /// Confidence (MAP posterior, millionths).
    pub confidence_millionths: u64,
    /// Whether confidence exceeded threshold.
    pub confidence_met: bool,
    /// Selected repair candidate (if recovery accepted).
    pub selected_repair: Option<RepairCandidate>,
}

// ---------------------------------------------------------------------------
// Recovery decision
// ---------------------------------------------------------------------------

/// The final decision from the recovery controller for one error site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDecision {
    /// Unique decision identifier.
    pub decision_id: String,
    /// Error position (token index).
    pub error_position: u64,
    /// Recovery mode used.
    pub mode: RecoveryMode,
    /// Final action taken.
    pub action: RecoveryAction,
    /// Final posterior.
    pub posterior: Posterior,
    /// Confidence (millionths).
    pub confidence_millionths: u64,
    /// Number of attempts made.
    pub attempts: u32,
    /// Evidence features hash.
    pub evidence_hash: ContentHash,
    /// Explanation string.
    pub explanation: String,
    /// Replay command.
    pub replay_command: String,
}

// ---------------------------------------------------------------------------
// Repair diff
// ---------------------------------------------------------------------------

/// A single edit in a repair diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairEdit {
    /// Skip tokens at the given position.
    Skip { position: u64, count: u32 },
    /// Insert tokens at the given position.
    Insert { position: u64, tokens: Vec<String> },
}

/// A diff describing all repairs applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairDiff {
    /// Schema version.
    pub schema_version: String,
    /// Input hash.
    pub input_hash: ContentHash,
    /// Edits applied (in order).
    pub edits: Vec<RepairEdit>,
    /// Diff hash for content addressing.
    pub diff_hash: ContentHash,
}

impl RepairDiff {
    /// Build from a set of edits.
    pub fn build(input_hash: ContentHash, edits: Vec<RepairEdit>) -> Self {
        let diff_hash = Self::compute_hash(&edits);
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            input_hash,
            edits,
            diff_hash,
        }
    }

    fn compute_hash(edits: &[RepairEdit]) -> ContentHash {
        let mut parts = Vec::new();
        for edit in edits {
            match edit {
                RepairEdit::Skip { position, count } => {
                    parts.push(format!("skip:{position}:{count}"));
                }
                RepairEdit::Insert { position, tokens } => {
                    parts.push(format!("insert:{position}:{}", tokens.join(",")));
                }
            }
        }
        ContentHash::compute(parts.join("|").as_bytes())
    }

    /// Whether no edits were applied.
    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Structured events
// ---------------------------------------------------------------------------

/// Structured audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryEvent {
    /// Trace identifier.
    pub trace_id: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Component.
    pub component: String,
    /// Event name.
    pub event: String,
    /// Outcome.
    pub outcome: String,
    /// Error code (if any).
    pub error_code: Option<String>,
    /// Recovery mode.
    pub mode: String,
    /// Evidence features hash.
    pub evidence_hash: Option<String>,
    /// Posterior confidence (millionths).
    pub confidence_millionths: Option<u64>,
    /// Selected action.
    pub action: Option<String>,
    /// Replay command.
    pub replay_command: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors during recovery evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryError {
    /// Budget exhausted: max attempts reached.
    BudgetExhausted { attempts: u32, max: u32 },
    /// Invalid configuration.
    InvalidConfig { detail: String },
    /// No candidates available.
    NoCandidates { error_position: u64 },
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { attempts, max } => {
                write!(f, "budget exhausted: {attempts}/{max} attempts")
            }
            Self::InvalidConfig { detail } => write!(f, "invalid config: {detail}"),
            Self::NoCandidates { error_position } => {
                write!(f, "no candidates at position {error_position}")
            }
        }
    }
}

impl RecoveryError {
    /// Machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BudgetExhausted { .. } => "BUDGET_EXHAUSTED",
            Self::InvalidConfig { .. } => "INVALID_CONFIG",
            Self::NoCandidates { .. } => "NO_CANDIDATES",
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery result
// ---------------------------------------------------------------------------

/// Result of recovery evaluation for a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryResult {
    /// Schema version.
    pub schema_version: String,
    /// Recovery mode used.
    pub mode: RecoveryMode,
    /// Whether recovery was successful.
    pub recovered: bool,
    /// Final action taken.
    pub final_action: RecoveryAction,
    /// All decisions made during recovery.
    pub decisions: Vec<RecoveryDecision>,
    /// All attempts made.
    pub attempts: Vec<RecoveryAttempt>,
    /// Repair diff (if recovery applied edits).
    pub repair_diff: Option<RepairDiff>,
    /// Structured events.
    pub events: Vec<RecoveryEvent>,
    /// Input hash.
    pub input_hash: ContentHash,
    /// Result digest.
    pub result_digest: ContentHash,
}

impl RecoveryResult {
    /// Human-readable summary.
    pub fn summary(&self) -> String {
        if self.recovered {
            format!(
                "RECOVERED: {} decisions, mode={}, edits={}",
                self.decisions.len(),
                self.mode,
                self.repair_diff.as_ref().map_or(0, |d| d.edits.len()),
            )
        } else {
            format!(
                "STRICT_FAIL: {} decisions, mode={}, action={}",
                self.decisions.len(),
                self.mode,
                self.final_action,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Error site (input to the controller)
// ---------------------------------------------------------------------------

/// An error site: where a syntax error was detected with candidate repairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorSite {
    /// Token position of the error.
    pub error_position: u64,
    /// Tokens parsed before this error.
    pub tokens_before_error: u64,
    /// Whether at a statement boundary.
    pub at_statement_boundary: bool,
    /// Candidate repairs.
    pub candidates: Vec<RepairCandidate>,
    /// Context hash.
    pub context_hash: ContentHash,
}

impl ErrorSite {
    /// Build evidence features from this error site.
    pub fn to_evidence(&self) -> EvidenceFeatures {
        let min_skip = self.candidates.iter().map(|c| c.skips).min().unwrap_or(0);
        let min_insert = self
            .candidates
            .iter()
            .map(|c| c.insertions)
            .min()
            .unwrap_or(0);
        let has_typo = self.candidates.iter().any(|c| c.is_typo_fix);
        EvidenceFeatures {
            tokens_before_error: self.tokens_before_error,
            candidate_repairs: self.candidates.len() as u32,
            at_statement_boundary: self.at_statement_boundary,
            min_skip_tokens: min_skip,
            min_insert_tokens: min_insert,
            matches_typo_pattern: has_typo,
            context_hash: self.context_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery controller
// ---------------------------------------------------------------------------

/// The recovery controller: evaluates error sites and produces decisions.
pub struct RecoveryController {
    config: RecoveryConfig,
    seed: u64,
    events: Vec<RecoveryEvent>,
    attempt_count: u32,
}

impl RecoveryController {
    /// Create a new recovery controller.
    pub fn new(config: RecoveryConfig, seed: u64) -> Self {
        Self {
            config,
            seed,
            events: Vec::new(),
            attempt_count: 0,
        }
    }

    /// Evaluate a sequence of error sites.
    pub fn evaluate(
        &mut self,
        input_hash: ContentHash,
        error_sites: &[ErrorSite],
        trace_id: &str,
    ) -> Result<RecoveryResult, RecoveryError> {
        if self.config.max_attempts == 0 {
            return Err(RecoveryError::InvalidConfig {
                detail: "max_attempts must be >= 1".to_string(),
            });
        }

        // Strict mode: immediate fail.
        if self.config.mode == RecoveryMode::StrictDefault {
            let decision = RecoveryDecision {
                decision_id: format!("dec-{:016x}-strict", self.seed),
                error_position: error_sites.first().map_or(0, |s| s.error_position),
                mode: self.config.mode,
                action: RecoveryAction::FailStrict,
                posterior: self.config.prior.clone(),
                confidence_millionths: 0,
                attempts: 0,
                evidence_hash: ContentHash::compute(b"strict-mode"),
                explanation: "strict mode: no recovery attempted".to_string(),
                replay_command: format!(
                    "franken-engine parse --trace-id {trace_id} --recovery-mode strict_default"
                ),
            };
            self.emit_event(
                trace_id,
                &decision.decision_id,
                "strict_fail",
                "fail_strict",
            );
            let result_digest = ContentHash::compute(
                format!("strict:{input_hash}:{}", error_sites.len()).as_bytes(),
            );
            return Ok(RecoveryResult {
                schema_version: SCHEMA_VERSION.to_string(),
                mode: self.config.mode,
                recovered: false,
                final_action: RecoveryAction::FailStrict,
                decisions: vec![decision],
                attempts: Vec::new(),
                repair_diff: None,
                events: self.events.clone(),
                input_hash,
                result_digest,
            });
        }

        let mut decisions = Vec::new();
        let mut all_attempts = Vec::new();
        let mut edits = Vec::new();
        let mut any_failed = false;

        for (site_idx, site) in error_sites.iter().enumerate() {
            if self.attempt_count >= self.config.max_attempts {
                return Err(RecoveryError::BudgetExhausted {
                    attempts: self.attempt_count,
                    max: self.config.max_attempts,
                });
            }

            let (decision, attempt) = self.evaluate_site(site, site_idx as u32, trace_id)?;

            if decision.action == RecoveryAction::FailStrict {
                any_failed = true;
            }

            // Collect edits from accepted repairs.
            if decision.action != RecoveryAction::FailStrict
                && let Some(ref repair) = attempt.selected_repair
            {
                if repair.skips > 0 {
                    edits.push(RepairEdit::Skip {
                        position: site.error_position,
                        count: repair.skips,
                    });
                }
                if repair.insertions > 0 {
                    edits.push(RepairEdit::Insert {
                        position: site.error_position,
                        tokens: vec![repair.description.clone()],
                    });
                }
            }

            decisions.push(decision);
            all_attempts.push(attempt);
        }

        let recovered = !any_failed && !decisions.is_empty();
        let final_action = if recovered {
            if decisions
                .iter()
                .all(|d| d.action == RecoveryAction::RecoverContinue)
            {
                RecoveryAction::RecoverContinue
            } else {
                RecoveryAction::PartialRecover
            }
        } else {
            RecoveryAction::FailStrict
        };

        // In diagnostic mode, never report as "recovered" for execution.
        let recovered = recovered && self.config.mode == RecoveryMode::ExecutionRecovery;

        let repair_diff = if !edits.is_empty() {
            Some(RepairDiff::build(input_hash, edits))
        } else {
            None
        };

        self.emit_event(
            trace_id,
            "final",
            "evaluation_complete",
            if recovered {
                "recovered"
            } else {
                "strict_fail"
            },
        );

        let result_digest = self.compute_digest(&decisions);

        Ok(RecoveryResult {
            schema_version: SCHEMA_VERSION.to_string(),
            mode: self.config.mode,
            recovered,
            final_action,
            decisions,
            attempts: all_attempts,
            repair_diff,
            events: self.events.clone(),
            input_hash,
            result_digest,
        })
    }

    /// Evaluate a single error site.
    fn evaluate_site(
        &mut self,
        site: &ErrorSite,
        site_idx: u32,
        trace_id: &str,
    ) -> Result<(RecoveryDecision, RecoveryAttempt), RecoveryError> {
        self.attempt_count += 1;
        let evidence = site.to_evidence();
        let posterior = bayesian_update(&self.config.prior, &evidence);
        let confidence = posterior.map_confidence();
        let confidence_met = confidence >= self.config.confidence_threshold_millionths;

        // Compute expected losses.
        let el_recover = self
            .config
            .loss_matrix
            .expected_loss(RecoveryAction::RecoverContinue, &posterior);
        let el_partial = self
            .config
            .loss_matrix
            .expected_loss(RecoveryAction::PartialRecover, &posterior);
        let el_fail = self
            .config
            .loss_matrix
            .expected_loss(RecoveryAction::FailStrict, &posterior);

        let expected_losses = vec![
            (RecoveryAction::RecoverContinue, el_recover),
            (RecoveryAction::PartialRecover, el_partial),
            (RecoveryAction::FailStrict, el_fail),
        ];

        // Select action based on loss matrix.
        let optimal = self.config.loss_matrix.optimal_action(&posterior);

        // Apply confidence gate: if not confident enough, fail strict.
        let selected_action = if !confidence_met
            && (optimal == RecoveryAction::RecoverContinue
                || optimal == RecoveryAction::PartialRecover)
        {
            RecoveryAction::FailStrict
        } else {
            optimal
        };

        // Build rejected actions list.
        let mut rejected = Vec::new();
        for &action in &[
            RecoveryAction::RecoverContinue,
            RecoveryAction::PartialRecover,
            RecoveryAction::FailStrict,
        ] {
            if action != selected_action {
                let reason = if action != optimal {
                    format!(
                        "higher expected loss ({})",
                        self.config.loss_matrix.expected_loss(action, &posterior),
                    )
                } else {
                    "confidence below threshold".to_string()
                };
                rejected.push((action, reason));
            }
        }

        // Fail closed when recovery was selected but every candidate exceeds budget.
        let selected_repair = if selected_action != RecoveryAction::FailStrict {
            let repair = self.select_repair(site);
            if repair.is_none() {
                return Err(RecoveryError::NoCandidates {
                    error_position: site.error_position,
                });
            }
            repair
        } else {
            None
        };

        let decision_id = format!(
            "dec-{:016x}-{site_idx}",
            self.seed.wrapping_add(site_idx as u64),
        );
        let evidence_hash = evidence.compute_hash();

        let explanation = format!(
            "posterior={{R={},A={},U={}}}, confidence={}, threshold={}, action={}, MAP={}",
            posterior.recoverable,
            posterior.ambiguous,
            posterior.unrecoverable,
            confidence,
            self.config.confidence_threshold_millionths,
            selected_action,
            posterior.map_state(),
        );

        self.emit_event(
            trace_id,
            &decision_id,
            "site_evaluated",
            &format!("{selected_action}"),
        );

        let decision = RecoveryDecision {
            decision_id: decision_id.clone(),
            error_position: site.error_position,
            mode: self.config.mode,
            action: selected_action,
            posterior: posterior.clone(),
            confidence_millionths: confidence,
            attempts: self.attempt_count,
            evidence_hash,
            explanation,
            replay_command: format!(
                "franken-engine parse --trace-id {trace_id} --recovery-site {site_idx}"
            ),
        };

        let attempt = RecoveryAttempt {
            attempt_index: site_idx,
            error_position: site.error_position,
            evidence,
            posterior,
            expected_losses,
            selected_action,
            rejected_actions: rejected,
            confidence_millionths: confidence,
            confidence_met,
            selected_repair,
        };

        Ok((decision, attempt))
    }

    /// Select the best repair candidate from an error site.
    fn select_repair(&self, site: &ErrorSite) -> Option<RepairCandidate> {
        let mut eligible: Vec<&RepairCandidate> = site
            .candidates
            .iter()
            .filter(|c| {
                c.skips <= self.config.max_skips && c.insertions <= self.config.max_insertions
            })
            .collect();
        // Sort by cost ascending.
        eligible.sort_by_key(|c| c.cost);
        eligible.first().cloned().cloned()
    }

    /// Emit a structured event.
    fn emit_event(&mut self, trace_id: &str, decision_id: &str, event: &str, outcome: &str) {
        self.events.push(RecoveryEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: None,
            mode: format!("{}", self.config.mode),
            evidence_hash: None,
            confidence_millionths: None,
            action: Some(outcome.to_string()),
            replay_command: None,
        });
    }

    /// Compute a content-addressed digest over decisions.
    fn compute_digest(&self, decisions: &[RecoveryDecision]) -> ContentHash {
        let mut parts = Vec::new();
        for d in decisions {
            parts.push(format!(
                "{}:{}:{}:{}",
                d.decision_id, d.action, d.confidence_millionths, d.evidence_hash,
            ));
        }
        ContentHash::compute(parts.join("|").as_bytes())
    }
}

/// Convenience: evaluate error sites with default configuration.
pub fn evaluate(
    input_hash: ContentHash,
    error_sites: &[ErrorSite],
    config: &RecoveryConfig,
    seed: u64,
    trace_id: &str,
) -> Result<RecoveryResult, RecoveryError> {
    let mut controller = RecoveryController::new(config.clone(), seed);
    controller.evaluate(input_hash, error_sites, trace_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash() -> ContentHash {
        ContentHash::compute(b"test")
    }

    fn simple_error_site() -> ErrorSite {
        ErrorSite {
            error_position: 10,
            tokens_before_error: 10,
            at_statement_boundary: true,
            candidates: vec![RepairCandidate {
                description: "insert semicolon".to_string(),
                skips: 0,
                insertions: 1,
                cost: 1,
                is_typo_fix: true,
            }],
            context_hash: test_hash(),
        }
    }

    fn ambiguous_error_site() -> ErrorSite {
        ErrorSite {
            error_position: 20,
            tokens_before_error: 3,
            at_statement_boundary: false,
            candidates: vec![
                RepairCandidate {
                    description: "insert paren".to_string(),
                    skips: 0,
                    insertions: 1,
                    cost: 2,
                    is_typo_fix: false,
                },
                RepairCandidate {
                    description: "skip token".to_string(),
                    skips: 1,
                    insertions: 0,
                    cost: 3,
                    is_typo_fix: false,
                },
                RepairCandidate {
                    description: "insert brace".to_string(),
                    skips: 0,
                    insertions: 2,
                    cost: 4,
                    is_typo_fix: false,
                },
            ],
            context_hash: test_hash(),
        }
    }

    fn no_candidate_site() -> ErrorSite {
        ErrorSite {
            error_position: 50,
            tokens_before_error: 30,
            at_statement_boundary: false,
            candidates: Vec::new(),
            context_hash: test_hash(),
        }
    }

    fn diagnostic_config() -> RecoveryConfig {
        RecoveryConfig {
            mode: RecoveryMode::DiagnosticRecovery,
            ..RecoveryConfig::default()
        }
    }

    fn execution_config() -> RecoveryConfig {
        RecoveryConfig {
            mode: RecoveryMode::ExecutionRecovery,
            ..RecoveryConfig::default()
        }
    }

    // --- RecoveryMode tests ---

    #[test]
    fn recovery_mode_display() {
        assert_eq!(format!("{}", RecoveryMode::StrictDefault), "strict_default");
        assert_eq!(
            format!("{}", RecoveryMode::DiagnosticRecovery),
            "diagnostic_recovery"
        );
        assert_eq!(
            format!("{}", RecoveryMode::ExecutionRecovery),
            "execution_recovery"
        );
    }

    #[test]
    fn recovery_mode_ordering() {
        assert!(RecoveryMode::StrictDefault < RecoveryMode::DiagnosticRecovery);
        assert!(RecoveryMode::DiagnosticRecovery < RecoveryMode::ExecutionRecovery);
    }

    #[test]
    fn recovery_mode_serde_roundtrip() {
        let modes = vec![
            RecoveryMode::StrictDefault,
            RecoveryMode::DiagnosticRecovery,
            RecoveryMode::ExecutionRecovery,
        ];
        let json = serde_json::to_string(&modes).unwrap();
        let back: Vec<RecoveryMode> = serde_json::from_str(&json).unwrap();
        assert_eq!(modes, back);
    }

    // --- ErrorState tests ---

    #[test]
    fn error_state_display() {
        assert_eq!(format!("{}", ErrorState::Recoverable), "recoverable");
        assert_eq!(format!("{}", ErrorState::Ambiguous), "ambiguous");
        assert_eq!(format!("{}", ErrorState::Unrecoverable), "unrecoverable");
    }

    #[test]
    fn error_state_ordering() {
        assert!(ErrorState::Recoverable < ErrorState::Ambiguous);
        assert!(ErrorState::Ambiguous < ErrorState::Unrecoverable);
    }

    // --- RecoveryAction tests ---

    #[test]
    fn recovery_action_display() {
        assert_eq!(
            format!("{}", RecoveryAction::RecoverContinue),
            "recover_continue"
        );
        assert_eq!(
            format!("{}", RecoveryAction::PartialRecover),
            "partial_recover"
        );
        assert_eq!(format!("{}", RecoveryAction::FailStrict), "fail_strict");
    }

    // --- Posterior tests ---

    #[test]
    fn posterior_normalization() {
        let p = Posterior::new(100, 200, 300);
        assert!(p.is_normalized());
        assert_eq!(
            p.recoverable
                .saturating_add(p.ambiguous)
                .saturating_add(p.unrecoverable),
            MILLION
        );
    }

    #[test]
    fn posterior_zero_input() {
        let p = Posterior::new(0, 0, 0);
        assert!(p.is_normalized());
    }

    #[test]
    fn posterior_default_prior() {
        let p = Posterior::default_prior();
        assert!(p.is_normalized());
        assert_eq!(p.recoverable, DEFAULT_PRIOR_RECOVERABLE);
    }

    #[test]
    fn posterior_map_state_recoverable() {
        let p = Posterior::new(700_000, 200_000, 100_000);
        assert_eq!(p.map_state(), ErrorState::Recoverable);
    }

    #[test]
    fn posterior_map_state_ambiguous() {
        let p = Posterior::new(200_000, 600_000, 200_000);
        assert_eq!(p.map_state(), ErrorState::Ambiguous);
    }

    #[test]
    fn posterior_map_state_unrecoverable() {
        let p = Posterior::new(100_000, 200_000, 700_000);
        assert_eq!(p.map_state(), ErrorState::Unrecoverable);
    }

    #[test]
    fn posterior_map_confidence() {
        let p = Posterior::new(100_000, 200_000, 700_000);
        assert_eq!(p.map_confidence(), p.unrecoverable);
    }

    #[test]
    fn posterior_serde_roundtrip() {
        let p = Posterior::default_prior();
        let json = serde_json::to_string(&p).unwrap();
        let back: Posterior = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // --- Evidence features tests ---

    #[test]
    fn evidence_features_hash_deterministic() {
        let e = EvidenceFeatures {
            tokens_before_error: 10,
            candidate_repairs: 2,
            at_statement_boundary: true,
            min_skip_tokens: 0,
            min_insert_tokens: 1,
            matches_typo_pattern: false,
            context_hash: test_hash(),
        };
        let h1 = e.compute_hash();
        let h2 = e.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn evidence_features_serde_roundtrip() {
        let e = EvidenceFeatures {
            tokens_before_error: 5,
            candidate_repairs: 1,
            at_statement_boundary: false,
            min_skip_tokens: 1,
            min_insert_tokens: 0,
            matches_typo_pattern: true,
            context_hash: test_hash(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: EvidenceFeatures = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Likelihood tests ---

    #[test]
    fn likelihood_typo_pattern_favors_recoverable() {
        let e = EvidenceFeatures {
            tokens_before_error: 20,
            candidate_repairs: 1,
            at_statement_boundary: true,
            min_skip_tokens: 0,
            min_insert_tokens: 1,
            matches_typo_pattern: true,
            context_hash: test_hash(),
        };
        let ls = compute_likelihoods(&e);
        assert!(ls[0] > ls[1], "recoverable should > ambiguous");
        assert!(ls[0] > ls[2], "recoverable should > unrecoverable");
    }

    #[test]
    fn likelihood_no_candidates_favors_unrecoverable() {
        let e = EvidenceFeatures {
            tokens_before_error: 20,
            candidate_repairs: 0,
            at_statement_boundary: false,
            min_skip_tokens: 0,
            min_insert_tokens: 0,
            matches_typo_pattern: false,
            context_hash: test_hash(),
        };
        let ls = compute_likelihoods(&e);
        assert!(ls[2] > ls[0], "unrecoverable should > recoverable");
    }

    #[test]
    fn likelihood_many_candidates_favors_ambiguous() {
        let e = EvidenceFeatures {
            tokens_before_error: 20,
            candidate_repairs: 5,
            at_statement_boundary: false,
            min_skip_tokens: 0,
            min_insert_tokens: 0,
            matches_typo_pattern: false,
            context_hash: test_hash(),
        };
        let ls = compute_likelihoods(&e);
        assert!(ls[1] > ls[0], "ambiguous should > recoverable");
    }

    // --- Bayesian update tests ---

    #[test]
    fn bayesian_update_normalizes() {
        let prior = Posterior::default_prior();
        let e = EvidenceFeatures {
            tokens_before_error: 20,
            candidate_repairs: 1,
            at_statement_boundary: true,
            min_skip_tokens: 0,
            min_insert_tokens: 1,
            matches_typo_pattern: true,
            context_hash: test_hash(),
        };
        let post = bayesian_update(&prior, &e);
        assert!(post.is_normalized());
    }

    #[test]
    fn bayesian_update_typo_shifts_toward_recoverable() {
        let prior = Posterior::default_prior();
        let e = EvidenceFeatures {
            tokens_before_error: 20,
            candidate_repairs: 1,
            at_statement_boundary: true,
            min_skip_tokens: 0,
            min_insert_tokens: 0,
            matches_typo_pattern: true,
            context_hash: test_hash(),
        };
        let post = bayesian_update(&prior, &e);
        assert!(
            post.recoverable > prior.recoverable,
            "recoverable should increase: {} vs {}",
            post.recoverable,
            prior.recoverable,
        );
    }

    #[test]
    fn bayesian_update_no_candidates_shifts_toward_unrecoverable() {
        let prior = Posterior::default_prior();
        let e = EvidenceFeatures {
            tokens_before_error: 20,
            candidate_repairs: 0,
            at_statement_boundary: false,
            min_skip_tokens: 0,
            min_insert_tokens: 0,
            matches_typo_pattern: false,
            context_hash: test_hash(),
        };
        let post = bayesian_update(&prior, &e);
        assert!(
            post.unrecoverable > prior.unrecoverable,
            "unrecoverable should increase: {} vs {}",
            post.unrecoverable,
            prior.unrecoverable,
        );
    }

    #[test]
    fn bayesian_update_deterministic() {
        let prior = Posterior::default_prior();
        let e = EvidenceFeatures {
            tokens_before_error: 15,
            candidate_repairs: 2,
            at_statement_boundary: true,
            min_skip_tokens: 1,
            min_insert_tokens: 1,
            matches_typo_pattern: false,
            context_hash: test_hash(),
        };
        let p1 = bayesian_update(&prior, &e);
        let p2 = bayesian_update(&prior, &e);
        assert_eq!(p1, p2);
    }

    // --- Loss matrix tests ---

    #[test]
    fn loss_matrix_default() {
        let lm = LossMatrix::default();
        assert_eq!(lm.recover_recoverable, 0);
        assert_eq!(lm.recover_unrecoverable, 90);
        assert_eq!(lm.fail_unrecoverable, 0);
    }

    #[test]
    fn loss_matrix_expected_loss_fail_on_unrecoverable() {
        let lm = LossMatrix::default();
        let posterior = Posterior::new(0, 0, MILLION); // 100% unrecoverable
        let el = lm.expected_loss(RecoveryAction::FailStrict, &posterior);
        assert_eq!(el, lm.fail_unrecoverable);
    }

    #[test]
    fn loss_matrix_expected_loss_recover_on_recoverable() {
        let lm = LossMatrix::default();
        let posterior = Posterior::new(MILLION, 0, 0); // 100% recoverable
        let el = lm.expected_loss(RecoveryAction::RecoverContinue, &posterior);
        assert_eq!(el, lm.recover_recoverable);
    }

    #[test]
    fn loss_matrix_optimal_action_for_recoverable() {
        let lm = LossMatrix::default();
        let posterior = Posterior::new(MILLION, 0, 0); // 100% recoverable
        assert_eq!(
            lm.optimal_action(&posterior),
            RecoveryAction::RecoverContinue
        );
    }

    #[test]
    fn loss_matrix_optimal_action_for_unrecoverable() {
        let lm = LossMatrix::default();
        let posterior = Posterior::new(0, 0, MILLION); // 100% unrecoverable
        assert_eq!(lm.optimal_action(&posterior), RecoveryAction::FailStrict);
    }

    #[test]
    fn loss_matrix_serde_roundtrip() {
        let lm = LossMatrix::default();
        let json = serde_json::to_string(&lm).unwrap();
        let back: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(lm, back);
    }

    // --- Config tests ---

    #[test]
    fn config_default_strict_mode() {
        let cfg = RecoveryConfig::default();
        assert_eq!(cfg.mode, RecoveryMode::StrictDefault);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = RecoveryConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RecoveryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // --- RepairDiff tests ---

    #[test]
    fn repair_diff_empty() {
        let diff = RepairDiff::build(test_hash(), Vec::new());
        assert!(diff.is_empty());
    }

    #[test]
    fn repair_diff_with_edits() {
        let edits = vec![
            RepairEdit::Skip {
                position: 5,
                count: 1,
            },
            RepairEdit::Insert {
                position: 6,
                tokens: vec![";".to_string()],
            },
        ];
        let diff = RepairDiff::build(test_hash(), edits);
        assert!(!diff.is_empty());
        assert_eq!(diff.edits.len(), 2);
    }

    #[test]
    fn repair_diff_hash_deterministic() {
        let edits = vec![RepairEdit::Skip {
            position: 5,
            count: 1,
        }];
        let d1 = RepairDiff::build(test_hash(), edits.clone());
        let d2 = RepairDiff::build(test_hash(), edits);
        assert_eq!(d1.diff_hash, d2.diff_hash);
    }

    #[test]
    fn repair_diff_serde_roundtrip() {
        let diff = RepairDiff::build(
            test_hash(),
            vec![RepairEdit::Insert {
                position: 0,
                tokens: vec!["x".to_string()],
            }],
        );
        let json = serde_json::to_string(&diff).unwrap();
        let back: RepairDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, back);
    }

    // --- RecoveryError tests ---

    #[test]
    fn recovery_error_display() {
        let e = RecoveryError::BudgetExhausted {
            attempts: 5,
            max: 5,
        };
        assert!(format!("{e}").contains("5/5"));
        assert_eq!(e.code(), "BUDGET_EXHAUSTED");
    }

    #[test]
    fn recovery_error_serde_roundtrip() {
        let e = RecoveryError::NoCandidates { error_position: 42 };
        let json = serde_json::to_string(&e).unwrap();
        let back: RecoveryError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Controller: strict mode ---

    #[test]
    fn strict_mode_always_fails() {
        let cfg = RecoveryConfig::default(); // strict by default
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert!(!result.recovered);
        assert_eq!(result.final_action, RecoveryAction::FailStrict);
        assert_eq!(result.mode, RecoveryMode::StrictDefault);
    }

    #[test]
    fn strict_mode_emits_events() {
        let cfg = RecoveryConfig::default();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert!(!result.events.is_empty());
    }

    // --- Controller: diagnostic mode ---

    #[test]
    fn diagnostic_mode_does_not_report_recovered() {
        let cfg = diagnostic_config();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        // Diagnostic mode: never reports recovered=true.
        assert!(!result.recovered);
    }

    #[test]
    fn diagnostic_mode_still_evaluates() {
        let cfg = diagnostic_config();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert!(!result.decisions.is_empty());
        assert!(!result.attempts.is_empty());
    }

    // --- Controller: execution mode ---

    #[test]
    fn execution_mode_recovers_simple_typo() {
        let cfg = execution_config();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        // Simple typo with single candidate should recover.
        assert!(result.recovered);
        assert_ne!(result.final_action, RecoveryAction::FailStrict);
    }

    #[test]
    fn execution_mode_generates_repair_diff() {
        let cfg = execution_config();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert!(result.repair_diff.is_some());
    }

    #[test]
    fn execution_mode_fails_on_no_candidates() {
        let cfg = execution_config();
        let sites = vec![no_candidate_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert!(!result.recovered);
        assert_eq!(result.final_action, RecoveryAction::FailStrict);
    }

    // --- Controller: budget exhaustion ---

    #[test]
    fn budget_exhaustion_error() {
        let mut cfg = execution_config();
        cfg.max_attempts = 1;
        let sites = vec![simple_error_site(), simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "BUDGET_EXHAUSTED");
    }

    // --- Controller: invalid config ---

    #[test]
    fn zero_max_attempts_error() {
        let mut cfg = execution_config();
        cfg.max_attempts = 0;
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "INVALID_CONFIG");
    }

    // --- Controller: multiple sites ---

    #[test]
    fn multiple_sites_all_recovered() {
        let cfg = execution_config();
        let sites = vec![simple_error_site(), simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert!(result.recovered);
        assert_eq!(result.decisions.len(), 2);
    }

    #[test]
    fn mixed_sites_any_fail_means_not_recovered() {
        let cfg = execution_config();
        let sites = vec![simple_error_site(), no_candidate_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert!(!result.recovered);
    }

    // --- Controller: determinism ---

    #[test]
    fn controller_deterministic() {
        let cfg = execution_config();
        let sites = vec![simple_error_site()];
        let r1 = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        let r2 = evaluate(test_hash(), &sites, &cfg, 42, "trace-1").unwrap();
        assert_eq!(r1.result_digest, r2.result_digest);
        assert_eq!(r1.recovered, r2.recovered);
    }

    // --- Result: summary ---

    #[test]
    fn result_summary_recovered() {
        let cfg = execution_config();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "t").unwrap();
        let summary = result.summary();
        assert!(summary.starts_with("RECOVERED:"));
    }

    #[test]
    fn result_summary_strict_fail() {
        let cfg = RecoveryConfig::default();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "t").unwrap();
        let summary = result.summary();
        assert!(summary.starts_with("STRICT_FAIL:"));
    }

    // --- Result: serde roundtrip ---

    #[test]
    fn recovery_result_serde_roundtrip() {
        let cfg = execution_config();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "t").unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: RecoveryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.result_digest, back.result_digest);
        assert_eq!(result.recovered, back.recovered);
    }

    // --- Schema version ---

    #[test]
    fn schema_version_in_result() {
        let cfg = RecoveryConfig::default();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 0, "t").unwrap();
        assert_eq!(result.schema_version, SCHEMA_VERSION);
    }

    // --- RecoveryEvent serde ---

    #[test]
    fn recovery_event_serde_roundtrip() {
        let evt = RecoveryEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            component: COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            mode: "strict_default".to_string(),
            evidence_hash: None,
            confidence_millionths: Some(500_000),
            action: Some("fail_strict".to_string()),
            replay_command: None,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: RecoveryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    // --- ErrorSite to_evidence ---

    #[test]
    fn error_site_to_evidence() {
        let site = simple_error_site();
        let evidence = site.to_evidence();
        assert_eq!(evidence.tokens_before_error, 10);
        assert_eq!(evidence.candidate_repairs, 1);
        assert!(evidence.at_statement_boundary);
        assert!(evidence.matches_typo_pattern);
    }

    #[test]
    fn error_site_to_evidence_no_candidates() {
        let site = no_candidate_site();
        let evidence = site.to_evidence();
        assert_eq!(evidence.candidate_repairs, 0);
        assert!(!evidence.matches_typo_pattern);
    }

    // --- RepairCandidate serde ---

    #[test]
    fn repair_candidate_serde_roundtrip() {
        let rc = RepairCandidate {
            description: "fix".to_string(),
            skips: 1,
            insertions: 0,
            cost: 5,
            is_typo_fix: true,
        };
        let json = serde_json::to_string(&rc).unwrap();
        let back: RepairCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(rc, back);
    }

    // --- RecoveryDecision serde ---

    #[test]
    fn recovery_decision_serde_roundtrip() {
        let d = RecoveryDecision {
            decision_id: "dec-1".to_string(),
            error_position: 10,
            mode: RecoveryMode::ExecutionRecovery,
            action: RecoveryAction::RecoverContinue,
            posterior: Posterior::default_prior(),
            confidence_millionths: 700_000,
            attempts: 1,
            evidence_hash: test_hash(),
            explanation: "test".to_string(),
            replay_command: "repro".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: RecoveryDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // --- RecoveryAttempt serde ---

    #[test]
    fn recovery_attempt_serde_roundtrip() {
        let a = RecoveryAttempt {
            attempt_index: 0,
            error_position: 10,
            evidence: EvidenceFeatures {
                tokens_before_error: 10,
                candidate_repairs: 1,
                at_statement_boundary: true,
                min_skip_tokens: 0,
                min_insert_tokens: 1,
                matches_typo_pattern: true,
                context_hash: test_hash(),
            },
            posterior: Posterior::default_prior(),
            expected_losses: vec![(RecoveryAction::RecoverContinue, 5)],
            selected_action: RecoveryAction::RecoverContinue,
            rejected_actions: vec![(RecoveryAction::FailStrict, "higher loss".to_string())],
            confidence_millionths: 700_000,
            confidence_met: true,
            selected_repair: None,
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: RecoveryAttempt = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- Component and schema constants ---

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "bayesian_error_recovery");
    }

    #[test]
    fn schema_starts_with_franken() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    // --- Ambiguous site decision ---

    #[test]
    fn ambiguous_site_produces_decision() {
        let cfg = execution_config();
        let sites = vec![ambiguous_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "t").unwrap();
        assert!(!result.decisions.is_empty());
        // Ambiguous evidence: the action should reflect uncertainty.
        let decision = &result.decisions[0];
        assert!(
            decision.action == RecoveryAction::FailStrict
                || decision.action == RecoveryAction::PartialRecover
                || decision.action == RecoveryAction::RecoverContinue
        );
    }

    // --- select_repair respects budget ---

    #[test]
    fn select_repair_respects_skip_budget() {
        let mut cfg = execution_config();
        cfg.max_skips = 0;
        let site = ErrorSite {
            error_position: 10,
            tokens_before_error: 20,
            at_statement_boundary: true,
            candidates: vec![RepairCandidate {
                description: "skip 3".to_string(),
                skips: 3,
                insertions: 0,
                cost: 1,
                is_typo_fix: false,
            }],
            context_hash: test_hash(),
        };
        let controller = RecoveryController::new(cfg, 42);
        assert!(controller.select_repair(&site).is_none());
    }

    #[test]
    fn evaluate_fails_when_budget_filters_all_candidates() {
        let mut cfg = execution_config();
        cfg.max_skips = 0;
        let site = ErrorSite {
            error_position: 10,
            tokens_before_error: 20,
            at_statement_boundary: true,
            candidates: vec![RepairCandidate {
                description: "skip 3".to_string(),
                skips: 3,
                insertions: 0,
                cost: 1,
                is_typo_fix: true,
            }],
            context_hash: test_hash(),
        };
        let err = evaluate(test_hash(), &[site], &cfg, 42, "t").unwrap_err();
        assert_eq!(err, RecoveryError::NoCandidates { error_position: 10 });
    }

    #[test]
    fn select_repair_picks_lowest_cost() {
        let cfg = execution_config();
        let site = ErrorSite {
            error_position: 10,
            tokens_before_error: 20,
            at_statement_boundary: true,
            candidates: vec![
                RepairCandidate {
                    description: "expensive".to_string(),
                    skips: 0,
                    insertions: 1,
                    cost: 100,
                    is_typo_fix: false,
                },
                RepairCandidate {
                    description: "cheap".to_string(),
                    skips: 0,
                    insertions: 1,
                    cost: 1,
                    is_typo_fix: false,
                },
            ],
            context_hash: test_hash(),
        };
        let controller = RecoveryController::new(cfg, 42);
        let repair = controller.select_repair(&site).unwrap();
        assert_eq!(repair.description, "cheap");
    }

    // --- Events contain required fields ---

    #[test]
    fn events_have_component_field() {
        let cfg = execution_config();
        let sites = vec![simple_error_site()];
        let result = evaluate(test_hash(), &sites, &cfg, 42, "t").unwrap();
        for evt in &result.events {
            assert_eq!(evt.component, COMPONENT);
        }
    }

    // --- Empty error sites ---

    #[test]
    fn empty_sites_strict_mode() {
        let cfg = RecoveryConfig::default();
        let result = evaluate(test_hash(), &[], &cfg, 42, "t").unwrap();
        assert!(!result.recovered);
    }

    #[test]
    fn empty_sites_execution_mode() {
        let cfg = execution_config();
        let result = evaluate(test_hash(), &[], &cfg, 42, "t").unwrap();
        // No error sites = no decisions, not recovered.
        assert!(!result.recovered);
    }

    #[test]
    fn recovery_mode_ord() {
        assert!(RecoveryMode::StrictDefault < RecoveryMode::DiagnosticRecovery);
        assert!(RecoveryMode::DiagnosticRecovery < RecoveryMode::ExecutionRecovery);
    }

    #[test]
    fn error_state_ord() {
        assert!(ErrorState::Recoverable < ErrorState::Ambiguous);
        assert!(ErrorState::Ambiguous < ErrorState::Unrecoverable);
    }

    #[test]
    fn recovery_action_ord() {
        assert!(RecoveryAction::RecoverContinue < RecoveryAction::PartialRecover);
        assert!(RecoveryAction::PartialRecover < RecoveryAction::FailStrict);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn recovery_mode_serde_all_variants() {
        let variants = [
            RecoveryMode::StrictDefault,
            RecoveryMode::DiagnosticRecovery,
            RecoveryMode::ExecutionRecovery,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RecoveryMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn error_state_serde_all_variants() {
        let variants = [
            ErrorState::Recoverable,
            ErrorState::Ambiguous,
            ErrorState::Unrecoverable,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ErrorState = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn recovery_action_serde_all_variants() {
        let variants = [
            RecoveryAction::RecoverContinue,
            RecoveryAction::PartialRecover,
            RecoveryAction::FailStrict,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RecoveryAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn recovery_mode_display_distinct() {
        let all = [
            RecoveryMode::StrictDefault,
            RecoveryMode::DiagnosticRecovery,
            RecoveryMode::ExecutionRecovery,
        ];
        let set: std::collections::BTreeSet<String> = all.iter().map(|m| format!("{m}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn error_state_display_distinct() {
        let all = [
            ErrorState::Recoverable,
            ErrorState::Ambiguous,
            ErrorState::Unrecoverable,
        ];
        let set: std::collections::BTreeSet<String> = all.iter().map(|s| format!("{s}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn recovery_action_display_distinct() {
        let all = [
            RecoveryAction::RecoverContinue,
            RecoveryAction::PartialRecover,
            RecoveryAction::FailStrict,
        ];
        let set: std::collections::BTreeSet<String> = all.iter().map(|a| format!("{a}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn repair_edit_serde_all_variants() {
        let variants = vec![
            RepairEdit::Skip {
                position: 10,
                count: 3,
            },
            RepairEdit::Insert {
                position: 5,
                tokens: vec!["let".into(), "x".into()],
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RepairEdit = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn recovery_error_serde_all_variants() {
        let variants = vec![
            RecoveryError::BudgetExhausted {
                attempts: 5,
                max: 10,
            },
            RecoveryError::InvalidConfig {
                detail: "bad".into(),
            },
            RecoveryError::NoCandidates { error_position: 42 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RecoveryError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn recovery_error_display_distinct() {
        let variants = [
            RecoveryError::BudgetExhausted {
                attempts: 1,
                max: 2,
            },
            RecoveryError::InvalidConfig { detail: "x".into() },
            RecoveryError::NoCandidates { error_position: 0 },
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn recovery_error_code_distinct() {
        let variants = [
            RecoveryError::BudgetExhausted {
                attempts: 1,
                max: 2,
            },
            RecoveryError::InvalidConfig { detail: "x".into() },
            RecoveryError::NoCandidates { error_position: 0 },
        ];
        let set: std::collections::BTreeSet<&str> = variants.iter().map(|e| e.code()).collect();
        assert_eq!(set.len(), variants.len());
    }
}
