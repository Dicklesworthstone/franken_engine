//! Bayesian syntax-error recovery controller with strict bounded attempts,
//! explicit confidence calibration, and execution-safe fallback semantics.
//!
//! ## Modes
//!
//! - **Strict**: default. Parse fails on any error (no recovery attempted).
//! - **Diagnostic**: recovery attempted, results reported but not used for execution.
//! - **Execution**: recovery used for execution if posterior confidence exceeds threshold.
//!
//! ## Architecture
//!
//! 1. **Evidence extraction**: extract features from the error site.
//! 2. **Posterior update**: Bayesian update from prior + evidence → posterior.
//! 3. **Loss-matrix evaluation**: expected loss for each action.
//! 4. **Decision**: select action with minimum expected loss.
//! 5. **Bounded execution**: apply recovery edits within attempt budget.
//! 6. **Parity check**: verify recovered output against oracle invariants.
//!
//! ## Related beads
//!
//! - bd-1gfn (this module)
//! - bd-3rjg (interference gate — upstream)
//! - bd-1b70 (parser oracle — related)

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "parser_error_recovery";

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.parser-error-recovery.v1";

/// Default maximum recovery attempts per file.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default maximum token skips per attempt.
pub const DEFAULT_MAX_TOKEN_SKIPS: u32 = 10;

/// Default maximum inserted-token edits per attempt.
pub const DEFAULT_MAX_INSERTIONS: u32 = 3;

/// Default posterior confidence threshold for execution mode (millionths).
pub const DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS: u64 = 800_000; // 80%

/// Default prior probability for recoverable state (millionths).
pub const DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS: u64 = 600_000; // 60%

/// Default prior probability for ambiguous state (millionths).
pub const DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS: u64 = 300_000; // 30%

/// Default prior probability for unrecoverable state (millionths).
pub const DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS: u64 = 100_000; // 10%

// ---------------------------------------------------------------------------
// Recovery mode
// ---------------------------------------------------------------------------

/// Recovery mode policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecoveryMode {
    /// No recovery — parse fails on error.
    Strict,
    /// Recovery attempted, results reported but not used for execution.
    Diagnostic,
    /// Recovery used for execution if confidence exceeds threshold.
    Execution,
}

impl fmt::Display for RecoveryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Diagnostic => write!(f, "diagnostic"),
            Self::Execution => write!(f, "execution"),
        }
    }
}

// ---------------------------------------------------------------------------
// Error state classification
// ---------------------------------------------------------------------------

/// Bayesian state of the syntax error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ErrorState {
    /// Local syntax defect, recoverable without semantic distortion.
    Recoverable,
    /// Multiple plausible repairs — ambiguous.
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

/// Action the recovery controller can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// Attempt full recovery and continue parsing.
    RecoverContinue,
    /// Partial recovery — skip error site and continue.
    PartialRecover,
    /// Strict failure — do not attempt recovery.
    FailStrict,
}

impl fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecoverContinue => write!(f, "recover-continue"),
            Self::PartialRecover => write!(f, "partial-recover"),
            Self::FailStrict => write!(f, "fail-strict"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence features
// ---------------------------------------------------------------------------

/// Evidence features extracted from the error site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFeatures {
    /// Number of tokens consumed before the error.
    pub tokens_before_error: u64,
    /// Number of tokens remaining after the error.
    pub tokens_after_error: u64,
    /// Error position (byte offset).
    pub error_offset: u64,
    /// Whether the error is at a statement boundary.
    pub at_statement_boundary: bool,
    /// Whether a single-token insertion could fix the error.
    pub single_token_fix: bool,
    /// Whether a single-token deletion could fix the error.
    pub single_token_delete: bool,
    /// Number of candidate repair alternatives.
    pub candidate_count: u32,
    /// Hash of the evidence features for determinism verification.
    pub features_hash: ContentHash,
}

impl EvidenceFeatures {
    /// Compute the features hash.
    pub fn with_hash(mut self) -> Self {
        let data = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.tokens_before_error,
            self.tokens_after_error,
            self.error_offset,
            self.at_statement_boundary,
            self.single_token_fix,
            self.single_token_delete,
            self.candidate_count
        );
        self.features_hash = ContentHash::compute(data.as_bytes());
        self
    }
}

// ---------------------------------------------------------------------------
// Prior and posterior
// ---------------------------------------------------------------------------

/// Prior/posterior probability distribution over error states (millionths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProbabilities {
    /// P(Recoverable) in millionths.
    pub recoverable: u64,
    /// P(Ambiguous) in millionths.
    pub ambiguous: u64,
    /// P(Unrecoverable) in millionths.
    pub unrecoverable: u64,
}

impl StateProbabilities {
    /// Validate that probabilities sum to 1_000_000.
    pub fn is_valid(&self) -> bool {
        self.recoverable + self.ambiguous + self.unrecoverable == 1_000_000
    }

    /// Return the most likely state.
    pub fn most_likely(&self) -> ErrorState {
        if self.recoverable >= self.ambiguous && self.recoverable >= self.unrecoverable {
            ErrorState::Recoverable
        } else if self.ambiguous >= self.unrecoverable {
            ErrorState::Ambiguous
        } else {
            ErrorState::Unrecoverable
        }
    }

    /// Return the confidence (probability) of the most likely state.
    pub fn confidence(&self) -> u64 {
        self.recoverable.max(self.ambiguous).max(self.unrecoverable)
    }
}

impl Default for StateProbabilities {
    fn default() -> Self {
        Self {
            recoverable: DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS,
            ambiguous: DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS,
            unrecoverable: DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS,
        }
    }
}

/// Bayesian update: compute posterior from prior + evidence.
///
/// Uses simple likelihood ratios based on evidence features:
/// - Statement boundary → increases P(recoverable)
/// - Single-token fix → increases P(recoverable)
/// - Multiple candidates → increases P(ambiguous)
/// - No candidates → increases P(unrecoverable)
pub fn bayesian_update(
    prior: &StateProbabilities,
    evidence: &EvidenceFeatures,
) -> StateProbabilities {
    // Likelihood multipliers (millionths, 1_000_000 = 1.0)
    let mut lr_recoverable = 1_000_000u64;
    let mut lr_ambiguous = 1_000_000u64;
    let mut lr_unrecoverable = 1_000_000u64;

    if evidence.at_statement_boundary {
        lr_recoverable = lr_recoverable.saturating_mul(1_500_000) / 1_000_000; // 1.5x
        lr_ambiguous = lr_ambiguous.saturating_mul(800_000) / 1_000_000; // 0.8x
        lr_unrecoverable = lr_unrecoverable.saturating_mul(600_000) / 1_000_000; // 0.6x
    }

    if evidence.single_token_fix {
        lr_recoverable = lr_recoverable.saturating_mul(2_000_000) / 1_000_000; // 2.0x
        lr_ambiguous = lr_ambiguous.saturating_mul(700_000) / 1_000_000; // 0.7x
        lr_unrecoverable = lr_unrecoverable.saturating_mul(300_000) / 1_000_000; // 0.3x
    }

    if evidence.single_token_delete {
        lr_recoverable = lr_recoverable.saturating_mul(1_800_000) / 1_000_000; // 1.8x
        lr_ambiguous = lr_ambiguous.saturating_mul(800_000) / 1_000_000; // 0.8x
        lr_unrecoverable = lr_unrecoverable.saturating_mul(400_000) / 1_000_000; // 0.4x
    }

    if evidence.candidate_count > 3 {
        lr_ambiguous = lr_ambiguous.saturating_mul(2_000_000) / 1_000_000; // 2.0x
        lr_recoverable = lr_recoverable.saturating_mul(600_000) / 1_000_000; // 0.6x
    } else if evidence.candidate_count == 0 {
        lr_unrecoverable = lr_unrecoverable.saturating_mul(3_000_000) / 1_000_000; // 3.0x
        lr_recoverable = lr_recoverable.saturating_mul(200_000) / 1_000_000; // 0.2x
    }

    // Unnormalized posterior.
    let raw_rec = prior.recoverable.saturating_mul(lr_recoverable);
    let raw_amb = prior.ambiguous.saturating_mul(lr_ambiguous);
    let raw_unrec = prior.unrecoverable.saturating_mul(lr_unrecoverable);

    let total = raw_rec.saturating_add(raw_amb).saturating_add(raw_unrec);
    if total == 0 {
        return StateProbabilities::default();
    }

    // Normalize to millionths.
    let rec = raw_rec
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_div(total))
        .unwrap_or(0);
    let amb = raw_amb
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_div(total))
        .unwrap_or(0);
    let unrec = 1_000_000u64.saturating_sub(rec).saturating_sub(amb);

    StateProbabilities {
        recoverable: rec,
        ambiguous: amb,
        unrecoverable: unrec,
    }
}

// ---------------------------------------------------------------------------
// Loss matrix
// ---------------------------------------------------------------------------

/// Loss matrix: expected cost of each action in each state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossMatrix {
    /// L(RecoverContinue, Recoverable)
    pub recover_recoverable: u64,
    /// L(RecoverContinue, Ambiguous)
    pub recover_ambiguous: u64,
    /// L(RecoverContinue, Unrecoverable)
    pub recover_unrecoverable: u64,
    /// L(PartialRecover, Recoverable)
    pub partial_recoverable: u64,
    /// L(PartialRecover, Ambiguous)
    pub partial_ambiguous: u64,
    /// L(PartialRecover, Unrecoverable)
    pub partial_unrecoverable: u64,
    /// L(FailStrict, Recoverable)
    pub fail_recoverable: u64,
    /// L(FailStrict, Ambiguous)
    pub fail_ambiguous: u64,
    /// L(FailStrict, Unrecoverable)
    pub fail_unrecoverable: u64,
}

impl Default for LossMatrix {
    fn default() -> Self {
        Self {
            recover_recoverable: 2,
            recover_ambiguous: 55,
            recover_unrecoverable: 90,
            partial_recoverable: 8,
            partial_ambiguous: 15,
            partial_unrecoverable: 30,
            fail_recoverable: 12,
            fail_ambiguous: 5,
            fail_unrecoverable: 1,
        }
    }
}

/// Compute expected loss for an action given state probabilities.
pub fn expected_loss(
    action: RecoveryAction,
    posterior: &StateProbabilities,
    matrix: &LossMatrix,
) -> u64 {
    let (l_rec, l_amb, l_unrec) = match action {
        RecoveryAction::RecoverContinue => (
            matrix.recover_recoverable,
            matrix.recover_ambiguous,
            matrix.recover_unrecoverable,
        ),
        RecoveryAction::PartialRecover => (
            matrix.partial_recoverable,
            matrix.partial_ambiguous,
            matrix.partial_unrecoverable,
        ),
        RecoveryAction::FailStrict => (
            matrix.fail_recoverable,
            matrix.fail_ambiguous,
            matrix.fail_unrecoverable,
        ),
    };

    // Expected loss = sum(P(state) * L(action, state)) / 1_000_000
    let raw = posterior
        .recoverable
        .saturating_mul(l_rec)
        .saturating_add(posterior.ambiguous.saturating_mul(l_amb))
        .saturating_add(posterior.unrecoverable.saturating_mul(l_unrec));

    raw.checked_div(1_000_000).unwrap_or(0)
}

/// Select the action with minimum expected loss.
pub fn select_action(posterior: &StateProbabilities, matrix: &LossMatrix) -> RecoveryAction {
    let el_recover = expected_loss(RecoveryAction::RecoverContinue, posterior, matrix);
    let el_partial = expected_loss(RecoveryAction::PartialRecover, posterior, matrix);
    let el_fail = expected_loss(RecoveryAction::FailStrict, posterior, matrix);

    if el_recover <= el_partial && el_recover <= el_fail {
        RecoveryAction::RecoverContinue
    } else if el_partial <= el_fail {
        RecoveryAction::PartialRecover
    } else {
        RecoveryAction::FailStrict
    }
}

// ---------------------------------------------------------------------------
// Recovery configuration
// ---------------------------------------------------------------------------

/// Configuration for the error recovery controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Recovery mode.
    pub mode: RecoveryMode,
    /// Maximum recovery attempts per file.
    pub max_attempts: u32,
    /// Maximum token skips per attempt.
    pub max_token_skips: u32,
    /// Maximum inserted-token edits per attempt.
    pub max_insertions: u32,
    /// Posterior confidence threshold for execution mode (millionths).
    pub confidence_threshold_millionths: u64,
    /// Prior probability distribution.
    pub prior: StateProbabilities,
    /// Loss matrix.
    pub loss_matrix: LossMatrix,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            mode: RecoveryMode::Strict,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            max_token_skips: DEFAULT_MAX_TOKEN_SKIPS,
            max_insertions: DEFAULT_MAX_INSERTIONS,
            confidence_threshold_millionths: DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS,
            prior: StateProbabilities::default(),
            loss_matrix: LossMatrix::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Repair edit
// ---------------------------------------------------------------------------

/// A single repair edit applied during recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairEdit {
    /// Insert a token at the given offset.
    Insert { offset: u64, token_text: String },
    /// Delete a token at the given offset.
    Delete { offset: u64, length: u64 },
    /// Replace a token at the given offset.
    Replace {
        offset: u64,
        length: u64,
        replacement: String,
    },
    /// Skip tokens starting at offset.
    Skip { offset: u64, count: u32 },
}

impl fmt::Display for RepairEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insert { offset, token_text } => {
                write!(f, "insert '{}' at {}", token_text, offset)
            }
            Self::Delete { offset, length } => write!(f, "delete {}B at {}", length, offset),
            Self::Replace {
                offset,
                length,
                replacement,
            } => {
                write!(
                    f,
                    "replace {}B at {} with '{}'",
                    length, offset, replacement
                )
            }
            Self::Skip { offset, count } => write!(f, "skip {} tokens at {}", count, offset),
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery attempt
// ---------------------------------------------------------------------------

/// Record of a single recovery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAttempt {
    /// Attempt index (0-based).
    pub attempt_index: u32,
    /// Evidence features at the error site.
    pub evidence: EvidenceFeatures,
    /// Prior probabilities.
    pub prior: StateProbabilities,
    /// Posterior probabilities after Bayesian update.
    pub posterior: StateProbabilities,
    /// Selected action.
    pub action: RecoveryAction,
    /// Expected losses for each action.
    pub expected_losses: ExpectedLosses,
    /// Rejected alternative actions with their expected losses.
    pub rejected_actions: Vec<(RecoveryAction, u64)>,
    /// Repair edits applied (if any).
    pub edits: Vec<RepairEdit>,
    /// Whether the attempt succeeded.
    pub succeeded: bool,
    /// Confidence of the selected action.
    pub confidence_millionths: u64,
}

/// Expected losses for all three actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedLosses {
    pub recover_continue: u64,
    pub partial_recover: u64,
    pub fail_strict: u64,
}

// ---------------------------------------------------------------------------
// Decision ledger
// ---------------------------------------------------------------------------

/// Full decision ledger for a recovery session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionLedger {
    /// Schema version.
    pub schema_version: String,
    /// Input hash.
    pub input_hash: ContentHash,
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Recovery mode used.
    pub mode: RecoveryMode,
    /// All recovery attempts.
    pub attempts: Vec<RecoveryAttempt>,
    /// Final outcome.
    pub outcome: RecoveryOutcome,
    /// Total repair edits applied.
    pub total_edits: u64,
    /// Whether parity was checked post-recovery.
    pub parity_checked: bool,
    /// Parity result (if checked).
    pub parity_ok: Option<bool>,
    /// Repair diff hash (for audit).
    pub repair_diff_hash: Option<ContentHash>,
}

/// Outcome of the recovery session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecoveryOutcome {
    /// No errors found — clean parse.
    CleanParse,
    /// Errors found and successfully recovered.
    Recovered,
    /// Errors found, partial recovery applied.
    PartiallyRecovered,
    /// Errors found, recovery not attempted (strict mode).
    StrictFailed,
    /// Recovery attempted but failed.
    RecoveryFailed,
    /// Budget exhausted.
    BudgetExhausted,
}

impl fmt::Display for RecoveryOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CleanParse => write!(f, "clean-parse"),
            Self::Recovered => write!(f, "recovered"),
            Self::PartiallyRecovered => write!(f, "partially-recovered"),
            Self::StrictFailed => write!(f, "strict-failed"),
            Self::RecoveryFailed => write!(f, "recovery-failed"),
            Self::BudgetExhausted => write!(f, "budget-exhausted"),
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery controller
// ---------------------------------------------------------------------------

/// Syntax-error description for the recovery controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntaxError {
    /// Error position (byte offset).
    pub offset: u64,
    /// Error message.
    pub message: String,
    /// Tokens consumed before the error.
    pub tokens_before: u64,
    /// Tokens remaining after the error.
    pub tokens_after: u64,
    /// Whether at a statement boundary.
    pub at_statement_boundary: bool,
    /// Candidate repair tokens.
    pub candidates: Vec<String>,
}

/// Run the recovery controller on a list of syntax errors.
pub fn run_recovery(
    errors: &[SyntaxError],
    input_bytes: u64,
    config: &RecoveryConfig,
) -> DecisionLedger {
    let input_hash = ContentHash::compute(&input_bytes.to_le_bytes());

    // Clean parse — no errors.
    if errors.is_empty() {
        return DecisionLedger {
            schema_version: SCHEMA_VERSION.to_string(),
            input_hash,
            input_bytes,
            mode: config.mode,
            attempts: Vec::new(),
            outcome: RecoveryOutcome::CleanParse,
            total_edits: 0,
            parity_checked: false,
            parity_ok: None,
            repair_diff_hash: None,
        };
    }

    // Strict mode — no recovery.
    if config.mode == RecoveryMode::Strict {
        return DecisionLedger {
            schema_version: SCHEMA_VERSION.to_string(),
            input_hash,
            input_bytes,
            mode: config.mode,
            attempts: Vec::new(),
            outcome: RecoveryOutcome::StrictFailed,
            total_edits: 0,
            parity_checked: false,
            parity_ok: None,
            repair_diff_hash: None,
        };
    }

    let mut attempts = Vec::new();
    let mut total_edits = 0u64;
    let mut all_succeeded = true;
    let mut any_succeeded = false;

    for (idx, error) in errors.iter().enumerate() {
        if idx as u32 >= config.max_attempts {
            return DecisionLedger {
                schema_version: SCHEMA_VERSION.to_string(),
                input_hash,
                input_bytes,
                mode: config.mode,
                attempts,
                outcome: RecoveryOutcome::BudgetExhausted,
                total_edits,
                parity_checked: false,
                parity_ok: None,
                repair_diff_hash: None,
            };
        }

        let evidence = extract_evidence(error);
        let posterior = bayesian_update(&config.prior, &evidence);
        let action = select_action(&posterior, &config.loss_matrix);

        let el_recover = expected_loss(
            RecoveryAction::RecoverContinue,
            &posterior,
            &config.loss_matrix,
        );
        let el_partial = expected_loss(
            RecoveryAction::PartialRecover,
            &posterior,
            &config.loss_matrix,
        );
        let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &config.loss_matrix);

        let expected_losses = ExpectedLosses {
            recover_continue: el_recover,
            partial_recover: el_partial,
            fail_strict: el_fail,
        };

        // Build rejected actions list.
        let mut rejected = Vec::new();
        let all_actions = [
            RecoveryAction::RecoverContinue,
            RecoveryAction::PartialRecover,
            RecoveryAction::FailStrict,
        ];
        for &a in &all_actions {
            if a != action {
                rejected.push((a, expected_loss(a, &posterior, &config.loss_matrix)));
            }
        }

        // Execution mode gate: if confidence is below threshold, force strict fail.
        let effective_action = if config.mode == RecoveryMode::Execution
            && posterior.confidence() < config.confidence_threshold_millionths
            && action != RecoveryAction::FailStrict
        {
            RecoveryAction::FailStrict
        } else {
            action
        };

        let (edits, succeeded) = apply_action(effective_action, error, config);
        let edit_count = edits.len() as u64;
        total_edits += edit_count;

        if succeeded {
            any_succeeded = true;
        } else {
            all_succeeded = false;
        }

        attempts.push(RecoveryAttempt {
            attempt_index: idx as u32,
            evidence,
            prior: config.prior.clone(),
            posterior: posterior.clone(),
            action: effective_action,
            expected_losses,
            rejected_actions: rejected,
            edits,
            succeeded,
            confidence_millionths: posterior.confidence(),
        });
    }

    let outcome = if all_succeeded && any_succeeded {
        RecoveryOutcome::Recovered
    } else if any_succeeded {
        RecoveryOutcome::PartiallyRecovered
    } else {
        RecoveryOutcome::RecoveryFailed
    };

    let repair_diff_hash = if total_edits > 0 {
        let diff_data = format!("edits:{}", total_edits);
        Some(ContentHash::compute(diff_data.as_bytes()))
    } else {
        None
    };

    DecisionLedger {
        schema_version: SCHEMA_VERSION.to_string(),
        input_hash,
        input_bytes,
        mode: config.mode,
        attempts,
        outcome,
        total_edits,
        parity_checked: false,
        parity_ok: None,
        repair_diff_hash,
    }
}

/// Extract evidence features from a syntax error.
fn extract_evidence(error: &SyntaxError) -> EvidenceFeatures {
    let single_token_fix = error.candidates.len() == 1;
    let single_token_delete = error.tokens_after > 0;

    EvidenceFeatures {
        tokens_before_error: error.tokens_before,
        tokens_after_error: error.tokens_after,
        error_offset: error.offset,
        at_statement_boundary: error.at_statement_boundary,
        single_token_fix,
        single_token_delete,
        candidate_count: error.candidates.len() as u32,
        features_hash: ContentHash::compute(b"placeholder"),
    }
    .with_hash()
}

/// Apply a recovery action to generate repair edits.
fn apply_action(
    action: RecoveryAction,
    error: &SyntaxError,
    config: &RecoveryConfig,
) -> (Vec<RepairEdit>, bool) {
    match action {
        RecoveryAction::FailStrict => (Vec::new(), false),
        RecoveryAction::RecoverContinue => {
            if let Some(candidate) = error.candidates.first() {
                let edits = vec![RepairEdit::Insert {
                    offset: error.offset,
                    token_text: candidate.clone(),
                }];
                (edits, true)
            } else {
                (Vec::new(), false)
            }
        }
        RecoveryAction::PartialRecover => {
            let skip_count = 1u32.min(config.max_token_skips);
            let edits = vec![RepairEdit::Skip {
                offset: error.offset,
                count: skip_count,
            }];
            (edits, true)
        }
    }
}

// ---------------------------------------------------------------------------
// Calibration report
// ---------------------------------------------------------------------------

/// Calibration report: false-positive/false-negative frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationReport {
    /// Schema version.
    pub schema_version: String,
    /// Total test cases.
    pub total_cases: u64,
    /// True positives (correctly recovered).
    pub true_positives: u64,
    /// False positives (incorrectly recovered — semantic distortion).
    pub false_positives: u64,
    /// True negatives (correctly refused recovery).
    pub true_negatives: u64,
    /// False negatives (missed valid recovery).
    pub false_negatives: u64,
    /// False-positive rate (millionths).
    pub false_positive_rate_millionths: u64,
    /// False-negative rate (millionths).
    pub false_negative_rate_millionths: u64,
    /// Confidence threshold used.
    pub confidence_threshold_millionths: u64,
    /// Operating point identifier.
    pub operating_point_id: String,
}

impl CalibrationReport {
    /// Compute calibration metrics from raw counts.
    pub fn compute(
        true_positives: u64,
        false_positives: u64,
        true_negatives: u64,
        false_negatives: u64,
        confidence_threshold_millionths: u64,
    ) -> Self {
        let total_cases = true_positives + false_positives + true_negatives + false_negatives;
        let actual_negatives = false_positives + true_negatives;
        let actual_positives = true_positives + false_negatives;

        let fpr = if actual_negatives > 0 {
            false_positives
                .checked_mul(1_000_000)
                .and_then(|n| n.checked_div(actual_negatives))
                .unwrap_or(0)
        } else {
            0
        };

        let fnr = if actual_positives > 0 {
            false_negatives
                .checked_mul(1_000_000)
                .and_then(|n| n.checked_div(actual_positives))
                .unwrap_or(0)
        } else {
            0
        };

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            total_cases,
            true_positives,
            false_positives,
            true_negatives,
            false_negatives,
            false_positive_rate_millionths: fpr,
            false_negative_rate_millionths: fnr,
            confidence_threshold_millionths,
            operating_point_id: format!("threshold-{}", confidence_threshold_millionths),
        }
    }
}

// ---------------------------------------------------------------------------
// Mode policy table
// ---------------------------------------------------------------------------

/// Mode policy entry: defines boundaries for each recovery mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModePolicyEntry {
    /// Recovery mode.
    pub mode: RecoveryMode,
    /// Description.
    pub description: String,
    /// Whether recovery edits are applied to output.
    pub edits_applied: bool,
    /// Whether execution uses recovered output.
    pub execution_uses_recovery: bool,
    /// Minimum confidence for this mode (millionths).
    pub min_confidence_millionths: u64,
    /// Maximum false-positive rate allowed (millionths).
    pub max_fpr_millionths: u64,
}

/// Build the canonical mode policy table.
pub fn mode_policy_table() -> Vec<ModePolicyEntry> {
    vec![
        ModePolicyEntry {
            mode: RecoveryMode::Strict,
            description: "No recovery. Parse fails on any error.".to_string(),
            edits_applied: false,
            execution_uses_recovery: false,
            min_confidence_millionths: 0,
            max_fpr_millionths: 0,
        },
        ModePolicyEntry {
            mode: RecoveryMode::Diagnostic,
            description: "Recovery attempted for reporting only.".to_string(),
            edits_applied: true,
            execution_uses_recovery: false,
            min_confidence_millionths: 0,
            max_fpr_millionths: 1_000_000, // no limit for diagnostics
        },
        ModePolicyEntry {
            mode: RecoveryMode::Execution,
            description: "Recovery used for execution if confidence exceeds threshold.".to_string(),
            edits_applied: true,
            execution_uses_recovery: true,
            min_confidence_millionths: DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS,
            max_fpr_millionths: 20_000, // 2% max FPR
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_error() -> SyntaxError {
        SyntaxError {
            offset: 10,
            message: "expected ';'".to_string(),
            tokens_before: 5,
            tokens_after: 20,
            at_statement_boundary: true,
            candidates: vec![";".to_string()],
        }
    }

    fn simple_evidence() -> EvidenceFeatures {
        EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: false,
            candidate_count: 1,
            features_hash: ContentHash::compute(b"simple-evidence"),
        }
    }

    fn ambiguous_error() -> SyntaxError {
        SyntaxError {
            offset: 25,
            message: "unexpected token".to_string(),
            tokens_before: 10,
            tokens_after: 15,
            at_statement_boundary: false,
            candidates: vec![
                ";".to_string(),
                ")".to_string(),
                "}".to_string(),
                ",".to_string(),
            ],
        }
    }

    fn unrecoverable_error() -> SyntaxError {
        SyntaxError {
            offset: 50,
            message: "completely garbled".to_string(),
            tokens_before: 2,
            tokens_after: 0,
            at_statement_boundary: false,
            candidates: vec![],
        }
    }

    fn diagnostic_config() -> RecoveryConfig {
        RecoveryConfig {
            mode: RecoveryMode::Diagnostic,
            ..RecoveryConfig::default()
        }
    }

    // --- Mode tests ---

    #[test]
    fn recovery_mode_display() {
        assert_eq!(RecoveryMode::Strict.to_string(), "strict");
        assert_eq!(RecoveryMode::Diagnostic.to_string(), "diagnostic");
        assert_eq!(RecoveryMode::Execution.to_string(), "execution");
    }

    #[test]
    fn recovery_mode_ordering() {
        assert!(RecoveryMode::Strict < RecoveryMode::Diagnostic);
        assert!(RecoveryMode::Diagnostic < RecoveryMode::Execution);
    }

    // --- Error state tests ---

    #[test]
    fn error_state_display() {
        assert_eq!(ErrorState::Recoverable.to_string(), "recoverable");
        assert_eq!(ErrorState::Ambiguous.to_string(), "ambiguous");
        assert_eq!(ErrorState::Unrecoverable.to_string(), "unrecoverable");
    }

    // --- Action tests ---

    #[test]
    fn recovery_action_display() {
        assert_eq!(
            RecoveryAction::RecoverContinue.to_string(),
            "recover-continue"
        );
        assert_eq!(
            RecoveryAction::PartialRecover.to_string(),
            "partial-recover"
        );
        assert_eq!(RecoveryAction::FailStrict.to_string(), "fail-strict");
    }

    // --- Evidence tests ---

    #[test]
    fn evidence_features_hash_deterministic() {
        let e1 = EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: true,
            candidate_count: 1,
            features_hash: ContentHash::compute(b"placeholder"),
        }
        .with_hash();
        let e2 = EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: true,
            candidate_count: 1,
            features_hash: ContentHash::compute(b"placeholder"),
        }
        .with_hash();
        assert_eq!(e1.features_hash, e2.features_hash);
    }

    #[test]
    fn evidence_features_serde_roundtrip() {
        let e = EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: false,
            candidate_count: 2,
            features_hash: ContentHash::compute(b"test"),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: EvidenceFeatures = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Prior/posterior tests ---

    #[test]
    fn default_prior_sums_to_one() {
        let prior = StateProbabilities::default();
        assert!(prior.is_valid());
    }

    #[test]
    fn prior_most_likely_recoverable() {
        let prior = StateProbabilities::default();
        assert_eq!(prior.most_likely(), ErrorState::Recoverable);
    }

    #[test]
    fn prior_confidence() {
        let prior = StateProbabilities::default();
        assert_eq!(prior.confidence(), DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS);
    }

    #[test]
    fn bayesian_update_single_token_fix_increases_recoverable() {
        let prior = StateProbabilities::default();
        let evidence = EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: true,
            candidate_count: 1,
            features_hash: ContentHash::compute(b"test"),
        };
        let posterior = bayesian_update(&prior, &evidence);
        assert!(posterior.recoverable > prior.recoverable);
    }

    #[test]
    fn bayesian_update_no_candidates_increases_unrecoverable() {
        let prior = StateProbabilities::default();
        let evidence = EvidenceFeatures {
            tokens_before_error: 2,
            tokens_after_error: 0,
            error_offset: 50,
            at_statement_boundary: false,
            single_token_fix: false,
            single_token_delete: false,
            candidate_count: 0,
            features_hash: ContentHash::compute(b"test"),
        };
        let posterior = bayesian_update(&prior, &evidence);
        assert!(posterior.unrecoverable > prior.unrecoverable);
    }

    #[test]
    fn bayesian_update_many_candidates_increases_ambiguous() {
        let prior = StateProbabilities::default();
        let evidence = EvidenceFeatures {
            tokens_before_error: 10,
            tokens_after_error: 15,
            error_offset: 25,
            at_statement_boundary: false,
            single_token_fix: false,
            single_token_delete: true,
            candidate_count: 5,
            features_hash: ContentHash::compute(b"test"),
        };
        let posterior = bayesian_update(&prior, &evidence);
        assert!(posterior.ambiguous > prior.ambiguous);
    }

    #[test]
    fn bayesian_update_preserves_normalization() {
        let prior = StateProbabilities::default();
        let evidence = EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: false,
            candidate_count: 1,
            features_hash: ContentHash::compute(b"test"),
        };
        let posterior = bayesian_update(&prior, &evidence);
        let total = posterior.recoverable + posterior.ambiguous + posterior.unrecoverable;
        // Allow ±1 for rounding.
        assert!((999_999..=1_000_001).contains(&total));
    }

    #[test]
    fn bayesian_update_deterministic() {
        let prior = StateProbabilities::default();
        let evidence = extract_evidence(&simple_error());
        let p1 = bayesian_update(&prior, &evidence);
        let p2 = bayesian_update(&prior, &evidence);
        assert_eq!(p1, p2);
    }

    // --- Loss matrix tests ---

    #[test]
    fn loss_matrix_default() {
        let m = LossMatrix::default();
        assert_eq!(m.recover_unrecoverable, 90);
        assert_eq!(m.fail_unrecoverable, 1);
    }

    #[test]
    fn loss_matrix_serde_roundtrip() {
        let m = LossMatrix::default();
        let json = serde_json::to_string(&m).unwrap();
        let back: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn expected_loss_recoverable_state_favors_recover() {
        let posterior = StateProbabilities {
            recoverable: 900_000,
            ambiguous: 50_000,
            unrecoverable: 50_000,
        };
        let matrix = LossMatrix::default();
        let el_recover = expected_loss(RecoveryAction::RecoverContinue, &posterior, &matrix);
        let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &matrix);
        assert!(el_recover < el_fail);
    }

    #[test]
    fn expected_loss_unrecoverable_state_favors_fail() {
        let posterior = StateProbabilities {
            recoverable: 50_000,
            ambiguous: 50_000,
            unrecoverable: 900_000,
        };
        let matrix = LossMatrix::default();
        let el_recover = expected_loss(RecoveryAction::RecoverContinue, &posterior, &matrix);
        let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &matrix);
        assert!(el_fail < el_recover);
    }

    #[test]
    fn select_action_recoverable() {
        let posterior = StateProbabilities {
            recoverable: 900_000,
            ambiguous: 50_000,
            unrecoverable: 50_000,
        };
        let matrix = LossMatrix::default();
        let action = select_action(&posterior, &matrix);
        assert_eq!(action, RecoveryAction::RecoverContinue);
    }

    #[test]
    fn select_action_unrecoverable() {
        let posterior = StateProbabilities {
            recoverable: 50_000,
            ambiguous: 50_000,
            unrecoverable: 900_000,
        };
        let matrix = LossMatrix::default();
        let action = select_action(&posterior, &matrix);
        assert_eq!(action, RecoveryAction::FailStrict);
    }

    #[test]
    fn select_action_ambiguous() {
        let posterior = StateProbabilities {
            recoverable: 100_000,
            ambiguous: 800_000,
            unrecoverable: 100_000,
        };
        let matrix = LossMatrix::default();
        let action = select_action(&posterior, &matrix);
        // With default loss matrix, high ambiguity favors FailStrict (lowest expected loss).
        assert_eq!(action, RecoveryAction::FailStrict);
    }

    // --- Config tests ---

    #[test]
    fn config_default() {
        let config = RecoveryConfig::default();
        assert_eq!(config.mode, RecoveryMode::Strict);
        assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert!(config.prior.is_valid());
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = RecoveryConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: RecoveryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- Repair edit tests ---

    #[test]
    fn repair_edit_display() {
        let insert = RepairEdit::Insert {
            offset: 10,
            token_text: ";".to_string(),
        };
        assert!(insert.to_string().contains("insert ';' at 10"));
        let delete = RepairEdit::Delete {
            offset: 5,
            length: 3,
        };
        assert!(delete.to_string().contains("delete 3B at 5"));
        let skip = RepairEdit::Skip {
            offset: 20,
            count: 2,
        };
        assert!(skip.to_string().contains("skip 2 tokens at 20"));
    }

    #[test]
    fn repair_edit_serde_roundtrip() {
        let edit = RepairEdit::Replace {
            offset: 10,
            length: 5,
            replacement: "var".to_string(),
        };
        let json = serde_json::to_string(&edit).unwrap();
        let back: RepairEdit = serde_json::from_str(&json).unwrap();
        assert_eq!(edit, back);
    }

    // --- Outcome tests ---

    #[test]
    fn outcome_display() {
        assert_eq!(RecoveryOutcome::CleanParse.to_string(), "clean-parse");
        assert_eq!(RecoveryOutcome::Recovered.to_string(), "recovered");
        assert_eq!(RecoveryOutcome::StrictFailed.to_string(), "strict-failed");
        assert_eq!(
            RecoveryOutcome::BudgetExhausted.to_string(),
            "budget-exhausted"
        );
    }

    // --- Run recovery tests ---

    #[test]
    fn run_recovery_no_errors() {
        let config = diagnostic_config();
        let ledger = run_recovery(&[], 100, &config);
        assert_eq!(ledger.outcome, RecoveryOutcome::CleanParse);
        assert!(ledger.attempts.is_empty());
    }

    #[test]
    fn run_recovery_strict_mode() {
        let config = RecoveryConfig::default(); // strict
        let errors = [simple_error()];
        let ledger = run_recovery(&errors, 100, &config);
        assert_eq!(ledger.outcome, RecoveryOutcome::StrictFailed);
        assert!(ledger.attempts.is_empty());
    }

    #[test]
    fn run_recovery_diagnostic_simple_error() {
        let config = diagnostic_config();
        let errors = [simple_error()];
        let ledger = run_recovery(&errors, 100, &config);
        assert_eq!(ledger.outcome, RecoveryOutcome::Recovered);
        assert_eq!(ledger.attempts.len(), 1);
        assert!(ledger.attempts[0].succeeded);
        assert!(ledger.total_edits > 0);
    }

    #[test]
    fn run_recovery_diagnostic_unrecoverable() {
        let config = diagnostic_config();
        let errors = [unrecoverable_error()];
        let ledger = run_recovery(&errors, 100, &config);
        // Should fail strict due to no candidates.
        assert!(!ledger.attempts.is_empty());
    }

    #[test]
    fn run_recovery_diagnostic_ambiguous() {
        let config = diagnostic_config();
        let errors = [ambiguous_error()];
        let ledger = run_recovery(&errors, 100, &config);
        assert_eq!(ledger.attempts.len(), 1);
    }

    #[test]
    fn run_recovery_budget_exhaustion() {
        let config = RecoveryConfig {
            mode: RecoveryMode::Diagnostic,
            max_attempts: 2,
            ..RecoveryConfig::default()
        };
        let errors = [simple_error(), simple_error(), simple_error()];
        let ledger = run_recovery(&errors, 100, &config);
        assert_eq!(ledger.outcome, RecoveryOutcome::BudgetExhausted);
        assert_eq!(ledger.attempts.len(), 2);
    }

    #[test]
    fn run_recovery_execution_mode_confidence_gate() {
        let config = RecoveryConfig {
            mode: RecoveryMode::Execution,
            confidence_threshold_millionths: 999_000, // very high threshold
            ..RecoveryConfig::default()
        };
        let errors = [ambiguous_error()];
        let ledger = run_recovery(&errors, 100, &config);
        // High threshold should force strict fail for ambiguous.
        assert!(!ledger.attempts.is_empty());
        // The action should be fail-strict due to confidence gate.
        assert_eq!(ledger.attempts[0].action, RecoveryAction::FailStrict);
    }

    #[test]
    fn run_recovery_deterministic() {
        let config = diagnostic_config();
        let errors = [simple_error()];
        let l1 = run_recovery(&errors, 100, &config);
        let l2 = run_recovery(&errors, 100, &config);
        assert_eq!(l1.outcome, l2.outcome);
        assert_eq!(l1.total_edits, l2.total_edits);
    }

    #[test]
    fn run_recovery_repair_diff_hash_present() {
        let config = diagnostic_config();
        let errors = [simple_error()];
        let ledger = run_recovery(&errors, 100, &config);
        assert!(ledger.repair_diff_hash.is_some());
    }

    #[test]
    fn run_recovery_multiple_errors_mixed() {
        let config = diagnostic_config();
        let errors = [simple_error(), ambiguous_error(), unrecoverable_error()];
        let ledger = run_recovery(&errors, 100, &config);
        assert_eq!(ledger.attempts.len(), 3);
        assert!(ledger.total_edits > 0);
    }

    #[test]
    fn decision_ledger_serde_roundtrip() {
        let config = diagnostic_config();
        let errors = [simple_error()];
        let ledger = run_recovery(&errors, 100, &config);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: DecisionLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    #[test]
    fn decision_ledger_schema_version() {
        let config = diagnostic_config();
        let ledger = run_recovery(&[], 100, &config);
        assert_eq!(ledger.schema_version, SCHEMA_VERSION);
    }

    // --- Calibration report tests ---

    #[test]
    fn calibration_report_compute() {
        let report = CalibrationReport::compute(90, 2, 95, 8, 800_000);
        assert_eq!(report.total_cases, 195);
        assert_eq!(report.true_positives, 90);
        assert!(report.false_positive_rate_millionths > 0);
    }

    #[test]
    fn calibration_report_zero_positives() {
        let report = CalibrationReport::compute(0, 0, 100, 0, 800_000);
        assert_eq!(report.false_positive_rate_millionths, 0);
    }

    #[test]
    fn calibration_report_serde_roundtrip() {
        let report = CalibrationReport::compute(80, 5, 90, 10, 800_000);
        let json = serde_json::to_string(&report).unwrap();
        let back: CalibrationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // --- Mode policy table tests ---

    #[test]
    fn mode_policy_table_has_three_entries() {
        let table = mode_policy_table();
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn mode_policy_strict_no_edits() {
        let table = mode_policy_table();
        let strict = table
            .iter()
            .find(|e| e.mode == RecoveryMode::Strict)
            .unwrap();
        assert!(!strict.edits_applied);
        assert!(!strict.execution_uses_recovery);
    }

    #[test]
    fn mode_policy_execution_has_safety_boundary() {
        let table = mode_policy_table();
        let exec = table
            .iter()
            .find(|e| e.mode == RecoveryMode::Execution)
            .unwrap();
        assert!(exec.execution_uses_recovery);
        assert!(exec.min_confidence_millionths > 0);
        assert!(exec.max_fpr_millionths <= 20_000); // 2%
    }

    #[test]
    fn mode_policy_serde_roundtrip() {
        let table = mode_policy_table();
        let json = serde_json::to_string(&table).unwrap();
        let back: Vec<ModePolicyEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(table, back);
    }

    // --- Attempt detail tests ---

    #[test]
    fn attempt_has_rejected_actions() {
        let config = diagnostic_config();
        let errors = [simple_error()];
        let ledger = run_recovery(&errors, 100, &config);
        assert_eq!(ledger.attempts[0].rejected_actions.len(), 2);
    }

    #[test]
    fn attempt_expected_losses_consistent() {
        let config = diagnostic_config();
        let errors = [simple_error()];
        let ledger = run_recovery(&errors, 100, &config);
        let attempt = &ledger.attempts[0];
        // The selected action should have the minimum expected loss.
        let selected_loss = match attempt.action {
            RecoveryAction::RecoverContinue => attempt.expected_losses.recover_continue,
            RecoveryAction::PartialRecover => attempt.expected_losses.partial_recover,
            RecoveryAction::FailStrict => attempt.expected_losses.fail_strict,
        };
        for (_, loss) in &attempt.rejected_actions {
            assert!(selected_loss <= *loss);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_mode_serde_roundtrip() {
        for mode in [
            RecoveryMode::Strict,
            RecoveryMode::Diagnostic,
            RecoveryMode::Execution,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: RecoveryMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn error_state_serde_roundtrip() {
        for state in [
            ErrorState::Recoverable,
            ErrorState::Ambiguous,
            ErrorState::Unrecoverable,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: ErrorState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn recovery_action_display_uniqueness_btreeset() {
        let actions = [
            RecoveryAction::RecoverContinue,
            RecoveryAction::PartialRecover,
            RecoveryAction::FailStrict,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for a in &actions {
            displays.insert(a.to_string());
        }
        assert_eq!(
            displays.len(),
            3,
            "all RecoveryAction variants produce distinct Display strings"
        );
    }

    #[test]
    fn recovery_outcome_display_uniqueness_btreeset() {
        let outcomes = [
            RecoveryOutcome::CleanParse,
            RecoveryOutcome::Recovered,
            RecoveryOutcome::PartiallyRecovered,
            RecoveryOutcome::StrictFailed,
            RecoveryOutcome::RecoveryFailed,
            RecoveryOutcome::BudgetExhausted,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for o in &outcomes {
            displays.insert(o.to_string());
        }
        assert_eq!(
            displays.len(),
            6,
            "all RecoveryOutcome variants produce distinct Display strings"
        );
    }

    #[test]
    fn state_probabilities_default_is_valid() {
        let sp = StateProbabilities::default();
        assert!(sp.is_valid(), "default probabilities must sum to 1_000_000");
        assert_eq!(sp.recoverable, DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS);
    }

    #[test]
    fn state_probabilities_most_likely_for_each_extreme() {
        let rec = StateProbabilities {
            recoverable: 800_000,
            ambiguous: 100_000,
            unrecoverable: 100_000,
        };
        assert_eq!(rec.most_likely(), ErrorState::Recoverable);

        let amb = StateProbabilities {
            recoverable: 100_000,
            ambiguous: 800_000,
            unrecoverable: 100_000,
        };
        assert_eq!(amb.most_likely(), ErrorState::Ambiguous);

        let unrec = StateProbabilities {
            recoverable: 100_000,
            ambiguous: 100_000,
            unrecoverable: 800_000,
        };
        assert_eq!(unrec.most_likely(), ErrorState::Unrecoverable);
    }

    #[test]
    fn syntax_error_serde_roundtrip() {
        let err = simple_error();
        let json = serde_json::to_string(&err).unwrap();
        let back: SyntaxError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn recovery_config_serde_roundtrip() {
        let config = RecoveryConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: RecoveryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // ── Enrichment: Copy semantics ──────────────────────────────────

    #[test]
    fn recovery_mode_copy_from_array() {
        let arr = [
            RecoveryMode::Strict,
            RecoveryMode::Diagnostic,
            RecoveryMode::Execution,
        ];
        let copied = arr[1];
        assert_eq!(copied, RecoveryMode::Diagnostic);
        assert_eq!(arr[1], RecoveryMode::Diagnostic);
    }

    #[test]
    fn error_state_copy_from_array() {
        let arr = [
            ErrorState::Recoverable,
            ErrorState::Ambiguous,
            ErrorState::Unrecoverable,
        ];
        let copied = arr[2];
        assert_eq!(copied, ErrorState::Unrecoverable);
        assert_eq!(arr[2], ErrorState::Unrecoverable);
    }

    #[test]
    fn recovery_action_copy_from_array() {
        let arr = [
            RecoveryAction::RecoverContinue,
            RecoveryAction::PartialRecover,
            RecoveryAction::FailStrict,
        ];
        let copied = arr[0];
        assert_eq!(copied, RecoveryAction::RecoverContinue);
        assert_eq!(arr[0], RecoveryAction::RecoverContinue);
    }

    #[test]
    fn recovery_outcome_copy_from_array() {
        let arr = [
            RecoveryOutcome::CleanParse,
            RecoveryOutcome::Recovered,
            RecoveryOutcome::PartiallyRecovered,
            RecoveryOutcome::StrictFailed,
            RecoveryOutcome::RecoveryFailed,
            RecoveryOutcome::BudgetExhausted,
        ];
        let copied = arr[4];
        assert_eq!(copied, RecoveryOutcome::RecoveryFailed);
        assert_eq!(arr[4], RecoveryOutcome::RecoveryFailed);
    }

    // ── Enrichment: Debug distinctness ──────────────────────────────

    #[test]
    fn recovery_mode_debug_all_distinct() {
        use std::collections::BTreeSet;
        let dbgs: BTreeSet<String> = [
            RecoveryMode::Strict,
            RecoveryMode::Diagnostic,
            RecoveryMode::Execution,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 3);
    }

    #[test]
    fn error_state_debug_all_distinct() {
        use std::collections::BTreeSet;
        let dbgs: BTreeSet<String> = [
            ErrorState::Recoverable,
            ErrorState::Ambiguous,
            ErrorState::Unrecoverable,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 3);
    }

    #[test]
    fn recovery_outcome_debug_all_distinct() {
        use std::collections::BTreeSet;
        let dbgs: BTreeSet<String> = [
            RecoveryOutcome::CleanParse,
            RecoveryOutcome::Recovered,
            RecoveryOutcome::PartiallyRecovered,
            RecoveryOutcome::StrictFailed,
            RecoveryOutcome::RecoveryFailed,
            RecoveryOutcome::BudgetExhausted,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 6);
    }

    // ── Enrichment: Serde variant distinctness ──────────────────────

    #[test]
    fn recovery_mode_serde_variants_distinct() {
        use std::collections::BTreeSet;
        let jsons: BTreeSet<String> = [
            RecoveryMode::Strict,
            RecoveryMode::Diagnostic,
            RecoveryMode::Execution,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn error_state_serde_variants_distinct() {
        use std::collections::BTreeSet;
        let jsons: BTreeSet<String> = [
            ErrorState::Recoverable,
            ErrorState::Ambiguous,
            ErrorState::Unrecoverable,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn recovery_outcome_serde_variants_distinct() {
        use std::collections::BTreeSet;
        let jsons: BTreeSet<String> = [
            RecoveryOutcome::CleanParse,
            RecoveryOutcome::Recovered,
            RecoveryOutcome::PartiallyRecovered,
            RecoveryOutcome::StrictFailed,
            RecoveryOutcome::RecoveryFailed,
            RecoveryOutcome::BudgetExhausted,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
        assert_eq!(jsons.len(), 6);
    }

    #[test]
    fn repair_edit_serde_variants_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            RepairEdit::Insert {
                offset: 0,
                token_text: ";".into(),
            },
            RepairEdit::Delete {
                offset: 0,
                length: 1,
            },
            RepairEdit::Replace {
                offset: 0,
                length: 1,
                replacement: ";".into(),
            },
            RepairEdit::Skip {
                offset: 0,
                count: 1,
            },
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 4);
    }

    // ── Enrichment: Clone independence ──────────────────────────────

    #[test]
    fn state_probabilities_clone_independence() {
        let mut original = StateProbabilities::default();
        let cloned = original.clone();
        original.recoverable = 0;
        assert_eq!(original.recoverable, 0);
        assert_eq!(cloned.recoverable, DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS);
    }

    #[test]
    fn loss_matrix_clone_independence() {
        let mut original = LossMatrix::default();
        let cloned = original.clone();
        original.recover_recoverable = 999;
        assert_eq!(original.recover_recoverable, 999);
        assert_eq!(cloned.recover_recoverable, 2);
    }

    #[test]
    fn recovery_config_clone_independence() {
        let mut original = RecoveryConfig::default();
        let cloned = original.clone();
        original.max_attempts = 999;
        assert_eq!(original.max_attempts, 999);
        assert_eq!(cloned.max_attempts, DEFAULT_MAX_ATTEMPTS);
    }

    // ── Enrichment: JSON field-name stability ───────────────────────

    #[test]
    fn evidence_features_json_field_names() {
        let ef = EvidenceFeatures {
            tokens_before_error: 10,
            tokens_after_error: 20,
            error_offset: 100,
            at_statement_boundary: true,
            single_token_fix: false,
            single_token_delete: false,
            candidate_count: 2,
            features_hash: ContentHash::compute(b"test"),
        };
        let val: serde_json::Value = serde_json::to_value(&ef).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("tokens_before_error"));
        assert!(obj.contains_key("tokens_after_error"));
        assert!(obj.contains_key("error_offset"));
        assert!(obj.contains_key("at_statement_boundary"));
        assert!(obj.contains_key("single_token_fix"));
        assert!(obj.contains_key("single_token_delete"));
        assert!(obj.contains_key("candidate_count"));
        assert!(obj.contains_key("features_hash"));
        assert_eq!(obj.len(), 8);
    }

    #[test]
    fn state_probabilities_json_field_names() {
        let sp = StateProbabilities::default();
        let val: serde_json::Value = serde_json::to_value(&sp).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("recoverable"));
        assert!(obj.contains_key("ambiguous"));
        assert!(obj.contains_key("unrecoverable"));
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn loss_matrix_json_field_names() {
        let lm = LossMatrix::default();
        let val: serde_json::Value = serde_json::to_value(&lm).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("recover_recoverable"));
        assert!(obj.contains_key("recover_ambiguous"));
        assert!(obj.contains_key("recover_unrecoverable"));
        assert!(obj.contains_key("partial_recoverable"));
        assert!(obj.contains_key("partial_ambiguous"));
        assert!(obj.contains_key("partial_unrecoverable"));
        assert!(obj.contains_key("fail_recoverable"));
        assert!(obj.contains_key("fail_ambiguous"));
        assert!(obj.contains_key("fail_unrecoverable"));
        assert_eq!(obj.len(), 9);
    }

    #[test]
    fn expected_losses_json_field_names() {
        let el = ExpectedLosses {
            recover_continue: 10,
            partial_recover: 20,
            fail_strict: 30,
        };
        let val: serde_json::Value = serde_json::to_value(&el).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("recover_continue"));
        assert!(obj.contains_key("partial_recover"));
        assert!(obj.contains_key("fail_strict"));
        assert_eq!(obj.len(), 3);
    }

    // ── Enrichment: Display format ──────────────────────────────────

    #[test]
    fn recovery_mode_display_all_distinct() {
        use std::collections::BTreeSet;
        let displays: BTreeSet<String> = [
            RecoveryMode::Strict,
            RecoveryMode::Diagnostic,
            RecoveryMode::Execution,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn recovery_outcome_display_all_distinct() {
        use std::collections::BTreeSet;
        let displays: BTreeSet<String> = [
            RecoveryOutcome::CleanParse,
            RecoveryOutcome::Recovered,
            RecoveryOutcome::PartiallyRecovered,
            RecoveryOutcome::StrictFailed,
            RecoveryOutcome::RecoveryFailed,
            RecoveryOutcome::BudgetExhausted,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(displays.len(), 6);
    }

    #[test]
    fn repair_edit_display_all_variants() {
        let edits = [
            RepairEdit::Insert {
                offset: 10,
                token_text: ";".into(),
            },
            RepairEdit::Delete {
                offset: 20,
                length: 3,
            },
            RepairEdit::Replace {
                offset: 30,
                length: 2,
                replacement: "{}".into(),
            },
            RepairEdit::Skip {
                offset: 40,
                count: 5,
            },
        ];
        use std::collections::BTreeSet;
        let displays: BTreeSet<String> = edits.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), 4);
        assert!(edits[0].to_string().contains("insert"));
        assert!(edits[1].to_string().contains("delete"));
        assert!(edits[2].to_string().contains("replace"));
        assert!(edits[3].to_string().contains("skip"));
    }

    // ── Enrichment: Hash consistency ────────────────────────────────

    #[test]
    fn recovery_mode_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        RecoveryMode::Strict.hash(&mut h1);
        RecoveryMode::Strict.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn error_state_hash_all_distinct() {
        use std::collections::BTreeSet;
        use std::hash::{Hash, Hasher};
        let variants = [
            ErrorState::Recoverable,
            ErrorState::Ambiguous,
            ErrorState::Unrecoverable,
        ];
        let hashes: BTreeSet<u64> = variants
            .iter()
            .map(|v| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                v.hash(&mut h);
                h.finish()
            })
            .collect();
        assert_eq!(hashes.len(), 3);
    }

    // ── Enrichment: Boundary/edge cases ─────────────────────────────

    #[test]
    fn bayesian_update_all_zero_priors_returns_default() {
        let prior = StateProbabilities {
            recoverable: 0,
            ambiguous: 0,
            unrecoverable: 0,
        };
        let evidence = simple_evidence();
        let posterior = bayesian_update(&prior, &evidence);
        // When total is 0, falls back to default
        assert!(posterior.is_valid());
    }

    #[test]
    fn bayesian_update_strong_recoverable_evidence() {
        let prior = StateProbabilities::default();
        let evidence = EvidenceFeatures {
            tokens_before_error: 50,
            tokens_after_error: 100,
            error_offset: 200,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: true,
            candidate_count: 1,
            features_hash: ContentHash::compute(b"strong"),
        };
        let posterior = bayesian_update(&prior, &evidence);
        assert!(posterior.is_valid());
        assert_eq!(posterior.most_likely(), ErrorState::Recoverable);
        assert!(posterior.recoverable > prior.recoverable);
    }

    #[test]
    fn bayesian_update_no_candidates_favors_unrecoverable() {
        let prior = StateProbabilities {
            recoverable: 333_334,
            ambiguous: 333_333,
            unrecoverable: 333_333,
        };
        let evidence = EvidenceFeatures {
            tokens_before_error: 50,
            tokens_after_error: 100,
            error_offset: 200,
            at_statement_boundary: false,
            single_token_fix: false,
            single_token_delete: false,
            candidate_count: 0,
            features_hash: ContentHash::compute(b"none"),
        };
        let posterior = bayesian_update(&prior, &evidence);
        assert!(posterior.is_valid());
        assert_eq!(posterior.most_likely(), ErrorState::Unrecoverable);
    }

    #[test]
    fn bayesian_update_many_candidates_favors_ambiguous() {
        let prior = StateProbabilities {
            recoverable: 333_334,
            ambiguous: 333_333,
            unrecoverable: 333_333,
        };
        let evidence = EvidenceFeatures {
            tokens_before_error: 50,
            tokens_after_error: 100,
            error_offset: 200,
            at_statement_boundary: false,
            single_token_fix: false,
            single_token_delete: false,
            candidate_count: 10,
            features_hash: ContentHash::compute(b"many"),
        };
        let posterior = bayesian_update(&prior, &evidence);
        assert!(posterior.is_valid());
        assert_eq!(posterior.most_likely(), ErrorState::Ambiguous);
    }

    #[test]
    fn select_action_unrecoverable_state_selects_fail() {
        let posterior = StateProbabilities {
            recoverable: 0,
            ambiguous: 0,
            unrecoverable: 1_000_000,
        };
        let action = select_action(&posterior, &LossMatrix::default());
        assert_eq!(action, RecoveryAction::FailStrict);
    }

    #[test]
    fn select_action_recoverable_state_selects_recover() {
        let posterior = StateProbabilities {
            recoverable: 1_000_000,
            ambiguous: 0,
            unrecoverable: 0,
        };
        let action = select_action(&posterior, &LossMatrix::default());
        assert_eq!(action, RecoveryAction::RecoverContinue);
    }

    #[test]
    fn expected_loss_all_zero_probabilities() {
        let posterior = StateProbabilities {
            recoverable: 0,
            ambiguous: 0,
            unrecoverable: 0,
        };
        let loss = expected_loss(
            RecoveryAction::RecoverContinue,
            &posterior,
            &LossMatrix::default(),
        );
        assert_eq!(loss, 0);
    }

    #[test]
    fn evidence_features_with_hash_deterministic() {
        let ef1 = EvidenceFeatures {
            tokens_before_error: 10,
            tokens_after_error: 20,
            error_offset: 100,
            at_statement_boundary: true,
            single_token_fix: false,
            single_token_delete: false,
            candidate_count: 2,
            features_hash: ContentHash::compute(b"dummy"),
        }
        .with_hash();
        let ef2 = EvidenceFeatures {
            tokens_before_error: 10,
            tokens_after_error: 20,
            error_offset: 100,
            at_statement_boundary: true,
            single_token_fix: false,
            single_token_delete: false,
            candidate_count: 2,
            features_hash: ContentHash::compute(b"other"),
        }
        .with_hash();
        assert_eq!(ef1.features_hash, ef2.features_hash);
    }

    #[test]
    fn state_probabilities_confidence_returns_max() {
        let sp = StateProbabilities {
            recoverable: 100_000,
            ambiguous: 700_000,
            unrecoverable: 200_000,
        };
        assert_eq!(sp.confidence(), 700_000);
    }

    // ── Enrichment: Serde roundtrips ────────────────────────────────

    #[test]
    fn loss_matrix_serde_roundtrip_enrichment() {
        let lm = LossMatrix::default();
        let json = serde_json::to_string(&lm).unwrap();
        let back: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(lm, back);
    }

    #[test]
    fn repair_edit_serde_roundtrip_all_variants() {
        let variants = [
            RepairEdit::Insert {
                offset: 10,
                token_text: "semicolon".into(),
            },
            RepairEdit::Delete {
                offset: 20,
                length: 5,
            },
            RepairEdit::Replace {
                offset: 30,
                length: 3,
                replacement: "{}".into(),
            },
            RepairEdit::Skip {
                offset: 40,
                count: 7,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RepairEdit = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn expected_losses_serde_roundtrip() {
        let el = ExpectedLosses {
            recover_continue: 5,
            partial_recover: 12,
            fail_strict: 8,
        };
        let json = serde_json::to_string(&el).unwrap();
        let back: ExpectedLosses = serde_json::from_str(&json).unwrap();
        assert_eq!(el, back);
    }

    // ── Enrichment: Debug nonempty ──────────────────────────────────

    #[test]
    fn evidence_features_debug_nonempty() {
        let ef = simple_evidence();
        let dbg = format!("{ef:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("EvidenceFeatures"));
    }

    #[test]
    fn decision_ledger_debug_nonempty() {
        let dl = DecisionLedger {
            schema_version: SCHEMA_VERSION.to_string(),
            input_hash: ContentHash::compute(b"test"),
            input_bytes: 100,
            mode: RecoveryMode::Strict,
            attempts: Vec::new(),
            outcome: RecoveryOutcome::CleanParse,
            total_edits: 0,
            parity_checked: false,
            parity_ok: None,
            repair_diff_hash: None,
        };
        let dbg = format!("{dl:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("DecisionLedger"));
    }

    #[test]
    fn loss_matrix_debug_nonempty() {
        let lm = LossMatrix::default();
        let dbg = format!("{lm:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("LossMatrix"));
    }
}
