//! Deterministic evidence replay checker for decision/evidence linkage.
//!
//! Accepts a sequence of [`CanonicalEvidenceEntry`] entries (from
//! `evidence_emission`) and replays each decision to verify that the
//! recorded outcome matches the replayed outcome.  Detects:
//!
//! - **Divergences**: replayed outcome differs from recorded outcome.
//! - **Tamper**: artifact hash or chain hash mismatch.
//! - **Sequence gaps**: missing entries in the ledger.
//! - **Timestamp monotonicity violations**: entries out of order.
//! - **Schema migration boundaries**: version transitions in the ledger.
//! - **Policy version discontinuities**: unexpected policy-id changes.
//!
//! The checker is designed to be runnable as a CI check, a frankenlab
//! post-condition, or an operator audit tool.
//!
//! Plan reference: Section 10.13, item 11, bd-2sbb.
//! Cross-refs: bd-uvmm (evidence emission), bd-3a5e (decision contracts).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence_emission::CanonicalEvidenceEntry;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT_NAME: &str = "evidence-replay-checker";

// ---------------------------------------------------------------------------
// ReplayErrorCode — machine-readable error codes
// ---------------------------------------------------------------------------

/// Machine-readable error codes for specific violation diagnostics.
///
/// These map to the enrichment spec from bd-2sbb for structured log
/// assertions and operator tooling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReplayErrorCode {
    /// Artifact hash recomputed from ledger entry content does not match.
    HashMismatch,
    /// Chain hash breaks the append-only integrity chain.
    ChainBroken,
    /// Entry body appears truncated or fails deserialization.
    EntryTruncated,
    /// Sequence number has a gap (expected_seq, actual_seq included).
    SequenceGap,
    /// Timestamp is not monotonically non-decreasing.
    TimestampMonotonicityViolation,
    /// Replayed action name differs from recorded.
    OutcomeDivergence,
    /// Calibration score exceeds tolerance.
    CalibrationDivergence,
    /// Expected loss exceeds tolerance.
    ExpectedLossDivergence,
    /// Fallback-active flag mismatch.
    FallbackDivergence,
    /// Schema version changed mid-ledger without migration marker.
    SchemaMigrationDetected,
    /// Policy version changed unexpectedly.
    PolicyVersionDiscontinuity,
    /// Epoch regression detected (current epoch < previous).
    EpochRegression,
}

impl fmt::Display for ReplayErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HashMismatch => "HASH_MISMATCH",
            Self::ChainBroken => "CHAIN_BROKEN",
            Self::EntryTruncated => "ENTRY_TRUNCATED",
            Self::SequenceGap => "SEQUENCE_GAP",
            Self::TimestampMonotonicityViolation => "TIMESTAMP_MONOTONICITY_VIOLATION",
            Self::OutcomeDivergence => "OUTCOME_DIVERGENCE",
            Self::CalibrationDivergence => "CALIBRATION_DIVERGENCE",
            Self::ExpectedLossDivergence => "EXPECTED_LOSS_DIVERGENCE",
            Self::FallbackDivergence => "FALLBACK_DIVERGENCE",
            Self::SchemaMigrationDetected => "SCHEMA_MIGRATION_DETECTED",
            Self::PolicyVersionDiscontinuity => "POLICY_VERSION_DISCONTINUITY",
            Self::EpochRegression => "EPOCH_REGRESSION",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// ReplayViolation — what went wrong
// ---------------------------------------------------------------------------

/// Types of replay violations detected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReplayViolationType {
    /// Replayed outcome differs from recorded outcome.
    OutcomeDivergence,
    /// Artifact hash does not match ledger entry content.
    ArtifactHashMismatch,
    /// Chain hash does not match expected value.
    ChainHashMismatch,
    /// Sequence number gap detected.
    SequenceGap,
    /// Timestamp monotonicity violation.
    TimestampMonotonicityViolation,
    /// Entry is truncated or malformed.
    EntryTruncated,
    /// Calibration score divergence (floating-point instability).
    CalibrationDivergence,
    /// Expected loss divergence.
    ExpectedLossDivergence,
    /// Fallback-active flag divergence.
    FallbackDivergence,
    /// Schema migration detected at a boundary.
    SchemaMigration,
    /// Policy version changed without explicit transition.
    PolicyVersionChange,
    /// Epoch regression detected.
    EpochRegression,
}

impl fmt::Display for ReplayViolationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::OutcomeDivergence => "outcome_divergence",
            Self::ArtifactHashMismatch => "artifact_hash_mismatch",
            Self::ChainHashMismatch => "chain_hash_mismatch",
            Self::SequenceGap => "sequence_gap",
            Self::TimestampMonotonicityViolation => "timestamp_monotonicity_violation",
            Self::EntryTruncated => "entry_truncated",
            Self::CalibrationDivergence => "calibration_divergence",
            Self::ExpectedLossDivergence => "expected_loss_divergence",
            Self::FallbackDivergence => "fallback_divergence",
            Self::SchemaMigration => "schema_migration",
            Self::PolicyVersionChange => "policy_version_change",
            Self::EpochRegression => "epoch_regression",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// ReplayViolation — a specific violation
// ---------------------------------------------------------------------------

/// A single replay violation with context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayViolation {
    /// Which entry had the violation.
    pub sequence: u64,
    /// Entry ID.
    pub entry_id: String,
    /// Type of violation.
    pub violation_type: ReplayViolationType,
    /// Machine-readable error code.
    pub error_code: ReplayErrorCode,
    /// Human-readable description.
    pub detail: String,
    /// Expected value (if applicable).
    pub expected: Option<String>,
    /// Actual value (if applicable).
    pub actual: Option<String>,
}

// ---------------------------------------------------------------------------
// ReplayOutcome — replayed decision result
// ---------------------------------------------------------------------------

/// The outcome of replaying a single decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayedOutcome {
    /// Replayed action name.
    pub action: String,
    /// Replayed expected loss of chosen action.
    pub chosen_expected_loss: f64,
    /// Replayed calibration score.
    pub calibration_score: f64,
    /// Replayed fallback flag.
    pub fallback_active: bool,
    /// Replayed expected losses by action.
    pub expected_losses: BTreeMap<String, f64>,
}

// ---------------------------------------------------------------------------
// DecisionReplayFn — pluggable replay evaluator
// ---------------------------------------------------------------------------

/// A function that re-evaluates a decision given the recorded inputs.
///
/// Takes (action_name, posterior, expected_losses, calibration_score, fallback_active)
/// and returns the replayed outcome.  In production, this would call the
/// actual decision contract; in tests, it can be a deterministic stub.
pub type DecisionReplayFn = Box<dyn Fn(&CanonicalEvidenceEntry) -> ReplayedOutcome>;

// ---------------------------------------------------------------------------
// ReplayEvent — structured log entry
// ---------------------------------------------------------------------------

/// Structured log event for replay operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// ReplayConfig
// ---------------------------------------------------------------------------

/// Configuration for the replay checker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Tolerance for floating-point comparison of calibration scores.
    pub calibration_tolerance: f64,
    /// Tolerance for expected loss comparison.
    pub loss_tolerance: f64,
    /// Whether to allow sequence gaps (for forensic analysis of partial ledgers).
    pub allow_gaps: bool,
    /// Whether to halt on first violation.
    pub halt_on_first: bool,
    /// Progress reporting interval (emit event every N entries).
    pub progress_interval: u64,
    /// Whether to track schema migration boundaries.
    pub track_schema_migrations: bool,
    /// Whether to track policy version transitions.
    pub track_policy_versions: bool,
    /// Whether to detect epoch regressions.
    pub detect_epoch_regression: bool,
    /// Whether unexpected policy version transitions are violations
    /// (as opposed to merely logged transitions).
    pub policy_discontinuity_is_violation: bool,
    /// Whether schema migrations without explicit markers are violations.
    pub schema_migration_is_violation: bool,
    /// Set of policy IDs that form valid transition targets.  If non-empty,
    /// any policy transition to an ID not in this set is flagged.
    pub allowed_policy_ids: BTreeSet<String>,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            calibration_tolerance: 1e-9,
            loss_tolerance: 1e-9,
            allow_gaps: false,
            halt_on_first: false,
            progress_interval: 1000,
            track_schema_migrations: true,
            track_policy_versions: true,
            detect_epoch_regression: true,
            policy_discontinuity_is_violation: false,
            schema_migration_is_violation: false,
            allowed_policy_ids: BTreeSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// SchemaMigrationRecord — tracks schema version transitions
// ---------------------------------------------------------------------------

/// Records a schema version transition in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMigrationRecord {
    /// Sequence number where the migration was detected.
    pub at_sequence: u64,
    /// Previous schema version.
    pub from_version: String,
    /// New schema version.
    pub to_version: String,
}

// ---------------------------------------------------------------------------
// PolicyVersionRecord — tracks policy version transitions
// ---------------------------------------------------------------------------

/// Records a policy version transition in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVersionRecord {
    /// Sequence number where the transition was detected.
    pub at_sequence: u64,
    /// Previous policy ID.
    pub from_policy: String,
    /// New policy ID.
    pub to_policy: String,
}

// ---------------------------------------------------------------------------
// ReplayDiagnostics — detailed per-run diagnostics
// ---------------------------------------------------------------------------

/// Detailed diagnostics collected during a replay run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReplayDiagnostics {
    /// Schema versions encountered during replay.
    pub schema_versions_seen: BTreeSet<String>,
    /// Schema migration boundaries detected.
    pub schema_migrations: Vec<SchemaMigrationRecord>,
    /// Policy versions encountered during replay.
    pub policy_versions_seen: BTreeSet<String>,
    /// Policy version transitions detected.
    pub policy_transitions: Vec<PolicyVersionRecord>,
    /// Distinct trace IDs seen.
    pub distinct_trace_ids: u64,
    /// Distinct decision IDs seen.
    pub distinct_decision_ids: u64,
    /// First entry timestamp.
    pub first_ts: Option<u64>,
    /// Last entry timestamp.
    pub last_ts: Option<u64>,
    /// Epoch range observed (min, max).
    pub epoch_range: Option<(u64, u64)>,
}

// ---------------------------------------------------------------------------
// ReplayManifest — reproducibility artifact
// ---------------------------------------------------------------------------

/// Reproducibility manifest for a replay run.
///
/// Contains enough information to reproduce the replay on a different
/// machine and verify identical results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayManifest {
    /// Configuration used for the replay.
    pub config: ReplayConfig,
    /// Number of entries in the source ledger.
    pub source_entry_count: u64,
    /// Hash of the first entry (for ledger identity).
    pub first_entry_hash: Option<ContentHash>,
    /// Hash of the last entry.
    pub last_entry_hash: Option<ContentHash>,
    /// Final rolling hash (the cross-machine comparison value).
    pub final_rolling_hash: ContentHash,
    /// Whether the replay passed.
    pub passed: bool,
    /// Number of violations found.
    pub violation_count: u64,
}

// ---------------------------------------------------------------------------
// ReplayEvidenceArtifact — structured output for CI/operator
// ---------------------------------------------------------------------------

/// Structured evidence artifact produced by a replay run.
///
/// Contains the manifest, per-violation detail, diagnostics, and
/// structured events — suitable for writing to `evidence_replay.jsonl`
/// or embedding in a CI gate report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayEvidenceArtifact {
    /// Reproducibility manifest.
    pub manifest: ReplayManifest,
    /// Detailed diagnostics.
    pub diagnostics: ReplayDiagnostics,
    /// Per-violation records.
    pub violations: Vec<ReplayViolation>,
    /// Structured events emitted during the run.
    pub events: Vec<ReplayEvent>,
    /// Whether the run passed the CI gate.
    pub gate_passed: bool,
}

// ---------------------------------------------------------------------------
// ReplayResult — overall result of a replay run
// ---------------------------------------------------------------------------

/// Summary result of replaying an evidence ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    /// Total entries processed.
    pub entries_processed: u64,
    /// Total entries skipped (gaps when allow_gaps=true).
    pub entries_skipped: u64,
    /// All violations detected.
    pub violations: Vec<ReplayViolation>,
    /// Whether the replay passed (no violations).
    pub passed: bool,
    /// Rolling hash at end of replay (for cross-machine comparison).
    pub final_rolling_hash: ContentHash,
    /// Epoch at end of replay.
    pub epoch: SecurityEpoch,
    /// Detailed diagnostics.
    pub diagnostics: ReplayDiagnostics,
}

impl ReplayResult {
    /// Count violations by type.
    pub fn violation_counts(&self) -> BTreeMap<ReplayViolationType, u64> {
        let mut counts = BTreeMap::new();
        for v in &self.violations {
            *counts.entry(v.violation_type.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Whether a specific violation type was detected.
    pub fn has_violation(&self, vtype: &ReplayViolationType) -> bool {
        self.violations.iter().any(|v| &v.violation_type == vtype)
    }

    /// Whether a specific error code was detected.
    pub fn has_error_code(&self, code: &ReplayErrorCode) -> bool {
        self.violations.iter().any(|v| &v.error_code == code)
    }

    /// Find violations at a specific sequence number.
    pub fn violations_at(&self, seq: u64) -> Vec<&ReplayViolation> {
        self.violations
            .iter()
            .filter(|v| v.sequence == seq)
            .collect()
    }

    /// Build a reproducibility manifest for this result.
    pub fn manifest(
        &self,
        config: &ReplayConfig,
        entries: &[CanonicalEvidenceEntry],
    ) -> ReplayManifest {
        ReplayManifest {
            config: config.clone(),
            source_entry_count: entries.len() as u64,
            first_entry_hash: entries.first().map(|e| e.artifact_hash),
            last_entry_hash: entries.last().map(|e| e.artifact_hash),
            final_rolling_hash: self.final_rolling_hash,
            passed: self.passed,
            violation_count: self.violations.len() as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// EvidenceReplayChecker — the main checker
// ---------------------------------------------------------------------------

/// Deterministic evidence replay checker.
///
/// Verifies chain integrity, sequence continuity, timestamp monotonicity,
/// schema migration boundaries, policy version tracking, epoch regression,
/// and decision outcome determinism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReplayChecker {
    config: ReplayConfig,
    events: Vec<ReplayEvent>,
    epoch: SecurityEpoch,
}

impl EvidenceReplayChecker {
    pub fn new(config: ReplayConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
            epoch: SecurityEpoch::from_raw(0),
        }
    }

    /// Set the security epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }

    /// Access the replay configuration.
    pub fn config(&self) -> &ReplayConfig {
        &self.config
    }

    /// Replay a sequence of evidence entries, verifying integrity and
    /// determinism.
    ///
    /// The `replay_fn` is called for each entry to re-evaluate the decision.
    /// If `None`, only structural checks (chain hash, sequence, timestamp,
    /// schema migration, epoch regression) are performed.
    pub fn replay(
        &mut self,
        entries: &[CanonicalEvidenceEntry],
        replay_fn: Option<&DecisionReplayFn>,
    ) -> ReplayResult {
        let mut violations = Vec::new();
        let mut processed: u64 = 0;
        let mut skipped: u64 = 0;
        let mut prev_entry: Option<&CanonicalEvidenceEntry> = None;
        let mut rolling_hash = ContentHash::compute(b"evidence-genesis");
        let mut diagnostics = ReplayDiagnostics::default();
        let mut trace_ids = BTreeSet::new();
        let mut decision_ids = BTreeSet::new();
        let mut halted = false;

        for entry in entries {
            if halted {
                break;
            }

            // Progress reporting.
            if processed > 0
                && self.config.progress_interval > 0
                && processed.is_multiple_of(self.config.progress_interval)
            {
                self.push_event(entry, "replay_progress", "in_progress", None);
            }

            // Track diagnostics.
            diagnostics
                .schema_versions_seen
                .insert(entry.schema_version.clone());
            diagnostics
                .policy_versions_seen
                .insert(entry.policy_id.clone());
            trace_ids.insert(entry.trace_id.clone());
            decision_ids.insert(entry.decision_id.clone());

            if diagnostics.first_ts.is_none() {
                diagnostics.first_ts = Some(entry.ts_unix_ms);
            }
            diagnostics.last_ts = Some(entry.ts_unix_ms);

            let epoch_val = entry.epoch.as_u64();
            diagnostics.epoch_range = Some(match diagnostics.epoch_range {
                Some((lo, hi)) => (lo.min(epoch_val), hi.max(epoch_val)),
                None => (epoch_val, epoch_val),
            });

            // 1. Check artifact integrity.
            if !entry.verify_artifact_integrity() {
                violations.push(ReplayViolation {
                    sequence: entry.sequence,
                    entry_id: entry.entry_id.to_string(),
                    violation_type: ReplayViolationType::ArtifactHashMismatch,
                    error_code: ReplayErrorCode::HashMismatch,
                    detail: "artifact hash does not match ledger entry content".to_string(),
                    expected: Some(entry.artifact_hash.to_string()),
                    actual: None,
                });
                self.push_event(
                    entry,
                    "artifact_integrity_fail",
                    "fail",
                    Some("HASH_MISMATCH"),
                );
                if self.config.halt_on_first {
                    halted = true;
                    processed += 1;
                    continue;
                }
            }

            // 2. Check chain hash.
            if !entry.verify_chain_link(prev_entry) {
                violations.push(ReplayViolation {
                    sequence: entry.sequence,
                    entry_id: entry.entry_id.to_string(),
                    violation_type: ReplayViolationType::ChainHashMismatch,
                    error_code: ReplayErrorCode::ChainBroken,
                    detail: "chain hash mismatch".to_string(),
                    expected: None,
                    actual: Some(entry.chain_hash.to_string()),
                });
                if self.config.halt_on_first {
                    halted = true;
                    processed += 1;
                    continue;
                }
            }

            // 3. Check sequence continuity.
            if let Some(prev) = prev_entry {
                let expected_seq = prev.sequence + 1;
                if entry.sequence != expected_seq {
                    if self.config.allow_gaps {
                        skipped += entry.sequence.saturating_sub(expected_seq);
                        self.push_event(
                            entry,
                            "sequence_gap_skipped",
                            "warn",
                            Some("SEQUENCE_GAP"),
                        );
                    } else {
                        violations.push(ReplayViolation {
                            sequence: entry.sequence,
                            entry_id: entry.entry_id.to_string(),
                            violation_type: ReplayViolationType::SequenceGap,
                            error_code: ReplayErrorCode::SequenceGap,
                            detail: format!(
                                "expected sequence {expected_seq}, got {}",
                                entry.sequence
                            ),
                            expected: Some(expected_seq.to_string()),
                            actual: Some(entry.sequence.to_string()),
                        });
                        if self.config.halt_on_first {
                            halted = true;
                            processed += 1;
                            continue;
                        }
                    }
                }

                // 4. Check timestamp monotonicity.
                if entry.ts_unix_ms < prev.ts_unix_ms {
                    violations.push(ReplayViolation {
                        sequence: entry.sequence,
                        entry_id: entry.entry_id.to_string(),
                        violation_type: ReplayViolationType::TimestampMonotonicityViolation,
                        error_code: ReplayErrorCode::TimestampMonotonicityViolation,
                        detail: format!(
                            "timestamp {} < previous {}",
                            entry.ts_unix_ms, prev.ts_unix_ms
                        ),
                        expected: Some(format!(">= {}", prev.ts_unix_ms)),
                        actual: Some(entry.ts_unix_ms.to_string()),
                    });
                    if self.config.halt_on_first {
                        halted = true;
                        processed += 1;
                        continue;
                    }
                }

                // 5. Schema migration boundary detection.
                if self.config.track_schema_migrations
                    && entry.schema_version != prev.schema_version
                {
                    diagnostics.schema_migrations.push(SchemaMigrationRecord {
                        at_sequence: entry.sequence,
                        from_version: prev.schema_version.clone(),
                        to_version: entry.schema_version.clone(),
                    });
                    if self.config.schema_migration_is_violation {
                        violations.push(ReplayViolation {
                            sequence: entry.sequence,
                            entry_id: entry.entry_id.to_string(),
                            violation_type: ReplayViolationType::SchemaMigration,
                            error_code: ReplayErrorCode::SchemaMigrationDetected,
                            detail: format!(
                                "schema version changed from {} to {}",
                                prev.schema_version, entry.schema_version
                            ),
                            expected: Some(prev.schema_version.clone()),
                            actual: Some(entry.schema_version.clone()),
                        });
                        self.push_event(
                            entry,
                            "schema_migration_violation",
                            "fail",
                            Some("SCHEMA_MIGRATION_DETECTED"),
                        );
                        if self.config.halt_on_first {
                            halted = true;
                            processed += 1;
                            continue;
                        }
                    } else {
                        self.push_event(
                            entry,
                            "schema_migration_boundary",
                            "info",
                            Some("SCHEMA_MIGRATION_DETECTED"),
                        );
                    }
                }

                // 6. Policy version transition.
                if self.config.track_policy_versions && entry.policy_id != prev.policy_id {
                    diagnostics.policy_transitions.push(PolicyVersionRecord {
                        at_sequence: entry.sequence,
                        from_policy: prev.policy_id.clone(),
                        to_policy: entry.policy_id.clone(),
                    });

                    let is_disallowed = self.config.policy_discontinuity_is_violation
                        || (!self.config.allowed_policy_ids.is_empty()
                            && !self.config.allowed_policy_ids.contains(&entry.policy_id));

                    if is_disallowed {
                        violations.push(ReplayViolation {
                            sequence: entry.sequence,
                            entry_id: entry.entry_id.to_string(),
                            violation_type: ReplayViolationType::PolicyVersionChange,
                            error_code: ReplayErrorCode::PolicyVersionDiscontinuity,
                            detail: format!(
                                "policy changed from {} to {}",
                                prev.policy_id, entry.policy_id
                            ),
                            expected: Some(prev.policy_id.clone()),
                            actual: Some(entry.policy_id.clone()),
                        });
                        self.push_event(
                            entry,
                            "policy_version_discontinuity",
                            "fail",
                            Some("POLICY_VERSION_DISCONTINUITY"),
                        );
                        if self.config.halt_on_first {
                            halted = true;
                            processed += 1;
                            continue;
                        }
                    } else {
                        self.push_event(entry, "policy_version_transition", "info", None);
                    }
                }

                // 7. Epoch regression detection.
                if self.config.detect_epoch_regression && entry.epoch.as_u64() < prev.epoch.as_u64()
                {
                    violations.push(ReplayViolation {
                        sequence: entry.sequence,
                        entry_id: entry.entry_id.to_string(),
                        violation_type: ReplayViolationType::EpochRegression,
                        error_code: ReplayErrorCode::EpochRegression,
                        detail: format!(
                            "epoch {} < previous epoch {}",
                            entry.epoch.as_u64(),
                            prev.epoch.as_u64()
                        ),
                        expected: Some(format!(">= {}", prev.epoch.as_u64())),
                        actual: Some(entry.epoch.as_u64().to_string()),
                    });
                    if self.config.halt_on_first {
                        halted = true;
                        processed += 1;
                        continue;
                    }
                }
            }

            // 8. Replay decision (if replay function provided).
            if let Some(replay) = replay_fn {
                let replayed = replay(entry);
                self.check_outcome(entry, &replayed, &mut violations);
                if self.config.halt_on_first && !violations.is_empty() {
                    halted = true;
                    processed += 1;
                    continue;
                }
            }

            // Update rolling hash.
            let mut hash_input = rolling_hash.as_bytes().to_vec();
            hash_input.extend_from_slice(entry.artifact_hash.as_bytes());
            rolling_hash = ContentHash::compute(&hash_input);

            prev_entry = Some(entry);
            processed += 1;
        }

        diagnostics.distinct_trace_ids = trace_ids.len() as u64;
        diagnostics.distinct_decision_ids = decision_ids.len() as u64;

        let passed = violations.is_empty();
        let event_outcome = if passed { "pass" } else { "fail" };
        if let Some(last) = entries.last() {
            self.push_event(last, "replay_complete", event_outcome, None);
        }

        ReplayResult {
            entries_processed: processed,
            entries_skipped: skipped,
            violations,
            passed,
            final_rolling_hash: rolling_hash,
            epoch: self.epoch,
            diagnostics,
        }
    }

    /// All structured log events.
    pub fn events(&self) -> &[ReplayEvent] {
        &self.events
    }

    /// Clear accumulated events (useful between replay runs).
    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    /// Replay and produce a full evidence artifact suitable for CI gates
    /// and operator audit.
    ///
    /// This is the primary entry point for automated replay pipelines.
    /// It runs the replay, collects all events, and produces a self-contained
    /// artifact combining the manifest, diagnostics, violations, and events.
    pub fn replay_and_collect(
        &mut self,
        entries: &[CanonicalEvidenceEntry],
        replay_fn: Option<&DecisionReplayFn>,
    ) -> ReplayEvidenceArtifact {
        self.clear_events();
        let result = self.replay(entries, replay_fn);
        let manifest = result.manifest(&self.config, entries);
        ReplayEvidenceArtifact {
            manifest,
            diagnostics: result.diagnostics.clone(),
            violations: result.violations.clone(),
            events: self.events.clone(),
            gate_passed: result.passed,
        }
    }

    /// Verify cross-machine determinism by running the replay twice and
    /// comparing rolling hashes.
    ///
    /// Returns `true` if both runs produce identical results.
    pub fn verify_cross_machine_determinism(
        config: &ReplayConfig,
        entries: &[CanonicalEvidenceEntry],
        replay_fn: Option<&DecisionReplayFn>,
    ) -> bool {
        let mut checker_a = Self::new(config.clone());
        let result_a = checker_a.replay(entries, replay_fn);

        let mut checker_b = Self::new(config.clone());
        let result_b = checker_b.replay(entries, replay_fn);

        result_a.final_rolling_hash == result_b.final_rolling_hash
            && result_a.passed == result_b.passed
            && result_a.entries_processed == result_b.entries_processed
            && result_a.violations.len() == result_b.violations.len()
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn check_outcome(
        &self,
        entry: &CanonicalEvidenceEntry,
        replayed: &ReplayedOutcome,
        violations: &mut Vec<ReplayViolation>,
    ) {
        let recorded = &entry.ledger_entry;

        // Action name.
        if replayed.action != recorded.action {
            violations.push(ReplayViolation {
                sequence: entry.sequence,
                entry_id: entry.entry_id.to_string(),
                violation_type: ReplayViolationType::OutcomeDivergence,
                error_code: ReplayErrorCode::OutcomeDivergence,
                detail: "action name mismatch".to_string(),
                expected: Some(recorded.action.clone()),
                actual: Some(replayed.action.clone()),
            });
            if self.config.halt_on_first {
                return;
            }
        }

        // Calibration score.
        if (replayed.calibration_score - recorded.calibration_score).abs()
            > self.config.calibration_tolerance
        {
            violations.push(ReplayViolation {
                sequence: entry.sequence,
                entry_id: entry.entry_id.to_string(),
                violation_type: ReplayViolationType::CalibrationDivergence,
                error_code: ReplayErrorCode::CalibrationDivergence,
                detail: "calibration score divergence".to_string(),
                expected: Some(format!("{}", recorded.calibration_score)),
                actual: Some(format!("{}", replayed.calibration_score)),
            });
            if self.config.halt_on_first {
                return;
            }
        }

        // Chosen expected loss.
        if (replayed.chosen_expected_loss - recorded.chosen_expected_loss).abs()
            > self.config.loss_tolerance
        {
            violations.push(ReplayViolation {
                sequence: entry.sequence,
                entry_id: entry.entry_id.to_string(),
                violation_type: ReplayViolationType::ExpectedLossDivergence,
                error_code: ReplayErrorCode::ExpectedLossDivergence,
                detail: "chosen expected loss divergence".to_string(),
                expected: Some(format!("{}", recorded.chosen_expected_loss)),
                actual: Some(format!("{}", replayed.chosen_expected_loss)),
            });
            if self.config.halt_on_first {
                return;
            }
        }

        // Fallback active.
        if replayed.fallback_active != recorded.fallback_active {
            violations.push(ReplayViolation {
                sequence: entry.sequence,
                entry_id: entry.entry_id.to_string(),
                violation_type: ReplayViolationType::FallbackDivergence,
                error_code: ReplayErrorCode::FallbackDivergence,
                detail: "fallback_active flag mismatch".to_string(),
                expected: Some(format!("{}", recorded.fallback_active)),
                actual: Some(format!("{}", replayed.fallback_active)),
            });
        }
    }

    fn push_event(
        &mut self,
        entry: &CanonicalEvidenceEntry,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(ReplayEvent {
            trace_id: entry.trace_id.clone(),
            decision_id: entry.decision_id.clone(),
            policy_id: entry.policy_id.clone(),
            component: COMPONENT_NAME.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{
        MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
    };
    use crate::evidence_emission::{
        ActionCategory, CanonicalEvidenceEmitter, EmitterConfig, EvidenceEmissionRequest,
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_emitter() -> CanonicalEvidenceEmitter {
        CanonicalEvidenceEmitter::new(EmitterConfig::default())
    }

    fn mock_cx() -> MockCx {
        MockCx::new(trace_id_from_seed(1), MockBudget::new(100_000))
    }

    fn make_request(action: &str, ts: u64) -> EvidenceEmissionRequest {
        EvidenceEmissionRequest {
            category: ActionCategory::DecisionContract,
            action_name: action.to_string(),
            trace_id: trace_id_from_seed(1),
            decision_id: decision_id_from_seed(1),
            policy_id: policy_id_from_seed(1),
            ts_unix_ms: ts,
            posterior: vec![0.7, 0.3],
            expected_losses: {
                let mut m = BTreeMap::new();
                m.insert("allow".to_string(), 0.1);
                m.insert("deny".to_string(), 0.9);
                // Include the action itself so validation passes for
                // dynamically-named actions (e.g. "action_0", "action_1").
                m.insert(action.to_string(), 0.1);
                m
            },
            chosen_expected_loss: 0.1,
            calibration_score: 0.85,
            fallback_active: false,
            top_features: vec![("severity".to_string(), 0.6)],
            metadata: BTreeMap::new(),
        }
    }

    /// Build a ledger of N entries for testing.
    fn build_ledger(n: usize) -> Vec<CanonicalEvidenceEntry> {
        let mut emitter = make_emitter();
        let mut cx = mock_cx();
        for i in 0..n {
            let ts = 1_700_000_000_000 + (i as u64) * 1000;
            let req = make_request(&format!("action_{i}"), ts);
            emitter.emit(&mut cx, &req).unwrap();
        }
        emitter.entries().to_vec()
    }

    /// Deterministic replay function that echoes back the recorded values.
    fn identity_replay() -> DecisionReplayFn {
        Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
            action: entry.ledger_entry.action.clone(),
            chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
            calibration_score: entry.ledger_entry.calibration_score,
            fallback_active: entry.ledger_entry.fallback_active,
            expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
        })
    }

    /// Replay function that diverges on the action name.
    fn diverging_action_replay() -> DecisionReplayFn {
        Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
            action: format!("WRONG_{}", entry.ledger_entry.action),
            chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
            calibration_score: entry.ledger_entry.calibration_score,
            fallback_active: entry.ledger_entry.fallback_active,
            expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // ReplayViolationType tests
    // -----------------------------------------------------------------------

    #[test]
    fn violation_type_display() {
        assert_eq!(
            ReplayViolationType::OutcomeDivergence.to_string(),
            "outcome_divergence"
        );
        assert_eq!(ReplayViolationType::SequenceGap.to_string(), "sequence_gap");
        assert_eq!(
            ReplayViolationType::ArtifactHashMismatch.to_string(),
            "artifact_hash_mismatch"
        );
    }

    #[test]
    fn violation_type_serde_roundtrip() {
        let vt = ReplayViolationType::ChainHashMismatch;
        let json = serde_json::to_string(&vt).unwrap();
        let back: ReplayViolationType = serde_json::from_str(&json).unwrap();
        assert_eq!(vt, back);
    }

    // -----------------------------------------------------------------------
    // ReplayConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_values() {
        let cfg = ReplayConfig::default();
        assert!(!cfg.allow_gaps);
        assert!(!cfg.halt_on_first);
        assert_eq!(cfg.progress_interval, 1000);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = ReplayConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ReplayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // -----------------------------------------------------------------------
    // Valid ledger passes replay
    // -----------------------------------------------------------------------

    #[test]
    fn valid_ledger_passes_structural_checks() {
        let ledger = build_ledger(5);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(result.passed);
        assert_eq!(result.entries_processed, 5);
        assert_eq!(result.violations.len(), 0);
    }

    #[test]
    fn valid_ledger_passes_with_identity_replay() {
        let ledger = build_ledger(5);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let replay = identity_replay();
        let result = checker.replay(&ledger, Some(&replay));
        assert!(result.passed);
        assert_eq!(result.entries_processed, 5);
    }

    // -----------------------------------------------------------------------
    // Artifact hash mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_artifact_detected() {
        let mut ledger = build_ledger(3);
        ledger[1].ledger_entry.ts_unix_ms = 999; // tamper
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(!result.passed);
        assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
    }

    // -----------------------------------------------------------------------
    // Chain hash mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_chain_hash_detected() {
        let mut ledger = build_ledger(3);
        ledger[1].chain_hash = ContentHash::compute(b"tampered");
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(!result.passed);
        assert!(result.has_violation(&ReplayViolationType::ChainHashMismatch));
    }

    // -----------------------------------------------------------------------
    // Sequence gap
    // -----------------------------------------------------------------------

    #[test]
    fn sequence_gap_detected() {
        let mut ledger = build_ledger(3);
        ledger[1].sequence = 5; // gap: expected 1, got 5
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(!result.passed);
        assert!(result.has_violation(&ReplayViolationType::SequenceGap));
        let gap_v = result
            .violations
            .iter()
            .find(|v| v.violation_type == ReplayViolationType::SequenceGap)
            .unwrap();
        assert_eq!(gap_v.expected.as_deref(), Some("1"));
        assert_eq!(gap_v.actual.as_deref(), Some("5"));
    }

    #[test]
    fn sequence_gap_allowed_with_config() {
        let mut ledger = build_ledger(3);
        ledger[1].sequence = 5;
        let config = ReplayConfig {
            allow_gaps: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        // Gap is allowed, but chain hash will still fail due to sequence mutation
        assert!(!result.has_violation(&ReplayViolationType::SequenceGap));
        assert_eq!(result.entries_skipped, 4); // skipped seq 1-4
    }

    // -----------------------------------------------------------------------
    // Timestamp monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_out_of_order_detected() {
        let mut ledger = build_ledger(3);
        // Make entry 2's timestamp earlier than entry 1's
        ledger[2].ts_unix_ms = ledger[0].ts_unix_ms - 1;
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
    }

    // -----------------------------------------------------------------------
    // Outcome divergence
    // -----------------------------------------------------------------------

    #[test]
    fn action_name_divergence_detected() {
        let ledger = build_ledger(3);
        let replay = diverging_action_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        assert!(!result.passed);
        assert_eq!(
            result.violation_counts()[&ReplayViolationType::OutcomeDivergence],
            3
        );
    }

    #[test]
    fn calibration_divergence_detected() {
        let ledger = build_ledger(1);
        let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| {
            ReplayedOutcome {
                action: entry.ledger_entry.action.clone(),
                chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
                calibration_score: entry.ledger_entry.calibration_score + 0.5, // diverge
                fallback_active: entry.ledger_entry.fallback_active,
                expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
            }
        });
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        assert!(result.has_violation(&ReplayViolationType::CalibrationDivergence));
    }

    #[test]
    fn expected_loss_divergence_detected() {
        let ledger = build_ledger(1);
        let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| {
            ReplayedOutcome {
                action: entry.ledger_entry.action.clone(),
                chosen_expected_loss: 999.0, // diverge
                calibration_score: entry.ledger_entry.calibration_score,
                fallback_active: entry.ledger_entry.fallback_active,
                expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
            }
        });
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        assert!(result.has_violation(&ReplayViolationType::ExpectedLossDivergence));
    }

    #[test]
    fn fallback_divergence_detected() {
        let ledger = build_ledger(1);
        let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| {
            ReplayedOutcome {
                action: entry.ledger_entry.action.clone(),
                chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
                calibration_score: entry.ledger_entry.calibration_score,
                fallback_active: !entry.ledger_entry.fallback_active, // flip
                expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
            }
        });
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        assert!(result.has_violation(&ReplayViolationType::FallbackDivergence));
    }

    // -----------------------------------------------------------------------
    // Halt on first violation
    // -----------------------------------------------------------------------

    #[test]
    fn halt_on_first_stops_early() {
        let ledger = build_ledger(5);
        let replay = diverging_action_replay();
        let config = ReplayConfig {
            halt_on_first: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, Some(&replay));
        assert!(!result.passed);
        // Should have stopped at first entry.
        assert_eq!(result.violations.len(), 1);
        assert!(result.entries_processed < 5);
    }

    // -----------------------------------------------------------------------
    // Empty ledger
    // -----------------------------------------------------------------------

    #[test]
    fn empty_ledger_passes() {
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&[], None);
        assert!(result.passed);
        assert_eq!(result.entries_processed, 0);
    }

    // -----------------------------------------------------------------------
    // Single entry
    // -----------------------------------------------------------------------

    #[test]
    fn single_entry_passes() {
        let ledger = build_ledger(1);
        let replay = identity_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        assert!(result.passed);
    }

    // -----------------------------------------------------------------------
    // Cross-machine replay (deterministic hash)
    // -----------------------------------------------------------------------

    #[test]
    fn cross_machine_replay_produces_same_hash() {
        let ledger = build_ledger(10);
        let replay = identity_replay();

        let mut checker_a = EvidenceReplayChecker::new(ReplayConfig::default());
        let result_a = checker_a.replay(&ledger, Some(&replay));

        let mut checker_b = EvidenceReplayChecker::new(ReplayConfig::default());
        let result_b = checker_b.replay(&ledger, Some(&replay));

        assert_eq!(result_a.final_rolling_hash, result_b.final_rolling_hash);
        assert!(result_a.passed);
        assert!(result_b.passed);
    }

    // -----------------------------------------------------------------------
    // Large ledger
    // -----------------------------------------------------------------------

    #[test]
    fn large_ledger_replay() {
        let ledger = build_ledger(100);
        let replay = identity_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        assert!(result.passed);
        assert_eq!(result.entries_processed, 100);
    }

    // -----------------------------------------------------------------------
    // Violation counts
    // -----------------------------------------------------------------------

    #[test]
    fn violation_counts_aggregated() {
        let ledger = build_ledger(3);
        let replay = diverging_action_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        let counts = result.violation_counts();
        assert_eq!(counts[&ReplayViolationType::OutcomeDivergence], 3);
    }

    // -----------------------------------------------------------------------
    // Epoch propagation
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_propagated_to_result() {
        let ledger = build_ledger(1);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        checker.set_epoch(SecurityEpoch::from_raw(99));
        let result = checker.replay(&ledger, None);
        assert_eq!(result.epoch, SecurityEpoch::from_raw(99));
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    #[test]
    fn replay_complete_event_emitted() {
        let ledger = build_ledger(3);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(result.passed);
        assert!(!checker.events().is_empty());
        let last = checker.events().last().unwrap();
        assert_eq!(last.event, "replay_complete");
        assert_eq!(last.outcome, "pass");
    }

    #[test]
    fn replay_fail_event_emitted() {
        let ledger = build_ledger(3);
        let replay = diverging_action_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        checker.replay(&ledger, Some(&replay));
        let last = checker.events().last().unwrap();
        assert_eq!(last.event, "replay_complete");
        assert_eq!(last.outcome, "fail");
    }

    // -----------------------------------------------------------------------
    // ReplayResult serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn replay_result_serde_roundtrip() {
        let ledger = build_ledger(3);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        let json = serde_json::to_string(&result).unwrap();
        let back: ReplayResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn replay_violation_serde_roundtrip() {
        let v = ReplayViolation {
            sequence: 42,
            entry_id: "ev-42".to_string(),
            violation_type: ReplayViolationType::OutcomeDivergence,
            error_code: ReplayErrorCode::OutcomeDivergence,
            detail: "test".to_string(),
            expected: Some("a".to_string()),
            actual: Some("b".to_string()),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ReplayViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn replay_event_serde_roundtrip() {
        let e = ReplayEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ReplayEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // -----------------------------------------------------------------------
    // Deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_replay_identical_runs() {
        let run = || {
            let ledger = build_ledger(5);
            let replay = identity_replay();
            let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
            checker.set_epoch(SecurityEpoch::from_raw(1));
            checker.replay(&ledger, Some(&replay))
        };
        let r1 = run();
        let r2 = run();
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // Multiple violation types in one run
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_violation_types_detected() {
        let mut ledger = build_ledger(3);
        // Tamper artifact hash of entry 0.
        ledger[0].ledger_entry.ts_unix_ms = 999;
        // Create sequence gap for entry 2.
        ledger[2].sequence = 10;

        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(!result.passed);
        assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
        assert!(result.has_violation(&ReplayViolationType::SequenceGap));
    }

    // -----------------------------------------------------------------------
    // Epoch regression detection
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_regression_detected() {
        let mut ledger = build_ledger(3);
        // Make entry 2's epoch lower than entry 1's.
        ledger[2].epoch = SecurityEpoch::from_raw(0);
        ledger[1].epoch = SecurityEpoch::from_raw(5);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(result.has_violation(&ReplayViolationType::EpochRegression));
        assert!(result.has_error_code(&ReplayErrorCode::EpochRegression));
    }

    #[test]
    fn epoch_regression_disabled() {
        let mut ledger = build_ledger(3);
        ledger[2].epoch = SecurityEpoch::from_raw(0);
        ledger[1].epoch = SecurityEpoch::from_raw(5);
        let config = ReplayConfig {
            detect_epoch_regression: false,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        assert!(!result.has_violation(&ReplayViolationType::EpochRegression));
    }

    // -----------------------------------------------------------------------
    // Policy version discontinuity violations
    // -----------------------------------------------------------------------

    #[test]
    fn policy_discontinuity_logged_not_violated_by_default() {
        let mut ledger = build_ledger(3);
        ledger[1].policy_id = "policy-v2".to_string();
        ledger[2].policy_id = "policy-v2".to_string();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        // Default: transitions tracked but not violations.
        assert!(!result.has_violation(&ReplayViolationType::PolicyVersionChange));
        assert_eq!(result.diagnostics.policy_transitions.len(), 1);
        assert_eq!(result.diagnostics.policy_versions_seen.len(), 2);
    }

    #[test]
    fn policy_discontinuity_is_violation_when_configured() {
        let mut ledger = build_ledger(3);
        ledger[1].policy_id = "policy-v2".to_string();
        let config = ReplayConfig {
            policy_discontinuity_is_violation: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        assert!(result.has_violation(&ReplayViolationType::PolicyVersionChange));
        assert!(result.has_error_code(&ReplayErrorCode::PolicyVersionDiscontinuity));
    }

    #[test]
    fn policy_allowed_ids_filter_violations() {
        let mut ledger = build_ledger(3);
        let original_policy = ledger[0].policy_id.clone();
        ledger[1].policy_id = "policy-approved".to_string();
        ledger[2].policy_id = "policy-unapproved".to_string();
        let mut allowed = BTreeSet::new();
        allowed.insert(original_policy);
        allowed.insert("policy-approved".to_string());
        let config = ReplayConfig {
            allowed_policy_ids: allowed,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        // Only the unapproved transition should be a violation.
        let policy_violations: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.violation_type == ReplayViolationType::PolicyVersionChange)
            .collect();
        assert_eq!(policy_violations.len(), 1);
        assert_eq!(
            policy_violations[0].actual.as_deref(),
            Some("policy-unapproved")
        );
    }

    // -----------------------------------------------------------------------
    // Schema migration violations
    // -----------------------------------------------------------------------

    #[test]
    fn schema_migration_tracked_not_violated_by_default() {
        let mut ledger = build_ledger(3);
        ledger[2].schema_version = "2.0.0".to_string();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(!result.has_violation(&ReplayViolationType::SchemaMigration));
        assert_eq!(result.diagnostics.schema_migrations.len(), 1);
        assert_eq!(result.diagnostics.schema_versions_seen.len(), 2);
    }

    #[test]
    fn schema_migration_is_violation_when_configured() {
        let mut ledger = build_ledger(3);
        ledger[2].schema_version = "2.0.0".to_string();
        let config = ReplayConfig {
            schema_migration_is_violation: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        assert!(result.has_violation(&ReplayViolationType::SchemaMigration));
        assert!(result.has_error_code(&ReplayErrorCode::SchemaMigrationDetected));
    }

    // -----------------------------------------------------------------------
    // Batch replay and evidence artifact
    // -----------------------------------------------------------------------

    #[test]
    fn replay_and_collect_produces_artifact() {
        let ledger = build_ledger(5);
        let replay = identity_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let artifact = checker.replay_and_collect(&ledger, Some(&replay));
        assert!(artifact.gate_passed);
        assert_eq!(artifact.manifest.source_entry_count, 5);
        assert!(artifact.manifest.passed);
        assert_eq!(artifact.violations.len(), 0);
        assert!(!artifact.events.is_empty());
    }

    #[test]
    fn replay_and_collect_failing_artifact() {
        let ledger = build_ledger(3);
        let replay = diverging_action_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let artifact = checker.replay_and_collect(&ledger, Some(&replay));
        assert!(!artifact.gate_passed);
        assert!(!artifact.manifest.passed);
        assert_eq!(artifact.violations.len(), 3);
    }

    #[test]
    fn evidence_artifact_serde_roundtrip() {
        let ledger = build_ledger(3);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let artifact = checker.replay_and_collect(&ledger, None);
        let json = serde_json::to_string(&artifact).unwrap();
        let back: ReplayEvidenceArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    // -----------------------------------------------------------------------
    // Cross-machine determinism verification
    // -----------------------------------------------------------------------

    #[test]
    fn verify_cross_machine_determinism_passes() {
        let ledger = build_ledger(10);
        let replay = identity_replay();
        let config = ReplayConfig::default();
        assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
            &config,
            &ledger,
            Some(&replay)
        ));
    }

    #[test]
    fn verify_cross_machine_determinism_structural_only() {
        let ledger = build_ledger(20);
        let config = ReplayConfig::default();
        assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
            &config, &ledger, None
        ));
    }

    // -----------------------------------------------------------------------
    // Diagnostics tracking
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostics_track_trace_and_decision_ids() {
        let ledger = build_ledger(5);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(result.diagnostics.distinct_trace_ids > 0);
        assert!(result.diagnostics.distinct_decision_ids > 0);
    }

    #[test]
    fn diagnostics_track_timestamp_range() {
        let ledger = build_ledger(5);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(result.diagnostics.first_ts.is_some());
        assert!(result.diagnostics.last_ts.is_some());
        assert!(result.diagnostics.first_ts.unwrap() <= result.diagnostics.last_ts.unwrap());
    }

    #[test]
    fn diagnostics_track_epoch_range() {
        let ledger = build_ledger(5);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert!(result.diagnostics.epoch_range.is_some());
        let (lo, hi) = result.diagnostics.epoch_range.unwrap();
        assert!(lo <= hi);
    }

    // -----------------------------------------------------------------------
    // Manifest generation
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_reflects_replay_result() {
        let ledger = build_ledger(5);
        let replay = identity_replay();
        let config = ReplayConfig::default();
        let mut checker = EvidenceReplayChecker::new(config.clone());
        let result = checker.replay(&ledger, Some(&replay));
        let manifest = result.manifest(&config, &ledger);
        assert!(manifest.passed);
        assert_eq!(manifest.source_entry_count, 5);
        assert_eq!(manifest.violation_count, 0);
        assert!(manifest.first_entry_hash.is_some());
        assert!(manifest.last_entry_hash.is_some());
        assert_ne!(
            manifest.first_entry_hash.as_ref(),
            manifest.last_entry_hash.as_ref()
        );
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let ledger = build_ledger(3);
        let config = ReplayConfig::default();
        let mut checker = EvidenceReplayChecker::new(config.clone());
        let result = checker.replay(&ledger, None);
        let manifest = result.manifest(&config, &ledger);
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ReplayManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    // -----------------------------------------------------------------------
    // Violations at specific sequence
    // -----------------------------------------------------------------------

    #[test]
    fn violations_at_returns_correct_entries() {
        let ledger = build_ledger(3);
        let replay = diverging_action_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, Some(&replay));
        let at_0 = result.violations_at(0);
        assert_eq!(at_0.len(), 1);
        assert_eq!(
            at_0[0].violation_type,
            ReplayViolationType::OutcomeDivergence
        );
    }

    // -----------------------------------------------------------------------
    // Error code display
    // -----------------------------------------------------------------------

    #[test]
    fn error_code_display_all_variants() {
        assert_eq!(ReplayErrorCode::HashMismatch.to_string(), "HASH_MISMATCH");
        assert_eq!(ReplayErrorCode::ChainBroken.to_string(), "CHAIN_BROKEN");
        assert_eq!(
            ReplayErrorCode::EntryTruncated.to_string(),
            "ENTRY_TRUNCATED"
        );
        assert_eq!(ReplayErrorCode::SequenceGap.to_string(), "SEQUENCE_GAP");
        assert_eq!(
            ReplayErrorCode::TimestampMonotonicityViolation.to_string(),
            "TIMESTAMP_MONOTONICITY_VIOLATION"
        );
        assert_eq!(
            ReplayErrorCode::OutcomeDivergence.to_string(),
            "OUTCOME_DIVERGENCE"
        );
        assert_eq!(
            ReplayErrorCode::CalibrationDivergence.to_string(),
            "CALIBRATION_DIVERGENCE"
        );
        assert_eq!(
            ReplayErrorCode::ExpectedLossDivergence.to_string(),
            "EXPECTED_LOSS_DIVERGENCE"
        );
        assert_eq!(
            ReplayErrorCode::FallbackDivergence.to_string(),
            "FALLBACK_DIVERGENCE"
        );
        assert_eq!(
            ReplayErrorCode::SchemaMigrationDetected.to_string(),
            "SCHEMA_MIGRATION_DETECTED"
        );
        assert_eq!(
            ReplayErrorCode::PolicyVersionDiscontinuity.to_string(),
            "POLICY_VERSION_DISCONTINUITY"
        );
        assert_eq!(
            ReplayErrorCode::EpochRegression.to_string(),
            "EPOCH_REGRESSION"
        );
    }

    // -----------------------------------------------------------------------
    // Violation type display
    // -----------------------------------------------------------------------

    #[test]
    fn violation_type_display_all_variants() {
        assert_eq!(
            ReplayViolationType::OutcomeDivergence.to_string(),
            "outcome_divergence"
        );
        assert_eq!(
            ReplayViolationType::ArtifactHashMismatch.to_string(),
            "artifact_hash_mismatch"
        );
        assert_eq!(
            ReplayViolationType::ChainHashMismatch.to_string(),
            "chain_hash_mismatch"
        );
        assert_eq!(ReplayViolationType::SequenceGap.to_string(), "sequence_gap");
        assert_eq!(
            ReplayViolationType::TimestampMonotonicityViolation.to_string(),
            "timestamp_monotonicity_violation"
        );
        assert_eq!(
            ReplayViolationType::EntryTruncated.to_string(),
            "entry_truncated"
        );
        assert_eq!(
            ReplayViolationType::CalibrationDivergence.to_string(),
            "calibration_divergence"
        );
        assert_eq!(
            ReplayViolationType::ExpectedLossDivergence.to_string(),
            "expected_loss_divergence"
        );
        assert_eq!(
            ReplayViolationType::FallbackDivergence.to_string(),
            "fallback_divergence"
        );
        assert_eq!(
            ReplayViolationType::SchemaMigration.to_string(),
            "schema_migration"
        );
        assert_eq!(
            ReplayViolationType::PolicyVersionChange.to_string(),
            "policy_version_change"
        );
        assert_eq!(
            ReplayViolationType::EpochRegression.to_string(),
            "epoch_regression"
        );
    }

    // -----------------------------------------------------------------------
    // Adversarial inputs
    // -----------------------------------------------------------------------

    #[test]
    fn adversarial_empty_entry_id() {
        let mut ledger = build_ledger(1);
        ledger[0].entry_id = crate::evidence_emission::EvidenceEntryId::new("");
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        // Empty entry_id should not crash; integrity check may fail.
        assert_eq!(result.entries_processed, 1);
    }

    #[test]
    fn adversarial_all_zero_timestamps() {
        let mut ledger = build_ledger(3);
        for entry in &mut ledger {
            entry.ts_unix_ms = 0;
        }
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        // All-zero timestamps are monotonically non-decreasing.
        assert!(!result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
    }

    #[test]
    fn adversarial_duplicate_sequences() {
        let mut ledger = build_ledger(3);
        ledger[1].sequence = 0; // same as entry 0
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        // Duplicate sequence (0, 0) means gap: expected 1, got 0.
        // The checker should detect this as a chain or sequence issue.
        assert!(!result.passed);
    }

    #[test]
    fn adversarial_max_epoch() {
        let mut ledger = build_ledger(1);
        ledger[0].epoch = SecurityEpoch::from_raw(u64::MAX);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        // Should not panic on max epoch.
        assert_eq!(result.entries_processed, 1);
    }

    #[test]
    fn adversarial_very_large_sequence_gap() {
        let mut ledger = build_ledger(2);
        ledger[1].sequence = u64::MAX;
        let config = ReplayConfig {
            allow_gaps: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        // Should handle very large gap without panic.
        assert!(result.entries_skipped > 0);
    }

    // -----------------------------------------------------------------------
    // Config edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn config_new_fields_serde_roundtrip() {
        let mut config = ReplayConfig {
            policy_discontinuity_is_violation: true,
            schema_migration_is_violation: true,
            ..Default::default()
        };
        config.allowed_policy_ids.insert("p1".to_string());
        config.allowed_policy_ids.insert("p2".to_string());
        let json = serde_json::to_string(&config).unwrap();
        let back: ReplayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -----------------------------------------------------------------------
    // Structured events for violations
    // -----------------------------------------------------------------------

    #[test]
    fn policy_discontinuity_emits_structured_event() {
        let mut ledger = build_ledger(3);
        ledger[1].policy_id = "policy-v2".to_string();
        ledger[2].policy_id = "policy-v2".to_string();
        let config = ReplayConfig {
            policy_discontinuity_is_violation: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        checker.replay(&ledger, None);
        let events = checker.events();
        let policy_events: Vec<_> = events
            .iter()
            .filter(|e| e.event == "policy_version_discontinuity")
            .collect();
        assert_eq!(policy_events.len(), 1);
        assert_eq!(policy_events[0].outcome, "fail");
        assert_eq!(
            policy_events[0].error_code.as_deref(),
            Some("POLICY_VERSION_DISCONTINUITY")
        );
    }

    #[test]
    fn schema_migration_violation_emits_structured_event() {
        let mut ledger = build_ledger(3);
        ledger[2].schema_version = "2.0.0".to_string();
        let config = ReplayConfig {
            schema_migration_is_violation: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        checker.replay(&ledger, None);
        let events = checker.events();
        let migration_events: Vec<_> = events
            .iter()
            .filter(|e| e.event == "schema_migration_violation")
            .collect();
        assert_eq!(migration_events.len(), 1);
        assert_eq!(migration_events[0].outcome, "fail");
    }

    #[test]
    fn non_violation_schema_migration_emits_info_event() {
        let mut ledger = build_ledger(3);
        ledger[2].schema_version = "2.0.0".to_string();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        checker.replay(&ledger, None);
        let events = checker.events();
        let migration_events: Vec<_> = events
            .iter()
            .filter(|e| e.event == "schema_migration_boundary")
            .collect();
        assert_eq!(migration_events.len(), 1);
        assert_eq!(migration_events[0].outcome, "info");
    }

    // -----------------------------------------------------------------------
    // Diagnostics serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostics_serde_roundtrip() {
        let ledger = build_ledger(5);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        let json = serde_json::to_string(&result.diagnostics).unwrap();
        let back: ReplayDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(result.diagnostics, back);
    }

    // -----------------------------------------------------------------------
    // Halt-on-first with various violation types
    // -----------------------------------------------------------------------

    #[test]
    fn halt_on_first_stops_at_epoch_regression() {
        let mut ledger = build_ledger(5);
        ledger[1].epoch = SecurityEpoch::from_raw(10);
        ledger[2].epoch = SecurityEpoch::from_raw(1); // regression
        let config = ReplayConfig {
            halt_on_first: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        assert!(!result.passed);
        // Should stop after detecting the regression.
        assert!(result.entries_processed < 5);
    }

    #[test]
    fn halt_on_first_stops_at_policy_discontinuity() {
        let mut ledger = build_ledger(5);
        ledger[1].policy_id = "new-policy".to_string();
        let config = ReplayConfig {
            halt_on_first: true,
            policy_discontinuity_is_violation: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        assert!(!result.passed);
        assert!(result.entries_processed < 5);
    }

    #[test]
    fn halt_on_first_stops_at_schema_migration_violation() {
        let mut ledger = build_ledger(5);
        ledger[1].schema_version = "2.0.0".to_string();
        let config = ReplayConfig {
            halt_on_first: true,
            schema_migration_is_violation: true,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        let result = checker.replay(&ledger, None);
        assert!(!result.passed);
        assert!(result.entries_processed < 5);
    }

    // -----------------------------------------------------------------------
    // Checker state persistence via serde
    // -----------------------------------------------------------------------

    #[test]
    fn checker_serde_roundtrip() {
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        checker.set_epoch(SecurityEpoch::from_raw(42));
        let json = serde_json::to_string(&checker).unwrap();
        let back: EvidenceReplayChecker = serde_json::from_str(&json).unwrap();
        assert_eq!(checker.config(), back.config());
        assert_eq!(checker.events().len(), back.events().len());
    }

    // -----------------------------------------------------------------------
    // Multiple schema migrations in one ledger
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_schema_migrations_all_tracked() {
        let mut ledger = build_ledger(5);
        ledger[1].schema_version = "2.0.0".to_string();
        ledger[2].schema_version = "2.0.0".to_string();
        ledger[3].schema_version = "3.0.0".to_string();
        ledger[4].schema_version = "3.0.0".to_string();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert_eq!(result.diagnostics.schema_migrations.len(), 2);
        assert_eq!(result.diagnostics.schema_versions_seen.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Multiple policy transitions in one ledger
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_policy_transitions_all_tracked() {
        let mut ledger = build_ledger(5);
        ledger[1].policy_id = "pol-v2".to_string();
        ledger[2].policy_id = "pol-v2".to_string();
        ledger[3].policy_id = "pol-v3".to_string();
        ledger[4].policy_id = "pol-v3".to_string();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let result = checker.replay(&ledger, None);
        assert_eq!(result.diagnostics.policy_transitions.len(), 2);
        assert_eq!(result.diagnostics.policy_versions_seen.len(), 3);
    }

    // -----------------------------------------------------------------------
    // ReplayEvidenceArtifact serde roundtrip (comprehensive)
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_artifact_with_violations_serde_roundtrip() {
        let ledger = build_ledger(3);
        let replay = diverging_action_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let artifact = checker.replay_and_collect(&ledger, Some(&replay));
        assert!(!artifact.gate_passed);
        let json = serde_json::to_string(&artifact).unwrap();
        let back: ReplayEvidenceArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    // -----------------------------------------------------------------------
    // Events cleared between runs
    // -----------------------------------------------------------------------

    #[test]
    fn replay_and_collect_clears_events_between_runs() {
        let ledger = build_ledger(3);
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        let art1 = checker.replay_and_collect(&ledger, None);
        let art2 = checker.replay_and_collect(&ledger, None);
        // Events should be identical between runs (cleared before each).
        assert_eq!(art1.events.len(), art2.events.len());
    }

    #[test]
    fn replay_error_code_ord() {
        assert!(ReplayErrorCode::HashMismatch < ReplayErrorCode::ChainBroken);
        assert!(ReplayErrorCode::ChainBroken < ReplayErrorCode::EntryTruncated);
        assert!(ReplayErrorCode::SequenceGap < ReplayErrorCode::TimestampMonotonicityViolation);
        assert!(
            ReplayErrorCode::SchemaMigrationDetected < ReplayErrorCode::PolicyVersionDiscontinuity
        );
        assert!(ReplayErrorCode::PolicyVersionDiscontinuity < ReplayErrorCode::EpochRegression);
    }

    #[test]
    fn replay_violation_type_ord() {
        assert!(ReplayViolationType::OutcomeDivergence < ReplayViolationType::ArtifactHashMismatch);
        assert!(ReplayViolationType::ArtifactHashMismatch < ReplayViolationType::ChainHashMismatch);
        assert!(
            ReplayViolationType::SequenceGap < ReplayViolationType::TimestampMonotonicityViolation
        );
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn replay_error_code_serde_all_variants() {
        let variants = [
            ReplayErrorCode::HashMismatch,
            ReplayErrorCode::ChainBroken,
            ReplayErrorCode::EntryTruncated,
            ReplayErrorCode::SequenceGap,
            ReplayErrorCode::TimestampMonotonicityViolation,
            ReplayErrorCode::OutcomeDivergence,
            ReplayErrorCode::CalibrationDivergence,
            ReplayErrorCode::ExpectedLossDivergence,
            ReplayErrorCode::FallbackDivergence,
            ReplayErrorCode::SchemaMigrationDetected,
            ReplayErrorCode::PolicyVersionDiscontinuity,
            ReplayErrorCode::EpochRegression,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 12);
    }

    #[test]
    fn replay_violation_type_serde_all_variants() {
        let variants = [
            ReplayViolationType::OutcomeDivergence,
            ReplayViolationType::ArtifactHashMismatch,
            ReplayViolationType::ChainHashMismatch,
            ReplayViolationType::SequenceGap,
            ReplayViolationType::TimestampMonotonicityViolation,
            ReplayViolationType::EntryTruncated,
            ReplayViolationType::CalibrationDivergence,
            ReplayViolationType::ExpectedLossDivergence,
            ReplayViolationType::FallbackDivergence,
            ReplayViolationType::SchemaMigration,
            ReplayViolationType::PolicyVersionChange,
            ReplayViolationType::EpochRegression,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReplayViolationType = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 12);
    }

    #[test]
    fn replay_error_code_display_all_distinct() {
        let variants = [
            ReplayErrorCode::HashMismatch,
            ReplayErrorCode::ChainBroken,
            ReplayErrorCode::EntryTruncated,
            ReplayErrorCode::SequenceGap,
            ReplayErrorCode::TimestampMonotonicityViolation,
            ReplayErrorCode::OutcomeDivergence,
            ReplayErrorCode::CalibrationDivergence,
            ReplayErrorCode::ExpectedLossDivergence,
            ReplayErrorCode::FallbackDivergence,
            ReplayErrorCode::SchemaMigrationDetected,
            ReplayErrorCode::PolicyVersionDiscontinuity,
            ReplayErrorCode::EpochRegression,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.to_string()), "duplicate display: {v}");
        }
        assert_eq!(seen.len(), 12);
    }

    #[test]
    fn replay_violation_type_display_all_distinct() {
        let variants = [
            ReplayViolationType::OutcomeDivergence,
            ReplayViolationType::ArtifactHashMismatch,
            ReplayViolationType::ChainHashMismatch,
            ReplayViolationType::SequenceGap,
            ReplayViolationType::TimestampMonotonicityViolation,
            ReplayViolationType::EntryTruncated,
            ReplayViolationType::CalibrationDivergence,
            ReplayViolationType::ExpectedLossDivergence,
            ReplayViolationType::FallbackDivergence,
            ReplayViolationType::SchemaMigration,
            ReplayViolationType::PolicyVersionChange,
            ReplayViolationType::EpochRegression,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.to_string()), "duplicate display: {v}");
        }
        assert_eq!(seen.len(), 12);
    }
}
