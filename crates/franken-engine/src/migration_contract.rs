//! Migration contract for explicit cutover boundaries on security-critical
//! formats and policies.
//!
//! When schemas, serialization formats, key types, or policy structures change
//! between versions, the migration must be an explicit, auditable, deterministic
//! cutover — not a hidden translator or compatibility shim.
//!
//! # Cutover types
//!
//! - **Hard cutover**: all objects must be in the new format after migration;
//!   old-format objects are rejected.
//! - **Soft migration**: both old and new formats are accepted during a
//!   transition window with a declared end.
//! - **Parallel run**: both old and new format pipelines run simultaneously
//!   with output comparison during validation; discrepancies abort the migration.
//!
//! # Execution steps
//!
//! 1. Pre-migration: validate all existing data can be converted (dry run).
//! 2. Checkpoint: create a checkpoint marking the migration epoch boundary.
//! 3. Execute: convert existing data or activate new-format acceptance.
//! 4. Verify: run conformance checks against migrated data.
//! 5. Commit: mark migration as complete; begin rejecting old format (hard cutover).
//!
//! Plan reference: Section 10.10 item 29, bd-29s.
//! Dependencies: bd-1p4 (activation lifecycle for rollback primitives).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT: &str = "migration_contract";

// ---------------------------------------------------------------------------
// Cutover types
// ---------------------------------------------------------------------------

/// Type of cutover strategy for a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CutoverType {
    /// All objects must be in the new format after migration.
    HardCutover,
    /// Both old and new formats accepted during a transition window.
    SoftMigration,
    /// Both pipelines run in parallel; discrepancies abort.
    ParallelRun,
}

impl fmt::Display for CutoverType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardCutover => write!(f, "hard_cutover"),
            Self::SoftMigration => write!(f, "soft_migration"),
            Self::ParallelRun => write!(f, "parallel_run"),
        }
    }
}

// ---------------------------------------------------------------------------
// Object classes affected by migrations
// ---------------------------------------------------------------------------

/// Security-critical object classes that may undergo format migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObjectClass {
    SerializationSchema,
    KeyFormat,
    TokenFormat,
    CheckpointFormat,
    RevocationFormat,
    PolicyStructure,
    EvidenceFormat,
    AttestationFormat,
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationSchema => write!(f, "serialization_schema"),
            Self::KeyFormat => write!(f, "key_format"),
            Self::TokenFormat => write!(f, "token_format"),
            Self::CheckpointFormat => write!(f, "checkpoint_format"),
            Self::RevocationFormat => write!(f, "revocation_format"),
            Self::PolicyStructure => write!(f, "policy_structure"),
            Self::EvidenceFormat => write!(f, "evidence_format"),
            Self::AttestationFormat => write!(f, "attestation_format"),
        }
    }
}

impl ObjectClass {
    pub const ALL: [ObjectClass; 8] = [
        Self::SerializationSchema,
        Self::KeyFormat,
        Self::TokenFormat,
        Self::CheckpointFormat,
        Self::RevocationFormat,
        Self::PolicyStructure,
        Self::EvidenceFormat,
        Self::AttestationFormat,
    ];
}

// ---------------------------------------------------------------------------
// Migration declaration
// ---------------------------------------------------------------------------

/// Declaration of a migration: what changes, how, and what is compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationDeclaration {
    /// Unique identifier for this migration.
    pub migration_id: String,
    /// Source format version.
    pub from_version: String,
    /// Target format version.
    pub to_version: String,
    /// Object classes affected by this migration.
    pub affected_objects: Vec<ObjectClass>,
    /// Cutover strategy.
    pub cutover_type: CutoverType,
    /// Human-readable description.
    pub description: String,
    /// Compatibility boundary: what IS compatible across the migration.
    pub compatible_across: Vec<String>,
    /// Compatibility boundary: what is NOT compatible.
    pub incompatible_across: Vec<String>,
    /// For soft migration: tick at which old format is rejected.
    pub transition_end_tick: Option<u64>,
}

// ---------------------------------------------------------------------------
// Migration execution steps
// ---------------------------------------------------------------------------

/// Steps in the migration execution pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MigrationStep {
    /// Validate all data can be converted (dry run).
    PreMigration,
    /// Create epoch-boundary checkpoint.
    Checkpoint,
    /// Convert or activate new-format acceptance.
    Execute,
    /// Run conformance checks on migrated data.
    Verify,
    /// Mark migration as complete.
    Commit,
    /// Rollback to pre-migration state.
    Rollback,
}

impl fmt::Display for MigrationStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreMigration => write!(f, "pre_migration"),
            Self::Checkpoint => write!(f, "checkpoint"),
            Self::Execute => write!(f, "execute"),
            Self::Verify => write!(f, "verify"),
            Self::Commit => write!(f, "commit"),
            Self::Rollback => write!(f, "rollback"),
        }
    }
}

impl MigrationStep {
    /// Normal forward pipeline order.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::PreMigration => Some(Self::Checkpoint),
            Self::Checkpoint => Some(Self::Execute),
            Self::Execute => Some(Self::Verify),
            Self::Verify => Some(Self::Commit),
            Self::Commit => None,
            Self::Rollback => None,
        }
    }

    pub const FORWARD_PIPELINE: [MigrationStep; 5] = [
        Self::PreMigration,
        Self::Checkpoint,
        Self::Execute,
        Self::Verify,
        Self::Commit,
    ];
}

// ---------------------------------------------------------------------------
// Migration state
// ---------------------------------------------------------------------------

/// Current state of a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MigrationState {
    /// Declared but not started.
    Declared,
    /// Pre-migration dry run in progress.
    DryRunning,
    /// Dry run passed, awaiting checkpoint.
    DryRunPassed,
    /// Dry run failed.
    DryRunFailed,
    /// Checkpoint created, executing migration.
    Executing,
    /// Execution complete, verifying.
    Verifying,
    /// Verification passed, awaiting commit.
    Verified,
    /// Verification failed.
    VerificationFailed,
    /// Migration committed (terminal success).
    Committed,
    /// Rolling back.
    RollingBack,
    /// Rolled back (terminal).
    RolledBack,
}

impl fmt::Display for MigrationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declared => write!(f, "declared"),
            Self::DryRunning => write!(f, "dry_running"),
            Self::DryRunPassed => write!(f, "dry_run_passed"),
            Self::DryRunFailed => write!(f, "dry_run_failed"),
            Self::Executing => write!(f, "executing"),
            Self::Verifying => write!(f, "verifying"),
            Self::Verified => write!(f, "verified"),
            Self::VerificationFailed => write!(f, "verification_failed"),
            Self::Committed => write!(f, "committed"),
            Self::RollingBack => write!(f, "rolling_back"),
            Self::RolledBack => write!(f, "rolled_back"),
        }
    }
}

impl MigrationState {
    /// Whether this is a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::RolledBack | Self::DryRunFailed
        )
    }
}

// ---------------------------------------------------------------------------
// Migration errors
// ---------------------------------------------------------------------------

/// Errors during migration execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationContractError {
    /// Migration not found.
    MigrationNotFound { migration_id: String },
    /// Invalid state transition.
    InvalidTransition {
        from: MigrationState,
        to: MigrationState,
    },
    /// Dry run found objects that cannot be converted.
    DryRunFailed {
        migration_id: String,
        unconvertible_count: usize,
        detail: String,
    },
    /// Verification found discrepancies.
    VerificationFailed {
        migration_id: String,
        discrepancy_count: usize,
        detail: String,
    },
    /// Old-format object rejected after hard cutover.
    OldFormatRejected {
        migration_id: String,
        object_class: ObjectClass,
        detail: String,
    },
    /// Migration already exists.
    DuplicateMigration { migration_id: String },
    /// Rollback failed.
    RollbackFailed {
        migration_id: String,
        detail: String,
    },
    /// Parallel run discrepancy detected.
    ParallelRunDiscrepancy {
        migration_id: String,
        discrepancy_count: usize,
    },
}

impl fmt::Display for MigrationContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MigrationNotFound { migration_id } => {
                write!(f, "migration not found: {migration_id}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} -> {to}")
            }
            Self::DryRunFailed {
                migration_id,
                unconvertible_count,
                detail,
            } => {
                write!(
                    f,
                    "dry run failed for {migration_id}: {unconvertible_count} unconvertible: {detail}"
                )
            }
            Self::VerificationFailed {
                migration_id,
                discrepancy_count,
                detail,
            } => {
                write!(
                    f,
                    "verification failed for {migration_id}: {discrepancy_count} discrepancies: {detail}"
                )
            }
            Self::OldFormatRejected {
                migration_id,
                object_class,
                detail,
            } => {
                write!(
                    f,
                    "old format {object_class} rejected after {migration_id}: {detail}"
                )
            }
            Self::DuplicateMigration { migration_id } => {
                write!(f, "duplicate migration: {migration_id}")
            }
            Self::RollbackFailed {
                migration_id,
                detail,
            } => {
                write!(f, "rollback failed for {migration_id}: {detail}")
            }
            Self::ParallelRunDiscrepancy {
                migration_id,
                discrepancy_count,
            } => {
                write!(
                    f,
                    "parallel run discrepancy for {migration_id}: {discrepancy_count}"
                )
            }
        }
    }
}

impl std::error::Error for MigrationContractError {}

/// Stable error codes.
pub fn error_code(err: &MigrationContractError) -> &'static str {
    match err {
        MigrationContractError::MigrationNotFound { .. } => "MC_MIGRATION_NOT_FOUND",
        MigrationContractError::InvalidTransition { .. } => "MC_INVALID_TRANSITION",
        MigrationContractError::DryRunFailed { .. } => "MC_DRY_RUN_FAILED",
        MigrationContractError::VerificationFailed { .. } => "MC_VERIFICATION_FAILED",
        MigrationContractError::OldFormatRejected { .. } => "MC_OLD_FORMAT_REJECTED",
        MigrationContractError::DuplicateMigration { .. } => "MC_DUPLICATE_MIGRATION",
        MigrationContractError::RollbackFailed { .. } => "MC_ROLLBACK_FAILED",
        MigrationContractError::ParallelRunDiscrepancy { .. } => "MC_PARALLEL_DISCREPANCY",
    }
}

// ---------------------------------------------------------------------------
// Migration audit events
// ---------------------------------------------------------------------------

/// Structured audit event emitted during migration operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub migration_id: Option<String>,
    pub step: Option<String>,
    pub affected_count: Option<usize>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub timestamp: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Dry run result
// ---------------------------------------------------------------------------

/// Result of a pre-migration dry run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunResult {
    pub migration_id: String,
    pub total_objects: usize,
    pub convertible: usize,
    pub unconvertible: usize,
    pub details: Vec<String>,
}

impl DryRunResult {
    pub fn passed(&self) -> bool {
        self.unconvertible == 0
    }
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/// Result of post-migration conformance verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub migration_id: String,
    pub objects_checked: usize,
    pub discrepancies: usize,
    pub details: Vec<String>,
}

impl VerificationResult {
    pub fn passed(&self) -> bool {
        self.discrepancies == 0
    }
}

// ---------------------------------------------------------------------------
// Migration entry (internal state)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationEntry {
    declaration: MigrationDeclaration,
    state: MigrationState,
    checkpoint_seq: Option<u64>,
    started_at: Option<DeterministicTimestamp>,
    completed_at: Option<DeterministicTimestamp>,
    dry_run_result: Option<DryRunResult>,
    verification_result: Option<VerificationResult>,
}

// ---------------------------------------------------------------------------
// Migration registry (persistent, ordered list of applied migrations)
// ---------------------------------------------------------------------------

/// Append-only record of a completed migration in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedMigrationRecord {
    pub migration_id: String,
    pub from_version: String,
    pub to_version: String,
    pub cutover_type: CutoverType,
    pub affected_objects: Vec<ObjectClass>,
    pub applied_at: DeterministicTimestamp,
    pub checkpoint_seq: u64,
}

// ---------------------------------------------------------------------------
// MigrationRunner — the orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the multi-step migration process with rollback support.
#[derive(Debug)]
pub struct MigrationRunner {
    migrations: Vec<MigrationEntry>,
    applied: Vec<AppliedMigrationRecord>,
    events: Vec<MigrationEvent>,
    current_tick: u64,
}

impl MigrationRunner {
    pub fn new() -> Self {
        Self {
            migrations: Vec::new(),
            applied: Vec::new(),
            events: Vec::new(),
            current_tick: 0,
        }
    }

    /// Set current logical tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Number of declared migrations.
    pub fn migration_count(&self) -> usize {
        self.migrations.len()
    }

    /// Number of applied (committed) migrations.
    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    /// Applied migration records.
    pub fn applied_migrations(&self) -> &[AppliedMigrationRecord] {
        &self.applied
    }

    /// Get the state of a migration.
    pub fn state(&self, migration_id: &str) -> Option<MigrationState> {
        self.find_entry(migration_id).map(|e| e.state)
    }

    // -- Declare ----------------------------------------------------------

    /// Declare a new migration.
    pub fn declare(
        &mut self,
        declaration: MigrationDeclaration,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        if self.find_entry(&declaration.migration_id).is_some() {
            return Err(MigrationContractError::DuplicateMigration {
                migration_id: declaration.migration_id.clone(),
            });
        }

        let mid = declaration.migration_id.clone();
        self.migrations.push(MigrationEntry {
            declaration,
            state: MigrationState::Declared,
            checkpoint_seq: None,
            started_at: None,
            completed_at: None,
            dry_run_result: None,
            verification_result: None,
        });

        self.push_event(trace_id, "migration_declared", "ok", None, Some(&mid), None);
        Ok(())
    }

    // -- Pre-migration (dry run) ------------------------------------------

    /// Execute a dry run to validate all data can be converted.
    pub fn dry_run(
        &mut self,
        migration_id: &str,
        result: DryRunResult,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Declared {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::DryRunning,
            });
        }

        let passed = result.passed();
        entry.dry_run_result = Some(result.clone());

        if passed {
            entry.state = MigrationState::DryRunPassed;
            let _ = entry;
            self.push_event(
                trace_id,
                "dry_run_complete",
                "pass",
                None,
                Some(migration_id),
                Some(result.total_objects),
            );
        } else {
            entry.state = MigrationState::DryRunFailed;
            let _ = entry;
            self.push_event(
                trace_id,
                "dry_run_complete",
                "fail",
                Some("MC_DRY_RUN_FAILED"),
                Some(migration_id),
                Some(result.unconvertible),
            );
            return Err(MigrationContractError::DryRunFailed {
                migration_id: migration_id.to_string(),
                unconvertible_count: result.unconvertible,
                detail: result.details.join("; "),
            });
        }

        Ok(())
    }

    // -- Checkpoint -------------------------------------------------------

    /// Record the epoch-boundary checkpoint and transition to Executing.
    pub fn create_checkpoint(
        &mut self,
        migration_id: &str,
        checkpoint_seq: u64,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let tick = self.current_tick;
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::DryRunPassed {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Executing,
            });
        }

        entry.state = MigrationState::Executing;
        entry.checkpoint_seq = Some(checkpoint_seq);
        entry.started_at = Some(DeterministicTimestamp(tick));
        let _ = entry;

        self.push_event(
            trace_id,
            "checkpoint_created",
            "ok",
            None,
            Some(migration_id),
            None,
        );
        Ok(())
    }

    // -- Execute ----------------------------------------------------------

    /// Mark execution as complete, transition to Verifying.
    pub fn complete_execution(
        &mut self,
        migration_id: &str,
        affected_count: usize,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Executing {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Verifying,
            });
        }

        entry.state = MigrationState::Verifying;
        let _ = entry;

        self.push_event(
            trace_id,
            "execution_complete",
            "ok",
            None,
            Some(migration_id),
            Some(affected_count),
        );
        Ok(())
    }

    // -- Verify -----------------------------------------------------------

    /// Submit verification result.
    pub fn verify(
        &mut self,
        migration_id: &str,
        result: VerificationResult,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Verifying {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Verified,
            });
        }

        let passed = result.passed();
        entry.verification_result = Some(result.clone());

        if passed {
            entry.state = MigrationState::Verified;
            let _ = entry;
            self.push_event(
                trace_id,
                "verification_complete",
                "pass",
                None,
                Some(migration_id),
                Some(result.objects_checked),
            );
        } else {
            entry.state = MigrationState::VerificationFailed;
            let _ = entry;
            self.push_event(
                trace_id,
                "verification_complete",
                "fail",
                Some("MC_VERIFICATION_FAILED"),
                Some(migration_id),
                Some(result.discrepancies),
            );
            return Err(MigrationContractError::VerificationFailed {
                migration_id: migration_id.to_string(),
                discrepancy_count: result.discrepancies,
                detail: result.details.join("; "),
            });
        }

        Ok(())
    }

    // -- Commit -----------------------------------------------------------

    /// Commit the migration. After this, old format may be rejected
    /// (for hard cutover).
    pub fn commit(
        &mut self,
        migration_id: &str,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let tick = self.current_tick;
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Verified {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Committed,
            });
        }

        entry.state = MigrationState::Committed;
        entry.completed_at = Some(DeterministicTimestamp(tick));

        let record = AppliedMigrationRecord {
            migration_id: entry.declaration.migration_id.clone(),
            from_version: entry.declaration.from_version.clone(),
            to_version: entry.declaration.to_version.clone(),
            cutover_type: entry.declaration.cutover_type,
            affected_objects: entry.declaration.affected_objects.clone(),
            applied_at: DeterministicTimestamp(tick),
            checkpoint_seq: entry.checkpoint_seq.unwrap_or(0),
        };
        let _ = entry;

        self.applied.push(record);
        self.push_event(
            trace_id,
            "migration_committed",
            "ok",
            None,
            Some(migration_id),
            None,
        );
        Ok(())
    }

    // -- Rollback ---------------------------------------------------------

    /// Roll back a migration to its pre-migration state.
    pub fn rollback(
        &mut self,
        migration_id: &str,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let tick = self.current_tick;
        let entry = self.find_entry_mut(migration_id)?;
        let old_state = entry.state;

        // Can only rollback from non-terminal, non-declared, non-committed states.
        if old_state.is_terminal() || old_state == MigrationState::Declared {
            return Err(MigrationContractError::InvalidTransition {
                from: old_state,
                to: MigrationState::RollingBack,
            });
        }

        entry.state = MigrationState::RollingBack;

        self.push_event(
            trace_id,
            "rollback_started",
            "ok",
            None,
            Some(migration_id),
            None,
        );

        let entry = self.find_entry_mut(migration_id)?;
        entry.state = MigrationState::RolledBack;
        entry.completed_at = Some(DeterministicTimestamp(tick));

        self.push_event(
            trace_id,
            "rollback_complete",
            "ok",
            None,
            Some(migration_id),
            None,
        );
        Ok(())
    }

    // -- Format enforcement -----------------------------------------------

    /// Check if an old-format object should be rejected based on committed
    /// hard-cutover migrations. Returns `Ok(())` if accepted, or an error
    /// if a committed hard cutover rejects the old format.
    pub fn check_format_acceptance(
        &self,
        object_class: ObjectClass,
        format_version: &str,
    ) -> Result<(), MigrationContractError> {
        for record in &self.applied {
            if record.cutover_type == CutoverType::HardCutover
                && record.affected_objects.contains(&object_class)
                && record.from_version == format_version
            {
                return Err(MigrationContractError::OldFormatRejected {
                    migration_id: record.migration_id.clone(),
                    object_class,
                    detail: format!(
                        "hard cutover {} -> {} rejects old format {}",
                        record.from_version, record.to_version, format_version
                    ),
                });
            }
        }
        Ok(())
    }

    /// Check format acceptance for soft migration with transition window.
    pub fn check_soft_migration_window(&self, migration_id: &str) -> Option<bool> {
        let entry = self.find_entry(migration_id)?;
        if entry.declaration.cutover_type != CutoverType::SoftMigration {
            return None;
        }
        if entry.state != MigrationState::Committed {
            return Some(true); // Not committed yet, old format still accepted.
        }
        let end_tick = entry.declaration.transition_end_tick?;
        Some(self.current_tick < end_tick)
    }

    // -- Accessors --------------------------------------------------------

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<MigrationEvent> {
        std::mem::take(&mut self.events)
    }

    /// Accumulated events.
    pub fn events(&self) -> &[MigrationEvent] {
        &self.events
    }

    /// Get the declaration for a migration.
    pub fn declaration(&self, migration_id: &str) -> Option<&MigrationDeclaration> {
        self.find_entry(migration_id).map(|e| &e.declaration)
    }

    /// Summary of all migrations and their states.
    pub fn summary(&self) -> BTreeMap<String, MigrationState> {
        let mut result = BTreeMap::new();
        for entry in &self.migrations {
            result.insert(entry.declaration.migration_id.clone(), entry.state);
        }
        result
    }

    // -- Internal ---------------------------------------------------------

    fn find_entry(&self, migration_id: &str) -> Option<&MigrationEntry> {
        self.migrations
            .iter()
            .find(|e| e.declaration.migration_id == migration_id)
    }

    fn find_entry_mut(
        &mut self,
        migration_id: &str,
    ) -> Result<&mut MigrationEntry, MigrationContractError> {
        self.migrations
            .iter_mut()
            .find(|e| e.declaration.migration_id == migration_id)
            .ok_or_else(|| MigrationContractError::MigrationNotFound {
                migration_id: migration_id.to_string(),
            })
    }

    fn push_event(
        &mut self,
        trace_id: &str,
        event: &str,
        outcome: &str,
        err_code: Option<&str>,
        migration_id: Option<&str>,
        affected_count: Option<usize>,
    ) {
        let (from_ver, to_ver) = migration_id
            .and_then(|mid| self.find_entry(mid))
            .map(|e| {
                (
                    Some(e.declaration.from_version.clone()),
                    Some(e.declaration.to_version.clone()),
                )
            })
            .unwrap_or((None, None));

        self.events.push(MigrationEvent {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: err_code.map(str::to_string),
            migration_id: migration_id.map(str::to_string),
            step: None,
            affected_count,
            from_version: from_ver,
            to_version: to_ver,
            timestamp: DeterministicTimestamp(self.current_tick),
        });
    }
}

impl Default for MigrationRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers ----------------------------------------------------------

    fn make_declaration(id: &str, cutover: CutoverType) -> MigrationDeclaration {
        MigrationDeclaration {
            migration_id: id.to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            affected_objects: vec![ObjectClass::SerializationSchema, ObjectClass::KeyFormat],
            cutover_type: cutover,
            description: format!("test migration {id}"),
            compatible_across: vec!["wire_format".to_string()],
            incompatible_across: vec!["storage_format".to_string()],
            transition_end_tick: if cutover == CutoverType::SoftMigration {
                Some(1000)
            } else {
                None
            },
        }
    }

    fn passing_dry_run(mid: &str) -> DryRunResult {
        DryRunResult {
            migration_id: mid.to_string(),
            total_objects: 100,
            convertible: 100,
            unconvertible: 0,
            details: Vec::new(),
        }
    }

    fn failing_dry_run(mid: &str) -> DryRunResult {
        DryRunResult {
            migration_id: mid.to_string(),
            total_objects: 100,
            convertible: 90,
            unconvertible: 10,
            details: vec!["10 objects have incompatible field X".to_string()],
        }
    }

    fn passing_verification(mid: &str) -> VerificationResult {
        VerificationResult {
            migration_id: mid.to_string(),
            objects_checked: 100,
            discrepancies: 0,
            details: Vec::new(),
        }
    }

    fn failing_verification(mid: &str) -> VerificationResult {
        VerificationResult {
            migration_id: mid.to_string(),
            objects_checked: 100,
            discrepancies: 5,
            details: vec!["5 objects failed conformance".to_string()],
        }
    }

    fn run_full_pipeline(runner: &mut MigrationRunner, mid: &str, cutover: CutoverType) {
        // SAFETY: Test helper uses valid declaration; declare succeeds in controlled test environment.
        // SAFETY: Test helper uses valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration(mid, cutover), "trace-1")
            .expect("serde deserialization should succeed");
        // SAFETY: Test helper uses valid dry run; dry_run succeeds in controlled test environment.
        runner
            .dry_run(mid, passing_dry_run(mid), "trace-1")
            .expect("serde deserialization should succeed");
        // SAFETY: Test helper uses valid checkpoint; create_checkpoint succeeds in controlled test environment.
        runner
            .create_checkpoint(mid, 42, "trace-1")
            .expect("serde deserialization should succeed");
        // SAFETY: Test helper uses valid execution; complete_execution succeeds in controlled test environment.
        runner
            .complete_execution(mid, 100, "trace-1")
            .expect("serde deserialization should succeed");
        // SAFETY: Test helper uses valid verification; verify succeeds in controlled test environment.
        runner
            .verify(mid, passing_verification(mid), "trace-1")
            .expect("serde deserialization should succeed");
        // SAFETY: Test helper uses valid commit; commit succeeds in controlled test environment.
        runner
            .commit(mid, "trace-1")
            .expect("serde deserialization should succeed");
    }

    // -- declaration ------------------------------------------------------

    #[test]
    fn declare_migration() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.migration_count(), 1);
        assert_eq!(runner.state("m-1"), Some(MigrationState::Declared));
    }

    #[test]
    fn reject_duplicate_declaration() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let err = runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::DuplicateMigration { .. }
        ));
    }

    // -- dry run ----------------------------------------------------------

    #[test]
    fn dry_run_pass() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        // SAFETY: Test uses valid dry run; dry_run succeeds in controlled test environment.
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-1"), Some(MigrationState::DryRunPassed));
    }

    #[test]
    fn dry_run_fail() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let err = runner
            .dry_run("m-1", failing_dry_run("m-1"), "t")
            .unwrap_err();
        assert!(matches!(err, MigrationContractError::DryRunFailed { .. }));
        assert_eq!(runner.state("m-1"), Some(MigrationState::DryRunFailed));
    }

    #[test]
    fn dry_run_requires_declared_state() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        let err = runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- checkpoint -------------------------------------------------------

    #[test]
    fn checkpoint_after_dry_run() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        // SAFETY: Test uses valid dry run; dry_run succeeds in controlled test environment.
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        // SAFETY: Test uses valid checkpoint; create_checkpoint succeeds in controlled test environment.
        runner
            .create_checkpoint("m-1", 42, "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-1"), Some(MigrationState::Executing));
    }

    #[test]
    fn checkpoint_requires_dry_run_passed() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let err = runner.create_checkpoint("m-1", 42, "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- execute ----------------------------------------------------------

    #[test]
    fn complete_execution_transitions_to_verifying() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-1", 42, "t")
            .expect("serde deserialization should succeed");
        runner
            .complete_execution("m-1", 100, "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-1"), Some(MigrationState::Verifying));
    }

    // -- verify -----------------------------------------------------------

    #[test]
    fn verification_pass() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        // SAFETY: Test uses valid dry run; dry_run succeeds in controlled test environment.
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        // SAFETY: Test uses valid checkpoint; create_checkpoint succeeds in controlled test environment.
        runner
            .create_checkpoint("m-1", 42, "t")
            .expect("serde deserialization should succeed");
        // SAFETY: Test uses valid execution; complete_execution succeeds in controlled test environment.
        runner
            .complete_execution("m-1", 100, "t")
            .expect("serde deserialization should succeed");
        // SAFETY: Test uses valid verification; verify succeeds in controlled test environment.
        runner
            .verify("m-1", passing_verification("m-1"), "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-1"), Some(MigrationState::Verified));
    }

    #[test]
    fn verification_fail() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-1", 42, "t")
            .expect("serde deserialization should succeed");
        runner
            .complete_execution("m-1", 100, "t")
            .expect("serde deserialization should succeed");
        let err = runner
            .verify("m-1", failing_verification("m-1"), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::VerificationFailed { .. }
        ));
        assert_eq!(
            runner.state("m-1"),
            Some(MigrationState::VerificationFailed)
        );
    }

    // -- commit -----------------------------------------------------------

    #[test]
    fn commit_migration() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
        assert_eq!(runner.state("m-1"), Some(MigrationState::Committed));
        assert_eq!(runner.applied_count(), 1);
        assert_eq!(runner.applied_migrations()[0].migration_id, "m-1");
    }

    #[test]
    fn commit_requires_verified() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let err = runner.commit("m-1", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- rollback ---------------------------------------------------------

    #[test]
    fn rollback_from_executing() {
        let mut runner = MigrationRunner::new();
        // SAFETY: Test creates valid declaration; declare succeeds in controlled test environment.
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-1", 42, "t")
            .expect("serde deserialization should succeed");
        runner
            .rollback("m-1", "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
    }

    #[test]
    fn rollback_from_verifying() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-1", 42, "t")
            .expect("serde deserialization should succeed");
        runner
            .complete_execution("m-1", 100, "t")
            .expect("serde deserialization should succeed");
        runner
            .rollback("m-1", "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
    }

    #[test]
    fn rollback_from_declared_fails() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let err = runner.rollback("m-1", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn rollback_from_committed_fails() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
        let err = runner.rollback("m-1", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- format enforcement -----------------------------------------------

    #[test]
    fn hard_cutover_rejects_old_format() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        let err = runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::OldFormatRejected { .. }
        ));
    }

    #[test]
    fn hard_cutover_accepts_new_format() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v2")
            .expect("serde deserialization should succeed");
    }

    #[test]
    fn hard_cutover_only_rejects_affected_classes() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        // TokenFormat is NOT in affected_objects, so old version should be fine.
        runner
            .check_format_acceptance(ObjectClass::TokenFormat, "v1")
            .expect("serde deserialization should succeed");
    }

    #[test]
    fn soft_migration_does_not_reject_old_format() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);

        // Soft migration doesn't reject old format via check_format_acceptance.
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
            .expect("serde deserialization should succeed");
    }

    // -- soft migration window --------------------------------------------

    #[test]
    fn soft_migration_window_open_before_end() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);

        runner.set_tick(500);
        assert_eq!(runner.check_soft_migration_window("m-1"), Some(true));
    }

    #[test]
    fn soft_migration_window_closed_after_end() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);

        runner.set_tick(1000);
        assert_eq!(runner.check_soft_migration_window("m-1"), Some(false));
    }

    // -- events -----------------------------------------------------------

    #[test]
    fn events_emitted_for_full_pipeline() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        let events = runner.drain_events();
        assert!(events.len() >= 5); // declare, dry_run, checkpoint, execution, verify, commit

        let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
        assert!(event_names.contains(&"migration_declared"));
        assert!(event_names.contains(&"dry_run_complete"));
        assert!(event_names.contains(&"checkpoint_created"));
        assert!(event_names.contains(&"execution_complete"));
        assert!(event_names.contains(&"verification_complete"));
        assert!(event_names.contains(&"migration_committed"));

        assert!(events.iter().all(|e| e.component == "migration_contract"));
    }

    #[test]
    fn rollback_events_emitted() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-1", 42, "t")
            .expect("serde deserialization should succeed");
        runner
            .rollback("m-1", "t")
            .expect("serde deserialization should succeed");

        let events = runner.drain_events();
        let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
        assert!(event_names.contains(&"rollback_started"));
        assert!(event_names.contains(&"rollback_complete"));
    }

    // -- migration not found ----------------------------------------------

    #[test]
    fn operations_on_missing_migration_fail() {
        let mut runner = MigrationRunner::new();
        assert!(matches!(
            runner.dry_run("missing", passing_dry_run("missing"), "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
        assert!(matches!(
            runner.create_checkpoint("missing", 42, "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
        assert!(matches!(
            runner.commit("missing", "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
        assert!(matches!(
            runner.rollback("missing", "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
    }

    // -- summary ----------------------------------------------------------

    #[test]
    fn summary_shows_all_migrations() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        run_full_pipeline(&mut runner, "m-2", CutoverType::SoftMigration);

        let summary = runner.summary();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary["m-1"], MigrationState::Declared);
        assert_eq!(summary["m-2"], MigrationState::Committed);
    }

    // -- serde roundtrips -------------------------------------------------

    #[test]
    fn cutover_type_serde_roundtrip() {
        for ct in [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ] {
            let json = serde_json::to_string(&ct).expect("serde deserialization should succeed");
            let deser: CutoverType =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(ct, deser);
        }
    }

    #[test]
    fn object_class_serde_roundtrip() {
        for oc in ObjectClass::ALL {
            let json = serde_json::to_string(&oc).expect("serde deserialization should succeed");
            let deser: ObjectClass =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(oc, deser);
        }
    }

    #[test]
    fn migration_state_serde_roundtrip() {
        for state in [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ] {
            let json = serde_json::to_string(&state).expect("serde deserialization should succeed");
            let deser: MigrationState =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(state, deser);
        }
    }

    #[test]
    fn migration_declaration_serde_roundtrip() {
        let decl = make_declaration("m-1", CutoverType::HardCutover);
        let json = serde_json::to_string(&decl).expect("serde deserialization should succeed");
        let deser: MigrationDeclaration =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(decl, deser);
    }

    #[test]
    fn migration_event_serde_roundtrip() {
        let event = MigrationEvent {
            trace_id: "t-1".to_string(),
            component: COMPONENT.to_string(),
            event: "migration_declared".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            migration_id: Some("m-1".to_string()),
            step: None,
            affected_count: Some(100),
            from_version: Some("v1".to_string()),
            to_version: Some("v2".to_string()),
            timestamp: DeterministicTimestamp(42),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let deser: MigrationEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, deser);
    }

    #[test]
    fn migration_error_serde_roundtrip() {
        let errors = vec![
            MigrationContractError::MigrationNotFound {
                migration_id: "x".to_string(),
            },
            MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            },
            MigrationContractError::DryRunFailed {
                migration_id: "x".to_string(),
                unconvertible_count: 10,
                detail: "d".to_string(),
            },
            MigrationContractError::OldFormatRejected {
                migration_id: "x".to_string(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".to_string(),
            },
            MigrationContractError::DuplicateMigration {
                migration_id: "x".to_string(),
            },
            MigrationContractError::RollbackFailed {
                migration_id: "x".to_string(),
                detail: "d".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
            let deser: MigrationContractError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, deser);
        }
    }

    #[test]
    fn applied_migration_record_serde_roundtrip() {
        let record = AppliedMigrationRecord {
            migration_id: "m-1".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            cutover_type: CutoverType::HardCutover,
            affected_objects: vec![ObjectClass::KeyFormat],
            applied_at: DeterministicTimestamp(42),
            checkpoint_seq: 10,
        };
        let json = serde_json::to_string(&record).expect("serde deserialization should succeed");
        let deser: AppliedMigrationRecord =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(record, deser);
    }

    // -- display coverage -------------------------------------------------

    #[test]
    fn cutover_type_display() {
        assert_eq!(CutoverType::HardCutover.to_string(), "hard_cutover");
        assert_eq!(CutoverType::SoftMigration.to_string(), "soft_migration");
        assert_eq!(CutoverType::ParallelRun.to_string(), "parallel_run");
    }

    #[test]
    fn object_class_display() {
        assert_eq!(
            ObjectClass::SerializationSchema.to_string(),
            "serialization_schema"
        );
        assert_eq!(ObjectClass::KeyFormat.to_string(), "key_format");
    }

    #[test]
    fn migration_state_display() {
        assert_eq!(MigrationState::Declared.to_string(), "declared");
        assert_eq!(MigrationState::Committed.to_string(), "committed");
        assert_eq!(MigrationState::RolledBack.to_string(), "rolled_back");
    }

    #[test]
    fn migration_step_display() {
        assert_eq!(MigrationStep::PreMigration.to_string(), "pre_migration");
        assert_eq!(MigrationStep::Commit.to_string(), "commit");
    }

    #[test]
    fn migration_state_terminal() {
        assert!(MigrationState::Committed.is_terminal());
        assert!(MigrationState::RolledBack.is_terminal());
        assert!(MigrationState::DryRunFailed.is_terminal());
        assert!(!MigrationState::VerificationFailed.is_terminal());
        assert!(!MigrationState::Declared.is_terminal());
        assert!(!MigrationState::Executing.is_terminal());
    }

    #[test]
    fn migration_step_next() {
        assert_eq!(
            MigrationStep::PreMigration.next(),
            Some(MigrationStep::Checkpoint)
        );
        assert_eq!(
            MigrationStep::Checkpoint.next(),
            Some(MigrationStep::Execute)
        );
        assert_eq!(MigrationStep::Execute.next(), Some(MigrationStep::Verify));
        assert_eq!(MigrationStep::Verify.next(), Some(MigrationStep::Commit));
        assert_eq!(MigrationStep::Commit.next(), None);
        assert_eq!(MigrationStep::Rollback.next(), None);
    }

    #[test]
    fn migration_step_forward_pipeline() {
        assert_eq!(MigrationStep::FORWARD_PIPELINE.len(), 5);
    }

    // -- error codes ------------------------------------------------------

    #[test]
    fn error_codes_stable() {
        assert_eq!(
            error_code(&MigrationContractError::MigrationNotFound {
                migration_id: "x".to_string()
            }),
            "MC_MIGRATION_NOT_FOUND"
        );
        assert_eq!(
            error_code(&MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            }),
            "MC_INVALID_TRANSITION"
        );
        assert_eq!(
            error_code(&MigrationContractError::DryRunFailed {
                migration_id: "x".to_string(),
                unconvertible_count: 5,
                detail: "d".to_string()
            }),
            "MC_DRY_RUN_FAILED"
        );
        assert_eq!(
            error_code(&MigrationContractError::OldFormatRejected {
                migration_id: "x".to_string(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".to_string()
            }),
            "MC_OLD_FORMAT_REJECTED"
        );
        assert_eq!(
            error_code(&MigrationContractError::ParallelRunDiscrepancy {
                migration_id: "x".to_string(),
                discrepancy_count: 3
            }),
            "MC_PARALLEL_DISCREPANCY"
        );
    }

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<MigrationContractError> = vec![
            MigrationContractError::MigrationNotFound {
                migration_id: "x".to_string(),
            },
            MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            },
            MigrationContractError::DryRunFailed {
                migration_id: "x".to_string(),
                unconvertible_count: 5,
                detail: "d".to_string(),
            },
            MigrationContractError::VerificationFailed {
                migration_id: "x".to_string(),
                discrepancy_count: 3,
                detail: "d".to_string(),
            },
            MigrationContractError::OldFormatRejected {
                migration_id: "x".to_string(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".to_string(),
            },
            MigrationContractError::DuplicateMigration {
                migration_id: "x".to_string(),
            },
            MigrationContractError::RollbackFailed {
                migration_id: "x".to_string(),
                detail: "d".to_string(),
            },
            MigrationContractError::ParallelRunDiscrepancy {
                migration_id: "x".to_string(),
                discrepancy_count: 2,
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    // -- declaration accessor ---------------------------------------------

    #[test]
    fn declaration_accessor() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let decl = runner
            .declaration("m-1")
            .expect("serde deserialization should succeed");
        assert_eq!(decl.migration_id, "m-1");
        assert_eq!(decl.cutover_type, CutoverType::HardCutover);
    }

    // -- deterministic replay ---------------------------------------------

    #[test]
    fn full_pipeline_deterministic() {
        let run = || {
            let mut runner = MigrationRunner::new();
            runner.set_tick(0);
            run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
            let events = runner.drain_events();
            serde_json::to_string(&events).expect("serde deserialization should succeed")
        };
        assert_eq!(run(), run());
    }

    // -- multiple migrations in order -------------------------------------

    #[test]
    fn multiple_migrations_applied_in_order() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);

        let mut d1 = make_declaration("m-1", CutoverType::HardCutover);
        d1.from_version = "v1".to_string();
        d1.to_version = "v2".to_string();
        runner
            .declare(d1, "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-1", 10, "t")
            .expect("serde deserialization should succeed");
        runner
            .complete_execution("m-1", 50, "t")
            .expect("serde deserialization should succeed");
        runner
            .verify("m-1", passing_verification("m-1"), "t")
            .expect("serde deserialization should succeed");
        runner
            .commit("m-1", "t")
            .expect("serde deserialization should succeed");

        runner.set_tick(100);
        let mut d2 = make_declaration("m-2", CutoverType::SoftMigration);
        d2.from_version = "v2".to_string();
        d2.to_version = "v3".to_string();
        runner
            .declare(d2, "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-2", passing_dry_run("m-2"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-2", 20, "t")
            .expect("serde deserialization should succeed");
        runner
            .complete_execution("m-2", 50, "t")
            .expect("serde deserialization should succeed");
        runner
            .verify("m-2", passing_verification("m-2"), "t")
            .expect("serde deserialization should succeed");
        runner
            .commit("m-2", "t")
            .expect("serde deserialization should succeed");

        assert_eq!(runner.applied_count(), 2);
        assert_eq!(runner.applied_migrations()[0].from_version, "v1");
        assert_eq!(runner.applied_migrations()[0].to_version, "v2");
        assert_eq!(runner.applied_migrations()[1].from_version, "v2");
        assert_eq!(runner.applied_migrations()[1].to_version, "v3");
    }

    // -- dry run / verification result helpers ----------------------------

    #[test]
    fn dry_run_result_passed() {
        assert!(passing_dry_run("m-1").passed());
        assert!(!failing_dry_run("m-1").passed());
    }

    #[test]
    fn verification_result_passed() {
        assert!(passing_verification("m-1").passed());
        assert!(!failing_verification("m-1").passed());
    }

    // -- object class ALL constant ----------------------------------------

    #[test]
    fn object_class_all_has_eight() {
        assert_eq!(ObjectClass::ALL.len(), 8);
    }

    // -- default -----------------------------------------------------------

    #[test]
    fn runner_default() {
        let runner = MigrationRunner::default();
        assert_eq!(runner.migration_count(), 0);
        assert_eq!(runner.applied_count(), 0);
    }

    // -- Enrichment: Display uniqueness via BTreeSet --------------------

    #[test]
    fn cutover_type_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn migration_state_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 11);
    }

    // -- Enrichment: std::error::Error impl --------------------------

    #[test]
    fn migration_contract_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(MigrationContractError::MigrationNotFound {
            migration_id: "test".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment: parallel run cutover behavior ------------------

    #[test]
    fn parallel_run_full_pipeline() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-par", CutoverType::ParallelRun);
        assert_eq!(runner.state("m-par"), Some(MigrationState::Committed));
        assert_eq!(runner.applied_count(), 1);
    }

    // -- Enrichment: soft migration window for non-soft cutover -----

    #[test]
    fn soft_migration_window_none_for_hard_cutover() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-hard", CutoverType::HardCutover);
        // Hard cutover has no transition_end_tick, so window check returns None
        assert_eq!(runner.check_soft_migration_window("m-hard"), None);
    }

    // -- Enrichment: check_format_acceptance for unaffected class ----

    #[test]
    fn format_acceptance_for_unregistered_migration_passes() {
        let runner = MigrationRunner::new();
        // No migrations registered, so any format is accepted
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
            .expect("serde deserialization should succeed");
    }

    // -- Enrichment: MigrationStep ordering -------------------------

    #[test]
    fn migration_step_ordering() {
        assert!(MigrationStep::PreMigration < MigrationStep::Checkpoint);
        assert!(MigrationStep::Checkpoint < MigrationStep::Execute);
        assert!(MigrationStep::Execute < MigrationStep::Verify);
        assert!(MigrationStep::Verify < MigrationStep::Commit);
    }

    // -- Enrichment: rollback after verification failed -------------

    #[test]
    fn rollback_from_verification_failed() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-vf", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-vf", passing_dry_run("m-vf"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-vf", 42, "t")
            .expect("serde deserialization should succeed");
        runner
            .complete_execution("m-vf", 100, "t")
            .expect("serde deserialization should succeed");
        let _ = runner.verify("m-vf", failing_verification("m-vf"), "t");
        assert_eq!(
            runner.state("m-vf"),
            Some(MigrationState::VerificationFailed)
        );
        // VerificationFailed is not terminal — rollback should succeed
        runner
            .rollback("m-vf", "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-vf"), Some(MigrationState::RolledBack));
    }

    // =====================================================================
    // Enrichment batch: +50 tests across 10 categories
    // =====================================================================

    // -- Category 1: Copy semantics -----------------------------------

    #[test]
    fn cutover_type_copy_semantics() {
        let a = CutoverType::HardCutover;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn object_class_copy_semantics() {
        let a = ObjectClass::KeyFormat;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn migration_step_copy_semantics() {
        let a = MigrationStep::Execute;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn migration_state_copy_semantics() {
        let a = MigrationState::Verifying;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn cutover_type_all_variants_survive_copy() {
        for ct in [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ] {
            let copied = ct;
            assert_eq!(ct, copied);
        }
    }

    // -- Category 2: Debug distinctness -------------------------------

    #[test]
    fn cutover_type_debug_distinct() {
        let dbgs: std::collections::BTreeSet<String> = [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 3);
    }

    #[test]
    fn object_class_debug_distinct() {
        let dbgs: std::collections::BTreeSet<String> =
            ObjectClass::ALL.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(dbgs.len(), 8);
    }

    #[test]
    fn migration_step_debug_distinct() {
        let all = [
            MigrationStep::PreMigration,
            MigrationStep::Checkpoint,
            MigrationStep::Execute,
            MigrationStep::Verify,
            MigrationStep::Commit,
            MigrationStep::Rollback,
        ];
        let dbgs: std::collections::BTreeSet<String> =
            all.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(dbgs.len(), 6);
    }

    #[test]
    fn migration_state_debug_distinct() {
        let all = [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ];
        let dbgs: std::collections::BTreeSet<String> =
            all.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(dbgs.len(), 11);
    }

    #[test]
    fn migration_contract_error_debug_distinct() {
        let all: Vec<MigrationContractError> = vec![
            MigrationContractError::MigrationNotFound {
                migration_id: "a".into(),
            },
            MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            },
            MigrationContractError::DryRunFailed {
                migration_id: "a".into(),
                unconvertible_count: 1,
                detail: "d".into(),
            },
            MigrationContractError::VerificationFailed {
                migration_id: "a".into(),
                discrepancy_count: 1,
                detail: "d".into(),
            },
            MigrationContractError::OldFormatRejected {
                migration_id: "a".into(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".into(),
            },
            MigrationContractError::DuplicateMigration {
                migration_id: "a".into(),
            },
            MigrationContractError::RollbackFailed {
                migration_id: "a".into(),
                detail: "d".into(),
            },
            MigrationContractError::ParallelRunDiscrepancy {
                migration_id: "a".into(),
                discrepancy_count: 1,
            },
        ];
        let dbgs: std::collections::BTreeSet<String> =
            all.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(dbgs.len(), 8);
    }

    // -- Category 3: Serde variant distinctness -----------------------

    #[test]
    fn cutover_type_serde_variant_distinct() {
        let jsons: std::collections::BTreeSet<String> = [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
        .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn object_class_serde_variant_distinct() {
        let jsons: std::collections::BTreeSet<String> = ObjectClass::ALL
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 8);
    }

    #[test]
    fn migration_step_serde_variant_distinct() {
        let all = [
            MigrationStep::PreMigration,
            MigrationStep::Checkpoint,
            MigrationStep::Execute,
            MigrationStep::Verify,
            MigrationStep::Commit,
            MigrationStep::Rollback,
        ];
        let jsons: std::collections::BTreeSet<String> = all
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 6);
    }

    #[test]
    fn migration_state_serde_variant_distinct() {
        let all = [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ];
        let jsons: std::collections::BTreeSet<String> = all
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 11);
    }

    // -- Category 4: Clone independence -------------------------------

    #[test]
    fn migration_declaration_clone_independence() {
        let original = make_declaration("m-clone", CutoverType::HardCutover);
        let mut cloned = original.clone();
        cloned.migration_id = "m-clone-modified".to_string();
        cloned.description = "modified".to_string();
        assert_eq!(original.migration_id, "m-clone");
        assert_ne!(original.migration_id, cloned.migration_id);
    }

    #[test]
    fn dry_run_result_clone_independence() {
        let original = passing_dry_run("m-1");
        let mut cloned = original.clone();
        cloned.total_objects = 999;
        cloned.details.push("extra".to_string());
        assert_eq!(original.total_objects, 100);
        assert!(original.details.is_empty());
    }

    #[test]
    fn verification_result_clone_independence() {
        let original = failing_verification("m-1");
        let mut cloned = original.clone();
        cloned.discrepancies = 999;
        cloned.details.push("extra".to_string());
        assert_eq!(original.discrepancies, 5);
        assert_eq!(original.details.len(), 1);
    }

    #[test]
    fn migration_event_clone_independence() {
        let original = MigrationEvent {
            trace_id: "t".to_string(),
            component: COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("E1".to_string()),
            migration_id: Some("m-1".to_string()),
            step: None,
            affected_count: Some(10),
            from_version: Some("v1".to_string()),
            to_version: Some("v2".to_string()),
            timestamp: DeterministicTimestamp(42),
        };
        let mut cloned = original.clone();
        cloned.trace_id = "modified".to_string();
        cloned.error_code = None;
        assert_eq!(original.trace_id, "t");
        assert_eq!(original.error_code, Some("E1".to_string()));
    }

    #[test]
    fn applied_migration_record_clone_independence() {
        let original = AppliedMigrationRecord {
            migration_id: "m-1".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            cutover_type: CutoverType::HardCutover,
            affected_objects: vec![ObjectClass::KeyFormat],
            applied_at: DeterministicTimestamp(42),
            checkpoint_seq: 10,
        };
        let mut cloned = original.clone();
        cloned.migration_id = "modified".to_string();
        cloned.affected_objects.push(ObjectClass::TokenFormat);
        assert_eq!(original.migration_id, "m-1");
        assert_eq!(original.affected_objects.len(), 1);
    }

    #[test]
    fn migration_contract_error_clone_independence() {
        let original = MigrationContractError::DryRunFailed {
            migration_id: "m-1".to_string(),
            unconvertible_count: 5,
            detail: "orig".to_string(),
        };
        let mut cloned = original.clone();
        if let MigrationContractError::DryRunFailed { ref mut detail, .. } = cloned {
            *detail = "modified".to_string();
        }
        if let MigrationContractError::DryRunFailed { ref detail, .. } = original {
            assert_eq!(detail, "orig");
        }
    }

    // -- Category 5: JSON field-name stability ------------------------

    #[test]
    fn migration_declaration_json_field_names() {
        let decl = make_declaration("m-1", CutoverType::HardCutover);
        let json = serde_json::to_string(&decl).expect("serde deserialization should succeed");
        assert!(json.contains("\"migration_id\""));
        assert!(json.contains("\"from_version\""));
        assert!(json.contains("\"to_version\""));
        assert!(json.contains("\"affected_objects\""));
        assert!(json.contains("\"cutover_type\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"compatible_across\""));
        assert!(json.contains("\"incompatible_across\""));
        assert!(json.contains("\"transition_end_tick\""));
    }

    #[test]
    fn migration_event_json_field_names() {
        let event = MigrationEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("E".to_string()),
            migration_id: Some("m".to_string()),
            step: Some("s".to_string()),
            affected_count: Some(1),
            from_version: Some("v1".to_string()),
            to_version: Some("v2".to_string()),
            timestamp: DeterministicTimestamp(0),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
        assert!(json.contains("\"migration_id\""));
        assert!(json.contains("\"step\""));
        assert!(json.contains("\"affected_count\""));
        assert!(json.contains("\"from_version\""));
        assert!(json.contains("\"to_version\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn dry_run_result_json_field_names() {
        let dr = passing_dry_run("m-1");
        let json = serde_json::to_string(&dr).expect("serde deserialization should succeed");
        assert!(json.contains("\"migration_id\""));
        assert!(json.contains("\"total_objects\""));
        assert!(json.contains("\"convertible\""));
        assert!(json.contains("\"unconvertible\""));
        assert!(json.contains("\"details\""));
    }

    #[test]
    fn verification_result_json_field_names() {
        let vr = passing_verification("m-1");
        let json = serde_json::to_string(&vr).expect("serde deserialization should succeed");
        assert!(json.contains("\"migration_id\""));
        assert!(json.contains("\"objects_checked\""));
        assert!(json.contains("\"discrepancies\""));
        assert!(json.contains("\"details\""));
    }

    #[test]
    fn applied_migration_record_json_field_names() {
        let record = AppliedMigrationRecord {
            migration_id: "m-1".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            cutover_type: CutoverType::HardCutover,
            affected_objects: vec![ObjectClass::KeyFormat],
            applied_at: DeterministicTimestamp(42),
            checkpoint_seq: 10,
        };
        let json = serde_json::to_string(&record).expect("serde deserialization should succeed");
        assert!(json.contains("\"migration_id\""));
        assert!(json.contains("\"from_version\""));
        assert!(json.contains("\"to_version\""));
        assert!(json.contains("\"cutover_type\""));
        assert!(json.contains("\"affected_objects\""));
        assert!(json.contains("\"applied_at\""));
        assert!(json.contains("\"checkpoint_seq\""));
    }

    // -- Category 6: Display format checks ----------------------------

    #[test]
    fn object_class_display_all_variants() {
        assert_eq!(ObjectClass::TokenFormat.to_string(), "token_format");
        assert_eq!(
            ObjectClass::CheckpointFormat.to_string(),
            "checkpoint_format"
        );
        assert_eq!(
            ObjectClass::RevocationFormat.to_string(),
            "revocation_format"
        );
        assert_eq!(ObjectClass::PolicyStructure.to_string(), "policy_structure");
        assert_eq!(ObjectClass::EvidenceFormat.to_string(), "evidence_format");
        assert_eq!(
            ObjectClass::AttestationFormat.to_string(),
            "attestation_format"
        );
    }

    #[test]
    fn migration_state_display_all_variants_exact() {
        assert_eq!(MigrationState::DryRunning.to_string(), "dry_running");
        assert_eq!(MigrationState::DryRunPassed.to_string(), "dry_run_passed");
        assert_eq!(MigrationState::DryRunFailed.to_string(), "dry_run_failed");
        assert_eq!(MigrationState::Executing.to_string(), "executing");
        assert_eq!(MigrationState::Verifying.to_string(), "verifying");
        assert_eq!(MigrationState::Verified.to_string(), "verified");
        assert_eq!(
            MigrationState::VerificationFailed.to_string(),
            "verification_failed"
        );
        assert_eq!(MigrationState::RollingBack.to_string(), "rolling_back");
    }

    #[test]
    fn migration_step_display_all_variants_exact() {
        assert_eq!(MigrationStep::Checkpoint.to_string(), "checkpoint");
        assert_eq!(MigrationStep::Execute.to_string(), "execute");
        assert_eq!(MigrationStep::Verify.to_string(), "verify");
        assert_eq!(MigrationStep::Rollback.to_string(), "rollback");
    }

    #[test]
    fn error_display_migration_not_found_exact() {
        let err = MigrationContractError::MigrationNotFound {
            migration_id: "m-42".to_string(),
        };
        assert_eq!(err.to_string(), "migration not found: m-42");
    }

    #[test]
    fn error_display_invalid_transition_exact() {
        let err = MigrationContractError::InvalidTransition {
            from: MigrationState::Declared,
            to: MigrationState::Executing,
        };
        assert_eq!(err.to_string(), "invalid transition: declared -> executing");
    }

    #[test]
    fn error_display_duplicate_migration_exact() {
        let err = MigrationContractError::DuplicateMigration {
            migration_id: "m-dup".to_string(),
        };
        assert_eq!(err.to_string(), "duplicate migration: m-dup");
    }

    #[test]
    fn error_display_rollback_failed_exact() {
        let err = MigrationContractError::RollbackFailed {
            migration_id: "m-rb".to_string(),
            detail: "disk full".to_string(),
        };
        assert_eq!(err.to_string(), "rollback failed for m-rb: disk full");
    }

    #[test]
    fn error_display_parallel_run_discrepancy_exact() {
        let err = MigrationContractError::ParallelRunDiscrepancy {
            migration_id: "m-par".to_string(),
            discrepancy_count: 7,
        };
        assert_eq!(err.to_string(), "parallel run discrepancy for m-par: 7");
    }

    // -- Category 7: Hash consistency ---------------------------------

    #[test]
    fn cutover_type_hash_consistency() {
        use std::hash::{Hash, Hasher};
        for ct in [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ] {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            ct.hash(&mut h1);
            ct.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn object_class_hash_consistency() {
        use std::hash::{Hash, Hasher};
        for oc in ObjectClass::ALL {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            oc.hash(&mut h1);
            oc.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn migration_step_hash_consistency() {
        use std::hash::{Hash, Hasher};
        for step in MigrationStep::FORWARD_PIPELINE {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            step.hash(&mut h1);
            step.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn migration_state_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let all = [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ];
        for state in all {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            state.hash(&mut h1);
            state.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    // -- Category 8: Boundary/edge cases ------------------------------

    #[test]
    fn dry_run_result_zero_objects() {
        let dr = DryRunResult {
            migration_id: "m-zero".to_string(),
            total_objects: 0,
            convertible: 0,
            unconvertible: 0,
            details: Vec::new(),
        };
        assert!(dr.passed());
    }

    #[test]
    fn verification_result_zero_objects() {
        let vr = VerificationResult {
            migration_id: "m-zero".to_string(),
            objects_checked: 0,
            discrepancies: 0,
            details: Vec::new(),
        };
        assert!(vr.passed());
    }

    #[test]
    fn migration_declaration_empty_strings() {
        let decl = MigrationDeclaration {
            migration_id: String::new(),
            from_version: String::new(),
            to_version: String::new(),
            affected_objects: Vec::new(),
            cutover_type: CutoverType::HardCutover,
            description: String::new(),
            compatible_across: Vec::new(),
            incompatible_across: Vec::new(),
            transition_end_tick: None,
        };
        let json = serde_json::to_string(&decl).expect("serde deserialization should succeed");
        let deser: MigrationDeclaration =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(decl, deser);
    }

    #[test]
    fn migration_declaration_max_tick() {
        let decl = MigrationDeclaration {
            migration_id: "m-max".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            affected_objects: vec![ObjectClass::KeyFormat],
            cutover_type: CutoverType::SoftMigration,
            description: "max tick".to_string(),
            compatible_across: Vec::new(),
            incompatible_across: Vec::new(),
            transition_end_tick: Some(u64::MAX),
        };
        let json = serde_json::to_string(&decl).expect("serde deserialization should succeed");
        let deser: MigrationDeclaration =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(deser.transition_end_tick, Some(u64::MAX));
    }

    #[test]
    fn runner_set_tick_max() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(u64::MAX);
        // Just verify it doesn't panic
        assert_eq!(runner.migration_count(), 0);
    }

    #[test]
    fn checkpoint_seq_u64_max() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-max", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-max", passing_dry_run("m-max"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-max", u64::MAX, "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-max"), Some(MigrationState::Executing));
    }

    #[test]
    fn soft_migration_window_at_exact_boundary() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full_pipeline(&mut runner, "m-boundary", CutoverType::SoftMigration);
        // transition_end_tick is 1000; tick=999 should be open, tick=1000 should be closed
        runner.set_tick(999);
        assert_eq!(runner.check_soft_migration_window("m-boundary"), Some(true));
        runner.set_tick(1000);
        assert_eq!(
            runner.check_soft_migration_window("m-boundary"),
            Some(false)
        );
    }

    #[test]
    fn state_of_nonexistent_migration_is_none() {
        let runner = MigrationRunner::new();
        assert_eq!(runner.state("nonexistent"), None);
    }

    #[test]
    fn declaration_of_nonexistent_migration_is_none() {
        let runner = MigrationRunner::new();
        assert!(runner.declaration("nonexistent").is_none());
    }

    #[test]
    fn check_soft_migration_window_nonexistent_is_none() {
        let runner = MigrationRunner::new();
        assert_eq!(runner.check_soft_migration_window("nonexistent"), None);
    }

    #[test]
    fn events_empty_initially() {
        let runner = MigrationRunner::new();
        assert!(runner.events().is_empty());
    }

    #[test]
    fn drain_events_empties_list() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        assert!(!runner.events().is_empty());
        let drained = runner.drain_events();
        assert!(!drained.is_empty());
        assert!(runner.events().is_empty());
    }

    #[test]
    fn complete_execution_on_missing_migration() {
        let mut runner = MigrationRunner::new();
        let err = runner.complete_execution("missing", 100, "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::MigrationNotFound { .. }
        ));
    }

    #[test]
    fn verify_on_missing_migration() {
        let mut runner = MigrationRunner::new();
        let err = runner
            .verify("missing", passing_verification("missing"), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::MigrationNotFound { .. }
        ));
    }

    // -- Category 9: Serde roundtrips (complex structs) ---------------

    #[test]
    fn dry_run_result_serde_roundtrip() {
        let dr = DryRunResult {
            migration_id: "m-serde".to_string(),
            total_objects: 5000,
            convertible: 4990,
            unconvertible: 10,
            details: vec!["err1".to_string(), "err2".to_string()],
        };
        let json = serde_json::to_string(&dr).expect("serde deserialization should succeed");
        let deser: DryRunResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(dr, deser);
    }

    #[test]
    fn verification_result_serde_roundtrip() {
        let vr = VerificationResult {
            migration_id: "m-serde".to_string(),
            objects_checked: 10000,
            discrepancies: 3,
            details: vec!["mismatch at obj-7".to_string()],
        };
        let json = serde_json::to_string(&vr).expect("serde deserialization should succeed");
        let deser: VerificationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(vr, deser);
    }

    #[test]
    fn migration_declaration_soft_serde_roundtrip() {
        let decl = make_declaration("m-soft", CutoverType::SoftMigration);
        let json = serde_json::to_string(&decl).expect("serde deserialization should succeed");
        let deser: MigrationDeclaration =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(decl, deser);
        assert_eq!(deser.transition_end_tick, Some(1000));
    }

    #[test]
    fn migration_event_with_all_none_fields_serde_roundtrip() {
        let event = MigrationEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            migration_id: None,
            step: None,
            affected_count: None,
            from_version: None,
            to_version: None,
            timestamp: DeterministicTimestamp(0),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let deser: MigrationEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, deser);
    }

    #[test]
    fn migration_step_serde_roundtrip() {
        for step in MigrationStep::FORWARD_PIPELINE {
            let json = serde_json::to_string(&step).expect("serde deserialization should succeed");
            let deser: MigrationStep =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(step, deser);
        }
        // Also test Rollback
        let json = serde_json::to_string(&MigrationStep::Rollback)
            .expect("serde deserialization should succeed");
        let deser: MigrationStep =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(MigrationStep::Rollback, deser);
    }

    #[test]
    fn error_verification_failed_serde_roundtrip() {
        let err = MigrationContractError::VerificationFailed {
            migration_id: "m-vf".to_string(),
            discrepancy_count: 42,
            detail: "field mismatch".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let deser: MigrationContractError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, deser);
    }

    #[test]
    fn error_parallel_run_discrepancy_serde_roundtrip() {
        let err = MigrationContractError::ParallelRunDiscrepancy {
            migration_id: "m-par".to_string(),
            discrepancy_count: 99,
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let deser: MigrationContractError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, deser);
    }

    // -- Category 10: Debug nonempty ----------------------------------

    #[test]
    fn cutover_type_debug_nonempty() {
        for ct in [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ] {
            assert!(!format!("{ct:?}").is_empty());
        }
    }

    #[test]
    fn object_class_debug_nonempty() {
        for oc in ObjectClass::ALL {
            assert!(!format!("{oc:?}").is_empty());
        }
    }

    #[test]
    fn migration_step_debug_nonempty() {
        for step in MigrationStep::FORWARD_PIPELINE {
            assert!(!format!("{step:?}").is_empty());
        }
        assert!(!format!("{:?}", MigrationStep::Rollback).is_empty());
    }

    #[test]
    fn migration_state_debug_nonempty() {
        let all = [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ];
        for s in all {
            assert!(!format!("{s:?}").is_empty());
        }
    }

    #[test]
    fn migration_declaration_debug_nonempty() {
        let decl = make_declaration("m-1", CutoverType::HardCutover);
        assert!(!format!("{decl:?}").is_empty());
    }

    #[test]
    fn migration_event_debug_nonempty() {
        let event = MigrationEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            migration_id: None,
            step: None,
            affected_count: None,
            from_version: None,
            to_version: None,
            timestamp: DeterministicTimestamp(0),
        };
        assert!(!format!("{event:?}").is_empty());
    }

    #[test]
    fn dry_run_result_debug_nonempty() {
        let dr = passing_dry_run("m-1");
        assert!(!format!("{dr:?}").is_empty());
    }

    #[test]
    fn verification_result_debug_nonempty() {
        let vr = passing_verification("m-1");
        assert!(!format!("{vr:?}").is_empty());
    }

    #[test]
    fn applied_migration_record_debug_nonempty() {
        let record = AppliedMigrationRecord {
            migration_id: "m-1".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            cutover_type: CutoverType::HardCutover,
            affected_objects: vec![ObjectClass::KeyFormat],
            applied_at: DeterministicTimestamp(42),
            checkpoint_seq: 10,
        };
        assert!(!format!("{record:?}").is_empty());
    }

    #[test]
    fn migration_runner_debug_nonempty() {
        let runner = MigrationRunner::new();
        assert!(!format!("{runner:?}").is_empty());
    }

    // -- Additional edge-case / behavior tests ------------------------

    #[test]
    fn error_code_for_rollback_failed() {
        assert_eq!(
            error_code(&MigrationContractError::RollbackFailed {
                migration_id: "x".to_string(),
                detail: "d".to_string(),
            }),
            "MC_ROLLBACK_FAILED"
        );
    }

    #[test]
    fn error_code_for_duplicate_migration() {
        assert_eq!(
            error_code(&MigrationContractError::DuplicateMigration {
                migration_id: "x".to_string(),
            }),
            "MC_DUPLICATE_MIGRATION"
        );
    }

    #[test]
    fn error_code_for_verification_failed() {
        assert_eq!(
            error_code(&MigrationContractError::VerificationFailed {
                migration_id: "x".to_string(),
                discrepancy_count: 1,
                detail: "d".to_string(),
            }),
            "MC_VERIFICATION_FAILED"
        );
    }

    #[test]
    fn migration_state_non_terminal_variants() {
        let non_terminal = [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::RollingBack,
        ];
        for s in non_terminal {
            assert!(!s.is_terminal(), "{s:?} should not be terminal");
        }
    }

    #[test]
    fn rollback_from_dry_run_passed() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-drp", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-drp", passing_dry_run("m-drp"), "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-drp"), Some(MigrationState::DryRunPassed));
        runner
            .rollback("m-drp", "t")
            .expect("serde deserialization should succeed");
        assert_eq!(runner.state("m-drp"), Some(MigrationState::RolledBack));
    }

    #[test]
    fn rollback_from_rolled_back_fails() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-rb", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        runner
            .dry_run("m-rb", passing_dry_run("m-rb"), "t")
            .expect("serde deserialization should succeed");
        runner
            .create_checkpoint("m-rb", 1, "t")
            .expect("serde deserialization should succeed");
        runner
            .rollback("m-rb", "t")
            .expect("serde deserialization should succeed");
        // RolledBack is terminal — cannot rollback again
        let err = runner.rollback("m-rb", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn rollback_from_dry_run_failed_fails() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-drf", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let _ = runner.dry_run("m-drf", failing_dry_run("m-drf"), "t");
        assert_eq!(runner.state("m-drf"), Some(MigrationState::DryRunFailed));
        // DryRunFailed is terminal — cannot rollback
        let err = runner.rollback("m-drf", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn summary_empty_runner() {
        let runner = MigrationRunner::new();
        assert!(runner.summary().is_empty());
    }

    #[test]
    fn complete_execution_requires_executing_state() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-ce", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let err = runner.complete_execution("m-ce", 100, "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn verify_requires_verifying_state() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-vr", CutoverType::HardCutover), "t")
            .expect("serde deserialization should succeed");
        let err = runner
            .verify("m-vr", passing_verification("m-vr"), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }
}
