//! Migration compatibility validation for control-plane schema evolution.
//!
//! Ensures that schema changes to evidence entries, decision contract
//! formats, and Cx serialization preserve replay compatibility or fail
//! with explicit, machine-readable migration errors.
//!
//! # Architecture
//!
//! A [`GoldenLedger`] stores a frozen corpus of evidence entries at a
//! specific schema version.  [`MigrationFunction`] describes a versioned,
//! deterministic transform from one schema version to another.
//! [`MigrationCompatibilityChecker`] orchestrates replay of golden
//! ledgers through migration functions, verifying either:
//!
//! - **Backward compatibility**: old entries replay correctly under the
//!   new schema (no violations).
//! - **Explicit migration**: old entries are migrated by a registered
//!   migration function, and the result replays correctly.
//! - **Machine-readable rejection**: entries that cannot be migrated
//!   produce a [`MigrationError`] identifying the incompatible fields.
//!
//! # Plan references
//!
//! Section 10.13, item 16, bd-3q36.
//! Cross-refs: bd-2sbb (replay checker), bd-uvmm (evidence emission).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence_emission::CanonicalEvidenceEntry;
use crate::evidence_replay_checker::{
    EvidenceReplayChecker, ReplayConfig, ReplayResult, SchemaMigrationRecord,
};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT_NAME: &str = "migration_compatibility";

// ---------------------------------------------------------------------------
// MigrationError — machine-readable migration failures
// ---------------------------------------------------------------------------

/// Structured, machine-readable migration error identifying exactly
/// which fields or constraints prevented migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationError {
    /// Source schema version string.
    pub from_version: String,
    /// Target schema version string.
    pub to_version: String,
    /// Error code for programmatic handling.
    pub error_code: MigrationErrorCode,
    /// List of incompatible fields.
    pub incompatible_fields: Vec<IncompatibleField>,
    /// Human-readable description.
    pub message: String,
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "migration {} -> {}: {} ({} incompatible fields)",
            self.from_version,
            self.to_version,
            self.error_code,
            self.incompatible_fields.len()
        )
    }
}

impl std::error::Error for MigrationError {}

/// Error codes for migration failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MigrationErrorCode {
    /// Major version mismatch (breaking change).
    MajorVersionIncompatible,
    /// Required field missing in source.
    RequiredFieldMissing,
    /// Field type changed in a non-coercible way.
    FieldTypeChanged,
    /// Migration function returned an error.
    MigrationFunctionFailed,
    /// Migration function produced non-deterministic output.
    NonDeterministicMigration,
    /// Partial replay: some entries succeed, some fail.
    PartialReplayFailure,
    /// No migration function registered for this version pair.
    NoMigrationPath,
    /// Lossy migration (information loss).
    LossyMigration,
}

impl fmt::Display for MigrationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MajorVersionIncompatible => "major_version_incompatible",
            Self::RequiredFieldMissing => "required_field_missing",
            Self::FieldTypeChanged => "field_type_changed",
            Self::MigrationFunctionFailed => "migration_function_failed",
            Self::NonDeterministicMigration => "non_deterministic_migration",
            Self::PartialReplayFailure => "partial_replay_failure",
            Self::NoMigrationPath => "no_migration_path",
            Self::LossyMigration => "lossy_migration",
        };
        f.write_str(s)
    }
}

/// Describes a specific incompatible field in a migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncompatibleField {
    /// Field path (e.g., "metadata.calibration_score").
    pub field_path: String,
    /// Description of the incompatibility.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// GoldenLedger — frozen evidence corpus at a specific schema version
// ---------------------------------------------------------------------------

/// A frozen corpus of evidence entries recorded at a specific schema version.
///
/// Golden ledgers are immutable once created: they represent the canonical
/// evidence format at the time of recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoldenLedger {
    /// Human-readable name for this golden ledger.
    pub name: String,
    /// Schema version at which these entries were recorded.
    pub schema_version: String,
    /// The frozen evidence entries.
    pub entries: Vec<CanonicalEvidenceEntry>,
    /// Content hash of the serialized entries (for tamper detection).
    pub corpus_hash: ContentHash,
    /// When this golden ledger was frozen (monotonic ms).
    pub frozen_at_ms: u64,
    /// Metadata about the golden ledger.
    pub metadata: BTreeMap<String, String>,
}

impl GoldenLedger {
    /// Create a golden ledger from a set of evidence entries.
    pub fn freeze(
        name: impl Into<String>,
        schema_version: impl Into<String>,
        entries: Vec<CanonicalEvidenceEntry>,
        frozen_at_ms: u64,
    ) -> Self {
        let payload = serde_json::to_vec(&entries).unwrap_or_default();
        let corpus_hash = ContentHash::compute(&payload);
        Self {
            name: name.into(),
            schema_version: schema_version.into(),
            entries,
            corpus_hash,
            frozen_at_ms,
            metadata: BTreeMap::new(),
        }
    }

    /// Verify the corpus hash matches the entries.
    pub fn verify_integrity(&self) -> bool {
        let payload = serde_json::to_vec(&self.entries).unwrap_or_default();
        let computed = ContentHash::compute(&payload);
        self.corpus_hash == computed
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// MigrationFunction — versioned, deterministic transform
// ---------------------------------------------------------------------------

/// A registered migration function that transforms evidence entries
/// from one schema version to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationFunction {
    /// Source schema version.
    pub from_version: String,
    /// Target schema version.
    pub to_version: String,
    /// Whether this migration is lossy (information loss).
    pub lossy: bool,
    /// Description of what this migration does.
    pub description: String,
}

/// The transform applied to each entry during migration.
pub type MigrationTransformFn =
    fn(&CanonicalEvidenceEntry) -> Result<CanonicalEvidenceEntry, MigrationError>;

// ---------------------------------------------------------------------------
// MigrationRegistry — registered migration paths
// ---------------------------------------------------------------------------

/// Registry of migration functions between schema versions.
#[derive(Debug)]
pub struct MigrationRegistry {
    migrations: Vec<(MigrationFunction, MigrationTransformFn)>,
}

impl MigrationRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            migrations: Vec::new(),
        }
    }

    /// Register a migration function.
    pub fn register(&mut self, func: MigrationFunction, transform: MigrationTransformFn) {
        self.migrations.push((func, transform));
    }

    /// Find a migration function for the given version pair.
    pub fn find(&self, from: &str, to: &str) -> Option<&(MigrationFunction, MigrationTransformFn)> {
        self.migrations
            .iter()
            .find(|(f, _)| f.from_version == from && f.to_version == to)
    }

    /// All registered migrations.
    pub fn all(&self) -> &[(MigrationFunction, MigrationTransformFn)] {
        &self.migrations
    }
}

impl Default for MigrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MigrationCompatibilityEvent — structured log events
// ---------------------------------------------------------------------------

/// Structured event emitted during migration compatibility checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationCompatibilityEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub from_version: String,
    pub to_version: String,
}

// ---------------------------------------------------------------------------
// MigrationTestResult — outcome of a migration compatibility test
// ---------------------------------------------------------------------------

/// Outcome of a migration compatibility test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationOutcome {
    /// Entries are backward-compatible; no migration needed.
    BackwardCompatible,
    /// Entries were migrated successfully.
    MigratedSuccessfully,
    /// Migration is lossy but succeeded.
    LossyMigration,
    /// Migration failed with structured error.
    Failed,
}

impl fmt::Display for MigrationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackwardCompatible => write!(f, "backward_compatible"),
            Self::MigratedSuccessfully => write!(f, "migrated_successfully"),
            Self::LossyMigration => write!(f, "lossy_migration"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Full result from a migration compatibility test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationTestResult {
    /// Name of the golden ledger tested.
    pub golden_ledger_name: String,
    /// Source schema version.
    pub from_version: String,
    /// Target schema version.
    pub to_version: String,
    /// Outcome.
    pub outcome: MigrationOutcome,
    /// Number of entries processed.
    pub entries_processed: usize,
    /// Number of entries that replayed successfully after migration.
    pub entries_replayed_ok: usize,
    /// Migration errors encountered.
    pub errors: Vec<MigrationError>,
    /// Replay result (if replay was performed).
    pub replay_violations: usize,
    /// Schema migrations detected during replay.
    pub schema_migrations_detected: Vec<SchemaMigrationRecord>,
    /// Whether the migration function was deterministic.
    pub determinism_verified: bool,
}

impl MigrationTestResult {
    /// Whether the test passed (no errors, all entries replayed).
    pub fn passed(&self) -> bool {
        self.errors.is_empty()
            && self.replay_violations == 0
            && self.outcome != MigrationOutcome::Failed
    }
}

// ---------------------------------------------------------------------------
// MigrationCompatibilityChecker — the orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates migration compatibility tests against golden ledgers.
///
/// Given a corpus of golden ledgers and a registry of migration functions,
/// the checker verifies that evidence replays correctly across schema
/// version boundaries.
#[derive(Debug)]
pub struct MigrationCompatibilityChecker {
    registry: MigrationRegistry,
    golden_ledgers: Vec<GoldenLedger>,
    events: Vec<MigrationCompatibilityEvent>,
    target_schema_version: String,
}

impl MigrationCompatibilityChecker {
    /// Create a new checker targeting the given schema version.
    pub fn new(target_schema_version: impl Into<String>, registry: MigrationRegistry) -> Self {
        Self {
            registry,
            golden_ledgers: Vec::new(),
            events: Vec::new(),
            target_schema_version: target_schema_version.into(),
        }
    }

    /// Add a golden ledger to the test corpus.
    pub fn add_golden_ledger(&mut self, ledger: GoldenLedger) {
        self.golden_ledgers.push(ledger);
    }

    /// Number of golden ledgers registered.
    pub fn golden_ledger_count(&self) -> usize {
        self.golden_ledgers.len()
    }

    /// Target schema version.
    pub fn target_version(&self) -> &str {
        &self.target_schema_version
    }

    /// Run all migration compatibility tests.
    ///
    /// For each golden ledger:
    /// 1. Check if entries are already at the target version (backward compat).
    /// 2. If not, look up and apply a migration function.
    /// 3. Replay the (possibly migrated) entries.
    /// 4. Verify determinism of the migration function.
    pub fn run_all(&mut self) -> Vec<MigrationTestResult> {
        let ledgers: Vec<GoldenLedger> = self.golden_ledgers.clone();
        let mut results = Vec::new();
        for ledger in &ledgers {
            results.push(self.test_golden_ledger(ledger));
        }
        results
    }

    /// Test a single golden ledger against the target schema version.
    pub fn test_golden_ledger(&mut self, ledger: &GoldenLedger) -> MigrationTestResult {
        let from = &ledger.schema_version;
        let to = &self.target_schema_version;

        // Step 1: Check if already at target version.
        if from == to {
            return self.check_backward_compatible(ledger);
        }

        // Step 2: Look up migration function.
        let migration = self.registry.find(from, to);
        match migration {
            Some((func, transform)) => {
                let func = func.clone();
                self.apply_migration(ledger, &func, *transform)
            }
            None => {
                // No migration path — check if target is forward-compatible.
                self.check_no_migration_path(ledger)
            }
        }
    }

    /// Check backward compatibility: entries at target version replay cleanly.
    fn check_backward_compatible(&mut self, ledger: &GoldenLedger) -> MigrationTestResult {
        let replay_result = self.replay_entries(&ledger.entries);
        let violations = replay_result.violations.len();

        self.push_event(
            &ledger.schema_version,
            &self.target_schema_version.clone(),
            "backward_compat_check",
            if violations == 0 { "pass" } else { "fail" },
            None,
        );

        MigrationTestResult {
            golden_ledger_name: ledger.name.clone(),
            from_version: ledger.schema_version.clone(),
            to_version: self.target_schema_version.clone(),
            outcome: if violations == 0 {
                MigrationOutcome::BackwardCompatible
            } else {
                MigrationOutcome::Failed
            },
            entries_processed: ledger.entries.len(),
            entries_replayed_ok: ledger.entries.len().saturating_sub(violations),
            errors: Vec::new(),
            replay_violations: violations,
            schema_migrations_detected: replay_result.diagnostics.schema_migrations.clone(),
            determinism_verified: true,
        }
    }

    /// Apply a migration function and replay the result.
    fn apply_migration(
        &mut self,
        ledger: &GoldenLedger,
        func: &MigrationFunction,
        transform: MigrationTransformFn,
    ) -> MigrationTestResult {
        let mut migrated_entries = Vec::new();
        let mut errors = Vec::new();

        // Apply migration to each entry.
        for entry in &ledger.entries {
            match transform(entry) {
                Ok(migrated) => migrated_entries.push(migrated),
                Err(err) => errors.push(err),
            }
        }

        if !errors.is_empty() {
            self.push_event(
                &func.from_version,
                &func.to_version,
                "migration_apply",
                "fail",
                Some("migration_function_failed"),
            );

            return MigrationTestResult {
                golden_ledger_name: ledger.name.clone(),
                from_version: func.from_version.clone(),
                to_version: func.to_version.clone(),
                outcome: MigrationOutcome::Failed,
                entries_processed: ledger.entries.len(),
                entries_replayed_ok: 0,
                errors,
                replay_violations: 0,
                schema_migrations_detected: Vec::new(),
                determinism_verified: false,
            };
        }

        // Verify determinism: apply migration a second time and compare.
        let determinism_ok = self.verify_determinism(ledger, transform);

        // Replay migrated entries.
        let replay_result = self.replay_entries(&migrated_entries);
        let violations = replay_result.violations.len();

        let outcome = if violations > 0 {
            MigrationOutcome::Failed
        } else if func.lossy {
            MigrationOutcome::LossyMigration
        } else {
            MigrationOutcome::MigratedSuccessfully
        };

        self.push_event(
            &func.from_version,
            &func.to_version,
            "migration_complete",
            if violations == 0 { "pass" } else { "fail" },
            None,
        );

        MigrationTestResult {
            golden_ledger_name: ledger.name.clone(),
            from_version: func.from_version.clone(),
            to_version: func.to_version.clone(),
            outcome,
            entries_processed: ledger.entries.len(),
            entries_replayed_ok: migrated_entries.len().saturating_sub(violations),
            errors: Vec::new(),
            replay_violations: violations,
            schema_migrations_detected: replay_result.diagnostics.schema_migrations.clone(),
            determinism_verified: determinism_ok,
        }
    }

    /// Check when no migration path exists.
    fn check_no_migration_path(&mut self, ledger: &GoldenLedger) -> MigrationTestResult {
        let target = self.target_schema_version.clone();
        self.push_event(
            &ledger.schema_version,
            &target,
            "no_migration_path",
            "fail",
            Some("no_migration_path"),
        );

        MigrationTestResult {
            golden_ledger_name: ledger.name.clone(),
            from_version: ledger.schema_version.clone(),
            to_version: target,
            outcome: MigrationOutcome::Failed,
            entries_processed: ledger.entries.len(),
            entries_replayed_ok: 0,
            errors: vec![MigrationError {
                from_version: ledger.schema_version.clone(),
                to_version: self.target_schema_version.clone(),
                error_code: MigrationErrorCode::NoMigrationPath,
                incompatible_fields: Vec::new(),
                message: format!(
                    "no migration registered from {} to {}",
                    ledger.schema_version, self.target_schema_version
                ),
            }],
            replay_violations: 0,
            schema_migrations_detected: Vec::new(),
            determinism_verified: false,
        }
    }

    /// Verify that a migration function is deterministic.
    fn verify_determinism(
        &mut self,
        ledger: &GoldenLedger,
        transform: MigrationTransformFn,
    ) -> bool {
        let run = |entries: &[CanonicalEvidenceEntry]| -> Vec<Vec<u8>> {
            entries
                .iter()
                .filter_map(|e| {
                    transform(e)
                        .ok()
                        .map(|m| serde_json::to_vec(&m).unwrap_or_default())
                })
                .collect()
        };

        let r1 = run(&ledger.entries);
        let r2 = run(&ledger.entries);
        let ok = r1 == r2;

        if !ok {
            self.push_event(
                &ledger.schema_version,
                &self.target_schema_version.clone(),
                "determinism_check",
                "fail",
                Some("non_deterministic_migration"),
            );
        }

        ok
    }

    /// Replay entries through the replay checker.
    fn replay_entries(&self, entries: &[CanonicalEvidenceEntry]) -> ReplayResult {
        let config = ReplayConfig {
            track_schema_migrations: true,
            schema_migration_is_violation: false,
            ..ReplayConfig::default()
        };
        let mut checker = EvidenceReplayChecker::new(config);
        checker.replay(entries, None)
    }

    /// Accumulated events.
    pub fn events(&self) -> &[MigrationCompatibilityEvent] {
        &self.events
    }

    /// Access the migration registry.
    pub fn registry(&self) -> &MigrationRegistry {
        &self.registry
    }

    fn push_event(
        &mut self,
        from: &str,
        to: &str,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(MigrationCompatibilityEvent {
            trace_id: String::new(),
            decision_id: String::new(),
            policy_id: String::new(),
            component: COMPONENT_NAME.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            from_version: from.to_string(),
            to_version: to.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// GoldenLedgerManifest — tracks all golden ledgers with content hashes
// ---------------------------------------------------------------------------

/// Content-addressable manifest of all golden ledgers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoldenLedgerManifest {
    /// Map of ledger name → corpus hash.
    pub entries: BTreeMap<String, ManifestEntry>,
}

/// A single entry in the golden ledger manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub schema_version: String,
    pub corpus_hash: ContentHash,
    pub entry_count: usize,
    pub frozen_at_ms: u64,
}

impl GoldenLedgerManifest {
    /// Create an empty manifest.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Add a golden ledger to the manifest.
    pub fn add(&mut self, ledger: &GoldenLedger) {
        self.entries.insert(
            ledger.name.clone(),
            ManifestEntry {
                schema_version: ledger.schema_version.clone(),
                corpus_hash: ledger.corpus_hash,
                entry_count: ledger.entries.len(),
                frozen_at_ms: ledger.frozen_at_ms,
            },
        );
    }

    /// Check if a golden ledger's hash matches the manifest.
    pub fn verify(&self, ledger: &GoldenLedger) -> bool {
        self.entries
            .get(&ledger.name)
            .is_some_and(|entry| entry.corpus_hash == ledger.corpus_hash)
    }

    /// Number of ledgers tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for GoldenLedgerManifest {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Cutover migration contract (bd-29s)
//
// Explicit cutover boundaries for security-critical format and policy changes.
// No hidden translators: format conversion is an explicit, auditable,
// deterministic cutover operation.
//
// Plan reference: Section 10.10 item 29, bd-29s.
// ===========================================================================

/// Type of cutover for a migration declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CutoverType {
    /// All objects must be in the new format after migration; old format
    /// is rejected.  Used for security-critical changes where dual-format
    /// support creates ambiguity.
    HardCutover,
    /// Both old and new formats accepted during a transition window.
    /// After the window expires, the old format is rejected.
    SoftMigration,
    /// Both old and new pipelines run simultaneously with output comparison
    /// during migration validation.  Discrepancies trigger abort.
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

/// Class of security-critical objects affected by a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObjectClass {
    /// Serialization schemas (evidence, decision, policy).
    SerializationSchema,
    /// Cryptographic key formats.
    KeyFormat,
    /// Authentication / capability token formats.
    TokenFormat,
    /// Checkpoint / epoch formats.
    CheckpointFormat,
    /// Revocation record formats.
    RevocationFormat,
    /// Policy structure / DSL formats.
    PolicyFormat,
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationSchema => write!(f, "serialization_schema"),
            Self::KeyFormat => write!(f, "key_format"),
            Self::TokenFormat => write!(f, "token_format"),
            Self::CheckpointFormat => write!(f, "checkpoint_format"),
            Self::RevocationFormat => write!(f, "revocation_format"),
            Self::PolicyFormat => write!(f, "policy_format"),
        }
    }
}

/// Declares a migration with explicit cutover boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationDeclaration {
    /// Unique identifier for this migration.
    pub migration_id: String,
    /// Source format version.
    pub from_version: String,
    /// Target format version.
    pub to_version: String,
    /// Classes of objects affected.
    pub affected_objects: BTreeSet<ObjectClass>,
    /// Type of cutover.
    pub cutover_type: CutoverType,
    /// Human-readable description of what changes.
    pub description: String,
    /// Compatibility boundary: what is compatible across the boundary.
    pub compatible_across_boundary: Vec<String>,
    /// Compatibility boundary: what is NOT compatible.
    pub incompatible_across_boundary: Vec<String>,
}

/// Phase of migration execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MigrationPhase {
    /// Validate all existing data can be converted (dry run).
    PreMigration,
    /// Create epoch-boundary checkpoint.
    Checkpoint,
    /// Execute the migration (convert data or activate new format).
    Execute,
    /// Run conformance suite against migrated data.
    Verify,
    /// Mark migration as complete; begin rejecting old format.
    Commit,
    /// Rollback to pre-migration state.
    Rollback,
}

impl fmt::Display for MigrationPhase {
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

/// Outcome of a migration phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PhaseOutcome {
    /// Phase completed successfully.
    Success,
    /// Phase failed; migration should be aborted.
    Failed,
    /// Phase skipped (not applicable for this cutover type).
    Skipped,
}

impl fmt::Display for PhaseOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// Record of a single migration phase execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseExecutionRecord {
    pub migration_id: String,
    pub phase: MigrationPhase,
    pub outcome: PhaseOutcome,
    pub affected_count: usize,
    pub detail: String,
    pub timestamp: DeterministicTimestamp,
}

/// Cutover-specific migration error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CutoverError {
    /// Migration declaration is invalid.
    InvalidDeclaration { detail: String },
    /// Pre-migration dry run found data that cannot be converted.
    DryRunFailed { unconvertible_count: usize },
    /// Conformance verification after migration failed.
    VerificationFailed { violations: usize },
    /// Discrepancy detected during parallel run.
    ParallelRunDiscrepancy { discrepancy_count: usize },
    /// Old-format object rejected after hard cutover.
    OldFormatRejected { object_class: ObjectClass },
    /// Transition window expired for soft migration.
    TransitionWindowExpired { migration_id: String },
    /// Migration phase failed.
    PhaseFailed {
        phase: MigrationPhase,
        detail: String,
    },
    /// Migration already committed; cannot rollback.
    AlreadyCommitted { migration_id: String },
    /// No migration in progress.
    NoMigrationInProgress,
    /// Migration not found in registry.
    MigrationNotFound { migration_id: String },
}

impl fmt::Display for CutoverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeclaration { detail } => {
                write!(f, "invalid migration declaration: {detail}")
            }
            Self::DryRunFailed {
                unconvertible_count,
            } => {
                write!(
                    f,
                    "pre-migration dry run failed: {unconvertible_count} unconvertible objects"
                )
            }
            Self::VerificationFailed { violations } => {
                write!(
                    f,
                    "post-migration verification failed: {violations} violations"
                )
            }
            Self::ParallelRunDiscrepancy { discrepancy_count } => {
                write!(
                    f,
                    "parallel run discrepancy: {discrepancy_count} mismatches"
                )
            }
            Self::OldFormatRejected { object_class } => {
                write!(
                    f,
                    "old-format object rejected after hard cutover: {object_class}"
                )
            }
            Self::TransitionWindowExpired { migration_id } => {
                write!(
                    f,
                    "soft migration transition window expired: {migration_id}"
                )
            }
            Self::PhaseFailed { phase, detail } => {
                write!(f, "migration phase {phase} failed: {detail}")
            }
            Self::AlreadyCommitted { migration_id } => {
                write!(f, "migration already committed: {migration_id}")
            }
            Self::NoMigrationInProgress => write!(f, "no migration in progress"),
            Self::MigrationNotFound { migration_id } => {
                write!(f, "migration not found: {migration_id}")
            }
        }
    }
}

impl std::error::Error for CutoverError {}

/// Stable error codes for cutover errors.
pub fn cutover_error_code(err: &CutoverError) -> &'static str {
    match err {
        CutoverError::InvalidDeclaration { .. } => "MC_INVALID_DECLARATION",
        CutoverError::DryRunFailed { .. } => "MC_DRY_RUN_FAILED",
        CutoverError::VerificationFailed { .. } => "MC_VERIFICATION_FAILED",
        CutoverError::ParallelRunDiscrepancy { .. } => "MC_PARALLEL_DISCREPANCY",
        CutoverError::OldFormatRejected { .. } => "MC_OLD_FORMAT_REJECTED",
        CutoverError::TransitionWindowExpired { .. } => "MC_WINDOW_EXPIRED",
        CutoverError::PhaseFailed { .. } => "MC_PHASE_FAILED",
        CutoverError::AlreadyCommitted { .. } => "MC_ALREADY_COMMITTED",
        CutoverError::NoMigrationInProgress => "MC_NO_MIGRATION",
        CutoverError::MigrationNotFound { .. } => "MC_NOT_FOUND",
    }
}

/// State of a cutover migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CutoverState {
    /// Declared but not started.
    Declared,
    /// Pre-migration dry run in progress or complete.
    PreMigrated,
    /// Checkpoint created.
    Checkpointed,
    /// Data migration executed.
    Executed,
    /// Post-migration verification passed.
    Verified,
    /// Migration committed; old format rejected.
    Committed,
    /// Migration rolled back.
    RolledBack,
}

impl fmt::Display for CutoverState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declared => write!(f, "declared"),
            Self::PreMigrated => write!(f, "pre_migrated"),
            Self::Checkpointed => write!(f, "checkpointed"),
            Self::Executed => write!(f, "executed"),
            Self::Verified => write!(f, "verified"),
            Self::Committed => write!(f, "committed"),
            Self::RolledBack => write!(f, "rolled_back"),
        }
    }
}

/// Entry in the applied migrations log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedMigrationEntry {
    pub migration_id: String,
    pub from_version: String,
    pub to_version: String,
    pub cutover_type: CutoverType,
    pub state: CutoverState,
    pub affected_objects: BTreeSet<ObjectClass>,
    pub phase_records: Vec<PhaseExecutionRecord>,
    pub declared_at: DeterministicTimestamp,
    pub committed_at: Option<DeterministicTimestamp>,
}

/// Structured audit event for cutover migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoverAuditEvent {
    pub trace_id: String,
    pub component: String,
    pub migration_id: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub phase: Option<String>,
    pub affected_count: Option<usize>,
    pub timestamp: DeterministicTimestamp,
}

/// Transition window for soft migrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionWindow {
    pub migration_id: String,
    pub start_tick: u64,
    pub end_tick: u64,
    /// Whether old format is still accepted.
    pub old_format_accepted: bool,
}

impl TransitionWindow {
    /// Check if the window is expired at the given tick.
    pub fn is_expired(&self, current_tick: u64) -> bool {
        current_tick >= self.end_tick
    }

    /// Check if the window is active at the given tick.
    pub fn is_active(&self, current_tick: u64) -> bool {
        current_tick >= self.start_tick && current_tick < self.end_tick
    }
}

/// Grouped input for audit event recording (avoids >7 arg functions).
struct AuditInput<'a> {
    trace_id: &'a str,
    migration_id: &'a str,
    event: &'a str,
    outcome: &'a str,
    phase: Option<&'a str>,
    affected_count: Option<usize>,
    error_code: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// CutoverMigrationRunner — orchestrates multi-step migration
// ---------------------------------------------------------------------------

/// Orchestrates the multi-step cutover migration process.
#[derive(Debug)]
pub struct CutoverMigrationRunner {
    /// All declared migrations.
    declarations: Vec<MigrationDeclaration>,
    /// Applied migration log (append-only).
    applied: Vec<AppliedMigrationEntry>,
    /// Currently in-progress migration (at most one).
    active_migration: Option<ActiveMigration>,
    /// Structured audit events.
    audit_events: Vec<CutoverAuditEvent>,
    /// Transition windows for soft migrations.
    transition_windows: Vec<TransitionWindow>,
    /// Current logical tick.
    current_tick: u64,
}

/// Internal state for an active migration.
#[derive(Debug, Clone)]
struct ActiveMigration {
    declaration: MigrationDeclaration,
    state: CutoverState,
    phase_records: Vec<PhaseExecutionRecord>,
    pre_migration_data_count: usize,
    checkpoint_seq: Option<u64>,
    verification_violations: usize,
    parallel_discrepancies: usize,
}

impl CutoverMigrationRunner {
    /// Create a new runner.
    pub fn new() -> Self {
        Self {
            declarations: Vec::new(),
            applied: Vec::new(),
            active_migration: None,
            audit_events: Vec::new(),
            transition_windows: Vec::new(),
            current_tick: 0,
        }
    }

    /// Set the current logical tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Declare a migration.  Does not start execution.
    pub fn declare(
        &mut self,
        declaration: MigrationDeclaration,
        trace_id: &str,
    ) -> Result<(), CutoverError> {
        // Validate declaration.
        if declaration.migration_id.is_empty() {
            return Err(CutoverError::InvalidDeclaration {
                detail: "migration_id is empty".to_string(),
            });
        }
        if declaration.affected_objects.is_empty() {
            return Err(CutoverError::InvalidDeclaration {
                detail: "affected_objects is empty".to_string(),
            });
        }
        if declaration.from_version == declaration.to_version {
            return Err(CutoverError::InvalidDeclaration {
                detail: "from_version equals to_version".to_string(),
            });
        }

        // Check for duplicate migration_id.
        if self
            .declarations
            .iter()
            .any(|d| d.migration_id == declaration.migration_id)
        {
            return Err(CutoverError::InvalidDeclaration {
                detail: format!("duplicate migration_id: {}", declaration.migration_id),
            });
        }

        self.push_audit(AuditInput {
            trace_id,
            migration_id: &declaration.migration_id,
            event: "migration_declared",
            outcome: "ok",
            phase: None,
            affected_count: None,
            error_code: None,
        });
        self.declarations.push(declaration);
        Ok(())
    }

    /// Begin execution of a declared migration.
    /// Starts with the pre-migration (dry run) phase.
    pub fn begin(
        &mut self,
        migration_id: &str,
        data_count: usize,
        trace_id: &str,
    ) -> Result<(), CutoverError> {
        if self.active_migration.is_some() {
            return Err(CutoverError::PhaseFailed {
                phase: MigrationPhase::PreMigration,
                detail: "another migration is already in progress".to_string(),
            });
        }

        let declaration = self
            .declarations
            .iter()
            .find(|d| d.migration_id == migration_id)
            .cloned()
            .ok_or_else(|| CutoverError::MigrationNotFound {
                migration_id: migration_id.to_string(),
            })?;

        let record = PhaseExecutionRecord {
            migration_id: migration_id.to_string(),
            phase: MigrationPhase::PreMigration,
            outcome: PhaseOutcome::Success,
            affected_count: data_count,
            detail: "dry run complete".to_string(),
            timestamp: DeterministicTimestamp(self.current_tick),
        };

        self.active_migration = Some(ActiveMigration {
            declaration: declaration.clone(),
            state: CutoverState::PreMigrated,
            phase_records: vec![record],
            pre_migration_data_count: data_count,
            checkpoint_seq: None,
            verification_violations: 0,
            parallel_discrepancies: 0,
        });

        self.push_audit(AuditInput {
            trace_id,
            migration_id,
            event: "pre_migration_complete",
            outcome: "ok",
            phase: Some("pre_migration"),
            affected_count: Some(data_count),
            error_code: None,
        });

        Ok(())
    }

    /// Report a dry-run failure (unconvertible data found).
    pub fn fail_dry_run(
        &mut self,
        unconvertible_count: usize,
        trace_id: &str,
    ) -> Result<(), CutoverError> {
        let active = self
            .active_migration
            .as_mut()
            .ok_or(CutoverError::NoMigrationInProgress)?;

        active.state = CutoverState::RolledBack;
        active.phase_records.push(PhaseExecutionRecord {
            migration_id: active.declaration.migration_id.clone(),
            phase: MigrationPhase::PreMigration,
            outcome: PhaseOutcome::Failed,
            affected_count: unconvertible_count,
            detail: format!("{unconvertible_count} objects cannot be converted"),
            timestamp: DeterministicTimestamp(self.current_tick),
        });

        let mid = active.declaration.migration_id.clone();
        self.push_audit(AuditInput {
            trace_id,
            migration_id: &mid,
            event: "dry_run_failed",
            outcome: "fail",
            phase: Some("pre_migration"),
            affected_count: Some(unconvertible_count),
            error_code: Some("MC_DRY_RUN_FAILED"),
        });

        // Move to applied log as rolled back.
        self.finalize_active(CutoverState::RolledBack);
        Err(CutoverError::DryRunFailed {
            unconvertible_count,
        })
    }

    /// Create the epoch-boundary checkpoint.
    pub fn create_checkpoint(
        &mut self,
        checkpoint_seq: u64,
        trace_id: &str,
    ) -> Result<(), CutoverError> {
        let active = self
            .active_migration
            .as_mut()
            .ok_or(CutoverError::NoMigrationInProgress)?;

        if active.state != CutoverState::PreMigrated {
            return Err(CutoverError::PhaseFailed {
                phase: MigrationPhase::Checkpoint,
                detail: format!("expected PreMigrated state, got {}", active.state),
            });
        }

        active.checkpoint_seq = Some(checkpoint_seq);
        active.state = CutoverState::Checkpointed;
        active.phase_records.push(PhaseExecutionRecord {
            migration_id: active.declaration.migration_id.clone(),
            phase: MigrationPhase::Checkpoint,
            outcome: PhaseOutcome::Success,
            affected_count: 0,
            detail: format!("checkpoint_seq={checkpoint_seq}"),
            timestamp: DeterministicTimestamp(self.current_tick),
        });

        let mid = active.declaration.migration_id.clone();
        self.push_audit(AuditInput {
            trace_id,
            migration_id: &mid,
            event: "checkpoint_created",
            outcome: "ok",
            phase: Some("checkpoint"),
            affected_count: None,
            error_code: None,
        });

        Ok(())
    }

    /// Execute the migration (convert data or activate new format).
    pub fn execute(&mut self, converted_count: usize, trace_id: &str) -> Result<(), CutoverError> {
        let active = self
            .active_migration
            .as_mut()
            .ok_or(CutoverError::NoMigrationInProgress)?;

        if active.state != CutoverState::Checkpointed {
            return Err(CutoverError::PhaseFailed {
                phase: MigrationPhase::Execute,
                detail: format!("expected Checkpointed state, got {}", active.state),
            });
        }

        active.state = CutoverState::Executed;
        active.phase_records.push(PhaseExecutionRecord {
            migration_id: active.declaration.migration_id.clone(),
            phase: MigrationPhase::Execute,
            outcome: PhaseOutcome::Success,
            affected_count: converted_count,
            detail: format!("{converted_count} objects converted"),
            timestamp: DeterministicTimestamp(self.current_tick),
        });

        let mid = active.declaration.migration_id.clone();
        self.push_audit(AuditInput {
            trace_id,
            migration_id: &mid,
            event: "migration_executed",
            outcome: "ok",
            phase: Some("execute"),
            affected_count: Some(converted_count),
            error_code: None,
        });

        Ok(())
    }

    /// Report verification outcome.
    /// `violations == 0` means verification passed.
    pub fn verify(&mut self, violations: usize, trace_id: &str) -> Result<(), CutoverError> {
        let active = self
            .active_migration
            .as_mut()
            .ok_or(CutoverError::NoMigrationInProgress)?;

        if active.state != CutoverState::Executed {
            return Err(CutoverError::PhaseFailed {
                phase: MigrationPhase::Verify,
                detail: format!("expected Executed state, got {}", active.state),
            });
        }

        active.verification_violations = violations;

        if violations > 0 {
            active.phase_records.push(PhaseExecutionRecord {
                migration_id: active.declaration.migration_id.clone(),
                phase: MigrationPhase::Verify,
                outcome: PhaseOutcome::Failed,
                affected_count: violations,
                detail: format!("{violations} conformance violations"),
                timestamp: DeterministicTimestamp(self.current_tick),
            });

            let mid = active.declaration.migration_id.clone();
            self.push_audit(AuditInput {
                trace_id,
                migration_id: &mid,
                event: "verification_failed",
                outcome: "fail",
                phase: Some("verify"),
                affected_count: Some(violations),
                error_code: Some("MC_VERIFICATION_FAILED"),
            });

            // Auto-rollback on verification failure.
            self.finalize_active(CutoverState::RolledBack);
            return Err(CutoverError::VerificationFailed { violations });
        }

        active.state = CutoverState::Verified;
        active.phase_records.push(PhaseExecutionRecord {
            migration_id: active.declaration.migration_id.clone(),
            phase: MigrationPhase::Verify,
            outcome: PhaseOutcome::Success,
            affected_count: 0,
            detail: "conformance passed".to_string(),
            timestamp: DeterministicTimestamp(self.current_tick),
        });

        let mid = active.declaration.migration_id.clone();
        self.push_audit(AuditInput {
            trace_id,
            migration_id: &mid,
            event: "verification_passed",
            outcome: "ok",
            phase: Some("verify"),
            affected_count: None,
            error_code: None,
        });

        Ok(())
    }

    /// Report parallel run discrepancies.
    pub fn report_parallel_discrepancies(
        &mut self,
        discrepancy_count: usize,
        trace_id: &str,
    ) -> Result<(), CutoverError> {
        let active = self
            .active_migration
            .as_mut()
            .ok_or(CutoverError::NoMigrationInProgress)?;

        if active.declaration.cutover_type != CutoverType::ParallelRun {
            return Err(CutoverError::PhaseFailed {
                phase: MigrationPhase::Verify,
                detail: "parallel discrepancy only valid for ParallelRun cutover".to_string(),
            });
        }

        active.parallel_discrepancies = discrepancy_count;

        if discrepancy_count > 0 {
            let mid = active.declaration.migration_id.clone();
            self.push_audit(AuditInput {
                trace_id,
                migration_id: &mid,
                event: "parallel_run_discrepancy",
                outcome: "fail",
                phase: Some("verify"),
                affected_count: Some(discrepancy_count),
                error_code: Some("MC_PARALLEL_DISCREPANCY"),
            });

            self.finalize_active(CutoverState::RolledBack);
            return Err(CutoverError::ParallelRunDiscrepancy { discrepancy_count });
        }

        Ok(())
    }

    /// Commit the migration.  After commit, old format is rejected
    /// (for hard cutover) or transition window begins (for soft migration).
    pub fn commit(&mut self, trace_id: &str) -> Result<AppliedMigrationEntry, CutoverError> {
        let active = self
            .active_migration
            .as_mut()
            .ok_or(CutoverError::NoMigrationInProgress)?;

        if active.state != CutoverState::Verified {
            return Err(CutoverError::PhaseFailed {
                phase: MigrationPhase::Commit,
                detail: format!("expected Verified state, got {}", active.state),
            });
        }

        active.state = CutoverState::Committed;
        active.phase_records.push(PhaseExecutionRecord {
            migration_id: active.declaration.migration_id.clone(),
            phase: MigrationPhase::Commit,
            outcome: PhaseOutcome::Success,
            affected_count: active.pre_migration_data_count,
            detail: "migration committed".to_string(),
            timestamp: DeterministicTimestamp(self.current_tick),
        });

        // For soft migrations, open a transition window.
        if active.declaration.cutover_type == CutoverType::SoftMigration {
            self.transition_windows.push(TransitionWindow {
                migration_id: active.declaration.migration_id.clone(),
                start_tick: self.current_tick,
                end_tick: self.current_tick + 1000, // default window
                old_format_accepted: true,
            });
        }

        let mid = active.declaration.migration_id.clone();
        self.push_audit(AuditInput {
            trace_id,
            migration_id: &mid,
            event: "migration_committed",
            outcome: "ok",
            phase: Some("commit"),
            affected_count: None,
            error_code: None,
        });

        let entry = self.finalize_active(CutoverState::Committed);
        Ok(entry)
    }

    /// Rollback the active migration.
    pub fn rollback(&mut self, trace_id: &str) -> Result<(), CutoverError> {
        let active = self
            .active_migration
            .as_mut()
            .ok_or(CutoverError::NoMigrationInProgress)?;

        if active.state == CutoverState::Committed {
            return Err(CutoverError::AlreadyCommitted {
                migration_id: active.declaration.migration_id.clone(),
            });
        }

        active.phase_records.push(PhaseExecutionRecord {
            migration_id: active.declaration.migration_id.clone(),
            phase: MigrationPhase::Rollback,
            outcome: PhaseOutcome::Success,
            affected_count: 0,
            detail: "rolled back".to_string(),
            timestamp: DeterministicTimestamp(self.current_tick),
        });

        let mid = active.declaration.migration_id.clone();
        self.push_audit(AuditInput {
            trace_id,
            migration_id: &mid,
            event: "migration_rolled_back",
            outcome: "ok",
            phase: Some("rollback"),
            affected_count: None,
            error_code: None,
        });

        self.finalize_active(CutoverState::RolledBack);
        Ok(())
    }

    /// Check whether an old-format object should be accepted.
    /// Returns `Err(OldFormatRejected)` if a hard cutover has been committed
    /// for this object class.
    pub fn check_format_acceptance(&self, object_class: ObjectClass) -> Result<(), CutoverError> {
        for entry in self.applied.iter().rev() {
            if entry.state != CutoverState::Committed {
                continue;
            }
            if !entry.affected_objects.contains(&object_class) {
                continue;
            }

            match entry.cutover_type {
                CutoverType::HardCutover => {
                    return Err(CutoverError::OldFormatRejected { object_class });
                }
                CutoverType::SoftMigration => {
                    // Check if transition window is still open.
                    let window = self
                        .transition_windows
                        .iter()
                        .find(|w| w.migration_id == entry.migration_id);
                    if let Some(w) = window
                        && w.is_expired(self.current_tick)
                    {
                        return Err(CutoverError::TransitionWindowExpired {
                            migration_id: entry.migration_id.clone(),
                        });
                    }
                }
                CutoverType::ParallelRun => {
                    // Parallel run always accepts both formats during comparison.
                }
            }
        }
        Ok(())
    }

    // -- Accessors ----------------------------------------------------------

    /// Number of declared migrations.
    pub fn declaration_count(&self) -> usize {
        self.declarations.len()
    }

    /// Applied migrations log.
    pub fn applied_migrations(&self) -> &[AppliedMigrationEntry] {
        &self.applied
    }

    /// Drain accumulated audit events.
    pub fn drain_audit_events(&mut self) -> Vec<CutoverAuditEvent> {
        std::mem::take(&mut self.audit_events)
    }

    /// Access audit events.
    pub fn audit_events(&self) -> &[CutoverAuditEvent] {
        &self.audit_events
    }

    /// Active migration state.
    pub fn active_state(&self) -> Option<CutoverState> {
        self.active_migration.as_ref().map(|m| m.state)
    }

    /// Active migration id.
    pub fn active_migration_id(&self) -> Option<&str> {
        self.active_migration
            .as_ref()
            .map(|m| m.declaration.migration_id.as_str())
    }

    /// Transition windows.
    pub fn transition_windows(&self) -> &[TransitionWindow] {
        &self.transition_windows
    }

    // -- Internal -----------------------------------------------------------

    fn finalize_active(&mut self, final_state: CutoverState) -> AppliedMigrationEntry {
        let active = self.active_migration.take().expect("must have active");
        let entry = AppliedMigrationEntry {
            migration_id: active.declaration.migration_id,
            from_version: active.declaration.from_version,
            to_version: active.declaration.to_version,
            cutover_type: active.declaration.cutover_type,
            state: final_state,
            affected_objects: active.declaration.affected_objects,
            phase_records: active.phase_records.clone(),
            declared_at: active
                .phase_records
                .first()
                .map(|r| r.timestamp)
                .unwrap_or(DeterministicTimestamp(self.current_tick)),
            committed_at: if final_state == CutoverState::Committed {
                Some(DeterministicTimestamp(self.current_tick))
            } else {
                None
            },
        };
        self.applied.push(entry.clone());
        entry
    }

    fn push_audit(&mut self, input: AuditInput<'_>) {
        self.audit_events.push(CutoverAuditEvent {
            trace_id: input.trace_id.to_string(),
            component: COMPONENT_NAME.to_string(),
            migration_id: input.migration_id.to_string(),
            event: input.event.to_string(),
            outcome: input.outcome.to_string(),
            error_code: input.error_code.map(str::to_string),
            phase: input.phase.map(str::to_string),
            affected_count: input.affected_count,
            timestamp: DeterministicTimestamp(self.current_tick),
        });
    }
}

impl Default for CutoverMigrationRunner {
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
    use crate::control_plane::mocks::{
        MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
    };
    use crate::evidence_emission::{
        ActionCategory, CanonicalEvidenceEmitter, EmitterConfig, EvidenceEmissionRequest,
    };
    use std::collections::BTreeMap;

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    fn mock_cx() -> MockCx {
        MockCx::new(trace_id_from_seed(1), MockBudget::new(100_000))
    }

    fn make_emitter() -> CanonicalEvidenceEmitter {
        CanonicalEvidenceEmitter::new(EmitterConfig::default())
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
                m.insert("deny".to_string(), 0.4);
                m
            },
            chosen_expected_loss: 0.1,
            calibration_score: 0.94,
            fallback_active: false,
            top_features: vec![("feature_a".to_string(), 0.85)],
            metadata: BTreeMap::new(),
        }
    }

    fn build_golden_ledger(name: &str, schema_version: &str, n: usize) -> GoldenLedger {
        let mut emitter = make_emitter();
        let mut cx = mock_cx();
        for i in 0..n {
            let ts = 1_700_000_000_000 + (i as u64) * 1000;
            let req = make_request(&format!("action_{i}"), ts);
            emitter.emit(&mut cx, &req).expect("emit");
        }
        let entries = emitter.entries().to_vec();
        GoldenLedger::freeze(name, schema_version, entries, 1_700_000_000_000)
    }

    fn build_golden_ledger_with_versions(name: &str, versions: &[&str]) -> GoldenLedger {
        let mut emitter = make_emitter();
        let mut cx = mock_cx();
        for (i, _) in versions.iter().enumerate() {
            let ts = 1_700_000_000_000 + (i as u64) * 1000;
            let req = make_request(&format!("action_{i}"), ts);
            emitter.emit(&mut cx, &req).expect("emit");
        }
        let mut entries = emitter.entries().to_vec();
        for (i, ver) in versions.iter().enumerate() {
            entries[i].schema_version = ver.to_string();
        }
        let first_version = versions.first().copied().unwrap_or("evidence-v1");
        GoldenLedger::freeze(name, first_version, entries, 1_700_000_000_000)
    }

    /// Identity migration: entries pass through unchanged (for testing).
    fn identity_migration(
        entry: &CanonicalEvidenceEntry,
    ) -> Result<CanonicalEvidenceEntry, MigrationError> {
        Ok(entry.clone())
    }

    /// Version-bumping migration: updates schema_version to v2.
    fn v1_to_v2_migration(
        entry: &CanonicalEvidenceEntry,
    ) -> Result<CanonicalEvidenceEntry, MigrationError> {
        let mut migrated = entry.clone();
        migrated.schema_version = "evidence-v2".to_string();
        // Add a migration marker in metadata.
        migrated
            .metadata
            .insert("migrated_from".to_string(), "evidence-v1".to_string());
        Ok(migrated)
    }

    /// Failing migration: always returns an error.
    fn failing_migration(
        entry: &CanonicalEvidenceEntry,
    ) -> Result<CanonicalEvidenceEntry, MigrationError> {
        Err(MigrationError {
            from_version: entry.schema_version.clone(),
            to_version: "evidence-v2".to_string(),
            error_code: MigrationErrorCode::RequiredFieldMissing,
            incompatible_fields: vec![IncompatibleField {
                field_path: "metadata.new_required_field".to_string(),
                reason: "field required in v2 but absent in v1".to_string(),
            }],
            message: "cannot migrate: required field missing".to_string(),
        })
    }

    // -------------------------------------------------------------------
    // MigrationErrorCode
    // -------------------------------------------------------------------

    #[test]
    fn migration_error_code_display() {
        assert_eq!(
            MigrationErrorCode::MajorVersionIncompatible.to_string(),
            "major_version_incompatible"
        );
        assert_eq!(
            MigrationErrorCode::NonDeterministicMigration.to_string(),
            "non_deterministic_migration"
        );
        assert_eq!(
            MigrationErrorCode::NoMigrationPath.to_string(),
            "no_migration_path"
        );
    }

    #[test]
    fn migration_error_code_ordering() {
        assert!(
            MigrationErrorCode::MajorVersionIncompatible < MigrationErrorCode::RequiredFieldMissing
        );
    }

    #[test]
    fn migration_error_code_serde_roundtrip() {
        for code in [
            MigrationErrorCode::MajorVersionIncompatible,
            MigrationErrorCode::RequiredFieldMissing,
            MigrationErrorCode::FieldTypeChanged,
            MigrationErrorCode::MigrationFunctionFailed,
            MigrationErrorCode::NonDeterministicMigration,
            MigrationErrorCode::PartialReplayFailure,
            MigrationErrorCode::NoMigrationPath,
            MigrationErrorCode::LossyMigration,
        ] {
            let json = serde_json::to_string(&code).expect("serialize");
            let restored: MigrationErrorCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(code, restored);
        }
    }

    // -------------------------------------------------------------------
    // MigrationError
    // -------------------------------------------------------------------

    #[test]
    fn migration_error_display() {
        let err = MigrationError {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            error_code: MigrationErrorCode::RequiredFieldMissing,
            incompatible_fields: vec![IncompatibleField {
                field_path: "metadata.x".to_string(),
                reason: "missing".to_string(),
            }],
            message: "test".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("v1"));
        assert!(s.contains("v2"));
        assert!(s.contains("1 incompatible fields"));
    }

    #[test]
    fn migration_error_serde_roundtrip() {
        let err = MigrationError {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            error_code: MigrationErrorCode::FieldTypeChanged,
            incompatible_fields: vec![
                IncompatibleField {
                    field_path: "candidates[0].expected_loss".to_string(),
                    reason: "type changed from i64 to f64".to_string(),
                },
                IncompatibleField {
                    field_path: "metadata.score".to_string(),
                    reason: "renamed to metadata.calibration_score".to_string(),
                },
            ],
            message: "two fields incompatible".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: MigrationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    // -------------------------------------------------------------------
    // GoldenLedger
    // -------------------------------------------------------------------

    #[test]
    fn golden_ledger_freeze_and_verify() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);
        assert_eq!(ledger.name, "test-v1");
        assert_eq!(ledger.schema_version, "evidence-v1");
        assert_eq!(ledger.len(), 5);
        assert!(!ledger.is_empty());
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn golden_ledger_tamper_detected() {
        let mut ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        assert!(ledger.verify_integrity());

        // Tamper with an entry.
        ledger.entries[1].action_name = "tampered".to_string();
        assert!(!ledger.verify_integrity());
    }

    #[test]
    fn golden_ledger_serde_roundtrip() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        let json = serde_json::to_string(&ledger).expect("serialize");
        let restored: GoldenLedger = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ledger, restored);
    }

    #[test]
    fn golden_ledger_empty() {
        let ledger = GoldenLedger::freeze("empty", "evidence-v1", Vec::new(), 0);
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert!(ledger.verify_integrity());
    }

    // -------------------------------------------------------------------
    // MigrationOutcome
    // -------------------------------------------------------------------

    #[test]
    fn migration_outcome_display() {
        assert_eq!(
            MigrationOutcome::BackwardCompatible.to_string(),
            "backward_compatible"
        );
        assert_eq!(
            MigrationOutcome::MigratedSuccessfully.to_string(),
            "migrated_successfully"
        );
        assert_eq!(
            MigrationOutcome::LossyMigration.to_string(),
            "lossy_migration"
        );
        assert_eq!(MigrationOutcome::Failed.to_string(), "failed");
    }

    #[test]
    fn migration_outcome_serde_roundtrip() {
        for outcome in [
            MigrationOutcome::BackwardCompatible,
            MigrationOutcome::MigratedSuccessfully,
            MigrationOutcome::LossyMigration,
            MigrationOutcome::Failed,
        ] {
            let json = serde_json::to_string(&outcome).expect("serialize");
            let restored: MigrationOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(outcome, restored);
        }
    }

    // -------------------------------------------------------------------
    // MigrationRegistry
    // -------------------------------------------------------------------

    #[test]
    fn registry_find_registered_migration() {
        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "test migration".to_string(),
            },
            identity_migration,
        );

        assert!(registry.find("evidence-v1", "evidence-v2").is_some());
        assert!(registry.find("evidence-v2", "evidence-v3").is_none());
    }

    #[test]
    fn registry_all_migrations() {
        let mut registry = MigrationRegistry::new();
        assert!(registry.all().is_empty());

        registry.register(
            MigrationFunction {
                from_version: "v1".to_string(),
                to_version: "v2".to_string(),
                lossy: false,
                description: "m1".to_string(),
            },
            identity_migration,
        );
        registry.register(
            MigrationFunction {
                from_version: "v2".to_string(),
                to_version: "v3".to_string(),
                lossy: true,
                description: "m2".to_string(),
            },
            identity_migration,
        );

        assert_eq!(registry.all().len(), 2);
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — backward compatibility
    // -------------------------------------------------------------------

    #[test]
    fn checker_backward_compatible_same_version() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);
        let registry = MigrationRegistry::new();
        let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed());
        assert_eq!(results[0].outcome, MigrationOutcome::BackwardCompatible);
        assert_eq!(results[0].entries_processed, 5);
        assert_eq!(results[0].entries_replayed_ok, 5);
        assert!(results[0].determinism_verified);
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — successful migration
    // -------------------------------------------------------------------

    #[test]
    fn checker_successful_migration_v1_to_v2() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);

        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "add metadata field".to_string(),
            },
            v1_to_v2_migration,
        );

        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed());
        assert_eq!(results[0].outcome, MigrationOutcome::MigratedSuccessfully);
        assert!(results[0].determinism_verified);
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — no migration path
    // -------------------------------------------------------------------

    #[test]
    fn checker_no_migration_path() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        let registry = MigrationRegistry::new(); // empty

        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed());
        assert_eq!(results[0].outcome, MigrationOutcome::Failed);
        assert_eq!(results[0].errors.len(), 1);
        assert_eq!(
            results[0].errors[0].error_code,
            MigrationErrorCode::NoMigrationPath
        );
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — failing migration function
    // -------------------------------------------------------------------

    #[test]
    fn checker_failing_migration_function() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);

        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "broken migration".to_string(),
            },
            failing_migration,
        );

        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed());
        assert_eq!(results[0].outcome, MigrationOutcome::Failed);
        assert_eq!(results[0].errors.len(), 3); // One per entry
        assert_eq!(
            results[0].errors[0].error_code,
            MigrationErrorCode::RequiredFieldMissing
        );
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — lossy migration
    // -------------------------------------------------------------------

    #[test]
    fn checker_lossy_migration_marked() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);

        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: true,
                description: "lossy schema change".to_string(),
            },
            v1_to_v2_migration,
        );

        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed());
        assert_eq!(results[0].outcome, MigrationOutcome::LossyMigration);
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — multiple golden ledgers
    // -------------------------------------------------------------------

    #[test]
    fn checker_multiple_golden_ledgers() {
        let ledger_v1 = build_golden_ledger("v1-corpus", "evidence-v1", 3);
        let ledger_v2 = build_golden_ledger("v2-corpus", "evidence-v2", 4);

        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "v1 to v2".to_string(),
            },
            v1_to_v2_migration,
        );

        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger_v1);
        checker.add_golden_ledger(ledger_v2);

        let results = checker.run_all();
        assert_eq!(results.len(), 2);
        assert!(results[0].passed()); // v1 migrated to v2
        assert!(results[1].passed()); // v2 backward compatible
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — determinism verification
    // -------------------------------------------------------------------

    #[test]
    fn checker_deterministic_migration_verified() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);

        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "deterministic migration".to_string(),
            },
            v1_to_v2_migration,
        );

        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert!(results[0].determinism_verified);
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityChecker — structured events
    // -------------------------------------------------------------------

    #[test]
    fn checker_emits_structured_events() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        let registry = MigrationRegistry::new();
        let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
        checker.add_golden_ledger(ledger);

        let _ = checker.run_all();

        let events = checker.events();
        assert!(!events.is_empty());
        assert_eq!(events[0].component, "migration_compatibility");
        assert_eq!(events[0].event, "backward_compat_check");
        assert_eq!(events[0].outcome, "pass");
    }

    #[test]
    fn checker_events_have_version_info() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        let registry = MigrationRegistry::new();
        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);

        let _ = checker.run_all();

        let events = checker.events();
        assert!(!events.is_empty());
        assert_eq!(events[0].from_version, "evidence-v1");
        assert_eq!(events[0].to_version, "evidence-v2");
    }

    // -------------------------------------------------------------------
    // MigrationCompatibilityEvent — serde
    // -------------------------------------------------------------------

    #[test]
    fn migration_event_serde_roundtrip() {
        let event = MigrationCompatibilityEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "migration_compatibility".to_string(),
            event: "backward_compat_check".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: MigrationCompatibilityEvent =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -------------------------------------------------------------------
    // MigrationTestResult — serde and passed()
    // -------------------------------------------------------------------

    #[test]
    fn test_result_passed_when_no_errors() {
        let result = MigrationTestResult {
            golden_ledger_name: "test".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            outcome: MigrationOutcome::MigratedSuccessfully,
            entries_processed: 5,
            entries_replayed_ok: 5,
            errors: Vec::new(),
            replay_violations: 0,
            schema_migrations_detected: Vec::new(),
            determinism_verified: true,
        };
        assert!(result.passed());
    }

    #[test]
    fn test_result_failed_with_replay_violations() {
        let result = MigrationTestResult {
            golden_ledger_name: "test".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            outcome: MigrationOutcome::MigratedSuccessfully,
            entries_processed: 5,
            entries_replayed_ok: 3,
            errors: Vec::new(),
            replay_violations: 2,
            schema_migrations_detected: Vec::new(),
            determinism_verified: true,
        };
        assert!(!result.passed());
    }

    #[test]
    fn test_result_failed_with_errors() {
        let result = MigrationTestResult {
            golden_ledger_name: "test".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            outcome: MigrationOutcome::Failed,
            entries_processed: 5,
            entries_replayed_ok: 0,
            errors: vec![MigrationError {
                from_version: "v1".to_string(),
                to_version: "v2".to_string(),
                error_code: MigrationErrorCode::NoMigrationPath,
                incompatible_fields: Vec::new(),
                message: "no path".to_string(),
            }],
            replay_violations: 0,
            schema_migrations_detected: Vec::new(),
            determinism_verified: false,
        };
        assert!(!result.passed());
    }

    // -------------------------------------------------------------------
    // GoldenLedgerManifest
    // -------------------------------------------------------------------

    #[test]
    fn manifest_add_and_verify() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        let mut manifest = GoldenLedgerManifest::new();
        manifest.add(&ledger);

        assert_eq!(manifest.len(), 1);
        assert!(!manifest.is_empty());
        assert!(manifest.verify(&ledger));
    }

    #[test]
    fn manifest_tampered_ledger_fails_verify() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        let mut manifest = GoldenLedgerManifest::new();
        manifest.add(&ledger);

        // Create a tampered version.
        let mut tampered = ledger;
        tampered.entries[0].action_name = "tampered".to_string();
        // Recompute corpus_hash for the tampered entries.
        let payload = serde_json::to_vec(&tampered.entries).unwrap();
        tampered.corpus_hash = ContentHash::compute(&payload);

        assert!(!manifest.verify(&tampered));
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
        let mut manifest = GoldenLedgerManifest::new();
        manifest.add(&ledger);

        let json = serde_json::to_string(&manifest).expect("serialize");
        let restored: GoldenLedgerManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, restored);
    }

    #[test]
    fn manifest_unknown_ledger_fails_verify() {
        let ledger = build_golden_ledger("unknown", "evidence-v1", 3);
        let manifest = GoldenLedgerManifest::new();
        assert!(!manifest.verify(&ledger));
    }

    // -------------------------------------------------------------------
    // Mixed schema versions in a single ledger
    // -------------------------------------------------------------------

    #[test]
    fn mixed_schema_versions_detected_in_replay() {
        let ledger = build_golden_ledger_with_versions(
            "mixed",
            &[
                "evidence-v1",
                "evidence-v1",
                "evidence-v2",
                "evidence-v2",
                "evidence-v3",
            ],
        );

        let registry = MigrationRegistry::new();
        let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert_eq!(results.len(), 1);
        // The migration boundaries should be detected.
        let migrations = &results[0].schema_migrations_detected;
        assert_eq!(migrations.len(), 2); // v1→v2 and v2→v3
    }

    // -------------------------------------------------------------------
    // Partial replay failure detection
    // -------------------------------------------------------------------

    #[test]
    fn partial_replay_flagged_not_treated_as_pass() {
        // Build a ledger where migration fails for all entries.
        // (Since MigrationTransformFn is a function pointer, not a closure,
        // we test via the failing_migration function.)
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);
        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "partial fail migration".to_string(),
            },
            failing_migration,
        );

        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);

        let results = checker.run_all();
        assert!(!results[0].passed());
        assert_eq!(results[0].outcome, MigrationOutcome::Failed);
    }

    // -------------------------------------------------------------------
    // Run-all determinism
    // -------------------------------------------------------------------

    #[test]
    fn run_all_deterministic_across_runs() {
        let make_checker = || {
            let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);

            let mut registry = MigrationRegistry::new();
            registry.register(
                MigrationFunction {
                    from_version: "evidence-v1".to_string(),
                    to_version: "evidence-v2".to_string(),
                    lossy: false,
                    description: "test".to_string(),
                },
                v1_to_v2_migration,
            );

            let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
            checker.add_golden_ledger(ledger);
            checker
        };

        let mut c1 = make_checker();
        let mut c2 = make_checker();

        let r1 = c1.run_all();
        let r2 = c2.run_all();

        // Compare serialized results for exact determinism.
        let j1 = serde_json::to_string(&r1).unwrap();
        let j2 = serde_json::to_string(&r2).unwrap();
        assert_eq!(j1, j2);
    }

    // -------------------------------------------------------------------
    // Empty golden ledger corpus
    // -------------------------------------------------------------------

    #[test]
    fn checker_empty_corpus() {
        let registry = MigrationRegistry::new();
        let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
        assert_eq!(checker.golden_ledger_count(), 0);

        let results = checker.run_all();
        assert!(results.is_empty());
    }

    // -------------------------------------------------------------------
    // IncompatibleField serde
    // -------------------------------------------------------------------

    #[test]
    fn incompatible_field_serde_roundtrip() {
        let field = IncompatibleField {
            field_path: "metadata.x".to_string(),
            reason: "type changed".to_string(),
        };
        let json = serde_json::to_string(&field).expect("serialize");
        let restored: IncompatibleField = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(field, restored);
    }

    // -------------------------------------------------------------------
    // MigrationFunction serde
    // -------------------------------------------------------------------

    #[test]
    fn migration_function_serde_roundtrip() {
        let func = MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: false,
            description: "test".to_string(),
        };
        let json = serde_json::to_string(&func).expect("serialize");
        let restored: MigrationFunction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(func.from_version, restored.from_version);
        assert_eq!(func.to_version, restored.to_version);
        assert_eq!(func.lossy, restored.lossy);
    }

    // -------------------------------------------------------------------
    // Checker — target version accessor
    // -------------------------------------------------------------------

    #[test]
    fn checker_target_version() {
        let registry = MigrationRegistry::new();
        let checker = MigrationCompatibilityChecker::new("evidence-v3", registry);
        assert_eq!(checker.target_version(), "evidence-v3");
    }

    // -------------------------------------------------------------------
    // v1_to_v2_migration adds metadata marker
    // -------------------------------------------------------------------

    #[test]
    fn v1_to_v2_migration_adds_marker() {
        let ledger = build_golden_ledger("test", "evidence-v1", 1);
        let entry = &ledger.entries[0];

        let migrated = v1_to_v2_migration(entry).unwrap();
        assert_eq!(migrated.schema_version, "evidence-v2");
        assert_eq!(
            migrated.metadata.get("migrated_from").map(String::as_str),
            Some("evidence-v1")
        );
    }

    // -------------------------------------------------------------------
    // Lossy migration is still considered "passed"
    // -------------------------------------------------------------------

    #[test]
    fn lossy_migration_passes_when_replay_ok() {
        let result = MigrationTestResult {
            golden_ledger_name: "test".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            outcome: MigrationOutcome::LossyMigration,
            entries_processed: 3,
            entries_replayed_ok: 3,
            errors: Vec::new(),
            replay_violations: 0,
            schema_migrations_detected: Vec::new(),
            determinism_verified: true,
        };
        assert!(result.passed());
    }

    // ===================================================================
    // Cutover migration contract tests (bd-29s)
    // ===================================================================

    fn test_declaration(id: &str, cutover: CutoverType) -> MigrationDeclaration {
        let mut affected = BTreeSet::new();
        affected.insert(ObjectClass::SerializationSchema);
        MigrationDeclaration {
            migration_id: id.to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            affected_objects: affected,
            cutover_type: cutover,
            description: "test migration".to_string(),
            compatible_across_boundary: vec!["wire format".to_string()],
            incompatible_across_boundary: vec!["storage format".to_string()],
        }
    }

    fn run_full_migration(runner: &mut CutoverMigrationRunner, id: &str) -> AppliedMigrationEntry {
        runner.begin(id, 100, "trace-1").unwrap();
        runner.set_tick(10);
        runner.create_checkpoint(1, "trace-1").unwrap();
        runner.set_tick(20);
        runner.execute(100, "trace-1").unwrap();
        runner.set_tick(30);
        runner.verify(0, "trace-1").unwrap();
        runner.set_tick(40);
        runner.commit("trace-1").unwrap()
    }

    // -- CutoverType -------------------------------------------------------

    #[test]
    fn cutover_type_display() {
        assert_eq!(CutoverType::HardCutover.to_string(), "hard_cutover");
        assert_eq!(CutoverType::SoftMigration.to_string(), "soft_migration");
        assert_eq!(CutoverType::ParallelRun.to_string(), "parallel_run");
    }

    #[test]
    fn cutover_type_serde_roundtrip() {
        for ct in [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ] {
            let json = serde_json::to_string(&ct).unwrap();
            let deser: CutoverType = serde_json::from_str(&json).unwrap();
            assert_eq!(ct, deser);
        }
    }

    // -- ObjectClass -------------------------------------------------------

    #[test]
    fn object_class_display() {
        assert_eq!(
            ObjectClass::SerializationSchema.to_string(),
            "serialization_schema"
        );
        assert_eq!(ObjectClass::KeyFormat.to_string(), "key_format");
        assert_eq!(
            ObjectClass::RevocationFormat.to_string(),
            "revocation_format"
        );
    }

    #[test]
    fn object_class_serde_roundtrip() {
        for oc in [
            ObjectClass::SerializationSchema,
            ObjectClass::KeyFormat,
            ObjectClass::TokenFormat,
            ObjectClass::CheckpointFormat,
            ObjectClass::RevocationFormat,
            ObjectClass::PolicyFormat,
        ] {
            let json = serde_json::to_string(&oc).unwrap();
            let deser: ObjectClass = serde_json::from_str(&json).unwrap();
            assert_eq!(oc, deser);
        }
    }

    // -- MigrationPhase ----------------------------------------------------

    #[test]
    fn migration_phase_display() {
        assert_eq!(MigrationPhase::PreMigration.to_string(), "pre_migration");
        assert_eq!(MigrationPhase::Commit.to_string(), "commit");
        assert_eq!(MigrationPhase::Rollback.to_string(), "rollback");
    }

    #[test]
    fn migration_phase_serde_roundtrip() {
        for phase in [
            MigrationPhase::PreMigration,
            MigrationPhase::Checkpoint,
            MigrationPhase::Execute,
            MigrationPhase::Verify,
            MigrationPhase::Commit,
            MigrationPhase::Rollback,
        ] {
            let json = serde_json::to_string(&phase).unwrap();
            let deser: MigrationPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(phase, deser);
        }
    }

    // -- PhaseOutcome ------------------------------------------------------

    #[test]
    fn phase_outcome_display() {
        assert_eq!(PhaseOutcome::Success.to_string(), "success");
        assert_eq!(PhaseOutcome::Failed.to_string(), "failed");
        assert_eq!(PhaseOutcome::Skipped.to_string(), "skipped");
    }

    // -- MigrationDeclaration serde ----------------------------------------

    #[test]
    fn migration_declaration_serde_roundtrip() {
        let decl = test_declaration("mig-1", CutoverType::HardCutover);
        let json = serde_json::to_string(&decl).unwrap();
        let deser: MigrationDeclaration = serde_json::from_str(&json).unwrap();
        assert_eq!(decl, deser);
    }

    // -- CutoverError display and codes ------------------------------------

    #[test]
    fn cutover_error_display_all_variants() {
        let errors: Vec<CutoverError> = vec![
            CutoverError::InvalidDeclaration {
                detail: "test".to_string(),
            },
            CutoverError::DryRunFailed {
                unconvertible_count: 5,
            },
            CutoverError::VerificationFailed { violations: 3 },
            CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 2,
            },
            CutoverError::OldFormatRejected {
                object_class: ObjectClass::KeyFormat,
            },
            CutoverError::TransitionWindowExpired {
                migration_id: "m1".to_string(),
            },
            CutoverError::PhaseFailed {
                phase: MigrationPhase::Execute,
                detail: "fail".to_string(),
            },
            CutoverError::AlreadyCommitted {
                migration_id: "m1".to_string(),
            },
            CutoverError::NoMigrationInProgress,
            CutoverError::MigrationNotFound {
                migration_id: "m1".to_string(),
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn cutover_error_codes_stable() {
        assert_eq!(
            cutover_error_code(&CutoverError::InvalidDeclaration {
                detail: "x".to_string()
            }),
            "MC_INVALID_DECLARATION"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::DryRunFailed {
                unconvertible_count: 1
            }),
            "MC_DRY_RUN_FAILED"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::NoMigrationInProgress),
            "MC_NO_MIGRATION"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::OldFormatRejected {
                object_class: ObjectClass::KeyFormat
            }),
            "MC_OLD_FORMAT_REJECTED"
        );
    }

    #[test]
    fn cutover_error_serde_roundtrip() {
        let err = CutoverError::VerificationFailed { violations: 5 };
        let json = serde_json::to_string(&err).unwrap();
        let deser: CutoverError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }

    // -- CutoverState ------------------------------------------------------

    #[test]
    fn cutover_state_display() {
        assert_eq!(CutoverState::Declared.to_string(), "declared");
        assert_eq!(CutoverState::Committed.to_string(), "committed");
        assert_eq!(CutoverState::RolledBack.to_string(), "rolled_back");
    }

    #[test]
    fn cutover_state_serde_roundtrip() {
        for state in [
            CutoverState::Declared,
            CutoverState::PreMigrated,
            CutoverState::Checkpointed,
            CutoverState::Executed,
            CutoverState::Verified,
            CutoverState::Committed,
            CutoverState::RolledBack,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let deser: CutoverState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, deser);
        }
    }

    // -- TransitionWindow --------------------------------------------------

    #[test]
    fn transition_window_active_and_expired() {
        let w = TransitionWindow {
            migration_id: "m1".to_string(),
            start_tick: 100,
            end_tick: 200,
            old_format_accepted: true,
        };
        assert!(!w.is_active(50)); // before start
        assert!(w.is_active(100)); // at start
        assert!(w.is_active(150)); // during
        assert!(!w.is_active(200)); // at end (expired)
        assert!(w.is_expired(200));
        assert!(!w.is_expired(199));
    }

    #[test]
    fn transition_window_serde_roundtrip() {
        let w = TransitionWindow {
            migration_id: "m1".to_string(),
            start_tick: 10,
            end_tick: 20,
            old_format_accepted: true,
        };
        let json = serde_json::to_string(&w).unwrap();
        let deser: TransitionWindow = serde_json::from_str(&json).unwrap();
        assert_eq!(w, deser);
    }

    // -- Declaration validation --------------------------------------------

    #[test]
    fn declare_valid_migration() {
        let mut runner = CutoverMigrationRunner::new();
        let decl = test_declaration("mig-1", CutoverType::HardCutover);
        runner.declare(decl, "trace-1").unwrap();
        assert_eq!(runner.declaration_count(), 1);
    }

    #[test]
    fn declare_rejects_empty_migration_id() {
        let mut runner = CutoverMigrationRunner::new();
        let mut decl = test_declaration("", CutoverType::HardCutover);
        decl.migration_id = String::new();
        let err = runner.declare(decl, "trace-1").unwrap_err();
        assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
    }

    #[test]
    fn declare_rejects_empty_affected_objects() {
        let mut runner = CutoverMigrationRunner::new();
        let mut decl = test_declaration("mig-1", CutoverType::HardCutover);
        decl.affected_objects.clear();
        let err = runner.declare(decl, "trace-1").unwrap_err();
        assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
    }

    #[test]
    fn declare_rejects_same_from_to_version() {
        let mut runner = CutoverMigrationRunner::new();
        let mut decl = test_declaration("mig-1", CutoverType::HardCutover);
        decl.to_version = decl.from_version.clone();
        let err = runner.declare(decl, "trace-1").unwrap_err();
        assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
    }

    #[test]
    fn declare_rejects_duplicate_id() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        let err = runner
            .declare(test_declaration("mig-1", CutoverType::SoftMigration), "t")
            .unwrap_err();
        assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
    }

    // -- Full hard cutover lifecycle ----------------------------------------

    #[test]
    fn hard_cutover_full_lifecycle() {
        let mut runner = CutoverMigrationRunner::new();
        let decl = test_declaration("mig-1", CutoverType::HardCutover);
        runner.declare(decl, "trace-1").unwrap();

        let entry = run_full_migration(&mut runner, "mig-1");
        assert_eq!(entry.state, CutoverState::Committed);
        assert_eq!(entry.cutover_type, CutoverType::HardCutover);
        assert!(entry.committed_at.is_some());
        assert_eq!(entry.phase_records.len(), 5); // pre, checkpoint, execute, verify, commit
    }

    #[test]
    fn hard_cutover_rejects_old_format_after_commit() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        let err = runner
            .check_format_acceptance(ObjectClass::SerializationSchema)
            .unwrap_err();
        assert!(matches!(err, CutoverError::OldFormatRejected { .. }));
    }

    #[test]
    fn hard_cutover_accepts_unaffected_object_class() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        // KeyFormat was not affected by this migration.
        runner
            .check_format_acceptance(ObjectClass::KeyFormat)
            .unwrap();
    }

    // -- Soft migration lifecycle -------------------------------------------

    #[test]
    fn soft_migration_opens_transition_window() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::SoftMigration), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        assert_eq!(runner.transition_windows().len(), 1);
        let window = &runner.transition_windows()[0];
        assert_eq!(window.migration_id, "mig-1");
        assert!(window.old_format_accepted);
    }

    #[test]
    fn soft_migration_accepts_old_format_during_window() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::SoftMigration), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        // Still within transition window.
        runner.set_tick(41);
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema)
            .unwrap();
    }

    #[test]
    fn soft_migration_rejects_old_format_after_window() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::SoftMigration), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        // After transition window expires (commit at tick 40, window = 1000).
        runner.set_tick(1041);
        let err = runner
            .check_format_acceptance(ObjectClass::SerializationSchema)
            .unwrap_err();
        assert!(matches!(err, CutoverError::TransitionWindowExpired { .. }));
    }

    // -- Parallel run lifecycle ---------------------------------------------

    #[test]
    fn parallel_run_discrepancy_aborts() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::ParallelRun), "t")
            .unwrap();

        runner.begin("mig-1", 100, "t").unwrap();
        runner.set_tick(10);
        runner.create_checkpoint(1, "t").unwrap();
        runner.set_tick(20);
        runner.execute(100, "t").unwrap();

        runner.set_tick(25);
        let err = runner.report_parallel_discrepancies(5, "t").unwrap_err();
        assert!(matches!(
            err,
            CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 5
            }
        ));
        assert!(runner.active_migration_id().is_none()); // cleaned up
    }

    #[test]
    fn parallel_run_no_discrepancy_ok() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::ParallelRun), "t")
            .unwrap();

        runner.begin("mig-1", 100, "t").unwrap();
        runner.set_tick(10);
        runner.create_checkpoint(1, "t").unwrap();
        runner.set_tick(20);
        runner.execute(100, "t").unwrap();

        runner.report_parallel_discrepancies(0, "t").unwrap();
        // Can continue to verify and commit.
    }

    #[test]
    fn parallel_discrepancy_rejected_for_non_parallel() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.begin("mig-1", 100, "t").unwrap();

        let err = runner.report_parallel_discrepancies(0, "t").unwrap_err();
        assert!(matches!(err, CutoverError::PhaseFailed { .. }));
    }

    // -- Verification failure auto-rollback ---------------------------------

    #[test]
    fn verification_failure_rolls_back() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();

        runner.begin("mig-1", 100, "t").unwrap();
        runner.create_checkpoint(1, "t").unwrap();
        runner.execute(100, "t").unwrap();

        let err = runner.verify(3, "t").unwrap_err();
        assert!(matches!(
            err,
            CutoverError::VerificationFailed { violations: 3 }
        ));

        // Migration should be rolled back and cleaned up.
        assert!(runner.active_migration_id().is_none());
        let applied = runner.applied_migrations();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].state, CutoverState::RolledBack);
    }

    // -- Dry run failure ----------------------------------------------------

    #[test]
    fn dry_run_failure_rolls_back() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();

        runner.begin("mig-1", 100, "t").unwrap();
        let err = runner.fail_dry_run(10, "t").unwrap_err();
        assert!(matches!(
            err,
            CutoverError::DryRunFailed {
                unconvertible_count: 10
            }
        ));
        assert!(runner.active_migration_id().is_none());
    }

    // -- Manual rollback ----------------------------------------------------

    #[test]
    fn manual_rollback_before_commit() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();

        runner.begin("mig-1", 100, "t").unwrap();
        runner.create_checkpoint(1, "t").unwrap();
        runner.execute(100, "t").unwrap();
        runner.rollback("t").unwrap();

        assert!(runner.active_migration_id().is_none());
        assert_eq!(
            runner.applied_migrations()[0].state,
            CutoverState::RolledBack
        );
    }

    #[test]
    fn rollback_after_commit_fails() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        // No active migration to rollback.
        let err = runner.rollback("t").unwrap_err();
        assert!(matches!(err, CutoverError::NoMigrationInProgress));
    }

    // -- Phase ordering enforcement -----------------------------------------

    #[test]
    fn checkpoint_requires_pre_migrated() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.begin("mig-1", 100, "t").unwrap();
        runner.create_checkpoint(1, "t").unwrap();

        // Already checkpointed; creating another should fail.
        let err = runner.create_checkpoint(2, "t").unwrap_err();
        assert!(matches!(err, CutoverError::PhaseFailed { .. }));
    }

    #[test]
    fn execute_requires_checkpointed() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.begin("mig-1", 100, "t").unwrap();

        // Trying to execute without checkpoint.
        let err = runner.execute(100, "t").unwrap_err();
        assert!(matches!(err, CutoverError::PhaseFailed { .. }));
    }

    #[test]
    fn verify_requires_executed() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.begin("mig-1", 100, "t").unwrap();
        runner.create_checkpoint(1, "t").unwrap();

        let err = runner.verify(0, "t").unwrap_err();
        assert!(matches!(err, CutoverError::PhaseFailed { .. }));
    }

    #[test]
    fn commit_requires_verified() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.begin("mig-1", 100, "t").unwrap();
        runner.create_checkpoint(1, "t").unwrap();
        runner.execute(100, "t").unwrap();

        let err = runner.commit("t").unwrap_err();
        assert!(matches!(err, CutoverError::PhaseFailed { .. }));
    }

    // -- Missing migration ID -----------------------------------------------

    #[test]
    fn begin_unknown_migration_fails() {
        let mut runner = CutoverMigrationRunner::new();
        let err = runner.begin("nonexistent", 100, "t").unwrap_err();
        assert!(matches!(err, CutoverError::MigrationNotFound { .. }));
    }

    // -- Concurrent migration rejected --------------------------------------

    #[test]
    fn only_one_active_migration() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        let mut decl2 = test_declaration("mig-2", CutoverType::SoftMigration);
        decl2.from_version = "v2".to_string();
        decl2.to_version = "v3".to_string();
        runner.declare(decl2, "t").unwrap();

        runner.begin("mig-1", 100, "t").unwrap();
        let err = runner.begin("mig-2", 50, "t").unwrap_err();
        assert!(matches!(err, CutoverError::PhaseFailed { .. }));
    }

    // -- Audit events -------------------------------------------------------

    #[test]
    fn audit_events_emitted_on_lifecycle() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        let events = runner.audit_events();
        assert!(events.len() >= 5);
        assert!(events.iter().any(|e| e.event == "migration_declared"));
        assert!(events.iter().any(|e| e.event == "pre_migration_complete"));
        assert!(events.iter().any(|e| e.event == "checkpoint_created"));
        assert!(events.iter().any(|e| e.event == "migration_executed"));
        assert!(events.iter().any(|e| e.event == "migration_committed"));
    }

    #[test]
    fn audit_events_include_error_code_on_failure() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.begin("mig-1", 100, "t").unwrap();
        runner.create_checkpoint(1, "t").unwrap();
        runner.execute(100, "t").unwrap();
        let _ = runner.verify(2, "t");

        let events = runner.drain_audit_events();
        let fail_event = events
            .iter()
            .find(|e| e.event == "verification_failed")
            .unwrap();
        assert_eq!(
            fail_event.error_code.as_deref(),
            Some("MC_VERIFICATION_FAILED")
        );
        assert_eq!(fail_event.affected_count, Some(2));
    }

    #[test]
    fn drain_clears_audit_events() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        assert!(!runner.audit_events().is_empty());
        let drained = runner.drain_audit_events();
        assert!(!drained.is_empty());
        assert!(runner.audit_events().is_empty());
    }

    // -- Applied migrations log ---------------------------------------------

    #[test]
    fn applied_migrations_preserved() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");

        let applied = runner.applied_migrations();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].migration_id, "mig-1");
        assert_eq!(applied[0].from_version, "v1");
        assert_eq!(applied[0].to_version, "v2");
    }

    // -- CutoverAuditEvent serde -------------------------------------------

    #[test]
    fn cutover_audit_event_serde_roundtrip() {
        let event = CutoverAuditEvent {
            trace_id: "t-1".to_string(),
            component: "migration_compatibility".to_string(),
            migration_id: "mig-1".to_string(),
            event: "migration_committed".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            phase: Some("commit".to_string()),
            affected_count: Some(100),
            timestamp: DeterministicTimestamp(42),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deser: CutoverAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deser);
    }

    // -- AppliedMigrationEntry serde ---------------------------------------

    #[test]
    fn applied_migration_entry_serde_roundtrip() {
        let mut affected = BTreeSet::new();
        affected.insert(ObjectClass::SerializationSchema);
        let entry = AppliedMigrationEntry {
            migration_id: "mig-1".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            cutover_type: CutoverType::HardCutover,
            state: CutoverState::Committed,
            affected_objects: affected,
            phase_records: Vec::new(),
            declared_at: DeterministicTimestamp(10),
            committed_at: Some(DeterministicTimestamp(40)),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deser: AppliedMigrationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deser);
    }

    // -- PhaseExecutionRecord serde ----------------------------------------

    #[test]
    fn phase_execution_record_serde_roundtrip() {
        let record = PhaseExecutionRecord {
            migration_id: "mig-1".to_string(),
            phase: MigrationPhase::Execute,
            outcome: PhaseOutcome::Success,
            affected_count: 100,
            detail: "done".to_string(),
            timestamp: DeterministicTimestamp(20),
        };
        let json = serde_json::to_string(&record).unwrap();
        let deser: PhaseExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deser);
    }

    // -- Determinism: repeated runs same events ----------------------------

    #[test]
    fn cutover_lifecycle_deterministic() {
        let run = || {
            let mut runner = CutoverMigrationRunner::new();
            runner
                .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
                .unwrap();
            run_full_migration(&mut runner, "mig-1");
            serde_json::to_string(runner.audit_events()).unwrap()
        };
        assert_eq!(run(), run());
    }

    // -- No active migration operations fail --------------------------------

    #[test]
    fn operations_without_active_fail() {
        let mut runner = CutoverMigrationRunner::new();
        assert!(matches!(
            runner.create_checkpoint(1, "t"),
            Err(CutoverError::NoMigrationInProgress)
        ));
        assert!(matches!(
            runner.execute(10, "t"),
            Err(CutoverError::NoMigrationInProgress)
        ));
        assert!(matches!(
            runner.verify(0, "t"),
            Err(CutoverError::NoMigrationInProgress)
        ));
        assert!(matches!(
            runner.commit("t"),
            Err(CutoverError::NoMigrationInProgress)
        ));
        assert!(matches!(
            runner.rollback("t"),
            Err(CutoverError::NoMigrationInProgress)
        ));
    }

    // -- Accessors ----------------------------------------------------------

    #[test]
    fn runner_accessors() {
        let runner = CutoverMigrationRunner::new();
        assert_eq!(runner.declaration_count(), 0);
        assert!(runner.applied_migrations().is_empty());
        assert!(runner.active_state().is_none());
        assert!(runner.active_migration_id().is_none());
        assert!(runner.transition_windows().is_empty());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn golden_ledger_freeze_empty_entries() {
        let ledger = GoldenLedger::freeze("empty", "v1", Vec::new(), 0);
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn golden_ledger_metadata_does_not_affect_integrity() {
        let mut ledger = build_golden_ledger("test", "evidence-v1", 3);
        assert!(ledger.verify_integrity());
        ledger
            .metadata
            .insert("extra".to_string(), "info".to_string());
        // Metadata is not part of corpus_hash
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn manifest_overwrite_same_name() {
        let mut manifest = GoldenLedgerManifest::new();
        let ledger_a = build_golden_ledger("shared-name", "v1", 3);
        let ledger_b = build_golden_ledger("shared-name", "v2", 5);
        manifest.add(&ledger_a);
        assert_eq!(manifest.len(), 1);
        assert!(manifest.verify(&ledger_a));
        // Adding same name overwrites
        manifest.add(&ledger_b);
        assert_eq!(manifest.len(), 1);
        assert!(manifest.verify(&ledger_b));
        assert!(!manifest.verify(&ledger_a));
    }

    #[test]
    fn manifest_multiple_distinct_ledgers() {
        let mut manifest = GoldenLedgerManifest::new();
        assert!(manifest.is_empty());
        let l1 = build_golden_ledger("alpha", "v1", 2);
        let l2 = build_golden_ledger("beta", "v1", 4);
        manifest.add(&l1);
        manifest.add(&l2);
        assert_eq!(manifest.len(), 2);
        assert!(!manifest.is_empty());
        assert!(manifest.verify(&l1));
        assert!(manifest.verify(&l2));
    }

    #[test]
    fn migration_test_result_passed_all_conditions() {
        let result = MigrationTestResult {
            golden_ledger_name: "test".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            outcome: MigrationOutcome::MigratedSuccessfully,
            entries_processed: 5,
            entries_replayed_ok: 5,
            errors: Vec::new(),
            replay_violations: 0,
            schema_migrations_detected: Vec::new(),
            determinism_verified: true,
        };
        assert!(result.passed());
    }

    #[test]
    fn migration_test_result_failed_when_outcome_is_failed() {
        let result = MigrationTestResult {
            golden_ledger_name: "test".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            outcome: MigrationOutcome::Failed,
            entries_processed: 5,
            entries_replayed_ok: 3,
            errors: Vec::new(),
            replay_violations: 0,
            schema_migrations_detected: Vec::new(),
            determinism_verified: true,
        };
        assert!(!result.passed());
    }

    #[test]
    fn declare_validation_empty_affected_objects_detail() {
        let mut runner = CutoverMigrationRunner::new();
        let mut decl = test_declaration("m1", CutoverType::HardCutover);
        decl.affected_objects.clear();
        let err = runner.declare(decl, "t").unwrap_err();
        if let CutoverError::InvalidDeclaration { detail } = &err {
            assert!(detail.contains("affected_objects"), "detail: {detail}");
        } else {
            panic!("expected InvalidDeclaration, got {err:?}");
        }
    }

    #[test]
    fn declare_validation_same_versions_detail() {
        let mut runner = CutoverMigrationRunner::new();
        let mut decl = test_declaration("m1", CutoverType::HardCutover);
        decl.from_version = "v1".to_string();
        decl.to_version = "v1".to_string();
        let err = runner.declare(decl, "t").unwrap_err();
        if let CutoverError::InvalidDeclaration { detail } = &err {
            assert!(detail.contains("from_version"), "detail: {detail}");
        } else {
            panic!("expected InvalidDeclaration, got {err:?}");
        }
    }

    #[test]
    fn begin_unknown_migration_id_fails() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("m1", CutoverType::HardCutover), "t")
            .unwrap();
        assert!(matches!(
            runner.begin("nonexistent", 50, "t"),
            Err(CutoverError::MigrationNotFound { .. })
        ));
    }

    #[test]
    fn parallel_run_accepts_old_format_after_commit() {
        let mut runner = CutoverMigrationRunner::new();
        let decl = test_declaration("m-par", CutoverType::ParallelRun);
        runner.declare(decl, "t").unwrap();
        let _entry = run_full_migration(&mut runner, "m-par");
        // ParallelRun always accepts both formats
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema)
            .unwrap();
    }

    #[test]
    fn check_format_acceptance_unaffected_class_always_ok() {
        let mut runner = CutoverMigrationRunner::new();
        let decl = test_declaration("m-hard", CutoverType::HardCutover);
        runner.declare(decl, "t").unwrap();
        let _entry = run_full_migration(&mut runner, "m-hard");
        // KeyFormat is not in affected_objects, so should pass
        runner
            .check_format_acceptance(ObjectClass::KeyFormat)
            .unwrap();
    }

    #[test]
    fn active_state_tracks_through_lifecycle() {
        let mut runner = CutoverMigrationRunner::new();
        let decl = test_declaration("m-track", CutoverType::HardCutover);
        runner.declare(decl, "t").unwrap();
        assert!(runner.active_state().is_none());
        runner.begin("m-track", 50, "t").unwrap();
        assert_eq!(runner.active_state(), Some(CutoverState::PreMigrated));
        assert_eq!(runner.active_migration_id(), Some("m-track"));
    }

    #[test]
    fn cutover_error_code_all_variants_stable() {
        // Verify that cutover_error_code returns non-empty string for all variants
        let errors = vec![
            CutoverError::InvalidDeclaration {
                detail: String::new(),
            },
            CutoverError::DryRunFailed {
                unconvertible_count: 0,
            },
            CutoverError::VerificationFailed { violations: 0 },
            CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 0,
            },
            CutoverError::OldFormatRejected {
                object_class: ObjectClass::KeyFormat,
            },
            CutoverError::TransitionWindowExpired {
                migration_id: String::new(),
            },
            CutoverError::PhaseFailed {
                phase: MigrationPhase::Execute,
                detail: String::new(),
            },
            CutoverError::AlreadyCommitted {
                migration_id: String::new(),
            },
            CutoverError::NoMigrationInProgress,
            CutoverError::MigrationNotFound {
                migration_id: String::new(),
            },
        ];
        for err in &errors {
            let code = cutover_error_code(err);
            assert!(!code.is_empty(), "empty code for {err:?}");
        }
    }

    #[test]
    fn phase_outcome_display_all_variants() {
        assert_eq!(PhaseOutcome::Success.to_string(), "success");
        assert_eq!(PhaseOutcome::Failed.to_string(), "failed");
        assert_eq!(PhaseOutcome::Skipped.to_string(), "skipped");
    }

    #[test]
    fn cutover_state_display_all_variants() {
        let variants = [
            CutoverState::Declared,
            CutoverState::PreMigrated,
            CutoverState::Checkpointed,
            CutoverState::Executed,
            CutoverState::Verified,
            CutoverState::Committed,
            CutoverState::RolledBack,
        ];
        let mut displays: Vec<String> = variants.iter().map(|v| v.to_string()).collect();
        let original = displays.clone();
        displays.sort();
        displays.dedup();
        assert_eq!(
            displays.len(),
            original.len(),
            "Display values must be unique"
        );
    }

    #[test]
    fn phase_execution_record_serde_preserves_phase() {
        let record = PhaseExecutionRecord {
            migration_id: "m1".to_string(),
            phase: MigrationPhase::Rollback,
            outcome: PhaseOutcome::Failed,
            affected_count: 42,
            detail: "processed all objects".to_string(),
            timestamp: DeterministicTimestamp(1000),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: PhaseExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.phase, back.phase);
        assert_eq!(record.outcome, back.outcome);
    }

    #[test]
    fn applied_entry_committed_at_present_after_commit() {
        let mut runner = CutoverMigrationRunner::new();
        let decl = test_declaration("m-ts", CutoverType::HardCutover);
        runner.declare(decl, "t").unwrap();
        let entry = run_full_migration(&mut runner, "m-ts");
        assert_eq!(entry.state, CutoverState::Committed);
        assert!(entry.committed_at.is_some());
    }

    #[test]
    fn audit_event_optional_fields_populated() {
        let event = CutoverAuditEvent {
            trace_id: "t1".to_string(),
            component: "migration_compatibility".to_string(),
            migration_id: "m1".to_string(),
            event: "migration_declared".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("PHASE_FAILED".to_string()),
            phase: Some("Execute".to_string()),
            affected_count: Some(50),
            timestamp: DeterministicTimestamp(2000),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("PHASE_FAILED"));
        assert!(json.contains("Execute"));
        let back: CutoverAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.error_code, back.error_code);
        assert_eq!(event.phase, back.phase);
        assert_eq!(event.affected_count, back.affected_count);
    }

    #[test]
    fn migration_compatibility_event_fields_populated() {
        let event = MigrationCompatibilityEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "migration_compatibility".to_string(),
            event: "test_golden_ledger".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: MigrationCompatibilityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn migration_error_code_display_all_8_variants() {
        let expected = [
            (
                MigrationErrorCode::MajorVersionIncompatible,
                "major_version_incompatible",
            ),
            (
                MigrationErrorCode::RequiredFieldMissing,
                "required_field_missing",
            ),
            (MigrationErrorCode::FieldTypeChanged, "field_type_changed"),
            (
                MigrationErrorCode::MigrationFunctionFailed,
                "migration_function_failed",
            ),
            (
                MigrationErrorCode::NonDeterministicMigration,
                "non_deterministic_migration",
            ),
            (
                MigrationErrorCode::PartialReplayFailure,
                "partial_replay_failure",
            ),
            (MigrationErrorCode::NoMigrationPath, "no_migration_path"),
            (MigrationErrorCode::LossyMigration, "lossy_migration"),
        ];
        for (code, label) in expected {
            assert_eq!(code.to_string(), label);
        }
    }

    #[test]
    fn object_class_display_all_6_variants() {
        let expected = [
            (ObjectClass::SerializationSchema, "serialization_schema"),
            (ObjectClass::KeyFormat, "key_format"),
            (ObjectClass::TokenFormat, "token_format"),
            (ObjectClass::CheckpointFormat, "checkpoint_format"),
            (ObjectClass::RevocationFormat, "revocation_format"),
            (ObjectClass::PolicyFormat, "policy_format"),
        ];
        for (oc, label) in expected {
            assert_eq!(oc.to_string(), label);
        }
    }

    #[test]
    fn migration_phase_display_all_6_variants() {
        let expected = [
            (MigrationPhase::PreMigration, "pre_migration"),
            (MigrationPhase::Checkpoint, "checkpoint"),
            (MigrationPhase::Execute, "execute"),
            (MigrationPhase::Verify, "verify"),
            (MigrationPhase::Commit, "commit"),
            (MigrationPhase::Rollback, "rollback"),
        ];
        for (phase, label) in expected {
            assert_eq!(phase.to_string(), label);
        }
    }

    #[test]
    fn migration_error_display_exact_format() {
        let err = MigrationError {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            error_code: MigrationErrorCode::FieldTypeChanged,
            incompatible_fields: vec![
                IncompatibleField {
                    field_path: "a".to_string(),
                    reason: "r1".to_string(),
                },
                IncompatibleField {
                    field_path: "b".to_string(),
                    reason: "r2".to_string(),
                },
            ],
            message: "two fields".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "migration evidence-v1 -> evidence-v2: field_type_changed (2 incompatible fields)"
        );
    }

    #[test]
    fn migration_error_source_returns_none() {
        let err = MigrationError {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            error_code: MigrationErrorCode::NoMigrationPath,
            incompatible_fields: Vec::new(),
            message: "no path".to_string(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn cutover_error_source_returns_none() {
        let err = CutoverError::NoMigrationInProgress;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn cutover_error_serde_all_10_variants() {
        let errors: Vec<CutoverError> = vec![
            CutoverError::InvalidDeclaration {
                detail: "test".to_string(),
            },
            CutoverError::DryRunFailed {
                unconvertible_count: 5,
            },
            CutoverError::VerificationFailed { violations: 3 },
            CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 2,
            },
            CutoverError::OldFormatRejected {
                object_class: ObjectClass::KeyFormat,
            },
            CutoverError::TransitionWindowExpired {
                migration_id: "m1".to_string(),
            },
            CutoverError::PhaseFailed {
                phase: MigrationPhase::Execute,
                detail: "fail".to_string(),
            },
            CutoverError::AlreadyCommitted {
                migration_id: "m1".to_string(),
            },
            CutoverError::NoMigrationInProgress,
            CutoverError::MigrationNotFound {
                migration_id: "m1".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let deser: CutoverError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, deser);
        }
    }

    #[test]
    fn cutover_error_code_all_10_variants_exact() {
        assert_eq!(
            cutover_error_code(&CutoverError::InvalidDeclaration {
                detail: String::new()
            }),
            "MC_INVALID_DECLARATION"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::DryRunFailed {
                unconvertible_count: 0
            }),
            "MC_DRY_RUN_FAILED"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::VerificationFailed { violations: 0 }),
            "MC_VERIFICATION_FAILED"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 0
            }),
            "MC_PARALLEL_DISCREPANCY"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::OldFormatRejected {
                object_class: ObjectClass::KeyFormat
            }),
            "MC_OLD_FORMAT_REJECTED"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::TransitionWindowExpired {
                migration_id: String::new()
            }),
            "MC_WINDOW_EXPIRED"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::PhaseFailed {
                phase: MigrationPhase::Execute,
                detail: String::new()
            }),
            "MC_PHASE_FAILED"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::AlreadyCommitted {
                migration_id: String::new()
            }),
            "MC_ALREADY_COMMITTED"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::NoMigrationInProgress),
            "MC_NO_MIGRATION"
        );
        assert_eq!(
            cutover_error_code(&CutoverError::MigrationNotFound {
                migration_id: String::new()
            }),
            "MC_NOT_FOUND"
        );
    }

    #[test]
    fn cutover_error_display_exact_content() {
        assert_eq!(
            CutoverError::InvalidDeclaration {
                detail: "bad input".to_string()
            }
            .to_string(),
            "invalid migration declaration: bad input"
        );
        assert_eq!(
            CutoverError::DryRunFailed {
                unconvertible_count: 7
            }
            .to_string(),
            "pre-migration dry run failed: 7 unconvertible objects"
        );
        assert_eq!(
            CutoverError::VerificationFailed { violations: 3 }.to_string(),
            "post-migration verification failed: 3 violations"
        );
        assert_eq!(
            CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 2
            }
            .to_string(),
            "parallel run discrepancy: 2 mismatches"
        );
        assert_eq!(
            CutoverError::OldFormatRejected {
                object_class: ObjectClass::TokenFormat
            }
            .to_string(),
            "old-format object rejected after hard cutover: token_format"
        );
        assert_eq!(
            CutoverError::NoMigrationInProgress.to_string(),
            "no migration in progress"
        );
    }

    #[test]
    fn phase_outcome_serde_roundtrip() {
        for po in [
            PhaseOutcome::Success,
            PhaseOutcome::Failed,
            PhaseOutcome::Skipped,
        ] {
            let json = serde_json::to_string(&po).unwrap();
            let deser: PhaseOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(po, deser);
        }
    }

    #[test]
    fn manifest_entry_serde_roundtrip() {
        let entry = ManifestEntry {
            schema_version: "evidence-v1".to_string(),
            corpus_hash: ContentHash::compute(b"test"),
            entry_count: 42,
            frozen_at_ms: 1_700_000_000_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deser: ManifestEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deser);
    }

    #[test]
    fn migration_test_result_serde_roundtrip() {
        let result = MigrationTestResult {
            golden_ledger_name: "test-v1".to_string(),
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            outcome: MigrationOutcome::LossyMigration,
            entries_processed: 10,
            entries_replayed_ok: 8,
            errors: vec![MigrationError {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                error_code: MigrationErrorCode::LossyMigration,
                incompatible_fields: vec![IncompatibleField {
                    field_path: "metadata.score".to_string(),
                    reason: "precision loss".to_string(),
                }],
                message: "lossy".to_string(),
            }],
            replay_violations: 2,
            schema_migrations_detected: Vec::new(),
            determinism_verified: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: MigrationTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.golden_ledger_name, deser.golden_ledger_name);
        assert_eq!(result.outcome, deser.outcome);
        assert_eq!(result.errors.len(), deser.errors.len());
        assert_eq!(result.replay_violations, deser.replay_violations);
    }

    #[test]
    fn default_impls_produce_empty_state() {
        let reg = MigrationRegistry::default();
        assert!(reg.all().is_empty());

        let manifest = GoldenLedgerManifest::default();
        assert!(manifest.is_empty());

        let runner = CutoverMigrationRunner::default();
        assert_eq!(runner.declaration_count(), 0);
        assert!(runner.applied_migrations().is_empty());
    }

    #[test]
    fn golden_ledger_frozen_at_ms_preserved() {
        let ledger = GoldenLedger::freeze("test", "v1", Vec::new(), 1_700_999_999_999);
        assert_eq!(ledger.frozen_at_ms, 1_700_999_999_999);
        let json = serde_json::to_string(&ledger).unwrap();
        let deser: GoldenLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.frozen_at_ms, 1_700_999_999_999);
    }

    #[test]
    fn golden_ledger_metadata_preserved_in_serde() {
        let mut ledger = GoldenLedger::freeze("test", "v1", Vec::new(), 0);
        ledger
            .metadata
            .insert("key".to_string(), "value".to_string());
        let json = serde_json::to_string(&ledger).unwrap();
        let deser: GoldenLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.metadata.get("key").map(String::as_str), Some("value"));
    }

    #[test]
    fn transition_window_zero_width() {
        let w = TransitionWindow {
            migration_id: "m1".to_string(),
            start_tick: 100,
            end_tick: 100,
            old_format_accepted: true,
        };
        // At tick 100: is_active returns false (start < end fails), is_expired returns true
        assert!(!w.is_active(100));
        assert!(w.is_expired(100));
    }

    #[test]
    fn cutover_state_ordering() {
        assert!(CutoverState::Declared < CutoverState::PreMigrated);
        assert!(CutoverState::PreMigrated < CutoverState::Checkpointed);
        assert!(CutoverState::Checkpointed < CutoverState::Executed);
        assert!(CutoverState::Executed < CutoverState::Verified);
        assert!(CutoverState::Verified < CutoverState::Committed);
        assert!(CutoverState::Committed < CutoverState::RolledBack);
    }

    #[test]
    fn migration_phase_ordering() {
        assert!(MigrationPhase::PreMigration < MigrationPhase::Checkpoint);
        assert!(MigrationPhase::Checkpoint < MigrationPhase::Execute);
        assert!(MigrationPhase::Execute < MigrationPhase::Verify);
        assert!(MigrationPhase::Verify < MigrationPhase::Commit);
        assert!(MigrationPhase::Commit < MigrationPhase::Rollback);
    }

    #[test]
    fn applied_entry_rolled_back_has_no_committed_at() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("m-rb", CutoverType::HardCutover), "t")
            .unwrap();
        runner.begin("m-rb", 50, "t").unwrap();
        runner.create_checkpoint(1, "t").unwrap();
        runner.execute(50, "t").unwrap();
        runner.rollback("t").unwrap();

        let applied = runner.applied_migrations();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].state, CutoverState::RolledBack);
        assert!(applied[0].committed_at.is_none());
    }

    #[test]
    fn checker_events_on_no_migration_path_include_error_code() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 2);
        let registry = MigrationRegistry::new();
        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);
        let _ = checker.run_all();

        let events = checker.events();
        let no_path_event = events
            .iter()
            .find(|e| e.event == "no_migration_path")
            .unwrap();
        assert_eq!(
            no_path_event.error_code.as_deref(),
            Some("no_migration_path")
        );
    }

    #[test]
    fn checker_events_on_failing_migration_include_error_code() {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 2);
        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "broken".to_string(),
            },
            failing_migration,
        );
        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);
        let _ = checker.run_all();

        let events = checker.events();
        let fail_event = events
            .iter()
            .find(|e| e.event == "migration_apply")
            .unwrap();
        assert_eq!(
            fail_event.error_code.as_deref(),
            Some("migration_function_failed")
        );
        assert_eq!(fail_event.outcome, "fail");
    }

    #[test]
    fn checker_registry_accessor() {
        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "v1".to_string(),
                to_version: "v2".to_string(),
                lossy: false,
                description: "test".to_string(),
            },
            identity_migration,
        );
        let checker = MigrationCompatibilityChecker::new("v2", registry);
        assert_eq!(checker.registry().all().len(), 1);
    }

    #[test]
    fn migration_declaration_compatible_fields_preserved() {
        let mut decl = test_declaration("m1", CutoverType::SoftMigration);
        decl.compatible_across_boundary = vec!["wire".to_string(), "api".to_string()];
        decl.incompatible_across_boundary = vec!["storage".to_string()];
        let json = serde_json::to_string(&decl).unwrap();
        let deser: MigrationDeclaration = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.compatible_across_boundary.len(), 2);
        assert_eq!(deser.incompatible_across_boundary.len(), 1);
    }

    #[test]
    fn soft_migration_transition_window_bounds() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("m-soft", CutoverType::SoftMigration), "t")
            .unwrap();
        // Commit happens at tick 40 in run_full_migration
        let _entry = run_full_migration(&mut runner, "m-soft");

        let windows = runner.transition_windows();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].start_tick, 40); // commit tick
        assert_eq!(windows[0].end_tick, 1040); // start + 1000 default
    }

    #[test]
    fn hard_cutover_no_transition_window() {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("m-hard", CutoverType::HardCutover), "t")
            .unwrap();
        let _entry = run_full_migration(&mut runner, "m-hard");
        assert!(runner.transition_windows().is_empty());
    }
}
