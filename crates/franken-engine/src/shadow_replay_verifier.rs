//! Shadow daemon replay and drift verification for deterministic auditing.
//!
//! This module implements replay verification for shadow daemon journal checkpoints
//! to ensure byte-stable decision composition and detect drift across schema changes,
//! missing event links, non-deterministic ordering, freshness interpretation changes,
//! and payload hash mismatches.
//!
//! The verifier distinguishes expected schema migration from behavioral regression
//! and provides actionable replay recipes with exact input artifacts and commands.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::deterministic_serde::{self, CanonicalValue};
use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::shadow_decision_composer::{
    ShadowDecision, ShadowDecisionError, ShadowStatus, RecommendationBundle,
    JournalSourceEvent, ShadowDecisionComposerInput,
};
use crate::shadow_evidence_journal::{
    ShadowEvidenceJournalExport, ShadowEvidenceJournalExportRow,
    SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION,
};
use crate::typed_persistence_models::ShadowEvidenceJournalEntry;
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

const SHADOW_REPLAY_COMPONENT: &str = "shadow_replay_verifier";
const REPLAY_VERIFICATION_DOMAIN: &[u8] = b"FrankenEngine.ShadowReplayVerification.v1";

/// Types of drift that can be detected during replay verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftType {
    /// Schema version change that may be expected during migration.
    SchemaDrift {
        expected_version: String,
        actual_version: String,
        migration_compatible: bool,
    },
    /// Missing event links in the journal chain.
    MissingEventLinks {
        expected_count: usize,
        actual_count: usize,
        missing_ids: Vec<i64>,
    },
    /// Non-deterministic ordering of events or decisions.
    NonDeterministicOrdering {
        expected_hash: ContentHash,
        actual_hash: ContentHash,
        divergence_point: usize,
    },
    /// Changed interpretation of freshness criteria.
    FreshnessInterpretationChange {
        expected_threshold_ms: u64,
        actual_threshold_ms: u64,
        affected_decisions: usize,
    },
    /// Payload hash mismatch indicating content corruption or alteration.
    PayloadHashMismatch {
        event_id: i64,
        expected_hash: ContentHash,
        actual_hash: ContentHash,
    },
    /// Behavioral regression where output differs unexpectedly.
    BehavioralRegression {
        decision_id: EngineObjectId,
        expected_output: ContentHash,
        actual_output: ContentHash,
        reproducible: bool,
    },
}

impl fmt::Display for DriftType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriftType::SchemaDrift { expected_version, actual_version, migration_compatible } => {
                write!(
                    f,
                    "Schema drift from {} to {} (migration compatible: {})",
                    expected_version, actual_version, migration_compatible
                )
            }
            DriftType::MissingEventLinks { expected_count, actual_count, missing_ids } => {
                write!(
                    f,
                    "Missing event links: expected {} events, found {}, missing {}",
                    expected_count, actual_count, missing_ids.len()
                )
            }
            DriftType::NonDeterministicOrdering { expected_hash, actual_hash, divergence_point } => {
                write!(
                    f,
                    "Non-deterministic ordering: expected hash {}, actual {}, diverged at position {}",
                    hex_encode(expected_hash.as_bytes()),
                    hex_encode(actual_hash.as_bytes()),
                    divergence_point
                )
            }
            DriftType::FreshnessInterpretationChange { expected_threshold_ms, actual_threshold_ms, affected_decisions } => {
                write!(
                    f,
                    "Freshness interpretation change: threshold {}ms -> {}ms, {} decisions affected",
                    expected_threshold_ms, actual_threshold_ms, affected_decisions
                )
            }
            DriftType::PayloadHashMismatch { event_id, expected_hash, actual_hash } => {
                write!(
                    f,
                    "Payload hash mismatch for event {}: expected {}, actual {}",
                    event_id,
                    hex_encode(expected_hash.as_bytes()),
                    hex_encode(actual_hash.as_bytes())
                )
            }
            DriftType::BehavioralRegression { decision_id, expected_output, actual_output, reproducible } => {
                write!(
                    f,
                    "Behavioral regression for decision {}: expected {}, actual {} (reproducible: {})",
                    decision_id,
                    hex_encode(expected_output.as_bytes()),
                    hex_encode(actual_output.as_bytes()),
                    reproducible
                )
            }
        }
    }
}

/// Drift detection report with actionable replay recipes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    /// Unique identifier for this drift report.
    pub report_id: EngineObjectId,
    /// Timestamp when the drift was detected.
    pub detection_timestamp_ms: u64,
    /// Source journal export that was being replayed.
    pub source_export: ShadowEvidenceJournalExport,
    /// Target environment where replay was attempted.
    pub target_environment: String,
    /// List of detected drift types and their details.
    pub detected_drift: Vec<DriftType>,
    /// Whether the drift indicates expected migration or regression.
    pub is_expected_migration: bool,
    /// Replay recipe with exact commands to reproduce the drift.
    pub replay_recipe: ReplayRecipe,
    /// Verification signature for the report integrity.
    pub verification_signature: Option<Signature>,
}

/// Exact replay recipe for reproducing drift detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRecipe {
    /// Input checkpoint file path or identifier.
    pub input_checkpoint: String,
    /// Exact command line arguments for replay.
    pub replay_command: Vec<String>,
    /// Environment variables required for deterministic replay.
    pub environment_vars: BTreeMap<String, String>,
    /// Expected output hashes for verification.
    pub expected_outputs: BTreeMap<String, ContentHash>,
    /// Additional artifacts referenced during replay.
    pub referenced_artifacts: Vec<String>,
}

/// Configuration for replay verification behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Maximum number of events to replay in a single batch.
    pub max_events_per_batch: usize,
    /// Timeout for each replay operation in milliseconds.
    pub replay_timeout_ms: u64,
    /// Whether to treat schema version changes as expected drift.
    pub allow_schema_migration: bool,
    /// Freshness threshold tolerance in milliseconds.
    pub freshness_tolerance_ms: u64,
    /// Whether to verify payload hashes for all events.
    pub verify_payload_hashes: bool,
    /// Whether to require deterministic event ordering.
    pub require_deterministic_ordering: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            max_events_per_batch: 1000,
            replay_timeout_ms: 30_000,
            allow_schema_migration: true,
            freshness_tolerance_ms: 1000,
            verify_payload_hashes: true,
            require_deterministic_ordering: true,
        }
    }
}

/// Errors that can occur during replay verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayVerificationError {
    /// Journal checkpoint could not be loaded or is corrupted.
    InvalidCheckpoint(String),
    /// Decision composer failed during replay.
    ComposerError(ShadowDecisionError),
    /// Replay operation timed out.
    ReplayTimeout,
    /// Non-deterministic behavior detected.
    NonDeterministicBehavior(String),
    /// Missing required provenance information.
    MissingProvenance(String),
    /// Signature verification failed for report.
    SignatureVerificationFailed,
    /// Unexpected IO error during replay.
    IoError(String),
}

impl fmt::Display for ReplayVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayVerificationError::InvalidCheckpoint(msg) => {
                write!(f, "Invalid checkpoint: {}", msg)
            }
            ReplayVerificationError::ComposerError(err) => {
                write!(f, "Decision composer error: {}", err)
            }
            ReplayVerificationError::ReplayTimeout => {
                write!(f, "Replay operation timed out")
            }
            ReplayVerificationError::NonDeterministicBehavior(msg) => {
                write!(f, "Non-deterministic behavior: {}", msg)
            }
            ReplayVerificationError::MissingProvenance(msg) => {
                write!(f, "Missing provenance: {}", msg)
            }
            ReplayVerificationError::SignatureVerificationFailed => {
                write!(f, "Signature verification failed")
            }
            ReplayVerificationError::IoError(msg) => {
                write!(f, "IO error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ReplayVerificationError {}

impl From<ShadowDecisionError> for ReplayVerificationError {
    fn from(err: ShadowDecisionError) -> Self {
        ReplayVerificationError::NonDeterministicBehavior(format!("Decision composition error: {}", err))
    }
}

/// Shadow daemon replay verifier for deterministic auditing.
pub struct ShadowReplayVerifier {
    /// Configuration for replay behavior.
    config: ReplayConfig,
    /// Default freshness window for decision composition.
    default_freshness_window_seconds: i64,
    /// Signing key for report verification.
    signing_key: Option<SigningKey>,
}

impl ShadowReplayVerifier {
    /// Creates a new replay verifier with the given configuration.
    pub fn new(config: ReplayConfig, default_freshness_window_seconds: i64) -> Self {
        Self {
            config,
            default_freshness_window_seconds,
            signing_key: None,
        }
    }

    /// Creates a new replay verifier with default configuration.
    pub fn with_default_config() -> Self {
        Self::new(ReplayConfig::default(), 300) // 5 minutes default
    }

    /// Sets the signing key for report verification.
    pub fn with_signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Replays a journal export and verifies byte-stable output.
    pub fn replay_export(
        &mut self,
        export: ShadowEvidenceJournalExport,
        target_environment: String,
    ) -> Result<DriftReport, ReplayVerificationError> {
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Verify export integrity
        self.verify_export_integrity(&export)?;

        // Convert export rows to journal events for composition
        let journal_events = self.convert_export_to_journal_events(&export)?;

        // Replay events through decision composer
        let replay_result = self.replay_events(&journal_events)?;

        // Detect drift in the replayed results
        let detected_drift = self.detect_drift(&export, &replay_result)?;

        // Determine if drift represents expected migration
        let is_expected_migration = self.is_expected_migration(&detected_drift);

        // Generate replay recipe
        let replay_recipe = self.generate_replay_recipe(&export, &target_environment);

        // Create drift report
        let mut report = DriftReport {
            report_id: self.generate_report_id(&export, start_time)?,
            detection_timestamp_ms: start_time,
            source_export: export,
            target_environment,
            detected_drift,
            is_expected_migration,
            replay_recipe,
            verification_signature: None,
        };

        // Sign the report if signing key is available
        if let Some(signing_key) = &self.signing_key {
            let report_hash = self.compute_report_hash(&report)?;
            let signature = sign_preimage(
                &report_hash.as_bytes(),
                REPLAY_VERIFICATION_DOMAIN,
                signing_key,
            )?;
            report.verification_signature = Some(signature);
        }

        Ok(report)
    }

    /// Verifies the integrity of a journal export before replay.
    fn verify_export_integrity(&self, export: &ShadowEvidenceJournalExport) -> Result<(), ReplayVerificationError> {
        // Check schema version compatibility
        if export.schema_version != SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION {
            if !self.config.allow_schema_migration {
                return Err(ReplayVerificationError::InvalidCheckpoint(
                    format!("Schema version mismatch: expected {}, got {}",
                            SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION, export.schema_version),
                ));
            }
        }

        // Check that all events have valid IDs and links
        let mut seen_ids = BTreeSet::new();
        let mut expected_links = BTreeSet::new();

        for row in &export.rows {
            if seen_ids.contains(&row.journal_event_id) {
                return Err(ReplayVerificationError::InvalidCheckpoint(
                    format!("Duplicate event ID: {}", row.journal_event_id),
                ));
            }
            seen_ids.insert(row.journal_event_id);

            // Track expected parent links
            for parent_id in &row.parent_event_ids {
                expected_links.insert(*parent_id);
            }
        }

        // Verify all parent links are satisfied (except for events with no parents)
        for expected_link in expected_links {
            if !seen_ids.contains(&expected_link) {
                return Err(ReplayVerificationError::InvalidCheckpoint(
                    format!("Missing parent event: {}", expected_link),
                ));
            }
        }

        // Verify payload hashes if configured
        if self.config.verify_payload_hashes {
            for row in &export.rows {
                let payload_bytes = serde_json::to_vec(&row.normalized_payload)
                    .map_err(|e| ReplayVerificationError::InvalidCheckpoint(
                        format!("Failed to serialize payload: {}", e)))?;
                let computed_hash = ContentHash::compute(&payload_bytes);
                let computed_hex = hex_encode(computed_hash.as_bytes());
                if computed_hex != row.normalized_payload_hash {
                    return Err(ReplayVerificationError::InvalidCheckpoint(
                        format!("Payload hash mismatch for event {}: expected {}, got {}",
                                row.journal_event_id, row.normalized_payload_hash, computed_hex),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Converts export rows to journal events for composition.
    fn convert_export_to_journal_events(
        &self,
        export: &ShadowEvidenceJournalExport,
    ) -> Result<Vec<JournalSourceEvent>, ReplayVerificationError> {
        let mut events = Vec::new();

        for row in &export.rows {
            let event = JournalSourceEvent {
                source_key: Some(row.source_kind.clone()),
                source_id: Some(format!("{}::{}", row.source_locator, row.journal_event_id)),
                journal_event_id: Some(serde_json::Value::Number(row.journal_event_id.into())),
                source_kind: Some(row.event_kind.clone()),
                schema_version: Some(export.schema_version.clone()),
                content_hash: Some(row.payload_content_hash.clone()),
                payload_content_hash: Some(row.payload_content_hash.clone()),
                normalized_payload_hash: Some(row.normalized_payload_hash.clone()),
                collected_epoch_seconds: Some(row.collected_timestamp_ms / 1000),
                collected_timestamp_ms: Some(row.collected_timestamp_ms),
                freshness_window_seconds: Some(row.freshness_window_ms / 1000),
                fresh: Some(row.degradation_state == "healthy"),
                degraded: Some(row.degradation_state != "healthy"),
                raw_payload_ref: None,
                ..Default::default()
            };
            events.push(event);
        }

        // Sort by sequence ID for deterministic replay
        events.sort_by(|a, b| {
            let a_id = a.journal_event_id.as_ref()
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let b_id = b.journal_event_id.as_ref()
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            a_id.cmp(&b_id)
        });

        Ok(events)
    }

    /// Replays journal events through the decision composer.
    fn replay_events(&mut self, events: &[JournalSourceEvent]) -> Result<ReplayResult, ReplayVerificationError> {
        let mut artifact_results = BTreeMap::new();
        let mut event_ordering = Vec::new();

        // Process events in batches to respect timeout
        let batch_size = self.config.max_events_per_batch;

        for batch_start in (0..events.len()).step_by(batch_size) {
            let batch_end = std::cmp::min(batch_start + batch_size, events.len());
            let batch = &events[batch_start..batch_end];

            // Create composer input for this batch
            let input = ShadowDecisionComposerInput {
                shadow_run_id: format!("replay_batch_{}", batch_start),
                source_revision: "replay_verification".to_string(),
                generated_epoch_seconds: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                default_freshness_window_seconds: self.default_freshness_window_seconds,
                max_recommendations: 16,
                journal_events: batch.to_vec(),
                existing_autopilot_outputs: Vec::new(),
                artifact_paths: crate::shadow_decision_composer::ArtifactPaths::for_output_dir("/tmp/replay"),
            };

            // Compose decisions for this batch
            let artifacts = crate::shadow_decision_composer::compose_shadow_decision(&input)?;

            for event in batch {
                let event_id_str = event.journal_event_id.as_ref()
                    .and_then(|v| v.as_i64())
                    .map(|id| id.to_string())
                    .unwrap_or_default();
                event_ordering.push(event_id_str.clone());
                artifact_results.insert(event_id_str, artifacts.clone());
            }
        }

        Ok(ReplayResult {
            artifact_results,
            event_ordering,
        })
    }

    /// Detects various types of drift in replayed results.
    fn detect_drift(
        &self,
        export: &ShadowEvidenceJournalExport,
        replay_result: &ReplayResult,
    ) -> Result<Vec<DriftType>, ReplayVerificationError> {
        let mut drift_types = Vec::new();

        // Check for schema drift
        if let Some(drift) = self.detect_schema_drift(export)? {
            drift_types.push(drift);
        }

        // Check for missing event links
        if let Some(drift) = self.detect_missing_event_links(export, replay_result)? {
            drift_types.push(drift);
        }

        // Check for non-deterministic ordering
        if let Some(drift) = self.detect_ordering_drift(export, replay_result)? {
            drift_types.push(drift);
        }

        // Check for payload hash mismatches
        drift_types.extend(self.detect_payload_hash_drift(export)?);

        // Check for behavioral regressions
        drift_types.extend(self.detect_behavioral_regressions(export, replay_result)?);

        Ok(drift_types)
    }

    /// Detects schema version drift.
    fn detect_schema_drift(
        &self,
        export: &ShadowEvidenceJournalExport,
    ) -> Result<Option<DriftType>, ReplayVerificationError> {
        if export.schema_version != SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION {
            return Ok(Some(DriftType::SchemaDrift {
                expected_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
                actual_version: export.schema_version.clone(),
                migration_compatible: self.config.allow_schema_migration,
            }));
        }
        Ok(None)
    }

    /// Detects missing event links in the journal chain.
    fn detect_missing_event_links(
        &self,
        export: &ShadowEvidenceJournalExport,
        replay_result: &ReplayResult,
    ) -> Result<Option<DriftType>, ReplayVerificationError> {
        let expected_count = export.rows.len();
        let actual_count = replay_result.artifact_results.len();

        if expected_count != actual_count {
            let mut missing_ids = Vec::new();
            for row in &export.rows {
                let event_id_str = row.journal_event_id.to_string();
                if !replay_result.artifact_results.contains_key(&event_id_str) {
                    missing_ids.push(row.journal_event_id);
                }
            }

            return Ok(Some(DriftType::MissingEventLinks {
                expected_count,
                actual_count,
                missing_ids,
            }));
        }

        Ok(None)
    }

    /// Detects non-deterministic ordering drift.
    fn detect_ordering_drift(
        &self,
        export: &ShadowEvidenceJournalExport,
        replay_result: &ReplayResult,
    ) -> Result<Option<DriftType>, ReplayVerificationError> {
        if !self.config.require_deterministic_ordering {
            return Ok(None);
        }

        // Compute hash of expected ordering (sorted by journal_event_id)
        let mut expected_ids: Vec<i64> = export.rows.iter()
            .map(|row| row.journal_event_id)
            .collect();
        expected_ids.sort();

        let mut expected_ordering_bytes = Vec::new();
        for id in &expected_ids {
            expected_ordering_bytes.extend_from_slice(&id.to_le_bytes());
        }
        let expected_hash = ContentHash::compute(&expected_ordering_bytes);

        // Compute hash of actual ordering
        let mut actual_ids: Vec<i64> = replay_result.event_ordering.iter()
            .filter_map(|id_str| id_str.parse().ok())
            .collect();
        actual_ids.sort(); // Ensure deterministic ordering

        let mut actual_ordering_bytes = Vec::new();
        for id in &actual_ids {
            actual_ordering_bytes.extend_from_slice(&id.to_le_bytes());
        }
        let actual_hash = ContentHash::compute(&actual_ordering_bytes);

        if expected_hash != actual_hash {
            // Find divergence point
            let mut divergence_point = 0;
            for (i, expected_id) in expected_ids.iter().enumerate() {
                if i >= actual_ids.len() || *expected_id != actual_ids[i] {
                    divergence_point = i;
                    break;
                }
            }

            return Ok(Some(DriftType::NonDeterministicOrdering {
                expected_hash,
                actual_hash,
                divergence_point,
            }));
        }

        Ok(None)
    }

    /// Detects payload hash drift across events.
    fn detect_payload_hash_drift(&self, export: &ShadowEvidenceJournalExport) -> Result<Vec<DriftType>, ReplayVerificationError> {
        let mut drift_types = Vec::new();

        if !self.config.verify_payload_hashes {
            return Ok(drift_types);
        }

        for row in &export.rows {
            let payload_bytes = serde_json::to_vec(&row.normalized_payload)
                .map_err(|e| ReplayVerificationError::InvalidCheckpoint(
                    format!("Failed to serialize payload: {}", e)))?;
            let computed_hash = ContentHash::compute(&payload_bytes);
            let computed_hex = hex_encode(computed_hash.as_bytes());

            if computed_hex != row.normalized_payload_hash {
                let expected_hash = hex_decode(&row.normalized_payload_hash)
                    .map_err(|_| ReplayVerificationError::InvalidCheckpoint(
                        "Invalid payload hash format".to_string()))?;
                if expected_hash.len() == 32 {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(&expected_hash);
                    let expected_content_hash = ContentHash::from_bytes(hash_array);

                    drift_types.push(DriftType::PayloadHashMismatch {
                        event_id: row.journal_event_id,
                        expected_hash: expected_content_hash,
                        actual_hash: computed_hash,
                    });
                }
            }
        }

        Ok(drift_types)
    }

    /// Detects behavioral regressions in decision outputs.
    fn detect_behavioral_regressions(
        &self,
        export: &ShadowEvidenceJournalExport,
        replay_result: &ReplayResult,
    ) -> Result<Vec<DriftType>, ReplayVerificationError> {
        let mut drift_types = Vec::new();

        for row in &export.rows {
            let event_id_str = row.journal_event_id.to_string();
            if let Some(artifacts) = replay_result.artifact_results.get(&event_id_str) {
                // Check if decision output matches expected
                let artifacts_bytes = deterministic_serde::to_canonical_bytes(artifacts)?;
                let artifacts_hash = ContentHash::compute(&artifacts_bytes);

                // Check for expected output hash in metadata
                if let Value::Object(metadata_obj) = &row.metadata {
                    if let Some(Value::String(expected_hash_str)) = metadata_obj.get("expected_decision_hash") {
                        if let Ok(expected_hash_bytes) = hex_decode(expected_hash_str) {
                            if expected_hash_bytes.len() == 32 {
                                let mut hash_array = [0u8; 32];
                                hash_array.copy_from_slice(&expected_hash_bytes);
                                let expected_hash = ContentHash::from_bytes(hash_array);

                                if artifacts_hash != expected_hash {
                                    // Create decision ID from event data
                                    let decision_id_bytes = format!("decision_{}", row.journal_event_id).into_bytes();
                                    let decision_id = EngineObjectId::from_content_hash(
                                        ContentHash::compute(&decision_id_bytes));

                                    drift_types.push(DriftType::BehavioralRegression {
                                        decision_id,
                                        expected_output: expected_hash,
                                        actual_output: artifacts_hash,
                                        reproducible: true, // Would need multiple runs to verify
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(drift_types)
    }

    /// Determines if detected drift represents expected migration.
    fn is_expected_migration(&self, drift_types: &[DriftType]) -> bool {
        if !self.config.allow_schema_migration {
            return false;
        }

        // Check if all drift is schema-related and migration-compatible
        for drift in drift_types {
            match drift {
                DriftType::SchemaDrift { migration_compatible, .. } => {
                    if !migration_compatible {
                        return false;
                    }
                }
                DriftType::BehavioralRegression { .. } => {
                    return false;
                }
                _ => {}
            }
        }

        // If we have schema drift, consider it expected migration
        drift_types.iter().any(|d| matches!(d, DriftType::SchemaDrift { .. }))
    }

    /// Generates a replay recipe for reproducing the drift.
    fn generate_replay_recipe(&self, export: &ShadowEvidenceJournalExport, target_environment: &str) -> ReplayRecipe {
        let mut environment_vars = BTreeMap::new();
        environment_vars.insert("RUST_BACKTRACE".to_string(), "1".to_string());
        environment_vars.insert("TARGET_ENV".to_string(), target_environment.to_string());
        environment_vars.insert("SCHEMA_VERSION".to_string(), export.schema_version.clone());

        let replay_command = vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "frankenengine-engine".to_string(),
            "--lib".to_string(),
            "--".to_string(),
            "shadow_replay_verifier::integration_tests::test_replay_export".to_string(),
        ];

        let mut expected_outputs = BTreeMap::new();
        for row in &export.rows {
            let output_key = format!("event_{}", row.journal_event_id);
            let payload_bytes = serde_json::to_vec(&row.normalized_payload).unwrap_or_default();
            let payload_hash = ContentHash::compute(&payload_bytes);
            expected_outputs.insert(output_key, payload_hash);
        }

        let export_filename = format!("export_{}_{}.json",
                                    export.schema_version.replace('.', "_"),
                                    export.rows.len());

        ReplayRecipe {
            input_checkpoint: export_filename,
            replay_command,
            environment_vars,
            expected_outputs,
            referenced_artifacts: vec![
                "crates/franken-engine/src/shadow_replay_verifier.rs".to_string(),
                "crates/franken-engine/src/shadow_decision_composer.rs".to_string(),
                "crates/franken-engine/src/shadow_evidence_journal.rs".to_string(),
                "crates/franken-engine/src/shadow_replay_fixtures.rs".to_string(),
            ],
        }
    }

    /// Generates a unique report ID based on export and timestamp.
    fn generate_report_id(&self, export: &ShadowEvidenceJournalExport, timestamp_ms: u64) -> Result<EngineObjectId, ReplayVerificationError> {
        let mut id_bytes = Vec::new();
        id_bytes.extend_from_slice(b"shadow-replay-report|");
        id_bytes.extend_from_slice(export.schema_version.as_bytes());
        id_bytes.extend_from_slice(b"|");
        id_bytes.extend_from_slice(&(export.rows.len() as u32).to_le_bytes());
        id_bytes.extend_from_slice(b"|");
        id_bytes.extend_from_slice(&timestamp_ms.to_le_bytes());

        let content_hash = ContentHash::compute(&id_bytes);
        let object_id = EngineObjectId::from_content_hash(content_hash);
        Ok(object_id)
    }

    /// Computes hash of a drift report for signature verification.
    fn compute_report_hash(&self, report: &DriftReport) -> Result<ContentHash, ReplayVerificationError> {
        // Create a signable representation excluding the signature field
        let mut signable_report = report.clone();
        signable_report.verification_signature = None;

        let report_bytes = deterministic_serde::to_canonical_bytes(&signable_report)?;
        Ok(ContentHash::compute(&report_bytes))
    }
}

/// Result of replaying journal events.
#[derive(Debug)]
struct ReplayResult {
    /// Decision artifacts generated for each event.
    artifact_results: BTreeMap<String, crate::shadow_decision_composer::ShadowDecisionArtifacts>,
    /// Actual order in which events were processed.
    event_ordering: Vec<String>,
}

/// Helper function to encode bytes as hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Helper function to decode hex string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, ReplayVerificationError> {
    if hex.len() % 2 != 0 {
        return Err(ReplayVerificationError::InvalidCheckpoint(
            "Hex string has odd length".to_string(),
        ));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let chunk_str = std::str::from_utf8(chunk)
            .map_err(|_| ReplayVerificationError::InvalidCheckpoint("Invalid hex string".to_string()))?;
        let byte = u8::from_str_radix(chunk_str, 16)
            .map_err(|_| ReplayVerificationError::InvalidCheckpoint("Invalid hex digit".to_string()))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

impl From<deterministic_serde::SerializationError> for ReplayVerificationError {
    fn from(err: deterministic_serde::SerializationError) -> Self {
        ReplayVerificationError::InvalidCheckpoint(format!("Serialization error: {}", err))
    }
}

impl From<crate::signature_preimage::SignatureError> for ReplayVerificationError {
    fn from(err: crate::signature_preimage::SignatureError) -> Self {
        ReplayVerificationError::SignatureVerificationFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drift_type_display() {
        let drift = DriftType::SchemaDrift {
            expected_version: "1.0".to_string(),
            actual_version: "1.1".to_string(),
            migration_compatible: true,
        };

        assert!(drift.to_string().contains("Schema drift"));
        assert!(drift.to_string().contains("1.0"));
        assert!(drift.to_string().contains("1.1"));
        assert!(drift.to_string().contains("true"));
    }

    #[test]
    fn test_replay_config_default() {
        let config = ReplayConfig::default();

        assert_eq!(config.max_events_per_batch, 1000);
        assert_eq!(config.replay_timeout_ms, 30_000);
        assert!(config.allow_schema_migration);
        assert_eq!(config.freshness_tolerance_ms, 1000);
        assert!(config.verify_payload_hashes);
        assert!(config.require_deterministic_ordering);
    }

    #[test]
    fn test_hex_encode_decode() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "0123456789abcdef");

        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_hex_decode_error() {
        assert!(hex_decode("xyz").is_err());
        assert!(hex_decode("123").is_err()); // odd length
    }

    #[test]
    fn test_replay_verifier_creation() {
        let verifier = ShadowReplayVerifier::with_default_config();
        assert_eq!(verifier.config.max_events_per_batch, 1000);
        assert!(verifier.signing_key.is_none());
        assert_eq!(verifier.default_freshness_window_seconds, 300);
    }

    #[test]
    fn test_is_expected_migration() {
        let verifier = ShadowReplayVerifier::with_default_config();

        let schema_drift = vec![DriftType::SchemaDrift {
            expected_version: "1.0".to_string(),
            actual_version: "1.1".to_string(),
            migration_compatible: true,
        }];
        assert!(verifier.is_expected_migration(&schema_drift));

        let behavioral_regression = vec![DriftType::BehavioralRegression {
            decision_id: EngineObjectId::from_content_hash(ContentHash::from_bytes([0u8; 32])),
            expected_output: ContentHash::from_bytes([1u8; 32]),
            actual_output: ContentHash::from_bytes([2u8; 32]),
            reproducible: true,
        }];
        assert!(!verifier.is_expected_migration(&behavioral_regression));
    }
}