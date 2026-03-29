//! Parser evidence indexer and schema-migration pipeline.
//!
//! This module indexes parser run manifests + structured event logs into a
//! deterministic cross-run view that supports:
//! - replay pointer lookups (run -> artifacts -> replay command),
//! - regression correlation across runs,
//! - fail-closed schema compatibility and migration upgrades.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical schema for indexed parser evidence documents.
pub const PARSER_EVIDENCE_INDEX_SCHEMA_V1: &str = "franken-engine.parser-evidence-index.v1";

/// Single run artifact pointers linked into the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserRunArtifactRef {
    pub run_id: String,
    pub manifest_schema_version: String,
    pub manifest_path: String,
    pub events_path: String,
    pub commands_path: String,
    pub replay_command: String,
    pub generated_at_utc: Option<String>,
    pub outcome: Option<String>,
}

/// Canonical indexed event row used for correlation and migration checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedParserEvent {
    pub run_id: String,
    pub sequence: u64,
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub replay_command: Option<String>,
    pub scenario_id: Option<String>,
}

/// Schema migration boundary observed while traversing the indexed event stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMigrationBoundary {
    pub run_id: String,
    pub sequence: u64,
    pub from_schema: String,
    pub to_schema: String,
}

/// Deterministic evidence index document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserEvidenceIndex {
    pub schema_version: String,
    pub runs: Vec<ParserRunArtifactRef>,
    pub events: Vec<IndexedParserEvent>,
    pub schema_migrations: Vec<SchemaMigrationBoundary>,
}

/// Correlation key used for cross-run regression clustering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CorrelationKey {
    pub component: String,
    pub event: String,
    pub scenario_id: Option<String>,
    pub error_code: Option<String>,
    pub outcome: String,
}

/// Aggregated cross-run regression signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelatedRegression {
    pub key: CorrelationKey,
    pub run_count: u64,
    pub occurrence_count: u64,
    pub run_ids: Vec<String>,
    pub trace_ids: Vec<String>,
    pub replay_commands: Vec<String>,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CorrelationAccumulator {
    run_ids: BTreeSet<String>,
    trace_ids: BTreeSet<String>,
    replay_commands: BTreeSet<String>,
    occurrence_count: u64,
}

/// Schema version family + major parsed from `<family>.v<major>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SchemaVersionTag {
    pub family: String,
    pub major: u32,
}

/// Migration step declaration used by the migration planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMigrationStep {
    pub migration_id: String,
    pub from_schema: String,
    pub to_schema: String,
}

/// Applied migration summary emitted by migration execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedSchemaMigration {
    pub migration_id: String,
    pub from_schema: String,
    pub to_schema: String,
    pub affected_records: u64,
}

/// Indexer/migration errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceIndexerError {
    MissingField(&'static str),
    InvalidFieldType {
        field: &'static str,
        expected: &'static str,
    },
    DuplicateRunId(String),
    UnknownRunId(String),
    InvalidSchemaVersion(String),
    IncompatibleSchemaFamily {
        from_schema: String,
        to_schema: String,
    },
    NoMigrationPath {
        from_schema: String,
        to_schema: String,
    },
    Json(String),
}

impl fmt::Display for EvidenceIndexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field `{field}`"),
            Self::InvalidFieldType { field, expected } => {
                write!(f, "invalid field type for `{field}` (expected {expected})")
            }
            Self::DuplicateRunId(run_id) => write!(f, "duplicate run_id `{run_id}`"),
            Self::UnknownRunId(run_id) => write!(f, "unknown run_id `{run_id}`"),
            Self::InvalidSchemaVersion(schema) => {
                write!(
                    f,
                    "invalid schema version `{schema}`; expected `<family>.v<major>`"
                )
            }
            Self::IncompatibleSchemaFamily {
                from_schema,
                to_schema,
            } => write!(
                f,
                "incompatible schema families between `{from_schema}` and `{to_schema}`"
            ),
            Self::NoMigrationPath {
                from_schema,
                to_schema,
            } => write!(f, "no migration path from `{from_schema}` to `{to_schema}`"),
            Self::Json(msg) => write!(f, "json error: {msg}"),
        }
    }
}

impl Error for EvidenceIndexerError {}

impl From<serde_json::Error> for EvidenceIndexerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value.to_string())
    }
}

/// Incremental builder for parser evidence index documents.
#[derive(Debug, Default)]
pub struct ParserEvidenceIndexBuilder {
    runs: BTreeMap<String, ParserRunArtifactRef>,
    events: Vec<IndexedParserEvent>,
}

impl SchemaVersionTag {
    /// Parse `<family>.v<major>` schema form.
    pub fn parse(schema: &str) -> Result<Self, EvidenceIndexerError> {
        if let Some((family, major_str)) = schema.rsplit_once(".v") {
            if family.is_empty() {
                return Err(EvidenceIndexerError::InvalidSchemaVersion(
                    schema.to_string(),
                ));
            }
            if let Ok(major) = major_str.parse::<u32>() {
                return Ok(Self {
                    family: family.to_string(),
                    major,
                });
            }
        }
        Err(EvidenceIndexerError::InvalidSchemaVersion(
            schema.to_string(),
        ))
    }
}

impl ParserRunArtifactRef {
    /// Build a run artifact row from a manifest JSON value and known file pointers.
    pub fn from_manifest_value(
        manifest: &Value,
        manifest_path: impl Into<String>,
        events_path: impl Into<String>,
        commands_path: impl Into<String>,
    ) -> Result<Self, EvidenceIndexerError> {
        let run_id = required_string(manifest, "run_id")?;
        let manifest_schema_version = required_string(manifest, "schema_version")?;
        SchemaVersionTag::parse(&manifest_schema_version)?;
        let replay_command = required_string(manifest, "replay_command")?;

        Ok(Self {
            run_id,
            manifest_schema_version,
            manifest_path: manifest_path.into(),
            events_path: events_path.into(),
            commands_path: commands_path.into(),
            replay_command,
            generated_at_utc: optional_string(manifest, "generated_at_utc")?,
            outcome: optional_string(manifest, "outcome")?,
        })
    }
}

impl IndexedParserEvent {
    fn from_value(
        run_id: &str,
        sequence: u64,
        value: &Value,
    ) -> Result<Self, EvidenceIndexerError> {
        let schema_version = required_string(value, "schema_version")?;
        SchemaVersionTag::parse(&schema_version)?;

        let scenario_id = first_present_string(value, &["scenario_id", "fixture_id"])?;

        Ok(Self {
            run_id: run_id.to_string(),
            sequence,
            schema_version,
            trace_id: required_string(value, "trace_id")?,
            decision_id: required_string(value, "decision_id")?,
            policy_id: required_string(value, "policy_id")?,
            component: required_string(value, "component")?,
            event: required_string(value, "event")?,
            outcome: required_string(value, "outcome")?,
            error_code: optional_string(value, "error_code")?,
            replay_command: optional_string(value, "replay_command")?,
            scenario_id,
        })
    }
}

impl ParserEvidenceIndexBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one run manifest to the index builder.
    pub fn add_run(
        &mut self,
        manifest: &Value,
        manifest_path: impl Into<String>,
        events_path: impl Into<String>,
        commands_path: impl Into<String>,
    ) -> Result<&mut Self, EvidenceIndexerError> {
        let run = ParserRunArtifactRef::from_manifest_value(
            manifest,
            manifest_path,
            events_path,
            commands_path,
        )?;
        if self.runs.contains_key(&run.run_id) {
            return Err(EvidenceIndexerError::DuplicateRunId(run.run_id));
        }
        self.runs.insert(run.run_id.clone(), run);
        Ok(self)
    }

    /// Add JSONL events for a known run.
    pub fn add_events_jsonl(
        &mut self,
        run_id: &str,
        events_jsonl: &str,
    ) -> Result<&mut Self, EvidenceIndexerError> {
        if !self.runs.contains_key(run_id) {
            return Err(EvidenceIndexerError::UnknownRunId(run_id.to_string()));
        }

        let mut seq = self
            .events
            .iter()
            .filter(|event| event.run_id == run_id)
            .map(|event| event.sequence)
            .max()
            .map_or(0, |last| last.saturating_add(1));
        for raw_line in events_jsonl.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line)?;
            let event = IndexedParserEvent::from_value(run_id, seq, &value)?;
            self.events.push(event);
            seq = seq.saturating_add(1);
        }
        Ok(self)
    }

    /// Build deterministic index output.
    pub fn build(self) -> ParserEvidenceIndex {
        let mut runs: Vec<ParserRunArtifactRef> = self.runs.into_values().collect();
        runs.sort_by(|a, b| a.run_id.cmp(&b.run_id));

        let mut events = self.events;
        events.sort_by(|a, b| {
            a.run_id
                .cmp(&b.run_id)
                .then(a.sequence.cmp(&b.sequence))
                .then(a.component.cmp(&b.component))
                .then(a.event.cmp(&b.event))
        });

        let schema_migrations = compute_schema_migrations(&events);

        ParserEvidenceIndex {
            schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
            runs,
            events,
            schema_migrations,
        }
    }
}

impl ParserEvidenceIndex {
    /// Cluster repeated failures across runs for regression forensics.
    pub fn correlate_regressions(&self) -> Vec<CorrelatedRegression> {
        let mut groups: BTreeMap<CorrelationKey, CorrelationAccumulator> = BTreeMap::new();

        for event in &self.events {
            if event.outcome != "fail" && event.error_code.is_none() {
                continue;
            }

            let key = CorrelationKey {
                component: event.component.clone(),
                event: event.event.clone(),
                scenario_id: event.scenario_id.clone(),
                error_code: event.error_code.clone(),
                outcome: event.outcome.clone(),
            };

            let entry = groups.entry(key).or_insert_with(|| CorrelationAccumulator {
                run_ids: BTreeSet::new(),
                trace_ids: BTreeSet::new(),
                replay_commands: BTreeSet::new(),
                occurrence_count: 0,
            });
            entry.run_ids.insert(event.run_id.clone());
            entry.trace_ids.insert(event.trace_id.clone());
            if let Some(replay) = &event.replay_command
                && !replay.is_empty()
            {
                entry.replay_commands.insert(replay.clone());
            }
            entry.occurrence_count = entry.occurrence_count.saturating_add(1);
        }

        let mut out = Vec::new();
        for (key, acc) in groups {
            if acc.run_ids.len() < 2 {
                continue;
            }
            out.push(CorrelatedRegression {
                severity: classify_correlation_severity(&key),
                run_count: acc.run_ids.len() as u64,
                occurrence_count: acc.occurrence_count,
                run_ids: acc.run_ids.into_iter().collect(),
                trace_ids: acc.trace_ids.into_iter().collect(),
                replay_commands: acc.replay_commands.into_iter().collect(),
                key,
            });
        }

        out.sort_by(|a, b| {
            b.occurrence_count
                .cmp(&a.occurrence_count)
                .then(b.run_count.cmp(&a.run_count))
                .then(a.key.cmp(&b.key))
        });
        out
    }

    /// Validate that all indexed event schemas are compatible with a target schema.
    pub fn validate_event_schema_compatibility(
        &self,
        target_schema: &str,
    ) -> Result<(), EvidenceIndexerError> {
        let target = SchemaVersionTag::parse(target_schema)?;
        for event in &self.events {
            let observed = SchemaVersionTag::parse(&event.schema_version)?;
            if observed.family != target.family {
                return Err(EvidenceIndexerError::IncompatibleSchemaFamily {
                    from_schema: event.schema_version.clone(),
                    to_schema: target_schema.to_string(),
                });
            }
            if observed.major > target.major {
                return Err(EvidenceIndexerError::NoMigrationPath {
                    from_schema: event.schema_version.clone(),
                    to_schema: target_schema.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Apply schema migration steps to indexed events and return migration receipts.
    pub fn migrate_event_schemas(
        &mut self,
        target_schema: &str,
        steps: &[SchemaMigrationStep],
    ) -> Result<Vec<AppliedSchemaMigration>, EvidenceIndexerError> {
        let mut receipts: BTreeMap<String, AppliedSchemaMigration> = BTreeMap::new();
        for event in &mut self.events {
            if event.schema_version == target_schema {
                continue;
            }

            let path = resolve_migration_path(&event.schema_version, target_schema, steps)?;
            for step in path {
                let receipt = receipts
                    .entry(step.migration_id.clone())
                    .or_insert_with(|| AppliedSchemaMigration {
                        migration_id: step.migration_id.clone(),
                        from_schema: step.from_schema.clone(),
                        to_schema: step.to_schema.clone(),
                        affected_records: 0,
                    });
                receipt.affected_records = receipt.affected_records.saturating_add(1);
                event.schema_version = step.to_schema;
            }
        }

        self.schema_migrations = compute_schema_migrations(&self.events);
        let mut out: Vec<AppliedSchemaMigration> = receipts.into_values().collect();
        out.sort_by(|a, b| a.migration_id.cmp(&b.migration_id));
        Ok(out)
    }
}

fn classify_correlation_severity(key: &CorrelationKey) -> String {
    if key.error_code.is_some() {
        "high".to_string()
    } else if key.outcome == "fail" {
        "medium".to_string()
    } else {
        "info".to_string()
    }
}

fn compute_schema_migrations(events: &[IndexedParserEvent]) -> Vec<SchemaMigrationBoundary> {
    let mut ordered: Vec<&IndexedParserEvent> = events.iter().collect();
    ordered.sort_by(|a, b| {
        a.run_id
            .cmp(&b.run_id)
            .then(a.sequence.cmp(&b.sequence))
            .then(a.component.cmp(&b.component))
            .then(a.event.cmp(&b.event))
    });

    let mut out = Vec::new();
    let mut prev_run_id: Option<&str> = None;
    let mut prev_schema: Option<&str> = None;

    for event in ordered {
        if let (Some(prev_run), Some(prev)) = (prev_run_id, prev_schema)
            && prev_run == event.run_id
            && prev != event.schema_version
        {
            out.push(SchemaMigrationBoundary {
                run_id: event.run_id.clone(),
                sequence: event.sequence,
                from_schema: prev.to_string(),
                to_schema: event.schema_version.clone(),
            });
        }
        prev_run_id = Some(event.run_id.as_str());
        prev_schema = Some(event.schema_version.as_str());
    }

    out
}

fn resolve_migration_path(
    from_schema: &str,
    target_schema: &str,
    steps: &[SchemaMigrationStep],
) -> Result<Vec<SchemaMigrationStep>, EvidenceIndexerError> {
    if from_schema == target_schema {
        return Ok(Vec::new());
    }

    let from_tag = SchemaVersionTag::parse(from_schema)?;
    let target_tag = SchemaVersionTag::parse(target_schema)?;
    if from_tag.family != target_tag.family {
        return Err(EvidenceIndexerError::IncompatibleSchemaFamily {
            from_schema: from_schema.to_string(),
            to_schema: target_schema.to_string(),
        });
    }
    let expected_family = from_tag.family.clone();

    let mut current = from_schema.to_string();
    let mut path = Vec::new();
    let mut visited = BTreeSet::new();
    let max_hops = 32_u32;
    let mut hops = 0_u32;

    while current != target_schema {
        if !visited.insert(current.clone()) {
            return Err(EvidenceIndexerError::NoMigrationPath {
                from_schema: from_schema.to_string(),
                to_schema: target_schema.to_string(),
            });
        }
        if hops >= max_hops {
            return Err(EvidenceIndexerError::NoMigrationPath {
                from_schema: from_schema.to_string(),
                to_schema: target_schema.to_string(),
            });
        }

        let mut next_step: Option<&SchemaMigrationStep> = None;
        for step in steps.iter().filter(|step| step.from_schema == current) {
            // Reject ambiguity only on the branch we are actually traversing.
            // Unrelated duplicate declarations elsewhere in the step set should
            // not poison a valid migration path.
            if next_step.replace(step).is_some() {
                return Err(EvidenceIndexerError::NoMigrationPath {
                    from_schema: from_schema.to_string(),
                    to_schema: target_schema.to_string(),
                });
            }
        }

        let Some(step) = next_step else {
            return Err(EvidenceIndexerError::NoMigrationPath {
                from_schema: from_schema.to_string(),
                to_schema: target_schema.to_string(),
            });
        };
        let step_from_tag = SchemaVersionTag::parse(&step.from_schema)?;
        let step_to_tag = SchemaVersionTag::parse(&step.to_schema)?;
        if step_from_tag.family != expected_family || step_to_tag.family != expected_family {
            return Err(EvidenceIndexerError::IncompatibleSchemaFamily {
                from_schema: step.from_schema.clone(),
                to_schema: step.to_schema.clone(),
            });
        }
        let step_clone = (*step).clone();
        current = step_clone.to_schema.clone();
        path.push(step_clone);
        hops = hops.saturating_add(1);
    }

    Ok(path)
}

fn required_string(value: &Value, field: &'static str) -> Result<String, EvidenceIndexerError> {
    let Some(v) = value.get(field) else {
        return Err(EvidenceIndexerError::MissingField(field));
    };
    let Some(s) = v.as_str() else {
        return Err(EvidenceIndexerError::InvalidFieldType {
            field,
            expected: "string",
        });
    };
    if s.is_empty() {
        return Err(EvidenceIndexerError::MissingField(field));
    }
    Ok(s.to_string())
}

fn optional_string(
    value: &Value,
    field: &'static str,
) -> Result<Option<String>, EvidenceIndexerError> {
    let Some(v) = value.get(field) else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let Some(s) = v.as_str() else {
        return Err(EvidenceIndexerError::InvalidFieldType {
            field,
            expected: "string|null",
        });
    };
    if s.is_empty() {
        return Ok(None);
    }
    Ok(Some(s.to_string()))
}

fn first_present_string(
    value: &Value,
    fields: &[&'static str],
) -> Result<Option<String>, EvidenceIndexerError> {
    for field in fields {
        if let Some(candidate) = optional_string(value, field)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(run_id: &str, schema: &str, replay: &str) -> Value {
        serde_json::json!({
            "schema_version": schema,
            "run_id": run_id,
            "replay_command": replay,
            "generated_at_utc": "2026-02-25T00:00:00Z",
            "outcome": "pass"
        })
    }

    fn event(run_id: &str, sequence: u64, schema_version: &str) -> IndexedParserEvent {
        IndexedParserEvent {
            run_id: run_id.to_string(),
            sequence,
            schema_version: schema_version.to_string(),
            trace_id: format!("trace-{run_id}-{sequence}"),
            decision_id: format!("decision-{run_id}-{sequence}"),
            policy_id: "policy".to_string(),
            component: "component".to_string(),
            event: "event".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            replay_command: None,
            scenario_id: None,
        }
    }

    #[test]
    fn schema_version_parse_ok() {
        let tag = SchemaVersionTag::parse("franken-engine.parser-log-event.v12").unwrap();
        assert_eq!(tag.family, "franken-engine.parser-log-event");
        assert_eq!(tag.major, 12);
    }

    #[test]
    fn schema_version_parse_rejects_invalid() {
        let err = SchemaVersionTag::parse("franken-engine.parser-log-event").unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
    }

    #[test]
    fn builder_indexes_runs_and_events_deterministically() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest(
                    "run-b",
                    "franken-engine.parser-evidence-index.run.v1",
                    "replay-b",
                ),
                "manifest-b.json",
                "events-b.jsonl",
                "commands-b.txt",
            )
            .unwrap();
        builder
            .add_run(
                &manifest(
                    "run-a",
                    "franken-engine.parser-evidence-index.run.v1",
                    "replay-a",
                ),
                "manifest-a.json",
                "events-a.jsonl",
                "commands-a.txt",
            )
            .unwrap();

        builder
            .add_events_jsonl(
                "run-b",
                r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"tb","decision_id":"db","policy_id":"pb","component":"gate","event":"done","outcome":"pass","error_code":null}"#,
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"ta","decision_id":"da","policy_id":"pa","component":"gate","event":"done","outcome":"pass","error_code":null}"#,
            )
            .unwrap();

        let index = builder.build();
        assert_eq!(index.runs[0].run_id, "run-a");
        assert_eq!(index.runs[1].run_id, "run-b");
        assert_eq!(index.events[0].run_id, "run-a");
        assert_eq!(index.events[1].run_id, "run-b");
        assert!(index.schema_migrations.is_empty());
    }

    #[test]
    fn cross_run_correlation_clusters_repeated_failures() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        for run_id in ["run-a", "run-b"] {
            builder
                .add_run(
                    &manifest(
                        run_id,
                        "franken-engine.parser-evidence-index.run.v1",
                        &format!("replay-{run_id}"),
                    ),
                    format!("{run_id}.manifest"),
                    format!("{run_id}.events"),
                    format!("{run_id}.commands"),
                )
                .unwrap();

            let events = format!(
                "{{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"trace-{run_id}\",\"decision_id\":\"decision-{run_id}\",\"policy_id\":\"policy\",\"component\":\"parser_equivalence\",\"event\":\"drift_detected\",\"outcome\":\"fail\",\"error_code\":\"FE-PARSER-DRIFT\",\"replay_command\":\"replay-{run_id}\",\"scenario_id\":\"fixture-1\"}}"
            );
            builder.add_events_jsonl(run_id, &events).unwrap();
        }

        let index = builder.build();
        let clusters = index.correlate_regressions();
        assert_eq!(clusters.len(), 1);

        let cluster = &clusters[0];
        assert_eq!(cluster.run_count, 2);
        assert_eq!(cluster.occurrence_count, 2);
        assert_eq!(cluster.key.component, "parser_equivalence");
        assert_eq!(cluster.key.event, "drift_detected");
        assert_eq!(cluster.key.scenario_id.as_deref(), Some("fixture-1"));
        assert_eq!(cluster.key.error_code.as_deref(), Some("FE-PARSER-DRIFT"));
        assert_eq!(cluster.severity, "high");
    }

    #[test]
    fn migration_path_requires_same_family() {
        let steps = vec![SchemaMigrationStep {
            migration_id: "mig-1".to_string(),
            from_schema: "franken-engine.parser-log-event.v1".to_string(),
            to_schema: "franken-engine.parser-log-event.v2".to_string(),
        }];

        let err = resolve_migration_path(
            "franken-engine.other-event.v1",
            "franken-engine.parser-log-event.v2",
            &steps,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            EvidenceIndexerError::IncompatibleSchemaFamily { .. }
        ));
    }

    #[test]
    fn migrate_event_schemas_applies_step_and_updates_boundaries() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest(
                    "run-a",
                    "franken-engine.parser-evidence-index.run.v1",
                    "replay-a",
                ),
                "manifest-a.json",
                "events-a.jsonl",
                "commands-a.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"
{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"t1","decision_id":"d1","policy_id":"p1","component":"gate","event":"start","outcome":"pass","error_code":null}
{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"t2","decision_id":"d2","policy_id":"p1","component":"gate","event":"done","outcome":"pass","error_code":null}
"#,
            )
            .unwrap();

        let mut index = builder.build();
        assert!(index.schema_migrations.is_empty());

        let receipts = index
            .migrate_event_schemas(
                "franken-engine.parser-log-event.v2",
                &[SchemaMigrationStep {
                    migration_id: "mig-log-v1-v2".to_string(),
                    from_schema: "franken-engine.parser-log-event.v1".to_string(),
                    to_schema: "franken-engine.parser-log-event.v2".to_string(),
                }],
            )
            .unwrap();

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].migration_id, "mig-log-v1-v2");
        assert_eq!(receipts[0].affected_records, 2);
        assert!(
            index
                .events
                .iter()
                .all(|e| e.schema_version == "franken-engine.parser-log-event.v2")
        );
        assert!(index.schema_migrations.is_empty());
    }

    #[test]
    fn validate_schema_compatibility_rejects_newer_major() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest(
                    "run-a",
                    "franken-engine.parser-evidence-index.run.v1",
                    "replay-a",
                ),
                "manifest-a.json",
                "events-a.jsonl",
                "commands-a.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"franken-engine.parser-log-event.v3","trace_id":"t1","decision_id":"d1","policy_id":"p1","component":"gate","event":"done","outcome":"pass","error_code":null}"#,
            )
            .unwrap();

        let index = builder.build();
        let err = index
            .validate_event_schema_compatibility("franken-engine.parser-log-event.v2")
            .unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
    }

    // --- enrichment tests ---

    #[test]
    fn schema_version_parse_empty_family_rejected() {
        let err = SchemaVersionTag::parse(".v1").unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
    }

    #[test]
    fn schema_version_parse_non_numeric_major_rejected() {
        let err = SchemaVersionTag::parse("family.vabc").unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
    }

    #[test]
    fn schema_version_parse_no_dot_v_separator() {
        let err = SchemaVersionTag::parse("family-v1").unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
    }

    #[test]
    fn schema_version_parse_zero_major() {
        let tag = SchemaVersionTag::parse("fam.v0").unwrap();
        assert_eq!(tag.family, "fam");
        assert_eq!(tag.major, 0);
    }

    #[test]
    fn schema_version_tag_serde_round_trip() {
        let tag = SchemaVersionTag::parse("franken-engine.parser-log-event.v5").unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        let back: SchemaVersionTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, back);
    }

    #[test]
    fn schema_version_tag_ordering() {
        let a = SchemaVersionTag::parse("alpha.v1").unwrap();
        let b = SchemaVersionTag::parse("alpha.v2").unwrap();
        let c = SchemaVersionTag::parse("beta.v1").unwrap();
        assert!(a < b);
        assert!(a < c);
    }

    #[test]
    fn builder_duplicate_run_id_rejected() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay-a"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        let err = builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay-a2"),
                "m2.json",
                "e2.jsonl",
                "c2.txt",
            )
            .unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::DuplicateRunId(id) if id == "run-a"));
    }

    #[test]
    fn builder_events_for_unknown_run_rejected() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        let err = builder
            .add_events_jsonl("nonexistent-run", r#"{"schema_version":"fam.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#)
            .unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::UnknownRunId(id) if id == "nonexistent-run"));
    }

    #[test]
    fn builder_skips_blank_lines_in_jsonl() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                "\n  \n{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t\",\"decision_id\":\"d\",\"policy_id\":\"p\",\"component\":\"c\",\"event\":\"e\",\"outcome\":\"pass\"}\n\n",
            )
            .unwrap();
        let index = builder.build();
        assert_eq!(index.events.len(), 1);
    }

    #[test]
    fn add_events_jsonl_appends_sequence_for_same_run() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();

        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v1","trace_id":"t1","decision_id":"d1","policy_id":"p","component":"c","event":"e1","outcome":"pass"}"#,
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v1","trace_id":"t2","decision_id":"d2","policy_id":"p","component":"c","event":"e2","outcome":"pass"}"#,
            )
            .unwrap();

        let index = builder.build();
        assert_eq!(index.events.len(), 2);
        assert_eq!(index.events[0].sequence, 0);
        assert_eq!(index.events[1].sequence, 1);
    }

    #[test]
    fn manifest_missing_run_id_rejected() {
        let val = serde_json::json!({
            "schema_version": "fam.run.v1",
            "replay_command": "replay"
        });
        let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
    }

    #[test]
    fn manifest_empty_run_id_rejected() {
        let val = serde_json::json!({
            "schema_version": "fam.run.v1",
            "run_id": "",
            "replay_command": "replay"
        });
        let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
    }

    #[test]
    fn manifest_non_string_run_id_rejected() {
        let val = serde_json::json!({
            "schema_version": "fam.run.v1",
            "run_id": 42,
            "replay_command": "replay"
        });
        let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
        assert!(matches!(
            err,
            EvidenceIndexerError::InvalidFieldType {
                field: "run_id",
                ..
            }
        ));
    }

    #[test]
    fn manifest_optional_fields_absent() {
        let val = serde_json::json!({
            "schema_version": "fam.run.v1",
            "run_id": "run-1",
            "replay_command": "replay-cmd"
        });
        let r = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap();
        assert!(r.generated_at_utc.is_none());
        assert!(r.outcome.is_none());
    }

    #[test]
    fn manifest_optional_fields_null() {
        let val = serde_json::json!({
            "schema_version": "fam.run.v1",
            "run_id": "run-1",
            "replay_command": "replay-cmd",
            "generated_at_utc": null,
            "outcome": null
        });
        let r = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap();
        assert!(r.generated_at_utc.is_none());
        assert!(r.outcome.is_none());
    }

    #[test]
    fn event_uses_fixture_id_when_scenario_id_absent() {
        let val = serde_json::json!({
            "schema_version": "fam.event.v1",
            "trace_id": "t",
            "decision_id": "d",
            "policy_id": "p",
            "component": "c",
            "event": "e",
            "outcome": "pass",
            "fixture_id": "fix-42"
        });
        let event = IndexedParserEvent::from_value("run-1", 0, &val).unwrap();
        assert_eq!(event.scenario_id.as_deref(), Some("fix-42"));
    }

    #[test]
    fn event_prefers_scenario_id_over_fixture_id() {
        let val = serde_json::json!({
            "schema_version": "fam.event.v1",
            "trace_id": "t",
            "decision_id": "d",
            "policy_id": "p",
            "component": "c",
            "event": "e",
            "outcome": "pass",
            "scenario_id": "scen-1",
            "fixture_id": "fix-42"
        });
        let event = IndexedParserEvent::from_value("run-1", 0, &val).unwrap();
        assert_eq!(event.scenario_id.as_deref(), Some("scen-1"));
    }

    #[test]
    fn correlate_regressions_ignores_single_run_failures() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay-a"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"gate","event":"fail_check","outcome":"fail","error_code":"E01"}"#,
            )
            .unwrap();
        let index = builder.build();
        let clusters = index.correlate_regressions();
        assert!(clusters.is_empty());
    }

    #[test]
    fn correlate_regressions_ignores_pass_events() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        for run_id in ["run-a", "run-b"] {
            builder
                .add_run(
                    &manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")),
                    format!("{run_id}-m.json"),
                    format!("{run_id}-e.jsonl"),
                    format!("{run_id}-c.txt"),
                )
                .unwrap();
            let events = format!(
                "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t-{run_id}\",\"decision_id\":\"d\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"check\",\"outcome\":\"pass\"}}"
            );
            builder.add_events_jsonl(run_id, &events).unwrap();
        }
        let index = builder.build();
        assert!(index.correlate_regressions().is_empty());
    }

    #[test]
    fn correlation_severity_medium_for_fail_without_error_code() {
        let key = CorrelationKey {
            component: "c".to_string(),
            event: "e".to_string(),
            scenario_id: None,
            error_code: None,
            outcome: "fail".to_string(),
        };
        assert_eq!(classify_correlation_severity(&key), "medium");
    }

    #[test]
    fn correlation_severity_info_for_non_fail_non_error() {
        let key = CorrelationKey {
            component: "c".to_string(),
            event: "e".to_string(),
            scenario_id: None,
            error_code: None,
            outcome: "warn".to_string(),
        };
        assert_eq!(classify_correlation_severity(&key), "info");
    }

    #[test]
    fn validate_schema_compatibility_accepts_same_version() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v2","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
            )
            .unwrap();
        let index = builder.build();
        index
            .validate_event_schema_compatibility("fam.event.v2")
            .unwrap();
    }

    #[test]
    fn validate_schema_compatibility_rejects_different_family() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam-a.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
            )
            .unwrap();
        let index = builder.build();
        let err = index
            .validate_event_schema_compatibility("fam-b.event.v1")
            .unwrap_err();
        assert!(matches!(
            err,
            EvidenceIndexerError::IncompatibleSchemaFamily { .. }
        ));
    }

    #[test]
    fn migrate_noop_when_already_at_target() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v2","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
            )
            .unwrap();
        let mut index = builder.build();
        let receipts = index.migrate_event_schemas("fam.event.v2", &[]).unwrap();
        assert!(receipts.is_empty());
    }

    #[test]
    fn migrate_multi_hop() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
            )
            .unwrap();
        let steps = vec![
            SchemaMigrationStep {
                migration_id: "mig-1-2".to_string(),
                from_schema: "fam.event.v1".to_string(),
                to_schema: "fam.event.v2".to_string(),
            },
            SchemaMigrationStep {
                migration_id: "mig-2-3".to_string(),
                from_schema: "fam.event.v2".to_string(),
                to_schema: "fam.event.v3".to_string(),
            },
        ];
        let mut index = builder.build();
        let receipts = index.migrate_event_schemas("fam.event.v3", &steps).unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].migration_id, "mig-1-2");
        assert_eq!(receipts[1].migration_id, "mig-2-3");
        assert!(
            index
                .events
                .iter()
                .all(|e| e.schema_version == "fam.event.v3")
        );
    }

    #[test]
    fn migrate_no_path_returns_error() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
            )
            .unwrap();
        let mut index = builder.build();
        let err = index
            .migrate_event_schemas("fam.event.v5", &[])
            .unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
    }

    #[test]
    fn schema_migration_boundary_detected_on_version_change() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                concat!(
                    r#"{"schema_version":"fam.event.v1","trace_id":"t1","decision_id":"d1","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
                    "\n",
                    r#"{"schema_version":"fam.event.v2","trace_id":"t2","decision_id":"d2","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
                ),
            )
            .unwrap();
        let index = builder.build();
        assert_eq!(index.schema_migrations.len(), 1);
        assert_eq!(index.schema_migrations[0].from_schema, "fam.event.v1");
        assert_eq!(index.schema_migrations[0].to_schema, "fam.event.v2");
    }

    #[test]
    fn duplicate_migration_sources_fail_closed() {
        let err = resolve_migration_path(
            "fam.event.v1",
            "fam.event.v2",
            &[
                SchemaMigrationStep {
                    migration_id: "mig-1-2".to_string(),
                    from_schema: "fam.event.v1".to_string(),
                    to_schema: "fam.event.v2".to_string(),
                },
                SchemaMigrationStep {
                    migration_id: "mig-1-9".to_string(),
                    from_schema: "fam.event.v1".to_string(),
                    to_schema: "fam.event.v9".to_string(),
                },
            ],
        )
        .unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
    }

    #[test]
    fn duplicate_migration_sources_off_path_do_not_block_valid_path() {
        let path = resolve_migration_path(
            "fam.event.v1",
            "fam.event.v2",
            &[
                SchemaMigrationStep {
                    migration_id: "mig-1-2".to_string(),
                    from_schema: "fam.event.v1".to_string(),
                    to_schema: "fam.event.v2".to_string(),
                },
                SchemaMigrationStep {
                    migration_id: "mig-8-9".to_string(),
                    from_schema: "fam.event.v8".to_string(),
                    to_schema: "fam.event.v9".to_string(),
                },
                SchemaMigrationStep {
                    migration_id: "mig-8-10".to_string(),
                    from_schema: "fam.event.v8".to_string(),
                    to_schema: "fam.event.v10".to_string(),
                },
            ],
        )
        .expect("off-path ambiguity should not block valid migration");

        assert_eq!(path.len(), 1);
        assert_eq!(path[0].migration_id, "mig-1-2");
    }

    #[test]
    fn cyclic_migration_path_fails_without_waiting_for_hop_cap() {
        let err = resolve_migration_path(
            "fam.event.v1",
            "fam.event.v3",
            &[
                SchemaMigrationStep {
                    migration_id: "mig-1-2".to_string(),
                    from_schema: "fam.event.v1".to_string(),
                    to_schema: "fam.event.v2".to_string(),
                },
                SchemaMigrationStep {
                    migration_id: "mig-2-1".to_string(),
                    from_schema: "fam.event.v2".to_string(),
                    to_schema: "fam.event.v1".to_string(),
                },
            ],
        )
        .unwrap_err();

        assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
    }

    #[test]
    fn cross_family_intermediate_step_fails_closed() {
        let err = resolve_migration_path(
            "fam.event.v1",
            "fam.event.v3",
            &[
                SchemaMigrationStep {
                    migration_id: "mig-1-other".to_string(),
                    from_schema: "fam.event.v1".to_string(),
                    to_schema: "other.event.v2".to_string(),
                },
                SchemaMigrationStep {
                    migration_id: "mig-other-3".to_string(),
                    from_schema: "other.event.v2".to_string(),
                    to_schema: "fam.event.v3".to_string(),
                },
            ],
        )
        .unwrap_err();

        assert!(matches!(
            err,
            EvidenceIndexerError::IncompatibleSchemaFamily { .. }
        ));
    }

    #[test]
    fn schema_migration_boundary_not_inferred_across_run_ids() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay-a"),
                "run-a-m.json",
                "run-a-e.jsonl",
                "run-a-c.txt",
            )
            .unwrap();
        builder
            .add_run(
                &manifest("run-b", "fam.run.v1", "replay-b"),
                "run-b-m.json",
                "run-b-e.jsonl",
                "run-b-c.txt",
            )
            .unwrap();

        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v1","trace_id":"ta","decision_id":"da","policy_id":"p","component":"c","event":"done","outcome":"pass"}"#,
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-b",
                r#"{"schema_version":"fam.event.v2","trace_id":"tb","decision_id":"db","policy_id":"p","component":"c","event":"done","outcome":"pass"}"#,
            )
            .unwrap();

        let index = builder.build();
        assert!(
            index.schema_migrations.is_empty(),
            "cross-run schema changes must not be treated as in-run migrations"
        );
    }

    #[test]
    fn schema_migration_boundary_detected_with_unsorted_input() {
        let events = vec![
            event("run-a", 0, "fam.event.v1"),
            event("run-b", 0, "fam.event.v1"),
            event("run-a", 1, "fam.event.v2"),
        ];

        let boundaries = compute_schema_migrations(&events);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].run_id, "run-a");
        assert_eq!(boundaries[0].sequence, 1);
        assert_eq!(boundaries[0].from_schema, "fam.event.v1");
        assert_eq!(boundaries[0].to_schema, "fam.event.v2");
    }

    #[test]
    fn error_display_all_variants() {
        let variants: Vec<EvidenceIndexerError> = vec![
            EvidenceIndexerError::MissingField("run_id"),
            EvidenceIndexerError::InvalidFieldType {
                field: "run_id",
                expected: "string",
            },
            EvidenceIndexerError::DuplicateRunId("run-a".to_string()),
            EvidenceIndexerError::UnknownRunId("run-x".to_string()),
            EvidenceIndexerError::InvalidSchemaVersion("bad".to_string()),
            EvidenceIndexerError::IncompatibleSchemaFamily {
                from_schema: "a.v1".to_string(),
                to_schema: "b.v1".to_string(),
            },
            EvidenceIndexerError::NoMigrationPath {
                from_schema: "a.v1".to_string(),
                to_schema: "a.v9".to_string(),
            },
            EvidenceIndexerError::Json("parse error".to_string()),
        ];
        for variant in &variants {
            let msg = format!("{variant}");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(EvidenceIndexerError::MissingField("f"));
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn parser_evidence_index_serde_round_trip() {
        let index = ParserEvidenceIndex {
            schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
            runs: vec![],
            events: vec![],
            schema_migrations: vec![],
        };
        let json = serde_json::to_string(&index).unwrap();
        let back: ParserEvidenceIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index, back);
    }

    #[test]
    fn correlated_regression_serde_round_trip() {
        let cr = CorrelatedRegression {
            key: CorrelationKey {
                component: "parser".to_string(),
                event: "drift".to_string(),
                scenario_id: Some("s1".to_string()),
                error_code: Some("E01".to_string()),
                outcome: "fail".to_string(),
            },
            run_count: 3,
            occurrence_count: 7,
            run_ids: vec!["r1".to_string(), "r2".to_string()],
            trace_ids: vec!["t1".to_string()],
            replay_commands: vec!["cmd".to_string()],
            severity: "high".to_string(),
        };
        let json = serde_json::to_string(&cr).unwrap();
        let back: CorrelatedRegression = serde_json::from_str(&json).unwrap();
        assert_eq!(cr, back);
    }

    #[test]
    fn applied_schema_migration_serde_round_trip() {
        let m = AppliedSchemaMigration {
            migration_id: "mig-1".to_string(),
            from_schema: "fam.v1".to_string(),
            to_schema: "fam.v2".to_string(),
            affected_records: 42,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: AppliedSchemaMigration = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn build_empty_index() {
        let builder = ParserEvidenceIndexBuilder::new();
        let index = builder.build();
        assert_eq!(index.schema_version, PARSER_EVIDENCE_INDEX_SCHEMA_V1);
        assert!(index.runs.is_empty());
        assert!(index.events.is_empty());
        assert!(index.schema_migrations.is_empty());
    }

    #[test]
    fn json_error_conversion() {
        let bad_json = "not json";
        let err: Result<Value, _> = serde_json::from_str(bad_json);
        let indexer_err: EvidenceIndexerError = err.unwrap_err().into();
        assert!(matches!(indexer_err, EvidenceIndexerError::Json(_)));
        assert!(format!("{indexer_err}").contains("json error"));
    }

    #[test]
    fn correlation_key_ordering_is_deterministic() {
        let a = CorrelationKey {
            component: "a".to_string(),
            event: "e".to_string(),
            scenario_id: None,
            error_code: None,
            outcome: "fail".to_string(),
        };
        let b = CorrelationKey {
            component: "b".to_string(),
            event: "e".to_string(),
            scenario_id: None,
            error_code: None,
            outcome: "fail".to_string(),
        };
        assert!(a < b);
        assert!(a == a.clone());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn correlation_key_serde_roundtrip() {
        let key = CorrelationKey {
            component: "parser".into(),
            event: "parse_error".into(),
            scenario_id: Some("sc-1".into()),
            error_code: Some("E001".into()),
            outcome: "fail".into(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let back: CorrelationKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn schema_migration_boundary_serde_roundtrip() {
        let boundary = SchemaMigrationBoundary {
            run_id: "run-1".into(),
            sequence: 42,
            from_schema: "parser_event.v1".into(),
            to_schema: "parser_event.v2".into(),
        };
        let json = serde_json::to_string(&boundary).unwrap();
        let back: SchemaMigrationBoundary = serde_json::from_str(&json).unwrap();
        assert_eq!(boundary, back);
    }

    #[test]
    fn schema_migration_step_serde_roundtrip() {
        let step = SchemaMigrationStep {
            migration_id: "mig-1".into(),
            from_schema: "parser_event.v1".into(),
            to_schema: "parser_event.v2".into(),
        };
        let json = serde_json::to_string(&step).unwrap();
        let back: SchemaMigrationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    #[test]
    fn indexed_parser_event_serde_roundtrip() {
        let event = IndexedParserEvent {
            run_id: "run-1".into(),
            sequence: 1,
            schema_version: "parser_event.v1".into(),
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "pol-1".into(),
            component: "parser".into(),
            event: "parse_complete".into(),
            outcome: "ok".into(),
            error_code: None,
            replay_command: Some("replay --run run-1".into()),
            scenario_id: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: IndexedParserEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn parser_run_artifact_ref_serde_roundtrip() {
        let artifact = ParserRunArtifactRef {
            run_id: "run-1".into(),
            manifest_schema_version: "v1".into(),
            manifest_path: "path/manifest.json".into(),
            events_path: "path/events.jsonl".into(),
            commands_path: "path/commands.sh".into(),
            replay_command: "replay --run run-1".into(),
            generated_at_utc: Some("2026-02-26T00:00:00Z".into()),
            outcome: Some("pass".into()),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: ParserRunArtifactRef = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn schema_version_tag_ordering_by_major() {
        let a = SchemaVersionTag {
            family: "parser_event".into(),
            major: 1,
        };
        let b = SchemaVersionTag {
            family: "parser_event".into(),
            major: 2,
        };
        assert!(a < b);
    }

    #[test]
    fn correlation_key_none_fields_serde_roundtrip() {
        let key = CorrelationKey {
            component: "c".into(),
            event: "e".into(),
            scenario_id: None,
            error_code: None,
            outcome: "ok".into(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let back: CorrelationKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    // -- Enrichment: PearlTower 2026-02-27 --

    #[test]
    fn clone_eq_parser_run_artifact_ref() {
        let a = ParserRunArtifactRef {
            run_id: "run-x".into(),
            manifest_schema_version: "fam.run.v1".into(),
            manifest_path: "/m.json".into(),
            events_path: "/e.jsonl".into(),
            commands_path: "/c.txt".into(),
            replay_command: "replay --run run-x".into(),
            generated_at_utc: Some("2026-02-27T00:00:00Z".into()),
            outcome: Some("pass".into()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_indexed_parser_event() {
        let a = IndexedParserEvent {
            run_id: "run-y".into(),
            sequence: 99,
            schema_version: "fam.event.v3".into(),
            trace_id: "tr-99".into(),
            decision_id: "dec-99".into(),
            policy_id: "pol-a".into(),
            component: "gate".into(),
            event: "evaluate".into(),
            outcome: "fail".into(),
            error_code: Some("E-42".into()),
            replay_command: Some("replay --trace tr-99".into()),
            scenario_id: Some("scen-7".into()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_schema_migration_boundary() {
        let a = SchemaMigrationBoundary {
            run_id: "run-z".into(),
            sequence: 5,
            from_schema: "fam.event.v1".into(),
            to_schema: "fam.event.v2".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_correlated_regression() {
        let a = CorrelatedRegression {
            key: CorrelationKey {
                component: "lexer".into(),
                event: "token_mismatch".into(),
                scenario_id: None,
                error_code: Some("LEX-01".into()),
                outcome: "fail".into(),
            },
            run_count: 4,
            occurrence_count: 12,
            run_ids: vec!["r1".into(), "r2".into(), "r3".into(), "r4".into()],
            trace_ids: vec!["t1".into(), "t2".into()],
            replay_commands: vec!["cmd1".into()],
            severity: "high".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_parser_evidence_index() {
        let a = ParserEvidenceIndex {
            schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.into(),
            runs: vec![],
            events: vec![],
            schema_migrations: vec![],
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn json_field_presence_indexed_parser_event() {
        let ev = IndexedParserEvent {
            run_id: "run-fp".into(),
            sequence: 7,
            schema_version: "fam.event.v1".into(),
            trace_id: "tr-fp".into(),
            decision_id: "dec-fp".into(),
            policy_id: "pol-fp".into(),
            component: "verifier".into(),
            event: "check".into(),
            outcome: "pass".into(),
            error_code: None,
            replay_command: None,
            scenario_id: Some("scen-fp".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"run_id\""));
        assert!(json.contains("\"sequence\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"scenario_id\""));
    }

    #[test]
    fn json_field_presence_correlated_regression() {
        let cr = CorrelatedRegression {
            key: CorrelationKey {
                component: "c".into(),
                event: "e".into(),
                scenario_id: None,
                error_code: None,
                outcome: "fail".into(),
            },
            run_count: 2,
            occurrence_count: 3,
            run_ids: vec!["r1".into()],
            trace_ids: vec!["t1".into()],
            replay_commands: vec![],
            severity: "medium".into(),
        };
        let json = serde_json::to_string(&cr).unwrap();
        assert!(json.contains("\"run_count\""));
        assert!(json.contains("\"occurrence_count\""));
        assert!(json.contains("\"severity\""));
        assert!(json.contains("\"key\""));
    }

    #[test]
    fn json_field_presence_applied_schema_migration() {
        let m = AppliedSchemaMigration {
            migration_id: "mig-fp".into(),
            from_schema: "fam.v1".into(),
            to_schema: "fam.v2".into(),
            affected_records: 100,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"migration_id\""));
        assert!(json.contains("\"from_schema\""));
        assert!(json.contains("\"to_schema\""));
        assert!(json.contains("\"affected_records\""));
    }

    #[test]
    fn error_source_is_none_for_all_variants() {
        let variants: Vec<EvidenceIndexerError> = vec![
            EvidenceIndexerError::MissingField("f"),
            EvidenceIndexerError::InvalidFieldType {
                field: "f",
                expected: "string",
            },
            EvidenceIndexerError::DuplicateRunId("r".into()),
            EvidenceIndexerError::UnknownRunId("r".into()),
            EvidenceIndexerError::InvalidSchemaVersion("bad".into()),
            EvidenceIndexerError::IncompatibleSchemaFamily {
                from_schema: "a.v1".into(),
                to_schema: "b.v1".into(),
            },
            EvidenceIndexerError::NoMigrationPath {
                from_schema: "a.v1".into(),
                to_schema: "a.v9".into(),
            },
            EvidenceIndexerError::Json("msg".into()),
        ];
        for v in &variants {
            assert!(v.source().is_none());
        }
    }

    #[test]
    fn display_uniqueness_across_error_variants() {
        let a = EvidenceIndexerError::MissingField("run_id");
        let b = EvidenceIndexerError::DuplicateRunId("run-a".into());
        let c = EvidenceIndexerError::InvalidSchemaVersion("bad".into());
        let d = EvidenceIndexerError::Json("parse fail".into());
        let msgs: Vec<String> = vec![a, b, c, d]
            .into_iter()
            .map(|e| format!("{e}"))
            .collect();
        for i in 0..msgs.len() {
            for j in (i + 1)..msgs.len() {
                assert_ne!(msgs[i], msgs[j], "variants {i} and {j} must differ");
            }
        }
    }

    #[test]
    fn correlation_key_ord_with_scenario_and_error_code() {
        let base = CorrelationKey {
            component: "c".into(),
            event: "e".into(),
            scenario_id: None,
            error_code: None,
            outcome: "fail".into(),
        };
        let with_scenario = CorrelationKey {
            scenario_id: Some("s1".into()),
            ..base.clone()
        };
        let with_error = CorrelationKey {
            error_code: Some("E01".into()),
            ..base.clone()
        };
        // None < Some in Ord for Option<String>
        assert!(base < with_scenario);
        assert!(base < with_error);
        // Verify reflexive
        assert!(base == base.clone());
        assert!(with_scenario == with_scenario.clone());
    }

    #[test]
    fn validate_schema_compatibility_empty_events_passes() {
        let index = ParserEvidenceIndex {
            schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.into(),
            runs: vec![],
            events: vec![],
            schema_migrations: vec![],
        };
        // No events means nothing to reject.
        index
            .validate_event_schema_compatibility("fam.event.v99")
            .unwrap();
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_schema_version_parse_multiple_dot_v_picks_last() {
        // rsplit_once(".v") picks the last ".v" so family includes earlier segments.
        let tag = SchemaVersionTag::parse("a.v1.v2").unwrap();
        assert_eq!(tag.family, "a.v1");
        assert_eq!(tag.major, 2);
    }

    #[test]
    fn enrichment_schema_version_parse_large_major() {
        let tag = SchemaVersionTag::parse("franken-engine.v999999").unwrap();
        assert_eq!(tag.family, "franken-engine");
        assert_eq!(tag.major, 999_999);
    }

    #[test]
    fn enrichment_schema_version_tag_clone_eq() {
        let a = SchemaVersionTag {
            family: "fam".into(),
            major: 7,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_schema_migration_step_clone_eq() {
        let a = SchemaMigrationStep {
            migration_id: "mig-x".into(),
            from_schema: "fam.v1".into(),
            to_schema: "fam.v2".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_applied_schema_migration_clone_eq() {
        let a = AppliedSchemaMigration {
            migration_id: "mig-a".into(),
            from_schema: "fam.v1".into(),
            to_schema: "fam.v3".into(),
            affected_records: 100,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_parser_evidence_index_full_serde_roundtrip() {
        let index = ParserEvidenceIndex {
            schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.into(),
            runs: vec![ParserRunArtifactRef {
                run_id: "run-rt".into(),
                manifest_schema_version: "fam.run.v1".into(),
                manifest_path: "/m.json".into(),
                events_path: "/e.jsonl".into(),
                commands_path: "/c.txt".into(),
                replay_command: "replay --run run-rt".into(),
                generated_at_utc: Some("2026-03-02T00:00:00Z".into()),
                outcome: Some("pass".into()),
            }],
            events: vec![IndexedParserEvent {
                run_id: "run-rt".into(),
                sequence: 0,
                schema_version: "fam.event.v1".into(),
                trace_id: "t-1".into(),
                decision_id: "d-1".into(),
                policy_id: "pol-1".into(),
                component: "gate".into(),
                event: "check".into(),
                outcome: "pass".into(),
                error_code: None,
                replay_command: None,
                scenario_id: Some("scen-1".into()),
            }],
            schema_migrations: vec![SchemaMigrationBoundary {
                run_id: "run-rt".into(),
                sequence: 1,
                from_schema: "fam.event.v1".into(),
                to_schema: "fam.event.v2".into(),
            }],
        };
        let json = serde_json::to_string_pretty(&index).unwrap();
        let back: ParserEvidenceIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index, back);
    }

    #[test]
    fn enrichment_json_field_presence_parser_run_artifact_ref() {
        let r = ParserRunArtifactRef {
            run_id: "run-fp".into(),
            manifest_schema_version: "fam.run.v1".into(),
            manifest_path: "/m.json".into(),
            events_path: "/e.jsonl".into(),
            commands_path: "/c.txt".into(),
            replay_command: "replay".into(),
            generated_at_utc: Some("2026-03-02T12:00:00Z".into()),
            outcome: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"run_id\""));
        assert!(json.contains("\"manifest_schema_version\""));
        assert!(json.contains("\"manifest_path\""));
        assert!(json.contains("\"events_path\""));
        assert!(json.contains("\"commands_path\""));
        assert!(json.contains("\"replay_command\""));
        assert!(json.contains("\"generated_at_utc\""));
        assert!(json.contains("\"outcome\""));
    }

    #[test]
    fn enrichment_json_field_presence_schema_migration_boundary() {
        let b = SchemaMigrationBoundary {
            run_id: "run-x".into(),
            sequence: 3,
            from_schema: "fam.event.v1".into(),
            to_schema: "fam.event.v2".into(),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("\"run_id\""));
        assert!(json.contains("\"sequence\""));
        assert!(json.contains("\"from_schema\""));
        assert!(json.contains("\"to_schema\""));
    }

    #[test]
    fn enrichment_json_field_presence_schema_migration_step() {
        let s = SchemaMigrationStep {
            migration_id: "mig-fp".into(),
            from_schema: "fam.event.v1".into(),
            to_schema: "fam.event.v2".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"migration_id\""));
        assert!(json.contains("\"from_schema\""));
        assert!(json.contains("\"to_schema\""));
    }

    #[test]
    fn enrichment_error_debug_format() {
        let err = EvidenceIndexerError::DuplicateRunId("run-dbg".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("DuplicateRunId"));
        assert!(dbg.contains("run-dbg"));
    }

    #[test]
    fn enrichment_resolve_migration_path_same_from_to() {
        let result = resolve_migration_path("fam.event.v3", "fam.event.v3", &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn enrichment_correlation_sorted_by_occurrence_count_desc() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        for run_id in ["run-a", "run-b"] {
            builder
                .add_run(
                    &manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")),
                    format!("{run_id}-m.json"),
                    format!("{run_id}-e.jsonl"),
                    format!("{run_id}-c.txt"),
                )
                .unwrap();
        }

        // gate/check fails in both runs once each -> occurrence_count=2
        // gate/drift fails in both runs but run-a has 2 occurrences -> occurrence_count=3
        for run_id in ["run-a", "run-b"] {
            let ev_check = format!(
                "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"tc-{run_id}\",\"decision_id\":\"dc-{run_id}\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"check\",\"outcome\":\"fail\"}}"
            );
            builder.add_events_jsonl(run_id, &ev_check).unwrap();
        }
        for run_id in ["run-a", "run-b"] {
            let ev_drift = format!(
                "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"td-{run_id}\",\"decision_id\":\"dd-{run_id}\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"drift\",\"outcome\":\"fail\"}}"
            );
            builder.add_events_jsonl(run_id, &ev_drift).unwrap();
        }
        // Extra drift for run-a
        builder.add_events_jsonl(
            "run-a",
            r#"{"schema_version":"fam.event.v1","trace_id":"td-a-extra","decision_id":"dd-a-extra","policy_id":"p","component":"gate","event":"drift","outcome":"fail"}"#,
        ).unwrap();

        let index = builder.build();
        let clusters = index.correlate_regressions();
        assert_eq!(clusters.len(), 2);
        // drift has 3 occurrences, check has 2 -- drift should come first
        assert_eq!(clusters[0].key.event, "drift");
        assert_eq!(clusters[0].occurrence_count, 3);
        assert_eq!(clusters[1].key.event, "check");
        assert_eq!(clusters[1].occurrence_count, 2);
    }

    #[test]
    fn enrichment_correlate_regressions_collects_replay_commands() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        for run_id in ["run-a", "run-b"] {
            builder
                .add_run(
                    &manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")),
                    format!("{run_id}-m.json"),
                    format!("{run_id}-e.jsonl"),
                    format!("{run_id}-c.txt"),
                )
                .unwrap();
            let ev = format!(
                "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t-{run_id}\",\"decision_id\":\"d-{run_id}\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"fail_check\",\"outcome\":\"fail\",\"replay_command\":\"replay-cmd-{run_id}\"}}"
            );
            builder.add_events_jsonl(run_id, &ev).unwrap();
        }
        let index = builder.build();
        let clusters = index.correlate_regressions();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].replay_commands.len(), 2);
        assert!(
            clusters[0]
                .replay_commands
                .contains(&"replay-cmd-run-a".to_string())
        );
        assert!(
            clusters[0]
                .replay_commands
                .contains(&"replay-cmd-run-b".to_string())
        );
    }

    #[test]
    fn enrichment_correlate_includes_error_code_with_non_fail_outcome() {
        // Events with error_code set but outcome != "fail" should still be correlated.
        let mut builder = ParserEvidenceIndexBuilder::new();
        for run_id in ["run-a", "run-b"] {
            builder
                .add_run(
                    &manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")),
                    format!("{run_id}-m.json"),
                    format!("{run_id}-e.jsonl"),
                    format!("{run_id}-c.txt"),
                )
                .unwrap();
            let ev = format!(
                "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t-{run_id}\",\"decision_id\":\"d-{run_id}\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"warn_check\",\"outcome\":\"warn\",\"error_code\":\"E-WARN\"}}"
            );
            builder.add_events_jsonl(run_id, &ev).unwrap();
        }
        let index = builder.build();
        let clusters = index.correlate_regressions();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].key.outcome, "warn");
        assert_eq!(clusters[0].key.error_code.as_deref(), Some("E-WARN"));
        assert_eq!(clusters[0].severity, "high");
    }

    #[test]
    fn enrichment_optional_string_rejects_non_string_non_null() {
        let val = serde_json::json!({ "field": 123 });
        let err = optional_string(&val, "field").unwrap_err();
        assert!(matches!(
            err,
            EvidenceIndexerError::InvalidFieldType {
                field: "field",
                expected: "string|null",
            }
        ));
    }

    #[test]
    fn enrichment_manifest_with_invalid_schema_version_rejected() {
        let val = serde_json::json!({
            "schema_version": "bad-no-version-tag",
            "run_id": "run-1",
            "replay_command": "replay"
        });
        let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
        assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
    }

    #[test]
    fn enrichment_multiple_boundaries_within_single_run() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay"),
                "m.json",
                "e.jsonl",
                "c.txt",
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-a",
                concat!(
                    r#"{"schema_version":"fam.event.v1","trace_id":"t1","decision_id":"d1","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
                    "\n",
                    r#"{"schema_version":"fam.event.v2","trace_id":"t2","decision_id":"d2","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
                    "\n",
                    r#"{"schema_version":"fam.event.v3","trace_id":"t3","decision_id":"d3","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
                ),
            )
            .unwrap();
        let index = builder.build();
        assert_eq!(index.schema_migrations.len(), 2);
        assert_eq!(index.schema_migrations[0].from_schema, "fam.event.v1");
        assert_eq!(index.schema_migrations[0].to_schema, "fam.event.v2");
        assert_eq!(index.schema_migrations[1].from_schema, "fam.event.v2");
        assert_eq!(index.schema_migrations[1].to_schema, "fam.event.v3");
    }

    #[test]
    fn enrichment_migrate_mixed_schemas_across_runs() {
        let mut builder = ParserEvidenceIndexBuilder::new();
        builder
            .add_run(
                &manifest("run-a", "fam.run.v1", "replay-a"),
                "a-m.json",
                "a-e.jsonl",
                "a-c.txt",
            )
            .unwrap();
        builder
            .add_run(
                &manifest("run-b", "fam.run.v1", "replay-b"),
                "b-m.json",
                "b-e.jsonl",
                "b-c.txt",
            )
            .unwrap();

        // run-a has v1 events, run-b has v2 events
        builder
            .add_events_jsonl(
                "run-a",
                r#"{"schema_version":"fam.event.v1","trace_id":"ta","decision_id":"da","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
            )
            .unwrap();
        builder
            .add_events_jsonl(
                "run-b",
                r#"{"schema_version":"fam.event.v2","trace_id":"tb","decision_id":"db","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
            )
            .unwrap();

        let steps = vec![
            SchemaMigrationStep {
                migration_id: "mig-1-2".into(),
                from_schema: "fam.event.v1".into(),
                to_schema: "fam.event.v2".into(),
            },
            SchemaMigrationStep {
                migration_id: "mig-2-3".into(),
                from_schema: "fam.event.v2".into(),
                to_schema: "fam.event.v3".into(),
            },
        ];
        let mut index = builder.build();
        let receipts = index.migrate_event_schemas("fam.event.v3", &steps).unwrap();

        // Both migration steps should be applied
        assert_eq!(receipts.len(), 2);
        // All events should now be v3
        assert!(
            index
                .events
                .iter()
                .all(|e| e.schema_version == "fam.event.v3")
        );
        // mig-1-2 affects run-a's 1 event; mig-2-3 affects both events (run-a after first hop + run-b)
        let mig_1_2 = receipts
            .iter()
            .find(|r| r.migration_id == "mig-1-2")
            .unwrap();
        assert_eq!(mig_1_2.affected_records, 1);
        let mig_2_3 = receipts
            .iter()
            .find(|r| r.migration_id == "mig-2-3")
            .unwrap();
        assert_eq!(mig_2_3.affected_records, 2);
    }
}
