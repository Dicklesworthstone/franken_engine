use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::relation::{
    ChoiceStream, GeneratedPair, MetamorphicRelation, OracleKind, PropertyContract,
    RelationRunOutcome, Subsystem,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub seed: u64,
    pub environment_fingerprint: String,
}

impl RunContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        component: impl Into<String>,
        relation_catalog_hash: impl Into<String>,
        seed: u64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            component: component.into(),
            relation_catalog_hash: relation_catalog_hash.into(),
            seed,
            environment_fingerprint: environment_fingerprint(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimizerConfig {
    pub max_iterations: usize,
    pub max_duration: Duration,
    pub target_ast_nodes: usize,
}

impl Default for MinimizerConfig {
    fn default() -> Self {
        Self {
            max_iterations: 256,
            max_duration: Duration::from_secs(60),
            target_ast_nodes: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkAttemptVerdict {
    pub stage: String,
    pub target: String,
    pub choice_label: Option<String>,
    pub candidate_value: Option<u64>,
    pub accepted: bool,
    pub reason: String,
    pub before_size_metric: usize,
    pub after_size_metric: usize,
    pub before_ast_metric: usize,
    pub after_ast_metric: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FailureMinimization {
    replayable_choice_stream: Option<ChoiceStream>,
    final_pair: GeneratedPair,
    verdicts: Vec<ShrinkAttemptVerdict>,
    choice_stream_reduced: bool,
    ddmin_reduced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureArtifact {
    pub relation_id: String,
    pub seed: u64,
    pub input_source: String,
    pub variant_source: String,
    pub expected_equivalence: String,
    pub actual_divergence: String,
    pub minimized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    pub relation_id: String,
    pub pair_index: u32,
    pub seed: u64,
    pub generator_id: String,
    pub divergence_detail: String,
    pub minimized: bool,
    pub minimized_pair: GeneratedPair,
    pub original_size_metric: usize,
    pub minimized_size_metric: usize,
    pub original_ast_metric: usize,
    pub minimized_ast_metric: usize,
    pub original_choice_count: usize,
    pub minimized_choice_count: usize,
    pub shrink_strategy: String,
    pub choice_stream_reduced: bool,
    pub ddmin_reduced: bool,
    pub replayable_choice_stream: Option<ChoiceStream>,
    pub shrink_verdicts: Vec<ShrinkAttemptVerdict>,
    pub failure_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyGeneratorCatalogEntry {
    pub relation_id: String,
    pub subsystem: String,
    pub oracle: String,
    pub generator_id: String,
    pub scheduled_pairs_budget: u32,
    pub sample_seed: u64,
    pub sample_choice_count: usize,
    pub replay_supported: bool,
    pub shrink_strategy: String,
    pub consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyGeneratorCatalogReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub generator_count: usize,
    pub generators: Vec<PropertyGeneratorCatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceFieldSchema {
    pub index: u32,
    pub label: String,
    pub strategy: String,
    pub min_value: u64,
    pub max_value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationChoiceStreamSchemaEntry {
    pub relation_id: String,
    pub generator_id: String,
    pub replay_supported: bool,
    pub fields: Vec<ChoiceFieldSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorChoiceStreamSchemaReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub stream_schema_version: String,
    pub top_level_fields: Vec<String>,
    pub relation_schemas: Vec<RelationChoiceStreamSchemaEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkerVerdictEntry {
    pub relation_id: String,
    pub pair_index: u32,
    pub seed: u64,
    pub generator_id: String,
    pub original_size_metric: usize,
    pub minimized_size_metric: usize,
    pub original_ast_metric: usize,
    pub minimized_ast_metric: usize,
    pub original_choice_count: usize,
    pub minimized_choice_count: usize,
    pub choice_stream_reduced: bool,
    pub ddmin_reduced: bool,
    pub accepted_steps: usize,
    pub rejected_steps: usize,
    pub failure_file: Option<String>,
    pub verdicts: Vec<ShrinkAttemptVerdict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkerVerdictReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub total_failures: usize,
    pub total_attempts: usize,
    pub total_accepted: usize,
    pub total_rejected: usize,
    pub entries: Vec<ShrinkerVerdictEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizedPropertyCounterexample {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_id: String,
    pub pair_index: u32,
    pub seed: u64,
    pub generator_id: String,
    pub divergence_detail: String,
    pub original_pair: GeneratedPair,
    pub minimized_pair: GeneratedPair,
    pub original_choice_stream: ChoiceStream,
    pub replayable_choice_stream: Option<ChoiceStream>,
    pub property_contract: PropertyContract,
    pub original_size_metric: usize,
    pub minimized_size_metric: usize,
    pub original_ast_metric: usize,
    pub minimized_ast_metric: usize,
    pub choice_stream_reduced: bool,
    pub ddmin_reduced: bool,
    pub failure_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationExecution {
    pub relation_id: String,
    pub subsystem: Subsystem,
    pub oracle: OracleKind,
    pub pairs_tested: u32,
    pub violations_found: u32,
    pub min_failure_size: Option<usize>,
    pub duration_us: u64,
    pub outcomes: Vec<RelationRunOutcome>,
    pub failure_records: Vec<FailureRecord>,
    pub failure_files: Vec<String>,
    pub log_event: RelationLogEvent,
}

impl RelationExecution {
    pub fn outcome(&self) -> &'static str {
        if self.violations_found == 0 {
            "pass"
        } else {
            "fail"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedScheduleEntry {
    pub relation_id: String,
    pub subsystem: String,
    pub oracle: String,
    pub pairs_tested: u32,
    pub start_seed: u64,
    pub end_seed: u64,
    pub schedule_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedManifest {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub corpus_version: String,
    pub base_seed: u64,
    pub relation_count: usize,
    pub relation_seed_schedule: Vec<SeedScheduleEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClass {
    Correctness,
    Security,
    Determinism,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
}

impl FindingSeverity {
    pub fn as_priority(self) -> &'static str {
        match self {
            Self::Critical => "p0",
            Self::High => "p1",
            Self::Medium => "p2",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Critical => 3,
            Self::High => 2,
            Self::Medium => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityPolicyRule {
    pub rule_id: String,
    pub description: String,
    pub finding_class: FindingClass,
    pub severity: FindingSeverity,
    pub priority: String,
    pub owner_track: String,
    pub owner_hint: String,
    pub escalation_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerAssignment {
    pub owner_track: String,
    pub owner_hint: String,
    pub escalation_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignFinding {
    pub counterexample_id: String,
    pub relation_id: String,
    pub subsystem: String,
    pub oracle: String,
    pub pair_index: u32,
    pub run_seed: u64,
    pub finding_class: FindingClass,
    pub severity: FindingSeverity,
    pub priority: String,
    pub owner_assignment: OwnerAssignment,
    pub divergence_detail: String,
    pub minimized_reproduction_id: Option<String>,
    pub deterministic_evidence_link: String,
    pub replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignTriageSummary {
    pub total_findings: u32,
    pub blocking_findings: u32,
    pub highest_severity: Option<FindingSeverity>,
    pub correctness_findings: u32,
    pub security_findings: u32,
    pub determinism_findings: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignTriageReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub seed: u64,
    pub replay_command: String,
    pub priority_policy: Vec<PriorityPolicyRule>,
    pub summary: CampaignTriageSummary,
    pub findings: Vec<CampaignFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproGovernanceAction {
    pub schema_version: String,
    pub action: String,
    pub bead_id: String,
    pub fingerprint: String,
    pub counterexample_id: String,
    pub relation_id: String,
    pub finding_class: FindingClass,
    pub severity: FindingSeverity,
    pub priority: String,
    pub owner_track: String,
    pub owner_hint: String,
    pub deterministic_evidence_link: String,
    pub replay_command: String,
    pub minimized_reproduction_id: Option<String>,
    pub divergence_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproGovernanceActionsReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub generated_from: String,
    pub action_count: usize,
    pub actions: Vec<ReproGovernanceAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: String,
    pub pairs_tested: u32,
    pub violations_found: u32,
    pub min_failure_size: Option<usize>,
    pub duration_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteExecution {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub environment_fingerprint: String,
    pub seed: u64,
    pub total_pairs: u32,
    pub total_violations: u32,
    pub relation_executions: Vec<RelationExecution>,
}

impl SuiteExecution {
    pub fn outcome(&self) -> &'static str {
        if self.total_violations == 0 {
            "pass"
        } else {
            "fail"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationEvidenceEntry {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: String,
    pub oracle: String,
    pub pairs_tested: u32,
    pub violations_found: u32,
    pub min_failure_size: Option<usize>,
    pub duration_us: u64,
    pub relation_catalog_hash: String,
    pub seed: u64,
    pub total_violations: Option<u32>,
    pub environment_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedTranscriptEntry {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: String,
    pub pair_index: u32,
    pub run_seed: u64,
}

impl RelationEvidenceEntry {
    pub fn from_execution(execution: &RelationExecution, context: &RunContext) -> Self {
        Self {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: context.component.clone(),
            event: "relation_completed".to_string(),
            outcome: execution.outcome().to_string(),
            error_code: if execution.violations_found == 0 {
                None
            } else {
                Some("FE-META-0001".to_string())
            },
            relation_id: execution.relation_id.clone(),
            subsystem: execution.subsystem.as_str().to_string(),
            oracle: execution.oracle.as_str().to_string(),
            pairs_tested: execution.pairs_tested,
            violations_found: execution.violations_found,
            min_failure_size: execution.min_failure_size,
            duration_us: execution.duration_us,
            relation_catalog_hash: context.relation_catalog_hash.clone(),
            seed: context.seed,
            total_violations: None,
            environment_fingerprint: context.environment_fingerprint.clone(),
        }
    }

    pub fn summary_from_suite(suite: &SuiteExecution) -> Self {
        Self {
            trace_id: suite.trace_id.clone(),
            decision_id: suite.decision_id.clone(),
            policy_id: suite.policy_id.clone(),
            component: suite.component.clone(),
            event: "suite_summary".to_string(),
            outcome: suite.outcome().to_string(),
            error_code: if suite.total_violations == 0 {
                None
            } else {
                Some("FE-META-0001".to_string())
            },
            relation_id: "__summary__".to_string(),
            subsystem: "all".to_string(),
            oracle: "all".to_string(),
            pairs_tested: suite.total_pairs,
            violations_found: suite.total_violations,
            min_failure_size: suite
                .relation_executions
                .iter()
                .filter_map(|entry| entry.min_failure_size)
                .min(),
            duration_us: suite
                .relation_executions
                .iter()
                .map(|entry| entry.duration_us)
                .sum(),
            relation_catalog_hash: suite.relation_catalog_hash.clone(),
            seed: suite.seed,
            total_violations: Some(suite.total_violations),
            environment_fingerprint: suite.environment_fingerprint.clone(),
        }
    }
}

pub fn run_relation_with_budget(
    relation: &dyn MetamorphicRelation,
    context: &RunContext,
    pairs: u32,
    failure_output_dir: Option<&Path>,
    minimizer: MinimizerConfig,
) -> std::io::Result<RelationExecution> {
    let start = Instant::now();
    let mut outcomes = Vec::with_capacity(pairs as usize);
    let mut violations_found = 0u32;
    let mut min_failure_size = None::<usize>;
    let mut failure_records = Vec::<FailureRecord>::new();
    let mut failure_files = Vec::<String>::new();

    if let Some(path) = failure_output_dir {
        fs::create_dir_all(path)?;
    }

    for offset in 0..pairs {
        let run_seed = context.seed.wrapping_add(u64::from(offset));
        let outcome = relation.run_once(
            &context.trace_id,
            &context.decision_id,
            &context.policy_id,
            &context.component,
            run_seed,
        );

        if !outcome.equivalence.is_equivalent() {
            violations_found = violations_found.saturating_add(1);
            let minimization = minimize_failure_outcome(relation, &outcome, minimizer);
            let minimized_pair = minimization.final_pair;
            let minimized = minimized_pair.size_metric() < outcome.pair.size_metric();
            let pair_size = minimized_pair.ast_node_metric();
            let divergence_detail = outcome
                .equivalence
                .detail()
                .unwrap_or("unknown divergence")
                .to_string();
            min_failure_size = Some(match min_failure_size {
                Some(existing) => existing.min(pair_size),
                None => pair_size,
            });

            let mut failure_file = None::<String>;
            if let Some(path) = failure_output_dir {
                let artifact = FailureArtifact {
                    relation_id: relation.spec().id.clone(),
                    seed: run_seed,
                    input_source: minimized_pair.input_source.clone(),
                    variant_source: minimized_pair.variant_source.clone(),
                    expected_equivalence: "equivalent".to_string(),
                    actual_divergence: divergence_detail.clone(),
                    minimized,
                };

                let file = write_failure_artifact(path, &artifact)?;
                let display = file.display().to_string();
                failure_file = Some(display.clone());
                failure_files.push(display);
            }

            failure_records.push(FailureRecord {
                relation_id: relation.spec().id.clone(),
                pair_index: offset,
                seed: run_seed,
                generator_id: outcome.generator_id.clone(),
                divergence_detail,
                minimized,
                minimized_pair: minimized_pair.clone(),
                original_size_metric: outcome.pair.size_metric(),
                minimized_size_metric: minimized_pair.size_metric(),
                original_ast_metric: outcome.pair.ast_node_metric(),
                minimized_ast_metric: minimized_pair.ast_node_metric(),
                original_choice_count: outcome.choice_stream.choice_count(),
                minimized_choice_count: minimization.replayable_choice_stream.as_ref().map_or(
                    outcome.choice_stream.choice_count(),
                    ChoiceStream::choice_count,
                ),
                shrink_strategy: outcome.property_contract.shrink_strategy.clone(),
                choice_stream_reduced: minimization.choice_stream_reduced,
                ddmin_reduced: minimization.ddmin_reduced,
                replayable_choice_stream: minimization.replayable_choice_stream,
                shrink_verdicts: minimization.verdicts,
                failure_file,
            });
        }

        outcomes.push(outcome);
    }

    let duration_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let log_event = RelationLogEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: context.component.clone(),
        event: "relation_completed".to_string(),
        outcome: if violations_found == 0 {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if violations_found == 0 {
            None
        } else {
            Some("FE-META-0001".to_string())
        },
        relation_id: relation.spec().id.clone(),
        subsystem: relation.spec().subsystem.as_str().to_string(),
        pairs_tested: pairs,
        violations_found,
        min_failure_size,
        duration_us,
    };

    Ok(RelationExecution {
        relation_id: relation.spec().id.clone(),
        subsystem: relation.spec().subsystem,
        oracle: relation.spec().oracle,
        pairs_tested: pairs,
        violations_found,
        min_failure_size,
        duration_us,
        outcomes,
        failure_records,
        failure_files,
        log_event,
    })
}

pub fn run_suite(
    relations: &[&dyn MetamorphicRelation],
    context: &RunContext,
    pairs_override: Option<u32>,
    failure_output_dir: Option<&Path>,
    minimizer: MinimizerConfig,
) -> std::io::Result<SuiteExecution> {
    let mut relation_executions = Vec::with_capacity(relations.len());
    let mut total_pairs = 0u32;
    let mut total_violations = 0u32;

    for relation in relations {
        let budget = pairs_override.unwrap_or(relation.spec().budget_pairs);
        let relation_execution =
            run_relation_with_budget(*relation, context, budget, failure_output_dir, minimizer)?;

        total_pairs = total_pairs.saturating_add(relation_execution.pairs_tested);
        total_violations = total_violations.saturating_add(relation_execution.violations_found);
        relation_executions.push(relation_execution);
    }

    Ok(SuiteExecution {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: context.component.clone(),
        relation_catalog_hash: context.relation_catalog_hash.clone(),
        environment_fingerprint: context.environment_fingerprint.clone(),
        seed: context.seed,
        total_pairs,
        total_violations,
        relation_executions,
    })
}

pub fn write_evidence_jsonl(path: &Path, entries: &[RelationEvidenceEntry]) -> std::io::Result<()> {
    let mut lines = String::new();
    for entry in entries {
        let json =
            serde_json::to_string(entry).expect("evidence entry serialization should succeed");
        lines.push_str(&json);
        lines.push('\n');
    }
    fs::write(path, lines)
}

pub fn evidence_entries_for_suite(suite: &SuiteExecution) -> Vec<RelationEvidenceEntry> {
    let base_context = RunContext {
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        relation_catalog_hash: suite.relation_catalog_hash.clone(),
        seed: suite.seed,
        environment_fingerprint: suite.environment_fingerprint.clone(),
    };

    let mut entries = suite
        .relation_executions
        .iter()
        .map(|execution| RelationEvidenceEntry::from_execution(execution, &base_context))
        .collect::<Vec<_>>();
    entries.push(RelationEvidenceEntry::summary_from_suite(suite));
    entries
}

pub fn relation_log_events_for_suite(suite: &SuiteExecution) -> Vec<RelationLogEvent> {
    let mut events = suite
        .relation_executions
        .iter()
        .map(|execution| execution.log_event.clone())
        .collect::<Vec<_>>();

    events.push(RelationLogEvent {
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        event: "suite_completed".to_string(),
        outcome: suite.outcome().to_string(),
        error_code: if suite.total_violations == 0 {
            None
        } else {
            Some("FE-META-0001".to_string())
        },
        relation_id: "__summary__".to_string(),
        subsystem: "all".to_string(),
        pairs_tested: suite.total_pairs,
        violations_found: suite.total_violations,
        min_failure_size: suite
            .relation_executions
            .iter()
            .filter_map(|entry| entry.min_failure_size)
            .min(),
        duration_us: suite
            .relation_executions
            .iter()
            .map(|entry| entry.duration_us)
            .sum(),
    });

    events
}

pub fn seed_transcript_entries_for_suite(suite: &SuiteExecution) -> Vec<SeedTranscriptEntry> {
    suite
        .relation_executions
        .iter()
        .flat_map(|execution| {
            execution
                .outcomes
                .iter()
                .enumerate()
                .map(|(pair_index, outcome)| SeedTranscriptEntry {
                    trace_id: outcome.trace_id.clone(),
                    decision_id: outcome.decision_id.clone(),
                    policy_id: outcome.policy_id.clone(),
                    component: outcome.component.clone(),
                    event: "pair_seed_evaluated".to_string(),
                    outcome: outcome.outcome.clone(),
                    error_code: outcome.error_code.clone(),
                    relation_id: execution.relation_id.clone(),
                    subsystem: execution.subsystem.as_str().to_string(),
                    pair_index: pair_index as u32,
                    run_seed: outcome.seed,
                })
        })
        .collect()
}

pub fn write_seed_transcript_jsonl(
    path: &Path,
    entries: &[SeedTranscriptEntry],
) -> std::io::Result<()> {
    let mut lines = String::new();
    for entry in entries {
        let json = serde_json::to_string(entry).expect("seed transcript serialization should pass");
        lines.push_str(&json);
        lines.push('\n');
    }

    fs::write(path, lines)
}

pub fn seed_manifest_for_suite(suite: &SuiteExecution) -> SeedManifest {
    let relation_seed_schedule = suite
        .relation_executions
        .iter()
        .map(|execution| {
            let end_seed = if execution.pairs_tested == 0 {
                suite.seed
            } else {
                suite
                    .seed
                    .wrapping_add(u64::from(execution.pairs_tested.saturating_sub(1)))
            };
            SeedScheduleEntry {
                relation_id: execution.relation_id.clone(),
                subsystem: execution.subsystem.as_str().to_string(),
                oracle: execution.oracle.as_str().to_string(),
                pairs_tested: execution.pairs_tested,
                start_seed: suite.seed,
                end_seed,
                schedule_policy: "run_seed = base_seed.wrapping_add(pair_index)".to_string(),
            }
        })
        .collect::<Vec<_>>();

    SeedManifest {
        schema_version: "franken-engine.metamorphic.seed-manifest.v1".to_string(),
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        relation_catalog_hash: suite.relation_catalog_hash.clone(),
        corpus_version: suite.relation_catalog_hash.clone(),
        base_seed: suite.seed,
        relation_count: suite.relation_executions.len(),
        relation_seed_schedule,
    }
}

pub fn write_seed_manifest_json(path: &Path, manifest: &SeedManifest) -> std::io::Result<()> {
    let payload =
        serde_json::to_vec_pretty(manifest).expect("seed manifest serialization should succeed");
    fs::write(path, payload)
}

pub fn property_generator_catalog_for_suite(
    suite: &SuiteExecution,
) -> PropertyGeneratorCatalogReport {
    let generators = suite
        .relation_executions
        .iter()
        .filter_map(|execution| {
            let sample = execution.outcomes.first()?;
            Some(PropertyGeneratorCatalogEntry {
                relation_id: execution.relation_id.clone(),
                subsystem: execution.subsystem.as_str().to_string(),
                oracle: execution.oracle.as_str().to_string(),
                generator_id: sample.generator_id.clone(),
                scheduled_pairs_budget: execution.pairs_tested,
                sample_seed: sample.seed,
                sample_choice_count: sample.choice_stream.choice_count(),
                replay_supported: sample.property_contract.replay_supported,
                shrink_strategy: sample.property_contract.shrink_strategy.clone(),
                consumers: vec![
                    "metamorphic".to_string(),
                    "fuzz".to_string(),
                    "differential".to_string(),
                ],
            })
        })
        .collect::<Vec<_>>();

    PropertyGeneratorCatalogReport {
        schema_version: "franken-engine.metamorphic.property-generator-catalog.v1".to_string(),
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        relation_catalog_hash: suite.relation_catalog_hash.clone(),
        generator_count: generators.len(),
        generators,
    }
}

pub fn write_property_generator_catalog_json(
    path: &Path,
    catalog: &PropertyGeneratorCatalogReport,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec_pretty(catalog)
        .expect("property generator catalog serialization should succeed");
    fs::write(path, payload)
}

pub fn generator_choice_stream_schema_for_suite(
    suite: &SuiteExecution,
) -> GeneratorChoiceStreamSchemaReport {
    let relation_schemas = suite
        .relation_executions
        .iter()
        .filter_map(|execution| {
            let sample = execution.outcomes.first()?;
            Some(RelationChoiceStreamSchemaEntry {
                relation_id: execution.relation_id.clone(),
                generator_id: sample.generator_id.clone(),
                replay_supported: sample.property_contract.replay_supported,
                fields: sample
                    .choice_stream
                    .choices
                    .iter()
                    .map(|choice| ChoiceFieldSchema {
                        index: choice.index,
                        label: choice.label.clone(),
                        strategy: choice.strategy.clone(),
                        min_value: choice.min_value,
                        max_value: choice.max_value,
                    })
                    .collect(),
            })
        })
        .collect::<Vec<_>>();

    GeneratorChoiceStreamSchemaReport {
        schema_version: "franken-engine.metamorphic.generator-choice-stream-schema.v1".to_string(),
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        relation_catalog_hash: suite.relation_catalog_hash.clone(),
        stream_schema_version: "franken-engine.metamorphic.choice-stream.v1".to_string(),
        top_level_fields: vec![
            "schema_version".to_string(),
            "relation_id".to_string(),
            "generator_id".to_string(),
            "seed".to_string(),
            "choices".to_string(),
        ],
        relation_schemas,
    }
}

pub fn write_generator_choice_stream_schema_json(
    path: &Path,
    schema: &GeneratorChoiceStreamSchemaReport,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec_pretty(schema)
        .expect("generator choice stream schema serialization should succeed");
    fs::write(path, payload)
}

pub fn minimized_property_counterexamples_for_suite(
    suite: &SuiteExecution,
) -> Vec<MinimizedPropertyCounterexample> {
    suite
        .relation_executions
        .iter()
        .flat_map(|execution| {
            execution.failure_records.iter().filter_map(move |failure| {
                let outcome = execution.outcomes.get(failure.pair_index as usize)?;
                Some(MinimizedPropertyCounterexample {
                    trace_id: suite.trace_id.clone(),
                    decision_id: suite.decision_id.clone(),
                    policy_id: suite.policy_id.clone(),
                    component: suite.component.clone(),
                    relation_id: execution.relation_id.clone(),
                    pair_index: failure.pair_index,
                    seed: failure.seed,
                    generator_id: failure.generator_id.clone(),
                    divergence_detail: failure.divergence_detail.clone(),
                    original_pair: outcome.pair.clone(),
                    minimized_pair: failure.minimized_pair.clone(),
                    original_choice_stream: outcome.choice_stream.clone(),
                    replayable_choice_stream: failure.replayable_choice_stream.clone(),
                    property_contract: outcome.property_contract.clone(),
                    original_size_metric: failure.original_size_metric,
                    minimized_size_metric: failure.minimized_size_metric,
                    original_ast_metric: failure.original_ast_metric,
                    minimized_ast_metric: failure.minimized_ast_metric,
                    choice_stream_reduced: failure.choice_stream_reduced,
                    ddmin_reduced: failure.ddmin_reduced,
                    failure_file: failure.failure_file.clone(),
                })
            })
        })
        .collect()
}

pub fn write_minimized_property_counterexamples_jsonl(
    path: &Path,
    counterexamples: &[MinimizedPropertyCounterexample],
) -> std::io::Result<()> {
    let mut lines = String::new();
    for counterexample in counterexamples {
        let json = serde_json::to_string(counterexample)
            .expect("minimized property counterexample serialization should succeed");
        lines.push_str(&json);
        lines.push('\n');
    }
    fs::write(path, lines)
}

pub fn shrinker_verdict_report_for_suite(suite: &SuiteExecution) -> ShrinkerVerdictReport {
    let entries = suite
        .relation_executions
        .iter()
        .flat_map(|execution| {
            execution
                .failure_records
                .iter()
                .map(|failure| ShrinkerVerdictEntry {
                    relation_id: execution.relation_id.clone(),
                    pair_index: failure.pair_index,
                    seed: failure.seed,
                    generator_id: failure.generator_id.clone(),
                    original_size_metric: failure.original_size_metric,
                    minimized_size_metric: failure.minimized_size_metric,
                    original_ast_metric: failure.original_ast_metric,
                    minimized_ast_metric: failure.minimized_ast_metric,
                    original_choice_count: failure.original_choice_count,
                    minimized_choice_count: failure.minimized_choice_count,
                    choice_stream_reduced: failure.choice_stream_reduced,
                    ddmin_reduced: failure.ddmin_reduced,
                    accepted_steps: failure
                        .shrink_verdicts
                        .iter()
                        .filter(|verdict| verdict.accepted)
                        .count(),
                    rejected_steps: failure
                        .shrink_verdicts
                        .iter()
                        .filter(|verdict| !verdict.accepted)
                        .count(),
                    failure_file: failure.failure_file.clone(),
                    verdicts: failure.shrink_verdicts.clone(),
                })
        })
        .collect::<Vec<_>>();
    let total_attempts = entries.iter().map(|entry| entry.verdicts.len()).sum();
    let total_accepted = entries.iter().map(|entry| entry.accepted_steps).sum();
    let total_rejected = entries.iter().map(|entry| entry.rejected_steps).sum();

    ShrinkerVerdictReport {
        schema_version: "franken-engine.metamorphic.shrinker-verdict-report.v1".to_string(),
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        relation_catalog_hash: suite.relation_catalog_hash.clone(),
        total_failures: entries.len(),
        total_attempts,
        total_accepted,
        total_rejected,
        entries,
    }
}

pub fn write_shrinker_verdict_report_json(
    path: &Path,
    report: &ShrinkerVerdictReport,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec_pretty(report)
        .expect("shrinker verdict report serialization should succeed");
    fs::write(path, payload)
}

pub fn campaign_triage_report_for_suite(
    suite: &SuiteExecution,
    replay_command: &str,
) -> CampaignTriageReport {
    let mut findings = suite
        .relation_executions
        .iter()
        .flat_map(|execution| {
            execution.failure_records.iter().map(move |failure| {
                let (finding_class, severity, owner_assignment) =
                    classify_failure(execution.subsystem, &failure.divergence_detail);
                let counterexample_id = stable_counterexample_id(
                    &suite.trace_id,
                    &execution.relation_id,
                    failure.seed,
                    failure.pair_index,
                    &failure.divergence_detail,
                );
                let deterministic_evidence_link = format!(
                    "repro://metamorphic/{}/{}/{}/{}",
                    suite.relation_catalog_hash,
                    execution.relation_id,
                    failure.seed,
                    counterexample_id
                );

                CampaignFinding {
                    counterexample_id,
                    relation_id: execution.relation_id.clone(),
                    subsystem: execution.subsystem.as_str().to_string(),
                    oracle: execution.oracle.as_str().to_string(),
                    pair_index: failure.pair_index,
                    run_seed: failure.seed,
                    finding_class,
                    severity,
                    priority: severity.as_priority().to_string(),
                    owner_assignment,
                    divergence_detail: failure.divergence_detail.clone(),
                    minimized_reproduction_id: failure.failure_file.clone(),
                    deterministic_evidence_link,
                    replay_command: replay_command.to_string(),
                }
            })
        })
        .collect::<Vec<_>>();

    findings.sort_by(|left, right| {
        right
            .severity
            .rank()
            .cmp(&left.severity.rank())
            .then_with(|| left.relation_id.cmp(&right.relation_id))
            .then_with(|| left.run_seed.cmp(&right.run_seed))
            .then_with(|| left.pair_index.cmp(&right.pair_index))
            .then_with(|| left.counterexample_id.cmp(&right.counterexample_id))
    });

    let total_findings = findings.len() as u32;
    let blocking_findings = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.severity,
                FindingSeverity::Critical | FindingSeverity::High
            )
        })
        .count() as u32;
    let highest_severity = findings
        .iter()
        .map(|finding| finding.severity)
        .max_by_key(|severity| severity.rank());
    let correctness_findings = findings
        .iter()
        .filter(|finding| matches!(finding.finding_class, FindingClass::Correctness))
        .count() as u32;
    let security_findings = findings
        .iter()
        .filter(|finding| matches!(finding.finding_class, FindingClass::Security))
        .count() as u32;
    let determinism_findings = findings
        .iter()
        .filter(|finding| matches!(finding.finding_class, FindingClass::Determinism))
        .count() as u32;

    CampaignTriageReport {
        schema_version: "franken-engine.metamorphic.triage-report.v1".to_string(),
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        relation_catalog_hash: suite.relation_catalog_hash.clone(),
        seed: suite.seed,
        replay_command: replay_command.to_string(),
        priority_policy: priority_policy_rules(),
        summary: CampaignTriageSummary {
            total_findings,
            blocking_findings,
            highest_severity,
            correctness_findings,
            security_findings,
            determinism_findings,
        },
        findings,
    }
}

pub fn write_campaign_triage_report_json(
    path: &Path,
    report: &CampaignTriageReport,
) -> std::io::Result<()> {
    let payload =
        serde_json::to_vec_pretty(report).expect("triage report serialization should succeed");
    fs::write(path, payload)
}

pub fn repro_governance_actions_from_triage(
    report: &CampaignTriageReport,
) -> ReproGovernanceActionsReport {
    let mut deduplicated_actions = BTreeMap::<String, ReproGovernanceAction>::new();

    for finding in &report.findings {
        let fingerprint = stable_governance_fingerprint(finding);
        let bead_suffix = fingerprint.strip_prefix("sha256:").unwrap_or(&fingerprint);
        let bead_prefix_len = bead_suffix.len().min(8);
        let bead_id = format!("bd-auto-{}", &bead_suffix[..bead_prefix_len]);
        deduplicated_actions
            .entry(fingerprint.clone())
            .or_insert_with(|| ReproGovernanceAction {
                schema_version: "franken-engine.metamorphic.repro-governance-action.v1".to_string(),
                action: "create".to_string(),
                bead_id,
                fingerprint,
                counterexample_id: finding.counterexample_id.clone(),
                relation_id: finding.relation_id.clone(),
                finding_class: finding.finding_class,
                severity: finding.severity,
                priority: finding.priority.clone(),
                owner_track: finding.owner_assignment.owner_track.clone(),
                owner_hint: finding.owner_assignment.owner_hint.clone(),
                deterministic_evidence_link: finding.deterministic_evidence_link.clone(),
                replay_command: finding.replay_command.clone(),
                minimized_reproduction_id: finding.minimized_reproduction_id.clone(),
                divergence_detail: finding.divergence_detail.clone(),
            });
    }

    let actions = deduplicated_actions.into_values().collect::<Vec<_>>();

    ReproGovernanceActionsReport {
        schema_version: "franken-engine.metamorphic.repro-governance-actions.v1".to_string(),
        trace_id: report.trace_id.clone(),
        decision_id: report.decision_id.clone(),
        policy_id: report.policy_id.clone(),
        component: report.component.clone(),
        relation_catalog_hash: report.relation_catalog_hash.clone(),
        generated_from: report.schema_version.clone(),
        action_count: actions.len(),
        actions,
    }
}

pub fn write_repro_governance_actions_json(
    path: &Path,
    report: &ReproGovernanceActionsReport,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec_pretty(report)
        .expect("repro governance actions serialization should succeed");
    fs::write(path, payload)
}

pub fn minimize_failure_pair(
    relation: &dyn MetamorphicRelation,
    pair: &GeneratedPair,
    config: MinimizerConfig,
) -> GeneratedPair {
    ddmin_minimize_failure_pair(relation, pair, config)
}

fn minimize_failure_outcome(
    relation: &dyn MetamorphicRelation,
    outcome: &RelationRunOutcome,
    config: MinimizerConfig,
) -> FailureMinimization {
    if outcome.equivalence.is_equivalent() {
        return FailureMinimization {
            replayable_choice_stream: Some(outcome.choice_stream.clone()),
            final_pair: outcome.pair.clone(),
            verdicts: vec![shrink_verdict(
                ShrinkVerdictSpec {
                    stage: "choice_stream",
                    target: "pair",
                    choice_label: None,
                    candidate_value: None,
                    reason: "already_equivalent",
                },
                false,
                &outcome.pair,
                &outcome.pair,
            )],
            choice_stream_reduced: false,
            ddmin_reduced: false,
        };
    }

    let start = Instant::now();
    let mut verdicts = Vec::new();
    let mut replayable_choice_stream = Some(outcome.choice_stream.clone());
    let mut replay_pair = outcome.pair.clone();
    let mut choice_stream_reduced = false;

    if outcome.property_contract.replay_supported && outcome.choice_stream.choice_count() > 0 {
        match minimize_recorded_choice_stream(relation, &outcome.choice_stream, config, start) {
            Some((choice_stream, pair, choice_verdicts, reduced)) => {
                replayable_choice_stream = Some(choice_stream);
                replay_pair = pair;
                verdicts.extend(choice_verdicts);
                choice_stream_reduced = reduced;
            }
            None => {
                replayable_choice_stream = None;
                verdicts.push(shrink_verdict(
                    ShrinkVerdictSpec {
                        stage: "choice_stream",
                        target: "pair",
                        choice_label: None,
                        candidate_value: None,
                        reason: "replay_failed",
                    },
                    false,
                    &outcome.pair,
                    &outcome.pair,
                ));
            }
        }
    } else {
        verdicts.push(shrink_verdict(
            ShrinkVerdictSpec {
                stage: "choice_stream",
                target: "pair",
                choice_label: None,
                candidate_value: None,
                reason: if outcome.property_contract.replay_supported {
                    "no_recorded_choices"
                } else {
                    "replay_not_supported"
                },
            },
            false,
            &outcome.pair,
            &outcome.pair,
        ));
    }

    let ddmin_pair = ddmin_minimize_failure_pair(relation, &replay_pair, config);
    let ddmin_reduced = is_strict_improvement(&replay_pair, &ddmin_pair);
    verdicts.push(shrink_verdict(
        ShrinkVerdictSpec {
            stage: "ddmin",
            target: "pair",
            choice_label: None,
            candidate_value: None,
            reason: if ddmin_reduced {
                "structural_reduction_accepted"
            } else {
                "no_structural_improvement"
            },
        },
        ddmin_reduced,
        &replay_pair,
        &ddmin_pair,
    ));

    let final_pair = if ddmin_reduced {
        ddmin_pair
    } else {
        replay_pair.clone()
    };

    FailureMinimization {
        replayable_choice_stream,
        final_pair,
        verdicts,
        choice_stream_reduced,
        ddmin_reduced,
    }
}

fn minimize_recorded_choice_stream(
    relation: &dyn MetamorphicRelation,
    choice_stream: &ChoiceStream,
    config: MinimizerConfig,
    start: Instant,
) -> Option<(ChoiceStream, GeneratedPair, Vec<ShrinkAttemptVerdict>, bool)> {
    let mut best_stream = choice_stream.clone();
    let mut best_case = relation.replay_case(&best_stream)?;
    let mut verdicts = Vec::new();
    let mut reduced_any = false;
    let mut iterations = 0usize;

    loop {
        if iterations >= config.max_iterations || start.elapsed() > config.max_duration {
            break;
        }

        let mut improved = false;
        for choice_index in 0..best_stream.choices.len() {
            let choice = best_stream.choices[choice_index].clone();
            if choice.value == choice.min_value {
                verdicts.push(shrink_verdict(
                    ShrinkVerdictSpec {
                        stage: "choice_stream",
                        target: "choice",
                        choice_label: Some(choice.label.clone()),
                        candidate_value: Some(choice.value),
                        reason: "already_at_minimum",
                    },
                    false,
                    &best_case.pair,
                    &best_case.pair,
                ));
                continue;
            }

            for candidate_value in shrink_candidates(choice.value, choice.min_value) {
                if iterations >= config.max_iterations || start.elapsed() > config.max_duration {
                    break;
                }
                iterations = iterations.saturating_add(1);

                let mut candidate_stream = best_stream.clone();
                candidate_stream.choices[choice_index].value = candidate_value;
                let Some(candidate_case) = relation.replay_case(&candidate_stream) else {
                    verdicts.push(shrink_verdict(
                        ShrinkVerdictSpec {
                            stage: "choice_stream",
                            target: "choice",
                            choice_label: Some(choice.label.clone()),
                            candidate_value: Some(candidate_value),
                            reason: "replay_mismatch",
                        },
                        false,
                        &best_case.pair,
                        &best_case.pair,
                    ));
                    continue;
                };

                if relation.oracle(&candidate_case.pair).is_equivalent() {
                    verdicts.push(shrink_verdict(
                        ShrinkVerdictSpec {
                            stage: "choice_stream",
                            target: "choice",
                            choice_label: Some(choice.label.clone()),
                            candidate_value: Some(candidate_value),
                            reason: "lost_divergence",
                        },
                        false,
                        &best_case.pair,
                        &candidate_case.pair,
                    ));
                    continue;
                }

                let accepted = is_strict_improvement(&best_case.pair, &candidate_case.pair);
                verdicts.push(shrink_verdict(
                    ShrinkVerdictSpec {
                        stage: "choice_stream",
                        target: "choice",
                        choice_label: Some(choice.label.clone()),
                        candidate_value: Some(candidate_value),
                        reason: if accepted {
                            "choice_stream_reduction_accepted"
                        } else {
                            "not_smaller"
                        },
                    },
                    accepted,
                    &best_case.pair,
                    &candidate_case.pair,
                ));

                if accepted {
                    best_stream = candidate_stream;
                    best_case = candidate_case;
                    improved = true;
                    reduced_any = true;
                    break;
                }
            }

            if improved {
                break;
            }
        }

        if !improved {
            break;
        }
    }

    Some((best_stream, best_case.pair, verdicts, reduced_any))
}

fn shrink_candidates(current: u64, min_value: u64) -> Vec<u64> {
    if current <= min_value {
        return Vec::new();
    }

    let mut candidates = vec![min_value];
    let mut probe = current;
    while probe > min_value {
        let next = min_value + (probe - min_value) / 2;
        if next <= min_value || next >= probe {
            break;
        }
        candidates.push(next);
        probe = next;
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn is_strict_improvement(current: &GeneratedPair, candidate: &GeneratedPair) -> bool {
    let current_size = current.size_metric();
    let candidate_size = candidate.size_metric();
    let current_ast = current.ast_node_metric();
    let candidate_ast = candidate.ast_node_metric();

    candidate_size <= current_size
        && candidate_ast <= current_ast
        && (candidate_size < current_size || candidate_ast < current_ast)
}

struct ShrinkVerdictSpec<'a> {
    stage: &'a str,
    target: &'a str,
    choice_label: Option<String>,
    candidate_value: Option<u64>,
    reason: &'a str,
}

fn shrink_verdict(
    spec: ShrinkVerdictSpec<'_>,
    accepted: bool,
    before: &GeneratedPair,
    after: &GeneratedPair,
) -> ShrinkAttemptVerdict {
    ShrinkAttemptVerdict {
        stage: spec.stage.to_string(),
        target: spec.target.to_string(),
        choice_label: spec.choice_label,
        candidate_value: spec.candidate_value,
        accepted,
        reason: spec.reason.to_string(),
        before_size_metric: before.size_metric(),
        after_size_metric: after.size_metric(),
        before_ast_metric: before.ast_node_metric(),
        after_ast_metric: after.ast_node_metric(),
    }
}

fn ddmin_minimize_failure_pair(
    relation: &dyn MetamorphicRelation,
    pair: &GeneratedPair,
    config: MinimizerConfig,
) -> GeneratedPair {
    if relation.oracle(pair).is_equivalent() {
        return pair.clone();
    }

    let start = Instant::now();
    let mut best = pair.clone();

    best.input_source =
        ddmin_reduce_tokens(&best.input_source, config, start, &mut |candidate_input| {
            if !relation.validate_program(candidate_input) {
                return false;
            }

            let candidate_pair = GeneratedPair {
                input_source: candidate_input.to_string(),
                variant_source: best.variant_source.clone(),
            };

            if !relation.validate_program(&candidate_pair.variant_source) {
                return false;
            }

            !relation.oracle(&candidate_pair).is_equivalent()
        });

    best.input_source = ddmin_reduce(&best.input_source, config, start, &mut |candidate_input| {
        if !relation.validate_program(candidate_input) {
            return false;
        }

        let candidate_pair = GeneratedPair {
            input_source: candidate_input.to_string(),
            variant_source: best.variant_source.clone(),
        };

        if !relation.validate_program(&candidate_pair.variant_source) {
            return false;
        }

        !relation.oracle(&candidate_pair).is_equivalent()
    });

    best.variant_source = ddmin_reduce_tokens(
        &best.variant_source,
        config,
        start,
        &mut |candidate_variant| {
            if !relation.validate_program(candidate_variant) {
                return false;
            }

            let candidate_pair = GeneratedPair {
                input_source: best.input_source.clone(),
                variant_source: candidate_variant.to_string(),
            };

            if !relation.validate_program(&candidate_pair.input_source) {
                return false;
            }

            !relation.oracle(&candidate_pair).is_equivalent()
        },
    );

    best.variant_source = ddmin_reduce(
        &best.variant_source,
        config,
        start,
        &mut |candidate_variant| {
            if !relation.validate_program(candidate_variant) {
                return false;
            }

            let candidate_pair = GeneratedPair {
                input_source: best.input_source.clone(),
                variant_source: candidate_variant.to_string(),
            };

            if !relation.validate_program(&candidate_pair.input_source) {
                return false;
            }

            !relation.oracle(&candidate_pair).is_equivalent()
        },
    );

    best = trim_pair_to_target(relation, best, config, start);

    if relation.oracle(&best).is_equivalent() {
        pair.clone()
    } else {
        best
    }
}

fn trim_pair_to_target(
    relation: &dyn MetamorphicRelation,
    mut pair: GeneratedPair,
    config: MinimizerConfig,
    start: Instant,
) -> GeneratedPair {
    while pair.ast_node_metric() > config.target_ast_nodes && start.elapsed() <= config.max_duration
    {
        let mut improved = false;
        let input_tokens = pair
            .input_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let variant_tokens = pair
            .variant_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        let input_first = input_tokens.len() >= variant_tokens.len();
        let sides = if input_first {
            [Side::Input, Side::Variant]
        } else {
            [Side::Variant, Side::Input]
        };

        for side in sides {
            let tokens = match side {
                Side::Input => &input_tokens,
                Side::Variant => &variant_tokens,
            };

            if tokens.len() <= 1 {
                continue;
            }

            for index in 0..tokens.len() {
                let candidate_tokens = tokens
                    .iter()
                    .take(index)
                    .chain(tokens.iter().skip(index + 1))
                    .cloned()
                    .collect::<Vec<_>>();
                let candidate_source = candidate_tokens.join(" ");
                if candidate_source.trim().is_empty() {
                    continue;
                }

                let candidate_pair = match side {
                    Side::Input => GeneratedPair {
                        input_source: candidate_source,
                        variant_source: pair.variant_source.clone(),
                    },
                    Side::Variant => GeneratedPair {
                        input_source: pair.input_source.clone(),
                        variant_source: candidate_source,
                    },
                };

                if !relation.validate_program(&candidate_pair.input_source)
                    || !relation.validate_program(&candidate_pair.variant_source)
                {
                    continue;
                }

                if relation.oracle(&candidate_pair).is_equivalent() {
                    continue;
                }

                pair = candidate_pair;
                improved = true;
                break;
            }

            if improved {
                break;
            }
        }

        if !improved {
            break;
        }
    }

    pair
}

#[derive(Clone, Copy)]
enum Side {
    Input,
    Variant,
}

fn ddmin_reduce_tokens(
    input: &str,
    config: MinimizerConfig,
    start: Instant,
    predicate: &mut dyn FnMut(&str) -> bool,
) -> String {
    let mut tokens = input
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if tokens.len() <= 1 {
        return input.to_string();
    }

    let mut granularity = 2usize;
    let mut iterations = 0usize;

    while tokens.len() > 1
        && iterations < config.max_iterations
        && start.elapsed() <= config.max_duration
    {
        let length = tokens.len();
        let chunk_size = length.div_ceil(granularity);
        let mut reduced = false;

        for chunk in 0..granularity {
            let begin = chunk * chunk_size;
            if begin >= length {
                break;
            }
            let end = (begin + chunk_size).min(length);

            let candidate_tokens = tokens
                .iter()
                .take(begin)
                .chain(tokens.iter().skip(end))
                .cloned()
                .collect::<Vec<_>>();

            if candidate_tokens.is_empty() {
                continue;
            }

            let candidate = candidate_tokens.join(" ");
            if !predicate(&candidate) {
                continue;
            }

            tokens = candidate_tokens;
            reduced = true;
            break;
        }

        iterations = iterations.saturating_add(1);

        if tokens.len() <= config.target_ast_nodes {
            break;
        }

        if reduced {
            granularity = granularity.saturating_sub(1).max(2);
        } else if granularity >= length {
            break;
        } else {
            granularity = (granularity * 2).min(length);
        }
    }

    tokens.join(" ")
}

fn ddmin_reduce(
    input: &str,
    config: MinimizerConfig,
    start: Instant,
    predicate: &mut dyn FnMut(&str) -> bool,
) -> String {
    let mut best = input.to_string();
    let mut granularity = 2usize;
    let mut iterations = 0usize;

    while best.chars().count() > 1
        && iterations < config.max_iterations
        && start.elapsed() <= config.max_duration
    {
        let chars = best.chars().collect::<Vec<_>>();
        let length = chars.len();
        let chunk_size = length.div_ceil(granularity);
        let mut reduced = false;

        for chunk in 0..granularity {
            let begin = chunk * chunk_size;
            if begin >= length {
                break;
            }
            let end = (begin + chunk_size).min(length);

            let candidate = chars
                .iter()
                .take(begin)
                .chain(chars.iter().skip(end))
                .copied()
                .collect::<String>();

            if candidate.trim().is_empty() {
                continue;
            }

            if !predicate(&candidate) {
                continue;
            }

            best = candidate;
            reduced = true;
            break;
        }

        iterations = iterations.saturating_add(1);

        if best
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .count()
            <= config.target_ast_nodes
        {
            break;
        }

        if reduced {
            granularity = granularity.saturating_sub(1).max(2);
        } else if granularity >= length {
            break;
        } else {
            granularity = (granularity * 2).min(length);
        }
    }

    best
}

fn write_failure_artifact(path: &Path, artifact: &FailureArtifact) -> std::io::Result<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(artifact.relation_id.as_bytes());
    hasher.update(artifact.seed.to_le_bytes());
    hasher.update(artifact.input_source.as_bytes());
    hasher.update(artifact.variant_source.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let short_hash = &digest[..12];
    let file_name = format!(
        "metamorphic_failure_{}_{}.json",
        sanitize_relation_id(&artifact.relation_id),
        short_hash
    );

    let path = path.join(file_name);
    let payload =
        serde_json::to_vec_pretty(artifact).expect("failure artifact serialization should succeed");
    fs::write(&path, payload)?;
    Ok(path)
}

fn sanitize_relation_id(relation_id: &str) -> String {
    relation_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn priority_policy_rules() -> Vec<PriorityPolicyRule> {
    vec![
        PriorityPolicyRule {
            rule_id: "security-critical".to_string(),
            description: "Security-relevant divergence routes to security lane with immediate escalation.".to_string(),
            finding_class: FindingClass::Security,
            severity: FindingSeverity::Critical,
            priority: FindingSeverity::Critical.as_priority().to_string(),
            owner_track: "frx-security-lane".to_string(),
            owner_hint: "security-oncall".to_string(),
            escalation_required: true,
        },
        PriorityPolicyRule {
            rule_id: "determinism-high".to_string(),
            description:
                "Determinism drift routes to verification lane and blocks promotion pending rerun evidence."
                    .to_string(),
            finding_class: FindingClass::Determinism,
            severity: FindingSeverity::High,
            priority: FindingSeverity::High.as_priority().to_string(),
            owner_track: "frx-verification-lane".to_string(),
            owner_hint: "verification-oncall".to_string(),
            escalation_required: true,
        },
        PriorityPolicyRule {
            rule_id: "correctness-parser-ir".to_string(),
            description: "Parser/IR correctness drifts route to compiler lane for remediation.".to_string(),
            finding_class: FindingClass::Correctness,
            severity: FindingSeverity::Medium,
            priority: FindingSeverity::Medium.as_priority().to_string(),
            owner_track: "frx-compiler-lane".to_string(),
            owner_hint: "compiler-oncall".to_string(),
            escalation_required: false,
        },
        PriorityPolicyRule {
            rule_id: "correctness-execution".to_string(),
            description: "Execution correctness drifts route to runtime lane for remediation.".to_string(),
            finding_class: FindingClass::Correctness,
            severity: FindingSeverity::Medium,
            priority: FindingSeverity::Medium.as_priority().to_string(),
            owner_track: "frx-js-runtime-lane".to_string(),
            owner_hint: "runtime-oncall".to_string(),
            escalation_required: false,
        },
    ]
}

fn classify_failure(
    subsystem: Subsystem,
    detail: &str,
) -> (FindingClass, FindingSeverity, OwnerAssignment) {
    let lowered = detail.to_ascii_lowercase();
    let security_keywords = [
        "capability",
        "permission",
        "ifc",
        "containment",
        "isolation",
        "sandbox",
        "escape",
        "authority",
        "privilege",
        "secret",
        "taint",
        "policy",
    ];
    let determinism_keywords = [
        "nondetermin",
        "determin",
        "flaky",
        "race",
        "ordering",
        "schedule",
        "timing",
        "clock",
        "random",
        "heisen",
        "interleav",
    ];

    if security_keywords
        .iter()
        .any(|keyword| lowered.contains(keyword))
    {
        return (
            FindingClass::Security,
            FindingSeverity::Critical,
            OwnerAssignment {
                owner_track: "frx-security-lane".to_string(),
                owner_hint: "security-oncall".to_string(),
                escalation_required: true,
            },
        );
    }

    if determinism_keywords
        .iter()
        .any(|keyword| lowered.contains(keyword))
    {
        return (
            FindingClass::Determinism,
            FindingSeverity::High,
            OwnerAssignment {
                owner_track: "frx-verification-lane".to_string(),
                owner_hint: "verification-oncall".to_string(),
                escalation_required: true,
            },
        );
    }

    let owner_assignment = match subsystem {
        Subsystem::Execution => OwnerAssignment {
            owner_track: "frx-js-runtime-lane".to_string(),
            owner_hint: "runtime-oncall".to_string(),
            escalation_required: false,
        },
        Subsystem::Parser | Subsystem::Ir => OwnerAssignment {
            owner_track: "frx-compiler-lane".to_string(),
            owner_hint: "compiler-oncall".to_string(),
            escalation_required: false,
        },
    };

    (
        FindingClass::Correctness,
        FindingSeverity::Medium,
        owner_assignment,
    )
}

fn stable_counterexample_id(
    trace_id: &str,
    relation_id: &str,
    seed: u64,
    pair_index: u32,
    divergence_detail: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(trace_id.as_bytes());
    hasher.update(relation_id.as_bytes());
    hasher.update(seed.to_le_bytes());
    hasher.update(pair_index.to_le_bytes());
    hasher.update(divergence_detail.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("cex-{}", &digest[..16])
}

fn stable_governance_fingerprint(finding: &CampaignFinding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.counterexample_id.as_bytes());
    hasher.update(finding.relation_id.as_bytes());
    hasher.update(finding.run_seed.to_le_bytes());
    hasher.update(finding.pair_index.to_le_bytes());
    hasher.update(finding.divergence_detail.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{digest}")
}

pub fn environment_fingerprint() -> String {
    let toolchain = std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string());
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "default".to_string());

    format!(
        "os={} arch={} family={} toolchain={} target_dir={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY,
        toolchain,
        target_dir
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::catalog::RelationCatalog;
    use crate::relation::{
        ChoiceStream, Equivalence, GeneratedCase, GeneratedPair, GenerationChoice,
        MetamorphicRelation, OracleKind, PropertyContract, RelationSpec, Subsystem,
        default_generator_id,
    };
    use crate::{build_enabled_relations, build_relation};

    use super::{
        FindingClass, FindingSeverity, MinimizerConfig, RelationEvidenceEntry, RunContext,
        campaign_triage_report_for_suite, evidence_entries_for_suite,
        generator_choice_stream_schema_for_suite, minimize_failure_pair,
        minimized_property_counterexamples_for_suite, property_generator_catalog_for_suite,
        relation_log_events_for_suite, repro_governance_actions_from_triage,
        run_relation_with_budget, run_suite, seed_manifest_for_suite,
        seed_transcript_entries_for_suite, shrinker_verdict_report_for_suite,
    };

    struct AlwaysPassRelation {
        spec: RelationSpec,
    }

    impl MetamorphicRelation for AlwaysPassRelation {
        fn spec(&self) -> &RelationSpec {
            &self.spec
        }

        fn generate_pair(&self, seed: u64) -> GeneratedPair {
            GeneratedPair {
                input_source: format!("let alpha = {seed} + 1; return alpha;"),
                variant_source: format!("let alpha = {seed} + 1; return alpha;"),
            }
        }

        fn oracle(&self, _pair: &GeneratedPair) -> Equivalence {
            Equivalence::Equivalent
        }

        fn validate_program(&self, source: &str) -> bool {
            !source.trim().is_empty()
        }
    }

    struct SyntheticViolationRelation {
        spec: RelationSpec,
    }

    impl MetamorphicRelation for SyntheticViolationRelation {
        fn spec(&self) -> &RelationSpec {
            &self.spec
        }

        fn generate_pair(&self, _seed: u64) -> GeneratedPair {
            let mut input_tokens = Vec::new();
            let mut variant_tokens = Vec::new();
            for index in 0..80 {
                input_tokens.push(format!("node_{index}"));
                variant_tokens.push(format!("node_{index}"));
            }
            variant_tokens.push("bad".to_string());

            GeneratedPair {
                input_source: input_tokens.join(" "),
                variant_source: variant_tokens.join(" "),
            }
        }

        fn oracle(&self, pair: &GeneratedPair) -> Equivalence {
            if pair.variant_source.contains("bad") {
                Equivalence::Diverged {
                    detail: "synthetic divergence".to_string(),
                }
            } else {
                Equivalence::Equivalent
            }
        }

        fn validate_program(&self, source: &str) -> bool {
            !source.trim().is_empty()
        }
    }

    struct PatternViolationRelation {
        spec: RelationSpec,
        divergence_detail: &'static str,
    }

    impl MetamorphicRelation for PatternViolationRelation {
        fn spec(&self) -> &RelationSpec {
            &self.spec
        }

        fn generate_pair(&self, seed: u64) -> GeneratedPair {
            GeneratedPair {
                input_source: format!("let value_{seed} = 1; return value_{seed};"),
                variant_source: format!(
                    "let value_{seed} = 1; return value_{seed}; // {}",
                    self.divergence_detail
                ),
            }
        }

        fn oracle(&self, _pair: &GeneratedPair) -> Equivalence {
            Equivalence::Diverged {
                detail: self.divergence_detail.to_string(),
            }
        }

        fn validate_program(&self, source: &str) -> bool {
            !source.trim().is_empty()
        }
    }

    struct ChoiceStreamViolationRelation {
        spec: RelationSpec,
    }

    impl ChoiceStreamViolationRelation {
        fn make_pair(left: usize, right: usize) -> GeneratedPair {
            let input_tokens = std::iter::repeat_n("node", left).collect::<Vec<_>>();
            let variant_tokens = std::iter::repeat_n("node", right).collect::<Vec<_>>();
            GeneratedPair {
                input_source: input_tokens.join(" "),
                variant_source: format!("{} bad", variant_tokens.join(" ")),
            }
        }
    }

    impl MetamorphicRelation for ChoiceStreamViolationRelation {
        fn spec(&self) -> &RelationSpec {
            &self.spec
        }

        fn generate_pair(&self, seed: u64) -> GeneratedPair {
            let left = 2 + (seed as usize % 6);
            let right = 3 + (seed as usize % 6);
            Self::make_pair(left, right)
        }

        fn generate_case(&self, seed: u64) -> GeneratedCase {
            let left = 2 + (seed as usize % 6);
            let right = 3 + (seed as usize % 6);
            let generator_id = default_generator_id(&self.spec.id);
            let pair = Self::make_pair(left, right);

            GeneratedCase {
                relation_id: self.spec.id.clone(),
                generator_id: generator_id.clone(),
                seed,
                pair: pair.clone(),
                choice_stream: ChoiceStream {
                    schema_version: "franken-engine.metamorphic.choice-stream.v1".to_string(),
                    relation_id: self.spec.id.clone(),
                    generator_id: generator_id.clone(),
                    seed,
                    choices: vec![
                        GenerationChoice {
                            index: 0,
                            label: "left_nodes".to_string(),
                            strategy: "integer_range".to_string(),
                            min_value: 1,
                            max_value: 8,
                            value: left as u64,
                        },
                        GenerationChoice {
                            index: 1,
                            label: "right_nodes".to_string(),
                            strategy: "integer_range".to_string(),
                            min_value: 1,
                            max_value: 8,
                            value: right as u64,
                        },
                    ],
                },
                property_contract: PropertyContract {
                    schema_version: "franken-engine.metamorphic.property-contract.v1".to_string(),
                    relation_id: self.spec.id.clone(),
                    generator_id,
                    expected_equivalence: "equivalent".to_string(),
                    validates_input: true,
                    validates_variant: true,
                    replay_supported: true,
                    shrink_strategy: "recorded_choice_stream_then_ddmin".to_string(),
                },
            }
        }

        fn replay_case(&self, choice_stream: &ChoiceStream) -> Option<GeneratedCase> {
            let left = choice_stream.choices.first()?.value as usize;
            let right = choice_stream.choices.get(1)?.value as usize;
            let generator_id = default_generator_id(&self.spec.id);
            if choice_stream.generator_id != generator_id {
                return None;
            }
            if choice_stream.relation_id != self.spec.id {
                return None;
            }

            Some(GeneratedCase {
                relation_id: self.spec.id.clone(),
                generator_id: generator_id.clone(),
                seed: choice_stream.seed,
                pair: Self::make_pair(left, right),
                choice_stream: choice_stream.clone(),
                property_contract: PropertyContract {
                    schema_version: "franken-engine.metamorphic.property-contract.v1".to_string(),
                    relation_id: self.spec.id.clone(),
                    generator_id,
                    expected_equivalence: "equivalent".to_string(),
                    validates_input: true,
                    validates_variant: true,
                    replay_supported: true,
                    shrink_strategy: "recorded_choice_stream_then_ddmin".to_string(),
                },
            })
        }

        fn oracle(&self, pair: &GeneratedPair) -> Equivalence {
            if pair.variant_source.contains("bad") {
                Equivalence::Diverged {
                    detail: "choice stream divergence".to_string(),
                }
            } else {
                Equivalence::Equivalent
            }
        }

        fn validate_program(&self, source: &str) -> bool {
            !source.trim().is_empty()
        }
    }

    fn test_context() -> RunContext {
        RunContext::new(
            "trace-test",
            "decision-test",
            "policy-test",
            "metamorphic_suite",
            "sha256:test",
            7,
        )
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "franken_metamorphic_{label}_{nanos}_{}",
            std::process::id()
        ))
    }

    #[test]
    fn budget_is_enforced_exactly() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "test_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "test".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 10,
                enabled: true,
            },
        };

        let execution = run_relation_with_budget(
            &relation,
            &test_context(),
            10,
            None,
            MinimizerConfig::default(),
        )
        .expect("relation should execute");

        assert_eq!(execution.pairs_tested, 10);
        assert_eq!(execution.outcomes.len(), 10);
        assert_eq!(execution.violations_found, 0);
    }

    #[test]
    fn evidence_marks_failure_with_error_code() {
        let execution = super::RelationExecution {
            relation_id: "r".to_string(),
            subsystem: Subsystem::Ir,
            oracle: OracleKind::IrEquality,
            pairs_tested: 3,
            violations_found: 1,
            min_failure_size: Some(5),
            duration_us: 100,
            outcomes: Vec::new(),
            failure_records: Vec::new(),
            failure_files: Vec::new(),
            log_event: super::RelationLogEvent {
                trace_id: "trace".to_string(),
                decision_id: "decision".to_string(),
                policy_id: "policy".to_string(),
                component: "metamorphic_suite".to_string(),
                event: "relation_completed".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-META-0001".to_string()),
                relation_id: "r".to_string(),
                subsystem: "ir".to_string(),
                pairs_tested: 3,
                violations_found: 1,
                min_failure_size: Some(5),
                duration_us: 100,
            },
        };

        let entry = RelationEvidenceEntry::from_execution(&execution, &test_context());
        assert_eq!(entry.error_code.as_deref(), Some("FE-META-0001"));
        assert_eq!(entry.outcome, "fail");
        assert_eq!(entry.event, "relation_completed");
    }

    #[test]
    fn relation_soundness_meta_test_for_curated_seed_set() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relations = build_enabled_relations(&catalog);

        for relation in &relations {
            for seed in 0..20u64 {
                let pair = relation.generate_pair(seed);
                assert!(
                    relation.oracle(&pair).is_equivalent(),
                    "relation {} failed soundness at seed {}",
                    relation.spec().id,
                    seed
                );
            }
        }
    }

    #[test]
    fn generator_coverage_meta_test_exceeds_ninety_nine_percent() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relations = build_enabled_relations(&catalog);

        for relation in &relations {
            let mut valid = 0usize;
            let total = 500usize;
            for seed in 0..total as u64 {
                let pair = relation.generate_pair(seed);
                if relation.validate_program(&pair.input_source)
                    && relation.validate_program(&pair.variant_source)
                {
                    valid += 1;
                }
            }

            let pass_rate = (valid as f64) / (total as f64);
            assert!(
                pass_rate >= 0.99,
                "relation {} coverage {:.3} below threshold",
                relation.spec().id,
                pass_rate
            );
        }
    }

    #[test]
    fn property_contracts_remain_valid_for_enabled_relations() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relations = build_enabled_relations(&catalog);

        for relation in &relations {
            let generated = relation.generate_case(11);
            assert!(
                generated.property_contract.validates_input,
                "input contract invalid for {}",
                relation.spec().id
            );
            assert!(
                generated.property_contract.validates_variant,
                "variant contract invalid for {}",
                relation.spec().id
            );
            assert_eq!(
                generated.property_contract.expected_equivalence,
                "equivalent"
            );
            let replayed = relation
                .replay_case(&generated.choice_stream)
                .expect("recorded choice stream should replay");
            assert_eq!(generated.pair, replayed.pair);
        }
    }

    #[test]
    fn catalog_relation_choice_stream_replay_round_trips() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relation = build_relation(&catalog, "parser_whitespace_invariance")
            .expect("relation should exist");
        let generated = relation.generate_case(42);
        let replayed = relation
            .replay_case(&generated.choice_stream)
            .expect("replay should succeed");

        assert_eq!(generated.pair, replayed.pair);
        assert_eq!(generated.choice_stream, replayed.choice_stream);
        assert!(generated.choice_stream.choice_count() > 0);
    }

    #[test]
    fn minimizer_effectiveness_meta_test_reduces_to_target_budget() {
        let relation = SyntheticViolationRelation {
            spec: RelationSpec {
                id: "synthetic_violation".to_string(),
                subsystem: Subsystem::Parser,
                description: "synthetic".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };

        let pair = relation.generate_pair(1);
        let minimized = minimize_failure_pair(
            &relation,
            &pair,
            MinimizerConfig {
                max_iterations: 512,
                max_duration: Duration::from_secs(60),
                target_ast_nodes: 20,
            },
        );

        assert!(!relation.oracle(&minimized).is_equivalent());
        assert!(
            minimized.ast_node_metric() <= 20,
            "expected <= 20 nodes, got {}",
            minimized.ast_node_metric()
        );
    }

    #[test]
    fn accepted_shrink_steps_are_monotonic() {
        let relation = ChoiceStreamViolationRelation {
            spec: RelationSpec {
                id: "choice_stream_violation".to_string(),
                subsystem: Subsystem::Parser,
                description: "choice stream".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };

        let execution = run_relation_with_budget(
            &relation,
            &test_context(),
            1,
            None,
            MinimizerConfig {
                max_iterations: 128,
                max_duration: Duration::from_secs(30),
                target_ast_nodes: 4,
            },
        )
        .expect("relation should execute");

        let failure = execution
            .failure_records
            .first()
            .expect("relation should emit a failure");
        assert!(failure.choice_stream_reduced);
        assert!(failure.minimized_size_metric <= failure.original_size_metric);
        assert!(failure.minimized_ast_metric <= failure.original_ast_metric);
        assert!(
            failure
                .shrink_verdicts
                .iter()
                .filter(|verdict| verdict.accepted)
                .all(
                    |verdict| verdict.after_size_metric <= verdict.before_size_metric
                        && verdict.after_ast_metric <= verdict.before_ast_metric
                )
        );
    }

    #[test]
    fn generator_artifact_helpers_emit_choice_stream_outputs() {
        let relation = ChoiceStreamViolationRelation {
            spec: RelationSpec {
                id: "choice_stream_artifact_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "choice stream artifact".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];
        let suite = run_suite(
            &relation_refs,
            &context,
            Some(1),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");

        let generator_catalog = property_generator_catalog_for_suite(&suite);
        assert_eq!(generator_catalog.generator_count, 1);
        assert_eq!(
            generator_catalog.generators[0].consumers,
            vec!["metamorphic", "fuzz", "differential"]
        );

        let choice_schema = generator_choice_stream_schema_for_suite(&suite);
        assert_eq!(choice_schema.relation_schemas.len(), 1);
        assert_eq!(choice_schema.relation_schemas[0].fields.len(), 2);

        let shrink_report = shrinker_verdict_report_for_suite(&suite);
        assert_eq!(shrink_report.total_failures, 1);
        assert!(shrink_report.total_attempts >= 1);

        let counterexamples = minimized_property_counterexamples_for_suite(&suite);
        assert_eq!(counterexamples.len(), 1);
        assert!(counterexamples[0].replayable_choice_stream.is_some());
        assert_eq!(
            counterexamples[0].property_contract.expected_equivalence,
            "equivalent"
        );
    }

    #[test]
    fn violation_runs_emit_failure_artifact_payloads() {
        let relation = SyntheticViolationRelation {
            spec: RelationSpec {
                id: "synthetic_violation".to_string(),
                subsystem: Subsystem::Parser,
                description: "synthetic".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };
        let output_dir = temp_dir("failure_artifacts");
        fs::create_dir_all(&output_dir).expect("temp output dir should be creatable");

        let execution = run_relation_with_budget(
            &relation,
            &test_context(),
            1,
            Some(&output_dir),
            MinimizerConfig {
                max_iterations: 512,
                max_duration: Duration::from_secs(60),
                target_ast_nodes: 20,
            },
        )
        .expect("synthetic relation should execute");

        assert_eq!(execution.violations_found, 1);
        assert_eq!(execution.failure_records.len(), 1);
        assert_eq!(execution.failure_files.len(), 1);
        assert_eq!(execution.failure_records[0].pair_index, 0);
        assert_eq!(execution.failure_records[0].seed, 7);
        assert_eq!(
            execution.failure_records[0].divergence_detail,
            "synthetic divergence"
        );
        assert_eq!(
            execution.failure_records[0].failure_file.as_deref(),
            Some(execution.failure_files[0].as_str())
        );

        let failure_path = PathBuf::from(&execution.failure_files[0]);
        assert!(failure_path.exists(), "failure artifact path must exist");
        let file_name = failure_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("failure artifact file name should be valid UTF-8");
        assert!(file_name.starts_with("metamorphic_failure_synthetic_violation_"));
        assert!(file_name.ends_with(".json"));

        let raw = fs::read_to_string(&failure_path).expect("failure artifact should be readable");
        let artifact: super::FailureArtifact =
            serde_json::from_str(&raw).expect("failure artifact JSON should parse");
        assert_eq!(artifact.relation_id, "synthetic_violation");
        assert_eq!(artifact.seed, 7);
        assert!(artifact.minimized, "divergence payload should be minimized");
        assert_eq!(artifact.expected_equivalence, "equivalent");
        assert_eq!(artifact.actual_divergence, "synthetic divergence");
        assert!(artifact.variant_source.contains("bad"));

        fs::remove_dir_all(&output_dir).expect("temp output dir should be removable");
    }

    #[test]
    fn failure_artifact_path_is_stable_for_identical_violation_inputs() {
        let relation = SyntheticViolationRelation {
            spec: RelationSpec {
                id: "synthetic_violation".to_string(),
                subsystem: Subsystem::Parser,
                description: "synthetic".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };
        let output_dir = temp_dir("stable_failure_artifact");
        fs::create_dir_all(&output_dir).expect("temp output dir should be creatable");

        let first = run_relation_with_budget(
            &relation,
            &test_context(),
            1,
            Some(&output_dir),
            MinimizerConfig::default(),
        )
        .expect("first run should succeed");
        let second = run_relation_with_budget(
            &relation,
            &test_context(),
            1,
            Some(&output_dir),
            MinimizerConfig::default(),
        )
        .expect("second run should succeed");

        assert_eq!(first.failure_files.len(), 1);
        assert_eq!(second.failure_files.len(), 1);
        assert_eq!(first.failure_files[0], second.failure_files[0]);
        assert_eq!(first.failure_records, second.failure_records);

        fs::remove_dir_all(&output_dir).expect("temp output dir should be removable");
    }

    #[test]
    fn determinism_meta_test_for_same_seed() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relation =
            build_relation(&catalog, "ir_lowering_determinism").expect("relation should exist");
        let context = test_context();

        let first =
            run_relation_with_budget(&relation, &context, 50, None, MinimizerConfig::default())
                .expect("first run should pass");
        let second =
            run_relation_with_budget(&relation, &context, 50, None, MinimizerConfig::default())
                .expect("second run should pass");

        assert_eq!(first.outcomes, second.outcomes);
        assert_eq!(first.violations_found, second.violations_found);
    }

    #[test]
    fn suite_logging_contains_required_fields() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relation = build_relation(&catalog, "execution_gc_timing_independence")
            .expect("relation should exist");
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let suite = run_suite(
            &relation_refs,
            &context,
            Some(10),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite run should pass");

        let events = relation_log_events_for_suite(&suite);
        assert!(events.iter().all(|event| !event.trace_id.is_empty()));
        assert!(events.iter().all(|event| !event.decision_id.is_empty()));
        assert!(events.iter().all(|event| !event.policy_id.is_empty()));
        assert!(events.iter().all(|event| !event.component.is_empty()));
        assert!(events.iter().all(|event| !event.event.is_empty()));
        assert!(events.iter().all(|event| !event.outcome.is_empty()));
    }

    #[test]
    fn evidence_entries_include_suite_summary() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "summary_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "summary".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let suite = run_suite(
            &relation_refs,
            &context,
            Some(2),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");

        let entries = evidence_entries_for_suite(&suite);
        assert!(entries.iter().any(|entry| entry.event == "suite_summary"));
        assert!(
            entries
                .iter()
                .filter(|entry| entry.event == "suite_summary")
                .all(|entry| entry.total_violations.is_some())
        );
    }

    #[test]
    fn seed_transcript_rows_are_ordered_and_seeded_deterministically() {
        let relation_left = AlwaysPassRelation {
            spec: RelationSpec {
                id: "left_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "left".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let relation_right = AlwaysPassRelation {
            spec: RelationSpec {
                id: "right_relation".to_string(),
                subsystem: Subsystem::Execution,
                description: "right".to_string(),
                oracle: OracleKind::CanonicalOutputEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation_left, &relation_right];

        let suite = run_suite(
            &relation_refs,
            &context,
            Some(2),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");
        let transcript = seed_transcript_entries_for_suite(&suite);

        let relation_order = transcript
            .iter()
            .map(|entry| entry.relation_id.as_str())
            .collect::<Vec<_>>();
        let seed_order = transcript
            .iter()
            .map(|entry| entry.run_seed)
            .collect::<Vec<_>>();
        let pair_indexes = transcript
            .iter()
            .map(|entry| entry.pair_index)
            .collect::<Vec<_>>();

        assert_eq!(
            relation_order,
            vec![
                "left_relation",
                "left_relation",
                "right_relation",
                "right_relation"
            ]
        );
        assert_eq!(seed_order, vec![7, 8, 7, 8]);
        assert_eq!(pair_indexes, vec![0, 1, 0, 1]);
        assert!(
            transcript
                .iter()
                .all(|entry| entry.event == "pair_seed_evaluated")
        );
    }

    #[test]
    fn seed_transcript_is_stable_for_identical_suite_inputs() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "stable_seed_relation".to_string(),
                subsystem: Subsystem::Ir,
                description: "stable".to_string(),
                oracle: OracleKind::IrEquality,
                budget_pairs: 3,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let first = run_suite(
            &relation_refs,
            &context,
            Some(3),
            None,
            MinimizerConfig::default(),
        )
        .expect("first suite should run");
        let second = run_suite(
            &relation_refs,
            &context,
            Some(3),
            None,
            MinimizerConfig::default(),
        )
        .expect("second suite should run");

        assert_eq!(
            seed_transcript_entries_for_suite(&first),
            seed_transcript_entries_for_suite(&second)
        );
    }

    #[test]
    fn seed_transcript_writer_emits_jsonl_rows() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "writer_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "writer".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];
        let suite = run_suite(
            &relation_refs,
            &context,
            Some(2),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");
        let transcript = seed_transcript_entries_for_suite(&suite);

        let file_name = format!(
            "seed_transcript_writer_test_{}_{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        );
        let output_path = std::env::temp_dir().join(file_name);

        super::write_seed_transcript_jsonl(&output_path, &transcript)
            .expect("writer should serialize transcript");
        let payload =
            std::fs::read_to_string(&output_path).expect("seed transcript file should exist");
        let _ = std::fs::remove_file(&output_path);

        let lines = payload.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), transcript.len());
        assert_eq!(lines.len(), 2);
        assert!(
            lines
                .iter()
                .all(|line| line.contains("\"event\":\"pair_seed_evaluated\""))
        );
    }

    #[test]
    fn seed_manifest_is_stable_for_identical_suite_inputs() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "seed_manifest_relation".to_string(),
                subsystem: Subsystem::Ir,
                description: "seed manifest".to_string(),
                oracle: OracleKind::IrEquality,
                budget_pairs: 3,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let first = run_suite(
            &relation_refs,
            &context,
            Some(3),
            None,
            MinimizerConfig::default(),
        )
        .expect("first suite should run");
        let second = run_suite(
            &relation_refs,
            &context,
            Some(3),
            None,
            MinimizerConfig::default(),
        )
        .expect("second suite should run");

        let first_manifest = seed_manifest_for_suite(&first);
        let second_manifest = seed_manifest_for_suite(&second);
        assert_eq!(first_manifest, second_manifest);
        assert_eq!(first_manifest.base_seed, 7);
        assert_eq!(first_manifest.relation_seed_schedule.len(), 1);
        assert_eq!(first_manifest.relation_seed_schedule[0].start_seed, 7);
        assert_eq!(first_manifest.relation_seed_schedule[0].end_seed, 9);
    }

    #[test]
    fn campaign_triage_report_routes_and_prioritizes_findings() {
        let security_relation = PatternViolationRelation {
            spec: RelationSpec {
                id: "security_relation".to_string(),
                subsystem: Subsystem::Execution,
                description: "security".to_string(),
                oracle: OracleKind::SideEffectTraceEquality,
                budget_pairs: 1,
                enabled: true,
            },
            divergence_detail: "capability containment escape detected",
        };
        let determinism_relation = PatternViolationRelation {
            spec: RelationSpec {
                id: "determinism_relation".to_string(),
                subsystem: Subsystem::Execution,
                description: "determinism".to_string(),
                oracle: OracleKind::CanonicalOutputEquality,
                budget_pairs: 1,
                enabled: true,
            },
            divergence_detail: "nondeterministic ordering drift observed",
        };
        let correctness_relation = PatternViolationRelation {
            spec: RelationSpec {
                id: "correctness_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "correctness".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
            divergence_detail: "semantic mismatch in parser output",
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![
            &correctness_relation,
            &security_relation,
            &determinism_relation,
        ];

        let suite = run_suite(
            &relation_refs,
            &context,
            Some(1),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");
        let report = campaign_triage_report_for_suite(
            &suite,
            "./scripts/e2e/metamorphic_suite_replay.sh ci",
        );

        assert_eq!(report.summary.total_findings, 3);
        assert_eq!(report.summary.blocking_findings, 2);
        assert_eq!(report.summary.security_findings, 1);
        assert_eq!(report.summary.determinism_findings, 1);
        assert_eq!(report.summary.correctness_findings, 1);
        assert_eq!(
            report.summary.highest_severity,
            Some(FindingSeverity::Critical)
        );
        assert_eq!(report.findings.len(), 3);

        let security = &report.findings[0];
        assert_eq!(security.finding_class, FindingClass::Security);
        assert_eq!(security.severity, FindingSeverity::Critical);
        assert_eq!(security.priority, "p0");
        assert_eq!(security.owner_assignment.owner_track, "frx-security-lane");
        assert!(security.owner_assignment.escalation_required);

        let determinism = &report.findings[1];
        assert_eq!(determinism.finding_class, FindingClass::Determinism);
        assert_eq!(determinism.severity, FindingSeverity::High);
        assert_eq!(determinism.priority, "p1");
        assert_eq!(
            determinism.owner_assignment.owner_track,
            "frx-verification-lane"
        );
        assert!(determinism.owner_assignment.escalation_required);

        let correctness = &report.findings[2];
        assert_eq!(correctness.finding_class, FindingClass::Correctness);
        assert_eq!(correctness.severity, FindingSeverity::Medium);
        assert_eq!(correctness.priority, "p2");
        assert_eq!(
            correctness.owner_assignment.owner_track,
            "frx-compiler-lane"
        );
        assert!(!correctness.owner_assignment.escalation_required);
    }

    #[test]
    fn campaign_triage_report_is_stable_for_identical_suite_inputs() {
        let relation = SyntheticViolationRelation {
            spec: RelationSpec {
                id: "stable_triage_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "stable triage".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let first = run_suite(
            &relation_refs,
            &context,
            Some(1),
            None,
            MinimizerConfig::default(),
        )
        .expect("first suite should run");
        let second = run_suite(
            &relation_refs,
            &context,
            Some(1),
            None,
            MinimizerConfig::default(),
        )
        .expect("second suite should run");

        let first_report = campaign_triage_report_for_suite(
            &first,
            "./scripts/e2e/metamorphic_suite_replay.sh ci",
        );
        let second_report = campaign_triage_report_for_suite(
            &second,
            "./scripts/e2e/metamorphic_suite_replay.sh ci",
        );
        assert_eq!(first_report, second_report);
    }

    #[test]
    fn repro_governance_actions_are_stable_for_identical_triage_inputs() {
        let relation = SyntheticViolationRelation {
            spec: RelationSpec {
                id: "stable_governance_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "stable governance".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];
        let suite = run_suite(
            &relation_refs,
            &context,
            Some(1),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");
        let triage = campaign_triage_report_for_suite(
            &suite,
            "./scripts/e2e/metamorphic_suite_replay.sh ci",
        );

        let first = repro_governance_actions_from_triage(&triage);
        let second = repro_governance_actions_from_triage(&triage);

        assert_eq!(first, second);
        assert_eq!(first.action_count, triage.findings.len());
        assert!(!first.actions.is_empty());
        assert!(
            first
                .actions
                .iter()
                .all(|action| action.bead_id.starts_with("bd-auto-"))
        );
        assert!(
            first
                .actions
                .iter()
                .all(|action| action.fingerprint.starts_with("sha256:"))
        );
    }

    #[test]
    fn repro_governance_actions_deduplicate_by_fingerprint() {
        let relation = SyntheticViolationRelation {
            spec: RelationSpec {
                id: "dedupe_governance_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "dedupe governance".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];
        let suite = run_suite(
            &relation_refs,
            &context,
            Some(1),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");
        let mut triage = campaign_triage_report_for_suite(
            &suite,
            "./scripts/e2e/metamorphic_suite_replay.sh ci",
        );
        triage.findings.push(
            triage
                .findings
                .first()
                .expect("triage should contain at least one finding")
                .clone(),
        );

        let actions = repro_governance_actions_from_triage(&triage);
        assert_eq!(triage.findings.len(), 2);
        assert_eq!(actions.action_count, 1);
        assert_eq!(actions.actions.len(), 1);
    }
}
