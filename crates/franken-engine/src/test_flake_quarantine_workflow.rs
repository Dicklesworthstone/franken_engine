//! FRX-20.5 deterministic flake detection, reproducer bundles, and quarantine workflow.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION: &str =
    "frx.flake-quarantine-workflow.contract.v1";
pub const FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION: &str = "frx.flake-quarantine-workflow.event.v1";
pub const FLAKE_WORKFLOW_FAILURE_CODE: &str = "FE-FRX-20-5-FLAKE-QUARANTINE-0001";
pub const FLAKE_WORKFLOW_COMPONENT: &str = "frx_flake_quarantine_workflow";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlakeSeverity {
    Warning,
    High,
}

impl FlakeSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::High => "high",
        }
    }
}

impl fmt::Display for FlakeSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuarantineAction {
    Observe,
    QuarantineImmediate,
}

impl QuarantineAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::QuarantineImmediate => "quarantine-immediate",
        }
    }
}

impl fmt::Display for QuarantineAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Active,
    Expired,
    Lifted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakePolicy {
    pub warning_flake_threshold_millionths: u32,
    pub high_flake_threshold_millionths: u32,
    pub quarantine_ttl_epochs: u32,
    pub max_flake_burden_millionths: u32,
    pub trend_stability_epsilon_millionths: u32,
}

impl Default for FlakePolicy {
    fn default() -> Self {
        Self {
            warning_flake_threshold_millionths: 50_000,
            high_flake_threshold_millionths: 300_000,
            quarantine_ttl_epochs: 3,
            max_flake_burden_millionths: 250_000,
            trend_stability_epsilon_millionths: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeRunRecord {
    pub run_id: String,
    pub epoch: u32,
    pub suite_kind: String,
    pub scenario_id: String,
    pub outcome: String,
    pub error_signature: Option<String>,
    pub replay_command_ci: String,
    pub replay_command_local: String,
    pub artifact_bundle_id: String,
    pub related_unit_suites: Vec<String>,
    pub root_cause_hypothesis_artifacts: Vec<String>,
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducerBundle {
    pub bundle_id: String,
    pub suite_kind: String,
    pub scenario_id: String,
    pub seed: u64,
    pub replay_command_ci: String,
    pub replay_command_local: String,
    pub artifact_bundle_ids: Vec<String>,
    pub run_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeClassification {
    pub suite_kind: String,
    pub scenario_id: String,
    pub pass_count: u32,
    pub fail_count: u32,
    pub flake_rate_millionths: u32,
    pub severity: FlakeSeverity,
    pub quarantine_action: QuarantineAction,
    pub dominant_error_signature: String,
    pub impacted_unit_suites: Vec<String>,
    pub root_cause_hypothesis_artifacts: Vec<String>,
    pub reproducer_bundle: ReproducerBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub suite_kind: String,
    pub scenario_id: String,
    pub owner: String,
    pub owner_bound: bool,
    pub opened_epoch: u32,
    pub expires_epoch: u32,
    pub status: QuarantineStatus,
    pub reason: String,
    pub linked_reproducer_bundle_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBurdenPoint {
    pub epoch: u32,
    pub total_cases: u32,
    pub flaky_cases: u32,
    pub high_severity_cases: u32,
    pub flake_burden_millionths: u32,
    pub high_severity_burden_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfidenceReport {
    pub latest_epoch: u32,
    pub flake_burden_millionths: u32,
    pub high_severity_flake_count: u32,
    pub trend_direction: TrendDirection,
    pub trend_delta_millionths: i64,
    pub per_epoch_burden: Vec<EpochBurdenPoint>,
    pub promotion_outcome: String,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeWorkflowEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub suite_kind: String,
    pub scenario_id: String,
    pub flake_rate_millionths: Option<u32>,
    pub replay_command_ci: String,
    pub replay_command_local: String,
    pub quarantine_owner: Option<String>,
    pub quarantine_expires_epoch: Option<u32>,
    pub impacted_unit_suites: Vec<String>,
    pub root_cause_hypothesis_artifacts: Vec<String>,
}

#[must_use]
pub fn classify_flakes(runs: &[FlakeRunRecord], policy: &FlakePolicy) -> Vec<FlakeClassification> {
    let mut grouped = BTreeMap::<(String, String), Vec<&FlakeRunRecord>>::new();
    for run in runs {
        grouped
            .entry((run.suite_kind.clone(), run.scenario_id.clone()))
            .or_default()
            .push(run);
    }

    let mut flakes = Vec::new();
    for ((suite_kind, scenario_id), mut entries) in grouped {
        entries.sort_by(|left, right| left.run_id.cmp(&right.run_id));

        let pass_count = entries
            .iter()
            .filter(|entry| entry.outcome == "pass")
            .count() as u32;
        let fail_count = entries
            .iter()
            .filter(|entry| entry.outcome == "fail")
            .count() as u32;

        if pass_count == 0 || fail_count == 0 {
            continue;
        }

        let total_runs = pass_count.saturating_add(fail_count).max(1);
        let flake_rate_millionths = pass_count
            .min(fail_count)
            .saturating_mul(1_000_000)
            .saturating_div(total_runs);

        if flake_rate_millionths < policy.warning_flake_threshold_millionths {
            continue;
        }

        let severity = if flake_rate_millionths >= policy.high_flake_threshold_millionths {
            FlakeSeverity::High
        } else {
            FlakeSeverity::Warning
        };

        let quarantine_action = match severity {
            FlakeSeverity::High => QuarantineAction::QuarantineImmediate,
            FlakeSeverity::Warning => QuarantineAction::Observe,
        };

        let impacted_unit_suites = unique_sorted(entries.iter().flat_map(|entry| {
            entry
                .related_unit_suites
                .iter()
                .map(std::string::String::as_str)
        }));
        let root_cause_hypothesis_artifacts = unique_sorted(entries.iter().flat_map(|entry| {
            entry
                .root_cause_hypothesis_artifacts
                .iter()
                .map(std::string::String::as_str)
        }));
        let reproducer_bundle = build_reproducer_bundle(&suite_kind, &scenario_id, &entries);

        flakes.push(FlakeClassification {
            suite_kind,
            scenario_id,
            pass_count,
            fail_count,
            flake_rate_millionths,
            severity,
            quarantine_action,
            dominant_error_signature: dominant_error_signature(&entries),
            impacted_unit_suites,
            root_cause_hypothesis_artifacts,
            reproducer_bundle,
        });
    }

    flakes
}

#[must_use]
pub fn build_quarantine_records(
    classifications: &[FlakeClassification],
    owners: &BTreeMap<String, String>,
    current_epoch: u32,
    policy: &FlakePolicy,
) -> Vec<QuarantineRecord> {
    let ttl = policy.quarantine_ttl_epochs.max(1);
    let mut records = Vec::new();

    for flake in classifications
        .iter()
        .filter(|flake| flake.severity == FlakeSeverity::High)
    {
        let case_id = case_key(&flake.suite_kind, &flake.scenario_id);
        let owner = owners
            .get(&case_id)
            .or_else(|| owners.get(&flake.scenario_id))
            .map_or_else(
                || "unassigned".to_string(),
                |value| value.trim().to_string(),
            );
        let owner_bound = !owner.is_empty() && owner != "unassigned";

        records.push(QuarantineRecord {
            suite_kind: flake.suite_kind.clone(),
            scenario_id: flake.scenario_id.clone(),
            owner,
            owner_bound,
            opened_epoch: current_epoch,
            expires_epoch: current_epoch.saturating_add(ttl),
            status: QuarantineStatus::Active,
            reason: format!(
                "high_flake_rate:{}",
                case_key(&flake.suite_kind, &flake.scenario_id)
            ),
            linked_reproducer_bundle_id: flake.reproducer_bundle.bundle_id.clone(),
        });
    }

    records
}

#[must_use]
pub fn validate_quarantine_records(
    records: &[QuarantineRecord],
    current_epoch: u32,
) -> Vec<String> {
    let mut violations = Vec::new();
    for record in records {
        if !record.owner_bound {
            violations.push(format!(
                "missing_owner_binding:{}",
                case_key(&record.suite_kind, &record.scenario_id)
            ));
        }
        if record.expires_epoch <= record.opened_epoch {
            violations.push(format!(
                "non_expiring_quarantine:{}",
                case_key(&record.suite_kind, &record.scenario_id)
            ));
        }
        if record.status == QuarantineStatus::Active && record.expires_epoch <= current_epoch {
            violations.push(format!(
                "expired_active_quarantine:{}",
                case_key(&record.suite_kind, &record.scenario_id)
            ));
        }
    }
    violations
}

#[must_use]
pub fn validate_reproducer_replay_commands(classifications: &[FlakeClassification]) -> Vec<String> {
    let mut violations = Vec::new();

    for flake in classifications {
        let case_id = case_key(&flake.suite_kind, &flake.scenario_id);
        let bundle = &flake.reproducer_bundle;

        let replay_ci = bundle.replay_command_ci.trim();
        if replay_ci.is_empty() {
            violations.push(format!("missing_ci_replay_command:{case_id}"));
        } else if !is_valid_ci_replay_command(replay_ci) {
            violations.push(format!("invalid_ci_replay_command:{case_id}"));
        }

        let replay_local = bundle.replay_command_local.trim();
        if replay_local.is_empty() {
            violations.push(format!("missing_local_replay_command:{case_id}"));
        } else if !is_valid_local_replay_command(replay_local) {
            violations.push(format!("invalid_local_replay_command:{case_id}"));
        }

        if bundle.run_ids.is_empty() {
            violations.push(format!("missing_reproducer_run_ids:{case_id}"));
        }
        if bundle.artifact_bundle_ids.is_empty() {
            violations.push(format!("missing_reproducer_artifact_ids:{case_id}"));
        }
    }

    violations
}

#[must_use]
pub fn validate_flake_linkage(classifications: &[FlakeClassification]) -> Vec<String> {
    let mut violations = Vec::new();

    for flake in classifications {
        let case_id = case_key(&flake.suite_kind, &flake.scenario_id);

        if flake.impacted_unit_suites.is_empty() {
            violations.push(format!("missing_impacted_unit_suite_links:{case_id}"));
        }
        if flake.root_cause_hypothesis_artifacts.is_empty() {
            violations.push(format!("missing_root_cause_hypothesis_artifacts:{case_id}"));
        }

        let impacted_unique = flake
            .impacted_unit_suites
            .iter()
            .map(std::string::String::as_str)
            .collect::<BTreeSet<_>>();
        if impacted_unique.len() != flake.impacted_unit_suites.len() {
            violations.push(format!("duplicate_impacted_unit_suite_links:{case_id}"));
        }

        let root_cause_unique = flake
            .root_cause_hypothesis_artifacts
            .iter()
            .map(std::string::String::as_str)
            .collect::<BTreeSet<_>>();
        if root_cause_unique.len() != flake.root_cause_hypothesis_artifacts.len() {
            violations.push(format!(
                "duplicate_root_cause_hypothesis_artifacts:{case_id}"
            ));
        }
    }

    violations
}

#[must_use]
pub fn validate_structured_event_contract(events: &[FlakeWorkflowEvent]) -> Vec<String> {
    let mut violations = Vec::new();

    for event in events {
        let case_id = case_key(&event.suite_kind, &event.scenario_id);

        if event.schema_version != FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION {
            violations.push(format!("invalid_event_schema_version:{case_id}"));
        }
        if event.trace_id.trim().is_empty() {
            violations.push(format!("missing_trace_id:{case_id}"));
        }
        if event.decision_id.trim().is_empty() {
            violations.push(format!("missing_decision_id:{case_id}"));
        }
        if event.policy_id.trim().is_empty() {
            violations.push(format!("missing_policy_id:{case_id}"));
        }
        if event.component.trim().is_empty() {
            violations.push(format!("missing_component:{case_id}"));
        }
        if event.event.trim().is_empty() {
            violations.push(format!("missing_event_name:{case_id}"));
        }
        if event.outcome.trim().is_empty() {
            violations.push(format!("missing_outcome:{case_id}"));
        }

        let replay_ci = event.replay_command_ci.trim();
        let allow_script_ci = event.event == "gate_confidence_evaluated";
        if replay_ci.is_empty() {
            violations.push(format!("missing_event_replay_command_ci:{case_id}"));
        } else if !(is_valid_ci_replay_command(replay_ci)
            || (allow_script_ci && is_replay_test_command(replay_ci)))
        {
            violations.push(format!("invalid_event_replay_command_ci:{case_id}"));
        }

        let replay_local = event.replay_command_local.trim();
        if replay_local.is_empty() {
            violations.push(format!("missing_event_replay_command_local:{case_id}"));
        } else if !is_valid_local_replay_command(replay_local) {
            violations.push(format!("invalid_event_replay_command_local:{case_id}"));
        }

        if event.event == "flake_classified" {
            if event.impacted_unit_suites.is_empty() {
                violations.push(format!("missing_event_impacted_unit_suite_links:{case_id}"));
            }
            if event.root_cause_hypothesis_artifacts.is_empty() {
                violations.push(format!(
                    "missing_event_root_cause_hypothesis_artifacts:{case_id}"
                ));
            }
        }
    }

    violations
}

#[must_use]
pub fn evaluate_gate_confidence(
    runs: &[FlakeRunRecord],
    classifications: &[FlakeClassification],
    policy: &FlakePolicy,
) -> GateConfidenceReport {
    let per_epoch_burden = compute_epoch_burden_points(runs, policy);
    let latest = per_epoch_burden
        .last()
        .cloned()
        .unwrap_or(EpochBurdenPoint {
            epoch: 0,
            total_cases: 0,
            flaky_cases: 0,
            high_severity_cases: 0,
            flake_burden_millionths: 0,
            high_severity_burden_millionths: 0,
        });
    let previous_burden = per_epoch_burden
        .iter()
        .rev()
        .nth(1)
        .map_or(latest.flake_burden_millionths, |point| {
            point.flake_burden_millionths
        });
    let trend_delta_millionths =
        i64::from(latest.flake_burden_millionths) - i64::from(previous_burden);
    let trend_direction = if trend_delta_millionths.unsigned_abs()
        <= u64::from(policy.trend_stability_epsilon_millionths)
    {
        TrendDirection::Stable
    } else if trend_delta_millionths < 0 {
        TrendDirection::Improving
    } else {
        TrendDirection::Degrading
    };

    let mut blockers = classifications
        .iter()
        .filter(|flake| flake.severity == FlakeSeverity::High)
        .map(|flake| {
            format!(
                "high_flake_rate:{}",
                case_key(&flake.suite_kind, &flake.scenario_id)
            )
        })
        .collect::<Vec<_>>();

    if latest.flake_burden_millionths > policy.max_flake_burden_millionths {
        blockers.push(format!(
            "flake_burden_exceeds_budget:{}",
            latest.flake_burden_millionths
        ));
    }

    blockers.sort();
    blockers.dedup();

    let promotion_outcome = if blockers.is_empty() {
        "promote"
    } else {
        "hold"
    };

    GateConfidenceReport {
        latest_epoch: latest.epoch,
        flake_burden_millionths: latest.flake_burden_millionths,
        high_severity_flake_count: classifications
            .iter()
            .filter(|flake| flake.severity == FlakeSeverity::High)
            .count() as u32,
        trend_direction,
        trend_delta_millionths,
        per_epoch_burden,
        promotion_outcome: promotion_outcome.to_string(),
        blockers,
    }
}

#[must_use]
pub fn emit_structured_events(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    classifications: &[FlakeClassification],
    quarantines: &[QuarantineRecord],
    report: &GateConfidenceReport,
) -> Vec<FlakeWorkflowEvent> {
    let quarantine_index = quarantines
        .iter()
        .map(|record| (case_key(&record.suite_kind, &record.scenario_id), record))
        .collect::<BTreeMap<_, _>>();

    let mut events = Vec::new();
    for flake in classifications {
        let key = case_key(&flake.suite_kind, &flake.scenario_id);
        let quarantine = quarantine_index.get(&key).copied();
        events.push(FlakeWorkflowEvent {
            schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: format!("{decision_id}-{key}"),
            policy_id: policy_id.to_string(),
            component: FLAKE_WORKFLOW_COMPONENT.to_string(),
            event: "flake_classified".to_string(),
            outcome: flake.severity.as_str().to_string(),
            error_code: (flake.severity == FlakeSeverity::High)
                .then(|| FLAKE_WORKFLOW_FAILURE_CODE.to_string()),
            suite_kind: flake.suite_kind.clone(),
            scenario_id: flake.scenario_id.clone(),
            flake_rate_millionths: Some(flake.flake_rate_millionths),
            replay_command_ci: flake.reproducer_bundle.replay_command_ci.clone(),
            replay_command_local: flake.reproducer_bundle.replay_command_local.clone(),
            quarantine_owner: quarantine.map(|record| record.owner.clone()),
            quarantine_expires_epoch: quarantine.map(|record| record.expires_epoch),
            impacted_unit_suites: flake.impacted_unit_suites.clone(),
            root_cause_hypothesis_artifacts: flake.root_cause_hypothesis_artifacts.clone(),
        });
    }

    events.push(FlakeWorkflowEvent {
        schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: FLAKE_WORKFLOW_COMPONENT.to_string(),
        event: "gate_confidence_evaluated".to_string(),
        outcome: report.promotion_outcome.clone(),
        error_code: (report.promotion_outcome == "hold")
            .then(|| FLAKE_WORKFLOW_FAILURE_CODE.to_string()),
        suite_kind: "gate".to_string(),
        scenario_id: "__gate__".to_string(),
        flake_rate_millionths: Some(report.flake_burden_millionths),
        replay_command_ci: "scripts/run_frx_flake_quarantine_workflow_suite.sh ci".to_string(),
        replay_command_local: "scripts/e2e/frx_flake_quarantine_workflow_replay.sh".to_string(),
        quarantine_owner: None,
        quarantine_expires_epoch: None,
        impacted_unit_suites: Vec::new(),
        root_cause_hypothesis_artifacts: report.blockers.clone(),
    });

    events
}

fn compute_epoch_burden_points(
    runs: &[FlakeRunRecord],
    policy: &FlakePolicy,
) -> Vec<EpochBurdenPoint> {
    let mut by_epoch = BTreeMap::<u32, Vec<FlakeRunRecord>>::new();
    for run in runs {
        by_epoch.entry(run.epoch).or_default().push(run.clone());
    }

    let mut points = Vec::new();
    for (epoch, epoch_runs) in by_epoch {
        let total_cases = epoch_runs
            .iter()
            .map(|run| case_key(&run.suite_kind, &run.scenario_id))
            .collect::<BTreeSet<_>>()
            .len() as u32;
        let classifications = classify_flakes(&epoch_runs, policy);
        let flaky_cases = classifications.len() as u32;
        let high_severity_cases = classifications
            .iter()
            .filter(|flake| flake.severity == FlakeSeverity::High)
            .count() as u32;
        let denominator = total_cases.max(1);
        points.push(EpochBurdenPoint {
            epoch,
            total_cases,
            flaky_cases,
            high_severity_cases,
            flake_burden_millionths: flaky_cases
                .saturating_mul(1_000_000)
                .saturating_div(denominator),
            high_severity_burden_millionths: high_severity_cases
                .saturating_mul(1_000_000)
                .saturating_div(denominator),
        });
    }

    points
}

fn dominant_error_signature(entries: &[&FlakeRunRecord]) -> String {
    let mut counts = BTreeMap::<String, u32>::new();
    for entry in entries {
        if entry.outcome == "fail"
            && let Some(signature) = entry.error_signature.as_ref()
        {
            *counts.entry(signature.clone()).or_default() += 1;
        }
    }

    counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
        .map_or_else(|| "none".to_string(), |(signature, _)| signature)
}

fn build_reproducer_bundle(
    suite_kind: &str,
    scenario_id: &str,
    entries: &[&FlakeRunRecord],
) -> ReproducerBundle {
    let run_ids = unique_sorted(entries.iter().map(|entry| entry.run_id.as_str()));
    let artifact_bundle_ids = unique_sorted(
        entries
            .iter()
            .map(|entry| entry.artifact_bundle_id.as_str()),
    );
    let replay_command_ci = entries
        .iter()
        .map(|entry| entry.replay_command_ci.as_str())
        .min()
        .map_or_else(String::new, ToString::to_string);
    let replay_command_local = entries
        .iter()
        .map(|entry| entry.replay_command_local.as_str())
        .min()
        .map_or_else(String::new, ToString::to_string);
    let seed = entries.iter().map(|entry| entry.seed).min().unwrap_or(0);

    let bundle_id = derive_bundle_id(
        suite_kind,
        scenario_id,
        seed,
        &run_ids,
        &artifact_bundle_ids,
        &replay_command_ci,
        &replay_command_local,
    );

    ReproducerBundle {
        bundle_id,
        suite_kind: suite_kind.to_string(),
        scenario_id: scenario_id.to_string(),
        seed,
        replay_command_ci,
        replay_command_local,
        artifact_bundle_ids,
        run_ids,
    }
}

fn derive_bundle_id(
    suite_kind: &str,
    scenario_id: &str,
    seed: u64,
    run_ids: &[String],
    artifact_bundle_ids: &[String],
    replay_command_ci: &str,
    replay_command_local: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(suite_kind.as_bytes());
    hasher.update([0]);
    hasher.update(scenario_id.as_bytes());
    hasher.update([0]);
    hasher.update(seed.to_be_bytes());
    hasher.update([0]);
    for run_id in run_ids {
        hasher.update(run_id.as_bytes());
        hasher.update([0]);
    }
    for artifact_id in artifact_bundle_ids {
        hasher.update(artifact_id.as_bytes());
        hasher.update([0]);
    }
    hasher.update(replay_command_ci.as_bytes());
    hasher.update([0]);
    hasher.update(replay_command_local.as_bytes());
    let digest = hasher.finalize();
    format!("flake-repro-{}", hex::encode(&digest[..12]))
}

fn unique_sorted<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
}

fn case_key(suite_kind: &str, scenario_id: &str) -> String {
    format!("{suite_kind}::{scenario_id}")
}

fn is_replay_test_command(command: &str) -> bool {
    command.contains("cargo test") || command.ends_with(".sh") || command.contains(".sh ")
}

fn is_valid_ci_replay_command(command: &str) -> bool {
    (command.starts_with("rch exec")
        || command.contains(" rch exec ")
        || command.contains(";rch exec ")
        || command.contains("&&rch exec ")
        || command.contains("||rch exec "))
        && is_replay_test_command(command)
}

fn is_valid_local_replay_command(command: &str) -> bool {
    !command.contains("rch exec") && is_replay_test_command(command)
}

#[cfg(test)]
mod tests {
    use super::{
        EpochBurdenPoint, FLAKE_WORKFLOW_COMPONENT, FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION,
        FlakeClassification, FlakePolicy, FlakeRunRecord, FlakeSeverity, FlakeWorkflowEvent,
        GateConfidenceReport, QuarantineAction, QuarantineRecord, QuarantineStatus,
        ReproducerBundle, TrendDirection, build_quarantine_records, classify_flakes,
        emit_structured_events, evaluate_gate_confidence, validate_flake_linkage,
        validate_quarantine_records, validate_reproducer_replay_commands,
        validate_structured_event_contract,
    };
    use std::collections::BTreeMap;

    fn sample_runs() -> Vec<FlakeRunRecord> {
        vec![
            FlakeRunRecord {
                run_id: "run-001".to_string(),
                epoch: 1,
                suite_kind: "e2e".to_string(),
                scenario_id: "scenario-hydration".to_string(),
                outcome: "pass".to_string(),
                error_signature: None,
                replay_command_ci: "rch exec -- cargo test --test frx_hydration".to_string(),
                replay_command_local: "cargo test --test frx_hydration".to_string(),
                artifact_bundle_id: "bundle-a".to_string(),
                related_unit_suites: vec!["unit-hydration".to_string()],
                root_cause_hypothesis_artifacts: vec!["hypothesis-hydration-a".to_string()],
                seed: 11,
            },
            FlakeRunRecord {
                run_id: "run-002".to_string(),
                epoch: 1,
                suite_kind: "e2e".to_string(),
                scenario_id: "scenario-hydration".to_string(),
                outcome: "fail".to_string(),
                error_signature: Some("panic:hydration-mismatch".to_string()),
                replay_command_ci: "rch exec -- cargo test --test frx_hydration".to_string(),
                replay_command_local: "cargo test --test frx_hydration".to_string(),
                artifact_bundle_id: "bundle-b".to_string(),
                related_unit_suites: vec!["unit-hydration".to_string(), "unit-router".to_string()],
                root_cause_hypothesis_artifacts: vec!["hypothesis-hydration-b".to_string()],
                seed: 11,
            },
            FlakeRunRecord {
                run_id: "run-101".to_string(),
                epoch: 2,
                suite_kind: "e2e".to_string(),
                scenario_id: "scenario-hydration".to_string(),
                outcome: "fail".to_string(),
                error_signature: Some("panic:hydration-mismatch".to_string()),
                replay_command_ci: "rch exec -- cargo test --test frx_hydration".to_string(),
                replay_command_local: "cargo test --test frx_hydration".to_string(),
                artifact_bundle_id: "bundle-c".to_string(),
                related_unit_suites: vec!["unit-hydration".to_string()],
                root_cause_hypothesis_artifacts: vec!["hypothesis-hydration-b".to_string()],
                seed: 11,
            },
            FlakeRunRecord {
                run_id: "run-102".to_string(),
                epoch: 2,
                suite_kind: "e2e".to_string(),
                scenario_id: "scenario-hydration".to_string(),
                outcome: "pass".to_string(),
                error_signature: None,
                replay_command_ci: "rch exec -- cargo test --test frx_hydration".to_string(),
                replay_command_local: "cargo test --test frx_hydration".to_string(),
                artifact_bundle_id: "bundle-d".to_string(),
                related_unit_suites: vec!["unit-hydration".to_string()],
                root_cause_hypothesis_artifacts: vec!["hypothesis-hydration-b".to_string()],
                seed: 11,
            },
        ]
    }

    #[test]
    fn classifications_are_deterministic_and_emit_reproducer_bundle() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let first = classify_flakes(&runs, &policy);
        let second = classify_flakes(&runs, &policy);
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        let flake = &first[0];
        assert_eq!(flake.severity, FlakeSeverity::High);
        assert!(
            flake
                .reproducer_bundle
                .bundle_id
                .starts_with("flake-repro-")
        );
        assert!(!flake.reproducer_bundle.replay_command_ci.is_empty());
        assert!(!flake.reproducer_bundle.replay_command_local.is_empty());
    }

    #[test]
    fn reproducer_replay_commands_meet_ci_replay_contract() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let classifications = classify_flakes(&sample_runs(), &policy);
        let violations = validate_reproducer_replay_commands(&classifications);
        assert!(
            violations.is_empty(),
            "expected valid replay commands for CI/local deterministic replay: {violations:?}"
        );
    }

    #[test]
    fn reproducer_replay_commands_detect_invalid_ci_and_local_shapes() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let mut classifications = classify_flakes(&sample_runs(), &policy);
        let flake = classifications.first_mut().expect("flake classification");
        flake.reproducer_bundle.replay_command_ci =
            "cargo test --test frx_hydration -- hydration_case --exact".to_string();
        flake.reproducer_bundle.replay_command_local =
            "rch exec -- cargo test --test frx_hydration -- hydration_case --exact".to_string();
        flake.reproducer_bundle.run_ids.clear();
        flake.reproducer_bundle.artifact_bundle_ids.clear();

        let violations = validate_reproducer_replay_commands(&classifications);
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("invalid_ci_replay_command:")),
            "expected CI replay command violation: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("invalid_local_replay_command:")),
            "expected local replay command violation: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("missing_reproducer_run_ids:")),
            "expected missing run id violation: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("missing_reproducer_artifact_ids:")),
            "expected missing artifact id violation: {violations:?}"
        );
    }

    #[test]
    fn flake_linkage_validator_accepts_non_empty_unique_links() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let classifications = classify_flakes(&sample_runs(), &policy);
        let violations = validate_flake_linkage(&classifications);
        assert!(
            violations.is_empty(),
            "expected valid linkage for impacted suites and root-cause artifacts: {violations:?}"
        );
    }

    #[test]
    fn flake_linkage_validator_detects_missing_and_duplicate_links() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let mut classifications = classify_flakes(&sample_runs(), &policy);
        let flake = classifications.first_mut().expect("flake classification");
        flake.impacted_unit_suites =
            vec!["unit-hydration".to_string(), "unit-hydration".to_string()];
        flake.root_cause_hypothesis_artifacts.clear();

        let violations = validate_flake_linkage(&classifications);
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("duplicate_impacted_unit_suite_links:")),
            "expected duplicate impacted-suite violation: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("missing_root_cause_hypothesis_artifacts:")),
            "expected missing root-cause artifact violation: {violations:?}"
        );
    }

    #[test]
    fn structured_event_contract_validator_accepts_well_formed_events() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let classifications = classify_flakes(&runs, &policy);
        let mut owners = BTreeMap::new();
        owners.insert(
            "e2e::scenario-hydration".to_string(),
            "quality-oncall".to_string(),
        );
        let quarantines = build_quarantine_records(&classifications, &owners, 7, &policy);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        let events = emit_structured_events(
            "trace-frx-20-5",
            "decision-frx-20-5",
            "policy-frx-20-5-v1",
            &classifications,
            &quarantines,
            &report,
        );
        let violations = validate_structured_event_contract(&events);
        assert!(
            violations.is_empty(),
            "expected valid structured-event contract: {violations:?}"
        );
    }

    #[test]
    fn structured_event_contract_validator_detects_invalid_replay_and_linkage() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let classifications = classify_flakes(&runs, &policy);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        let mut events = emit_structured_events(
            "trace-frx-20-5",
            "decision-frx-20-5",
            "policy-frx-20-5-v1",
            &classifications,
            &[],
            &report,
        );
        let flake_event = events
            .iter_mut()
            .find(|event| event.event == "flake_classified")
            .expect("flake event");
        flake_event.replay_command_ci = "cargo test --test frx_hydration".to_string();
        flake_event.replay_command_local =
            "rch exec -- cargo test --test frx_hydration".to_string();
        flake_event.impacted_unit_suites.clear();
        flake_event.root_cause_hypothesis_artifacts.clear();

        let violations = validate_structured_event_contract(&events);
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("invalid_event_replay_command_ci:")),
            "expected invalid CI replay violation: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("invalid_event_replay_command_local:")),
            "expected invalid local replay violation: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|value| value.starts_with("missing_event_impacted_unit_suite_links:")),
            "expected missing impacted-suite linkage violation: {violations:?}"
        );
        assert!(
            violations.iter().any(|value| {
                value.starts_with("missing_event_root_cause_hypothesis_artifacts:")
            }),
            "expected missing root-cause linkage violation: {violations:?}"
        );
    }

    #[test]
    fn quarantine_records_require_owner_and_expiry() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            quarantine_ttl_epochs: 2,
            ..FlakePolicy::default()
        };
        let classifications = classify_flakes(&sample_runs(), &policy);
        let mut owners = BTreeMap::new();
        owners.insert(
            "e2e::scenario-hydration".to_string(),
            "quality-oncall".to_string(),
        );
        let quarantines = build_quarantine_records(&classifications, &owners, 7, &policy);
        assert_eq!(quarantines.len(), 1);
        assert!(quarantines[0].owner_bound);
        assert_eq!(quarantines[0].opened_epoch, 7);
        assert_eq!(quarantines[0].expires_epoch, 9);
        assert!(validate_quarantine_records(&quarantines, 7).is_empty());
    }

    #[test]
    fn gate_confidence_reports_trend_and_blockers() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            max_flake_burden_millionths: 200_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let classifications = classify_flakes(&runs, &policy);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        assert_eq!(report.latest_epoch, 2);
        assert!(!report.per_epoch_burden.is_empty());
        assert_eq!(report.promotion_outcome, "hold");
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("high_flake_rate"))
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: FlakeSeverity Display + as_str
    // -----------------------------------------------------------------------

    #[test]
    fn flake_severity_display_warning() {
        assert_eq!(FlakeSeverity::Warning.to_string(), "warning");
        assert_eq!(FlakeSeverity::Warning.as_str(), "warning");
    }

    #[test]
    fn flake_severity_display_high() {
        assert_eq!(FlakeSeverity::High.to_string(), "high");
        assert_eq!(FlakeSeverity::High.as_str(), "high");
    }

    #[test]
    fn flake_severity_as_str_matches_display() {
        for s in [FlakeSeverity::Warning, FlakeSeverity::High] {
            assert_eq!(s.as_str(), s.to_string());
        }
    }

    #[test]
    fn flake_severity_serde_roundtrip() {
        for s in [FlakeSeverity::Warning, FlakeSeverity::High] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let back: FlakeSeverity =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(s, back);
        }
    }

    #[test]
    fn flake_severity_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&FlakeSeverity::Warning)
                .expect("serde deserialization should succeed"),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&FlakeSeverity::High)
                .expect("serde deserialization should succeed"),
            "\"high\""
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: QuarantineAction Display + as_str + serde
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_action_display() {
        assert_eq!(super::QuarantineAction::Observe.to_string(), "observe");
        assert_eq!(
            super::QuarantineAction::QuarantineImmediate.to_string(),
            "quarantine-immediate"
        );
    }

    #[test]
    fn quarantine_action_as_str_matches_display() {
        for a in [
            super::QuarantineAction::Observe,
            super::QuarantineAction::QuarantineImmediate,
        ] {
            assert_eq!(a.as_str(), a.to_string());
        }
    }

    #[test]
    fn quarantine_action_serde_roundtrip() {
        for a in [
            super::QuarantineAction::Observe,
            super::QuarantineAction::QuarantineImmediate,
        ] {
            let json = serde_json::to_string(&a).expect("serde deserialization should succeed");
            let back: super::QuarantineAction =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(a, back);
        }
    }

    #[test]
    fn quarantine_action_serde_kebab_case() {
        assert_eq!(
            serde_json::to_string(&super::QuarantineAction::Observe)
                .expect("serde deserialization should succeed"),
            "\"observe\""
        );
        assert_eq!(
            serde_json::to_string(&super::QuarantineAction::QuarantineImmediate)
                .expect("serde deserialization should succeed"),
            "\"quarantine-immediate\""
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: QuarantineStatus serde
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_status_serde_roundtrip() {
        for s in [
            super::QuarantineStatus::Active,
            super::QuarantineStatus::Expired,
            super::QuarantineStatus::Lifted,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let back: super::QuarantineStatus =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(s, back);
        }
    }

    #[test]
    fn quarantine_status_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&super::QuarantineStatus::Active)
                .expect("serde deserialization should succeed"),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&super::QuarantineStatus::Expired)
                .expect("serde deserialization should succeed"),
            "\"expired\""
        );
        assert_eq!(
            serde_json::to_string(&super::QuarantineStatus::Lifted)
                .expect("serde deserialization should succeed"),
            "\"lifted\""
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: TrendDirection serde
    // -----------------------------------------------------------------------

    #[test]
    fn trend_direction_serde_roundtrip() {
        for d in [
            super::TrendDirection::Improving,
            super::TrendDirection::Stable,
            super::TrendDirection::Degrading,
        ] {
            let json = serde_json::to_string(&d).expect("serde deserialization should succeed");
            let back: super::TrendDirection =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(d, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: FlakePolicy serde + default
    // -----------------------------------------------------------------------

    #[test]
    fn flake_policy_default_thresholds() {
        let p = FlakePolicy::default();
        assert_eq!(p.warning_flake_threshold_millionths, 50_000);
        assert_eq!(p.high_flake_threshold_millionths, 300_000);
        assert_eq!(p.quarantine_ttl_epochs, 3);
        assert!(p.warning_flake_threshold_millionths < p.high_flake_threshold_millionths);
    }

    #[test]
    fn flake_policy_serde_roundtrip() {
        let p = FlakePolicy::default();
        let json = serde_json::to_string(&p).expect("serde deserialization should succeed");
        let back: FlakePolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(p, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: classify_flakes edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn classify_flakes_empty_runs() {
        let classifications = classify_flakes(&[], &FlakePolicy::default());
        assert!(classifications.is_empty());
    }

    #[test]
    fn classify_flakes_all_pass_no_flakes() {
        let runs = vec![FlakeRunRecord {
            run_id: "r1".into(),
            epoch: 1,
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            outcome: "pass".into(),
            error_signature: None,
            replay_command_ci: "ci cmd".into(),
            replay_command_local: "local cmd".into(),
            artifact_bundle_id: "b1".into(),
            related_unit_suites: vec![],
            root_cause_hypothesis_artifacts: vec![],
            seed: 42,
        }];
        let classifications = classify_flakes(&runs, &FlakePolicy::default());
        assert!(classifications.is_empty());
    }

    #[test]
    fn classify_flakes_all_fail_no_flakes() {
        let runs = vec![FlakeRunRecord {
            run_id: "r1".into(),
            epoch: 1,
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            outcome: "fail".into(),
            error_signature: Some("panic:err".into()),
            replay_command_ci: "ci".into(),
            replay_command_local: "local".into(),
            artifact_bundle_id: "b1".into(),
            related_unit_suites: vec![],
            root_cause_hypothesis_artifacts: vec![],
            seed: 42,
        }];
        let classifications = classify_flakes(&runs, &FlakePolicy::default());
        assert!(classifications.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: FlakeRunRecord serde
    // -----------------------------------------------------------------------

    #[test]
    fn flake_run_record_serde_roundtrip() {
        let rec = FlakeRunRecord {
            run_id: "r1".into(),
            epoch: 5,
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            outcome: "fail".into(),
            error_signature: Some("sig".into()),
            replay_command_ci: "ci cmd".into(),
            replay_command_local: "local cmd".into(),
            artifact_bundle_id: "b1".into(),
            related_unit_suites: vec!["unit-a".into()],
            root_cause_hypothesis_artifacts: vec!["h1".into()],
            seed: 42,
        };
        let json = serde_json::to_string(&rec).expect("serde deserialization should succeed");
        let back: FlakeRunRecord =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(rec, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: validate_quarantine_records violations
    // -----------------------------------------------------------------------

    #[test]
    fn validate_quarantine_records_missing_owner() {
        let records = vec![super::QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            owner: String::new(),
            owner_bound: false,
            opened_epoch: 1,
            expires_epoch: 4,
            status: super::QuarantineStatus::Active,
            reason: "flaky".into(),
            linked_reproducer_bundle_id: "b1".into(),
        }];
        let violations = validate_quarantine_records(&records, 2);
        assert!(!violations.is_empty());
        assert!(violations[0].contains("missing_owner_binding"));
    }

    #[test]
    fn validate_quarantine_records_non_expiring() {
        let records = vec![super::QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            owner: "team-a".into(),
            owner_bound: true,
            opened_epoch: 5,
            expires_epoch: 5,
            status: super::QuarantineStatus::Active,
            reason: "flaky".into(),
            linked_reproducer_bundle_id: "b1".into(),
        }];
        let violations = validate_quarantine_records(&records, 3);
        assert!(!violations.is_empty());
    }

    #[test]
    fn validate_quarantine_records_valid_passes() {
        let records = vec![super::QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            owner: "team-a".into(),
            owner_bound: true,
            opened_epoch: 1,
            expires_epoch: 5,
            status: super::QuarantineStatus::Active,
            reason: "flaky".into(),
            linked_reproducer_bundle_id: "b1".into(),
        }];
        let violations = validate_quarantine_records(&records, 2);
        assert!(violations.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: evaluate_gate_confidence edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn gate_confidence_empty_runs_returns_default() {
        let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
        assert_eq!(report.latest_epoch, 0);
        assert_eq!(report.promotion_outcome, "promote");
        assert!(report.blockers.is_empty());
    }

    #[test]
    fn gate_confidence_no_flakes_promotes() {
        let runs = vec![FlakeRunRecord {
            run_id: "r1".into(),
            epoch: 1,
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            outcome: "pass".into(),
            error_signature: None,
            replay_command_ci: "ci".into(),
            replay_command_local: "local".into(),
            artifact_bundle_id: "b1".into(),
            related_unit_suites: vec![],
            root_cause_hypothesis_artifacts: vec![],
            seed: 42,
        }];
        let report = evaluate_gate_confidence(&runs, &[], &FlakePolicy::default());
        assert_eq!(report.promotion_outcome, "promote");
    }

    // -----------------------------------------------------------------------
    // Enrichment: FlakeWorkflowEvent serde
    // -----------------------------------------------------------------------

    #[test]
    fn flake_workflow_event_serde_roundtrip() {
        let evt = super::FlakeWorkflowEvent {
            schema_version: super::FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.into(),
            trace_id: "trace-1".into(),
            decision_id: "dec-1".into(),
            policy_id: "pol-1".into(),
            component: super::FLAKE_WORKFLOW_COMPONENT.into(),
            event: "flake_classified".into(),
            outcome: "quarantine-immediate".into(),
            error_code: Some(super::FLAKE_WORKFLOW_FAILURE_CODE.into()),
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            flake_rate_millionths: Some(500_000),
            replay_command_ci: "ci".into(),
            replay_command_local: "local".into(),
            quarantine_owner: Some("team-a".into()),
            quarantine_expires_epoch: Some(10),
            impacted_unit_suites: vec!["unit-a".into()],
            root_cause_hypothesis_artifacts: vec!["h1".into()],
        };
        let json = serde_json::to_string(&evt).expect("serde deserialization should succeed");
        let back: super::FlakeWorkflowEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(evt, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GateConfidenceReport serde
    // -----------------------------------------------------------------------

    #[test]
    fn gate_confidence_report_serde_roundtrip() {
        let report = super::GateConfidenceReport {
            latest_epoch: 5,
            flake_burden_millionths: 100_000,
            high_severity_flake_count: 2,
            trend_direction: super::TrendDirection::Degrading,
            trend_delta_millionths: 50_000,
            per_epoch_burden: vec![super::EpochBurdenPoint {
                epoch: 5,
                total_cases: 10,
                flaky_cases: 3,
                high_severity_cases: 1,
                flake_burden_millionths: 300_000,
                high_severity_burden_millionths: 100_000,
            }],
            promotion_outcome: "hold".into(),
            blockers: vec!["high_flake_rate: e2e/sc-1".into()],
        };
        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let back: super::GateConfidenceReport =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(report, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: QuarantineRecord serde
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_record_serde_roundtrip() {
        let rec = super::QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            owner: "team-a".into(),
            owner_bound: true,
            opened_epoch: 1,
            expires_epoch: 4,
            status: super::QuarantineStatus::Active,
            reason: "flaky test".into(),
            linked_reproducer_bundle_id: "b1".into(),
        };
        let json = serde_json::to_string(&rec).expect("serde deserialization should succeed");
        let back: super::QuarantineRecord =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(rec, back);
    }

    // ── Enrichment batch 2 ────────────────────────────────────────────

    #[test]
    fn constants_have_expected_values() {
        assert!(super::FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION.contains("v1"));
        assert!(super::FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.contains("v1"));
        assert!(super::FLAKE_WORKFLOW_FAILURE_CODE.starts_with("FE-FRX-"));
        assert_eq!(
            super::FLAKE_WORKFLOW_COMPONENT,
            "frx_flake_quarantine_workflow"
        );
    }

    #[test]
    fn case_key_format() {
        assert_eq!(super::case_key("e2e", "sc-1"), "e2e::sc-1");
        assert_eq!(super::case_key("unit", "auth"), "unit::auth");
    }

    #[test]
    fn unique_sorted_deduplicates_and_sorts() {
        let items = vec!["c", "a", "b", "a", "c"];
        let result = super::unique_sorted(items.into_iter());
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn unique_sorted_filters_empty_and_whitespace() {
        let items = vec!["a", "", "  ", "b"];
        let result = super::unique_sorted(items.into_iter());
        assert_eq!(result, vec!["a", "b"]);
    }

    #[test]
    fn dominant_error_signature_picks_most_frequent() {
        let runs = sample_runs();
        let refs: Vec<&FlakeRunRecord> = runs.iter().collect();
        let sig = super::dominant_error_signature(&refs);
        assert_eq!(sig, "panic:hydration-mismatch");
    }

    #[test]
    fn dominant_error_signature_returns_none_for_no_errors() {
        let run = FlakeRunRecord {
            run_id: "r1".into(),
            epoch: 1,
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            outcome: "pass".into(),
            error_signature: None,
            replay_command_ci: "ci".into(),
            replay_command_local: "local".into(),
            artifact_bundle_id: "b1".into(),
            related_unit_suites: vec![],
            root_cause_hypothesis_artifacts: vec![],
            seed: 42,
        };
        let refs = vec![&run];
        let sig = super::dominant_error_signature(&refs);
        assert_eq!(sig, "none");
    }

    #[test]
    fn derive_bundle_id_is_deterministic() {
        let id1 = super::derive_bundle_id(
            "e2e",
            "sc-1",
            42,
            &["r1".into()],
            &["b1".into()],
            "ci",
            "local",
        );
        let id2 = super::derive_bundle_id(
            "e2e",
            "sc-1",
            42,
            &["r1".into()],
            &["b1".into()],
            "ci",
            "local",
        );
        assert_eq!(id1, id2);
        assert!(id1.starts_with("flake-repro-"));
    }

    #[test]
    fn derive_bundle_id_changes_with_seed() {
        let id1 = super::derive_bundle_id(
            "e2e",
            "sc-1",
            42,
            &["r1".into()],
            &["b1".into()],
            "ci",
            "local",
        );
        let id2 = super::derive_bundle_id(
            "e2e",
            "sc-1",
            99,
            &["r1".into()],
            &["b1".into()],
            "ci",
            "local",
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn classify_flakes_warning_severity() {
        // 2 pass, 1 fail → flake_rate = min(2,1)*1M/3 = 333_333
        // Warning threshold 50k, High threshold 400k → Warning
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 50_000,
            high_flake_threshold_millionths: 400_000,
            ..FlakePolicy::default()
        };
        let runs = vec![
            FlakeRunRecord {
                run_id: "r1".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-w".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b1".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 10,
            },
            FlakeRunRecord {
                run_id: "r2".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-w".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b2".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 10,
            },
            FlakeRunRecord {
                run_id: "r3".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-w".into(),
                outcome: "fail".into(),
                error_signature: Some("err".into()),
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b3".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 10,
            },
        ];
        let classifications = classify_flakes(&runs, &policy);
        assert_eq!(classifications.len(), 1);
        assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
        assert_eq!(
            classifications[0].quarantine_action,
            super::QuarantineAction::Observe
        );
    }

    #[test]
    fn build_quarantine_records_only_high_severity() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 50_000,
            high_flake_threshold_millionths: 400_000,
            ..FlakePolicy::default()
        };
        let runs = vec![
            FlakeRunRecord {
                run_id: "r1".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-w".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b1".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 10,
            },
            FlakeRunRecord {
                run_id: "r2".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-w".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b2".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 10,
            },
            FlakeRunRecord {
                run_id: "r3".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-w".into(),
                outcome: "fail".into(),
                error_signature: Some("err".into()),
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b3".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 10,
            },
        ];
        let classifications = classify_flakes(&runs, &policy);
        assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
        let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
        assert!(
            quarantines.is_empty(),
            "Warning-level flakes should not be quarantined"
        );
    }

    #[test]
    fn build_quarantine_records_unassigned_owner() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let classifications = classify_flakes(&sample_runs(), &policy);
        let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
        assert_eq!(quarantines.len(), 1);
        assert_eq!(quarantines[0].owner, "unassigned");
        assert!(!quarantines[0].owner_bound);
    }

    #[test]
    fn validate_quarantine_records_expired_active() {
        let records = vec![super::QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            owner: "team-a".into(),
            owner_bound: true,
            opened_epoch: 1,
            expires_epoch: 4,
            status: super::QuarantineStatus::Active,
            reason: "flaky".into(),
            linked_reproducer_bundle_id: "b1".into(),
        }];
        let violations = validate_quarantine_records(&records, 5);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("expired_active_quarantine"))
        );
    }

    #[test]
    fn validate_quarantine_records_lifted_not_expired() {
        let records = vec![super::QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            owner: "team-a".into(),
            owner_bound: true,
            opened_epoch: 1,
            expires_epoch: 4,
            status: super::QuarantineStatus::Lifted,
            reason: "fixed".into(),
            linked_reproducer_bundle_id: "b1".into(),
        }];
        let violations = validate_quarantine_records(&records, 10);
        assert!(
            !violations
                .iter()
                .any(|v| v.contains("expired_active_quarantine"))
        );
    }

    #[test]
    fn emit_structured_events_includes_gate_event() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let classifications = classify_flakes(&runs, &policy);
        let mut owners = BTreeMap::new();
        owners.insert("e2e::scenario-hydration".into(), "oncall".into());
        let quarantines = build_quarantine_records(&classifications, &owners, 1, &policy);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        let events = super::emit_structured_events(
            "trace-1",
            "dec-1",
            "pol-1",
            &classifications,
            &quarantines,
            &report,
        );
        assert_eq!(events.len(), classifications.len() + 1);
        let gate_event = events.last().expect("serde deserialization should succeed");
        assert_eq!(gate_event.event, "gate_confidence_evaluated");
        assert_eq!(gate_event.suite_kind, "gate");
        assert_eq!(gate_event.scenario_id, "__gate__");
    }

    #[test]
    fn emit_structured_events_classification_event_fields() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let classifications = classify_flakes(&runs, &policy);
        let mut owners = BTreeMap::new();
        owners.insert("e2e::scenario-hydration".into(), "oncall".into());
        let quarantines = build_quarantine_records(&classifications, &owners, 1, &policy);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        let events = super::emit_structured_events(
            "trace-1",
            "dec-1",
            "pol-1",
            &classifications,
            &quarantines,
            &report,
        );
        let first = &events[0];
        assert_eq!(first.event, "flake_classified");
        assert_eq!(
            first.schema_version,
            super::FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION
        );
        assert_eq!(first.component, super::FLAKE_WORKFLOW_COMPONENT);
        assert_eq!(first.trace_id, "trace-1");
        assert!(first.flake_rate_millionths.is_some());
        assert_eq!(
            first.error_code,
            Some(super::FLAKE_WORKFLOW_FAILURE_CODE.to_string())
        );
        assert_eq!(first.quarantine_owner, Some("oncall".to_string()));
        assert!(first.quarantine_expires_epoch.is_some());
    }

    #[test]
    fn emit_structured_events_warning_no_error_code() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 50_000,
            high_flake_threshold_millionths: 600_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let classifications = classify_flakes(&runs, &policy);
        assert!(!classifications.is_empty());
        assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        let events = super::emit_structured_events(
            "trace-1",
            "dec-1",
            "pol-1",
            &classifications,
            &[],
            &report,
        );
        let first = &events[0];
        assert_eq!(first.error_code, None);
    }

    #[test]
    fn gate_confidence_trend_stable_within_epsilon() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 900_000,
            trend_stability_epsilon_millionths: 10_000,
            ..FlakePolicy::default()
        };
        let runs = vec![
            FlakeRunRecord {
                run_id: "r1".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b1".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 1,
            },
            FlakeRunRecord {
                run_id: "r2".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                outcome: "fail".into(),
                error_signature: Some("e".into()),
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b2".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 1,
            },
            FlakeRunRecord {
                run_id: "r3".into(),
                epoch: 2,
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b3".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 1,
            },
            FlakeRunRecord {
                run_id: "r4".into(),
                epoch: 2,
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                outcome: "fail".into(),
                error_signature: Some("e".into()),
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b4".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 1,
            },
        ];
        let classifications = classify_flakes(&runs, &policy);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        assert_eq!(report.trend_direction, super::TrendDirection::Stable);
    }

    #[test]
    fn gate_confidence_burden_exceeds_budget_blocks() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 900_000,
            max_flake_burden_millionths: 0,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let classifications = classify_flakes(&runs, &policy);
        let report = evaluate_gate_confidence(&runs, &classifications, &policy);
        assert!(
            report
                .blockers
                .iter()
                .any(|b| b.contains("flake_burden_exceeds_budget"))
        );
        assert_eq!(report.promotion_outcome, "hold");
    }

    #[test]
    fn flake_classification_serde_roundtrip() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let classifications = classify_flakes(&sample_runs(), &policy);
        assert!(!classifications.is_empty());
        let json = serde_json::to_string(&classifications[0])
            .expect("serde deserialization should succeed");
        let back: super::FlakeClassification =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(classifications[0], back);
    }

    #[test]
    fn reproducer_bundle_serde_roundtrip() {
        let bundle = super::ReproducerBundle {
            bundle_id: "flake-repro-abc123".into(),
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            seed: 42,
            replay_command_ci: "ci cmd".into(),
            replay_command_local: "local cmd".into(),
            artifact_bundle_ids: vec!["b1".into()],
            run_ids: vec!["r1".into()],
        };
        let json = serde_json::to_string(&bundle).expect("serde deserialization should succeed");
        let back: super::ReproducerBundle =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(bundle, back);
    }

    #[test]
    fn epoch_burden_point_serde_roundtrip() {
        let point = super::EpochBurdenPoint {
            epoch: 3,
            total_cases: 10,
            flaky_cases: 2,
            high_severity_cases: 1,
            flake_burden_millionths: 200_000,
            high_severity_burden_millionths: 100_000,
        };
        let json = serde_json::to_string(&point).expect("serde deserialization should succeed");
        let back: super::EpochBurdenPoint =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(point, back);
    }

    #[test]
    fn compute_epoch_burden_points_multiple_epochs() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 900_000,
            ..FlakePolicy::default()
        };
        let runs = sample_runs();
        let points = super::compute_epoch_burden_points(&runs, &policy);
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].epoch, 1);
        assert_eq!(points[1].epoch, 2);
        assert!(points[0].total_cases >= 1);
        assert!(points[1].total_cases >= 1);
    }

    #[test]
    fn classify_flakes_below_threshold_excluded() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 999_999,
            high_flake_threshold_millionths: 1_000_000,
            ..FlakePolicy::default()
        };
        let runs = vec![
            FlakeRunRecord {
                run_id: "r1".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b1".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 1,
            },
            FlakeRunRecord {
                run_id: "r2".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                outcome: "pass".into(),
                error_signature: None,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b2".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 1,
            },
            FlakeRunRecord {
                run_id: "r3".into(),
                epoch: 1,
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                outcome: "fail".into(),
                error_signature: Some("e".into()),
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_id: "b3".into(),
                related_unit_suites: vec![],
                root_cause_hypothesis_artifacts: vec![],
                seed: 1,
            },
        ];
        let classifications = classify_flakes(&runs, &policy);
        assert!(classifications.is_empty());
    }

    #[test]
    fn build_quarantine_records_owner_lookup_by_scenario_id_fallback() {
        let policy = FlakePolicy {
            warning_flake_threshold_millionths: 1,
            high_flake_threshold_millionths: 100_000,
            ..FlakePolicy::default()
        };
        let classifications = classify_flakes(&sample_runs(), &policy);
        let mut owners = BTreeMap::new();
        owners.insert(
            "scenario-hydration".to_string(),
            "fallback-owner".to_string(),
        );
        let quarantines = build_quarantine_records(&classifications, &owners, 1, &policy);
        assert_eq!(quarantines[0].owner, "fallback-owner");
        assert!(quarantines[0].owner_bound);
    }

    // ── Enrichment: FlakeSeverity display / as_str ───────────────────

    #[test]
    fn flake_severity_display_matches_as_str() {
        assert_eq!(
            FlakeSeverity::Warning.to_string(),
            FlakeSeverity::Warning.as_str()
        );
        assert_eq!(
            FlakeSeverity::High.to_string(),
            FlakeSeverity::High.as_str()
        );
    }

    #[test]
    fn flake_severity_serde_roundtrip_all() {
        for v in [FlakeSeverity::Warning, FlakeSeverity::High] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: FlakeSeverity =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(v, back);
        }
    }

    // ── Enrichment: QuarantineAction display / as_str ────────────────

    #[test]
    fn quarantine_action_display_matches_as_str() {
        assert_eq!(QuarantineAction::Observe.to_string(), "observe");
        assert_eq!(
            QuarantineAction::QuarantineImmediate.to_string(),
            "quarantine-immediate"
        );
    }

    #[test]
    fn quarantine_action_serde_roundtrip_all() {
        for v in [
            QuarantineAction::Observe,
            QuarantineAction::QuarantineImmediate,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: QuarantineAction =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(v, back);
        }
    }

    // ── Enrichment: QuarantineStatus serde ───────────────────────────

    #[test]
    fn quarantine_status_serde_roundtrip_all() {
        for v in [
            QuarantineStatus::Active,
            QuarantineStatus::Expired,
            QuarantineStatus::Lifted,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: QuarantineStatus =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(v, back);
        }
    }

    // ── Enrichment: TrendDirection serde ──────────────────────────────

    #[test]
    fn trend_direction_serde_roundtrip_all() {
        for v in [
            TrendDirection::Improving,
            TrendDirection::Stable,
            TrendDirection::Degrading,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: TrendDirection =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(v, back);
        }
    }

    // ── Enrichment: FlakePolicy serde ────────────────────────────────

    #[test]
    fn flake_policy_serde_roundtrip_alt() {
        let policy = FlakePolicy::default();
        let json = serde_json::to_string(&policy).expect("serde deserialization should succeed");
        let back: FlakePolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(policy, back);
    }

    // ── Enrichment: FlakeWorkflowEvent serde ─────────────────────────

    #[test]
    fn flake_workflow_event_none_fields_serde() {
        let ev = FlakeWorkflowEvent {
            schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: "t1".into(),
            decision_id: "d1".into(),
            policy_id: "p1".into(),
            component: FLAKE_WORKFLOW_COMPONENT.into(),
            event: "flake_classified".into(),
            outcome: "quarantined".into(),
            error_code: None,
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            flake_rate_millionths: None,
            replay_command_ci: "ci cmd".into(),
            replay_command_local: "local cmd".into(),
            quarantine_owner: None,
            quarantine_expires_epoch: None,
            impacted_unit_suites: vec![],
            root_cause_hypothesis_artifacts: vec![],
        };
        let json = serde_json::to_string(&ev).expect("serde deserialization should succeed");
        let back: FlakeWorkflowEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(ev, back);
    }

    #[test]
    fn flake_workflow_event_all_some_fields_serde() {
        let ev = FlakeWorkflowEvent {
            schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: "t2".into(),
            decision_id: "d2".into(),
            policy_id: "p2".into(),
            component: FLAKE_WORKFLOW_COMPONENT.into(),
            event: "flake_classified".into(),
            outcome: "ok".into(),
            error_code: Some("FE-FRX-20-5-001".into()),
            suite_kind: "unit".into(),
            scenario_id: "sc-2".into(),
            flake_rate_millionths: Some(250_000),
            replay_command_ci: "ci".into(),
            replay_command_local: "local".into(),
            quarantine_owner: Some("team-a".into()),
            quarantine_expires_epoch: Some(5),
            impacted_unit_suites: vec!["suite-a".into()],
            root_cause_hypothesis_artifacts: vec!["art-1".into()],
        };
        let json = serde_json::to_string(&ev).expect("serde deserialization should succeed");
        let back: FlakeWorkflowEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(ev, back);
    }

    // ── Enrichment: validate_quarantine_records ──────────────────────

    #[test]
    fn validate_quarantine_records_unbound_owner_violation() {
        let records = vec![QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            owner: "unassigned".into(),
            owner_bound: false,
            opened_epoch: 1,
            expires_epoch: 4,
            status: QuarantineStatus::Active,
            reason: "test".into(),
            linked_reproducer_bundle_id: "b1".into(),
        }];
        let violations = validate_quarantine_records(&records, 1);
        assert!(
            violations
                .iter()
                .any(|v| v.starts_with("missing_owner_binding:"))
        );
    }

    #[test]
    fn validate_quarantine_records_expired_active_violation() {
        let records = vec![QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-2".into(),
            owner: "team-a".into(),
            owner_bound: true,
            opened_epoch: 1,
            expires_epoch: 3,
            status: QuarantineStatus::Active,
            reason: "test".into(),
            linked_reproducer_bundle_id: "b2".into(),
        }];
        // current_epoch >= expires_epoch => expired_active_quarantine
        let violations = validate_quarantine_records(&records, 3);
        assert!(
            violations
                .iter()
                .any(|v| v.starts_with("expired_active_quarantine:"))
        );
    }

    #[test]
    fn validate_quarantine_records_clean() {
        let records = vec![QuarantineRecord {
            suite_kind: "e2e".into(),
            scenario_id: "sc-3".into(),
            owner: "team-b".into(),
            owner_bound: true,
            opened_epoch: 1,
            expires_epoch: 5,
            status: QuarantineStatus::Active,
            reason: "test".into(),
            linked_reproducer_bundle_id: "b3".into(),
        }];
        let violations = validate_quarantine_records(&records, 2);
        assert!(violations.is_empty());
    }

    // ── Enrichment: ReproducerBundle serde ────────────────────────────

    #[test]
    fn reproducer_bundle_serde_roundtrip_alt() {
        let bundle = ReproducerBundle {
            bundle_id: "bid-1".into(),
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            seed: 42,
            replay_command_ci: "ci cmd".into(),
            replay_command_local: "local cmd".into(),
            artifact_bundle_ids: vec!["a1".into(), "a2".into()],
            run_ids: vec!["r1".into(), "r2".into()],
        };
        let json = serde_json::to_string(&bundle).expect("serde deserialization should succeed");
        let back: ReproducerBundle =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(bundle, back);
    }

    // ── Enrichment: EpochBurdenPoint serde ───────────────────────────

    #[test]
    fn epoch_burden_point_serde_roundtrip_alt() {
        let pt = EpochBurdenPoint {
            epoch: 5,
            total_cases: 100,
            flaky_cases: 10,
            high_severity_cases: 3,
            flake_burden_millionths: 100_000,
            high_severity_burden_millionths: 30_000,
        };
        let json = serde_json::to_string(&pt).expect("serde deserialization should succeed");
        let back: EpochBurdenPoint =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(pt, back);
    }

    // ── Enrichment: GateConfidenceReport serde ───────────────────────

    #[test]
    fn gate_confidence_report_serde_roundtrip_alt() {
        let report = GateConfidenceReport {
            latest_epoch: 3,
            flake_burden_millionths: 50_000,
            high_severity_flake_count: 1,
            trend_direction: TrendDirection::Stable,
            trend_delta_millionths: 0,
            per_epoch_burden: vec![],
            promotion_outcome: "blocked".into(),
            blockers: vec!["blocker-1".into()],
        };
        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let back: GateConfidenceReport =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(report, back);
    }

    // ── Enrichment: FlakeClassification serde ────────────────────────

    #[test]
    fn flake_classification_serde_roundtrip_alt() {
        let fc = FlakeClassification {
            suite_kind: "e2e".into(),
            scenario_id: "sc-1".into(),
            pass_count: 7,
            fail_count: 3,
            flake_rate_millionths: 300_000,
            severity: FlakeSeverity::High,
            quarantine_action: QuarantineAction::QuarantineImmediate,
            dominant_error_signature: "sig-a".into(),
            impacted_unit_suites: vec!["suite-1".into()],
            root_cause_hypothesis_artifacts: vec!["art-1".into()],
            reproducer_bundle: ReproducerBundle {
                bundle_id: "bid".into(),
                suite_kind: "e2e".into(),
                scenario_id: "sc-1".into(),
                seed: 1,
                replay_command_ci: "ci".into(),
                replay_command_local: "local".into(),
                artifact_bundle_ids: vec!["a1".into()],
                run_ids: vec!["r1".into()],
            },
        };
        let json = serde_json::to_string(&fc).expect("serde deserialization should succeed");
        let back: FlakeClassification =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(fc, back);
    }

    // ── Enrichment: QuarantineRecord serde ───────────────────────────

    #[test]
    fn quarantine_record_serde_roundtrip_alt() {
        let qr = QuarantineRecord {
            suite_kind: "unit".into(),
            scenario_id: "sc-q".into(),
            owner: "team-x".into(),
            owner_bound: true,
            opened_epoch: 2,
            expires_epoch: 5,
            status: QuarantineStatus::Active,
            reason: "high_flake_rate:unit::sc-q".into(),
            linked_reproducer_bundle_id: "b1".into(),
        };
        let json = serde_json::to_string(&qr).expect("serde deserialization should succeed");
        let back: QuarantineRecord =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(qr, back);
    }
}
