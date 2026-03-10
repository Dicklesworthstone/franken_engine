#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SchedulerPartition {
    partition_id: String,
    fixture_limit: u64,
    seed_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SchedulerManifest {
    nightly_cron_utc: String,
    timezone: String,
    locale: String,
    deterministic_seed: u64,
    partitions: Vec<SchedulerPartition>,
    expected_manifest_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct WaiverRecord {
    waiver_id: String,
    fingerprint: String,
    severity: String,
    expires_utc: String,
    approved_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExistingRemediation {
    fingerprint: String,
    bead_id: String,
    status: String,
    owner_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DriftFinding {
    finding_id: String,
    fixture_id: String,
    fingerprint: String,
    severity: String,
    classification: String,
    owner_hint: String,
    replay_command: String,
    artifact_path: String,
    minimized_source_hash: String,
    provenance_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_blockers: Vec<String>,
    expected_escalations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedRemediationAction {
    fingerprint: String,
    action: String,
    bead_id: String,
    owner_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DifferentialNightlyGovernanceFixture {
    schema_version: String,
    governance_version: String,
    bead_id: String,
    evaluation_time_utc: String,
    scheduler_manifest: SchedulerManifest,
    waivers: Vec<WaiverRecord>,
    existing_remediations: Vec<ExistingRemediation>,
    drift_findings: Vec<DriftFinding>,
    required_log_keys: Vec<String>,
    expected_gate: ExpectedGate,
    expected_remediation_actions: Vec<ExpectedRemediationAction>,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateDecision {
    outcome: String,
    blockers: Vec<String>,
    escalations: Vec<String>,
    finding_outcomes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemediationAction {
    fingerprint: String,
    action: String,
    bead_id: String,
    owner_hint: String,
}

fn load_fixture() -> DifferentialNightlyGovernanceFixture {
    let path = Path::new("tests/fixtures/parser_differential_nightly_governance_v1.json");
    let bytes = fs::read(path).expect("read parser differential nightly governance fixture");
    serde_json::from_slice(&bytes)
        .expect("deserialize parser differential nightly governance fixture")
}

fn fnv1a64(input: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in input {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

fn scheduler_manifest_fingerprint(manifest: &SchedulerManifest) -> String {
    let mut partitions = manifest.partitions.clone();
    partitions.sort_by(|left, right| left.partition_id.cmp(&right.partition_id));

    let mut payload = String::new();
    payload.push_str(&manifest.nightly_cron_utc);
    payload.push('|');
    payload.push_str(&manifest.timezone);
    payload.push('|');
    payload.push_str(&manifest.locale);
    payload.push('|');
    payload.push_str(&manifest.deterministic_seed.to_string());
    for partition in partitions {
        payload.push('|');
        payload.push_str(&partition.partition_id);
        payload.push(':');
        payload.push_str(&partition.fixture_limit.to_string());
        payload.push(':');
        payload.push_str(&partition.seed_offset.to_string());
    }

    format!("fnv1a64:{:016x}", fnv1a64(payload.as_bytes()))
}

fn find_matching_waiver<'a>(
    finding: &DriftFinding,
    waivers: &'a [WaiverRecord],
) -> Option<&'a WaiverRecord> {
    waivers.iter().find(|waiver| {
        waiver.fingerprint == finding.fingerprint && waiver.severity == finding.severity
    })
}

fn evaluate_gate(fixture: &DifferentialNightlyGovernanceFixture) -> GateDecision {
    let mut blockers = BTreeSet::new();
    let mut escalations = BTreeSet::new();
    let mut finding_outcomes = BTreeMap::new();

    for finding in &fixture.drift_findings {
        let waiver = find_matching_waiver(finding, &fixture.waivers);
        let waiver_active = waiver
            .map(|entry| entry.expires_utc.as_str() >= fixture.evaluation_time_utc.as_str())
            .unwrap_or(false);
        let waiver_expired = waiver
            .map(|entry| entry.expires_utc.as_str() < fixture.evaluation_time_utc.as_str())
            .unwrap_or(false);

        if waiver_expired {
            blockers.insert(format!(
                "waiver_expired:{}",
                waiver.expect("known waiver").waiver_id
            ));
        }

        match finding.severity.as_str() {
            "critical" if waiver_active => {
                finding_outcomes.insert(finding.finding_id.clone(), "waived_critical".to_string());
            }
            "critical" => {
                blockers.insert(format!("critical_unwaived:{}", finding.finding_id));
                escalations.insert(format!("page_owner:{}", finding.owner_hint));
                finding_outcomes
                    .insert(finding.finding_id.clone(), "critical_unwaived".to_string());
            }
            "minor" if waiver_active => {
                finding_outcomes.insert(finding.finding_id.clone(), "waived_observe".to_string());
            }
            "minor" => {
                finding_outcomes.insert(finding.finding_id.clone(), "minor_unwaived".to_string());
            }
            _ => {
                blockers.insert(format!("unknown_severity:{}", finding.finding_id));
                finding_outcomes.insert(finding.finding_id.clone(), "unknown_severity".to_string());
            }
        }
    }

    let blockers = blockers.into_iter().collect::<Vec<_>>();
    let escalations = escalations.into_iter().collect::<Vec<_>>();
    let outcome = if blockers.is_empty() {
        "promote"
    } else {
        "hold"
    }
    .to_string();

    GateDecision {
        outcome,
        blockers,
        escalations,
        finding_outcomes,
    }
}

fn auto_bead_id(fingerprint: &str) -> String {
    let normalized = fingerprint
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint)
        .chars()
        .take(8)
        .collect::<String>();
    format!("bd-auto-{normalized}")
}

fn remediation_actions(
    fixture: &DifferentialNightlyGovernanceFixture,
    decisions: &GateDecision,
) -> Vec<RemediationAction> {
    let existing = fixture
        .existing_remediations
        .iter()
        .map(|entry| (entry.fingerprint.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    let mut actions = BTreeMap::<String, RemediationAction>::new();

    for finding in &fixture.drift_findings {
        let outcome = decisions
            .finding_outcomes
            .get(&finding.finding_id)
            .expect("finding outcome should exist")
            .as_str();
        if outcome == "waived_observe" || outcome == "waived_critical" {
            continue;
        }

        if let Some(existing_entry) = existing.get(finding.fingerprint.as_str()) {
            actions.insert(
                finding.fingerprint.clone(),
                RemediationAction {
                    fingerprint: finding.fingerprint.clone(),
                    action: "update".to_string(),
                    bead_id: existing_entry.bead_id.clone(),
                    owner_hint: existing_entry.owner_hint.clone(),
                },
            );
        } else {
            actions.insert(
                finding.fingerprint.clone(),
                RemediationAction {
                    fingerprint: finding.fingerprint.clone(),
                    action: "create".to_string(),
                    bead_id: auto_bead_id(&finding.fingerprint),
                    owner_hint: finding.owner_hint.clone(),
                },
            );
        }
    }

    actions.into_values().collect::<Vec<_>>()
}

fn emit_structured_events(
    fixture: &DifferentialNightlyGovernanceFixture,
    actions: &[RemediationAction],
    decisions: &GateDecision,
) -> Vec<BTreeMap<String, String>> {
    let mut action_by_fingerprint = BTreeMap::new();
    for action in actions {
        action_by_fingerprint.insert(action.fingerprint.as_str(), action.action.as_str());
    }

    fixture
        .drift_findings
        .iter()
        .map(|finding| {
            let mut event = BTreeMap::new();
            event.insert(
                "trace_id".to_string(),
                "trace-parser-diff-nightly-v1".to_string(),
            );
            event.insert(
                "decision_id".to_string(),
                "decision-parser-diff-nightly-v1".to_string(),
            );
            event.insert(
                "policy_id".to_string(),
                "policy-parser-diff-nightly-governance-v1".to_string(),
            );
            event.insert(
                "component".to_string(),
                "parser_differential_nightly_governance".to_string(),
            );
            event.insert("event".to_string(), "finding_governed".to_string());
            event.insert(
                "outcome".to_string(),
                decisions
                    .finding_outcomes
                    .get(&finding.finding_id)
                    .expect("finding outcome should exist")
                    .clone(),
            );
            event.insert(
                "error_code".to_string(),
                if finding.severity == "critical" {
                    "FE-PARSER-DIFF-NIGHTLY-CRITICAL".to_string()
                } else {
                    "none".to_string()
                },
            );
            event.insert("finding_id".to_string(), finding.finding_id.clone());
            event.insert("fingerprint".to_string(), finding.fingerprint.clone());
            event.insert("severity".to_string(), finding.severity.clone());
            event.insert("owner_hint".to_string(), finding.owner_hint.clone());
            event.insert("replay_command".to_string(), finding.replay_command.clone());
            event.insert(
                "remediation_action".to_string(),
                action_by_fingerprint
                    .get(finding.fingerprint.as_str())
                    .copied()
                    .unwrap_or("none")
                    .to_string(),
            );
            event
        })
        .collect::<Vec<_>>()
}

#[test]
fn fixture_contract_version_and_scheduler_fingerprint_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-differential-nightly-governance.v1"
    );
    assert_eq!(fixture.governance_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-2mds.1.2.4.2");

    let fingerprint = scheduler_manifest_fingerprint(&fixture.scheduler_manifest);
    assert_eq!(
        fingerprint,
        fixture.scheduler_manifest.expected_manifest_fingerprint
    );
}

#[test]
fn scheduler_partitions_sort_uniquely_with_deterministic_seed_offsets() {
    let fixture = load_fixture();
    let mut ids = fixture
        .scheduler_manifest
        .partitions
        .iter()
        .map(|partition| partition.partition_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), fixture.scheduler_manifest.partitions.len());

    let mut offsets = fixture
        .scheduler_manifest
        .partitions
        .iter()
        .map(|partition| partition.seed_offset)
        .collect::<Vec<_>>();
    offsets.sort();
    offsets.dedup();
    assert_eq!(offsets.len(), fixture.scheduler_manifest.partitions.len());

    assert_eq!(fixture.scheduler_manifest.timezone, "UTC");
    assert_eq!(fixture.scheduler_manifest.locale, "C");
}

#[test]
fn governance_gate_matches_expected_blockers_and_escalations() {
    let fixture = load_fixture();
    let decision = evaluate_gate(&fixture);
    assert_eq!(decision.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(decision.blockers, fixture.expected_gate.expected_blockers);
    assert_eq!(
        decision.escalations,
        fixture.expected_gate.expected_escalations
    );
}

#[test]
fn remediation_actions_are_deterministic_for_create_and_update_paths() {
    let fixture = load_fixture();
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    let actual = actions
        .iter()
        .map(|action| ExpectedRemediationAction {
            fingerprint: action.fingerprint.clone(),
            action: action.action.clone(),
            bead_id: action.bead_id.clone(),
            owner_hint: action.owner_hint.clone(),
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, fixture.expected_remediation_actions);
}

#[test]
fn structured_events_include_required_governance_keys() {
    let fixture = load_fixture();
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    let events = emit_structured_events(&fixture, &actions, &decision);

    for event in events {
        for key in &fixture.required_log_keys {
            assert!(
                event.contains_key(key),
                "event missing required key `{key}`: {:?}",
                event
            );
        }
        assert!(
            event
                .get("replay_command")
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            "replay_command must be present and non-empty"
        );
    }
}

#[test]
fn replay_scenarios_map_to_governance_outcomes() {
    let fixture = load_fixture();
    let decision = evaluate_gate(&fixture);

    let finding_outcomes = fixture
        .drift_findings
        .iter()
        .map(|finding| {
            (
                finding.replay_command.as_str(),
                decision
                    .finding_outcomes
                    .get(&finding.finding_id)
                    .expect("finding outcome should exist")
                    .as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for scenario in &fixture.replay_scenarios {
        let actual = finding_outcomes
            .get(scenario.replay_command.as_str())
            .copied()
            .unwrap_or("missing");
        let expected = match scenario.expected_outcome.as_str() {
            "update_existing" | "create_new" => "critical_unwaived",
            "waived_observe" => "waived_observe",
            other => panic!("unexpected expected_outcome `{other}`"),
        };
        assert_eq!(
            actual, expected,
            "scenario {} should map to expected governance outcome",
            scenario.scenario_id
        );
    }
}

// ---------- fnv1a64 ----------

#[test]
fn fnv1a64_empty_input_returns_basis() {
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325_u64);
}

#[test]
fn fnv1a64_deterministic() {
    let a = fnv1a64(b"hello world");
    let b = fnv1a64(b"hello world");
    assert_eq!(a, b);
}

#[test]
fn fnv1a64_different_inputs_differ() {
    assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
}

#[test]
fn fnv1a64_single_byte_differs_from_basis() {
    assert_ne!(fnv1a64(b"\x00"), fnv1a64(b""));
}

// ---------- scheduler_manifest_fingerprint ----------

#[test]
fn scheduler_manifest_fingerprint_starts_with_fnv1a64() {
    let fixture = load_fixture();
    let fp = scheduler_manifest_fingerprint(&fixture.scheduler_manifest);
    assert!(
        fp.starts_with("fnv1a64:"),
        "fingerprint must start with fnv1a64:"
    );
}

#[test]
fn scheduler_manifest_fingerprint_deterministic() {
    let fixture = load_fixture();
    let fp1 = scheduler_manifest_fingerprint(&fixture.scheduler_manifest);
    let fp2 = scheduler_manifest_fingerprint(&fixture.scheduler_manifest);
    assert_eq!(fp1, fp2);
}

#[test]
fn scheduler_manifest_fingerprint_changes_with_seed() {
    let fixture = load_fixture();
    let fp1 = scheduler_manifest_fingerprint(&fixture.scheduler_manifest);
    let mut modified = fixture.scheduler_manifest.clone();
    modified.deterministic_seed = modified.deterministic_seed.wrapping_add(1);
    let fp2 = scheduler_manifest_fingerprint(&modified);
    assert_ne!(fp1, fp2);
}

// ---------- find_matching_waiver ----------

#[test]
fn find_matching_waiver_matches_fingerprint_and_severity() {
    let finding = DriftFinding {
        finding_id: "f1".to_string(),
        fixture_id: "fix1".to_string(),
        fingerprint: "sha256:abc".to_string(),
        severity: "critical".to_string(),
        classification: "class1".to_string(),
        owner_hint: "owner1".to_string(),
        replay_command: "./replay.sh".to_string(),
        artifact_path: "path".to_string(),
        minimized_source_hash: "hash1".to_string(),
        provenance_hash: "hash2".to_string(),
    };
    let waivers = vec![WaiverRecord {
        waiver_id: "w1".to_string(),
        fingerprint: "sha256:abc".to_string(),
        severity: "critical".to_string(),
        expires_utc: "2027-01-01T00:00:00Z".to_string(),
        approved_by: "admin".to_string(),
    }];
    assert!(find_matching_waiver(&finding, &waivers).is_some());
}

#[test]
fn find_matching_waiver_no_match_wrong_severity() {
    let finding = DriftFinding {
        finding_id: "f1".to_string(),
        fixture_id: "fix1".to_string(),
        fingerprint: "sha256:abc".to_string(),
        severity: "minor".to_string(),
        classification: "class1".to_string(),
        owner_hint: "owner1".to_string(),
        replay_command: "./replay.sh".to_string(),
        artifact_path: "path".to_string(),
        minimized_source_hash: "hash1".to_string(),
        provenance_hash: "hash2".to_string(),
    };
    let waivers = vec![WaiverRecord {
        waiver_id: "w1".to_string(),
        fingerprint: "sha256:abc".to_string(),
        severity: "critical".to_string(),
        expires_utc: "2027-01-01T00:00:00Z".to_string(),
        approved_by: "admin".to_string(),
    }];
    assert!(find_matching_waiver(&finding, &waivers).is_none());
}

#[test]
fn find_matching_waiver_no_match_empty() {
    let finding = DriftFinding {
        finding_id: "f1".to_string(),
        fixture_id: "fix1".to_string(),
        fingerprint: "sha256:abc".to_string(),
        severity: "critical".to_string(),
        classification: "class1".to_string(),
        owner_hint: "owner1".to_string(),
        replay_command: "./replay.sh".to_string(),
        artifact_path: "path".to_string(),
        minimized_source_hash: "hash1".to_string(),
        provenance_hash: "hash2".to_string(),
    };
    assert!(find_matching_waiver(&finding, &[]).is_none());
}

// ---------- auto_bead_id ----------

#[test]
fn auto_bead_id_strips_sha256_prefix() {
    assert_eq!(auto_bead_id("sha256:abcdef01234"), "bd-auto-abcdef01");
}

#[test]
fn auto_bead_id_no_prefix() {
    assert_eq!(auto_bead_id("abcdef01234"), "bd-auto-abcdef01");
}

#[test]
fn auto_bead_id_short_input() {
    assert_eq!(auto_bead_id("abc"), "bd-auto-abc");
}

// ---------- evaluate_gate synthetic ----------

fn make_finding(id: &str, severity: &str, fingerprint: &str) -> DriftFinding {
    DriftFinding {
        finding_id: id.to_string(),
        fixture_id: format!("fixture-{id}"),
        fingerprint: fingerprint.to_string(),
        severity: severity.to_string(),
        classification: "class".to_string(),
        owner_hint: "owner".to_string(),
        replay_command: format!("./scripts/e2e/{id}.sh"),
        artifact_path: "path".to_string(),
        minimized_source_hash: "hash".to_string(),
        provenance_hash: "hash".to_string(),
    }
}

fn make_gov_fixture(
    findings: Vec<DriftFinding>,
    waivers: Vec<WaiverRecord>,
) -> DifferentialNightlyGovernanceFixture {
    DifferentialNightlyGovernanceFixture {
        schema_version: "franken-engine.parser-differential-nightly-governance.v1".to_string(),
        governance_version: "1.0.0".to_string(),
        bead_id: "bd-test".to_string(),
        evaluation_time_utc: "2026-06-01T00:00:00Z".to_string(),
        scheduler_manifest: SchedulerManifest {
            nightly_cron_utc: "0 3 * * *".to_string(),
            timezone: "UTC".to_string(),
            locale: "C".to_string(),
            deterministic_seed: 42,
            partitions: vec![],
            expected_manifest_fingerprint: String::new(),
        },
        waivers,
        existing_remediations: vec![],
        drift_findings: findings,
        required_log_keys: vec![],
        expected_gate: ExpectedGate {
            expected_outcome: String::new(),
            expected_blockers: vec![],
            expected_escalations: vec![],
        },
        expected_remediation_actions: vec![],
        replay_scenarios: vec![],
    }
}

#[test]
fn evaluate_gate_promotes_with_no_findings() {
    let fixture = make_gov_fixture(vec![], vec![]);
    let decision = evaluate_gate(&fixture);
    assert_eq!(decision.outcome, "promote");
    assert!(decision.blockers.is_empty());
}

#[test]
fn evaluate_gate_holds_on_critical_unwaived() {
    let fixture = make_gov_fixture(vec![make_finding("f1", "critical", "sha256:aaa")], vec![]);
    let decision = evaluate_gate(&fixture);
    assert_eq!(decision.outcome, "hold");
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("critical_unwaived:f1"))
    );
    assert!(
        decision
            .escalations
            .iter()
            .any(|e| e.contains("page_owner:owner"))
    );
}

#[test]
fn evaluate_gate_promotes_with_waived_critical() {
    let waiver = WaiverRecord {
        waiver_id: "w1".to_string(),
        fingerprint: "sha256:aaa".to_string(),
        severity: "critical".to_string(),
        expires_utc: "2027-01-01T00:00:00Z".to_string(),
        approved_by: "admin".to_string(),
    };
    let fixture = make_gov_fixture(
        vec![make_finding("f1", "critical", "sha256:aaa")],
        vec![waiver],
    );
    let decision = evaluate_gate(&fixture);
    assert_eq!(decision.outcome, "promote");
    assert_eq!(
        decision.finding_outcomes.get("f1").unwrap(),
        "waived_critical"
    );
}

#[test]
fn evaluate_gate_holds_on_expired_waiver() {
    let waiver = WaiverRecord {
        waiver_id: "w1".to_string(),
        fingerprint: "sha256:aaa".to_string(),
        severity: "critical".to_string(),
        expires_utc: "2025-01-01T00:00:00Z".to_string(),
        approved_by: "admin".to_string(),
    };
    let fixture = make_gov_fixture(
        vec![make_finding("f1", "critical", "sha256:aaa")],
        vec![waiver],
    );
    let decision = evaluate_gate(&fixture);
    assert_eq!(decision.outcome, "hold");
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("waiver_expired:w1"))
    );
}

#[test]
fn evaluate_gate_minor_unwaived_does_not_block() {
    let fixture = make_gov_fixture(vec![make_finding("f1", "minor", "sha256:bbb")], vec![]);
    let decision = evaluate_gate(&fixture);
    assert_eq!(decision.outcome, "promote");
    assert_eq!(
        decision.finding_outcomes.get("f1").unwrap(),
        "minor_unwaived"
    );
}

#[test]
fn evaluate_gate_unknown_severity_blocks() {
    let fixture = make_gov_fixture(vec![make_finding("f1", "exotic", "sha256:ccc")], vec![]);
    let decision = evaluate_gate(&fixture);
    assert_eq!(decision.outcome, "hold");
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("unknown_severity:f1"))
    );
}

// ---------- remediation_actions ----------

#[test]
fn remediation_actions_creates_for_unknown_fingerprint() {
    let fixture = make_gov_fixture(
        vec![make_finding("f1", "critical", "sha256:new12345")],
        vec![],
    );
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, "create");
    assert_eq!(actions[0].bead_id, "bd-auto-new12345");
}

#[test]
fn remediation_actions_updates_for_existing_fingerprint() {
    let mut fixture = make_gov_fixture(
        vec![make_finding("f1", "critical", "sha256:existing")],
        vec![],
    );
    fixture.existing_remediations.push(ExistingRemediation {
        fingerprint: "sha256:existing".to_string(),
        bead_id: "bd-existing-1".to_string(),
        status: "open".to_string(),
        owner_hint: "existing-owner".to_string(),
    });
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, "update");
    assert_eq!(actions[0].bead_id, "bd-existing-1");
}

#[test]
fn remediation_actions_skips_waived() {
    let waiver = WaiverRecord {
        waiver_id: "w1".to_string(),
        fingerprint: "sha256:aaa".to_string(),
        severity: "critical".to_string(),
        expires_utc: "2027-01-01T00:00:00Z".to_string(),
        approved_by: "admin".to_string(),
    };
    let fixture = make_gov_fixture(
        vec![make_finding("f1", "critical", "sha256:aaa")],
        vec![waiver],
    );
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    assert!(actions.is_empty());
}

// ---------- emit_structured_events ----------

#[test]
fn emit_structured_events_one_per_finding() {
    let fixture = make_gov_fixture(
        vec![
            make_finding("f1", "critical", "sha256:aaa"),
            make_finding("f2", "minor", "sha256:bbb"),
        ],
        vec![],
    );
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    let events = emit_structured_events(&fixture, &actions, &decision);
    assert_eq!(events.len(), 2);
}

#[test]
fn emit_structured_events_critical_has_error_code() {
    let fixture = make_gov_fixture(vec![make_finding("f1", "critical", "sha256:aaa")], vec![]);
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    let events = emit_structured_events(&fixture, &actions, &decision);
    assert_eq!(
        events[0].get("error_code").unwrap(),
        "FE-PARSER-DIFF-NIGHTLY-CRITICAL"
    );
}

#[test]
fn emit_structured_events_minor_has_none_error_code() {
    let fixture = make_gov_fixture(vec![make_finding("f1", "minor", "sha256:bbb")], vec![]);
    let decision = evaluate_gate(&fixture);
    let actions = remediation_actions(&fixture, &decision);
    let events = emit_structured_events(&fixture, &actions, &decision);
    assert_eq!(events[0].get("error_code").unwrap(), "none");
}

// ---------- evaluate_gate determinism ----------

#[test]
fn evaluate_gate_deterministic() {
    let fixture = load_fixture();
    let d1 = evaluate_gate(&fixture);
    let d2 = evaluate_gate(&fixture);
    assert_eq!(d1, d2);
}
