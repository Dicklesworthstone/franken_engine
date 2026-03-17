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

#[path = "../src/conformance_harness.rs"]
mod conformance_harness;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use conformance_harness::{
    ConformanceLogEvent, ConformanceRunResult, ConformanceRunner, ConformanceWaiverSet,
};
use serde_json::Value;

const IFC_RELEASE_GATE_ERROR: &str = "FE-IFCR-1001";
const REQUIRED_FLOW_PATH_TYPES: [&str; 5] =
    ["direct", "indirect", "implicit", "temporal", "covert"];
const REQUIRED_EXFIL_VECTOR_DOMAINS: [&str; 6] = [
    "ifc_corpus/exfil/eval_function",
    "ifc_corpus/exfil/proxy_reflect",
    "ifc_corpus/exfil/native_addon_escape",
    "ifc_corpus/exfil/shared_array_buffer",
    "ifc_corpus/exfil/structured_clone",
    "ifc_corpus/exfil/prototype_chain",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct IfcReleaseGateMetrics {
    benign_total: usize,
    exfil_total: usize,
    declassify_total: usize,
    false_positive_count: usize,
    unauthorized_exfil_success_count: usize,
    direct_indirect_bypass_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IfcReleaseGateDecision {
    blocked: bool,
    error_code: Option<String>,
    blockers: Vec<String>,
    metrics: IfcReleaseGateMetrics,
}

impl IfcReleaseGateDecision {
    fn allows_release(&self) -> bool {
        !self.blocked && self.error_code.is_none()
    }
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/ifc_corpus/ifc_conformance_assets.json")
}

fn run_ifc_corpus() -> ConformanceRunResult {
    ConformanceRunner::default()
        .run(manifest_path(), &ConformanceWaiverSet::default())
        .expect("ifc corpus should execute")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{label}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

fn latest_run_dir(root: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = fs::read_dir(root)
        .expect("artifact root should be readable")
        .map(|entry| entry.expect("entry should be readable").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs.pop().expect("expected at least one run directory")
}

fn write_complete_ifc_replay_fixture(root: &Path, stamp: &str, marker: &str) -> PathBuf {
    let run_dir = root.join(stamp);
    let evidence_dir = run_dir.join("ifc_conformance").join("fixture-run");
    fs::create_dir_all(&evidence_dir).expect("fixture evidence dir should be creatable");
    fs::write(
        run_dir.join("run_manifest.json"),
        format!(
            "{{\"schema_version\":\"fixture\",\"marker\":\"{marker}\",\"outcome\":\"pass\"}}\n"
        ),
    )
    .expect("fixture manifest should be writable");
    fs::write(
        run_dir.join("ifc_release_gate_events.jsonl"),
        format!("{{\"event\":\"fixture\",\"marker\":\"{marker}\"}}\n"),
    )
    .expect("fixture events should be writable");
    fs::write(
        run_dir.join("commands.txt"),
        format!("fixture-command {marker}\n"),
    )
    .expect("fixture commands should be writable");
    fs::write(
        evidence_dir.join("ifc_conformance_evidence.jsonl"),
        format!("{{\"evidence\":\"fixture\",\"marker\":\"{marker}\"}}\n"),
    )
    .expect("fixture evidence should be writable");
    run_dir
}

fn event_has_required_fields(event: &ConformanceLogEvent) -> bool {
    !event.trace_id.trim().is_empty()
        && !event.decision_id.trim().is_empty()
        && !event.policy_id.trim().is_empty()
        && !event.component.trim().is_empty()
        && !event.event.trim().is_empty()
        && !event.outcome.trim().is_empty()
}

fn evaluate_ifc_release_gate(run: &ConformanceRunResult) -> IfcReleaseGateDecision {
    let mut blockers = Vec::new();

    if let Err(err) = run.enforce_ci_gate() {
        blockers.push(format!("conformance ci gate rejected run: {err}"));
    }

    if run.summary.failed > 0 || run.summary.errored > 0 {
        blockers.push(format!(
            "run summary contains failures (failed={}, errored={})",
            run.summary.failed, run.summary.errored
        ));
    }

    let ifc_logs: Vec<&ConformanceLogEvent> = run
        .logs
        .iter()
        .filter(|event| event.category.is_some())
        .collect();
    if ifc_logs.is_empty() {
        blockers.push("manifest produced no IFC logs".to_string());
    }

    let mut benign_total = 0usize;
    let mut exfil_total = 0usize;
    let mut declassify_total = 0usize;
    let mut false_positive_count = 0usize;
    let mut unauthorized_exfil_success_count = 0usize;
    let mut direct_indirect_bypass_count = 0usize;
    let mut flow_path_coverage = BTreeSet::new();
    let mut vector_domain_coverage = BTreeSet::new();

    for event in &ifc_logs {
        if !event_has_required_fields(event) {
            blockers.push(format!(
                "asset `{}` missing required structured log fields",
                event.asset_id
            ));
        }

        if event.source_labels.is_empty() || event.sink_clearances.is_empty() {
            blockers.push(format!(
                "asset `{}` missing source/sink IFC labels in log",
                event.asset_id
            ));
        }

        if let Some(flow_path) = event.flow_path_type.as_deref() {
            flow_path_coverage.insert(flow_path.to_string());
        }

        for required_domain in REQUIRED_EXFIL_VECTOR_DOMAINS {
            if event.semantic_domain == required_domain {
                vector_domain_coverage.insert(required_domain.to_string());
            }
        }

        match event.category.as_deref() {
            Some("benign") => {
                benign_total += 1;
                if event.actual_outcome.as_deref() == Some("block") {
                    false_positive_count += 1;
                }
            }
            Some("exfil") => {
                exfil_total += 1;
                if event.actual_outcome.as_deref() != Some("block") {
                    unauthorized_exfil_success_count += 1;
                    if matches!(event.flow_path_type.as_deref(), Some("direct" | "indirect")) {
                        direct_indirect_bypass_count += 1;
                    }
                }
                if event.evidence_type.as_deref() != Some("flow_violation") {
                    blockers.push(format!(
                        "exfil asset `{}` missing flow_violation evidence type",
                        event.asset_id
                    ));
                }
                if event
                    .evidence_id
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    blockers.push(format!(
                        "exfil asset `{}` missing evidence_id receipt handle",
                        event.asset_id
                    ));
                }
            }
            Some("declassify") => {
                declassify_total += 1;
                if event.actual_outcome.as_deref() != Some("declassify") {
                    blockers.push(format!(
                        "declassify asset `{}` did not produce declassify outcome",
                        event.asset_id
                    ));
                }
                if event.evidence_type.as_deref() != Some("declassification_receipt") {
                    blockers.push(format!(
                        "declassify asset `{}` missing declassification receipt type",
                        event.asset_id
                    ));
                }
                if event
                    .evidence_id
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty() || !value.starts_with("dr-"))
                {
                    blockers.push(format!(
                        "declassify asset `{}` missing signed receipt handle",
                        event.asset_id
                    ));
                }
            }
            Some(other) => blockers.push(format!(
                "asset `{}` reported unsupported IFC category `{other}`",
                event.asset_id
            )),
            None => {}
        }
    }

    for required in REQUIRED_FLOW_PATH_TYPES {
        if !flow_path_coverage.contains(required) {
            blockers.push(format!("missing exfil flow-path coverage `{required}`"));
        }
    }

    for required in REQUIRED_EXFIL_VECTOR_DOMAINS {
        if !vector_domain_coverage.contains(required) {
            blockers.push(format!(
                "missing bypass-vector corpus coverage `{required}`"
            ));
        }
    }

    if false_positive_count > 0 {
        blockers.push(format!(
            "false positives detected for benign workloads: {false_positive_count}"
        ));
    }
    if unauthorized_exfil_success_count > 0 {
        blockers.push(format!(
            "unauthorized exfiltration succeeded in {} workload(s)",
            unauthorized_exfil_success_count
        ));
    }
    if direct_indirect_bypass_count > 0 {
        blockers.push(format!(
            "direct/indirect bypasses observed: {direct_indirect_bypass_count}"
        ));
    }

    if benign_total < 100 {
        blockers.push(format!("benign corpus too small: {benign_total} < 100"));
    }
    if exfil_total < 80 {
        blockers.push(format!("exfil corpus too small: {exfil_total} < 80"));
    }
    if declassify_total < 30 {
        blockers.push(format!(
            "declassify corpus too small: {declassify_total} < 30"
        ));
    }

    let blocked = !blockers.is_empty();
    let error_code = if blocked {
        Some(IFC_RELEASE_GATE_ERROR.to_string())
    } else {
        None
    };

    IfcReleaseGateDecision {
        blocked,
        error_code,
        blockers,
        metrics: IfcReleaseGateMetrics {
            benign_total,
            exfil_total,
            declassify_total,
            false_positive_count,
            unauthorized_exfil_success_count,
            direct_indirect_bypass_count,
        },
    }
}

#[test]
fn ifc_release_gate_accepts_published_corpus() {
    let run = run_ifc_corpus();
    let decision = evaluate_ifc_release_gate(&run);

    assert!(
        decision.allows_release(),
        "blockers: {:?}",
        decision.blockers
    );
    assert_eq!(decision.error_code, None);
    assert_eq!(decision.metrics.false_positive_count, 0);
    assert_eq!(decision.metrics.unauthorized_exfil_success_count, 0);
    assert_eq!(decision.metrics.direct_indirect_bypass_count, 0);
    assert!(decision.metrics.benign_total >= 100);
    assert!(decision.metrics.exfil_total >= 80);
    assert!(decision.metrics.declassify_total >= 30);
}

#[test]
fn ifc_release_gate_is_deterministic_for_identical_inputs() {
    let first = evaluate_ifc_release_gate(&run_ifc_corpus());
    let second = evaluate_ifc_release_gate(&run_ifc_corpus());

    assert_eq!(first, second);
    assert!(first.allows_release());
}

#[test]
fn ifc_release_gate_blocks_when_exfiltration_is_allowed() {
    let mut run = run_ifc_corpus();
    let exfil_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("exfil"))
        .expect("expected at least one exfil workload");

    exfil_event.actual_outcome = Some("allow".to_string());
    exfil_event.evidence_type = Some("none".to_string());
    exfil_event.evidence_id = None;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(IFC_RELEASE_GATE_ERROR));
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("unauthorized exfiltration succeeded"))
    );
}

#[test]
fn ifc_release_gate_blocks_when_declassification_receipt_is_missing() {
    let mut run = run_ifc_corpus();
    let declass_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("declassify"))
        .expect("expected at least one declassify workload");

    declass_event.evidence_id = None;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(IFC_RELEASE_GATE_ERROR));
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("missing signed receipt handle"))
    );
}

// ---------- IfcReleaseGateDecision ----------

#[test]
fn allows_release_true_when_no_blockers() {
    let decision = IfcReleaseGateDecision {
        blocked: false,
        error_code: None,
        blockers: Vec::new(),
        metrics: IfcReleaseGateMetrics {
            benign_total: 100,
            exfil_total: 80,
            declassify_total: 30,
            false_positive_count: 0,
            unauthorized_exfil_success_count: 0,
            direct_indirect_bypass_count: 0,
        },
    };
    assert!(decision.allows_release());
}

#[test]
fn allows_release_false_when_blocked() {
    let decision = IfcReleaseGateDecision {
        blocked: true,
        error_code: Some("FE-IFCR-1001".to_string()),
        blockers: vec!["some blocker".to_string()],
        metrics: IfcReleaseGateMetrics {
            benign_total: 0,
            exfil_total: 0,
            declassify_total: 0,
            false_positive_count: 0,
            unauthorized_exfil_success_count: 0,
            direct_indirect_bypass_count: 0,
        },
    };
    assert!(!decision.allows_release());
}

#[test]
fn allows_release_false_when_error_code_present() {
    let decision = IfcReleaseGateDecision {
        blocked: false,
        error_code: Some("FE-IFCR-1001".to_string()),
        blockers: Vec::new(),
        metrics: IfcReleaseGateMetrics {
            benign_total: 100,
            exfil_total: 80,
            declassify_total: 30,
            false_positive_count: 0,
            unauthorized_exfil_success_count: 0,
            direct_indirect_bypass_count: 0,
        },
    };
    assert!(!decision.allows_release());
}

// ---------- event_has_required_fields ----------

#[test]
fn event_has_required_fields_accepts_valid_event() {
    let event = ConformanceLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "ifc".to_string(),
        event: "evaluate".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "asset-1".to_string(),
        workload_id: "asset-1".to_string(),
        semantic_domain: "test".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    assert!(event_has_required_fields(&event));
}

#[test]
fn event_has_required_fields_rejects_empty_trace_id() {
    let event = ConformanceLogEvent {
        trace_id: "".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "ifc".to_string(),
        event: "evaluate".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "asset-1".to_string(),
        workload_id: "asset-1".to_string(),
        semantic_domain: "test".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    assert!(!event_has_required_fields(&event));
}

// ---------- constants ----------

#[test]
fn ifc_release_gate_error_constant() {
    assert_eq!(IFC_RELEASE_GATE_ERROR, "FE-IFCR-1001");
}

#[test]
fn required_flow_path_types_has_five_entries() {
    assert_eq!(REQUIRED_FLOW_PATH_TYPES.len(), 5);
}

#[test]
fn required_exfil_vector_domains_has_six_entries() {
    assert_eq!(REQUIRED_EXFIL_VECTOR_DOMAINS.len(), 6);
}

// ---------- gate blocks on false positive ----------

#[test]
fn ifc_release_gate_blocks_when_benign_is_blocked() {
    let mut run = run_ifc_corpus();
    let benign_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("benign"))
        .expect("expected at least one benign workload");
    benign_event.actual_outcome = Some("block".to_string());

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(decision.metrics.false_positive_count > 0);
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("false positives"))
    );
}

// ---------- gate metrics on clean run ----------

#[test]
fn ifc_release_gate_clean_metrics() {
    let run = run_ifc_corpus();
    let decision = evaluate_ifc_release_gate(&run);
    assert_eq!(decision.metrics.false_positive_count, 0);
    assert_eq!(decision.metrics.unauthorized_exfil_success_count, 0);
    assert_eq!(decision.metrics.direct_indirect_bypass_count, 0);
}

// ---------- manifest_path ----------

#[test]
fn ifc_manifest_path_exists() {
    assert!(manifest_path().exists());
}

#[test]
fn ifc_release_gate_suite_script_uses_replay_wrapper_contract() {
    let script = fs::read_to_string(repo_root().join("scripts/run_ifc_release_gate.sh"))
        .expect("ifc release gate script should be readable");

    for expected in [
        "replay_command=\"./scripts/e2e/ifc_release_gate_replay.sh ${mode}\"",
        "\"suite_replay\":",
        "\"cat $(json_escape \\\"$manifest_path\\\")\"",
        "\"cat $(json_escape \\\"$events_path\\\")\"",
        "\"cat $(json_escape \\\"$commands_path\\\")\"",
        "\"$(json_escape \\\"$replay_command\\\")\"",
    ] {
        assert!(
            script.contains(expected),
            "suite script should contain contract fragment `{expected}`"
        );
    }
}

#[test]
fn ifc_release_gate_suite_script_fail_closes_on_interrupt_signal() {
    let script = fs::read_to_string(repo_root().join("scripts/run_ifc_release_gate.sh"))
        .expect("ifc release gate script should be readable");

    for expected in [
        "handle_signal()",
        "failed_command=\"${failed_command:-./scripts/run_ifc_release_gate.sh ${mode} (signal:${signal})}\"",
        "write_manifest 130",
        "trap 'handle_signal INT' INT",
        "trap 'handle_signal TERM' TERM",
    ] {
        assert!(
            script.contains(expected),
            "suite script should fail closed on signal with fragment `{expected}`"
        );
    }
}

#[test]
fn ifc_release_gate_replay_wrapper_defaults_to_gate_mode() {
    let script = fs::read_to_string(repo_root().join("scripts/e2e/ifc_release_gate_replay.sh"))
        .expect("ifc release gate replay wrapper should be readable");

    assert!(
        script.contains("mode=\"${1:-gate}\""),
        "replay wrapper should default to gate mode"
    );
    assert!(
        script.contains("\"${root_dir}/scripts/run_ifc_release_gate.sh\" \"${mode}\""),
        "replay wrapper should delegate to the suite script with the selected mode"
    );
}

#[test]
fn ifc_release_gate_replay_wrapper_selects_latest_complete_bundle() {
    let script = fs::read_to_string(repo_root().join("scripts/e2e/ifc_release_gate_replay.sh"))
        .expect("ifc release gate replay wrapper should be readable");

    for expected in [
        "latest_complete_run_dir()",
        "\"${candidate}/run_manifest.json\"",
        "\"${candidate}/ifc_release_gate_events.jsonl\"",
        "\"${candidate}/commands.txt\"",
        "\"${candidate}/ifc_conformance\"",
        "latest_artifact_dir_path",
        "newest directory ${latest_artifact_dir_path} is incomplete",
        "using latest complete run directory ${latest_run_dir}",
        "missing_bundle_exit_code",
    ] {
        assert!(
            script.contains(expected),
            "replay wrapper should contain complete-bundle contract fragment `{expected}`"
        );
    }
}

#[test]
fn ifc_release_gate_replay_wrapper_prints_canonical_artifacts() {
    let script = fs::read_to_string(repo_root().join("scripts/e2e/ifc_release_gate_replay.sh"))
        .expect("ifc release gate replay wrapper should be readable");

    for expected in [
        "[ifc-release-gate] latest manifest:",
        "cat \"${latest_run_dir}/run_manifest.json\"",
        "[ifc-release-gate] latest events:",
        "cat \"${latest_run_dir}/ifc_release_gate_events.jsonl\"",
        "[ifc-release-gate] latest commands:",
        "cat \"${latest_run_dir}/commands.txt\"",
        "[ifc-release-gate] latest evidence:",
        "cat \"${latest_evidence_path}\"",
        "[ifc-release-gate] latest conformance output tree:",
        "ls -R \"${latest_run_dir}/ifc_conformance\"",
    ] {
        assert!(
            script.contains(expected),
            "replay wrapper should print canonical artifact fragment `{expected}`"
        );
    }
}

// ---------- gate blocks on missing evidence_id for exfil ----------

#[test]
fn ifc_release_gate_blocks_when_exfil_missing_evidence_id() {
    let mut run = run_ifc_corpus();
    let exfil_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("exfil"))
        .expect("expected at least one exfil workload");

    exfil_event.evidence_id = None;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("missing evidence_id receipt handle"))
    );
}

// ---------- gate blocks on empty structured log fields ----------

#[test]
fn ifc_release_gate_blocks_when_event_has_empty_component() {
    let mut run = run_ifc_corpus();
    let event = run
        .logs
        .iter_mut()
        .find(|event| event.category.is_some())
        .expect("expected at least one ifc event");
    event.component = "".to_string();

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("missing required structured log fields"))
    );
}

// ---------- gate blocks on missing source/sink labels ----------

#[test]
fn ifc_release_gate_blocks_when_source_labels_empty() {
    let mut run = run_ifc_corpus();
    let event = run
        .logs
        .iter_mut()
        .find(|event| event.category.is_some())
        .expect("expected at least one ifc event");
    event.source_labels.clear();

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("missing source/sink IFC labels"))
    );
}

// ---------- gate blocks on wrong declassify outcome ----------

#[test]
fn ifc_release_gate_blocks_when_declassify_outcome_is_wrong() {
    let mut run = run_ifc_corpus();
    let declass_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("declassify"))
        .expect("expected at least one declassify workload");

    declass_event.actual_outcome = Some("allow".to_string());

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("did not produce declassify outcome"))
    );
}

// ---------- gate blocks on wrong declassify evidence type ----------

#[test]
fn ifc_release_gate_blocks_when_declassify_evidence_type_is_wrong() {
    let mut run = run_ifc_corpus();
    let declass_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("declassify"))
        .expect("expected at least one declassify workload");

    declass_event.evidence_type = Some("none".to_string());

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("missing declassification receipt type"))
    );
}

#[test]
fn ifc_release_gate_deterministic_for_same_input() {
    let run = run_ifc_corpus();
    let a = evaluate_ifc_release_gate(&run);
    let b = evaluate_ifc_release_gate(&run);
    assert_eq!(a.blocked, b.blocked);
    assert_eq!(a.blockers.len(), b.blockers.len());
}

#[test]
fn ifc_release_gate_unmodified_corpus_is_not_blocked() {
    let run = run_ifc_corpus();
    let decision = evaluate_ifc_release_gate(&run);
    assert!(!decision.blocked, "unmodified corpus should pass gate");
}

#[test]
fn ifc_release_gate_decision_has_empty_blockers_on_pass() {
    let run = run_ifc_corpus();
    let decision = evaluate_ifc_release_gate(&run);
    if !decision.blocked {
        assert!(decision.blockers.is_empty());
    }
}

#[test]
fn ifc_corpus_covers_all_required_flow_path_types() {
    let run = run_ifc_corpus();
    let flow_paths: BTreeSet<String> = run
        .logs
        .iter()
        .filter_map(|e| e.flow_path_type.clone())
        .collect();
    for required in REQUIRED_FLOW_PATH_TYPES {
        assert!(
            flow_paths.contains(required),
            "missing required flow path type in corpus: {required}"
        );
    }
}

#[test]
fn ifc_corpus_covers_all_required_exfil_vector_domains() {
    let run = run_ifc_corpus();
    let domains: BTreeSet<String> = run.logs.iter().map(|e| e.semantic_domain.clone()).collect();
    for required in REQUIRED_EXFIL_VECTOR_DOMAINS {
        assert!(
            domains.contains(required),
            "missing required exfil vector domain in corpus: {required}"
        );
    }
}

#[test]
fn ifc_corpus_has_benign_exfil_and_declassify_categories() {
    let run = run_ifc_corpus();
    let categories: BTreeSet<String> = run.logs.iter().filter_map(|e| e.category.clone()).collect();
    for cat in ["benign", "exfil", "declassify"] {
        assert!(
            categories.contains(cat),
            "missing IFC category in corpus: {cat}"
        );
    }
}

#[test]
fn event_has_required_fields_rejects_empty_decision_id() {
    let event = ConformanceLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "  ".to_string(),
        policy_id: "policy-1".to_string(),
        component: "ifc".to_string(),
        event: "evaluate".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "asset-1".to_string(),
        workload_id: "asset-1".to_string(),
        semantic_domain: "test".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    assert!(!event_has_required_fields(&event));
}

#[test]
fn event_has_required_fields_rejects_empty_policy_id() {
    let event = ConformanceLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "".to_string(),
        component: "ifc".to_string(),
        event: "evaluate".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "asset-1".to_string(),
        workload_id: "asset-1".to_string(),
        semantic_domain: "test".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    assert!(!event_has_required_fields(&event));
}

#[test]
fn ifc_release_gate_blocks_on_direct_indirect_bypass() {
    let mut run = run_ifc_corpus();
    // Find an exfil event with direct/indirect flow path and allow it to succeed
    let exfil_event = run
        .logs
        .iter_mut()
        .find(|event| {
            event.category.as_deref() == Some("exfil")
                && matches!(event.flow_path_type.as_deref(), Some("direct" | "indirect"))
        })
        .expect("expected at least one direct/indirect exfil workload");

    exfil_event.actual_outcome = Some("allow".to_string());
    exfil_event.evidence_type = Some("none".to_string());
    exfil_event.evidence_id = None;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(decision.metrics.direct_indirect_bypass_count > 0);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("direct/indirect bypasses"))
    );
}

#[test]
fn ifc_release_gate_blocks_on_non_direct_false_negative() {
    let mut run = run_ifc_corpus();
    let exfil_event = run
        .logs
        .iter_mut()
        .find(|event| {
            event.category.as_deref() == Some("exfil")
                && matches!(
                    event.flow_path_type.as_deref(),
                    Some("implicit" | "temporal" | "covert")
                )
        })
        .expect("expected at least one non-direct exfil workload");

    exfil_event.actual_outcome = Some("allow".to_string());
    exfil_event.evidence_type = Some("none".to_string());
    exfil_event.evidence_id = None;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert_eq!(decision.metrics.unauthorized_exfil_success_count, 1);
    assert_eq!(decision.metrics.direct_indirect_bypass_count, 0);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("unauthorized exfiltration succeeded"))
    );
}

#[test]
fn ifc_release_gate_metrics_corpus_size_meets_minimum_thresholds() {
    let run = run_ifc_corpus();
    let decision = evaluate_ifc_release_gate(&run);
    assert!(
        decision.metrics.benign_total >= 100,
        "benign corpus must be >= 100, got {}",
        decision.metrics.benign_total
    );
    assert!(
        decision.metrics.exfil_total >= 80,
        "exfil corpus must be >= 80, got {}",
        decision.metrics.exfil_total
    );
    assert!(
        decision.metrics.declassify_total >= 30,
        "declassify corpus must be >= 30, got {}",
        decision.metrics.declassify_total
    );
}

// ---------- IfcReleaseGateMetrics clone/debug/eq ----------

#[test]
fn ifc_release_gate_metrics_clone_preserves_equality() {
    let metrics = IfcReleaseGateMetrics {
        benign_total: 150,
        exfil_total: 90,
        declassify_total: 40,
        false_positive_count: 2,
        unauthorized_exfil_success_count: 1,
        direct_indirect_bypass_count: 0,
    };
    let cloned = metrics.clone();
    assert_eq!(metrics, cloned);
}

#[test]
fn ifc_release_gate_metrics_debug_contains_field_names() {
    let metrics = IfcReleaseGateMetrics {
        benign_total: 0,
        exfil_total: 0,
        declassify_total: 0,
        false_positive_count: 0,
        unauthorized_exfil_success_count: 0,
        direct_indirect_bypass_count: 0,
    };
    let dbg = format!("{metrics:?}");
    assert!(dbg.contains("benign_total"));
    assert!(dbg.contains("exfil_total"));
    assert!(dbg.contains("declassify_total"));
    assert!(dbg.contains("false_positive_count"));
    assert!(dbg.contains("unauthorized_exfil_success_count"));
    assert!(dbg.contains("direct_indirect_bypass_count"));
}

#[test]
fn ifc_release_gate_metrics_inequality_on_different_values() {
    let a = IfcReleaseGateMetrics {
        benign_total: 100,
        exfil_total: 80,
        declassify_total: 30,
        false_positive_count: 0,
        unauthorized_exfil_success_count: 0,
        direct_indirect_bypass_count: 0,
    };
    let b = IfcReleaseGateMetrics {
        benign_total: 101,
        exfil_total: 80,
        declassify_total: 30,
        false_positive_count: 0,
        unauthorized_exfil_success_count: 0,
        direct_indirect_bypass_count: 0,
    };
    assert_ne!(a, b);
}

// ---------- IfcReleaseGateDecision clone/debug ----------

#[test]
fn ifc_release_gate_decision_clone_preserves_equality() {
    let decision = IfcReleaseGateDecision {
        blocked: true,
        error_code: Some("FE-IFCR-1001".to_string()),
        blockers: vec!["blocker-a".to_string(), "blocker-b".to_string()],
        metrics: IfcReleaseGateMetrics {
            benign_total: 50,
            exfil_total: 40,
            declassify_total: 10,
            false_positive_count: 1,
            unauthorized_exfil_success_count: 2,
            direct_indirect_bypass_count: 3,
        },
    };
    let cloned = decision.clone();
    assert_eq!(decision, cloned);
    assert_eq!(decision.allows_release(), cloned.allows_release());
}

#[test]
fn ifc_release_gate_decision_debug_contains_blocked_field() {
    let decision = IfcReleaseGateDecision {
        blocked: true,
        error_code: Some("FE-IFCR-1001".to_string()),
        blockers: vec!["test".to_string()],
        metrics: IfcReleaseGateMetrics {
            benign_total: 0,
            exfil_total: 0,
            declassify_total: 0,
            false_positive_count: 0,
            unauthorized_exfil_success_count: 0,
            direct_indirect_bypass_count: 0,
        },
    };
    let dbg = format!("{decision:?}");
    assert!(dbg.contains("blocked"));
    assert!(dbg.contains("error_code"));
    assert!(dbg.contains("blockers"));
    assert!(dbg.contains("metrics"));
}

// ---------- allows_release edge cases ----------

#[test]
fn allows_release_false_when_both_blocked_and_error_code() {
    let decision = IfcReleaseGateDecision {
        blocked: true,
        error_code: Some("FE-IFCR-1001".to_string()),
        blockers: vec!["dual failure".to_string()],
        metrics: IfcReleaseGateMetrics {
            benign_total: 0,
            exfil_total: 0,
            declassify_total: 0,
            false_positive_count: 0,
            unauthorized_exfil_success_count: 0,
            direct_indirect_bypass_count: 0,
        },
    };
    assert!(!decision.allows_release());
}

// ---------- event_has_required_fields — additional fields ----------

#[test]
fn event_has_required_fields_rejects_whitespace_only_component() {
    let event = ConformanceLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "   ".to_string(),
        event: "evaluate".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "asset-1".to_string(),
        workload_id: "asset-1".to_string(),
        semantic_domain: "test".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    assert!(!event_has_required_fields(&event));
}

#[test]
fn event_has_required_fields_rejects_empty_event_field() {
    let event = ConformanceLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "ifc".to_string(),
        event: "".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "asset-1".to_string(),
        workload_id: "asset-1".to_string(),
        semantic_domain: "test".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    assert!(!event_has_required_fields(&event));
}

#[test]
fn event_has_required_fields_rejects_whitespace_only_outcome() {
    let event = ConformanceLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "ifc".to_string(),
        event: "evaluate".to_string(),
        outcome: " \t ".to_string(),
        error_code: None,
        asset_id: "asset-1".to_string(),
        workload_id: "asset-1".to_string(),
        semantic_domain: "test".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    assert!(!event_has_required_fields(&event));
}

// ---------- gate blocks on empty IFC logs ----------

#[test]
fn ifc_release_gate_blocks_when_no_ifc_logs_present() {
    let mut run = run_ifc_corpus();
    // Remove all IFC-relevant logs (those with a category)
    for event in &mut run.logs {
        event.category = None;
    }
    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("manifest produced no IFC logs"))
    );
}

// ---------- gate blocks on unsupported category ----------

#[test]
fn ifc_release_gate_blocks_on_unsupported_ifc_category() {
    let mut run = run_ifc_corpus();
    let event = run
        .logs
        .iter_mut()
        .find(|e| e.category.is_some())
        .expect("expected at least one categorized event");
    event.category = Some("unknown_category".to_string());

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("unsupported IFC category `unknown_category`"))
    );
}

// ---------- gate blocks on sink_clearances empty ----------

#[test]
fn ifc_release_gate_blocks_when_sink_clearances_empty() {
    let mut run = run_ifc_corpus();
    let event = run
        .logs
        .iter_mut()
        .find(|e| e.category.is_some())
        .expect("expected at least one categorized event");
    event.sink_clearances.clear();

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("missing source/sink IFC labels"))
    );
}

// ---------- gate blocks on corpus size thresholds ----------

#[test]
fn ifc_release_gate_blocks_when_benign_corpus_too_small() {
    let mut run = run_ifc_corpus();
    // Remove all but 10 benign events to fall below the 100 threshold
    let mut benign_count = 0usize;
    for event in &mut run.logs {
        if event.category.as_deref() == Some("benign") {
            benign_count += 1;
            if benign_count > 10 {
                event.category = None;
            }
        }
    }
    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("benign corpus too small"))
    );
}

#[test]
fn ifc_release_gate_blocks_when_exfil_corpus_too_small() {
    let mut run = run_ifc_corpus();
    // Remove all but 5 exfil events to fall below the 80 threshold
    let mut exfil_count = 0usize;
    for event in &mut run.logs {
        if event.category.as_deref() == Some("exfil") {
            exfil_count += 1;
            if exfil_count > 5 {
                event.category = None;
            }
        }
    }
    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("exfil corpus too small"))
    );
}

#[test]
fn ifc_release_gate_blocks_when_declassify_corpus_too_small() {
    let mut run = run_ifc_corpus();
    // Remove all but 5 declassify events to fall below the 30 threshold
    let mut declass_count = 0usize;
    for event in &mut run.logs {
        if event.category.as_deref() == Some("declassify") {
            declass_count += 1;
            if declass_count > 5 {
                event.category = None;
            }
        }
    }
    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("declassify corpus too small"))
    );
}

// ---------- gate blocks on exfil missing flow_violation evidence type ----------

#[test]
fn ifc_release_gate_blocks_when_exfil_evidence_type_wrong() {
    let mut run = run_ifc_corpus();
    let exfil_event = run
        .logs
        .iter_mut()
        .find(|e| e.category.as_deref() == Some("exfil"))
        .expect("expected at least one exfil workload");
    exfil_event.evidence_type = Some("incorrect_type".to_string());

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("missing flow_violation evidence type"))
    );
}

// ---------- gate blocks on empty evidence_id for exfil ----------

#[test]
fn ifc_release_gate_blocks_when_exfil_evidence_id_is_whitespace() {
    let mut run = run_ifc_corpus();
    let exfil_event = run
        .logs
        .iter_mut()
        .find(|e| e.category.as_deref() == Some("exfil"))
        .expect("expected at least one exfil workload");
    exfil_event.evidence_id = Some("   ".to_string());

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("missing evidence_id receipt handle"))
    );
}

// ---------- gate blocks on declassify receipt not starting with dr- ----------

#[test]
fn ifc_release_gate_blocks_when_declassify_receipt_lacks_dr_prefix() {
    let mut run = run_ifc_corpus();
    let declass_event = run
        .logs
        .iter_mut()
        .find(|e| e.category.as_deref() == Some("declassify"))
        .expect("expected at least one declassify workload");
    declass_event.evidence_id = Some("no-prefix-receipt".to_string());

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("missing signed receipt handle"))
    );
}

// ---------- constants unique and non-empty ----------

#[test]
fn required_flow_path_types_are_unique() {
    let set: BTreeSet<&str> = REQUIRED_FLOW_PATH_TYPES.iter().copied().collect();
    assert_eq!(set.len(), REQUIRED_FLOW_PATH_TYPES.len());
}

#[test]
fn required_exfil_vector_domains_are_unique() {
    let set: BTreeSet<&str> = REQUIRED_EXFIL_VECTOR_DOMAINS.iter().copied().collect();
    assert_eq!(set.len(), REQUIRED_EXFIL_VECTOR_DOMAINS.len());
}

#[test]
fn required_flow_path_types_all_nonempty() {
    for path_type in REQUIRED_FLOW_PATH_TYPES {
        assert!(
            !path_type.trim().is_empty(),
            "flow path type must not be empty"
        );
    }
}

#[test]
fn required_exfil_vector_domains_all_nonempty() {
    for domain in REQUIRED_EXFIL_VECTOR_DOMAINS {
        assert!(!domain.trim().is_empty(), "domain must not be empty");
    }
}

// ---------- gate accumulates multiple blockers ----------

#[test]
fn ifc_release_gate_accumulates_multiple_blockers() {
    let mut run = run_ifc_corpus();
    // Corrupt both a benign and an exfil event simultaneously
    for event in &mut run.logs {
        if event.category.as_deref() == Some("benign") {
            event.actual_outcome = Some("block".to_string());
            break;
        }
    }
    for event in &mut run.logs {
        if event.category.as_deref() == Some("exfil") {
            event.actual_outcome = Some("allow".to_string());
            event.evidence_type = Some("none".to_string());
            event.evidence_id = None;
            break;
        }
    }
    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    // Should have at least two blockers: false positive + unauthorized exfil
    assert!(
        decision.blockers.len() >= 2,
        "expected at least 2 blockers, got {}",
        decision.blockers.len()
    );
    let has_fp = decision
        .blockers
        .iter()
        .any(|b| b.contains("false positives"));
    let has_exfil = decision
        .blockers
        .iter()
        .any(|b| b.contains("unauthorized exfiltration succeeded"));
    assert!(has_fp, "expected false positive blocker");
    assert!(has_exfil, "expected unauthorized exfiltration blocker");
}

// ---------- gate blocks when ci gate fails ----------

#[test]
fn ifc_release_gate_blocks_when_summary_has_failures() {
    let mut run = run_ifc_corpus();
    run.summary.failed = 1;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("run summary contains failures"))
    );
}

#[test]
fn ifc_release_gate_blocks_when_summary_has_errors() {
    let mut run = run_ifc_corpus();
    run.summary.errored = 3;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("run summary contains failures"))
    );
}

// ---------- metrics zero-value construction ----------

#[test]
fn ifc_release_gate_metrics_all_zeros() {
    let metrics = IfcReleaseGateMetrics {
        benign_total: 0,
        exfil_total: 0,
        declassify_total: 0,
        false_positive_count: 0,
        unauthorized_exfil_success_count: 0,
        direct_indirect_bypass_count: 0,
    };
    assert_eq!(metrics.benign_total, 0);
    assert_eq!(metrics.exfil_total, 0);
    assert_eq!(metrics.declassify_total, 0);
    assert_eq!(metrics.false_positive_count, 0);
    assert_eq!(metrics.unauthorized_exfil_success_count, 0);
    assert_eq!(metrics.direct_indirect_bypass_count, 0);
}

// ---------- metrics usize::MAX boundary ----------

#[test]
fn ifc_release_gate_metrics_max_values() {
    let metrics = IfcReleaseGateMetrics {
        benign_total: usize::MAX,
        exfil_total: usize::MAX,
        declassify_total: usize::MAX,
        false_positive_count: usize::MAX,
        unauthorized_exfil_success_count: usize::MAX,
        direct_indirect_bypass_count: usize::MAX,
    };
    let cloned = metrics.clone();
    assert_eq!(metrics, cloned);
    assert_eq!(metrics.benign_total, usize::MAX);
}

// ---------- decision with empty blockers but blocked true ----------

#[test]
fn ifc_release_gate_decision_blocked_with_empty_blockers_still_blocked() {
    let decision = IfcReleaseGateDecision {
        blocked: true,
        error_code: None,
        blockers: Vec::new(),
        metrics: IfcReleaseGateMetrics {
            benign_total: 100,
            exfil_total: 80,
            declassify_total: 30,
            false_positive_count: 0,
            unauthorized_exfil_success_count: 0,
            direct_indirect_bypass_count: 0,
        },
    };
    // blocked is true, so allows_release returns false
    assert!(!decision.allows_release());
}

// ---------- gate blocks on missing flow path coverage ----------

#[test]
fn ifc_release_gate_blocks_when_flow_path_coverage_missing() {
    let mut run = run_ifc_corpus();
    // Remove all "covert" flow path types so coverage check fails
    for event in &mut run.logs {
        if event.flow_path_type.as_deref() == Some("covert") {
            event.flow_path_type = None;
        }
    }
    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("missing exfil flow-path coverage `covert`"))
    );
}

// ---------- gate blocks on missing vector domain coverage ----------

#[test]
fn ifc_release_gate_blocks_when_vector_domain_coverage_missing() {
    let mut run = run_ifc_corpus();
    let target_domain = REQUIRED_EXFIL_VECTOR_DOMAINS[0];
    // Remove all events matching the first required exfil vector domain
    for event in &mut run.logs {
        if event.semantic_domain == target_domain {
            event.semantic_domain = "unrelated_domain".to_string();
        }
    }
    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(decision.blockers.iter().any(|b| b.contains(&format!(
        "missing bypass-vector corpus coverage `{target_domain}`"
    ))));
}

// ---------- manifest path correctness ----------

#[test]
fn ifc_manifest_path_ends_with_expected_filename() {
    let path = manifest_path();
    assert_eq!(
        path.file_name().and_then(|n| n.to_str()),
        Some("ifc_conformance_assets.json")
    );
}

#[test]
fn ifc_manifest_path_contains_ifc_corpus_dir() {
    let path = manifest_path();
    let path_str = path.to_string_lossy();
    assert!(
        path_str.contains("ifc_corpus"),
        "manifest path should contain ifc_corpus directory"
    );
}

// ---------- gate blocks on whitespace-only trace_id in categorized event ----------

#[test]
fn ifc_release_gate_blocks_when_categorized_event_has_whitespace_trace_id() {
    let mut run = run_ifc_corpus();
    let event = run
        .logs
        .iter_mut()
        .find(|e| e.category.is_some())
        .expect("expected at least one categorized event");
    event.trace_id = "   ".to_string();

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("missing required structured log fields"))
    );
}

#[test]
fn ifc_release_gate_replay_wrapper_executes_latest_complete_fixture_bundle() {
    let artifact_root = temp_dir("ifc_release_gate_replay_fixture");
    let complete_run_dir =
        write_complete_ifc_replay_fixture(&artifact_root, "20250101T000000Z", "older-complete");

    let output = Command::new(repo_root().join("scripts/e2e/ifc_release_gate_replay.sh"))
        .current_dir(repo_root())
        .env("IFC_RELEASE_GATE_ARTIFACT_ROOT", &artifact_root)
        .arg("unsupported-mode")
        .output()
        .expect("replay wrapper should execute");

    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("newest directory")
            && stderr.contains("using latest complete run directory"),
        "stderr should explain incomplete newest bundle selection: {stderr}"
    );
    assert!(
        !stderr.contains("No such file or directory"),
        "wrapper should avoid noisy missing-file errors: {stderr}"
    );
    assert!(stdout.contains(&format!(
        "[ifc-release-gate] latest manifest: {}/run_manifest.json",
        complete_run_dir.display()
    )));
    assert!(stdout.contains("older-complete"));
    assert!(stdout.contains("fixture-command older-complete"));
    assert!(stdout.contains("ifc_conformance_evidence.jsonl"));
}

#[test]
fn ifc_release_gate_replay_wrapper_fails_closed_without_complete_bundle() {
    let artifact_root = temp_dir("ifc_release_gate_replay_fail_closed");

    let output = Command::new(repo_root().join("scripts/e2e/ifc_release_gate_replay.sh"))
        .current_dir(repo_root())
        .env("IFC_RELEASE_GATE_ARTIFACT_ROOT", &artifact_root)
        .arg("unsupported-mode")
        .output()
        .expect("replay wrapper should execute");

    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("could not locate a complete run directory under"),
        "stderr should explain why the wrapper failed closed: {stderr}"
    );
    assert!(
        !stderr.contains("No such file or directory"),
        "wrapper should avoid noisy missing-file errors: {stderr}"
    );
    assert!(
        !stdout.contains("[ifc-release-gate] latest manifest:"),
        "wrapper should not print canonical artifacts when no complete bundle exists"
    );

    let newest_run_dir = latest_run_dir(&artifact_root);
    let manifest: Value = serde_json::from_slice(
        &fs::read(newest_run_dir.join("run_manifest.json"))
            .expect("fail-closed manifest should exist"),
    )
    .expect("fail-closed manifest should parse");
    assert_eq!(manifest["outcome"].as_str(), Some("fail"));
    assert_eq!(
        manifest["failed_command"].as_str(),
        Some("./scripts/run_ifc_release_gate.sh unsupported-mode")
    );
    assert_eq!(
        manifest["artifacts"]["suite_replay"].as_str(),
        Some("./scripts/e2e/ifc_release_gate_replay.sh unsupported-mode")
    );

    let events = fs::read_to_string(newest_run_dir.join("ifc_release_gate_events.jsonl"))
        .expect("fail-closed events should exist");
    assert!(events.contains("\"outcome\":\"fail\""));
    assert!(events.contains("\"error_code\":\"FE-IFCR-1003\""));
}
