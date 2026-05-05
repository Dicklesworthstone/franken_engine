#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_engine::proof_evidence_index::{
    GateReportImport, import_gate_report_json, import_proof_cost_manifest_json,
    import_proof_manifest_json, import_validation_plan_json, proof_evidence_query_report_json,
    query_proof_by_bead, query_recent_failed_gates,
};
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};
use serde_json::{Value, json};

const BEAD_ID: &str = "bd-3snv2";
const GENERATED_MS: i64 = 1_777_000_000_000;
const FRESHNESS_MS: i64 = 86_400_000;

#[derive(Debug)]
struct Harness {
    repo_root: PathBuf,
    run_root: PathBuf,
    commands_path: PathBuf,
    events_path: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let repo_root = repo_root();
        let run_root = std::env::var_os("SWARM_VALIDATION_CONTROL_PLANE_E2E_ARTIFACT_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                repo_root
                    .join("artifacts")
                    .join("swarm_validation_control_plane_e2e")
                    .join(format!("cargo-test-{}", std::process::id()))
            });
        let run_root = if run_root.is_absolute() {
            run_root
        } else {
            repo_root.join(run_root)
        };
        fs::create_dir_all(&run_root).expect("create e2e run root");
        let commands_path = run_root.join("commands.txt");
        let events_path = run_root.join("events.jsonl");
        fs::write(&commands_path, "").expect("initialize command log");
        fs::write(&events_path, "").expect("initialize event log");
        Self {
            repo_root,
            run_root,
            commands_path,
            events_path,
        }
    }

    fn run<I, S>(
        &self,
        step: &str,
        program: &str,
        args: I,
        envs: &[(&str, &str)],
        expected_exit_codes: &[i32],
    ) where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args: Vec<String> = args
            .into_iter()
            .map(|arg| arg.as_ref().to_string_lossy().into_owned())
            .collect();
        let step_dir = self.run_root.join(step);
        fs::create_dir_all(&step_dir).expect("create step dir");
        append_line(
            &self.commands_path,
            &format!("{} {}", program, shell_join(&args)),
        );

        let mut command = Command::new(program);
        command.current_dir(&self.repo_root);
        command.args(&args);
        for (key, value) in envs {
            command.env(key, value);
        }
        let output = command.output().unwrap_or_else(|err| {
            panic!("failed to run {step} command `{program}`: {err}");
        });
        let exit_code = exit_code(&output);
        let stdout_path = step_dir.join("stdout.log");
        let stderr_path = step_dir.join("stderr.log");
        fs::write(&stdout_path, &output.stdout).expect("write stdout log");
        fs::write(&stderr_path, &output.stderr).expect("write stderr log");

        let decision = if expected_exit_codes.contains(&exit_code) {
            "pass"
        } else {
            "fail"
        };
        append_json_line(
            &self.events_path,
            json!({
                "schema_version": "franken-engine.proof-artifact-event.v1",
                "event_name": "swarm_validation_control_plane_e2e.component_invoked",
                "severity": if decision == "pass" { "info" } else { "error" },
                "step_id": step,
                "command_id": step,
                "decision": decision,
                "exit_code": exit_code,
                "duration_ms": 0,
                "stdout_path": path_string(&stdout_path),
                "stderr_path": path_string(&stderr_path)
            }),
        );

        if !expected_exit_codes.contains(&exit_code) {
            panic!(
                "{step} exited {exit_code}, expected {:?}; stdout={}, stderr={}",
                expected_exit_codes,
                path_string(&stdout_path),
                path_string(&stderr_path)
            );
        }
    }

    fn write_json(&self, relative_path: &str, value: Value) -> PathBuf {
        let path = self.run_root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create json parent");
        }
        fs::write(
            &path,
            serde_json::to_vec_pretty(&value).expect("serialize json fixture"),
        )
        .expect("write json fixture");
        path
    }
}

#[test]
fn no_mock_control_plane_e2e_imports_and_reports_pass_and_degraded_paths() {
    let harness = Harness::new();
    let source_revision = git_head(&harness.repo_root);
    let contract_path = harness
        .repo_root
        .join("docs/swarm_validation_control_plane_contract_v1.json");
    let contract = read_json(&contract_path);
    assert_eq!(
        contract["schema_version"],
        "franken-engine.swarm-validation-control-plane-contract.v1"
    );
    assert!(
        contract["workload_surfaces"]
            .as_array()
            .expect("contract surfaces")
            .iter()
            .any(|surface| surface["surface_id"] == "focused_proof_runner")
    );

    let scope_path = harness.write_json(
        "inputs/rch-policy-scope.json",
        json!([
            "scripts/e2e/swarm_validation_control_plane_e2e.sh",
            "docs/swarm_validation_control_plane_contract_v1.json",
            "scripts/focused_proof_runner.sh",
            "scripts/focused_proof_cost_gate.sh",
            "scripts/swarm_validation_planner.sh",
            "scripts/swarm_resource_governor.sh",
            "scripts/swarm_operator_status_report.sh"
        ]),
    );
    let scope_txt = harness.run_root.join("inputs/rch-policy-scope.txt");
    fs::write(
        &scope_txt,
        read_json(&scope_path)
            .as_array()
            .expect("scope array")
            .iter()
            .map(|item| item.as_str().expect("scope string"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("write scope text");
    let rch_policy_pass_dir = harness.run_root.join("pass/rch-policy");
    harness.run(
        "rch-policy-pass",
        "scripts/rch_policy_compliance_gate.sh",
        [
            "--output-dir",
            path_str(&rch_policy_pass_dir),
            "--scope-file",
            path_str(&scope_txt),
        ],
        &[],
        &[0],
    );

    let validation_plan_pass_dir = harness.run_root.join("pass/validation-plan");
    harness.run(
        "validation-plan-pass",
        "scripts/swarm_validation_planner.sh",
        [
            "--bead-id",
            BEAD_ID,
            "--source-revision",
            &source_revision,
            "--output-dir",
            path_str(&validation_plan_pass_dir),
            "--package",
            "frankenengine-engine",
            "--test-target",
            "swarm_validation_control_plane_e2e",
            "--changed-path",
            "scripts/e2e/swarm_validation_control_plane_e2e.sh",
            "--changed-path",
            "crates/franken-engine/tests/swarm_validation_control_plane_e2e.rs",
        ],
        &[("SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE", "")],
        &[0],
    );
    let pass_plan_path = harness.run_root.join("pass/validation-plan/plan.json");
    let pass_plan = read_json(&pass_plan_path);
    assert_ne!(pass_plan["decision"], "fail_closed");
    assert!(
        pass_plan["commands"]
            .as_array()
            .expect("planned commands")
            .iter()
            .any(
                |command| command["display"].as_str().unwrap_or_default().contains(
                    "cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e"
                )
            )
    );

    let resource_governor_pass_dir = harness.run_root.join("pass/resource-governor");
    harness.run(
        "resource-governor-pass",
        "scripts/swarm_resource_governor.sh",
        [
            "--bead-id",
            BEAD_ID,
            "--output-dir",
            path_str(&resource_governor_pass_dir),
            "--active-compile-count",
            "0",
            "--disk-available-bytes",
            "2147483648",
            "--target-dir",
            "/tmp/rch_target_franken_engine_bd_3snv2_e2e",
            "--target-dir-writable",
            "true",
            "--memory-available-bytes",
            "2147483648",
            "--rch-present",
            "true",
            "--rch-status",
            "ok",
            "--rch-fallback-detected",
            "false",
            "--command-exit-code",
            "0",
            "--command-failure-kind",
            "none",
            "--ownership-state",
            "none",
            "--dirty-state",
            "clean",
        ],
        &[],
        &[0],
    );
    let pass_decision_path = harness
        .run_root
        .join("pass/resource-governor/decision.json");
    assert_eq!(read_json(&pass_decision_path)["decision"], "admit");

    let focused_root = harness.run_root.join("pass/focused-proof-runner");
    harness.run(
        "focused-proof-runner-pass",
        "scripts/focused_proof_runner.sh",
        std::iter::empty::<&str>(),
        &[
            ("FOCUSED_PROOF_ARTIFACT_ROOT", path_str(&focused_root)),
            ("FOCUSED_PROOF_RUN_ID", "pass"),
            ("FOCUSED_PROOF_BEAD_ID", BEAD_ID),
            (
                "FOCUSED_PROOF_SUITE",
                "swarm_validation_control_plane_e2e",
            ),
            ("FOCUSED_PROOF_COMMAND", "printf swarm-control-plane-ok"),
            ("FOCUSED_PROOF_CARGO_PACKAGE", "frankenengine-engine"),
            (
                "FOCUSED_PROOF_EXPECTED_TARGETS",
                "swarm_validation_control_plane_e2e,frankenengine-engine",
            ),
            (
                "FOCUSED_PROOF_OBSERVED_TARGETS",
                "frankenengine-engine|test|swarm_validation_control_plane_e2e|test|true|true|explicit e2e\nfrankenengine-engine|lib|frankenengine-engine|test|true|false|test harness dependency",
            ),
            ("FOCUSED_PROOF_WORKER", "control-plane-e2e"),
            (
                "FOCUSED_PROOF_SYNC_ROOTS",
                "/data/projects/franken_engine,/dp/frankensqlite,/dp/sqlmodel_rust",
            ),
            ("FOCUSED_PROOF_DURATION_MS_OVERRIDE", "0"),
        ],
        &[0],
    );
    let focused_manifest_path = focused_root.join("pass/manifest.json");
    let proof_cost_path = focused_root.join("pass/proof_cost_manifest.json");
    let focused_report_path = focused_root.join("pass/source_report.json");
    assert_eq!(read_json(&focused_manifest_path)["status"], "pass");

    let budget_path = harness.write_json(
        "pass/proof-cost-budget.json",
        json!({
            "schema_version": "franken-engine.focused-proof-cost-budget.v1",
            "suite": "swarm_validation_control_plane_e2e",
            "max_total_compiled_targets": 2,
            "max_total_linked_targets": 1,
            "max_unexpected_targets": 0,
            "max_targets_by_kind": {
                "test": 1,
                "lib": 1
            },
            "upstream_beads": ["bd-7kc4g", "bd-1onpa", "bd-zmuv5", "bd-p03vs", "bd-jw854"],
            "gated_bead": BEAD_ID
        }),
    );
    let proof_cost_gate_pass_dir = harness.run_root.join("pass/proof-cost-gate");
    harness.run(
        "focused-proof-cost-gate-pass",
        "scripts/focused_proof_cost_gate.sh",
        [
            path_str(&proof_cost_path),
            path_str(&budget_path),
            path_str(&proof_cost_gate_pass_dir),
        ],
        &[],
        &[0],
    );
    let cost_gate_report_path = harness
        .run_root
        .join("pass/proof-cost-gate/diagnostics.json");
    assert_eq!(read_json(&cost_gate_report_path)["status"], "pass");

    let mut adapter = InMemoryStorageAdapter::new();
    let context = EventContext::new(
        "trace-swarm-control-plane-e2e",
        "decision-swarm-control-plane-e2e",
        "policy-swarm-control-plane-e2e",
    )
    .expect("valid event context");

    import_proof_manifest_json(
        &mut adapter,
        &fs::read_to_string(&focused_manifest_path).expect("read focused manifest"),
        &source_revision,
        FRESHNESS_MS,
        &context,
    )
    .expect("focused proof manifest imports");
    import_proof_cost_manifest_json(
        &mut adapter,
        &fs::read_to_string(&proof_cost_path).expect("read proof cost manifest"),
        &source_revision,
        &source_revision,
        GENERATED_MS,
        FRESHNESS_MS,
        &context,
    )
    .expect("proof cost manifest imports");
    import_validation_plan_json(
        &mut adapter,
        &fs::read_to_string(&pass_plan_path).expect("read validation plan"),
        &source_revision,
        GENERATED_MS,
        FRESHNESS_MS,
        &context,
    )
    .expect("validation plan imports");
    import_gate_report_json(
        &mut adapter,
        &fs::read_to_string(&focused_report_path).expect("read focused report"),
        GateReportImport {
            bead_id: BEAD_ID,
            source_revision: &source_revision,
            artifact_path: path_str(&focused_report_path),
            expected_source_revision: &source_revision,
            generated_timestamp_ms: GENERATED_MS,
            freshness_policy_ms: FRESHNESS_MS,
        },
        &context,
    )
    .expect("focused runner report imports");
    import_gate_report_json(
        &mut adapter,
        &fs::read_to_string(&cost_gate_report_path).expect("read cost gate report"),
        GateReportImport {
            bead_id: BEAD_ID,
            source_revision: &source_revision,
            artifact_path: path_str(&cost_gate_report_path),
            expected_source_revision: &source_revision,
            generated_timestamp_ms: GENERATED_MS,
            freshness_policy_ms: FRESHNESS_MS,
        },
        &context,
    )
    .expect("cost gate report imports");

    let pass_rows =
        query_proof_by_bead(&mut adapter, BEAD_ID, &context).expect("proof evidence query by bead");
    let receipt_kinds: Vec<&str> = pass_rows
        .iter()
        .map(|row| row.receipt_kind.as_str())
        .collect();
    for required in [
        "command_receipt",
        "proof_artifact",
        "proof_cost_manifest",
        "validation_command",
        "validation_plan",
        "gate_report",
    ] {
        assert!(
            receipt_kinds.contains(&required),
            "missing proof evidence receipt kind {required}: {receipt_kinds:?}"
        );
    }
    let proof_index_path = harness.write_json(
        "pass/proof-index.json",
        serde_json::from_str(
            &proof_evidence_query_report_json("proof_by_bead", pass_rows)
                .expect("proof index report serializes"),
        )
        .expect("proof index report parses"),
    );

    let fixtures = write_status_fixtures(
        &harness,
        &source_revision,
        &pass_decision_path,
        &pass_plan_path,
        &proof_index_path,
        "pass",
    );
    let operator_status_pass_dir = harness.run_root.join("pass/operator-status");
    harness.run(
        "operator-status-pass",
        "scripts/swarm_operator_status_report.sh",
        [
            "--bead-id",
            BEAD_ID,
            "--source-revision",
            &source_revision,
            "--output-dir",
            path_str(&operator_status_pass_dir),
            "--agent-mail-status",
            "ok",
            "--rch-status",
            "ok",
            "--proof-index-status",
            "ok",
            "--ready-json",
            path_str(&fixtures.ready),
            "--in-progress-json",
            path_str(&fixtures.in_progress),
            "--bv-plan-json",
            path_str(&fixtures.bv_plan),
            "--reservations-json",
            path_str(&fixtures.reservations),
            "--resource-decision-json",
            path_str(&pass_decision_path),
            "--validation-plan-json",
            path_str(&pass_plan_path),
            "--proof-index-json",
            path_str(&proof_index_path),
            "--proof-outcomes-json",
            path_str(&fixtures.proof_outcomes),
            "--stale-evidence-json",
            path_str(&fixtures.stale_evidence),
            "--dirty-files-json",
            path_str(&fixtures.dirty_files),
        ],
        &[],
        &[0],
    );
    let pass_status_path = harness.run_root.join("pass/operator-status/status.json");
    assert_eq!(read_json(&pass_status_path)["status"], "healthy");

    let validation_plan_degraded_dir = harness.run_root.join("degraded/validation-plan");
    harness.run(
        "validation-plan-degraded",
        "scripts/swarm_validation_planner.sh",
        [
            "--bead-id",
            BEAD_ID,
            "--source-revision",
            &source_revision,
            "--output-dir",
            path_str(&validation_plan_degraded_dir),
            "--changed-path",
            "unknown/control-plane/path.rs",
        ],
        &[("SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE", "")],
        &[42],
    );
    let degraded_plan_path = harness.run_root.join("degraded/validation-plan/plan.json");
    assert_eq!(read_json(&degraded_plan_path)["decision"], "fail_closed");

    let resource_governor_degraded_dir = harness.run_root.join("degraded/resource-governor");
    harness.run(
        "resource-governor-degraded",
        "scripts/swarm_resource_governor.sh",
        [
            "--bead-id",
            BEAD_ID,
            "--output-dir",
            path_str(&resource_governor_degraded_dir),
            "--active-compile-count",
            "5",
            "--disk-available-bytes",
            "64",
            "--target-dir",
            "/tmp/rch_target_franken_engine_bd_3snv2_e2e",
            "--target-dir-writable",
            "true",
            "--memory-available-bytes",
            "2147483648",
            "--rch-present",
            "true",
            "--rch-status",
            "ok",
            "--rch-fallback-detected",
            "true",
            "--command-exit-code",
            "0",
            "--command-failure-kind",
            "none",
            "--ownership-state",
            "none",
            "--dirty-state",
            "clean",
        ],
        &[],
        &[42],
    );
    let degraded_decision_path = harness
        .run_root
        .join("degraded/resource-governor/decision.json");
    assert_eq!(
        read_json(&degraded_decision_path)["decision"],
        "fail_closed"
    );

    let broad_root = harness.run_root.join("degraded/focused-proof-runner");
    harness.run(
        "focused-proof-runner-degraded",
        "scripts/focused_proof_runner.sh",
        std::iter::empty::<&str>(),
        &[
            ("FOCUSED_PROOF_ARTIFACT_ROOT", path_str(&broad_root)),
            ("FOCUSED_PROOF_RUN_ID", "broadening"),
            ("FOCUSED_PROOF_BEAD_ID", BEAD_ID),
            (
                "FOCUSED_PROOF_SUITE",
                "swarm_validation_control_plane_e2e",
            ),
            ("FOCUSED_PROOF_COMMAND", "printf swarm-control-plane-ok"),
            ("FOCUSED_PROOF_CARGO_PACKAGE", "frankenengine-engine"),
            (
                "FOCUSED_PROOF_EXPECTED_TARGETS",
                "swarm_validation_control_plane_e2e",
            ),
            (
                "FOCUSED_PROOF_OBSERVED_TARGETS",
                "frankenengine-engine|test|swarm_validation_control_plane_e2e|test|true|true|explicit e2e\nfrankenengine-engine|test|unexpected_broad_target|test|true|true|hidden fanout",
            ),
            ("FOCUSED_PROOF_WORKER", "control-plane-e2e"),
            ("FOCUSED_PROOF_DURATION_MS_OVERRIDE", "0"),
        ],
        &[42],
    );
    let broad_report_path = broad_root.join("broadening/source_report.json");
    import_gate_report_json(
        &mut adapter,
        &fs::read_to_string(&broad_report_path).expect("read broadening report"),
        GateReportImport {
            bead_id: BEAD_ID,
            source_revision: &source_revision,
            artifact_path: path_str(&broad_report_path),
            expected_source_revision: &source_revision,
            generated_timestamp_ms: GENERATED_MS + 1,
            freshness_policy_ms: FRESHNESS_MS,
        },
        &context,
    )
    .expect("failed focused runner report imports");
    let failed_rows =
        query_recent_failed_gates(&mut adapter, 10, &context).expect("failed gates query");
    assert!(
        failed_rows
            .iter()
            .any(|row| row.receipt_kind == "gate_report"),
        "degraded gate report should be indexed as failed evidence"
    );
    let failed_index_path = harness.write_json(
        "degraded/proof-index.json",
        serde_json::from_str(
            &proof_evidence_query_report_json("recent_failed_gates", failed_rows)
                .expect("failed proof index report serializes"),
        )
        .expect("failed proof index report parses"),
    );

    let degraded_fixtures = write_status_fixtures(
        &harness,
        &source_revision,
        &degraded_decision_path,
        &degraded_plan_path,
        &failed_index_path,
        "degraded",
    );
    let operator_status_degraded_dir = harness.run_root.join("degraded/operator-status");
    harness.run(
        "operator-status-degraded",
        "scripts/swarm_operator_status_report.sh",
        [
            "--bead-id",
            BEAD_ID,
            "--source-revision",
            &source_revision,
            "--output-dir",
            path_str(&operator_status_degraded_dir),
            "--agent-mail-status",
            "ok",
            "--rch-status",
            "ok",
            "--proof-index-status",
            "ok",
            "--ready-json",
            path_str(&degraded_fixtures.ready),
            "--in-progress-json",
            path_str(&degraded_fixtures.in_progress),
            "--bv-plan-json",
            path_str(&degraded_fixtures.bv_plan),
            "--reservations-json",
            path_str(&degraded_fixtures.reservations),
            "--resource-decision-json",
            path_str(&degraded_decision_path),
            "--validation-plan-json",
            path_str(&degraded_plan_path),
            "--proof-index-json",
            path_str(&failed_index_path),
            "--proof-outcomes-json",
            path_str(&degraded_fixtures.proof_outcomes),
            "--stale-evidence-json",
            path_str(&degraded_fixtures.stale_evidence),
            "--dirty-files-json",
            path_str(&degraded_fixtures.dirty_files),
        ],
        &[],
        &[0],
    );
    let degraded_status_path = harness
        .run_root
        .join("degraded/operator-status/status.json");
    assert_eq!(read_json(&degraded_status_path)["status"], "degraded");

    let component_steps = read_json_lines(&harness.events_path)
        .into_iter()
        .filter_map(|event| event["step_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    for required_step in [
        "rch-policy-pass",
        "validation-plan-pass",
        "resource-governor-pass",
        "focused-proof-runner-pass",
        "focused-proof-cost-gate-pass",
        "operator-status-pass",
        "validation-plan-degraded",
        "resource-governor-degraded",
        "focused-proof-runner-degraded",
        "operator-status-degraded",
    ] {
        assert!(
            component_steps.iter().any(|step| step == required_step),
            "missing component invocation {required_step}: {component_steps:?}"
        );
    }

    let report_path = harness.write_json(
        "control_plane_report.json",
        json!({
            "schema_version": "franken-engine.swarm-validation-control-plane-e2e.v1",
            "status": "pass",
            "bead_id": BEAD_ID,
            "source_revision": source_revision,
            "contract_input": path_string(&contract_path),
            "resource_decisions": {
                "pass": path_string(&pass_decision_path),
                "degraded": path_string(&degraded_decision_path)
            },
            "validation_plans": {
                "pass": path_string(&pass_plan_path),
                "degraded": path_string(&degraded_plan_path)
            },
            "rch_policy": path_string(&harness.run_root.join("pass/rch-policy/diagnostics.json")),
            "focused_proof": {
                "manifest": path_string(&focused_manifest_path),
                "proof_cost_manifest": path_string(&proof_cost_path),
                "cost_gate_report": path_string(&cost_gate_report_path)
            },
            "proof_evidence_index": {
                "pass": path_string(&proof_index_path),
                "failed_gates": path_string(&failed_index_path)
            },
            "operator_status": {
                "pass": path_string(&pass_status_path),
                "degraded": path_string(&degraded_status_path)
            },
            "events_jsonl": path_string(&harness.events_path),
            "commands_txt": path_string(&harness.commands_path)
        }),
    );
    let markdown_path = harness.run_root.join("control_plane_report.md");
    fs::write(
        &markdown_path,
        format!(
            "# Swarm Validation Control Plane E2E\n\n- Status: `pass`\n- Report: `{}`\n- Events: `{}`\n- Commands: `{}`\n",
            path_string(&report_path),
            path_string(&harness.events_path),
            path_string(&harness.commands_path)
        ),
    )
    .expect("write markdown report");

    println!(
        "swarm_validation_control_plane_e2e_artifacts={}",
        path_string(&harness.run_root)
    );
    println!(
        "swarm_validation_control_plane_e2e_report={}",
        path_string(&report_path)
    );
}

#[derive(Debug)]
struct StatusFixtures {
    ready: PathBuf,
    in_progress: PathBuf,
    bv_plan: PathBuf,
    reservations: PathBuf,
    proof_outcomes: PathBuf,
    stale_evidence: PathBuf,
    dirty_files: PathBuf,
}

fn write_status_fixtures(
    harness: &Harness,
    source_revision: &str,
    resource_decision_path: &Path,
    validation_plan_path: &Path,
    proof_index_path: &Path,
    mode: &str,
) -> StatusFixtures {
    let prefix = format!("{mode}/status-fixtures");
    let ready = harness.write_json(
        &format!("{prefix}/ready.json"),
        json!([{
            "id": "bd-ckrz1",
            "title": "Next swarm-control follow-up",
            "priority": 1,
            "status": "open",
            "assignee": null
        }]),
    );
    let in_progress = harness.write_json(
        &format!("{prefix}/in-progress.json"),
        json!([{
            "id": BEAD_ID,
            "title": "No-mock e2e proof for the swarm validation control plane",
            "priority": 1,
            "status": "in_progress",
            "assignee": "SandyThrush"
        }]),
    );
    let bv_plan = harness.write_json(
        &format!("{prefix}/bv-plan.json"),
        json!({
            "plan": {
                "tracks": [{
                    "track_id": "track-control-plane",
                    "items": [{
                        "id": BEAD_ID,
                        "title": "No-mock e2e proof for the swarm validation control plane",
                        "priority": 1,
                        "status": "in_progress"
                    }]
                }]
            }
        }),
    );
    let reservations = harness.write_json(
        &format!("{prefix}/reservations.json"),
        json!([{
            "path": "scripts/e2e/swarm_validation_control_plane_e2e.sh",
            "holder": "SandyThrush",
            "exclusive": true
        }, {
            "path": "crates/franken-engine/tests/swarm_validation_control_plane_e2e.rs",
            "holder": "SandyThrush",
            "exclusive": true
        }]),
    );
    let proof_outcomes = harness.write_json(
        &format!("{prefix}/proof-outcomes.json"),
        json!([{
            "bead_id": BEAD_ID,
            "artifact_id": format!("control-plane-{mode}"),
            "status": if mode == "pass" { "pass" } else { "fail" },
            "source_revision": source_revision,
            "resource_decision": path_string(resource_decision_path),
            "validation_plan": path_string(validation_plan_path),
            "proof_index": path_string(proof_index_path)
        }]),
    );
    let stale_evidence = harness.write_json(
        &format!("{prefix}/stale-evidence.json"),
        if mode == "pass" {
            json!([])
        } else {
            json!([{
                "artifact_id": "control-plane-stale-proof",
                "stale": true,
                "age_hours": 72
            }])
        },
    );
    let dirty_files = harness.write_json(
        &format!("{prefix}/dirty-files.json"),
        if mode == "pass" {
            json!([])
        } else {
            json!([{
                "path": "crates/franken-engine/src/semantic_dark_matter_engine.rs",
                "reserved": true,
                "overlaps_ready": true
            }])
        },
    );

    StatusFixtures {
        ready,
        in_progress,
        bv_plan,
        reservations,
        proof_outcomes,
        stale_evidence,
        dirty_files,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repo root")
}

fn git_head(repo_root: &Path) -> String {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse runs");
    assert!(
        output.status.success(),
        "git rev-parse failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git stdout utf8")
        .trim()
        .to_string()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|err| {
        panic!("read json {} failed: {err}", path.display());
    }))
    .unwrap_or_else(|err| panic!("parse json {} failed: {err}", path.display()))
}

fn read_json_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read json lines {} failed: {err}", path.display()))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("event json parses"))
        .collect()
}

fn append_line(path: &Path, line: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .expect("open append file");
    writeln!(file, "{line}").expect("append line");
}

fn append_json_line(path: &Path, value: Value) {
    append_line(
        path,
        &serde_json::to_string(&value).expect("serialize json line"),
    );
}

fn exit_code(output: &Output) -> i32 {
    output.status.code().unwrap_or(255)
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("path is utf8")
}

fn path_string(path: &Path) -> String {
    path_str(path).to_string()
}

fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "-_./:=,".contains(ch))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
