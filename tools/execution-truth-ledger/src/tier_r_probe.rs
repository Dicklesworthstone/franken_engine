#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_engine::verification_coverage_contract::{
    TIER_R_BRANCH_SIGNALS, TIER_R_IMPLEMENTATION_TRUTH, TIER_R_PROBE_CASES,
    TIER_R_PROBE_SCHEMA_VERSION, TierRBuildEnvironment, TierRDenialProbe, TierRProbeReport,
    TierRProbeScenario, TierRSourceManifest, TierRStageEvent, read_bounded_regular_file,
    tier_r_expected_semantic_digest, validate_tier_r_build_environment, validate_tier_r_probe,
    validate_tier_r_source_manifest,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const EMBEDDED_SOURCE_MANIFEST: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/vcc_tier_r_source_manifest.json"));
const EMBEDDED_BUILD_ENVIRONMENT: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/vcc_tier_r_build_environment.json"
));

fn main() -> ExitCode {
    let run_id = env::var("VCC_RUN_ID").unwrap_or_else(|_| "run-vcc-tier-r-probe".to_string());
    let trace_id =
        env::var("VCC_TRACE_ID").unwrap_or_else(|_| "trace-vcc-tier-r-probe".to_string());
    let (mut report, mut failure) = build_probe_report(run_id, trace_id);
    let findings = validate_tier_r_probe(&report);
    if !findings.is_empty() {
        report.status = "fail".to_string();
        failure.get_or_insert_with(|| format!("probe self-validation failed: {findings:?}"));
    }
    if let Err(reason) = write_source_manifest_if_requested() {
        report.status = "fail".to_string();
        failure.get_or_insert(reason);
    }
    if let Err(reason) = write_build_environment_if_requested() {
        report.status = "fail".to_string();
        failure.get_or_insert(reason);
    }
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("serialize provisional Tier-R probe: {error}");
            return ExitCode::from(2);
        }
    }
    if report.status == "pass" {
        ExitCode::SUCCESS
    } else {
        if let Some(reason) = failure {
            eprintln!("{reason}");
        }
        ExitCode::FAILURE
    }
}

fn build_probe_report(run_id: String, trace_id: String) -> (TierRProbeReport, Option<String>) {
    let mut scenarios = Vec::new();
    let mut stage_events = Vec::new();
    let mut failure = None;
    for &(scenario_id, source, expected) in TIER_R_PROBE_CASES {
        match execute_scenario(scenario_id, source, expected, &trace_id) {
            Ok(scenario) => {
                if scenario.decision != "pass" && failure.is_none() {
                    failure = Some(format!(
                        "{scenario_id} did not satisfy reference invariants"
                    ));
                }
                stage_events.extend(stage_events_for_scenario(&scenario));
                scenarios.push(scenario);
            }
            Err(reason) => {
                failure.get_or_insert_with(|| reason.clone());
                scenarios.push(TierRProbeScenario {
                    scenario_id: scenario_id.to_string(),
                    source_sha256: sha256_hex(source.as_bytes()),
                    reference_ir_sha256: "0".repeat(64),
                    expected_value: expected.to_string(),
                    reference_value: format!("error:{reason}"),
                    reference_instructions: 0,
                    reference_events: Vec::new(),
                    expected_semantic_digest: tier_r_expected_semantic_digest(expected),
                    reference_semantic_digest: "0".repeat(64),
                    decision: "fail".to_string(),
                });
            }
        }
    }
    let denial = denial_probe(&trace_id);
    if denial.decision != "deny" && failure.is_none() {
        failure = Some("VmDispatch denial probe did not fail closed".to_string());
    }
    if denial.decision == "deny" {
        let capability_hash = sha256_hex(denial.capability.as_bytes());
        stage_events.push(TierRStageEvent {
            sequence: 0,
            scenario_id: denial.scenario_id.clone(),
            stage: "reference_capability_denied".to_string(),
            input_sha256: capability_hash.clone(),
            output_sha256: capability_hash,
            decision: "deny".to_string(),
        });
    }
    for (index, event) in stage_events.iter_mut().enumerate() {
        event.sequence = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
    }
    let reference_source_sha256 = match reference_source_sha256() {
        Ok(hash) => hash,
        Err(reason) => {
            failure.get_or_insert_with(|| reason.clone());
            "0".repeat(64)
        }
    };
    let build_environment_sha256 = match build_environment_sha256(&reference_source_sha256) {
        Ok(hash) => hash,
        Err(reason) => {
            failure.get_or_insert_with(|| reason.clone());
            "0".repeat(64)
        }
    };
    let probe_executable_sha256 = match current_executable_sha256() {
        Ok(hash) => hash,
        Err(reason) => {
            failure.get_or_insert_with(|| reason.clone());
            "0".repeat(64)
        }
    };
    let branch_signals: Vec<String> = TIER_R_BRANCH_SIGNALS
        .iter()
        .filter(|required| stage_events.iter().any(|event| event.stage == **required))
        .map(|signal| (*signal).to_string())
        .collect();
    let report = TierRProbeReport {
        schema_version: TIER_R_PROBE_SCHEMA_VERSION.to_string(),
        classification: "provisional_not_certified_tier_r".to_string(),
        run_id,
        trace_id,
        implementation_truth: TIER_R_IMPLEMENTATION_TRUTH.to_string(),
        reference_source_sha256,
        build_environment_sha256,
        probe_executable_sha256,
        status: if failure.is_none() { "pass" } else { "fail" }.to_string(),
        scenarios,
        denial,
        stage_events,
        branch_signals,
    };
    (report, failure)
}

fn stage_events_for_scenario(scenario: &TierRProbeScenario) -> Vec<TierRStageEvent> {
    if scenario.decision != "pass" {
        return Vec::new();
    }
    vec![
        TierRStageEvent {
            sequence: 0,
            scenario_id: scenario.scenario_id.clone(),
            stage: "reference_parse_completed".to_string(),
            input_sha256: scenario.source_sha256.clone(),
            output_sha256: scenario.source_sha256.clone(),
            decision: "pass".to_string(),
        },
        TierRStageEvent {
            sequence: 0,
            scenario_id: scenario.scenario_id.clone(),
            stage: "reference_lowering_completed".to_string(),
            input_sha256: scenario.source_sha256.clone(),
            output_sha256: scenario.reference_ir_sha256.clone(),
            decision: "pass".to_string(),
        },
        TierRStageEvent {
            sequence: 0,
            scenario_id: scenario.scenario_id.clone(),
            stage: "reference_execution_started".to_string(),
            input_sha256: scenario.reference_ir_sha256.clone(),
            output_sha256: scenario.reference_ir_sha256.clone(),
            decision: "pass".to_string(),
        },
        TierRStageEvent {
            sequence: 0,
            scenario_id: scenario.scenario_id.clone(),
            stage: "reference_execution_completed".to_string(),
            input_sha256: scenario.reference_ir_sha256.clone(),
            output_sha256: scenario.reference_semantic_digest.clone(),
            decision: "pass".to_string(),
        },
        TierRStageEvent {
            sequence: 0,
            scenario_id: scenario.scenario_id.clone(),
            stage: "expected_observable_equal".to_string(),
            input_sha256: scenario.expected_semantic_digest.clone(),
            output_sha256: scenario.reference_semantic_digest.clone(),
            decision: "pass".to_string(),
        },
    ]
}

fn execute_scenario(
    scenario_id: &str,
    source: &str,
    expected: &str,
    trace_id: &str,
) -> Result<TierRProbeScenario, String> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .map_err(|error| format!("{scenario_id}: parse failed: {error}"))?;
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("vcc:{scenario_id}"));
    let context = LoweringContext::new(
        format!("{trace_id}:{scenario_id}"),
        format!("decision:{scenario_id}"),
        "verification-coverage-contract",
    );
    let module = lower_ir0_to_ir3(&ir0, &context)
        .map_err(|error| format!("{scenario_id}: lowering failed: {error}"))?
        .ir3;
    let reference_ir_sha256 = sha256_hex(
        &serde_json::to_vec(&module)
            .map_err(|error| format!("{scenario_id}: serialize reference IR3: {error}"))?,
    );
    let reference = QuickJsLane::with_config(execution_config())
        .execute(&module, &format!("{trace_id}:{scenario_id}:reference"))
        .map_err(|error| format!("{scenario_id}: reference execute failed: {error}"))?;
    let reference_value = serde_json::to_string(&reference.value)
        .map_err(|error| format!("{scenario_id}: serialize typed reference value: {error}"))?;
    let reference_events = event_names(&reference);
    let expected_semantic_digest = tier_r_expected_semantic_digest(expected);
    let reference_semantic_digest = semantic_digest(&reference);
    let passed = reference_value == expected
        && reference.instructions_executed > 0
        && reference_events
            .iter()
            .any(|event| event == "execution_started")
        && reference_events
            .iter()
            .any(|event| event == "execution_completed")
        && reference_semantic_digest == expected_semantic_digest;
    Ok(TierRProbeScenario {
        scenario_id: scenario_id.to_string(),
        source_sha256: sha256_hex(source.as_bytes()),
        reference_ir_sha256,
        expected_value: expected.to_string(),
        reference_value,
        reference_instructions: reference.instructions_executed,
        reference_events,
        expected_semantic_digest,
        reference_semantic_digest,
        decision: if passed { "pass" } else { "fail" }.to_string(),
    })
}

fn execution_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn denial_probe(trace_id: &str) -> TierRDenialProbe {
    let source = "1 + 1;";
    let result = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .map_err(|error| error.to_string())
        .and_then(|tree| {
            let ir0 = Ir0Module::from_syntax_tree(tree, "vcc:capability-denial");
            lower_ir0_to_ir3(
                &ir0,
                &LoweringContext::new(
                    format!("{trace_id}:capability-denial"),
                    "decision:capability-denial",
                    "verification-coverage-contract",
                ),
            )
            .map(|output| output.ir3)
            .map_err(|error| error.to_string())
        });
    let (error_class, capability, decision) = match result {
        Err(reason) => (
            format!("setup_failed:{reason}"),
            "unknown".to_string(),
            "fail".to_string(),
        ),
        Ok(module) => {
            let mut config = InterpreterConfig::quickjs_defaults();
            config.granted_capabilities = BTreeSet::new();
            match QuickJsLane::with_config(config)
                .execute(&module, &format!("{trace_id}:capability-denial"))
            {
                Err(InterpreterError::CapabilityDenied { capability })
                    if capability == "VmDispatch" =>
                {
                    (
                        "CapabilityDenied".to_string(),
                        capability,
                        "deny".to_string(),
                    )
                }
                Err(InterpreterError::CapabilityDenied { capability }) => (
                    "CapabilityDeniedWrongCapability".to_string(),
                    capability,
                    "fail".to_string(),
                ),
                Err(error) => (
                    format!("unexpected:{error}"),
                    "unknown".to_string(),
                    "fail".to_string(),
                ),
                Ok(_) => ("none".to_string(), "none".to_string(), "fail".to_string()),
            }
        }
    };
    TierRDenialProbe {
        scenario_id: "vm-dispatch-capability-denial".to_string(),
        error_class,
        capability,
        decision,
    }
}

fn event_names(result: &ExecutionResult) -> Vec<String> {
    result
        .events
        .iter()
        .map(|event| event.event.clone())
        .collect()
}

fn semantic_digest(result: &ExecutionResult) -> String {
    let console: Vec<_> = result
        .console_output
        .iter()
        .map(|entry| {
            json!({
                "level": format!("{:?}", entry.level).to_ascii_lowercase(),
                "message": entry.message,
            })
        })
        .collect();
    let hostcalls: Vec<_> = result
        .hostcall_decisions
        .iter()
        .map(|decision| {
            json!({
                "capability": format!("{:?}", decision.capability),
                "allowed": decision.allowed,
            })
        })
        .collect();
    let payload = json!({
        "value": serde_json::to_string(&result.value)
            .expect("reference Value is infallibly serializable"),
        "console": console,
        "hostcalls": hostcalls,
        "hook_action": result
            .requested_hook_action
            .as_ref()
            .map(|action| format!("{action:?}"))
            .unwrap_or_else(|| "none".to_string()),
    });
    sha256_hex(&serde_json::to_vec(&payload).expect("semantic payload serializes"))
}

fn reference_source_sha256() -> Result<String, String> {
    let source_manifest: TierRSourceManifest = serde_json::from_slice(EMBEDDED_SOURCE_MANIFEST)
        .map_err(|error| format!("parse embedded Tier-R source manifest: {error}"))?;
    let mut canonical_manifest = serde_json::to_vec_pretty(&source_manifest)
        .map_err(|error| format!("serialize embedded Tier-R source manifest: {error}"))?;
    canonical_manifest.push(b'\n');
    if canonical_manifest != EMBEDDED_SOURCE_MANIFEST {
        return Err("embedded Tier-R source manifest is not canonical JSON".to_string());
    }
    let findings = validate_tier_r_source_manifest(&source_manifest);
    if !findings.is_empty() {
        return Err(format!(
            "embedded Tier-R source manifest failed validation: {findings:?}"
        ));
    }
    let live_aggregate = sha256_hex(EMBEDDED_SOURCE_MANIFEST);
    let embedded_aggregate = env!("VCC_TIER_R_BUILD_SOURCE_SHA256");
    if live_aggregate != embedded_aggregate {
        return Err(format!(
            "embedded Tier-R build-input closure mismatch: expected {embedded_aggregate}, got {live_aggregate}"
        ));
    }
    Ok(embedded_aggregate.to_string())
}

fn write_source_manifest_if_requested() -> Result<(), String> {
    let Some(output_path) = env::var_os("VCC_TIER_R_SOURCE_MANIFEST_OUTPUT") else {
        return Ok(());
    };
    let path = Path::new(&output_path);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "create Tier-R source manifest output {} without replacement: {error}",
                path.display()
            )
        })?;
    output
        .write_all(EMBEDDED_SOURCE_MANIFEST)
        .and_then(|()| output.sync_all())
        .map_err(|error| {
            format!(
                "write Tier-R source manifest output {}: {error}",
                path.display()
            )
        })
}

fn build_environment_sha256(reference_source_sha256: &str) -> Result<String, String> {
    let environment: TierRBuildEnvironment = serde_json::from_slice(EMBEDDED_BUILD_ENVIRONMENT)
        .map_err(|error| format!("parse embedded Tier-R build environment: {error}"))?;
    let mut canonical = serde_json::to_vec_pretty(&environment)
        .map_err(|error| format!("serialize embedded Tier-R build environment: {error}"))?;
    canonical.push(b'\n');
    if canonical != EMBEDDED_BUILD_ENVIRONMENT {
        return Err("embedded Tier-R build environment is not canonical JSON".to_string());
    }
    let findings = validate_tier_r_build_environment(&environment);
    if !findings.is_empty() {
        return Err(format!(
            "embedded Tier-R build environment failed validation: {findings:?}"
        ));
    }
    if environment.source_manifest_sha256 != reference_source_sha256 {
        return Err(format!(
            "embedded Tier-R builder source identity {} differs from live source manifest {reference_source_sha256}",
            environment.source_manifest_sha256
        ));
    }
    let live_hash = sha256_hex(EMBEDDED_BUILD_ENVIRONMENT);
    let expected_hash = env!("VCC_TIER_R_BUILD_ENVIRONMENT_SHA256");
    if live_hash != expected_hash {
        return Err(format!(
            "embedded Tier-R build-environment identity mismatch: expected {expected_hash}, got {live_hash}"
        ));
    }
    Ok(expected_hash.to_string())
}

fn write_build_environment_if_requested() -> Result<(), String> {
    let Some(output_path) = env::var_os("VCC_TIER_R_BUILD_ENVIRONMENT_OUTPUT") else {
        return Ok(());
    };
    let path = Path::new(&output_path);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "create Tier-R build-environment output {} without replacement: {error}",
                path.display()
            )
        })?;
    output
        .write_all(EMBEDDED_BUILD_ENVIRONMENT)
        .and_then(|()| output.sync_all())
        .map_err(|error| {
            format!(
                "write Tier-R build-environment output {}: {error}",
                path.display()
            )
        })
}

fn current_executable_sha256() -> Result<String, String> {
    let path = env::current_exe().map_err(|error| format!("resolve probe executable: {error}"))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect probe executable {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "probe executable is not a regular non-symlink file: {}",
            path.display()
        ));
    }
    let bytes = read_bounded_regular_file(&path, 256 * 1024 * 1024)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_reference_lane_satisfies_the_structural_contract() {
        let (report, failure) = build_probe_report(
            "run-tier-r-test".to_string(),
            "trace-tier-r-test".to_string(),
        );
        assert!(failure.is_none(), "{failure:?}");
        assert_eq!(report.status, "pass");
        assert!(
            validate_tier_r_probe(&report).is_empty(),
            "{:?}",
            validate_tier_r_probe(&report)
        );
    }
}
