use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use frankenengine_engine::module_compatibility_matrix::CompatibilityScenarioReport;
use frankenengine_engine::runtime_diagnostics_cli::{
    CompatibilityAdvisoryInput, CompatibilityAdvisoryOutput, EvidenceExportFilter,
    GaEvidenceArtifactCategory, GaEvidenceArtifactLink, GaEvidencePackageInput,
    OnboardingScorecardInput, OnboardingScorecardSignal, RolloutDecisionArtifactInput,
    RuntimeDiagnosticsCliInput, SupportBundleFile, SupportBundleOutput,
    SupportBundleRedactionPolicy, build_compatibility_advisories, build_ga_evidence_package,
    build_onboarding_scorecard, build_rollout_decision_artifact, collect_runtime_diagnostics,
    export_evidence_bundle, export_support_bundle, parse_decision_type, parse_evidence_severity,
    render_compatibility_advisory_summary, render_diagnostics_summary, render_evidence_summary,
    render_ga_evidence_package_summary, render_onboarding_scorecard_summary,
    render_preflight_summary, render_rollout_decision_artifact_summary,
    render_support_bundle_summary, run_preflight_doctor,
};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(usage());
    }

    match args[0].as_str() {
        "diagnostics" => run_diagnostics(&args[1..]),
        "export-evidence" => run_export(&args[1..]),
        "support-bundle" => run_support_bundle(&args[1..]),
        "doctor" => run_doctor(&args[1..]),
        "compatibility-advisories" => run_compatibility_advisories(&args[1..]),
        "onboarding-scorecard" => run_onboarding_scorecard(&args[1..]),
        "rollout-decision-artifact" => run_rollout_decision_artifact(&args[1..]),
        "ga-evidence-package" => run_ga_evidence_package(&args[1..]),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
    }
}

fn usage() -> String {
    [
        "runtime_diagnostics usage:",
        "  runtime_diagnostics diagnostics --input <path> [--summary]",
        "  runtime_diagnostics export-evidence --input <path> [--summary]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "  runtime_diagnostics support-bundle --input <path> [--summary] [--out-dir <path>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
        "  runtime_diagnostics doctor --input <path> [--summary] [--out-dir <path>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
        "  runtime_diagnostics compatibility-advisories --scenario-report <path> [--summary]",
        "      [--source-report <path_or_url>] [--out <path>]",
        "  runtime_diagnostics onboarding-scorecard --input <path> [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals_json_path>]",
        "  runtime_diagnostics rollout-decision-artifact --input <path> [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals_json_path>] [--advisories <signals_json_path>] [--platform-signals <signals_json_path>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
        "  runtime_diagnostics ga-evidence-package --input <path> [--summary] [--out-dir <path>]",
        "      --release-candidate <id> [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals_json_path>] [--advisories <signals_json_path>] [--platform-signals <signals_json_path>]",
        "      [--conformance-artifact <path>[::description]]...",
        "      [--performance-artifact <path>[::description]]...",
        "      [--security-artifact <path>[::description]]...",
        "      [--third-party-replay-command <command>]...",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
    ]
    .join("\n")
}

fn run_diagnostics(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            flag => return Err(format!("unknown flag for diagnostics: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let output = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );

    if summary {
        println!("{}", render_diagnostics_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode diagnostics output: {error}"))?
        );
    }

    Ok(())
}

fn run_export(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut filter = EvidenceExportFilter::default();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            flag => return Err(format!("unknown flag for export-evidence: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let output = export_evidence_bundle(&input, filter);
    if summary {
        println!("{}", render_evidence_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode evidence export output: {error}"))?
        );
    }

    Ok(())
}

fn run_support_bundle(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for support-bundle: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };
    let output = export_support_bundle(&input, filter, redaction_policy);

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&output, &out_dir)?;
    }

    if summary {
        println!("{}", render_support_bundle_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode support bundle output: {error}"))?
        );
    }

    Ok(())
}

fn run_doctor(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for doctor: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };

    let output = run_preflight_doctor(&input, filter, redaction_policy);

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&output.support_bundle, &out_dir)?;
        let report_path = out_dir.join("support_bundle/preflight_report.json");
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create preflight report directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&output)
                .map_err(|error| format!("failed to encode preflight report: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write preflight report '{}': {error}",
                report_path.display()
            )
        })?;
    }

    if summary {
        println!("{}", render_preflight_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode preflight doctor output: {error}"))?
        );
    }

    Ok(())
}

fn run_compatibility_advisories(args: &[String]) -> Result<(), String> {
    let mut scenario_report_path: Option<&str> = None;
    let mut source_report: Option<String> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut summary = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--scenario-report" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--scenario-report requires a path".to_string())?;
                scenario_report_path = Some(value);
            }
            "--source-report" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--source-report requires a value".to_string())?;
                source_report = Some(value.clone());
            }
            "--out" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out requires a path".to_string())?;
                out_path = Some(PathBuf::from(value));
            }
            "--summary" => summary = true,
            flag => {
                return Err(format!("unknown flag for compatibility-advisories: {flag}"));
            }
        }
        index += 1;
    }

    let scenario_report_path = scenario_report_path
        .ok_or_else(|| "missing required --scenario-report <path>".to_string())?;
    let scenario_report = load_compatibility_scenario_report(scenario_report_path)?;
    let output = build_compatibility_advisories(&CompatibilityAdvisoryInput {
        source_report: source_report.unwrap_or_else(|| scenario_report_path.to_string()),
        scenario_report,
    });

    if let Some(path) = out_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create compatibility advisory output directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &path,
            serde_json::to_vec_pretty(&output).map_err(|error| {
                format!("failed to encode compatibility advisory output: {error}")
            })?,
        )
        .map_err(|error| {
            format!(
                "failed to write compatibility advisory output '{}': {error}",
                path.display()
            )
        })?;
    }

    if summary {
        println!("{}", render_compatibility_advisory_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|error| format!(
                "failed to encode compatibility advisory output: {error}"
            ))?
        );
    }

    Ok(())
}

fn run_onboarding_scorecard(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut signals_path = None::<String>;
    let mut workload_id = None::<String>;
    let mut package_name = None::<String>;
    let mut target_platforms = Vec::<String>::new();
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signals requires a value".to_string())?;
                signals_path = Some(value.clone());
            }
            "--workload-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--workload-id requires a value".to_string())?;
                workload_id = Some(value.clone());
            }
            "--package-name" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--package-name requires a value".to_string())?;
                package_name = Some(value.clone());
            }
            "--target-platform" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--target-platform requires a value".to_string())?;
                target_platforms.push(value.clone());
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for onboarding-scorecard: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;
    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };
    let preflight = run_preflight_doctor(&input, filter, redaction_policy);

    let external_signals = match signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let workload_id = workload_id.unwrap_or_else(|| input.trace_id.clone());
    let package_name = package_name.unwrap_or_else(|| workload_id.clone());
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id,
        package_name,
        target_platforms,
        preflight: preflight.clone(),
        external_signals,
    });

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&preflight.support_bundle, &out_dir)?;
        let report_path = out_dir.join("support_bundle/preflight_report.json");
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create preflight report directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&preflight)
                .map_err(|error| format!("failed to encode preflight report: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write preflight report '{}': {error}",
                report_path.display()
            )
        })?;

        let scorecard_path = out_dir.join("support_bundle/onboarding_scorecard.json");
        if let Some(parent) = scorecard_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create onboarding scorecard directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &scorecard_path,
            serde_json::to_vec_pretty(&scorecard)
                .map_err(|error| format!("failed to encode onboarding scorecard: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write onboarding scorecard '{}': {error}",
                scorecard_path.display()
            )
        })?;
    }

    if summary {
        println!("{}", render_onboarding_scorecard_summary(&scorecard));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&scorecard).map_err(|error| format!(
                "failed to encode onboarding scorecard output: {error}"
            ))?
        );
    }

    Ok(())
}

fn run_rollout_decision_artifact(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut workload_id = None::<String>;
    let mut package_name = None::<String>;
    let mut target_platforms = Vec::<String>::new();
    let mut signals_path = None::<String>;
    let mut advisories_path = None::<String>;
    let mut platform_signals_path = None::<String>;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--workload-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--workload-id requires a value".to_string())?;
                workload_id = Some(value.to_string());
            }
            "--package-name" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--package-name requires a value".to_string())?;
                package_name = Some(value.to_string());
            }
            "--target-platform" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--target-platform requires a value".to_string())?;
                target_platforms.push(value.to_string());
            }
            "--signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signals requires a value".to_string())?;
                signals_path = Some(value.to_string());
            }
            "--advisories" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--advisories requires a value".to_string())?;
                advisories_path = Some(value.to_string());
            }
            "--platform-signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--platform-signals requires a value".to_string())?;
                platform_signals_path = Some(value.to_string());
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => {
                return Err(format!(
                    "unknown flag for rollout-decision-artifact: {flag}"
                ));
            }
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;
    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };
    let preflight = run_preflight_doctor(&input, filter, redaction_policy);

    let external_signals = match signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let compatibility_advisories = match advisories_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let platform_matrix_signals = match platform_signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };

    let workload_id = workload_id.unwrap_or_else(|| input.trace_id.clone());
    let package_name = package_name.unwrap_or_else(|| workload_id.clone());
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id,
        package_name,
        target_platforms,
        preflight: preflight.clone(),
        external_signals,
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: scorecard.clone(),
        compatibility_advisories,
        platform_matrix_signals,
    });

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&preflight.support_bundle, &out_dir)?;

        let report_path = out_dir.join("support_bundle/preflight_report.json");
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create preflight report directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&preflight)
                .map_err(|error| format!("failed to encode preflight report: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write preflight report '{}': {error}",
                report_path.display()
            )
        })?;

        let scorecard_path = out_dir.join("support_bundle/onboarding_scorecard.json");
        if let Some(parent) = scorecard_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create onboarding scorecard directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &scorecard_path,
            serde_json::to_vec_pretty(&scorecard)
                .map_err(|error| format!("failed to encode onboarding scorecard: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write onboarding scorecard '{}': {error}",
                scorecard_path.display()
            )
        })?;

        let artifact_path = out_dir.join("support_bundle/rollout_decision_artifact.json");
        if let Some(parent) = artifact_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create rollout decision artifact directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &artifact_path,
            serde_json::to_vec_pretty(&artifact)
                .map_err(|error| format!("failed to encode rollout decision artifact: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write rollout decision artifact '{}': {error}",
                artifact_path.display()
            )
        })?;
    }

    if summary {
        println!("{}", render_rollout_decision_artifact_summary(&artifact));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&artifact).map_err(|error| format!(
                "failed to encode rollout decision artifact output: {error}"
            ))?
        );
    }

    Ok(())
}

fn run_ga_evidence_package(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut workload_id = None::<String>;
    let mut package_name = None::<String>;
    let mut target_platforms = Vec::<String>::new();
    let mut signals_path = None::<String>;
    let mut advisories_path = None::<String>;
    let mut platform_signals_path = None::<String>;
    let mut release_candidate_id = None::<String>;
    let mut external_evidence_links = Vec::<GaEvidenceArtifactLink>::new();
    let mut third_party_replay_commands = Vec::<String>::new();
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--release-candidate" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--release-candidate requires a value".to_string())?;
                release_candidate_id = Some(value.to_string());
            }
            "--workload-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--workload-id requires a value".to_string())?;
                workload_id = Some(value.to_string());
            }
            "--package-name" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--package-name requires a value".to_string())?;
                package_name = Some(value.to_string());
            }
            "--target-platform" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--target-platform requires a value".to_string())?;
                target_platforms.push(value.to_string());
            }
            "--signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signals requires a value".to_string())?;
                signals_path = Some(value.to_string());
            }
            "--advisories" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--advisories requires a value".to_string())?;
                advisories_path = Some(value.to_string());
            }
            "--platform-signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--platform-signals requires a value".to_string())?;
                platform_signals_path = Some(value.to_string());
            }
            "--conformance-artifact" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--conformance-artifact requires a value".to_string())?;
                external_evidence_links.push(parse_ga_artifact_link(
                    "--conformance-artifact",
                    GaEvidenceArtifactCategory::Conformance,
                    value,
                )?);
            }
            "--performance-artifact" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--performance-artifact requires a value".to_string())?;
                external_evidence_links.push(parse_ga_artifact_link(
                    "--performance-artifact",
                    GaEvidenceArtifactCategory::Performance,
                    value,
                )?);
            }
            "--security-artifact" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--security-artifact requires a value".to_string())?;
                external_evidence_links.push(parse_ga_artifact_link(
                    "--security-artifact",
                    GaEvidenceArtifactCategory::Security,
                    value,
                )?);
            }
            "--third-party-replay-command" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--third-party-replay-command requires a value".to_string())?;
                third_party_replay_commands.push(value.to_string());
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for ga-evidence-package: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let release_candidate_id = release_candidate_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "missing required --release-candidate <id>".to_string())?;
    let input = load_input(path)?;
    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };
    let preflight = run_preflight_doctor(&input, filter, redaction_policy);

    let external_signals = match signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let compatibility_advisories = match advisories_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let platform_matrix_signals = match platform_signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };

    let workload_id = workload_id.unwrap_or_else(|| input.trace_id.clone());
    let package_name = package_name.unwrap_or_else(|| workload_id.clone());
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id,
        package_name,
        target_platforms,
        preflight: preflight.clone(),
        external_signals,
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: scorecard.clone(),
        compatibility_advisories,
        platform_matrix_signals,
    });
    let output = build_ga_evidence_package(&GaEvidencePackageInput {
        release_candidate_id,
        support_bundle: preflight.support_bundle.clone(),
        onboarding_scorecard: scorecard.clone(),
        rollout_decision_artifact: artifact.clone(),
        external_evidence_links,
        third_party_replay_commands,
    });

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&preflight.support_bundle, &out_dir)?;
        write_json_file(
            &out_dir,
            "support_bundle/preflight_report.json",
            &preflight,
            "preflight report",
        )?;
        write_json_file(
            &out_dir,
            "support_bundle/onboarding_scorecard.json",
            &scorecard,
            "onboarding scorecard",
        )?;
        write_json_file(
            &out_dir,
            "support_bundle/rollout_decision_artifact.json",
            &artifact,
            "rollout decision artifact",
        )?;
        write_materialized_files(&output.files, &out_dir)?;
    }

    if summary {
        println!("{}", render_ga_evidence_package_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode ga evidence package output: {error}"))?
        );
    }

    Ok(())
}

fn write_materialized_files(files: &[SupportBundleFile], out_dir: &Path) -> Result<(), String> {
    for file in files {
        let destination = out_dir.join(&file.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create output directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(&destination, file.content.as_bytes()).map_err(|error| {
            format!(
                "failed to write output file '{}': {error}",
                destination.display()
            )
        })?;
    }
    Ok(())
}

fn write_support_bundle_files(output: &SupportBundleOutput, out_dir: &Path) -> Result<(), String> {
    write_materialized_files(&output.files, out_dir)
}

fn parse_u64_flag(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("{flag} expects a u64 value: {error}"))
}

fn load_input(path: &str) -> Result<RuntimeDiagnosticsCliInput, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read input file '{path}': {error}"))?;
    serde_json::from_str::<RuntimeDiagnosticsCliInput>(&content)
        .map_err(|error| format!("failed to parse input file '{path}' as JSON: {error}"))
}

fn load_compatibility_scenario_report(path: &str) -> Result<CompatibilityScenarioReport, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read scenario report file '{path}': {error}"))?;
    serde_json::from_str::<CompatibilityScenarioReport>(&content)
        .map_err(|error| format!("failed to parse scenario report file '{path}' as JSON: {error}"))
}

fn load_onboarding_signals(path: &str) -> Result<Vec<OnboardingScorecardSignal>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read signal file '{path}': {error}"))?;
    if let Ok(signals) = serde_json::from_str::<Vec<OnboardingScorecardSignal>>(&content) {
        return Ok(signals);
    }
    if let Ok(bundle) = serde_json::from_str::<CompatibilityAdvisoryOutput>(&content) {
        return Ok(bundle.signals);
    }
    Err(format!(
        "failed to parse signal file '{path}' as JSON array or compatibility advisory bundle"
    ))
}

fn parse_ga_artifact_link(
    flag: &str,
    category: GaEvidenceArtifactCategory,
    value: &str,
) -> Result<GaEvidenceArtifactLink, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{flag} requires <path> or <path>::<description>, got empty value"
        ));
    }

    let (path, description) = match trimmed.split_once("::") {
        Some((path, description)) => (path.trim(), description.trim()),
        None => (trimmed, ""),
    };
    if path.is_empty() {
        return Err(format!(
            "{flag} requires a non-empty path before optional ::description"
        ));
    }

    let description = if description.is_empty() {
        format!("{category} evidence artifact")
    } else {
        description.to_string()
    };

    Ok(GaEvidenceArtifactLink {
        category,
        path: path.to_string(),
        description,
    })
}

fn write_json_file<T: Serialize>(
    out_dir: &Path,
    relative_path: &str,
    value: &T,
    label: &str,
) -> Result<(), String> {
    let destination = out_dir.join(relative_path);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create {label} directory '{}': {error}",
                parent.display()
            )
        })?;
    }

    let encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode {label}: {error}"))?;
    fs::write(&destination, encoded).map_err(|error| {
        format!(
            "failed to write {label} '{}': {error}",
            destination.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use frankenengine_engine::module_compatibility_matrix::{
        CompatibilityEvent, CompatibilityMode, CompatibilityObservationOutcome,
        CompatibilityRuntime, DivergenceCategory,
    };

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX_EPOCH")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "frankenengine-runtime-diagnostics-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn sample_scenario_report() -> CompatibilityScenarioReport {
        let case_id = "case-engine-bug".to_string();
        let mut divergence_category_counts = BTreeMap::new();
        divergence_category_counts.insert(DivergenceCategory::EngineBug.as_str().to_string(), 1);
        let mut actionable_guidance = BTreeMap::new();
        actionable_guidance.insert(
            case_id.clone(),
            "patch runtime lane semantics and replay matrix".to_string(),
        );

        CompatibilityScenarioReport {
            schema_version: "franken-engine.module-interop-scenario-report.v1".to_string(),
            scenario_id: "scenario-e2e".to_string(),
            trace_id: "trace-e2e".to_string(),
            decision_id: "decision-e2e".to_string(),
            policy_id: "policy-e2e".to_string(),
            generated_at_unix_ms: 1_111,
            total_observations: 1,
            matched_observations: 0,
            divergence_category_counts,
            actionable_guidance,
            outcomes: vec![CompatibilityObservationOutcome {
                case_id,
                runtime: CompatibilityRuntime::FrankenEngine,
                mode: CompatibilityMode::Native,
                observed_behavior: "franken_behavior".to_string(),
                expected_behavior: "reference_behavior".to_string(),
                matched: false,
                divergence: None,
                divergence_category: Some(DivergenceCategory::EngineBug),
                actionable_guidance: Some(
                    "patch runtime lane semantics and replay matrix".to_string(),
                ),
                event: CompatibilityEvent {
                    seq: 1,
                    trace_id: "trace-e2e".to_string(),
                    decision_id: "decision-e2e".to_string(),
                    policy_id: "policy-e2e".to_string(),
                    component: "module_compatibility_matrix".to_string(),
                    event: "compatibility_observation".to_string(),
                    outcome: "deny".to_string(),
                    error_code: "FE-MODCOMP-0008".to_string(),
                    case_id: "case-engine-bug".to_string(),
                    runtime: "franken_engine".to_string(),
                    mode: "native".to_string(),
                    detail: "deterministic synthetic divergence".to_string(),
                },
            }],
        }
    }

    #[test]
    fn compatibility_advisories_command_writes_bundle_json() {
        let temp_dir = unique_temp_dir("compat-advisories");
        fs::create_dir_all(&temp_dir).expect("temp directory should be created");

        let scenario_path = temp_dir.join("scenario_report.json");
        fs::write(
            &scenario_path,
            serde_json::to_vec_pretty(&sample_scenario_report())
                .expect("scenario report should encode"),
        )
        .expect("scenario report should be written");

        let out_path = temp_dir.join("compatibility_advisories.json");
        let args = vec![
            "--scenario-report".to_string(),
            scenario_path.display().to_string(),
            "--source-report".to_string(),
            "artifacts/compat/scenario_report.json".to_string(),
            "--out".to_string(),
            out_path.display().to_string(),
            "--summary".to_string(),
        ];
        run_compatibility_advisories(&args)
            .expect("compatibility-advisories command should complete successfully");

        let output = fs::read_to_string(&out_path).expect("output bundle should exist");
        let decoded = serde_json::from_str::<CompatibilityAdvisoryOutput>(&output)
            .expect("output bundle should decode");
        assert_eq!(decoded.advisory_count, 1);
        assert_eq!(decoded.advisories.len(), 1);
        assert_eq!(decoded.signals.len(), 1);
        assert_eq!(decoded.signals[0].source, "compatibility_advisory");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn load_onboarding_signals_accepts_compatibility_advisory_bundle() {
        let temp_dir = unique_temp_dir("compat-bundle-signals");
        fs::create_dir_all(&temp_dir).expect("temp directory should be created");

        let advisory_bundle = build_compatibility_advisories(&CompatibilityAdvisoryInput {
            source_report: "artifacts/compat/scenario_report.json".to_string(),
            scenario_report: sample_scenario_report(),
        });
        let advisory_path = temp_dir.join("compatibility_advisories.json");
        fs::write(
            &advisory_path,
            serde_json::to_vec_pretty(&advisory_bundle).expect("bundle should encode"),
        )
        .expect("bundle should be written");

        let signals = load_onboarding_signals(&advisory_path.display().to_string())
            .expect("bundle should decode as onboarding signals");
        assert_eq!(signals.len(), advisory_bundle.signals.len());
        assert_eq!(signals[0].source, "compatibility_advisory");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
