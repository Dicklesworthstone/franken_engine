use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::benchmark_denominator::BenchmarkCase;
use frankenengine_engine::causal_replay::CounterfactualConfig;
use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, render_verdict_summary, verify_receipt_by_id,
};
use frankenengine_engine::third_party_verifier::{
    BenchmarkClaimBundle, ContainmentClaimBundle, ReplayClaimBundle,
    THIRD_PARTY_VERIFIER_COMPONENT, ThirdPartyVerificationReport, VerificationAttestation,
    VerificationAttestationInput, VerificationCheckResult, VerificationVerdict, VerifierEvent,
    generate_attestation, render_attestation_summary, render_report_summary, verify_attestation,
    verify_benchmark_claim, verify_containment_claim, verify_replay_claim,
};
use serde::{Deserialize, de::DeserializeOwned};

const CODE_BENCHMARK_FAIRNESS: &str = "FE-TPV-BENCH-0005";
const CODE_BUNDLE_MISSING_FILE: &str = "FE-TPV-BUNDLE-0001";
const CODE_BUNDLE_PARSE_ERROR: &str = "FE-TPV-BUNDLE-0002";
const CODE_BUNDLE_CONTEXT_MISMATCH: &str = "FE-TPV-BUNDLE-0003";
const CODE_BUNDLE_REMOTE_EXEC: &str = "FE-TPV-BUNDLE-0004";

fn main() {
    let exit_code = match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn run(args: Vec<String>) -> Result<i32, String> {
    if args.is_empty() {
        return Err(usage());
    }

    match args[0].as_str() {
        "receipt" => run_receipt(&args[1..]),
        "benchmark" => run_benchmark(&args[1..]),
        "replay" => run_replay(&args[1..]),
        "containment" => run_containment(&args[1..]),
        "attestation" => run_attestation(&args[1..]),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(0)
        }
        other => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
    }
}

fn usage() -> String {
    [
        "franken-verify usage:",
        "  franken-verify receipt <receipt_id> --input <path> [--summary]",
        "  franken-verify benchmark --input <path> [--summary]",
        "  franken-verify benchmark audit --input <path> [--summary]",
        "  franken-verify benchmark fairness --input <path> [--summary]",
        "  franken-verify benchmark reproduce --bundle <dir> [--summary] [--output <path>]",
        "  franken-verify benchmark verify --bundle <dir> [--summary] [--output <path>]",
        "  franken-verify replay --input <path> [--summary]",
        "      [--signature-key-hex <hex> | --signature-key-file <path>]",
        "      [--receipt-key <signer_hex>=<verification_key_hex>]...",
        "      [--receipt-key-file <path>]...",
        "      [--counterfactual-config-file <path>]...",
        "  franken-verify containment --input <path> [--summary]",
        "  franken-verify attestation create --input <path> [--summary]",
        "      [--signing-key-hex <hex> | --signing-key-file <path>]",
        "  franken-verify attestation verify --input <path> [--summary]",
        "",
        "exit codes:",
        "  0   verification passed",
        "  20  signature verification failure",
        "  21  transparency verification failure",
        "  22  attestation verification failure",
        "  23  stale cached data warning/failure",
        "  24  partially verified (checks skipped)",
        "  25  verification failed",
        "  26  inconclusive verification",
        "  2   CLI/input error",
    ]
    .join("\n")
}

fn run_receipt(args: &[String]) -> Result<i32, String> {
    let receipt_id = args
        .first()
        .ok_or_else(|| format!("receipt subcommand requires <receipt_id>\n\n{}", usage()))?;

    let mut input_path: Option<&str> = None;
    let mut summary = false;

    let mut index = 1usize;
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
            flag => return Err(format!("unknown flag for receipt: {flag}")),
        }
        index += 1;
    }

    let input_path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(input_path)?;
    let verdict = verify_receipt_by_id(&input, receipt_id).map_err(|error| error.to_string())?;

    if summary {
        println!("{}", render_verdict_summary(&verdict));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&verdict)
                .map_err(|error| format!("failed to encode verifier output: {error}"))?
        );
    }
    Ok(verdict.exit_code)
}

fn run_benchmark(args: &[String]) -> Result<i32, String> {
    if let Some(mode) = args.first() {
        match mode.as_str() {
            "verify" | "reproduce" => return run_benchmark_verify_bundle(&args[1..]),
            "audit" => return run_benchmark_audit(&args[1..]),
            "fairness" => return run_benchmark_fairness(&args[1..]),
            _ => {}
        }
    }
    run_benchmark_audit(args)
}

fn run_benchmark_audit(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "benchmark")?;
    let input = load_json::<BenchmarkClaimBundle>(input_path, "benchmark bundle")?;
    let report = verify_benchmark_claim(&input);
    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn run_benchmark_fairness(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "benchmark fairness")?;
    let input = load_json::<BenchmarkClaimBundle>(input_path, "benchmark bundle")?;

    let node_ids = benchmark_workload_id_set(&input.input.node_cases);
    let bun_ids = benchmark_workload_id_set(&input.input.bun_cases);
    let fairness_passed = node_ids == bun_ids;

    let check = if fairness_passed {
        VerificationCheckResult {
            name: "cross_runtime_workload_set_matches".to_string(),
            passed: true,
            error_code: None,
            detail: "node and bun workload sets are identical".to_string(),
        }
    } else {
        VerificationCheckResult {
            name: "cross_runtime_workload_set_matches".to_string(),
            passed: false,
            error_code: Some(CODE_BENCHMARK_FAIRNESS.to_string()),
            detail: format!(
                "node workload ids {:?} differ from bun workload ids {:?}",
                node_ids, bun_ids
            ),
        }
    };

    let verdict = if fairness_passed {
        VerificationVerdict::Verified
    } else {
        VerificationVerdict::Failed
    };
    let report = ThirdPartyVerificationReport {
        claim_type: "benchmark_fairness".to_string(),
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        verdict,
        confidence_statement: if fairness_passed {
            "cross-runtime workload fairness check passed".to_string()
        } else {
            "cross-runtime workload fairness check failed".to_string()
        },
        scope_limitations: Vec::new(),
        checks: vec![check],
        events: vec![
            VerifierEvent {
                trace_id: input.trace_id.clone(),
                decision_id: input.decision_id.clone(),
                policy_id: input.policy_id.clone(),
                component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
                event: "benchmark_fairness_check_started".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
            },
            VerifierEvent {
                trace_id: input.trace_id,
                decision_id: input.decision_id,
                policy_id: input.policy_id,
                component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
                event: "benchmark_fairness_check_completed".to_string(),
                outcome: if fairness_passed {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                },
                error_code: if fairness_passed {
                    None
                } else {
                    Some(CODE_BENCHMARK_FAIRNESS.to_string())
                },
            },
        ],
    };

    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn benchmark_workload_id_set(cases: &[BenchmarkCase]) -> BTreeSet<String> {
    cases.iter().map(|case| case.workload_id.clone()).collect()
}

#[derive(Debug, Deserialize)]
struct BenchmarkBundleManifest {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

fn run_benchmark_verify_bundle(args: &[String]) -> Result<i32, String> {
    let mut bundle_dir: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut summary = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--bundle" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--bundle requires a path".to_string())?;
                bundle_dir = Some(PathBuf::from(value));
            }
            "--output" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--output requires a path".to_string())?;
                output_path = Some(PathBuf::from(value));
            }
            "--summary" => summary = true,
            flag => return Err(format!("unknown flag for benchmark verify: {flag}")),
        }
        index += 1;
    }

    let bundle_dir = bundle_dir.ok_or_else(|| {
        "benchmark verify requires --bundle <dir> containing env.json, manifest.json, repro.lock, commands.txt, and results.json".to_string()
    })?;
    let results_path = bundle_dir.join("results.json");
    if !results_path.is_file() {
        return Err(format!(
            "benchmark bundle missing required file: {}",
            results_path.display()
        ));
    }

    let results_str = results_path
        .to_str()
        .ok_or_else(|| format!("bundle path is not valid utf-8: {}", results_path.display()))?;
    let input = load_json::<BenchmarkClaimBundle>(results_str, "benchmark bundle results")?;
    let mut report = verify_benchmark_claim(&input);

    validate_bundle_contract(&bundle_dir, &input, &mut report);

    if let Some(path) = output_path {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create output directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &path,
            serde_json::to_string_pretty(&report)
                .map_err(|error| format!("failed to encode verifier output: {error}"))?,
        )
        .map_err(|error| format!("failed to write report '{}': {error}", path.display()))?;
    }

    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn validate_bundle_contract(
    bundle_dir: &Path,
    input: &BenchmarkClaimBundle,
    report: &mut frankenengine_engine::third_party_verifier::ThirdPartyVerificationReport,
) {
    let required_files = [
        "env.json",
        "manifest.json",
        "repro.lock",
        "commands.txt",
        "results.json",
    ];

    let mut bundle_violations = false;
    for file in required_files {
        let path = bundle_dir.join(file);
        let present = path.is_file();
        append_bundle_check(
            report,
            format!("bundle_file_{file}_present"),
            present,
            CODE_BUNDLE_MISSING_FILE,
            if present {
                format!("required bundle file present: {}", path.display())
            } else {
                format!("required bundle file missing: {}", path.display())
            },
        );
        if !present {
            bundle_violations = true;
        }
    }

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = if manifest_path.is_file() {
        match load_json_path::<BenchmarkBundleManifest>(&manifest_path, "benchmark bundle manifest")
        {
            Ok(manifest) => {
                let schema_ok = !manifest.schema_version.trim().is_empty();
                append_bundle_check(
                    report,
                    "bundle_manifest_schema_version_present".to_string(),
                    schema_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if schema_ok {
                        format!(
                            "bundle manifest schema_version present: {}",
                            manifest.schema_version
                        )
                    } else {
                        "bundle manifest schema_version must be non-empty".to_string()
                    },
                );
                if !schema_ok {
                    bundle_violations = true;
                }

                let context_matches = manifest.trace_id == input.trace_id
                    && manifest.decision_id == input.decision_id
                    && manifest.policy_id == input.policy_id;
                append_bundle_check(
                    report,
                    "bundle_manifest_context_matches_claim".to_string(),
                    context_matches,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if context_matches {
                        "bundle manifest trace/decision/policy context matches results.json claim"
                            .to_string()
                    } else {
                        format!(
                            "bundle manifest context mismatch: manifest=({}, {}, {}), results=({}, {}, {})",
                            manifest.trace_id,
                            manifest.decision_id,
                            manifest.policy_id,
                            input.trace_id,
                            input.decision_id,
                            input.policy_id
                        )
                    },
                );
                if !context_matches {
                    bundle_violations = true;
                }

                Some(manifest)
            }
            Err(error) => {
                append_bundle_check(
                    report,
                    "bundle_manifest_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error,
                );
                bundle_violations = true;
                None
            }
        }
    } else {
        None
    };

    let env_path = bundle_dir.join("env.json");
    if env_path.is_file() {
        match load_json_path::<serde_json::Value>(&env_path, "benchmark bundle env.json") {
            Ok(value) => {
                let env_obj = value.as_object().cloned().expect("serde deserialization should succeed");
                let env_ok = !env_obj.is_empty()
                    && env_obj.contains_key("toolchain")
                    && env_obj.contains_key("os")
                    && env_obj.contains_key("arch");
                append_bundle_check(
                    report,
                    "bundle_env_has_core_fields".to_string(),
                    env_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if env_ok {
                        "env.json includes required fields: toolchain, os, arch".to_string()
                    } else {
                        "env.json must be a non-empty object containing toolchain, os, and arch"
                            .to_string()
                    },
                );
                if !env_ok {
                    bundle_violations = true;
                }
            }
            Err(error) => {
                append_bundle_check(
                    report,
                    "bundle_env_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error,
                );
                bundle_violations = true;
            }
        }
    }

    let repro_path = bundle_dir.join("repro.lock");
    if repro_path.is_file() {
        let repro_ok = fs::read_to_string(&repro_path)
            .map(|content| {
                let trimmed = content.trim();
                if trimmed.is_empty() {
                    return false;
                }
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    serde_json::from_str::<serde_json::Value>(trimmed)
                        .map(|value| value.is_object() || value.is_array())
                        .unwrap_or(false)
                } else {
                    true
                }
            })
            .unwrap_or(false);
        append_bundle_check(
            report,
            "bundle_repro_lock_present_and_non_empty".to_string(),
            repro_ok,
            CODE_BUNDLE_PARSE_ERROR,
            if repro_ok {
                format!(
                    "repro.lock is present and parseable: {}",
                    repro_path.display()
                )
            } else {
                format!("repro.lock is missing or invalid: {}", repro_path.display())
            },
        );
        if !repro_ok {
            bundle_violations = true;
        }
    }

    let commands_path = bundle_dir.join("commands.txt");
    if commands_path.is_file() {
        match fs::read_to_string(&commands_path) {
            Ok(content) => {
                let non_empty = !content.trim().is_empty();
                append_bundle_check(
                    report,
                    "bundle_commands_non_empty".to_string(),
                    non_empty,
                    CODE_BUNDLE_PARSE_ERROR,
                    if non_empty {
                        format!(
                            "commands.txt contains command transcript: {}",
                            commands_path.display()
                        )
                    } else {
                        format!("commands.txt is empty: {}", commands_path.display())
                    },
                );
                if !non_empty {
                    bundle_violations = true;
                }

                let remote_only = content.lines().any(|line| line.contains("rch exec --"));
                append_bundle_check(
                    report,
                    "bundle_commands_include_rch_exec".to_string(),
                    remote_only,
                    CODE_BUNDLE_REMOTE_EXEC,
                    if remote_only {
                        "commands.txt includes rch-wrapped execution evidence".to_string()
                    } else {
                        "commands.txt must include at least one `rch exec --` command to satisfy remote-heavy execution policy".to_string()
                    },
                );
                if !remote_only {
                    bundle_violations = true;
                }
            }
            Err(error) => {
                append_bundle_check(
                    report,
                    "bundle_commands_readable".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    format!(
                        "failed to read commands.txt '{}': {error}",
                        commands_path.display()
                    ),
                );
                bundle_violations = true;
            }
        }
    }

    let scope = if let Some(manifest) = manifest {
        format!(
            "bundle={} schema={} trace={} decision={} policy={}",
            bundle_dir.display(),
            manifest.schema_version,
            manifest.trace_id,
            manifest.decision_id,
            manifest.policy_id
        )
    } else {
        format!("bundle={}", bundle_dir.display())
    };
    report.events.push(VerifierEvent {
        trace_id: report.trace_id.clone(),
        decision_id: report.decision_id.clone(),
        policy_id: report.policy_id.clone(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: "benchmark_bundle_contract_checked".to_string(),
        outcome: if bundle_violations {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
        error_code: if bundle_violations {
            Some(CODE_BUNDLE_PARSE_ERROR.to_string())
        } else {
            None
        },
    });
    if bundle_violations {
        report.verdict = VerificationVerdict::Failed;
        report.confidence_statement =
            "verification failed: benchmark bundle contract violations detected".to_string();
        report.scope_limitations.push(scope);
    } else if report.confidence_statement.trim().is_empty() {
        report.confidence_statement =
            "bundle contract checks passed alongside benchmark claim recomputation".to_string();
    }
}

fn append_bundle_check(
    report: &mut frankenengine_engine::third_party_verifier::ThirdPartyVerificationReport,
    name: String,
    passed: bool,
    error_code: &'static str,
    detail: String,
) {
    report.checks.push(VerificationCheckResult {
        name,
        passed,
        error_code: if passed {
            None
        } else {
            Some(error_code.to_string())
        },
        detail,
    });
}

fn run_replay(args: &[String]) -> Result<i32, String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut signature_key_hex: Option<String> = None;
    let mut receipt_key_overrides = Vec::<String>::new();
    let mut receipt_key_files = Vec::<String>::new();
    let mut counterfactual_config_files = Vec::<String>::new();

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
            "--signature-key-hex" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signature-key-hex requires a value".to_string())?;
                signature_key_hex = Some(value.trim().to_string());
            }
            "--signature-key-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signature-key-file requires a path".to_string())?;
                signature_key_hex = Some(load_trimmed_file(value, "signature key file")?);
            }
            "--receipt-key" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    "--receipt-key requires <signer_hex>=<verification_key_hex>".to_string()
                })?;
                receipt_key_overrides.push(value.to_string());
            }
            "--receipt-key-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--receipt-key-file requires a path".to_string())?;
                receipt_key_files.push(value.to_string());
            }
            "--counterfactual-config-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--counterfactual-config-file requires a path".to_string())?;
                counterfactual_config_files.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for replay: {flag}")),
        }
        index += 1;
    }

    let input_path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let mut input = load_json::<ReplayClaimBundle>(input_path, "replay bundle")?;

    if let Some(hex) = signature_key_hex {
        input.signature_verification_key_hex = Some(hex);
    }

    for path in receipt_key_files {
        let parsed = load_receipt_key_map(&path)?;
        input.receipt_verification_keys_hex.extend(parsed);
    }

    for raw in receipt_key_overrides {
        let (signer_id_hex, key_hex) = parse_receipt_key_pair(raw.trim())?;
        input
            .receipt_verification_keys_hex
            .insert(signer_id_hex, key_hex);
    }

    for path in counterfactual_config_files {
        let mut parsed = load_counterfactual_configs(&path)?;
        input.counterfactual_configs.append(&mut parsed);
    }

    let report = verify_replay_claim(&input);
    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn run_containment(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "containment")?;
    let input = load_json::<ContainmentClaimBundle>(input_path, "containment bundle")?;
    let report = verify_containment_claim(&input);
    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn run_attestation(args: &[String]) -> Result<i32, String> {
    let mode = args.first().ok_or_else(|| {
        format!(
            "attestation subcommand requires 'create' or 'verify'\n\n{}",
            usage()
        )
    })?;
    match mode.as_str() {
        "create" => run_attestation_create(&args[1..]),
        "verify" => run_attestation_verify(&args[1..]),
        other => Err(format!(
            "unknown attestation mode '{other}' (expected 'create' or 'verify')"
        )),
    }
}

fn run_attestation_create(args: &[String]) -> Result<i32, String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut signing_key_hex: Option<String> = None;
    let mut signing_key_file: Option<String> = None;

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
            "--signing-key-hex" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signing-key-hex requires a value".to_string())?;
                signing_key_hex = Some(value.trim().to_string());
            }
            "--signing-key-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signing-key-file requires a path".to_string())?;
                signing_key_file = Some(value.to_string());
            }
            flag => return Err(format!("unknown flag for attestation create: {flag}")),
        }
        index += 1;
    }

    if signing_key_hex.is_some() && signing_key_file.is_some() {
        return Err("--signing-key-hex and --signing-key-file are mutually exclusive".to_string());
    }

    let input_path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let mut input = load_json::<VerificationAttestationInput>(input_path, "attestation input")?;
    if let Some(hex) = signing_key_hex {
        input.signing_key_hex = Some(hex);
    } else if let Some(path) = signing_key_file {
        input.signing_key_hex = Some(load_trimmed_file(&path, "attestation signing key file")?);
    }

    let attestation = generate_attestation(&input)?;
    if summary {
        println!("{}", render_attestation_summary(&attestation));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&attestation)
                .map_err(|error| format!("failed to encode attestation output: {error}"))?
        );
    }
    Ok(0)
}

fn run_attestation_verify(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "attestation verify")?;
    let input = load_json::<VerificationAttestation>(input_path, "attestation")?;
    let report = verify_attestation(&input);
    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn parse_input_flags<'a>(args: &'a [String], subcommand: &str) -> Result<(&'a str, bool), String> {
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
            flag => return Err(format!("unknown flag for {subcommand}: {flag}")),
        }
        index += 1;
    }

    let input_path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    Ok((input_path, summary))
}

fn parse_receipt_key_pair(raw: &str) -> Result<(String, String), String> {
    let (signer_id_hex, key_hex) = raw
        .split_once('=')
        .ok_or_else(|| "--receipt-key expects <signer_hex>=<verification_key_hex>".to_string())?;
    let signer_id_hex = signer_id_hex.trim();
    let key_hex = key_hex.trim();
    if signer_id_hex.is_empty() || key_hex.is_empty() {
        return Err("--receipt-key requires non-empty signer and key hex values".to_string());
    }
    Ok((signer_id_hex.to_string(), key_hex.to_string()))
}

fn load_receipt_key_map(path: &str) -> Result<BTreeMap<String, String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read receipt-key file '{path}': {error}"))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(format!("receipt-key file '{path}' is empty"));
    }

    if trimmed.starts_with('{') {
        return serde_json::from_str::<BTreeMap<String, String>>(trimmed).map_err(|error| {
            format!("failed to parse receipt-key file '{path}' as JSON signer->key map: {error}")
        });
    }

    let mut parsed = BTreeMap::new();
    for (line_index, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (signer_id_hex, key_hex) = parse_receipt_key_pair(line).map_err(|error| {
            format!(
                "receipt-key file '{path}' line {} is invalid: {error}",
                line_index + 1
            )
        })?;
        parsed.insert(signer_id_hex, key_hex);
    }

    if parsed.is_empty() {
        return Err(format!(
            "receipt-key file '{path}' contains no signer->key entries"
        ));
    }
    Ok(parsed)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CounterfactualConfigFile {
    One(CounterfactualConfig),
    Many(Vec<CounterfactualConfig>),
}

fn load_counterfactual_configs(path: &str) -> Result<Vec<CounterfactualConfig>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read counterfactual config file '{path}': {error}"))?;
    let parsed = serde_json::from_str::<CounterfactualConfigFile>(&content).map_err(|error| {
        format!("failed to parse counterfactual config file '{path}' as JSON object/array: {error}")
    })?;
    let configs = match parsed {
        CounterfactualConfigFile::One(config) => vec![config],
        CounterfactualConfigFile::Many(configs) => configs,
    };
    if configs.is_empty() {
        return Err(format!(
            "counterfactual config file '{path}' must include at least one config"
        ));
    }
    Ok(configs)
}

fn load_trimmed_file(path: &str, label: &str) -> Result<String, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {label} '{path}': {error}"))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} '{path}' is empty"));
    }
    Ok(trimmed.to_string())
}

fn print_report(
    report: &frankenengine_engine::third_party_verifier::ThirdPartyVerificationReport,
    summary: bool,
) -> Result<(), String> {
    if summary {
        println!("{}", render_report_summary(report));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(report)
                .map_err(|error| format!("failed to encode verifier output: {error}"))?
        );
    }
    Ok(())
}

fn load_input(path: &str) -> Result<ReceiptVerifierCliInput, String> {
    load_json::<ReceiptVerifierCliInput>(path, "verifier JSON input")
}

fn load_json_path<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read '{}': {error}", path.display()))?;
    serde_json::from_str::<T>(&content)
        .map_err(|error| format!("failed to parse '{}' as {label}: {error}", path.display()))
}

fn load_json<T: DeserializeOwned>(path: &str, label: &str) -> Result<T, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("failed to read '{path}': {error}"))?;
    serde_json::from_str::<T>(&content)
        .map_err(|error| format!("failed to parse '{path}' as {label}: {error}"))
}
