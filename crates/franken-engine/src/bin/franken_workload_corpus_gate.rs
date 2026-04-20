#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::workload_corpus_gate::{
    BaselineRuntime, DivergenceClass, EquivalenceResult, GateConfig, GateVerdict, InputLanguage,
    LicenseStatus, ObservabilityMode, WorkloadCorpus, WorkloadCorpusGate, WorkloadFamily,
    WorkloadOrigin, WorkloadProvenance, WorkloadSpecimen,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_workload_corpus_gate.v1";
const CORPUS_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.workload-corpus-manifest.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.workload-corpus-gate.run-manifest.v1";
const EVENT_SCHEMA_VERSION: &str = "franken-engine.workload-corpus-gate.event.v1";
const COMPONENT: &str = "franken_workload_corpus_gate";
const POLICY_ID: &str = "franken-engine.workload-corpus-gate.policy.v1";

enum CliAction {
    Help,
    Error {
        argument: String,
        message: String,
    },
    Run {
        out_dir: PathBuf,
        min_per_family: Option<usize>,
        min_equivalence_rate: Option<u64>,
        corpus_manifest_path: Option<PathBuf>,
        equivalence_artifacts_path: Option<PathBuf>,
        publication_mode: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
struct CliErrorOutput {
    schema_version: String,
    component: String,
    error: String,
    argument: String,
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    gate_report: String,
    corpus_manifest: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    corpus_hash: String,
    report_hash: String,
    verdict: String,
    total_specimens: usize,
    families_covered: usize,
    overall_equivalence_rate: u64,
}

#[derive(Debug, Clone, Serialize)]
struct RunManifest {
    schema_version: String,
    component: String,
    policy_id: String,
    generated_at_utc: String,
    out_dir: String,
    total_specimens: usize,
    families_covered: usize,
    verdict: String,
    gate_config: GateConfigSummary,
}

#[derive(Debug, Clone, Serialize)]
struct GateConfigSummary {
    min_families: usize,
    min_per_family: usize,
    equivalence_threshold: u64,
    max_divergence_ratio: u64,
    require_publishable_licenses: bool,
    require_observability_coverage: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Event {
    schema_version: String,
    timestamp_utc: String,
    component: String,
    event_type: String,
    data: serde_json::Value,
}

fn parse_args_from(args: &[String]) -> CliAction {
    if args.len() < 2 {
        return CliAction::Help;
    }

    match args[1].as_str() {
        "--help" | "-h" | "help" => CliAction::Help,
        _ => {
            let mut out_dir = None;
            let mut min_per_family = None;
            let mut min_equivalence_rate = None;
            let mut corpus_manifest_path = None;
            let mut equivalence_artifacts_path = None;
            let mut publication_mode = false;

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--out-dir" => {
                        if i + 1 < args.len() {
                            if args[i + 1].starts_with("--") {
                                return CliAction::Error {
                                    argument: args[i].clone(),
                                    message: "missing value".to_string(),
                                };
                            }
                            out_dir = Some(PathBuf::from(&args[i + 1]));
                            i += 2;
                        } else {
                            return CliAction::Error {
                                argument: args[i].clone(),
                                message: "missing value".to_string(),
                            };
                        }
                    }
                    "--min-per-family" => {
                        if i + 1 < args.len() {
                            let raw = &args[i + 1];
                            let val = match raw.parse::<usize>() {
                                Ok(val) => val,
                                Err(_) => {
                                    return CliAction::Error {
                                        argument: args[i].clone(),
                                        message: format!("invalid integer value: {raw}"),
                                    };
                                }
                            };
                            min_per_family = Some(val);
                            i += 2;
                        } else {
                            return CliAction::Error {
                                argument: args[i].clone(),
                                message: "missing value".to_string(),
                            };
                        }
                    }
                    "--min-equivalence-rate" => {
                        if i + 1 < args.len() {
                            let raw = &args[i + 1];
                            let val = match raw.parse::<u64>() {
                                Ok(val) => val,
                                Err(_) => {
                                    return CliAction::Error {
                                        argument: args[i].clone(),
                                        message: format!("invalid integer value: {raw}"),
                                    };
                                }
                            };
                            min_equivalence_rate = Some(val);
                            i += 2;
                        } else {
                            return CliAction::Error {
                                argument: args[i].clone(),
                                message: "missing value".to_string(),
                            };
                        }
                    }
                    "--corpus-manifest" => {
                        if i + 1 < args.len() {
                            if args[i + 1].starts_with("--") {
                                return CliAction::Error {
                                    argument: args[i].clone(),
                                    message: "missing value".to_string(),
                                };
                            }
                            corpus_manifest_path = Some(PathBuf::from(&args[i + 1]));
                            i += 2;
                        } else {
                            return CliAction::Error {
                                argument: args[i].clone(),
                                message: "missing value".to_string(),
                            };
                        }
                    }
                    "--equivalence-artifacts" => {
                        if i + 1 < args.len() {
                            if args[i + 1].starts_with("--") {
                                return CliAction::Error {
                                    argument: args[i].clone(),
                                    message: "missing value".to_string(),
                                };
                            }
                            equivalence_artifacts_path = Some(PathBuf::from(&args[i + 1]));
                            i += 2;
                        } else {
                            return CliAction::Error {
                                argument: args[i].clone(),
                                message: "missing value".to_string(),
                            };
                        }
                    }
                    "--publication-mode" => {
                        publication_mode = true;
                        i += 1;
                    }
                    unknown => {
                        return CliAction::Error {
                            argument: unknown.to_string(),
                            message: "unknown option".to_string(),
                        };
                    }
                }
            }

            CliAction::Run {
                out_dir: out_dir.unwrap_or_else(|| PathBuf::from(".")),
                min_per_family,
                min_equivalence_rate,
                corpus_manifest_path,
                equivalence_artifacts_path,
                publication_mode,
            }
        }
    }
}

fn parse_args() -> CliAction {
    let args: Vec<String> = env::args().collect();
    parse_args_from(&args)
}

fn print_help() {
    println!("Usage: franken_workload_corpus_gate [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --out-dir <DIR>              Output directory for artifacts");
    println!("  --min-per-family <N>         Minimum specimens per family");
    println!("  --min-equivalence-rate <N>   Minimum equivalence rate (millionths)");
    println!("  --corpus-manifest <FILE>     Path to curated workload corpus manifest");
    println!("  --equivalence-artifacts <DIR> Path to directory with equivalence artifacts");
    println!("  --publication-mode           Reject internal fixtures for publication");
    println!("  --help, -h                   Show this help");
    println!();
    println!("Evaluates workload corpus for behavior-equivalence gating of performance claims.");
}

fn load_curated_corpus(
    manifest_path: &Path,
    equivalence_artifacts_path: Option<&PathBuf>,
) -> Result<WorkloadCorpus, Box<dyn std::error::Error>> {
    let manifest_content = fs::read_to_string(manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;

    let specimens = manifest["specimens"]
        .as_array()
        .ok_or("Missing 'specimens' array in manifest")?;

    let mut corpus = WorkloadCorpus::new();

    for specimen_data in specimens {
        let specimen = parse_specimen_from_manifest(specimen_data)?;
        corpus.add_specimen(specimen)?;
    }

    // Load equivalence artifacts if provided
    if let Some(artifacts_path) = equivalence_artifacts_path {
        load_equivalence_artifacts(&mut corpus, artifacts_path)?;
    }

    Ok(corpus)
}

fn parse_specimen_from_manifest(
    data: &serde_json::Value,
) -> Result<WorkloadSpecimen, Box<dyn std::error::Error>> {
    let id = data["id"]
        .as_str()
        .ok_or("Missing 'id' field")?
        .to_string();
    let name = data["name"]
        .as_str()
        .ok_or("Missing 'name' field")?
        .to_string();

    let family: WorkloadFamily = serde_json::from_value(data["family"].clone())?;
    let language: InputLanguage = serde_json::from_value(data["language"].clone())?;

    let provenance_data = data["provenance"]
        .as_object()
        .ok_or("Missing 'provenance' object")?;

    let origin: WorkloadOrigin = serde_json::from_value(provenance_data["origin"].clone())?;
    let license: LicenseStatus = serde_json::from_value(provenance_data["license"].clone())?;

    let source_url = provenance_data["source_url"]
        .as_str()
        .ok_or("Missing 'provenance.source_url' field")?
        .to_string();

    let source_version = provenance_data["source_version"]
        .as_str()
        .ok_or("Missing 'provenance.source_version' field")?
        .to_string();

    let selection_rationale = provenance_data["selection_rationale"]
        .as_str()
        .ok_or("Missing 'provenance.selection_rationale' field")?
        .to_string();

    let content_hash_str = provenance_data["content_hash"]
        .as_str()
        .ok_or("Missing 'provenance.content_hash' field")?;
    let content_hash = parse_content_hash(content_hash_str)?;

    let spdx_id = provenance_data["spdx_id"].as_str().map(|s| s.to_string());

    let mut observability_modes = BTreeSet::new();
    if let Some(modes_array) = data["observability_modes"].as_array() {
        for mode_val in modes_array {
            let mode: ObservabilityMode = serde_json::from_value(mode_val.clone())?;
            observability_modes.insert(mode);
        }
    } else {
        observability_modes.insert(ObservabilityMode::BudgetedDefault);
    }

    let mut secondary_families = BTreeSet::new();
    if let Some(sec_fam_array) = data["secondary_families"].as_array() {
        for fam_val in sec_fam_array {
            let fam: WorkloadFamily = serde_json::from_value(fam_val.clone())?;
            secondary_families.insert(fam);
        }
    }

    let mut tags = BTreeSet::new();
    if let Some(tags_array) = data["tags"].as_array() {
        for tag_val in tags_array {
            if let Some(tag_str) = tag_val.as_str() {
                tags.insert(tag_str.to_string());
            }
        }
    }

    let approximate_lines = data["approximate_lines"].as_u64().unwrap_or(0) as usize;
    let requires_native_addons = data["requires_native_addons"].as_bool().unwrap_or(false);
    let exercises_async = data["exercises_async"].as_bool().unwrap_or(false);

    let provenance = WorkloadProvenance {
        origin,
        source_url,
        license,
        spdx_id,
        source_version,
        selection_rationale,
        content_hash,
    };

    Ok(WorkloadSpecimen {
        id,
        name,
        family,
        secondary_families,
        language,
        provenance,
        observability_modes,
        approximate_lines,
        requires_native_addons,
        exercises_async,
        tags,
    })
}

fn parse_content_hash(hex_str: &str) -> Result<ContentHash, Box<dyn std::error::Error>> {
    // Remove 'content:' prefix if present
    let hex_str = hex_str.strip_prefix("content:").unwrap_or(hex_str);

    if hex_str.len() != 64 {
        return Err("ContentHash hex string must be exactly 64 characters".into());
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            return Err("ContentHash hex string too long".into());
        }
        let hex_byte = std::str::from_utf8(chunk)?;
        bytes[i] = u8::from_str_radix(hex_byte, 16)?;
    }

    Ok(ContentHash::from_bytes(bytes))
}

fn load_equivalence_artifacts(
    corpus: &mut WorkloadCorpus,
    artifacts_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(artifacts_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().unwrap_or_default() == "json" {
            let content = fs::read_to_string(&path)?;
            let equiv_data: serde_json::Value = serde_json::from_str(&content)?;

            let specimen_id = equiv_data["specimen_id"]
                .as_str()
                .ok_or("Missing 'specimen_id' in equivalence data")?
                .to_string();

            let baseline: BaselineRuntime = serde_json::from_value(equiv_data["baseline"].clone())?;
            let divergence_class: DivergenceClass = serde_json::from_value(equiv_data["divergence_class"].clone())?;

            let divergence_description = equiv_data["divergence_description"]
                .as_str()
                .unwrap_or("")
                .to_string();

            let output_hash_matches = equiv_data["output_hash_matches"]
                .as_bool()
                .unwrap_or(false);

            let franken_hash_str = equiv_data["franken_output_hash"]
                .as_str()
                .ok_or("Missing 'franken_output_hash' in equivalence data")?;
            let franken_output_hash = parse_content_hash(franken_hash_str)?;

            let baseline_hash_str = equiv_data["baseline_output_hash"]
                .as_str()
                .ok_or("Missing 'baseline_output_hash' in equivalence data")?;
            let baseline_output_hash = parse_content_hash(baseline_hash_str)?;

            let evidence_path = equiv_data["evidence_path"]
                .as_str()
                .map(|s| s.to_string());

            let equivalence_result = EquivalenceResult {
                specimen_id,
                baseline,
                divergence_class,
                divergence_description,
                output_hash_matches,
                franken_output_hash,
                baseline_output_hash,
                evidence_path,
            };

            corpus.record_equivalence(equivalence_result);
        }
    }

    Ok(())
}

fn build_seed_corpus() -> WorkloadCorpus {
    let mut corpus = WorkloadCorpus::new();

    for family in WorkloadFamily::ALL {
        let id = format!("seed_{}", family.as_str());
        let mut observability_modes = BTreeSet::new();
        observability_modes.insert(ObservabilityMode::BudgetedDefault);

        let mut tags = BTreeSet::new();
        tags.insert("seed".to_string());
        tags.insert(family.as_str().to_string());

        let specimen = WorkloadSpecimen {
            id: id.clone(),
            name: format!("Seed {} workload", family.as_str()),
            family: *family,
            secondary_families: BTreeSet::new(),
            language: InputLanguage::JavaScript,
            provenance: WorkloadProvenance {
                origin: WorkloadOrigin::InternalFixture,
                source_url: format!("internal://workload-corpus/{}", family.as_str()),
                license: LicenseStatus::Permissive,
                spdx_id: Some("MIT".to_string()),
                source_version: "seed-v1".to_string(),
                selection_rationale: format!("Representative {} workload", family.as_str()),
                content_hash: ContentHash::compute(id.as_bytes()),
            },
            observability_modes,
            approximate_lines: 2,
            requires_native_addons: *family == WorkloadFamily::NativeAddon,
            exercises_async: matches!(
                family,
                WorkloadFamily::AsyncHeavy | WorkloadFamily::HostcallSpike
            ),
            tags,
        };

        if let Err(e) = corpus.add_specimen(specimen) {
            eprintln!(
                "Warning: Failed to add seed specimen for {}: {:?}",
                family.as_str(),
                e
            );
        } else {
            let equiv = EquivalenceResult {
                specimen_id: id,
                baseline: BaselineRuntime::NodeJs,
                divergence_class: DivergenceClass::Identical,
                divergence_description: String::new(),
                output_hash_matches: true,
                franken_output_hash: ContentHash::compute(b"seed-output"),
                baseline_output_hash: ContentHash::compute(b"seed-output"),
                evidence_path: Some("internal://workload-corpus/seed-equivalence".to_string()),
            };
            corpus.record_equivalence(equiv);
        }
    }

    corpus
}

fn write_event(
    events_file: &Path,
    event_type: &str,
    data: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let event = Event {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        component: COMPONENT.to_string(),
        event_type: event_type.to_string(),
        data,
    };

    let event_json = serde_json::to_string(&event)?;
    use std::io::Write;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_file)?;
    writeln!(file, "{event_json}")?;
    Ok(())
}

fn verdict_label(verdict: &GateVerdict) -> &'static str {
    match verdict {
        GateVerdict::Pass => "pass",
        GateVerdict::Fail { .. } => "fail",
        GateVerdict::InsufficientData { .. } => "insufficient_data",
    }
}

fn emit_cli_error(argument: String, message: String) -> Result<(), Box<dyn std::error::Error>> {
    let output = CliErrorOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        error: message,
        argument,
    };
    eprintln!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let action = parse_args();

    match action {
        CliAction::Help => {
            print_help();
            Ok(())
        }
        CliAction::Error { argument, message } => {
            emit_cli_error(argument, message)?;
            std::process::exit(2);
        }
        CliAction::Run {
            out_dir,
            min_per_family,
            min_equivalence_rate,
            corpus_manifest_path,
            equivalence_artifacts_path,
            publication_mode,
        } => {
            // Ensure output directory exists
            fs::create_dir_all(&out_dir)?;

            // Set up artifact paths
            let gate_report_path = out_dir.join("gate_report.json");
            let corpus_manifest_path = out_dir.join("corpus_manifest.json");
            let run_manifest_path = out_dir.join("run_manifest.json");
            let events_path = out_dir.join("events.jsonl");
            let commands_path = out_dir.join("commands.txt");

            // Reset events.jsonl for clean per-run isolation
            if events_path.exists() {
                fs::remove_file(&events_path)?;
            }

            // Write initial event
            write_event(
                &events_path,
                "gate_start",
                serde_json::json!({
                    "out_dir": out_dir.display().to_string()
                }),
            )?;

            // Build or load corpus
            let corpus = if let Some(ref manifest_path) = corpus_manifest_path {
                load_curated_corpus(manifest_path, equivalence_artifacts_path.as_ref())?
            } else if publication_mode {
                return Err(
                    "Publication mode requires --corpus-manifest and --equivalence-artifacts"
                        .into(),
                );
            } else {
                build_seed_corpus()
            };
            write_event(
                &events_path,
                "corpus_built",
                serde_json::json!({
                    "total_specimens": corpus.specimens.len(),
                    "families_covered": corpus.family_coverage.len()
                }),
            )?;

            // Configure gate
            let mut config = GateConfig::default();
            if let Some(min) = min_per_family {
                config.min_per_family = min;
            }
            if let Some(rate) = min_equivalence_rate {
                config.equivalence_threshold = rate;
            }

            // Run gate evaluation
            let gate = WorkloadCorpusGate::new(config.clone());
            let report = gate.evaluate(&corpus);

            write_event(
                &events_path,
                "gate_evaluated",
                serde_json::json!({
                    "verdict": verdict_label(&report.verdict),
                    "total_specimens": report.total_specimens,
                    "families_covered": report.families_covered
                }),
            )?;

            // Write gate report
            let gate_report_json = serde_json::to_string_pretty(&report)?;
            fs::write(&gate_report_path, &gate_report_json)?;

            // Write corpus manifest
            let corpus_manifest = serde_json::json!({
                "schema_version": CORPUS_MANIFEST_SCHEMA_VERSION,
                "total_specimens": corpus.specimens.len(),
                "families_covered": corpus.family_coverage.len(),
                "specimens": corpus.specimens.keys().collect::<Vec<_>>(),
                "family_coverage": corpus.family_coverage
            });
            fs::write(
                &corpus_manifest_path,
                serde_json::to_string_pretty(&corpus_manifest)?,
            )?;

            // Write run manifest
            let run_manifest = RunManifest {
                schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
                component: COMPONENT.to_string(),
                policy_id: POLICY_ID.to_string(),
                generated_at_utc: chrono::Utc::now().to_rfc3339(),
                out_dir: out_dir.display().to_string(),
                total_specimens: report.total_specimens,
                families_covered: report.families_covered,
                verdict: verdict_label(&report.verdict).to_string(),
                gate_config: GateConfigSummary {
                    min_per_family: config.min_per_family,
                    min_families: config.min_families,
                    equivalence_threshold: config.equivalence_threshold,
                    max_divergence_ratio: config.max_divergence_ratio,
                    require_publishable_licenses: config.require_publishable_licenses,
                    require_observability_coverage: config.require_observability_coverage,
                },
            };
            fs::write(
                &run_manifest_path,
                serde_json::to_string_pretty(&run_manifest)?,
            )?;

            // Write commands log with complete CLI parameters for reproducible replay
            let mut replay_cmd = format!(
                "franken_workload_corpus_gate --out-dir {}",
                out_dir.display()
            );
            if let Some(min_fam) = min_per_family {
                replay_cmd.push_str(&format!(" --min-per-family {}", min_fam));
            }
            if let Some(min_eq_rate) = min_equivalence_rate {
                replay_cmd.push_str(&format!(" --min-equivalence-rate {}", min_eq_rate));
            }
            if let Some(ref manifest_path) = corpus_manifest_path {
                replay_cmd.push_str(&format!(" --corpus-manifest {}", manifest_path.display()));
            }
            if let Some(ref artifacts_path) = equivalence_artifacts_path {
                replay_cmd.push_str(&format!(" --equivalence-artifacts {}", artifacts_path.display()));
            }
            if publication_mode {
                replay_cmd.push_str(" --publication-mode");
            }

            let commands = [replay_cmd, "# Corpus evaluation completed".to_string()];
            fs::write(&commands_path, commands.join("\n"))?;

            // Compute hashes
            let corpus_hash = ContentHash::compute(corpus_manifest.to_string().as_bytes());
            let report_hash = ContentHash::compute(gate_report_json.as_bytes());

            // Write final event
            write_event(
                &events_path,
                "gate_complete",
                serde_json::json!({
                    "verdict": verdict_label(&report.verdict),
                    "corpus_hash": corpus_hash.to_string(),
                    "report_hash": report_hash.to_string()
                }),
            )?;

            // Output final summary
            let output = CommandOutput {
                schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
                out_dir: out_dir.display().to_string(),
                gate_report: gate_report_path.display().to_string(),
                corpus_manifest: corpus_manifest_path.display().to_string(),
                run_manifest: run_manifest_path.display().to_string(),
                events_jsonl: events_path.display().to_string(),
                commands_txt: commands_path.display().to_string(),
                corpus_hash: corpus_hash.to_string(),
                report_hash: report_hash.to_string(),
                verdict: verdict_label(&report.verdict).to_string(),
                total_specimens: report.total_specimens,
                families_covered: report.families_covered,
                overall_equivalence_rate: report.aggregate_equivalence_rate_millionths,
            };

            println!("{}", serde_json::to_string_pretty(&output)?);

            // Exit with appropriate code based on verdict
            if report.verdict.permits_publication() {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        }
    }
}
