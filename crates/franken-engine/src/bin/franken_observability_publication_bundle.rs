#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use frankenengine_engine::observability_publication_bundle::{
    BEAD_ID, COMPONENT, ObservabilityPublicationArtifacts, write_observability_publication_bundle,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_observability_publication_bundle.v1";

enum CliAction {
    Help,
    Run { out_dir: PathBuf },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    bead_id: String,
    component: String,
    out_dir: String,
    observability_budget_sentinel_report: String,
    observability_on_supremacy_matrix: String,
    observability_claim_delta_report: String,
    telemetry_demotion_receipts: String,
    observability_publication_policy: String,
    support_bundle_observability_attestation: String,
    bundle_hash: String,
    attested: bool,
    suppressed_claim_count: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let out_dir = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(());
        }
        CliAction::Run { out_dir } => out_dir,
    };

    let artifacts =
        write_observability_publication_bundle(&out_dir).map_err(|error| error.to_string())?;
    let output = render_output(artifacts);
    let rendered = serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn render_output(artifacts: ObservabilityPublicationArtifacts) -> CommandOutput {
    CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        out_dir: artifacts.out_dir.display().to_string(),
        observability_budget_sentinel_report: artifacts
            .observability_budget_sentinel_report_path
            .display()
            .to_string(),
        observability_on_supremacy_matrix: artifacts
            .observability_on_supremacy_matrix_path
            .display()
            .to_string(),
        observability_claim_delta_report: artifacts
            .observability_claim_delta_report_path
            .display()
            .to_string(),
        telemetry_demotion_receipts: artifacts
            .telemetry_demotion_receipts_path
            .display()
            .to_string(),
        observability_publication_policy: artifacts
            .observability_publication_policy_path
            .display()
            .to_string(),
        support_bundle_observability_attestation: artifacts
            .support_bundle_observability_attestation_path
            .display()
            .to_string(),
        bundle_hash: artifacts.bundle_hash,
        attested: artifacts.attested,
        suppressed_claim_count: artifacts.suppressed_claim_count,
    }
}

fn parse_args(args: &[String]) -> Result<CliAction, String> {
    if args.is_empty() {
        return Err(help_text());
    }

    let mut out_dir: Option<PathBuf> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "--out-dir" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--out-dir requires a path".to_string());
                };
                out_dir = Some(PathBuf::from(value));
                index += 2;
            }
            other => {
                return Err(format!(
                    "unrecognized argument `{other}`\n\n{}",
                    help_text()
                ));
            }
        }
    }

    out_dir
        .map(|out_dir| CliAction::Run { out_dir })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_observability_publication_bundle --out-dir <DIR>".to_string()
}
