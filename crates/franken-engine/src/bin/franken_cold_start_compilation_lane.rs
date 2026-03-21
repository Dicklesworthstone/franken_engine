use std::fs;

use frankenengine_engine::cold_start_compilation_lane::{
    ArtifactContext, BundleWriteReport, emit_default_bundle, render_summary,
};
use serde::Serialize;

const LOCAL_BUNDLE_JSON_BEGIN: &str = "__RGC_COLD_START_COMPILATION_LANE_BUNDLE_JSON_BEGIN__";
const LOCAL_BUNDLE_JSON_END: &str = "__RGC_COLD_START_COMPILATION_LANE_BUNDLE_JSON_END__";

#[derive(Debug, Serialize)]
struct LocalBundleFile {
    relative_path: String,
    contents: String,
}

#[derive(Debug, Serialize)]
struct LocalBundlePayload {
    artifact_dir: String,
    files: Vec<LocalBundleFile>,
}

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

    let mut artifact_dir: Option<String> = None;
    let mut trace_id = None;
    let mut decision_id = None;
    let mut policy_id = None;
    let mut run_id = None;
    let mut generated_at_utc = None;
    let mut source_commit = None;
    let mut toolchain = None;
    let mut summary = false;
    let mut emit_local_bundle_json = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--artifact-dir" => {
                index += 1;
                artifact_dir = Some(
                    args.get(index)
                        .ok_or_else(|| "--artifact-dir requires a path".to_string())?
                        .clone(),
                );
            }
            "--trace-id" => {
                index += 1;
                trace_id = Some(
                    args.get(index)
                        .ok_or_else(|| "--trace-id requires a value".to_string())?
                        .clone(),
                );
            }
            "--decision-id" => {
                index += 1;
                decision_id = Some(
                    args.get(index)
                        .ok_or_else(|| "--decision-id requires a value".to_string())?
                        .clone(),
                );
            }
            "--policy-id" => {
                index += 1;
                policy_id = Some(
                    args.get(index)
                        .ok_or_else(|| "--policy-id requires a value".to_string())?
                        .clone(),
                );
            }
            "--run-id" => {
                index += 1;
                run_id = Some(
                    args.get(index)
                        .ok_or_else(|| "--run-id requires a value".to_string())?
                        .clone(),
                );
            }
            "--generated-at-utc" => {
                index += 1;
                generated_at_utc = Some(
                    args.get(index)
                        .ok_or_else(|| "--generated-at-utc requires a value".to_string())?
                        .clone(),
                );
            }
            "--source-commit" => {
                index += 1;
                source_commit = Some(
                    args.get(index)
                        .ok_or_else(|| "--source-commit requires a value".to_string())?
                        .clone(),
                );
            }
            "--toolchain" => {
                index += 1;
                toolchain = Some(
                    args.get(index)
                        .ok_or_else(|| "--toolchain requires a value".to_string())?
                        .clone(),
                );
            }
            "--summary" => summary = true,
            "--emit-local-bundle-json" => emit_local_bundle_json = true,
            "help" | "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            flag => return Err(format!("unknown flag '{flag}'\n\n{}", usage())),
        }
        index += 1;
    }

    let artifact_dir =
        artifact_dir.ok_or_else(|| "missing required --artifact-dir <path>".to_string())?;
    let mut context = ArtifactContext::new(artifact_dir);
    if let Some(trace_id) = trace_id {
        context.trace_id = trace_id;
    }
    if let Some(decision_id) = decision_id {
        context.decision_id = decision_id;
    }
    if let Some(policy_id) = policy_id {
        context.policy_id = policy_id;
    }
    if let Some(run_id) = run_id {
        context.run_id = run_id;
    }
    if let Some(generated_at_utc) = generated_at_utc {
        context.generated_at_utc = generated_at_utc;
    }
    if let Some(source_commit) = source_commit {
        context.source_commit = source_commit;
    }
    if let Some(toolchain) = toolchain {
        context.toolchain = toolchain;
    }
    context.command_invocation = build_command_line(&context);

    let bundle = emit_default_bundle(&context)
        .map_err(|error| format!("failed to emit cold-start compilation lane bundle: {error}"))?;

    if summary {
        println!("{}", render_summary(&bundle.report));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "artifact_dir": bundle.artifact_dir,
                "report_path": bundle.report_path,
                "observability_delta_path": bundle.observability_delta_path,
                "aot_bundle_report_path": bundle.aot_bundle_report_path,
                "runtime_image_manifest_path": bundle.runtime_image_manifest_path,
                "trace_ids_path": bundle.trace_ids_path,
                "summary_path": bundle.summary_path,
                "written_files": bundle.written_files,
            }))
            .map_err(|error| format!("failed to encode bundle summary: {error}"))?
        );
    }

    if emit_local_bundle_json {
        let payload = build_local_bundle_payload(&bundle)?;
        println!("{LOCAL_BUNDLE_JSON_BEGIN}");
        println!(
            "{}",
            serde_json::to_string(&payload)
                .map_err(|error| format!("failed to encode local bundle payload: {error}"))?
        );
        println!("{LOCAL_BUNDLE_JSON_END}");
    }

    Ok(())
}

fn build_local_bundle_payload(bundle: &BundleWriteReport) -> Result<LocalBundlePayload, String> {
    let files = bundle
        .report
        .required_artifacts
        .iter()
        .map(|relative_path| {
            let absolute_path = bundle.artifact_dir.join(relative_path);
            let contents = fs::read_to_string(&absolute_path).map_err(|error| {
                format!(
                    "failed to read emitted artifact {}: {error}",
                    absolute_path.display()
                )
            })?;
            Ok(LocalBundleFile {
                relative_path: relative_path.clone(),
                contents,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(LocalBundlePayload {
        artifact_dir: bundle.artifact_dir.display().to_string(),
        files,
    })
}

fn build_command_line(context: &ArtifactContext) -> String {
    format!(
        "cargo run -p frankenengine-engine --bin franken_cold_start_compilation_lane -- --artifact-dir {} --trace-id {} --decision-id {} --policy-id {} --run-id {} --generated-at-utc {} --source-commit {} --toolchain {}",
        context.artifact_dir.display(),
        context.trace_id,
        context.decision_id,
        context.policy_id,
        context.run_id,
        context.generated_at_utc,
        context.source_commit,
        context.toolchain,
    )
}

fn usage() -> String {
    [
        "franken_cold_start_compilation_lane usage:",
        "  cargo run -p frankenengine-engine --bin franken_cold_start_compilation_lane -- \\",
        "      --artifact-dir <path> [--summary] [--trace-id <id>] [--decision-id <id>] \\",
        "      [--policy-id <id>] [--run-id <id>] [--generated-at-utc <rfc3339>] \\",
        "      [--source-commit <sha>] [--toolchain <name>] [--emit-local-bundle-json]",
    ]
    .join("\n")
}
