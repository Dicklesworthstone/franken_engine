#[path = "../seqlock_candidate_inventory.rs"]
mod seqlock_candidate_inventory;

use seqlock_candidate_inventory::{
    ArtifactContext, canonical_generated_at_utc, emit_default_inventory_bundle, render_summary,
    run_id_for_timestamp,
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

    let mut artifact_dir: Option<String> = None;
    let mut trace_id = None;
    let mut decision_id = None;
    let mut policy_id = None;
    let mut run_id = None;
    let mut generated_at_utc = None;
    let mut source_commit = None;
    let mut toolchain = None;
    let mut summary = false;

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
    let run_id_was_supplied = run_id.is_some();
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
    if let Some(generated_at_utc) = generated_at_utc {
        let canonical = canonical_generated_at_utc(&generated_at_utc)
            .map_err(|error| format!("invalid --generated-at-utc: {error}"))?;
        context.generated_at_utc = canonical.clone();
        if !run_id_was_supplied {
            context.run_id = run_id_for_timestamp(&canonical)
                .map_err(|error| format!("invalid --generated-at-utc: {error}"))?;
        }
    }
    if let Some(run_id) = run_id {
        context.run_id = run_id;
    }
    if let Some(source_commit) = source_commit {
        context.source_commit = source_commit;
    }
    if let Some(toolchain) = toolchain {
        context.toolchain = toolchain;
    }
    context.command_invocation = build_command_line(&context);

    let bundle = emit_default_inventory_bundle(&context)
        .map_err(|error| format!("failed to write artifact bundle: {error}"))?;

    if summary {
        println!("{}", render_summary(&bundle.inventory));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&bundle)
                .map_err(|error| format!("failed to encode bundle summary: {error}"))?
        );
    }

    Ok(())
}

fn build_command_line(context: &ArtifactContext) -> String {
    format!(
        "cargo run -p frankenengine-engine --bin franken_seqlock_candidate_inventory -- --artifact-dir {} --trace-id {} --decision-id {} --policy-id {} --run-id {} --generated-at-utc {} --source-commit {} --toolchain {}",
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
        "franken_seqlock_candidate_inventory usage:",
        "  cargo run -p frankenengine-engine --bin franken_seqlock_candidate_inventory -- \\",
        "      --artifact-dir <path> [--summary] [--trace-id <id>] [--decision-id <id>] \\",
        "      [--policy-id <id>] [--run-id <id>] [--generated-at-utc <rfc3339>] \\",
        "      [--source-commit <sha>] [--toolchain <name>]",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(label: &str) -> String {
        static NEXT_DIR_ID: AtomicU64 = AtomicU64::new(0);
        let dir_id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "franken-engine-seqlock-candidate-cli-{label}-{}-{dir_id}",
            std::process::id(),
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path.display().to_string()
    }

    #[test]
    fn generated_at_utc_rejects_invalid_rfc3339() {
        let err = run(vec![
            "--artifact-dir".to_string(),
            temp_dir("invalid-ts"),
            "--generated-at-utc".to_string(),
            "not-a-timestamp".to_string(),
        ])
        .expect_err("invalid timestamp should fail closed");

        assert!(err.contains("invalid --generated-at-utc"));
        assert!(err.contains("RFC3339"));
    }

    #[test]
    fn generated_at_utc_updates_default_run_id() {
        let artifact_dir = temp_dir("generated-at-run-id");
        run(vec![
            "--artifact-dir".to_string(),
            artifact_dir.clone(),
            "--generated-at-utc".to_string(),
            "2026-01-01T01:02:03+01:00".to_string(),
            "--summary".to_string(),
        ])
        .expect("valid timestamp should write bundle");

        let run_manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(std::path::Path::new(&artifact_dir).join("run_manifest.json"))
                .expect("read run manifest"),
        )
        .expect("run manifest parses");
        assert_eq!(run_manifest["generated_at_utc"], "2026-01-01T00:02:03Z");
        assert_eq!(
            run_manifest["run_id"],
            "run-seqlock_candidate_inventory-20260101T000203"
        );
    }
}
