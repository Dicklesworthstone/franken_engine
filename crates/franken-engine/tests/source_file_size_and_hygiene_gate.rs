#![forbid(unsafe_code)]
//! Source file size & workspace hygiene gate (`bd-rc-2026-11-11-epic-g2vrp.2`).
//!
//! Guarantees that no Rust source file in `crates/` exceeds `25,000` lines
//! (preventing `rustfmt`'s Myers/LCS `diff::lines` O(N^2) 123.4 GiB OOM crash)
//! and that every `baseline_interpreter` module remains `<= 20,000` lines.

use std::fs;
use std::path::{Path, PathBuf};

const MAX_WORKSPACE_RUST_FILE_LINES: usize = 25_000;
const MAX_BASELINE_INTERPRETER_FILE_LINES: usize = 20_000;

fn workspace_crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ parent")
        .to_path_buf()
}

fn collect_files_recursively(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_files_recursively(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn all_workspace_rust_files_stay_within_rustfmt_safe_line_budget() {
    let crates_dir = workspace_crates_dir();
    let mut all_files = Vec::new();
    collect_files_recursively(&crates_dir, &mut all_files);

    let mut oversized_workspace = Vec::new();
    let mut oversized_interpreter = Vec::new();
    let mut unexpected_patch_debris = Vec::new();
    let mut checked_rs_count = 0usize;

    for path in &all_files {
        let rel = path
            .strip_prefix(&crates_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        if rel.ends_with(".orig") {
            unexpected_patch_debris.push(rel.clone());
            continue;
        }
        if rel.ends_with(".rej")
            && !matches!(
                rel.as_str(),
                "franken-engine/src/baseline_interpreter.rs.rej"
                    | "franken-engine/src/control_plane_mock_inventory.rs.rej"
            )
        {
            unexpected_patch_debris.push(rel.clone());
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        checked_rs_count += 1;
        let content =
            fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read `{rel}`: {err}"));
        let lines = content.lines().count();

        if lines > MAX_WORKSPACE_RUST_FILE_LINES {
            eprintln!(
                "{{\"path\":\"crates/{rel}\",\"lines\":{lines},\"limit\":{MAX_WORKSPACE_RUST_FILE_LINES},\"status\":\"fail_workspace_limit\"}}"
            );
            oversized_workspace.push((rel.clone(), lines));
        }
        let is_baseline_interpreter = rel == "franken-engine/src/baseline_interpreter.rs"
            || rel.starts_with("franken-engine/src/baseline_interpreter/");
        if is_baseline_interpreter && lines > MAX_BASELINE_INTERPRETER_FILE_LINES {
            eprintln!(
                "{{\"path\":\"crates/{rel}\",\"lines\":{lines},\"limit\":{MAX_BASELINE_INTERPRETER_FILE_LINES},\"status\":\"fail_interpreter_limit\"}}"
            );
            oversized_interpreter.push((rel, lines));
        }
    }

    assert!(
        checked_rs_count >= 500,
        "expected >=500 .rs files in crates/, scanned {checked_rs_count}"
    );
    assert!(
        unexpected_patch_debris.is_empty(),
        "unexpected .orig/.rej patch debris in crates/: {unexpected_patch_debris:?}"
    );
    assert!(
        oversized_interpreter.is_empty(),
        "baseline_interpreter files exceed {MAX_BASELINE_INTERPRETER_FILE_LINES} LoC: {oversized_interpreter:?}"
    );
    assert!(
        oversized_workspace.is_empty(),
        "workspace Rust files exceed {MAX_WORKSPACE_RUST_FILE_LINES} LoC (rustfmt OOM risk): {oversized_workspace:?}"
    );
}
