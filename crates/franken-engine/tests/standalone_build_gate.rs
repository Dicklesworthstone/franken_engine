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

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!("frankenengine-{label}-{}-{nanos}", process::id()))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_text(path: &str) -> String {
    let path = repo_root().join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn single_run_dir(root: &PathBuf) -> PathBuf {
    let mut entries = fs::read_dir(root)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", root.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one run dir under {}",
        root.display()
    );
    entries.remove(0)
}

#[test]
fn standalone_build_gate_script_routes_heavy_lanes_through_rch() {
    let script = read_repo_text("scripts/test_standalone_build.sh");
    assert!(
        script.contains("STANDALONE_BUILD_GATE_SKIP_REMOTE"),
        "script should support a cheap skip mode for tests"
    );
    assert!(
        script.contains("rch exec -- env"),
        "script should route heavy cargo lanes through rch"
    );
    assert!(
        script.contains("cargo check -p frankenengine-engine --no-default-features"),
        "script should verify standalone cargo check"
    );
    assert!(
        script.contains("cargo test -p frankenengine-engine --no-default-features"),
        "script should verify standalone cargo test"
    );
    assert!(
        script.contains("cargo check -p frankenengine-engine --all-features"),
        "script should verify the full integration cargo check"
    );
    assert!(
        script.contains("skipped_missing_external_deps"),
        "script should classify a missing sibling-dependency full lane explicitly"
    );
    assert!(
        script.contains("overall_status"),
        "script should emit an overall manifest status"
    );
}

#[test]
fn standalone_build_gate_skip_mode_emits_manifest_and_commands() {
    let out_dir = unique_temp_dir("standalone-build-gate");
    let script = repo_root().join("scripts/test_standalone_build.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("ci")
        .env("STANDALONE_BUILD_GATE_ARTIFACT_ROOT", &out_dir)
        .env("STANDALONE_BUILD_GATE_SKIP_REMOTE", "1")
        .output()
        .expect("run standalone build gate script");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let run_dir = single_run_dir(&out_dir);
    let manifest_path = run_dir.join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("manifest must be valid json");

    assert_eq!(
        manifest["schema_version"],
        "franken-engine.standalone-build-gate.v1"
    );
    assert_eq!(manifest["mode"], "ci");
    assert_eq!(
        manifest["build_modes"]["standalone"]["status"],
        "not_verified"
    );
    assert_eq!(
        manifest["build_modes"]["full_integration"]["status"],
        "not_verified"
    );

    let lanes = manifest["lanes"]
        .as_array()
        .expect("lanes should be an array");
    assert_eq!(lanes.len(), 3, "ci mode should report three lanes");
    for lane in lanes {
        assert_eq!(lane["status"], "skipped");
    }

    let commands = fs::read_to_string(run_dir.join("commands.txt")).expect("read commands");
    assert!(
        commands.contains("cargo check -p frankenengine-engine --no-default-features"),
        "commands.txt should record the standalone check lane"
    );
    assert!(
        commands.contains("cargo test -p frankenengine-engine --no-default-features"),
        "commands.txt should record the standalone test lane"
    );
    assert!(
        commands.contains("cargo check -p frankenengine-engine --all-features"),
        "commands.txt should record the full integration lane"
    );
}

#[test]
fn readme_documents_build_modes_and_gate_script() {
    let readme = read_repo_text("README.md");
    assert!(
        readme.contains("./scripts/test_standalone_build.sh ci"),
        "README should point operators at the RC-6.4 build gate script"
    );
    assert!(
        readme.contains("cargo check -p frankenengine-engine --no-default-features"),
        "README should document the standalone verification command"
    );
    assert!(
        readme.contains("cargo test -p frankenengine-engine --no-default-features"),
        "README should document the standalone test command"
    );
    assert!(
        readme.contains("cargo check -p frankenengine-engine --all-features"),
        "README should document the full integration verification command"
    );
    assert!(
        readme.contains("artifacts/standalone_build_gate/"),
        "README should document the build-gate artifact root"
    );
}
