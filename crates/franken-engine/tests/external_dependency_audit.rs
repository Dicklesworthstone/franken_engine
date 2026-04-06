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

#[test]
fn dependency_audit_script_uses_rch_for_compile_checks() {
    let script = read_repo_text("scripts/audit_external_deps.sh");
    assert!(
        script.contains("DEPENDENCY_AUDIT_SKIP_REMOTE"),
        "script should support a cheap non-remote mode for tests"
    );
    assert!(
        script.contains("rch exec -- env"),
        "script should use rch for external cargo checks"
    );
    assert!(
        script.contains("blocked_by_external_path_dependencies"),
        "script should report standalone-build blockage explicitly"
    );
}

#[test]
fn dependency_audit_script_emits_manifest_in_skip_remote_mode() {
    let out_dir = unique_temp_dir("dependency-audit");
    let script = repo_root().join("scripts/audit_external_deps.sh");
    let output = Command::new("bash")
        .arg(&script)
        .env("DEPENDENCY_AUDIT_ARTIFACT_ROOT", &out_dir)
        .env("DEPENDENCY_AUDIT_SKIP_REMOTE", "1")
        .output()
        .expect("run dependency audit script");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest_path = out_dir.join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("manifest must be valid json");

    assert_eq!(
        manifest["schema_version"],
        "franken-engine.external-dependency-audit.v1"
    );
    assert_eq!(
        manifest["standalone_build"]["status"],
        "blocked_by_external_path_dependencies"
    );
    assert_eq!(
        manifest["full_integration_dependency_health"]["status"],
        "not_verified"
    );

    let dependencies = manifest["dependencies"]
        .as_array()
        .expect("dependencies should be an array");
    assert_eq!(dependencies.len(), 3, "expected the asupersync tripod only");

    for dependency_key in ["franken-kernel", "franken-decision", "franken-evidence"] {
        let dependency = dependencies
            .iter()
            .find(|entry| entry["dependency_key"] == dependency_key)
            .unwrap_or_else(|| panic!("missing dependency entry for {dependency_key}"));
        assert!(
            dependency["path_exists"].as_bool().unwrap_or(false),
            "{dependency_key} path should exist on this machine"
        );
        assert!(
            dependency["cargo_toml_present"].as_bool().unwrap_or(false),
            "{dependency_key} should have Cargo.toml"
        );
        assert_eq!(dependency["compile_check"]["status"], "skipped");
    }

    let kernel = dependencies
        .iter()
        .find(|entry| entry["dependency_key"] == "franken-kernel")
        .expect("kernel dependency present");
    let kernel_symbols = kernel["imported_symbols"]
        .as_array()
        .expect("kernel imported symbols array");
    assert!(
        kernel_symbols.iter().any(|symbol| symbol == "Cx"),
        "kernel import surface should record Cx"
    );
    assert!(
        kernel["approved_boundary_files"]
            .as_array()
            .expect("boundary file array")
            .iter()
            .any(|path| path == "crates/franken-engine/src/control_plane/mod.rs"),
        "kernel dependency should point at the control-plane adapter boundary"
    );

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(
        commands.contains("rg -n 'path = \"/dp/' -g 'Cargo.toml' ."),
        "commands.txt should record the dependency scan"
    );
}
