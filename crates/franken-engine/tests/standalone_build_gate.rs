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

fn load_dependency_isolation_contract() -> serde_json::Value {
    serde_json::from_str(&read_repo_text(
        "docs/cross_repo_dependency_isolation_v1.json",
    ))
    .expect("dependency isolation contract should parse")
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
fn moved_buffer_target_preserves_ownership_and_feature_modes() {
    use std::collections::{BTreeMap, BTreeSet};

    let engine: toml::Value = toml::from_str(&read_repo_text("crates/franken-engine/Cargo.toml"))
        .expect("parse engine manifest");
    let companion: toml::Value = toml::from_str(&read_repo_text(
        "crates/franken-engine-control-plane-integration-tests/Cargo.toml",
    ))
    .expect("parse companion manifest");
    let sentinel = "__moved_to_frankenengine_control_plane_integration_tests";
    let mut moved = BTreeMap::new();
    for target in engine["test"].as_array().expect("engine explicit tests") {
        if target
            .get("required-features")
            .and_then(toml::Value::as_array)
            .is_some_and(|features| {
                features
                    .iter()
                    .any(|feature| feature.as_str() == Some(sentinel))
            })
        {
            moved.insert(target["name"].as_str().unwrap(), target);
        }
    }
    let owned = companion["test"]
        .as_array()
        .expect("companion explicit tests")
        .iter()
        .map(|target| (target["name"].as_str().unwrap(), target))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        moved.len(),
        26,
        "all existing targets plus Buffer stay moved"
    );
    assert_eq!(owned.len(), 26);
    assert!(owned.contains_key("buffer_value_bd_9vouw_104"));
    assert_eq!(
        moved.keys().collect::<Vec<_>>(),
        owned.keys().collect::<Vec<_>>()
    );
    for (name, target) in moved {
        let original = repo_root()
            .join("crates/franken-engine")
            .join(target["path"].as_str().unwrap())
            .canonicalize()
            .unwrap();
        let compiled = repo_root()
            .join("crates/franken-engine-control-plane-integration-tests")
            .join(owned[name]["path"].as_str().unwrap())
            .canonicalize()
            .unwrap();
        assert_eq!(original, compiled, "the same test source is owned: {name}");
    }
    assert_eq!(companion["package"]["autotests"].as_bool(), Some(false));
    assert_eq!(
        companion["features"]["default"].as_array().unwrap(),
        &[toml::Value::String("engine-defaults".into())]
    );
    assert_eq!(
        companion["features"]["engine-defaults"].as_array().unwrap(),
        &[toml::Value::String("frankenengine-engine/default".into())]
    );
    let dependency = &companion["dev-dependencies"]["frankenengine-engine"];
    assert_eq!(dependency["default-features"].as_bool(), Some(false));
    let explicit = dependency["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|feature| feature.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        explicit,
        BTreeSet::from(["asupersync-integration", "tee-test-mock"])
    );
    assert!(
        engine["dev-dependencies"]
            .get("frankenengine-engine")
            .is_none(),
        "moving tests must not recreate the engine self dev-dependency"
    );
    assert!(
        !engine["features"]["default"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature.as_str() == Some("tee-test-mock")),
        "mock TEE stays outside engine production defaults"
    );
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
        script.contains(r#""RCH_BUILD_TIMEOUT_SEC=${rch_timeout_seconds}""#)
            && script.contains(r#""RCH_TEST_TIMEOUT_SEC=${rch_timeout_seconds}""#),
        "the gate should propagate its one-hour cold-build budget into rch"
    );
    assert!(
        script.contains(r#""RCH_REQUIRE_REMOTE=1""#),
        "the gate should refuse local cargo fallback before it starts"
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
        script.contains("cargo test -p frankenengine-control-plane-integration-tests --no-default-features --test buffer_value_bd_9vouw_104"),
        "script should retain the moved Buffer target's standalone coverage"
    );
    assert!(
        script.contains(
            "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl"
        ),
        "script should verify the standalone frankenctl release build"
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
    assert!(
        script.contains(r#"[[ "$run_failures" -gt 0 || "$failed_lane_count" -gt 0 ]]"#),
        "every recorded lane failure should make the gate fail closed"
    );

    let workflow = read_repo_text(".github/workflows/quality-gates.yml");
    assert!(
        workflow.contains("test ! -e /dp"),
        "the PR release lane should prove that the hosted runner has no /dp checkout"
    );
    assert!(
        workflow.contains(
            "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl"
        ),
        "the PR workflow should enforce the exact standalone release build"
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
        .env(
            "STANDALONE_BUILD_GATE_SIBLING_ROOT",
            out_dir.join("intentionally-absent-siblings"),
        )
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
    assert_eq!(lanes.len(), 14, "ci mode should report every declared lane");
    for lane_name in [
        "standalone-check",
        "standalone-test",
        "standalone-fleet-test",
        "standalone-buffer-test",
        "standalone-release",
        "full-check",
    ] {
        let lane = lanes
            .iter()
            .find(|lane| lane["lane"] == lane_name)
            .unwrap_or_else(|| panic!("missing lane {lane_name}"));
        assert_eq!(lane["status"], "skipped", "heavy lane {lane_name}");
    }
    for sibling in [
        "asupersync",
        "frankentui",
        "frankensqlite",
        "sqlmodel_rust",
        "fastapi_rust",
        "frankenpandas",
    ] {
        let lane_name = format!("full-integration-{sibling}");
        let lane = lanes
            .iter()
            .find(|lane| lane["lane"] == lane_name)
            .unwrap_or_else(|| panic!("missing lane {lane_name}"));
        assert_eq!(
            lane["status"], "skipped",
            "the fixture makes sibling lane {lane_name} deterministically absent"
        );
    }
    for lane_name in ["sibling-isolation", "patch-version-consistency"] {
        let lane = lanes
            .iter()
            .find(|lane| lane["lane"] == lane_name)
            .unwrap_or_else(|| panic!("missing lane {lane_name}"));
        assert_eq!(lane["status"], "passed", "policy lane {lane_name}");
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
        commands.contains("cargo test -p frankenengine-control-plane-integration-tests --no-default-features --test fleet_quarantine_integration"),
        "commands.txt should retain the moved fleet test lane"
    );
    assert!(
        commands.contains("cargo test -p frankenengine-control-plane-integration-tests --no-default-features --test buffer_value_bd_9vouw_104"),
        "commands.txt should retain the moved Buffer test lane"
    );
    assert!(
        commands.contains(
            "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl"
        ),
        "commands.txt should record the standalone release lane"
    );
    assert!(
        commands.contains("cargo check -p frankenengine-engine --all-features"),
        "commands.txt should record the full integration lane"
    );
}

#[cfg(unix)]
#[test]
fn standalone_build_gate_rejects_injected_fleet_command_failure() {
    assert_moved_target_command_failure_blocks_gate(
        "fleet_quarantine_integration",
        "standalone-fleet-test",
    );
}

#[cfg(unix)]
#[test]
fn standalone_build_gate_rejects_injected_buffer_command_failure() {
    assert_moved_target_command_failure_blocks_gate(
        "buffer_value_bd_9vouw_104",
        "standalone-buffer-test",
    );
}

#[cfg(unix)]
fn assert_moved_target_command_failure_blocks_gate(failing_target: &str, failing_lane: &str) {
    use std::os::unix::fs::PermissionsExt;

    let out_dir = unique_temp_dir(&format!("standalone-{failing_target}-command-failure"));
    let bin_dir = out_dir.join("injected-bin");
    fs::create_dir_all(&bin_dir).expect("create injected command directory");
    let rch = bin_dir.join("rch");
    let toolchain: toml::Value = toml::from_str(
        &fs::read_to_string(repo_root().join("rust-toolchain.toml")).expect("read repository pin"),
    )
    .expect("parse repository toolchain");
    let pinned_channel = toolchain["toolchain"]["channel"]
        .as_str()
        .expect("pinned channel");
    // Protocol fault double tests the shell gate, not any Rust compilation or
    // integration execution. With the declared pin, only the selected command
    // fails. A floating-nightly override must also fail the permitted lane.
    fs::write(
        &rch,
        r#"#!/usr/bin/env bash
pin_seen=0
for argument in "$@"; do
  if [[ "$argument" == "RUSTUP_TOOLCHAIN=$EXPECTED_RUSTUP_TOOLCHAIN" ]]; then
    pin_seen=1
  fi
done
if [[ "$pin_seen" != 1 ]]; then
  echo 'Remote command finished: exit=91' >&2
  exit 91
fi
case "$*" in
*"--test $INJECTED_FAILING_TARGET"*)
  echo 'Remote command finished: exit=23' >&2
  exit 23
  ;;
*) echo 'Remote command finished: exit=0' ;;
esac
"#,
    )
    .expect("write injected RCH protocol double");
    fs::set_permissions(&rch, fs::Permissions::from_mode(0o755)).expect("make double executable");
    let mut paths = vec![bin_dir];
    paths.extend(env::split_paths(&env::var_os("PATH").expect("PATH")));
    let output = Command::new("bash")
        .arg(repo_root().join("scripts/test_standalone_build.sh"))
        .arg("standalone-test")
        .env("PATH", env::join_paths(paths).expect("fixture PATH"))
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("EXPECTED_RUSTUP_TOOLCHAIN", pinned_channel)
        .env("INJECTED_FAILING_TARGET", failing_target)
        .env(
            "STANDALONE_BUILD_GATE_ARTIFACT_ROOT",
            out_dir.join("results"),
        )
        .env("STANDALONE_BUILD_GATE_SKIP_REMOTE", "0")
        .output()
        .expect("run moved-target command failure drill");
    assert!(
        !output.status.success(),
        "the moved {failing_target} failure must block the gate"
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(single_run_dir(&out_dir.join("results")).join("manifest.json"))
            .expect("read failure manifest"),
    )
    .expect("parse failure manifest");
    let lanes = manifest["lanes"].as_array().expect("lanes");
    assert_eq!(lanes.len(), 3);
    for (name, status) in [
        ("standalone-test", "passed"),
        (
            "standalone-fleet-test",
            if failing_lane == "standalone-fleet-test" {
                "failed"
            } else {
                "passed"
            },
        ),
        (
            "standalone-buffer-test",
            if failing_lane == "standalone-buffer-test" {
                "failed"
            } else {
                "passed"
            },
        ),
    ] {
        let lane = lanes
            .iter()
            .find(|lane| lane["lane"] == name)
            .expect("lane");
        assert_eq!(lane["status"], status, "{name}");
    }
    assert_eq!(manifest["build_modes"]["standalone"]["status"], "blocked");
    assert_eq!(manifest["summary"]["standalone_gate_passed"], false);
    assert_eq!(manifest["summary"]["failed_lane_count"], 1);
    assert_eq!(manifest["summary"]["overall_status"], "blocked");
}

#[test]
fn standalone_build_gate_fails_closed_on_a_non_standalone_lane() {
    let out_dir = unique_temp_dir("standalone-build-gate-failure");
    let sibling_root = unique_temp_dir("standalone-build-gate-siblings");
    let malformed_sibling = sibling_root.join("asupersync");
    fs::create_dir_all(&malformed_sibling).expect("create malformed sibling fixture");
    fs::write(
        malformed_sibling.join("Cargo.toml"),
        "this is deliberately not a Cargo manifest\n",
    )
    .expect("write malformed sibling fixture");

    let script = repo_root().join("scripts/test_standalone_build.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("ci")
        .env("STANDALONE_BUILD_GATE_ARTIFACT_ROOT", &out_dir)
        .env("STANDALONE_BUILD_GATE_SKIP_REMOTE", "1")
        .env("STANDALONE_BUILD_GATE_SIBLING_ROOT", &sibling_root)
        .output()
        .expect("run standalone build gate failure drill");
    assert!(
        !output.status.success(),
        "a failed sibling lane must make ci mode fail closed"
    );

    let run_dir = single_run_dir(&out_dir);
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(run_dir.join("manifest.json")).expect("read failure manifest"),
    )
    .expect("failure manifest must be valid json");
    let failed_lane = manifest["lanes"]
        .as_array()
        .expect("lanes should be an array")
        .iter()
        .find(|lane| lane["lane"] == "full-integration-asupersync")
        .expect("malformed sibling lane should be recorded");
    assert_eq!(failed_lane["status"], "failed");
    assert_eq!(manifest["summary"]["failed_lane_count"], 1);
    assert_eq!(manifest["summary"]["overall_status"], "blocked");
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
    assert!(
        readme.contains("docs/cross_repo_dependency_isolation_v1.json"),
        "README should point at the machine-readable RC-6 dependency isolation contract"
    );
    assert!(
        readme.contains("docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md"),
        "README should point at the canonical RC-6 dependency isolation doc"
    );
    assert!(
        readme.contains("through `rch`"),
        "README should state that heavy build-gate cargo lanes stay on rch"
    );
}

#[test]
fn dependency_isolation_contract_documents_standalone_and_full_integration_modes() {
    let doc = read_repo_text("docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md");
    assert!(
        doc.contains("./scripts/audit_external_deps.sh"),
        "dependency isolation doc should point at the audit script"
    );
    assert!(
        doc.contains("./scripts/test_standalone_build.sh ci"),
        "dependency isolation doc should point at the build gate"
    );
    assert!(
        doc.contains("cargo check -p frankenengine-engine --no-default-features"),
        "dependency isolation doc should document the standalone check command"
    );
    assert!(
        doc.contains(
            "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl"
        ),
        "dependency isolation doc should document the standalone release command"
    );
    assert!(
        doc.contains("cargo check -p frankenengine-engine --all-features"),
        "dependency isolation doc should document the full integration command"
    );

    let contract = load_dependency_isolation_contract();
    assert_eq!(
        contract["verification_surfaces"]["standalone_build_gate"]["artifact_root"].as_str(),
        Some("artifacts/standalone_build_gate")
    );
    assert_eq!(
        contract["verification_surfaces"]["standalone_build_gate"]["operator_command"].as_str(),
        Some("./scripts/test_standalone_build.sh ci")
    );
    assert_eq!(
        contract["verification_surfaces"]["standalone_build_gate"]["strict_mode"].as_str(),
        Some("rch_only_no_local_fallback")
    );
    assert_eq!(
        contract["verification_surfaces"]["standalone_build_gate"]["manifest_schema_version"]
            .as_str(),
        Some("franken-engine.standalone-build-gate.v1")
    );
    let build_gate_artifacts =
        contract["verification_surfaces"]["standalone_build_gate"]["artifacts"]
            .as_array()
            .expect("standalone build gate artifacts should be an array");
    for artifact in [
        "<timestamp>/manifest.json",
        "<timestamp>/events.jsonl",
        "<timestamp>/commands.txt",
        "<timestamp>/step_logs/",
    ] {
        assert!(
            build_gate_artifacts
                .iter()
                .any(|entry| entry.as_str() == Some(artifact)),
            "standalone build gate contract should list artifact {artifact}"
        );
    }

    let standalone_commands = contract["build_modes"]["standalone"]["commands"]
        .as_array()
        .expect("standalone commands should be an array");
    let fleet_command = "cargo test -p frankenengine-control-plane-integration-tests --no-default-features --test fleet_quarantine_integration";
    let buffer_command = "cargo test -p frankenengine-control-plane-integration-tests --no-default-features --test buffer_value_bd_9vouw_104";
    assert!(doc.contains(fleet_command));
    assert!(doc.contains(buffer_command));
    assert!(
        standalone_commands
            .iter()
            .any(|command| command == fleet_command)
    );
    assert!(
        standalone_commands
            .iter()
            .any(|command| command == buffer_command)
    );
    let workflow = read_repo_text(".github/workflows/quality-gates.yml");
    for command in [
        "cargo check -p frankenengine-engine -p frankenengine-control-plane-integration-tests",
        "cargo clippy -p frankenengine-engine -p frankenengine-control-plane-integration-tests --all-targets -- -D warnings",
        "cargo test -p frankenengine-engine -p frankenengine-control-plane-integration-tests",
    ] {
        assert!(
            workflow.contains(command),
            "missing both-package CI command: {command}"
        );
    }
    assert!(standalone_commands.iter().any(|command| {
        command
            .as_str()
            .is_some_and(|command| command.contains("--no-default-features"))
    }));
    assert!(standalone_commands.iter().any(|command| {
        command.as_str().is_some_and(|command| {
            command
                == "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl"
        })
    }));

    let full_commands = contract["build_modes"]["full_integration"]["commands"]
        .as_array()
        .expect("full-integration commands should be an array");
    assert!(full_commands.iter().any(|command| {
        command
            .as_str()
            .is_some_and(|command| command.contains("--all-features"))
    }));

    let operator_verification = contract["operator_verification"]
        .as_array()
        .expect("operator_verification should be an array");
    for command in [
        "./scripts/test_standalone_build.sh ci",
        "cat artifacts/standalone_build_gate/<timestamp>/manifest.json",
        "cat artifacts/standalone_build_gate/<timestamp>/events.jsonl",
        "cat artifacts/standalone_build_gate/<timestamp>/commands.txt",
    ] {
        assert!(
            operator_verification
                .iter()
                .any(|entry| entry.as_str() == Some(command)),
            "operator verification should include command {command}"
        );
    }
}
