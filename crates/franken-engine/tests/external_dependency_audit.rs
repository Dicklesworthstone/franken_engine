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

fn engine_cargo_toml() -> String {
    read_repo_text("crates/franken-engine/Cargo.toml")
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
    assert_eq!(manifest["standalone_build"]["status"], "ready");
    assert_eq!(
        manifest["full_integration_dependency_health"]["status"],
        "not_verified"
    );

    let dependencies = manifest["dependencies"]
        .as_array()
        .expect("dependencies should be an array");
    assert!(
        dependencies.is_empty(),
        "versioned asupersync crates should not be reported as hard /dp path dependencies"
    );
    assert!(
        manifest["standalone_build"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no external /dp path dependencies")),
        "standalone manifest should explain that no hard /dp path dependencies were found"
    );

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(
        commands.contains("rg -n 'path = \"/dp/' -g 'Cargo.toml' ."),
        "commands.txt should record the dependency scan"
    );
}

#[test]
fn dependency_isolation_contract_documents_registry_backed_surface() {
    let doc = read_repo_text("docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md");
    for section in [
        "# Cross-Repo Dependency Isolation (`bd-6a61n.6`)",
        "## Scope",
        "## Dependency Manifest",
        "## Feature Gate and Build Modes",
        "## Verification Surfaces",
        "## Artifacts",
        "## RCH-Only Operator Commands",
    ] {
        assert!(
            doc.contains(section),
            "dependency isolation doc missing section: {section}"
        );
    }

    let contract = load_dependency_isolation_contract();
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("franken-engine.cross-repo-dependency-isolation.contract.v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("bd-6a61n.6"));

    let feature_gates = contract["feature_gates"]
        .as_array()
        .expect("feature_gates should be an array");
    for feature in [
        "asupersync-integration",
        "sibling-persistence",
        "sibling-service-api",
        "sibling-dataframes",
    ] {
        assert!(
            feature_gates
                .iter()
                .any(|gate| gate["feature"] == feature && gate["default_enabled"] == true),
            "contract should document default-enabled feature {feature}"
        );
    }

    let dependencies = contract["dependencies"]
        .as_array()
        .expect("dependencies should be an array");
    let expected_dependencies = [
        ("franken-kernel", "asupersync-integration", "0.3.4"),
        ("franken-decision", "asupersync-integration", "0.3.4"),
        ("franken-evidence", "asupersync-integration", "0.3.4"),
        ("sqlmodel", "sibling-persistence", "0.3.1"),
        ("sqlmodel-core", "sibling-persistence", "0.3.1"),
        ("sqlmodel-frankensqlite", "sibling-persistence", "0.3.1"),
        ("fastapi-core", "sibling-service-api", "0.3.1"),
        ("fp-io", "sibling-dataframes", "0.2.0"),
        ("fp-frame", "sibling-dataframes", "0.2.0"),
        ("fp-columnar", "sibling-dataframes", "0.2.0"),
        ("fp-index", "sibling-dataframes", "0.2.0"),
        ("fp-types", "sibling-dataframes", "0.2.0"),
    ];
    assert_eq!(
        dependencies.len(),
        expected_dependencies.len(),
        "contract should inventory every direct optional cross-repo dependency"
    );

    for (dependency_key, feature_gate, version) in expected_dependencies {
        let dependency = dependencies
            .iter()
            .find(|entry| entry["dependency_key"] == dependency_key)
            .unwrap_or_else(|| panic!("missing dependency {dependency_key}"));
        assert_eq!(dependency["feature_gate"].as_str(), Some(feature_gate));
        assert_eq!(dependency["source_kind"].as_str(), Some("crates.io"));
        assert_eq!(dependency["version_requirement"].as_str(), Some(version));
    }

    assert_eq!(
        contract["verification_surfaces"]["dependency_audit"]["script"].as_str(),
        Some("./scripts/audit_external_deps.sh")
    );
    assert_eq!(
        contract["verification_surfaces"]["dependency_audit"]["operator_command"].as_str(),
        Some("./scripts/audit_external_deps.sh")
    );
    assert_eq!(
        contract["verification_surfaces"]["dependency_audit"]["strict_mode"].as_str(),
        Some("rch_only_no_local_fallback")
    );
    assert_eq!(
        contract["verification_surfaces"]["dependency_audit"]["artifact_root"].as_str(),
        Some("artifacts/dependency_audit")
    );
    assert_eq!(
        contract["verification_surfaces"]["dependency_audit"]["manifest_schema_version"].as_str(),
        Some("franken-engine.external-dependency-audit.v1")
    );
    let audit_artifacts = contract["verification_surfaces"]["dependency_audit"]["artifacts"]
        .as_array()
        .expect("dependency audit artifacts should be an array");
    for artifact in ["manifest.json", "commands.txt", "logs/"] {
        assert!(
            audit_artifacts
                .iter()
                .any(|entry| entry.as_str() == Some(artifact)),
            "dependency audit contract should list artifact {artifact}"
        );
    }
    assert_eq!(
        contract["verification_surfaces"]["standalone_build_gate"]["script"].as_str(),
        Some("./scripts/test_standalone_build.sh")
    );
    assert_eq!(
        contract["verification_surfaces"]["standalone_build_gate"]["strict_mode"].as_str(),
        Some("rch_only_no_local_fallback")
    );
    let operator_verification = contract["operator_verification"]
        .as_array()
        .expect("operator_verification should be an array");
    for command in [
        "./scripts/audit_external_deps.sh",
        "./scripts/test_standalone_build.sh ci",
        "cat artifacts/dependency_audit/manifest.json",
        "cat artifacts/dependency_audit/commands.txt",
    ] {
        assert!(
            operator_verification
                .iter()
                .any(|entry| entry.as_str() == Some(command)),
            "operator verification should include command {command}"
        );
    }
}

#[test]
fn dependency_isolation_contract_matches_workspace_feature_gates() {
    let cargo_toml = engine_cargo_toml();
    let manifest: toml::Value =
        toml::from_str(&cargo_toml).expect("engine Cargo.toml should parse");
    let manifest_features = manifest["features"]
        .as_table()
        .expect("manifest features should be a table");
    let default_features = manifest_features["default"]
        .as_array()
        .expect("default features should be an array");
    let manifest_dependencies = manifest["dependencies"]
        .as_table()
        .expect("manifest dependencies should be a table");
    let contract = load_dependency_isolation_contract();
    let feature_gates = contract["feature_gates"]
        .as_array()
        .expect("feature_gates should be an array");
    let expected_gates: &[(&str, &[(&str, &str)])] = &[
        (
            "asupersync-integration",
            &[
                ("franken-kernel", "0.3.4"),
                ("franken-decision", "0.3.4"),
                ("franken-evidence", "0.3.4"),
            ],
        ),
        (
            "sibling-persistence",
            &[
                ("sqlmodel", "0.3.1"),
                ("sqlmodel-core", "0.3.1"),
                ("sqlmodel-frankensqlite", "0.3.1"),
            ],
        ),
        ("sibling-service-api", &[("fastapi-core", "0.3.1")]),
        (
            "sibling-dataframes",
            &[
                ("fp-io", "0.2.0"),
                ("fp-frame", "0.2.0"),
                ("fp-columnar", "0.2.0"),
                ("fp-index", "0.2.0"),
                ("fp-types", "0.2.0"),
            ],
        ),
    ];

    for &(feature, dependencies) in expected_gates {
        assert!(
            default_features
                .iter()
                .any(|value| value.as_str() == Some(feature)),
            "engine Cargo.toml should default-enable feature {feature}"
        );
        let manifest_feature_dependencies = manifest_features[feature]
            .as_array()
            .unwrap_or_else(|| panic!("manifest feature {feature} should be an array"));
        let feature_gate = feature_gates
            .iter()
            .find(|gate| gate["feature"] == feature)
            .unwrap_or_else(|| panic!("contract should declare feature gate {feature}"));
        let enabled_dependencies = feature_gate["enables_dependencies"]
            .as_array()
            .expect("enables_dependencies should be an array");

        for &(dependency_key, version) in dependencies {
            let feature_dependency = format!("dep:{dependency_key}");
            assert!(
                manifest_feature_dependencies
                    .iter()
                    .any(|value| value.as_str() == Some(feature_dependency.as_str())),
                "engine Cargo.toml should route {dependency_key} through {feature}"
            );
            let manifest_dependency = manifest_dependencies
                .get(dependency_key)
                .and_then(toml::Value::as_table)
                .unwrap_or_else(|| panic!("missing manifest dependency {dependency_key}"));
            assert_eq!(
                manifest_dependency
                    .get("version")
                    .and_then(toml::Value::as_str),
                Some(version),
                "registry version for {dependency_key}"
            );
            assert_eq!(
                manifest_dependency
                    .get("optional")
                    .and_then(toml::Value::as_bool),
                Some(true),
                "optional flag for {dependency_key}"
            );
            assert!(
                !manifest_dependency.contains_key("path"),
                "{dependency_key} must not regain a path source"
            );
            assert!(
                enabled_dependencies
                    .iter()
                    .any(|value| value.as_str() == Some(dependency_key)),
                "contract should list {dependency_key} in feature gate {feature}"
            );
        }
    }
}
