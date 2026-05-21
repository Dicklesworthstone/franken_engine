#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

const SCENARIO_DIR: &str = "tests/red_team_scenarios";
const SCHEMA_VERSION: &str = "franken-engine.red-team-scenario.v1";
const BASELINE_VERSION: &str = "node-bun-frankenengine-red-team-v1";
const EXPECTED_SCENARIOS: &[&str] = &[
    "ambient_authority_via_globalthis",
    "capability_shadowed_import",
    "computed_member_capability_evasion",
    "declassification_without_receipt",
    "dynamic_import_capability_evasion",
    "environment_variable_exfiltration",
    "eval_capability_evasion",
    "function_constructor_evasion",
    "process_privilege_surface_probe",
    "prototype_pollution_capability_escape",
    "proxy_trap_authority_smuggling",
    "reflect_apply_authority_smuggling",
    "shell_command_injection_package_script",
    "supply_chain_backdoor_execution",
    "typed_effect_laundering_downcast",
    "with_block_scope_smuggling",
];

fn scenario_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SCENARIO_DIR)
}

fn read_manifest(path: &Path) -> Value {
    let content = std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("manifest should be readable at {}: {error}", path.display())
    });
    serde_json::from_str(&content)
        .unwrap_or_else(|error| panic!("manifest should parse at {}: {error}", path.display()))
}

fn required_string<'a>(manifest: &'a Value, field: &str) -> &'a str {
    manifest
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("manifest field {field} must be a non-empty string"))
}

fn nested_string<'a>(manifest: &'a Value, path: &[&str]) -> &'a str {
    let mut value = manifest;
    for key in path {
        value = value
            .get(*key)
            .unwrap_or_else(|| panic!("manifest missing nested field {}", path.join(".")));
    }
    value
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            panic!(
                "manifest field {} must be a non-empty string",
                path.join(".")
            )
        })
}

#[test]
fn red_team_scenario_manifests_have_required_shape() {
    let dir = scenario_dir();
    let mut observed_names = BTreeSet::new();
    let mut attack_vectors = BTreeSet::new();

    for expected_name in EXPECTED_SCENARIOS {
        let manifest_path = dir.join(format!("{expected_name}.manifest.json"));
        let program_path = dir.join(format!("{expected_name}.js"));
        assert!(
            manifest_path.is_file(),
            "missing manifest {}",
            manifest_path.display()
        );
        assert!(
            program_path.is_file(),
            "missing JS {}",
            program_path.display()
        );

        let manifest = read_manifest(&manifest_path);
        assert_eq!(required_string(&manifest, "schema_version"), SCHEMA_VERSION);
        assert_eq!(
            required_string(&manifest, "baseline_version"),
            BASELINE_VERSION
        );
        assert_eq!(required_string(&manifest, "name"), *expected_name);
        assert_eq!(
            nested_string(&manifest, &["payload", "program"]),
            format!("{expected_name}.js")
        );
        assert!(!nested_string(&manifest, &["payload", "success_criteria"]).is_empty());

        assert_eq!(
            nested_string(&manifest, &["expected_outcome", "node", "outcome"]),
            "succeeds"
        );
        assert_eq!(
            nested_string(&manifest, &["expected_outcome", "bun", "outcome"]),
            "succeeds"
        );
        assert_eq!(
            nested_string(&manifest, &["expected_outcome", "frankenengine", "outcome"]),
            "fail_closed"
        );
        assert!(!nested_string(&manifest, &["expected_outcome", "node", "observable"]).is_empty());
        assert!(!nested_string(&manifest, &["expected_outcome", "bun", "observable"]).is_empty());
        assert!(
            !nested_string(
                &manifest,
                &["expected_outcome", "frankenengine", "denial_reason"]
            )
            .is_empty()
        );
        assert!(!nested_string(&manifest, &["measurement", "success_signal"]).is_empty());
        assert!(!nested_string(&manifest, &["measurement", "failure_signal"]).is_empty());

        observed_names.insert(required_string(&manifest, "name").to_string());
        assert!(
            attack_vectors.insert(required_string(&manifest, "attack_vector").to_string()),
            "attack_vector should be unique per curated scenario"
        );
    }

    let expected_names = EXPECTED_SCENARIOS
        .iter()
        .map(|name| (*name).to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(observed_names, expected_names);
}
