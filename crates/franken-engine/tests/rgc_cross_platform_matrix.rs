#![forbid(unsafe_code)]
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

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

const MATRIX_SCHEMA_VERSION: &str = "franken-engine.rgc-cross-platform-matrix.v1";
const MATRIX_JSON: &str = include_str!("../../../docs/rgc_cross_platform_matrix_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CrossPlatformMatrixContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    targets: Vec<TargetSpec>,
    drift_classes: Vec<DriftClass>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TargetSpec {
    target_id: String,
    os: String,
    arch: String,
    tier: String,
    required: bool,
    path_style: String,
    line_endings: String,
    manifest_env_var: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DriftClass {
    class_id: String,
    severity: String,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetRunSummary {
    outcome: String,
    error_code: Option<String>,
    witness_digest: String,
    toolchain_fingerprint: String,
    normalized_runtime_digest: String,
    normalized_cli_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DriftExplanation {
    class_id: String,
    severity: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> CrossPlatformMatrixContract {
    serde_json::from_str(MATRIX_JSON).expect("RGC cross-platform matrix contract must parse")
}

fn load_doc() -> String {
    let path = repo_root().join("docs/RGC_CROSS_PLATFORM_MATRIX_V1.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn normalize_platform_path(path: &str) -> String {
    let mut normalized = path.replace('\\', "/");
    if normalized.len() >= 2 && normalized.as_bytes()[1] == b':' {
        let drive = normalized[..1].to_ascii_lowercase();
        normalized = format!("{drive}{}", &normalized[1..]);
    }

    let mut collapsed = String::with_capacity(normalized.len());
    let mut prev_slash = false;
    for ch in normalized.chars() {
        if ch == '/' {
            if !prev_slash {
                collapsed.push(ch);
            }
            prev_slash = true;
        } else {
            collapsed.push(ch);
            prev_slash = false;
        }
    }
    collapsed
}

fn normalize_line_endings(input: &str) -> String {
    input.replace("\r\n", "\n").replace('\r', "\n")
}

fn classify_drift(baseline: &TargetRunSummary, target: &TargetRunSummary) -> DriftExplanation {
    if target.witness_digest == "missing-input" {
        return DriftExplanation {
            class_id: "missing_target_input".to_string(),
            severity: "critical".to_string(),
        };
    }

    if baseline.outcome != target.outcome || baseline.error_code != target.error_code {
        return DriftExplanation {
            class_id: "workflow_behavior_drift".to_string(),
            severity: "critical".to_string(),
        };
    }

    if baseline.witness_digest == target.witness_digest {
        return DriftExplanation {
            class_id: "none".to_string(),
            severity: "info".to_string(),
        };
    }

    if baseline.normalized_runtime_digest == target.normalized_runtime_digest
        && baseline.normalized_cli_digest == target.normalized_cli_digest
    {
        return DriftExplanation {
            class_id: "artifact_only_drift".to_string(),
            severity: "warning".to_string(),
        };
    }

    if baseline.toolchain_fingerprint != target.toolchain_fingerprint {
        return DriftExplanation {
            class_id: "toolchain_fingerprint_delta".to_string(),
            severity: "warning".to_string(),
        };
    }

    DriftExplanation {
        class_id: "unexplained_digest_drift".to_string(),
        severity: "critical".to_string(),
    }
}

#[test]
fn rgc_063_doc_contains_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "# RGC Cross-Platform Matrix Contract V1",
        "## Scope",
        "## Contract Version",
        "## Matrix Dimensions",
        "## Drift Classification",
        "## Structured Logging Contract",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(doc.contains(section), "missing required section: {section}");
    }
}

#[test]
fn rgc_063_contract_is_versioned_and_target_complete() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, MATRIX_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.13");
    assert_eq!(contract.policy_id, "policy-rgc-cross-platform-matrix-v1");

    let target_ids: BTreeSet<_> = contract
        .targets
        .iter()
        .map(|t| t.target_id.as_str())
        .collect();
    let expected_target_ids: BTreeSet<_> = [
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
        "windows-arm64",
    ]
    .into_iter()
    .collect();
    assert_eq!(target_ids, expected_target_ids);

    let oses: BTreeSet<_> = contract.targets.iter().map(|t| t.os.as_str()).collect();
    assert_eq!(oses, BTreeSet::from(["linux", "macos", "windows"]));
    let arches: BTreeSet<_> = contract.targets.iter().map(|t| t.arch.as_str()).collect();
    assert_eq!(arches, BTreeSet::from(["arm64", "x64"]));

    let required_targets: BTreeSet<_> = contract
        .targets
        .iter()
        .filter(|target| target.required)
        .map(|target| target.target_id.as_str())
        .collect();
    assert!(required_targets.contains("linux-x64"));
    assert!(required_targets.contains("linux-arm64"));
    assert!(required_targets.contains("macos-arm64"));
    assert!(required_targets.contains("windows-x64"));
}

#[test]
fn rgc_063_contract_declares_required_logs_artifacts_and_drift_classes() {
    let contract = parse_contract();

    let required_logs: BTreeSet<_> = contract
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "target_id",
        "outcome",
        "error_code",
    ] {
        assert!(
            required_logs.contains(field),
            "missing required log key {field}"
        );
    }

    let required_artifacts: BTreeSet<_> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "matrix_target_deltas.jsonl",
        "matrix_summary.json",
    ] {
        assert!(
            required_artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    let drift_classes: BTreeSet<_> = contract
        .drift_classes
        .iter()
        .map(|entry| (entry.class_id.as_str(), entry.severity.as_str()))
        .collect();
    for entry in [
        ("none", "info"),
        ("artifact_only_drift", "warning"),
        ("toolchain_fingerprint_delta", "warning"),
        ("workflow_behavior_drift", "critical"),
        ("unexplained_digest_drift", "critical"),
        ("missing_target_input", "critical"),
        ("missing_baseline_input", "critical"),
    ] {
        assert!(
            drift_classes.contains(&entry),
            "missing drift class {:?}",
            entry
        );
    }
}

#[test]
fn rgc_063_targets_reference_expected_env_vars_and_replay_script() {
    let contract = parse_contract();
    for target in &contract.targets {
        assert!(
            target.manifest_env_var.starts_with("RGC_CROSS_PLATFORM_"),
            "unexpected manifest env var for {}",
            target.target_id
        );
        assert!(
            target
                .replay_command
                .starts_with("./scripts/e2e/rgc_cross_platform_matrix_replay.sh"),
            "unexpected replay command for {}",
            target.target_id
        );
        assert!(
            ["ga", "candidate"].contains(&target.tier.as_str()),
            "unexpected tier {} for {}",
            target.tier,
            target.target_id
        );
        assert!(
            ["posix", "windows"].contains(&target.path_style.as_str()),
            "unexpected path_style {} for {}",
            target.path_style,
            target.target_id
        );
        assert!(
            ["lf", "crlf"].contains(&target.line_endings.as_str()),
            "unexpected line_endings {} for {}",
            target.line_endings,
            target.target_id
        );
    }
}

#[test]
fn rgc_063_normalization_helpers_are_deterministic() {
    assert_eq!(
        normalize_platform_path(r"C:\\franken\\.\artifacts\\run_manifest.json"),
        "c:/franken/./artifacts/run_manifest.json"
    );
    assert_eq!(
        normalize_platform_path("/tmp//franken///events.jsonl"),
        "/tmp/franken/events.jsonl"
    );

    assert_eq!(
        normalize_line_endings("line1\r\nline2\rline3\nline4"),
        "line1\nline2\nline3\nline4"
    );
}

#[test]
fn rgc_063_drift_classifier_assigns_expected_classes() {
    let baseline = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:stable".to_string(),
        toolchain_fingerprint: "fp-linux".to_string(),
        normalized_runtime_digest: "sha256:runtime-stable".to_string(),
        normalized_cli_digest: "sha256:cli-stable".to_string(),
    };

    let parity = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:stable".to_string(),
        toolchain_fingerprint: "fp-linux".to_string(),
        normalized_runtime_digest: "sha256:runtime-stable".to_string(),
        normalized_cli_digest: "sha256:cli-stable".to_string(),
    };
    let parity_class = classify_drift(&baseline, &parity);
    assert_eq!(parity_class.class_id, "none");
    assert_eq!(parity_class.severity, "info");

    let artifact_only = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:windows-crlf".to_string(),
        toolchain_fingerprint: "fp-linux".to_string(),
        normalized_runtime_digest: "sha256:runtime-stable".to_string(),
        normalized_cli_digest: "sha256:cli-stable".to_string(),
    };
    let artifact_class = classify_drift(&baseline, &artifact_only);
    assert_eq!(artifact_class.class_id, "artifact_only_drift");
    assert_eq!(artifact_class.severity, "warning");

    let toolchain_delta = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:macos-build".to_string(),
        toolchain_fingerprint: "fp-macos".to_string(),
        normalized_runtime_digest: "sha256:runtime-macos".to_string(),
        normalized_cli_digest: "sha256:cli-macos".to_string(),
    };
    let toolchain_class = classify_drift(&baseline, &toolchain_delta);
    assert_eq!(toolchain_class.class_id, "toolchain_fingerprint_delta");
    assert_eq!(toolchain_class.severity, "warning");

    let behavior_drift = TargetRunSummary {
        outcome: "fail".to_string(),
        error_code: Some("FE-RUNTIME-0001".to_string()),
        witness_digest: "sha256:runtime-fail".to_string(),
        toolchain_fingerprint: "fp-linux".to_string(),
        normalized_runtime_digest: "sha256:runtime-fail".to_string(),
        normalized_cli_digest: "sha256:cli-stable".to_string(),
    };
    let behavior_class = classify_drift(&baseline, &behavior_drift);
    assert_eq!(behavior_class.class_id, "workflow_behavior_drift");
    assert_eq!(behavior_class.severity, "critical");

    let missing_target = TargetRunSummary {
        outcome: "unknown".to_string(),
        error_code: Some("missing_input".to_string()),
        witness_digest: "missing-input".to_string(),
        toolchain_fingerprint: "unknown".to_string(),
        normalized_runtime_digest: "unknown".to_string(),
        normalized_cli_digest: "unknown".to_string(),
    };
    let missing_class = classify_drift(&baseline, &missing_target);
    assert_eq!(missing_class.class_id, "missing_target_input");
    assert_eq!(missing_class.severity, "critical");

    let unexplained = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:drift-unknown".to_string(),
        toolchain_fingerprint: "fp-linux".to_string(),
        normalized_runtime_digest: "sha256:runtime-other".to_string(),
        normalized_cli_digest: "sha256:cli-other".to_string(),
    };
    let unexplained_class = classify_drift(&baseline, &unexplained);
    assert_eq!(unexplained_class.class_id, "unexplained_digest_drift");
    assert_eq!(unexplained_class.severity, "critical");
}

#[test]
fn rgc_063_gate_runner_and_operator_commands_are_wired() {
    let contract = parse_contract();
    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_cross_platform_matrix_gate.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_cross_platform_matrix_replay.sh"
    );
    assert!(
        contract
            .gate_runner
            .strict_mode
            .contains("RGC_CROSS_PLATFORM_REQUIRE_MATRIX")
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-cross-platform-matrix.run-manifest.v1"
    );

    let repo = repo_root();
    assert!(repo.join(&contract.gate_runner.script).exists());
    assert!(repo.join(&contract.gate_runner.replay_wrapper).exists());

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("run_rgc_cross_platform_matrix_gate.sh ci"))
    );
}

#[test]
fn rgc_063_normalize_platform_path_identity_for_unix() {
    assert_eq!(
        normalize_platform_path("/tmp/franken/events.jsonl"),
        "/tmp/franken/events.jsonl"
    );
}

#[test]
fn rgc_063_normalize_line_endings_identity_for_lf() {
    assert_eq!(normalize_line_endings("line1\nline2\n"), "line1\nline2\n");
}

#[test]
fn rgc_063_drift_classifier_deterministic() {
    let baseline = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:a".to_string(),
        toolchain_fingerprint: "fp-a".to_string(),
        normalized_runtime_digest: "sha256:r".to_string(),
        normalized_cli_digest: "sha256:c".to_string(),
    };
    let a = classify_drift(&baseline, &baseline);
    let b = classify_drift(&baseline, &baseline);
    assert_eq!(a, b);
    assert_eq!(a.class_id, "none");
}

#[test]
fn rgc_063_target_ids_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for target in &contract.targets {
        assert!(
            seen.insert(&target.target_id),
            "duplicate target_id: {}",
            target.target_id
        );
    }
}

#[test]
fn rgc_063_drift_class_ids_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for dc in &contract.drift_classes {
        assert!(
            seen.insert(&dc.class_id),
            "duplicate drift class_id: {}",
            dc.class_id
        );
    }
}

#[test]
fn rgc_063_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

#[test]
fn rgc_063_doc_file_is_nonempty() {
    let doc = load_doc();
    assert!(!doc.is_empty());
}

// ---------- normalize_platform_path edge cases ----------

#[test]
fn rgc_063_normalize_platform_path_empty_input() {
    assert_eq!(normalize_platform_path(""), "");
}

#[test]
fn rgc_063_normalize_platform_path_only_slashes() {
    assert_eq!(normalize_platform_path("///"), "/");
}

// ---------- normalize_line_endings edge cases ----------

#[test]
fn rgc_063_normalize_line_endings_empty() {
    assert_eq!(normalize_line_endings(""), "");
}

#[test]
fn rgc_063_normalize_line_endings_standalone_cr() {
    assert_eq!(normalize_line_endings("a\rb\rc"), "a\nb\nc");
}

// ---------- all drift classes have non-empty description ----------

#[test]
fn rgc_063_all_drift_classes_have_nonempty_description() {
    let contract = parse_contract();
    for dc in &contract.drift_classes {
        assert!(
            !dc.description.trim().is_empty(),
            "drift class {} has empty description",
            dc.class_id
        );
    }
}

#[test]
fn rgc_063_contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn rgc_063_contract_has_nonempty_policy_id() {
    let contract = parse_contract();
    assert!(!contract.policy_id.trim().is_empty());
}

#[test]
fn rgc_063_gate_runner_has_nonempty_script() {
    let contract = parse_contract();
    assert!(!contract.gate_runner.script.trim().is_empty());
    assert!(!contract.gate_runner.replay_wrapper.trim().is_empty());
}

// ---------- additional enrichment tests ----------

#[test]
fn rgc_063_schema_version_follows_dotted_format() {
    let contract = parse_contract();
    // Schema version must contain dots separating namespace segments
    let parts: Vec<&str> = contract.schema_version.split('.').collect();
    assert!(
        parts.len() >= 3,
        "schema_version should have at least 3 dot-separated segments, got: {}",
        contract.schema_version
    );
    for part in &parts {
        assert!(
            !part.trim().is_empty(),
            "schema_version segment must not be empty"
        );
    }
}

#[test]
fn rgc_063_contract_version_is_semver() {
    let contract = parse_contract();
    let parts: Vec<&str> = contract.contract_version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "contract_version must be semver (major.minor.patch)"
    );
    for part in &parts {
        assert!(
            part.parse::<u32>().is_ok(),
            "contract_version segment '{}' must be a non-negative integer",
            part
        );
    }
}

#[test]
fn rgc_063_all_target_fields_are_nonempty() {
    let contract = parse_contract();
    for target in &contract.targets {
        assert!(!target.target_id.trim().is_empty(), "target_id empty");
        assert!(
            !target.os.trim().is_empty(),
            "os empty for {}",
            target.target_id
        );
        assert!(
            !target.arch.trim().is_empty(),
            "arch empty for {}",
            target.target_id
        );
        assert!(
            !target.tier.trim().is_empty(),
            "tier empty for {}",
            target.target_id
        );
        assert!(
            !target.path_style.trim().is_empty(),
            "path_style empty for {}",
            target.target_id
        );
        assert!(
            !target.line_endings.trim().is_empty(),
            "line_endings empty for {}",
            target.target_id
        );
        assert!(
            !target.manifest_env_var.trim().is_empty(),
            "manifest_env_var empty for {}",
            target.target_id
        );
        assert!(
            !target.replay_command.trim().is_empty(),
            "replay_command empty for {}",
            target.target_id
        );
    }
}

#[test]
fn rgc_063_windows_targets_use_crlf_and_windows_path_style() {
    let contract = parse_contract();
    for target in contract.targets.iter().filter(|t| t.os == "windows") {
        assert_eq!(
            target.line_endings, "crlf",
            "windows target {} should use crlf line endings",
            target.target_id
        );
        assert_eq!(
            target.path_style, "windows",
            "windows target {} should use windows path_style",
            target.target_id
        );
    }
}

#[test]
fn rgc_063_posix_targets_use_lf_and_posix_path_style() {
    let contract = parse_contract();
    for target in contract
        .targets
        .iter()
        .filter(|t| t.os == "linux" || t.os == "macos")
    {
        assert_eq!(
            target.line_endings, "lf",
            "posix target {} should use lf line endings",
            target.target_id
        );
        assert_eq!(
            target.path_style, "posix",
            "posix target {} should use posix path_style",
            target.target_id
        );
    }
}

#[test]
fn rgc_063_drift_severity_values_are_in_allowed_set() {
    let contract = parse_contract();
    let allowed: BTreeSet<&str> = ["info", "warning", "critical"].into_iter().collect();
    for dc in &contract.drift_classes {
        assert!(
            allowed.contains(dc.severity.as_str()),
            "drift class {} has invalid severity '{}', allowed: {:?}",
            dc.class_id,
            dc.severity,
            allowed
        );
    }
}

#[test]
fn rgc_063_required_log_keys_contain_no_duplicates() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for key in &contract.required_log_keys {
        assert!(seen.insert(key), "duplicate required_log_key: {}", key);
    }
}

#[test]
fn rgc_063_required_artifacts_contain_no_duplicates() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for artifact in &contract.required_artifacts {
        assert!(
            seen.insert(artifact),
            "duplicate required_artifact: {}",
            artifact
        );
    }
}

#[test]
fn rgc_063_operator_verification_commands_are_nonempty_strings() {
    let contract = parse_contract();
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must not be empty"
    );
    for cmd in &contract.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator verification command must not be empty"
        );
    }
}

#[test]
fn rgc_063_normalize_platform_path_windows_drive_letter_lowercased() {
    // Uppercase drive letters should be lowercased
    assert_eq!(
        normalize_platform_path("D:\\projects\\franken"),
        "d:/projects/franken"
    );
    // Already lowercase drive letter stays the same
    assert_eq!(
        normalize_platform_path("d:\\projects\\franken"),
        "d:/projects/franken"
    );
}

// ---------- enrichment batch: clone/debug, serde round-trips, edge cases ----------

#[test]
fn rgc_063_cross_platform_matrix_contract_clone_equals_original() {
    let contract = parse_contract();
    let cloned = contract.clone();
    assert_eq!(contract, cloned);
}

#[test]
fn rgc_063_cross_platform_matrix_contract_debug_is_nonempty() {
    let contract = parse_contract();
    let debug_str = format!("{:?}", contract);
    assert!(!debug_str.is_empty());
    assert!(debug_str.contains("CrossPlatformMatrixContract"));
}

#[test]
fn rgc_063_target_spec_clone_preserves_all_fields() {
    let contract = parse_contract();
    for target in &contract.targets {
        let cloned = target.clone();
        assert_eq!(target.target_id, cloned.target_id);
        assert_eq!(target.os, cloned.os);
        assert_eq!(target.arch, cloned.arch);
        assert_eq!(target.tier, cloned.tier);
        assert_eq!(target.required, cloned.required);
        assert_eq!(target.path_style, cloned.path_style);
        assert_eq!(target.line_endings, cloned.line_endings);
        assert_eq!(target.manifest_env_var, cloned.manifest_env_var);
        assert_eq!(target.replay_command, cloned.replay_command);
    }
}

#[test]
fn rgc_063_drift_class_debug_contains_class_id() {
    let contract = parse_contract();
    for dc in &contract.drift_classes {
        let debug_str = format!("{:?}", dc);
        assert!(
            debug_str.contains(&dc.class_id),
            "Debug output for DriftClass should contain class_id"
        );
    }
}

#[test]
fn rgc_063_gate_runner_clone_equals_original() {
    let contract = parse_contract();
    let cloned = contract.gate_runner.clone();
    assert_eq!(contract.gate_runner, cloned);
}

#[test]
fn rgc_063_target_run_summary_debug_contains_outcome() {
    let summary = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:abc".to_string(),
        toolchain_fingerprint: "fp-test".to_string(),
        normalized_runtime_digest: "sha256:rt".to_string(),
        normalized_cli_digest: "sha256:cli".to_string(),
    };
    let debug_str = format!("{:?}", summary);
    assert!(debug_str.contains("pass"));
    assert!(debug_str.contains("TargetRunSummary"));
}

#[test]
fn rgc_063_drift_explanation_clone_and_eq() {
    let explanation = DriftExplanation {
        class_id: "artifact_only_drift".to_string(),
        severity: "warning".to_string(),
    };
    let cloned = explanation.clone();
    assert_eq!(explanation, cloned);
    assert_eq!(explanation.class_id, "artifact_only_drift");
    assert_eq!(explanation.severity, "warning");
}

#[test]
fn rgc_063_normalize_platform_path_preserves_relative_paths() {
    assert_eq!(
        normalize_platform_path("relative/path/to/file.json"),
        "relative/path/to/file.json"
    );
    assert_eq!(
        normalize_platform_path("relative\\path\\to\\file.json"),
        "relative/path/to/file.json"
    );
}

#[test]
fn rgc_063_normalize_platform_path_single_char_non_drive() {
    // Single char that is NOT followed by colon should not be treated as drive letter
    assert_eq!(normalize_platform_path("a/b/c"), "a/b/c");
}

#[test]
fn rgc_063_normalize_line_endings_mixed_crlf_and_cr() {
    // Mix of \r\n and standalone \r in one string
    let input = "first\r\nsecond\rthird\r\nfourth";
    let result = normalize_line_endings(input);
    assert_eq!(result, "first\nsecond\nthird\nfourth");
    // Ensure no \r remains
    assert!(!result.contains('\r'));
}

#[test]
fn rgc_063_normalize_line_endings_only_crlf() {
    assert_eq!(normalize_line_endings("\r\n\r\n\r\n"), "\n\n\n");
}

#[test]
fn rgc_063_drift_classifier_missing_input_takes_priority_over_outcome_drift() {
    // Even if outcomes differ, missing-input witness should classify as missing_target_input
    let baseline = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:baseline".to_string(),
        toolchain_fingerprint: "fp-base".to_string(),
        normalized_runtime_digest: "sha256:rt".to_string(),
        normalized_cli_digest: "sha256:cli".to_string(),
    };
    let target = TargetRunSummary {
        outcome: "fail".to_string(),
        error_code: Some("ERR-999".to_string()),
        witness_digest: "missing-input".to_string(),
        toolchain_fingerprint: "fp-different".to_string(),
        normalized_runtime_digest: "sha256:rt-other".to_string(),
        normalized_cli_digest: "sha256:cli-other".to_string(),
    };
    let result = classify_drift(&baseline, &target);
    assert_eq!(result.class_id, "missing_target_input");
    assert_eq!(result.severity, "critical");
}

#[test]
fn rgc_063_drift_classifier_error_code_mismatch_is_behavior_drift() {
    let baseline = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:base".to_string(),
        toolchain_fingerprint: "fp".to_string(),
        normalized_runtime_digest: "sha256:rt".to_string(),
        normalized_cli_digest: "sha256:cli".to_string(),
    };
    let target = TargetRunSummary {
        outcome: "pass".to_string(),
        error_code: Some("FE-0042".to_string()),
        witness_digest: "sha256:other".to_string(),
        toolchain_fingerprint: "fp".to_string(),
        normalized_runtime_digest: "sha256:rt".to_string(),
        normalized_cli_digest: "sha256:cli".to_string(),
    };
    let result = classify_drift(&baseline, &target);
    assert_eq!(result.class_id, "workflow_behavior_drift");
    assert_eq!(result.severity, "critical");
}

#[test]
fn rgc_063_target_id_format_is_os_dash_arch() {
    let contract = parse_contract();
    for target in &contract.targets {
        let expected_id = format!("{}-{}", target.os, target.arch);
        assert_eq!(
            target.target_id, expected_id,
            "target_id '{}' does not match expected os-arch format '{}'",
            target.target_id, expected_id
        );
    }
}

#[test]
fn rgc_063_manifest_env_vars_are_unique_across_targets() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for target in &contract.targets {
        assert!(
            seen.insert(&target.manifest_env_var),
            "duplicate manifest_env_var: {}",
            target.manifest_env_var
        );
    }
}

#[test]
fn rgc_063_contract_deserialization_rejects_missing_required_field() {
    // Remove a required field and verify deserialization fails
    let bad_json = r#"{"schema_version":"v1","contract_version":"1.0.0","bead_id":"bd-test","policy_id":"pol-test","required_log_keys":[],"required_artifacts":[],"targets":[],"drift_classes":[],"operator_verification":[]}"#;
    // This should fail because gate_runner is missing
    let result: Result<CrossPlatformMatrixContract, _> = serde_json::from_str(bad_json);
    assert!(
        result.is_err(),
        "deserialization should fail when gate_runner field is missing"
    );
}

#[test]
fn rgc_063_at_least_one_critical_drift_class_exists() {
    let contract = parse_contract();
    let critical_count = contract
        .drift_classes
        .iter()
        .filter(|dc| dc.severity == "critical")
        .count();
    assert!(
        critical_count >= 1,
        "contract must have at least one critical drift class"
    );
}

#[test]
fn rgc_063_normalize_platform_path_trailing_slash_preserved() {
    assert_eq!(normalize_platform_path("/tmp/franken/"), "/tmp/franken/");
    assert_eq!(normalize_platform_path("C:\\franken\\"), "c:/franken/");
}
