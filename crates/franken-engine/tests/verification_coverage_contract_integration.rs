#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use chrono::{DateTime, Duration, Utc};
use frankenengine_engine::verification_coverage_contract::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactDigest, ArtifactManifest, BRIDGE_ROOT, CONTRACT_PATH,
    ERROR_ARTIFACT_CONTRACT, ERROR_BOUNDS, ERROR_BRANCH_PROOF, ERROR_CLOCK_AUTHORITY,
    ERROR_EVENT_SCHEMA, ERROR_GENERATION_DRIFT, ERROR_HASH_DRIFT, ERROR_HISTORICAL_PROOF, ERROR_IO,
    ERROR_ORDER_OR_DUPLICATE, ERROR_OUTCOME_MISMATCH, ERROR_OWNER, ERROR_PROVENANCE,
    ERROR_REPRODUCTION, ERROR_RETRY_MASKING, ERROR_SCHEMA, ERROR_SECRET_LEAK,
    ERROR_SILENT_FALLBACK, ERROR_SUBJECT_DRIFT, ERROR_TIER_R_TRUTH, ERROR_UNSAFE_PATH,
    EVENT_SCHEMA_VERSION, EnvironmentManifest, EvidenceState, FailureReference,
    HarnessExecutionClass, MinimizedSeed, OWNING_BEAD, ProvenanceEdge, ProvenanceGraph,
    ProvenanceNode, REPORT_SCHEMA_VERSION, RUN_MANIFEST_SCHEMA_VERSION, ReproLock,
    ReproductionRecord, ResourceDelta, RunManifest, RunOutcome, SampleArtifact, SampleArtifactKind,
    SubjectKind, TIER_R_BRANCH_SIGNALS, TIER_R_IMPLEMENTATION_TRUTH, TIER_R_PROBE_CASES,
    TIER_R_PROBE_SCHEMA_VERSION, TierRBuildEnvironment, TierRDenialProbe, TierRInvocationRecord,
    TierRProbeReport, TierRProbeScenario, TierRSourceFile, TierRSourceManifest, TierRStageEvent,
    ValidationContext, ValidationFinding, ValidationOutput, VerificationCoverageContract,
    VerificationEvent, VerificationSample, canonical_json_bytes, generate_contract,
    minimized_seed_identity, render_markdown, tier_r_expected_semantic_digest, validate_bundle,
    validate_contract_file, validate_event_stream, validate_tier_r_build_environment,
    validate_tier_r_probe, write_artifact_manifest, write_bytes_no_replace, write_events_jsonl,
};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, NamedTempFile, TempDir, tempdir};

const CONTRACT_RELATIVE_PATH: &str = "docs/verification_coverage_contract_v1.json";
const MARKDOWN_RELATIVE_PATH: &str = "docs/VERIFICATION_COVERAGE_CONTRACT_V1.md";
const RUN_ID: &str = "run-vcc-integration";
const TRACE_ID: &str = "trace-vcc-integration";
const TEST_ID: &str = "verification-coverage-contract-integration";
const SCENARIO_ID: &str = "hermetic-complete-bundle";
const SEED: u64 = 0x5eed_cafe;
const PLATFORM: &str = "linux-fixture";
const TARGET: &str = "x86_64-unknown-linux-gnu";
const TIER: &str = "verification-control-plane";
const PROFILE: &str = "evidence-on";
const REPRODUCTION_COMMAND: &str = "./scripts/reproduce-vcc --locked";
const TIER_R_COMMAND: &str = "./tier_r_probe_executable tier_r_probe.json";
const SOURCE_IDENTITY_COMMAND: &str = "./scripts/source-identity";
const SECRET_PROBE: &str = "token=fe_vcc_test_7f4c9e8d2a61b0f5c3e7d9a42b68c1ef";
const TIER_R_FIXED_SOURCE_INPUTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "crates/franken-core/Cargo.toml",
    "crates/franken-extension-host/Cargo.toml",
    "crates/franken-engine/src/bin/franken_execution_truth_ledger.rs",
    "crates/franken-engine/src/bin/franken_verification_coverage_contract.rs",
    "crates/franken-engine/src/execution_truth_ledger.rs",
    "crates/franken-engine/src/verification_coverage_contract.rs",
    "tools/execution-truth-ledger/Cargo.lock",
    "tools/execution-truth-ledger/Cargo.toml",
    "tools/execution-truth-ledger/build.rs",
];

static AUTHORITY_FIXTURE: OnceLock<TempDir> = OnceLock::new();

fn live_repo_root() -> PathBuf {
    for mut path in [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        PathBuf::from(file!()),
    ] {
        if path.is_file() {
            path.pop();
        }
        loop {
            if path.join(".beads/issues.jsonl").is_file()
                && path
                    .join("docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md")
                    .is_file()
            {
                return path;
            }
            if !path.pop() {
                break;
            }
        }
    }
    panic!("could not find FrankenEngine repository root");
}

fn authority_fixture_root() -> &'static Path {
    AUTHORITY_FIXTURE
        .get_or_init(build_authority_fixture)
        .path()
}

fn build_authority_fixture() -> TempDir {
    let live_root = live_repo_root();
    let mut last_difference = String::new();
    for attempt in 1..=4 {
        let live_contract =
            generate_contract(&live_root).expect("generate live contract for hermetic fixture");
        let fixture = tempdir().expect("create authority fixture");
        let root = fixture.path();
        for top_level in ["crates", "scripts", "tools", "docs"] {
            mirror_directory_shape(&live_root.join(top_level), &root.join(top_level));
        }

        let mut paths = BTreeSet::new();
        paths.extend(
            live_contract
                .authority_sources
                .iter()
                .map(|source| source.path.clone()),
        );
        for family in &live_contract.harness_families {
            paths.extend(family.members.iter().map(|member| member.path.clone()));
            paths.extend(
                family
                    .source_inventory_signals
                    .iter()
                    .map(|signal| signal.path.clone()),
            );
        }
        for relative in paths {
            let source = live_root.join(&relative);
            assert!(
                source.is_file(),
                "generated inventory references missing file {}",
                source.display()
            );
            copy_file(&source, &root.join(relative));
        }

        let fixture_contract =
            generate_contract(root).expect("regenerate from the hermetic authority snapshot");
        let live_bytes = canonical_json_bytes(&live_contract).expect("serialize live contract");
        let fixture_bytes =
            canonical_json_bytes(&fixture_contract).expect("serialize fixture contract");
        if live_bytes == fixture_bytes {
            write_contract_documents(root, &fixture_contract);
            return fixture;
        }

        // Other agents may update an authority while this relatively expensive
        // snapshot is being assembled. Accept the fixture if it exactly matches
        // a refreshed live generation; otherwise retry from a new coherent cut.
        let refreshed_contract =
            generate_contract(&live_root).expect("refresh live contract after snapshot race");
        let refreshed_bytes =
            canonical_json_bytes(&refreshed_contract).expect("serialize refreshed live contract");
        if fixture_bytes == refreshed_bytes {
            write_contract_documents(root, &fixture_contract);
            return fixture;
        }

        let authority_differences: Vec<&str> = live_contract
            .authority_sources
            .iter()
            .zip(&fixture_contract.authority_sources)
            .filter(|(live, fixture)| live != fixture)
            .map(|(live, _)| live.authority_id.as_str())
            .collect();
        let family_differences: Vec<String> = live_contract
            .harness_families
            .iter()
            .zip(&fixture_contract.harness_families)
            .filter(|(live, fixture)| live != fixture)
            .map(|(live, fixture)| {
                format!(
                    "{} live={}/{} fixture={}/{}",
                    live.family_id,
                    live.members.len(),
                    live.inventory_sha256,
                    fixture.members.len(),
                    fixture.inventory_sha256
                )
            })
            .collect();
        last_difference = format!(
            "attempt={attempt} live_sha={} fixture_sha={} refreshed_sha={} authority_differences={authority_differences:?} family_differences={family_differences:?} coverage_rows_equal={} integrations_equal={}",
            sha256(&live_bytes),
            sha256(&fixture_bytes),
            sha256(&refreshed_bytes),
            live_contract.coverage_rows == fixture_contract.coverage_rows,
            live_contract.integrations == fixture_contract.integrations,
        );
    }
    panic!("could not obtain a coherent hermetic authority snapshot: {last_difference}");
}

fn mirror_directory_shape(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory shape");
    for entry in fs::read_dir(source).expect("read source directory shape") {
        let entry = entry.expect("read source directory-shape entry");
        if !entry
            .file_type()
            .expect("inspect directory-shape entry")
            .is_dir()
        {
            continue;
        }
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some("target" | "artifacts" | "node_modules" | ".git")
        ) {
            continue;
        }
        mirror_directory_shape(&entry.path(), &destination.join(name));
    }
}

fn copy_file(source: &Path, destination: &Path) {
    fs::create_dir_all(destination.parent().expect("destination parent"))
        .expect("create destination parent");
    fs::copy(source, destination).expect("copy fixture file");
}

fn tier_r_source_inputs(repo_root: &Path) -> Vec<String> {
    let mut inputs: Vec<String> = TIER_R_FIXED_SOURCE_INPUTS
        .iter()
        .map(|path| (*path).to_string())
        .collect();
    for optional in ["rust-toolchain.toml", ".cargo/config.toml"] {
        if repo_root.join(optional).is_file() {
            inputs.push(optional.to_string());
        }
    }
    collect_rust_source_paths(repo_root, "tools/execution-truth-ledger/src", &mut inputs);
    collect_rust_source_paths(repo_root, "crates/franken-core/src", &mut inputs);
    collect_rust_source_paths(repo_root, "crates/franken-extension-host/src", &mut inputs);
    inputs.sort();
    inputs.dedup();
    inputs
}

fn collect_rust_source_paths(repo_root: &Path, relative: &str, inputs: &mut Vec<String>) {
    let directory = repo_root.join(relative);
    let mut entries: Vec<_> = fs::read_dir(&directory)
        .unwrap_or_else(|error| {
            panic!(
                "read Tier-R source directory {}: {error}",
                directory.display()
            )
        })
        .map(|entry| entry.expect("read Tier-R source entry"))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type().unwrap_or_else(|error| {
            panic!("inspect Tier-R source {}: {error}", entry.path().display())
        });
        assert!(
            !file_type.is_symlink(),
            "Tier-R source closure cannot contain symlink {}",
            entry.path().display()
        );
        let child_relative = format!(
            "{relative}/{}",
            entry
                .file_name()
                .to_str()
                .expect("Tier-R source path must be UTF-8")
        );
        if file_type.is_dir() {
            collect_rust_source_paths(repo_root, &child_relative, inputs);
        } else if file_type.is_file()
            && entry.path().extension().and_then(|value| value.to_str()) == Some("rs")
        {
            inputs.push(child_relative);
        }
    }
}

fn clone_authority_fixture(detached: &[&str]) -> TempDir {
    let source_root = authority_fixture_root();
    let clone = tempdir().expect("create fixture clone");
    clone_tree(
        source_root,
        clone.path(),
        source_root,
        &detached.iter().copied().collect(),
    );
    clone
}

fn clone_tree(source: &Path, destination: &Path, source_root: &Path, detached: &BTreeSet<&str>) {
    fs::create_dir_all(destination).expect("create cloned fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("read fixture entry");
        let file_type = entry.file_type().expect("inspect fixture entry");
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            clone_tree(&entry.path(), &target, source_root, detached);
        } else {
            assert!(
                file_type.is_file(),
                "authority fixture contains only regular files"
            );
            let relative = entry
                .path()
                .strip_prefix(source_root)
                .expect("fixture path is below root")
                .to_string_lossy()
                .replace('\\', "/");
            fs::create_dir_all(target.parent().expect("clone target parent"))
                .expect("create clone parent");
            if detached.contains(relative.as_str()) || fs::hard_link(entry.path(), &target).is_err()
            {
                fs::copy(entry.path(), &target).expect("copy detached fixture file");
            }
        }
    }
}

fn write_contract_documents(root: &Path, contract: &VerificationCoverageContract) {
    let contract_path = root.join(CONTRACT_RELATIVE_PATH);
    fs::create_dir_all(contract_path.parent().expect("contract parent"))
        .expect("create contract parent");
    fs::write(
        &contract_path,
        canonical_json_bytes(contract).expect("serialize canonical contract"),
    )
    .expect("write canonical contract");
    fs::write(root.join(MARKDOWN_RELATIVE_PATH), render_markdown(contract))
        .expect("write rendered contract");
}

fn load_contract(root: &Path) -> VerificationCoverageContract {
    read_json(&root.join(CONTRACT_RELATIVE_PATH))
}

fn fixed_context(_root: &Path) -> ValidationContext {
    ValidationContext::certifying_now()
}

fn validate_temporary(root: &Path, contract: &VerificationCoverageContract) -> ValidationOutput {
    let file = NamedTempFile::new().expect("temporary contract");
    fs::write(
        file.path(),
        canonical_json_bytes(contract).expect("serialize temporary contract"),
    )
    .expect("write temporary contract");
    validate_contract_file(root, file.path(), &fixed_context(root))
}

fn assert_validation_code(output: &ValidationOutput, expected: &str) {
    assert!(
        output
            .report
            .findings
            .iter()
            .any(|finding| finding.error_code == expected),
        "expected {expected}; findings: {:?}",
        output.report.findings
    );
}

fn assert_validation_any_code(output: &ValidationOutput, expected: &[&str]) {
    assert!(
        output
            .report
            .findings
            .iter()
            .any(|finding| expected.contains(&finding.error_code.as_str())),
        "expected one of {expected:?}; findings: {:?}",
        output.report.findings
    );
}

fn mutate_issue<F>(root: &Path, issue_id: &str, mut mutation: F)
where
    F: FnMut(&mut Value),
{
    let tracker = root.join(".beads/issues.jsonl");
    let text = fs::read_to_string(&tracker).expect("read fixture tracker");
    let mut changed = false;
    let mut output = String::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut issue: Value = serde_json::from_str(line).expect("parse tracker line");
        if issue["id"] == issue_id {
            mutation(&mut issue);
            changed = true;
        }
        output.push_str(&serde_json::to_string(&issue).expect("serialize tracker line"));
        output.push('\n');
    }
    assert!(changed, "fixture tracker must contain {issue_id}");
    fs::write(tracker, output).expect("write mutated tracker");
}

fn bridge_task_ids(root: &Path) -> BTreeSet<String> {
    fs::read_to_string(root.join(".beads/issues.jsonl"))
        .expect("read tracker")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("parse tracker issue"))
        .filter(|issue| issue["issue_type"] == "task")
        .filter_map(|issue| issue["id"].as_str().map(str::to_string))
        .filter(|id| id == BRIDGE_ROOT || id.starts_with(&format!("{BRIDGE_ROOT}.")))
        .collect()
}

fn claim_ids(root: &Path) -> BTreeSet<String> {
    let matrix: Value = read_json(&root.join("docs/claim_to_proof_matrix_v1.json"));
    matrix["claims"]
        .as_array()
        .expect("claim array")
        .iter()
        .map(|claim| claim["claim_id"].as_str().expect("claim id").to_string())
        .collect()
}

#[test]
fn canonical_contract_counts_and_subjects_derive_from_live_authorities() {
    let root = authority_fixture_root();
    let output = validate_contract_file(
        root,
        &root.join(CONTRACT_RELATIVE_PATH),
        &fixed_context(root),
    );
    assert!(
        output.passed(),
        "canonical fixture must validate: {:?}",
        output.report.findings
    );

    let contract = load_contract(root);
    let expected_tasks = bridge_task_ids(root);
    let expected_claims = claim_ids(root);
    let actual_tasks: BTreeSet<String> = contract
        .coverage_rows
        .iter()
        .filter(|row| row.subject_kind == SubjectKind::BridgeTask)
        .map(|row| row.subject_id.clone())
        .collect();
    let actual_claims: BTreeSet<String> = contract
        .coverage_rows
        .iter()
        .filter(|row| row.subject_kind == SubjectKind::Claim)
        .map(|row| row.subject_id.clone())
        .collect();

    assert_eq!(actual_tasks, expected_tasks);
    assert_eq!(actual_claims, expected_claims);
    assert_eq!(output.report.bridge_task_count, actual_tasks.len());
    assert_eq!(output.report.claim_count, actual_claims.len());
    assert_eq!(
        output.report.coverage_row_count,
        actual_tasks.len() + actual_claims.len()
    );
    assert_eq!(
        output.report.harness_family_count,
        contract.harness_families.len()
    );
    assert_eq!(
        output.report.harness_member_count,
        contract
            .harness_families
            .iter()
            .map(|family| family.members.len())
            .sum::<usize>()
    );
    let event_report = validate_event_stream(&event_bytes(&output.events));
    assert_eq!(
        event_report.error_count, 0,
        "validator events must satisfy their own schema: {:?}",
        event_report.findings
    );
    let published_validation_artifacts = BTreeSet::from([
        "contract.json".to_string(),
        "generated_contract.json".to_string(),
    ]);
    for event in &output.events {
        assert!(
            event
                .artifact_hashes
                .keys()
                .all(|path| published_validation_artifacts.contains(path)),
            "event {} misclassifies source inventory or a logical comparison value as a published artifact: {:?}",
            event.sequence,
            event.artifact_hashes.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn synthetic_clock_can_test_logic_but_cannot_certify_freshness() {
    let root = authority_fixture_root();
    let cutoff = DateTime::parse_from_rfc3339(&load_contract(root).source_cutoff_utc)
        .expect("source cutoff parses")
        .with_timezone(&Utc);
    let context = ValidationContext::deterministic_for_tests(cutoff + Duration::hours(1));
    let output = validate_contract_file(root, &root.join(CONTRACT_RELATIVE_PATH), &context);
    assert_validation_code(&output, ERROR_CLOCK_AUTHORITY);
    assert!(!output.report.certifying_clock);
}

#[test]
fn generation_and_rendering_are_byte_deterministic_in_a_hermetic_snapshot() {
    let root = authority_fixture_root();
    let first = generate_contract(root).expect("first generation");
    let second = generate_contract(root).expect("second generation");
    assert_eq!(
        canonical_json_bytes(&first).expect("serialize first generation"),
        canonical_json_bytes(&second).expect("serialize second generation")
    );
    assert_eq!(
        canonical_json_bytes(&first).expect("serialize generated contract"),
        fs::read(root.join(CONTRACT_RELATIVE_PATH)).expect("read canonical contract")
    );
    assert_eq!(
        render_markdown(&first),
        fs::read_to_string(root.join(MARKDOWN_RELATIVE_PATH)).expect("read markdown")
    );
}

#[test]
fn claim_matrix_freshness_policy_is_typed_and_fail_closed() {
    let fixture = clone_authority_fixture(&["docs/claim_to_proof_matrix_v1.json"]);
    let matrix_path = fixture.path().join("docs/claim_to_proof_matrix_v1.json");
    let mut matrix: Value = read_json(&matrix_path);
    matrix["max_authored_freshness_days"] = Value::from(179_u64);
    fs::write(
        &matrix_path,
        serde_json::to_vec_pretty(&matrix).expect("serialize malformed freshness policy"),
    )
    .expect("write malformed freshness policy");

    let error = generate_contract(fixture.path()).expect_err("invalid tier ceiling must fail");
    assert!(
        error.contains(ERROR_SCHEMA) && error.contains("max_authored_freshness_days"),
        "unexpected error: {error}"
    );
}

#[test]
fn coverage_rows_have_exact_subjects_independent_owners_and_no_wildcards() {
    let contract = load_contract(authority_fixture_root());
    assert!(contract.coverage_rows.iter().all(|row| {
        !row.row_id.contains('*')
            && !row.subject_id.contains('*')
            && row.subject_id != row.independent_owner
            && !row.required_layers.is_empty()
            && !row.required_platforms.is_empty()
            && !row.required_tiers.is_empty()
            && !row.required_security_profiles.is_empty()
    }));
    let wildcard = contract
        .harness_families
        .iter()
        .find(|family| family.family_id == "rgc-wildcard-coverage-matrix")
        .expect("stale wildcard predecessor remains explicitly classified");
    assert_eq!(wildcard.execution_class, HarnessExecutionClass::Stale);
    assert!(!wildcard.current_coverage_eligible);
}

#[test]
fn authority_description_acceptance_and_dependency_drift_are_detected() {
    for field in ["description", "acceptance_criteria", "dependencies"] {
        let fixture = clone_authority_fixture(&[".beads/issues.jsonl"]);
        mutate_issue(fixture.path(), OWNING_BEAD, |issue| match field {
            "description" => {
                issue[field] = Value::String(format!(
                    "{}\nmeaningful requirement drift",
                    issue[field].as_str().unwrap_or_default()
                ));
            }
            "acceptance_criteria" => {
                issue[field] = Value::String(format!(
                    "{}\nnew independently observable criterion",
                    issue[field].as_str().unwrap_or_default()
                ));
            }
            "dependencies" => {
                let dependencies = issue[field]
                    .as_array_mut()
                    .expect("dependencies must be an array");
                dependencies.push(serde_json::json!({
                    "issue_id": OWNING_BEAD,
                    "depends_on_id": BRIDGE_ROOT,
                    "type": "blocks"
                }));
            }
            _ => unreachable!(),
        });
        let output = validate_contract_file(
            fixture.path(),
            &fixture.path().join(CONTRACT_RELATIVE_PATH),
            &fixed_context(fixture.path()),
        );
        assert_validation_any_code(
            &output,
            &[
                ERROR_GENERATION_DRIFT,
                ERROR_SUBJECT_DRIFT,
                ERROR_HASH_DRIFT,
            ],
        );
    }
}

#[test]
fn contract_authority_projection_owner_and_generic_runner_mutants_fail() {
    let root = authority_fixture_root();

    let mut contract = load_contract(root);
    contract.authority_sources[0].projection_sha256 = sha256(b"fabricated projection");
    assert_validation_any_code(
        &validate_temporary(root, &contract),
        &[ERROR_GENERATION_DRIFT, ERROR_SUBJECT_DRIFT],
    );

    let mut contract = load_contract(root);
    let wrong_owner = bridge_task_ids(root)
        .into_iter()
        .find(|candidate| {
            candidate != &contract.coverage_rows[0].subject_id
                && candidate != &contract.coverage_rows[0].independent_owner
                && !contract.coverage_rows[0]
                    .required_verification_packs
                    .contains(candidate)
        })
        .expect("a distinct live tracker identity for the ownership mutant");
    contract.coverage_rows[0].independent_owner = wrong_owner;
    assert_validation_code(&validate_temporary(root, &contract), ERROR_OWNER);

    let mut contract = load_contract(root);
    let family = contract
        .harness_families
        .iter_mut()
        .find(|family| family.current_coverage_eligible)
        .expect("current eligible family");
    family.runner = "cargo test".to_string();
    assert_validation_any_code(
        &validate_temporary(root, &contract),
        &[ERROR_GENERATION_DRIFT, "FE-VCC-1009"],
    );
}

#[test]
fn same_file_test_removal_is_detected() {
    const THIS_TEST_FILE: &str =
        "crates/franken-engine/tests/verification_coverage_contract_integration.rs";
    let contract = load_contract(authority_fixture_root());
    assert!(
        contract.harness_families.iter().any(|family| {
            family
                .members
                .iter()
                .any(|member| member.path == THIS_TEST_FILE && member.sha256.is_some())
        }),
        "this same-file integration suite must be content-addressed by the contract"
    );

    let fixture = clone_authority_fixture(&[THIS_TEST_FILE]);
    let path = fixture.path().join(THIS_TEST_FILE);
    let before = fs::read_to_string(&path).expect("read same-file fixture");
    let marker = "#[test]\nfn same_file_test_removal_is_detected()";
    assert!(
        before.contains(marker),
        "same-file mutation marker must exist"
    );
    fs::write(
        &path,
        before.replacen(marker, "fn same_file_test_removal_is_detected()", 1),
    )
    .expect("remove test attribute in fixture");

    let output = validate_contract_file(
        fixture.path(),
        &fixture.path().join(CONTRACT_RELATIVE_PATH),
        &fixed_context(fixture.path()),
    );
    assert_validation_any_code(&output, &[ERROR_HASH_DRIFT, ERROR_GENERATION_DRIFT]);
}

#[test]
fn post_close_regeneration_preserves_history_without_claiming_current_evidence() {
    let fixture = clone_authority_fixture(&[
        ".beads/issues.jsonl",
        CONTRACT_RELATIVE_PATH,
        MARKDOWN_RELATIVE_PATH,
    ]);
    mutate_issue(fixture.path(), OWNING_BEAD, |issue| {
        issue["status"] = Value::String("closed".to_string());
    });
    let regenerated =
        generate_contract(fixture.path()).expect("regenerate after truthful tracker closure");
    let owner_row = regenerated
        .coverage_rows
        .iter()
        .find(|row| row.subject_id == OWNING_BEAD)
        .expect("owning row");
    assert_eq!(owner_row.authority_state, "closed");
    assert_eq!(
        owner_row.evidence_state,
        EvidenceState::HistoricalUnrecertified
    );
    write_contract_documents(fixture.path(), &regenerated);
    let output = validate_contract_file(
        fixture.path(),
        &fixture.path().join(CONTRACT_RELATIVE_PATH),
        &fixed_context(fixture.path()),
    );
    assert!(
        output.passed(),
        "truthful post-close regeneration must validate: {:?}",
        output.report.findings
    );
}

#[test]
fn historical_row_cannot_be_promoted_and_row_removal_fails_closed() {
    let root = authority_fixture_root();
    let mut contract = load_contract(root);
    let historical = contract
        .coverage_rows
        .iter_mut()
        .find(|row| row.evidence_state == EvidenceState::HistoricalUnrecertified)
        .expect("historical bridge row");
    historical.evidence_state = EvidenceState::CandidateCurrentRun;
    assert_validation_any_code(
        &validate_temporary(root, &contract),
        &[ERROR_HISTORICAL_PROOF, ERROR_SUBJECT_DRIFT],
    );

    let mut contract = load_contract(root);
    contract.coverage_rows.pop();
    assert_validation_any_code(
        &validate_temporary(root, &contract),
        &[ERROR_SUBJECT_DRIFT, ERROR_GENERATION_DRIFT],
    );
}

fn measured_resources(duration_ns: i64) -> ResourceDelta {
    ResourceDelta {
        cpu_time_ns: Some(duration_ns),
        wall_time_ns: Some(duration_ns),
        max_rss_bytes: None,
        allocated_bytes: None,
        io_read_bytes: None,
        io_write_bytes: None,
        measurement_sources: BTreeMap::from([
            ("cpu_time_ns".to_string(), "measured:test-clock".to_string()),
            (
                "wall_time_ns".to_string(),
                "measured:test-clock".to_string(),
            ),
            (
                "max_rss_bytes".to_string(),
                "unavailable:test-platform".to_string(),
            ),
            (
                "allocated_bytes".to_string(),
                "unavailable:test-allocator".to_string(),
            ),
            (
                "io_read_bytes".to_string(),
                "unavailable:test-platform".to_string(),
            ),
            (
                "io_write_bytes".to_string(),
                "unavailable:test-platform".to_string(),
            ),
        ]),
    }
}

fn base_event(
    sequence: u64,
    event: &str,
    phase: &str,
    attempt: u32,
    artifact_hashes: &BTreeMap<String, String>,
) -> VerificationEvent {
    VerificationEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        run_id: RUN_ID.to_string(),
        trace_id: TRACE_ID.to_string(),
        test_id: TEST_ID.to_string(),
        scenario_id: SCENARIO_ID.to_string(),
        seed: SEED,
        attempt,
        platform: PLATFORM.to_string(),
        target: TARGET.to_string(),
        tier: TIER.to_string(),
        security_profile: PROFILE.to_string(),
        phase: phase.to_string(),
        sequence,
        event: event.to_string(),
        decision: "pass".to_string(),
        reason_code: "FE-VCC-0000".to_string(),
        reason: format!("{event} completed"),
        error_class: None,
        fallback: "none".to_string(),
        rollback: "prior-valid-artifacts-preserved".to_string(),
        duration_ns: 11,
        resource_delta: measured_resources(11),
        artifact_hashes: artifact_hashes.clone(),
    }
}

fn outcome_label(outcome: RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Pass => "pass",
        RunOutcome::Fail => "fail",
        RunOutcome::Deny => "deny",
        RunOutcome::Fallback => "fallback",
        RunOutcome::Cancel => "cancel",
        RunOutcome::Crash => "crash",
        RunOutcome::Rollback => "rollback",
    }
}

fn make_nonpassing(event: &mut VerificationEvent, outcome: RunOutcome) {
    event.decision = outcome_label(outcome).to_string();
    event.reason_code = ERROR_IO.to_string();
    event.reason = "retained fixture failure".to_string();
    event.error_class = Some("FixtureFailure".to_string());
    if outcome == RunOutcome::Fallback {
        event.fallback = "deterministic-safe-mode".to_string();
    }
}

fn passing_events(artifact_hashes: BTreeMap<String, String>) -> Vec<VerificationEvent> {
    vec![
        base_event(1, "run_started", "start", 1, &artifact_hashes),
        base_event(2, "contract_check", "validate", 1, &artifact_hashes),
        base_event(3, "run_completed", "finalize", 1, &artifact_hashes),
    ]
}

fn failing_retry_events(
    artifact_hashes: BTreeMap<String, String>,
    outcome: RunOutcome,
) -> Vec<VerificationEvent> {
    let mut events = vec![
        base_event(1, "run_started", "start", 1, &artifact_hashes),
        base_event(2, "contract_check", "validate", 1, &artifact_hashes),
        base_event(3, "attempt_failed", "retry", 1, &artifact_hashes),
        base_event(4, "contract_check", "validate", 2, &artifact_hashes),
        base_event(5, "run_completed", "finalize", 2, &artifact_hashes),
    ];
    for event in &mut events[1..] {
        make_nonpassing(event, outcome);
    }
    events
}

fn event_bytes(events: &[VerificationEvent]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event).expect("serialize event");
        bytes.push(b'\n');
    }
    bytes
}

fn assert_event_code(
    report: &frankenengine_engine::verification_coverage_contract::EventValidationReport,
    expected: &str,
) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.error_code == expected),
        "expected {expected}; findings: {:?}",
        report.findings
    );
}

#[test]
fn event_lifecycle_accepts_exact_pass_and_truthful_retry_failure_streams() {
    let pass = validate_event_stream(&event_bytes(&passing_events(BTreeMap::new())));
    assert_eq!(pass.error_count, 0, "{:?}", pass.findings);
    assert_eq!(pass.terminal_decision.as_deref(), Some("pass"));
    assert_eq!(pass.first_failure, None);

    let fail_events = failing_retry_events(BTreeMap::new(), RunOutcome::Fail);
    let fail = validate_event_stream(&event_bytes(&fail_events));
    assert_eq!(fail.error_count, 0, "{:?}", fail.findings);
    assert_eq!(fail.terminal_decision.as_deref(), Some("fail"));
    assert_eq!(
        fail.first_failure,
        Some(FailureReference {
            sequence: 2,
            reason_code: ERROR_IO.to_string(),
        })
    );
}

#[test]
fn event_framing_schema_registry_order_and_truncation_fail_closed() {
    let events = passing_events(BTreeMap::new());

    let mut no_newline = event_bytes(&events);
    no_newline.pop();
    assert_event_code(&validate_event_stream(&no_newline), ERROR_EVENT_SCHEMA);

    let mut blank_line = event_bytes(&events);
    blank_line.extend_from_slice(b"\n");
    assert_event_code(&validate_event_stream(&blank_line), ERROR_EVENT_SCHEMA);

    let mut truncated = events.clone();
    truncated.pop();
    assert_event_code(
        &validate_event_stream(&event_bytes(&truncated)),
        ERROR_EVENT_SCHEMA,
    );

    let mut reordered = events.clone();
    reordered.swap(0, 1);
    assert_event_code(
        &validate_event_stream(&event_bytes(&reordered)),
        ERROR_ORDER_OR_DUPLICATE,
    );

    let mut unknown_reason = events.clone();
    unknown_reason[1].reason_code = "FE-VCC-9876".to_string();
    assert_event_code(
        &validate_event_stream(&event_bytes(&unknown_reason)),
        ERROR_EVENT_SCHEMA,
    );

    let mut unknown_event = events.clone();
    unknown_event[1].event = "guest_claimed_success".to_string();
    assert_event_code(
        &validate_event_stream(&event_bytes(&unknown_event)),
        ERROR_EVENT_SCHEMA,
    );

    let mut after_terminal = events.clone();
    let mut late = base_event(4, "contract_check", "late", 1, &BTreeMap::new());
    late.reason = "event after terminal".to_string();
    after_terminal.push(late);
    assert_event_code(
        &validate_event_stream(&event_bytes(&after_terminal)),
        ERROR_ORDER_OR_DUPLICATE,
    );

    let mut lines: Vec<Value> = events
        .iter()
        .map(|event| serde_json::to_value(event).expect("event value"))
        .collect();
    lines[1]["unknown_field"] = Value::Bool(true);
    let bytes = jsonl_values(&lines);
    assert_event_code(&validate_event_stream(&bytes), ERROR_EVENT_SCHEMA);
}

#[test]
fn event_retry_failure_and_terminal_pass_cannot_be_masked() {
    let mut no_attempt_failure = failing_retry_events(BTreeMap::new(), RunOutcome::Fail);
    no_attempt_failure[2].event = "contract_check".to_string();
    assert_event_code(
        &validate_event_stream(&event_bytes(&no_attempt_failure)),
        ERROR_RETRY_MASKING,
    );

    let mut passing_attempt_failure = failing_retry_events(BTreeMap::new(), RunOutcome::Fail);
    passing_attempt_failure[2].decision = "pass".to_string();
    passing_attempt_failure[2].reason_code = "FE-VCC-0000".to_string();
    passing_attempt_failure[2].error_class = None;
    assert_event_code(
        &validate_event_stream(&event_bytes(&passing_attempt_failure)),
        ERROR_RETRY_MASKING,
    );

    let mut masked = failing_retry_events(BTreeMap::new(), RunOutcome::Fail);
    let terminal = masked.last_mut().expect("terminal");
    terminal.decision = "pass".to_string();
    terminal.reason_code = "FE-VCC-0000".to_string();
    terminal.error_class = None;
    assert_event_code(
        &validate_event_stream(&event_bytes(&masked)),
        ERROR_RETRY_MASKING,
    );

    let mut nonpassing_terminal_without_failure = passing_events(BTreeMap::new());
    make_nonpassing(
        nonpassing_terminal_without_failure
            .last_mut()
            .expect("terminal"),
        RunOutcome::Fail,
    );
    assert_event_code(
        &validate_event_stream(&event_bytes(&nonpassing_terminal_without_failure)),
        ERROR_OUTCOME_MISMATCH,
    );

    let mut silent_fallback = passing_events(BTreeMap::new());
    silent_fallback[1].fallback = "safe-mode".to_string();
    assert_event_code(
        &validate_event_stream(&event_bytes(&silent_fallback)),
        ERROR_SILENT_FALLBACK,
    );
}

#[test]
fn event_registry_preserves_every_nonpassing_terminal_outcome() {
    for outcome in [
        RunOutcome::Fail,
        RunOutcome::Deny,
        RunOutcome::Fallback,
        RunOutcome::Cancel,
        RunOutcome::Crash,
        RunOutcome::Rollback,
    ] {
        let report = validate_event_stream(&event_bytes(&failing_retry_events(
            BTreeMap::new(),
            outcome,
        )));
        assert_eq!(
            report.error_count, 0,
            "{outcome:?} must be a valid retained terminal outcome: {:?}",
            report.findings
        );
        assert_eq!(
            report.terminal_decision.as_deref(),
            Some(outcome_label(outcome))
        );
    }
}

#[test]
fn event_resource_semantics_are_exact_and_fail_closed() {
    let cases = [
        {
            let mut events = passing_events(BTreeMap::new());
            events[1].resource_delta.cpu_time_ns = Some(-1);
            events
        },
        {
            let mut events = passing_events(BTreeMap::new());
            events[1].resource_delta.cpu_time_ns = None;
            events
        },
        {
            let mut events = passing_events(BTreeMap::new());
            events[1].resource_delta.measurement_sources.insert(
                "cpu_time_ns".to_string(),
                "unavailable:no-counter".to_string(),
            );
            events
        },
        {
            let mut events = passing_events(BTreeMap::new());
            events[1]
                .resource_delta
                .measurement_sources
                .remove("io_write_bytes");
            events
        },
        {
            let mut events = passing_events(BTreeMap::new());
            events[1]
                .resource_delta
                .measurement_sources
                .insert("seventh_counter".to_string(), "measured:test".to_string());
            events
        },
    ];
    for events in cases {
        assert_event_code(
            &validate_event_stream(&event_bytes(&events)),
            ERROR_EVENT_SCHEMA,
        );
    }
}

#[test]
fn event_secret_and_artifact_path_mutants_are_rejected() {
    let mut secret = passing_events(BTreeMap::new());
    secret[1].reason = SECRET_PROBE.to_string();
    assert_event_code(
        &validate_event_stream(&event_bytes(&secret)),
        ERROR_SECRET_LEAK,
    );

    let mut unsafe_path = passing_events(BTreeMap::new());
    unsafe_path[1]
        .artifact_hashes
        .insert("../escape".to_string(), sha256(b"artifact"));
    assert_event_code(
        &validate_event_stream(&event_bytes(&unsafe_path)),
        ERROR_EVENT_SCHEMA,
    );

    let mut bad_hash = passing_events(BTreeMap::new());
    bad_hash[1]
        .artifact_hashes
        .insert("contract.json".to_string(), "not-a-sha".to_string());
    assert_event_code(
        &validate_event_stream(&event_bytes(&bad_hash)),
        ERROR_EVENT_SCHEMA,
    );
}

#[test]
fn no_replace_event_and_byte_publication_preserve_original_bytes() {
    let directory = tempdir().expect("temporary publication directory");
    let events_path = directory.path().join("events.jsonl");
    let events = passing_events(BTreeMap::new());
    write_events_jsonl(&events_path, &events).expect("first event publication");
    let original = fs::read(&events_path).expect("read original events");
    assert!(write_events_jsonl(&events_path, &events).is_err());
    assert_eq!(fs::read(&events_path).expect("reread events"), original);

    let bytes_path = directory.path().join("artifact.txt");
    write_bytes_no_replace(&bytes_path, b"original\n").expect("first byte publication");
    assert!(write_bytes_no_replace(&bytes_path, b"replacement\n").is_err());
    assert_eq!(
        fs::read(&bytes_path).expect("reread byte artifact"),
        b"original\n"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(0x5643_4301),
        .. ProptestConfig::default()
    })]

    #[test]
    fn property_clean_reason_text_preserves_a_valid_lifecycle(
        reason in "[A-Za-z0-9 ._-]{0,128}"
    ) {
        let mut events = passing_events(BTreeMap::new());
        events[1].reason = reason;
        let report = validate_event_stream(&event_bytes(&events));
        prop_assert_eq!(report.error_count, 0, "{:?}", report.findings);
    }

    #[test]
    fn property_any_later_stable_identity_mutation_is_detected(
        selector in 0usize..9,
        suffix in "[a-z]{1,24}"
    ) {
        let mut events = passing_events(BTreeMap::new());
        let event = &mut events[1];
        let mutated = format!("mutated-{suffix}");
        match selector {
            0 => event.run_id = mutated,
            1 => event.trace_id = mutated,
            2 => event.test_id = mutated,
            3 => event.scenario_id = mutated,
            4 => event.seed = event.seed.wrapping_add(1),
            5 => event.platform = mutated,
            6 => event.target = mutated,
            7 => event.tier = mutated,
            8 => event.security_profile = mutated,
            _ => unreachable!(),
        }
        let report = validate_event_stream(&event_bytes(&events));
        prop_assert!(
            report.findings.iter().any(|finding| {
                finding.error_code == ERROR_ORDER_OR_DUPLICATE
            }),
            "{:?}",
            report.findings
        );
    }
}

fn valid_tier_r_report(
    run_id: &str,
    trace_id: &str,
    reference_source_sha256: String,
    build_environment_sha256: String,
    executable_sha256: String,
) -> TierRProbeReport {
    let mut stage_events = Vec::new();
    let scenarios: Vec<TierRProbeScenario> = TIER_R_PROBE_CASES
        .iter()
        .map(|(scenario_id, source, expected)| {
            let source_sha256 = sha256(source.as_bytes());
            let ir_sha256 = sha256(format!("reference-ir:{scenario_id}").as_bytes());
            let semantic_digest = tier_r_expected_semantic_digest(expected);
            let scenario = TierRProbeScenario {
                scenario_id: (*scenario_id).to_string(),
                source_sha256: source_sha256.clone(),
                reference_ir_sha256: ir_sha256.clone(),
                expected_value: (*expected).to_string(),
                reference_value: (*expected).to_string(),
                reference_instructions: 17,
                reference_events: vec![
                    "execution_started".to_string(),
                    "execution_completed".to_string(),
                ],
                expected_semantic_digest: semantic_digest.clone(),
                reference_semantic_digest: semantic_digest.clone(),
                decision: "pass".to_string(),
            };
            stage_events.extend([
                TierRStageEvent {
                    sequence: 0,
                    scenario_id: (*scenario_id).to_string(),
                    stage: "reference_parse_completed".to_string(),
                    input_sha256: source_sha256.clone(),
                    output_sha256: source_sha256.clone(),
                    decision: "pass".to_string(),
                },
                TierRStageEvent {
                    sequence: 0,
                    scenario_id: (*scenario_id).to_string(),
                    stage: "reference_lowering_completed".to_string(),
                    input_sha256: source_sha256,
                    output_sha256: ir_sha256.clone(),
                    decision: "pass".to_string(),
                },
                TierRStageEvent {
                    sequence: 0,
                    scenario_id: (*scenario_id).to_string(),
                    stage: "reference_execution_started".to_string(),
                    input_sha256: ir_sha256.clone(),
                    output_sha256: ir_sha256,
                    decision: "pass".to_string(),
                },
                TierRStageEvent {
                    sequence: 0,
                    scenario_id: (*scenario_id).to_string(),
                    stage: "reference_execution_completed".to_string(),
                    input_sha256: scenario.reference_ir_sha256.clone(),
                    output_sha256: semantic_digest.clone(),
                    decision: "pass".to_string(),
                },
                TierRStageEvent {
                    sequence: 0,
                    scenario_id: (*scenario_id).to_string(),
                    stage: "expected_observable_equal".to_string(),
                    input_sha256: semantic_digest.clone(),
                    output_sha256: semantic_digest,
                    decision: "pass".to_string(),
                },
            ]);
            scenario
        })
        .collect();
    let denial_hash = sha256(b"VmDispatch");
    stage_events.push(TierRStageEvent {
        sequence: 0,
        scenario_id: "vm-dispatch-denial".to_string(),
        stage: "reference_capability_denied".to_string(),
        input_sha256: denial_hash.clone(),
        output_sha256: denial_hash,
        decision: "deny".to_string(),
    });
    for (index, event) in stage_events.iter_mut().enumerate() {
        event.sequence = u64::try_from(index).expect("stage index") + 1;
    }

    TierRProbeReport {
        schema_version: TIER_R_PROBE_SCHEMA_VERSION.to_string(),
        classification: "provisional_not_certified_tier_r".to_string(),
        run_id: run_id.to_string(),
        trace_id: trace_id.to_string(),
        implementation_truth: TIER_R_IMPLEMENTATION_TRUTH.to_string(),
        reference_source_sha256,
        build_environment_sha256,
        probe_executable_sha256: executable_sha256,
        status: "pass".to_string(),
        scenarios,
        denial: TierRDenialProbe {
            scenario_id: "vm-dispatch-denial".to_string(),
            error_class: "CapabilityDenied".to_string(),
            capability: "VmDispatch".to_string(),
            decision: "deny".to_string(),
        },
        stage_events,
        branch_signals: TIER_R_BRANCH_SIGNALS
            .iter()
            .map(|signal| (*signal).to_string())
            .collect(),
    }
}

#[test]
fn tier_r_report_binds_typed_values_stages_digests_and_real_identities() {
    let report = valid_tier_r_report(
        RUN_ID,
        TRACE_ID,
        sha256(b"reference source"),
        sha256(b"build environment"),
        sha256(b"probe executable"),
    );
    assert!(
        validate_tier_r_probe(&report).is_empty(),
        "{:?}",
        validate_tier_r_probe(&report)
    );
    assert_eq!(
        report
            .scenarios
            .iter()
            .map(|scenario| scenario.expected_value.as_str())
            .collect::<Vec<_>>(),
        TIER_R_PROBE_CASES
            .iter()
            .map(|(_, _, expected)| *expected)
            .collect::<Vec<_>>()
    );
}

#[test]
fn tier_r_typed_value_digest_stage_and_executable_mutants_fail() {
    let valid = || {
        valid_tier_r_report(
            RUN_ID,
            TRACE_ID,
            sha256(b"reference source"),
            sha256(b"build environment"),
            sha256(b"probe executable"),
        )
    };

    let mut typed = valid();
    typed.scenarios[0].reference_value = "3".to_string();
    assert_finding_code(&validate_tier_r_probe(&typed), ERROR_TIER_R_TRUTH);

    let mut digest = valid();
    digest.scenarios[1].reference_semantic_digest = sha256(b"wrong observable");
    assert_finding_code(&validate_tier_r_probe(&digest), ERROR_TIER_R_TRUTH);

    let mut stage = valid();
    stage.stage_events.swap(0, 1);
    assert_finding_code(&validate_tier_r_probe(&stage), ERROR_BRANCH_PROOF);

    let mut duplicate = valid();
    duplicate.scenarios[1].scenario_id = duplicate.scenarios[0].scenario_id.clone();
    assert_finding_code(&validate_tier_r_probe(&duplicate), ERROR_ORDER_OR_DUPLICATE);

    let mut executable = valid();
    executable.probe_executable_sha256 = "0".repeat(64);
    assert_finding_code(&validate_tier_r_probe(&executable), ERROR_TIER_R_TRUTH);
}

fn assert_finding_code(findings: &[ValidationFinding], expected: &str) {
    assert!(
        findings
            .iter()
            .any(|finding| finding.error_code == expected),
        "expected {expected}; findings: {findings:?}"
    );
}

#[derive(Debug, Clone, Copy)]
enum SampleChoice {
    Raw,
    Minimized,
}

#[derive(Debug, Clone)]
struct BundleOptions {
    sample: SampleChoice,
    expected_outcome: RunOutcome,
    observed_outcome: RunOutcome,
    guest_stdout: Vec<u8>,
    source_dirty: bool,
}

impl BundleOptions {
    fn passing_raw() -> Self {
        Self {
            sample: SampleChoice::Raw,
            expected_outcome: RunOutcome::Pass,
            observed_outcome: RunOutcome::Pass,
            guest_stdout: Vec::new(),
            source_dirty: false,
        }
    }

    fn failing_minimized() -> Self {
        Self {
            sample: SampleChoice::Minimized,
            expected_outcome: RunOutcome::Pass,
            observed_outcome: RunOutcome::Fail,
            guest_stdout: Vec::new(),
            source_dirty: false,
        }
    }

    fn passing_raw_dirty() -> Self {
        Self {
            source_dirty: true,
            ..Self::passing_raw()
        }
    }
}

fn build_bundle(options: BundleOptions) -> TempDir {
    let directory = tempdir().expect("temporary bundle");
    let root = directory.path();
    let contract = load_contract(authority_fixture_root());
    let contract_bytes = canonical_json_bytes(&contract).expect("serialize contract");
    write_file(root, "contract.json", &contract_bytes);
    write_file(root, "generated_contract.json", &contract_bytes);
    write_file(
        root,
        "rendered_contract.md",
        render_markdown(&contract).as_bytes(),
    );

    let contract_sha256 = sha256(&contract_bytes);
    let generated_sha256 = contract_sha256.clone();
    let created_at = Utc::now().to_rfc3339();
    let report_findings = if options.observed_outcome == RunOutcome::Pass {
        Vec::new()
    } else {
        vec![ValidationFinding {
            error_code: ERROR_IO.to_string(),
            phase: "fixture.observed_failure".to_string(),
            reason: "retained expected-versus-observed failure".to_string(),
            subject_id: None,
            family_id: None,
        }]
    };
    let bridge_task_count = contract
        .coverage_rows
        .iter()
        .filter(|row| row.subject_kind == SubjectKind::BridgeTask)
        .count();
    let claim_count = contract.coverage_rows.len() - bridge_task_count;
    let validation_report =
        frankenengine_engine::verification_coverage_contract::ValidationReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            contract_path: CONTRACT_PATH.to_string(),
            contract_sha256: contract_sha256.clone(),
            generated_contract_sha256: generated_sha256.clone(),
            source_cutoff_utc: contract.source_cutoff_utc.clone(),
            as_of_utc: created_at.clone(),
            certifying_clock: true,
            status: if options.observed_outcome == RunOutcome::Pass {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            bridge_task_count,
            claim_count,
            coverage_row_count: contract.coverage_rows.len(),
            harness_family_count: contract.harness_families.len(),
            harness_member_count: contract
                .harness_families
                .iter()
                .map(|family| family.members.len())
                .sum(),
            checks_run: if options.observed_outcome == RunOutcome::Pass {
                1
            } else {
                3
            },
            error_count: report_findings.len(),
            findings: report_findings,
        };
    write_json_file(root, "validation_report.json", &validation_report);

    write_file(
        root,
        "root.Cargo.lock",
        b"# fixture root lock\nversion = 4\n",
    );
    write_file(
        root,
        "tool.Cargo.lock",
        b"# fixture tool lock\nversion = 4\n",
    );
    write_file(
        root,
        "reference/source.snapshot",
        b"franken-core reference source snapshot\n",
    );
    let source_snapshot =
        fs::read(root.join("reference/source.snapshot")).expect("read source snapshot");
    let live_root = live_repo_root();
    let mut source_files = Vec::new();
    for relative in tier_r_source_inputs(&live_root) {
        let bytes = fs::read(live_root.join(&relative))
            .unwrap_or_else(|error| panic!("read Tier-R source input {relative}: {error}"));
        write_file(root, &format!("tier_r_source/{relative}"), &bytes);
        source_files.push(TierRSourceFile {
            path: relative,
            bytes: u64::try_from(bytes.len()).expect("Tier-R source input length"),
            sha256: sha256(&bytes),
        });
    }
    let source_manifest = TierRSourceManifest {
        schema_version: "franken-engine.tier-r-source-manifest.v1".to_string(),
        hash_algorithm: "sha256".to_string(),
        identity_basis: "canonical-json-path-bytes-content-sha256-v1".to_string(),
        files: source_files,
    };
    write_json_file(root, "tier_r_source_manifest.json", &source_manifest);
    let reference_source_sha256 = hash_file(&root.join("tier_r_source_manifest.json"));
    let tier_r_build_environment = TierRBuildEnvironment {
        schema_version: "franken-engine.tier-r-build-environment.v1".to_string(),
        rustc_verbose_version: "rustc 1.fixture\nhost: x86_64-unknown-linux-gnu".to_string(),
        cargo_version: "cargo 1.fixture".to_string(),
        host: TARGET.to_string(),
        target: TARGET.to_string(),
        profile: "release".to_string(),
        opt_level: "3".to_string(),
        requested_toolchain: Some("fixture-toolchain".to_string()),
        active_features: vec!["CARGO_FEATURE_TIER_R_PROBE".to_string()],
        build_flags_source: "none".to_string(),
        build_flags_sha256: sha256(b""),
        builder_identity_source: "HOSTNAME".to_string(),
        builder_identity_sha256: Some(sha256(b"vcc-fixture-builder")),
        source_manifest_sha256: reference_source_sha256.clone(),
    };
    assert!(
        validate_tier_r_build_environment(&tier_r_build_environment).is_empty(),
        "fixture Tier-R build environment must satisfy the public schema"
    );
    write_json_file(
        root,
        "tier_r_build_environment.json",
        &tier_r_build_environment,
    );
    let tier_r_build_environment_sha256 = hash_file(&root.join("tier_r_build_environment.json"));
    let source_tree_sha256 =
        single_file_source_tree_identity("reference/source.snapshot", false, &source_snapshot);

    let reproduction_script = b"#!/bin/sh\nset -eu\nprintf 'reproduction-ok\\n'\n";
    write_file(root, "scripts/reproduce-vcc", reproduction_script);
    make_executable(&root.join("scripts/reproduce-vcc"));
    let tier_script = b"#!/bin/sh\nset -eu\nexec cat \"$1\"\n";
    write_file(root, "tier_r_probe_executable", tier_script);
    make_executable(&root.join("tier_r_probe_executable"));
    let source_identity_script = b"#!/bin/sh\nset -eu\npython3 - <<'PY'\nimport hashlib\nimport struct\npath = b'reference/source.snapshot'\nmode = b'100644'\nwith open(path, 'rb') as source:\n    content = source.read()\ndigest = hashlib.sha256()\nfor value in (path, mode, content):\n    digest.update(struct.pack('<Q', len(value)))\n    digest.update(value)\nprint(digest.hexdigest())\nPY\n";
    write_file(root, "scripts/source-identity", source_identity_script);
    make_executable(&root.join("scripts/source-identity"));
    let identity_output = Command::new(root.join("scripts/source-identity"))
        .current_dir(root)
        .output()
        .expect("execute source-identity fixture");
    assert!(identity_output.status.success());
    assert_eq!(
        String::from_utf8(identity_output.stdout)
            .expect("source identity is UTF-8")
            .trim(),
        source_tree_sha256
    );
    let executable_sha256 =
        sha256(&fs::read(root.join("tier_r_probe_executable")).expect("read executable"));

    let tier_report = valid_tier_r_report(
        RUN_ID,
        TRACE_ID,
        reference_source_sha256.clone(),
        tier_r_build_environment_sha256.clone(),
        executable_sha256.clone(),
    );
    write_json_file(root, "tier_r_probe.json", &tier_report);

    let reproduction_output = Command::new(root.join("scripts/reproduce-vcc"))
        .arg("--locked")
        .current_dir(root)
        .output()
        .expect("execute reproduction fixture");
    assert!(reproduction_output.status.success());
    write_file(root, "reproduction.stdout.log", &reproduction_output.stdout);
    write_file(root, "reproduction.stderr.log", &reproduction_output.stderr);

    let tier_output = Command::new(root.join("tier_r_probe_executable"))
        .arg("tier_r_probe.json")
        .current_dir(root)
        .output()
        .expect("execute Tier-R fixture");
    assert!(tier_output.status.success());
    assert_eq!(
        tier_output.stdout,
        fs::read(root.join("tier_r_probe.json")).expect("read Tier-R report"),
        "invocation stdout must be the retained Tier-R report"
    );
    write_file(root, "tier_r_probe.stderr.log", &tier_output.stderr);

    write_file(root, "guest.stdout.log", &options.guest_stdout);
    write_file(root, "guest.stderr.log", b"");
    write_file(
        root,
        "LEGAL.md",
        b"# Fixture provenance\n\nNo external corpus is embedded.\n",
    );

    let source_diff_sha256 = if options.source_dirty {
        let source_diff = b"diff --git a/reference/source.snapshot b/reference/source.snapshot\n";
        write_file(root, "source.diff", source_diff);
        Some(sha256(source_diff))
    } else {
        None
    };
    let environment = EnvironmentManifest {
        schema_version: "franken-engine.verification-environment.v2".to_string(),
        platform: PLATFORM.to_string(),
        target: TARGET.to_string(),
        tier: TIER.to_string(),
        security_profile: PROFILE.to_string(),
        rustc_version: "rustc fixture".to_string(),
        cargo_version: "cargo fixture".to_string(),
        toolchain: "fixture-toolchain".to_string(),
        toolchain_role: "local_orchestrator".to_string(),
        repository_revision: live_git_revision(),
        source_tree_basis: "sorted-relative-path-mode-length-and-bytes-sha256-v1".to_string(),
        source_identity_command: SOURCE_IDENTITY_COMMAND.to_string(),
        source_state: if options.source_dirty {
            "dirty"
        } else {
            "clean"
        }
        .to_string(),
        source_tree_sha256: source_tree_sha256.clone(),
        source_diff_sha256,
        source_diff_basis: options
            .source_dirty
            .then(|| "git-binary-patch-including-untracked-v1".to_string()),
    };
    write_json_file(root, "env.json", &environment);

    let commands = format!("{REPRODUCTION_COMMAND}\n{TIER_R_COMMAND}\n{SOURCE_IDENTITY_COMMAND}\n");
    write_file(root, "commands.txt", commands.as_bytes());

    let artifact_hashes = BTreeMap::from([("contract.json".to_string(), contract_sha256.clone())]);
    let events = if options.observed_outcome == RunOutcome::Pass {
        passing_events(artifact_hashes)
    } else {
        failing_retry_events(artifact_hashes, options.observed_outcome)
    };
    let event_report = validate_event_stream(&event_bytes(&events));
    assert_eq!(
        event_report.error_count, 0,
        "fixture events must be valid: {:?}",
        event_report.findings
    );
    write_events_jsonl(&root.join("events.jsonl"), &events).expect("write event stream");

    let sample_artifact = match options.sample {
        SampleChoice::Raw => {
            let sample = VerificationSample {
                schema_version: "franken-engine.verification-sample.v1".to_string(),
                sample_id: "fixture-sample".to_string(),
                seed: SEED,
                outcome: options.observed_outcome,
                duration_ns: 11,
                artifact_hashes: BTreeMap::from([(
                    "contract.json".to_string(),
                    contract_sha256.clone(),
                )]),
            };
            let mut bytes = serde_json::to_vec(&sample).expect("serialize raw sample");
            bytes.push(b'\n');
            write_file(root, "samples.jsonl", &bytes);
            SampleArtifact {
                kind: SampleArtifactKind::RawSamples,
                path: "samples.jsonl".to_string(),
            }
        }
        SampleChoice::Minimized => {
            let reduced_sha256 = minimized_seed_identity(SEED, REPRODUCTION_COMMAND);
            let mut original_sha256 = reference_source_sha256.clone();
            if original_sha256 == reduced_sha256 {
                original_sha256 = sha256(b"distinct original failing input");
            }
            let minimized = MinimizedSeed {
                schema_version: "franken-engine.verification-minimized-seed.v1".to_string(),
                seed: SEED,
                original_sha256,
                reduced_sha256,
                reduction_steps: 7,
                reproduction_command: REPRODUCTION_COMMAND.to_string(),
            };
            write_json_file(root, "minimized_seed.json", &minimized);
            SampleArtifact {
                kind: SampleArtifactKind::MinimizedSeed,
                path: "minimized_seed.json".to_string(),
            }
        }
    };

    let reproduction_record = ReproductionRecord {
        schema_version: "franken-engine.verification-reproduction-record.v1".to_string(),
        command: REPRODUCTION_COMMAND.to_string(),
        executed_at_utc: created_at.clone(),
        exit_code: reproduction_output
            .status
            .code()
            .expect("reproduction exit code"),
        stdout_path: "reproduction.stdout.log".to_string(),
        stdout_sha256: sha256(&reproduction_output.stdout),
        stderr_path: "reproduction.stderr.log".to_string(),
        stderr_sha256: sha256(&reproduction_output.stderr),
        cleanup_complete: true,
        rollback_verified: true,
    };
    write_json_file(root, "reproduction_record.json", &reproduction_record);

    let tier_invocation = TierRInvocationRecord {
        schema_version: "franken-engine.tier-r-invocation.v1".to_string(),
        command: TIER_R_COMMAND.to_string(),
        executed_at_utc: created_at.clone(),
        exit_code: tier_output.status.code().expect("Tier-R exit code"),
        stdout_path: "tier_r_probe.json".to_string(),
        stdout_sha256: sha256(&tier_output.stdout),
        stderr_path: "tier_r_probe.stderr.log".to_string(),
        stderr_sha256: sha256(&tier_output.stderr),
        executable_path: "tier_r_probe_executable".to_string(),
        executable_sha256,
    };
    write_json_file(root, "tier_r_invocation.json", &tier_invocation);

    let repro_lock = ReproLock {
        schema_version: "franken-engine.verification-repro-lock.v1".to_string(),
        source_tree_sha256,
        cargo_lock_sha256: hash_file(&root.join("root.Cargo.lock")),
        tool_lock_sha256: hash_file(&root.join("tool.Cargo.lock")),
        contract_sha256,
        generated_contract_sha256: generated_sha256,
        commands_sha256: hash_file(&root.join("commands.txt")),
        tier_r_source_sha256: tier_report.reference_source_sha256.clone(),
        tier_r_build_environment_sha256: tier_report.build_environment_sha256.clone(),
    };
    write_json_file(root, "repro.lock", &repro_lock);

    let mut required_files = inventory_paths(root);
    required_files.extend([
        "artifact_manifest.json".to_string(),
        "provenance_graph.json".to_string(),
        "run_manifest.json".to_string(),
    ]);
    required_files.sort();
    required_files.dedup();

    let run_manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        run_id: RUN_ID.to_string(),
        trace_id: TRACE_ID.to_string(),
        test_id: TEST_ID.to_string(),
        scenario_id: SCENARIO_ID.to_string(),
        seed: SEED,
        attempt: 1,
        platform: PLATFORM.to_string(),
        target: TARGET.to_string(),
        tier: TIER.to_string(),
        security_profile: PROFILE.to_string(),
        created_at_utc: created_at,
        clock_source: "witnessed_wall_clock".to_string(),
        expected_outcome: options.expected_outcome,
        observed_outcome: options.observed_outcome,
        exit_code: if options.observed_outcome == RunOutcome::Pass {
            0
        } else {
            1
        },
        first_failure: event_report.first_failure,
        reproduction_command: REPRODUCTION_COMMAND.to_string(),
        artifact_manifest: "artifact_manifest.json".to_string(),
        contract: "contract.json".to_string(),
        generated_contract: "generated_contract.json".to_string(),
        rendered_markdown: "rendered_contract.md".to_string(),
        validation_report: "validation_report.json".to_string(),
        events: "events.jsonl".to_string(),
        tier_r_probe: "tier_r_probe.json".to_string(),
        tier_r_source_manifest: "tier_r_source_manifest.json".to_string(),
        tier_r_build_environment: "tier_r_build_environment.json".to_string(),
        sample_artifact,
        required_files,
        guest_stdout: "guest.stdout.log".to_string(),
        guest_stderr: "guest.stderr.log".to_string(),
    };
    write_json_file(root, "run_manifest.json", &run_manifest);
    write_provenance_graph(root);
    write_artifact_manifest(root).expect("write artifact manifest");

    let manifest: RunManifest = read_json(&root.join("run_manifest.json"));
    assert_eq!(
        manifest.required_files,
        inventory_paths(root),
        "run manifest must bind the exact sorted inventory"
    );
    directory
}

fn write_provenance_graph(root: &Path) {
    let paths = inventory_paths(root);
    let mut nodes = vec![ProvenanceNode {
        node_id: "requirement-root".to_string(),
        kind: "requirement".to_string(),
        sha256: Some(hash_file(&root.join("contract.json"))),
        artifact_path: None,
    }];
    let mut artifact_node_ids = Vec::new();
    let mut verdict_id = String::new();
    for (index, path) in paths
        .iter()
        .filter(|path| {
            !matches!(
                path.as_str(),
                "artifact_manifest.json" | "provenance_graph.json"
            )
        })
        .enumerate()
    {
        let node_id = format!("artifact-{index:03}");
        let kind = match path.as_str() {
            "run_manifest.json" => "run",
            "events.jsonl" => "event_stream",
            "validation_report.json" => {
                verdict_id.clone_from(&node_id);
                "verdict"
            }
            _ => "artifact",
        };
        nodes.push(ProvenanceNode {
            node_id: node_id.clone(),
            kind: kind.to_string(),
            sha256: Some(hash_file(&root.join(path))),
            artifact_path: Some(path.clone()),
        });
        artifact_node_ids.push(node_id);
    }
    assert!(!verdict_id.is_empty(), "validation report provenance node");

    let mut edges = Vec::new();
    for node_id in &artifact_node_ids {
        edges.push(ProvenanceEdge {
            from: "requirement-root".to_string(),
            relation: "requires".to_string(),
            to: node_id.clone(),
        });
        if node_id != &verdict_id {
            edges.push(ProvenanceEdge {
                from: node_id.clone(),
                relation: "contributes_to".to_string(),
                to: verdict_id.clone(),
            });
        }
    }
    let graph = ProvenanceGraph {
        schema_version: "franken-engine.verification-provenance-graph.v1".to_string(),
        nodes,
        edges,
    };
    write_json_file(root, "provenance_graph.json", &graph);
}

fn write_file(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("artifact parent")).expect("create artifact parent");
    fs::write(path, bytes).expect("write artifact");
}

fn write_json_file<T: Serialize>(root: &Path, relative: &str, value: &T) {
    write_file(root, relative, &pretty_json_bytes(value));
}

fn pretty_json_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize JSON artifact");
    bytes.push(b'\n');
    bytes
}

fn read_json<T: DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&fs::read(path).expect("read JSON file")).expect("parse JSON file")
}

fn jsonl_values(values: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        serde_json::to_writer(&mut bytes, value).expect("serialize JSONL value");
        bytes.push(b'\n');
    }
    bytes
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn single_file_source_tree_identity(relative: &str, executable: bool, bytes: &[u8]) -> String {
    let mode = if executable { b"100755" } else { b"100644" };
    let mut digest = Sha256::new();
    for value in [relative.as_bytes(), mode.as_slice(), bytes] {
        digest.update(
            u64::try_from(value.len())
                .expect("source identity component length")
                .to_le_bytes(),
        );
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

fn live_git_revision() -> String {
    static REVISION: OnceLock<String> = OnceLock::new();
    REVISION
        .get_or_init(|| {
            let output = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(live_repo_root())
                .output()
                .expect("execute git revision query");
            assert!(output.status.success(), "git revision query must succeed");
            let revision = String::from_utf8(output.stdout)
                .expect("git revision is UTF-8")
                .trim()
                .to_string();
            assert!(
                matches!(revision.len(), 40 | 64)
                    && revision
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "git revision must be a lowercase object ID"
            );
            revision
        })
        .clone()
}

fn hash_file(path: &Path) -> String {
    sha256(&fs::read(path).expect("read hash input"))
}

fn inventory_paths(root: &Path) -> Vec<String> {
    fn visit(root: &Path, directory: &Path, paths: &mut Vec<String>) {
        for entry in fs::read_dir(directory).expect("read bundle directory") {
            let entry = entry.expect("read bundle entry");
            let file_type = entry.file_type().expect("inspect bundle entry");
            if file_type.is_dir() {
                visit(root, &entry.path(), paths);
            } else if file_type.is_file() {
                paths.push(
                    entry
                        .path()
                        .strip_prefix(root)
                        .expect("bundle relative path")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let mut paths = Vec::new();
    visit(root, root, &mut paths);
    paths.sort();
    paths
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)
            .expect("executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("set executable permissions");
    }
}

fn rehash_artifact_manifest(root: &Path) {
    let files = inventory_paths(root)
        .into_iter()
        .filter(|path| path != "artifact_manifest.json")
        .map(|path| {
            let bytes = fs::read(root.join(&path)).expect("read artifact for rehash");
            ArtifactDigest {
                path,
                sha256: sha256(&bytes),
                bytes: u64::try_from(bytes.len()).expect("artifact size"),
            }
        })
        .collect();
    let manifest = ArtifactManifest {
        schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
        hash_algorithm: "sha256".to_string(),
        files,
    };
    fs::write(
        root.join("artifact_manifest.json"),
        pretty_json_bytes(&manifest),
    )
    .expect("rewrite mutation manifest");
}

fn coordinate_tier_r_build_environment_rewrite(root: &Path) {
    let build_environment_sha256 = hash_file(&root.join("tier_r_build_environment.json"));

    let probe_path = root.join("tier_r_probe.json");
    let mut probe: TierRProbeReport = read_json(&probe_path);
    probe.build_environment_sha256 = build_environment_sha256.clone();
    fs::write(&probe_path, pretty_json_bytes(&probe))
        .expect("bind probe to rewritten Tier-R build environment");

    let invocation_path = root.join("tier_r_invocation.json");
    let mut invocation: TierRInvocationRecord = read_json(&invocation_path);
    invocation.stdout_sha256 = hash_file(&probe_path);
    fs::write(invocation_path, pretty_json_bytes(&invocation))
        .expect("bind invocation to rewritten Tier-R probe");

    let lock_path = root.join("repro.lock");
    let mut lock: ReproLock = read_json(&lock_path);
    lock.tier_r_build_environment_sha256 = build_environment_sha256;
    fs::write(lock_path, pretty_json_bytes(&lock))
        .expect("bind reproduction lock to rewritten Tier-R build environment");

    write_provenance_graph(root);
    rehash_artifact_manifest(root);
}

fn assert_bundle_code(
    report: &frankenengine_engine::verification_coverage_contract::BundleValidationReport,
    expected: &str,
) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.error_code == expected),
        "expected {expected}; findings: {:?}",
        report.findings
    );
}

#[test]
fn complete_raw_sample_bundle_passes_with_real_hashes_and_executions() {
    let bundle = build_bundle(BundleOptions::passing_raw());
    let report = validate_bundle(bundle.path());
    assert_eq!(report.error_count, 0, "{:?}", report.findings);
    assert_eq!(report.event_count, 3);

    let manifest: ArtifactManifest = read_json(&bundle.path().join("artifact_manifest.json"));
    assert!(manifest.files.iter().all(|entry| {
        let bytes = fs::read(bundle.path().join(&entry.path)).expect("read manifested artifact");
        entry.bytes == bytes.len() as u64 && entry.sha256 == sha256(&bytes)
    }));
}

#[test]
fn complete_minimized_failure_bundle_preserves_expected_observed_difference() {
    let bundle = build_bundle(BundleOptions::failing_minimized());
    let report = validate_bundle(bundle.path());
    assert_eq!(
        report.error_count, 0,
        "truthful observed failure is a valid evidence bundle: {:?}",
        report.findings
    );
    assert_eq!(report.event_count, 5);

    let manifest: RunManifest = read_json(&bundle.path().join("run_manifest.json"));
    assert_eq!(manifest.expected_outcome, RunOutcome::Pass);
    assert_eq!(manifest.observed_outcome, RunOutcome::Fail);
    assert_eq!(manifest.exit_code, 1);
    assert_eq!(
        manifest.first_failure,
        Some(FailureReference {
            sequence: 2,
            reason_code: ERROR_IO.to_string(),
        })
    );
    let minimized: MinimizedSeed = read_json(&bundle.path().join("minimized_seed.json"));
    assert_eq!(
        minimized.reduced_sha256,
        minimized_seed_identity(minimized.seed, &minimized.reproduction_command)
    );
}

#[test]
fn raw_sample_seed_outcome_and_artifact_binding_mutants_fail() {
    for mutation in ["seed", "outcome", "artifact"] {
        let bundle = build_bundle(BundleOptions::passing_raw());
        let path = bundle.path().join("samples.jsonl");
        let mut sample: VerificationSample =
            serde_json::from_str(fs::read_to_string(&path).expect("read sample").trim_end())
                .expect("parse sample");
        match mutation {
            "seed" => sample.seed = sample.seed.wrapping_add(1),
            "outcome" => sample.outcome = RunOutcome::Fail,
            "artifact" => {
                sample
                    .artifact_hashes
                    .insert("contract.json".to_string(), sha256(b"unbound"));
            }
            _ => unreachable!(),
        }
        let mut bytes = serde_json::to_vec(&sample).expect("serialize sample mutant");
        bytes.push(b'\n');
        fs::write(path, bytes).expect("write sample mutant");
        rehash_artifact_manifest(bundle.path());
        assert_bundle_code(&validate_bundle(bundle.path()), ERROR_ARTIFACT_CONTRACT);
    }
}

#[test]
fn guest_event_spoof_is_isolated_from_harness_event_count() {
    let spoof = serde_json::to_vec(&passing_events(BTreeMap::new())[1])
        .expect("serialize guest spoof event");
    let mut options = BundleOptions::passing_raw();
    options.guest_stdout = spoof;
    let bundle = build_bundle(options);
    let report = validate_bundle(bundle.path());
    assert_eq!(report.error_count, 0, "{:?}", report.findings);
    assert_eq!(
        report.event_count, 3,
        "guest stdout must never be parsed as harness events"
    );
}

#[test]
fn bundle_path_traversal_outcome_event_and_artifact_mismatches_fail() {
    let traversal = build_bundle(BundleOptions::passing_raw());
    let mut manifest: RunManifest = read_json(&traversal.path().join("run_manifest.json"));
    manifest.sample_artifact.path = "../samples.jsonl".to_string();
    write_json_file(traversal.path(), "run_manifest.json", &manifest);
    rehash_artifact_manifest(traversal.path());
    assert_bundle_code(&validate_bundle(traversal.path()), ERROR_ARTIFACT_CONTRACT);

    let outcome = build_bundle(BundleOptions::passing_raw());
    let mut manifest: RunManifest = read_json(&outcome.path().join("run_manifest.json"));
    manifest.observed_outcome = RunOutcome::Fail;
    write_json_file(outcome.path(), "run_manifest.json", &manifest);
    rehash_artifact_manifest(outcome.path());
    assert_bundle_code(&validate_bundle(outcome.path()), ERROR_OUTCOME_MISMATCH);

    let artifact = build_bundle(BundleOptions::passing_raw());
    let mut events: Vec<VerificationEvent> =
        fs::read_to_string(artifact.path().join("events.jsonl"))
            .expect("read events")
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse event"))
            .collect();
    events[1]
        .artifact_hashes
        .insert("contract.json".to_string(), sha256(b"mismatched contract"));
    fs::write(artifact.path().join("events.jsonl"), event_bytes(&events))
        .expect("write artifact mismatch");
    rehash_artifact_manifest(artifact.path());
    assert_bundle_code(&validate_bundle(artifact.path()), ERROR_PROVENANCE);
}

#[test]
fn provenance_graph_kind_hash_and_reachability_mutants_fail() {
    for mutation in [
        "requirement_hash",
        "run_kind",
        "artifact_hash",
        "reachability",
    ] {
        let bundle = build_bundle(BundleOptions::passing_raw());
        let path = bundle.path().join("provenance_graph.json");
        let mut graph: ProvenanceGraph = read_json(&path);
        match mutation {
            "requirement_hash" => {
                graph
                    .nodes
                    .iter_mut()
                    .find(|node| node.kind == "requirement")
                    .expect("requirement node")
                    .sha256 = Some(sha256(b"wrong requirement"));
            }
            "run_kind" => {
                graph
                    .nodes
                    .iter_mut()
                    .find(|node| node.artifact_path.as_deref() == Some("run_manifest.json"))
                    .expect("run node")
                    .kind = "artifact".to_string();
            }
            "artifact_hash" => {
                graph
                    .nodes
                    .iter_mut()
                    .find(|node| node.artifact_path.as_deref() == Some("contract.json"))
                    .expect("contract node")
                    .sha256 = Some(sha256(b"wrong contract commitment"));
            }
            "reachability" => {
                let run_node = graph
                    .nodes
                    .iter()
                    .find(|node| node.kind == "run")
                    .expect("run node")
                    .node_id
                    .clone();
                graph
                    .edges
                    .retain(|edge| edge.to != run_node || edge.from != "requirement-root");
            }
            _ => unreachable!(),
        }
        fs::write(path, pretty_json_bytes(&graph)).expect("write provenance mutant");
        rehash_artifact_manifest(bundle.path());
        assert_bundle_code(&validate_bundle(bundle.path()), ERROR_PROVENANCE);
    }
}

#[test]
fn reproduction_lock_clock_and_cleanup_mutants_fail_closed() {
    for field in ["cleanup", "rollback"] {
        let bundle = build_bundle(BundleOptions::passing_raw());
        let path = bundle.path().join("reproduction_record.json");
        let mut record: ReproductionRecord = read_json(&path);
        if field == "cleanup" {
            record.cleanup_complete = false;
        } else {
            record.rollback_verified = false;
        }
        fs::write(path, pretty_json_bytes(&record)).expect("write reproduction mutant");
        rehash_artifact_manifest(bundle.path());
        assert_bundle_code(&validate_bundle(bundle.path()), ERROR_REPRODUCTION);
    }

    let lock = build_bundle(BundleOptions::passing_raw());
    let path = lock.path().join("repro.lock");
    let mut repro_lock: ReproLock = read_json(&path);
    repro_lock.cargo_lock_sha256 = sha256(b"unbound root lock");
    fs::write(path, pretty_json_bytes(&repro_lock)).expect("write repro-lock mutant");
    rehash_artifact_manifest(lock.path());
    assert_bundle_code(&validate_bundle(lock.path()), ERROR_PROVENANCE);

    let report = build_bundle(BundleOptions::passing_raw());
    let path = report.path().join("validation_report.json");
    let mut validation: frankenengine_engine::verification_coverage_contract::ValidationReport =
        read_json(&path);
    validation.certifying_clock = false;
    fs::write(path, pretty_json_bytes(&validation)).expect("write clock mutant");
    rehash_artifact_manifest(report.path());
    assert_bundle_code(&validate_bundle(report.path()), ERROR_PROVENANCE);

    let manifest = build_bundle(BundleOptions::passing_raw());
    let path = manifest.path().join("run_manifest.json");
    let mut run_manifest: RunManifest = read_json(&path);
    run_manifest.clock_source = "synthetic_test_clock".to_string();
    fs::write(path, pretty_json_bytes(&run_manifest)).expect("write run clock mutant");
    rehash_artifact_manifest(manifest.path());
    assert_bundle_code(&validate_bundle(manifest.path()), ERROR_CLOCK_AUTHORITY);
}

#[test]
fn tier_r_bundle_executable_and_stage_mutations_fail_closed() {
    for mutation in ["executable", "stage"] {
        let bundle = build_bundle(BundleOptions::passing_raw());
        let path = bundle.path().join("tier_r_probe.json");
        let mut report: TierRProbeReport = read_json(&path);
        match mutation {
            "executable" => report.probe_executable_sha256 = sha256(b"different executable"),
            "stage" => report.stage_events.swap(0, 1),
            _ => unreachable!(),
        }
        fs::write(path, pretty_json_bytes(&report)).expect("write Tier-R mutant");
        rehash_artifact_manifest(bundle.path());
        let expected = if mutation == "executable" {
            ERROR_TIER_R_TRUTH
        } else {
            ERROR_BRANCH_PROOF
        };
        assert_bundle_code(&validate_bundle(bundle.path()), expected);
    }
}

#[test]
fn tier_r_source_digest_cannot_be_forged_by_coordinating_report_and_lock() {
    let bundle = build_bundle(BundleOptions::passing_raw());
    let forged = sha256(b"attacker-selected unmanifested Tier-R source");

    let probe_path = bundle.path().join("tier_r_probe.json");
    let mut probe: TierRProbeReport = read_json(&probe_path);
    probe.reference_source_sha256 = forged.clone();
    fs::write(&probe_path, pretty_json_bytes(&probe)).expect("write forged probe source digest");

    let lock_path = bundle.path().join("repro.lock");
    let mut lock: ReproLock = read_json(&lock_path);
    lock.tier_r_source_sha256 = forged;
    fs::write(lock_path, pretty_json_bytes(&lock)).expect("write coordinated forged lock");

    let invocation_path = bundle.path().join("tier_r_invocation.json");
    let mut invocation: TierRInvocationRecord = read_json(&invocation_path);
    invocation.stdout_sha256 = hash_file(&probe_path);
    fs::write(invocation_path, pretty_json_bytes(&invocation))
        .expect("write coordinated forged invocation");

    write_provenance_graph(bundle.path());
    rehash_artifact_manifest(bundle.path());
    assert_bundle_code(&validate_bundle(bundle.path()), ERROR_TIER_R_TRUTH);
}

#[test]
fn tier_r_source_manifest_entries_bind_actual_manifested_bytes() {
    let changed_source = build_bundle(BundleOptions::passing_raw());
    let source_path = changed_source
        .path()
        .join("tier_r_source/crates/franken-core/src/lib.rs");
    let mut source_bytes = fs::read(&source_path).expect("read Tier-R source artifact");
    source_bytes.extend_from_slice(b"\n// post-build unbound source mutation\n");
    fs::write(&source_path, source_bytes).expect("write Tier-R source artifact mutant");
    write_provenance_graph(changed_source.path());
    rehash_artifact_manifest(changed_source.path());
    assert_bundle_code(&validate_bundle(changed_source.path()), ERROR_TIER_R_TRUTH);

    let forged_claim = build_bundle(BundleOptions::passing_raw());
    let source_manifest_path = forged_claim.path().join("tier_r_source_manifest.json");
    let mut source_manifest: TierRSourceManifest = read_json(&source_manifest_path);
    source_manifest.files[0].sha256 = sha256(b"forged source-entry claim");
    fs::write(&source_manifest_path, pretty_json_bytes(&source_manifest))
        .expect("write forged Tier-R source manifest");
    let forged_source_identity = hash_file(&source_manifest_path);

    let probe_path = forged_claim.path().join("tier_r_probe.json");
    let mut probe: TierRProbeReport = read_json(&probe_path);
    probe.reference_source_sha256 = forged_source_identity.clone();
    fs::write(&probe_path, pretty_json_bytes(&probe))
        .expect("bind probe to forged source manifest");

    let lock_path = forged_claim.path().join("repro.lock");
    let mut lock: ReproLock = read_json(&lock_path);
    lock.tier_r_source_sha256 = forged_source_identity;
    fs::write(lock_path, pretty_json_bytes(&lock)).expect("bind lock to forged source manifest");

    let invocation_path = forged_claim.path().join("tier_r_invocation.json");
    let mut invocation: TierRInvocationRecord = read_json(&invocation_path);
    invocation.stdout_sha256 = hash_file(&probe_path);
    fs::write(invocation_path, pretty_json_bytes(&invocation))
        .expect("bind invocation to coordinated forged probe");

    write_provenance_graph(forged_claim.path());
    rehash_artifact_manifest(forged_claim.path());
    assert_bundle_code(&validate_bundle(forged_claim.path()), ERROR_TIER_R_TRUTH);
}

#[test]
fn v2_build_environment_rejects_invalid_and_noncanonical_artifacts() {
    for mutation in ["invalid_profile", "noncanonical_json"] {
        let bundle = build_bundle(BundleOptions::passing_raw());
        let path = bundle.path().join("tier_r_build_environment.json");
        let mut environment: TierRBuildEnvironment = read_json(&path);
        if mutation == "invalid_profile" {
            environment.profile = "debug".to_string();
            fs::write(&path, pretty_json_bytes(&environment))
                .expect("write invalid Tier-R build profile");
        } else {
            fs::write(
                &path,
                serde_json::to_vec(&environment)
                    .expect("serialize noncanonical Tier-R build environment"),
            )
            .expect("write noncanonical Tier-R build environment");
        }
        coordinate_tier_r_build_environment_rewrite(bundle.path());
        assert_bundle_code(&validate_bundle(bundle.path()), ERROR_TIER_R_TRUTH);
    }
}

#[test]
fn v2_build_environment_source_manifest_digest_must_match() {
    let bundle = build_bundle(BundleOptions::passing_raw());
    let path = bundle.path().join("tier_r_build_environment.json");
    let mut environment: TierRBuildEnvironment = read_json(&path);
    environment.source_manifest_sha256 = "1".repeat(64);
    fs::write(path, pretty_json_bytes(&environment))
        .expect("write Tier-R source-manifest digest mismatch");
    coordinate_tier_r_build_environment_rewrite(bundle.path());
    assert_bundle_code(&validate_bundle(bundle.path()), ERROR_TIER_R_TRUTH);
}

#[test]
fn v2_probe_build_environment_digest_must_match_artifact() {
    let bundle = build_bundle(BundleOptions::passing_raw());
    let probe_path = bundle.path().join("tier_r_probe.json");
    let mut probe: TierRProbeReport = read_json(&probe_path);
    probe.build_environment_sha256 = "1".repeat(64);
    fs::write(&probe_path, pretty_json_bytes(&probe))
        .expect("write probe build-environment digest mismatch");

    let invocation_path = bundle.path().join("tier_r_invocation.json");
    let mut invocation: TierRInvocationRecord = read_json(&invocation_path);
    invocation.stdout_sha256 = hash_file(&probe_path);
    fs::write(invocation_path, pretty_json_bytes(&invocation))
        .expect("bind invocation to rewritten probe");
    write_provenance_graph(bundle.path());
    rehash_artifact_manifest(bundle.path());
    assert_bundle_code(&validate_bundle(bundle.path()), ERROR_TIER_R_TRUTH);
}

#[test]
fn v2_repro_lock_build_environment_digest_must_match_artifact() {
    let bundle = build_bundle(BundleOptions::passing_raw());
    let path = bundle.path().join("repro.lock");
    let mut lock: ReproLock = read_json(&path);
    lock.tier_r_build_environment_sha256 = "1".repeat(64);
    fs::write(path, pretty_json_bytes(&lock))
        .expect("write reproduction-lock build-environment mismatch");
    write_provenance_graph(bundle.path());
    rehash_artifact_manifest(bundle.path());
    assert_bundle_code(&validate_bundle(bundle.path()), ERROR_PROVENANCE);
}

#[test]
fn v2_run_manifest_requires_exact_tier_r_artifact_paths() {
    for field in ["source_manifest", "build_environment"] {
        let bundle = build_bundle(BundleOptions::passing_raw());
        let path = bundle.path().join("run_manifest.json");
        let mut manifest: RunManifest = read_json(&path);
        if field == "source_manifest" {
            manifest.tier_r_source_manifest = "tier_r_source_manifest-v2.json".to_string();
        } else {
            manifest.tier_r_build_environment = "tier_r_build_environment-v2.json".to_string();
        }
        fs::write(path, pretty_json_bytes(&manifest))
            .expect("write run-manifest Tier-R path mismatch");
        write_provenance_graph(bundle.path());
        rehash_artifact_manifest(bundle.path());
        assert_bundle_code(&validate_bundle(bundle.path()), ERROR_ARTIFACT_CONTRACT);
    }
}

#[test]
fn v2_environment_requires_local_orchestrator_toolchain_role() {
    let bundle = build_bundle(BundleOptions::passing_raw());
    let path = bundle.path().join("env.json");
    let mut environment: EnvironmentManifest = read_json(&path);
    environment.toolchain_role = "tier_r_builder".to_string();
    fs::write(path, pretty_json_bytes(&environment))
        .expect("write environment toolchain-role mismatch");
    write_provenance_graph(bundle.path());
    rehash_artifact_manifest(bundle.path());
    assert_bundle_code(&validate_bundle(bundle.path()), ERROR_ARTIFACT_CONTRACT);
}

#[test]
fn v2_environment_rejects_v1_schema() {
    let bundle = build_bundle(BundleOptions::passing_raw());
    let path = bundle.path().join("env.json");
    let mut environment: EnvironmentManifest = read_json(&path);
    environment.schema_version = "franken-engine.verification-environment.v1".to_string();
    fs::write(path, pretty_json_bytes(&environment)).expect("write v1 environment schema");
    write_provenance_graph(bundle.path());
    rehash_artifact_manifest(bundle.path());
    assert_bundle_code(&validate_bundle(bundle.path()), ERROR_ARTIFACT_CONTRACT);
}

#[test]
fn dirty_environment_requires_a_bound_diff_basis_and_identity_command() {
    let bundle = build_bundle(BundleOptions::passing_raw_dirty());
    let report = validate_bundle(bundle.path());
    assert_eq!(
        report.error_count, 0,
        "a complete dirty-state witness must validate: {:?}",
        report.findings
    );

    let mutant = build_bundle(BundleOptions::passing_raw_dirty());
    let path = mutant.path().join("env.json");
    let mut environment: EnvironmentManifest = read_json(&path);
    environment.source_diff_basis = Some("unspecified-diff".to_string());
    fs::write(path, pretty_json_bytes(&environment)).expect("write dirty environment mutant");
    rehash_artifact_manifest(mutant.path());
    assert_bundle_code(&validate_bundle(mutant.path()), ERROR_ARTIFACT_CONTRACT);
}

#[cfg(unix)]
#[test]
fn bundle_symlink_is_rejected_before_hash_validation() {
    use std::os::unix::fs::symlink;

    let bundle = build_bundle(BundleOptions::passing_raw());
    symlink("contract.json", bundle.path().join("linked-contract")).expect("create bundle symlink");
    assert_bundle_code(&validate_bundle(bundle.path()), ERROR_UNSAFE_PATH);
}

#[test]
fn bundle_file_count_and_file_size_bounds_fail_before_allocation() {
    let count = build_bundle(BundleOptions::passing_raw());
    let contract = load_contract(authority_fixture_root());
    fs::create_dir_all(count.path().join("overflow")).expect("create overflow directory");
    let existing = inventory_paths(count.path()).len();
    for index in 0..=contract
        .artifact_contract
        .max_files
        .saturating_sub(existing)
    {
        fs::write(count.path().join(format!("overflow/{index:04}.bin")), b"x")
            .expect("write overflow artifact");
    }
    assert_bundle_code(&validate_bundle(count.path()), ERROR_BOUNDS);

    let size = build_bundle(BundleOptions::passing_raw());
    let oversized = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(size.path().join("oversized.bin"))
        .expect("create sparse oversized file");
    oversized
        .set_len(contract.artifact_contract.max_file_bytes + 1)
        .expect("extend sparse oversized file");
    assert_bundle_code(&validate_bundle(size.path()), ERROR_BOUNDS);

    let directories = build_bundle(BundleOptions::passing_raw());
    for index in 0..=contract.artifact_contract.max_directories {
        fs::create_dir_all(directories.path().join(format!("directories/{index:04}")))
            .expect("create bounded directory mutant");
    }
    assert_bundle_code(&validate_bundle(directories.path()), ERROR_BOUNDS);

    let depth = build_bundle(BundleOptions::passing_raw());
    let mut nested = depth.path().to_path_buf();
    for index in 0..=contract.artifact_contract.max_depth {
        nested.push(format!("depth-{index:02}"));
    }
    fs::create_dir_all(&nested).expect("create over-deep bundle path");
    fs::write(nested.join("leaf.bin"), b"x").expect("write over-deep leaf");
    assert_bundle_code(&validate_bundle(depth.path()), ERROR_BOUNDS);

    let total = build_bundle(BundleOptions::passing_raw());
    for index in 0..4 {
        let sparse = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(total.path().join(format!("total-{index}.bin")))
            .expect("create sparse total-size artifact");
        sparse
            .set_len(contract.artifact_contract.max_file_bytes)
            .expect("extend sparse total-size artifact");
    }
    assert_bundle_code(&validate_bundle(total.path()), ERROR_BOUNDS);
}

#[test]
fn every_textual_artifact_surface_rejects_secret_material() {
    let inventory_bundle = build_bundle(BundleOptions::passing_raw());
    let manifest: ArtifactManifest =
        read_json(&inventory_bundle.path().join("artifact_manifest.json"));
    let mut textual_paths: Vec<String> = manifest
        .files
        .iter()
        .filter(|entry| textual_path(&entry.path))
        .map(|entry| entry.path.clone())
        .collect();
    textual_paths.extend([
        "artifact_manifest.json".to_string(),
        "tier_r_probe_executable".to_string(),
        "scripts/reproduce-vcc".to_string(),
        "scripts/source-identity".to_string(),
    ]);
    textual_paths.sort();

    for path in textual_paths {
        let bundle = build_bundle(BundleOptions::passing_raw());
        inject_secret(bundle.path(), &path);
        if path != "artifact_manifest.json" {
            rehash_artifact_manifest(bundle.path());
        }
        let report = validate_bundle(bundle.path());
        assert_bundle_code(&report, ERROR_SECRET_LEAK);
    }

    let minimized = build_bundle(BundleOptions::failing_minimized());
    inject_secret(minimized.path(), "minimized_seed.json");
    rehash_artifact_manifest(minimized.path());
    assert_bundle_code(&validate_bundle(minimized.path()), ERROR_SECRET_LEAK);

    let dirty = build_bundle(BundleOptions::passing_raw_dirty());
    inject_secret(dirty.path(), "source.diff");
    rehash_artifact_manifest(dirty.path());
    assert_bundle_code(&validate_bundle(dirty.path()), ERROR_SECRET_LEAK);
}

fn textual_path(path: &str) -> bool {
    [
        ".json", ".jsonl", ".txt", ".md", ".log", ".lock", ".sh", ".ps1", ".toml",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

fn inject_secret(root: &Path, relative: &str) {
    match relative {
        "contract.json" | "generated_contract.json" => {
            let mut contract: VerificationCoverageContract = read_json(&root.join(relative));
            contract.purpose = SECRET_PROBE.to_string();
            fs::write(
                root.join(relative),
                canonical_json_bytes(&contract).expect("serialize contract secret mutant"),
            )
            .expect("write contract secret mutant");
        }
        "events.jsonl" => {
            let mut events: Vec<VerificationEvent> = fs::read_to_string(root.join(relative))
                .expect("read events")
                .lines()
                .map(|line| serde_json::from_str(line).expect("parse event"))
                .collect();
            events[0].reason = SECRET_PROBE.to_string();
            fs::write(root.join(relative), event_bytes(&events))
                .expect("write event secret mutant");
        }
        "samples.jsonl" => {
            let path = root.join(relative);
            let mut sample: VerificationSample =
                serde_json::from_str(fs::read_to_string(&path).expect("read sample").trim_end())
                    .expect("parse sample");
            sample.sample_id = SECRET_PROBE.to_string();
            let mut bytes = serde_json::to_vec(&sample).expect("serialize sample");
            bytes.push(b'\n');
            fs::write(path, bytes).expect("write sample secret mutant");
        }
        "run_manifest.json" => {
            let mut value: RunManifest = read_json(&root.join(relative));
            value.scenario_id = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "artifact_manifest.json" => {
            let mut value: ArtifactManifest = read_json(&root.join(relative));
            value.hash_algorithm = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "validation_report.json" => {
            let mut value: frankenengine_engine::verification_coverage_contract::ValidationReport =
                read_json(&root.join(relative));
            value.contract_path = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "env.json" => {
            let mut value: EnvironmentManifest = read_json(&root.join(relative));
            value.rustc_version = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "repro.lock" => {
            let mut value: ReproLock = read_json(&root.join(relative));
            value.schema_version = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "reproduction_record.json" => {
            let mut value: ReproductionRecord = read_json(&root.join(relative));
            value.command = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "tier_r_probe.json" => {
            let mut value: TierRProbeReport = read_json(&root.join(relative));
            value.implementation_truth = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "tier_r_invocation.json" => {
            let mut value: TierRInvocationRecord = read_json(&root.join(relative));
            value.command = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "provenance_graph.json" => {
            let mut value: ProvenanceGraph = read_json(&root.join(relative));
            value.schema_version = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        "minimized_seed.json" => {
            let mut value: MinimizedSeed = read_json(&root.join(relative));
            value.reproduction_command = SECRET_PROBE.to_string();
            write_json_file(root, relative, &value);
        }
        _ => {
            let path = root.join(relative);
            let mut bytes = fs::read(&path).expect("read textual artifact");
            bytes.extend_from_slice(format!("\n{SECRET_PROBE}\n").as_bytes());
            fs::write(path, bytes).expect("write textual secret mutant");
        }
    }
}

#[test]
fn bundle_report_redacts_secret_bearing_paths_and_diagnostics() {
    let hostile = TempBuilder::new()
        .prefix("token=path-secret-value")
        .tempdir()
        .expect("create hostile path fixture");
    let report = validate_bundle(hostile.path());
    let serialized = serde_json::to_string(&report).expect("serialize hostile-path report");
    assert!(
        !serialized.contains("path-secret-value"),
        "structured bundle diagnostics must redact secret-bearing paths: {serialized}"
    );
}

fn cli_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_franken_verification_coverage_contract"))
}

#[test]
fn cli_help_usage_unknown_and_malformed_event_exit_codes_are_stable() {
    let help = Command::new(cli_binary())
        .arg("--help")
        .output()
        .expect("run CLI help");
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("usage:"));

    let no_args = Command::new(cli_binary())
        .output()
        .expect("run CLI without command");
    assert_eq!(no_args.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&no_args.stderr).contains("usage:"));

    let unknown = Command::new(cli_binary())
        .arg("unknown-command")
        .output()
        .expect("run CLI unknown command");
    assert_eq!(unknown.status.code(), Some(2));

    let directory = tempdir().expect("CLI malformed event fixture");
    let events = directory.path().join("events.jsonl");
    fs::write(&events, b"{not-json}\n").expect("write malformed events");
    let malformed = Command::new(cli_binary())
        .args(["validate-events", "--events"])
        .arg(&events)
        .output()
        .expect("run malformed event validation");
    assert_eq!(malformed.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&malformed.stdout).expect("parse CLI event report");
    assert_eq!(report["status"], "fail");
    assert!(report["error_count"].as_u64().unwrap_or_default() > 0);

    let blank_identity = Command::new(cli_binary())
        .args(["validate", "--repo-root"])
        .arg(authority_fixture_root())
        .args(["--run-id", ""])
        .output()
        .expect("run CLI with blank run identity");
    assert_eq!(blank_identity.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&blank_identity.stderr).contains("must be nonblank"),
        "blank identity diagnostic: {}",
        String::from_utf8_lossy(&blank_identity.stderr)
    );
}

#[test]
fn cli_generate_resolves_repo_relative_output_and_never_overwrites() {
    let fixture = clone_authority_fixture(&[]);
    let relative_output = "artifacts/generated-contract.json";
    let first = Command::new(cli_binary())
        .args(["generate", "--repo-root"])
        .arg(fixture.path())
        .args(["--output", relative_output])
        .output()
        .expect("run first CLI generation");
    assert_eq!(
        first.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let output_path = fixture.path().join(relative_output);
    let original = fs::read(&output_path).expect("read generated CLI output");
    assert_eq!(
        original,
        canonical_json_bytes(
            &generate_contract(fixture.path()).expect("regenerate CLI expected contract")
        )
        .expect("serialize CLI expected contract")
    );

    let second = Command::new(cli_binary())
        .args(["generate", "--repo-root"])
        .arg(fixture.path())
        .args(["--output", relative_output])
        .output()
        .expect("run second CLI generation");
    assert_eq!(second.status.code(), Some(2));
    assert_eq!(
        fs::read(output_path).expect("reread generated CLI output"),
        original,
        "no-replace CLI failure must preserve the original artifact"
    );
}
