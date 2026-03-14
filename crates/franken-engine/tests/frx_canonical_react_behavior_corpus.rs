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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures_dir() -> PathBuf {
    repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/fixtures")
}

fn traces_dir() -> PathBuf {
    repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces")
}

fn list_json_files(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|err| panic!("failed to read dir entry: {err}"))
                .path()
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
        .collect();
    files.sort();
    files
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct CorpusContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    corpus: CorpusContractCorpus,
    determinism_contract: DeterminismContract,
    failure_policy: FailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CorpusContractCorpus {
    fixtures_dir: String,
    traces_dir: String,
    minimum_fixture_count: usize,
    required_focus_tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DeterminismContract {
    fixture_schema_version: String,
    trace_schema_version: String,
    require_stable_fixture_ref_and_scenario_id: bool,
    require_monotonic_event_sequence: bool,
    require_monotonic_event_timing_us: bool,
}

#[derive(Debug, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
    block_on_missing_fixture: bool,
    block_on_trace_mismatch: bool,
    block_on_schema_drift: bool,
}

#[derive(Debug, Deserialize)]
struct FixtureSpec {
    schema_version: String,
    scenario_id: String,
    fixture_ref: String,
    runtime_mode: String,
    semantic_focus: Vec<String>,
    stimulus: Vec<StimulusStep>,
    expected_observable: Vec<String>,
    component_source: String,
}

#[derive(Debug, Deserialize)]
struct StimulusStep {
    step: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct ObservableTrace {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    scenario_id: String,
    fixture_ref: String,
    seed: u64,
    events: Vec<TraceEvent>,
    outcome: String,
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TraceEvent {
    seq: u64,
    phase: String,
    actor: String,
    event: String,
    decision_path: String,
    timing_us: u64,
    outcome: String,
}

#[test]
fn frx_02_1_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_CANONICAL_REACT_BEHAVIOR_CORPUS_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Canonical React Behavior Corpus v1",
        "## Scope",
        "## Corpus Layout",
        "## Determinism and Replay Contract",
        "## Observable Trace Contract",
        "## CI Gate and Failure Policy",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing doc section in {}: {section}",
            path.display()
        );
    }

    let doc_lower = doc.to_ascii_lowercase();
    for phrase in [
        "hooks",
        "concurrent",
        "suspense",
        "hydration",
        "error boundary",
        "portal",
        "fail-closed",
        "deterministic",
    ] {
        assert!(
            doc_lower.contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_02_1_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);

    assert_eq!(
        contract.schema_version,
        "frx.canonical-react-behavior-corpus.contract.v1"
    );
    assert_eq!(contract.bead_id, "bd-mjh3.2.1");
    assert_eq!(contract.generated_by, "bd-mjh3.2.1");

    assert_eq!(
        contract.corpus.fixtures_dir,
        "crates/franken-engine/tests/conformance/frx_react_corpus/fixtures"
    );
    assert_eq!(
        contract.corpus.traces_dir,
        "crates/franken-engine/tests/conformance/frx_react_corpus/traces"
    );
    assert!(
        contract.corpus.minimum_fixture_count >= 10,
        "minimum fixture count should enforce high-risk semantic coverage"
    );

    assert_eq!(
        contract.determinism_contract.fixture_schema_version,
        "frx.react.fixture.v1"
    );
    assert_eq!(
        contract.determinism_contract.trace_schema_version,
        "frx.react.observable.trace.v1"
    );
    assert!(
        contract
            .determinism_contract
            .require_stable_fixture_ref_and_scenario_id
    );
    assert!(
        contract
            .determinism_contract
            .require_monotonic_event_sequence
    );
    assert!(
        contract
            .determinism_contract
            .require_monotonic_event_timing_us
    );

    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        "FE-FRX-02-1-CORPUS-GATE-0001"
    );
    assert!(contract.failure_policy.block_on_missing_fixture);
    assert!(contract.failure_policy.block_on_trace_mismatch);
    assert!(contract.failure_policy.block_on_schema_drift);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_frx_canonical_react_behavior_corpus_suite.sh ci")),
        "operator verification must include ci replay command"
    );
}

#[test]
fn frx_02_1_fixture_corpus_matches_contract_and_risk_coverage() {
    let contract_path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&contract_path);

    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    assert!(
        files.len() >= contract.corpus.minimum_fixture_count,
        "fixture count {} below contract minimum {}",
        files.len(),
        contract.corpus.minimum_fixture_count
    );

    let mut seen_fixture_refs = BTreeSet::new();
    let mut seen_scenarios = BTreeSet::new();
    let mut aggregated_focus_tags = BTreeSet::new();

    for path in files {
        let fixture: FixtureSpec = load_json(&path);
        let name = path
            .file_name()
            .and_then(|entry| entry.to_str())
            .unwrap_or_else(|| panic!("invalid fixture filename {}", path.display()));
        let expected_ref = name
            .strip_suffix(".fixture.json")
            .unwrap_or_else(|| panic!("unexpected fixture suffix {}", path.display()));

        assert_eq!(
            fixture.schema_version,
            contract.determinism_contract.fixture_schema_version
        );
        assert_eq!(
            fixture.fixture_ref, expected_ref,
            "fixture_ref should match fixture filename stem for deterministic indexing"
        );
        assert!(!fixture.scenario_id.is_empty());
        assert!(
            seen_fixture_refs.insert(fixture.fixture_ref.clone()),
            "duplicate fixture_ref {}",
            fixture.fixture_ref
        );
        assert!(
            seen_scenarios.insert(fixture.scenario_id.clone()),
            "duplicate scenario_id {}",
            fixture.scenario_id
        );

        assert!(
            !fixture.semantic_focus.is_empty(),
            "semantic_focus cannot be empty"
        );
        for tag in fixture.semantic_focus {
            assert!(
                !tag.trim().is_empty(),
                "semantic_focus tags must be non-empty"
            );
            aggregated_focus_tags.insert(tag);
        }

        assert!(!fixture.stimulus.is_empty(), "stimulus cannot be empty");
        for stimulus in fixture.stimulus {
            assert!(
                !stimulus.step.trim().is_empty(),
                "stimulus step must be present"
            );
            assert!(
                !stimulus.payload.trim().is_empty(),
                "stimulus payload must be present"
            );
        }

        assert!(
            !fixture.expected_observable.is_empty(),
            "expected_observable cannot be empty"
        );
        assert!(
            !fixture.component_source.trim().is_empty(),
            "component_source must be populated"
        );
        assert!(
            matches!(
                fixture.runtime_mode.as_str(),
                "client" | "server" | "hydrate" | "hydration"
            ),
            "runtime_mode must be one of client/server/hydrate/hydration"
        );
    }

    for required_tag in &contract.corpus.required_focus_tags {
        assert!(
            aggregated_focus_tags.contains(required_tag),
            "required focus tag missing from fixture corpus: {required_tag}"
        );
    }
}

#[test]
fn frx_02_1_traces_are_versioned_and_replay_deterministic() {
    let contract_path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&contract_path);

    let fixture_files = list_json_files(&fixtures_dir(), ".fixture.json");
    let trace_files = list_json_files(&traces_dir(), ".trace.json");
    assert_eq!(
        trace_files.len(),
        fixture_files.len(),
        "fixture/trace cardinality mismatch"
    );

    let mut fixture_index: BTreeMap<String, String> = BTreeMap::new();
    for path in fixture_files {
        let fixture: FixtureSpec = load_json(&path);
        fixture_index.insert(fixture.fixture_ref, fixture.scenario_id);
    }

    let mut seen_trace_ids = BTreeSet::new();
    for path in trace_files {
        let trace: ObservableTrace = load_json(&path);
        assert_eq!(
            trace.schema_version,
            contract.determinism_contract.trace_schema_version
        );
        assert_eq!(trace.component, "frx_react_corpus");
        assert!(
            trace.trace_id.starts_with("trace-frx-react-"),
            "trace_id should carry deterministic frx-react prefix"
        );
        assert!(
            trace.decision_id.starts_with("decision-frx-react-"),
            "decision_id should carry deterministic frx-react prefix"
        );
        assert!(
            trace.policy_id.starts_with("policy-frx-react-corpus-v"),
            "policy_id should carry policy version prefix"
        );
        assert!(
            trace.seed > 0,
            "seed must be non-zero for deterministic replay"
        );
        assert!(
            seen_trace_ids.insert(trace.trace_id.clone()),
            "duplicate trace_id"
        );

        let expected_scenario = fixture_index.get(&trace.fixture_ref).unwrap_or_else(|| {
            panic!(
                "trace references missing fixture_ref: {}",
                trace.fixture_ref
            )
        });
        assert_eq!(&trace.scenario_id, expected_scenario);

        assert!(!trace.events.is_empty(), "trace events cannot be empty");

        let mut prev_seq = 0_u64;
        let mut prev_timing = 0_u64;
        for event in trace.events {
            assert!(
                event.seq > prev_seq,
                "event seq must be strictly increasing"
            );
            assert!(
                event.timing_us >= prev_timing,
                "event timing_us must be monotonic"
            );
            assert!(
                !event.phase.trim().is_empty(),
                "event.phase must be populated"
            );
            assert!(
                !event.actor.trim().is_empty(),
                "event.actor must be populated"
            );
            assert!(
                !event.event.trim().is_empty(),
                "event.event must be populated"
            );
            assert!(
                !event.decision_path.trim().is_empty(),
                "event.decision_path must be populated"
            );
            assert!(
                !event.outcome.trim().is_empty(),
                "event.outcome must be populated"
            );
            prev_seq = event.seq;
            prev_timing = event.timing_us;
        }

        if trace.outcome == "pass" {
            assert!(
                trace.error_code.is_none(),
                "pass traces should not carry error_code"
            );
        }
    }
}

// ---------- helper functions ----------

#[test]
fn list_json_files_returns_sorted_results() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    let names: Vec<&str> = files
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn list_json_files_filters_by_suffix() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    for file in &files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap();
        assert!(name.ends_with(".fixture.json"));
    }
}

#[test]
fn fixtures_dir_exists() {
    assert!(fixtures_dir().exists());
}

#[test]
fn traces_dir_exists() {
    assert!(traces_dir().exists());
}

// ---------- CorpusContract ----------

#[test]
fn contract_schema_version_is_stable() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert_eq!(
        contract.schema_version,
        "frx.canonical-react-behavior-corpus.contract.v1"
    );
}

#[test]
fn contract_fixture_count_minimum_is_at_least_10() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(contract.corpus.minimum_fixture_count >= 10);
}

// ---------- fixture/trace counts ----------

#[test]
fn fixture_count_matches_trace_count() {
    let fixtures = list_json_files(&fixtures_dir(), ".fixture.json");
    let traces = list_json_files(&traces_dir(), ".trace.json");
    assert_eq!(fixtures.len(), traces.len());
}

#[test]
fn fixture_count_meets_minimum() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    let fixtures = list_json_files(&fixtures_dir(), ".fixture.json");
    assert!(fixtures.len() >= contract.corpus.minimum_fixture_count);
}

// ---------- FixtureSpec ----------

#[test]
fn fixture_schema_version_matches_contract() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    let fixture: FixtureSpec = load_json(&files[0]);
    assert_eq!(
        fixture.schema_version,
        contract.determinism_contract.fixture_schema_version
    );
}

// ---------- ObservableTrace ----------

#[test]
fn trace_schema_version_matches_contract() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    let files = list_json_files(&traces_dir(), ".trace.json");
    let trace: ObservableTrace = load_json(&files[0]);
    assert_eq!(
        trace.schema_version,
        contract.determinism_contract.trace_schema_version
    );
}

// ---------- trace_ids unique across all traces ----------

#[test]
fn all_trace_ids_are_unique_across_corpus() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    let mut seen = BTreeSet::new();
    for path in files {
        let trace: ObservableTrace = load_json(&path);
        assert!(
            seen.insert(trace.trace_id.clone()),
            "duplicate trace_id: {}",
            trace.trace_id
        );
    }
}

// ---------- all fixtures have unique fixture_refs ----------

#[test]
fn all_fixture_refs_are_unique() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    let mut seen = BTreeSet::new();
    for path in files {
        let fixture: FixtureSpec = load_json(&path);
        assert!(
            seen.insert(fixture.fixture_ref.clone()),
            "duplicate fixture_ref: {}",
            fixture.fixture_ref
        );
    }
}

// ---------- all traces have pass or fail outcome ----------

#[test]
fn all_trace_outcomes_are_recognized_values() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    for path in files {
        let trace: ObservableTrace = load_json(&path);
        assert!(
            matches!(trace.outcome.as_str(), "pass" | "fail" | "fallback"),
            "unexpected trace outcome: {}",
            trace.outcome
        );
    }
}

// ---------- doc file is nonempty ----------

#[test]
fn frx_02_1_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_CANONICAL_REACT_BEHAVIOR_CORPUS_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn fixtures_dir_exists_and_contains_json_files() {
    let dir = fixtures_dir();
    assert!(dir.is_dir(), "fixtures directory must exist");
    let files = list_json_files(&dir, ".fixture.json");
    assert!(
        !files.is_empty(),
        "fixtures directory must contain fixture files"
    );
}

#[test]
fn traces_dir_exists_and_contains_trace_files() {
    let dir = traces_dir();
    assert!(dir.is_dir(), "traces directory must exist");
    let files = list_json_files(&dir, ".trace.json");
    assert!(
        !files.is_empty(),
        "traces directory must contain trace files"
    );
}

#[test]
fn all_fixtures_have_nonempty_fixture_ref() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    for path in files {
        let fixture: FixtureSpec = load_json(&path);
        assert!(
            !fixture.fixture_ref.trim().is_empty(),
            "fixture_ref must not be empty in {}",
            path.display()
        );
    }
}

#[test]
fn contract_has_nonempty_bead_id() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn contract_has_nonempty_generated_by() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(!contract.generated_by.trim().is_empty());
}

#[test]
fn contract_failure_policy_is_fail_closed() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert!(!contract.failure_policy.error_code.trim().is_empty());
}

// ---------- operator_verification ----------

#[test]
fn contract_operator_verification_is_non_empty() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must contain at least one verification entry"
    );
    for (i, entry) in contract.operator_verification.iter().enumerate() {
        assert!(
            !entry.trim().is_empty(),
            "operator_verification[{i}] must not be blank"
        );
    }
}

// ---------- stimulus coverage ----------

#[test]
fn all_fixtures_have_at_least_one_stimulus_step() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    for path in &files {
        let fixture: FixtureSpec = load_json(path);
        assert!(
            !fixture.stimulus.is_empty(),
            "fixture {} must contain at least one stimulus step",
            path.display()
        );
        for step in &fixture.stimulus {
            assert!(
                !step.step.trim().is_empty(),
                "stimulus step name must be non-empty in {}",
                path.display()
            );
        }
    }
}

// ---------- trace seed determinism ----------

#[test]
fn all_traces_have_non_zero_seed() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    for path in &files {
        let trace: ObservableTrace = load_json(path);
        assert!(
            trace.seed > 0,
            "trace {} must carry non-zero seed for deterministic replay, got 0",
            path.display()
        );
    }
}

// ---------- contract required_focus_tags ----------

#[test]
fn contract_required_focus_tags_is_non_empty() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        !contract.corpus.required_focus_tags.is_empty(),
        "contract must mandate at least one required_focus_tag for risk coverage"
    );
    for tag in &contract.corpus.required_focus_tags {
        assert!(
            !tag.trim().is_empty(),
            "required_focus_tags entries must be non-blank"
        );
    }
}

// ---------- trace decision_id prefix ----------

#[test]
fn all_trace_decision_ids_carry_frx_react_prefix() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    for path in &files {
        let trace: ObservableTrace = load_json(path);
        assert!(
            trace.decision_id.starts_with("decision-frx-react-"),
            "decision_id in {} must start with 'decision-frx-react-', got '{}'",
            path.display(),
            trace.decision_id
        );
    }
}

// ---------- fixture scenario_id non-empty ----------

#[test]
fn all_fixture_scenario_ids_are_non_empty() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    let mut seen_ids = BTreeSet::new();
    for path in &files {
        let fixture: FixtureSpec = load_json(path);
        assert!(
            !fixture.scenario_id.trim().is_empty(),
            "scenario_id must be non-empty in {}",
            path.display()
        );
        assert!(
            seen_ids.insert(fixture.scenario_id.clone()),
            "duplicate scenario_id '{}' in {}",
            fixture.scenario_id,
            path.display()
        );
    }
}

// ---------- trace policy_id prefix ----------

#[test]
fn all_trace_policy_ids_carry_frx_react_corpus_prefix() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    for path in &files {
        let trace: ObservableTrace = load_json(path);
        assert!(
            trace.policy_id.starts_with("policy-frx-react-corpus-v"),
            "policy_id in {} must start with 'policy-frx-react-corpus-v', got '{}'",
            path.display(),
            trace.policy_id
        );
    }
}

// ---------- fixture runtime_mode coverage ----------

#[test]
fn fixtures_cover_both_client_and_server_runtime_modes() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    let modes: BTreeSet<String> = files
        .iter()
        .map(|p| {
            let fixture: FixtureSpec = load_json(p);
            fixture.runtime_mode
        })
        .collect();
    assert!(
        modes.contains("client"),
        "fixture corpus must include client runtime_mode"
    );
    assert!(
        modes.contains("server") || modes.contains("hydrate") || modes.contains("hydration"),
        "fixture corpus must include at least one server-side runtime_mode"
    );
}

// ---------- trace component is always frx_react_corpus ----------

#[test]
fn all_traces_have_frx_react_corpus_component() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    for path in &files {
        let trace: ObservableTrace = load_json(path);
        assert_eq!(
            trace.component,
            "frx_react_corpus",
            "trace {} must have component 'frx_react_corpus', got '{}'",
            path.display(),
            trace.component
        );
    }
}

// ---------- fixture expected_observable entries are nonempty ----------

#[test]
fn all_fixture_expected_observables_are_nonempty_strings() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    for path in &files {
        let fixture: FixtureSpec = load_json(path);
        assert!(
            !fixture.expected_observable.is_empty(),
            "expected_observable in {} must not be empty",
            path.display()
        );
        for (i, obs) in fixture.expected_observable.iter().enumerate() {
            assert!(
                !obs.trim().is_empty(),
                "expected_observable[{i}] in {} must not be blank",
                path.display()
            );
        }
    }
}

// ---------- trace event decision_paths are consistent within a trace ----------

#[test]
fn all_trace_events_have_non_empty_event_field() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    for path in &files {
        let trace: ObservableTrace = load_json(path);
        for (i, ev) in trace.events.iter().enumerate() {
            assert!(
                !ev.event.trim().is_empty(),
                "event[{i}].event in trace {} must not be blank",
                path.display()
            );
            assert!(
                !ev.phase.trim().is_empty(),
                "event[{i}].phase in trace {} must not be blank",
                path.display()
            );
            assert!(
                !ev.actor.trim().is_empty(),
                "event[{i}].actor in trace {} must not be blank",
                path.display()
            );
        }
    }
}

// ===== PearlTower enrichment session 2026-03-14 =====

#[test]
fn enrichment_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let a: CorpusContract = load_json(&path);
    let b: CorpusContract = load_json(&path);
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
}

#[test]
fn enrichment_contract_schema_version_has_frx_prefix() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        contract.schema_version.starts_with("frx."),
        "schema_version must start with frx.: {}",
        contract.schema_version
    );
}

#[test]
fn enrichment_contract_bead_id_is_hierarchical() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        contract.bead_id.starts_with("bd-"),
        "bead_id must start with bd-: {}",
        contract.bead_id
    );
}

#[test]
fn enrichment_contract_generated_by_references_bead() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        contract.generated_by.starts_with("bd-"),
        "generated_by must reference a bead: {}",
        contract.generated_by
    );
}

#[test]
fn enrichment_contract_minimum_fixture_count_is_positive() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        contract.corpus.minimum_fixture_count > 0,
        "minimum_fixture_count must be positive"
    );
}

#[test]
fn enrichment_fixture_count_meets_contract_minimum() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    assert!(
        files.len() >= contract.corpus.minimum_fixture_count,
        "corpus must have at least {} fixtures, found {}",
        contract.corpus.minimum_fixture_count,
        files.len()
    );
}

#[test]
fn enrichment_all_fixtures_have_nonempty_expected_observables() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    for path in &files {
        let fixture: FixtureSpec = load_json(path);
        assert!(
            !fixture.expected_observable.is_empty(),
            "expected_observable must not be empty in {}",
            path.display()
        );
    }
}

#[test]
fn enrichment_all_traces_have_at_least_one_event() {
    let files = list_json_files(&traces_dir(), ".trace.json");
    for path in &files {
        let trace: ObservableTrace = load_json(path);
        assert!(
            !trace.events.is_empty(),
            "trace {} must have at least one event",
            path.display()
        );
    }
}

#[test]
fn enrichment_fixture_refs_are_unique_across_corpus() {
    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    let mut seen = BTreeSet::new();
    for path in &files {
        let fixture: FixtureSpec = load_json(path);
        assert!(
            seen.insert(fixture.fixture_ref.clone()),
            "duplicate fixture_ref '{}' in {}",
            fixture.fixture_ref,
            path.display()
        );
    }
}

#[test]
fn enrichment_contract_determinism_flags_are_set() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        contract
            .determinism_contract
            .require_stable_fixture_ref_and_scenario_id,
        "determinism contract must require stable fixture_ref and scenario_id"
    );
}

#[test]
fn enrichment_contract_fixture_schema_version_is_nonempty() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);
    assert!(
        !contract
            .determinism_contract
            .fixture_schema_version
            .trim()
            .is_empty(),
        "fixture_schema_version must not be empty"
    );
    assert!(
        !contract
            .determinism_contract
            .trace_schema_version
            .trim()
            .is_empty(),
        "trace_schema_version must not be empty"
    );
}
