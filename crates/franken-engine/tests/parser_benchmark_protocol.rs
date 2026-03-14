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

use std::{collections::BTreeSet, fs, path::Path};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserMode, ParserOptions};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct MeasurementWindow {
    warmup_iterations: u32,
    measurement_iterations: u32,
    replicates: u32,
    max_relative_stdev_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct CorpusTier {
    tier_id: String,
    description: String,
    min_cases: u32,
    max_cases: u32,
    release_required: bool,
}

#[derive(Debug, Deserialize)]
struct BenchmarkCase {
    case_id: String,
    tier_id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_semantic_class: String,
}

#[derive(Debug, Deserialize)]
struct ParserBenchmarkProtocolFixture {
    schema_version: String,
    protocol_version: String,
    parser_mode: String,
    deterministic_environment_contract: String,
    measurement_window: MeasurementWindow,
    corpus_tiers: Vec<CorpusTier>,
    metrics: Vec<String>,
    structured_event_keys: Vec<String>,
    runner_commands: std::collections::BTreeMap<String, String>,
    benchmark_cases: Vec<BenchmarkCase>,
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown goal: {other}"),
    }
}

fn load_fixture() -> ParserBenchmarkProtocolFixture {
    let fixture_path = Path::new("tests/fixtures/parser_benchmark_protocol_v1.json");
    let bytes = fs::read(fixture_path).expect("read parser benchmark protocol fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser benchmark protocol fixture")
}

fn load_doc() -> String {
    let doc_path = Path::new("../../docs/PARSER_BENCHMARK_PROTOCOL.md");
    fs::read_to_string(doc_path).expect("read parser benchmark protocol doc")
}

#[test]
fn parser_benchmark_protocol_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "## Scope",
        "## Contract Version",
        "## Corpus Tier Model (Normative)",
        "## Workload Contract",
        "## Measurement Window Contract",
        "## Required Metric Families",
        "## Structured Event Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
        "## Operator Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "parser benchmark protocol doc missing section: {section}"
        );
    }
}

#[test]
fn fixture_declares_expected_protocol_contract_versions() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-benchmark-protocol.v1"
    );
    assert_eq!(fixture.protocol_version, "1.0.0");
    assert_eq!(fixture.parser_mode, ParserMode::ScalarReference.as_str());
    assert_eq!(
        fixture.deterministic_environment_contract,
        "franken-engine.parser-frontier.env-contract.v1"
    );
}

#[test]
fn fixture_measurement_window_is_nonzero_and_ordered() {
    let fixture = load_fixture();
    let w = fixture.measurement_window;
    assert!(w.warmup_iterations > 0);
    assert!(w.measurement_iterations > 0);
    assert!(w.replicates > 0);
    assert!(
        w.measurement_iterations >= w.warmup_iterations,
        "measurement iterations should not be below warmup iterations"
    );
    assert!(w.max_relative_stdev_millionths > 0);
}

#[test]
fn fixture_contains_all_required_corpus_tiers() {
    let fixture = load_fixture();
    assert!(
        !fixture.corpus_tiers.is_empty(),
        "corpus tier list must not be empty"
    );

    let expected: BTreeSet<&str> = ["smoke", "core", "stress", "adversarial"]
        .into_iter()
        .collect();
    let mut seen = BTreeSet::new();
    for tier in &fixture.corpus_tiers {
        assert!(!tier.description.trim().is_empty());
        assert!(tier.min_cases > 0);
        assert!(tier.max_cases >= tier.min_cases);
        assert!(tier.release_required);
        let inserted = seen.insert(tier.tier_id.as_str());
        assert!(inserted, "duplicate tier id: {}", tier.tier_id);
    }
    assert_eq!(seen, expected);
}

#[test]
fn fixture_runner_commands_are_rch_gate_entrypoints() {
    let fixture = load_fixture();
    for mode in ["check", "test", "clippy", "ci"] {
        let command = fixture
            .runner_commands
            .get(mode)
            .unwrap_or_else(|| panic!("missing runner command for mode `{mode}`"));
        assert!(
            command.starts_with("./scripts/run_parser_benchmark_protocol.sh "),
            "unexpected runner command for {mode}: {command}"
        );
    }
}

#[test]
fn fixture_declares_required_metric_and_event_keys() {
    let fixture = load_fixture();

    let required_metrics: BTreeSet<&str> = [
        "throughput_sources_per_second",
        "latency_ns_p50",
        "latency_ns_p95",
        "latency_ns_p99",
        "bytes_per_source_avg",
        "tokens_per_source_avg",
        "semantic_hash_stability_rate",
    ]
    .into_iter()
    .collect();
    let metrics: BTreeSet<&str> = fixture.metrics.iter().map(String::as_str).collect();
    assert_eq!(metrics, required_metrics);

    let required_event_keys: BTreeSet<&str> = [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let event_keys: BTreeSet<&str> = fixture
        .structured_event_keys
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(event_keys, required_event_keys);
}

#[test]
fn benchmark_cases_are_parseable_and_reference_known_tiers() {
    let fixture = load_fixture();
    let tier_ids: BTreeSet<&str> = fixture
        .corpus_tiers
        .iter()
        .map(|tier| tier.tier_id.as_str())
        .collect();
    assert!(
        !fixture.benchmark_cases.is_empty(),
        "benchmark case list must not be empty"
    );

    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let mut case_ids = BTreeSet::new();
    for case in &fixture.benchmark_cases {
        assert!(!case.family_id.trim().is_empty());
        assert!(!case.expected_semantic_class.trim().is_empty());
        assert!(
            tier_ids.contains(case.tier_id.as_str()),
            "unknown tier for case {}: {}",
            case.case_id,
            case.tier_id
        );
        let inserted = case_ids.insert(case.case_id.as_str());
        assert!(inserted, "duplicate case id: {}", case.case_id);

        parser
            .parse_with_options(
                case.source.as_str(),
                parse_goal(case.goal.as_str()),
                &options,
            )
            .unwrap_or_else(|error| panic!("case `{}` failed parse: {error}", case.case_id));
    }
}

// ---------- parse_goal helper ----------

#[test]
fn parse_goal_maps_script() {
    assert_eq!(parse_goal("script"), ParseGoal::Script);
}

#[test]
fn parse_goal_maps_module() {
    assert_eq!(parse_goal("module"), ParseGoal::Module);
}

#[test]
#[should_panic(expected = "unknown goal")]
fn parse_goal_panics_on_unknown() {
    parse_goal("invalid");
}

// ---------- load_fixture helper ----------

#[test]
fn load_fixture_returns_valid_fixture() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.is_empty());
    assert!(!fixture.benchmark_cases.is_empty());
    assert!(!fixture.corpus_tiers.is_empty());
}

// ---------- load_doc helper ----------

#[test]
fn load_doc_returns_nonempty_string() {
    let doc = load_doc();
    assert!(!doc.is_empty());
    assert!(doc.contains("Benchmark"));
}

// ---------- MeasurementWindow ----------

#[test]
fn measurement_window_from_fixture_is_well_formed() {
    let fixture = load_fixture();
    let w = &fixture.measurement_window;
    assert!(w.warmup_iterations > 0);
    assert!(w.measurement_iterations >= w.warmup_iterations);
    assert!(w.replicates > 0);
    assert!(w.max_relative_stdev_millionths > 0);
}

// ---------- CorpusTier ----------

#[test]
fn corpus_tiers_have_unique_ids() {
    let fixture = load_fixture();
    let ids: BTreeSet<_> = fixture
        .corpus_tiers
        .iter()
        .map(|t| t.tier_id.as_str())
        .collect();
    assert_eq!(ids.len(), fixture.corpus_tiers.len());
}

#[test]
fn corpus_tiers_are_all_release_required() {
    let fixture = load_fixture();
    for tier in &fixture.corpus_tiers {
        assert!(
            tier.release_required,
            "tier {} not release-required",
            tier.tier_id
        );
    }
}

// ---------- BenchmarkCase ----------

#[test]
fn benchmark_cases_have_unique_ids() {
    let fixture = load_fixture();
    let ids: BTreeSet<_> = fixture
        .benchmark_cases
        .iter()
        .map(|c| c.case_id.as_str())
        .collect();
    assert_eq!(ids.len(), fixture.benchmark_cases.len());
}

#[test]
fn benchmark_cases_reference_valid_tiers() {
    let fixture = load_fixture();
    let tier_ids: BTreeSet<_> = fixture
        .corpus_tiers
        .iter()
        .map(|t| t.tier_id.as_str())
        .collect();
    for case in &fixture.benchmark_cases {
        assert!(
            tier_ids.contains(case.tier_id.as_str()),
            "case {} references unknown tier {}",
            case.case_id,
            case.tier_id
        );
    }
}

#[test]
fn benchmark_cases_have_nonempty_sources() {
    let fixture = load_fixture();
    for case in &fixture.benchmark_cases {
        assert!(
            !case.source.trim().is_empty(),
            "case {} has empty source",
            case.case_id
        );
    }
}

// ---------- ParserMode ----------

#[test]
fn parser_mode_scalar_reference_as_str() {
    assert!(!ParserMode::ScalarReference.as_str().is_empty());
}

// ---------- ParserOptions ----------

#[test]
fn parser_options_default_is_well_formed() {
    let options = ParserOptions::default();
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options("42", ParseGoal::Script, &options)
        .expect("parse with default options");
    assert_eq!(tree.body.len(), 1);
}

// ---------- runner_commands ----------

#[test]
fn runner_commands_have_four_modes() {
    let fixture = load_fixture();
    assert_eq!(fixture.runner_commands.len(), 4);
    assert!(fixture.runner_commands.contains_key("check"));
    assert!(fixture.runner_commands.contains_key("test"));
    assert!(fixture.runner_commands.contains_key("clippy"));
    assert!(fixture.runner_commands.contains_key("ci"));
}

// ---------- structured_event_keys ----------

#[test]
fn structured_event_keys_include_trace_id() {
    let fixture = load_fixture();
    assert!(
        fixture
            .structured_event_keys
            .contains(&"trace_id".to_string())
    );
    assert!(
        fixture
            .structured_event_keys
            .contains(&"outcome".to_string())
    );
}

#[test]
fn fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.benchmark_cases.len(), b.benchmark_cases.len());
}

#[test]
fn doc_has_more_than_50_lines() {
    let doc = load_doc();
    assert!(doc.lines().count() > 50);
}

// ────────────────────────────────────────────────────────────
// Enrichment: parse stability, family coverage, serde depth
// ────────────────────────────────────────────────────────────

#[test]
fn benchmark_cases_produce_deterministic_canonical_hashes() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    for case in &fixture.benchmark_cases {
        let goal = parse_goal(&case.goal);
        let tree_1 = parser
            .parse_with_options(case.source.as_str(), goal, &options)
            .unwrap_or_else(|e| panic!("case {} first parse failed: {e}", case.case_id));
        let tree_2 = parser
            .parse_with_options(case.source.as_str(), goal, &options)
            .unwrap_or_else(|e| panic!("case {} second parse failed: {e}", case.case_id));
        assert_eq!(
            tree_1.canonical_hash(),
            tree_2.canonical_hash(),
            "case {} must produce deterministic canonical hash",
            case.case_id
        );
    }
}

#[test]
fn benchmark_cases_cover_all_corpus_tiers() {
    let fixture = load_fixture();
    let tier_ids: BTreeSet<&str> = fixture
        .corpus_tiers
        .iter()
        .map(|t| t.tier_id.as_str())
        .collect();
    let case_tiers: BTreeSet<&str> = fixture
        .benchmark_cases
        .iter()
        .map(|c| c.tier_id.as_str())
        .collect();
    for tier in &tier_ids {
        assert!(
            case_tiers.contains(tier),
            "no benchmark case covers required corpus tier: {tier}"
        );
    }
}

#[test]
fn benchmark_cases_family_ids_are_nonempty_and_lowercase() {
    let fixture = load_fixture();
    for case in &fixture.benchmark_cases {
        assert!(
            !case.family_id.trim().is_empty(),
            "case {} has empty family_id",
            case.case_id
        );
        assert_eq!(
            case.family_id,
            case.family_id.to_lowercase(),
            "case {} family_id should be lowercase: {}",
            case.case_id,
            case.family_id
        );
    }
}

#[test]
fn measurement_window_serde_round_trip() {
    let fixture = load_fixture();
    let json = serde_json::to_string(&fixture.measurement_window).expect("serialize");
    let recovered: MeasurementWindow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.warmup_iterations,
        fixture.measurement_window.warmup_iterations
    );
    assert_eq!(
        recovered.measurement_iterations,
        fixture.measurement_window.measurement_iterations
    );
    assert_eq!(recovered.replicates, fixture.measurement_window.replicates);
    assert_eq!(
        recovered.max_relative_stdev_millionths,
        fixture.measurement_window.max_relative_stdev_millionths
    );
}

#[test]
fn benchmark_cases_expected_semantic_class_is_nonempty() {
    let fixture = load_fixture();
    for case in &fixture.benchmark_cases {
        assert!(
            !case.expected_semantic_class.trim().is_empty(),
            "case {} has empty expected_semantic_class",
            case.case_id
        );
    }
}

// ===== PearlTower enrichment =====

#[test]
fn enrichment_measurement_window_serde_roundtrip_preserves_all_fields() {
    // Construct a MeasurementWindow directly and verify that a serde JSON
    // roundtrip faithfully preserves every field, including boundary values.
    let original = MeasurementWindow {
        warmup_iterations: 1,
        measurement_iterations: 1,
        replicates: 1,
        max_relative_stdev_millionths: 1,
    };
    let json = serde_json::to_string(&original).expect("serialize MeasurementWindow");
    let recovered: MeasurementWindow =
        serde_json::from_str(&json).expect("deserialize MeasurementWindow");
    assert_eq!(recovered.warmup_iterations, original.warmup_iterations);
    assert_eq!(
        recovered.measurement_iterations,
        original.measurement_iterations
    );
    assert_eq!(recovered.replicates, original.replicates);
    assert_eq!(
        recovered.max_relative_stdev_millionths,
        original.max_relative_stdev_millionths
    );
}

#[test]
fn enrichment_measurement_window_serde_roundtrip_extreme_values() {
    // Verify that u32::MAX round-trips cleanly through JSON without truncation
    // or overflow, since millionths-based fields may approach large magnitudes
    // in stress configurations.
    let original = MeasurementWindow {
        warmup_iterations: u32::MAX,
        measurement_iterations: u32::MAX,
        replicates: u32::MAX,
        max_relative_stdev_millionths: u32::MAX,
    };
    let json = serde_json::to_string(&original).expect("serialize extreme MeasurementWindow");
    let recovered: MeasurementWindow =
        serde_json::from_str(&json).expect("deserialize extreme MeasurementWindow");
    assert_eq!(recovered.warmup_iterations, u32::MAX);
    assert_eq!(recovered.measurement_iterations, u32::MAX);
    assert_eq!(recovered.replicates, u32::MAX);
    assert_eq!(recovered.max_relative_stdev_millionths, u32::MAX);
}

#[test]
fn enrichment_measurement_window_debug_contains_field_names() {
    // The Debug derive must surface field names so that assertion failures in
    // test output are human-readable without requiring a manual Display impl.
    let w = MeasurementWindow {
        warmup_iterations: 3,
        measurement_iterations: 7,
        replicates: 2,
        max_relative_stdev_millionths: 50_000,
    };
    let debug_str = format!("{w:?}");
    assert!(
        debug_str.contains("warmup_iterations"),
        "debug missing warmup_iterations"
    );
    assert!(
        debug_str.contains("measurement_iterations"),
        "debug missing measurement_iterations"
    );
    assert!(debug_str.contains("replicates"), "debug missing replicates");
    assert!(
        debug_str.contains("max_relative_stdev_millionths"),
        "debug missing stdev field"
    );
}

#[test]
fn enrichment_corpus_tier_min_cases_never_zero() {
    // min_cases == 0 would allow a tier to be trivially satisfied by an empty
    // corpus, violating the protocol's coverage guarantees.
    let fixture = load_fixture();
    for tier in &fixture.corpus_tiers {
        assert!(
            tier.min_cases > 0,
            "tier {} has min_cases == 0, which defeats coverage guarantees",
            tier.tier_id
        );
    }
}

#[test]
fn enrichment_corpus_tier_max_cases_gte_min_cases() {
    // A tier where max_cases < min_cases is internally inconsistent and would
    // make it impossible to satisfy both bounds simultaneously.
    let fixture = load_fixture();
    for tier in &fixture.corpus_tiers {
        assert!(
            tier.max_cases >= tier.min_cases,
            "tier {} has max_cases ({}) < min_cases ({})",
            tier.tier_id,
            tier.max_cases,
            tier.min_cases
        );
    }
}

#[test]
fn enrichment_benchmark_case_count_satisfies_smoke_tier_min() {
    // The smoke tier must have at least its declared min_cases satisfied by the
    // actual benchmark_cases list so the gate remains meaningful for PRs.
    let fixture = load_fixture();
    let smoke_tier = fixture
        .corpus_tiers
        .iter()
        .find(|t| t.tier_id == "smoke")
        .expect("smoke tier must exist");
    assert!(
        smoke_tier.min_cases > 0,
        "smoke tier min_cases must be positive"
    );
    let smoke_cases = fixture
        .benchmark_cases
        .iter()
        .filter(|c| c.tier_id == "smoke")
        .count();
    assert!(smoke_cases > 0, "smoke tier must have at least one case");
}

#[test]
fn enrichment_protocol_version_is_semver_shaped() {
    // The protocol_version must follow MAJOR.MINOR.PATCH so that downstream
    // tooling can parse and compare versions programmatically.
    let fixture = load_fixture();
    let parts: Vec<&str> = fixture.protocol_version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "protocol_version '{}' does not have three dot-separated components",
        fixture.protocol_version
    );
    for part in &parts {
        assert!(
            part.parse::<u32>().is_ok(),
            "protocol_version component '{}' is not a non-negative integer",
            part
        );
    }
}

#[test]
fn enrichment_runner_commands_all_values_are_nonempty() {
    // Every runner command value must be a non-empty string; a blank command
    // would silently succeed in shell without executing the protocol runner.
    let fixture = load_fixture();
    for (mode, command) in &fixture.runner_commands {
        assert!(
            !command.trim().is_empty(),
            "runner command for mode '{mode}' is empty"
        );
    }
}

#[test]
fn enrichment_fixture_load_is_deterministic_across_three_loads() {
    // Three independent loads of the fixture must yield identical content,
    // proving the fixture is a stable, side-effect-free artifact.
    let a = load_fixture();
    let b = load_fixture();
    let c = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(b.schema_version, c.schema_version);
    assert_eq!(a.benchmark_cases.len(), b.benchmark_cases.len());
    assert_eq!(b.benchmark_cases.len(), c.benchmark_cases.len());
    assert_eq!(a.corpus_tiers.len(), b.corpus_tiers.len());
    assert_eq!(b.corpus_tiers.len(), c.corpus_tiers.len());
    // Case IDs must be identical in order across all three loads.
    for (idx, ((ca, cb), cc)) in a
        .benchmark_cases
        .iter()
        .zip(b.benchmark_cases.iter())
        .zip(c.benchmark_cases.iter())
        .enumerate()
    {
        assert_eq!(
            ca.case_id, cb.case_id,
            "case id mismatch at index {idx} between load A and B"
        );
        assert_eq!(
            cb.case_id, cc.case_id,
            "case id mismatch at index {idx} between load B and C"
        );
    }
}

#[test]
fn enrichment_parse_goal_exhaustive_known_variants() {
    // Ensure both known ParseGoal variants are mapped and that the helper
    // returns the correct variant for each — a regression guard against
    // future parse_goal refactors that silently swap the arms.
    let script = parse_goal("script");
    let module = parse_goal("module");
    assert_eq!(script, ParseGoal::Script);
    assert_eq!(module, ParseGoal::Module);
    assert_ne!(
        script, module,
        "Script and Module must be distinct variants"
    );
}
