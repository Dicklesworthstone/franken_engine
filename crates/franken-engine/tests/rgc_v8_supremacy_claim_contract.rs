use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct ChangelogEntry {
    version: String,
    rationale: String,
    impact_assessment: String,
    compatibility_notes: String,
    changed_at_utc: String,
}

#[derive(Debug, Deserialize)]
struct CellFamily {
    family_id: String,
    description: String,
    measurement_family: String,
    required_dimensions: Vec<String>,
    required_for_universal_phrase: bool,
}

#[derive(Debug, Deserialize)]
struct FamilyThreshold {
    family_id: String,
    minimum_confidence_millionths: u32,
    minimum_effect_millionths: u32,
    max_tail_regression_millionths: u32,
    max_memory_regression_millionths: u32,
    allowed_procedures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SupremacyClaimContract {
    matrix_dimensions: Vec<String>,
    allowed_statistical_procedures: Vec<String>,
    cell_families: Vec<CellFamily>,
    family_thresholds: Vec<FamilyThreshold>,
    universal_phrase_requires_all_green: bool,
    universal_phrase_side_constraints: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DowngradeRule {
    when_missing: String,
    require_phrase_class: String,
}

#[derive(Debug, Deserialize)]
struct PublishedLanguageContract {
    phrase_classes: Vec<String>,
    forbidden_universal_phrases: Vec<String>,
    required_qualifier_terms: Vec<String>,
    required_artifact_fields: Vec<String>,
    downgrade_rules: Vec<DowngradeRule>,
}

#[derive(Debug, Deserialize)]
struct PublicationScenario {
    scenario_id: String,
    phrase_class: String,
    phrase_text: String,
    published_families: Vec<String>,
    cell_statuses: BTreeMap<String, String>,
    evidence_complete: bool,
    shipped_path: bool,
    tail_constraints_ok: bool,
    memory_constraints_ok: bool,
    expected_verdict: String,
    replay_command: String,
}

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: String,
    contract_version: String,
    log_schema_version: String,
    required_artifacts: Vec<String>,
    required_consumers: Vec<String>,
    changelog: Vec<ChangelogEntry>,
    supremacy_claim_contract: SupremacyClaimContract,
    published_language_contract: PublishedLanguageContract,
    publication_scenarios: Vec<PublicationScenario>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhraseClass {
    UniversalDominance,
    ScopedObserved,
    Target,
    Hypothesis,
}

impl PhraseClass {
    fn parse(raw: &str) -> Self {
        match raw {
            "universal_dominance" => Self::UniversalDominance,
            "scoped_observed" => Self::ScopedObserved,
            "target" => Self::Target,
            "hypothesis" => Self::Hypothesis,
            other => panic!("unknown phrase class: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::UniversalDominance => "universal_dominance",
            Self::ScopedObserved => "scoped_observed",
            Self::Target => "target",
            Self::Hypothesis => "hypothesis",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellStatus {
    Green,
    Missing,
    Mixed,
    Red,
}

impl CellStatus {
    fn parse(raw: &str) -> Self {
        match raw {
            "green" => Self::Green,
            "missing" => Self::Missing,
            "mixed" => Self::Mixed,
            "red" => Self::Red,
            other => panic!("unknown cell status: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationVerdict {
    AllowUniversal,
    AllowScoped,
    AllowQualified,
    Forbid,
}

impl PublicationVerdict {
    fn parse(raw: &str) -> Self {
        match raw {
            "allow_universal" => Self::AllowUniversal,
            "allow_scoped" => Self::AllowScoped,
            "allow_qualified" => Self::AllowQualified,
            "forbid" => Self::Forbid,
            other => panic!("unknown verdict: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AllowUniversal => "allow_universal",
            Self::AllowScoped => "allow_scoped",
            Self::AllowQualified => "allow_qualified",
            Self::Forbid => "forbid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GateEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    scenario_id: String,
    phrase_class: String,
    replay_command: String,
}

fn load_fixture() -> ContractFixture {
    let path = Path::new("tests/fixtures/rgc_v8_supremacy_claim_contract_v1.json");
    let bytes = fs::read(path).expect("read V8 supremacy contract fixture");
    serde_json::from_slice(&bytes).expect("deserialize V8 supremacy contract fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RGC_V8_SUPREMACY_CLAIM_CONTRACT_V1.md");
    fs::read_to_string(path).expect("read V8 supremacy contract doc")
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn deterministic_id(prefix: &str, scenario_id: &str, phrase_class: PhraseClass) -> String {
    let payload = format!("{prefix}|{scenario_id}|{}", phrase_class.as_str());
    format!("{prefix}-{:016x}", fnv1a64(payload.as_bytes()))
}

fn phrase_contains_required_term(phrase: &str, term: &str) -> bool {
    phrase
        .to_ascii_lowercase()
        .contains(&term.to_ascii_lowercase())
}

fn phrase_uses_forbidden_literal(fixture: &ContractFixture, phrase: &str) -> bool {
    let lower = phrase.to_ascii_lowercase();
    fixture
        .published_language_contract
        .forbidden_universal_phrases
        .iter()
        .any(|candidate| lower.contains(&candidate.to_ascii_lowercase()))
}

fn evaluate_publication_scenario(
    fixture: &ContractFixture,
    scenario: &PublicationScenario,
) -> PublicationVerdict {
    let phrase_class = PhraseClass::parse(scenario.phrase_class.as_str());
    let required_families = fixture
        .supremacy_claim_contract
        .cell_families
        .iter()
        .filter(|family| family.required_for_universal_phrase)
        .map(|family| family.family_id.as_str())
        .collect::<Vec<_>>();

    let published_families_green = scenario.published_families.iter().all(|family_id| {
        scenario
            .cell_statuses
            .get(family_id)
            .is_some_and(|status| CellStatus::parse(status) == CellStatus::Green)
    });
    let all_required_green = required_families.iter().all(|family_id| {
        scenario
            .cell_statuses
            .get(*family_id)
            .is_some_and(|status| CellStatus::parse(status) == CellStatus::Green)
    });
    let universal_ready = all_required_green
        && scenario.evidence_complete
        && scenario.shipped_path
        && scenario.tail_constraints_ok
        && scenario.memory_constraints_ok;

    match phrase_class {
        PhraseClass::UniversalDominance => {
            if phrase_uses_forbidden_literal(fixture, scenario.phrase_text.as_str())
                && universal_ready
                && published_families_green
            {
                PublicationVerdict::AllowUniversal
            } else {
                PublicationVerdict::Forbid
            }
        }
        PhraseClass::ScopedObserved => {
            if !phrase_contains_required_term(scenario.phrase_text.as_str(), "observed") {
                return PublicationVerdict::Forbid;
            }
            if phrase_uses_forbidden_literal(fixture, scenario.phrase_text.as_str()) {
                return PublicationVerdict::Forbid;
            }
            if published_families_green && scenario.evidence_complete && scenario.shipped_path {
                PublicationVerdict::AllowScoped
            } else {
                PublicationVerdict::Forbid
            }
        }
        PhraseClass::Target => {
            if phrase_contains_required_term(scenario.phrase_text.as_str(), "target")
                && !phrase_uses_forbidden_literal(fixture, scenario.phrase_text.as_str())
            {
                PublicationVerdict::AllowQualified
            } else {
                PublicationVerdict::Forbid
            }
        }
        PhraseClass::Hypothesis => {
            if phrase_contains_required_term(scenario.phrase_text.as_str(), "hypothesis")
                && !phrase_uses_forbidden_literal(fixture, scenario.phrase_text.as_str())
            {
                PublicationVerdict::AllowQualified
            } else {
                PublicationVerdict::Forbid
            }
        }
    }
}

fn simulate_gate_events(fixture: &ContractFixture) -> Vec<GateEvent> {
    fixture
        .publication_scenarios
        .iter()
        .map(|scenario| {
            let phrase_class = PhraseClass::parse(scenario.phrase_class.as_str());
            let verdict = evaluate_publication_scenario(fixture, scenario);
            GateEvent {
                schema_version: fixture.log_schema_version.clone(),
                trace_id: deterministic_id(
                    "trace-rgc-v8-claim",
                    &scenario.scenario_id,
                    phrase_class,
                ),
                decision_id: deterministic_id(
                    "decision-rgc-v8-claim",
                    &scenario.scenario_id,
                    phrase_class,
                ),
                policy_id: "policy-rgc-v8-supremacy-claim-v1".to_string(),
                component: "rgc_v8_supremacy_claim_contract".to_string(),
                event: "publication_phrase_evaluated".to_string(),
                outcome: verdict.as_str().to_string(),
                error_code: if verdict == PublicationVerdict::Forbid {
                    Some("FE-RGC-V8-SUPREMACY-0001".to_string())
                } else {
                    None
                },
                scenario_id: scenario.scenario_id.clone(),
                phrase_class: phrase_class.as_str().to_string(),
                replay_command: scenario.replay_command.clone(),
            }
        })
        .collect()
}

fn scenario_by_id<'a>(fixture: &'a ContractFixture, scenario_id: &str) -> &'a PublicationScenario {
    fixture
        .publication_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("missing publication scenario `{scenario_id}`"))
}

fn assert_scenario_matches_expected_verdict(fixture: &ContractFixture, scenario_id: &str) {
    let scenario = scenario_by_id(fixture, scenario_id);
    let actual = evaluate_publication_scenario(fixture, scenario);
    let expected = PublicationVerdict::parse(scenario.expected_verdict.as_str());
    assert_eq!(
        actual, expected,
        "unexpected publication verdict for scenario `{scenario_id}`"
    );
    assert!(
        !scenario.replay_command.trim().is_empty(),
        "scenario `{scenario_id}` must carry a replay command"
    );
}

macro_rules! publication_scenario_test {
    ($test_name:ident, $scenario_id:literal) => {
        #[test]
        fn $test_name() {
            let fixture = load_fixture();
            assert_scenario_matches_expected_verdict(&fixture, $scenario_id);
        }
    };
}

#[test]
fn v8_supremacy_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "## Contract Version",
        "## Supremacy Matrix",
        "## Statistical Thresholds and Side Constraints",
        "## Publication Language Policy",
        "## Machine-Readable Consumers",
        "## Required Artifacts",
        "## Deterministic Execution Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "required section missing from V8 supremacy doc: {section}"
        );
    }
}

#[test]
fn v8_supremacy_doc_mentions_required_family_keywords() {
    let doc = load_doc();
    let required_keywords = [
        "parse_compile",
        "startup",
        "throughput_hot_loops",
        "async",
        "module_graphs",
        "npm_cohorts",
        "react_compile",
        "react_ssr",
        "react_client",
        "macro_workloads",
        "tail_latency",
        "memory",
        "beats V8 across the board",
        "scoped_observed",
        "target",
        "hypothesis",
        "./scripts/run_rgc_v8_supremacy_claim_contract.sh ci",
    ];

    for keyword in required_keywords {
        assert!(
            doc.contains(keyword),
            "required keyword missing from V8 supremacy doc: {keyword}"
        );
    }
}

#[test]
fn v8_supremacy_doc_word_count_exceeds_minimum() {
    let doc = load_doc();
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 250,
        "V8 supremacy contract doc must have at least 250 words, found {word_count}"
    );
}

#[test]
fn fixture_versions_artifacts_and_consumers_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.rgc-v8-supremacy-claim-contract.v1"
    );
    assert_eq!(fixture.contract_version, "0.1.0");
    assert_eq!(
        fixture.log_schema_version,
        "franken-engine.rgc-v8-supremacy-claim.log-event.v1"
    );

    let artifact_set = fixture
        .required_artifacts
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected_artifacts = BTreeSet::from([
        "supremacy_claim_contract.json".to_string(),
        "published_language_contract.json".to_string(),
        "run_manifest.json".to_string(),
        "events.jsonl".to_string(),
        "commands.txt".to_string(),
    ]);
    assert_eq!(artifact_set, expected_artifacts);

    let consumer_set = fixture
        .required_consumers
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected_consumers = BTreeSet::from([
        "benchmark".to_string(),
        "docs".to_string(),
        "rollout".to_string(),
        "ga".to_string(),
    ]);
    assert_eq!(consumer_set, expected_consumers);
}

#[test]
fn changelog_entries_are_complete() {
    let fixture = load_fixture();
    assert!(!fixture.changelog.is_empty(), "changelog must not be empty");
    for entry in fixture.changelog {
        assert!(!entry.version.trim().is_empty());
        assert!(!entry.rationale.trim().is_empty());
        assert!(!entry.impact_assessment.trim().is_empty());
        assert!(!entry.compatibility_notes.trim().is_empty());
        assert!(!entry.changed_at_utc.trim().is_empty());
    }
}

#[test]
fn matrix_dimensions_and_side_constraints_are_complete() {
    let fixture = load_fixture();
    let dims = fixture
        .supremacy_claim_contract
        .matrix_dimensions
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected_dims = BTreeSet::from([
        "workload_cell".to_string(),
        "environment".to_string(),
        "entry_mode".to_string(),
        "warm_state".to_string(),
        "measurement_family".to_string(),
    ]);
    assert_eq!(dims, expected_dims);
    assert!(
        fixture
            .supremacy_claim_contract
            .universal_phrase_requires_all_green
    );

    let side_constraints = fixture
        .supremacy_claim_contract
        .universal_phrase_side_constraints
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected_constraints = BTreeSet::from([
        "tail_latency_non_regression".to_string(),
        "memory_non_regression".to_string(),
        "shipped_path_only".to_string(),
        "artifact_complete".to_string(),
    ]);
    assert_eq!(side_constraints, expected_constraints);
}

#[test]
fn cell_families_cover_required_board() {
    let fixture = load_fixture();
    let families = fixture
        .supremacy_claim_contract
        .cell_families
        .iter()
        .map(|family| family.family_id.clone())
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "parse_compile".to_string(),
        "startup".to_string(),
        "throughput_hot_loops".to_string(),
        "async".to_string(),
        "module_graphs".to_string(),
        "npm_cohorts".to_string(),
        "react_compile".to_string(),
        "react_ssr".to_string(),
        "react_client".to_string(),
        "macro_workloads".to_string(),
        "tail_latency".to_string(),
        "memory".to_string(),
    ]);
    assert_eq!(families, expected);

    for family in &fixture.supremacy_claim_contract.cell_families {
        assert!(!family.description.trim().is_empty());
        assert!(!family.measurement_family.trim().is_empty());
        assert_eq!(
            family.required_dimensions, fixture.supremacy_claim_contract.matrix_dimensions,
            "family `{}` must use the canonical matrix dimensions",
            family.family_id
        );
        assert!(
            family.required_for_universal_phrase,
            "all board families should currently be required for universal claims"
        );
    }
}

#[test]
fn threshold_entries_exist_for_every_family_and_use_allowed_procedures() {
    let fixture = load_fixture();
    let allowed = fixture
        .supremacy_claim_contract
        .allowed_statistical_procedures
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let threshold_ids = fixture
        .supremacy_claim_contract
        .family_thresholds
        .iter()
        .map(|threshold| threshold.family_id.clone())
        .collect::<BTreeSet<_>>();
    let family_ids = fixture
        .supremacy_claim_contract
        .cell_families
        .iter()
        .map(|family| family.family_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(threshold_ids, family_ids);

    for threshold in &fixture.supremacy_claim_contract.family_thresholds {
        assert!(threshold.minimum_confidence_millionths >= 990_000);
        assert!(
            threshold
                .allowed_procedures
                .iter()
                .all(|procedure| allowed.contains(procedure))
        );
        if threshold.family_id == "tail_latency" {
            assert_eq!(threshold.max_tail_regression_millionths, 0);
        }
        if threshold.family_id == "memory" {
            assert_eq!(threshold.max_memory_regression_millionths, 0);
        }
        assert!(
            threshold.minimum_effect_millionths <= 30_000,
            "threshold `{}` should remain a modest relative-effect floor",
            threshold.family_id
        );
    }
}

#[test]
fn published_language_contract_has_forbidden_literals_and_downgrade_rules() {
    let fixture = load_fixture();
    let contract = fixture.published_language_contract;
    let phrase_classes = contract.phrase_classes.into_iter().collect::<BTreeSet<_>>();
    let expected_classes = BTreeSet::from([
        "universal_dominance".to_string(),
        "scoped_observed".to_string(),
        "target".to_string(),
        "hypothesis".to_string(),
    ]);
    assert_eq!(phrase_classes, expected_classes);

    assert!(
        contract
            .forbidden_universal_phrases
            .iter()
            .any(|phrase| phrase == "beats V8 across the board")
    );
    assert_eq!(
        contract.required_qualifier_terms,
        vec![
            "observed".to_string(),
            "target".to_string(),
            "hypothesis".to_string()
        ]
    );
    assert_eq!(
        contract.required_artifact_fields,
        vec![
            "scope".to_string(),
            "environment".to_string(),
            "artifact_path".to_string(),
            "publication_date".to_string(),
            "revision".to_string()
        ]
    );

    let downgrade_targets = contract
        .downgrade_rules
        .into_iter()
        .map(|rule| (rule.when_missing, rule.require_phrase_class))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        downgrade_targets.get("any required family missing_or_mixed"),
        Some(&"scoped_observed".to_string())
    );
    assert_eq!(
        downgrade_targets.get("board_incomplete_but_program_defined"),
        Some(&"target".to_string())
    );
}

#[test]
fn publication_policy_matches_scenario_expectations() {
    let fixture = load_fixture();
    assert!(
        !fixture.publication_scenarios.is_empty(),
        "publication scenarios must not be empty"
    );
    for scenario in &fixture.publication_scenarios {
        assert_scenario_matches_expected_verdict(&fixture, scenario.scenario_id.as_str());
    }
}

#[test]
fn replay_commands_are_exact_scenario_replays() {
    let fixture = load_fixture();
    for scenario in &fixture.publication_scenarios {
        let expected = format!(
            "./scripts/run_rgc_v8_supremacy_claim_contract.sh ci --scenario {}",
            scenario.scenario_id
        );
        assert_eq!(
            scenario.replay_command, expected,
            "scenario `{}` replay command must be exact and script-supported",
            scenario.scenario_id
        );
    }
}

publication_scenario_test!(
    publication_scenario_all_green_universal,
    "all_green_universal"
);
publication_scenario_test!(
    publication_scenario_missing_react_ssr_universal,
    "missing_react_ssr_universal"
);
publication_scenario_test!(
    publication_scenario_tail_regression_universal,
    "tail_regression_universal"
);
publication_scenario_test!(
    publication_scenario_scoped_observed_startup_parse,
    "scoped_observed_startup_parse"
);
publication_scenario_test!(
    publication_scenario_target_until_react_client_green,
    "target_until_react_client_green"
);
publication_scenario_test!(
    publication_scenario_hypothesis_pending_mixed_board,
    "hypothesis_pending_mixed_board"
);

#[test]
fn gate_events_are_deterministic_and_log_complete() {
    let fixture = load_fixture();
    let first = simulate_gate_events(&fixture);
    let second = simulate_gate_events(&fixture);
    assert_eq!(first, second, "gate events must be deterministic");

    assert_eq!(first.len(), fixture.publication_scenarios.len());
    for event in first {
        assert_eq!(
            event.schema_version,
            "franken-engine.rgc-v8-supremacy-claim.log-event.v1"
        );
        assert!(!event.trace_id.trim().is_empty());
        assert!(!event.decision_id.trim().is_empty());
        assert_eq!(event.policy_id, "policy-rgc-v8-supremacy-claim-v1");
        assert_eq!(event.component, "rgc_v8_supremacy_claim_contract");
        assert_eq!(event.event, "publication_phrase_evaluated");
        assert!(!event.outcome.trim().is_empty());
        assert!(!event.scenario_id.trim().is_empty());
        assert!(!event.phrase_class.trim().is_empty());
        assert!(!event.replay_command.trim().is_empty());
        if event.outcome == "forbid" {
            assert_eq!(
                event.error_code.as_deref(),
                Some("FE-RGC-V8-SUPREMACY-0001")
            );
        } else {
            assert_eq!(event.error_code, None);
        }
    }
}
