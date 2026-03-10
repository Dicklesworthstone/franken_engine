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
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct CriteriaChangelogEntry {
    version: String,
    rationale: String,
    impact_assessment: String,
    compatibility_notes: String,
    changed_at_utc: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RuleClass {
    Correctness,
    Determinism,
    Performance,
    Reproducibility,
    VerificationRigor,
    UserFacingQuality,
}

impl RuleClass {
    fn parse(raw: &str) -> Self {
        match raw {
            "correctness" => Self::Correctness,
            "determinism" => Self::Determinism,
            "performance" => Self::Performance,
            "reproducibility" => Self::Reproducibility,
            "verification_rigor" => Self::VerificationRigor,
            "user_facing_quality" => Self::UserFacingQuality,
            other => panic!("unknown rule class: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::Determinism => "determinism",
            Self::Performance => "performance",
            Self::Reproducibility => "reproducibility",
            Self::VerificationRigor => "verification_rigor",
            Self::UserFacingQuality => "user_facing_quality",
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuleDefinition {
    rule_id: String,
    rule_class: String,
    description: String,
    minimum_millionths: u32,
    weight_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct GatingPolicy {
    minimum_weighted_score_millionths: u32,
    hard_fail_classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ArtifactBundle {
    artifact_bundle_id: String,
    git_sha: String,
    metrics_millionths: BundleMetrics,
    expected_verdict: String,
    replay_command: String,
}

#[derive(Debug, Deserialize)]
struct BundleMetrics {
    correctness: u32,
    determinism: u32,
    performance: u32,
    reproducibility: u32,
    verification_rigor: u32,
    user_facing_quality: u32,
}

#[derive(Debug, Deserialize)]
struct SupremacyCriteriaFixture {
    schema_version: String,
    criteria_version: String,
    log_schema_version: String,
    required_log_keys: Vec<String>,
    criteria_changelog: Vec<CriteriaChangelogEntry>,
    gating_policy: GatingPolicy,
    rule_definitions: Vec<RuleDefinition>,
    artifact_bundles: Vec<ArtifactBundle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Hold,
    Fail,
}

impl Verdict {
    fn from_raw(raw: &str) -> Self {
        match raw {
            "pass" => Self::Pass,
            "hold" => Self::Hold,
            "fail" => Self::Fail,
            other => panic!("unknown verdict: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Hold => "hold",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvaluationResult {
    run_id: String,
    artifact_bundle_id: String,
    git_sha: String,
    criteria_version: String,
    weighted_score_millionths: u32,
    verdict: Verdict,
    replay_command: String,
    rule_pass: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GateEvent {
    schema_version: String,
    run_id: String,
    criteria_version: String,
    git_sha: String,
    artifact_bundle_id: String,
    verdict: String,
    replay_command: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
}

fn load_fixture() -> SupremacyCriteriaFixture {
    let path = Path::new("tests/fixtures/parser_supremacy_criteria_contract_v1.json");
    let bytes = fs::read(path).expect("read parser supremacy criteria fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser supremacy criteria fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_SUPREMACY_CRITERIA_CONTRACT.md");
    fs::read_to_string(path).expect("read parser supremacy criteria doc")
}

fn metric_for_class(metrics: &BundleMetrics, class: RuleClass) -> u32 {
    match class {
        RuleClass::Correctness => metrics.correctness,
        RuleClass::Determinism => metrics.determinism,
        RuleClass::Performance => metrics.performance,
        RuleClass::Reproducibility => metrics.reproducibility,
        RuleClass::VerificationRigor => metrics.verification_rigor,
        RuleClass::UserFacingQuality => metrics.user_facing_quality,
    }
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

fn deterministic_run_id(criteria_version: &str, bundle_id: &str, git_sha: &str) -> String {
    let joined = format!("{criteria_version}|{bundle_id}|{git_sha}");
    format!("supremacy-run-{:016x}", fnv1a64(joined.as_bytes()))
}

fn evaluate_bundle(
    fixture: &SupremacyCriteriaFixture,
    bundle: &ArtifactBundle,
) -> EvaluationResult {
    let hard_fail_classes: BTreeSet<RuleClass> = fixture
        .gating_policy
        .hard_fail_classes
        .iter()
        .map(|raw| RuleClass::parse(raw))
        .collect();

    let mut weighted_numerator = 0_u128;
    let mut any_rule_failed = false;
    let mut hard_fail_triggered = false;
    let mut rule_pass = BTreeMap::new();

    for rule in &fixture.rule_definitions {
        let class = RuleClass::parse(rule.rule_class.as_str());
        let metric_value = metric_for_class(&bundle.metrics_millionths, class);
        let passed = metric_value >= rule.minimum_millionths;
        rule_pass.insert(rule.rule_id.clone(), passed);

        weighted_numerator = weighted_numerator
            .saturating_add(u128::from(metric_value) * u128::from(rule.weight_millionths));

        if !passed {
            any_rule_failed = true;
            if hard_fail_classes.contains(&class) {
                hard_fail_triggered = true;
            }
        }
    }

    let weighted_score_millionths = (weighted_numerator / 1_000_000_u128) as u32;
    let meets_weighted =
        weighted_score_millionths >= fixture.gating_policy.minimum_weighted_score_millionths;

    let verdict = if hard_fail_triggered {
        Verdict::Fail
    } else if any_rule_failed || !meets_weighted {
        Verdict::Hold
    } else {
        Verdict::Pass
    };

    EvaluationResult {
        run_id: deterministic_run_id(
            fixture.criteria_version.as_str(),
            bundle.artifact_bundle_id.as_str(),
            bundle.git_sha.as_str(),
        ),
        artifact_bundle_id: bundle.artifact_bundle_id.clone(),
        git_sha: bundle.git_sha.clone(),
        criteria_version: fixture.criteria_version.clone(),
        weighted_score_millionths,
        verdict,
        replay_command: bundle.replay_command.clone(),
        rule_pass,
    }
}

fn simulate_gate_events(fixture: &SupremacyCriteriaFixture) -> Vec<GateEvent> {
    let mut events = Vec::new();
    for bundle in &fixture.artifact_bundles {
        let result = evaluate_bundle(fixture, bundle);
        events.push(GateEvent {
            schema_version: fixture.log_schema_version.clone(),
            run_id: result.run_id,
            criteria_version: result.criteria_version,
            git_sha: result.git_sha,
            artifact_bundle_id: result.artifact_bundle_id,
            verdict: result.verdict.as_str().to_string(),
            replay_command: result.replay_command,
            component: "parser_supremacy_criteria_gate".to_string(),
            event: "criteria_evaluated".to_string(),
            outcome: result.verdict.as_str().to_string(),
            error_code: if result.verdict == Verdict::Fail {
                Some("FE-PARSER-SUPREMACY-CRITERIA-0001".to_string())
            } else {
                None
            },
        });
    }
    events
}

#[test]
fn parser_supremacy_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser Supremacy Criteria Contract (`bd-2mds.1.8.1`)",
        "## Required Criteria Dimensions",
        "## Machine-Checkable Evaluator",
        "## Deterministic Gate Simulation",
        "## Criteria Changelog Policy",
        "## Structured Log Contract",
        "./scripts/run_parser_supremacy_criteria_gate.sh ci",
    ] {
        assert!(
            doc.contains(section),
            "required section missing from supremacy criteria doc: {section}"
        );
    }
}

#[test]
fn parser_supremacy_fixture_contract_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-supremacy-criteria-contract.v1"
    );
    assert_eq!(fixture.criteria_version, "0.1.0");
    assert_eq!(
        fixture.log_schema_version,
        "franken-engine.parser-supremacy-criteria.log-event.v1"
    );

    assert!(!fixture.criteria_changelog.is_empty());
    for entry in &fixture.criteria_changelog {
        assert!(!entry.version.trim().is_empty());
        assert!(!entry.rationale.trim().is_empty());
        assert!(!entry.impact_assessment.trim().is_empty());
        assert!(!entry.compatibility_notes.trim().is_empty());
        assert!(!entry.changed_at_utc.trim().is_empty());
    }

    for required_key in [
        "run_id",
        "criteria_version",
        "git_sha",
        "artifact_bundle_id",
        "verdict",
        "replay_command",
    ] {
        assert!(
            fixture
                .required_log_keys
                .iter()
                .any(|key| key == required_key),
            "required log key missing: {required_key}"
        );
    }

    let mut rule_ids = BTreeSet::new();
    let mut classes = BTreeSet::new();
    let mut weight_total = 0_u64;

    for rule in &fixture.rule_definitions {
        assert!(rule_ids.insert(rule.rule_id.clone()));
        assert!(!rule.description.trim().is_empty());
        assert!(rule.minimum_millionths <= 1_000_000);
        classes.insert(RuleClass::parse(rule.rule_class.as_str()));
        weight_total = weight_total.saturating_add(u64::from(rule.weight_millionths));
    }

    assert_eq!(
        weight_total, 1_000_000,
        "rule weights must sum to 1_000_000"
    );
    assert_eq!(classes.len(), 6, "all six rule classes must be present");

    let hard_fail_classes: BTreeSet<RuleClass> = fixture
        .gating_policy
        .hard_fail_classes
        .iter()
        .map(|raw| RuleClass::parse(raw))
        .collect();
    for required_hard_fail in [
        RuleClass::Correctness,
        RuleClass::Determinism,
        RuleClass::Reproducibility,
    ] {
        assert!(
            hard_fail_classes.contains(&required_hard_fail),
            "missing required hard-fail class: {}",
            required_hard_fail.as_str()
        );
    }
}

#[test]
fn parser_supremacy_evaluator_enforces_rule_classes() {
    let fixture = load_fixture();
    let mut expected = BTreeMap::new();

    for bundle in &fixture.artifact_bundles {
        expected.insert(
            bundle.artifact_bundle_id.clone(),
            Verdict::from_raw(bundle.expected_verdict.as_str()),
        );
    }

    for bundle in &fixture.artifact_bundles {
        let result = evaluate_bundle(&fixture, bundle);
        let expected_verdict = expected
            .get(bundle.artifact_bundle_id.as_str())
            .expect("expected verdict by bundle id");
        assert_eq!(
            &result.verdict, expected_verdict,
            "unexpected supremacy verdict for bundle `{}`",
            bundle.artifact_bundle_id
        );

        if result.verdict == Verdict::Pass {
            assert!(
                result.rule_pass.values().all(|value| *value),
                "pass verdict requires all rules to pass"
            );
        }

        if bundle.artifact_bundle_id == "bundle-parser-determinism-regression" {
            assert_eq!(result.verdict, Verdict::Fail);
            assert!(
                !result
                    .rule_pass
                    .get("determinism-replay")
                    .copied()
                    .expect("determinism rule outcome"),
                "determinism hard-fail should force fail verdict"
            );
        }
    }
}

#[test]
fn parser_supremacy_gate_simulation_is_deterministic_and_log_complete() {
    let fixture = load_fixture();
    let first = simulate_gate_events(&fixture);
    let second = simulate_gate_events(&fixture);
    assert_eq!(first, second, "gate simulation must be deterministic");

    assert_eq!(first.len(), fixture.artifact_bundles.len());

    for event in &first {
        let value = serde_json::to_value(event).expect("serialize gate event");
        let object = value.as_object().expect("gate event object");

        for key in &fixture.required_log_keys {
            assert!(
                object.contains_key(key),
                "gate event missing required key `{key}`"
            );
            let text = object
                .get(key)
                .and_then(|raw| raw.as_str())
                .unwrap_or_default();
            assert!(
                !text.trim().is_empty(),
                "gate event key `{key}` must not be empty"
            );
        }

        assert!(
            matches!(event.verdict.as_str(), "pass" | "hold" | "fail"),
            "unexpected verdict value"
        );
    }
}

// ---------- load_fixture helper ----------

#[test]
fn load_fixture_returns_valid_fixture() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.is_empty());
    assert!(!fixture.artifact_bundles.is_empty());
    assert!(!fixture.rule_definitions.is_empty());
}

// ---------- load_doc helper ----------

#[test]
fn load_doc_returns_nonempty_string() {
    let doc = load_doc();
    assert!(!doc.is_empty());
    assert!(doc.contains("Supremacy"));
}

// ---------- RuleClass ----------

#[test]
fn rule_class_parse_all_variants() {
    assert_eq!(RuleClass::parse("correctness"), RuleClass::Correctness);
    assert_eq!(RuleClass::parse("determinism"), RuleClass::Determinism);
    assert_eq!(RuleClass::parse("performance"), RuleClass::Performance);
    assert_eq!(
        RuleClass::parse("reproducibility"),
        RuleClass::Reproducibility
    );
    assert_eq!(
        RuleClass::parse("verification_rigor"),
        RuleClass::VerificationRigor
    );
    assert_eq!(
        RuleClass::parse("user_facing_quality"),
        RuleClass::UserFacingQuality
    );
}

#[test]
#[should_panic(expected = "unknown rule class")]
fn rule_class_parse_panics_on_unknown() {
    RuleClass::parse("nonsense");
}

#[test]
fn rule_class_as_str_roundtrips() {
    for class in [
        RuleClass::Correctness,
        RuleClass::Determinism,
        RuleClass::Performance,
        RuleClass::Reproducibility,
        RuleClass::VerificationRigor,
        RuleClass::UserFacingQuality,
    ] {
        assert_eq!(RuleClass::parse(class.as_str()), class);
    }
}

// ---------- Verdict ----------

#[test]
fn verdict_from_raw_all_variants() {
    assert_eq!(Verdict::from_raw("pass"), Verdict::Pass);
    assert_eq!(Verdict::from_raw("hold"), Verdict::Hold);
    assert_eq!(Verdict::from_raw("fail"), Verdict::Fail);
}

#[test]
#[should_panic(expected = "unknown verdict")]
fn verdict_from_raw_panics_on_unknown() {
    Verdict::from_raw("invalid");
}

#[test]
fn verdict_as_str_roundtrips() {
    for verdict in [Verdict::Pass, Verdict::Hold, Verdict::Fail] {
        assert_eq!(Verdict::from_raw(verdict.as_str()), verdict);
    }
}

#[test]
fn load_fixture_has_nonempty_artifact_bundles() {
    let fixture = load_fixture();
    assert!(!fixture.artifact_bundles.is_empty());
}

#[test]
fn load_fixture_has_nonempty_rule_definitions() {
    let fixture = load_fixture();
    assert!(!fixture.rule_definitions.is_empty());
}

#[test]
fn load_doc_mentions_supremacy() {
    let doc = load_doc();
    assert!(doc.contains("Supremacy"));
}

// ---------- metric_for_class ----------

#[test]
fn metric_for_class_returns_correct_field() {
    let metrics = BundleMetrics {
        correctness: 100,
        determinism: 200,
        performance: 300,
        reproducibility: 400,
        verification_rigor: 500,
        user_facing_quality: 600,
    };
    assert_eq!(metric_for_class(&metrics, RuleClass::Correctness), 100);
    assert_eq!(metric_for_class(&metrics, RuleClass::Determinism), 200);
    assert_eq!(metric_for_class(&metrics, RuleClass::Performance), 300);
    assert_eq!(metric_for_class(&metrics, RuleClass::Reproducibility), 400);
    assert_eq!(
        metric_for_class(&metrics, RuleClass::VerificationRigor),
        500
    );
    assert_eq!(
        metric_for_class(&metrics, RuleClass::UserFacingQuality),
        600
    );
}

// ---------- fnv1a64 ----------

#[test]
fn fnv1a64_is_deterministic() {
    let a = fnv1a64(b"test");
    let b = fnv1a64(b"test");
    assert_eq!(a, b);
}

#[test]
fn fnv1a64_differs_for_different_inputs() {
    assert_ne!(fnv1a64(b"a"), fnv1a64(b"b"));
}

// ---------- deterministic_run_id ----------

#[test]
fn deterministic_run_id_is_stable() {
    let a = deterministic_run_id("v1", "bundle-1", "abc123");
    let b = deterministic_run_id("v1", "bundle-1", "abc123");
    assert_eq!(a, b);
    assert!(a.starts_with("supremacy-run-"));
}

#[test]
fn deterministic_run_id_changes_with_inputs() {
    let a = deterministic_run_id("v1", "bundle-1", "abc123");
    let b = deterministic_run_id("v2", "bundle-1", "abc123");
    assert_ne!(a, b);
}

// ---------- evaluate_bundle determinism ----------

#[test]
fn evaluate_bundle_is_deterministic() {
    let fixture = load_fixture();
    let bundle = &fixture.artifact_bundles[0];
    let a = evaluate_bundle(&fixture, bundle);
    let b = evaluate_bundle(&fixture, bundle);
    assert_eq!(a, b);
}

// ---------- GateEvent ----------

#[test]
fn gate_event_serde_has_required_fields() {
    let event = GateEvent {
        schema_version: "v1".to_string(),
        run_id: "run-1".to_string(),
        criteria_version: "0.1.0".to_string(),
        git_sha: "abc".to_string(),
        artifact_bundle_id: "bundle-1".to_string(),
        verdict: "pass".to_string(),
        replay_command: "./replay.sh".to_string(),
        component: "gate".to_string(),
        event: "evaluated".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let value = serde_json::to_value(&event).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(obj.contains_key("run_id"));
    assert!(obj.contains_key("verdict"));
    assert!(obj.contains_key("error_code"));
}

// ---------- additional doc and contract validation ----------

#[test]
fn supremacy_doc_word_count_exceeds_minimum() {
    let doc = load_doc();
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 200,
        "supremacy criteria doc must have at least 200 words, found {word_count}"
    );
}

#[test]
fn supremacy_doc_contains_required_keywords() {
    let doc = load_doc();
    for keyword in [
        "deterministic",
        "correctness",
        "determinism",
        "performance",
        "reproducibility",
        "verification_rigor",
        "user_facing_quality",
        "hard-fail",
    ] {
        assert!(
            doc.contains(keyword),
            "supremacy criteria doc missing required keyword: {keyword}"
        );
    }
}

#[test]
fn supremacy_doc_section_ordering_is_correct() {
    let doc = load_doc();
    let sections = [
        "## Contract Version",
        "## Required Criteria Dimensions",
        "## Machine-Checkable Evaluator",
        "## Deterministic Gate Simulation",
        "## Criteria Changelog Policy",
        "## Structured Log Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
        "## Operator Verification",
    ];
    let mut last_pos = 0;
    for section in sections {
        if let Some(pos) = doc.find(section) {
            assert!(
                pos >= last_pos,
                "section `{section}` appears out of order in supremacy doc"
            );
            last_pos = pos;
        }
    }
}

#[test]
fn supremacy_fixture_rule_ids_have_consistent_format() {
    let fixture = load_fixture();
    for rule in &fixture.rule_definitions {
        assert!(
            rule.rule_id.contains('-'),
            "rule_id `{}` should use hyphenated format",
            rule.rule_id
        );
        assert!(
            !rule.rule_id.contains(' '),
            "rule_id `{}` must not contain spaces",
            rule.rule_id
        );
    }
}

#[test]
fn supremacy_fixture_all_bundles_have_replay_commands() {
    let fixture = load_fixture();
    for bundle in &fixture.artifact_bundles {
        assert!(
            !bundle.replay_command.trim().is_empty(),
            "bundle `{}` must have a replay command",
            bundle.artifact_bundle_id
        );
        assert!(
            bundle.replay_command.starts_with("./scripts/"),
            "bundle `{}` replay command must start with ./scripts/",
            bundle.artifact_bundle_id
        );
    }
}

#[test]
fn supremacy_fixture_bundle_ids_are_unique() {
    let fixture = load_fixture();
    let mut ids = BTreeSet::new();
    for bundle in &fixture.artifact_bundles {
        assert!(
            ids.insert(bundle.artifact_bundle_id.clone()),
            "duplicate artifact_bundle_id: {}",
            bundle.artifact_bundle_id
        );
    }
}

#[test]
fn supremacy_fixture_git_shas_are_nonempty() {
    let fixture = load_fixture();
    for bundle in &fixture.artifact_bundles {
        assert!(
            !bundle.git_sha.trim().is_empty(),
            "bundle `{}` must have a git_sha",
            bundle.artifact_bundle_id
        );
    }
}

#[test]
fn supremacy_gate_events_fail_verdict_has_error_code() {
    let fixture = load_fixture();
    let events = simulate_gate_events(&fixture);
    for event in &events {
        if event.verdict == "fail" {
            assert!(
                event.error_code.is_some(),
                "fail verdict must include an error_code"
            );
            let code = event.error_code.as_ref().unwrap();
            assert!(
                code.starts_with("FE-PARSER-"),
                "error code must start with FE-PARSER- prefix, got: {code}"
            );
        }
    }
}

#[test]
fn supremacy_gate_events_pass_verdict_has_no_error_code() {
    let fixture = load_fixture();
    let events = simulate_gate_events(&fixture);
    for event in &events {
        if event.verdict == "pass" {
            assert!(
                event.error_code.is_none(),
                "pass verdict must not include an error_code"
            );
        }
    }
}

#[test]
fn supremacy_fixture_minimum_weighted_score_is_reasonable() {
    let fixture = load_fixture();
    // The minimum weighted score should be positive and less than the max possible (1_000_000)
    assert!(fixture.gating_policy.minimum_weighted_score_millionths > 0);
    assert!(fixture.gating_policy.minimum_weighted_score_millionths <= 1_000_000);
}
