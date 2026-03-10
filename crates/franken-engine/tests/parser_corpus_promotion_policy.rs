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

use std::fs;
use std::path::Path;

use frankenengine_engine::ast::{ParseGoal, SyntaxTree};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, ParseDiagnosticEnvelope, ParseErrorCode, ParserMode,
    normalize_parse_error,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const NORMATIVE_CATALOG_PATH: &str = "tests/fixtures/parser_phase0_semantic_fixtures.json";
const ADVERSARIAL_CATALOG_PATH: &str = "tests/fixtures/parser_phase0_adversarial_fixtures.json";
const PROMOTION_POLICY_PATH: &str = "tests/fixtures/parser_reducer_promotion_policy.json";

#[derive(Debug, Clone, Deserialize)]
struct NormativeFixtureSpec {
    id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_hash: String,
}

#[derive(Debug, Deserialize)]
struct NormativeFixtureCatalog {
    schema_version: String,
    parser_mode: String,
    fixtures: Vec<NormativeFixtureSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct AdversarialFixtureSpec {
    id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_parse_error: String,
    expected_diagnostic_code: String,
    severity: String,
    provenance_tag: String,
}

#[derive(Debug, Deserialize)]
struct AdversarialFixtureCatalog {
    schema_version: String,
    parser_mode: String,
    fixtures: Vec<AdversarialFixtureSpec>,
}

#[derive(Debug, Deserialize)]
struct PromotionRule {
    corpus: String,
    requires_expected_hash: bool,
    requires_expected_diagnostic_code: bool,
    requires_ast_contract_compat: bool,
    requires_diag_compat: bool,
}

#[derive(Debug, Deserialize)]
struct AutoPromoteConfig {
    max_source_bytes: usize,
    allowed_outcomes: Vec<String>,
    requires_replay_command: bool,
}

#[derive(Debug, Deserialize)]
struct PromotionPolicy {
    schema_version: String,
    policy_id: String,
    parser_mode: String,
    ast_contract_schema: String,
    diagnostics_schema: String,
    diagnostics_taxonomy: String,
    provenance_hash_algorithm: String,
    promotion_rules: Vec<PromotionRule>,
    auto_promote: AutoPromoteConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PromotionReceipt {
    schema_version: String,
    policy_id: String,
    corpus: String,
    fixture_id: String,
    family_id: String,
    parser_mode: String,
    trace_id: String,
    decision_id: String,
    ast_contract_schema: String,
    diagnostics_schema: String,
    diagnostics_taxonomy: String,
    expected_hash: Option<String>,
    expected_diagnostic_code: Option<String>,
    observed_hash: Option<String>,
    observed_diagnostic_code: Option<String>,
    observed_parse_error: Option<String>,
    replay_command: String,
    promotion_outcome: String,
    promotion_reason: String,
    source_hash: String,
    provenance_hash: String,
}

fn load_normative_catalog() -> NormativeFixtureCatalog {
    let bytes =
        fs::read(Path::new(NORMATIVE_CATALOG_PATH)).expect("read normative parser fixture catalog");
    serde_json::from_slice(&bytes).expect("deserialize normative parser fixture catalog")
}

fn load_adversarial_catalog() -> AdversarialFixtureCatalog {
    let bytes = fs::read(Path::new(ADVERSARIAL_CATALOG_PATH))
        .expect("read adversarial parser fixture catalog");
    serde_json::from_slice(&bytes).expect("deserialize adversarial parser fixture catalog")
}

fn load_promotion_policy() -> PromotionPolicy {
    let bytes =
        fs::read(Path::new(PROMOTION_POLICY_PATH)).expect("read parser reducer promotion policy");
    serde_json::from_slice(&bytes).expect("deserialize parser reducer promotion policy")
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown parse goal `{other}` in parser corpus fixture"),
    }
}

fn parse_error_code(raw: &str) -> ParseErrorCode {
    ParseErrorCode::ALL
        .iter()
        .copied()
        .find(|code| code.as_str() == raw)
        .unwrap_or_else(|| panic!("unknown parse error code `{raw}` in adversarial fixture"))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn receipt_hash(receipt: &PromotionReceipt) -> String {
    let bytes = serde_json::to_vec(receipt).expect("serialize promotion receipt");
    hash_bytes(bytes.as_slice())
}

fn stable_replay_command(corpus: &str, fixture_id: &str) -> String {
    format!(
        "rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_reducer_promotion PARSER_REDUCER_CORPUS={corpus} PARSER_REDUCER_FIXTURE={fixture_id} cargo test -p frankenengine-engine --test parser_corpus_promotion_policy -- --nocapture"
    )
}

fn trace_id_for(corpus: &str, fixture_id: &str) -> String {
    format!("trace-parser-reducer-promotion-{corpus}-{fixture_id}")
}

fn decision_id_for(corpus: &str, fixture_id: &str) -> String {
    format!("decision-parser-reducer-promotion-{corpus}-{fixture_id}")
}

fn rule_for<'a>(policy: &'a PromotionPolicy, corpus: &str) -> &'a PromotionRule {
    policy
        .promotion_rules
        .iter()
        .find(|rule| rule.corpus == corpus)
        .unwrap_or_else(|| panic!("missing promotion rule for corpus `{corpus}`"))
}

fn outcome_allowed(policy: &PromotionPolicy, outcome: &str) -> bool {
    policy
        .auto_promote
        .allowed_outcomes
        .iter()
        .any(|allowed| allowed == outcome)
}

fn evaluate_normative(
    policy: &PromotionPolicy,
    fixture: &NormativeFixtureSpec,
    parser: &CanonicalEs2020Parser,
) -> PromotionReceipt {
    let rule = rule_for(policy, "normative");
    let source_hash = hash_bytes(fixture.source.as_bytes());
    let replay_command = stable_replay_command("normative", fixture.id.as_str());
    let ast_contract_match = policy.ast_contract_schema == SyntaxTree::canonical_schema_version();
    let diagnostics_schema_match =
        policy.diagnostics_schema == ParseDiagnosticEnvelope::schema_version();
    let diagnostics_taxonomy_match =
        policy.diagnostics_taxonomy == ParseDiagnosticEnvelope::taxonomy_version();

    let mut observed_hash = None;
    let mut observed_parse_error = None;
    let mut observed_diagnostic_code = None;
    let mut promotion_outcome = "reject".to_string();
    let mut promotion_reason = "parse failed for normative fixture".to_string();

    match parser.parse(fixture.source.as_str(), parse_goal(fixture.goal.as_str())) {
        Ok(tree) => {
            let hash = tree.canonical_hash();
            observed_hash = Some(hash.clone());

            let hash_match = hash == fixture.expected_hash;
            let expected_hash_ok = !rule.requires_expected_hash || hash_match;
            let ast_ok = !rule.requires_ast_contract_compat || ast_contract_match;
            let replay_ok =
                !policy.auto_promote.requires_replay_command || !replay_command.is_empty();
            let source_size_ok = fixture.source.len() <= policy.auto_promote.max_source_bytes;
            let diagnostics_contract_ok = !rule.requires_diag_compat
                || (diagnostics_schema_match && diagnostics_taxonomy_match);

            if expected_hash_ok && ast_ok && replay_ok && source_size_ok && diagnostics_contract_ok
            {
                promotion_outcome = "promote".to_string();
                promotion_reason =
                    "normative fixture hash matches canonical AST contract".to_string();
            } else {
                promotion_outcome = "hold".to_string();
                promotion_reason = "normative fixture did not satisfy promotion gates".to_string();
            }
        }
        Err(error) => {
            observed_parse_error = Some(error.code.as_str().to_string());
            observed_diagnostic_code = Some(error.code.stable_diagnostic_code().to_string());
        }
    }

    if !outcome_allowed(policy, promotion_outcome.as_str()) && promotion_outcome == "promote" {
        promotion_outcome = "hold".to_string();
        promotion_reason = "policy disallows this promotion outcome".to_string();
    }

    let provenance_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        policy.policy_id,
        fixture.id,
        fixture.family_id,
        source_hash,
        fixture.expected_hash,
        observed_hash.as_deref().unwrap_or("null"),
        promotion_outcome,
        SyntaxTree::canonical_schema_version(),
        ParseDiagnosticEnvelope::schema_version(),
        replay_command,
    );

    PromotionReceipt {
        schema_version: "franken-engine.parser-reducer-promotion.receipt.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        corpus: "normative".to_string(),
        fixture_id: fixture.id.clone(),
        family_id: fixture.family_id.clone(),
        parser_mode: policy.parser_mode.clone(),
        trace_id: trace_id_for("normative", fixture.id.as_str()),
        decision_id: decision_id_for("normative", fixture.id.as_str()),
        ast_contract_schema: policy.ast_contract_schema.clone(),
        diagnostics_schema: policy.diagnostics_schema.clone(),
        diagnostics_taxonomy: policy.diagnostics_taxonomy.clone(),
        expected_hash: Some(fixture.expected_hash.clone()),
        expected_diagnostic_code: None,
        observed_hash,
        observed_diagnostic_code,
        observed_parse_error,
        replay_command,
        promotion_outcome,
        promotion_reason,
        source_hash,
        provenance_hash: hash_bytes(provenance_input.as_bytes()),
    }
}

fn evaluate_adversarial(
    policy: &PromotionPolicy,
    fixture: &AdversarialFixtureSpec,
    parser: &CanonicalEs2020Parser,
) -> PromotionReceipt {
    let rule = rule_for(policy, "adversarial");
    let source_hash = hash_bytes(fixture.source.as_bytes());
    let replay_command = stable_replay_command("adversarial", fixture.id.as_str());
    let ast_contract_match = policy.ast_contract_schema == SyntaxTree::canonical_schema_version();

    let mut observed_hash = None;
    let mut observed_parse_error = None;
    let mut observed_diagnostic_code = None;
    let mut promotion_outcome = "reject".to_string();
    let mut promotion_reason = "adversarial fixture unexpectedly parsed".to_string();

    match parser.parse(fixture.source.as_str(), parse_goal(fixture.goal.as_str())) {
        Ok(tree) => {
            observed_hash = Some(tree.canonical_hash());
        }
        Err(error) => {
            let normalized = normalize_parse_error(&error);
            observed_parse_error = Some(error.code.as_str().to_string());
            observed_diagnostic_code = Some(normalized.diagnostic_code.clone());

            let parse_error_match =
                error.code == parse_error_code(fixture.expected_parse_error.as_str());
            let diagnostic_code_match =
                normalized.diagnostic_code == fixture.expected_diagnostic_code;
            let severity_match = normalized.severity.as_str() == fixture.severity;
            let diagnostics_schema_match = normalized.schema_version == policy.diagnostics_schema;
            let diagnostics_taxonomy_match =
                normalized.taxonomy_version == policy.diagnostics_taxonomy;
            let expected_diag_ok = !rule.requires_expected_diagnostic_code || diagnostic_code_match;
            let ast_ok = !rule.requires_ast_contract_compat || ast_contract_match;
            let diag_contract_ok = !rule.requires_diag_compat
                || (diagnostics_schema_match && diagnostics_taxonomy_match);
            let replay_ok =
                !policy.auto_promote.requires_replay_command || !replay_command.is_empty();
            let source_size_ok = fixture.source.len() <= policy.auto_promote.max_source_bytes;

            if parse_error_match
                && expected_diag_ok
                && severity_match
                && ast_ok
                && diag_contract_ok
                && replay_ok
                && source_size_ok
            {
                promotion_outcome = "promote".to_string();
                promotion_reason =
                    "adversarial fixture preserves diagnostics normalization contract".to_string();
            } else {
                promotion_outcome = "hold".to_string();
                promotion_reason =
                    "diagnostic code drift or contract compatibility failure".to_string();
            }
        }
    }

    if !outcome_allowed(policy, promotion_outcome.as_str()) && promotion_outcome == "promote" {
        promotion_outcome = "hold".to_string();
        promotion_reason = "policy disallows this promotion outcome".to_string();
    }

    let provenance_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        policy.policy_id,
        fixture.id,
        fixture.family_id,
        fixture.provenance_tag,
        source_hash,
        fixture.expected_parse_error,
        fixture.expected_diagnostic_code,
        observed_diagnostic_code.as_deref().unwrap_or("null"),
        promotion_outcome,
        ParseDiagnosticEnvelope::schema_version(),
        replay_command,
    );

    PromotionReceipt {
        schema_version: "franken-engine.parser-reducer-promotion.receipt.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        corpus: "adversarial".to_string(),
        fixture_id: fixture.id.clone(),
        family_id: fixture.family_id.clone(),
        parser_mode: policy.parser_mode.clone(),
        trace_id: trace_id_for("adversarial", fixture.id.as_str()),
        decision_id: decision_id_for("adversarial", fixture.id.as_str()),
        ast_contract_schema: policy.ast_contract_schema.clone(),
        diagnostics_schema: policy.diagnostics_schema.clone(),
        diagnostics_taxonomy: policy.diagnostics_taxonomy.clone(),
        expected_hash: None,
        expected_diagnostic_code: Some(fixture.expected_diagnostic_code.clone()),
        observed_hash,
        observed_diagnostic_code,
        observed_parse_error,
        replay_command,
        promotion_outcome,
        promotion_reason,
        source_hash,
        provenance_hash: hash_bytes(provenance_input.as_bytes()),
    }
}

#[test]
fn parser_corpus_normative_adversarial_promotion_contract_holds() {
    let normative = load_normative_catalog();
    let adversarial = load_adversarial_catalog();
    let policy = load_promotion_policy();

    assert_eq!(
        normative.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
    assert_eq!(
        adversarial.schema_version,
        "franken-engine.parser-phase0.adversarial-fixtures.v1"
    );
    assert_eq!(
        policy.schema_version,
        "franken-engine.parser-reducer-promotion.policy.v1"
    );

    assert_eq!(normative.parser_mode, ParserMode::ScalarReference.as_str());
    assert_eq!(
        adversarial.parser_mode,
        ParserMode::ScalarReference.as_str()
    );
    assert_eq!(policy.parser_mode, ParserMode::ScalarReference.as_str());
    assert_eq!(
        policy.ast_contract_schema,
        SyntaxTree::canonical_schema_version()
    );
    assert_eq!(
        policy.diagnostics_schema,
        ParseDiagnosticEnvelope::schema_version()
    );
    assert_eq!(
        policy.diagnostics_taxonomy,
        ParseDiagnosticEnvelope::taxonomy_version()
    );
    assert_eq!(policy.provenance_hash_algorithm, "sha256");

    let parser = CanonicalEs2020Parser;

    let normative_promoted = normative
        .fixtures
        .iter()
        .map(|fixture| evaluate_normative(&policy, fixture, &parser))
        .filter(|receipt| receipt.promotion_outcome == "promote")
        .count();
    assert_eq!(normative_promoted, normative.fixtures.len());

    let adversarial_receipts: Vec<_> = adversarial
        .fixtures
        .iter()
        .map(|fixture| evaluate_adversarial(&policy, fixture, &parser))
        .collect();
    assert_eq!(
        adversarial_receipts
            .iter()
            .filter(|receipt| receipt.promotion_outcome == "promote")
            .count(),
        adversarial.fixtures.len()
    );

    for receipt in adversarial_receipts {
        assert!(receipt.observed_hash.is_none());
        assert!(receipt.observed_parse_error.is_some());
        assert!(receipt.observed_diagnostic_code.is_some());
        assert!(receipt.provenance_hash.starts_with("sha256:"));
    }
}

#[test]
fn reducer_promotion_receipts_are_deterministic() {
    let normative = load_normative_catalog();
    let adversarial = load_adversarial_catalog();
    let policy = load_promotion_policy();
    let parser = CanonicalEs2020Parser;

    let normative_fixture = normative
        .fixtures
        .first()
        .expect("normative fixture catalog must not be empty");
    let adversarial_fixture = adversarial
        .fixtures
        .first()
        .expect("adversarial fixture catalog must not be empty");

    let normative_a = evaluate_normative(&policy, normative_fixture, &parser);
    let normative_b = evaluate_normative(&policy, normative_fixture, &parser);
    assert_eq!(normative_a, normative_b);
    assert_eq!(receipt_hash(&normative_a), receipt_hash(&normative_b));

    let adversarial_a = evaluate_adversarial(&policy, adversarial_fixture, &parser);
    let adversarial_b = evaluate_adversarial(&policy, adversarial_fixture, &parser);
    assert_eq!(adversarial_a, adversarial_b);
    assert_eq!(receipt_hash(&adversarial_a), receipt_hash(&adversarial_b));
}

#[test]
fn adversarial_promotion_detects_diagnostic_drift() {
    let adversarial = load_adversarial_catalog();
    let policy = load_promotion_policy();
    let parser = CanonicalEs2020Parser;

    let mut drift_fixture = adversarial
        .fixtures
        .first()
        .expect("adversarial fixture catalog must not be empty")
        .clone();
    drift_fixture.expected_diagnostic_code = "FE-PARSER-DIAG-UNSUPPORTED-SYNTAX-0001".to_string();

    let receipt = evaluate_adversarial(&policy, &drift_fixture, &parser);
    assert_ne!(receipt.promotion_outcome, "promote");
    assert!(
        receipt
            .promotion_reason
            .contains("diagnostic code drift or contract compatibility failure")
    );
}

// ---------- helper functions ----------

#[test]
fn parse_goal_maps_correctly() {
    assert_eq!(parse_goal("script"), ParseGoal::Script);
    assert_eq!(parse_goal("module"), ParseGoal::Module);
}

#[test]
fn parse_error_code_maps_all_known_codes() {
    for code in ParseErrorCode::ALL {
        let roundtrip = parse_error_code(code.as_str());
        assert_eq!(roundtrip, code);
    }
}

#[test]
fn hash_bytes_starts_with_sha256_prefix() {
    let h = hash_bytes(b"test data");
    assert!(h.starts_with("sha256:"));
    assert_eq!(h.len(), 7 + 64); // "sha256:" + 64 hex chars
}

#[test]
fn hash_bytes_is_deterministic() {
    assert_eq!(hash_bytes(b"hello"), hash_bytes(b"hello"));
}

#[test]
fn hash_bytes_differs_for_different_inputs() {
    assert_ne!(hash_bytes(b"hello"), hash_bytes(b"world"));
}

#[test]
fn trace_id_for_contains_corpus_and_fixture() {
    let id = trace_id_for("normative", "fixture-001");
    assert!(id.contains("normative"));
    assert!(id.contains("fixture-001"));
    assert!(id.starts_with("trace-"));
}

#[test]
fn decision_id_for_contains_corpus_and_fixture() {
    let id = decision_id_for("adversarial", "fixture-002");
    assert!(id.contains("adversarial"));
    assert!(id.contains("fixture-002"));
    assert!(id.starts_with("decision-"));
}

#[test]
fn stable_replay_command_contains_corpus_and_fixture() {
    let cmd = stable_replay_command("normative", "fixture-001");
    assert!(cmd.contains("PARSER_REDUCER_CORPUS=normative"));
    assert!(cmd.contains("PARSER_REDUCER_FIXTURE=fixture-001"));
}

// ---------- promotion policy loading ----------

#[test]
fn promotion_policy_has_two_rules() {
    let policy = load_promotion_policy();
    assert_eq!(policy.promotion_rules.len(), 2);
    assert!(
        policy
            .promotion_rules
            .iter()
            .any(|r| r.corpus == "normative")
    );
    assert!(
        policy
            .promotion_rules
            .iter()
            .any(|r| r.corpus == "adversarial")
    );
}

#[test]
fn promotion_policy_schema_version_is_v1() {
    let policy = load_promotion_policy();
    assert_eq!(
        policy.schema_version,
        "franken-engine.parser-reducer-promotion.policy.v1"
    );
}

#[test]
fn promotion_policy_provenance_uses_sha256() {
    let policy = load_promotion_policy();
    assert_eq!(policy.provenance_hash_algorithm, "sha256");
}

// ---------- catalog loading ----------

#[test]
fn normative_catalog_has_fixtures() {
    let catalog = load_normative_catalog();
    assert!(!catalog.fixtures.is_empty());
}

#[test]
fn adversarial_catalog_has_fixtures() {
    let catalog = load_adversarial_catalog();
    assert!(!catalog.fixtures.is_empty());
}

// ---------- receipt_hash ----------

#[test]
fn receipt_hash_is_deterministic() {
    let policy = load_promotion_policy();
    let normative = load_normative_catalog();
    let parser = CanonicalEs2020Parser;
    let fixture = normative.fixtures.first().expect("fixture");
    let receipt = evaluate_normative(&policy, fixture, &parser);
    assert_eq!(receipt_hash(&receipt), receipt_hash(&receipt));
}

// ---------- rule_for ----------

#[test]
fn rule_for_finds_normative_rule() {
    let policy = load_promotion_policy();
    let rule = rule_for(&policy, "normative");
    assert!(rule.requires_expected_hash);
}

#[test]
fn rule_for_finds_adversarial_rule() {
    let policy = load_promotion_policy();
    let rule = rule_for(&policy, "adversarial");
    assert!(rule.requires_expected_diagnostic_code);
}

// ---------- outcome_allowed ----------

#[test]
fn outcome_allowed_accepts_promote() {
    let policy = load_promotion_policy();
    assert!(outcome_allowed(&policy, "promote"));
}

#[test]
fn outcome_allowed_rejects_unknown() {
    let policy = load_promotion_policy();
    assert!(!outcome_allowed(&policy, "unknown_outcome"));
}

// ---------- PromotionReceipt ----------

#[test]
fn normative_receipt_has_expected_fields() {
    let policy = load_promotion_policy();
    let normative = load_normative_catalog();
    let parser = CanonicalEs2020Parser;
    let fixture = normative.fixtures.first().expect("fixture");
    let receipt = evaluate_normative(&policy, fixture, &parser);
    assert_eq!(receipt.corpus, "normative");
    assert_eq!(receipt.promotion_outcome, "promote");
    assert!(receipt.provenance_hash.starts_with("sha256:"));
    assert!(receipt.source_hash.starts_with("sha256:"));
    assert!(!receipt.replay_command.is_empty());
}

#[test]
fn adversarial_receipt_has_expected_fields() {
    let policy = load_promotion_policy();
    let adversarial = load_adversarial_catalog();
    let parser = CanonicalEs2020Parser;
    let fixture = adversarial.fixtures.first().expect("fixture");
    let receipt = evaluate_adversarial(&policy, fixture, &parser);
    assert_eq!(receipt.corpus, "adversarial");
    assert!(receipt.observed_parse_error.is_some());
    assert!(receipt.observed_diagnostic_code.is_some());
    assert!(receipt.observed_hash.is_none());
}

#[test]
fn hash_bytes_empty_input_is_deterministic() {
    let a = hash_bytes(b"");
    let b = hash_bytes(b"");
    assert_eq!(a, b);
    assert!(a.starts_with("sha256:"));
    assert_eq!(a.len(), 7 + 64);
}

#[test]
fn normative_catalog_fixture_ids_are_unique() {
    let catalog = load_normative_catalog();
    let mut seen = std::collections::BTreeSet::new();
    for fixture in &catalog.fixtures {
        assert!(
            seen.insert(&fixture.id),
            "duplicate normative fixture id: {}",
            fixture.id
        );
    }
}

#[test]
fn adversarial_catalog_fixture_ids_are_unique() {
    let catalog = load_adversarial_catalog();
    let mut seen = std::collections::BTreeSet::new();
    for fixture in &catalog.fixtures {
        assert!(
            seen.insert(&fixture.id),
            "duplicate adversarial fixture id: {}",
            fixture.id
        );
    }
}

#[test]
fn promotion_receipt_serde_roundtrip() {
    let policy = load_promotion_policy();
    let normative = load_normative_catalog();
    let parser = CanonicalEs2020Parser;
    let fixture = normative.fixtures.first().expect("fixture");
    let receipt = evaluate_normative(&policy, fixture, &parser);
    let json = serde_json::to_vec(&receipt).expect("serialize receipt");
    assert!(!json.is_empty(), "serialized receipt must not be empty");
    // Receipt is Serialize but not Deserialize, so just check JSON validity
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("receipt json must be valid");
    assert_eq!(value["corpus"].as_str().unwrap_or(""), "normative");
    assert_eq!(value["promotion_outcome"].as_str().unwrap_or(""), "promote");
}

#[test]
fn receipt_hash_differs_for_different_fixtures() {
    let policy = load_promotion_policy();
    let normative = load_normative_catalog();
    let parser = CanonicalEs2020Parser;
    assert!(
        normative.fixtures.len() >= 2,
        "need at least 2 normative fixtures"
    );
    let receipt_a = evaluate_normative(&policy, &normative.fixtures[0], &parser);
    let receipt_b = evaluate_normative(&policy, &normative.fixtures[1], &parser);
    assert_ne!(
        receipt_hash(&receipt_a),
        receipt_hash(&receipt_b),
        "distinct fixtures should produce distinct receipt hashes"
    );
}

#[test]
fn auto_promote_config_max_source_bytes_is_positive() {
    let policy = load_promotion_policy();
    assert!(
        policy.auto_promote.max_source_bytes > 0,
        "auto_promote max_source_bytes must be positive"
    );
}

#[test]
fn stable_replay_command_contains_test_name() {
    let cmd = stable_replay_command("normative", "fix-123");
    assert!(
        cmd.contains("parser_corpus_promotion_policy"),
        "replay command must reference this test file"
    );
}
