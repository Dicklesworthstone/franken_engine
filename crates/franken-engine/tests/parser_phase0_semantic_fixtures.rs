use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, ParserMode, ParserOptions,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureSpec {
    id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_hash: String,
}

#[derive(Debug, Deserialize)]
struct FixtureCatalog {
    schema_version: String,
    parser_mode: String,
    fixtures: Vec<FixtureSpec>,
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown goal in fixture catalog: {other}"),
    }
}

#[test]
fn parser_phase0_semantic_fixtures_match_expected_hashes() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read parser phase0 fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize parser phase0 fixture catalog");

    assert_eq!(
        catalog.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
    assert_eq!(catalog.parser_mode, ParserMode::ScalarReference.as_str());
    assert!(
        !catalog.fixtures.is_empty(),
        "parser phase0 fixture catalog must include fixtures"
    );

    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    for fixture in &catalog.fixtures {
        assert!(
            fixture.expected_hash.starts_with("sha256:"),
            "fixture `{}` missing expected hash prefix",
            fixture.id
        );

        let tree = parser
            .parse_with_options(
                fixture.source.as_str(),
                parse_goal(fixture.goal.as_str()),
                &options,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "fixture `{}` (`{}`) failed to parse: {error}",
                    fixture.id, fixture.family_id
                )
            });
        let actual = tree.canonical_hash();
        assert_eq!(
            actual, fixture.expected_hash,
            "fixture `{}` (`{}`) hash drift",
            fixture.id, fixture.family_id
        );
    }
}

#[test]
#[ignore]
fn print_parser_phase0_fixture_hashes() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read parser phase0 fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize parser phase0 fixture catalog");
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    for fixture in &catalog.fixtures {
        let tree = parser
            .parse_with_options(
                fixture.source.as_str(),
                parse_goal(fixture.goal.as_str()),
                &options,
            )
            .unwrap_or_else(|error| panic!("fixture `{}` parse failed: {error}", fixture.id));
        println!("{}\t{}", fixture.id, tree.canonical_hash());
    }
}

// ---------- ParserMode ----------

#[test]
fn parser_mode_scalar_reference_as_str() {
    assert_eq!(ParserMode::ScalarReference.as_str(), "scalar_reference");
}

// ---------- ParserOptions defaults ----------

#[test]
fn parser_options_default_uses_scalar_reference() {
    let options = ParserOptions::default();
    assert_eq!(options.mode, ParserMode::ScalarReference);
}

// ---------- ParseGoal ----------

#[test]
fn parse_goal_as_str_values() {
    use frankenengine_engine::ast::ParseGoal as PG;
    assert_eq!(PG::Script.as_str(), "script");
    assert_eq!(PG::Module.as_str(), "module");
}

// ---------- CanonicalEs2020Parser ----------

#[test]
fn parser_parses_simple_script_successfully() {
    let parser = CanonicalEs2020Parser;
    let result = parser.parse("var x = 1;", ParseGoal::Script);
    assert!(result.is_ok());
}

#[test]
fn parser_parses_simple_module_successfully() {
    let parser = CanonicalEs2020Parser;
    let result = parser.parse("export default 42;", ParseGoal::Module);
    assert!(result.is_ok());
}

#[test]
fn parser_rejects_empty_source() {
    use frankenengine_engine::parser::ParseErrorCode;
    let parser = CanonicalEs2020Parser;
    let result = parser.parse("", ParseGoal::Script);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ParseErrorCode::EmptySource);
}

// ---------- SyntaxTree ----------

#[test]
fn syntax_tree_canonical_hash_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let tree_a = parser.parse("var x = 1;", ParseGoal::Script).unwrap();
    let tree_b = parser.parse("var x = 1;", ParseGoal::Script).unwrap();
    assert_eq!(tree_a.canonical_hash(), tree_b.canonical_hash());
}

#[test]
fn syntax_tree_canonical_hash_starts_with_sha256_prefix() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("var x = 1;", ParseGoal::Script).unwrap();
    assert!(tree.canonical_hash().starts_with("sha256:"));
}

#[test]
fn syntax_tree_canonical_schema_version_is_nonempty() {
    use frankenengine_engine::ast::SyntaxTree;
    assert!(!SyntaxTree::canonical_schema_version().is_empty());
}

#[test]
fn syntax_tree_canonical_contract_version_is_nonempty() {
    use frankenengine_engine::ast::SyntaxTree;
    assert!(!SyntaxTree::canonical_contract_version().is_empty());
}

// ---------- ParseErrorCode ----------

#[test]
fn parse_error_code_all_has_seven_variants() {
    use frankenengine_engine::parser::ParseErrorCode;
    assert_eq!(ParseErrorCode::ALL.len(), 7);
}

#[test]
fn parse_error_code_as_str_values_are_nonempty() {
    use frankenengine_engine::parser::ParseErrorCode;
    for code in ParseErrorCode::ALL {
        assert!(!code.as_str().is_empty());
        assert!(!code.stable_diagnostic_code().is_empty());
    }
}

// ---------- ParseDiagnosticEnvelope ----------

#[test]
fn parse_diagnostic_envelope_schema_and_taxonomy_versions() {
    use frankenengine_engine::parser::ParseDiagnosticEnvelope;
    assert!(!ParseDiagnosticEnvelope::schema_version().is_empty());
    assert!(!ParseDiagnosticEnvelope::taxonomy_version().is_empty());
}

// ---------- Fixture catalog invariants ----------

#[test]
fn fixture_catalog_has_at_least_one_script_and_one_module_fixture() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture catalog");

    let has_script = catalog.fixtures.iter().any(|f| f.goal == "script");
    let has_module = catalog.fixtures.iter().any(|f| f.goal == "module");
    assert!(
        has_script,
        "catalog must contain at least one script fixture"
    );
    assert!(
        has_module,
        "catalog must contain at least one module fixture"
    );
}

#[test]
fn fixture_ids_are_unique() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture catalog");

    let mut seen = std::collections::BTreeSet::new();
    for fixture in &catalog.fixtures {
        assert!(
            seen.insert(fixture.id.clone()),
            "duplicate fixture id: {}",
            fixture.id
        );
    }
}

#[test]
fn fixture_family_ids_are_nonempty() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture catalog");

    for fixture in &catalog.fixtures {
        assert!(
            !fixture.family_id.is_empty(),
            "family_id must not be empty for fixture {}",
            fixture.id
        );
    }
}

// ---------- GrammarCompletenessMatrix ----------

#[test]
fn grammar_completeness_matrix_has_families() {
    let parser = CanonicalEs2020Parser;
    let matrix = parser.scalar_reference_grammar_matrix();
    assert!(!matrix.families.is_empty());
}

#[test]
fn grammar_completeness_summary_counts_are_consistent() {
    let parser = CanonicalEs2020Parser;
    let matrix = parser.scalar_reference_grammar_matrix();
    let summary = matrix.summary();
    assert_eq!(
        summary.family_count,
        (summary.supported_families
            + summary.partially_supported_families
            + summary.unsupported_families)
    );
}

// ---------- parse_with_options ----------

#[test]
fn parse_with_options_matches_default_parse() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let tree_default = parser.parse("var y = 2;", ParseGoal::Script).unwrap();
    let tree_options = parser
        .parse_with_options("var y = 2;", ParseGoal::Script, &options)
        .unwrap();
    assert_eq!(tree_default.canonical_hash(), tree_options.canonical_hash());
}

#[test]
fn parser_mode_debug_is_nonempty() {
    let mode = ParserMode::ScalarReference;
    assert!(!format!("{mode:?}").is_empty());
}

#[test]
fn parser_options_default_serde_roundtrip() {
    let options = ParserOptions::default();
    let json = serde_json::to_string(&options).expect("serialize");
    let recovered: ParserOptions = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(serde_json::to_string(&recovered).unwrap(), json);
}

#[test]
fn parse_goal_script_and_module_are_distinct() {
    let parser = CanonicalEs2020Parser;
    let h1 = parser
        .parse("42", ParseGoal::Script)
        .unwrap()
        .canonical_hash();
    let h2 = parser
        .parse("42", ParseGoal::Module)
        .unwrap()
        .canonical_hash();
    assert_ne!(h1, h2);
}

#[test]
fn fixture_catalog_schema_version_is_stable() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture catalog");
    assert_eq!(
        catalog.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
}

#[test]
fn all_fixture_hashes_start_with_sha256_prefix() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture catalog");
    for fixture in &catalog.fixtures {
        assert!(
            fixture.expected_hash.starts_with("sha256:"),
            "fixture `{}` hash missing sha256 prefix",
            fixture.id
        );
    }
}

#[test]
fn all_fixture_sources_are_nonempty() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture catalog");
    for fixture in &catalog.fixtures {
        assert!(
            !fixture.source.trim().is_empty(),
            "fixture `{}` has empty source",
            fixture.id
        );
    }
}

#[test]
fn fixture_goals_are_valid_values() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture catalog");
    for fixture in &catalog.fixtures {
        assert!(
            matches!(fixture.goal.as_str(), "script" | "module"),
            "fixture `{}` has invalid goal: {}",
            fixture.id,
            fixture.goal
        );
    }
}

#[test]
fn parse_goal_helper_maps_correctly() {
    assert_eq!(parse_goal("script"), ParseGoal::Script);
    assert_eq!(parse_goal("module"), ParseGoal::Module);
}

#[test]
fn grammar_matrix_supported_count_is_positive() {
    let parser = CanonicalEs2020Parser;
    let matrix = parser.scalar_reference_grammar_matrix();
    let summary = matrix.summary();
    assert!(
        summary.supported_families > 0,
        "at least some grammar families should be supported"
    );
}
