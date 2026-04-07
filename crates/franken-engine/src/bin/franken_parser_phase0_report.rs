#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use std::time::Instant;

use chrono::Utc;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserMode, ParserOptions};
use serde::{Deserialize, Serialize};

const FIXTURE_PATH: &str =
    "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json";
const REPETITIONS: usize = 128;

#[derive(Debug, Deserialize)]
struct FixtureSpec {
    id: String,
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

#[derive(Debug, Serialize)]
struct LatencySummary {
    sample_count: usize,
    repetitions: usize,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
}

#[derive(Debug, Serialize)]
struct BaselineReport {
    schema_version: String,
    generated_at_utc: String,
    parser_mode: String,
    fixture_catalog_path: String,
    fixture_catalog_schema: String,
    fixture_count: usize,
    deterministic_hash_validation: bool,
    grammar_completeness: frankenengine_engine::parser::GrammarCompletenessSummary,
    parser_budget: frankenengine_engine::parser::ParserBudget,
    latency: LatencySummary,
}

fn parse_goal(raw: &str) -> Result<ParseGoal, String> {
    match raw {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(format!("unknown fixture goal: {other}")),
    }
}

fn quantile(sorted: &[u64], q_percent: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() - 1).saturating_mul(q_percent) / 100;
    sorted[idx]
}

fn run() -> Result<BaselineReport, String> {
    let bytes = fs::read(Path::new(FIXTURE_PATH))
        .map_err(|error| format!("failed to read fixture catalog `{FIXTURE_PATH}`: {error}"))?;
    let catalog: FixtureCatalog = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse fixture catalog json: {error}"))?;

    if catalog.parser_mode != ParserMode::ScalarReference.as_str() {
        return Err(format!(
            "fixture catalog parser_mode must be `{}`",
            ParserMode::ScalarReference.as_str()
        ));
    }

    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let mut deterministic_hash_validation = true;
    for fixture in &catalog.fixtures {
        let tree = parser
            .parse_with_options(
                fixture.source.as_str(),
                parse_goal(fixture.goal.as_str())?,
                &options,
            )
            .map_err(|error| format!("fixture `{}` parse failed: {error}", fixture.id))?;

        if tree.canonical_hash() != fixture.expected_hash {
            deterministic_hash_validation = false;
        }
    }

    let mut samples_ns = Vec::<u64>::new();
    for _ in 0..REPETITIONS {
        for fixture in &catalog.fixtures {
            let start = Instant::now();
            let _tree = parser
                .parse_with_options(
                    fixture.source.as_str(),
                    parse_goal(fixture.goal.as_str())?,
                    &options,
                )
                .map_err(|error| {
                    format!(
                        "fixture `{}` parse failed during timing: {error}",
                        fixture.id
                    )
                })?;
            let elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            samples_ns.push(elapsed_ns);
        }
    }

    samples_ns.sort_unstable();

    let latency = LatencySummary {
        sample_count: samples_ns.len(),
        repetitions: REPETITIONS,
        p50_ns: quantile(&samples_ns, 50),
        p95_ns: quantile(&samples_ns, 95),
        p99_ns: quantile(&samples_ns, 99),
    };

    let grammar_completeness = parser.scalar_reference_grammar_matrix().summary();

    Ok(BaselineReport {
        schema_version: "franken-engine.parser-phase0.baseline.v1".to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        parser_mode: ParserMode::ScalarReference.as_str().to_string(),
        fixture_catalog_path: FIXTURE_PATH.to_string(),
        fixture_catalog_schema: catalog.schema_version,
        fixture_count: catalog.fixtures.len(),
        deterministic_hash_validation,
        grammar_completeness,
        parser_budget: options.budget,
        latency,
    })
}

fn main() {
    match run() {
        Ok(report) => {
            let json = serde_json::to_string_pretty(&report).unwrap_or_default();
            println!("{json}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
