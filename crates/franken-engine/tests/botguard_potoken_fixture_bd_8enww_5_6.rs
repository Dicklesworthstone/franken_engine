#![forbid(unsafe_code)]

//! bd-8enww.5.6 (YTBG-E6): offline franken_whisper PO-token fixture integration.
//!
//! This is the cross-repo contract seam between `franken_whisper` (which owns
//! extracting real BotGuard / PO-token JavaScript and the expected token/digest
//! from its downloader/extractor context) and `franken_engine` (which owns
//! *replaying* that frozen code through the public `HybridRouter` surface). The
//! split is deliberately narrow and fixture-driven so neither repo depends on the
//! other's internals:
//!
//!   - franken_whisper deposits `*.json` fixtures (one object or an array per file)
//!     pointed at by `FRANKEN_ENGINE_POTOKEN_FIXTURES`.
//!   - franken_engine validates each fixture (schema + `sha256:` source hashes +
//!     plain-identifier entrypoint), runs `<extracted_js>; <entrypoint>(<challenge>)`
//!     under the fixture's declared deterministic budget, and emits a structured
//!     run log per fixture (source hashes, deterministic env config, expected vs
//!     observed output, first divergence if any, consumed instruction steps).
//!
//! A committed synthetic fixture (`tests/fixtures/potoken/...`) always runs so the
//! offline path is proven WITHOUT any supplied fixture, network, browser, V8,
//! QuickJS, boa, or Python JS runtime. Its `expected_output` is independently
//! computed by the fixture generator's own oracle (a true differential check), and
//! the reproducer is composed only of primitives already proven green by the YTBG
//! suites: typed arrays (bd-8enww.2.*), the `Function` constructor (bd-8enww.3.*),
//! the deterministic `performance.now()` shim (bd-8enww.5.3), and try/catch
//! (bd-8enww.4.*).
//!
//! Acceptance criteria mapping:
//!   AC#1 — `POTOKEN_FIXTURE_CONTRACT` documents the self-contained fixture shape.
//!   AC#2 — the committed synthetic fixture runs offline; supplied franken_whisper
//!          fixtures run when present (structured skip when absent).
//!   AC#3 — every run log carries source hashes, the deterministic env config,
//!          expected/observed output, and the first divergence index if any.
//!   AC#4 — the engine-side path is pure `HybridRouter::eval_with_instruction_budget`:
//!          no network, browser, V8, QuickJS, boa, or Python JS runtime.
//!
//! Run with the structured log:
//!   cargo test -p frankenengine-engine --test botguard_potoken_fixture_bd_8enww_5_6 -- --nocapture

use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{env, fs};

use frankenengine_engine::HybridRouter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Environment variable franken_whisper sets to a JSON file or a directory of
/// `.json` fixtures. Absent => the supplied-fixture path is a structured skip.
const POTOKEN_FIXTURE_ENV: &str = "FRANKEN_ENGINE_POTOKEN_FIXTURES";
const POTOKEN_FIXTURE_SCHEMA: &str = "franken-engine.botguard-potoken-fixture.v1";
const POTOKEN_RUN_REPORT_SCHEMA: &str = "franken-engine.botguard-potoken-run-report.v1";

/// Containment-safe fallback budget if a fixture omits one. Large enough for a
/// BotGuard-shaped reproducer but still bounded (a malformed/adversarial fixture
/// fails closed with a deterministic budget fault rather than hanging).
const DEFAULT_POTOKEN_BUDGET: u64 = 5_000_000;

/// Path (relative to the crate manifest) of the committed offline fixture that
/// always runs.
const SYNTHETIC_FIXTURE_RELPATH: &str = "tests/fixtures/potoken/synthetic_botguard_potoken_v1.json";

const POTOKEN_FIXTURE_CONTRACT: &str = r#"
Offline franken_whisper PO-token / BotGuard fixture contract for bd-8enww.5.6.

Purpose:
- franken_whisper owns extracting real BotGuard / PO-token JavaScript and the
  expected token/digest from its downloader/extractor context.
- franken_engine owns replaying those frozen functions through
  HybridRouter::eval_with_instruction_budget WITHOUT fetching YouTube, invoking a
  browser, or depending on franken_whisper internals.

How to run:
- Set FRANKEN_ENGINE_POTOKEN_FIXTURES to a JSON file or a directory of .json files.
- Each file may contain one fixture object or an array of fixture objects.
- Run: cargo test -p frankenengine-engine --test botguard_potoken_fixture_bd_8enww_5_6 -- --nocapture
- A committed synthetic fixture runs unconditionally, so the offline path is proven
  even with no supplied fixture.

Required fixture fields:
{
  "schema_version": "franken-engine.botguard-potoken-fixture.v1",
  "fixture_id": "potoken-2026-06-30-player-abc123-001",
  "fixture_kind": "synthetic_botguard_potoken" | "po_token" | "botguard_vm",
  "source_url": "https://www.youtube.com/s/player/.../base.js",
  "source_observed_utc": "2026-06-30T00:00:00Z",
  "source_sha256": "sha256:<sha256 of the full fetched base.js body>",
  "extracted_js_sha256": "sha256:<sha256 of extracted_js below>",
  "entrypoint": "computePoToken",
  "extracted_js": "function computePoToken(challenge){ ... }",
  "challenge_input": "the challenge / input string passed to the entrypoint",
  "deterministic_env": {
    "instruction_budget": 5000000,
    "performance_base_tick": 0,
    "clock_source": "deterministic_instruction_tick"
  },
  "expected_output": "the extractor-verified token/digest",
  "notes": "optional context for humans"
}

Rules:
- entrypoint is restricted to a plain JavaScript identifier in v1.
- extracted_js must define that entrypoint; the engine evaluates
  `<extracted_js>; <entrypoint>(<challenge_input as a JSON string>)`.
- The run is bounded by deterministic_env.instruction_budget (or a safe default);
  exhaustion is a deterministic budget fault, not a hang.
- source_url/source_observed_utc/source_sha256 preserve provenance; tests never
  fetch the URL or touch the network.
- extracted_js_sha256 is verified locally so accidental fixture drift fails fast.
- Missing supplied fixtures are a structured skip, not a silent pass; any supplied
  fixture must pass or the test fails with a JSON report.
- The deterministic shims (performance.now base tick / clock source) keep replay
  artifacts free of wall-clock nondeterminism.
"#;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PoTokenFixture {
    schema_version: String,
    fixture_id: String,
    fixture_kind: String,
    source_url: String,
    source_observed_utc: String,
    source_sha256: String,
    extracted_js_sha256: String,
    entrypoint: String,
    extracted_js: String,
    challenge_input: String,
    deterministic_env: DeterministicEnv,
    expected_output: String,
    notes: Option<String>,
}

/// The deterministic environment shims a fixture pins so replay is reproducible.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeterministicEnv {
    /// Instruction budget for the run (falls back to `DEFAULT_POTOKEN_BUDGET`).
    instruction_budget: Option<u64>,
    /// The `performance.now()` base tick the deterministic shim starts from.
    performance_base_tick: Option<u64>,
    /// The clock source identifier recorded in the run log.
    clock_source: Option<String>,
}

impl DeterministicEnv {
    fn budget(&self) -> u64 {
        self.instruction_budget.unwrap_or(DEFAULT_POTOKEN_BUDGET)
    }
}

/// The first position where `expected` and `observed` diverge, by Unicode scalar.
#[derive(Debug, Clone, Serialize)]
struct DivergencePoint {
    index: usize,
    expected_char: Option<String>,
    observed_char: Option<String>,
}

/// One structured run-log record per fixture (AC#3).
#[derive(Debug, Serialize)]
struct PoTokenRunLog {
    fixture_id: String,
    fixture_kind: String,
    fixture_path: String,
    source_url: String,
    source_observed_utc: String,
    source_sha256: String,
    extracted_js_sha256: String,
    computed_extracted_js_sha256: String,
    entrypoint: String,
    challenge_input_sha256: String,
    instruction_budget: u64,
    performance_base_tick: Option<u64>,
    clock_source: Option<String>,
    expected_output: String,
    observed_kind: String,
    observed_output: String,
    instructions_executed: u64,
    passed: bool,
    first_divergence: Option<DivergencePoint>,
    duration_ns: u64,
    engine: Option<String>,
    route_reason: Option<String>,
    error_code: Option<String>,
    error_message: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct PoTokenRunReport {
    schema_version: &'static str,
    status: &'static str,
    env_var: &'static str,
    fixture_source: String,
    total_fixtures: usize,
    passed: usize,
    failed: usize,
    logs: Vec<PoTokenRunLog>,
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_plain_js_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first == '_' || first == '$' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
}

/// The first index at which two strings diverge by Unicode scalar, or `None` when
/// `observed` matches `expected` exactly.
fn first_divergence(expected: &str, observed: &str) -> Option<DivergencePoint> {
    let exp: Vec<char> = expected.chars().collect();
    let obs: Vec<char> = observed.chars().collect();
    let max = exp.len().max(obs.len());
    for index in 0..max {
        let e = exp.get(index).copied();
        let o = obs.get(index).copied();
        if e != o {
            return Some(DivergencePoint {
                index,
                expected_char: e.map(|c| c.to_string()),
                observed_char: o.map(|c| c.to_string()),
            });
        }
    }
    None
}

fn saturating_duration_ns(nanos: u128) -> u64 {
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn validate_potoken_fixture(fixture: &PoTokenFixture, source: &str) -> Result<(), String> {
    if fixture.schema_version != POTOKEN_FIXTURE_SCHEMA {
        return Err(format!(
            "{source} has schema_version {:?}, expected {:?}",
            fixture.schema_version, POTOKEN_FIXTURE_SCHEMA
        ));
    }
    for (field, value) in [
        ("fixture_id", fixture.fixture_id.as_str()),
        ("fixture_kind", fixture.fixture_kind.as_str()),
        ("source_url", fixture.source_url.as_str()),
        ("source_observed_utc", fixture.source_observed_utc.as_str()),
        ("entrypoint", fixture.entrypoint.as_str()),
        ("extracted_js", fixture.extracted_js.as_str()),
        ("challenge_input", fixture.challenge_input.as_str()),
        ("expected_output", fixture.expected_output.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{source} field {field} must not be empty"));
        }
    }
    validate_sha256_field(source, "source_sha256", &fixture.source_sha256)?;
    validate_sha256_field(source, "extracted_js_sha256", &fixture.extracted_js_sha256)?;
    if !is_plain_js_identifier(&fixture.entrypoint) {
        return Err(format!(
            "{source} entrypoint {:?} is not a plain JavaScript identifier",
            fixture.entrypoint
        ));
    }
    let computed = sha256_prefixed(fixture.extracted_js.as_bytes());
    if computed != fixture.extracted_js_sha256 {
        return Err(format!(
            "{source} extracted_js_sha256 mismatch for {}: field {}, computed {}",
            fixture.fixture_id, fixture.extracted_js_sha256, computed
        ));
    }
    Ok(())
}

fn validate_sha256_field(source: &str, field: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{source} field {field} must start with sha256:"));
    };
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{source} field {field} must be sha256: + 64 hex chars"
        ));
    }
    Ok(())
}

fn load_potoken_fixture_file(path: &Path) -> Result<Vec<(PathBuf, PoTokenFixture)>, String> {
    let content =
        fs::read_to_string(path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
    let fixtures = if content.trim_start().starts_with('[') {
        serde_json::from_str::<Vec<PoTokenFixture>>(&content)
            .map_err(|err| format!("parse {} as fixture array failed: {err}", path.display()))?
    } else {
        vec![
            serde_json::from_str::<PoTokenFixture>(&content)
                .map_err(|err| format!("parse {} as fixture failed: {err}", path.display()))?,
        ]
    };
    fixtures
        .into_iter()
        .map(|fixture| {
            validate_potoken_fixture(&fixture, &path.display().to_string())?;
            Ok((path.to_path_buf(), fixture))
        })
        .collect()
}

fn load_potoken_fixtures(root: &Path) -> Result<Vec<(PathBuf, PoTokenFixture)>, String> {
    if root.is_file() {
        return load_potoken_fixture_file(root);
    }
    if !root.is_dir() {
        return Err(format!(
            "{POTOKEN_FIXTURE_ENV} must point to a JSON file or directory, got {}",
            root.display()
        ));
    }
    let mut paths = Vec::new();
    for entry in
        fs::read_dir(root).map_err(|err| format!("read_dir {} failed: {err}", root.display()))?
    {
        let path = entry
            .map_err(|err| format!("read_dir entry failed: {err}"))?
            .path();
        if path.extension().is_some_and(|ext| ext == "json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut fixtures = Vec::new();
    for path in paths {
        fixtures.extend(load_potoken_fixture_file(&path)?);
    }
    Ok(fixtures)
}

fn run_potoken_fixture(path: &Path, fixture: &PoTokenFixture) -> PoTokenRunLog {
    let challenge_literal =
        serde_json::to_string(&fixture.challenge_input).expect("string literal must serialize");
    let eval_source = format!(
        "{}\n{}({})",
        fixture.extracted_js, fixture.entrypoint, challenge_literal
    );
    let budget = fixture.deterministic_env.budget();

    let started = Instant::now();
    let result = HybridRouter::default().eval_with_instruction_budget(&eval_source, budget);
    let duration_ns = saturating_duration_ns(started.elapsed().as_nanos());

    let base = |observed_kind: &str,
                observed_output: String,
                instructions_executed: u64,
                passed: bool,
                first_divergence: Option<DivergencePoint>,
                engine: Option<String>,
                route_reason: Option<String>,
                error_code: Option<String>,
                error_message: Option<String>|
     -> PoTokenRunLog {
        PoTokenRunLog {
            fixture_id: fixture.fixture_id.clone(),
            fixture_kind: fixture.fixture_kind.clone(),
            fixture_path: path.display().to_string(),
            source_url: fixture.source_url.clone(),
            source_observed_utc: fixture.source_observed_utc.clone(),
            source_sha256: fixture.source_sha256.clone(),
            extracted_js_sha256: fixture.extracted_js_sha256.clone(),
            computed_extracted_js_sha256: sha256_prefixed(fixture.extracted_js.as_bytes()),
            entrypoint: fixture.entrypoint.clone(),
            challenge_input_sha256: sha256_prefixed(fixture.challenge_input.as_bytes()),
            instruction_budget: budget,
            performance_base_tick: fixture.deterministic_env.performance_base_tick,
            clock_source: fixture.deterministic_env.clock_source.clone(),
            expected_output: fixture.expected_output.clone(),
            observed_kind: observed_kind.to_owned(),
            observed_output,
            instructions_executed,
            passed,
            first_divergence,
            duration_ns,
            engine,
            route_reason,
            error_code,
            error_message,
            notes: fixture.notes.clone(),
        }
    };

    match result {
        Ok(outcome) => {
            let passed = outcome.value == fixture.expected_output;
            let divergence = first_divergence(&fixture.expected_output, &outcome.value);
            base(
                "value",
                outcome.value.clone(),
                outcome.instructions_executed,
                passed,
                divergence,
                Some(format!("{:?}", outcome.engine)),
                Some(format!("{:?}", outcome.route_reason)),
                None,
                None,
            )
        }
        Err(error) => {
            let message = error.to_string();
            let error_code = message
                .split_whitespace()
                .next()
                .unwrap_or("eval.error")
                .to_owned();
            base(
                "engine_error",
                String::new(),
                0,
                false,
                None,
                None,
                None,
                Some(error_code),
                Some(message),
            )
        }
    }
}

fn run_potoken_fixture_set(
    fixture_source: String,
    fixtures: &[(PathBuf, PoTokenFixture)],
) -> PoTokenRunReport {
    let logs: Vec<PoTokenRunLog> = fixtures
        .iter()
        .map(|(path, fixture)| run_potoken_fixture(path, fixture))
        .collect();
    let passed = logs.iter().filter(|log| log.passed).count();
    PoTokenRunReport {
        schema_version: POTOKEN_RUN_REPORT_SCHEMA,
        status: "executed",
        env_var: POTOKEN_FIXTURE_ENV,
        fixture_source,
        total_fixtures: logs.len(),
        passed,
        failed: logs.len().saturating_sub(passed),
        logs,
    }
}

/// Path to the committed offline fixture, resolved against the crate manifest so
/// it runs regardless of the working directory.
fn synthetic_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(SYNTHETIC_FIXTURE_RELPATH)
}

fn render_report(report: &PoTokenRunReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => eprintln!("[bd-8enww.5.6] potoken-fixture report:\n{json}"),
        Err(err) => eprintln!("[bd-8enww.5.6] failed to render report: {err}"),
    }
}

/// AC#1: the embedded contract is self-contained and names every load-bearing field.
#[test]
fn potoken_fixture_contract_is_self_documenting() {
    for needle in [
        POTOKEN_FIXTURE_ENV,
        POTOKEN_FIXTURE_SCHEMA,
        "extracted_js",
        "extracted_js_sha256",
        "challenge_input",
        "deterministic_env",
        "instruction_budget",
        "expected_output",
        "HybridRouter::eval_with_instruction_budget",
    ] {
        assert!(
            POTOKEN_FIXTURE_CONTRACT.contains(needle),
            "contract must document {needle:?}"
        );
    }
}

/// AC#2 + AC#4: the committed synthetic fixture loads, validates, and runs offline
/// through the public engine surface, matching its independently-computed digest —
/// with no network, browser, V8, QuickJS, boa, or Python JS runtime.
#[test]
fn committed_synthetic_potoken_fixture_runs_offline_and_matches() {
    let path = synthetic_fixture_path();
    let fixtures = load_potoken_fixtures(&path)
        .unwrap_or_else(|err| panic!("committed synthetic fixture must load: {err}"));
    assert_eq!(fixtures.len(), 1, "exactly one committed synthetic fixture");

    let report = run_potoken_fixture_set(path.display().to_string(), &fixtures);
    render_report(&report);

    assert_eq!(report.total_fixtures, 1);
    assert_eq!(
        report.failed, 0,
        "committed synthetic fixture must reproduce its expected digest"
    );
    let log = &report.logs[0];
    assert!(log.passed);
    assert!(log.first_divergence.is_none(), "no divergence on a match");
    assert_eq!(log.fixture_kind, "synthetic_botguard_potoken");
    // The reproducer genuinely executes work (typed-array fold + generated fn +
    // performance reads), so the consumed-step count is non-trivial and within the
    // declared budget.
    assert!(
        log.instructions_executed > 0 && log.instructions_executed <= log.instruction_budget,
        "consumed steps {} must be in (0, budget {}]",
        log.instructions_executed,
        log.instruction_budget
    );
    // AC#3: the log carries the source hashes and the deterministic env config.
    assert!(log.source_sha256.starts_with("sha256:"));
    assert!(log.extracted_js_sha256.starts_with("sha256:"));
    assert_eq!(log.extracted_js_sha256, log.computed_extracted_js_sha256);
    assert_eq!(
        log.clock_source.as_deref(),
        Some("deterministic_instruction_tick")
    );
}

/// AC#4 (replay): the committed fixture is byte-for-byte deterministic across
/// independent evaluations, including the consumed-step count.
#[test]
fn committed_synthetic_potoken_fixture_is_deterministic() {
    let path = synthetic_fixture_path();
    let fixtures = load_potoken_fixtures(&path).expect("fixture loads");
    let (fpath, fixture) = &fixtures[0];

    let first = run_potoken_fixture(fpath, fixture);
    let second = run_potoken_fixture(fpath, fixture);

    assert!(first.passed && second.passed);
    assert_eq!(first.observed_output, second.observed_output);
    assert_eq!(
        first.instructions_executed, second.instructions_executed,
        "consumed steps must be deterministic across runs"
    );
    assert_eq!(first.observed_output, fixture.expected_output);
}

/// AC#3: a fixture whose `expected_output` is deliberately wrong produces a NON-pass
/// log that pinpoints the first divergence index — the signal franken_whisper uses
/// to localize an extractor/engine mismatch.
#[test]
fn divergence_is_reported_for_a_mismatched_expectation() {
    let path = synthetic_fixture_path();
    let (fpath, mut fixture) = load_potoken_fixtures(&path).expect("fixture loads")[0].clone();
    // Corrupt only the expected output; keep the (validated) source intact.
    let real = fixture.expected_output.clone();
    fixture.expected_output = "potoken.v1:0:mono=1:ok".to_string();

    let log = run_potoken_fixture(&fpath, &fixture);
    assert!(!log.passed, "a wrong expectation must not pass");
    let divergence = log
        .first_divergence
        .expect("a mismatch must report a first divergence");
    // The two strings share the "potoken.v1:" prefix (11 chars) and first diverge
    // at the accumulator digit.
    assert_eq!(divergence.index, "potoken.v1:".chars().count());
    assert_ne!(real, fixture.expected_output);
}

/// `first_divergence` returns `None` on an exact match and the first differing
/// scalar index otherwise (including length mismatches).
#[test]
fn first_divergence_helper_is_correct() {
    assert!(first_divergence("abc", "abc").is_none());
    let d = first_divergence("abc", "abx").expect("differs at index 2");
    assert_eq!(d.index, 2);
    assert_eq!(d.expected_char.as_deref(), Some("c"));
    assert_eq!(d.observed_char.as_deref(), Some("x"));
    let longer = first_divergence("ab", "abc").expect("observed is longer");
    assert_eq!(longer.index, 2);
    assert_eq!(longer.expected_char, None);
    assert_eq!(longer.observed_char.as_deref(), Some("c"));
}

/// AC#2 (supplied path) + AC#3: when franken_whisper supplies fixtures via the env
/// var they all run and pass with structured logs; when absent it is an explicit
/// structured skip, never a silent pass.
#[test]
fn supplied_franken_whisper_fixtures_run_or_skip() {
    let Some(root) = env::var_os(POTOKEN_FIXTURE_ENV) else {
        eprintln!(
            "[bd-8enww.5.6] SKIP supplied-fixture path: {POTOKEN_FIXTURE_ENV} unset (offline default). \
             The committed synthetic fixture already proves the engine-side path; set the env var to \
             a franken_whisper fixture file/dir to exercise supplied fixtures."
        );
        return;
    };
    let root = PathBuf::from(root);
    let fixtures = load_potoken_fixtures(&root).unwrap_or_else(|err| {
        panic!("supplied {POTOKEN_FIXTURE_ENV} fixtures must validate: {err}")
    });
    assert!(
        !fixtures.is_empty(),
        "{POTOKEN_FIXTURE_ENV}={} resolved to zero fixtures",
        root.display()
    );
    let report = run_potoken_fixture_set(root.display().to_string(), &fixtures);
    render_report(&report);
    assert_eq!(
        report.failed, 0,
        "every supplied franken_whisper fixture must reproduce its expected token"
    );
}
