//! `franken_coverage_frontier` (`bd-fqlfw.7.1` E7.T1 + `bd-fqlfw.7.2` E7.T2 +
//! `bd-fqlfw.7.5` E7.T5) — operator binary that clusters Test262 and
//! differential-oracle FAILURES by spec construct into a deterministic,
//! content-hashed coverage-frontier report, ranks those clusters by a transparent
//! impact score (`--rank`), and turns the ranked frontier into a gated, idempotent
//! auto-bead-filing plan (`--file-beads`).
//!
//! Failure sources (combine any):
//!   --report <path>          Consume a Test262 `ConformanceReport` JSON (as
//!                            emitted by `franken_test262_runner`). Repeatable.
//!   --run-suite <dir>        Run Test262 in-process via the existing runner over
//!                            the corpus at <dir> (a tc39/test262 checkout).
//!   --engine-core-oracle     Run the engine<->core differential oracle over the
//!                            built-in seed corpus (`default_engine_core_corpus`).
//!
//! Options:
//!   --rank                   Emit the ranked report (impact = failing-count ×
//!                            usage × locality) instead of the raw cluster list.
//!   --file-beads             Emit a gated auto-bead-filing PLAN for the top-N
//!                            ranked clusters (each carries its failing cases + an
//!                            E4 intrinsic-table scaffold). Plan-only by default —
//!                            review it, then re-run with --execute to file.
//!   --execute                With --file-beads: actually run `br create` for each
//!                            proposal and update the dedup ledger (requires
//!                            --ledger). Off by default (the human-review path).
//!   --ledger <path>          Dedup ledger JSON (cluster_id -> filed bead). Read to
//!                            skip already-filed clusters; rewritten by --execute.
//!   --top-n <N>              Clusters considered for --file-beads (default 10).
//!   --parent <id>            Parent bead id threaded into each filing command.
//!   --usage-signal <path>    JSON usage signal (construct → weight millionths)
//!                            from a real npm corpus scan; used with --rank or
//!                            --file-beads. Absent ⇒ neutral (no fabrication).
//!   --cross-reference        Truth-gate: cross-reference clusters against the
//!                            parser/lowering gap inventories. Exits 3 if any
//!                            cluster is an undocumented gap. (Excludes --rank.)
//!   --coverage-summary       Emit the weighted ES2020 coverage summary: six
//!                            category views + a single headline executed-%, with
//!                            a floor that exposes the weakest view. (Exclusive.)
//!   --sample-count <N>       Cap tests for --run-suite (0 = all; default 2000).
//!   --pattern <glob>         Glob filter for --run-suite.
//!   --construct-depth <N>    Path depth for Test262 construct keys (default 3).
//!   --sample-limit <N>       Sample case ids retained per cluster (default 8).
//!   --out <path>             Write the report JSON here (always also to stdout).
//!   -h, --help               Print this help.
//!
//! Exit codes: 0 report/plan emitted (and truth gate passed, if --cross-reference);
//! 2 usage error / no source selected / a --execute filing failed; 3 truth-gate
//! failure (undocumented gaps).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Serialize;

use frankenengine_engine::coverage_frontier::{
    CoverageFrontierReport, DEFAULT_CONSTRUCT_DEPTH, DEFAULT_SAMPLE_LIMIT, FailureObservation,
    cluster_failures, observations_from_conformance, observations_from_engine_core_report,
};
use frankenengine_engine::coverage_frontier_filing::{
    BeadFilingPlan, DEFAULT_TOP_N, FiledLedger, build_filing_plan,
};
use frankenengine_engine::coverage_frontier_rank::{
    ConstructCensus, UsageSignal, construct_census_from_conformance, merge_censuses, rank_clusters,
};
use frankenengine_engine::coverage_frontier_xref::{cross_reference, default_inventory_entries};
use frankenengine_engine::coverage_summary::{
    CoverageView, ViewCount, accumulate_conformance, finalize_summary,
};
use frankenengine_engine::differential_oracle::{
    default_engine_core_corpus, run_engine_core_differential_oracle,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::test262_conformance_runner::{
    ConformanceReport, RunnerConfig, Test262Runner,
};

const USAGE: &str = "\
franken_coverage_frontier — cluster + rank Test262/differential-oracle failures by spec construct (bd-fqlfw.7.1/7.2)

USAGE:
    franken_coverage_frontier [SOURCES] [OPTIONS]

SOURCES (select at least one; combinable):
    --report <path>          Consume a Test262 ConformanceReport JSON (repeatable)
    --run-suite <dir>        Run Test262 in-process over a tc39/test262 checkout
    --engine-core-oracle     Run the engine<->core differential oracle (seed corpus)

OPTIONS:
    --rank                   Emit the ranked report (impact = count × usage × locality)
    --file-beads             Emit a gated auto-bead-filing plan for the top-N ranked clusters
    --execute                With --file-beads: file the beads via `br create` (requires --ledger)
    --ledger <path>          Dedup ledger JSON (cluster_id -> filed bead); rewritten by --execute
    --top-n <N>              Clusters considered for --file-beads (default 10)
    --parent <id>            Parent bead id threaded into each --file-beads command
    --usage-signal <path>    JSON usage signal (construct → weight millionths), --rank/--file-beads
    --cross-reference        Truth-gate clusters vs parser/lowering gap inventories (exit 3 on drift)
    --coverage-summary       Emit the weighted ES2020 coverage summary (6 views + headline)
    --sample-count <N>       Cap tests for --run-suite (0 = all; default 2000)
    --pattern <glob>         Glob filter for --run-suite
    --construct-depth <N>    Construct-key path depth (default 3)
    --sample-limit <N>       Sample case ids per cluster (default 8)
    --out <path>             Write report JSON to <path> (also printed to stdout)
    -h, --help               Show this help
";

struct Args {
    reports: Vec<PathBuf>,
    run_suite: Option<PathBuf>,
    engine_core_oracle: bool,
    rank: bool,
    file_beads: bool,
    execute: bool,
    ledger: Option<PathBuf>,
    top_n: usize,
    parent: Option<String>,
    usage_signal: Option<PathBuf>,
    cross_reference: bool,
    coverage_summary: bool,
    sample_count: usize,
    pattern: Option<String>,
    construct_depth: usize,
    sample_limit: usize,
    out: Option<PathBuf>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            reports: Vec::new(),
            run_suite: None,
            engine_core_oracle: false,
            rank: false,
            file_beads: false,
            execute: false,
            ledger: None,
            top_n: DEFAULT_TOP_N,
            parent: None,
            usage_signal: None,
            cross_reference: false,
            coverage_summary: false,
            sample_count: 2000,
            pattern: None,
            construct_depth: DEFAULT_CONSTRUCT_DEPTH,
            sample_limit: DEFAULT_SAMPLE_LIMIT,
            out: None,
        }
    }
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || {
            iter.next()
                .ok_or_else(|| format!("flag `{flag}` requires a value"))
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(None),
            "--report" => args.reports.push(PathBuf::from(value()?)),
            "--run-suite" => args.run_suite = Some(PathBuf::from(value()?)),
            "--engine-core-oracle" => args.engine_core_oracle = true,
            "--rank" => args.rank = true,
            "--file-beads" => args.file_beads = true,
            "--execute" => args.execute = true,
            "--ledger" => args.ledger = Some(PathBuf::from(value()?)),
            "--top-n" => {
                args.top_n = value()?
                    .parse()
                    .map_err(|_| "--top-n expects an integer".to_string())?;
            }
            "--parent" => args.parent = Some(value()?),
            "--usage-signal" => args.usage_signal = Some(PathBuf::from(value()?)),
            "--cross-reference" => args.cross_reference = true,
            "--coverage-summary" => args.coverage_summary = true,
            "--sample-count" => {
                args.sample_count = value()?
                    .parse()
                    .map_err(|_| "--sample-count expects an integer".to_string())?;
            }
            "--pattern" => args.pattern = Some(value()?),
            "--construct-depth" => {
                args.construct_depth = value()?
                    .parse()
                    .map_err(|_| "--construct-depth expects an integer".to_string())?;
            }
            "--sample-limit" => {
                args.sample_limit = value()?
                    .parse()
                    .map_err(|_| "--sample-limit expects an integer".to_string())?;
            }
            "--out" => args.out = Some(PathBuf::from(value()?)),
            other => return Err(format!("unrecognized argument `{other}`")),
        }
    }
    Ok(Some(args))
}

/// Failure observations, the per-construct census (locality factor), and the
/// per-view coverage tally (weighted coverage summary), accumulated from the
/// Test262 conformance sources.
struct Collected {
    observations: Vec<FailureObservation>,
    census: BTreeMap<String, ConstructCensus>,
    coverage_tally: BTreeMap<CoverageView, ViewCount>,
    corpus_commit: String,
}

/// Fold one conformance report into the running observation list, census, and
/// coverage tally.
fn ingest_conformance(
    report: &ConformanceReport,
    depth: usize,
    observations: &mut Vec<FailureObservation>,
    census: &mut BTreeMap<String, ConstructCensus>,
    coverage_tally: &mut BTreeMap<CoverageView, ViewCount>,
) {
    observations.extend(observations_from_conformance(report, depth));
    let merged = merge_censuses(
        std::mem::take(census),
        &construct_census_from_conformance(report, depth),
    );
    *census = merged;
    accumulate_conformance(report, coverage_tally);
}

fn collect(args: &Args) -> Result<Collected, String> {
    let mut observations = Vec::new();
    let mut census: BTreeMap<String, ConstructCensus> = BTreeMap::new();
    let mut coverage_tally: BTreeMap<CoverageView, ViewCount> = BTreeMap::new();
    let mut corpus_commit = String::new();

    for report_path in &args.reports {
        let raw = std::fs::read_to_string(report_path)
            .map_err(|err| format!("reading {}: {err}", report_path.display()))?;
        let report: ConformanceReport = serde_json::from_str(&raw)
            .map_err(|err| format!("parsing ConformanceReport {}: {err}", report_path.display()))?;
        eprintln!(
            "[coverage_frontier] --report {}: {} records",
            report_path.display(),
            report.test_records.len()
        );
        if !report.test262_commit.is_empty() {
            corpus_commit = report.test262_commit.clone();
        }
        ingest_conformance(
            &report,
            args.construct_depth,
            &mut observations,
            &mut census,
            &mut coverage_tally,
        );
    }

    if let Some(suite) = &args.run_suite {
        let config = RunnerConfig {
            test262_path: suite.clone(),
            max_tests: args.sample_count,
            pattern: args.pattern.clone(),
            include_negative: true,
            ..RunnerConfig::default()
        };
        let runner = Test262Runner::new(config);
        let report = runner
            .run_conformance(SecurityEpoch::from_raw(0))
            .map_err(|err| format!("running Test262 suite {}: {err}", suite.display()))?;
        eprintln!(
            "[coverage_frontier] --run-suite {}: {}/{} tests",
            suite.display(),
            report.overall.total_tests,
            report.total_discovered
        );
        if !report.test262_commit.is_empty() {
            corpus_commit = report.test262_commit.clone();
        }
        ingest_conformance(
            &report,
            args.construct_depth,
            &mut observations,
            &mut census,
            &mut coverage_tally,
        );
    }

    if args.engine_core_oracle {
        let oracle = run_engine_core_differential_oracle(&default_engine_core_corpus(), 256);
        let derived = observations_from_engine_core_report(&oracle);
        eprintln!(
            "[coverage_frontier] --engine-core-oracle: {} cases, {} agreements, {} defects -> {} observations",
            oracle.cases_checked,
            oracle.agreements,
            oracle.defects.len(),
            derived.len()
        );
        observations.extend(derived);
    }

    Ok(Collected {
        observations,
        census,
        coverage_tally,
        corpus_commit,
    })
}

fn load_usage_signal(path: &PathBuf) -> Result<UsageSignal, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("reading usage signal {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("parsing usage signal {}: {err}", path.display()))
}

/// Load the dedup ledger from `path`. A missing file is treated as an empty
/// ledger (first run); a present-but-unparseable file is a hard error so a
/// corrupt ledger never silently re-files everything.
fn load_ledger(path: &Path) -> Result<FiledLedger, String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map_err(|err| format!("parsing ledger {}: {err}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(FiledLedger::new()),
        Err(err) => Err(format!("reading ledger {}: {err}", path.display())),
    }
}

/// Persist the dedup ledger to `path` as pretty JSON (records are a `BTreeMap`,
/// so the on-disk order is deterministic).
fn save_ledger(path: &Path, ledger: &FiledLedger) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(ledger).map_err(|err| format!("serializing ledger: {err}"))?;
    std::fs::write(path, format!("{json}\n"))
        .map_err(|err| format!("writing ledger {}: {err}", path.display()))
}

/// Result of attempting to file one proposal.
#[derive(Debug, Clone, Serialize)]
struct FiledBeadResult {
    cluster_id: String,
    /// The created bead id (empty on failure).
    bead_id: String,
    ok: bool,
    message: String,
}

/// The emitted record when `--file-beads --execute` actually files beads.
#[derive(Debug, Clone, Serialize)]
struct BeadFilingExecution {
    plan: BeadFilingPlan,
    results: Vec<FiledBeadResult>,
    ledger_records: usize,
}

/// Execute a filing plan: run `br create` for each proposal, recording each
/// filed cluster in the ledger. Failures are captured per-proposal (the caller
/// surfaces a non-zero exit) rather than aborting the whole batch — a transient
/// `br` failure on one bead must not lose the ids already filed.
///
/// Uses the proposal's structured fields (title/priority/labels/body) as direct
/// process args (no shell), so the body's newlines/quotes need no escaping; the
/// `--silent` flag makes `br` print only the new id on stdout. This mirrors the
/// reviewable `br_create_command` string the plan carries.
fn execute_filing_plan(
    plan: &BeadFilingPlan,
    ledger: &mut FiledLedger,
    parent: Option<&str>,
) -> Vec<FiledBeadResult> {
    let mut results = Vec::with_capacity(plan.proposals.len());
    for proposal in &plan.proposals {
        let mut cmd = Command::new("br");
        cmd.arg("create")
            .arg(&proposal.title)
            .arg("-t")
            .arg("task")
            .arg("-p")
            .arg(&proposal.priority)
            .arg("-l")
            .arg(&proposal.labels)
            .arg("-d")
            .arg(&proposal.body)
            .arg("--silent");
        if let Some(parent) = parent {
            cmd.arg("--parent").arg(parent);
        }
        match cmd.output() {
            Ok(out) if out.status.success() => {
                let bead_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
                ledger.record(
                    proposal.cluster_id.clone(),
                    bead_id.clone(),
                    proposal.construct.clone(),
                    "filed by franken_coverage_frontier --file-beads --execute",
                );
                results.push(FiledBeadResult {
                    cluster_id: proposal.cluster_id.clone(),
                    bead_id,
                    ok: true,
                    message: "created".to_string(),
                });
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                results.push(FiledBeadResult {
                    cluster_id: proposal.cluster_id.clone(),
                    bead_id: String::new(),
                    ok: false,
                    message: format!("br create failed: {}", stderr.trim()),
                });
            }
            Err(err) => {
                results.push(FiledBeadResult {
                    cluster_id: proposal.cluster_id.clone(),
                    bead_id: String::new(),
                    ok: false,
                    message: format!("spawning br failed: {err}"),
                });
            }
        }
    }
    results
}

fn emit<T: Serialize>(report: &T, out: &Option<PathBuf>) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(report).map_err(|err| format!("serializing report: {err}"))?;
    if let Some(path) = out {
        std::fs::write(path, format!("{json}\n"))
            .map_err(|err| format!("writing {}: {err}", path.display()))?;
        eprintln!("[coverage_frontier] wrote report to {}", path.display());
    }
    println!("{json}");
    Ok(())
}

fn run() -> Result<ExitCode, String> {
    let Some(args) = parse_args()? else {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    };

    if args.reports.is_empty() && args.run_suite.is_none() && !args.engine_core_oracle {
        return Err(
            "no failure source selected; pass --report, --run-suite, and/or --engine-core-oracle\n\n"
                .to_string()
                + USAGE,
        );
    }
    if args.usage_signal.is_some() && !args.rank && !args.file_beads {
        return Err("--usage-signal requires --rank or --file-beads".to_string());
    }
    let exclusive = [
        args.rank,
        args.cross_reference,
        args.coverage_summary,
        args.file_beads,
    ]
    .iter()
    .filter(|f| **f)
    .count();
    if exclusive > 1 {
        return Err(
            "--rank, --file-beads, --cross-reference, and --coverage-summary are mutually exclusive"
                .to_string(),
        );
    }
    if args.execute && !args.file_beads {
        return Err("--execute requires --file-beads".to_string());
    }
    if args.execute && args.ledger.is_none() {
        return Err(
            "--execute requires --ledger <path> so the dedup ledger is persisted after filing"
                .to_string(),
        );
    }

    let collected = collect(&args)?;

    if args.coverage_summary {
        let limitations = vec![
            "scope: ES2020-normative observable surface (language/* + built-ins/*); excludes intl402, annexB, proposals, and harness".to_string(),
            "EXECUTED means the engine evaluated a positive case without an engine error, or correctly rejected a negative case; assertion outcomes are NOT verified — this is an execution-coverage measure, not a spec-conformance pass-rate".to_string(),
            "the stricter harness-based ES2020 conformance pass-rate (assertions enforced, Test262 includes preloaded) is far lower — see docs/test262_real_corpus_pass_rate_v1.json; this executed-% must not be read as a conformance score".to_string(),
            "the runner does not preload Test262 harness includes (assert.js, sta.js, propertyHelper.js), so cases that call those helpers are recorded as engine errors and excluded from executed".to_string(),
        ];
        let commit = if collected.corpus_commit.is_empty() {
            "unknown".to_string()
        } else {
            collected.corpus_commit.clone()
        };
        let summary = finalize_summary(&collected.coverage_tally, commit, 0, limitations);
        eprintln!(
            "[coverage_frontier] coverage summary: {}/{} in-scope executed = {} millionths; floor view `{}` = {} millionths; digest {}",
            summary.in_scope_passed,
            summary.in_scope_total,
            summary.observable_surface_executed_millionths,
            summary.floor_view,
            summary.floor_view_executed_millionths,
            summary.report_digest
        );
        emit(&summary, &args.out)?;
        return Ok(ExitCode::SUCCESS);
    }

    let report: CoverageFrontierReport = cluster_failures(
        &collected.observations,
        args.construct_depth,
        args.sample_limit,
    );
    eprintln!(
        "[coverage_frontier] {} failures -> {} clusters (digest {})",
        report.total_failures, report.cluster_count, report.report_digest
    );

    if args.cross_reference {
        let xref = cross_reference(&report, &default_inventory_entries());
        eprintln!(
            "[coverage_frontier] truth gate: {} clusters -> {} reconciled, {} undocumented ({}); digest {}",
            xref.total_clusters,
            xref.reconciled_count,
            xref.undocumented_count,
            if xref.truth_gate_pass { "PASS" } else { "FAIL" },
            xref.report_digest
        );
        emit(&xref, &args.out)?;
        return Ok(if xref.truth_gate_pass {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        });
    }

    if args.file_beads {
        let usage = match &args.usage_signal {
            Some(path) => Some(load_usage_signal(path)?),
            None => None,
        };
        let ranked = rank_clusters(&report, &collected.census, usage.as_ref());
        let mut ledger = match &args.ledger {
            Some(path) => load_ledger(path)?,
            None => FiledLedger::new(),
        };
        let plan = build_filing_plan(
            &ranked,
            &report,
            &ledger,
            args.top_n,
            args.parent.as_deref(),
        );
        eprintln!(
            "[coverage_frontier] file-beads plan: {} considered, {} new proposals, {} skipped (dedup); plan digest {}",
            plan.considered_count, plan.proposal_count, plan.skipped_count, plan.plan_digest
        );

        if args.execute {
            let results = execute_filing_plan(&plan, &mut ledger, args.parent.as_deref());
            // Persist the dedup ledger so a re-run skips what we just filed.
            // (Validated above: --execute requires --ledger.)
            if let Some(path) = &args.ledger {
                save_ledger(path, &ledger)?;
                eprintln!(
                    "[coverage_frontier] wrote {} ledger records to {}",
                    ledger.records.len(),
                    path.display()
                );
            }
            let any_failed = results.iter().any(|r| !r.ok);
            let execution = BeadFilingExecution {
                plan,
                results,
                ledger_records: ledger.records.len(),
            };
            emit(&execution, &args.out)?;
            return Ok(if any_failed {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            });
        }

        eprintln!(
            "[coverage_frontier] plan-only (review then re-run with --execute --ledger <path> to file)"
        );
        emit(&plan, &args.out)?;
        return Ok(ExitCode::SUCCESS);
    }

    if args.rank {
        let usage = match &args.usage_signal {
            Some(path) => Some(load_usage_signal(path)?),
            None => None,
        };
        let ranked = rank_clusters(&report, &collected.census, usage.as_ref());
        eprintln!(
            "[coverage_frontier] ranked {} clusters (usage signal: {}, digest {})",
            ranked.cluster_count,
            ranked.usage_signal_source.as_deref().unwrap_or("neutral"),
            ranked.report_digest
        );
        emit(&ranked, &args.out)?;
    } else {
        emit(&report, &args.out)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}
