//! `franken_coverage_frontier` (`bd-fqlfw.7.1` E7.T1 + `bd-fqlfw.7.2` E7.T2) —
//! operator binary that clusters Test262 and differential-oracle FAILURES by
//! spec construct into a deterministic, content-hashed coverage-frontier
//! report, and (with `--rank`) ranks those clusters by a transparent impact
//! score.
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
//!   --usage-signal <path>    JSON usage signal (construct → weight millionths)
//!                            from a real npm corpus scan; only used with --rank.
//!                            Absent ⇒ neutral usage (no fabricated frequencies).
//!   --cross-reference        Truth-gate: cross-reference clusters against the
//!                            parser/lowering gap inventories. Exits 3 if any
//!                            cluster is an undocumented gap. (Excludes --rank.)
//!   --sample-count <N>       Cap tests for --run-suite (0 = all; default 2000).
//!   --pattern <glob>         Glob filter for --run-suite.
//!   --construct-depth <N>    Path depth for Test262 construct keys (default 3).
//!   --sample-limit <N>       Sample case ids retained per cluster (default 8).
//!   --out <path>             Write the report JSON here (always also to stdout).
//!   -h, --help               Print this help.
//!
//! Exit codes: 0 report emitted (and truth gate passed, if --cross-reference);
//! 2 usage error / no source selected; 3 truth-gate failure (undocumented gaps).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;

use frankenengine_engine::coverage_frontier::{
    CoverageFrontierReport, DEFAULT_CONSTRUCT_DEPTH, DEFAULT_SAMPLE_LIMIT, FailureObservation,
    cluster_failures, observations_from_conformance, observations_from_engine_core_report,
};
use frankenengine_engine::coverage_frontier_rank::{
    ConstructCensus, UsageSignal, construct_census_from_conformance, merge_censuses, rank_clusters,
};
use frankenengine_engine::coverage_frontier_xref::{cross_reference, default_inventory_entries};
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
    --usage-signal <path>    JSON usage signal (construct → weight millionths), --rank only
    --cross-reference        Truth-gate clusters vs parser/lowering gap inventories (exit 3 on drift)
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
    usage_signal: Option<PathBuf>,
    cross_reference: bool,
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
            usage_signal: None,
            cross_reference: false,
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
            "--usage-signal" => args.usage_signal = Some(PathBuf::from(value()?)),
            "--cross-reference" => args.cross_reference = true,
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

/// Failure observations plus the per-construct pass/fail census needed for the
/// locality factor (populated from Test262 conformance sources only).
struct Collected {
    observations: Vec<FailureObservation>,
    census: BTreeMap<String, ConstructCensus>,
}

/// Fold one conformance report into the running observation list and census.
fn ingest_conformance(
    report: &ConformanceReport,
    depth: usize,
    observations: &mut Vec<FailureObservation>,
    census: &mut BTreeMap<String, ConstructCensus>,
) {
    observations.extend(observations_from_conformance(report, depth));
    let merged = merge_censuses(
        std::mem::take(census),
        &construct_census_from_conformance(report, depth),
    );
    *census = merged;
}

fn collect(args: &Args) -> Result<Collected, String> {
    let mut observations = Vec::new();
    let mut census: BTreeMap<String, ConstructCensus> = BTreeMap::new();

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
        ingest_conformance(
            &report,
            args.construct_depth,
            &mut observations,
            &mut census,
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
        ingest_conformance(
            &report,
            args.construct_depth,
            &mut observations,
            &mut census,
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
    })
}

fn load_usage_signal(path: &PathBuf) -> Result<UsageSignal, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("reading usage signal {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("parsing usage signal {}: {err}", path.display()))
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
    if args.usage_signal.is_some() && !args.rank {
        return Err("--usage-signal requires --rank".to_string());
    }
    if args.rank && args.cross_reference {
        return Err("--rank and --cross-reference are mutually exclusive".to_string());
    }

    let collected = collect(&args)?;
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
