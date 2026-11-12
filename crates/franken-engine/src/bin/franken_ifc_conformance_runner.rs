#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::conformance_harness::{
    ConformanceEvidenceCollector, ConformanceRunner, ConformanceWaiverSet,
};
use serde_json::Value;

#[derive(Debug, Clone)]
struct CliArgs {
    manifest_path: PathBuf,
    output_root: PathBuf,
    waiver_path: Option<PathBuf>,
}

fn default_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/ifc_corpus/ifc_conformance_assets.json")
}

fn default_output_root() -> PathBuf {
    PathBuf::from("artifacts/ifc_conformance")
}

fn parse_args() -> Result<CliArgs, String> {
    let mut manifest_path = default_manifest_path();
    let mut output_root = default_output_root();
    let mut waiver_path = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--manifest requires a value".to_string())?;
                manifest_path = PathBuf::from(value);
            }
            "--output-root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output-root requires a value".to_string())?;
                output_root = PathBuf::from(value);
            }
            "--waivers" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--waivers requires a value".to_string())?;
                waiver_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                return Err(
                    "usage: franken_ifc_conformance_runner [--manifest <path>] [--output-root <path>] [--waivers <path>]".to_string(),
                );
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }

    Ok(CliArgs {
        manifest_path,
        output_root,
        waiver_path,
    })
}

fn load_waivers(path: Option<&PathBuf>) -> Result<ConformanceWaiverSet, Box<dyn Error>> {
    match path {
        Some(path) => Ok(ConformanceWaiverSet::load_toml(path)?),
        None => Ok(ConformanceWaiverSet::default()),
    }
}

#[derive(Debug, Clone)]
struct IfcSummaryMetrics {
    ci_blocking_failures: u64,
    false_positive_count: u64,
    false_negative_count: u64,
    false_negative_direct_indirect_count: u64,
    benign_total: u64,
    exfil_total: u64,
    declassify_total: u64,
}

fn read_ifc_summary_metrics(
    ifc_evidence_path: &PathBuf,
) -> Result<IfcSummaryMetrics, Box<dyn Error>> {
    let bytes = fs::read_to_string(ifc_evidence_path)?;
    let first_line = bytes
        .lines()
        .next()
        .ok_or_else(|| "ifc evidence file is empty".to_string())?;
    let summary: Value = serde_json::from_str(first_line)?;
    let category_counts = summary["category_counts"].as_object();
    let benign_total = category_counts
        .and_then(|counts| counts.get("benign"))
        .and_then(|value| value.get("total"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let exfil_total = category_counts
        .and_then(|counts| counts.get("exfil"))
        .and_then(|value| value.get("total"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let declassify_total = category_counts
        .and_then(|counts| counts.get("declassify"))
        .and_then(|value| value.get("total"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    Ok(IfcSummaryMetrics {
        ci_blocking_failures: summary["ci_blocking_failures"].as_u64().unwrap_or(0),
        false_positive_count: summary["false_positive_count"].as_u64().unwrap_or(0),
        false_negative_count: summary["false_negative_count"].as_u64().unwrap_or(0),
        false_negative_direct_indirect_count: summary["false_negative_direct_indirect_count"]
            .as_u64()
            .unwrap_or(0),
        benign_total,
        exfil_total,
        declassify_total,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args =
        parse_args().map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    let waivers = load_waivers(args.waiver_path.as_ref())?;
    let runner = ConformanceRunner::default();
    let run = runner.run(&args.manifest_path, &waivers)?;
    run.enforce_ci_gate()?;

    let collector = ConformanceEvidenceCollector::new(&args.output_root)?;
    let artifacts = collector.collect(&run)?;

    if let Some(ifc_path) = artifacts.ifc_conformance_evidence_path.as_ref() {
        let metrics = read_ifc_summary_metrics(ifc_path)?;
        if metrics.ci_blocking_failures > 0 {
            return Err(format!(
                "IFC CI gate blocked: ci_blocking_failures={} (see {})",
                metrics.ci_blocking_failures,
                ifc_path.display()
            )
            .into());
        }

        println!(
            "ifc metric.ci_blocking_failures={}",
            metrics.ci_blocking_failures
        );
        println!(
            "ifc metric.false_positive_count={}",
            metrics.false_positive_count
        );
        println!(
            "ifc metric.false_negative_count={}",
            metrics.false_negative_count
        );
        println!(
            "ifc metric.false_negative_direct_indirect_count={}",
            metrics.false_negative_direct_indirect_count
        );
        println!("ifc metric.benign_total={}", metrics.benign_total);
        println!("ifc metric.exfil_total={}", metrics.exfil_total);
        println!("ifc metric.declassify_total={}", metrics.declassify_total);
    } else {
        return Err("collector did not emit ifc_conformance_evidence.jsonl".into());
    }

    println!("ifc run_id={}", run.run_id);
    println!("ifc assets={}", run.summary.total_assets);
    println!("ifc run_manifest={}", artifacts.run_manifest_path.display());
    println!(
        "ifc conformance_evidence={}",
        artifacts.conformance_evidence_path.display()
    );
    if let Some(ifc_path) = artifacts.ifc_conformance_evidence_path {
        println!("ifc ifc_conformance_evidence={}", ifc_path.display());
    }

    Ok(())
}
