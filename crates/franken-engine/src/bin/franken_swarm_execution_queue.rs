#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process;

use frankenengine_engine::swarm_execution_queue_runner::{
    ExecutionQueueRunOptions, run_normalized_input_file,
};

fn usage() -> &'static str {
    "Usage: franken_swarm_execution_queue --normalized-input-json FILE --output-dir DIR [--queue-depth N] [--epoch N] [--timestamp-ns N] [--include-gated]"
}

fn main() {
    let mut normalized_input_json: Option<PathBuf> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut options = ExecutionQueueRunOptions::default();
    let command_line: Vec<String> = env::args().collect();

    let mut args = command_line.iter().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--normalized-input-json" => {
                normalized_input_json = args.next().map(PathBuf::from);
            }
            "--output-dir" => {
                output_dir = args.next().map(PathBuf::from);
            }
            "--queue-depth" => {
                options.queue_depth = parse_usize(args.next(), "--queue-depth");
            }
            "--epoch" => {
                options.epoch = parse_u64(args.next(), "--epoch");
            }
            "--timestamp-ns" => {
                options.timestamp_ns = parse_u64(args.next(), "--timestamp-ns");
            }
            "--include-gated" => {
                options.include_gated_in_queue = true;
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("{}", usage());
                process::exit(64);
            }
        }
    }

    let Some(normalized_input_json) = normalized_input_json else {
        eprintln!("missing --normalized-input-json");
        eprintln!("{}", usage());
        process::exit(64);
    };
    let Some(output_dir) = output_dir else {
        eprintln!("missing --output-dir");
        eprintln!("{}", usage());
        process::exit(64);
    };

    options.command_line = command_line;
    match run_normalized_input_file(&normalized_input_json, &output_dir, options) {
        Ok(output) => {
            println!("run_manifest_json={}", output.run_manifest_json.display());
            println!(
                "execution_queue_artifact_json={}",
                output.execution_queue_artifact_json.display()
            );
            println!(
                "risk_budget_receipt_json={}",
                output.risk_budget_receipt_json.display()
            );
            println!(
                "bottleneck_report_json={}",
                output.bottleneck_report_json.display()
            );
            println!(
                "operator_summary_md={}",
                output.operator_summary_md.display()
            );
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(err.exit_code());
        }
    }
}

fn parse_u64(value: Option<&String>, label: &str) -> u64 {
    value
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or_else(|| {
            eprintln!("{label} must be a non-negative integer");
            process::exit(64);
        })
}

fn parse_usize(value: Option<&String>, label: &str) -> usize {
    value
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or_else(|| {
            eprintln!("{label} must be a non-negative integer");
            process::exit(64);
        })
}
