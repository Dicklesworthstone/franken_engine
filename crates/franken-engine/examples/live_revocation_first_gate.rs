use std::env;
use std::process;

use frankenengine_engine::live_revocation_first_gate_example::{
    COMPONENT, write_live_revocation_first_gate_artifacts,
};

fn main() {
    let output_dir = env::args()
        .nth(1)
        .unwrap_or_else(|| "artifacts/live_revocation_first_gate/manual-run".to_string());

    match write_live_revocation_first_gate_artifacts(&output_dir) {
        Ok(report) => {
            println!(
                "{COMPONENT}: decision={} witness_id={} publication_id={}",
                report.decision, report.witness_id, report.publication_id
            );
            println!("{COMPONENT}: artifacts={output_dir}");
        }
        Err(error) => {
            eprintln!("{COMPONENT}: {error}");
            process::exit(1);
        }
    }
}
