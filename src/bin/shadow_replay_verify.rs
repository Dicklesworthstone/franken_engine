#!/usr/bin/env cargo

//! CLI wrapper for shadow replay verification
//! Usage: cargo run --bin shadow_replay_verify -- <journal_export.json> <replay_report_output.json>

use std::env;
use std::fs;

use frankenengine_engine::shadow_replay_verifier::{ShadowReplayVerifier, ReplayVerificationConfig};
use frankenengine_engine::shadow_evidence_journal::ShadowEvidenceJournalExport;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <journal_export.json> <replay_report_output.json>", args[0]);
        std::process::exit(1);
    }

    let journal_export_path = &args[1];
    let replay_report_output_path = &args[2];

    // Read journal export
    let export_content = fs::read_to_string(journal_export_path)?;
    let journal_export: ShadowEvidenceJournalExport = serde_json::from_str(&export_content)?;

    // Create replay verifier with default config
    let mut verifier = ShadowReplayVerifier::with_default_config()?;

    // Perform replay verification using real replay verifier
    let drift_report = verifier.replay_export(journal_export, "e2e_drill".to_string())?;

    // Write replay report output
    let report_json = serde_json::to_string_pretty(&drift_report)?;
    fs::write(replay_report_output_path, report_json)?;

    eprintln!("Shadow replay verification completed using real verifier");
    Ok(())
}