#!/usr/bin/env cargo

//! CLI wrapper for shadow decision composition
//! Usage: cargo run --bin shadow_compose_decision -- <journal_export.json> <status_output.json> <recommendations_output.json>

use std::env;
use std::fs;
use std::path::Path;

use frankenengine_engine::shadow_decision_composer::{compose_shadow_decision, ShadowDecisionInput, ShadowDecisionOutput};
use frankenengine_engine::shadow_evidence_journal::{ShadowEvidenceJournalExport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <journal_export.json> <status_output.json> <recommendations_output.json>", args[0]);
        std::process::exit(1);
    }

    let journal_export_path = &args[1];
    let status_output_path = &args[2];
    let recommendations_output_path = &args[3];

    // Read journal export
    let export_content = fs::read_to_string(journal_export_path)?;
    let journal_export: ShadowEvidenceJournalExport = serde_json::from_str(&export_content)?;

    // Compose decision using real shadow decision composer
    let decision_input = ShadowDecisionInput::from_journal_export(&journal_export)?;
    let decision_output = compose_shadow_decision(&decision_input)?;

    // Write status output
    let status = decision_output.to_status_json()?;
    fs::write(status_output_path, status)?;

    // Write recommendations output
    let recommendations = decision_output.to_recommendations_json()?;
    fs::write(recommendations_output_path, recommendations)?;

    eprintln!("Shadow decision composition completed using real composer");
    Ok(())
}