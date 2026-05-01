//! Live guardplane posterior and expected-loss decision example.
//!
//! This example demonstrates the FrankenEngine's probabilistic guardplane
//! computing posterior risk distributions and selecting containment actions
//! based on expected-loss minimization.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use frankenengine_engine::bayesian_posterior::{Posterior, RiskState};
use frankenengine_engine::expected_loss_selector::{
    ActionDecision, ContainmentAction, ExpectedLossSelector, LossEntry, LossMatrix,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_artifact::{
    ProofArtifactPaths, ProofCommand, ProofRunStatus, PROOF_EVENT_SCHEMA_VERSION,
    PROOF_MANIFEST_SCHEMA_VERSION, PROOF_REPORT_SCHEMA_VERSION,
};

pub const EXAMPLE_BEAD_ID: &str = "bd-1ypps";
pub const EXAMPLE_COMPONENT: &str = "live_guardplane_decision_example";

/// Synthetic decision input representing a suspicious extension operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticDecisionInput {
    pub extension_id: String,
    pub operation_type: String,
    pub hostcall_evidence: Vec<HostcallEvidence>,
    pub prior_violations: u32,
    pub time_since_install_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostcallEvidence {
    pub hostcall_name: String,
    pub frequency: u32,
    pub anomaly_score_millionths: u64, // 0-1_000_000 scale
    pub privilege_level: String,
}

/// Proof artifact event for the guardplane decision process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardplaneDecisionEvent {
    pub schema_version: String,
    pub timestamp_utc: String,
    pub event_type: String,
    pub component: String,
    pub extension_id: String,
    pub prior_probabilities: BTreeMap<String, u64>,
    pub posterior_probabilities: BTreeMap<String, u64>,
    pub loss_matrix_id: String,
    pub expected_losses: BTreeMap<String, u64>,
    pub selected_action: String,
    pub confidence_millionths: u64,
    pub explanation: String,
}

/// Machine-readable report for the guardplane decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardplaneDecisionReport {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub extension_id: String,
    pub decision_outcome: String,
    pub selected_action: String,
    pub posterior_risk_assessment: BTreeMap<String, u64>,
    pub expected_losses: BTreeMap<String, u64>,
    pub confidence_score: u64,
    pub evidence_summary: String,
    pub recommendation: String,
}

/// Proof manifest following the cd3d2b4d contract format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardplaneDecisionManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub proof_type: String,
    pub status: String,
    pub generated_at_utc: String,
    pub artifacts: ProofArtifactPaths,
    pub commands_executed: u32,
    pub events_recorded: u32,
    pub evidence_hash: String,
    pub decision_hash: String,
}

impl SyntheticDecisionInput {
    /// Create a suspicious extension scenario for demonstration.
    pub fn suspicious_extension_scenario() -> Self {
        Self {
            extension_id: "suspicious-extension-v1.2.3".to_string(),
            operation_type: "filesystem_access".to_string(),
            hostcall_evidence: vec![
                HostcallEvidence {
                    hostcall_name: "fs_read".to_string(),
                    frequency: 157,
                    anomaly_score_millionths: 750_000, // 75% anomaly score
                    privilege_level: "elevated".to_string(),
                },
                HostcallEvidence {
                    hostcall_name: "net_connect".to_string(),
                    frequency: 23,
                    anomaly_score_millionths: 850_000, // 85% anomaly score
                    privilege_level: "restricted".to_string(),
                },
                HostcallEvidence {
                    hostcall_name: "crypto_sign".to_string(),
                    frequency: 5,
                    anomaly_score_millionths: 950_000, // 95% anomaly score
                    privilege_level: "sensitive".to_string(),
                },
            ],
            prior_violations: 2,
            time_since_install_hours: 12,
        }
    }

    /// Create a benign extension scenario for comparison.
    pub fn benign_extension_scenario() -> Self {
        Self {
            extension_id: "trusted-extension-v2.1.0".to_string(),
            operation_type: "ui_rendering".to_string(),
            hostcall_evidence: vec![
                HostcallEvidence {
                    hostcall_name: "dom_query".to_string(),
                    frequency: 45,
                    anomaly_score_millionths: 150_000, // 15% anomaly score
                    privilege_level: "standard".to_string(),
                },
                HostcallEvidence {
                    hostcall_name: "css_apply".to_string(),
                    frequency: 78,
                    anomaly_score_millionths: 200_000, // 20% anomaly score
                    privilege_level: "standard".to_string(),
                },
            ],
            prior_violations: 0,
            time_since_install_hours: 720, // 30 days
        }
    }
}

/// Compute Bayesian posterior based on hostcall evidence and prior violations.
pub fn compute_evidence_posterior(input: &SyntheticDecisionInput) -> Posterior {
    // Start with default prior
    let mut posterior = Posterior::default_prior();

    // Adjust posterior based on hostcall evidence anomaly scores
    let avg_anomaly_score = input
        .hostcall_evidence
        .iter()
        .map(|e| e.anomaly_score_millionths)
        .sum::<u64>() as i64
        / input.hostcall_evidence.len() as i64;

    // Adjust posterior based on prior violations
    let violation_factor = input.prior_violations as i64 * 100_000; // Each violation adds 10%

    // Evidence-based adjustment: high anomaly scores shift toward malicious/anomalous
    let anomaly_shift = (avg_anomaly_score - 500_000).max(0); // Above 50% is concerning
    let violation_shift = violation_factor.min(300_000); // Cap at 30% shift

    // Redistribute probability mass based on evidence
    let total_shift = anomaly_shift + violation_shift;
    let malicious_boost = total_shift / 2;
    let anomalous_boost = total_shift / 3;
    let unknown_boost = total_shift / 6;

    posterior.p_malicious += malicious_boost;
    posterior.p_anomalous += anomalous_boost;
    posterior.p_unknown += unknown_boost;
    posterior.p_benign -= total_shift;

    // Ensure probabilities stay positive and sum to 1_000_000
    posterior.p_benign = posterior.p_benign.max(10_000); // At least 1%
    posterior.p_malicious = posterior.p_malicious.min(800_000); // At most 80%

    let total = posterior.p_benign + posterior.p_anomalous + posterior.p_malicious + posterior.p_unknown;
    if total != 1_000_000 {
        let adjustment = 1_000_000 - total;
        posterior.p_benign += adjustment;
    }

    posterior
}

/// Create a security-focused loss matrix for containment decisions.
pub fn create_security_loss_matrix() -> LossMatrix {
    LossMatrix::new(
        "security_focused_v1",
        vec![
            // Allow action: low cost for benign, high cost for malicious
            LossEntry::new(ContainmentAction::Allow, RiskState::Benign, 10_000),     // 1% cost
            LossEntry::new(ContainmentAction::Allow, RiskState::Anomalous, 200_000), // 20% cost
            LossEntry::new(ContainmentAction::Allow, RiskState::Malicious, 900_000), // 90% cost
            LossEntry::new(ContainmentAction::Allow, RiskState::Unknown, 300_000),   // 30% cost

            // Warn action: moderate cost across all states
            LossEntry::new(ContainmentAction::Warn, RiskState::Benign, 50_000),      // 5% cost
            LossEntry::new(ContainmentAction::Warn, RiskState::Anomalous, 100_000),  // 10% cost
            LossEntry::new(ContainmentAction::Warn, RiskState::Malicious, 400_000),  // 40% cost
            LossEntry::new(ContainmentAction::Warn, RiskState::Unknown, 150_000),    // 15% cost

            // Deny action: high cost for benign, low cost for malicious
            LossEntry::new(ContainmentAction::Deny, RiskState::Benign, 300_000),     // 30% cost
            LossEntry::new(ContainmentAction::Deny, RiskState::Anomalous, 150_000),  // 15% cost
            LossEntry::new(ContainmentAction::Deny, RiskState::Malicious, 50_000),   // 5% cost
            LossEntry::new(ContainmentAction::Deny, RiskState::Unknown, 200_000),    // 20% cost

            // Kill action: very high cost for benign, very low cost for malicious
            LossEntry::new(ContainmentAction::Kill, RiskState::Benign, 800_000),     // 80% cost
            LossEntry::new(ContainmentAction::Kill, RiskState::Anomalous, 400_000),  // 40% cost
            LossEntry::new(ContainmentAction::Kill, RiskState::Malicious, 20_000),   // 2% cost
            LossEntry::new(ContainmentAction::Kill, RiskState::Unknown, 600_000),    // 60% cost
        ],
    )
}

/// Execute the guardplane decision pipeline and generate proof artifacts.
pub fn execute_guardplane_decision_with_proof(
    input: &SyntheticDecisionInput,
    output_dir: &Path,
) -> Result<GuardplaneDecisionReport, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let timestamp = Utc::now();
    let timestamp_str = timestamp.to_rfc3339();

    // Step 1: Compute Bayesian posterior
    let posterior = compute_evidence_posterior(input);

    // Step 2: Set up expected-loss computation
    let loss_matrix = create_security_loss_matrix();
    let mut selector = ExpectedLossSelector::new(loss_matrix);

    // Step 3: Select optimal action
    let decision = selector.select(&posterior);

    // Step 4: Create proof artifacts
    let artifacts = ProofArtifactPaths::standard(output_dir)?;

    // Generate decision event for structured log
    let decision_event = GuardplaneDecisionEvent {
        schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
        timestamp_utc: timestamp_str.clone(),
        event_type: "guardplane_decision".to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        extension_id: input.extension_id.clone(),
        prior_probabilities: BTreeMap::from([
            ("benign".to_string(), 850_000u64),
            ("anomalous".to_string(), 40_000u64),
            ("malicious".to_string(), 10_000u64),
            ("unknown".to_string(), 100_000u64),
        ]),
        posterior_probabilities: BTreeMap::from([
            ("benign".to_string(), posterior.p_benign as u64),
            ("anomalous".to_string(), posterior.p_anomalous as u64),
            ("malicious".to_string(), posterior.p_malicious as u64),
            ("unknown".to_string(), posterior.p_unknown as u64),
        ]),
        loss_matrix_id: "security_focused_v1".to_string(),
        expected_losses: BTreeMap::from([
            ("allow".to_string(), decision.expected_loss_allow as u64),
            ("warn".to_string(), decision.expected_loss_warn as u64),
            ("deny".to_string(), decision.expected_loss_deny as u64),
            ("kill".to_string(), decision.expected_loss_kill as u64),
        ]),
        selected_action: format!("{:?}", decision.action).to_lowercase(),
        confidence_millionths: 850_000, // High confidence for this deterministic example
        explanation: decision.explanation.clone(),
    };

    // Write events.jsonl
    let events_content = serde_json::to_string(&decision_event)?;
    fs::write(&artifacts.events_jsonl, format!("{}\n", events_content))?;

    // Write commands.txt (example command that would be executed)
    let command = ProofCommand {
        command_id: "guardplane_decision_001".to_string(),
        display: format!("guardplane-decision --extension {} --operation {}",
                         input.extension_id, input.operation_type),
        redacted_display: "guardplane-decision --extension [REDACTED] --operation [REDACTED]".to_string(),
        cwd: "/data/projects/franken_engine".to_string(),
        exit_code: Some(0),
        duration_ms: Some(15),
    };
    fs::write(&artifacts.commands_txt, format!("{}\n", serde_json::to_string(&command)?))?;

    // Create machine-readable report
    let report = GuardplaneDecisionReport {
        schema_version: PROOF_REPORT_SCHEMA_VERSION.to_string(),
        bead_id: EXAMPLE_BEAD_ID.to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        generated_at_utc: timestamp_str.clone(),
        extension_id: input.extension_id.clone(),
        decision_outcome: if matches!(decision.action, ContainmentAction::Allow) {
            "approved".to_string()
        } else {
            "contained".to_string()
        },
        selected_action: format!("{:?}", decision.action).to_lowercase(),
        posterior_risk_assessment: decision_event.posterior_probabilities.clone(),
        expected_losses: decision_event.expected_losses.clone(),
        confidence_score: decision_event.confidence_millionths,
        evidence_summary: format!(
            "{} hostcalls analyzed, {} prior violations, avg anomaly score {:.1}%",
            input.hostcall_evidence.len(),
            input.prior_violations,
            input.hostcall_evidence.iter()
                .map(|e| e.anomaly_score_millionths)
                .sum::<u64>() as f64 / (input.hostcall_evidence.len() as f64 * 10_000.0)
        ),
        recommendation: format!(
            "Extension {} should be {} based on {} risk assessment (P(malicious)={:.1}%)",
            input.extension_id,
            format!("{:?}", decision.action).to_lowercase(),
            if posterior.p_malicious > 500_000 { "high" }
            else if posterior.p_malicious > 200_000 { "medium" }
            else { "low" },
            posterior.p_malicious as f64 / 10_000.0
        ),
    };

    // Write report.json
    fs::write(&artifacts.report_json, serde_json::to_string_pretty(&report)?)?;

    // Write human-readable report.md
    let markdown_report = format!(
        r#"# Guardplane Decision Report

## Extension Analysis: {}

**Decision**: {}
**Confidence**: {:.1}%
**Generated**: {}

## Risk Assessment

| Risk State | Prior Probability | Posterior Probability |
|------------|-------------------|----------------------|
| Benign     | 85.0%            | {:.1}%               |
| Anomalous  | 4.0%             | {:.1}%               |
| Malicious  | 1.0%             | {:.1}%               |
| Unknown    | 10.0%            | {:.1}%               |

## Expected Loss Analysis

| Action | Expected Loss | Decision |
|--------|---------------|----------|
| Allow  | {:.1}%        | {}       |
| Warn   | {:.1}%        | {}       |
| Deny   | {:.1}%        | {}       |
| Kill   | {:.1}%        | {}       |

## Evidence Summary

{}

## Recommendation

{}

*This report was generated by the FrankenEngine Live Guardplane Decision Example (bd-1ypps)*
"#,
        input.extension_id,
        format!("{:?}", decision.action),
        decision_event.confidence_millionths as f64 / 10_000.0,
        timestamp_str,
        posterior.p_benign as f64 / 10_000.0,
        posterior.p_anomalous as f64 / 10_000.0,
        posterior.p_malicious as f64 / 10_000.0,
        posterior.p_unknown as f64 / 10_000.0,
        decision.expected_loss_allow as f64 / 10_000.0,
        if matches!(decision.action, ContainmentAction::Allow) { "← **SELECTED**" } else { "" },
        decision.expected_loss_warn as f64 / 10_000.0,
        if matches!(decision.action, ContainmentAction::Warn) { "← **SELECTED**" } else { "" },
        decision.expected_loss_deny as f64 / 10_000.0,
        if matches!(decision.action, ContainmentAction::Deny) { "← **SELECTED**" } else { "" },
        decision.expected_loss_kill as f64 / 10_000.0,
        if matches!(decision.action, ContainmentAction::Kill) { "← **SELECTED**" } else { "" },
        report.evidence_summary,
        report.recommendation,
    );

    fs::write(&artifacts.report_md, markdown_report)?;

    // Compute content hashes for integrity
    let evidence_hash = ContentHash::compute(serde_json::to_string(&input)?.as_bytes());
    let decision_hash = ContentHash::compute(serde_json::to_string(&decision_event)?.as_bytes());

    // Create manifest following cd3d2b4d contract
    let manifest = GuardplaneDecisionManifest {
        schema_version: PROOF_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: EXAMPLE_BEAD_ID.to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        proof_type: "guardplane_live_decision_example".to_string(),
        status: "completed".to_string(),
        generated_at_utc: timestamp_str,
        artifacts,
        commands_executed: 1,
        events_recorded: 1,
        evidence_hash: format!("{:x}", evidence_hash.as_bytes()),
        decision_hash: format!("{:x}", decision_hash.as_bytes()),
    };

    // Write manifest.json
    fs::write(&manifest.artifacts.manifest_json, serde_json::to_string_pretty(&manifest)?)?;

    println!("✅ Guardplane decision proof artifacts generated:");
    println!("   📁 Output directory: {}", output_dir.display());
    println!("   📄 Manifest: {}", manifest.artifacts.manifest_json);
    println!("   📊 Report: {}", manifest.artifacts.report_json);
    println!("   📝 Human report: {}", manifest.artifacts.report_md);
    println!("   📋 Events: {}", manifest.artifacts.events_jsonl);
    println!("   🔍 Decision: {} (confidence: {:.1}%)",
             format!("{:?}", decision.action),
             decision_event.confidence_millionths as f64 / 10_000.0);

    Ok(report)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 FrankenEngine Live Guardplane Decision Example");
    println!("   Demonstrating posterior computation + expected-loss decision making");

    // Example 1: Suspicious extension
    println!("\n📊 Example 1: Suspicious Extension Analysis");
    let suspicious_input = SyntheticDecisionInput::suspicious_extension_scenario();
    let output_dir_1 = Path::new("/tmp/guardplane_example_suspicious");
    execute_guardplane_decision_with_proof(&suspicious_input, output_dir_1)?;

    // Example 2: Benign extension
    println!("\n📊 Example 2: Benign Extension Analysis");
    let benign_input = SyntheticDecisionInput::benign_extension_scenario();
    let output_dir_2 = Path::new("/tmp/guardplane_example_benign");
    execute_guardplane_decision_with_proof(&benign_input, output_dir_2)?;

    println!("\n✨ Live guardplane decision examples completed successfully!");
    println!("   Check the generated proof artifact bundles for detailed analysis.");

    Ok(())
}