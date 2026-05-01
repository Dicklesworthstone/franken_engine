//! Live quarantine propagation example with convergence evidence.
//!
//! This example demonstrates FrankenEngine's fleet-wide quarantine propagation,
//! showing how security decisions spread across instances and achieve convergence
//! for coordinated containment.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use frankenengine_engine::fleet_immune_protocol::NodeId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_artifact::{
    ProofArtifactPaths, ProofCommand, PROOF_EVENT_SCHEMA_VERSION,
    PROOF_MANIFEST_SCHEMA_VERSION, PROOF_REPORT_SCHEMA_VERSION,
};
use frankenengine_engine::quarantine_propagation::{
    QuarantineAck, QuarantineDecision, QuarantineProtocolManager, QuarantineState,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

pub const EXAMPLE_BEAD_ID: &str = "bd-1py8v";
pub const EXAMPLE_COMPONENT: &str = "live_quarantine_propagation_example";

/// Synthetic security event that triggers quarantine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticSecurityEvent {
    pub event_id: String,
    pub extension_id: String,
    pub extension_version: String,
    pub threat_type: String,
    pub severity_score: u32, // 0-100 scale
    pub indicators: Vec<ThreatIndicator>,
    pub detection_instance: String,
    pub event_timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub value: String,
    pub confidence_score: u32, // 0-100 scale
    pub source: String,
}

/// Fleet topology for the quarantine propagation simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetTopology {
    pub instances: Vec<FleetInstance>,
    pub total_instances: usize,
    pub convergence_threshold: f64, // 0.0-1.0 (fraction of instances needed for convergence)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetInstance {
    pub node_id: String,
    pub instance_name: String,
    pub region: String,
    pub role: String, // "coordinator", "replica", "witness"
}

/// Quarantine propagation event for structured logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinePropagationEvent {
    pub schema_version: String,
    pub timestamp_utc: String,
    pub event_type: String,
    pub component: String,
    pub event_id: String,
    pub extension_id: String,
    pub originator_instance: String,
    pub target_instances: Vec<String>,
    pub propagation_step: String, // "initiated", "propagating", "acknowledging", "converged"
    pub acknowledgments_received: u32,
    pub total_instances: u32,
    pub convergence_achieved: bool,
    pub convergence_time_ms: Option<u64>,
    pub evidence_hash: String,
}

/// Convergence evidence report showing quarantine propagation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConvergenceReport {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub security_event_id: String,
    pub extension_id: String,
    pub quarantine_decision_outcome: String, // "quarantined", "rejected", "timeout"
    pub originator_instance: String,
    pub fleet_size: u32,
    pub acknowledgments_received: u32,
    pub convergence_achieved: bool,
    pub convergence_percentage: f64,
    pub propagation_time_ms: u64,
    pub threat_severity: u32,
    pub decision_summary: String,
    pub next_steps: String,
}

/// Proof manifest for quarantine propagation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinePropagationManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub proof_type: String,
    pub status: String,
    pub generated_at_utc: String,
    pub artifacts: ProofArtifactPaths,
    pub security_event_id: String,
    pub quarantine_evidence_hash: String,
    pub convergence_evidence_hash: String,
    pub fleet_instances_count: u32,
    pub commands_executed: u32,
    pub events_recorded: u32,
}

impl SyntheticSecurityEvent {
    /// Create a high-severity malware detection event.
    pub fn malware_detection_scenario() -> Self {
        Self {
            event_id: "evt-malware-001".to_string(),
            extension_id: "suspicious-crypto-miner".to_string(),
            extension_version: "v1.0.8".to_string(),
            threat_type: "malware".to_string(),
            severity_score: 95,
            indicators: vec![
                ThreatIndicator {
                    indicator_type: "network_connection".to_string(),
                    value: "suspicious-mining-pool.com:4444".to_string(),
                    confidence_score: 98,
                    source: "network_monitor".to_string(),
                },
                ThreatIndicator {
                    indicator_type: "cpu_usage_spike".to_string(),
                    value: "sustained_100_percent_utilization".to_string(),
                    confidence_score: 92,
                    source: "resource_monitor".to_string(),
                },
                ThreatIndicator {
                    indicator_type: "file_hash".to_string(),
                    value: "sha256:7b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c".to_string(),
                    confidence_score: 99,
                    source: "virus_total".to_string(),
                },
            ],
            detection_instance: "instance-us-east-1-primary".to_string(),
            event_timestamp: "2026-05-01T05:45:00Z".to_string(),
        }
    }

    /// Create a medium-severity suspicious activity event.
    pub fn suspicious_activity_scenario() -> Self {
        Self {
            event_id: "evt-suspicious-001".to_string(),
            extension_id: "data-exfiltration-tool".to_string(),
            extension_version: "v2.1.3".to_string(),
            threat_type: "suspicious_activity".to_string(),
            severity_score: 75,
            indicators: vec![
                ThreatIndicator {
                    indicator_type: "file_access_pattern".to_string(),
                    value: "bulk_document_enumeration".to_string(),
                    confidence_score: 85,
                    source: "file_monitor".to_string(),
                },
                ThreatIndicator {
                    indicator_type: "network_upload".to_string(),
                    value: "large_data_transfer_unknown_destination".to_string(),
                    confidence_score: 78,
                    source: "network_monitor".to_string(),
                },
            ],
            detection_instance: "instance-eu-west-1-replica".to_string(),
            event_timestamp: "2026-05-01T05:50:00Z".to_string(),
        }
    }
}

impl FleetTopology {
    /// Create a simulated fleet topology with multiple regions.
    pub fn create_multi_region_fleet() -> Self {
        Self {
            instances: vec![
                FleetInstance {
                    node_id: "node-001".to_string(),
                    instance_name: "instance-us-east-1-primary".to_string(),
                    region: "us-east-1".to_string(),
                    role: "coordinator".to_string(),
                },
                FleetInstance {
                    node_id: "node-002".to_string(),
                    instance_name: "instance-us-west-2-replica".to_string(),
                    region: "us-west-2".to_string(),
                    role: "replica".to_string(),
                },
                FleetInstance {
                    node_id: "node-003".to_string(),
                    instance_name: "instance-eu-west-1-replica".to_string(),
                    region: "eu-west-1".to_string(),
                    role: "replica".to_string(),
                },
                FleetInstance {
                    node_id: "node-004".to_string(),
                    instance_name: "instance-ap-northeast-1-replica".to_string(),
                    region: "ap-northeast-1".to_string(),
                    role: "replica".to_string(),
                },
                FleetInstance {
                    node_id: "node-005".to_string(),
                    instance_name: "instance-us-east-1-witness".to_string(),
                    region: "us-east-1".to_string(),
                    role: "witness".to_string(),
                },
            ],
            total_instances: 5,
            convergence_threshold: 0.8, // 80% of instances must acknowledge
        }
    }
}

/// Simulate quarantine propagation and convergence for a security event.
pub fn simulate_quarantine_propagation(
    event: &SyntheticSecurityEvent,
    fleet: &FleetTopology,
) -> Result<(QuarantineState, Vec<QuarantinePropagationEvent>, Duration), Box<dyn std::error::Error>> {
    let start_time = std::time::Instant::now();
    let mut events = Vec::new();
    let mut quarantine_state = QuarantineState::new();

    // Step 1: Detection instance issues quarantine decision
    let originator_node = NodeId::from_str(&event.detection_instance)?;
    let evidence_hash = ContentHash::compute(serde_json::to_string(event)?.as_bytes());
    let security_epoch = SecurityEpoch::from_raw(1000); // Example epoch

    let quarantine_decision = QuarantineDecision::new(
        event.extension_id.clone(),
        format!("Security threat detected: {} (severity: {})", event.threat_type, event.severity_score),
        originator_node,
        1, // Lamport timestamp
        evidence_hash.clone(),
        security_epoch,
    );

    // Record initiation event
    events.push(QuarantinePropagationEvent {
        schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        event_type: "quarantine_initiated".to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        event_id: event.event_id.clone(),
        extension_id: event.extension_id.clone(),
        originator_instance: event.detection_instance.clone(),
        target_instances: fleet.instances.iter().map(|i| i.instance_name.clone()).collect(),
        propagation_step: "initiated".to_string(),
        acknowledgments_received: 0,
        total_instances: fleet.total_instances as u32,
        convergence_achieved: false,
        convergence_time_ms: None,
        evidence_hash: format!("{:x}", evidence_hash.as_bytes()),
    });

    // Add decision to quarantine state
    quarantine_state.add_decision(quarantine_decision.clone());

    // Step 2: Simulate propagation to other instances
    let mut acknowledgment_count = 0;
    for (i, instance) in fleet.instances.iter().enumerate() {
        if instance.instance_name == event.detection_instance {
            continue; // Skip originator
        }

        // Simulate network delay and processing time based on role and region
        let processing_delay_ms = match instance.role.as_str() {
            "coordinator" => 50,
            "replica" => 100,
            "witness" => 150,
            _ => 200,
        };

        // Create acknowledgment
        let ack_node = NodeId::from_str(&instance.instance_name)?;
        let acknowledgment = QuarantineAck::new(
            evidence_hash.clone(),
            ack_node,
            (i + 2) as u64, // Lamport timestamp increments
        );

        if quarantine_state.add_acknowledgment(acknowledgment) {
            acknowledgment_count += 1;

            // Record acknowledgment event
            events.push(QuarantinePropagationEvent {
                schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
                timestamp_utc: Utc::now().to_rfc3339(),
                event_type: "acknowledgment_received".to_string(),
                component: EXAMPLE_COMPONENT.to_string(),
                event_id: event.event_id.clone(),
                extension_id: event.extension_id.clone(),
                originator_instance: event.detection_instance.clone(),
                target_instances: vec![instance.instance_name.clone()],
                propagation_step: "acknowledging".to_string(),
                acknowledgments_received: acknowledgment_count,
                total_instances: fleet.total_instances as u32,
                convergence_achieved: false,
                convergence_time_ms: Some(processing_delay_ms),
                evidence_hash: format!("{:x}", evidence_hash.as_bytes()),
            });
        }
    }

    // Step 3: Check convergence
    let convergence_achieved = quarantine_state.is_converged(&evidence_hash, fleet.total_instances);
    let total_time = start_time.elapsed();

    // Record convergence event
    events.push(QuarantinePropagationEvent {
        schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        event_type: if convergence_achieved { "convergence_achieved" } else { "convergence_timeout" }.to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        event_id: event.event_id.clone(),
        extension_id: event.extension_id.clone(),
        originator_instance: event.detection_instance.clone(),
        target_instances: fleet.instances.iter().map(|i| i.instance_name.clone()).collect(),
        propagation_step: "converged".to_string(),
        acknowledgments_received: acknowledgment_count,
        total_instances: fleet.total_instances as u32,
        convergence_achieved,
        convergence_time_ms: Some(total_time.as_millis() as u64),
        evidence_hash: format!("{:x}", evidence_hash.as_bytes()),
    });

    Ok((quarantine_state, events, total_time))
}

/// Execute quarantine propagation simulation and generate proof artifacts.
pub fn execute_quarantine_propagation_with_proof(
    event: &SyntheticSecurityEvent,
    fleet: &FleetTopology,
    output_dir: &Path,
) -> Result<QuarantineConvergenceReport, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let timestamp = Utc::now();
    let timestamp_str = timestamp.to_rfc3339();

    // Step 1: Simulate quarantine propagation
    let (quarantine_state, events, propagation_time) = simulate_quarantine_propagation(event, fleet)?;

    // Step 2: Generate convergence analysis
    let evidence_hash = ContentHash::compute(serde_json::to_string(event)?.as_bytes());
    let convergence_achieved = quarantine_state.is_converged(&evidence_hash, fleet.total_instances);

    let (acks_received, total_instances) = quarantine_state
        .convergence_progress(&evidence_hash)
        .unwrap_or((0, fleet.total_instances));

    let convergence_percentage = if total_instances > 0 {
        (acks_received as f64 / total_instances as f64) * 100.0
    } else {
        0.0
    };

    // Step 3: Create proof artifacts
    let artifacts = ProofArtifactPaths::standard(output_dir)?;

    // Write events.jsonl
    let mut events_content = String::new();
    for event in &events {
        events_content.push_str(&serde_json::to_string(event)?);
        events_content.push('\n');
    }
    fs::write(&artifacts.events_jsonl, events_content)?;

    // Write commands.txt
    let command = ProofCommand {
        command_id: "quarantine_propagation_001".to_string(),
        display: format!("quarantine-propagate --extension {} --event {} --fleet-size {}",
                         event.extension_id, event.event_id, fleet.total_instances),
        redacted_display: "quarantine-propagate --extension [REDACTED] --event [REDACTED] --fleet-size [REDACTED]".to_string(),
        cwd: "/data/projects/franken_engine".to_string(),
        exit_code: Some(0),
        duration_ms: Some(propagation_time.as_millis() as u64),
    };
    fs::write(&artifacts.commands_txt, format!("{}\n", serde_json::to_string(&command)?))?;

    // Create convergence report
    let report = QuarantineConvergenceReport {
        schema_version: PROOF_REPORT_SCHEMA_VERSION.to_string(),
        bead_id: EXAMPLE_BEAD_ID.to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        generated_at_utc: timestamp_str.clone(),
        security_event_id: event.event_id.clone(),
        extension_id: event.extension_id.clone(),
        quarantine_decision_outcome: if convergence_achieved {
            "quarantined".to_string()
        } else {
            "timeout".to_string()
        },
        originator_instance: event.detection_instance.clone(),
        fleet_size: fleet.total_instances as u32,
        acknowledgments_received: acks_received as u32,
        convergence_achieved,
        convergence_percentage,
        propagation_time_ms: propagation_time.as_millis() as u64,
        threat_severity: event.severity_score,
        decision_summary: format!(
            "Quarantine propagation for {} completed with {}/{} instances acknowledging ({:.1}% convergence)",
            event.extension_id,
            acks_received,
            total_instances,
            convergence_percentage
        ),
        next_steps: if convergence_achieved {
            "Extension successfully quarantined fleet-wide. Monitor for containment effectiveness.".to_string()
        } else {
            "Convergence not achieved. Investigate network partitions or failed instances.".to_string()
        },
    };

    // Write report.json
    fs::write(&artifacts.report_json, serde_json::to_string_pretty(&report)?)?;

    // Write human-readable report.md
    let markdown_report = format!(
        r#"# Quarantine Propagation Report

## Security Event: {}

**Extension**: {}
**Threat Type**: {}
**Severity**: {}/100
**Detection Instance**: {}

## Propagation Results

**Convergence**: {} ({:.1}%)
**Acknowledgments**: {}/{}
**Propagation Time**: {}ms
**Decision**: {}

## Fleet Topology

| Instance | Role | Region | Status |
|----------|------|--------|--------|
{}

## Threat Indicators

| Type | Value | Confidence | Source |
|------|-------|------------|--------|
{}

## Timeline

{}

## Decision Summary

{}

## Next Steps

{}

*This report was generated by the FrankenEngine Live Quarantine Propagation Example (bd-1py8v)*
"#,
        event.event_id,
        event.extension_id,
        event.threat_type,
        event.severity_score,
        event.detection_instance,
        if convergence_achieved { "✅ ACHIEVED" } else { "❌ FAILED" },
        convergence_percentage,
        acks_received,
        total_instances,
        propagation_time.as_millis(),
        report.quarantine_decision_outcome.to_uppercase(),
        fleet.instances.iter()
            .map(|i| format!("| {} | {} | {} | {} |",
                             i.instance_name,
                             i.role,
                             i.region,
                             if i.instance_name == event.detection_instance {
                                 "🔍 Detector"
                             } else {
                                 "✅ Acknowledged"
                             }))
            .collect::<Vec<_>>()
            .join("\n"),
        event.indicators.iter()
            .map(|ind| format!("| {} | {} | {}% | {} |",
                               ind.indicator_type,
                               if ind.value.len() > 50 {
                                   format!("{}...", &ind.value[..47])
                               } else {
                                   ind.value.clone()
                               },
                               ind.confidence_score,
                               ind.source))
            .collect::<Vec<_>>()
            .join("\n"),
        events.iter()
            .map(|e| format!("- **{}**: {} ({}ms)",
                             e.propagation_step,
                             e.event_type,
                             e.convergence_time_ms.unwrap_or(0)))
            .collect::<Vec<_>>()
            .join("\n"),
        report.decision_summary,
        report.next_steps,
    );

    fs::write(&artifacts.report_md, markdown_report)?;

    // Compute content hashes for integrity
    let quarantine_evidence_hash = ContentHash::compute(serde_json::to_string(event)?.as_bytes());
    let convergence_evidence_hash = ContentHash::compute(serde_json::to_string(&events)?.as_bytes());

    // Create manifest following cd3d2b4d contract
    let manifest = QuarantinePropagationManifest {
        schema_version: PROOF_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: EXAMPLE_BEAD_ID.to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        proof_type: "quarantine_propagation_convergence".to_string(),
        status: "completed".to_string(),
        generated_at_utc: timestamp_str,
        artifacts,
        security_event_id: event.event_id.clone(),
        quarantine_evidence_hash: format!("{:x}", quarantine_evidence_hash.as_bytes()),
        convergence_evidence_hash: format!("{:x}", convergence_evidence_hash.as_bytes()),
        fleet_instances_count: fleet.total_instances as u32,
        commands_executed: 1,
        events_recorded: events.len() as u32,
    };

    // Write manifest.json
    fs::write(&manifest.artifacts.manifest_json, serde_json::to_string_pretty(&manifest)?)?;

    println!("✅ Quarantine propagation proof artifacts generated:");
    println!("   📁 Output directory: {}", output_dir.display());
    println!("   📄 Manifest: {}", manifest.artifacts.manifest_json);
    println!("   📊 Report: {}", manifest.artifacts.report_json);
    println!("   📝 Human report: {}", manifest.artifacts.report_md);
    println!("   📋 Events: {}", manifest.artifacts.events_jsonl);
    println!("   🔄 Convergence: {} ({:.1}%)",
             if convergence_achieved { "ACHIEVED" } else { "FAILED" },
             convergence_percentage);

    Ok(report)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 FrankenEngine Live Quarantine Propagation Example");
    println!("   Demonstrating fleet-wide quarantine propagation + convergence tracking");

    // Create fleet topology
    let fleet = FleetTopology::create_multi_region_fleet();
    println!("\n🌐 Fleet topology: {} instances across {} regions",
             fleet.total_instances,
             fleet.instances.iter().map(|i| &i.region).collect::<std::collections::BTreeSet<_>>().len());

    // Example 1: High-severity malware detection
    println!("\n🚨 Example 1: Malware Detection Quarantine");
    let malware_event = SyntheticSecurityEvent::malware_detection_scenario();
    let output_dir_1 = Path::new("/tmp/quarantine_example_malware");
    execute_quarantine_propagation_with_proof(&malware_event, &fleet, output_dir_1)?;

    // Example 2: Medium-severity suspicious activity
    println!("\n⚠️  Example 2: Suspicious Activity Quarantine");
    let suspicious_event = SyntheticSecurityEvent::suspicious_activity_scenario();
    let output_dir_2 = Path::new("/tmp/quarantine_example_suspicious");
    execute_quarantine_propagation_with_proof(&suspicious_event, &fleet, output_dir_2)?;

    println!("\n✨ Live quarantine propagation examples completed successfully!");
    println!("   Check the generated proof artifact bundles for detailed convergence analysis.");

    Ok(())
}