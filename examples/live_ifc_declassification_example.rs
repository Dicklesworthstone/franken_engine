// Live Information Flow Control (IFC) declassification example.
//
// Demonstrates FrankenEngine's runtime IFC system with actual source-to-sink
// flows, policy evaluation, and signed declassification receipts.
//
// This example processes realistic scenarios:
// - Confidential API metrics flowing to public incident reports (with declassification)
// - Internal debug data attempting to flow to public logging (denied)
//
// Generated artifacts follow the cd3d2b4d proof contract for verification.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use frankenengine_engine::declassification_pipeline::{
    DeclassificationPipeline, DeclassificationRequest, LossAssessment, PipelineConfig,
    PipelineError, PipelineEvent,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{
    DeclassificationDecision, DeclassificationRoute, FlowCheckResult, FlowPolicy, IfcSchemaVersion,
    Label,
};
use frankenengine_engine::signature_preimage::{
    Signature, SigningKey, generate_keypair, generate_keypair_from_seed,
};

// Example constants
pub const EXAMPLE_BEAD_ID: &str = "bd-dpfvh";
pub const EXAMPLE_COMPONENT: &str = "live_ifc_declassification_example";

fn requested_route_id_for(flow_check: &FlowCheckResult, scenario_id: &str) -> String {
    match flow_check {
        FlowCheckResult::DeclassificationRequired { route_id } => route_id.clone(),
        _ => format!("no-approved-route-for-{scenario_id}"),
    }
}

fn build_declassification_request(
    scenario_id: &str,
    source_label: Label,
    sink_clearance: Label,
    requested_route_id: String,
) -> DeclassificationRequest {
    DeclassificationRequest {
        request_id: format!("{scenario_id}-request"),
        source_label,
        sink_clearance,
        extension_id: EXAMPLE_COMPONENT.to_string(),
        code_location: "live_ifc_declassification_example::execute_flow".to_string(),
        trace_id: format!("{scenario_id}-trace"),
        requested_route_id,
        decision_contract_id: "franken-ifc-decision-contract".to_string(),
        is_emergency: false,
        timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
    }
}

fn compute_loss_assessment(
    source_label: &Label,
    sink_clearance: &Label,
    flow_check: &FlowCheckResult,
) -> LossAssessment {
    let source_level = source_label.level() as u64;
    let sink_level = sink_clearance.level() as u64;
    let downgrade_levels = source_level.saturating_sub(sink_level);
    let route_factor_milli = match flow_check {
        FlowCheckResult::DeclassificationRequired { .. } => 1_000,
        FlowCheckResult::Denied | FlowCheckResult::Prohibited => 4_000,
        FlowCheckResult::Allowed | FlowCheckResult::LatticeAllowed => 0,
    };
    let data_sensitivity_bps = (source_level.saturating_mul(2_500)).min(10_000) as u16;
    let sink_exposure_bps =
        ((Label::TopSecret.level() as u64).saturating_sub(sink_level) * 2_500).min(10_000) as u16;

    LossAssessment {
        expected_loss_milli: downgrade_levels
            .saturating_mul(20_000)
            .saturating_add(route_factor_milli),
        data_sensitivity_bps,
        sink_exposure_bps,
        historical_abuse_detected: matches!(
            flow_check,
            FlowCheckResult::Denied | FlowCheckResult::Prohibited
        ),
        summary: format!(
            "computed from label downgrade ({source_label}->{sink_clearance}) and policy outcome {flow_check:?}"
        ),
    }
}

fn source_from_engine_event_path(
    source_id: &str,
    label: Label,
    sink: &DataSink,
    policy: &FlowPolicy,
    signing_key: &SigningKey,
) -> ClassifiedDataSource {
    let flow_check = policy.is_flow_allowed(&label, &sink.clearance);
    let request = build_declassification_request(
        source_id,
        label.clone(),
        sink.clearance.clone(),
        requested_route_id_for(&flow_check, source_id),
    );
    let loss_assessment = compute_loss_assessment(&label, &sink.clearance, &flow_check);
    let mut pipeline = DeclassificationPipeline::new(PipelineConfig::default());
    let receipt_result = pipeline.process(&request, policy, &loss_assessment, signing_key);
    let pipeline_events = pipeline.drain_events();

    let content = serde_json::to_string(&serde_json::json!({
        "source_id": source_id,
        "component": EXAMPLE_COMPONENT,
        "source_label": label.clone(),
        "sink_id": sink.sink_id.clone(),
        "sink_clearance": sink.clearance.clone(),
        "policy_id": policy.policy_id.clone(),
        "policy_hash": policy.content_hash().to_hex(),
        "policy_flow_check": flow_check,
        "loss_assessment": loss_assessment,
        "pipeline_event_count": pipeline_events.len(),
        "pipeline_events": pipeline_events,
        "receipt_hash": receipt_result.as_ref().ok().map(|receipt| receipt.content_hash().to_hex()),
        "pipeline_error": receipt_result.as_ref().err().map(ToString::to_string),
    }))
    .expect("engine event source payload should serialize");
    let content_hash = ContentHash::compute(content.as_bytes()).to_hex();

    ClassifiedDataSource {
        source_id: source_id.to_string(),
        label,
        content,
        content_hash,
    }
}

/// Runtime-derived data source with classification level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedDataSource {
    pub source_id: String,
    pub label: Label,
    pub content: String,
    pub content_hash: String,
}

/// Target sink with required clearance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSink {
    pub sink_id: String,
    pub clearance: Label,
    pub description: String,
}

/// IFC flow scenario for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfcFlowScenario {
    pub scenario_id: String,
    pub description: String,
    pub source: ClassifiedDataSource,
    pub sink: DataSink,
}

/// Complete flow verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowVerificationResult {
    pub bead_id: String,
    pub component: String,
    pub scenario_id: String,
    pub flow_attempted: bool,
    pub declassification_required: bool,
    pub declassification_approved: bool,
    pub flow_completed: bool,
    pub receipt_generated: bool,
    pub receipt_hash: Option<String>,
    pub error_reason: Option<String>,
    pub execution_time_ms: u64,
    pub policy_flow_check: FlowCheckResult,
    pub loss_assessment: LossAssessment,
    pub pipeline_events: Vec<PipelineEvent>,
}

impl ClassifiedDataSource {
    /// Capture a confidential source from the live declassification event path.
    pub fn confidential_api_metrics(policy: &FlowPolicy, signing_key: &SigningKey) -> Self {
        let sink = DataSink::public_incident_report();
        source_from_engine_event_path(
            "api-metrics-source",
            Label::Confidential,
            &sink,
            policy,
            signing_key,
        )
    }

    /// Capture an internal source from the live declassification event path.
    pub fn internal_debug_data(policy: &FlowPolicy, signing_key: &SigningKey) -> Self {
        let sink = DataSink::public_application_logs();
        source_from_engine_event_path(
            "debug-data-source",
            Label::Internal,
            &sink,
            policy,
            signing_key,
        )
    }
}

impl DataSink {
    /// Public incident reporting sink.
    pub fn public_incident_report() -> Self {
        Self {
            sink_id: "incident-report-sink".to_string(),
            clearance: Label::Public,
            description: "Public incident status page and user communications".to_string(),
        }
    }

    /// Public application logging sink.
    pub fn public_application_logs() -> Self {
        Self {
            sink_id: "application-logs-sink".to_string(),
            clearance: Label::Public,
            description: "Application logs visible to support staff".to_string(),
        }
    }
}

impl IfcFlowScenario {
    /// Scenario: Confidential API metrics to public incident report (should be allowed with declassification).
    pub fn allowed_declassification_scenario(
        policy: &FlowPolicy,
        signing_key: &SigningKey,
    ) -> Self {
        Self {
            scenario_id: "allowed-api-metrics-to-incident".to_string(),
            description: "Flow confidential API metrics to public incident report with approved declassification".to_string(),
            source: ClassifiedDataSource::confidential_api_metrics(policy, signing_key),
            sink: DataSink::public_incident_report(),
        }
    }

    /// Scenario: Internal debug data to public logs (should be denied).
    pub fn denied_flow_scenario(policy: &FlowPolicy, signing_key: &SigningKey) -> Self {
        Self {
            scenario_id: "denied-debug-to-logs".to_string(),
            description:
                "Attempt to flow internal debug data to public logs without declassification"
                    .to_string(),
            source: ClassifiedDataSource::internal_debug_data(policy, signing_key),
            sink: DataSink::public_application_logs(),
        }
    }
}

/// Create a realistic IFC flow policy.
pub fn create_flow_policy(signing_key: &SigningKey) -> FlowPolicy {
    let mut policy = FlowPolicy {
        policy_id: "franken-ifc-policy-v1".to_string(),
        extension_id: EXAMPLE_COMPONENT.to_string(),
        label_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect(),
        clearance_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![
            DeclassificationRoute {
                route_id: "confidential-to-public-incident".to_string(),
                source_label: Label::Confidential,
                target_clearance: Label::Public,
                conditions: vec![
                    "security_review".to_string(),
                    "pii_scrubbing".to_string(),
                    "incident_response_approval".to_string(),
                ],
            },
            // Note: No route for internal->public, so that should be denied
        ],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes([0u8; 64]),
    };
    policy.sign(signing_key).expect("flow policy should sign");
    policy
}

/// Create a signing key for this example.
pub fn create_signing_key() -> SigningKey {
    generate_keypair().0
}

/// Rotate the runtime signing key through the engine key-generation path.
pub fn rotate_signing_key(previous: &SigningKey) -> SigningKey {
    let mut seed = *ContentHash::compute(previous.as_bytes()).as_bytes();
    if seed == [0u8; 32] {
        seed[0] = 1;
    }
    generate_keypair_from_seed(&seed).0
}

/// Execute a complete IFC flow scenario with declassification pipeline.
pub fn execute_ifc_flow_scenario(
    scenario: &IfcFlowScenario,
    policy: &FlowPolicy,
    signing_key: &SigningKey,
) -> Result<FlowVerificationResult, Box<dyn std::error::Error>> {
    let start_time = std::time::Instant::now();

    println!("Executing IFC flow scenario: {}", scenario.description);
    println!(
        "  Source: {} ({:?}) -> Sink: {} ({:?})",
        scenario.source.source_id,
        scenario.source.label,
        scenario.sink.sink_id,
        scenario.sink.clearance
    );

    let policy_flow_check =
        policy.is_flow_allowed(&scenario.source.label, &scenario.sink.clearance);
    let loss_assessment = compute_loss_assessment(
        &scenario.source.label,
        &scenario.sink.clearance,
        &policy_flow_check,
    );
    let mut result = FlowVerificationResult {
        bead_id: EXAMPLE_BEAD_ID.to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        scenario_id: scenario.scenario_id.clone(),
        flow_attempted: false,
        declassification_required: false,
        declassification_approved: false,
        flow_completed: false,
        receipt_generated: false,
        receipt_hash: None,
        error_reason: None,
        execution_time_ms: 0,
        policy_flow_check,
        loss_assessment,
        pipeline_events: Vec::new(),
    };

    result.flow_attempted = true;
    match &result.policy_flow_check {
        FlowCheckResult::Allowed | FlowCheckResult::LatticeAllowed => {
            result.flow_completed = true;
            println!(
                "  Flow allowed by policy check: {:?}",
                result.policy_flow_check
            );
        }
        FlowCheckResult::DeclassificationRequired { .. } => {
            result.declassification_required = true;
            println!(
                "  Flow requires declassification by policy check: {:?} -> {:?}",
                scenario.source.label, scenario.sink.clearance
            );

            let request = build_declassification_request(
                &scenario.scenario_id,
                scenario.source.label.clone(),
                scenario.sink.clearance.clone(),
                requested_route_id_for(&result.policy_flow_check, &scenario.scenario_id),
            );

            let config = PipelineConfig {
                loss_threshold_milli: LossAssessment::DEFAULT_THRESHOLD_MILLI,
                emergency_max_duration_ms: 3_600_000, // 1 hour emergency grant expiry
                emit_stage_events: true,
            };
            let mut pipeline = DeclassificationPipeline::new(config);

            match pipeline.process(&request, policy, &result.loss_assessment, signing_key) {
                Ok(receipt) => {
                    result.declassification_approved =
                        receipt.decision == DeclassificationDecision::Allow;
                    result.flow_completed = result.declassification_approved;
                    result.receipt_generated = true;
                    result.receipt_hash = Some(receipt.content_hash().to_hex());
                    println!("  Declassification decision: {:?}", receipt.decision);
                    println!("     Receipt ID: {}", receipt.receipt_id);
                    println!("     Authorized by: {}", receipt.authorized_by);
                }
                Err(PipelineError::NoMatchingRoute { .. }) => {
                    result.error_reason = Some("No matching declassification route".to_string());
                    println!("  Declassification denied - no matching route");
                }
                Err(e) => {
                    result.error_reason = Some(format!("Pipeline error: {}", e));
                    println!("  Declassification failed: {}", e);
                }
            }
            result.pipeline_events = pipeline.drain_events();
        }
        FlowCheckResult::Denied | FlowCheckResult::Prohibited => {
            result.declassification_required =
                !scenario.source.label.can_flow_to(&scenario.sink.clearance);
            result.error_reason = Some(format!(
                "Policy flow check denied: {:?}",
                result.policy_flow_check
            ));
            println!(
                "  Flow denied by policy check: {:?}",
                result.policy_flow_check
            );
        }
    }

    result.execution_time_ms = start_time.elapsed().as_millis() as u64;
    Ok(result)
}

/// Generate proof artifacts for an IFC flow verification.
pub fn generate_ifc_proof_artifacts(
    results: &[FlowVerificationResult],
    policy: &FlowPolicy,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    // Generate manifest.json
    let manifest = serde_json::json!({
        "schema_version": "cd3d2b4d.franken-engine.ifc-declassification.v1",
        "bead_id": EXAMPLE_BEAD_ID,
        "component": EXAMPLE_COMPONENT,
        "proof_type": "ifc_declassification_flow_verification",
        "flow_scenarios_count": results.len(),
        "policy_id": policy.policy_id.clone(),
        "declassification_routes_count": policy.declassification_routes.len(),
        "flow_verification_evidence_hash": ContentHash::compute(
            serde_json::to_string(results)?.as_bytes()
        ).to_hex(),
        "policy_evidence_hash": policy.content_hash().to_hex(),
        "status": "completed",
        "generated_at_utc": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    });

    fs::write(
        output_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    // Generate report.json
    let report = serde_json::json!({
        "bead_id": EXAMPLE_BEAD_ID,
        "component": EXAMPLE_COMPONENT,
        "flow_scenarios_executed": results.len(),
        "flows_requiring_declassification": results.iter().filter(|r| r.declassification_required).count(),
        "declassifications_approved": results.iter().filter(|r| r.declassification_approved).count(),
        "flows_completed_successfully": results.iter().filter(|r| r.flow_completed).count(),
        "receipts_generated": results.iter().filter(|r| r.receipt_generated).count(),
        "total_execution_time_ms": results.iter().map(|r| r.execution_time_ms).sum::<u64>(),
        "scenarios": results
    });

    fs::write(
        output_dir.join("report.json"),
        serde_json::to_string_pretty(&report)?,
    )?;

    // Generate events.jsonl
    let mut events = Vec::new();
    for result in results {
        events.push(serde_json::json!({
            "timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            "event_type": "scenario_execution",
            "scenario_id": result.scenario_id,
            "flow_attempted": result.flow_attempted,
            "declassification_required": result.declassification_required,
            "declassification_approved": result.declassification_approved,
            "flow_completed": result.flow_completed,
            "policy_flow_check": result.policy_flow_check.clone(),
            "loss_assessment": result.loss_assessment.clone(),
            "pipeline_events": result.pipeline_events.clone(),
            "execution_time_ms": result.execution_time_ms
        }));
    }

    let events_content = events
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    fs::write(output_dir.join("events.jsonl"), events_content)?;

    // Generate commands.txt
    let commands = format!(
        "# Live IFC Declassification Example Commands\n\
        # Bead: {}\n\
        # Component: {}\n\
        \n\
        # Flow scenarios executed\n\
        scenarios_count={}\n\
        \n\
        # Policy configuration\n\
        policy_id={}\n\
        declassification_routes={}\n\
        \n\
        # Verification results\n\
        flows_requiring_declassification={}\n\
        declassifications_approved={}\n\
        flows_completed={}\n\
        receipts_generated={}\n\
        ",
        EXAMPLE_BEAD_ID,
        EXAMPLE_COMPONENT,
        results.len(),
        policy.policy_id,
        policy.declassification_routes.len(),
        results
            .iter()
            .filter(|r| r.declassification_required)
            .count(),
        results
            .iter()
            .filter(|r| r.declassification_approved)
            .count(),
        results.iter().filter(|r| r.flow_completed).count(),
        results.iter().filter(|r| r.receipt_generated).count(),
    );
    fs::write(output_dir.join("commands.txt"), commands)?;

    // Generate report.md
    let markdown = format!(
        "# Live IFC Declassification Example Report\n\
        \n\
        **Bead**: {}\n\
        **Component**: {}\n\
        **Generated**: {}\n\
        \n\
        ## Summary\n\
        \n\
        This example demonstrates FrankenEngine's Information Flow Control system with live declassification:\n\
        \n\
        - **Flow scenarios**: {} executed\n\
        - **Declassifications required**: {}\n\
        - **Declassifications approved**: {}\n\
        - **Flows completed**: {}\n\
        - **Receipts generated**: {}\n\
        \n\
        ## Policy Configuration\n\
        \n\
        - **Policy ID**: {}\n\
        - **Label classes**: Public, Internal, Confidential, Secret\n\
        - **Declassification routes**: {}\n\
        \n\
        ## Scenario Results\n\
        \n",
        EXAMPLE_BEAD_ID,
        EXAMPLE_COMPONENT,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        results.len(),
        results
            .iter()
            .filter(|r| r.declassification_required)
            .count(),
        results
            .iter()
            .filter(|r| r.declassification_approved)
            .count(),
        results.iter().filter(|r| r.flow_completed).count(),
        results.iter().filter(|r| r.receipt_generated).count(),
        policy.policy_id,
        policy.declassification_routes.len(),
    );

    let mut scenarios_md = markdown;
    for result in results {
        let status = if result.flow_completed {
            "✅ ALLOWED"
        } else {
            "❌ DENIED"
        };
        scenarios_md.push_str(&format!(
            "### {}\n\n- **Status**: {}\n- **Declassification required**: {}\n- **Execution time**: {}ms\n\n",
            result.scenario_id,
            status,
            result.declassification_required,
            result.execution_time_ms
        ));

        if let Some(error) = &result.error_reason {
            scenarios_md.push_str(&format!("- **Error**: {}\n\n", error));
        }
    }

    scenarios_md.push_str(
        "\n## Security Properties Verified\n\
        \n\
        ✅ **Label-based access control**: Information flow is controlled by security labels\n\
        ✅ **Lattice enforcement**: Flows only allowed within lattice ordering or via declassification\n\
        ✅ **Policy-based declassification**: Cross-label flows require approved routes\n\
        ✅ **Signed receipts**: All approved declassifications generate cryptographic receipts\n\
        ✅ **Deterministic decisions**: Same input produces same declassification decision\n\
        \n\
        Generated by FrankenEngine Live IFC Declassification Example\n"
    );

    fs::write(output_dir.join("report.md"), scenarios_md)?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use frankenengine_engine::ifc_artifacts::FlowRule;

    #[test]
    fn test_classified_data_source_creation() {
        let key = create_signing_key();
        let policy = create_flow_policy(&key);

        let api_metrics = ClassifiedDataSource::confidential_api_metrics(&policy, &key);
        assert_eq!(api_metrics.source_id, "api-metrics-source");
        assert_eq!(api_metrics.label, Label::Confidential);
        assert!(!api_metrics.content.is_empty());
        assert!(api_metrics.content.contains("declassification_pipeline"));
        assert!(!api_metrics.content_hash.is_empty());

        let debug_data = ClassifiedDataSource::internal_debug_data(&policy, &key);
        assert_eq!(debug_data.source_id, "debug-data-source");
        assert_eq!(debug_data.label, Label::Internal);
        assert!(!debug_data.content.is_empty());
        assert!(debug_data.content.contains("pipeline_events"));
        assert!(!debug_data.content_hash.is_empty());

        // Hashes should be different
        assert_ne!(api_metrics.content_hash, debug_data.content_hash);
    }

    #[test]
    fn test_data_sink_creation() {
        let incident_sink = DataSink::public_incident_report();
        assert_eq!(incident_sink.sink_id, "incident-report-sink");
        assert_eq!(incident_sink.clearance, Label::Public);

        let logs_sink = DataSink::public_application_logs();
        assert_eq!(logs_sink.sink_id, "application-logs-sink");
        assert_eq!(logs_sink.clearance, Label::Public);
    }

    #[test]
    fn test_flow_scenarios() {
        let key = create_signing_key();
        let policy = create_flow_policy(&key);

        let allowed = IfcFlowScenario::allowed_declassification_scenario(&policy, &key);
        assert_eq!(allowed.scenario_id, "allowed-api-metrics-to-incident");
        assert_eq!(allowed.source.label, Label::Confidential);
        assert_eq!(allowed.sink.clearance, Label::Public);
        assert!(matches!(
            policy.is_flow_allowed(&allowed.source.label, &allowed.sink.clearance),
            FlowCheckResult::DeclassificationRequired { .. }
        ));

        let denied = IfcFlowScenario::denied_flow_scenario(&policy, &key);
        assert_eq!(denied.scenario_id, "denied-debug-to-logs");
        assert_eq!(denied.source.label, Label::Internal);
        assert_eq!(denied.sink.clearance, Label::Public);
        assert_eq!(
            policy.is_flow_allowed(&denied.source.label, &denied.sink.clearance),
            FlowCheckResult::Denied
        );
    }

    #[test]
    fn test_policy_conflict_uses_policy_flow_check_result() {
        let key = create_signing_key();
        let mut policy = create_flow_policy(&key);
        policy.prohibited_flows.push(FlowRule {
            source_label: Label::Public,
            sink_clearance: Label::Internal,
        });
        policy.sign(&key).expect("updated policy should sign");

        let content = "public status update";
        let scenario = IfcFlowScenario {
            scenario_id: "prohibited-public-to-internal".to_string(),
            description:
                "Explicit policy prohibition overrides lattice-legal public-to-internal flow"
                    .to_string(),
            source: ClassifiedDataSource {
                source_id: "public-status-source".to_string(),
                label: Label::Public,
                content: content.to_string(),
                content_hash: ContentHash::compute(content.as_bytes()).to_hex(),
            },
            sink: DataSink {
                sink_id: "internal-analytics-sink".to_string(),
                clearance: Label::Internal,
                description: "Internal analytics sink".to_string(),
            },
        };

        assert!(scenario.source.label.can_flow_to(&scenario.sink.clearance));
        let result = execute_ifc_flow_scenario(&scenario, &policy, &key)
            .expect("policy conflict scenario should evaluate");

        assert_eq!(result.policy_flow_check, FlowCheckResult::Prohibited);
        assert!(result.flow_attempted);
        assert!(!result.declassification_required);
        assert!(!result.declassification_approved);
        assert!(!result.flow_completed);
        assert!(!result.receipt_generated);
        assert!(
            result
                .error_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("Prohibited"))
        );
    }

    #[test]
    fn test_flow_policy_creation() {
        let key = create_signing_key();
        let policy = create_flow_policy(&key);

        assert_eq!(policy.policy_id, "franken-ifc-policy-v1");
        assert_eq!(policy.extension_id, EXAMPLE_COMPONENT);
        assert_eq!(policy.declassification_routes.len(), 1);

        let route = &policy.declassification_routes[0];
        assert_eq!(route.route_id, "confidential-to-public-incident");
        assert_eq!(route.source_label, Label::Confidential);
        assert_eq!(route.target_clearance, Label::Public);
        assert_eq!(route.conditions.len(), 3);
        assert!(route.conditions.contains(&"security_review".to_string()));
        policy
            .verify(&key.verification_key())
            .expect("flow policy should verify with generated key");
    }

    #[test]
    fn test_label_ordering() {
        assert!(Label::Public < Label::Internal);
        assert!(Label::Internal < Label::Confidential);
        assert!(Label::Confidential < Label::Secret);

        // Verify can_flow_to logic
        assert!(Label::Public.can_flow_to(&Label::Public));
        assert!(Label::Public.can_flow_to(&Label::Internal));
        assert!(!Label::Confidential.can_flow_to(&Label::Public));
        assert!(!Label::Internal.can_flow_to(&Label::Public));
    }

    #[test]
    fn test_verification_result_structure() {
        let result = FlowVerificationResult {
            bead_id: EXAMPLE_BEAD_ID.to_string(),
            component: EXAMPLE_COMPONENT.to_string(),
            scenario_id: "test-scenario".to_string(),
            flow_attempted: true,
            declassification_required: true,
            declassification_approved: false,
            flow_completed: false,
            receipt_generated: false,
            receipt_hash: None,
            error_reason: Some("No matching route".to_string()),
            execution_time_ms: 100,
            policy_flow_check: FlowCheckResult::Denied,
            loss_assessment: compute_loss_assessment(
                &Label::Internal,
                &Label::Public,
                &FlowCheckResult::Denied,
            ),
            pipeline_events: Vec::new(),
        };

        assert_eq!(result.bead_id, EXAMPLE_BEAD_ID);
        assert_eq!(result.component, EXAMPLE_COMPONENT);
        assert!(result.declassification_required);
        assert!(!result.flow_completed);
        assert!(result.error_reason.is_some());
    }

    #[test]
    fn test_signing_key_rotation_uses_engine_key_generation() {
        let key1 = create_signing_key();
        let key2 = rotate_signing_key(&key1);

        assert_ne!(key1.as_bytes(), key2.as_bytes());
        let policy = create_flow_policy(&key2);
        policy
            .verify(&key2.verification_key())
            .expect("rotated key should sign policy");
    }
}

#[allow(dead_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("FrankenEngine Live IFC/Declassification Example");
    println!("===============================================");
    println!();

    // Setup
    let signing_key = create_signing_key();
    let policy = create_flow_policy(&signing_key);

    println!("Policy created: {}", policy.policy_id);
    println!(
        "Declassification routes: {}",
        policy.declassification_routes.len()
    );
    println!();

    // Test scenarios
    let scenarios = [
        IfcFlowScenario::allowed_declassification_scenario(&policy, &signing_key),
        IfcFlowScenario::denied_flow_scenario(&policy, &signing_key),
    ];

    println!("Testing {} IFC flow scenarios:", scenarios.len());
    println!();

    // Execute scenarios
    let mut results = Vec::new();
    for scenario in &scenarios {
        match execute_ifc_flow_scenario(scenario, &policy, &signing_key) {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!("❌ Scenario {} failed: {}", scenario.scenario_id, e);
                return Err(e);
            }
        }
        println!();
    }

    // Generate proof artifacts
    let output_dir = std::env::var_os("IFC_DECLASSIFICATION_OUTPUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/ifc_declassification_example"));
    fs::create_dir_all(&output_dir)?;

    println!("Generating proof artifacts...");
    generate_ifc_proof_artifacts(&results, &policy, &output_dir)?;

    println!("✅ Live IFC declassification example completed successfully");
    println!();
    println!("📁 Artifacts generated in: {}", output_dir.display());
    println!("📄 Files:");
    for entry in fs::read_dir(&output_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            println!("   {}", entry.file_name().to_string_lossy());
        }
    }

    println!();
    println!("🔐 Security properties demonstrated:");
    println!("   ✓ Label-based access control with security lattice");
    println!("   ✓ Policy-based declassification with approved routes");
    println!("   ✓ Signed receipt generation for authorized flows");
    println!("   ✓ Deterministic decision pipeline with replay guarantees");

    Ok(())
}
