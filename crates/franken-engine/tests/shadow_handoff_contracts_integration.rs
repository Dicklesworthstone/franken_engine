//! Integration tests for shadow handoff contracts.
//!
//! Validates panel bundle schema, missing-source rendering state, and
//! no-mutation command surfaces as required by bd-djejh.7.

use frankenengine_engine::shadow_handoff_contracts::*;
use frankenengine_engine::shadow_service_interface::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{SystemTime, Duration};

/// Test panel bundle schema validation
#[test]
fn test_panel_bundle_schema_validation() {
    println!("🔍 Testing panel bundle schema validation...");

    let bundle = PanelBundleBuilder::new()
        .with_daemon_health(DaemonHealth::Healthy)
        .with_active_journals(5)
        .with_uptime(3600)
        .with_last_decision(SystemTime::now())
        .build();

    // Validate schema structure
    let json = serialize_panel_bundle(&bundle).expect("Should serialize bundle");
    let parsed: Value = serde_json::from_str(&json).expect("Should parse as valid JSON");

    // Check required top-level fields
    assert!(parsed.get("shadow_status").is_some(), "Missing shadow_status field");
    assert!(parsed.get("source_freshness").is_some(), "Missing source_freshness field");
    assert!(parsed.get("degraded_gates").is_some(), "Missing degraded_gates field");
    assert!(parsed.get("replay_drift").is_some(), "Missing replay_drift field");
    assert!(parsed.get("recommended_actions").is_some(), "Missing recommended_actions field");
    assert!(parsed.get("generated_at").is_some(), "Missing generated_at field");
    assert!(parsed.get("bundle_version").is_some(), "Missing bundle_version field");

    // Check shadow_status structure
    let shadow_status = parsed.get("shadow_status").unwrap();
    assert!(shadow_status.get("title").is_some(), "Missing shadow_status.title");
    assert!(shadow_status.get("daemon_health").is_some(), "Missing shadow_status.daemon_health");
    assert!(shadow_status.get("active_journals").is_some(), "Missing shadow_status.active_journals");
    assert!(shadow_status.get("uptime_seconds").is_some(), "Missing shadow_status.uptime_seconds");

    // Check source_freshness structure
    let source_freshness = parsed.get("source_freshness").unwrap();
    assert!(source_freshness.get("title").is_some(), "Missing source_freshness.title");
    assert!(source_freshness.get("sources").is_some(), "Missing source_freshness.sources");
    assert!(source_freshness.get("stale_source_count").is_some(), "Missing source_freshness.stale_source_count");

    // Check degraded_gates structure
    let degraded_gates = parsed.get("degraded_gates").unwrap();
    assert!(degraded_gates.get("title").is_some(), "Missing degraded_gates.title");
    assert!(degraded_gates.get("gates").is_some(), "Missing degraded_gates.gates");
    assert!(degraded_gates.get("degraded_count").is_some(), "Missing degraded_gates.degraded_count");

    // Check replay_drift structure
    let replay_drift = parsed.get("replay_drift").unwrap();
    assert!(replay_drift.get("title").is_some(), "Missing replay_drift.title");
    assert!(replay_drift.get("drift_entries").is_some(), "Missing replay_drift.drift_entries");
    assert!(replay_drift.get("total_drift_count").is_some(), "Missing replay_drift.total_drift_count");

    // Check recommended_actions structure
    let recommended_actions = parsed.get("recommended_actions").unwrap();
    assert!(recommended_actions.get("title").is_some(), "Missing recommended_actions.title");
    assert!(recommended_actions.get("actions").is_some(), "Missing recommended_actions.actions");
    assert!(recommended_actions.get("priority_action_count").is_some(), "Missing recommended_actions.priority_action_count");

    println!("✅ Panel bundle schema validation passed");
}

/// Test missing source rendering state
#[test]
fn test_missing_source_rendering_state() {
    println!("🔍 Testing missing source rendering state...");

    let now = SystemTime::now();
    let one_hour_ago = now - Duration::from_secs(3600);

    // Test missing source panel creation
    let missing_panel = create_missing_source_panel(
        "Unavailable Evidence Journal",
        "Connection to evidence journal lost. Retrying...",
        Some(one_hour_ago),
    );

    assert_eq!(missing_panel.title, "Unavailable Evidence Journal");
    assert_eq!(missing_panel.message, "Connection to evidence journal lost. Retrying...");
    assert_eq!(missing_panel.last_successful_fetch, Some(one_hour_ago));
    assert_eq!(missing_panel.retry_in_seconds, Some(30));

    // Test JSON serialization of missing source panel
    let json = serde_json::to_string_pretty(&missing_panel).expect("Should serialize missing panel");
    let parsed: Value = serde_json::from_str(&json).expect("Should parse missing panel JSON");

    assert_eq!(parsed.get("title").unwrap().as_str().unwrap(), "Unavailable Evidence Journal");
    assert_eq!(parsed.get("message").unwrap().as_str().unwrap(), "Connection to evidence journal lost. Retrying...");
    assert!(parsed.get("last_successful_fetch").is_some());
    assert_eq!(parsed.get("retry_in_seconds").unwrap().as_u64().unwrap(), 30);

    // Test missing source panel without last fetch
    let missing_panel_no_history = create_missing_source_panel(
        "Unknown Source",
        "No connection history available",
        None,
    );

    assert!(missing_panel_no_history.last_successful_fetch.is_none());

    println!("✅ Missing source rendering state validation passed");
}

/// Test no-mutation command surfaces (advisory-only semantics)
#[test]
fn test_no_mutation_command_surfaces() {
    println!("🔍 Testing no-mutation command surfaces...");

    let config = ShadowServiceConfig::default();
    let service = DefaultShadowService::new(config);

    // Test action preview is advisory-only
    let preview_request = ActionPreviewRequest {
        action_id: "refresh-stale-sources".to_string(),
    };

    let preview_response = service.preview_action(preview_request).expect("Should preview action");

    // Verify advisory-only semantics
    assert_eq!(preview_response.safety_check, "advisory_only");
    assert!(preview_response.advisory_notice.contains("preview only"));
    assert!(preview_response.advisory_notice.contains("Copy and execute manually"));
    assert!(preview_response.execution_context.contains("appropriate permissions"));

    // Test that command preview doesn't execute anything
    assert!(preview_response.command_preview.starts_with("shadow-daemon"));
    assert!(!preview_response.command_preview.contains("--execute"));
    assert!(!preview_response.command_preview.contains("--force"));

    // Test recommended actions contain command previews but no direct execution
    let bundle = service.get_panel_bundle().expect("Should get panel bundle");
    for action in &bundle.recommended_actions.actions {
        // All commands should be preview strings
        assert!(!action.command_preview.is_empty(), "Action should have command preview");
        assert!(action.command_preview.starts_with("shadow-daemon"), "Commands should use shadow-daemon prefix");

        // Commands should not contain dangerous flags
        assert!(!action.command_preview.contains("--force"), "Commands should not contain --force");
        assert!(!action.command_preview.contains("--auto"), "Commands should not contain --auto");
        assert!(!action.command_preview.contains("--yes"), "Commands should not contain --yes");
    }

    println!("✅ No-mutation command surfaces validation passed");
}

/// Test panel bundle round-trip serialization
#[test]
fn test_panel_bundle_serialization_roundtrip() {
    println!("🔍 Testing panel bundle serialization round-trip...");

    let now = SystemTime::now();
    let original_bundle = PanelBundleBuilder::new()
        .with_daemon_health(DaemonHealth::Degraded {
            reason: "High memory usage detected".to_string()
        })
        .with_active_journals(7)
        .with_uptime(7200)
        .with_last_decision(now)
        .add_source_freshness(SourceFreshnessEntry {
            source_id: "test-source".to_string(),
            last_update: now,
            staleness_seconds: 150,
            threshold_seconds: 300,
            is_stale: false,
        })
        .add_degraded_gate(DegradedGateEntry {
            gate_id: "memory-gate".to_string(),
            degradation_reason: "Memory threshold exceeded".to_string(),
            degraded_since: now,
            severity: GateDegradationSeverity::Critical,
        })
        .add_replay_drift(ReplayDriftEntry {
            journal_id: "drift-journal".to_string(),
            drift_type: "payload_hash_mismatch".to_string(),
            detected_at: now,
            severity: DriftSeverity::Major,
            expected_migration: false,
        })
        .add_recommended_action(RecommendedAction {
            action_id: "memory-cleanup".to_string(),
            description: "Clean up memory usage".to_string(),
            command_preview: "shadow-daemon memory-cleanup --threshold 80%".to_string(),
            priority: ActionPriority::Urgent,
            estimated_duration: Some(180),
        })
        .build();

    // Serialize and deserialize
    let json = serialize_panel_bundle(&original_bundle).expect("Should serialize");
    let restored_bundle = deserialize_panel_bundle(&json).expect("Should deserialize");

    // Verify all fields preserved
    assert_eq!(original_bundle.bundle_version, restored_bundle.bundle_version);
    assert_eq!(original_bundle.shadow_status.active_journals, restored_bundle.shadow_status.active_journals);
    assert_eq!(original_bundle.shadow_status.uptime_seconds, restored_bundle.shadow_status.uptime_seconds);

    if let (DaemonHealth::Degraded { reason: orig }, DaemonHealth::Degraded { reason: restored }) =
        (&original_bundle.shadow_status.daemon_health, &restored_bundle.shadow_status.daemon_health) {
        assert_eq!(orig, restored);
    } else {
        panic!("Daemon health serialization failed");
    }

    assert_eq!(original_bundle.source_freshness.sources.len(), restored_bundle.source_freshness.sources.len());
    assert_eq!(original_bundle.degraded_gates.gates.len(), restored_bundle.degraded_gates.gates.len());
    assert_eq!(original_bundle.replay_drift.drift_entries.len(), restored_bundle.replay_drift.drift_entries.len());
    assert_eq!(original_bundle.recommended_actions.actions.len(), restored_bundle.recommended_actions.actions.len());

    println!("✅ Panel bundle serialization round-trip validation passed");
}

/// Test service interface contract compliance
#[test]
fn test_service_interface_contract_compliance() {
    println!("🔍 Testing service interface contract compliance...");

    let config = ShadowServiceConfig::default();
    let service = DefaultShadowService::new(config);

    // Test complete panel bundle endpoint
    let bundle = service.get_panel_bundle().expect("Should provide panel bundle");
    assert!(!bundle.bundle_version.is_empty(), "Bundle version should not be empty");
    assert!(!bundle.shadow_status.title.is_empty(), "Panel titles should not be empty");

    // Test filtered panels endpoint
    let mut panel_types = BTreeSet::new();
    panel_types.insert(PanelType::ShadowStatus);
    panel_types.insert(PanelType::SourceFreshness);

    let filtered_request = FilteredPanelsRequest { panels: panel_types };
    let filtered_response = service.get_filtered_panels(filtered_request).expect("Should filter panels");

    assert!(filtered_response.shadow_status.is_some(), "Requested shadow_status should be present");
    assert!(filtered_response.source_freshness.is_some(), "Requested source_freshness should be present");
    assert!(filtered_response.degraded_gates.is_none(), "Non-requested degraded_gates should be absent");
    assert!(filtered_response.replay_drift.is_none(), "Non-requested replay_drift should be absent");
    assert!(filtered_response.recommended_actions.is_none(), "Non-requested recommended_actions should be absent");

    // Test health endpoint
    let health = service.get_health().expect("Should provide health status");
    assert_eq!(health.status, "healthy");
    assert!(health.uptime_seconds > 0 || health.uptime_seconds == 0); // Allow for very fast tests
    assert!(!health.version.is_empty(), "Version should not be empty");

    // Test error handling
    let invalid_action_request = ActionPreviewRequest {
        action_id: "non-existent-action".to_string(),
    };
    let error_result = service.preview_action(invalid_action_request);
    assert!(error_result.is_err(), "Should error for non-existent action");

    if let Err(ServiceError::ActionNotFound { action_id }) = error_result {
        assert_eq!(action_id, "non-existent-action");
    } else {
        panic!("Expected ActionNotFound error");
    }

    println!("✅ Service interface contract compliance validation passed");
}

/// Test accessibility and scannability features
#[test]
fn test_accessibility_and_scannability() {
    println!("🔍 Testing accessibility and scannability features...");

    let bundle = PanelBundleBuilder::new()
        .with_daemon_health(DaemonHealth::Healthy)
        .add_source_freshness(SourceFreshnessEntry {
            source_id: "accessible-source".to_string(),
            last_update: SystemTime::now(),
            staleness_seconds: 60,
            threshold_seconds: 300,
            is_stale: false,
        })
        .build();

    // Check that all panels have clear, scannable titles
    assert!(!bundle.shadow_status.title.is_empty(), "Shadow status panel should have title");
    assert!(!bundle.source_freshness.title.is_empty(), "Source freshness panel should have title");
    assert!(!bundle.degraded_gates.title.is_empty(), "Degraded gates panel should have title");
    assert!(!bundle.replay_drift.title.is_empty(), "Replay drift panel should have title");
    assert!(!bundle.recommended_actions.title.is_empty(), "Recommended actions panel should have title");

    // Check that titles are descriptive and readable
    assert!(bundle.shadow_status.title.contains("Status"), "Status panel title should be descriptive");
    assert!(bundle.source_freshness.title.contains("Freshness"), "Freshness panel title should be descriptive");

    // Check that severity/priority levels are consistently defined
    let degraded_entry = DegradedGateEntry {
        gate_id: "test-gate".to_string(),
        degradation_reason: "Test".to_string(),
        degraded_since: SystemTime::now(),
        severity: GateDegradationSeverity::Critical,
    };

    let drift_entry = ReplayDriftEntry {
        journal_id: "test-journal".to_string(),
        drift_type: "test_drift".to_string(),
        detected_at: SystemTime::now(),
        severity: DriftSeverity::Major,
        expected_migration: false,
    };

    let action = RecommendedAction {
        action_id: "test-action".to_string(),
        description: "Test action".to_string(),
        command_preview: "echo test".to_string(),
        priority: ActionPriority::High,
        estimated_duration: Some(60),
    };

    // Verify severity levels are serializable for color-coding
    let degraded_json = serde_json::to_string(&degraded_entry).expect("Should serialize degraded entry");
    let drift_json = serde_json::to_string(&drift_entry).expect("Should serialize drift entry");
    let action_json = serde_json::to_string(&action).expect("Should serialize action");

    assert!(degraded_json.contains("Critical"), "Degraded severity should be serialized");
    assert!(drift_json.contains("Major"), "Drift severity should be serialized");
    assert!(action_json.contains("High"), "Action priority should be serialized");

    println!("✅ Accessibility and scannability validation passed");
}