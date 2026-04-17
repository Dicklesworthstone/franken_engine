//! Integration tests for convergence SLO measurement and artifact publication.
//!
//! These tests verify the end-to-end convergence measurement workflow including
//! quarantine decision tracking, statistical analysis, SLO violation detection,
//! and artifact publication.

use frankenengine_engine::convergence_slo::{
    ConvergenceMeter, ConvergenceSloConfig, StatisticalAnalysisConfig,
};
use frankenengine_engine::fleet_immune_protocol::NodeId;
use frankenengine_engine::quarantine_propagation::QuarantineDecision;
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn test_config() -> ConvergenceSloConfig {
    let temp_dir = TempDir::new().unwrap();
    ConvergenceSloConfig {
        max_convergence_time_ms: 500,
        artifacts_directory: temp_dir.path().to_path_buf(),
        detailed_tracking: true,
        statistical_analysis: StatisticalAnalysisConfig {
            min_sample_size: 3,
            percentiles: vec![50.0, 95.0, 99.0],
            outlier_detection: true,
        },
    }
}

fn test_decision() -> QuarantineDecision {
    QuarantineDecision::new(
        "test-extension".to_string(),
        "Test quarantine decision".to_string(),
        NodeId("originator-instance".to_string()),
        1,
        SecurityEpoch::from_raw(1),
    )
}

#[test]
fn test_convergence_time_measured() {
    let config = test_config();
    let mut meter = ConvergenceMeter::new(config);

    let decision = test_decision();
    let evidence_hash = decision.evidence_hash;

    // Start measurement
    meter.start_measurement(&decision, 3).unwrap();

    let decision_time = Instant::now();
    let ack_time_1 = decision_time + Duration::from_millis(50);
    let ack_time_2 = decision_time + Duration::from_millis(100);

    // Record acknowledgments
    let converged_1 = meter
        .record_acknowledgment(evidence_hash, NodeId("instance-1".to_string()), ack_time_1)
        .unwrap();
    assert!(!converged_1);

    let converged_2 = meter
        .record_acknowledgment(evidence_hash, NodeId("instance-2".to_string()), ack_time_2)
        .unwrap();
    assert!(converged_2);

    // Verify measurement was completed
    assert_eq!(meter.completed_measurements.len(), 1);
    let measurement = &meter.completed_measurements[0];
    assert!(measurement.is_converged());
    assert!(measurement.convergence_duration_ms.is_some());
}

#[test]
fn test_slo_met() {
    let config = ConvergenceSloConfig {
        max_convergence_time_ms: 200, // 200ms threshold
        ..test_config()
    };
    let mut meter = ConvergenceMeter::new(config);

    let decision = test_decision();
    let evidence_hash = decision.evidence_hash;

    meter.start_measurement(&decision, 2).unwrap();

    // Fast convergence (under threshold)
    let ack_time = Instant::now() + Duration::from_millis(100);
    meter
        .record_acknowledgment(evidence_hash, NodeId("instance-1".to_string()), ack_time)
        .unwrap();

    let measurement = &meter.completed_measurements[0];
    assert_eq!(measurement.slo_met, Some(true));
}

#[test]
fn test_slo_violated() {
    let config = ConvergenceSloConfig {
        max_convergence_time_ms: 50, // Very low threshold
        ..test_config()
    };
    let mut meter = ConvergenceMeter::new(config);

    let decision = test_decision();
    let evidence_hash = decision.evidence_hash;

    meter.start_measurement(&decision, 2).unwrap();

    // Slow convergence (over threshold)
    let ack_time = Instant::now() + Duration::from_millis(100);
    meter
        .record_acknowledgment(evidence_hash, NodeId("instance-1".to_string()), ack_time)
        .unwrap();

    let measurement = &meter.completed_measurements[0];
    assert_eq!(measurement.slo_met, Some(false));
}

#[test]
fn test_statistical_analysis() {
    let config = ConvergenceSloConfig {
        statistical_analysis: StatisticalAnalysisConfig {
            min_sample_size: 3,
            percentiles: vec![50.0, 95.0, 99.0],
            outlier_detection: false,
        },
        ..test_config()
    };
    let mut meter = ConvergenceMeter::new(config);

    // Create multiple measurements with known convergence times
    let convergence_times = [100u64, 200, 300, 400, 500];

    for (i, &time_ms) in convergence_times.iter().enumerate() {
        let decision = QuarantineDecision::new(
            format!("extension-{}", i),
            "Test reason".to_string(),
            NodeId("originator".to_string()),
            i as u64 + 1,
            SecurityEpoch::from_raw(1),
        );

        meter.start_measurement(&decision, 2).unwrap();

        let ack_time = decision.decision_timestamp + Duration::from_millis(time_ms);
        meter
            .record_acknowledgment(
                decision.evidence_hash,
                NodeId("instance-1".to_string()),
                ack_time,
            )
            .unwrap();
    }

    let statistics = meter.compute_statistics().unwrap();
    assert_eq!(statistics.total_measurements, 5);
    assert_eq!(statistics.converged_count, 5);
    assert_eq!(statistics.min_convergence_ms, 100);
    assert_eq!(statistics.max_convergence_ms, 500);
    assert_eq!(statistics.average_convergence_ms, 300.0);

    // Check percentiles
    assert_eq!(statistics.percentiles.get("p50"), Some(&300));
    assert_eq!(statistics.percentiles.get("p95"), Some(&500));
    assert_eq!(statistics.percentiles.get("p99"), Some(&500));
}

#[test]
fn test_artifact_json_valid() {
    let temp_dir = TempDir::new().unwrap();
    let config = ConvergenceSloConfig {
        artifacts_directory: temp_dir.path().to_path_buf(),
        statistical_analysis: StatisticalAnalysisConfig {
            min_sample_size: 1,
            ..StatisticalAnalysisConfig::default()
        },
        ..test_config()
    };
    let mut meter = ConvergenceMeter::new(config);

    // Add a completed measurement
    let decision = test_decision();
    meter.start_measurement(&decision, 2).unwrap();
    let ack_time = Instant::now() + Duration::from_millis(150);
    meter
        .record_acknowledgment(
            decision.evidence_hash,
            NodeId("instance-1".to_string()),
            ack_time,
        )
        .unwrap();

    // Compute statistics
    meter.compute_statistics().unwrap();

    // Publish artifacts
    let publication_result = meter.publish_artifacts().unwrap();
    assert!(!publication_result.published_files.is_empty());

    // Verify files were created and contain valid JSON
    for file_path in &publication_result.published_files {
        assert!(file_path.exists());
        let content = std::fs::read_to_string(file_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.is_object());
    }
}

#[test]
fn test_slow_instance_detected() {
    let config = ConvergenceSloConfig {
        statistical_analysis: StatisticalAnalysisConfig {
            min_sample_size: 3,
            outlier_detection: true,
            ..StatisticalAnalysisConfig::default()
        },
        ..test_config()
    };
    let mut meter = ConvergenceMeter::new(config);

    // Create measurements where one instance is consistently slower
    for i in 0..5 {
        let decision = QuarantineDecision::new(
            format!("extension-{}", i),
            "Test reason".to_string(),
            NodeId("originator".to_string()),
            i as u64 + 1,
            SecurityEpoch::from_raw(1),
        );

        meter.start_measurement(&decision, 3).unwrap();

        // Instance-1 is fast (50ms), Instance-2 is slow (500ms)
        let fast_ack = decision.decision_timestamp + Duration::from_millis(50);
        let slow_ack = decision.decision_timestamp + Duration::from_millis(500);

        meter
            .record_acknowledgment(
                decision.evidence_hash,
                NodeId("instance-1".to_string()),
                fast_ack,
            )
            .unwrap();

        meter
            .record_acknowledgment(
                decision.evidence_hash,
                NodeId("instance-2".to_string()),
                slow_ack,
            )
            .unwrap();
    }

    let statistics = meter.compute_statistics().unwrap();

    // Should detect instance-2 as an outlier (slowest 10%)
    assert!(!statistics.outlier_instances.is_empty());
    assert!(
        statistics
            .outlier_instances
            .contains(&NodeId("instance-2".to_string()))
    );
}

#[test]
fn test_convergence_progress_tracking() {
    let config = test_config();
    let mut meter = ConvergenceMeter::new(config);

    let decision = test_decision();
    let evidence_hash = decision.evidence_hash;

    meter.start_measurement(&decision, 4).unwrap(); // 4 instances total

    // Check initial progress
    let (acked, expected) = meter.get_convergence_progress(&evidence_hash).unwrap();
    assert_eq!(acked, 0);
    assert_eq!(expected, 3); // 4 instances - 1 originator

    // Record first acknowledgment
    meter
        .record_acknowledgment(
            evidence_hash,
            NodeId("instance-1".to_string()),
            Instant::now(),
        )
        .unwrap();

    let (acked, expected) = meter.get_convergence_progress(&evidence_hash).unwrap();
    assert_eq!(acked, 1);
    assert_eq!(expected, 3);

    // Record second acknowledgment
    meter
        .record_acknowledgment(
            evidence_hash,
            NodeId("instance-2".to_string()),
            Instant::now(),
        )
        .unwrap();

    let (acked, expected) = meter.get_convergence_progress(&evidence_hash).unwrap();
    assert_eq!(acked, 2);
    assert_eq!(expected, 3);

    // Record final acknowledgment (should trigger convergence)
    meter
        .record_acknowledgment(
            evidence_hash,
            NodeId("instance-3".to_string()),
            Instant::now(),
        )
        .unwrap();

    // Should no longer be in active measurements
    assert!(meter.get_convergence_progress(&evidence_hash).is_none());
    assert!(meter.is_decision_converged(&evidence_hash));
}

#[test]
fn test_measurement_summary() {
    let config = test_config();
    let mut meter = ConvergenceMeter::new(config);

    // Start several measurements
    for i in 0..3 {
        let decision = QuarantineDecision::new(
            format!("extension-{}", i),
            "Test reason".to_string(),
            NodeId("originator".to_string()),
            i as u64 + 1,
            SecurityEpoch::from_raw(1),
        );
        meter.start_measurement(&decision, 2).unwrap();
    }

    // Complete one measurement
    let first_decision = QuarantineDecision::new(
        "extension-0".to_string(),
        "Test reason".to_string(),
        NodeId("originator".to_string()),
        1,
        SecurityEpoch::from_raw(1),
    );

    meter
        .record_acknowledgment(
            first_decision.evidence_hash,
            NodeId("instance-1".to_string()),
            Instant::now(),
        )
        .unwrap();

    let summary = meter.get_measurement_summary();
    assert_eq!(summary.active_measurements, 2);
    assert_eq!(summary.completed_measurements, 1);
    assert_eq!(summary.total_measurements, 3);
    assert!(!summary.latest_statistics_available);
}

#[test]
fn test_slo_compliance_summary() {
    let config = ConvergenceSloConfig {
        max_convergence_time_ms: 200,
        ..test_config()
    };
    let mut meter = ConvergenceMeter::new(config);

    // Create measurements with mixed SLO compliance
    let convergence_times = [100u64, 150, 250, 300]; // First two meet SLO, last two violate

    for (i, &time_ms) in convergence_times.iter().enumerate() {
        let decision = QuarantineDecision::new(
            format!("extension-{}", i),
            "Test reason".to_string(),
            NodeId("originator".to_string()),
            i as u64 + 1,
            SecurityEpoch::from_raw(1),
        );

        meter.start_measurement(&decision, 2).unwrap();

        let ack_time = decision.decision_timestamp + Duration::from_millis(time_ms);
        meter
            .record_acknowledgment(
                decision.evidence_hash,
                NodeId("instance-1".to_string()),
                ack_time,
            )
            .unwrap();
    }

    let slo_summary = meter.generate_slo_summary();
    assert_eq!(slo_summary.total_measurements, 4);
    assert_eq!(slo_summary.slo_violations, 2);
    assert_eq!(slo_summary.slo_compliance_percentage, 50.0);
    assert_eq!(slo_summary.max_convergence_time_ms, 200);
}

#[test]
fn test_end_to_end_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let config = ConvergenceSloConfig {
        max_convergence_time_ms: 300,
        artifacts_directory: temp_dir.path().to_path_buf(),
        detailed_tracking: true,
        statistical_analysis: StatisticalAnalysisConfig {
            min_sample_size: 2,
            percentiles: vec![50.0, 95.0, 99.0],
            outlier_detection: true,
        },
    };
    let mut meter = ConvergenceMeter::new(config);

    // Simulate complete workflow: decision → acknowledgments → convergence → analysis → artifacts
    let decision1 = QuarantineDecision::new(
        "malicious-extension-1".to_string(),
        "Detected malware behavior".to_string(),
        NodeId("security-scanner".to_string()),
        1,
        SecurityEpoch::from_raw(1),
    );

    let decision2 = QuarantineDecision::new(
        "malicious-extension-2".to_string(),
        "Suspicious network activity".to_string(),
        NodeId("network-monitor".to_string()),
        2,
        SecurityEpoch::from_raw(1),
    );

    // Start measurements
    meter.start_measurement(&decision1, 3).unwrap();
    meter.start_measurement(&decision2, 3).unwrap();

    // Simulate acknowledgments with different timing
    let base_time = Instant::now();

    // Decision 1: Fast convergence (under SLO)
    meter
        .record_acknowledgment(
            decision1.evidence_hash,
            NodeId("instance-1".to_string()),
            base_time + Duration::from_millis(100),
        )
        .unwrap();
    meter
        .record_acknowledgment(
            decision1.evidence_hash,
            NodeId("instance-2".to_string()),
            base_time + Duration::from_millis(150),
        )
        .unwrap();

    // Decision 2: Slow convergence (violates SLO)
    meter
        .record_acknowledgment(
            decision2.evidence_hash,
            NodeId("instance-1".to_string()),
            base_time + Duration::from_millis(250),
        )
        .unwrap();
    meter
        .record_acknowledgment(
            decision2.evidence_hash,
            NodeId("instance-2".to_string()),
            base_time + Duration::from_millis(400),
        )
        .unwrap();

    // Compute statistics
    let statistics = meter.compute_statistics().unwrap();
    assert_eq!(statistics.total_measurements, 2);
    assert_eq!(statistics.converged_count, 2);
    assert_eq!(statistics.slo_violations, 1); // Decision 2 violated SLO

    // Publish artifacts
    let publication_result = meter.publish_artifacts().unwrap();
    assert_eq!(publication_result.published_files.len(), 3); // measurements, statistics, slo_summary

    // Verify artifact content
    let artifacts_dir = publication_result.artifacts_directory;
    let measurements_file = artifacts_dir.join("convergence_measurements.json");
    let statistics_file = artifacts_dir.join("convergence_statistics.json");
    let slo_summary_file = artifacts_dir.join("slo_summary.json");

    assert!(measurements_file.exists());
    assert!(statistics_file.exists());
    assert!(slo_summary_file.exists());

    // Verify JSON structure
    let measurements_content = std::fs::read_to_string(measurements_file).unwrap();
    let measurements: Vec<serde_json::Value> = serde_json::from_str(&measurements_content).unwrap();
    assert_eq!(measurements.len(), 2);

    let statistics_content = std::fs::read_to_string(statistics_file).unwrap();
    let stats: serde_json::Value = serde_json::from_str(&statistics_content).unwrap();
    assert_eq!(stats["total_measurements"], 2);
    assert_eq!(stats["slo_violations"], 1);

    let slo_summary_content = std::fs::read_to_string(slo_summary_file).unwrap();
    let summary: serde_json::Value = serde_json::from_str(&slo_summary_content).unwrap();
    assert_eq!(summary["slo_compliance_percentage"], 50.0);
}
