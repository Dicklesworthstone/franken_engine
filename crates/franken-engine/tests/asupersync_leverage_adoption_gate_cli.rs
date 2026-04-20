use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::asupersync_leverage_adoption_gate::{
    AdoptionGateVerdict, AsupersyncLeverageAdoptionGate, build_asupersync_leverage_adoption_gate,
};
use frankenengine_engine::extension_host_topology_assessment::TopologyPromotionDecision;

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "frankenengine-asupersync-leverage-adoption-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn assert_required_files(out_dir: &Path) {
    for file in [
        "asupersync_leverage_adoption_gate.json",
        "decision_record.json",
        "diagnostic_contract_index.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "summary.md",
        "env.json",
        "repro.lock",
    ] {
        assert!(
            out_dir.join(file).exists(),
            "missing required artifact {}",
            out_dir.join(file).display()
        );
    }
    assert!(
        out_dir
            .join("step_logs")
            .join("step_001_generate.log")
            .exists()
    );
}

#[test]
fn adoption_gate_contract_links_closed_wave_artifacts() {
    let gate = build_asupersync_leverage_adoption_gate().unwrap();

    // After bd-2yez8 fix: gate should fail closed when child artifacts are missing
    assert_eq!(gate.verdict, AdoptionGateVerdict::Stop);
    assert_eq!(
        gate.topology_decision,
        TopologyPromotionDecision::TargetedPromotion
    );
    assert_eq!(gate.summary.mandatory_child_count, 8);

    // Should have outstanding children when artifacts are missing
    assert!(gate.summary.outstanding_child_count > 0);
    assert!(!gate.outstanding_risk_ids.is_empty());

    assert!(gate.stop_go_code.contains("stop"));
    assert!(gate.next_action.contains("artifact"));
    assert!(
        gate.mandatory_child_artifacts
            .iter()
            .any(|artifact| artifact.bead_id == "bd-3nr.1.6")
    );
    assert!(
        gate.diagnostic_contract_index
            .iter()
            .any(|entry| entry.diagnostic_id == "topology_decision")
    );
}

#[test]
fn binary_emits_adoption_gate_bundle() {
    let out_dir = unique_temp_dir("bundle");

    let output = Command::new(env!(
        "CARGO_BIN_EXE_franken_asupersync_leverage_adoption_gate"
    ))
    .args(["--out-dir", out_dir.to_str().unwrap()])
    .args(["--seed", "4317"])
    .output()
    .expect("run asupersync leverage adoption gate binary");

    assert!(
        output.status.success(),
        "binary failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_required_files(&out_dir);

    let gate: AsupersyncLeverageAdoptionGate = serde_json::from_slice(
        &fs::read(out_dir.join("asupersync_leverage_adoption_gate.json")).expect("read gate"),
    )
    .expect("parse gate");

    // After bd-2yez8 fix: gate should fail closed when child artifacts are missing
    assert_eq!(gate.verdict, AdoptionGateVerdict::Stop);
    assert!(gate.summary.satisfied_child_count < gate.summary.mandatory_child_count);

    let decision: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("decision_record.json")).expect("read decision"),
    )
    .expect("parse decision");
    assert_eq!(decision["verdict"].as_str(), Some("stop"));
    assert_eq!(
        decision["topology_decision"].as_str(),
        Some("targeted_promotion")
    );

    let diagnostics: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("diagnostic_contract_index.json")).expect("read diagnostics"),
    )
    .expect("parse diagnostics");
    assert_eq!(diagnostics.as_array().expect("diagnostics array").len(), 3);

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    assert_eq!(manifest["seed"].as_u64(), Some(4317));
    assert_eq!(manifest["outcome"].as_str(), Some("fail")); // After bd-2yez8: fail when artifacts missing
    assert_eq!(manifest["verdict"].as_str(), Some("stop"));
    assert_eq!(
        manifest["artifact_paths"]["adoption_gate"].as_str(),
        Some("asupersync_leverage_adoption_gate.json")
    );

    let trace_ids: serde_json::Value =
        serde_json::from_slice(&fs::read(out_dir.join("trace_ids.json")).expect("read trace ids"))
            .expect("parse trace ids");
    assert_eq!(trace_ids["scenario_id"].as_str(), Some("bd-3nr.1.7"));
    assert_eq!(trace_ids["seed"].as_u64(), Some(4317));

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    let lines: Vec<&str> = events.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let event: serde_json::Value = serde_json::from_str(line).expect("parse event");
        assert_eq!(event["trace_id"], trace_ids["trace_id"]);
        assert_eq!(event["outcome"].as_str(), Some("pass"));
        assert_eq!(event["error_code"], serde_json::Value::Null);
        assert_eq!(event["scenario_id"].as_str(), Some("bd-3nr.1.7"));
        assert!(
            event["stop_go_code"]
                .as_str()
                .expect("stop_go_code")
                .contains("targeted_lifecycle_supervision")
        );
    }

    let summary = fs::read_to_string(out_dir.join("summary.md")).expect("read summary");
    assert!(summary.contains("go_targeted"));
    assert!(summary.contains("Mandatory Child Artifacts"));
    assert!(summary.contains("Diagnostic Contracts"));

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(commands.contains("franken_asupersync_leverage_adoption_gate"));
    assert!(commands.contains("rch exec"));
}

#[test]
fn adoption_gate_fails_closed_on_missing_child_artifacts() {
    // Regression test for bd-2yez8: validate mandatory child artifacts before go verdict.
    // When child artifacts are missing/invalid, gate should emit Stop verdict with outstanding risk ids.
    use frankenengine_engine::asupersync_leverage_adoption_gate::{
        AdoptionGateVerdict, build_asupersync_leverage_adoption_gate,
    };

    // Build gate in clean environment where child artifacts don't exist
    let gate = build_asupersync_leverage_adoption_gate().unwrap();

    // Should fail closed with Stop verdict due to missing child artifacts
    assert_eq!(
        gate.verdict,
        AdoptionGateVerdict::Stop,
        "Gate should emit Stop verdict when child artifacts are missing"
    );

    // Should have outstanding risk IDs for missing artifacts
    assert!(
        !gate.outstanding_risk_ids.is_empty(),
        "Gate should have outstanding risk IDs for missing child artifacts"
    );

    // Should have outstanding child count > 0
    assert!(
        gate.summary.outstanding_child_count > 0,
        "Gate should report outstanding child artifacts"
    );

    // Should have fewer satisfied than total mandatory children
    assert!(
        gate.summary.satisfied_child_count < gate.summary.mandatory_child_count,
        "Gate should report some unsatisfied child artifacts"
    );

    // Should have stop-go code indicating failure
    assert!(
        gate.stop_go_code.contains("stop"),
        "Stop-go code should indicate stop verdict"
    );

    // Outstanding risk IDs should contain artifact-specific codes
    let risk_id_contains_missing = gate
        .outstanding_risk_ids
        .iter()
        .any(|id| id.contains("missing_or_invalid"));
    assert!(
        risk_id_contains_missing,
        "Outstanding risk IDs should contain missing/invalid artifact codes"
    );

    // Verify has_outstanding_child_artifacts correctly detects the issue
    assert!(
        gate.has_outstanding_child_artifacts(),
        "Gate should detect outstanding child artifacts"
    );
}
