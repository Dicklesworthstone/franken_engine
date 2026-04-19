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
    let gate = build_asupersync_leverage_adoption_gate();
    assert_eq!(gate.verdict, AdoptionGateVerdict::GoTargeted);
    assert_eq!(
        gate.topology_decision,
        TopologyPromotionDecision::TargetedPromotion
    );
    assert_eq!(gate.summary.mandatory_child_count, 8);
    assert_eq!(gate.summary.outstanding_child_count, 0);
    assert!(gate.outstanding_risk_ids.is_empty());
    assert!(gate.stop_go_code.contains("targeted_lifecycle_supervision"));
    assert!(gate.next_action.contains("extension lifecycle manager"));
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
    assert_eq!(gate.verdict, AdoptionGateVerdict::GoTargeted);
    assert_eq!(gate.summary.satisfied_child_count, 8);

    let decision: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("decision_record.json")).expect("read decision"),
    )
    .expect("parse decision");
    assert_eq!(decision["verdict"].as_str(), Some("go_targeted"));
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
    assert_eq!(manifest["outcome"].as_str(), Some("pass"));
    assert_eq!(manifest["verdict"].as_str(), Some("go_targeted"));
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
