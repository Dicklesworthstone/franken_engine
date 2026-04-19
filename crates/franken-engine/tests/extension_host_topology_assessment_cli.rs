use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::extension_host_topology_assessment::{
    TopologyPromotionAssessment, TopologyPromotionDecision, TopologySeamId,
    build_topology_promotion_assessment,
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "frankenengine-extension-host-topology-assessment-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn assert_required_files(out_dir: &Path) {
    for file in [
        "topology_promotion_assessment.json",
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
fn assessment_contract_has_targeted_lifecycle_promotion_only() {
    let assessment = build_topology_promotion_assessment();
    assert_eq!(
        assessment.decision,
        TopologyPromotionDecision::TargetedPromotion
    );
    assert!(!assessment.has_broader_promotion());
    assert_eq!(assessment.summary.total_seams, TopologySeamId::ALL.len());

    let targeted = assessment.targeted_seams();
    assert_eq!(targeted.len(), 1);
    assert_eq!(
        targeted[0].seam_id,
        TopologySeamId::ExtensionLifecycleManager
    );
    assert!(
        targeted[0]
            .required_upstream_primitives
            .iter()
            .any(|primitive| primitive.contains("supervision")),
        "targeted seam must name the supervision primitive"
    );
    assert!(
        targeted[0]
            .rollback_plan
            .contains("ExtensionLifecycleManager"),
        "targeted seam must include a concrete rollback plan"
    );
}

#[test]
fn binary_emits_topology_assessment_bundle() {
    let out_dir = unique_temp_dir("bundle");

    let output = Command::new(env!(
        "CARGO_BIN_EXE_franken_extension_host_topology_assessment"
    ))
    .args(["--out-dir", out_dir.to_str().unwrap()])
    .args(["--seed", "4242"])
    .output()
    .expect("run extension-host topology assessment binary");

    assert!(
        output.status.success(),
        "binary failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_required_files(&out_dir);

    let assessment: TopologyPromotionAssessment = serde_json::from_slice(
        &fs::read(out_dir.join("topology_promotion_assessment.json")).expect("read assessment"),
    )
    .expect("parse topology assessment");
    assert_eq!(
        assessment.decision,
        TopologyPromotionDecision::TargetedPromotion
    );
    assert_eq!(assessment.summary.targeted_promotion_count, 1);
    assert_eq!(assessment.summary.broader_promotion_count, 0);
    assert_eq!(assessment.targeted_seams().len(), 1);

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("parse run manifest");
    assert_eq!(manifest["seed"].as_u64(), Some(4242));
    assert_eq!(manifest["outcome"].as_str(), Some("pass"));
    assert_eq!(manifest["decision"].as_str(), Some("targeted_promotion"));
    assert_eq!(manifest["broader_promotion_count"].as_u64(), Some(0));
    assert_eq!(
        manifest["artifact_paths"]["topology_promotion_assessment"].as_str(),
        Some("topology_promotion_assessment.json")
    );

    let trace_ids: serde_json::Value =
        serde_json::from_slice(&fs::read(out_dir.join("trace_ids.json")).expect("read trace ids"))
            .expect("parse trace ids");
    assert_eq!(trace_ids["seed"].as_u64(), Some(4242));
    assert_eq!(trace_ids["scenario_id"].as_str(), Some("bd-3nr.1.6"));

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    let lines: Vec<&str> = events.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let event: serde_json::Value = serde_json::from_str(line).expect("parse event line");
        assert_eq!(event["trace_id"], trace_ids["trace_id"]);
        assert_eq!(event["outcome"].as_str(), Some("pass"));
        assert_eq!(event["error_code"], serde_json::Value::Null);
        assert_eq!(event["seed"].as_u64(), Some(4242));
        assert_eq!(
            event["topology_decision"].as_str(),
            Some("targeted_promotion")
        );
    }

    let summary = fs::read_to_string(out_dir.join("summary.md")).expect("read summary");
    assert!(summary.contains("extension_lifecycle_manager"));
    assert!(summary.contains("targeted_promotion"));
    assert!(summary.contains("broader AppSpec/actor promotion"));

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(commands.contains("franken_extension_host_topology_assessment"));
    assert!(commands.contains("rch exec"));
    assert!(!commands.contains(
        "cargo run -p frankenengine-engine --bin franken_extension_host_topology_assessment\n"
    ));
}
