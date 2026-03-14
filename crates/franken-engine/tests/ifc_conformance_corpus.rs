#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

#[path = "../src/conformance_harness.rs"]
mod conformance_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use conformance_harness::{
    ConformanceEvidenceCollector, ConformanceManifestError, ConformanceRunError, ConformanceRunner,
    ConformanceWaiverSet,
};
use serde_json::Value;

const REQUIRED_SOURCE_LABELS: [&str; 4] = [
    "credential",
    "key_material",
    "privileged_env",
    "policy_protected",
];
const REQUIRED_SINK_CLEARANCES: [&str; 4] = [
    "network_egress",
    "subprocess_ipc",
    "persistence_export",
    "explicit_declassify",
];
const REQUIRED_FLOW_PATHS: [&str; 5] = ["direct", "indirect", "implicit", "temporal", "covert"];

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/ifc_corpus/ifc_conformance_assets.json")
}

fn test_temp_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-engine-ifc-corpus-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) {
    fs::create_dir_all(dst).expect("create dst tree");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let metadata = entry.metadata().expect("metadata");
        if metadata.is_dir() {
            copy_tree(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("copy file");
        }
    }
}

fn parse_manifest_assets() -> Vec<Value> {
    let manifest_bytes = fs::read_to_string(manifest_path()).expect("read manifest");
    let manifest: Value = serde_json::from_str(&manifest_bytes).expect("parse manifest json");
    manifest["assets"].as_array().expect("assets array").clone()
}

#[test]
fn ifc_manifest_meets_size_and_taxonomy_requirements() {
    let assets = parse_manifest_assets();
    assert!(
        assets.len() >= 210,
        "IFC corpus should include at least 210 workloads"
    );

    let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_source_labels: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut category_sink_clearances: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut exfil_flow_paths = BTreeSet::new();

    for asset in &assets {
        let category = asset["category"].as_str().expect("category string");
        assert!(
            matches!(category, "benign" | "exfil" | "declassify"),
            "unexpected IFC category: {category}"
        );
        *category_counts.entry(category.to_string()).or_insert(0) += 1;

        let source_labels = asset["source_labels"]
            .as_array()
            .expect("source_labels array");
        assert!(
            !source_labels.is_empty(),
            "source_labels must be non-empty for IFC assets"
        );
        for label in source_labels {
            let label = label.as_str().expect("source label string").to_string();
            category_source_labels
                .entry(category.to_string())
                .or_default()
                .insert(label);
        }

        let sink_clearances = asset["sink_clearances"]
            .as_array()
            .expect("sink_clearances array");
        assert!(
            !sink_clearances.is_empty(),
            "sink_clearances must be non-empty for IFC assets"
        );
        for clearance in sink_clearances {
            let clearance = clearance
                .as_str()
                .expect("sink clearance string")
                .to_string();
            category_sink_clearances
                .entry(category.to_string())
                .or_default()
                .insert(clearance);
        }

        let flow_path = asset["flow_path_type"]
            .as_str()
            .expect("flow_path_type string");
        if category == "exfil" {
            exfil_flow_paths.insert(flow_path.to_string());
        }

        let expected_outcome = asset["expected_outcome"]
            .as_str()
            .expect("expected_outcome string");
        let expected_evidence_type = asset["expected_evidence_type"]
            .as_str()
            .expect("expected_evidence_type string");
        match category {
            "benign" => {
                assert_eq!(expected_outcome, "allow");
                assert_eq!(expected_evidence_type, "none");
            }
            "exfil" => {
                assert_eq!(expected_outcome, "block");
                assert_eq!(expected_evidence_type, "flow_violation");
            }
            "declassify" => {
                assert_eq!(expected_outcome, "declassify");
                assert_eq!(expected_evidence_type, "declassification_receipt");
            }
            _ => unreachable!("category validated above"),
        }
    }

    assert!(
        category_counts.get("benign").copied().unwrap_or(0) >= 100,
        "benign corpus must include at least 100 workloads"
    );
    assert!(
        category_counts.get("exfil").copied().unwrap_or(0) >= 80,
        "exfil corpus must include at least 80 workloads"
    );
    assert!(
        category_counts.get("declassify").copied().unwrap_or(0) >= 30,
        "declassify corpus must include at least 30 workloads"
    );

    for category in ["benign", "exfil", "declassify"] {
        let labels = category_source_labels
            .get(category)
            .expect("category labels tracked");
        for required in REQUIRED_SOURCE_LABELS {
            assert!(
                labels.contains(required),
                "category `{category}` missing source label `{required}`"
            );
        }

        let clearances = category_sink_clearances
            .get(category)
            .expect("category clearances tracked");
        for required in REQUIRED_SINK_CLEARANCES {
            assert!(
                clearances.contains(required),
                "category `{category}` missing sink clearance `{required}`"
            );
        }
    }

    for required_path in REQUIRED_FLOW_PATHS {
        assert!(
            exfil_flow_paths.contains(required_path),
            "exfil corpus missing flow path `{required_path}`"
        );
    }
}

#[test]
fn ifc_manifest_executes_deterministically_and_emits_ifc_evidence() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();

    let first = runner.run(manifest_path(), &waivers).expect("ifc run #1");
    let repeated_runs = (0..4)
        .map(|_| {
            runner
                .run(manifest_path(), &waivers)
                .expect("repeat ifc run")
        })
        .collect::<Vec<_>>();

    assert!(first.summary.total_assets >= 210);
    assert_eq!(first.summary.failed, 0);
    assert_eq!(first.summary.errored, 0);
    first
        .enforce_ci_gate()
        .expect("ifc corpus should satisfy ci gate");

    for run in &repeated_runs {
        assert_eq!(
            first.logs, run.logs,
            "runner output should be deterministic"
        );
        assert_eq!(
            first.summary, run.summary,
            "runner summary should be stable"
        );
    }

    let semantic_domains: Vec<_> = first
        .logs
        .iter()
        .map(|log| log.semantic_domain.as_str())
        .collect();
    assert!(
        semantic_domains
            .iter()
            .any(|domain| domain.contains("ifc_corpus/benign"))
    );
    assert!(
        semantic_domains
            .iter()
            .any(|domain| domain.contains("ifc_corpus/exfil"))
    );
    assert!(
        semantic_domains
            .iter()
            .any(|domain| domain.contains("ifc_corpus/declassify"))
    );

    assert!(first.logs.iter().all(|log| log.workload_id == log.asset_id));
    assert!(first.logs.iter().all(|log| log.duration_us > 0));
    assert!(first.logs.iter().all(|log| log.category.is_some()));
    assert!(first.logs.iter().all(|log| !log.source_labels.is_empty()));
    assert!(first.logs.iter().all(|log| !log.sink_clearances.is_empty()));
    assert!(first.logs.iter().all(|log| log.flow_path_type.is_some()));
    assert!(first.logs.iter().all(|log| log.expected_outcome.is_some()));
    assert!(first.logs.iter().all(|log| log.actual_outcome.is_some()));
    assert!(first.logs.iter().all(|log| log.evidence_type.is_some()));

    let collector =
        ConformanceEvidenceCollector::new(test_temp_dir("ifc-evidence")).expect("collector init");
    let artifacts = collector.collect(&first).expect("collect IFC artifacts");
    let ifc_path = artifacts
        .ifc_conformance_evidence_path
        .as_ref()
        .expect("ifc evidence should be emitted");
    assert!(ifc_path.exists(), "ifc evidence artifact should exist");

    let ifc_lines = fs::read_to_string(ifc_path).expect("read ifc evidence");
    let summary_line = ifc_lines.lines().next().expect("ifc summary line");
    let summary: Value = serde_json::from_str(summary_line).expect("parse ifc summary");
    assert_eq!(summary["corpus_hash"], first.asset_manifest_hash);
    assert_eq!(
        summary["environment_fingerprint"],
        first.summary.env_fingerprint
    );
    assert_eq!(summary["false_positive_count"], 0);
    assert_eq!(summary["false_negative_direct_indirect_count"], 0);
    assert_eq!(summary["ci_blocking_failures"], 0);
    assert!(
        summary["category_counts"]["benign"]["total"]
            .as_u64()
            .is_some_and(|v| v >= 100)
    );
    assert!(
        summary["category_counts"]["exfil"]["total"]
            .as_u64()
            .is_some_and(|v| v >= 80)
    );
    assert!(
        summary["category_counts"]["declassify"]["total"]
            .as_u64()
            .is_some_and(|v| v >= 30)
    );
}

#[test]
fn ifc_manifest_integrity_meta_test_detects_tampering() {
    let source_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/ifc_corpus");
    let temp_root = test_temp_dir("ifc-tamper").join("ifc_corpus");
    copy_tree(&source_root, &temp_root);

    let fixture_path = temp_root.join("fixtures/exfil_direct.fixture.json");
    fs::write(
        &fixture_path,
        r#"{"donor_harness":"franken-ifc","source":"secret = fs.read('/creds'); net.send(secret)","observed_output":"outcome:allow evidence:none"}"#,
    )
    .expect("tamper fixture");

    let manifest_path = temp_root.join("ifc_conformance_assets.json");
    let err = ConformanceRunner::default()
        .run(&manifest_path, &ConformanceWaiverSet::default())
        .expect_err("tampered fixture hash should fail");

    match err {
        ConformanceRunError::Manifest(ConformanceManifestError::FixtureHashMismatch { .. }) => {}
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn ifc_false_positive_injection_meta_test_allows_benign_network_egress() {
    let runner = ConformanceRunner::default();
    let run = runner
        .run(manifest_path(), &ConformanceWaiverSet::default())
        .expect("ifc run");

    let benign_network_log = run
        .logs
        .iter()
        .find(|log| {
            log.category.as_deref() == Some("benign")
                && log.sink_clearances.iter().any(|c| c == "network_egress")
        })
        .expect("benign network egress workload should exist");

    assert_eq!(
        benign_network_log.expected_outcome.as_deref(),
        Some("allow")
    );
    assert_eq!(benign_network_log.actual_outcome.as_deref(), Some("allow"));
    assert_eq!(benign_network_log.evidence_type.as_deref(), Some("none"));
    assert_eq!(benign_network_log.outcome, "pass");
}

// ---------- parse_manifest_assets ----------

#[test]
fn manifest_assets_are_non_empty() {
    let assets = parse_manifest_assets();
    assert!(!assets.is_empty());
}

// ---------- manifest_path ----------

#[test]
fn manifest_path_exists() {
    assert!(manifest_path().exists());
}

// ---------- REQUIRED constants ----------

#[test]
fn required_source_labels_are_four() {
    assert_eq!(REQUIRED_SOURCE_LABELS.len(), 4);
}

#[test]
fn required_sink_clearances_are_four() {
    assert_eq!(REQUIRED_SINK_CLEARANCES.len(), 4);
}

#[test]
fn required_flow_paths_are_five() {
    assert_eq!(REQUIRED_FLOW_PATHS.len(), 5);
}

// ---------- ConformanceRunner ----------

#[test]
fn conformance_runner_default_produces_valid_runner() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(manifest_path(), &waivers).expect("ifc run");
    assert!(result.summary.total_assets >= 210);
}

// ---------- ConformanceWaiverSet ----------

#[test]
fn conformance_waiver_set_default_has_no_waivers() {
    let waivers = ConformanceWaiverSet::default();
    assert!(waivers.waivers.is_empty());
}

// ---------- category counts ----------

#[test]
fn ifc_manifest_has_all_three_categories() {
    let assets = parse_manifest_assets();
    let categories: BTreeSet<_> = assets
        .iter()
        .map(|asset| asset["category"].as_str().unwrap().to_string())
        .collect();
    assert!(categories.contains("benign"));
    assert!(categories.contains("exfil"));
    assert!(categories.contains("declassify"));
}

// ---------- asset fields ----------

#[test]
fn every_asset_has_expected_outcome_field() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        assert!(asset["expected_outcome"].as_str().is_some());
    }
}

#[test]
fn every_asset_has_flow_path_type_field() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        assert!(asset["flow_path_type"].as_str().is_some());
    }
}

// ---------- ConformanceEvidenceCollector ----------

#[test]
fn evidence_collector_creates_artifact_directory() {
    let temp = test_temp_dir("evidence-collector-test");
    let _collector = ConformanceEvidenceCollector::new(temp.clone()).expect("collector");
    assert!(temp.exists());
}

// ---------- copy_tree ----------

#[test]
fn copy_tree_copies_files() {
    let src = test_temp_dir("copy-src");
    let dst = test_temp_dir("copy-dst").join("subtree");
    fs::write(src.join("test.txt"), "hello").expect("write test file");
    copy_tree(&src, &dst);
    assert!(dst.join("test.txt").exists());
    assert_eq!(fs::read_to_string(dst.join("test.txt")).unwrap(), "hello");
}

// ---------- asset_ids are unique ----------

#[test]
fn ifc_manifest_asset_ids_are_unique() {
    let assets = parse_manifest_assets();
    let mut seen = BTreeSet::new();
    for asset in &assets {
        let asset_id = asset["asset_id"].as_str().expect("asset_id string");
        assert!(
            seen.insert(asset_id.to_string()),
            "duplicate asset_id: {asset_id}"
        );
    }
}

// ---------- semantic_domain prefixed correctly ----------

#[test]
fn ifc_manifest_assets_have_semantic_domain_prefix() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        let domain = asset["semantic_domain"]
            .as_str()
            .expect("semantic_domain string");
        assert!(
            domain.starts_with("ifc_corpus/"),
            "unexpected semantic_domain prefix: {domain}"
        );
    }
}

// ---------- test_temp_dir creates unique paths ----------

#[test]
fn ifc_test_temp_dir_creates_unique_paths() {
    let a = test_temp_dir("unique-a");
    let b = test_temp_dir("unique-b");
    assert_ne!(a, b);
    assert!(a.exists());
    assert!(b.exists());
    fs::remove_dir_all(a).ok();
    fs::remove_dir_all(b).ok();
}

// ---------- every asset has evidence_type ----------

#[test]
fn every_asset_has_expected_evidence_type_field() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        assert!(asset["expected_evidence_type"].as_str().is_some());
    }
}

// ---------- every asset has source_labels and sink_clearances ----------

#[test]
fn every_asset_has_non_empty_source_and_sink_labels() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        let source = asset["source_labels"].as_array().expect("source_labels");
        let sink = asset["sink_clearances"]
            .as_array()
            .expect("sink_clearances");
        assert!(!source.is_empty());
        assert!(!sink.is_empty());
    }
}

#[test]
fn ifc_manifest_has_nonempty_schema_version() {
    let raw = fs::read_to_string(manifest_path()).expect("read manifest");
    let manifest: Value = serde_json::from_str(&raw).expect("parse");
    let sv = manifest["schema_version"].as_str().expect("schema_version");
    assert!(!sv.trim().is_empty());
}

#[test]
fn ifc_manifest_deterministic_double_load() {
    let raw = fs::read_to_string(manifest_path()).expect("read manifest");
    let a: Value = serde_json::from_str(&raw).expect("parse a");
    let b: Value = serde_json::from_str(&raw).expect("parse b");
    assert_eq!(a, b);
}

#[test]
fn ifc_manifest_assets_all_have_nonempty_ids() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        let id = asset["asset_id"].as_str().expect("asset_id");
        assert!(!id.trim().is_empty());
    }
}

// ---------- category-specific expected_outcome consistency ----------

#[test]
fn benign_assets_all_have_allow_outcome() {
    let assets = parse_manifest_assets();
    for asset in assets
        .iter()
        .filter(|a| a["category"].as_str() == Some("benign"))
    {
        assert_eq!(
            asset["expected_outcome"].as_str(),
            Some("allow"),
            "benign asset {} must have allow outcome",
            asset["asset_id"]
        );
    }
}

#[test]
fn exfil_assets_all_have_block_outcome() {
    let assets = parse_manifest_assets();
    for asset in assets
        .iter()
        .filter(|a| a["category"].as_str() == Some("exfil"))
    {
        assert_eq!(
            asset["expected_outcome"].as_str(),
            Some("block"),
            "exfil asset {} must have block outcome",
            asset["asset_id"]
        );
    }
}

#[test]
fn declassify_assets_all_have_declassify_outcome() {
    let assets = parse_manifest_assets();
    for asset in assets
        .iter()
        .filter(|a| a["category"].as_str() == Some("declassify"))
    {
        assert_eq!(
            asset["expected_outcome"].as_str(),
            Some("declassify"),
            "declassify asset {} must have declassify outcome",
            asset["asset_id"]
        );
    }
}

// ---------- exfil flow_path coverage ----------

#[test]
fn exfil_corpus_covers_all_five_flow_path_types() {
    let assets = parse_manifest_assets();
    let exfil_paths: BTreeSet<_> = assets
        .iter()
        .filter(|a| a["category"].as_str() == Some("exfil"))
        .filter_map(|a| a["flow_path_type"].as_str().map(|s| s.to_string()))
        .collect();
    for required in REQUIRED_FLOW_PATHS {
        assert!(
            exfil_paths.contains(required),
            "exfil corpus missing flow_path_type `{required}`"
        );
    }
}

// ---------- semantic_domain subcategory consistency ----------

#[test]
fn asset_semantic_domain_matches_category() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        let domain = asset["semantic_domain"].as_str().expect("semantic_domain");
        let category = asset["category"].as_str().expect("category");
        assert!(
            domain.contains(category),
            "asset {} has domain `{domain}` not matching category `{category}`",
            asset["asset_id"]
        );
    }
}

// ---------- copy_tree nested subdirectory ----------

#[test]
fn copy_tree_handles_nested_subdirectories() {
    let src = test_temp_dir("copy-nested-src");
    let subdir = src.join("inner");
    fs::create_dir_all(&subdir).expect("create inner dir");
    fs::write(subdir.join("nested.txt"), "nested").expect("write nested");
    let dst = test_temp_dir("copy-nested-dst").join("out");
    copy_tree(&src, &dst);
    assert_eq!(
        fs::read_to_string(dst.join("inner/nested.txt")).unwrap(),
        "nested"
    );
}

// ---------- manifest has fixture_hash entries ----------

#[test]
fn every_asset_has_nonempty_fixture_hash() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        let hash = asset["fixture_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("asset {} missing fixture_hash", asset["asset_id"]));
        assert!(
            !hash.trim().is_empty(),
            "fixture_hash must be non-empty for asset {}",
            asset["asset_id"]
        );
    }
}

// ---------- serde roundtrip: ConformanceAssetRecord ----------

#[test]
fn conformance_asset_record_serde_roundtrip_with_ifc_fields() {
    let record = conformance_harness::ConformanceAssetRecord {
        asset_id: "ifc-rt-001".to_string(),
        source_donor: "franken-ifc".to_string(),
        semantic_domain: "ifc_corpus/benign".to_string(),
        normative_reference: "IFC-SPEC-1".to_string(),
        fixture_path: "fixtures/benign_echo.fixture.json".to_string(),
        fixture_hash: "aaaa".to_string(),
        expected_output_path: "expected/benign_echo.txt".to_string(),
        expected_output_hash: "bbbb".to_string(),
        import_date: "2026-01-01".to_string(),
        category: Some("benign".to_string()),
        source_labels: vec!["credential".to_string()],
        sink_clearances: vec!["network_egress".to_string()],
        flow_path_type: Some("direct".to_string()),
        expected_outcome: Some("allow".to_string()),
        expected_evidence_type: Some("none".to_string()),
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let back: conformance_harness::ConformanceAssetRecord =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, back);
}

// ---------- serde roundtrip: ConformanceWaiverSet with waivers ----------

#[test]
fn conformance_waiver_set_serde_roundtrip() {
    let waiver_set = conformance_harness::ConformanceWaiverSet {
        waivers: vec![conformance_harness::ConformanceWaiver {
            asset_id: "ifc-waiver-001".to_string(),
            reason_code: conformance_harness::WaiverReasonCode::HarnessGap,
            tracking_bead: "bd-test".to_string(),
            expiry_date: "2027-01-01".to_string(),
        }],
    };
    let json = serde_json::to_string(&waiver_set).expect("serialize");
    let back: conformance_harness::ConformanceWaiverSet =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(waiver_set, back);
    assert_eq!(back.waivers.len(), 1);
}

// ---------- serde roundtrip: all WaiverReasonCode variants ----------

#[test]
fn waiver_reason_code_serde_roundtrip_all_variants() {
    let variants = [
        conformance_harness::WaiverReasonCode::HarnessGap,
        conformance_harness::WaiverReasonCode::HostHookMissing,
        conformance_harness::WaiverReasonCode::IntentionalDivergence,
        conformance_harness::WaiverReasonCode::NotYetImplemented,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: conformance_harness::WaiverReasonCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

// ---------- serde roundtrip: ConformanceRunnerConfig ----------

#[test]
fn conformance_runner_config_default_serde_roundtrip() {
    let config = conformance_harness::ConformanceRunnerConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let back: conformance_harness::ConformanceRunnerConfig =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, back);
    assert_eq!(back.locale, "C");
    assert_eq!(back.timezone, "UTC");
    assert_eq!(back.gc_schedule, "deterministic");
    assert_eq!(back.seed, 7);
}

// ---------- serde roundtrip: ConformanceReproMetadata default ----------

#[test]
fn conformance_repro_metadata_default_serde_roundtrip() {
    let meta = conformance_harness::ConformanceReproMetadata::default();
    let json = serde_json::to_string(&meta).expect("serialize");
    let back: conformance_harness::ConformanceReproMetadata =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(meta, back);
    assert!(meta.version_combination.contains_key("franken_engine"));
    assert_eq!(meta.first_seen_commit, "unknown");
    assert!(meta.regression_commit.is_none());
    assert!(meta.ci_run_id.is_none());
    assert_eq!(meta.issue_tracker_project, "beads");
}

// ---------- serde roundtrip: ConformanceFailureClass all variants ----------

#[test]
fn conformance_failure_class_serde_roundtrip_all_variants() {
    let variants = [
        conformance_harness::ConformanceFailureClass::Breaking,
        conformance_harness::ConformanceFailureClass::Behavioral,
        conformance_harness::ConformanceFailureClass::Observability,
        conformance_harness::ConformanceFailureClass::Performance,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: conformance_harness::ConformanceFailureClass =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

// ---------- serde roundtrip: ConformanceFailureSeverity all variants ----------

#[test]
fn conformance_failure_severity_serde_roundtrip_all_variants() {
    let variants = [
        conformance_harness::ConformanceFailureSeverity::Info,
        conformance_harness::ConformanceFailureSeverity::Warning,
        conformance_harness::ConformanceFailureSeverity::Error,
        conformance_harness::ConformanceFailureSeverity::Critical,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: conformance_harness::ConformanceFailureSeverity =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

// ---------- serde roundtrip: ConformanceDeltaKind all variants ----------

#[test]
fn conformance_delta_kind_serde_roundtrip_all_variants() {
    let variants = [
        conformance_harness::ConformanceDeltaKind::SchemaFieldAdded,
        conformance_harness::ConformanceDeltaKind::SchemaFieldRemoved,
        conformance_harness::ConformanceDeltaKind::SchemaFieldModified,
        conformance_harness::ConformanceDeltaKind::BehavioralSemanticShift,
        conformance_harness::ConformanceDeltaKind::TimingChange,
        conformance_harness::ConformanceDeltaKind::ErrorFormatChange,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: conformance_harness::ConformanceDeltaKind =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

// ---------- serde roundtrip: DonorFixture ----------

#[test]
fn donor_fixture_serde_roundtrip() {
    let fixture = conformance_harness::DonorFixture {
        donor_harness: "franken-ifc".to_string(),
        source: "console.log('hello')".to_string(),
        observed_output: "outcome:allow evidence:none".to_string(),
    };
    let json = serde_json::to_string(&fixture).expect("serialize");
    let back: conformance_harness::DonorFixture = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(fixture, back);
}

// ---------- serde roundtrip: ConformanceLogEvent ----------

#[test]
fn conformance_log_event_serde_roundtrip() {
    let event = conformance_harness::ConformanceLogEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: "policy-v1".to_string(),
        component: "conformance_runner".to_string(),
        event: "asset_execution".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "ifc-001".to_string(),
        workload_id: "ifc-001".to_string(),
        semantic_domain: "ifc_corpus/benign".to_string(),
        category: Some("benign".to_string()),
        source_labels: vec!["credential".to_string()],
        sink_clearances: vec!["network_egress".to_string()],
        flow_path_type: Some("direct".to_string()),
        expected_outcome: Some("allow".to_string()),
        actual_outcome: Some("allow".to_string()),
        evidence_type: Some("none".to_string()),
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let back: conformance_harness::ConformanceLogEvent =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, back);
}

// ---------- serde roundtrip: ConformanceRunSummary ----------

#[test]
fn conformance_run_summary_serde_roundtrip() {
    let summary = conformance_harness::ConformanceRunSummary {
        run_id: "run-123".to_string(),
        asset_manifest_hash: "abc123".to_string(),
        total_assets: 210,
        passed: 200,
        failed: 5,
        waived: 3,
        errored: 2,
        env_fingerprint: "fp-xyz".to_string(),
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let back: conformance_harness::ConformanceRunSummary =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, back);
}

// ---------- CiGateError Display ----------

#[test]
fn ci_gate_error_display_includes_counts() {
    let err = conformance_harness::ConformanceCiGateError {
        failed: 3,
        errored: 1,
    };
    let msg = format!("{err}");
    assert!(msg.contains("failed=3"));
    assert!(msg.contains("errored=1"));
}

// ---------- ConformanceRunResult enforce_ci_gate ----------

#[test]
fn enforce_ci_gate_passes_when_zero_failures_and_errors() {
    let result = conformance_harness::ConformanceRunResult {
        run_id: "run-ci-gate".to_string(),
        asset_manifest_hash: "hash".to_string(),
        logs: vec![],
        summary: conformance_harness::ConformanceRunSummary {
            run_id: "run-ci-gate".to_string(),
            asset_manifest_hash: "hash".to_string(),
            total_assets: 10,
            passed: 10,
            failed: 0,
            waived: 0,
            errored: 0,
            env_fingerprint: "fp".to_string(),
        },
        minimized_repros: vec![],
    };
    assert!(result.enforce_ci_gate().is_ok());
}

#[test]
fn enforce_ci_gate_fails_when_errored_nonzero() {
    let result = conformance_harness::ConformanceRunResult {
        run_id: "run-ci-gate-err".to_string(),
        asset_manifest_hash: "hash".to_string(),
        logs: vec![],
        summary: conformance_harness::ConformanceRunSummary {
            run_id: "run-ci-gate-err".to_string(),
            asset_manifest_hash: "hash".to_string(),
            total_assets: 10,
            passed: 9,
            failed: 0,
            waived: 0,
            errored: 1,
            env_fingerprint: "fp".to_string(),
        },
        minimized_repros: vec![],
    };
    let err = result.enforce_ci_gate().unwrap_err();
    assert_eq!(err.errored, 1);
    assert_eq!(err.failed, 0);
}

// ---------- DonorHarnessAdapter adapt_source ----------

#[test]
fn donor_harness_adapter_replaces_test262_builtins() {
    use conformance_harness::DonorHarnessApi;
    let adapter = conformance_harness::DonorHarnessAdapter;
    let result = adapter.adapt_source("$262.createRealm(); $DONE; print(42);");
    assert!(result.contains("__franken_create_realm()"));
    assert!(result.contains("__franken_done"));
    assert!(result.contains("franken_print("));
    assert!(!result.contains("$262"));
    assert!(!result.contains("$DONE"));
}

#[test]
fn donor_harness_adapter_passthrough_without_markers() {
    use conformance_harness::DonorHarnessApi;
    let adapter = conformance_harness::DonorHarnessAdapter;
    let source = "let x = 42; console.log(x);";
    let result = adapter.adapt_source(source);
    assert_eq!(result, source);
}

// ---------- classify_conformance_delta identical outputs ----------

#[test]
fn classify_conformance_delta_identical_returns_empty() {
    let deltas = conformance_harness::classify_conformance_delta("hello world", "hello world");
    assert!(deltas.is_empty());
}

// ---------- classify_conformance_delta behavioral shift ----------

#[test]
fn classify_conformance_delta_behavioral_shift_when_no_schema_or_error_change() {
    let deltas = conformance_harness::classify_conformance_delta("result: foo", "result: bar");
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == conformance_harness::ConformanceDeltaKind::BehavioralSemanticShift)
    );
}

// ---------- classify_conformance_delta error format change ----------

#[test]
fn classify_conformance_delta_error_format_change() {
    let deltas = conformance_harness::classify_conformance_delta(
        "TypeError: something is wrong",
        "ReferenceError: something is wrong",
    );
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == conformance_harness::ConformanceDeltaKind::ErrorFormatChange)
    );
}

// ---------- classify_conformance_delta timing change ----------

#[test]
fn classify_conformance_delta_timing_change_numeric_only() {
    let deltas =
        conformance_harness::classify_conformance_delta("elapsed 100 ms", "elapsed 200 ms");
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == conformance_harness::ConformanceDeltaKind::TimingChange)
    );
}

// ---------- classify_failure_class empty deltas ----------

#[test]
fn classify_failure_class_empty_deltas_returns_behavioral() {
    let result = conformance_harness::classify_failure_class(&[]);
    assert_eq!(
        result,
        conformance_harness::ConformanceFailureClass::Behavioral
    );
}

// ---------- severity_for_failure_class mapping ----------

#[test]
fn severity_for_failure_class_breaking_is_critical() {
    let sev = conformance_harness::severity_for_failure_class(
        conformance_harness::ConformanceFailureClass::Breaking,
    );
    assert_eq!(
        sev,
        conformance_harness::ConformanceFailureSeverity::Critical
    );
}

#[test]
fn severity_for_failure_class_behavioral_is_error() {
    let sev = conformance_harness::severity_for_failure_class(
        conformance_harness::ConformanceFailureClass::Behavioral,
    );
    assert_eq!(sev, conformance_harness::ConformanceFailureSeverity::Error);
}

#[test]
fn severity_for_failure_class_observability_is_warning() {
    let sev = conformance_harness::severity_for_failure_class(
        conformance_harness::ConformanceFailureClass::Observability,
    );
    assert_eq!(
        sev,
        conformance_harness::ConformanceFailureSeverity::Warning
    );
}

#[test]
fn severity_for_failure_class_performance_is_warning() {
    let sev = conformance_harness::severity_for_failure_class(
        conformance_harness::ConformanceFailureClass::Performance,
    );
    assert_eq!(
        sev,
        conformance_harness::ConformanceFailureSeverity::Warning
    );
}

// ---------- ConformanceReplayVerificationError Display ----------

#[test]
fn replay_verification_error_display_failure_not_reproduced() {
    let err = conformance_harness::ConformanceReplayVerificationError::FailureNotReproduced;
    let msg = format!("{err}");
    assert!(msg.contains("outputs are equal"));
}

#[test]
fn replay_verification_error_display_delta_drift() {
    let err = conformance_harness::ConformanceReplayVerificationError::DeltaClassificationDrift;
    let msg = format!("{err}");
    assert!(msg.contains("delta classification drifted"));
}

#[test]
fn replay_verification_error_display_digest_mismatch() {
    let err = conformance_harness::ConformanceReplayVerificationError::DigestMismatch {
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("aaa"));
    assert!(msg.contains("bbb"));
}

// ---------- ConformanceAssetManifest CURRENT_SCHEMA constant ----------

#[test]
fn conformance_asset_manifest_current_schema_is_nonempty() {
    let schema = conformance_harness::ConformanceAssetManifest::CURRENT_SCHEMA;
    assert!(!schema.is_empty());
    assert!(schema.starts_with("franken-engine.conformance-assets."));
}

// ---------- canonicalize_conformance_output props dedup ----------

#[test]
fn canonicalize_conformance_output_deduplicates_props() {
    let raw = "props: alpha, alpha, beta, beta";
    let result = conformance_harness::canonicalize_conformance_output(raw);
    assert_eq!(result, "props:alpha,beta");
}

// ---------- DeterministicRng clone and copy ----------

#[test]
fn deterministic_rng_clone_and_copy_semantics() {
    let original = conformance_harness::DeterministicRng::seeded(77);
    let cloned = original.clone();
    let copied = original;
    assert_eq!(original, cloned);
    assert_eq!(original, copied);
}

// ---------- ConformanceRunResult clone and debug ----------

#[test]
fn conformance_run_result_clone_preserves_equality() {
    let result = conformance_harness::ConformanceRunResult {
        run_id: "run-clone".to_string(),
        asset_manifest_hash: "hash-clone".to_string(),
        logs: vec![],
        summary: conformance_harness::ConformanceRunSummary {
            run_id: "run-clone".to_string(),
            asset_manifest_hash: "hash-clone".to_string(),
            total_assets: 0,
            passed: 0,
            failed: 0,
            waived: 0,
            errored: 0,
            env_fingerprint: "fp-clone".to_string(),
        },
        minimized_repros: vec![],
    };
    let cloned = result.clone();
    assert_eq!(result, cloned);
    let dbg = format!("{result:?}");
    assert!(dbg.contains("run-clone"));
}

// ---------- manifest assets expected_output_hash is hex-like ----------

#[test]
fn every_asset_fixture_hash_is_hex_like() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        let hash = asset["fixture_hash"].as_str().expect("fixture_hash");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "fixture_hash for {} should be hex, got: {}",
            asset["asset_id"],
            hash
        );
    }
}

// ---------- manifest assets expected_output_hash is hex-like ----------

#[test]
fn every_asset_expected_output_hash_is_hex_like() {
    let assets = parse_manifest_assets();
    for asset in &assets {
        let hash = asset["expected_output_hash"]
            .as_str()
            .expect("expected_output_hash");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "expected_output_hash for {} should be hex, got: {}",
            asset["asset_id"],
            hash
        );
    }
}

// ---------- BTreeMap ordering for source_labels and sink_clearances ----------

#[test]
fn ifc_source_labels_ordering_is_deterministic_in_btreeset() {
    let mut set = BTreeSet::new();
    for label in REQUIRED_SOURCE_LABELS.iter().rev() {
        set.insert(label.to_string());
    }
    let sorted: Vec<_> = set.into_iter().collect();
    let mut expected = REQUIRED_SOURCE_LABELS
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(sorted, expected);
}

// ---------- ConformanceAssetRecord optional fields default to None/empty ----------

#[test]
fn conformance_asset_record_optional_fields_default_when_absent() {
    let json = r#"{
        "asset_id": "test-opt",
        "source_donor": "test",
        "semantic_domain": "test/basic",
        "normative_reference": "test-ref",
        "fixture_path": "f.json",
        "fixture_hash": "aabb",
        "expected_output_path": "e.txt",
        "expected_output_hash": "ccdd",
        "import_date": "2026-01-01"
    }"#;
    let record: conformance_harness::ConformanceAssetRecord =
        serde_json::from_str(json).expect("deserialize with defaults");
    assert!(record.category.is_none());
    assert!(record.source_labels.is_empty());
    assert!(record.sink_clearances.is_empty());
    assert!(record.flow_path_type.is_none());
    assert!(record.expected_outcome.is_none());
    assert!(record.expected_evidence_type.is_none());
}
