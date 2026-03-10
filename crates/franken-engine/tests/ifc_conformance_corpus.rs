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
