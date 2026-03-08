#[path = "../src/conformance_harness.rs"]
mod conformance_harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use conformance_harness::{
    ConformanceEvidenceCollector, ConformanceManifestError, ConformanceRunner,
    ConformanceRunnerConfig, ConformanceWaiverSet, DonorHarnessAdapter, DonorHarnessApi,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn test_temp_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-engine-conformance-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn sample_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/transplanted/conformance_assets.json")
}

fn sample_waiver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance_waivers.toml")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn copy_tree(src: &Path, dst: &Path) {
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

fn update_expected_hash_for_asset(manifest_path: &Path, asset_id: &str, expected_file: &Path) {
    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("manifest read"))
            .expect("manifest parse");
    let hash = sha256_hex(&fs::read(expected_file).expect("expected bytes"));

    let assets = manifest["assets"]
        .as_array_mut()
        .expect("assets should be an array");
    for asset in assets {
        if asset["asset_id"] == asset_id {
            asset["expected_output_hash"] = Value::String(hash.clone());
        }
    }

    let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest serialize");
    fs::write(manifest_path, bytes).expect("manifest write");
}

#[test]
fn transplanted_manifest_runs_and_emits_conformance_evidence_artifact() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");

    let run = runner
        .run(sample_manifest_path(), &waivers)
        .expect("conformance run");

    assert_eq!(run.summary.total_assets, 10);
    assert_eq!(run.summary.failed, 0);
    assert_eq!(run.summary.errored, 0);
    assert!(run.logs.iter().all(|log| log.outcome == "pass"));
    run.enforce_ci_gate().expect("ci gate pass");

    // Verify all 10 semantic domains are represented in the run logs.
    let domains: std::collections::BTreeSet<&str> = run
        .logs
        .iter()
        .map(|log| log.semantic_domain.as_str())
        .collect();
    let expected_domains = [
        "promise_resolution",
        "proxy_trap_ordering",
        "closure_capture",
        "destructuring_binding",
        "iterator_protocol",
        "generator_lifecycle",
        "async_await_ordering",
        "symbol_behavior",
        "error_handling",
        "module_namespace_binding",
    ];
    for domain in &expected_domains {
        assert!(
            domains.contains(domain),
            "missing semantic domain in run logs: {domain}"
        );
    }

    let collector =
        ConformanceEvidenceCollector::new(test_temp_dir("evidence")).expect("collector");
    let artifacts = collector.collect(&run).expect("collect artifacts");

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.conformance_evidence_path.exists());

    let evidence = fs::read_to_string(artifacts.conformance_evidence_path).expect("evidence read");
    let first_line = evidence.lines().next().expect("summary line");
    assert!(first_line.contains("asset_manifest_hash"));
    assert!(first_line.contains("env_fingerprint"));
}

#[test]
fn harness_adapter_maps_donor_conventions_without_runtime_shims() {
    let adapter = DonorHarnessAdapter;
    let source = "$262.createRealm(); $DONE(print('ok'));";
    let adapted = adapter.adapt_source(source);

    assert!(adapted.contains("__franken_create_realm()"));
    assert!(adapted.contains("__franken_done"));
    assert!(adapted.contains("franken_print("));
}

#[test]
fn manifest_integrity_meta_test_detects_tampered_fixture_hash() {
    let source_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/transplanted");
    let temp_root = test_temp_dir("tamper").join("transplanted");
    copy_tree(&source_root, &temp_root);

    let fixture_path = temp_root.join("fixtures/promise_resolution.fixture.json");
    fs::write(
        &fixture_path,
        "{\"donor_harness\":\"quickjs\",\"source\":\"$DONE()\",\"observed_output\":\"tampered\"}",
    )
    .expect("tamper fixture");

    let manifest_path = temp_root.join("conformance_assets.json");
    let err = ConformanceRunner::default()
        .run(&manifest_path, &ConformanceWaiverSet::default())
        .expect_err("tampered fixture hash should fail");

    match err {
        conformance_harness::ConformanceRunError::Manifest(
            ConformanceManifestError::FixtureHashMismatch { asset_id, .. },
        ) => {
            assert_eq!(asset_id, "asset-promise-resolution");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn waiver_enforcement_meta_test_blocks_unwaived_and_accepts_waived_failures() {
    let source_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/transplanted");
    let temp_root = test_temp_dir("waivers").join("transplanted");
    copy_tree(&source_root, &temp_root);

    let manifest_path = temp_root.join("conformance_assets.json");
    let expected_path = temp_root.join("expected/proxy_trap_ordering.expected.txt");

    // Force one deterministic mismatch, then refresh manifest hash so integrity checks still pass.
    fs::write(&expected_path, "mismatch output\nprops:q,p").expect("rewrite expected output");
    update_expected_hash_for_asset(&manifest_path, "asset-proxy-trap-ordering", &expected_path);

    let runner = ConformanceRunner::default();
    let run_unwaived = runner
        .run(&manifest_path, &ConformanceWaiverSet::default())
        .expect("unwaived run");
    assert_eq!(run_unwaived.summary.failed, 1);
    assert_eq!(run_unwaived.summary.waived, 0);
    assert!(run_unwaived.enforce_ci_gate().is_err());

    let waiver_path = temp_root.join("conformance_waivers.toml");
    fs::write(
        &waiver_path,
        r#"[[waiver]]
asset_id = "asset-proxy-trap-ordering"
reason_code = "harness_gap"
tracking_bead = "bd-d93"
expiry_date = "2027-12-31"
"#,
    )
    .expect("waiver write");
    let waivers = ConformanceWaiverSet::load_toml(&waiver_path).expect("waiver parse");

    let run_waived = runner.run(&manifest_path, &waivers).expect("waived run");
    assert_eq!(run_waived.summary.failed, 0);
    assert_eq!(run_waived.summary.waived, 1);
    run_waived
        .enforce_ci_gate()
        .expect("waived should pass gate");
}

#[test]
fn determinism_meta_test_same_seed_matches_different_seed_changes_output() {
    let manifest_path = sample_manifest_path();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");

    let runner_a = ConformanceRunner {
        config: ConformanceRunnerConfig {
            seed: 19,
            run_date: "2026-02-20".to_string(),
            ..ConformanceRunnerConfig::default()
        },
        ..ConformanceRunner::default()
    };
    let runner_b = runner_a.clone();

    let run_a = runner_a.run(&manifest_path, &waivers).expect("run_a");
    let run_b = runner_b.run(&manifest_path, &waivers).expect("run_b");
    assert_eq!(run_a.logs, run_b.logs);
    assert_eq!(run_a.summary, run_b.summary);

    let runner_c = ConformanceRunner {
        config: ConformanceRunnerConfig {
            seed: 20,
            run_date: "2026-02-20".to_string(),
            ..ConformanceRunnerConfig::default()
        },
        ..ConformanceRunner::default()
    };

    let run_c = runner_c.run(&manifest_path, &waivers).expect("run_c");
    assert_ne!(run_a.logs, run_c.logs);
}

#[test]
fn per_asset_structured_logs_contain_required_fields() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");
    let run = runner
        .run(sample_manifest_path(), &waivers)
        .expect("conformance run");

    assert_eq!(run.logs.len(), 10, "should have one log entry per asset");

    for log in &run.logs {
        assert!(
            !log.trace_id.is_empty(),
            "log for {} missing trace_id",
            log.asset_id
        );
        assert!(
            !log.asset_id.is_empty(),
            "log for {} missing asset_id",
            log.asset_id
        );
        assert!(
            !log.semantic_domain.is_empty(),
            "log for {} missing semantic_domain",
            log.asset_id
        );
        assert!(
            ["pass", "fail", "waived", "error"].contains(&log.outcome.as_str()),
            "log for {} has invalid outcome: {}",
            log.asset_id,
            log.outcome
        );
        assert!(
            log.duration_us > 0,
            "log for {} has zero duration_us",
            log.asset_id
        );
    }
}

#[test]
fn evidence_artifact_schema_meta_test_validates_required_fields() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");
    let run = runner
        .run(sample_manifest_path(), &waivers)
        .expect("conformance run");

    let collector =
        ConformanceEvidenceCollector::new(test_temp_dir("schema-meta")).expect("collector");
    let artifacts = collector.collect(&run).expect("collect artifacts");

    // Validate run manifest JSON schema.
    let manifest_json: Value =
        serde_json::from_str(&fs::read_to_string(&artifacts.run_manifest_path).expect("read"))
            .expect("parse run manifest");
    assert!(
        manifest_json.get("total_assets").is_some(),
        "run manifest missing total_assets"
    );
    assert!(
        manifest_json.get("passed").is_some(),
        "run manifest missing passed"
    );
    assert!(
        manifest_json.get("failed").is_some(),
        "run manifest missing failed"
    );
    assert!(
        manifest_json.get("waived").is_some(),
        "run manifest missing waived"
    );
    assert!(
        manifest_json.get("asset_manifest_hash").is_some(),
        "run manifest missing asset_manifest_hash"
    );

    // Validate each JSONL evidence line.
    let evidence = fs::read_to_string(&artifacts.conformance_evidence_path).expect("read");
    let lines: Vec<&str> = evidence.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "conformance_evidence.jsonl should not be empty"
    );

    for line in &lines {
        let val: Value = serde_json::from_str(line).expect("each evidence line must be valid JSON");
        // Summary line has asset_manifest_hash, per-asset lines have asset_id.
        let is_summary = val.get("asset_manifest_hash").is_some();
        let is_asset = val.get("asset_id").is_some();
        assert!(
            is_summary || is_asset,
            "evidence line must be summary or asset record: {line}"
        );
    }
}

#[test]
fn expanded_manifest_covers_all_semantic_domains_from_spec() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");

    let domains: std::collections::BTreeSet<String> = manifest
        .assets
        .iter()
        .map(|a| a.semantic_domain.clone())
        .collect();

    // These are the mandatory ES2020 semantic domains for transplanted conformance.
    let required = [
        "promise_resolution",
        "proxy_trap_ordering",
        "closure_capture",
        "destructuring_binding",
        "iterator_protocol",
        "generator_lifecycle",
        "async_await_ordering",
        "symbol_behavior",
        "error_handling",
        "module_namespace_binding",
    ];

    for domain in &required {
        assert!(
            domains.contains(*domain),
            "manifest missing required semantic domain: {domain}"
        );
    }
    assert_eq!(
        manifest.assets.len(),
        10,
        "manifest should have exactly 10 transplanted assets"
    );
}

#[test]
fn non_determinism_detection_runs_10x_with_identical_output() {
    let manifest_path = sample_manifest_path();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");

    let runner = ConformanceRunner {
        config: ConformanceRunnerConfig {
            seed: 42,
            run_date: "2026-02-22".to_string(),
            ..ConformanceRunnerConfig::default()
        },
        ..ConformanceRunner::default()
    };

    let baseline = runner
        .clone()
        .run(&manifest_path, &waivers)
        .expect("baseline run");

    // Run 9 more times and verify bitwise-identical log output.
    for i in 1..10 {
        let repeat = runner
            .clone()
            .run(&manifest_path, &waivers)
            .unwrap_or_else(|e| panic!("run {i} failed: {e}"));
        assert_eq!(
            baseline.logs, repeat.logs,
            "non-determinism detected on run {i}: logs differ from baseline"
        );
        assert_eq!(
            baseline.summary, repeat.summary,
            "non-determinism detected on run {i}: summary differs from baseline"
        );
    }
}

#[test]
fn sha256_hex_is_deterministic() {
    let input = b"franken-engine conformance test";
    let a = sha256_hex(input);
    let b = sha256_hex(input);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64, "sha256 hex must be 64 characters");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha256_hex_empty_input_produces_known_hash() {
    let hash = sha256_hex(b"");
    // SHA-256 of empty input is the well-known constant
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn manifest_asset_ids_are_unique() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    let mut seen = std::collections::BTreeSet::new();
    for asset in &manifest.assets {
        assert!(
            seen.insert(&asset.asset_id),
            "duplicate asset_id: {}",
            asset.asset_id
        );
    }
}

#[test]
fn default_waiver_set_has_no_waivers() {
    let waivers = ConformanceWaiverSet::default();
    let runner = ConformanceRunner::default();
    let run = runner
        .run(sample_manifest_path(), &waivers)
        .expect("conformance run with default waivers");
    assert_eq!(run.summary.waived, 0);
}

#[test]
fn sample_waiver_path_exists() {
    let path = sample_waiver_path();
    assert!(path.exists(), "waiver path must exist: {}", path.display());
}

#[test]
fn manifest_assets_have_nonempty_semantic_domains() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    for asset in &manifest.assets {
        assert!(
            !asset.semantic_domain.trim().is_empty(),
            "asset {} has empty semantic_domain",
            asset.asset_id
        );
    }
}

#[test]
fn manifest_assets_have_nonempty_expected_output_hashes() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    for asset in &manifest.assets {
        assert!(
            !asset.expected_output_hash.trim().is_empty(),
            "asset {} has empty expected_output_hash",
            asset.asset_id
        );
    }
}

#[test]
fn all_conformance_logs_have_unique_trace_ids() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");
    let run = runner
        .run(sample_manifest_path(), &waivers)
        .expect("conformance run");
    let trace_ids: std::collections::BTreeSet<&str> =
        run.logs.iter().map(|log| log.trace_id.as_str()).collect();
    // Each asset gets its own unique trace_id
    assert_eq!(
        trace_ids.len(),
        run.logs.len(),
        "each conformance asset must have a unique trace_id"
    );
}

#[test]
fn manifest_assets_have_nonempty_asset_ids() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    for asset in &manifest.assets {
        assert!(
            !asset.asset_id.trim().is_empty(),
            "asset must have non-empty asset_id"
        );
    }
}

#[test]
fn sha256_hex_different_inputs_produce_different_hashes() {
    let a = sha256_hex(b"input_a");
    let b = sha256_hex(b"input_b");
    assert_ne!(a, b, "different inputs must produce different hashes");
}

#[test]
fn conformance_runner_default_seed_is_deterministic() {
    let r1 = ConformanceRunner::default();
    let r2 = ConformanceRunner::default();
    assert_eq!(r1.config.seed, r2.config.seed);
}

#[test]
fn conformance_manifest_deterministic_double_load() {
    let a = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load a");
    let b = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load b");
    assert_eq!(a.assets.len(), b.assets.len());
}

#[test]
fn sha256_hex_nonempty_for_nonempty_input() {
    let hash = sha256_hex(b"test input");
    assert!(!hash.is_empty());
    assert!(hash.len() == 64, "sha256 hex should be 64 chars");
}

#[test]
fn conformance_runner_config_default_is_constructible() {
    let config = ConformanceRunnerConfig::default();
    let _ = config.seed; // seed is always valid (u64)
}

#[test]
fn sample_manifest_file_exists() {
    assert!(
        sample_manifest_path().exists(),
        "sample manifest fixture must exist"
    );
}

#[test]
fn conformance_runner_config_debug_is_nonempty() {
    let config = ConformanceRunnerConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn conformance_waiver_set_debug_is_nonempty() {
    let waivers = ConformanceWaiverSet::default();
    assert!(!format!("{waivers:?}").is_empty());
}

#[test]
fn manifest_expected_output_hashes_are_valid_sha256_hex() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    for asset in &manifest.assets {
        let hash = &asset.expected_output_hash;
        assert_eq!(
            hash.len(),
            64,
            "asset {} expected_output_hash length should be 64, got {}",
            asset.asset_id,
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "asset {} expected_output_hash contains non-hex chars",
            asset.asset_id
        );
    }
}

#[test]
fn manifest_fixture_hashes_are_valid_sha256_hex() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    for asset in &manifest.assets {
        let hash = &asset.fixture_hash;
        assert_eq!(
            hash.len(),
            64,
            "asset {} fixture_hash length should be 64, got {}",
            asset.asset_id,
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "asset {} fixture_hash contains non-hex chars",
            asset.asset_id
        );
    }
}

#[test]
fn copy_tree_reproduces_directory_structure() {
    let src = test_temp_dir("copy-src");
    let dst = test_temp_dir("copy-dst");

    // Create a nested structure in src
    let sub = src.join("sub");
    fs::create_dir_all(&sub).expect("create subdir");
    fs::write(src.join("root.txt"), "root-content").expect("write root");
    fs::write(sub.join("nested.txt"), "nested-content").expect("write nested");

    copy_tree(&src, &dst);

    assert_eq!(
        fs::read_to_string(dst.join("root.txt")).expect("read root copy"),
        "root-content"
    );
    assert_eq!(
        fs::read_to_string(dst.join("sub/nested.txt")).expect("read nested copy"),
        "nested-content"
    );
}

#[test]
fn harness_adapter_preserves_non_donor_code() {
    let adapter = DonorHarnessAdapter;
    let source = "let x = 42;\nconsole.log(x);";
    let adapted = adapter.adapt_source(source);
    // No donor-specific patterns, so output should be identical
    assert_eq!(adapted, source);
}

#[test]
fn manifest_asset_records_have_nonempty_source_donor() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    for asset in &manifest.assets {
        assert!(
            !asset.source_donor.trim().is_empty(),
            "asset {} has empty source_donor",
            asset.asset_id
        );
    }
}

#[test]
fn manifest_serde_roundtrip_preserves_all_fields() {
    let manifest = conformance_harness::ConformanceAssetManifest::load(sample_manifest_path())
        .expect("load manifest");
    let json = serde_json::to_string(&manifest).expect("serialize");
    let recovered: conformance_harness::ConformanceAssetManifest =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest.schema_version, recovered.schema_version);
    assert_eq!(manifest.assets.len(), recovered.assets.len());
    for (orig, recov) in manifest.assets.iter().zip(recovered.assets.iter()) {
        assert_eq!(orig.asset_id, recov.asset_id);
        assert_eq!(orig.semantic_domain, recov.semantic_domain);
        assert_eq!(orig.fixture_hash, recov.fixture_hash);
        assert_eq!(orig.expected_output_hash, recov.expected_output_hash);
    }
}

#[test]
fn conformance_run_summary_total_equals_passed_plus_failed_plus_waived() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");
    let run = runner
        .run(sample_manifest_path(), &waivers)
        .expect("conformance run");
    assert_eq!(
        run.summary.total_assets,
        run.summary.passed + run.summary.failed + run.summary.waived + run.summary.errored,
        "total_assets must equal passed + failed + waived + errored"
    );
}
