//! Cross-platform reproducibility integration tests.
//!
//! Exercises the public `cross_platform_reproducibility` harness end-to-end:
//! standard-suite generation, the `ContentHash` reproducibility primitive, the
//! `execute_test`/`run_test_suite` orchestration path, and lossless JSON export.
//!
//! These tests run with a worker registry that has **no platform managers
//! configured** (`platform_configs` empty) and `retry_attempts: 0`. That makes
//! every per-platform execution fail-closed immediately with
//! `PlatformNotConfigured`/`PlatformNotImplemented` — no `bash`/`node`
//! shell-out, no remote SSH, no sleeps — so the harness logic is exercised
//! deterministically regardless of what is installed on the host. The actual
//! "byte-identical successful execution across real macOS/Windows/Linux
//! workers" assertion is preserved as an `#[ignore]`d test below; it requires
//! provisioned remote workers (bd-bg9l1.15 follow-up).
//!
//! History: this file previously held only `test_stub_..._disabled`, a
//! `println!` placeholder, because the underlying modules were said to have
//! compilation errors. Those modules (`cross_platform_reproducibility`,
//! `rch_worker_registry`, `worker_env_capture`, `macos_arm64_worker`,
//! `windows_x64_worker`) are now `pub mod`s that build with the crate, so the
//! suite is re-enabled here against the real public API (bd-bg9l1.15).

use std::collections::BTreeMap;

use frankenengine_engine::cross_platform_reproducibility::{
    CrossPlatformReproducibilityTester, ModuleType, OutputType, ReproducibilityTestConfig,
    ReproducibilityTestInput, ReproducibilityTestResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::rch_worker_registry::{
    RchWorkerRegistry, RchWorkerRegistryConfig, WorkerPlatform,
};

/// The three platforms the default reproducibility config targets.
const DEFAULT_TARGETS: [WorkerPlatform; 3] = [
    WorkerPlatform::MacOSArm64,
    WorkerPlatform::WindowsX64,
    WorkerPlatform::LinuxX64,
];

/// Build a tester whose worker registry has no platform managers configured,
/// so every execution fail-closes immediately (no shell-out, no retries). This
/// isolates the harness orchestration + hashing logic from any host tooling.
fn workerless_tester() -> CrossPlatformReproducibilityTester {
    let registry = RchWorkerRegistry::new(RchWorkerRegistryConfig {
        base_work_dir: std::env::temp_dir().join("frankenengine_repro_test_workers"),
        max_workers_per_platform: 1,
        verbose: false,
        platform_configs: BTreeMap::new(),
    });
    let config = ReproducibilityTestConfig {
        retry_attempts: 0,
        ..ReproducibilityTestConfig::default()
    };
    CrossPlatformReproducibilityTester::new(registry, config)
}

#[test]
fn standard_test_suite_is_a_stable_nonempty_contract() {
    let suite = CrossPlatformReproducibilityTester::generate_standard_test_suite();

    assert_eq!(
        suite.len(),
        10,
        "the standard reproducibility suite is a fixed 10-case contract"
    );

    let mut ids: Vec<&str> = suite.iter().map(|t| t.test_id.as_str()).collect();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "every test_id must be unique");

    for case in &suite {
        assert!(
            !case.source_code.trim().is_empty(),
            "case {} must carry real source to execute",
            case.test_id
        );
        assert!(
            !case.description.trim().is_empty(),
            "case {} must describe what it verifies",
            case.test_id
        );
        assert!(
            case.deterministic,
            "every standard-suite case is a determinism check (case {})",
            case.test_id
        );
        assert_eq!(
            case.output_type,
            OutputType::Stdout,
            "standard suite compares stdout (case {})",
            case.test_id
        );
        assert_eq!(case.module_type, ModuleType::Script);
    }

    // A representative member is present (guards against silent suite gutting).
    ids.sort_unstable();
    assert!(ids.contains(&"basic_arithmetic"));
    assert!(ids.contains(&"json_operations"));
}

#[test]
fn standard_test_suite_generation_is_deterministic() {
    // The input corpus itself must be byte-stable run to run — it is the
    // baseline artifact every cross-platform comparison is anchored against.
    let a = CrossPlatformReproducibilityTester::generate_standard_test_suite();
    let b = CrossPlatformReproducibilityTester::generate_standard_test_suite();
    assert_eq!(a, b, "standard suite generation must be deterministic");
}

#[test]
fn default_config_targets_macos_windows_and_linux() {
    let config = ReproducibilityTestConfig::default();
    assert_eq!(
        config.target_platforms, DEFAULT_TARGETS,
        "default config must fan out across macOS/Windows/Linux"
    );
    assert!(
        config.max_execution_time_seconds > 0,
        "a per-test timeout must be set"
    );
}

#[test]
fn content_hash_is_deterministic_and_collision_distinct() {
    // ContentHash is the load-bearing reproducibility primitive: identical
    // bytes => identical hash; differing bytes => differing hash.
    let payload = b"console.log(1 + 2 * 3)";
    assert_eq!(
        ContentHash::compute(payload),
        ContentHash::compute(payload),
        "same bytes must hash identically"
    );
    assert_ne!(
        ContentHash::compute(b"7"),
        ContentHash::compute(b"8"),
        "different bytes must hash differently"
    );
    // Hex rendering is stable too (used in divergence reports).
    assert_eq!(
        ContentHash::compute(payload).to_hex(),
        ContentHash::compute(payload).to_hex()
    );
}

#[test]
fn run_test_suite_exercises_every_platform_and_is_honest_without_workers() {
    let mut tester = workerless_tester();
    let results = tester
        .run_test_suite()
        .expect("run_test_suite must complete even when no workers are configured");

    assert_eq!(
        results.len(),
        CrossPlatformReproducibilityTester::generate_standard_test_suite().len(),
        "one result per standard-suite input"
    );

    for result in &results {
        let platforms: Vec<WorkerPlatform> = result.platform_results.keys().copied().collect();
        assert_eq!(
            platforms, DEFAULT_TARGETS,
            "each test must be attempted on every target platform"
        );

        // No managers are configured, so every platform fail-closes — the
        // harness must report that honestly rather than fake a green pass.
        for (platform, exec) in &result.platform_results {
            assert!(
                !exec.success,
                "platform {} has no configured worker, so execution cannot succeed",
                platform.as_str()
            );
            assert!(
                exec.error.is_some(),
                "a failed execution must carry an error message ({})",
                platform.as_str()
            );
        }

        // With zero successful executions, verify_reproducibility returns
        // false and short-circuits before recording divergences.
        assert!(
            !result.reproducible,
            "no successful executions => not reproducible"
        );
        assert!(
            result.expected_content_hash.is_none(),
            "no successful execution => no reference hash"
        );
        assert!(
            result.divergences.is_empty(),
            "the empty-success short-circuit records no divergences"
        );
    }
}

#[test]
fn execute_test_is_deterministic_modulo_timestamp() {
    let input = ReproducibilityTestInput {
        test_id: "harness_determinism".to_string(),
        description: "harness must produce identical artifacts run to run".to_string(),
        source_code: "console.log('stable')".to_string(),
        output_type: OutputType::Stdout,
        module_type: ModuleType::Script,
        flags: vec![],
        deterministic: true,
    };

    let mut tester = workerless_tester();
    let first = tester.execute_test(input.clone()).expect("first run");
    let second = tester.execute_test(input.clone()).expect("second run");

    // `executed_at` is a wall-clock stamp and is expected to differ; every
    // other field is the harness's deterministic output and must match.
    assert_eq!(first.test_input, second.test_input);
    assert_eq!(first.reproducible, second.reproducible);
    assert_eq!(first.expected_content_hash, second.expected_content_hash);
    assert_eq!(first.divergences, second.divergences);

    let keys_first: Vec<WorkerPlatform> = first.platform_results.keys().copied().collect();
    let keys_second: Vec<WorkerPlatform> = second.platform_results.keys().copied().collect();
    assert_eq!(keys_first, keys_second);

    for platform in keys_first {
        let a = &first.platform_results[&platform];
        let b = &second.platform_results[&platform];
        assert_eq!(a.content_hash, b.content_hash, "{}", platform.as_str());
        assert_eq!(a.exit_code, b.exit_code, "{}", platform.as_str());
        assert_eq!(a.success, b.success, "{}", platform.as_str());
        assert_eq!(a.platform, platform);
    }
}

#[test]
fn execute_test_echoes_input_and_covers_targets() {
    let input = ReproducibilityTestInput {
        test_id: "echo_check".to_string(),
        description: "result must echo its input".to_string(),
        source_code: "console.log(42)".to_string(),
        output_type: OutputType::Stdout,
        module_type: ModuleType::Script,
        flags: vec!["--strict".to_string()],
        deterministic: true,
    };

    let mut tester = workerless_tester();
    let result = tester.execute_test(input.clone()).expect("execute_test");

    assert_eq!(
        result.test_input, input,
        "result must carry the exact input"
    );
    let platforms: Vec<WorkerPlatform> = result.platform_results.keys().copied().collect();
    assert_eq!(platforms, DEFAULT_TARGETS);
}

#[test]
fn export_results_round_trips_losslessly() {
    let mut tester = workerless_tester();
    let results = tester.run_test_suite().expect("run_test_suite");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("repro_results.json");
    CrossPlatformReproducibilityTester::export_results(&results, &path)
        .expect("export must succeed");

    let json = std::fs::read_to_string(&path).expect("read exported json");
    let restored: Vec<ReproducibilityTestResult> =
        serde_json::from_str(&json).expect("exported JSON must deserialize back");

    assert_eq!(
        restored, results,
        "exported reproducibility results must round-trip byte-for-byte through serde"
    );
}

#[test]
#[ignore = "bd-bg9l1.15 follow-up: requires provisioned remote macOS/Windows/Linux \
            workers (RchWorkerRegistry with real platform_configs). With workers \
            configured, run_test_suite() over the deterministic standard suite must \
            yield reproducible == true and an expected_content_hash shared by every \
            platform. Un-ignore once a worker pool is available in CI."]
fn real_cross_platform_execution_is_byte_identical() {
    let mut tester = CrossPlatformReproducibilityTester::with_defaults();
    let results = tester.run_test_suite().expect("run_test_suite");
    for result in &results {
        assert!(
            result.reproducible,
            "deterministic case {} must be byte-identical across platforms",
            result.test_input.test_id
        );
        assert!(result.expected_content_hash.is_some());
    }
}
