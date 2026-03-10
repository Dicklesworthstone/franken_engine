//! Integration tests for the React package cohort validation and resolver
//! behaviour module (RGC-405A).

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenengine_engine::react_package_cohort::{
    build_cohort_matrix, build_cohort_matrix_with_edges, build_manifest,
    build_manifest_with_aliases, cohort_coverage_millionths, detect_alias_loops, format_compatible,
    franken_engine_react_cohort_manifest, resolve_alias_chain, resolve_subpath,
    resolve_subpath_with_fallbacks, validate_cohort, validate_edge_case, verify_format_consistency,
    write_react_package_cohort_bundle, CohortError, CohortMatrix, CohortValidationReport, EdgeCase,
    ExportCondition, ModuleFormat, PackageManifest, ReactCohortEvent, ReactCohortRunManifest,
    ReactCohortTraceIds, ReactCohortWriteError, ReactPackage, SubpathEntry,
    REACT_COHORT_BEAD_ID, REACT_COHORT_COMPONENT, REACT_COHORT_EVENT_SCHEMA_VERSION,
    REACT_COHORT_POLICY_ID, REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION, REACT_COHORT_SCHEMA_VERSION,
    REACT_COHORT_TRACE_IDS_SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static NEXT_TEMP_DIR_ID: AtomicU64 = AtomicU64::new(0);

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let sequence = NEXT_TEMP_DIR_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "franken-react-package-cohort-{prefix}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sample_subpath(
    sub: &str,
    cond: ExportCondition,
    path: &str,
    fmt: ModuleFormat,
) -> SubpathEntry {
    SubpathEntry::new(sub, vec![cond], path, fmt)
}

fn sample_react_manifest() -> PackageManifest {
    let subpaths = vec![
        sample_subpath(".", ExportCondition::Import, "./esm/react.js", ModuleFormat::Esm),
        sample_subpath(".", ExportCondition::Require, "./cjs/react.js", ModuleFormat::Cjs),
        sample_subpath(".", ExportCondition::Default, "./cjs/react.js", ModuleFormat::Cjs),
        sample_subpath(
            "./jsx-runtime",
            ExportCondition::Import,
            "./esm/jsx-runtime.js",
            ModuleFormat::Esm,
        ),
        sample_subpath(
            "./jsx-runtime",
            ExportCondition::Require,
            "./cjs/jsx-runtime.js",
            ModuleFormat::Cjs,
        ),
    ];
    build_manifest(ReactPackage::React, "18.3.1", subpaths)
}

fn manifest_with_aliases() -> PackageManifest {
    let subpaths = vec![
        sample_subpath(
            "./server.browser",
            ExportCondition::Import,
            "./esm/server.browser.js",
            ModuleFormat::Esm,
        ),
        sample_subpath(
            "./server.node",
            ExportCondition::Node,
            "./cjs/server.node.js",
            ModuleFormat::Cjs,
        ),
    ];
    let mut aliases = BTreeMap::new();
    aliases.insert("./server".to_string(), "./server.browser".to_string());
    build_manifest_with_aliases(ReactPackage::ReactDomServer, "18.3.1", subpaths, aliases)
}

// ---------------------------------------------------------------------------
// ReactPackage enum
// ---------------------------------------------------------------------------

#[test]
fn test_react_package_all_variants_and_npm_names() {
    assert_eq!(ReactPackage::ALL.len(), 7);
    // react sub-packages share "react" npm name
    assert_eq!(ReactPackage::React.npm_name(), "react");
    assert_eq!(ReactPackage::ReactJsxRuntime.npm_name(), "react");
    assert_eq!(ReactPackage::ReactJsxDevRuntime.npm_name(), "react");
    // react-dom sub-packages share "react-dom" npm name
    assert_eq!(ReactPackage::ReactDom.npm_name(), "react-dom");
    assert_eq!(ReactPackage::ReactDomServer.npm_name(), "react-dom");
    // standalone
    assert_eq!(ReactPackage::Scheduler.npm_name(), "scheduler");
    assert_eq!(ReactPackage::ReactReconciler.npm_name(), "react-reconciler");
}

#[test]
fn test_react_package_display_and_ordering() {
    for pkg in ReactPackage::ALL {
        assert_eq!(format!("{}", pkg), pkg.as_str());
    }
    for window in ReactPackage::ALL.windows(2) {
        assert!(window[0] < window[1]);
    }
}

#[test]
fn test_react_package_serde_roundtrip() {
    for pkg in ReactPackage::ALL {
        let json = serde_json::to_string(pkg).unwrap();
        let back: ReactPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(*pkg, back);
    }
}

// ---------------------------------------------------------------------------
// ExportCondition & ModuleFormat
// ---------------------------------------------------------------------------

#[test]
fn test_export_condition_keys_display_and_serde() {
    let expected_keys = [
        "import", "require", "default", "browser", "node", "react-server", "react-native",
    ];
    for (cond, key) in ExportCondition::ALL.iter().zip(expected_keys.iter()) {
        assert_eq!(cond.condition_key(), *key);
        assert_eq!(cond.to_string(), *key);
        let json = serde_json::to_string(cond).unwrap();
        let back: ExportCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(*cond, back);
    }
}

#[test]
fn test_module_format_variants_and_serde() {
    assert_eq!(ModuleFormat::Esm.as_str(), "esm");
    assert_eq!(ModuleFormat::Cjs.as_str(), "cjs");
    assert_eq!(ModuleFormat::Dual.as_str(), "dual");
    for fmt in ModuleFormat::ALL {
        let json = serde_json::to_string(fmt).unwrap();
        let back: ModuleFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(*fmt, back);
    }
}

// ---------------------------------------------------------------------------
// SubpathEntry
// ---------------------------------------------------------------------------

#[test]
fn test_subpath_entry_construction_and_matching() {
    let entry = SubpathEntry::new(
        "./client",
        vec![ExportCondition::Import, ExportCondition::Browser],
        "./esm/client.js",
        ModuleFormat::Esm,
    );
    assert_eq!(entry.subpath, "./client");
    assert_eq!(entry.conditions.len(), 2);
    assert!(entry.matches("./client", &ExportCondition::Import));
    assert!(entry.matches("./client", &ExportCondition::Browser));
    assert!(!entry.matches("./client", &ExportCondition::Require));
    assert!(!entry.matches("./other", &ExportCondition::Import));
}

#[test]
fn test_subpath_entry_display_and_serde() {
    let entry = sample_subpath(
        "./jsx-runtime",
        ExportCondition::Import,
        "./esm/jsx-runtime.js",
        ModuleFormat::Esm,
    );
    let display = entry.to_string();
    assert!(display.contains("./jsx-runtime"));
    assert!(display.contains("./esm/jsx-runtime.js"));
    let json = serde_json::to_string(&entry).unwrap();
    let back: SubpathEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// PackageManifest / build_manifest
// ---------------------------------------------------------------------------

#[test]
fn test_build_manifest_fields_and_counts() {
    let manifest = sample_react_manifest();
    assert_eq!(manifest.package, ReactPackage::React);
    assert_eq!(manifest.version, "18.3.1");
    assert_eq!(manifest.subpath_count(), 5);
    assert_eq!(manifest.alias_count(), 0);
}

#[test]
fn test_build_manifest_deterministic_hash() {
    let m1 = sample_react_manifest();
    let m2 = sample_react_manifest();
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn test_build_manifest_different_versions_different_hash() {
    let subpaths = vec![sample_subpath(
        ".",
        ExportCondition::Import,
        "./esm/react.js",
        ModuleFormat::Esm,
    )];
    let m1 = build_manifest(ReactPackage::React, "18.2.0", subpaths.clone());
    let m2 = build_manifest(ReactPackage::React, "18.3.1", subpaths);
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn test_build_manifest_with_aliases() {
    let manifest = manifest_with_aliases();
    assert_eq!(manifest.alias_count(), 1);
    assert_eq!(manifest.subpath_count(), 2);
}

#[test]
fn test_manifest_condition_coverage() {
    let manifest = sample_react_manifest();
    // Import, Require, Default = 3 out of 7
    let expected = 3u64 * 1_000_000 / 7;
    assert_eq!(manifest.condition_coverage_millionths(), expected);
    // Empty subpaths => 0 coverage
    let empty = build_manifest(ReactPackage::React, "18.3.1", vec![]);
    assert_eq!(empty.condition_coverage_millionths(), 0);
}

#[test]
fn test_manifest_display_and_serde() {
    let manifest = sample_react_manifest();
    let display = manifest.to_string();
    assert!(display.contains("react"));
    assert!(display.contains("18.3.1"));
    assert!(display.contains("5 subpaths"));
    let json = serde_json::to_string(&manifest).unwrap();
    let back: PackageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// resolve_subpath
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_subpath_esm_and_cjs() {
    let manifest = sample_react_manifest();
    let esm = resolve_subpath(&manifest, ".", &ExportCondition::Import).unwrap();
    assert_eq!(esm.resolved_path, "./esm/react.js");
    assert_eq!(esm.format, ModuleFormat::Esm);
    let cjs = resolve_subpath(&manifest, ".", &ExportCondition::Require).unwrap();
    assert_eq!(cjs.resolved_path, "./cjs/react.js");
    assert_eq!(cjs.format, ModuleFormat::Cjs);
}

#[test]
fn test_resolve_subpath_missing_and_wrong_condition() {
    let manifest = sample_react_manifest();
    let err = resolve_subpath(&manifest, "./nonexistent", &ExportCondition::Import).unwrap_err();
    match err {
        CohortError::SubpathMissing(msg) => assert!(msg.contains("nonexistent")),
        other => panic!("expected SubpathMissing, got: {:?}", other),
    }
    assert!(resolve_subpath(&manifest, ".", &ExportCondition::ReactNative).is_err());
}

#[test]
fn test_resolve_subpath_via_alias() {
    let manifest = manifest_with_aliases();
    let entry = resolve_subpath(&manifest, "./server", &ExportCondition::Import).unwrap();
    assert_eq!(entry.resolved_path, "./esm/server.browser.js");
}

// ---------------------------------------------------------------------------
// resolve_subpath_with_fallbacks
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_subpath_with_fallbacks_priority_order() {
    let manifest = sample_react_manifest();
    // Browser misses, Import hits
    let entry = resolve_subpath_with_fallbacks(
        &manifest,
        ".",
        &[ExportCondition::Browser, ExportCondition::Import],
    )
    .unwrap();
    assert_eq!(entry.resolved_path, "./esm/react.js");
    // First hit wins (Import before Require)
    let entry2 = resolve_subpath_with_fallbacks(
        &manifest,
        ".",
        &[ExportCondition::Import, ExportCondition::Require],
    )
    .unwrap();
    assert_eq!(entry2.format, ModuleFormat::Esm);
}

#[test]
fn test_resolve_subpath_with_fallbacks_all_miss() {
    let manifest = sample_react_manifest();
    assert!(resolve_subpath_with_fallbacks(
        &manifest,
        "./nonexistent",
        &[ExportCondition::Browser, ExportCondition::ReactNative],
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// EdgeCase
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_lifecycle() {
    let mut ec = EdgeCase::pending(
        "ec-lc",
        "lifecycle test",
        ReactPackage::React,
        ExportCondition::Import,
        "./esm/react.js",
    );
    // Initially pending
    assert!(!ec.passed);
    assert!(ec.actual_resolution.is_none());
    // Resolve with matching path
    ec.resolve("./esm/react.js");
    assert!(ec.passed);
    assert_eq!(ec.actual_resolution.as_deref(), Some("./esm/react.js"));
    // Mark failed
    ec.mark_failed();
    assert!(!ec.passed);
    assert!(ec.actual_resolution.is_none());
}

#[test]
fn test_edge_case_resolve_mismatch() {
    let mut ec = EdgeCase::pending(
        "ec-mm",
        "mismatch",
        ReactPackage::React,
        ExportCondition::Import,
        "./esm/react.js",
    );
    ec.resolve("./wrong.js");
    assert!(!ec.passed);
    assert_eq!(ec.actual_resolution.as_deref(), Some("./wrong.js"));
}

#[test]
fn test_edge_case_display_and_serde() {
    let mut ec = EdgeCase::pending(
        "ec-ds",
        "display/serde",
        ReactPackage::Scheduler,
        ExportCondition::Require,
        "./cjs/scheduler.js",
    );
    assert!(ec.to_string().contains("FAIL"));
    ec.resolve("./cjs/scheduler.js");
    assert!(ec.to_string().contains("PASS"));
    let json = serde_json::to_string(&ec).unwrap();
    let back: EdgeCase = serde_json::from_str(&json).unwrap();
    assert_eq!(ec, back);
}

// ---------------------------------------------------------------------------
// CohortError
// ---------------------------------------------------------------------------

#[test]
fn test_cohort_error_display_all_variants() {
    assert!(CohortError::PackageNotFound("react-missing".into()).to_string().contains("react-missing"));
    assert!(CohortError::SubpathMissing("./foo".into()).to_string().contains("./foo"));
    let fmt_err = CohortError::FormatMismatch {
        expected: ModuleFormat::Esm,
        actual: ModuleFormat::Cjs,
    };
    assert!(fmt_err.to_string().contains("esm"));
    assert!(fmt_err.to_string().contains("cjs"));
    let loop_err = CohortError::AliasLoop(vec!["a".into(), "b".into(), "a".into()]);
    assert!(loop_err.to_string().contains("a -> b -> a"));
    assert!(CohortError::InternalError("boom".into()).to_string().contains("boom"));
}

#[test]
fn test_cohort_error_serde_roundtrip() {
    let errors = vec![
        CohortError::PackageNotFound("react".into()),
        CohortError::SubpathMissing("./jsx-runtime".into()),
        CohortError::FormatMismatch {
            expected: ModuleFormat::Esm,
            actual: ModuleFormat::Cjs,
        },
        CohortError::AliasLoop(vec!["a".into(), "b".into()]),
        CohortError::InternalError("internal".into()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CohortError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// CohortMatrix
// ---------------------------------------------------------------------------

#[test]
fn test_build_cohort_matrix_basic() {
    let matrix = build_cohort_matrix(test_epoch(), vec![sample_react_manifest()]);
    assert_eq!(matrix.package_count(), 1);
    assert_eq!(matrix.total_subpaths, 5);
    assert!(matrix.edge_cases.is_empty());
    assert!(matrix.matrix_id.starts_with("cohort-matrix-1-"));
}

#[test]
fn test_build_cohort_matrix_deterministic_and_epoch_sensitive() {
    let mat1 = build_cohort_matrix(test_epoch(), vec![sample_react_manifest()]);
    let mat2 = build_cohort_matrix(test_epoch(), vec![sample_react_manifest()]);
    assert_eq!(mat1.content_hash, mat2.content_hash);
    assert_eq!(mat1.matrix_id, mat2.matrix_id);
    // Different epoch => different hash
    let mat3 = build_cohort_matrix(SecurityEpoch::from_raw(2), vec![sample_react_manifest()]);
    assert_ne!(mat1.content_hash, mat3.content_hash);
}

#[test]
fn test_cohort_matrix_pass_rate_all_pass() {
    let mut ec = EdgeCase::pending("ec-1", "test", ReactPackage::React, ExportCondition::Import, "./esm/react.js");
    ec.resolve("./esm/react.js");
    let matrix = build_cohort_matrix_with_edges(test_epoch(), vec![sample_react_manifest()], vec![ec]);
    assert_eq!(matrix.pass_rate_millionths(), 1_000_000);
    assert_eq!(matrix.passed_edge_cases(), 1);
    assert_eq!(matrix.failed_edge_cases(), 0);
}

#[test]
fn test_cohort_matrix_pass_rate_partial() {
    let mut ec1 = EdgeCase::pending("ec-p", "pass", ReactPackage::React, ExportCondition::Import, "./esm/react.js");
    ec1.resolve("./esm/react.js");
    let mut ec2 = EdgeCase::pending("ec-f", "fail", ReactPackage::React, ExportCondition::Import, "./esm/react.js");
    ec2.resolve("./wrong.js");
    let matrix = build_cohort_matrix_with_edges(test_epoch(), vec![sample_react_manifest()], vec![ec1, ec2]);
    assert_eq!(matrix.pass_rate_millionths(), 500_000);
}

#[test]
fn test_cohort_matrix_find_and_display_and_serde() {
    let matrix = build_cohort_matrix(test_epoch(), vec![sample_react_manifest()]);
    // No edge cases => full rate
    assert_eq!(matrix.pass_rate_millionths(), 1_000_000);
    // find_manifest
    assert!(matrix.find_manifest(ReactPackage::React).is_some());
    assert!(matrix.find_manifest(ReactPackage::ReactDom).is_none());
    // Display
    let display = matrix.to_string();
    assert!(display.contains("CohortMatrix"));
    assert!(display.contains("1 packages"));
    // Serde roundtrip
    let json = serde_json::to_string(&matrix).unwrap();
    let back: CohortMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
}

// ---------------------------------------------------------------------------
// detect_alias_loops
// ---------------------------------------------------------------------------

#[test]
fn test_detect_alias_loops_no_aliases() {
    assert!(detect_alias_loops(&sample_react_manifest()).is_empty());
}

#[test]
fn test_detect_alias_loops_two_and_three_node_cycles() {
    // Two-node cycle
    let mut aliases2 = BTreeMap::new();
    aliases2.insert("a".into(), "b".into());
    aliases2.insert("b".into(), "a".into());
    let m2 = build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases2);
    let loops2 = detect_alias_loops(&m2);
    assert!(!loops2.is_empty());
    assert!(loops2[0].contains(&"a".to_string()));
    // Three-node cycle
    let mut aliases3 = BTreeMap::new();
    aliases3.insert("x".into(), "y".into());
    aliases3.insert("y".into(), "z".into());
    aliases3.insert("z".into(), "x".into());
    let m3 = build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases3);
    assert!(!detect_alias_loops(&m3).is_empty());
}

#[test]
fn test_detect_alias_loops_chain_no_loop() {
    let mut aliases = BTreeMap::new();
    aliases.insert("a".into(), "b".into());
    aliases.insert("b".into(), "c".into());
    let manifest = build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases);
    assert!(detect_alias_loops(&manifest).is_empty());
}

// ---------------------------------------------------------------------------
// resolve_alias_chain
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_alias_chain_follows_and_terminates() {
    let mut aliases = BTreeMap::new();
    aliases.insert("a".into(), "b".into());
    aliases.insert("b".into(), "c".into());
    assert_eq!(resolve_alias_chain(&aliases, "a").unwrap(), "c");
    // No alias => returns start key
    assert_eq!(resolve_alias_chain(&BTreeMap::new(), "direct").unwrap(), "direct");
}

#[test]
fn test_resolve_alias_chain_detects_loop() {
    let mut aliases = BTreeMap::new();
    aliases.insert("a".into(), "b".into());
    aliases.insert("b".into(), "a".into());
    match resolve_alias_chain(&aliases, "a").unwrap_err() {
        CohortError::AliasLoop(chain) => {
            assert!(chain.contains(&"a".to_string()));
            assert!(chain.contains(&"b".to_string()));
        }
        other => panic!("expected AliasLoop, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// format_compatible
// ---------------------------------------------------------------------------

#[test]
fn test_format_compatible_matrix() {
    // Same format always compatible
    assert!(format_compatible(ModuleFormat::Esm, ModuleFormat::Esm));
    assert!(format_compatible(ModuleFormat::Cjs, ModuleFormat::Cjs));
    assert!(format_compatible(ModuleFormat::Dual, ModuleFormat::Dual));
    // Dual is bidirectionally compatible
    assert!(format_compatible(ModuleFormat::Esm, ModuleFormat::Dual));
    assert!(format_compatible(ModuleFormat::Dual, ModuleFormat::Cjs));
    // ESM and CJS are not compatible
    assert!(!format_compatible(ModuleFormat::Esm, ModuleFormat::Cjs));
    assert!(!format_compatible(ModuleFormat::Cjs, ModuleFormat::Esm));
}

// ---------------------------------------------------------------------------
// verify_format_consistency
// ---------------------------------------------------------------------------

#[test]
fn test_verify_format_consistency_clean() {
    assert!(verify_format_consistency(&sample_react_manifest()).is_empty());
}

#[test]
fn test_verify_format_consistency_conflict() {
    let subpaths = vec![
        sample_subpath(".", ExportCondition::Import, "./shared/index.js", ModuleFormat::Esm),
        sample_subpath(".", ExportCondition::Require, "./shared/index.js", ModuleFormat::Cjs),
    ];
    let manifest = build_manifest(ReactPackage::React, "18.3.1", subpaths);
    let errors = verify_format_consistency(&manifest);
    assert_eq!(errors.len(), 1);
    match &errors[0] {
        CohortError::FormatMismatch { expected, actual } => {
            assert_eq!(*expected, ModuleFormat::Esm);
            assert_eq!(*actual, ModuleFormat::Cjs);
        }
        other => panic!("expected FormatMismatch, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// validate_edge_case
// ---------------------------------------------------------------------------

#[test]
fn test_validate_edge_case_match_and_miss() {
    let manifest = sample_react_manifest();
    let pass_ec = EdgeCase {
        case_id: "ec-val-1".into(),
        description: "root ESM".into(),
        source_package: ReactPackage::React,
        condition: ExportCondition::Import,
        expected_resolution: "./esm/react.js".into(),
        actual_resolution: None,
        passed: false,
    };
    assert!(validate_edge_case(&manifest, &pass_ec));
    let fail_ec = EdgeCase {
        case_id: "ec-val-2".into(),
        description: "missing".into(),
        source_package: ReactPackage::React,
        condition: ExportCondition::Import,
        expected_resolution: "./nonexistent.js".into(),
        actual_resolution: None,
        passed: false,
    };
    assert!(!validate_edge_case(&manifest, &fail_ec));
}

// ---------------------------------------------------------------------------
// validate_cohort
// ---------------------------------------------------------------------------

#[test]
fn test_validate_cohort_clean() {
    let mut ec = EdgeCase::pending("ec-ok", "clean", ReactPackage::React, ExportCondition::Import, "./esm/react.js");
    ec.resolve("./esm/react.js");
    let matrix = build_cohort_matrix_with_edges(test_epoch(), vec![sample_react_manifest()], vec![ec]);
    let report = validate_cohort(&matrix);
    assert!(report.passed);
    assert_eq!(report.pass_rate_millionths, 1_000_000);
    assert!(report.alias_loops_detected.is_empty());
}

#[test]
fn test_validate_cohort_failure_modes() {
    // Failed edge case
    let mut ec = EdgeCase::pending("ec-bad", "bad", ReactPackage::React, ExportCondition::Import, "./esm/react.js");
    ec.resolve("./wrong.js");
    let matrix = build_cohort_matrix_with_edges(test_epoch(), vec![sample_react_manifest()], vec![ec]);
    assert!(!validate_cohort(&matrix).passed);
    // Alias loop
    let mut aliases = BTreeMap::new();
    aliases.insert("a".into(), "b".into());
    aliases.insert("b".into(), "a".into());
    let manifest = build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases);
    let matrix2 = build_cohort_matrix(test_epoch(), vec![manifest]);
    let report = validate_cohort(&matrix2);
    assert!(!report.passed);
    assert!(!report.alias_loops_detected.is_empty());
}

#[test]
fn test_validate_cohort_report_counts_display_serde() {
    let matrix = build_cohort_matrix(test_epoch(), vec![sample_react_manifest()]);
    let report = validate_cohort(&matrix);
    assert_eq!(report.per_package_subpath_counts.get("react"), Some(&5));
    assert!(report.to_string().contains("PASS"));
    let json = serde_json::to_string(&report).unwrap();
    let back: CohortValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// cohort_coverage_millionths
// ---------------------------------------------------------------------------

#[test]
fn test_cohort_coverage_various() {
    // Empty => 0
    assert_eq!(cohort_coverage_millionths(&[]), 0);
    // Single package => 1/7
    assert_eq!(cohort_coverage_millionths(&[sample_react_manifest()]), 1_000_000 / 7);
    // All packages => 100%
    let all: Vec<PackageManifest> = ReactPackage::ALL
        .iter()
        .map(|pkg| build_manifest(*pkg, "1.0.0", Vec::new()))
        .collect();
    assert_eq!(cohort_coverage_millionths(&all), 1_000_000);
    // Duplicates don't inflate
    let dupes = vec![
        build_manifest(ReactPackage::React, "18.3.0", Vec::new()),
        build_manifest(ReactPackage::React, "18.3.1", Vec::new()),
    ];
    assert_eq!(cohort_coverage_millionths(&dupes), 1_000_000 / 7);
}

// ---------------------------------------------------------------------------
// franken_engine_react_cohort_manifest (golden reference)
// ---------------------------------------------------------------------------

#[test]
fn test_golden_manifest_structure() {
    let matrix = franken_engine_react_cohort_manifest();
    assert_eq!(matrix.package_count(), 7);
    for pkg in ReactPackage::ALL {
        assert!(matrix.find_manifest(*pkg).is_some(), "missing manifest for {:?}", pkg);
    }
    // react: 7, react-dom: 8, react-dom/server: 4, jsx-runtime: 3,
    // jsx-dev-runtime: 3, scheduler: 3, reconciler: 3 = 31
    assert_eq!(matrix.total_subpaths, 31);
}

#[test]
fn test_golden_manifest_edge_cases_deterministic_validation() {
    let matrix = franken_engine_react_cohort_manifest();
    assert_eq!(matrix.failed_edge_cases(), 0);
    assert_eq!(matrix.pass_rate_millionths(), 1_000_000);
    // Deterministic
    let m2 = franken_engine_react_cohort_manifest();
    assert_eq!(matrix.content_hash, m2.content_hash);
    assert_eq!(matrix.matrix_id, m2.matrix_id);
    // Full validation passes
    let report = validate_cohort(&matrix);
    assert!(report.passed);
    assert!(report.alias_loops_detected.is_empty());
}

#[test]
fn test_golden_manifest_subpath_resolutions() {
    let matrix = franken_engine_react_cohort_manifest();
    // jsx-runtime ESM
    let jsx = matrix.find_manifest(ReactPackage::ReactJsxRuntime).unwrap();
    let entry = resolve_subpath(jsx, ".", &ExportCondition::Import).unwrap();
    assert_eq!(entry.resolved_path, "./esm/jsx-runtime.js");
    assert_eq!(entry.format, ModuleFormat::Esm);
    // dom/server multi-condition
    let server = matrix.find_manifest(ReactPackage::ReactDomServer).unwrap();
    assert_eq!(
        resolve_subpath(server, ".", &ExportCondition::Browser).unwrap().resolved_path,
        "./esm/react-dom-server.browser.js",
    );
    assert_eq!(
        resolve_subpath(server, ".", &ExportCondition::ReactServer).unwrap().resolved_path,
        "./esm/react-dom-server.edge.js",
    );
    let cjs = resolve_subpath(server, ".", &ExportCondition::Require).unwrap();
    assert_eq!(cjs.resolved_path, "./cjs/react-dom-server.node.js");
    assert_eq!(cjs.format, ModuleFormat::Cjs);
}

#[test]
fn test_golden_manifest_full_serde_roundtrip() {
    let matrix = franken_engine_react_cohort_manifest();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: CohortMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
}

// ---------------------------------------------------------------------------
// Artifact bundle / CLI
// ---------------------------------------------------------------------------

#[test]
fn write_bundle_creates_expected_files_and_manifest() {
    let out_dir = unique_temp_dir("bundle-files");
    let commands = vec![
        "franken_react_package_cohort".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];

    let artifacts = write_react_package_cohort_bundle(&out_dir, &commands).expect("write bundle");

    assert!(artifacts.matrix_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.trace_ids_path.exists());
    assert_eq!(artifacts.package_count, 7);

    let manifest: ReactCohortRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
            .expect("parse manifest");
    assert_eq!(
        manifest.schema_version,
        REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(manifest.component, REACT_COHORT_COMPONENT);
    assert_eq!(manifest.policy_id, REACT_COHORT_POLICY_ID);
    assert_eq!(manifest.package_count, artifacts.package_count as u64);
    assert_eq!(manifest.edge_case_count, artifacts.edge_case_count as u64);
    assert_eq!(
        manifest.artifact_paths.react_package_cohort_matrix,
        "react_package_cohort_matrix.json"
    );
    assert_eq!(manifest.artifact_paths.run_manifest, "run_manifest.json");
    assert_eq!(manifest.artifact_paths.events_jsonl, "events.jsonl");
    assert_eq!(manifest.artifact_paths.commands_txt, "commands.txt");
    assert_eq!(manifest.artifact_paths.trace_ids, "trace_ids.json");
}

#[test]
fn write_bundle_events_trace_ids_and_commands_are_structured() {
    let out_dir = unique_temp_dir("bundle-structured");
    let commands = vec![
        "franken_react_package_cohort".to_string(),
        "--out-dir".to_string(),
        "/tmp/react-package-cohort".to_string(),
    ];

    let artifacts = write_react_package_cohort_bundle(&out_dir, &commands).expect("write bundle");

    let events_text = fs::read_to_string(&artifacts.events_path).expect("read events");
    let events: Vec<ReactCohortEvent> = events_text
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse event"))
        .collect();
    assert_eq!(events.len(), artifacts.package_count + artifacts.edge_case_count + 2);
    assert_eq!(events.first().unwrap().event, "cohort_generation_started");
    assert_eq!(events.last().unwrap().event, "cohort_generation_completed");
    assert!(
        events
            .iter()
            .all(|event| event.schema_version == REACT_COHORT_EVENT_SCHEMA_VERSION)
    );

    let trace_ids: ReactCohortTraceIds =
        serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).expect("read trace ids"))
            .expect("parse trace ids");
    let short_hash = &artifacts.matrix_hash[..16];
    assert_eq!(trace_ids.schema_version, REACT_COHORT_TRACE_IDS_SCHEMA_VERSION);
    assert!(trace_ids.trace_id.contains(short_hash));
    assert!(trace_ids.decision_id.contains(short_hash));
    assert_eq!(trace_ids.policy_id, REACT_COHORT_POLICY_ID);

    let commands_txt = fs::read_to_string(&artifacts.commands_path).expect("read commands");
    for command in &commands {
        assert!(commands_txt.contains(command), "commands should contain {command}");
    }
}

#[test]
fn write_bundle_is_deterministic_across_output_directories() {
    let out_dir_a = unique_temp_dir("bundle-det-a");
    let out_dir_b = unique_temp_dir("bundle-det-b");
    let commands = vec![
        "franken_react_package_cohort".to_string(),
        "--out-dir".to_string(),
        "/tmp/react-package-cohort".to_string(),
    ];

    let bundle_a = write_react_package_cohort_bundle(&out_dir_a, &commands).expect("write A");
    let bundle_b = write_react_package_cohort_bundle(&out_dir_b, &commands).expect("write B");

    assert_eq!(bundle_a.matrix_hash, bundle_b.matrix_hash);
    assert_eq!(
        fs::read(&bundle_a.matrix_path).expect("read matrix A"),
        fs::read(&bundle_b.matrix_path).expect("read matrix B")
    );
    assert_eq!(
        fs::read(&bundle_a.run_manifest_path).expect("read manifest A"),
        fs::read(&bundle_b.run_manifest_path).expect("read manifest B")
    );
    assert_eq!(
        fs::read_to_string(&bundle_a.events_path).expect("read events A"),
        fs::read_to_string(&bundle_b.events_path).expect("read events B")
    );
    assert_eq!(
        fs::read(&bundle_a.trace_ids_path).expect("read trace ids A"),
        fs::read(&bundle_b.trace_ids_path).expect("read trace ids B")
    );
    assert_eq!(
        fs::read_to_string(&bundle_a.commands_path).expect("read commands A"),
        fs::read_to_string(&bundle_b.commands_path).expect("read commands B")
    );
}

#[test]
fn write_bundle_busy_error_reports_lock_path() {
    let out_dir = unique_temp_dir("bundle-busy");
    let lock_path = out_dir.join(".react_package_cohort.lock");
    fs::write(&lock_path, "held").expect("write lock");

    let err = write_react_package_cohort_bundle(&out_dir, &["test".to_string()])
        .expect_err("lock should reject concurrent writer");
    match err {
        ReactCohortWriteError::Busy { path } => {
            assert_eq!(path, lock_path.display().to_string());
        }
        other => panic!("expected Busy error, got {other:?}"),
    }
}

#[test]
fn write_bundle_releases_lock_after_success() {
    let out_dir = unique_temp_dir("bundle-lock-release");
    write_react_package_cohort_bundle(&out_dir, &["test".to_string()]).expect("write bundle");
    assert!(!out_dir.join(".react_package_cohort.lock").exists());
}

#[test]
fn franken_react_package_cohort_cli_writes_bundle() {
    let out_dir = unique_temp_dir("cli");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_react_package_cohort"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run franken_react_package_cohort");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cli stdout");
    assert_eq!(
        summary["schema_version"].as_str(),
        Some("franken-engine.franken_react_package_cohort.v1")
    );
    assert_eq!(summary["out_dir"].as_str(), Some(out_dir.to_str().unwrap()));
    assert_eq!(
        summary["trace_ids"].as_str(),
        Some(out_dir.join("trace_ids.json").to_str().unwrap())
    );
    assert_eq!(
        summary["run_manifest"].as_str(),
        Some(out_dir.join("run_manifest.json").to_str().unwrap())
    );
    assert_eq!(
        summary["events_jsonl"].as_str(),
        Some(out_dir.join("events.jsonl").to_str().unwrap())
    );
    assert_eq!(
        summary["commands_txt"].as_str(),
        Some(out_dir.join("commands.txt").to_str().unwrap())
    );

    let manifest: ReactCohortRunManifest =
        serde_json::from_slice(&fs::read(out_dir.join("run_manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    assert_eq!(
        manifest.schema_version,
        REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION
    );
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_constants() {
    assert!(!REACT_COHORT_SCHEMA_VERSION.is_empty());
    assert!(REACT_COHORT_SCHEMA_VERSION.contains("react-package-cohort"));
    assert!(REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION.contains("react-package-cohort"));
    assert!(REACT_COHORT_EVENT_SCHEMA_VERSION.contains("react-package-cohort"));
    assert!(REACT_COHORT_TRACE_IDS_SCHEMA_VERSION.contains("react-package-cohort"));
    assert!(!REACT_COHORT_BEAD_ID.is_empty());
    assert!(!REACT_COHORT_POLICY_ID.is_empty());
    assert!(!REACT_COHORT_COMPONENT.is_empty());
}
