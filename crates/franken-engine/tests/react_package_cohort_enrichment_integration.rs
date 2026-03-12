//! Enrichment integration tests for `react_package_cohort`.
//!
//! Covers gaps in existing unit and integration tests: npm-name sharing
//! semantics, manifest hash sensitivity, condition-coverage edge cases,
//! serde roundtrips for artifact/event/trace structs, format-compatible
//! exhaustive matrix, golden-manifest per-package invariants,
//! CohortValidationReport structural properties, and edge-case lifecycle
//! corner cases.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::react_package_cohort::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sub(subpath: &str, cond: ExportCondition, resolved: &str, fmt: ModuleFormat) -> SubpathEntry {
    SubpathEntry::new(subpath, vec![cond], resolved, fmt)
}

fn minimal_manifest(pkg: ReactPackage) -> PackageManifest {
    build_manifest(
        pkg,
        "1.0.0",
        vec![sub(
            ".",
            ExportCondition::Import,
            "./esm/index.js",
            ModuleFormat::Esm,
        )],
    )
}

// ---------------------------------------------------------------------------
// ReactPackage npm-name sharing semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_npm_name_sharing_react_family() {
    // React, ReactJsxRuntime, and ReactJsxDevRuntime all share "react"
    assert_eq!(ReactPackage::React.npm_name(), "react");
    assert_eq!(ReactPackage::ReactJsxRuntime.npm_name(), "react");
    assert_eq!(ReactPackage::ReactJsxDevRuntime.npm_name(), "react");
    // But they have distinct as_str values
    let strs: BTreeSet<_> = [
        ReactPackage::React.as_str(),
        ReactPackage::ReactJsxRuntime.as_str(),
        ReactPackage::ReactJsxDevRuntime.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        strs.len(),
        3,
        "as_str must be unique despite shared npm_name"
    );
}

#[test]
fn enrichment_npm_name_sharing_dom_family() {
    // ReactDom and ReactDomServer share "react-dom"
    assert_eq!(ReactPackage::ReactDom.npm_name(), "react-dom");
    assert_eq!(ReactPackage::ReactDomServer.npm_name(), "react-dom");
    let strs: BTreeSet<_> = [
        ReactPackage::ReactDom.as_str(),
        ReactPackage::ReactDomServer.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(strs.len(), 2);
}

#[test]
fn enrichment_all_as_str_values_unique() {
    let strs: BTreeSet<_> = ReactPackage::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(strs.len(), ReactPackage::ALL.len());
}

#[test]
fn enrichment_all_npm_names_non_empty() {
    for pkg in ReactPackage::ALL {
        assert!(!pkg.npm_name().is_empty());
    }
}

// ---------------------------------------------------------------------------
// ExportCondition ordering stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_export_condition_ordering_matches_all_array() {
    // ALL is sorted in declaration order which matches derived Ord
    let mut sorted = ExportCondition::ALL.to_vec();
    sorted.sort();
    assert_eq!(sorted, ExportCondition::ALL);
}

#[test]
fn enrichment_export_condition_all_keys_unique() {
    let keys: BTreeSet<_> = ExportCondition::ALL
        .iter()
        .map(|c| c.condition_key())
        .collect();
    assert_eq!(keys.len(), ExportCondition::ALL.len());
}

// ---------------------------------------------------------------------------
// ModuleFormat ordering stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_module_format_ordering_matches_all_array() {
    let mut sorted = ModuleFormat::ALL.to_vec();
    sorted.sort();
    assert_eq!(sorted, ModuleFormat::ALL);
}

// ---------------------------------------------------------------------------
// format_compatible exhaustive matrix
// ---------------------------------------------------------------------------

#[test]
fn enrichment_format_compatible_exhaustive_matrix() {
    // Same format always compatible
    for fmt in ModuleFormat::ALL {
        assert!(format_compatible(*fmt, *fmt));
    }
    // Dual compatible with Esm and Cjs in both directions
    assert!(format_compatible(ModuleFormat::Esm, ModuleFormat::Dual));
    assert!(format_compatible(ModuleFormat::Dual, ModuleFormat::Esm));
    assert!(format_compatible(ModuleFormat::Cjs, ModuleFormat::Dual));
    assert!(format_compatible(ModuleFormat::Dual, ModuleFormat::Cjs));
    // Esm and Cjs incompatible
    assert!(!format_compatible(ModuleFormat::Esm, ModuleFormat::Cjs));
    assert!(!format_compatible(ModuleFormat::Cjs, ModuleFormat::Esm));
}

// ---------------------------------------------------------------------------
// SubpathEntry matching and display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_subpath_entry_multi_condition_matching() {
    let entry = SubpathEntry::new(
        "./server",
        vec![ExportCondition::Import, ExportCondition::Node],
        "./esm/server.js",
        ModuleFormat::Esm,
    );
    assert!(entry.matches("./server", &ExportCondition::Import));
    assert!(entry.matches("./server", &ExportCondition::Node));
    assert!(!entry.matches("./server", &ExportCondition::Browser));
    assert!(!entry.matches("./client", &ExportCondition::Import));
}

#[test]
fn enrichment_subpath_entry_display_contains_subpath_and_path() {
    let entry = sub(
        "./jsx-runtime",
        ExportCondition::Import,
        "./esm/jsx.js",
        ModuleFormat::Esm,
    );
    let display = entry.to_string();
    assert!(display.contains("./jsx-runtime"));
    assert!(display.contains("./esm/jsx.js"));
    assert!(display.contains("esm"));
}

#[test]
fn enrichment_subpath_entry_serde_roundtrip() {
    let entry = SubpathEntry::new(
        "./server",
        vec![
            ExportCondition::Import,
            ExportCondition::Node,
            ExportCondition::ReactServer,
        ],
        "./esm/server.edge.js",
        ModuleFormat::Esm,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: SubpathEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Manifest hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_hash_sensitive_to_package_kind() {
    let m1 = minimal_manifest(ReactPackage::React);
    let m2 = minimal_manifest(ReactPackage::Scheduler);
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn enrichment_manifest_hash_sensitive_to_subpath_content() {
    let s1 = vec![sub(
        ".",
        ExportCondition::Import,
        "./esm/a.js",
        ModuleFormat::Esm,
    )];
    let s2 = vec![sub(
        ".",
        ExportCondition::Import,
        "./esm/b.js",
        ModuleFormat::Esm,
    )];
    let m1 = build_manifest(ReactPackage::React, "1.0.0", s1);
    let m2 = build_manifest(ReactPackage::React, "1.0.0", s2);
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn enrichment_manifest_hash_sensitive_to_aliases() {
    let subs = vec![sub(
        ".",
        ExportCondition::Import,
        "./esm/index.js",
        ModuleFormat::Esm,
    )];
    let m1 = build_manifest(ReactPackage::React, "1.0.0", subs.clone());

    let mut aliases = BTreeMap::new();
    aliases.insert("./legacy".to_string(), "./index".to_string());
    let m2 = build_manifest_with_aliases(ReactPackage::React, "1.0.0", subs, aliases);
    assert_ne!(m1.content_hash, m2.content_hash);
}

// ---------------------------------------------------------------------------
// condition_coverage_millionths edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_condition_coverage_zero_subpaths() {
    let m = build_manifest(ReactPackage::React, "1.0.0", vec![]);
    assert_eq!(m.condition_coverage_millionths(), 0);
}

#[test]
fn enrichment_condition_coverage_all_seven_conditions() {
    let subpaths: Vec<_> = ExportCondition::ALL
        .iter()
        .map(|c| {
            sub(
                ".",
                *c,
                &format!("./target/{}.js", c.condition_key()),
                ModuleFormat::Esm,
            )
        })
        .collect();
    let m = build_manifest(ReactPackage::React, "1.0.0", subpaths);
    assert_eq!(m.condition_coverage_millionths(), 1_000_000);
}

#[test]
fn enrichment_condition_coverage_fractional() {
    // 2 out of 7 conditions = 2/7 * 1_000_000 = 285714
    let subpaths = vec![
        sub(
            ".",
            ExportCondition::Import,
            "./esm/i.js",
            ModuleFormat::Esm,
        ),
        sub(
            ".",
            ExportCondition::Require,
            "./cjs/r.js",
            ModuleFormat::Cjs,
        ),
    ];
    let m = build_manifest(ReactPackage::React, "1.0.0", subpaths);
    let coverage = m.condition_coverage_millionths();
    assert_eq!(coverage, 2 * 1_000_000 / 7);
}

// ---------------------------------------------------------------------------
// PackageManifest counts and display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_counts_with_aliases() {
    let subpaths = vec![
        sub(
            ".",
            ExportCondition::Import,
            "./esm/a.js",
            ModuleFormat::Esm,
        ),
        sub(
            "./server",
            ExportCondition::Require,
            "./cjs/s.js",
            ModuleFormat::Cjs,
        ),
    ];
    let mut aliases = BTreeMap::new();
    aliases.insert("./old".to_string(), "./new".to_string());
    aliases.insert("./legacy".to_string(), "./old".to_string());
    let m = build_manifest_with_aliases(ReactPackage::ReactDom, "18.3.1", subpaths, aliases);
    assert_eq!(m.subpath_count(), 2);
    assert_eq!(m.alias_count(), 2);
    let display = m.to_string();
    assert!(display.contains("2 subpaths"));
    assert!(display.contains("2 aliases"));
    assert!(display.contains("react_dom"));
}

// ---------------------------------------------------------------------------
// EdgeCase lifecycle corners
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_case_pending_has_no_actual_and_fails() {
    let ec = EdgeCase::pending(
        "ec-1",
        "desc",
        ReactPackage::React,
        ExportCondition::Import,
        "./esm/react.js",
    );
    assert!(!ec.passed);
    assert!(ec.actual_resolution.is_none());
}

#[test]
fn enrichment_edge_case_resolve_wrong_sets_actual_but_fails() {
    let mut ec = EdgeCase::pending(
        "ec-2",
        "desc",
        ReactPackage::React,
        ExportCondition::Import,
        "./esm/react.js",
    );
    ec.resolve("./cjs/react.js");
    assert!(!ec.passed);
    assert_eq!(ec.actual_resolution.as_deref(), Some("./cjs/react.js"));
}

#[test]
fn enrichment_edge_case_mark_failed_clears_actual() {
    let mut ec = EdgeCase::pending(
        "ec-3",
        "desc",
        ReactPackage::React,
        ExportCondition::Import,
        "./esm/react.js",
    );
    ec.resolve("./esm/react.js");
    assert!(ec.passed);
    ec.mark_failed();
    assert!(!ec.passed);
    assert!(ec.actual_resolution.is_none());
}

#[test]
fn enrichment_edge_case_display_pass_fail() {
    let mut ec_pass = EdgeCase::pending(
        "ec-p",
        "pass case",
        ReactPackage::React,
        ExportCondition::Import,
        "./esm/react.js",
    );
    ec_pass.resolve("./esm/react.js");
    let pass_str = ec_pass.to_string();
    assert!(
        pass_str.contains("PASS"),
        "passed edge case display should contain PASS"
    );

    let ec_fail = EdgeCase::pending(
        "ec-f",
        "fail case",
        ReactPackage::React,
        ExportCondition::Import,
        "./esm/react.js",
    );
    let fail_str = ec_fail.to_string();
    assert!(
        fail_str.contains("FAIL"),
        "failed edge case display should contain FAIL"
    );
}

// ---------------------------------------------------------------------------
// CohortError display variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cohort_error_display_all_variants_distinct() {
    let errors = [
        CohortError::PackageNotFound("react-native".to_string()),
        CohortError::SubpathMissing("./nonexistent".to_string()),
        CohortError::FormatMismatch {
            expected: ModuleFormat::Esm,
            actual: ModuleFormat::Cjs,
        },
        CohortError::AliasLoop(vec!["a".to_string(), "b".to_string(), "a".to_string()]),
        CohortError::InternalError("unexpected state".to_string()),
    ];
    let displays: BTreeSet<_> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(
        displays.len(),
        errors.len(),
        "all error displays must be unique"
    );
    // PackageNotFound display contains the package name
    assert!(errors[0].to_string().contains("react-native"));
    // FormatMismatch display contains format names
    let fm_str = errors[2].to_string();
    assert!(fm_str.contains("esm") || fm_str.contains("Esm"));
}

// ---------------------------------------------------------------------------
// CohortMatrix edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cohort_matrix_no_edge_cases_full_pass_rate() {
    let m = build_cohort_matrix(
        SecurityEpoch::from_raw(1),
        vec![minimal_manifest(ReactPackage::React)],
    );
    assert_eq!(m.passed_edge_cases(), 0);
    assert_eq!(m.failed_edge_cases(), 0);
    // pass_rate with 0 edge cases should be 1_000_000 (100%)
    assert_eq!(m.pass_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_cohort_matrix_all_failing_edge_cases() {
    let ec1 = EdgeCase::pending(
        "ec-1",
        "d",
        ReactPackage::React,
        ExportCondition::Import,
        "./x",
    );
    let ec2 = EdgeCase::pending(
        "ec-2",
        "d",
        ReactPackage::React,
        ExportCondition::Require,
        "./y",
    );
    let m = build_cohort_matrix_with_edges(
        SecurityEpoch::from_raw(1),
        vec![minimal_manifest(ReactPackage::React)],
        vec![ec1, ec2],
    );
    assert_eq!(m.passed_edge_cases(), 0);
    assert_eq!(m.failed_edge_cases(), 2);
    assert_eq!(m.pass_rate_millionths(), 0);
}

#[test]
fn enrichment_cohort_matrix_total_subpaths_across_packages() {
    let m1 = build_manifest(
        ReactPackage::React,
        "1.0.0",
        vec![
            sub(".", ExportCondition::Import, "./a.js", ModuleFormat::Esm),
            sub(
                "./jsx",
                ExportCondition::Import,
                "./b.js",
                ModuleFormat::Esm,
            ),
        ],
    );
    let m2 = build_manifest(
        ReactPackage::Scheduler,
        "1.0.0",
        vec![sub(
            ".",
            ExportCondition::Import,
            "./c.js",
            ModuleFormat::Esm,
        )],
    );
    let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![m1, m2]);
    assert_eq!(matrix.total_subpaths, 3);
}

#[test]
fn enrichment_cohort_matrix_find_manifest_present_and_absent() {
    let matrix = build_cohort_matrix(
        SecurityEpoch::from_raw(1),
        vec![minimal_manifest(ReactPackage::React)],
    );
    assert!(matrix.find_manifest(ReactPackage::React).is_some());
    assert!(matrix.find_manifest(ReactPackage::Scheduler).is_none());
}

#[test]
fn enrichment_cohort_matrix_display_contains_matrix_id() {
    let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![]);
    let display = matrix.to_string();
    assert!(display.contains(&matrix.matrix_id));
}

// ---------------------------------------------------------------------------
// resolve_subpath_with_fallbacks priority
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resolve_with_fallbacks_first_match_wins() {
    let subpaths = vec![
        sub(
            ".",
            ExportCondition::Import,
            "./esm/index.js",
            ModuleFormat::Esm,
        ),
        sub(
            ".",
            ExportCondition::Require,
            "./cjs/index.js",
            ModuleFormat::Cjs,
        ),
        sub(
            ".",
            ExportCondition::Default,
            "./cjs/index.js",
            ModuleFormat::Cjs,
        ),
    ];
    let m = build_manifest(ReactPackage::React, "1.0.0", subpaths);
    let result = resolve_subpath_with_fallbacks(
        &m,
        ".",
        &[
            ExportCondition::Require,
            ExportCondition::Import,
            ExportCondition::Default,
        ],
    )
    .unwrap();
    // Require is first in fallback list so it wins
    assert_eq!(result.format, ModuleFormat::Cjs);
    assert!(result.conditions.contains(&ExportCondition::Require));
}

// ---------------------------------------------------------------------------
// resolve_alias_chain
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resolve_alias_chain_long_chain() {
    let mut aliases = BTreeMap::new();
    aliases.insert("a".to_string(), "b".to_string());
    aliases.insert("b".to_string(), "c".to_string());
    aliases.insert("c".to_string(), "d".to_string());
    aliases.insert("d".to_string(), "e".to_string());
    let result = resolve_alias_chain(&aliases, "a").unwrap();
    assert_eq!(result, "e");
}

#[test]
fn enrichment_resolve_alias_chain_identity() {
    let aliases = BTreeMap::new();
    let result = resolve_alias_chain(&aliases, "not-aliased").unwrap();
    assert_eq!(result, "not-aliased");
}

// ---------------------------------------------------------------------------
// detect_alias_loops deduplication
// ---------------------------------------------------------------------------

#[test]
fn enrichment_detect_alias_loops_deduplicates_same_cycle() {
    let mut aliases = BTreeMap::new();
    aliases.insert("a".to_string(), "b".to_string());
    aliases.insert("b".to_string(), "a".to_string());
    let subs = vec![sub(
        ".",
        ExportCondition::Import,
        "./x.js",
        ModuleFormat::Esm,
    )];
    let m = build_manifest_with_aliases(ReactPackage::React, "1.0.0", subs, aliases);
    let loops = detect_alias_loops(&m);
    // a→b→a cycle traversed from both "a" and "b" should produce only 1 unique cycle
    assert_eq!(loops.len(), 1);
}

// ---------------------------------------------------------------------------
// verify_format_consistency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_format_consistency_dual_same_path_ok() {
    // Same resolved path with same format is fine
    let subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./index.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Node],
            "./index.js",
            ModuleFormat::Esm,
        ),
    ];
    let m = build_manifest(ReactPackage::React, "1.0.0", subpaths);
    let errors = verify_format_consistency(&m);
    assert!(errors.is_empty());
}

#[test]
fn enrichment_verify_format_consistency_conflict_detected() {
    let subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./index.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./index.js",
            ModuleFormat::Cjs,
        ),
    ];
    let m = build_manifest(ReactPackage::React, "1.0.0", subpaths);
    let errors = verify_format_consistency(&m);
    assert_eq!(errors.len(), 1);
    assert!(matches!(errors[0], CohortError::FormatMismatch { .. }));
}

// ---------------------------------------------------------------------------
// validate_cohort report structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_cohort_report_has_per_package_counts() {
    let matrix = build_cohort_matrix(
        SecurityEpoch::from_raw(1),
        vec![
            minimal_manifest(ReactPackage::React),
            minimal_manifest(ReactPackage::Scheduler),
        ],
    );
    let report = validate_cohort(&matrix);
    assert!(report.passed);
    assert_eq!(report.per_package_subpath_counts.len(), 2);
    assert_eq!(report.per_package_subpath_counts["react"], 1);
    assert_eq!(report.per_package_subpath_counts["scheduler"], 1);
    assert!(report.alias_loops_detected.is_empty());
}

#[test]
fn enrichment_validate_cohort_report_serde_roundtrip() {
    let matrix = franken_engine_react_cohort_manifest();
    let report = validate_cohort(&matrix);
    let json = serde_json::to_string(&report).unwrap();
    let back: CohortValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_validate_cohort_report_display_non_empty() {
    let matrix = franken_engine_react_cohort_manifest();
    let report = validate_cohort(&matrix);
    let display = report.to_string();
    assert!(!display.is_empty());
    assert!(display.contains(&report.matrix_id));
}

// ---------------------------------------------------------------------------
// cohort_coverage_millionths
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cohort_coverage_duplicate_packages_counted_once() {
    let packages = vec![
        minimal_manifest(ReactPackage::React),
        minimal_manifest(ReactPackage::React),
        minimal_manifest(ReactPackage::React),
    ];
    let coverage = cohort_coverage_millionths(&packages);
    // Only 1 unique package out of 7
    assert_eq!(coverage, 1_000_000 / 7);
}

#[test]
fn enrichment_cohort_coverage_all_packages_full() {
    let packages: Vec<_> = ReactPackage::ALL
        .iter()
        .map(|p| minimal_manifest(*p))
        .collect();
    let coverage = cohort_coverage_millionths(&packages);
    assert_eq!(coverage, 1_000_000);
}

// ---------------------------------------------------------------------------
// Golden manifest structural invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_golden_manifest_all_seven_packages_present() {
    let matrix = franken_engine_react_cohort_manifest();
    let found: BTreeSet<_> = matrix.packages.iter().map(|m| m.package).collect();
    let expected: BTreeSet<_> = ReactPackage::ALL.iter().copied().collect();
    assert_eq!(found, expected);
}

#[test]
fn enrichment_golden_manifest_versions_populated() {
    let matrix = franken_engine_react_cohort_manifest();
    for manifest in &matrix.packages {
        assert!(
            !manifest.version.is_empty(),
            "version must be non-empty for {}",
            manifest.package
        );
        assert!(
            manifest.version.contains('.'),
            "version should be semver for {}",
            manifest.package
        );
    }
}

#[test]
fn enrichment_golden_manifest_content_hashes_unique() {
    let matrix = franken_engine_react_cohort_manifest();
    let hashes: BTreeSet<_> = matrix.packages.iter().map(|m| m.content_hash).collect();
    assert_eq!(hashes.len(), matrix.packages.len());
}

#[test]
fn enrichment_golden_manifest_has_react_server_condition() {
    let matrix = franken_engine_react_cohort_manifest();
    let dom_server = matrix.find_manifest(ReactPackage::ReactDomServer).unwrap();
    let has_react_server = dom_server
        .subpaths
        .iter()
        .any(|s| s.conditions.contains(&ExportCondition::ReactServer));
    assert!(
        has_react_server,
        "ReactDomServer should have react-server condition"
    );
}

#[test]
fn enrichment_golden_manifest_edge_case_ids_unique() {
    let matrix = franken_engine_react_cohort_manifest();
    let ids: BTreeSet<_> = matrix.edge_cases.iter().map(|ec| &ec.case_id).collect();
    assert_eq!(ids.len(), matrix.edge_cases.len());
}

// ---------------------------------------------------------------------------
// ReactCohortEvent optional field serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_optional_fields_skip_when_none() {
    let event = ReactCohortEvent {
        schema_version: REACT_COHORT_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: REACT_COHORT_POLICY_ID.to_string(),
        component: REACT_COHORT_COMPONENT.to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        package: None,
        case_id: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = parsed.as_object().unwrap();
    assert!(
        !obj.contains_key("package"),
        "None package should be skipped"
    );
    assert!(
        !obj.contains_key("case_id"),
        "None case_id should be skipped"
    );
    assert!(!obj.contains_key("detail"), "None detail should be skipped");
}

#[test]
fn enrichment_event_optional_fields_present_when_some() {
    let event = ReactCohortEvent {
        schema_version: REACT_COHORT_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: REACT_COHORT_POLICY_ID.to_string(),
        component: REACT_COHORT_COMPONENT.to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        package: Some("react".to_string()),
        case_id: Some("ec-1".to_string()),
        detail: Some("detail text".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ReactCohortEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.package.as_deref(), Some("react"));
    assert_eq!(back.case_id.as_deref(), Some("ec-1"));
    assert_eq!(back.detail.as_deref(), Some("detail text"));
}

// ---------------------------------------------------------------------------
// ReactCohortRunManifest / TraceIds / ArtifactPaths serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let rm = ReactCohortRunManifest {
        schema_version: REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: REACT_COHORT_COMPONENT.to_string(),
        trace_id: "trace-abc".to_string(),
        decision_id: "dec-abc".to_string(),
        policy_id: REACT_COHORT_POLICY_ID.to_string(),
        matrix_hash: "deadbeef".to_string(),
        package_count: 7,
        edge_case_count: 5,
        pass_count: 5,
        fail_count: 0,
        pass_rate_millionths: 1_000_000,
        contract_satisfied: true,
        artifact_paths: ReactCohortArtifactPaths {
            react_package_cohort_matrix: "matrix.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            trace_ids: "trace_ids.json".to_string(),
        },
    };
    let json = serde_json::to_string(&rm).unwrap();
    let back: ReactCohortRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(rm, back);
}

#[test]
fn enrichment_trace_ids_serde_roundtrip() {
    let ti = ReactCohortTraceIds {
        schema_version: REACT_COHORT_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: REACT_COHORT_COMPONENT.to_string(),
        trace_id: "trace-xyz".to_string(),
        decision_id: "dec-xyz".to_string(),
        policy_id: REACT_COHORT_POLICY_ID.to_string(),
    };
    let json = serde_json::to_string(&ti).unwrap();
    let back: ReactCohortTraceIds = serde_json::from_str(&json).unwrap();
    assert_eq!(ti, back);
}

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let ap = ReactCohortArtifactPaths {
        react_package_cohort_matrix: "matrix.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
        trace_ids: "trace_ids.json".to_string(),
    };
    let json = serde_json::to_string(&ap).unwrap();
    let back: ReactCohortArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(ap, back);
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_constants_all_start_with_prefix() {
    let constants = [
        REACT_COHORT_SCHEMA_VERSION,
        REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION,
        REACT_COHORT_EVENT_SCHEMA_VERSION,
        REACT_COHORT_TRACE_IDS_SCHEMA_VERSION,
    ];
    for c in &constants {
        assert!(
            c.starts_with("franken-engine."),
            "schema constant {c} must start with franken-engine."
        );
    }
    // All unique
    let set: BTreeSet<_> = constants.iter().collect();
    assert_eq!(set.len(), constants.len());
}

#[test]
fn enrichment_policy_and_bead_constants_non_empty() {
    assert!(!REACT_COHORT_BEAD_ID.is_empty());
    assert!(!REACT_COHORT_POLICY_ID.is_empty());
    assert!(!REACT_COHORT_COMPONENT.is_empty());
}

// ---------------------------------------------------------------------------
// CohortMatrix serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cohort_matrix_full_serde_roundtrip() {
    let matrix = franken_engine_react_cohort_manifest();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: CohortMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
    assert_eq!(matrix.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// CohortMatrix determinism across calls
// ---------------------------------------------------------------------------

#[test]
fn enrichment_golden_manifest_deterministic_across_calls() {
    let m1 = franken_engine_react_cohort_manifest();
    let m2 = franken_engine_react_cohort_manifest();
    assert_eq!(m1.content_hash, m2.content_hash);
    assert_eq!(m1.matrix_id, m2.matrix_id);
    assert_eq!(m1.total_subpaths, m2.total_subpaths);
}

// ---------------------------------------------------------------------------
// Bundle write and artifact structure (filesystem tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_write_bundle_artifact_paths_match_manifest() {
    let tmp = std::env::temp_dir().join(format!("react_cohort_enrichment_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let commands = vec!["cargo test".to_string(), "cargo clippy".to_string()];
    let artifacts = write_react_package_cohort_bundle(&tmp, &commands).unwrap();
    assert_eq!(artifacts.package_count, 7);
    assert_eq!(artifacts.edge_case_count, 5);
    assert!(artifacts.matrix_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.trace_ids_path.exists());

    // Run manifest references correct artifact paths
    let rm_bytes = std::fs::read(&artifacts.run_manifest_path).unwrap();
    let rm: ReactCohortRunManifest = serde_json::from_slice(&rm_bytes).unwrap();
    assert!(rm.contract_satisfied);
    assert_eq!(rm.package_count, 7);
    assert_eq!(rm.pass_rate_millionths, 1_000_000);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn enrichment_write_bundle_events_jsonl_well_formed() {
    let tmp = std::env::temp_dir().join(format!(
        "react_cohort_events_enrichment_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let artifacts = write_react_package_cohort_bundle(&tmp, &[]).unwrap();
    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let lines: Vec<_> = events_text.lines().collect();
    // Expected: 1 start + 7 package manifests + 5 edge cases + 1 completed = 14
    assert_eq!(lines.len(), 14);
    for line in &lines {
        let event: ReactCohortEvent = serde_json::from_str(line).unwrap();
        assert_eq!(event.component, REACT_COHORT_COMPONENT);
        assert!(event.schema_version.starts_with("franken-engine."));
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn enrichment_write_bundle_commands_written() {
    let tmp = std::env::temp_dir().join(format!(
        "react_cohort_cmds_enrichment_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let commands = vec!["cmd1".to_string(), "cmd2".to_string(), "cmd3".to_string()];
    let artifacts = write_react_package_cohort_bundle(&tmp, &commands).unwrap();
    let text = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines, vec!["cmd1", "cmd2", "cmd3"]);
    let _ = std::fs::remove_dir_all(&tmp);
}
