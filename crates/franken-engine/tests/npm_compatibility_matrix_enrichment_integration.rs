//! Enrichment integration tests for `npm_compatibility_matrix`.
//!
//! Covers: enum serde/display/ordering exhaustiveness, normalize edge cases,
//! overflow guards, remediation state machine completeness, multi-tier verdict
//! scenarios, cohort summary edge cases, error display for all variants,
//! content-hash sensitivity, and seed cohort integration.

use std::{collections::BTreeSet, fs, path::PathBuf};

use frankenengine_engine::npm_compatibility_matrix::{
    BEAD_ID, COMPONENT, CohortSummary, CohortTier, IncompatibilityRecord, IncompatibilityRootCause,
    IncompatibilitySeverity, MAX_INCOMPATIBILITIES_PER_PACKAGE, MAX_PACKAGES_PER_COHORT,
    MatrixVerdict, ModuleSystemReq, NpmCompatibilityError, NpmCompatibilityMatrix, PackageCategory,
    PackageRecord, PackageTestOutcome, PackageTestResult, RemediationState, SCHEMA_VERSION,
    seed_tier1_critical_packages, seed_tier2_popular_packages,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn pkg(name: &str, tier: CohortTier) -> PackageRecord {
    PackageRecord {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        tier,
        category: PackageCategory::UtilityLibrary,
        module_system: ModuleSystemReq::DualEsmCjs,
        weekly_downloads: 1_000_000,
        dependency_fanout: 5,
        node_api_deps: BTreeSet::new(),
        types_only: false,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn test_result(
    name: &str,
    outcome: PackageTestOutcome,
    total: u32,
    passed: u32,
) -> PackageTestResult {
    PackageTestResult {
        package_name: name.to_string(),
        version: "1.0.0".to_string(),
        outcome,
        total_tests: total,
        passed_tests: passed,
        failed_tests: total.saturating_sub(passed),
        skipped_tests: 0,
        output_hash: None,
        test_epoch: 1,
    }
}

fn incompat(id: &str, package: &str, severity: IncompatibilitySeverity) -> IncompatibilityRecord {
    IncompatibilityRecord {
        incompatibility_id: id.to_string(),
        package_name: package.to_string(),
        root_cause: IncompatibilityRootCause::MissingNodeApi,
        severity,
        summary: format!("issue in {package}"),
        minimized_repro: "require('missing')".to_string(),
        expected_behavior: "works".to_string(),
        actual_behavior: "throws".to_string(),
        remediation_state: RemediationState::Discovered,
        owner: String::new(),
        related_beads: BTreeSet::new(),
        discovered_epoch: 1,
        last_updated_epoch: 1,
    }
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn constants_are_nonempty() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    const {
        assert!(MAX_PACKAGES_PER_COHORT > 0);
        assert!(MAX_INCOMPATIBILITIES_PER_PACKAGE > 0);
    }
}

#[test]
fn schema_version_contains_module_name() {
    assert!(
        SCHEMA_VERSION.contains("npm-compatibility-matrix"),
        "schema version should reference module: {SCHEMA_VERSION}"
    );
}

#[test]
fn npm_runner_script_emits_exact_replay_and_bundle_contract() {
    let path = repo_root().join("scripts/run_rgc_npm_compatibility_matrix.sh");
    let script = read_to_string(&path);

    for needle in [
        "run_dir=\"${artifact_root}/${run_stamp}\"",
        "replay_command=\"RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR=${run_dir} ./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh\"",
        "run_dir_is_complete()",
        "npm_compat_matrix_report.json",
        "trace_ids.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "rgc npm compatibility matrix replay: ${replay_command}",
        "incomplete bundle",
    ] {
        assert!(script.contains(needle), "runner script missing {needle}");
    }
}

#[test]
fn npm_replay_wrapper_requires_complete_bundle_and_exact_run_dir() {
    let path = repo_root().join("scripts/e2e/rgc_npm_compatibility_matrix_replay.sh");
    let script = read_to_string(&path);

    for needle in [
        "RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR",
        "latest_complete_run_dir()",
        "npm_compat_matrix_report.json",
        "trace_ids.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "explicit run directory is incomplete",
        "latest report",
        "latest trace ids",
        "latest manifest",
        "latest events",
        "latest commands",
    ] {
        assert!(script.contains(needle), "replay wrapper missing {needle}");
    }
}

// ── CohortTier exhaustive ───────────────────────────────────────────────

#[test]
fn cohort_tier_all_variants_serde_roundtrip() {
    let all = [
        CohortTier::Tier1Critical,
        CohortTier::Tier2Popular,
        CohortTier::Tier3LongTail,
    ];
    for tier in all {
        let json = serde_json::to_string(&tier).unwrap();
        let back: CohortTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, back);
    }
}

#[test]
fn cohort_tier_display_unique() {
    let all = [
        CohortTier::Tier1Critical,
        CohortTier::Tier2Popular,
        CohortTier::Tier3LongTail,
    ];
    let mut seen = BTreeSet::new();
    for tier in all {
        let s = tier.to_string();
        assert!(!s.is_empty());
        assert!(seen.insert(s.clone()), "duplicate display: {s}");
        assert_eq!(s, tier.as_str());
    }
}

#[test]
fn cohort_tier_ordering_matches_criticality() {
    assert!(CohortTier::Tier1Critical < CohortTier::Tier2Popular);
    assert!(CohortTier::Tier2Popular < CohortTier::Tier3LongTail);
}

#[test]
fn cohort_tier_thresholds_decrease_by_tier() {
    assert!(
        CohortTier::Tier1Critical.unblock_threshold_millionths()
            > CohortTier::Tier2Popular.unblock_threshold_millionths()
    );
    assert!(
        CohortTier::Tier2Popular.unblock_threshold_millionths()
            > CohortTier::Tier3LongTail.unblock_threshold_millionths()
    );
}

// ── PackageCategory exhaustive ──────────────────────────────────────────

#[test]
fn package_category_all_variants_serde_roundtrip() {
    let all = [
        PackageCategory::BuildTool,
        PackageCategory::TestFramework,
        PackageCategory::HttpNetworking,
        PackageCategory::DatabaseOrm,
        PackageCategory::CliTool,
        PackageCategory::UtilityLibrary,
        PackageCategory::CryptoSecurity,
        PackageCategory::FileSystem,
        PackageCategory::StreamBuffer,
        PackageCategory::Framework,
        PackageCategory::Other,
    ];
    let mut displays = BTreeSet::new();
    for cat in all {
        let json = serde_json::to_string(&cat).unwrap();
        let back: PackageCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
        let s = cat.to_string();
        assert_eq!(s, cat.as_str());
        assert!(displays.insert(s.clone()), "duplicate display: {s}");
    }
    assert_eq!(displays.len(), 11);
}

// ── ModuleSystemReq exhaustive ──────────────────────────────────────────

#[test]
fn module_system_req_all_variants_serde_roundtrip() {
    let all = [
        ModuleSystemReq::EsmOnly,
        ModuleSystemReq::CjsOnly,
        ModuleSystemReq::DualEsmCjs,
        ModuleSystemReq::Unknown,
    ];
    let mut displays = BTreeSet::new();
    for ms in all {
        let json = serde_json::to_string(&ms).unwrap();
        let back: ModuleSystemReq = serde_json::from_str(&json).unwrap();
        assert_eq!(ms, back);
        let s = ms.as_str();
        assert!(!s.is_empty());
        assert!(displays.insert(s.to_string()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 4);
}

// ── IncompatibilityRootCause exhaustive ─────────────────────────────────

#[test]
fn root_cause_all_variants_serde_and_display() {
    let all = [
        IncompatibilityRootCause::MissingNodeApi,
        IncompatibilityRootCause::CjsRequireDivergence,
        IncompatibilityRootCause::EsmResolutionDivergence,
        IncompatibilityRootCause::ExportsMapDivergence,
        IncompatibilityRootCause::NativeAddon,
        IncompatibilityRootCause::V8SpecificApi,
        IncompatibilityRootCause::ProcessGlobalsDivergence,
        IncompatibilityRootCause::ChildProcessDivergence,
        IncompatibilityRootCause::StreamBufferDivergence,
        IncompatibilityRootCause::TypeScriptCompilation,
        IncompatibilityRootCause::RuntimeIdentityCheck,
        IncompatibilityRootCause::Other,
    ];
    let mut displays = BTreeSet::new();
    for rc in all {
        let json = serde_json::to_string(&rc).unwrap();
        let back: IncompatibilityRootCause = serde_json::from_str(&json).unwrap();
        assert_eq!(rc, back);
        let s = rc.to_string();
        assert_eq!(s, rc.as_str());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 12);
}

// ── IncompatibilitySeverity exhaustive ───────────────────────────────────

#[test]
fn severity_all_variants_serde_and_display() {
    let all = [
        IncompatibilitySeverity::Blocker,
        IncompatibilitySeverity::Major,
        IncompatibilitySeverity::Minor,
        IncompatibilitySeverity::Cosmetic,
    ];
    let mut displays = BTreeSet::new();
    for sev in all {
        let json = serde_json::to_string(&sev).unwrap();
        let back: IncompatibilitySeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
        let s = sev.to_string();
        assert_eq!(s, sev.as_str());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn severity_weight_strictly_decreasing() {
    let all = [
        IncompatibilitySeverity::Blocker,
        IncompatibilitySeverity::Major,
        IncompatibilitySeverity::Minor,
        IncompatibilitySeverity::Cosmetic,
    ];
    for w in all.windows(2) {
        assert!(
            w[0].weight_millionths() > w[1].weight_millionths(),
            "{:?} weight should exceed {:?}",
            w[0],
            w[1]
        );
    }
}

// ── RemediationState exhaustive ─────────────────────────────────────────

#[test]
fn remediation_state_all_variants_serde_and_display() {
    let all = [
        RemediationState::Discovered,
        RemediationState::Triaged,
        RemediationState::InProgress,
        RemediationState::FixLanded,
        RemediationState::Verified,
        RemediationState::WontFix,
    ];
    let mut displays = BTreeSet::new();
    for st in all {
        let json = serde_json::to_string(&st).unwrap();
        let back: RemediationState = serde_json::from_str(&json).unwrap();
        assert_eq!(st, back);
        let s = st.to_string();
        assert_eq!(s, st.as_str());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn remediation_is_resolved_only_for_terminal_states() {
    assert!(!RemediationState::Discovered.is_resolved());
    assert!(!RemediationState::Triaged.is_resolved());
    assert!(!RemediationState::InProgress.is_resolved());
    assert!(!RemediationState::FixLanded.is_resolved());
    assert!(RemediationState::Verified.is_resolved());
    assert!(RemediationState::WontFix.is_resolved());
}

// ── PackageTestOutcome exhaustive ───────────────────────────────────────

#[test]
fn test_outcome_all_variants_serde_and_display() {
    let all = [
        PackageTestOutcome::Compatible,
        PackageTestOutcome::PartiallyCompatible,
        PackageTestOutcome::Incompatible,
        PackageTestOutcome::Skipped,
        PackageTestOutcome::Untested,
    ];
    let mut displays = BTreeSet::new();
    for oc in all {
        let json = serde_json::to_string(&oc).unwrap();
        let back: PackageTestOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(oc, back);
        let s = oc.to_string();
        assert_eq!(s, oc.as_str());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn test_outcome_counts_as_compatible_only_for_compatible() {
    assert!(PackageTestOutcome::Compatible.counts_as_compatible());
    assert!(!PackageTestOutcome::PartiallyCompatible.counts_as_compatible());
    assert!(!PackageTestOutcome::Incompatible.counts_as_compatible());
    assert!(!PackageTestOutcome::Skipped.counts_as_compatible());
    assert!(!PackageTestOutcome::Untested.counts_as_compatible());
}

// ── MatrixVerdict exhaustive ────────────────────────────────────────────

#[test]
fn verdict_all_variants_serde_and_display() {
    let all = [
        MatrixVerdict::AllCohortsUnblocked,
        MatrixVerdict::PartiallyUnblocked,
        MatrixVerdict::Blocked,
        MatrixVerdict::InsufficientData,
    ];
    let mut displays = BTreeSet::new();
    for v in all {
        let json = serde_json::to_string(&v).unwrap();
        let back: MatrixVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
        let s = v.to_string();
        assert_eq!(s, v.as_str());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 4);
}

// ── NpmCompatibilityError display all variants ──────────────────────────

#[test]
fn error_display_all_variants_nonempty_and_unique() {
    let errors: Vec<NpmCompatibilityError> = vec![
        NpmCompatibilityError::DuplicatePackage { name: "foo".into() },
        NpmCompatibilityError::DuplicateIncompatibility {
            id: "INC-001".into(),
        },
        NpmCompatibilityError::PackageNotFound { name: "bar".into() },
        NpmCompatibilityError::IncompatibilityNotFound {
            id: "INC-999".into(),
        },
        NpmCompatibilityError::CohortOverflow {
            tier: CohortTier::Tier1Critical,
            count: 501,
        },
        NpmCompatibilityError::IncompatibilityOverflow {
            package: "baz".into(),
            count: 101,
        },
        NpmCompatibilityError::InvalidStateTransition {
            id: "INC-001".into(),
            from: RemediationState::Discovered,
            to: RemediationState::Verified,
        },
        NpmCompatibilityError::SnapshotHashMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        },
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty());
        assert!(displays.insert(s.clone()), "duplicate error display: {s}");
    }
    assert_eq!(displays.len(), 8);
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors: Vec<NpmCompatibilityError> = vec![
        NpmCompatibilityError::DuplicatePackage { name: "x".into() },
        NpmCompatibilityError::DuplicateIncompatibility { id: "y".into() },
        NpmCompatibilityError::PackageNotFound { name: "z".into() },
        NpmCompatibilityError::IncompatibilityNotFound { id: "w".into() },
        NpmCompatibilityError::CohortOverflow {
            tier: CohortTier::Tier3LongTail,
            count: 600,
        },
        NpmCompatibilityError::IncompatibilityOverflow {
            package: "q".into(),
            count: 200,
        },
        NpmCompatibilityError::InvalidStateTransition {
            id: "r".into(),
            from: RemediationState::Triaged,
            to: RemediationState::Verified,
        },
        NpmCompatibilityError::SnapshotHashMismatch {
            expected: "e".into(),
            actual: "a".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: NpmCompatibilityError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ── PackageRecord serde ─────────────────────────────────────────────────

#[test]
fn package_record_serde_roundtrip() {
    let mut p = pkg("express", CohortTier::Tier1Critical);
    p.category = PackageCategory::HttpNetworking;
    p.module_system = ModuleSystemReq::CjsOnly;
    p.node_api_deps.insert("http".to_string());
    p.node_api_deps.insert("fs".to_string());
    p.types_only = false;
    let json = serde_json::to_string(&p).unwrap();
    let back: PackageRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn package_record_types_only_flag() {
    let mut p = pkg("@types/node", CohortTier::Tier1Critical);
    p.types_only = true;
    let json = serde_json::to_string(&p).unwrap();
    let back: PackageRecord = serde_json::from_str(&json).unwrap();
    assert!(back.types_only);
}

// ── IncompatibilityRecord serde ─────────────────────────────────────────

#[test]
fn incompatibility_record_serde_roundtrip() {
    let mut inc = incompat("INC-test-001", "express", IncompatibilitySeverity::Blocker);
    inc.root_cause = IncompatibilityRootCause::NativeAddon;
    inc.owner = "PearlTower".to_string();
    inc.related_beads.insert("bd-xyz".to_string());
    let json = serde_json::to_string(&inc).unwrap();
    let back: IncompatibilityRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(inc, back);
}

// ── PackageTestResult serde and edge cases ──────────────────────────────

#[test]
fn package_test_result_serde_roundtrip() {
    let mut r = test_result("express", PackageTestOutcome::PartiallyCompatible, 100, 75);
    r.output_hash = Some("abc123".to_string());
    r.test_epoch = 42;
    let json = serde_json::to_string(&r).unwrap();
    let back: PackageTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn pass_rate_partial_pass() {
    let r = test_result("x", PackageTestOutcome::PartiallyCompatible, 4, 3);
    assert_eq!(r.pass_rate_millionths(), 750_000);
}

#[test]
fn pass_rate_full_pass() {
    let r = test_result("x", PackageTestOutcome::Compatible, 10, 10);
    assert_eq!(r.pass_rate_millionths(), 1_000_000);
}

#[test]
fn pass_rate_no_pass() {
    let r = test_result("x", PackageTestOutcome::Incompatible, 10, 0);
    assert_eq!(r.pass_rate_millionths(), 0);
}

// ── CohortSummary serde ─────────────────────────────────────────────────

#[test]
fn cohort_summary_serde_roundtrip() {
    let cs = CohortSummary {
        tier: CohortTier::Tier2Popular,
        total_packages: 10,
        compatible_count: 7,
        partially_compatible_count: 1,
        incompatible_count: 1,
        skipped_count: 0,
        untested_count: 1,
        compatibility_rate_millionths: 700_000,
        unblock_threshold_millionths: 900_000,
        unblocked: false,
        open_incompatibilities: 3,
        blocker_count: 1,
    };
    let json = serde_json::to_string(&cs).unwrap();
    let back: CohortSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(cs, back);
}

// ── Normalize edge cases ────────────────────────────────────────────────

#[test]
fn normalize_trims_whitespace_on_package() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut p = pkg("  lodash  ", CohortTier::Tier1Critical);
    p.node_api_deps.insert("  fs  ".to_string());
    p.node_api_deps.insert("".to_string());
    m.add_package(p).unwrap();
    assert_eq!(
        m.packages_in_tier(CohortTier::Tier1Critical)[0].name,
        "lodash"
    );
    let deps: Vec<&String> = m.packages_in_tier(CohortTier::Tier1Critical)[0]
        .node_api_deps
        .iter()
        .collect();
    assert_eq!(deps, vec!["fs"]);
}

#[test]
fn normalize_trims_whitespace_on_incompatibility() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut inc = incompat("  INC-001  ", "  express  ", IncompatibilitySeverity::Minor);
    inc.summary = "  issue  ".to_string();
    inc.owner = "  agent  ".to_string();
    inc.related_beads.insert("  bd-xyz  ".to_string());
    inc.related_beads.insert("".to_string());
    m.add_incompatibility(inc).unwrap();
    let stored = &m.incompatibilities[0];
    assert_eq!(stored.incompatibility_id, "INC-001");
    assert_eq!(stored.package_name, "express");
    assert_eq!(stored.summary, "issue");
    assert_eq!(stored.owner, "agent");
    assert!(stored.related_beads.contains("bd-xyz"));
    assert!(!stored.related_beads.contains(""));
}

// ── Overflow guards ─────────────────────────────────────────────────────

#[test]
fn cohort_overflow_guard_rejects_excess_packages() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..MAX_PACKAGES_PER_COHORT {
        m.add_package(pkg(&format!("pkg-{i}"), CohortTier::Tier3LongTail))
            .unwrap();
    }
    let err = m
        .add_package(pkg("overflow", CohortTier::Tier3LongTail))
        .unwrap_err();
    assert!(matches!(*err, NpmCompatibilityError::CohortOverflow { .. }));
}

#[test]
fn incompatibility_overflow_guard_rejects_excess() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..MAX_INCOMPATIBILITIES_PER_PACKAGE {
        m.add_incompatibility(incompat(
            &format!("INC-{i}"),
            "express",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
    }
    let err = m
        .add_incompatibility(incompat(
            "INC-overflow",
            "express",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap_err();
    assert!(matches!(
        *err,
        NpmCompatibilityError::IncompatibilityOverflow { .. }
    ));
}

// ── Remediation state machine completeness ──────────────────────────────

#[test]
fn all_valid_state_transitions_succeed() {
    let valid_transitions = [
        (RemediationState::Discovered, RemediationState::Triaged),
        (RemediationState::Triaged, RemediationState::InProgress),
        (RemediationState::Triaged, RemediationState::WontFix),
        (RemediationState::InProgress, RemediationState::FixLanded),
        (RemediationState::InProgress, RemediationState::WontFix),
        (RemediationState::FixLanded, RemediationState::Verified),
        (RemediationState::FixLanded, RemediationState::InProgress),
    ];

    for (i, (from, to)) in valid_transitions.iter().enumerate() {
        let mut m = NpmCompatibilityMatrix::new();
        let id = format!("INC-{i}");
        let mut inc = incompat(&id, "p", IncompatibilitySeverity::Minor);
        inc.remediation_state = *from;
        m.add_incompatibility(inc).unwrap();
        assert!(
            m.transition_remediation(&id, *to, 10).is_ok(),
            "transition {:?} -> {:?} should be valid",
            from,
            to
        );
    }
}

#[test]
fn invalid_state_transitions_rejected() {
    let invalid_transitions = [
        (RemediationState::Discovered, RemediationState::InProgress),
        (RemediationState::Discovered, RemediationState::FixLanded),
        (RemediationState::Discovered, RemediationState::Verified),
        (RemediationState::Discovered, RemediationState::WontFix),
        (RemediationState::Triaged, RemediationState::FixLanded),
        (RemediationState::Triaged, RemediationState::Verified),
        (RemediationState::InProgress, RemediationState::Triaged),
        (RemediationState::InProgress, RemediationState::Verified),
        (RemediationState::FixLanded, RemediationState::Triaged),
        (RemediationState::FixLanded, RemediationState::WontFix),
        (RemediationState::Verified, RemediationState::Discovered),
        (RemediationState::WontFix, RemediationState::Discovered),
    ];

    for (i, (from, to)) in invalid_transitions.iter().enumerate() {
        let mut m = NpmCompatibilityMatrix::new();
        let id = format!("INC-inv-{i}");
        let mut inc = incompat(&id, "p", IncompatibilitySeverity::Minor);
        inc.remediation_state = *from;
        m.add_incompatibility(inc).unwrap();
        assert!(
            m.transition_remediation(&id, *to, 10).is_err(),
            "transition {:?} -> {:?} should be invalid",
            from,
            to
        );
    }
}

#[test]
fn transition_updates_last_updated_epoch() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(incompat("INC-001", "p", IncompatibilitySeverity::Minor))
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::Triaged, 99)
        .unwrap();
    let rec = m
        .incompatibilities
        .iter()
        .find(|i| i.incompatibility_id == "INC-001")
        .unwrap();
    assert_eq!(rec.last_updated_epoch, 99);
}

// ── Multi-tier verdict scenarios ────────────────────────────────────────

#[test]
fn verdict_partially_unblocked() {
    let mut m = NpmCompatibilityMatrix::new();
    // Tier 1: 100% compatible → unblocked
    m.add_package(pkg("a", CohortTier::Tier1Critical)).unwrap();
    m.record_test_result(test_result("a", PackageTestOutcome::Compatible, 10, 10))
        .unwrap();
    // Tier 2: 0% compatible → blocked
    m.add_package(pkg("b", CohortTier::Tier2Popular)).unwrap();
    m.record_test_result(test_result("b", PackageTestOutcome::Incompatible, 10, 0))
        .unwrap();
    assert_eq!(m.verdict(), MatrixVerdict::PartiallyUnblocked);
}

#[test]
fn verdict_all_tiers_present_and_unblocked() {
    let mut m = NpmCompatibilityMatrix::new();
    for (name, tier) in [
        ("a", CohortTier::Tier1Critical),
        ("b", CohortTier::Tier2Popular),
        ("c", CohortTier::Tier3LongTail),
    ] {
        m.add_package(pkg(name, tier)).unwrap();
        m.record_test_result(test_result(name, PackageTestOutcome::Compatible, 10, 10))
            .unwrap();
    }
    assert_eq!(m.verdict(), MatrixVerdict::AllCohortsUnblocked);
}

#[test]
fn verdict_all_tiers_blocked() {
    let mut m = NpmCompatibilityMatrix::new();
    for (name, tier) in [
        ("a", CohortTier::Tier1Critical),
        ("b", CohortTier::Tier2Popular),
        ("c", CohortTier::Tier3LongTail),
    ] {
        m.add_package(pkg(name, tier)).unwrap();
        m.record_test_result(test_result(name, PackageTestOutcome::Incompatible, 10, 0))
            .unwrap();
    }
    assert_eq!(m.verdict(), MatrixVerdict::Blocked);
}

// ── Cohort summary edge cases ───────────────────────────────────────────

#[test]
fn cohort_summary_empty_tier_has_zero_rate() {
    let m = NpmCompatibilityMatrix::new();
    let summary = m.cohort_summary(CohortTier::Tier3LongTail);
    assert_eq!(summary.total_packages, 0);
    assert_eq!(summary.compatibility_rate_millionths, 0);
    assert!(!summary.unblocked);
}

#[test]
fn cohort_summary_all_skipped_has_zero_rate() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(pkg("a", CohortTier::Tier1Critical)).unwrap();
    m.add_package(pkg("b", CohortTier::Tier1Critical)).unwrap();
    m.record_test_result(test_result("a", PackageTestOutcome::Skipped, 0, 0))
        .unwrap();
    m.record_test_result(test_result("b", PackageTestOutcome::Skipped, 0, 0))
        .unwrap();
    let summary = m.cohort_summary(CohortTier::Tier1Critical);
    assert_eq!(summary.skipped_count, 2);
    assert_eq!(summary.compatibility_rate_millionths, 0);
}

#[test]
fn cohort_summary_blocker_count_reflects_open_blockers() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(pkg("express", CohortTier::Tier1Critical))
        .unwrap();
    m.add_incompatibility(incompat(
        "INC-001",
        "express",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m.add_incompatibility(incompat(
        "INC-002",
        "express",
        IncompatibilitySeverity::Major,
    ))
    .unwrap();
    let summary = m.cohort_summary(CohortTier::Tier1Critical);
    assert_eq!(summary.blocker_count, 1);
    assert_eq!(summary.open_incompatibilities, 2);
}

#[test]
fn cohort_summary_resolved_incompat_excluded_from_open() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(pkg("express", CohortTier::Tier1Critical))
        .unwrap();
    m.add_incompatibility(incompat(
        "INC-001",
        "express",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::InProgress, 3)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::FixLanded, 4)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::Verified, 5)
        .unwrap();
    let summary = m.cohort_summary(CohortTier::Tier1Critical);
    assert_eq!(summary.open_incompatibilities, 0);
    assert_eq!(summary.blocker_count, 0);
}

// ── Root cause distribution edge cases ──────────────────────────────────

#[test]
fn root_cause_distribution_excludes_resolved() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut inc = incompat("INC-001", "a", IncompatibilitySeverity::Minor);
    inc.root_cause = IncompatibilityRootCause::NativeAddon;
    m.add_incompatibility(inc).unwrap();
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::WontFix, 3)
        .unwrap();
    let dist = m.root_cause_distribution();
    assert!(dist.is_empty());
}

#[test]
fn root_cause_distribution_all_causes() {
    let mut m = NpmCompatibilityMatrix::new();
    let causes = [
        IncompatibilityRootCause::MissingNodeApi,
        IncompatibilityRootCause::CjsRequireDivergence,
        IncompatibilityRootCause::EsmResolutionDivergence,
        IncompatibilityRootCause::ExportsMapDivergence,
        IncompatibilityRootCause::NativeAddon,
        IncompatibilityRootCause::V8SpecificApi,
    ];
    for (i, cause) in causes.iter().enumerate() {
        let mut inc = incompat(
            &format!("INC-{i}"),
            &format!("pkg-{i}"),
            IncompatibilitySeverity::Minor,
        );
        inc.root_cause = *cause;
        m.add_incompatibility(inc).unwrap();
    }
    let dist = m.root_cause_distribution();
    assert_eq!(dist.len(), 6);
    for count in dist.values() {
        assert_eq!(*count, 1);
    }
}

// ── Top blockers edge cases ─────────────────────────────────────────────

#[test]
fn top_blockers_empty_matrix() {
    let m = NpmCompatibilityMatrix::new();
    assert!(m.top_blockers(10).is_empty());
}

#[test]
fn top_blockers_respects_limit() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..5 {
        m.add_incompatibility(incompat(
            &format!("INC-{i}"),
            &format!("pkg-{i}"),
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
    }
    let top = m.top_blockers(3);
    assert_eq!(top.len(), 3);
}

#[test]
fn top_blockers_excludes_resolved() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(incompat(
        "INC-001",
        "resolved-pkg",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::WontFix, 3)
        .unwrap();
    m.add_incompatibility(incompat(
        "INC-002",
        "open-pkg",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    let top = m.top_blockers(10);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].0, "open-pkg");
}

// ── Content hash sensitivity ────────────────────────────────────────────

#[test]
fn content_hash_changes_with_different_data() {
    let mut m1 = NpmCompatibilityMatrix::new();
    m1.add_package(pkg("a", CohortTier::Tier1Critical)).unwrap();
    let h1 = m1.normalize_and_hash();

    let mut m2 = NpmCompatibilityMatrix::new();
    m2.add_package(pkg("b", CohortTier::Tier1Critical)).unwrap();
    let h2 = m2.normalize_and_hash();

    assert_ne!(h1, h2);
}

#[test]
fn content_hash_stable_across_calls() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(pkg("a", CohortTier::Tier1Critical)).unwrap();
    let h1 = m.normalize_and_hash();
    let h2 = m.normalize_and_hash();
    assert_eq!(h1, h2);
}

// ── Seed cohort integration ─────────────────────────────────────────────

#[test]
fn seed_tier1_packages_integrate_into_matrix() {
    let mut m = NpmCompatibilityMatrix::new();
    for p in seed_tier1_critical_packages() {
        m.add_package(p).unwrap();
    }
    assert!(m.total_packages() >= 10);
    for p in m.packages_in_tier(CohortTier::Tier1Critical) {
        assert_eq!(p.tier, CohortTier::Tier1Critical);
        assert!(p.weekly_downloads > 0);
    }
}

#[test]
fn seed_tier2_packages_integrate_into_matrix() {
    let mut m = NpmCompatibilityMatrix::new();
    for p in seed_tier2_popular_packages() {
        m.add_package(p).unwrap();
    }
    assert!(m.total_packages() >= 10);
    for p in m.packages_in_tier(CohortTier::Tier2Popular) {
        assert_eq!(p.tier, CohortTier::Tier2Popular);
    }
}

#[test]
fn seed_tier1_and_tier2_no_overlap() {
    let t1 = seed_tier1_critical_packages();
    let t2 = seed_tier2_popular_packages();
    let names1: BTreeSet<String> = t1.iter().map(|p| p.name.clone()).collect();
    let names2: BTreeSet<String> = t2.iter().map(|p| p.name.clone()).collect();
    let overlap: Vec<&String> = names1.intersection(&names2).collect();
    assert!(overlap.is_empty(), "seed cohorts overlap: {overlap:?}");
}

#[test]
fn seed_packages_all_have_valid_categories() {
    for p in seed_tier1_critical_packages()
        .into_iter()
        .chain(seed_tier2_popular_packages())
    {
        let json = serde_json::to_string(&p.category).unwrap();
        let _: PackageCategory = serde_json::from_str(&json).unwrap();
    }
}

// ── Packages sorted by name after insertion ─────────────────────────────

#[test]
fn packages_sorted_alphabetically_after_insertion() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(pkg("zod", CohortTier::Tier1Critical))
        .unwrap();
    m.add_package(pkg("axios", CohortTier::Tier1Critical))
        .unwrap();
    m.add_package(pkg("express", CohortTier::Tier1Critical))
        .unwrap();
    let names: Vec<&str> = m
        .packages_in_tier(CohortTier::Tier1Critical)
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, vec!["axios", "express", "zod"]);
}

// ── Incompatibilities sorted by id after insertion ──────────────────────

#[test]
fn incompatibilities_sorted_by_id_after_insertion() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(incompat("INC-003", "a", IncompatibilitySeverity::Minor))
        .unwrap();
    m.add_incompatibility(incompat("INC-001", "a", IncompatibilitySeverity::Major))
        .unwrap();
    m.add_incompatibility(incompat("INC-002", "a", IncompatibilitySeverity::Blocker))
        .unwrap();
    let ids: Vec<&str> = m
        .incompatibilities
        .iter()
        .map(|i| i.incompatibility_id.as_str())
        .collect();
    assert_eq!(ids, vec!["INC-001", "INC-002", "INC-003"]);
}

// ── Test results sorted by package name ─────────────────────────────────

#[test]
fn test_results_sorted_by_package_name() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(pkg("zod", CohortTier::Tier1Critical))
        .unwrap();
    m.add_package(pkg("axios", CohortTier::Tier1Critical))
        .unwrap();
    m.record_test_result(test_result("zod", PackageTestOutcome::Compatible, 10, 10))
        .unwrap();
    m.record_test_result(test_result("axios", PackageTestOutcome::Compatible, 5, 5))
        .unwrap();
    let names: Vec<&str> = m
        .test_results
        .iter()
        .map(|r| r.package_name.as_str())
        .collect();
    assert_eq!(names, vec!["axios", "zod"]);
}

// ── Matrix serde roundtrip with full data ───────────────────────────────

#[test]
fn matrix_serde_roundtrip_full_data() {
    let mut m = NpmCompatibilityMatrix::new();
    m.snapshot_epoch = 42;
    m.add_package(pkg("a", CohortTier::Tier1Critical)).unwrap();
    m.add_package(pkg("b", CohortTier::Tier2Popular)).unwrap();
    m.record_test_result(test_result("a", PackageTestOutcome::Compatible, 50, 50))
        .unwrap();
    m.record_test_result(test_result(
        "b",
        PackageTestOutcome::PartiallyCompatible,
        50,
        30,
    ))
    .unwrap();
    m.add_incompatibility(incompat("INC-001", "b", IncompatibilitySeverity::Major))
        .unwrap();

    let json = serde_json::to_string(&m).unwrap();
    let back: NpmCompatibilityMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
    assert_eq!(back.snapshot_epoch, 42);
}

// ── Incompatibilities by root cause ─────────────────────────────────────

#[test]
fn incompatibilities_by_root_cause_filters_correctly() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut inc1 = incompat("INC-001", "a", IncompatibilitySeverity::Minor);
    inc1.root_cause = IncompatibilityRootCause::NativeAddon;
    m.add_incompatibility(inc1).unwrap();

    let mut inc2 = incompat("INC-002", "b", IncompatibilitySeverity::Minor);
    inc2.root_cause = IncompatibilityRootCause::V8SpecificApi;
    m.add_incompatibility(inc2).unwrap();

    assert_eq!(
        m.incompatibilities_by_root_cause(IncompatibilityRootCause::NativeAddon)
            .len(),
        1
    );
    assert_eq!(
        m.incompatibilities_by_root_cause(IncompatibilityRootCause::V8SpecificApi)
            .len(),
        1
    );
    assert_eq!(
        m.incompatibilities_by_root_cause(IncompatibilityRootCause::Other)
            .len(),
        0
    );
}

// ── Packages requiring API ──────────────────────────────────────────────

#[test]
fn packages_requiring_api_multiple_matches() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut p1 = pkg("a", CohortTier::Tier1Critical);
    p1.node_api_deps.insert("fs".to_string());
    p1.node_api_deps.insert("path".to_string());
    m.add_package(p1).unwrap();

    let mut p2 = pkg("b", CohortTier::Tier1Critical);
    p2.node_api_deps.insert("fs".to_string());
    m.add_package(p2).unwrap();

    let mut p3 = pkg("c", CohortTier::Tier1Critical);
    p3.node_api_deps.insert("crypto".to_string());
    m.add_package(p3).unwrap();

    assert_eq!(m.packages_requiring_api("fs").len(), 2);
    assert_eq!(m.packages_requiring_api("path").len(), 1);
    assert_eq!(m.packages_requiring_api("crypto").len(), 1);
    assert_eq!(m.packages_requiring_api("nonexistent").len(), 0);
}
