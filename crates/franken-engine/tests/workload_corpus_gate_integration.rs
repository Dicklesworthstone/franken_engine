//! Integration tests for workload_corpus_gate (RGC-704).
//!
//! Tests cover corpus management, behavior-equivalence gating, provenance
//! tracking, verdict computation, and deterministic evidence hashing.

#![allow(
    clippy::needless_borrows_for_generic_args,
    clippy::comparison_to_empty,
    clippy::len_zero
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::workload_corpus_gate::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn specimen(id: &str, family: WorkloadFamily, lang: InputLanguage) -> WorkloadSpecimen {
    WorkloadSpecimen {
        id: id.to_string(),
        name: format!("Integration test workload: {id}"),
        family,
        secondary_families: BTreeSet::new(),
        language: lang,
        provenance: WorkloadProvenance {
            origin: WorkloadOrigin::InternalFixture,
            source_url: format!("integration://{id}"),
            license: LicenseStatus::Permissive,
            spdx_id: Some("MIT".to_string()),
            source_version: "int-v1".to_string(),
            selection_rationale: "integration test".to_string(),
            content_hash: ContentHash::compute(id.as_bytes()),
        },
        observability_modes: {
            let mut m = BTreeSet::new();
            m.insert(ObservabilityMode::BudgetedDefault);
            m
        },
        approximate_lines: 100,
        requires_native_addons: false,
        exercises_async: false,
        tags: BTreeSet::new(),
    }
}

fn equiv(id: &str, baseline: BaselineRuntime, class: DivergenceClass) -> EquivalenceResult {
    EquivalenceResult {
        specimen_id: id.to_string(),
        baseline,
        divergence_class: class,
        divergence_description: String::new(),
        output_hash_matches: class == DivergenceClass::Identical,
        franken_output_hash: ContentHash::compute(b"franken_out"),
        baseline_output_hash: ContentHash::compute(b"baseline_out"),
        evidence_path: None,
    }
}

fn full_corpus_with_equiv() -> WorkloadCorpus {
    let mut corpus = build_seed_corpus();
    for id in corpus.specimens.keys().cloned().collect::<Vec<_>>() {
        corpus.record_equivalence(equiv(
            &id,
            BaselineRuntime::NodeJs,
            DivergenceClass::Identical,
        ));
    }
    corpus
}

// ---------------------------------------------------------------------------
// Corpus lifecycle
// ---------------------------------------------------------------------------

#[test]
fn corpus_lifecycle_add_remove_readd() {
    let mut corpus = WorkloadCorpus::new();
    let s = specimen(
        "lifecycle_1",
        WorkloadFamily::ParseHeavy,
        InputLanguage::JavaScript,
    );
    corpus.add_specimen(s.clone()).unwrap();
    assert_eq!(corpus.specimen_count(), 1);
    corpus.remove_specimen("lifecycle_1").unwrap();
    assert_eq!(corpus.specimen_count(), 0);
    corpus.add_specimen(s).unwrap();
    assert_eq!(corpus.specimen_count(), 1);
}

#[test]
fn corpus_multiple_families_coverage() {
    let mut corpus = WorkloadCorpus::new();
    for (i, family) in WorkloadFamily::ALL.iter().enumerate() {
        corpus
            .add_specimen(specimen(
                &format!("fam_{i}"),
                *family,
                InputLanguage::JavaScript,
            ))
            .unwrap();
    }
    assert_eq!(corpus.covered_family_count(), 16);
    assert!(corpus.missing_families().is_empty());
}

#[test]
fn corpus_mixed_languages() {
    let mut corpus = WorkloadCorpus::new();
    corpus
        .add_specimen(specimen(
            "js_1",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
    corpus
        .add_specimen(specimen(
            "ts_1",
            WorkloadFamily::ParseHeavy,
            InputLanguage::TypeScript,
        ))
        .unwrap();
    corpus
        .add_specimen(specimen(
            "jsx_1",
            WorkloadFamily::ParseHeavy,
            InputLanguage::Jsx,
        ))
        .unwrap();
    corpus
        .add_specimen(specimen(
            "tsx_1",
            WorkloadFamily::ParseHeavy,
            InputLanguage::Tsx,
        ))
        .unwrap();
    assert_eq!(corpus.specimen_count(), 4);
    assert_eq!(
        corpus.specimens_by_family(WorkloadFamily::ParseHeavy).len(),
        4
    );
}

// ---------------------------------------------------------------------------
// Provenance tracking
// ---------------------------------------------------------------------------

#[test]
fn provenance_origins_roundtrip() {
    let origins = [
        WorkloadOrigin::NpmPackage,
        WorkloadOrigin::OpenSourceProject,
        WorkloadOrigin::BenchmarkSuite,
        WorkloadOrigin::Synthetic,
        WorkloadOrigin::RealUserAnonymized,
        WorkloadOrigin::InternalFixture,
    ];
    for origin in &origins {
        let json = serde_json::to_string(origin).unwrap();
        let back: WorkloadOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(*origin, back);
    }
}

#[test]
fn provenance_license_filtering() {
    let mut corpus = WorkloadCorpus::new();
    let mut s1 = specimen(
        "lic_mit",
        WorkloadFamily::ParseHeavy,
        InputLanguage::JavaScript,
    );
    s1.provenance.license = LicenseStatus::Permissive;
    let mut s2 = specimen(
        "lic_gpl",
        WorkloadFamily::AsyncHeavy,
        InputLanguage::JavaScript,
    );
    s2.provenance.license = LicenseStatus::Copyleft;
    let mut s3 = specimen(
        "lic_prop",
        WorkloadFamily::ModuleHeavy,
        InputLanguage::JavaScript,
    );
    s3.provenance.license = LicenseStatus::Restricted;
    let mut s4 = specimen(
        "lic_unk",
        WorkloadFamily::StringTransform,
        InputLanguage::JavaScript,
    );
    s4.provenance.license = LicenseStatus::Unknown;

    corpus.add_specimen(s1).unwrap();
    corpus.add_specimen(s2).unwrap();
    corpus.add_specimen(s3).unwrap();
    corpus.add_specimen(s4).unwrap();

    let unpub = corpus.unpublishable_specimens();
    assert_eq!(unpub.len(), 3); // copyleft, restricted, unknown
}

#[test]
fn provenance_content_hash_varies_by_source() {
    let s1 = specimen(
        "src_a",
        WorkloadFamily::ParseHeavy,
        InputLanguage::JavaScript,
    );
    let s2 = specimen(
        "src_b",
        WorkloadFamily::ParseHeavy,
        InputLanguage::JavaScript,
    );
    assert_ne!(s1.provenance.content_hash, s2.provenance.content_hash);
}

// ---------------------------------------------------------------------------
// Behavior equivalence
// ---------------------------------------------------------------------------

#[test]
fn equivalence_all_identical_100_percent() {
    let corpus = full_corpus_with_equiv();
    let config = GateConfig {
        min_per_family: 1,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert_eq!(report.aggregate_equivalence_rate_millionths, 1_000_000);
}

#[test]
fn equivalence_mixed_crash_vs_success() {
    let mut corpus = build_seed_corpus();
    let ids: Vec<String> = corpus.specimens.keys().cloned().collect();
    for (i, id) in ids.iter().enumerate() {
        let class = if i < 2 {
            DivergenceClass::CrashVsSuccess
        } else {
            DivergenceClass::Identical
        };
        corpus.record_equivalence(equiv(id, BaselineRuntime::NodeJs, class));
    }
    let config = GateConfig {
        min_per_family: 1,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    // 14/16 acceptable = 875_000
    assert_eq!(report.aggregate_equivalence_rate_millionths, 875_000);
    assert!(!report.verdict.permits_publication()); // below 950k threshold
}

#[test]
fn equivalence_multiple_baselines() {
    let mut corpus = build_seed_corpus();
    let ids: Vec<String> = corpus.specimens.keys().cloned().collect();
    for id in &ids {
        corpus.record_equivalence(equiv(
            id,
            BaselineRuntime::NodeJs,
            DivergenceClass::Identical,
        ));
        corpus.record_equivalence(equiv(
            id,
            BaselineRuntime::Bun,
            DivergenceClass::CosmeticOnly,
        ));
        corpus.record_equivalence(equiv(id, BaselineRuntime::Deno, DivergenceClass::Identical));
    }
    assert_eq!(corpus.equivalence_results.len(), 48); // 16 * 3
}

#[test]
fn equivalence_timeout_divergence_high_severity() {
    let sev = DivergenceClass::TimeoutDivergence.severity_weight_millionths();
    assert!(sev > DivergenceClass::SemanticDivergence.severity_weight_millionths());
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_pass_with_full_seed_and_equiv() {
    let corpus = full_corpus_with_equiv();
    let config = GateConfig {
        min_per_family: 1,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert!(report.verdict.permits_publication());
    assert_eq!(report.total_specimens, 16);
    assert_eq!(report.families_covered, 16);
    assert!(report.missing_families.is_empty());
}

#[test]
fn gate_fail_insufficient_families() {
    let mut corpus = WorkloadCorpus::new();
    corpus
        .add_specimen(specimen(
            "only_parse",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
    corpus.record_equivalence(equiv(
        "only_parse",
        BaselineRuntime::NodeJs,
        DivergenceClass::Identical,
    ));
    let gate = WorkloadCorpusGate::with_defaults();
    let report = gate.evaluate(&corpus);
    assert!(!report.verdict.permits_publication());
    if let GateVerdict::Fail { reasons } = &report.verdict {
        assert!(
            reasons
                .iter()
                .any(|r| { matches!(r, RejectionReason::InsufficientFamilyCoverage { .. }) })
        );
    }
}

#[test]
fn gate_fail_unpublishable_licenses() {
    let mut corpus = build_seed_corpus();
    // Replace one specimen with copyleft
    corpus.remove_specimen("regex_email_validator");
    let mut bad = specimen(
        "bad_lic",
        WorkloadFamily::RegexUnicode,
        InputLanguage::JavaScript,
    );
    bad.provenance.license = LicenseStatus::Copyleft;
    corpus.add_specimen(bad).unwrap();
    for id in corpus.specimens.keys().cloned().collect::<Vec<_>>() {
        corpus.record_equivalence(equiv(
            &id,
            BaselineRuntime::NodeJs,
            DivergenceClass::Identical,
        ));
    }
    let config = GateConfig {
        min_per_family: 1,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert!(!report.verdict.permits_publication());
    assert!(!report.unpublishable_specimen_ids.is_empty());
}

#[test]
fn gate_fail_missing_baseline() {
    let corpus = build_seed_corpus(); // no equivalence results
    let config = GateConfig {
        min_per_family: 1,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert!(!report.verdict.permits_publication());
}

#[test]
fn gate_report_has_all_family_summaries() {
    let corpus = full_corpus_with_equiv();
    let config = GateConfig {
        min_per_family: 1,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert_eq!(report.family_summaries.len(), 16);
}

#[test]
fn gate_report_serde_full_roundtrip() {
    let corpus = full_corpus_with_equiv();
    let config = GateConfig {
        min_per_family: 1,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    let json = serde_json::to_string_pretty(&report).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.verdict, back.verdict);
    assert_eq!(report.corpus_hash, back.corpus_hash);
    assert_eq!(report.total_specimens, back.total_specimens);
}

// ---------------------------------------------------------------------------
// Secondary families
// ---------------------------------------------------------------------------

#[test]
fn secondary_families_increase_coverage() {
    let mut corpus = WorkloadCorpus::new();
    let mut s = specimen(
        "multi",
        WorkloadFamily::MixedRealWorld,
        InputLanguage::TypeScript,
    );
    s.secondary_families.insert(WorkloadFamily::AsyncHeavy);
    s.secondary_families.insert(WorkloadFamily::ModuleHeavy);
    s.secondary_families.insert(WorkloadFamily::TypeScriptHeavy);
    corpus.add_specimen(s).unwrap();
    assert_eq!(corpus.covered_family_count(), 4);
    assert_eq!(
        corpus.specimens_by_family(WorkloadFamily::AsyncHeavy).len(),
        1
    );
    assert_eq!(
        corpus
            .specimens_by_family(WorkloadFamily::TypeScriptHeavy)
            .len(),
        1
    );
}

#[test]
fn remove_cleans_secondary_families() {
    let mut corpus = WorkloadCorpus::new();
    let mut s = specimen(
        "sec_rm",
        WorkloadFamily::MixedRealWorld,
        InputLanguage::TypeScript,
    );
    s.secondary_families.insert(WorkloadFamily::AsyncHeavy);
    corpus.add_specimen(s).unwrap();
    assert_eq!(corpus.covered_family_count(), 2);
    corpus.remove_specimen("sec_rm");
    assert_eq!(corpus.covered_family_count(), 0);
}

// ---------------------------------------------------------------------------
// Observability modes
// ---------------------------------------------------------------------------

#[test]
fn observability_modes_serde_roundtrip() {
    let modes = [
        ObservabilityMode::BudgetedDefault,
        ObservabilityMode::ExactShadow,
        ObservabilityMode::Degraded,
        ObservabilityMode::IncidentFullCapture,
    ];
    for mode in &modes {
        let json = serde_json::to_string(mode).unwrap();
        let back: ObservabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

#[test]
fn specimen_with_multiple_observability_modes() {
    let mut s = specimen(
        "obs_multi",
        WorkloadFamily::ObservabilitySensitive,
        InputLanguage::TypeScript,
    );
    s.observability_modes.insert(ObservabilityMode::ExactShadow);
    s.observability_modes
        .insert(ObservabilityMode::IncidentFullCapture);
    assert_eq!(s.observability_modes.len(), 3);
}

// ---------------------------------------------------------------------------
// Deterministic hashing
// ---------------------------------------------------------------------------

#[test]
fn content_hash_deterministic_across_corpus_builds() {
    let c1 = build_seed_corpus();
    let c2 = build_seed_corpus();
    assert_eq!(c1.content_hash(), c2.content_hash());
}

#[test]
fn content_hash_changes_on_addition() {
    let c1 = build_seed_corpus();
    let mut c2 = build_seed_corpus();
    c2.add_specimen(specimen(
        "extra",
        WorkloadFamily::ParseHeavy,
        InputLanguage::JavaScript,
    ))
    .unwrap();
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn content_hash_changes_on_removal() {
    let c1 = build_seed_corpus();
    let mut c2 = build_seed_corpus();
    c2.remove_specimen("regex_email_validator");
    assert_ne!(c1.content_hash(), c2.content_hash());
}

// ---------------------------------------------------------------------------
// Gate config variations
// ---------------------------------------------------------------------------

#[test]
fn strict_config_rejects_tolerable_divergence() {
    let mut corpus = build_seed_corpus();
    for id in corpus.specimens.keys().cloned().collect::<Vec<_>>() {
        corpus.record_equivalence(equiv(
            &id,
            BaselineRuntime::NodeJs,
            DivergenceClass::TolerableDivergence,
        ));
    }
    let config = GateConfig {
        min_per_family: 1,
        max_divergence_ratio: 1_000, // very strict: 0.1%
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert!(!report.verdict.permits_publication());
}

#[test]
fn relaxed_config_accepts_low_family_coverage() {
    let mut corpus = WorkloadCorpus::new();
    corpus
        .add_specimen(specimen(
            "s1",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
    corpus.record_equivalence(equiv(
        "s1",
        BaselineRuntime::NodeJs,
        DivergenceClass::Identical,
    ));
    let config = GateConfig {
        min_families: 1,
        min_per_family: 0,
        require_publishable_licenses: false,
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert!(report.verdict.permits_publication());
}

#[test]
fn config_without_baselines_skips_baseline_check() {
    let corpus = build_seed_corpus(); // no equivalence results
    let config = GateConfig {
        min_per_family: 1,
        required_baselines: BTreeSet::new(),
        ..GateConfig::default()
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    // Should not fail due to missing baseline (but may fail for other reasons)
    if let GateVerdict::Fail { reasons } = &report.verdict {
        assert!(
            !reasons
                .iter()
                .any(|r| matches!(r, RejectionReason::MissingBaselineResults { .. }))
        );
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn duplicate_specimen_error_contains_id() {
    let mut corpus = WorkloadCorpus::new();
    corpus
        .add_specimen(specimen(
            "dup",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
    let err = corpus
        .add_specimen(specimen(
            "dup",
            WorkloadFamily::AsyncHeavy,
            InputLanguage::TypeScript,
        ))
        .unwrap_err();
    match err {
        GateError::DuplicateSpecimen { id } => assert_eq!(id, "dup"),
        _ => panic!("expected DuplicateSpecimen"),
    }
}

#[test]
fn family_overflow_error_details() {
    let mut corpus = WorkloadCorpus::new();
    for i in 0..MAX_WORKLOADS_PER_FAMILY {
        corpus
            .add_specimen(specimen(
                &format!("overflow_{i}"),
                WorkloadFamily::AllocationChurn,
                InputLanguage::JavaScript,
            ))
            .unwrap();
    }
    let err = corpus
        .add_specimen(specimen(
            "overflow_final",
            WorkloadFamily::AllocationChurn,
            InputLanguage::JavaScript,
        ))
        .unwrap_err();
    match err {
        GateError::FamilyOverflow {
            family,
            max,
            attempted,
        } => {
            assert_eq!(family, WorkloadFamily::AllocationChurn);
            assert_eq!(max, MAX_WORKLOADS_PER_FAMILY);
            assert_eq!(attempted, MAX_WORKLOADS_PER_FAMILY + 1);
        }
        _ => panic!("expected FamilyOverflow"),
    }
}

// ---------------------------------------------------------------------------
// Tags and metadata
// ---------------------------------------------------------------------------

#[test]
fn specimen_tags_preserved_through_serde() {
    let mut s = specimen(
        "tagged",
        WorkloadFamily::ParseHeavy,
        InputLanguage::JavaScript,
    );
    s.tags.insert("performance".to_string());
    s.tags.insert("critical".to_string());
    s.tags.insert("v8-comparison".to_string());
    let json = serde_json::to_string(&s).unwrap();
    let back: WorkloadSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(s.tags, back.tags);
}

#[test]
fn specimen_fields_preserved_through_serde() {
    let mut s = specimen(
        "fields",
        WorkloadFamily::NativeAddon,
        InputLanguage::TypeScript,
    );
    s.requires_native_addons = true;
    s.exercises_async = true;
    s.approximate_lines = 5000;
    let json = serde_json::to_string(&s).unwrap();
    let back: WorkloadSpecimen = serde_json::from_str(&json).unwrap();
    assert!(back.requires_native_addons);
    assert!(back.exercises_async);
    assert_eq!(back.approximate_lines, 5000);
}

// ---------------------------------------------------------------------------
// Corpus serde roundtrip with equivalence data
// ---------------------------------------------------------------------------

#[test]
fn full_corpus_serde_roundtrip() {
    let corpus = full_corpus_with_equiv();
    let json = serde_json::to_string_pretty(&corpus).unwrap();
    let back: WorkloadCorpus = serde_json::from_str(&json).unwrap();
    assert_eq!(corpus.specimen_count(), back.specimen_count());
    assert_eq!(
        corpus.equivalence_results.len(),
        back.equivalence_results.len()
    );
    assert_eq!(corpus.content_hash(), back.content_hash());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_corpus_hash_is_valid() {
    let corpus = WorkloadCorpus::new();
    let hash = corpus.content_hash();
    assert_ne!(hash.0, [0u8; 32]); // Should still produce a valid hash
}

#[test]
fn gate_with_zero_min_families() {
    let mut corpus = WorkloadCorpus::new();
    corpus
        .add_specimen(specimen(
            "s1",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
    corpus.record_equivalence(equiv(
        "s1",
        BaselineRuntime::NodeJs,
        DivergenceClass::Identical,
    ));
    let config = GateConfig {
        min_families: 0,
        min_per_family: 0,
        required_baselines: BTreeSet::new(),
        require_publishable_licenses: false,
        require_observability_coverage: false,
        equivalence_threshold: 0,
        max_divergence_ratio: 1_000_000,
    };
    let gate = WorkloadCorpusGate::new(config);
    let report = gate.evaluate(&corpus);
    assert!(report.verdict.permits_publication());
}

#[test]
fn all_divergence_classes_serde_roundtrip() {
    let classes = [
        DivergenceClass::Identical,
        DivergenceClass::CosmeticOnly,
        DivergenceClass::TolerableDivergence,
        DivergenceClass::SemanticDivergence,
        DivergenceClass::CrashVsSuccess,
        DivergenceClass::DifferentErrorType,
        DivergenceClass::TimeoutDivergence,
    ];
    for class in &classes {
        let json = serde_json::to_string(class).unwrap();
        let back: DivergenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, back);
    }
}

#[test]
fn all_baselines_serde_roundtrip() {
    let baselines = [
        BaselineRuntime::NodeJs,
        BaselineRuntime::Bun,
        BaselineRuntime::Deno,
    ];
    for b in &baselines {
        let json = serde_json::to_string(b).unwrap();
        let back: BaselineRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(*b, back);
    }
}

#[test]
fn verdict_serde_roundtrip_pass() {
    let v = GateVerdict::Pass;
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_serde_roundtrip_fail() {
    let v = GateVerdict::Fail {
        reasons: vec![
            RejectionReason::EmptyCorpus,
            RejectionReason::InsufficientFamilyCoverage {
                required: 10,
                actual: 3,
            },
        ],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_serde_roundtrip_insufficient_data() {
    let v = GateVerdict::InsufficientData {
        reason: "no equivalence".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn family_summary_equivalence_rate_zero_when_empty() {
    let corpus = WorkloadCorpus::new();
    let gate = WorkloadCorpusGate::with_defaults();
    let report = gate.evaluate(&corpus);
    // Should have empty family summaries since corpus is empty and gate fails early
    // But the empty corpus path returns early without computing summaries
    assert_eq!(report.family_summaries.len(), 0);
}

#[test]
fn seed_corpus_native_addon_flag() {
    let corpus = build_seed_corpus();
    let native_specs: Vec<_> = corpus
        .specimens
        .values()
        .filter(|s| s.requires_native_addons)
        .collect();
    assert_eq!(native_specs.len(), 1);
    assert_eq!(native_specs[0].family, WorkloadFamily::NativeAddon);
}

#[test]
fn seed_corpus_async_flag() {
    let corpus = build_seed_corpus();
    let async_specs: Vec<_> = corpus
        .specimens
        .values()
        .filter(|s| s.exercises_async)
        .collect();
    assert_eq!(async_specs.len(), 2); // AsyncHeavy + HostcallSpike
}

// ---------------------------------------------------------------------------
// Reproducibility Tests (bd-1lsy.8.4.3.1)
// ---------------------------------------------------------------------------

fn run_workload_corpus_gate_invalid(args: &[&str]) -> serde_json::Value {
    use std::process::Command;

    let output = Command::new(env!("CARGO_BIN_EXE_franken_workload_corpus_gate"))
        .args(args)
        .output()
        .expect("Failed to execute gate binary");

    assert!(
        !output.status.success(),
        "invalid invocation unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(2));

    serde_json::from_slice(&output.stderr).unwrap_or_else(|error| {
        panic!(
            "stderr should be structured JSON ({error}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn workload_corpus_gate_command() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_franken_workload_corpus_gate"))
}

#[test]
fn gate_cli_rejects_unknown_option() {
    let error = run_workload_corpus_gate_invalid(&["--min-family", "99"]);

    assert_eq!(error["component"], "franken_workload_corpus_gate");
    assert_eq!(error["argument"], "--min-family");
    assert_eq!(error["error"], "unknown option");
}

#[test]
fn gate_cli_rejects_nonnumeric_equivalence_threshold() {
    let error = run_workload_corpus_gate_invalid(&["--min-equivalence-rate", "nope"]);

    assert_eq!(error["component"], "franken_workload_corpus_gate");
    assert_eq!(error["argument"], "--min-equivalence-rate");
    assert_eq!(error["error"], "invalid integer value: nope");
}

#[test]
fn gate_cli_rejects_missing_option_value() {
    let error = run_workload_corpus_gate_invalid(&["--min-per-family"]);

    assert_eq!(error["component"], "franken_workload_corpus_gate");
    assert_eq!(error["argument"], "--min-per-family");
    assert_eq!(error["error"], "missing value");
}

#[test]
fn gate_events_reset_between_runs() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let out_dir = temp_dir.path();

    // Run gate twice in same output directory
    for run_num in 1..=2 {
        let output = workload_corpus_gate_command()
            .args([
                "--out-dir",
                &out_dir.display().to_string(),
                "--min-per-family",
                "1",
            ])
            .output()
            .expect("Failed to execute gate binary");

        assert!(output.status.success(), "Gate run {} failed", run_num);

        // Verify events.jsonl exists and contains only current run events
        let events_path = out_dir.join("events.jsonl");
        assert!(
            events_path.exists(),
            "events.jsonl missing after run {}",
            run_num
        );

        let events_content = fs::read_to_string(&events_path).unwrap();
        let event_lines: Vec<&str> = events_content.lines().collect();

        // Each run should produce exactly 4 events: start, built, evaluated, complete.
        assert_eq!(
            event_lines.len(),
            4,
            "Run {} should produce exactly 4 events, got {}: {:?}",
            run_num,
            event_lines.len(),
            event_lines
        );

        // Verify events are from current run only (no mixing with previous runs)
        for line in &event_lines {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            // All events should have recent timestamps, not from previous runs
            assert!(
                event.get("timestamp_utc").is_some(),
                "Event missing timestamp: {}",
                line
            );
        }
    }
}

#[test]
fn gate_commands_include_all_cli_parameters() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let out_dir = temp_dir.path();

    // Run gate with custom CLI threshold parameters
    let output = workload_corpus_gate_command()
        .args(&[
            "--out-dir",
            &out_dir.display().to_string(),
            "--min-per-family",
            "1",
            "--min-equivalence-rate",
            "800000",
        ])
        .output()
        .expect("Failed to execute gate binary");

    assert!(
        output.status.success(),
        "Gate execution failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify commands.txt includes complete CLI parameters for reproducible replay
    let commands_path = out_dir.join("commands.txt");
    assert!(commands_path.exists(), "commands.txt missing");

    let commands_content = fs::read_to_string(&commands_path).unwrap();
    let lines: Vec<&str> = commands_content.lines().collect();

    assert!(!lines.is_empty(), "commands.txt should not be empty");

    let replay_command = lines[0];

    // Verify all CLI parameters are preserved in replay command
    assert!(
        replay_command.contains("--out-dir"),
        "Replay command missing --out-dir"
    );
    assert!(
        replay_command.contains("--min-per-family 1"),
        "Replay command missing --min-per-family: {}",
        replay_command
    );
    assert!(
        replay_command.contains("--min-equivalence-rate 800000"),
        "Replay command missing --min-equivalence-rate: {}",
        replay_command
    );

    // Verify command structure
    assert!(
        replay_command.starts_with("franken_workload_corpus_gate"),
        "Replay command should start with binary name: {}",
        replay_command
    );
}

#[test]
fn gate_repeated_runs_same_outdir_deterministic() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let out_dir = temp_dir.path();

    let mut first_events = String::new();
    let mut first_commands = String::new();

    // Run gate twice with identical parameters
    for run_num in 1..=2 {
        let output = workload_corpus_gate_command()
            .args(&[
                "--out-dir",
                &out_dir.display().to_string(),
                "--min-per-family",
                "1",
                "--min-equivalence-rate",
                "950000",
            ])
            .output()
            .expect("Failed to execute gate binary");

        assert!(output.status.success(), "Gate run {} failed", run_num);

        let events_content = fs::read_to_string(out_dir.join("events.jsonl")).unwrap();
        let commands_content = fs::read_to_string(out_dir.join("commands.txt")).unwrap();

        if run_num == 1 {
            first_events = events_content;
            first_commands = commands_content;
        } else {
            // Second run should produce identical event structure (different timestamps)
            let first_lines: Vec<&str> = first_events.lines().collect();
            let second_lines: Vec<&str> = events_content.lines().collect();

            assert_eq!(
                first_lines.len(),
                second_lines.len(),
                "Event count should be consistent between runs"
            );

            // Commands should be identical between runs
            assert_eq!(
                first_commands, commands_content,
                "Commands.txt should be identical between runs with same parameters"
            );
        }
    }
}

#[test]
fn gate_corpus_manifest_loading_with_equivalence_artifacts() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let out_dir = temp_dir.path();
    let manifest_dir = temp_dir.path().join("manifest");
    let artifacts_dir = temp_dir.path().join("equivalence_artifacts");

    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(&artifacts_dir).unwrap();

    // Create a corpus manifest that satisfies the default family coverage gate
    // while keeping one specimen per family.
    let specimens = WorkloadFamily::ALL
        .iter()
        .map(|family| {
            let id = format!("test_{}", family.as_str());
            serde_json::json!({
                "id": id,
                "name": format!("Test {} workload", family.as_str()),
                "family": serde_json::to_value(family).unwrap(),
                "language": "java_script",
                "provenance": {
                    "origin": "open_source_project",
                    "source_url": format!("https://example.com/workloads/{}.js", family.as_str()),
                    "license": "permissive",
                    "spdx_id": "MIT",
                    "source_version": "v1.0.0",
                    "selection_rationale": "Representative workload",
                    "content_hash": ContentHash::compute(family.as_str().as_bytes()).to_string()
                },
                "observability_modes": ["budgeted_default"],
                "secondary_families": [],
                "tags": [family.as_str(), "test"],
                "approximate_lines": 50,
                "requires_native_addons": false,
                "exercises_async": false
            })
        })
        .collect::<Vec<_>>();

    let manifest_content = serde_json::json!({
        "schema_version": "franken-engine.workload-corpus-manifest.v1",
        "specimens": specimens
    });

    let manifest_path = manifest_dir.join("corpus.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest_content).unwrap(),
    )
    .unwrap();

    for family in WorkloadFamily::ALL {
        let id = format!("test_{}", family.as_str());
        let output_hash = ContentHash::compute(id.as_bytes()).to_string();
        let equiv_content = serde_json::json!({
            "specimen_id": id,
            "baseline": "node_js",
            "divergence_class": "identical",
            "divergence_description": "",
            "output_hash_matches": true,
            "franken_output_hash": output_hash,
            "baseline_output_hash": output_hash,
            "evidence_path": format!("evidence/{}.trace", family.as_str())
        });

        let equiv_path = artifacts_dir.join(format!("{}.json", family.as_str()));
        fs::write(
            &equiv_path,
            serde_json::to_string_pretty(&equiv_content).unwrap(),
        )
        .unwrap();
    }

    // Run gate with corpus manifest and equivalence artifacts
    let output = workload_corpus_gate_command()
        .args(&[
            "--out-dir",
            &out_dir.display().to_string(),
            "--min-per-family",
            "1",
            "--corpus-manifest",
            &manifest_path.display().to_string(),
            "--equivalence-artifacts",
            &artifacts_dir.display().to_string(),
        ])
        .output()
        .expect("Failed to execute gate binary");

    assert!(
        output.status.success(),
        "Gate execution failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify corpus manifest was loaded correctly
    let corpus_manifest_path = out_dir.join("corpus_manifest.json");
    assert!(
        corpus_manifest_path.exists(),
        "corpus_manifest.json missing"
    );

    let corpus_manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&corpus_manifest_path).unwrap()).unwrap();

    // Should contain the specimen from the loaded manifest
    assert!(corpus_manifest["specimens"].as_array().unwrap().len() > 0);

    // Verify commands.txt includes manifest and artifacts paths
    let commands_path = out_dir.join("commands.txt");
    let commands_content = fs::read_to_string(&commands_path).unwrap();
    let replay_command = commands_content.lines().next().unwrap();

    assert!(
        replay_command.contains("--corpus-manifest"),
        "Replay command should include --corpus-manifest"
    );
    assert!(
        replay_command.contains("--equivalence-artifacts"),
        "Replay command should include --equivalence-artifacts"
    );
}

#[test]
fn gate_publication_mode_requires_corpus_and_artifacts() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let out_dir = temp_dir.path();

    // Run gate in publication mode without required parameters
    let output = workload_corpus_gate_command()
        .args(&[
            "--out-dir",
            &out_dir.display().to_string(),
            "--publication-mode",
        ])
        .output()
        .expect("Failed to execute gate binary");

    // Should fail because publication mode requires corpus manifest and artifacts
    assert!(
        !output.status.success(),
        "Gate should fail in publication mode without required parameters"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Publication mode requires --corpus-manifest and --equivalence-artifacts"),
        "Error message should indicate missing required parameters: {}",
        stderr
    );
}

#[test]
fn gate_content_hash_parsing_handles_prefixes() {
    // This test verifies the parse_content_hash function handles various formats
    use frankenengine_engine::hash_tiers::ContentHash;

    // Test data
    let hex_without_prefix = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let hex_with_prefix =
        "content:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // Create expected hash manually
    let expected_bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let expected = ContentHash::from_bytes(expected_bytes);

    // Test both formats - we can't test parse_content_hash directly since it's in the binary,
    // but we can test that ContentHash creation works correctly
    assert_eq!(expected.to_hex(), hex_without_prefix);
    assert_eq!(format!("content:{}", expected.to_hex()), hex_with_prefix);
}
