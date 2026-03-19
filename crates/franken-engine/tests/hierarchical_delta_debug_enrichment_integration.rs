// Enrichment integration tests for hierarchical_delta_debug module.
//
// Covers: DefectClass Display uniqueness (10 fixed + custom), serde roundtrips
// (including Custom variant), ReductionLevel Display/ordering, ReductionStrategy
// serde/display, ReductionConfig defaults/serde/hashing, ProgramFragment
// construction/marking, StepOutcome, DeltaDebugger lifecycle, MinimalRepro
// reduction_percentage, ReductionSummary, ReductionEvidenceInventory, corpus,
// constants, and determinism checks.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hierarchical_delta_debug::{
    COMPONENT, DEFAULT_MAX_REDUCTION_STEPS, DEFAULT_MAX_REDUCTION_TIME_MS,
    DEFAULT_MIN_PROGRAM_SIZE, DefectClass, DeltaDebugSpecimenFamily, DeltaDebugger, MinimalRepro,
    ProgramFragment, REDUCTION_SCHEMA_VERSION, ReductionConfig, ReductionEvidenceInventory,
    ReductionLevel, ReductionStep, ReductionStrategy, ReductionSummary, StepOutcome,
    delta_debug_corpus, run_delta_debug_corpus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn sample_program() -> &'static str {
    "function add(a, b) {\n  const result = a + b;\n  console.log(result);\n  return result;\n}\n\nfunction mul(a, b) {\n  return a * b;\n}\n\nadd(1, 2);\nmul(3, 4);"
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_component_value() {
    assert_eq!(COMPONENT, "hierarchical_delta_debug");
}

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!REDUCTION_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_defaults_positive() {
    assert!(DEFAULT_MAX_REDUCTION_STEPS > 0);
    assert!(DEFAULT_MIN_PROGRAM_SIZE > 0);
    assert!(DEFAULT_MAX_REDUCTION_TIME_MS > 0);
}

// ===========================================================================
// DefectClass
// ===========================================================================

#[test]
fn enrichment_defect_class_display_all_non_empty() {
    let classes = vec![
        DefectClass::Crash,
        DefectClass::WrongOutput,
        DefectClass::PerformanceRegression,
        DefectClass::IfcViolation,
        DefectClass::DeterminismFailure,
        DefectClass::TypeUnsoundness,
        DefectClass::ModuleResolutionFailure,
        DefectClass::MemorySafetyViolation,
        DefectClass::Timeout,
        DefectClass::AssertionFailure,
        DefectClass::Custom { tag: "test".into() },
    ];
    for dc in &classes {
        let s = format!("{dc}");
        assert!(!s.is_empty());
    }
}

#[test]
fn enrichment_defect_class_display_uniqueness_of_fixed_variants() {
    let fixed = vec![
        DefectClass::Crash,
        DefectClass::WrongOutput,
        DefectClass::PerformanceRegression,
        DefectClass::IfcViolation,
        DefectClass::DeterminismFailure,
        DefectClass::TypeUnsoundness,
        DefectClass::ModuleResolutionFailure,
        DefectClass::MemorySafetyViolation,
        DefectClass::Timeout,
        DefectClass::AssertionFailure,
    ];
    let labels: BTreeSet<String> = fixed.iter().map(|d| format!("{d}")).collect();
    assert_eq!(labels.len(), 10);
}

#[test]
fn enrichment_defect_class_serde_roundtrip_builtin() {
    let dc = DefectClass::WrongOutput;
    let json = serde_json::to_string(&dc).unwrap();
    let back: DefectClass = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, back);
}

#[test]
fn enrichment_defect_class_serde_roundtrip_custom() {
    let dc = DefectClass::Custom {
        tag: "my-defect".into(),
    };
    let json = serde_json::to_string(&dc).unwrap();
    let back: DefectClass = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, back);
}

#[test]
fn enrichment_defect_class_ordering() {
    assert!(DefectClass::Crash < DefectClass::WrongOutput);
}

#[test]
fn enrichment_defect_class_custom_display_contains_tag() {
    let dc = DefectClass::Custom {
        tag: "fuzzer".into(),
    };
    let s = format!("{dc}");
    assert!(s.contains("fuzzer"));
}

#[test]
fn enrichment_defect_class_serde_all_fixed_variants() {
    let fixed: Vec<DefectClass> = vec![
        DefectClass::Crash,
        DefectClass::WrongOutput,
        DefectClass::PerformanceRegression,
        DefectClass::IfcViolation,
        DefectClass::DeterminismFailure,
        DefectClass::TypeUnsoundness,
        DefectClass::ModuleResolutionFailure,
        DefectClass::MemorySafetyViolation,
        DefectClass::Timeout,
        DefectClass::AssertionFailure,
    ];
    for dc in fixed {
        let json = serde_json::to_string(&dc).unwrap();
        let back: DefectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, back);
    }
}

// ===========================================================================
// ReductionLevel
// ===========================================================================

#[test]
fn enrichment_reduction_level_all_count() {
    assert_eq!(ReductionLevel::all().len(), 5);
}

#[test]
fn enrichment_reduction_level_ordering() {
    let levels = ReductionLevel::all();
    assert_eq!(levels[0], ReductionLevel::Module);
    assert_eq!(levels[1], ReductionLevel::Declaration);
    assert_eq!(levels[2], ReductionLevel::Statement);
    assert_eq!(levels[3], ReductionLevel::Expression);
    assert_eq!(levels[4], ReductionLevel::Token);
}

#[test]
fn enrichment_reduction_level_display_unique() {
    let labels: BTreeSet<String> = ReductionLevel::all()
        .iter()
        .map(|l| format!("{l}"))
        .collect();
    assert_eq!(labels.len(), 5);
}

#[test]
fn enrichment_reduction_level_serde_roundtrip() {
    for level in ReductionLevel::all() {
        let json = serde_json::to_string(level).unwrap();
        let back: ReductionLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*level, back);
    }
}

// ===========================================================================
// ReductionStrategy
// ===========================================================================

#[test]
fn enrichment_strategy_display_all_non_empty() {
    let strategies = vec![
        ReductionStrategy::DeltaDebugging,
        ReductionStrategy::HierarchicalDelta,
        ReductionStrategy::StructuredReduction,
        ReductionStrategy::SemanticPreserving,
        ReductionStrategy::TypeDirected,
    ];
    for s in &strategies {
        assert!(!format!("{s}").is_empty());
    }
}

#[test]
fn enrichment_strategy_serde_roundtrip_all() {
    let variants = vec![
        ReductionStrategy::DeltaDebugging,
        ReductionStrategy::HierarchicalDelta,
        ReductionStrategy::StructuredReduction,
        ReductionStrategy::SemanticPreserving,
        ReductionStrategy::TypeDirected,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: ReductionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// ReductionConfig
// ===========================================================================

#[test]
fn enrichment_config_default_values() {
    let c = ReductionConfig::default();
    assert_eq!(c.max_steps, DEFAULT_MAX_REDUCTION_STEPS);
    assert_eq!(c.min_program_size, DEFAULT_MIN_PROGRAM_SIZE);
    assert_eq!(c.max_time_ms, DEFAULT_MAX_REDUCTION_TIME_MS);
    assert!(c.preserve_syntax);
    assert!(c.preserve_imports);
    assert!(!c.strategies.is_empty());
    assert!(!c.levels.is_empty());
    assert!(!c.emit_intermediates);
}

#[test]
fn enrichment_config_hash_deterministic() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig::default();
    assert_eq!(c1.config_hash(), c2.config_hash());
}

#[test]
fn enrichment_config_hash_differs_on_change() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig {
        max_steps: 500,
        ..ReductionConfig::default()
    };
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn enrichment_config_hash_prefix() {
    let c = ReductionConfig::default();
    assert!(c.config_hash().starts_with("rc-"));
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let c = ReductionConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: ReductionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// ProgramFragment
// ===========================================================================

#[test]
fn enrichment_fragment_new_defaults() {
    let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    assert!(frag.fragment_id.starts_with("frag-"));
    assert_eq!(frag.size(), 11);
    assert!(frag.included);
    assert!(!frag.tested);
    assert!(!frag.removable);
    assert!(frag.parent_id.is_none());
}

#[test]
fn enrichment_fragment_mark_tested_removable() {
    let mut frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    frag.mark_tested(true);
    assert!(frag.tested);
    assert!(frag.removable);
    assert!(!frag.included);
}

#[test]
fn enrichment_fragment_mark_tested_essential() {
    let mut frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    frag.mark_tested(false);
    assert!(frag.tested);
    assert!(!frag.removable);
    assert!(frag.included);
}

#[test]
fn enrichment_fragment_id_deterministic() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    let f2 = ProgramFragment::new(ReductionLevel::Statement, "let y = 2;", 0, 11);
    assert_eq!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn enrichment_fragment_id_differs_by_level() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "x", 0, 1);
    let f2 = ProgramFragment::new(ReductionLevel::Expression, "x", 0, 1);
    assert_ne!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn enrichment_fragment_serde_roundtrip() {
    let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    let json = serde_json::to_string(&frag).unwrap();
    let back: ProgramFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(frag, back);
}

// ===========================================================================
// StepOutcome
// ===========================================================================

#[test]
fn enrichment_step_outcome_serde_roundtrip_all() {
    let outcomes = vec![
        StepOutcome::DefectPreserved,
        StepOutcome::DefectLost,
        StepOutcome::SyntaxError,
        StepOutcome::TestTimeout,
        StepOutcome::Skipped,
    ];
    for o in outcomes {
        let json = serde_json::to_string(&o).unwrap();
        let back: StepOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

// ===========================================================================
// ReductionStep
// ===========================================================================

#[test]
fn enrichment_reduction_step_hash_deterministic() {
    let step = ReductionStep {
        step_number: 1,
        level: ReductionLevel::Statement,
        strategy: ReductionStrategy::DeltaDebugging,
        removed_fragment_ids: vec!["frag-1".into()],
        outcome: StepOutcome::DefectPreserved,
        program_size_after: 100,
        progress: true,
    };
    let h1 = step.content_hash();
    let h2 = step.content_hash();
    assert_eq!(h1, h2);
    assert!(h1.starts_with("rs-"));
}

#[test]
fn enrichment_reduction_step_serde_roundtrip() {
    let step = ReductionStep {
        step_number: 1,
        level: ReductionLevel::Statement,
        strategy: ReductionStrategy::DeltaDebugging,
        removed_fragment_ids: vec!["frag-1".into()],
        outcome: StepOutcome::DefectPreserved,
        program_size_after: 100,
        progress: true,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: ReductionStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

// ===========================================================================
// DeltaDebugger
// ===========================================================================

#[test]
fn enrichment_debugger_fragment_creates_fragments() {
    let mut d = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        ep(1),
    );
    d.fragment();
    assert!(d.fragment_count() > 0);
}

#[test]
fn enrichment_debugger_reduce_full_pipeline() {
    let mut d = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        ep(1),
    );
    let repro = d.reduce(|source| {
        if source.contains("add") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });
    assert!(repro.repro_id.starts_with("mr-"));
    assert!(repro.source.contains("add"));
    assert!(repro.reduced_size <= repro.original_size);
    assert!(repro.stable);
}

#[test]
fn enrichment_debugger_summary_fields() {
    let mut d = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        ep(1),
    );
    d.fragment();
    let summary = d.summary();
    assert_eq!(summary.defect_class, DefectClass::Crash);
    assert_eq!(summary.original_size, sample_program().len() as u32);
}

// ===========================================================================
// MinimalRepro
// ===========================================================================

#[test]
fn enrichment_minimal_repro_serde_roundtrip() {
    let mut d = DeltaDebugger::new(
        "test source",
        DefectClass::Crash,
        ReductionConfig::default(),
        ep(1),
    );
    let repro = d.reduce(|_| StepOutcome::DefectPreserved);
    let json = serde_json::to_string(&repro).unwrap();
    let back: MinimalRepro = serde_json::from_str(&json).unwrap();
    assert_eq!(repro, back);
}

#[test]
fn enrichment_minimal_repro_reduction_percentage() {
    let repro = MinimalRepro {
        repro_id: "mr-test".into(),
        schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
        defect_class: DefectClass::Crash,
        source: "x".into(),
        original_size: 100,
        reduced_size: 25,
        reduction_ratio_millionths: 750_000,
        total_steps: 10,
        progress_steps: 5,
        original_fragment_count: 20,
        remaining_fragment_count: 5,
        essential_fragment_ids: vec![],
        config: ReductionConfig::default(),
        epoch: ep(1),
        stable: true,
    };
    assert_eq!(repro.reduction_percentage(), 75);
}

#[test]
fn enrichment_minimal_repro_zero_original_size() {
    let repro = MinimalRepro {
        repro_id: "mr-zero".into(),
        schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
        defect_class: DefectClass::Crash,
        source: "".into(),
        original_size: 0,
        reduced_size: 0,
        reduction_ratio_millionths: 0,
        total_steps: 0,
        progress_steps: 0,
        original_fragment_count: 0,
        remaining_fragment_count: 0,
        essential_fragment_ids: vec![],
        config: ReductionConfig::default(),
        epoch: ep(1),
        stable: true,
    };
    assert_eq!(repro.reduction_percentage(), 0);
}

// ===========================================================================
// ReductionSummary
// ===========================================================================

#[test]
fn enrichment_reduction_summary_serde_roundtrip() {
    let summary = ReductionSummary {
        repro_id: "mr-test".into(),
        defect_class: DefectClass::Crash,
        original_size: 100,
        reduced_size: 25,
        reduction_percentage: 75,
        total_steps: 10,
        progress_steps: 5,
        levels_attempted: vec![ReductionLevel::Statement],
        strategies_used: vec![ReductionStrategy::DeltaDebugging],
        stable: true,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: ReductionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ===========================================================================
// ReductionEvidenceInventory
// ===========================================================================

#[test]
fn enrichment_evidence_inventory_from_repros() {
    let repro = MinimalRepro {
        repro_id: "mr-ev".into(),
        schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
        defect_class: DefectClass::Crash,
        source: "x".into(),
        original_size: 100,
        reduced_size: 25,
        reduction_ratio_millionths: 750_000,
        total_steps: 10,
        progress_steps: 5,
        original_fragment_count: 20,
        remaining_fragment_count: 5,
        essential_fragment_ids: vec![],
        config: ReductionConfig::default(),
        epoch: ep(1),
        stable: true,
    };
    let inv = ReductionEvidenceInventory::from_repros(&[repro]);
    assert_eq!(inv.session_count, 1);
    assert_eq!(inv.total_steps, 10);
}

#[test]
fn enrichment_evidence_inventory_empty() {
    let inv = ReductionEvidenceInventory::from_repros(&[]);
    assert_eq!(inv.session_count, 0);
    assert_eq!(inv.avg_reduction_millionths, 0);
}

// ===========================================================================
// Corpus
// ===========================================================================

#[test]
fn enrichment_corpus_non_empty() {
    let corpus = delta_debug_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn enrichment_run_corpus_all_pass() {
    let results = run_delta_debug_corpus();
    assert!(results.iter().all(|(_, passed)| *passed));
}

#[test]
fn enrichment_specimen_family_serde_roundtrip() {
    let f = DeltaDebugSpecimenFamily::ReactComponent;
    let json = serde_json::to_string(&f).unwrap();
    let back: DeltaDebugSpecimenFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}
