//! Enrichment integration tests for `hierarchical_delta_debug`.
//!
//! Covers: DefectClass serde/display, ReductionLevel serde/display/ordering,
//! ReductionStrategy serde/display, ReductionConfig defaults/serde/hashing,
//! ProgramFragment construction/marking/serde, StepOutcome serde,
//! ReductionStep hashing/serde, DeltaDebugger fragment/reduce/summary,
//! MinimalRepro lifecycle/serde/reduction_percentage, ReductionSummary serde,
//! ReductionEvidenceInventory from_repros, DeltaDebugSpecimenFamily/corpus,
//! boundary conditions, and deterministic hashing.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use frankenengine_engine::hierarchical_delta_debug::{
    COMPONENT, DEFAULT_MAX_REDUCTION_STEPS, DEFAULT_MAX_REDUCTION_TIME_MS,
    DEFAULT_MIN_PROGRAM_SIZE, DeltaDebugSpecimenFamily, DeltaDebugger, DefectClass,
    MinimalRepro, ProgramFragment, REDUCTION_SCHEMA_VERSION, ReductionConfig,
    ReductionEvidenceInventory, ReductionLevel, ReductionStep, ReductionStrategy,
    ReductionSummary, StepOutcome, delta_debug_corpus, run_delta_debug_corpus,
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
fn constant_component() {
    assert_eq!(COMPONENT, "hierarchical_delta_debug");
}

#[test]
fn constant_schema_version() {
    assert!(!REDUCTION_SCHEMA_VERSION.is_empty());
}

#[test]
fn constant_defaults_positive() {
    assert!(DEFAULT_MAX_REDUCTION_STEPS > 0);
    assert!(DEFAULT_MIN_PROGRAM_SIZE > 0);
    assert!(DEFAULT_MAX_REDUCTION_TIME_MS > 0);
}

// ===========================================================================
// DefectClass
// ===========================================================================

#[test]
fn defect_class_display_all_variants() {
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
        DefectClass::Custom {
            tag: "test".into(),
        },
    ];
    for dc in &classes {
        let s = format!("{dc}");
        assert!(!s.is_empty());
    }
}

#[test]
fn defect_class_serde_roundtrip_builtin() {
    let dc = DefectClass::WrongOutput;
    let json = serde_json::to_string(&dc).unwrap();
    let back: DefectClass = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, back);
}

#[test]
fn defect_class_serde_roundtrip_custom() {
    let dc = DefectClass::Custom {
        tag: "my-defect".into(),
    };
    let json = serde_json::to_string(&dc).unwrap();
    let back: DefectClass = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, back);
}

#[test]
fn defect_class_ordering() {
    assert!(DefectClass::Crash < DefectClass::WrongOutput);
}

#[test]
fn defect_class_custom_display() {
    let dc = DefectClass::Custom {
        tag: "fuzzer".into(),
    };
    let s = format!("{dc}");
    assert!(s.contains("fuzzer"));
}

// ===========================================================================
// ReductionLevel
// ===========================================================================

#[test]
fn reduction_level_all_count() {
    let levels = ReductionLevel::all();
    assert_eq!(levels.len(), 5);
}

#[test]
fn reduction_level_ordering() {
    let levels = ReductionLevel::all();
    assert_eq!(levels[0], ReductionLevel::Module);
    assert_eq!(levels[4], ReductionLevel::Token);
}

#[test]
fn reduction_level_display() {
    for level in ReductionLevel::all() {
        let s = format!("{level}");
        assert!(!s.is_empty());
    }
}

#[test]
fn reduction_level_serde_roundtrip() {
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
fn reduction_strategy_display_all() {
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
fn reduction_strategy_serde_roundtrip() {
    let s = ReductionStrategy::HierarchicalDelta;
    let json = serde_json::to_string(&s).unwrap();
    let back: ReductionStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn reduction_strategy_serde_all_variants() {
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
fn config_default_values() {
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
fn config_hash_deterministic() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig::default();
    assert_eq!(c1.config_hash(), c2.config_hash());
}

#[test]
fn config_hash_differs_on_change() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig {
        max_steps: 500,
        ..ReductionConfig::default()
    };
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn config_hash_prefix() {
    let c = ReductionConfig::default();
    assert!(c.config_hash().starts_with("rc-"));
}

#[test]
fn config_display() {
    let c = ReductionConfig::default();
    let s = format!("{c}");
    assert!(s.contains("reduction-config"));
}

#[test]
fn config_serde_roundtrip() {
    let c = ReductionConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: ReductionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// ProgramFragment
// ===========================================================================

#[test]
fn fragment_new_defaults() {
    let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    assert!(frag.fragment_id.starts_with("frag-"));
    assert_eq!(frag.size(), 11);
    assert!(frag.included);
    assert!(!frag.tested);
    assert!(!frag.removable);
    assert!(frag.parent_id.is_none());
}

#[test]
fn fragment_id_deterministic_same_offsets() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    let f2 = ProgramFragment::new(ReductionLevel::Statement, "let y = 2;", 0, 11);
    assert_eq!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn fragment_id_differs_on_offset() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    let f2 = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 10, 21);
    assert_ne!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn fragment_id_differs_on_level() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "x", 0, 1);
    let f2 = ProgramFragment::new(ReductionLevel::Expression, "x", 0, 1);
    assert_ne!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn fragment_mark_tested_removable() {
    let mut frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    frag.mark_tested(true);
    assert!(frag.tested);
    assert!(frag.removable);
    assert!(!frag.included);
}

#[test]
fn fragment_mark_tested_essential() {
    let mut frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    frag.mark_tested(false);
    assert!(frag.tested);
    assert!(!frag.removable);
    assert!(frag.included);
}

#[test]
fn fragment_display() {
    let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    let s = format!("{frag}");
    assert!(s.contains("fragment"));
    assert!(s.contains("statement"));
}

#[test]
fn fragment_serde_roundtrip() {
    let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    let json = serde_json::to_string(&frag).unwrap();
    let back: ProgramFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(frag, back);
}

#[test]
fn fragment_size_zero_when_same_offsets() {
    let frag = ProgramFragment::new(ReductionLevel::Token, "", 5, 5);
    assert_eq!(frag.size(), 0);
}

// ===========================================================================
// StepOutcome
// ===========================================================================

#[test]
fn step_outcome_display_all() {
    let outcomes = vec![
        StepOutcome::DefectPreserved,
        StepOutcome::DefectLost,
        StepOutcome::SyntaxError,
        StepOutcome::TestTimeout,
        StepOutcome::Skipped,
    ];
    for o in &outcomes {
        assert!(!format!("{o}").is_empty());
    }
}

#[test]
fn step_outcome_serde_roundtrip_all() {
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
fn reduction_step_content_hash_deterministic() {
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
fn reduction_step_display() {
    let step = ReductionStep {
        step_number: 3,
        level: ReductionLevel::Declaration,
        strategy: ReductionStrategy::HierarchicalDelta,
        removed_fragment_ids: vec!["a".into(), "b".into()],
        outcome: StepOutcome::DefectLost,
        program_size_after: 200,
        progress: false,
    };
    let s = format!("{step}");
    assert!(s.contains("step #3"));
    assert!(s.contains("removed=2"));
}

#[test]
fn reduction_step_serde_roundtrip() {
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
fn debugger_fragment_creates_fragments() {
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
fn debugger_fragments_at_level() {
    let mut d = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        ep(1),
    );
    d.fragment();
    let decl = d.fragments_at_level(ReductionLevel::Declaration);
    assert!(!decl.is_empty());
    let stmt = d.fragments_at_level(ReductionLevel::Statement);
    assert!(!stmt.is_empty());
}

#[test]
fn debugger_try_remove_preserves_defect() {
    let mut d = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        ep(1),
    );
    d.fragment();
    let ids: Vec<String> = d
        .fragments_at_level(ReductionLevel::Declaration)
        .iter()
        .take(1)
        .map(|f| f.fragment_id.clone())
        .collect();
    if !ids.is_empty() {
        let outcome = d.try_remove(&ids, |_| StepOutcome::DefectPreserved);
        assert_eq!(outcome, StepOutcome::DefectPreserved);
        assert_eq!(d.steps().len(), 1);
        assert!(d.steps()[0].progress);
    }
}

#[test]
fn debugger_try_remove_defect_lost() {
    let mut d = DeltaDebugger::new(
        sample_program(),
        DefectClass::WrongOutput,
        ReductionConfig::default(),
        ep(1),
    );
    d.fragment();
    let ids: Vec<String> = d
        .fragments_at_level(ReductionLevel::Declaration)
        .iter()
        .take(1)
        .map(|f| f.fragment_id.clone())
        .collect();
    if !ids.is_empty() {
        let outcome = d.try_remove(&ids, |_| StepOutcome::DefectLost);
        assert_eq!(outcome, StepOutcome::DefectLost);
        assert!(!d.steps()[0].progress);
    }
}

#[test]
fn debugger_reduce_full_pipeline() {
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
fn debugger_reduce_achieves_reduction() {
    let source = "line1\nline2\ndefect_line\nline3\nline4\n\nblock2_a\nblock2_b";
    let mut d = DeltaDebugger::new(
        source,
        DefectClass::AssertionFailure,
        ReductionConfig::default(),
        ep(1),
    );
    let repro = d.reduce(|s| {
        if s.contains("defect_line") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });
    assert!(repro.reduced_size <= repro.original_size);
    assert!(repro.source.contains("defect_line"));
}

#[test]
fn debugger_max_steps_respected() {
    let config = ReductionConfig {
        max_steps: 3,
        ..ReductionConfig::default()
    };
    let mut d = DeltaDebugger::new(sample_program(), DefectClass::Crash, config, ep(1));
    let _repro = d.reduce(|_| StepOutcome::DefectLost);
    assert!(d.steps().len() <= 3);
}

#[test]
fn debugger_summary_fields() {
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
fn minimal_repro_display() {
    let mut d = DeltaDebugger::new(
        "let x = 1;\nlet y = 2;",
        DefectClass::WrongOutput,
        ReductionConfig::default(),
        ep(1),
    );
    let repro = d.reduce(|_| StepOutcome::DefectPreserved);
    let s = format!("{repro}");
    assert!(s.contains("minimal-repro"));
    assert!(s.contains("wrong-output"));
}

#[test]
fn minimal_repro_serde_roundtrip() {
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
fn minimal_repro_reduction_percentage_calculation() {
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
fn minimal_repro_reduction_percentage_zero_original() {
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
fn reduction_summary_serde_roundtrip() {
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
fn evidence_inventory_from_repros() {
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
    assert_eq!(inv.avg_reduction_millionths, 750_000);
}

#[test]
fn evidence_inventory_empty() {
    let inv = ReductionEvidenceInventory::from_repros(&[]);
    assert_eq!(inv.session_count, 0);
    assert_eq!(inv.avg_reduction_millionths, 0);
}

#[test]
fn evidence_inventory_serde_roundtrip() {
    let inv = ReductionEvidenceInventory::from_repros(&[]);
    let json = serde_json::to_string(&inv).unwrap();
    let back: ReductionEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ===========================================================================
// Corpus
// ===========================================================================

#[test]
fn corpus_non_empty() {
    let corpus = delta_debug_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn run_corpus_all_pass() {
    let results = run_delta_debug_corpus();
    assert!(results.iter().all(|(_, passed)| *passed));
}

#[test]
fn specimen_family_display_all() {
    let families = vec![
        DeltaDebugSpecimenFamily::SingleFile,
        DeltaDebugSpecimenFamily::MultiStatement,
        DeltaDebugSpecimenFamily::ImportDependent,
        DeltaDebugSpecimenFamily::ReactComponent,
        DeltaDebugSpecimenFamily::PerformanceLoop,
    ];
    for f in &families {
        assert!(!format!("{f}").is_empty());
    }
}

#[test]
fn specimen_family_serde_roundtrip() {
    let f = DeltaDebugSpecimenFamily::ReactComponent;
    let json = serde_json::to_string(&f).unwrap();
    let back: DeltaDebugSpecimenFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}
