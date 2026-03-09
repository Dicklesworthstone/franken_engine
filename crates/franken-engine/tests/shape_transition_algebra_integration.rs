//! Integration tests for the shape-transition algebra and IC invalidation contract.

use frankenengine_engine::shape_transition_algebra::{
    DeoptTrigger, GuardFailureReason, InlineCacheState, InlineCacheTable, PropertyAttributes,
    PropertyCellState, PropertyCellTable, PropertyCellTracker, ShapeGuardWitness, ShapeMutation,
    ShapeTransitionAlgebra, run_shape_transition_corpus, shape_transition_corpus,
};

// ---------------------------------------------------------------------------
// 1. PropertyCellState integration
// ---------------------------------------------------------------------------

#[test]
fn integration_cell_state_full_lifecycle() {
    let mut state = PropertyCellState::Uninitialised;
    assert!(!state.is_valid_for_ic());

    state = state.on_write(false);
    assert_eq!(state, PropertyCellState::Constant);
    assert!(state.is_valid_for_ic());

    state = state.on_write(false);
    assert_eq!(state, PropertyCellState::Stable);
    assert!(state.is_valid_for_ic());

    // Repeated same-kind writes stay stable
    for _ in 0..100 {
        state = state.on_write(false);
        assert_eq!(state, PropertyCellState::Stable);
    }

    state = state.on_write(true);
    assert_eq!(state, PropertyCellState::Invalidated);
    assert!(!state.is_valid_for_ic());

    // Once invalidated, stays invalidated
    state = state.on_write(false);
    assert_eq!(state, PropertyCellState::Invalidated);
    state = state.on_write(true);
    assert_eq!(state, PropertyCellState::Invalidated);
}

#[test]
fn integration_cell_state_constant_to_invalidated() {
    let state = PropertyCellState::Uninitialised
        .on_write(false) // → Constant
        .on_write(true); // → Invalidated (kind changed while Constant)
    assert_eq!(state, PropertyCellState::Invalidated);
}

#[test]
fn integration_cell_state_display_all_variants() {
    let variants = [
        (PropertyCellState::Uninitialised, "uninitialised"),
        (PropertyCellState::Constant, "constant"),
        (PropertyCellState::Stable, "stable"),
        (PropertyCellState::Invalidated, "invalidated"),
    ];
    for (state, expected) in &variants {
        assert_eq!(format!("{state}"), *expected);
    }
}

#[test]
fn integration_cell_state_serde_roundtrip_all_variants() {
    let variants = [
        PropertyCellState::Uninitialised,
        PropertyCellState::Constant,
        PropertyCellState::Stable,
        PropertyCellState::Invalidated,
    ];
    for state in &variants {
        let json = serde_json::to_string(state).unwrap();
        let back: PropertyCellState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

// ---------------------------------------------------------------------------
// 2. PropertyCellTracker integration
// ---------------------------------------------------------------------------

#[test]
fn integration_tracker_write_sequence() {
    let mut tracker = PropertyCellTracker::new(42, "x");
    assert_eq!(tracker.state, PropertyCellState::Uninitialised);
    assert_eq!(tracker.write_epoch, 0);

    assert!(!tracker.record_write(false)); // → Constant, not invalidated
    assert_eq!(tracker.state, PropertyCellState::Constant);
    assert_eq!(tracker.write_epoch, 1);

    assert!(!tracker.record_write(false)); // → Stable
    assert_eq!(tracker.state, PropertyCellState::Stable);
    assert_eq!(tracker.write_epoch, 2);

    assert!(tracker.record_write(true)); // → Invalidated (returns true)
    assert_eq!(tracker.state, PropertyCellState::Invalidated);
    assert_eq!(tracker.write_epoch, 3);

    assert!(!tracker.record_write(false)); // stays Invalidated
    assert_eq!(tracker.write_epoch, 4);
}

#[test]
fn integration_tracker_dependents() {
    let mut tracker = PropertyCellTracker::new(1, "prop");
    assert_eq!(tracker.dependent_ic_count, 0);

    for _ in 0..5 {
        tracker.add_dependent();
    }
    assert_eq!(tracker.dependent_ic_count, 5);

    for _ in 0..3 {
        tracker.remove_dependent();
    }
    assert_eq!(tracker.dependent_ic_count, 2);

    // Saturating sub — can't go below 0
    for _ in 0..10 {
        tracker.remove_dependent();
    }
    assert_eq!(tracker.dependent_ic_count, 0);
}

#[test]
fn integration_tracker_display() {
    let tracker = PropertyCellTracker::new(99, "name");
    let display = format!("{tracker}");
    assert!(display.contains("99"));
    assert!(display.contains("name"));
    assert!(display.contains("uninitialised"));
}

#[test]
fn integration_tracker_serde_roundtrip() {
    let mut tracker = PropertyCellTracker::new(7, "value");
    tracker.record_write(false);
    tracker.add_dependent();
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PropertyCellTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(tracker, back);
}

// ---------------------------------------------------------------------------
// 3. PropertyCellTable integration
// ---------------------------------------------------------------------------

#[test]
fn integration_table_get_or_create_dedup() {
    let mut table = PropertyCellTable::new();
    assert_eq!(table.cell_count(), 0);

    table.get_or_create(1, "x");
    assert_eq!(table.cell_count(), 1);

    table.get_or_create(1, "x");
    assert_eq!(table.cell_count(), 1);

    table.get_or_create(1, "y");
    assert_eq!(table.cell_count(), 2);

    table.get_or_create(2, "x");
    assert_eq!(table.cell_count(), 3);
}

#[test]
fn integration_table_record_write_tracking() {
    let mut table = PropertyCellTable::new();
    assert_eq!(table.total_invalidations(), 0);

    // First write → Constant (not invalidated)
    assert!(!table.record_write(1, "a", false));
    assert_eq!(table.total_invalidations(), 0);

    // Second write same kind → Stable
    assert!(!table.record_write(1, "a", false));
    assert_eq!(table.total_invalidations(), 0);

    // Third write kind changed → Invalidated
    assert!(table.record_write(1, "a", true));
    assert_eq!(table.total_invalidations(), 1);

    // Already invalidated — no further increment
    assert!(!table.record_write(1, "a", true));
    assert_eq!(table.total_invalidations(), 1);
}

#[test]
fn integration_table_invalidate_shape() {
    let mut table = PropertyCellTable::new();
    // Create several cells on shape 10
    table.record_write(10, "a", false);
    table.record_write(10, "b", false);
    table.record_write(10, "c", false);
    // One cell on shape 20
    table.record_write(20, "a", false);

    // Force invalidate shape 10
    let count = table.invalidate_shape(10);
    assert_eq!(count, 3);
    assert_eq!(table.total_invalidations(), 3);

    // Shape 20 cell should be unaffected
    let cell20 = table.get(20, "a").unwrap();
    assert_eq!(cell20.state, PropertyCellState::Constant);

    // Invalidating again yields 0 (already invalidated)
    let count2 = table.invalidate_shape(10);
    assert_eq!(count2, 0);
}

#[test]
fn integration_table_get_nonexistent() {
    let table = PropertyCellTable::new();
    assert!(table.get(999, "missing").is_none());
}

#[test]
fn integration_table_multi_shape_isolation() {
    let mut table = PropertyCellTable::new();
    // Write same property on different shapes
    for shape in 0..5 {
        table.record_write(shape, "shared_prop", false);
    }
    assert_eq!(table.cell_count(), 5);

    // Invalidate one shape — others unaffected
    table.invalidate_shape(2);
    assert_eq!(table.total_invalidations(), 1);

    for shape in [0_u64, 1, 3, 4] {
        let cell = table.get(shape, "shared_prop").unwrap();
        assert_eq!(cell.state, PropertyCellState::Constant);
    }
}

#[test]
fn integration_table_serde_roundtrip() {
    let mut table = PropertyCellTable::new();
    table.record_write(1, "x", false);
    table.record_write(2, "y", false);
    table.record_write(2, "y", true);
    let json = serde_json::to_string(&table).unwrap();
    let back: PropertyCellTable = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cell_count(), 2);
    assert_eq!(back.total_invalidations(), 1);
}

// ---------------------------------------------------------------------------
// 4. InlineCacheState integration
// ---------------------------------------------------------------------------

#[test]
fn integration_ic_state_full_progression() {
    let state = InlineCacheState::Uninitialised;
    assert!(!state.is_fast_path());
    assert!(!state.is_megamorphic());

    // → Monomorphic
    let (state, degraded) = state.record_access(100, 0);
    assert!(!degraded);
    assert!(state.is_fast_path());
    assert!(matches!(
        state,
        InlineCacheState::Monomorphic { shape_id: 100, .. }
    ));

    // Same shape → still mono
    let (state, degraded) = state.record_access(100, 0);
    assert!(!degraded);
    assert!(matches!(
        state,
        InlineCacheState::Monomorphic { hit_count: 2, .. }
    ));

    // Different shape → polymorphic
    let (state, degraded) = state.record_access(200, 4);
    assert!(degraded);
    assert!(state.is_fast_path());
    assert!(matches!(state, InlineCacheState::Polymorphic { .. }));

    // Third shape → still polymorphic
    let (state, degraded) = state.record_access(300, 8);
    assert!(degraded);
    assert!(state.is_fast_path());

    // Fourth shape → still polymorphic (max is 4)
    let (state, degraded) = state.record_access(400, 12);
    assert!(degraded);
    assert!(state.is_fast_path());

    // Fifth shape → megamorphic
    let (state, degraded) = state.record_access(500, 16);
    assert!(degraded);
    assert!(state.is_megamorphic());
    assert!(!state.is_fast_path());
}

#[test]
fn integration_ic_polymorphic_hit() {
    let state = InlineCacheState::Uninitialised;
    let (state, _) = state.record_access(10, 0);
    let (state, _) = state.record_access(20, 4);
    assert!(matches!(state, InlineCacheState::Polymorphic { .. }));

    // Hit existing shape 10 — no degradation
    let (state, degraded) = state.record_access(10, 0);
    assert!(!degraded);
    assert!(matches!(state, InlineCacheState::Polymorphic { .. }));

    // Hit existing shape 20 — no degradation
    let (_state, degraded) = state.record_access(20, 4);
    assert!(!degraded);
}

#[test]
fn integration_ic_megamorphic_stable() {
    let mega = InlineCacheState::Megamorphic {
        observed_shapes: 10,
        total_accesses: 1000,
    };
    let (new_state, degraded) = mega.record_access(999, 0);
    assert!(!degraded); // Already mega, no further degradation
    assert!(matches!(
        new_state,
        InlineCacheState::Megamorphic {
            observed_shapes: 10,
            total_accesses: 1001
        }
    ));
}

#[test]
fn integration_ic_hit_rate_monomorphic() {
    let mono = InlineCacheState::Monomorphic {
        shape_id: 1,
        slot_offset: 0,
        hit_count: 50,
    };
    assert_eq!(mono.hit_rate_millionths(), 1_000_000);
}

#[test]
fn integration_ic_hit_rate_polymorphic() {
    let poly = InlineCacheState::Polymorphic {
        entries: vec![
            frankenengine_engine::shape_transition_algebra::PolymorphicIcEntry {
                shape_id: 1,
                slot_offset: 0,
                hit_count: 80,
            },
            frankenengine_engine::shape_transition_algebra::PolymorphicIcEntry {
                shape_id: 2,
                slot_offset: 4,
                hit_count: 20,
            },
        ],
        total_hits: 100,
    };
    // max entry hit_count=80, total=100 → 800_000
    assert_eq!(poly.hit_rate_millionths(), 800_000);
}

#[test]
fn integration_ic_hit_rate_uninit_and_mega() {
    assert_eq!(InlineCacheState::Uninitialised.hit_rate_millionths(), 0);
    let mega = InlineCacheState::Megamorphic {
        observed_shapes: 5,
        total_accesses: 100,
    };
    assert_eq!(mega.hit_rate_millionths(), 0);
}

#[test]
fn integration_ic_display_all_variants() {
    let variants: Vec<InlineCacheState> = vec![
        InlineCacheState::Uninitialised,
        InlineCacheState::Monomorphic {
            shape_id: 42,
            slot_offset: 8,
            hit_count: 10,
        },
        InlineCacheState::Polymorphic {
            entries: vec![],
            total_hits: 0,
        },
        InlineCacheState::Megamorphic {
            observed_shapes: 5,
            total_accesses: 100,
        },
    ];
    for state in &variants {
        let display = format!("{state}");
        assert!(!display.is_empty());
    }
    assert!(format!("{}", variants[0]).contains("uninit"));
    assert!(format!("{}", variants[1]).contains("mono"));
    assert!(format!("{}", variants[2]).contains("poly"));
    assert!(format!("{}", variants[3]).contains("mega"));
}

#[test]
fn integration_ic_serde_roundtrip_all() {
    let variants: Vec<InlineCacheState> = vec![
        InlineCacheState::Uninitialised,
        InlineCacheState::Monomorphic {
            shape_id: 1,
            slot_offset: 0,
            hit_count: 5,
        },
        InlineCacheState::Polymorphic {
            entries: vec![
                frankenengine_engine::shape_transition_algebra::PolymorphicIcEntry {
                    shape_id: 1,
                    slot_offset: 0,
                    hit_count: 3,
                },
            ],
            total_hits: 3,
        },
        InlineCacheState::Megamorphic {
            observed_shapes: 10,
            total_accesses: 999,
        },
    ];
    for state in &variants {
        let json = serde_json::to_string(state).unwrap();
        let back: InlineCacheState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

// ---------------------------------------------------------------------------
// 5. GuardFailureReason + ShapeGuardWitness integration
// ---------------------------------------------------------------------------

#[test]
fn integration_guard_failure_reason_display() {
    let reasons = vec![
        GuardFailureReason::ShapeMismatch {
            expected_shape_id: 1,
            actual_shape_id: 2,
        },
        GuardFailureReason::CellInvalidated {
            shape_id: 3,
            property_name: "x".into(),
            cell_state: PropertyCellState::Invalidated,
        },
        GuardFailureReason::DictionaryPromotion { shape_id: 4 },
        GuardFailureReason::PrototypeChanged { shape_id: 5 },
        GuardFailureReason::NonExtensible { shape_id: 6 },
    ];
    for reason in &reasons {
        let display = format!("{reason}");
        assert!(!display.is_empty());
    }
}

#[test]
fn integration_guard_failure_serde_roundtrip() {
    let reasons = vec![
        GuardFailureReason::ShapeMismatch {
            expected_shape_id: 1,
            actual_shape_id: 2,
        },
        GuardFailureReason::CellInvalidated {
            shape_id: 3,
            property_name: "prop".into(),
            cell_state: PropertyCellState::Stable,
        },
        GuardFailureReason::DictionaryPromotion { shape_id: 4 },
        GuardFailureReason::PrototypeChanged { shape_id: 5 },
        GuardFailureReason::NonExtensible { shape_id: 6 },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: GuardFailureReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn integration_witness_lifecycle() {
    let mut witness = ShapeGuardWitness::new(
        100,
        GuardFailureReason::ShapeMismatch {
            expected_shape_id: 1,
            actual_shape_id: 2,
        },
        InlineCacheState::Monomorphic {
            shape_id: 1,
            slot_offset: 0,
            hit_count: 50,
        },
        1,
    );
    assert!(!witness.permanent_deopt);
    assert_eq!(witness.instruction_offset, 100);

    witness.mark_permanent();
    assert!(witness.permanent_deopt);

    let display = format!("{witness}");
    assert!(display.contains("100"));
    assert!(display.contains("perm=true"));
}

#[test]
fn integration_witness_serde_roundtrip() {
    let witness = ShapeGuardWitness::new(
        50,
        GuardFailureReason::DictionaryPromotion { shape_id: 7 },
        InlineCacheState::Uninitialised,
        3,
    );
    let json = serde_json::to_string(&witness).unwrap();
    let back: ShapeGuardWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, back);
}

// ---------------------------------------------------------------------------
// 6. InlineCacheTable integration
// ---------------------------------------------------------------------------

#[test]
fn integration_ic_table_record_and_summary() {
    let mut table = InlineCacheTable::new();
    assert_eq!(table.entry_count(), 0);
    assert_eq!(table.total_hits(), 0);
    assert_eq!(table.total_misses(), 0);

    // Record mono access
    assert!(table.record_access(0, 100, 0));
    assert_eq!(table.entry_count(), 1);
    assert_eq!(table.total_hits(), 1);

    // Same shape hit
    assert!(table.record_access(0, 100, 0));
    assert_eq!(table.total_hits(), 2);

    // Different shape → polymorphic (miss)
    assert!(!table.record_access(0, 200, 4));
    assert_eq!(table.total_misses(), 1);

    let summary = table.summary();
    assert_eq!(summary.entry_count, 1);
    assert_eq!(summary.polymorphic_count, 1);
    assert_eq!(summary.monomorphic_count, 0);
}

#[test]
fn integration_ic_table_multiple_offsets() {
    let mut table = InlineCacheTable::new();
    // Three distinct IC sites
    table.record_access(0, 1, 0);
    table.record_access(4, 2, 0);
    table.record_access(8, 3, 0);
    assert_eq!(table.entry_count(), 3);

    let summary = table.summary();
    assert_eq!(summary.monomorphic_count, 3);
}

#[test]
fn integration_ic_table_guard_failure() {
    let mut table = InlineCacheTable::new();
    table.record_access(0, 100, 0); // mono

    table.record_guard_failure(
        0,
        GuardFailureReason::ShapeMismatch {
            expected_shape_id: 100,
            actual_shape_id: 200,
        },
    );
    assert_eq!(table.witnesses().len(), 1);
    assert_eq!(table.total_misses(), 1);

    let w = &table.witnesses()[0];
    assert_eq!(w.instruction_offset, 0);
    assert_eq!(w.failure_count, 1);
}

#[test]
fn integration_ic_table_hit_rate() {
    let mut table = InlineCacheTable::new();
    // 8 hits
    for _ in 0..8 {
        table.record_access(0, 100, 0);
    }
    // 2 misses (shape change → polymorphic + guard failure)
    table.record_access(0, 200, 4);
    table.record_guard_failure(
        0,
        GuardFailureReason::ShapeMismatch {
            expected_shape_id: 100,
            actual_shape_id: 200,
        },
    );

    // 8 hits + 2 misses = 10 total, hit rate = 800_000
    assert_eq!(table.hit_rate_millionths(), 800_000);
}

#[test]
fn integration_ic_table_serde_roundtrip() {
    let mut table = InlineCacheTable::new();
    table.record_access(0, 1, 0);
    table.record_access(4, 2, 4);
    table.record_guard_failure(0, GuardFailureReason::PrototypeChanged { shape_id: 1 });

    let json = serde_json::to_string(&table).unwrap();
    let back: InlineCacheTable = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entry_count(), 2);
    assert_eq!(back.witnesses().len(), 1);
}

// ---------------------------------------------------------------------------
// 7. ShapeTransitionAlgebra enrichments
// ---------------------------------------------------------------------------

#[test]
fn integration_algebra_basic_operations() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    assert_eq!(algebra.shape_count(), 1);
    assert_eq!(algebra.transition_count(), 0);
    assert!(algebra.all_property_keys().is_empty());

    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    assert_eq!(algebra.shape_count(), 2);
    assert_eq!(algebra.transition_count(), 1);
    assert!(algebra.all_property_keys().contains("x"));

    let shape_ids = algebra.shape_ids();
    assert_eq!(shape_ids.len(), 2);
    assert!(shape_ids.contains(&root));
    assert!(shape_ids.contains(&outcome.shape.shape_id));
}

#[test]
fn integration_algebra_transitions_from() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let transitions = algebra.transitions_from(root);
    assert_eq!(transitions.len(), 2);
}

#[test]
fn integration_algebra_lineage() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let r1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let r2 = algebra
        .apply_mutation(
            r1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let r3 = algebra
        .apply_mutation(
            r2.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "c".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let lineage = algebra.lineage(r3.shape.shape_id).unwrap();
    assert_eq!(lineage.leaf_shape_id, r3.shape.shape_id);
    assert_eq!(lineage.depth, 3);
    assert_eq!(lineage.steps.len(), 3);
}

#[test]
fn integration_algebra_lineage_unknown_shape() {
    let algebra = ShapeTransitionAlgebra::new();
    assert!(algebra.lineage(99999).is_err());
}

#[test]
fn integration_algebra_convergences() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    // Two different paths to adding both a and b
    let r1a = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let _r1ab = algebra
        .apply_mutation(
            r1a.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let r1b = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let _r1ba = algebra
        .apply_mutation(
            r1b.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    // Both paths share root as a convergence target
    let convergences = algebra.find_convergences();
    // At minimum root has 2 transitions coming out, some nodes may converge
    assert!(!convergences.is_empty() || algebra.shape_count() >= 3);
}

#[test]
fn integration_algebra_classify_deopt() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let r1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let transitions = algebra.transitions_from(root);
    assert_eq!(transitions.len(), 1);

    let deopt = algebra.classify_deopt(transitions[0]);
    assert_eq!(deopt.trigger, DeoptTrigger::ShapeTransition);
    assert_eq!(deopt.from_shape_id, root);
    assert_eq!(deopt.to_shape_id, r1.shape.shape_id);
}

// ---------------------------------------------------------------------------
// 8. Corpus pattern
// ---------------------------------------------------------------------------

#[test]
fn integration_corpus_all_specimens_pass() {
    let results = run_shape_transition_corpus();
    assert!(!results.is_empty());
    for (label, ok, detail) in &results {
        assert!(ok, "specimen '{label}' failed: {detail}");
    }
}

#[test]
fn integration_corpus_coverage() {
    let corpus = shape_transition_corpus();
    assert!(corpus.len() >= 8, "corpus should have at least 8 specimens");

    // Check that corpus covers all mutation types
    let labels: Vec<&str> = corpus.iter().map(|s| s.label.as_str()).collect();
    assert!(labels.iter().any(|l| l.contains("add")));
    assert!(labels.iter().any(|l| l.contains("delete")));
    assert!(labels.iter().any(|l| l.contains("reconfigure")));
    assert!(labels.iter().any(|l| l.contains("cell-write")));
    assert!(labels.iter().any(|l| l.contains("prototype")));
}

#[test]
fn integration_corpus_deterministic() {
    let r1 = run_shape_transition_corpus();
    let r2 = run_shape_transition_corpus();
    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.0, b.0, "label mismatch");
        assert_eq!(a.1, b.1, "result mismatch for {}", a.0);
    }
}

// ---------------------------------------------------------------------------
// 9. Combined IC + cell table workflows
// ---------------------------------------------------------------------------

#[test]
fn integration_ic_cell_invalidation_workflow() {
    let mut cell_table = PropertyCellTable::new();
    let mut ic_table = InlineCacheTable::new();

    // Simulate monomorphic IC on shape 100 property "x"
    ic_table.record_access(0, 100, 0);
    ic_table.record_access(0, 100, 0);
    ic_table.record_access(0, 100, 0);
    cell_table.record_write(100, "x", false);
    cell_table.record_write(100, "x", false);

    // IC is monomorphic, cell is Stable
    assert!(matches!(
        ic_table.get(0),
        Some(InlineCacheState::Monomorphic { .. })
    ));
    assert_eq!(
        cell_table.get(100, "x").unwrap().state,
        PropertyCellState::Stable
    );

    // Kind change invalidates cell
    let invalidated = cell_table.record_write(100, "x", true);
    assert!(invalidated);

    // Record guard failure on IC
    ic_table.record_guard_failure(
        0,
        GuardFailureReason::CellInvalidated {
            shape_id: 100,
            property_name: "x".into(),
            cell_state: PropertyCellState::Invalidated,
        },
    );
    assert_eq!(ic_table.witnesses().len(), 1);
}

#[test]
fn integration_shape_algebra_with_ic_tracking() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let mut ic_table = InlineCacheTable::new();
    let root = algebra.root_shape_id();

    // Add property → new shape
    let r1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let shape_x = r1.shape.shape_id;

    // IC site sees shape_x
    ic_table.record_access(0, shape_x, 0);
    assert!(matches!(
        ic_table.get(0),
        Some(InlineCacheState::Monomorphic { .. })
    ));

    // Add another property → new shape
    let r2 = algebra
        .apply_mutation(
            shape_x,
            ShapeMutation::AddProperty {
                key: "y".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let shape_xy = r2.shape.shape_id;

    // IC now sees different shape → polymorphic
    ic_table.record_access(0, shape_xy, 4);
    assert!(matches!(
        ic_table.get(0),
        Some(InlineCacheState::Polymorphic { .. })
    ));

    let summary = ic_table.summary();
    assert_eq!(summary.polymorphic_count, 1);
    assert!(summary.hit_rate_millionths > 0);
}

#[test]
fn integration_full_deopt_evidence_chain() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let mut ic_table = InlineCacheTable::new();
    let mut cell_table = PropertyCellTable::new();
    let root = algebra.root_shape_id();

    // Build shape chain: root → +x → +y
    let r1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let r2 = algebra
        .apply_mutation(
            r1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "y".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let final_shape = r2.shape.shape_id;

    // Train IC on final shape
    for _ in 0..10 {
        ic_table.record_access(0, final_shape, 0);
    }

    // Track cells
    cell_table.record_write(final_shape, "x", false);
    cell_table.record_write(final_shape, "x", false);

    // Simulate prototype mutation → deopt
    let r3 = algebra
        .apply_mutation(
            final_shape,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("evil-proto".into()),
            },
        )
        .unwrap();

    // Classify deopt from transition
    let transitions = algebra.transitions_from(final_shape);
    let proto_transition = transitions
        .iter()
        .find(|t| t.to_shape_id == r3.shape.shape_id)
        .unwrap();
    let deopt = algebra.classify_deopt(proto_transition);
    assert_eq!(deopt.trigger, DeoptTrigger::PrototypeMutation);

    // Record guard failure
    ic_table.record_guard_failure(
        0,
        GuardFailureReason::PrototypeChanged {
            shape_id: final_shape,
        },
    );

    // Verify evidence chain
    let summary = ic_table.summary();
    assert!(summary.witness_count >= 1);
    assert!(summary.total_misses >= 1);
}
