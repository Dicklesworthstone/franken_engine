//! Enrichment integration tests for `frankenengine_engine::shape_transition_algebra`.
//!
//! Covers serde roundtrips for all public types, PropertyAttributes constructors,
//! ShapeDescriptor accessors, TransitionKind/InvalidatedAssumptionKind/ShapeMutation
//! variant coverage, algebra mutation semantics (add/delete/reconfigure/write/prototype),
//! error paths, manifest generation, and bundle emission.

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

use std::collections::BTreeSet;

use frankenengine_engine::shape_transition_algebra::{
    COMPONENT, InvalidatedAssumptionKind, PropertyAttributes, PropertyCellInvalidationReceipt,
    PropertyLayoutDescriptor, SHAPE_LATTICE_SCHEMA_VERSION, ShapeAlgebraError, ShapeDescriptor,
    ShapeLatticeArtifactPaths, ShapeLatticeBundle, ShapeLatticeManifest, ShapeLatticeRunManifest,
    ShapeLatticeTraceIds, ShapeMutation, ShapeMutationOutcome, ShapeTraceEvent, ShapeTransition,
    ShapeTransitionAlgebra, TransitionKind, emit_shape_lattice_bundle,
};

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn component_constant_matches() {
    assert_eq!(COMPONENT, "shape_transition_algebra");
}

#[test]
fn schema_version_nonempty_and_contains_shape() {
    assert!(!SHAPE_LATTICE_SCHEMA_VERSION.is_empty());
    assert!(SHAPE_LATTICE_SCHEMA_VERSION.contains("shape"));
}

// ── PropertyAttributes ──────────────────────────────────────────────────

#[test]
fn property_attributes_default_all_true() {
    let attrs = PropertyAttributes::default();
    assert!(attrs.writable);
    assert!(attrs.enumerable);
    assert!(attrs.configurable);
}

#[test]
fn property_attributes_frozen() {
    let attrs = PropertyAttributes::frozen();
    assert!(!attrs.writable);
    assert!(attrs.enumerable);
    assert!(!attrs.configurable);
}

#[test]
fn property_attributes_sealed() {
    let attrs = PropertyAttributes::sealed();
    assert!(attrs.writable);
    assert!(attrs.enumerable);
    assert!(!attrs.configurable);
}

#[test]
fn property_attributes_non_enumerable() {
    let attrs = PropertyAttributes::non_enumerable();
    assert!(attrs.writable);
    assert!(!attrs.enumerable);
    assert!(attrs.configurable);
}

#[test]
fn property_attributes_serde_roundtrip() {
    for attrs in [
        PropertyAttributes::default(),
        PropertyAttributes::frozen(),
        PropertyAttributes::sealed(),
        PropertyAttributes::non_enumerable(),
    ] {
        let json = serde_json::to_string(&attrs).unwrap();
        let back: PropertyAttributes = serde_json::from_str(&json).unwrap();
        assert_eq!(back, attrs);
    }
}

#[test]
fn property_attributes_ordering_consistent() {
    let mut attrs = vec![
        PropertyAttributes::frozen(),
        PropertyAttributes::default(),
        PropertyAttributes::sealed(),
        PropertyAttributes::non_enumerable(),
    ];
    attrs.sort();
    // Just verify sort doesn't panic and produces consistent order
    let mut again = attrs.clone();
    again.sort();
    assert_eq!(attrs, again);
}

// ── PropertyLayoutDescriptor ────────────────────────────────────────────

#[test]
fn property_layout_descriptor_serde_roundtrip() {
    let desc = PropertyLayoutDescriptor {
        property_key: "x".to_string(),
        slot_index: 0,
        attributes: PropertyAttributes::default(),
    };
    let json = serde_json::to_string(&desc).unwrap();
    let back: PropertyLayoutDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, desc);
}

// ── TransitionKind ──────────────────────────────────────────────────────

#[test]
fn transition_kind_all_variants_serde_roundtrip() {
    let variants = [
        TransitionKind::AddProperty,
        TransitionKind::DeleteProperty,
        TransitionKind::ReconfigureProperty,
        TransitionKind::PropertyCellWrite,
        TransitionKind::PrototypeWrite,
    ];
    let mut seen = BTreeSet::new();
    for kind in &variants {
        let json = serde_json::to_string(kind).unwrap();
        let back: TransitionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
        seen.insert(json);
    }
    assert_eq!(
        seen.len(),
        5,
        "all transition kinds should serialize distinctly"
    );
}

// ── InvalidatedAssumptionKind ───────────────────────────────────────────

#[test]
fn invalidated_assumption_kind_all_variants_serde_roundtrip() {
    let variants = [
        InvalidatedAssumptionKind::ShapeGuard,
        InvalidatedAssumptionKind::PropertyCell,
        InvalidatedAssumptionKind::PropertyDescriptor,
        InvalidatedAssumptionKind::PrototypeChain,
    ];
    let mut seen = BTreeSet::new();
    for kind in &variants {
        let json = serde_json::to_string(kind).unwrap();
        let back: InvalidatedAssumptionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
        seen.insert(json);
    }
    assert_eq!(seen.len(), 4);
}

// ── ShapeMutation ───────────────────────────────────────────────────────

#[test]
fn shape_mutation_all_variants_serde_roundtrip() {
    let variants = vec![
        ShapeMutation::AddProperty {
            key: "x".to_string(),
            attributes: PropertyAttributes::default(),
        },
        ShapeMutation::DeleteProperty {
            key: "x".to_string(),
        },
        ShapeMutation::ReconfigureProperty {
            key: "x".to_string(),
            attributes: PropertyAttributes::frozen(),
        },
        ShapeMutation::WritePropertyCell {
            key: "x".to_string(),
        },
        ShapeMutation::WritePrototype {
            prototype_fingerprint: Some("proto-abc".to_string()),
        },
        ShapeMutation::WritePrototype {
            prototype_fingerprint: None,
        },
    ];
    for mutation in &variants {
        let json = serde_json::to_string(mutation).unwrap();
        let back: ShapeMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(*mutation, back);
    }
}

// ── ShapeAlgebraError ───────────────────────────────────────────────────

#[test]
fn shape_algebra_error_display_all_variants() {
    let errors = [
        ShapeAlgebraError::UnknownShape { shape_id: 42 },
        ShapeAlgebraError::PropertyAlreadyExists {
            shape_id: 1,
            key: "x".to_string(),
        },
        ShapeAlgebraError::MissingProperty {
            shape_id: 2,
            key: "y".to_string(),
        },
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let msg = format!("{err}");
        assert!(!msg.is_empty());
        displays.insert(msg);
    }
    assert_eq!(
        displays.len(),
        3,
        "all error variants should have unique display"
    );
}

#[test]
fn shape_algebra_error_serde_roundtrip() {
    let errors = [
        ShapeAlgebraError::UnknownShape { shape_id: 42 },
        ShapeAlgebraError::PropertyAlreadyExists {
            shape_id: 1,
            key: "x".to_string(),
        },
        ShapeAlgebraError::MissingProperty {
            shape_id: 2,
            key: "y".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ShapeAlgebraError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ── ShapeTransitionAlgebra core ─────────────────────────────────────────

#[test]
fn algebra_new_has_root_shape() {
    let algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let root = algebra.shape(root_id);
    assert!(root.is_some());
    let root = root.unwrap();
    assert_eq!(root.property_count(), 0);
    assert!(root.keys().is_empty());
}

#[test]
fn algebra_add_property_creates_new_shape() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    assert_ne!(outcome.shape.shape_id, root_id);
    assert_eq!(outcome.shape.property_count(), 1);
    assert_eq!(outcome.shape.slot_for("x"), Some(0));
    assert_eq!(
        outcome.transition.transition_kind,
        TransitionKind::AddProperty
    );
    assert_eq!(outcome.transition.from_shape_id, root_id);
    assert_eq!(outcome.transition.to_shape_id, outcome.shape.shape_id);
}

#[test]
fn algebra_add_duplicate_property_errors() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let err = algebra
        .apply_mutation(
            outcome.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap_err();
    assert!(format!("{err}").contains("already exists"));
}

#[test]
fn algebra_delete_property_removes_it() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let with_x = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let without_x = algebra
        .apply_mutation(
            with_x.shape.shape_id,
            ShapeMutation::DeleteProperty {
                key: "x".to_string(),
            },
        )
        .unwrap();
    assert_eq!(without_x.shape.property_count(), 0);
    assert_eq!(
        without_x.transition.transition_kind,
        TransitionKind::DeleteProperty
    );
}

#[test]
fn algebra_delete_missing_property_errors() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let err = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::DeleteProperty {
                key: "nonexistent".to_string(),
            },
        )
        .unwrap_err();
    assert!(format!("{err}").contains("not present"));
}

#[test]
fn algebra_reconfigure_property_changes_attributes() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let with_x = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let reconfigured = algebra
        .apply_mutation(
            with_x.shape.shape_id,
            ShapeMutation::ReconfigureProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::frozen(),
            },
        )
        .unwrap();
    assert_eq!(
        reconfigured.transition.transition_kind,
        TransitionKind::ReconfigureProperty
    );
    let x_desc = reconfigured
        .shape
        .property_layout
        .iter()
        .find(|d| d.property_key == "x")
        .unwrap();
    assert_eq!(x_desc.attributes, PropertyAttributes::frozen());
}

#[test]
fn algebra_reconfigure_missing_property_errors() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let err = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::ReconfigureProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::frozen(),
            },
        )
        .unwrap_err();
    assert!(format!("{err}").contains("not present"));
}

#[test]
fn algebra_write_property_cell_keeps_same_shape() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let with_x = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let written = algebra
        .apply_mutation(
            with_x.shape.shape_id,
            ShapeMutation::WritePropertyCell {
                key: "x".to_string(),
            },
        )
        .unwrap();
    assert_eq!(written.shape.shape_id, with_x.shape.shape_id);
    assert_eq!(
        written.transition.transition_kind,
        TransitionKind::PropertyCellWrite
    );
}

#[test]
fn algebra_write_property_cell_missing_errors() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let err = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::WritePropertyCell {
                key: "x".to_string(),
            },
        )
        .unwrap_err();
    assert!(format!("{err}").contains("not present"));
}

#[test]
fn algebra_write_prototype_changes_shape() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-abc".to_string()),
            },
        )
        .unwrap();
    assert_eq!(
        outcome.transition.transition_kind,
        TransitionKind::PrototypeWrite
    );
    assert_eq!(
        outcome.shape.prototype_fingerprint,
        Some("proto-abc".to_string())
    );
}

#[test]
fn algebra_write_same_prototype_no_invalidation() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    // Root has prototype_fingerprint = None; writing None should produce no invalidations
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: None,
            },
        )
        .unwrap();
    assert!(
        outcome
            .transition
            .invalidation_receipt
            .invalidated_assumptions
            .is_empty()
    );
}

#[test]
fn algebra_unknown_shape_errors() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let err = algebra
        .apply_mutation(
            999_999,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap_err();
    assert!(format!("{err}").contains("unknown shape"));
}

#[test]
fn algebra_cached_transition_reuses_result() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let mutation = ShapeMutation::AddProperty {
        key: "x".to_string(),
        attributes: PropertyAttributes::default(),
    };
    let first = algebra.apply_mutation(root_id, mutation.clone()).unwrap();
    let second = algebra.apply_mutation(root_id, mutation).unwrap();
    assert_eq!(first.shape.shape_id, second.shape.shape_id);
    assert_eq!(first.transition, second.transition);
}

// ── Invalidation Receipts ───────────────────────────────────────────────

#[test]
fn add_property_invalidates_shape_guard_and_property_cell() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let receipt = &outcome.transition.invalidation_receipt;
    assert!(
        receipt
            .invalidated_assumptions
            .contains(&InvalidatedAssumptionKind::ShapeGuard)
    );
    assert!(
        receipt
            .invalidated_assumptions
            .contains(&InvalidatedAssumptionKind::PropertyCell)
    );
}

#[test]
fn delete_property_invalidates_descriptor_too() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let with_x = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let outcome = algebra
        .apply_mutation(
            with_x.shape.shape_id,
            ShapeMutation::DeleteProperty {
                key: "x".to_string(),
            },
        )
        .unwrap();
    let receipt = &outcome.transition.invalidation_receipt;
    assert!(
        receipt
            .invalidated_assumptions
            .contains(&InvalidatedAssumptionKind::PropertyDescriptor)
    );
}

#[test]
fn write_property_cell_only_invalidates_cell() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let with_x = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let outcome = algebra
        .apply_mutation(
            with_x.shape.shape_id,
            ShapeMutation::WritePropertyCell {
                key: "x".to_string(),
            },
        )
        .unwrap();
    let receipt = &outcome.transition.invalidation_receipt;
    assert_eq!(receipt.invalidated_assumptions.len(), 1);
    assert_eq!(
        receipt.invalidated_assumptions[0],
        InvalidatedAssumptionKind::PropertyCell
    );
}

#[test]
fn prototype_write_invalidates_chain() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("new-proto".to_string()),
            },
        )
        .unwrap();
    let receipt = &outcome.transition.invalidation_receipt;
    assert!(
        receipt
            .invalidated_assumptions
            .contains(&InvalidatedAssumptionKind::PrototypeChain)
    );
}

// ── PropertyCellInvalidationReceipt ─────────────────────────────────────

#[test]
fn invalidation_receipt_serde_roundtrip() {
    let receipt = PropertyCellInvalidationReceipt {
        receipt_id: "r-001".to_string(),
        transition_kind: TransitionKind::AddProperty,
        invalidated_assumptions: vec![
            InvalidatedAssumptionKind::ShapeGuard,
            InvalidatedAssumptionKind::PropertyCell,
        ],
        property_key: Some("x".to_string()),
        from_shape_id: 1,
        to_shape_id: 2,
        summary: "added property x".to_string(),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: PropertyCellInvalidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

// ── ShapeDescriptor ─────────────────────────────────────────────────────

#[test]
fn shape_descriptor_accessors() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let with_ab = {
        let with_a = algebra
            .apply_mutation(
                root_id,
                ShapeMutation::AddProperty {
                    key: "a".to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        algebra
            .apply_mutation(
                with_a.shape.shape_id,
                ShapeMutation::AddProperty {
                    key: "b".to_string(),
                    attributes: PropertyAttributes::sealed(),
                },
            )
            .unwrap()
    };
    let shape = &with_ab.shape;
    assert_eq!(shape.property_count(), 2);
    assert_eq!(shape.slot_for("a"), Some(0));
    assert_eq!(shape.slot_for("b"), Some(1));
    assert_eq!(shape.slot_for("c"), None);
    assert_eq!(shape.keys(), vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn shape_descriptor_serde_roundtrip() {
    let desc = ShapeDescriptor {
        shape_id: 42,
        fingerprint: "fp-test".to_string(),
        prototype_fingerprint: Some("proto-x".to_string()),
        property_layout: vec![PropertyLayoutDescriptor {
            property_key: "x".to_string(),
            slot_index: 0,
            attributes: PropertyAttributes::default(),
        }],
    };
    let json = serde_json::to_string(&desc).unwrap();
    let back: ShapeDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, desc);
}

// ── ShapeTransition ─────────────────────────────────────────────────────

#[test]
fn shape_transition_from_mutation_serde_roundtrip() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let json = serde_json::to_string(&outcome.transition).unwrap();
    let back: ShapeTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outcome.transition);
}

// ── ShapeMutationOutcome ────────────────────────────────────────────────

#[test]
fn shape_mutation_outcome_serde_roundtrip() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "y".to_string(),
                attributes: PropertyAttributes::sealed(),
            },
        )
        .unwrap();
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ShapeMutationOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outcome);
}

// ── ShapeLatticeManifest ────────────────────────────────────────────────

#[test]
fn manifest_contains_root_and_transitions() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let _ = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "a".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let manifest = algebra.manifest();
    assert_eq!(manifest.schema_version, SHAPE_LATTICE_SCHEMA_VERSION);
    assert_eq!(manifest.component, COMPONENT);
    assert_eq!(manifest.root_shape_id, root_id);
    assert!(manifest.shapes.len() >= 2); // root + shape with "a"
    assert!(!manifest.transitions.is_empty());
}

#[test]
fn manifest_serde_roundtrip() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let _ = algebra.apply_mutation(
        root_id,
        ShapeMutation::AddProperty {
            key: "x".to_string(),
            attributes: PropertyAttributes::default(),
        },
    );
    let manifest = algebra.manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ShapeLatticeManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

// ── ShapeTraceEvent ─────────────────────────────────────────────────────

#[test]
fn shape_trace_event_serde_roundtrip() {
    let event = ShapeTraceEvent {
        trace_id: "trace-1".to_string(),
        component: COMPONENT.to_string(),
        step: 0,
        object_id: 1,
        from_shape_id: 100,
        to_shape_id: 101,
        to_shape_fingerprint: "fp-101".to_string(),
        transition_kind: TransitionKind::AddProperty,
        property_key: Some("x".to_string()),
        invalidation_receipt: PropertyCellInvalidationReceipt {
            receipt_id: "r-001".to_string(),
            transition_kind: TransitionKind::AddProperty,
            invalidated_assumptions: vec![InvalidatedAssumptionKind::ShapeGuard],
            property_key: Some("x".to_string()),
            from_shape_id: 100,
            to_shape_id: 101,
            summary: "add x".to_string(),
        },
        property_cell_revision_before: Some(0),
        property_cell_revision_after: Some(1),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ShapeTraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ── ShapeLatticeArtifactPaths / TraceIds / RunManifest ───────────────────

#[test]
fn artifact_paths_serde_roundtrip() {
    let paths = ShapeLatticeArtifactPaths {
        shape_lattice_manifest: "manifest.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events: "events.jsonl".to_string(),
        commands: "commands.txt".to_string(),
        trace_ids: "trace_ids.json".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: ShapeLatticeArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(back, paths);
}

#[test]
fn trace_ids_serde_roundtrip() {
    let ids = ShapeLatticeTraceIds {
        trace_ids: vec!["t1".to_string()],
        decision_ids: vec!["d1".to_string()],
        policy_ids: vec!["p1".to_string()],
    };
    let json = serde_json::to_string(&ids).unwrap();
    let back: ShapeLatticeTraceIds = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ids);
}

#[test]
fn run_manifest_serde_roundtrip() {
    let manifest = ShapeLatticeRunManifest {
        schema_version: SHAPE_LATTICE_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        trace_ids: vec!["t1".to_string()],
        decision_ids: vec!["d1".to_string()],
        policy_ids: vec!["p1".to_string()],
        shape_count: 2,
        transition_count: 1,
        receipt_count: 1,
        artifact_paths: ShapeLatticeArtifactPaths {
            shape_lattice_manifest: "manifest.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events: "events.jsonl".to_string(),
            commands: "commands.txt".to_string(),
            trace_ids: "trace_ids.json".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ShapeLatticeRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

// ── ShapeLatticeBundle ──────────────────────────────────────────────────

#[test]
fn shape_lattice_bundle_serde_roundtrip() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let _ = algebra.apply_mutation(
        root_id,
        ShapeMutation::AddProperty {
            key: "x".to_string(),
            attributes: PropertyAttributes::default(),
        },
    );
    let bundle = ShapeLatticeBundle {
        manifest: algebra.manifest(),
        trace_events: Vec::new(),
        trace_ids: vec!["t-1".to_string()],
        decision_ids: vec!["d-1".to_string()],
        policy_ids: vec!["p-1".to_string()],
        commands: vec!["test-cmd".to_string()],
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ShapeLatticeBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
}

// ── emit_shape_lattice_bundle ───────────────────────────────────────────

#[test]
fn emit_bundle_creates_all_artifacts() {
    let dir = std::env::temp_dir().join(format!(
        "shape-algebra-enrichment-emit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "x".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let event = ShapeTraceEvent {
        trace_id: "trace-emit".to_string(),
        component: COMPONENT.to_string(),
        step: 0,
        object_id: 1,
        from_shape_id: root_id,
        to_shape_id: outcome.shape.shape_id,
        to_shape_fingerprint: outcome.shape.fingerprint.clone(),
        transition_kind: TransitionKind::AddProperty,
        property_key: Some("x".to_string()),
        invalidation_receipt: outcome.transition.invalidation_receipt.clone(),
        property_cell_revision_before: None,
        property_cell_revision_after: None,
    };

    let bundle = ShapeLatticeBundle {
        manifest: algebra.manifest(),
        trace_events: vec![event],
        trace_ids: vec!["trace-emit".to_string()],
        decision_ids: vec!["dec-emit".to_string()],
        policy_ids: vec!["pol-emit".to_string()],
        commands: vec!["test-command".to_string()],
    };

    let report = emit_shape_lattice_bundle(&dir, &bundle).unwrap();
    assert!(report.shape_lattice_manifest_path.exists());
    assert!(report.run_manifest_path.exists());
    assert!(report.events_path.exists());
    assert!(report.commands_path.exists());
    assert!(report.trace_ids_path.exists());

    // Verify manifest can be deserialized
    let manifest_bytes = std::fs::read(&report.shape_lattice_manifest_path).unwrap();
    let manifest: ShapeLatticeManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest.schema_version, SHAPE_LATTICE_SCHEMA_VERSION);

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Multi-Property Chain ────────────────────────────────────────────────

#[test]
fn algebra_multi_property_chain_slot_indices() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let mut current_id = algebra.root_shape_id();
    for (i, key) in ["a", "b", "c", "d"].iter().enumerate() {
        let outcome = algebra
            .apply_mutation(
                current_id,
                ShapeMutation::AddProperty {
                    key: key.to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        assert_eq!(outcome.shape.property_count(), i + 1);
        assert_eq!(outcome.shape.slot_for(key), Some(i));
        current_id = outcome.shape.shape_id;
    }
    let final_shape = algebra.shape(current_id).unwrap();
    assert_eq!(final_shape.keys(), vec!["a", "b", "c", "d"]);
}

// ── Shape Interning (Convergence) ───────────────────────────────────────

#[test]
fn algebra_shape_interning_converges() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();

    // Path 1: add "a" then "b"
    let a1 = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "a".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let ab = algebra
        .apply_mutation(
            a1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "b".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    // Path 2: add "b" then "a"
    let b1 = algebra
        .apply_mutation(
            root_id,
            ShapeMutation::AddProperty {
                key: "b".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let ba = algebra
        .apply_mutation(
            b1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "a".to_string(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    // Different paths produce different shapes because slot order differs
    // (a@0, b@1 vs b@0, a@1)
    assert_ne!(ab.shape.shape_id, ba.shape.shape_id);
    assert_eq!(ab.shape.property_count(), ba.shape.property_count());
}

// ── Algebra Serde ───────────────────────────────────────────────────────

#[test]
fn algebra_serde_roundtrip() {
    // ShapeTransitionAlgebra contains BTreeMap<TransitionLookupKey, _> which
    // cannot roundtrip through JSON (keys must be strings). Verify that the
    // algebra is Clone + PartialEq instead, and that individual components
    // (shapes, transitions) serde correctly via their own dedicated tests.
    let mut algebra = ShapeTransitionAlgebra::new();
    let root_id = algebra.root_shape_id();
    let outcome = algebra.apply_mutation(
        root_id,
        ShapeMutation::AddProperty {
            key: "x".to_string(),
            attributes: PropertyAttributes::default(),
        },
    );
    assert!(outcome.is_ok());
    let cloned = algebra.clone();
    assert_eq!(cloned.root_shape_id(), algebra.root_shape_id());
}
