//! Deep integration tests for `frankenengine_engine::shape_transition_algebra`.
//!
//! Covers multi-step transition chains, transition table caching, shape
//! interning/dedup, error edge cases, all attribute combinations, prototype
//! writes, WritePropertyCell semantics, invalidation receipt completeness,
//! manifest generation, fingerprint determinism, slot index correctness,
//! large shape sequences, serde round-trips, Display/Error formatting,
//! PropertyCellTracker lifecycle, and bundle emission.

#![forbid(unsafe_code)]
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
    COMPONENT, ConvergenceWitness, DeoptEvent, DeoptTrigger, InvalidatedAssumptionKind,
    PropertyAttributes, PropertyCellState, PropertyCellTable, PropertyCellTracker,
    PropertyLayoutDescriptor, SHAPE_LATTICE_SCHEMA_VERSION, ShapeAlgebraError, ShapeDescriptor,
    ShapeLatticeBundle, ShapeLatticeBundleReport, ShapeLatticeManifest, ShapeLatticeRunManifest,
    ShapeLatticeTraceIds, ShapeLineage, ShapeMutation, ShapeMutationOutcome, ShapeTraceEvent,
    ShapeTransition, ShapeTransitionAlgebra, TransitionKind, emit_shape_lattice_bundle,
};

// =========================================================================
// Helper: build an algebra and add N properties sequentially
// =========================================================================

fn build_chain(keys: &[&str]) -> (ShapeTransitionAlgebra, Vec<u64>) {
    let mut algebra = ShapeTransitionAlgebra::new();
    let mut ids = vec![algebra.root_shape_id()];
    for key in keys {
        let outcome = algebra
            .apply_mutation(
                *ids.last().unwrap(),
                ShapeMutation::AddProperty {
                    key: key.to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        ids.push(outcome.shape.shape_id);
    }
    (algebra, ids)
}

// =========================================================================
// 1. Multi-step transition chains
// =========================================================================

#[test]
fn deep_multi_step_add_reconfigure_delete_readd() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    // Step 1: add "x"
    let s1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    assert_eq!(s1.shape.property_count(), 1);
    assert_eq!(s1.shape.slot_for("x"), Some(0));

    // Step 2: reconfigure "x" to frozen
    let s2 = algebra
        .apply_mutation(
            s1.shape.shape_id,
            ShapeMutation::ReconfigureProperty {
                key: "x".into(),
                attributes: PropertyAttributes::frozen(),
            },
        )
        .unwrap();
    assert_ne!(s2.shape.shape_id, s1.shape.shape_id);
    let x_desc = s2
        .shape
        .property_layout
        .iter()
        .find(|d| d.property_key == "x")
        .unwrap();
    assert_eq!(x_desc.attributes, PropertyAttributes::frozen());

    // Step 3: delete "x"
    let s3 = algebra
        .apply_mutation(
            s2.shape.shape_id,
            ShapeMutation::DeleteProperty { key: "x".into() },
        )
        .unwrap();
    assert_eq!(s3.shape.property_count(), 0);

    // Step 4: re-add "x" with different attributes
    let s4 = algebra
        .apply_mutation(
            s3.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::sealed(),
            },
        )
        .unwrap();
    assert_eq!(s4.shape.property_count(), 1);
    let x_sealed = s4
        .shape
        .property_layout
        .iter()
        .find(|d| d.property_key == "x")
        .unwrap();
    assert_eq!(x_sealed.attributes, PropertyAttributes::sealed());
}

#[test]
fn deep_multi_step_chain_five_properties_then_delete_middle() {
    let keys = ["a", "b", "c", "d", "e"];
    let (mut algebra, ids) = build_chain(&keys);
    let shape_with_five = *ids.last().unwrap();

    // Delete "c" (the middle property)
    let outcome = algebra
        .apply_mutation(
            shape_with_five,
            ShapeMutation::DeleteProperty { key: "c".into() },
        )
        .unwrap();

    // After delete, slots should be renumbered
    assert_eq!(outcome.shape.property_count(), 4);
    assert_eq!(outcome.shape.slot_for("a"), Some(0));
    assert_eq!(outcome.shape.slot_for("b"), Some(1));
    assert_eq!(outcome.shape.slot_for("d"), Some(2));
    assert_eq!(outcome.shape.slot_for("e"), Some(3));
    assert_eq!(outcome.shape.slot_for("c"), None);
}

#[test]
fn deep_multi_step_add_write_cell_add_more() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let s1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    // WritePropertyCell on "x" -- shape identity preserved
    let s2 = algebra
        .apply_mutation(
            s1.shape.shape_id,
            ShapeMutation::WritePropertyCell { key: "x".into() },
        )
        .unwrap();
    assert_eq!(s2.shape.shape_id, s1.shape.shape_id);

    // Add more after cell write
    let s3 = algebra
        .apply_mutation(
            s2.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "y".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    assert_eq!(s3.shape.property_count(), 2);
    assert_eq!(s3.shape.slot_for("x"), Some(0));
    assert_eq!(s3.shape.slot_for("y"), Some(1));
}

// =========================================================================
// 2. Transition table caching
// =========================================================================

#[test]
fn deep_cached_transition_returns_same_shape_id() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let mutation = ShapeMutation::AddProperty {
        key: "cached".into(),
        attributes: PropertyAttributes::default(),
    };
    let first = algebra.apply_mutation(root, mutation.clone()).unwrap();
    let count_after_first = algebra.shape_count();

    let second = algebra.apply_mutation(root, mutation.clone()).unwrap();
    assert_eq!(first.shape.shape_id, second.shape.shape_id);
    assert_eq!(first.transition, second.transition);
    // No new shapes created
    assert_eq!(algebra.shape_count(), count_after_first);
}

#[test]
fn deep_cached_transition_delete_also_cached() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let add_outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "k".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let del_mutation = ShapeMutation::DeleteProperty { key: "k".into() };
    let del1 = algebra
        .apply_mutation(add_outcome.shape.shape_id, del_mutation.clone())
        .unwrap();
    let del2 = algebra
        .apply_mutation(add_outcome.shape.shape_id, del_mutation)
        .unwrap();
    assert_eq!(del1.shape.shape_id, del2.shape.shape_id);
    assert_eq!(del1.transition, del2.transition);
}

#[test]
fn deep_cached_transition_reconfigure_cached() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let added = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "r".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let reconf = ShapeMutation::ReconfigureProperty {
        key: "r".into(),
        attributes: PropertyAttributes::frozen(),
    };
    let r1 = algebra
        .apply_mutation(added.shape.shape_id, reconf.clone())
        .unwrap();
    let r2 = algebra
        .apply_mutation(added.shape.shape_id, reconf)
        .unwrap();
    assert_eq!(r1.shape.shape_id, r2.shape.shape_id);
}

// =========================================================================
// 3. Shape interning/dedup
// =========================================================================

#[test]
fn deep_interning_add_delete_returns_to_root_fingerprint() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let root_fp = algebra.shape(root).unwrap().fingerprint.clone();

    let added = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "temp".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let deleted = algebra
        .apply_mutation(
            added.shape.shape_id,
            ShapeMutation::DeleteProperty { key: "temp".into() },
        )
        .unwrap();

    // After add+delete, the fingerprint should match root
    assert_eq!(deleted.shape.fingerprint, root_fp);
    // Shape interning means the shape_id equals the root
    assert_eq!(deleted.shape.shape_id, root);
}

#[test]
fn deep_interning_same_layout_different_paths_same_fingerprint() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    // Path A: add "a", then add "b", then delete "a"
    let a1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let ab = algebra
        .apply_mutation(
            a1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let path_a_result = algebra
        .apply_mutation(
            ab.shape.shape_id,
            ShapeMutation::DeleteProperty { key: "a".into() },
        )
        .unwrap();

    // Path B: add "b" directly
    let path_b_result = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    // Both should have the same fingerprint and shape_id (interned)
    assert_eq!(
        path_a_result.shape.fingerprint,
        path_b_result.shape.fingerprint
    );
    assert_eq!(path_a_result.shape.shape_id, path_b_result.shape.shape_id);
}

#[test]
fn deep_interning_prototype_fingerprint_differentiates_shapes() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let proto_a = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-a".into()),
            },
        )
        .unwrap();
    let proto_b = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-b".into()),
            },
        )
        .unwrap();

    // Different prototypes => different shapes
    assert_ne!(proto_a.shape.shape_id, proto_b.shape.shape_id);
    assert_ne!(proto_a.shape.fingerprint, proto_b.shape.fingerprint);
}

// =========================================================================
// 4. Error edge cases
// =========================================================================

#[test]
fn deep_error_add_property_already_exists() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let added = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "dup".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let err = algebra
        .apply_mutation(
            added.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "dup".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ShapeAlgebraError::PropertyAlreadyExists { .. }
    ));
    let msg = format!("{err}");
    assert!(msg.contains("dup"));
    assert!(msg.contains("already exists"));
}

#[test]
fn deep_error_delete_missing_property() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let err = algebra
        .apply_mutation(
            root,
            ShapeMutation::DeleteProperty {
                key: "ghost".into(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, ShapeAlgebraError::MissingProperty { .. }));
    assert!(format!("{err}").contains("ghost"));
}

#[test]
fn deep_error_reconfigure_missing_property() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let err = algebra
        .apply_mutation(
            root,
            ShapeMutation::ReconfigureProperty {
                key: "phantom".into(),
                attributes: PropertyAttributes::frozen(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, ShapeAlgebraError::MissingProperty { .. }));
    assert!(format!("{err}").contains("phantom"));
}

#[test]
fn deep_error_write_cell_missing_property() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let err = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePropertyCell { key: "nope".into() },
        )
        .unwrap_err();
    assert!(matches!(err, ShapeAlgebraError::MissingProperty { .. }));
}

#[test]
fn deep_error_unknown_shape_for_all_mutations() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let bogus_id = 0xDEAD_BEEF_u64;

    let mutations = vec![
        ShapeMutation::AddProperty {
            key: "x".into(),
            attributes: PropertyAttributes::default(),
        },
        ShapeMutation::DeleteProperty { key: "x".into() },
        ShapeMutation::ReconfigureProperty {
            key: "x".into(),
            attributes: PropertyAttributes::frozen(),
        },
        ShapeMutation::WritePropertyCell { key: "x".into() },
        ShapeMutation::WritePrototype {
            prototype_fingerprint: Some("proto".into()),
        },
    ];

    for mutation in mutations {
        let err = algebra.apply_mutation(bogus_id, mutation).unwrap_err();
        assert!(
            matches!(err, ShapeAlgebraError::UnknownShape { .. }),
            "expected UnknownShape, got {err:?}"
        );
    }
}

// =========================================================================
// 5. PropertyAttributes edge combinations
// =========================================================================

#[test]
fn deep_all_eight_attribute_combinations() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let mut current = root;

    let combos: Vec<PropertyAttributes> = vec![
        PropertyAttributes {
            writable: false,
            enumerable: false,
            configurable: false,
        },
        PropertyAttributes {
            writable: false,
            enumerable: false,
            configurable: true,
        },
        PropertyAttributes {
            writable: false,
            enumerable: true,
            configurable: false,
        },
        PropertyAttributes {
            writable: false,
            enumerable: true,
            configurable: true,
        },
        PropertyAttributes {
            writable: true,
            enumerable: false,
            configurable: false,
        },
        PropertyAttributes {
            writable: true,
            enumerable: false,
            configurable: true,
        },
        PropertyAttributes {
            writable: true,
            enumerable: true,
            configurable: false,
        },
        PropertyAttributes {
            writable: true,
            enumerable: true,
            configurable: true,
        },
    ];

    for (i, attrs) in combos.iter().enumerate() {
        let key = format!("prop_{i}");
        let outcome = algebra
            .apply_mutation(
                current,
                ShapeMutation::AddProperty {
                    key: key.clone(),
                    attributes: *attrs,
                },
            )
            .unwrap();
        let desc = outcome
            .shape
            .property_layout
            .iter()
            .find(|d| d.property_key == key)
            .unwrap();
        assert_eq!(desc.attributes, *attrs);
        current = outcome.shape.shape_id;
    }

    let final_shape = algebra.shape(current).unwrap();
    assert_eq!(final_shape.property_count(), 8);
}

#[test]
fn deep_attribute_constructors_produce_known_combos() {
    let default = PropertyAttributes::default();
    assert!(default.writable && default.enumerable && default.configurable);

    let frozen = PropertyAttributes::frozen();
    assert!(!frozen.writable && frozen.enumerable && !frozen.configurable);

    let sealed = PropertyAttributes::sealed();
    assert!(sealed.writable && sealed.enumerable && !sealed.configurable);

    let non_enum = PropertyAttributes::non_enumerable();
    assert!(non_enum.writable && !non_enum.enumerable && non_enum.configurable);
}

// =========================================================================
// 6. Prototype writes
// =========================================================================

#[test]
fn deep_prototype_write_same_no_invalidation() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    // Root has prototype_fingerprint = None, writing None is a no-op
    let outcome = algebra
        .apply_mutation(
            root,
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
fn deep_prototype_write_different_causes_invalidation() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("new-proto".into()),
            },
        )
        .unwrap();
    let assumptions = &outcome
        .transition
        .invalidation_receipt
        .invalidated_assumptions;
    assert!(assumptions.contains(&InvalidatedAssumptionKind::ShapeGuard));
    assert!(assumptions.contains(&InvalidatedAssumptionKind::PrototypeChain));
}

#[test]
fn deep_prototype_write_then_same_no_invalidation() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let with_proto = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-1".into()),
            },
        )
        .unwrap();

    // Write the same prototype again
    let same_again = algebra
        .apply_mutation(
            with_proto.shape.shape_id,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-1".into()),
            },
        )
        .unwrap();
    assert!(
        same_again
            .transition
            .invalidation_receipt
            .invalidated_assumptions
            .is_empty()
    );
}

#[test]
fn deep_prototype_write_chain_three_levels() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let p1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-1".into()),
            },
        )
        .unwrap();
    let p2 = algebra
        .apply_mutation(
            p1.shape.shape_id,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-2".into()),
            },
        )
        .unwrap();
    let p3 = algebra
        .apply_mutation(
            p2.shape.shape_id,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-3".into()),
            },
        )
        .unwrap();

    assert_eq!(p3.shape.prototype_fingerprint, Some("proto-3".to_string()));
    // All three write transitions created distinct shapes
    let mut shape_ids = BTreeSet::new();
    shape_ids.insert(root);
    shape_ids.insert(p1.shape.shape_id);
    shape_ids.insert(p2.shape.shape_id);
    shape_ids.insert(p3.shape.shape_id);
    assert_eq!(shape_ids.len(), 4);
}

// =========================================================================
// 7. WritePropertyCell
// =========================================================================

#[test]
fn deep_write_property_cell_preserves_shape_id() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let added = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "val".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let written = algebra
        .apply_mutation(
            added.shape.shape_id,
            ShapeMutation::WritePropertyCell { key: "val".into() },
        )
        .unwrap();

    assert_eq!(written.shape.shape_id, added.shape.shape_id);
    assert_eq!(written.shape.fingerprint, added.shape.fingerprint);
}

#[test]
fn deep_write_property_cell_invalidation_receipt() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let added = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "cell_prop".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let written = algebra
        .apply_mutation(
            added.shape.shape_id,
            ShapeMutation::WritePropertyCell {
                key: "cell_prop".into(),
            },
        )
        .unwrap();

    let receipt = &written.transition.invalidation_receipt;
    assert_eq!(receipt.invalidated_assumptions.len(), 1);
    assert_eq!(
        receipt.invalidated_assumptions[0],
        InvalidatedAssumptionKind::PropertyCell
    );
    assert_eq!(receipt.transition_kind, TransitionKind::PropertyCellWrite);
}

#[test]
fn deep_write_property_cell_multiple_times_cached() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let added = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "z".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let w1 = algebra
        .apply_mutation(
            added.shape.shape_id,
            ShapeMutation::WritePropertyCell { key: "z".into() },
        )
        .unwrap();
    let w2 = algebra
        .apply_mutation(
            added.shape.shape_id,
            ShapeMutation::WritePropertyCell { key: "z".into() },
        )
        .unwrap();

    assert_eq!(w1.shape.shape_id, w2.shape.shape_id);
    assert_eq!(w1.transition, w2.transition);
}

// =========================================================================
// 8. Invalidation receipt completeness
// =========================================================================

#[test]
fn deep_receipt_add_property_has_shape_guard_and_cell() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let assumptions = &outcome
        .transition
        .invalidation_receipt
        .invalidated_assumptions;
    assert!(assumptions.contains(&InvalidatedAssumptionKind::ShapeGuard));
    assert!(assumptions.contains(&InvalidatedAssumptionKind::PropertyCell));
    assert_eq!(assumptions.len(), 2);
}

#[test]
fn deep_receipt_delete_property_has_three_kinds() {
    let (mut algebra, ids) = build_chain(&["x"]);
    let with_x = ids[1];

    let outcome = algebra
        .apply_mutation(with_x, ShapeMutation::DeleteProperty { key: "x".into() })
        .unwrap();
    let assumptions = &outcome
        .transition
        .invalidation_receipt
        .invalidated_assumptions;
    assert!(assumptions.contains(&InvalidatedAssumptionKind::ShapeGuard));
    assert!(assumptions.contains(&InvalidatedAssumptionKind::PropertyCell));
    assert!(assumptions.contains(&InvalidatedAssumptionKind::PropertyDescriptor));
    assert_eq!(assumptions.len(), 3);
}

#[test]
fn deep_receipt_reconfigure_has_three_kinds() {
    let (mut algebra, ids) = build_chain(&["p"]);
    let with_p = ids[1];

    let outcome = algebra
        .apply_mutation(
            with_p,
            ShapeMutation::ReconfigureProperty {
                key: "p".into(),
                attributes: PropertyAttributes::frozen(),
            },
        )
        .unwrap();
    let assumptions = &outcome
        .transition
        .invalidation_receipt
        .invalidated_assumptions;
    assert!(assumptions.contains(&InvalidatedAssumptionKind::ShapeGuard));
    assert!(assumptions.contains(&InvalidatedAssumptionKind::PropertyCell));
    assert!(assumptions.contains(&InvalidatedAssumptionKind::PropertyDescriptor));
    assert_eq!(assumptions.len(), 3);
}

#[test]
fn deep_receipt_cell_write_only_cell() {
    let (mut algebra, ids) = build_chain(&["v"]);
    let with_v = ids[1];

    let outcome = algebra
        .apply_mutation(with_v, ShapeMutation::WritePropertyCell { key: "v".into() })
        .unwrap();
    let assumptions = &outcome
        .transition
        .invalidation_receipt
        .invalidated_assumptions;
    assert_eq!(assumptions.len(), 1);
    assert_eq!(assumptions[0], InvalidatedAssumptionKind::PropertyCell);
}

#[test]
fn deep_receipt_prototype_write_has_chain_and_guard() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("p".into()),
            },
        )
        .unwrap();
    let assumptions = &outcome
        .transition
        .invalidation_receipt
        .invalidated_assumptions;
    assert!(assumptions.contains(&InvalidatedAssumptionKind::ShapeGuard));
    assert!(assumptions.contains(&InvalidatedAssumptionKind::PrototypeChain));
    assert_eq!(assumptions.len(), 2);
}

#[test]
fn deep_receipt_has_correct_from_to_ids() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "q".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let receipt = &outcome.transition.invalidation_receipt;
    assert_eq!(receipt.from_shape_id, root);
    assert_eq!(receipt.to_shape_id, outcome.shape.shape_id);
    assert_eq!(receipt.property_key, Some("q".to_string()));
    assert_eq!(receipt.transition_kind, TransitionKind::AddProperty);
    assert!(!receipt.receipt_id.is_empty());
}

// =========================================================================
// 9. Manifest generation
// =========================================================================

#[test]
fn deep_manifest_shape_and_transition_counts() {
    let keys: Vec<&str> = (0..10)
        .map(|i| match i {
            0 => "a",
            1 => "b",
            2 => "c",
            3 => "d",
            4 => "e",
            5 => "f",
            6 => "g",
            7 => "h",
            8 => "i",
            _ => "j",
        })
        .collect();
    let (algebra, _ids) = build_chain(&keys);
    let manifest = algebra.manifest();

    assert_eq!(manifest.shapes.len(), 11); // root + 10
    assert_eq!(manifest.transitions.len(), 10);
    assert_eq!(manifest.schema_version, SHAPE_LATTICE_SCHEMA_VERSION);
    assert_eq!(manifest.component, COMPONENT);
}

#[test]
fn deep_manifest_contains_all_shape_ids() {
    let (algebra, ids) = build_chain(&["x", "y", "z"]);
    let manifest = algebra.manifest();
    let manifest_ids: BTreeSet<u64> = manifest.shapes.iter().map(|s| s.shape_id).collect();
    for id in &ids {
        assert!(manifest_ids.contains(id), "manifest missing shape id {id}");
    }
}

#[test]
fn deep_manifest_root_id_is_correct() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let _ = algebra.apply_mutation(
        root,
        ShapeMutation::AddProperty {
            key: "x".into(),
            attributes: PropertyAttributes::default(),
        },
    );
    let manifest = algebra.manifest();
    assert_eq!(manifest.root_shape_id, root);
}

#[test]
fn deep_manifest_after_branching_transitions() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    // Branch: root -> +a, root -> +b
    let _a = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let _b = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let manifest = algebra.manifest();
    assert_eq!(manifest.shapes.len(), 3); // root, +a, +b
    assert_eq!(manifest.transitions.len(), 2);
}

// =========================================================================
// 10. Fingerprint determinism
// =========================================================================

#[test]
fn deep_fingerprint_deterministic_same_layout() {
    let (a1, ids1) = build_chain(&["x", "y"]);
    let (a2, ids2) = build_chain(&["x", "y"]);

    let fp1 = &a1.shape(*ids1.last().unwrap()).unwrap().fingerprint;
    let fp2 = &a2.shape(*ids2.last().unwrap()).unwrap().fingerprint;
    assert_eq!(fp1, fp2);
}

#[test]
fn deep_fingerprint_different_layouts_differ() {
    let (a1, ids1) = build_chain(&["x", "y"]);
    let (a2, ids2) = build_chain(&["y", "x"]);

    let fp1 = &a1.shape(*ids1.last().unwrap()).unwrap().fingerprint;
    let fp2 = &a2.shape(*ids2.last().unwrap()).unwrap().fingerprint;
    assert_ne!(fp1, fp2);
}

#[test]
fn deep_fingerprint_attribute_difference_changes_fingerprint() {
    let mut a1 = ShapeTransitionAlgebra::new();
    let r1 = a1.root_shape_id();
    let o1 = a1
        .apply_mutation(
            r1,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let mut a2 = ShapeTransitionAlgebra::new();
    let r2 = a2.root_shape_id();
    let o2 = a2
        .apply_mutation(
            r2,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::frozen(),
            },
        )
        .unwrap();

    assert_ne!(o1.shape.fingerprint, o2.shape.fingerprint);
}

#[test]
fn deep_fingerprint_root_shapes_identical_across_instances() {
    let a1 = ShapeTransitionAlgebra::new();
    let a2 = ShapeTransitionAlgebra::new();
    let fp1 = &a1.shape(a1.root_shape_id()).unwrap().fingerprint;
    let fp2 = &a2.shape(a2.root_shape_id()).unwrap().fingerprint;
    assert_eq!(fp1, fp2);
}

// =========================================================================
// 11. Slot index correctness
// =========================================================================

#[test]
fn deep_slot_indices_sequential_after_adds() {
    let (algebra, ids) = build_chain(&["a", "b", "c", "d"]);
    let shape = algebra.shape(*ids.last().unwrap()).unwrap();
    for (i, key) in ["a", "b", "c", "d"].iter().enumerate() {
        assert_eq!(shape.slot_for(key), Some(i));
    }
}

#[test]
fn deep_slot_indices_renumber_after_delete_first() {
    let (mut algebra, ids) = build_chain(&["a", "b", "c"]);
    let shape_abc = ids[3];

    let outcome = algebra
        .apply_mutation(shape_abc, ShapeMutation::DeleteProperty { key: "a".into() })
        .unwrap();

    assert_eq!(outcome.shape.slot_for("b"), Some(0));
    assert_eq!(outcome.shape.slot_for("c"), Some(1));
    assert_eq!(outcome.shape.slot_for("a"), None);
}

#[test]
fn deep_slot_indices_renumber_after_delete_last() {
    let (mut algebra, ids) = build_chain(&["a", "b", "c"]);
    let shape_abc = ids[3];

    let outcome = algebra
        .apply_mutation(shape_abc, ShapeMutation::DeleteProperty { key: "c".into() })
        .unwrap();

    assert_eq!(outcome.shape.slot_for("a"), Some(0));
    assert_eq!(outcome.shape.slot_for("b"), Some(1));
    assert_eq!(outcome.shape.slot_for("c"), None);
}

#[test]
fn deep_slot_indices_preserved_after_reconfigure() {
    let (mut algebra, ids) = build_chain(&["a", "b", "c"]);
    let shape_abc = ids[3];

    let outcome = algebra
        .apply_mutation(
            shape_abc,
            ShapeMutation::ReconfigureProperty {
                key: "b".into(),
                attributes: PropertyAttributes::frozen(),
            },
        )
        .unwrap();

    // Reconfigure preserves slot indices
    assert_eq!(outcome.shape.slot_for("a"), Some(0));
    assert_eq!(outcome.shape.slot_for("b"), Some(1));
    assert_eq!(outcome.shape.slot_for("c"), Some(2));
}

// =========================================================================
// 12. Large shape sequences (stress test)
// =========================================================================

#[test]
fn deep_large_sequence_fifty_properties() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let mut current = algebra.root_shape_id();

    for i in 0..50 {
        let key = format!("prop_{i:03}");
        let outcome = algebra
            .apply_mutation(
                current,
                ShapeMutation::AddProperty {
                    key: key.clone(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        assert_eq!(outcome.shape.property_count(), i + 1);
        assert_eq!(outcome.shape.slot_for(&key), Some(i));
        current = outcome.shape.shape_id;
    }

    let final_shape = algebra.shape(current).unwrap();
    assert_eq!(final_shape.property_count(), 50);
    assert_eq!(algebra.shape_count(), 51); // root + 50
    assert_eq!(algebra.transition_count(), 50);
}

#[test]
fn deep_large_sequence_add_then_delete_all() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let mut current = root;

    let prop_count = 20;
    for i in 0..prop_count {
        let outcome = algebra
            .apply_mutation(
                current,
                ShapeMutation::AddProperty {
                    key: format!("p{i}"),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        current = outcome.shape.shape_id;
    }

    // Delete all in reverse order
    for i in (0..prop_count).rev() {
        let outcome = algebra
            .apply_mutation(
                current,
                ShapeMutation::DeleteProperty {
                    key: format!("p{i}"),
                },
            )
            .unwrap();
        current = outcome.shape.shape_id;
    }

    // After deleting all, should be back at root
    assert_eq!(current, root);
    assert_eq!(algebra.shape(current).unwrap().property_count(), 0);
}

#[test]
fn deep_large_sequence_branching_fan_out() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    // Create 30 branches from root, each adding a unique property
    for i in 0..30 {
        let _outcome = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: format!("branch_{i}"),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
    }

    assert_eq!(algebra.shape_count(), 31); // root + 30
    assert_eq!(algebra.transition_count(), 30);
    let transitions = algebra.transitions_from(root);
    assert_eq!(transitions.len(), 30);
}

// =========================================================================
// 13. Serde round-trips
// =========================================================================

#[test]
fn deep_serde_property_layout_descriptor() {
    let desc = PropertyLayoutDescriptor {
        property_key: "test_key".into(),
        slot_index: 42,
        attributes: PropertyAttributes::sealed(),
    };
    let json = serde_json::to_string(&desc).unwrap();
    let back: PropertyLayoutDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

#[test]
fn deep_serde_shape_descriptor() {
    let desc = ShapeDescriptor {
        shape_id: 123456,
        fingerprint: "abc123".into(),
        prototype_fingerprint: Some("proto-xyz".into()),
        property_layout: vec![
            PropertyLayoutDescriptor {
                property_key: "a".into(),
                slot_index: 0,
                attributes: PropertyAttributes::default(),
            },
            PropertyLayoutDescriptor {
                property_key: "b".into(),
                slot_index: 1,
                attributes: PropertyAttributes::frozen(),
            },
        ],
    };
    let json = serde_json::to_string(&desc).unwrap();
    let back: ShapeDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

#[test]
fn deep_serde_shape_transition_from_algebra() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "serde_test".into(),
                attributes: PropertyAttributes::non_enumerable(),
            },
        )
        .unwrap();

    let json = serde_json::to_string(&outcome.transition).unwrap();
    let back: ShapeTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome.transition, back);
}

#[test]
fn deep_serde_shape_mutation_outcome() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "out".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let json = serde_json::to_string(&outcome).unwrap();
    let back: ShapeMutationOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

#[test]
fn deep_serde_lineage() {
    let (algebra, ids) = build_chain(&["x", "y", "z"]);
    let lineage = algebra.lineage(*ids.last().unwrap()).unwrap();

    let json = serde_json::to_string(&lineage).unwrap();
    let back: ShapeLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage, back);
}

#[test]
fn deep_serde_convergence_witness() {
    let witness = ConvergenceWitness {
        target_shape_id: 100,
        source_shape_ids: vec![1, 2, 3],
    };
    let json = serde_json::to_string(&witness).unwrap();
    let back: ConvergenceWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, back);
}

#[test]
fn deep_serde_deopt_event() {
    let event = DeoptEvent {
        trigger: DeoptTrigger::PrototypeMutation,
        from_shape_id: 10,
        to_shape_id: 20,
        property_key: Some("x".into()),
        invalidated_assumption_count: 2,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: DeoptEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn deep_serde_deopt_trigger_all_variants() {
    let triggers = [
        DeoptTrigger::ShapeTransition,
        DeoptTrigger::CellInvalidation,
        DeoptTrigger::PrototypeMutation,
        DeoptTrigger::DescriptorChange,
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let back: DeoptTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn deep_serde_shape_lattice_manifest() {
    let (algebra, _) = build_chain(&["a", "b"]);
    let manifest = algebra.manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ShapeLatticeManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn deep_serde_inline_cache_summary() {
    use frankenengine_engine::shape_transition_algebra::InlineCacheSummary;
    let summary = InlineCacheSummary {
        entry_count: 5,
        monomorphic_count: 3,
        polymorphic_count: 1,
        megamorphic_count: 1,
        uninitialised_count: 0,
        total_hits: 100,
        total_misses: 10,
        hit_rate_millionths: 909_090,
        witness_count: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: InlineCacheSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// =========================================================================
// 14. Display / Error formatting
// =========================================================================

#[test]
fn deep_display_shape_algebra_error_unknown_shape() {
    let err = ShapeAlgebraError::UnknownShape { shape_id: 42 };
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("unknown shape"));
}

#[test]
fn deep_display_shape_algebra_error_property_already_exists() {
    let err = ShapeAlgebraError::PropertyAlreadyExists {
        shape_id: 7,
        key: "foo".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("foo"));
    assert!(msg.contains("already exists"));
    assert!(msg.contains("7"));
}

#[test]
fn deep_display_shape_algebra_error_missing_property() {
    let err = ShapeAlgebraError::MissingProperty {
        shape_id: 99,
        key: "bar".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("bar"));
    assert!(msg.contains("not present"));
    assert!(msg.contains("99"));
}

#[test]
fn deep_display_error_is_std_error() {
    let err = ShapeAlgebraError::UnknownShape { shape_id: 1 };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn deep_display_all_error_variants_unique() {
    let errors = [
        ShapeAlgebraError::UnknownShape { shape_id: 1 },
        ShapeAlgebraError::PropertyAlreadyExists {
            shape_id: 2,
            key: "x".into(),
        },
        ShapeAlgebraError::MissingProperty {
            shape_id: 3,
            key: "y".into(),
        },
    ];
    let messages: BTreeSet<String> = errors.iter().map(|e| format!("{e}")).collect();
    assert_eq!(messages.len(), 3);
}

// =========================================================================
// 15. PropertyCellTracker extended lifecycle
// =========================================================================

#[test]
fn deep_tracker_full_lifecycle_with_dependents() {
    let mut tracker = PropertyCellTracker::new(100, "counter");
    assert_eq!(tracker.state, PropertyCellState::Uninitialised);
    assert_eq!(tracker.write_epoch, 0);
    assert_eq!(tracker.dependent_ic_count, 0);

    // Add dependents
    tracker.add_dependent();
    tracker.add_dependent();
    tracker.add_dependent();
    assert_eq!(tracker.dependent_ic_count, 3);

    // Write transitions: Uninitialised -> Constant -> Stable
    assert!(!tracker.record_write(false));
    assert_eq!(tracker.state, PropertyCellState::Constant);
    assert_eq!(tracker.write_epoch, 1);

    assert!(!tracker.record_write(false));
    assert_eq!(tracker.state, PropertyCellState::Stable);
    assert_eq!(tracker.write_epoch, 2);

    // Many same-kind writes stay Stable
    for _ in 0..50 {
        assert!(!tracker.record_write(false));
    }
    assert_eq!(tracker.state, PropertyCellState::Stable);
    assert_eq!(tracker.write_epoch, 52);

    // Kind change: Stable -> Invalidated (returns true)
    assert!(tracker.record_write(true));
    assert_eq!(tracker.state, PropertyCellState::Invalidated);
    assert_eq!(tracker.write_epoch, 53);

    // Further writes stay Invalidated, never re-trigger
    assert!(!tracker.record_write(false));
    assert!(!tracker.record_write(true));
    assert_eq!(tracker.state, PropertyCellState::Invalidated);
    assert_eq!(tracker.write_epoch, 55);
}

#[test]
fn deep_tracker_remove_dependent_saturates_at_zero() {
    let mut tracker = PropertyCellTracker::new(1, "p");
    tracker.remove_dependent();
    assert_eq!(tracker.dependent_ic_count, 0);
    tracker.add_dependent();
    tracker.remove_dependent();
    tracker.remove_dependent();
    assert_eq!(tracker.dependent_ic_count, 0);
}

#[test]
fn deep_tracker_display_format() {
    let mut tracker = PropertyCellTracker::new(42, "value");
    tracker.record_write(false); // Constant
    tracker.add_dependent();
    tracker.add_dependent();
    let display = format!("{tracker}");
    assert!(display.contains("42"));
    assert!(display.contains("value"));
    assert!(display.contains("constant"));
}

#[test]
fn deep_tracker_serde_roundtrip_with_state() {
    let mut tracker = PropertyCellTracker::new(10, "prop");
    tracker.record_write(false);
    tracker.record_write(false);
    tracker.add_dependent();
    tracker.add_dependent();
    tracker.add_dependent();

    let json = serde_json::to_string(&tracker).unwrap();
    let back: PropertyCellTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(tracker, back);
    assert_eq!(back.state, PropertyCellState::Stable);
    assert_eq!(back.write_epoch, 2);
    assert_eq!(back.dependent_ic_count, 3);
}

// =========================================================================
// 16. Bundle report / emission
// =========================================================================

#[test]
fn deep_bundle_serde_roundtrip_with_events() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "bundled".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let event = ShapeTraceEvent {
        trace_id: "trace-deep".into(),
        component: COMPONENT.into(),
        step: 0,
        object_id: 1,
        from_shape_id: root,
        to_shape_id: outcome.shape.shape_id,
        to_shape_fingerprint: outcome.shape.fingerprint.clone(),
        transition_kind: TransitionKind::AddProperty,
        property_key: Some("bundled".into()),
        invalidation_receipt: outcome.transition.invalidation_receipt.clone(),
        property_cell_revision_before: None,
        property_cell_revision_after: Some(1),
    };

    let bundle = ShapeLatticeBundle {
        manifest: algebra.manifest(),
        trace_events: vec![event],
        trace_ids: vec!["t1".into()],
        decision_ids: vec!["d1".into()],
        policy_ids: vec!["p1".into()],
        commands: vec!["cmd-1".into(), "cmd-2".into()],
    };

    let json = serde_json::to_string(&bundle).unwrap();
    let back: ShapeLatticeBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn deep_bundle_emission_creates_all_files() {
    let dir = std::env::temp_dir().join(format!(
        "shape-algebra-deep-emit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let o1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let o2 = algebra
        .apply_mutation(
            o1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();

    let events: Vec<ShapeTraceEvent> = vec![o1, o2]
        .iter()
        .enumerate()
        .map(|(i, o)| ShapeTraceEvent {
            trace_id: format!("trace-{i}"),
            component: COMPONENT.into(),
            step: i as u64,
            object_id: 1,
            from_shape_id: o.transition.from_shape_id,
            to_shape_id: o.transition.to_shape_id,
            to_shape_fingerprint: o.shape.fingerprint.clone(),
            transition_kind: o.transition.transition_kind.clone(),
            property_key: o.transition.property_key.clone(),
            invalidation_receipt: o.transition.invalidation_receipt.clone(),
            property_cell_revision_before: None,
            property_cell_revision_after: None,
        })
        .collect();

    let bundle = ShapeLatticeBundle {
        manifest: algebra.manifest(),
        trace_events: events,
        trace_ids: vec!["trace-0".into(), "trace-1".into()],
        decision_ids: vec!["dec-0".into()],
        policy_ids: vec!["pol-0".into()],
        commands: vec!["test".into()],
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
    assert_eq!(manifest.shapes.len(), 3);
    assert_eq!(manifest.transitions.len(), 2);

    // Verify run manifest
    let run_bytes = std::fs::read(&report.run_manifest_path).unwrap();
    let run_manifest: ShapeLatticeRunManifest = serde_json::from_slice(&run_bytes).unwrap();
    assert_eq!(run_manifest.shape_count, 3);
    assert_eq!(run_manifest.transition_count, 2);
    assert_eq!(run_manifest.receipt_count, 2);

    // Verify trace ids
    let trace_bytes = std::fs::read(&report.trace_ids_path).unwrap();
    let trace_ids: ShapeLatticeTraceIds = serde_json::from_slice(&trace_bytes).unwrap();
    assert_eq!(trace_ids.trace_ids.len(), 2);

    // Verify events are JSONL (newline-delimited)
    let events_str = std::fs::read_to_string(&report.events_path).unwrap();
    let event_lines: Vec<&str> = events_str.trim().lines().collect();
    assert_eq!(event_lines.len(), 2);
    for line in &event_lines {
        let _event: ShapeTraceEvent = serde_json::from_str(line).unwrap();
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn deep_bundle_emission_empty_events() {
    let dir = std::env::temp_dir().join(format!(
        "shape-algebra-deep-empty-emit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let algebra = ShapeTransitionAlgebra::new();
    let bundle = ShapeLatticeBundle {
        manifest: algebra.manifest(),
        trace_events: Vec::new(),
        trace_ids: Vec::new(),
        decision_ids: Vec::new(),
        policy_ids: Vec::new(),
        commands: Vec::new(),
    };

    let report = emit_shape_lattice_bundle(&dir, &bundle).unwrap();
    assert!(report.events_path.exists());

    // Empty events file should be empty string
    let events_str = std::fs::read_to_string(&report.events_path).unwrap();
    assert!(events_str.is_empty());

    let commands_str = std::fs::read_to_string(&report.commands_path).unwrap();
    assert!(commands_str.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn deep_bundle_report_serde_roundtrip() {
    let report = ShapeLatticeBundleReport {
        artifact_dir: "/tmp/test".into(),
        shape_lattice_manifest_path: "/tmp/test/manifest.json".into(),
        run_manifest_path: "/tmp/test/run_manifest.json".into(),
        events_path: "/tmp/test/events.jsonl".into(),
        commands_path: "/tmp/test/commands.txt".into(),
        trace_ids_path: "/tmp/test/trace_ids.json".into(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ShapeLatticeBundleReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// =========================================================================
// 17. Lineage and convergence
// =========================================================================

#[test]
fn deep_lineage_depth_matches_chain_length() {
    let (algebra, ids) = build_chain(&["a", "b", "c", "d", "e"]);
    let lineage = algebra.lineage(*ids.last().unwrap()).unwrap();
    assert_eq!(lineage.depth, 5);
    assert_eq!(lineage.steps.len(), 5);
    assert_eq!(lineage.leaf_shape_id, *ids.last().unwrap());
}

#[test]
fn deep_lineage_root_has_zero_depth() {
    let algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let lineage = algebra.lineage(root).unwrap();
    assert_eq!(lineage.depth, 0);
    assert!(lineage.steps.is_empty());
}

#[test]
fn deep_lineage_step_property_keys_match() {
    let (algebra, ids) = build_chain(&["x", "y", "z"]);
    let lineage = algebra.lineage(ids[3]).unwrap();
    assert_eq!(lineage.steps.len(), 3);
    assert_eq!(lineage.steps[0].property_key, Some("x".to_string()));
    assert_eq!(lineage.steps[1].property_key, Some("y".to_string()));
    assert_eq!(lineage.steps[2].property_key, Some("z".to_string()));
}

// =========================================================================
// 18. classify_deopt
// =========================================================================

#[test]
fn deep_classify_deopt_add_property() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let add_outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let transitions = algebra.transitions_from(root);
    let deopt = algebra.classify_deopt(transitions[0]);
    assert_eq!(deopt.trigger, DeoptTrigger::ShapeTransition);
    assert_eq!(deopt.from_shape_id, root);
    assert_eq!(deopt.to_shape_id, add_outcome.shape.shape_id);
    assert_eq!(deopt.property_key, Some("x".to_string()));
}

#[test]
fn deep_classify_deopt_reconfigure() {
    let (mut algebra, ids) = build_chain(&["p"]);
    let reconf_outcome = algebra
        .apply_mutation(
            ids[1],
            ShapeMutation::ReconfigureProperty {
                key: "p".into(),
                attributes: PropertyAttributes::sealed(),
            },
        )
        .unwrap();
    let transitions = algebra.transitions_from(ids[1]);
    let reconf_t = transitions
        .iter()
        .find(|t| t.to_shape_id == reconf_outcome.shape.shape_id)
        .unwrap();
    let deopt = algebra.classify_deopt(reconf_t);
    assert_eq!(deopt.trigger, DeoptTrigger::DescriptorChange);
}

#[test]
fn deep_classify_deopt_cell_write() {
    let (mut algebra, ids) = build_chain(&["v"]);
    let _cell_outcome = algebra
        .apply_mutation(ids[1], ShapeMutation::WritePropertyCell { key: "v".into() })
        .unwrap();
    let transitions = algebra.transitions_from(ids[1]);
    let cell_t = transitions
        .iter()
        .find(|t| t.transition_kind == TransitionKind::PropertyCellWrite)
        .unwrap();
    let deopt = algebra.classify_deopt(cell_t);
    assert_eq!(deopt.trigger, DeoptTrigger::CellInvalidation);
    assert_eq!(deopt.invalidated_assumption_count, 1);
}

#[test]
fn deep_classify_deopt_prototype_mutation() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    let _proto_outcome = algebra
        .apply_mutation(
            root,
            ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("new-proto".into()),
            },
        )
        .unwrap();
    let transitions = algebra.transitions_from(root);
    let proto_t = transitions
        .iter()
        .find(|t| t.transition_kind == TransitionKind::PrototypeWrite)
        .unwrap();
    let deopt = algebra.classify_deopt(proto_t);
    assert_eq!(deopt.trigger, DeoptTrigger::PrototypeMutation);
    assert_eq!(deopt.invalidated_assumption_count, 2);
}

// =========================================================================
// 19. PropertyCellTable extended
// =========================================================================

#[test]
fn deep_cell_table_multi_property_multi_shape() {
    let mut table = PropertyCellTable::new();

    // Write to 3 shapes, 2 properties each
    for shape in 0..3_u64 {
        table.record_write(shape, "x", false);
        table.record_write(shape, "y", false);
    }
    assert_eq!(table.cell_count(), 6);
    assert_eq!(table.total_invalidations(), 0);

    // Invalidate shape 1
    let count = table.invalidate_shape(1);
    assert_eq!(count, 2);
    assert_eq!(table.total_invalidations(), 2);

    // Shapes 0 and 2 unaffected
    for shape in [0_u64, 2] {
        assert_eq!(
            table.get(shape, "x").unwrap().state,
            PropertyCellState::Constant
        );
        assert_eq!(
            table.get(shape, "y").unwrap().state,
            PropertyCellState::Constant
        );
    }
}

#[test]
fn deep_cell_table_nonexistent_shape_invalidation_returns_zero() {
    let mut table = PropertyCellTable::new();
    table.record_write(1, "x", false);
    let count = table.invalidate_shape(999);
    assert_eq!(count, 0);
    assert_eq!(table.total_invalidations(), 0);
}

// =========================================================================
// 20. Determinism across multiple runs
// =========================================================================

#[test]
fn deep_determinism_same_operations_same_results() {
    let run = || {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let o1 = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let o2 = algebra
            .apply_mutation(
                o1.shape.shape_id,
                ShapeMutation::AddProperty {
                    key: "b".into(),
                    attributes: PropertyAttributes::frozen(),
                },
            )
            .unwrap();
        let o3 = algebra
            .apply_mutation(
                o2.shape.shape_id,
                ShapeMutation::ReconfigureProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::sealed(),
                },
            )
            .unwrap();
        (
            algebra.manifest(),
            o3.shape.shape_id,
            o3.shape.fingerprint.clone(),
        )
    };

    let (m1, id1, fp1) = run();
    let (m2, id2, fp2) = run();
    assert_eq!(m1, m2);
    assert_eq!(id1, id2);
    assert_eq!(fp1, fp2);
}

// =========================================================================
// 21. all_property_keys / shape_ids
// =========================================================================

#[test]
fn deep_all_property_keys_accumulates() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();

    assert!(algebra.all_property_keys().is_empty());

    let o1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    assert!(algebra.all_property_keys().contains("x"));

    let _o2 = algebra
        .apply_mutation(
            o1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "y".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    let keys = algebra.all_property_keys();
    assert!(keys.contains("x"));
    assert!(keys.contains("y"));
    assert_eq!(keys.len(), 2);
}

#[test]
fn deep_shape_ids_grows_with_mutations() {
    let mut algebra = ShapeTransitionAlgebra::new();
    let root = algebra.root_shape_id();
    assert_eq!(algebra.shape_ids().len(), 1);

    let o1 = algebra
        .apply_mutation(
            root,
            ShapeMutation::AddProperty {
                key: "a".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    assert_eq!(algebra.shape_ids().len(), 2);

    let _o2 = algebra
        .apply_mutation(
            o1.shape.shape_id,
            ShapeMutation::AddProperty {
                key: "b".into(),
                attributes: PropertyAttributes::default(),
            },
        )
        .unwrap();
    assert_eq!(algebra.shape_ids().len(), 3);
}
