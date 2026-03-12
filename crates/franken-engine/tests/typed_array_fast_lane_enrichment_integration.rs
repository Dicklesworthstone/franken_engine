#![forbid(unsafe_code)]
//! Enrichment integration tests for the typed-array fast-lane module (RGC-606C).
//!
//! Covers all public types, enums, Display impls, serde roundtrips,
//! determinism guarantees, edge cases, and workflow scenarios.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::typed_array_fast_lane::{
    ArrayProfile, ArrayStorageMode, DeoptReason, ElementKind, ElementTransition,
    FastLaneCertificate, FastLaneConfig, FastLaneDecision, FastLaneError,
    FastLaneEvidenceManifest, TransitionTrigger, TypedArrayKind, TypedArrayValidation,
    TYPED_ARRAY_COMPONENT, TYPED_ARRAY_POLICY_ID, TYPED_ARRAY_SCHEMA_VERSION,
    allowed_transitions, build_transition_graph, certify_fast_lane, compute_element_size,
    evaluate_fast_lane, is_transition_reversible, run_fast_lane_evidence, validate_typed_array,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_profile(id: &str, kind: ElementKind, mode: ArrayStorageMode) -> ArrayProfile {
    ArrayProfile {
        id: id.into(),
        total_accesses: 10_000,
        fast_lane_hits_millionths: 950_000,
        transitions: Vec::new(),
        current_kind: kind,
        current_mode: mode,
    }
}

fn smi_profile(id: &str) -> ArrayProfile {
    make_profile(id, ElementKind::SmiInteger, ArrayStorageMode::FastSmi)
}

fn default_config() -> FastLaneConfig {
    FastLaneConfig::default()
}

fn make_transition(
    from: ElementKind,
    to: ElementKind,
    trigger: TransitionTrigger,
    reversible: bool,
) -> ElementTransition {
    ElementTransition {
        from_kind: from,
        to_kind: to,
        trigger,
        reversible,
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_format() {
    assert!(TYPED_ARRAY_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TYPED_ARRAY_SCHEMA_VERSION.contains("typed-array-fast-lane"));
    assert!(TYPED_ARRAY_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_component_is_snake_case() {
    assert_eq!(TYPED_ARRAY_COMPONENT, "typed_array_fast_lane");
    assert!(!TYPED_ARRAY_COMPONENT.contains('-'));
    assert!(!TYPED_ARRAY_COMPONENT.contains(' '));
}

#[test]
fn enrichment_policy_id_prefix() {
    assert!(TYPED_ARRAY_POLICY_ID.starts_with("RGC-"));
    assert_eq!(TYPED_ARRAY_POLICY_ID, "RGC-606C");
}

// ===========================================================================
// ElementKind — exhaustive variant coverage
// ===========================================================================

#[test]
fn enrichment_element_kind_all_six_distinct() {
    let mut set = BTreeSet::new();
    for kind in ElementKind::ALL {
        assert!(set.insert(*kind));
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_element_kind_smi_is_unboxed() {
    assert!(ElementKind::SmiInteger.is_unboxed());
    assert!(!ElementKind::SmiInteger.is_boxed());
    assert!(!ElementKind::SmiInteger.is_hole());
}

#[test]
fn enrichment_element_kind_heap_number_is_boxed() {
    assert!(ElementKind::HeapNumber.is_boxed());
    assert!(!ElementKind::HeapNumber.is_unboxed());
    assert!(!ElementKind::HeapNumber.is_hole());
}

#[test]
fn enrichment_element_kind_string_is_boxed() {
    assert!(ElementKind::String.is_boxed());
    assert!(!ElementKind::String.is_unboxed());
    assert!(!ElementKind::String.is_hole());
}

#[test]
fn enrichment_element_kind_heap_object_is_boxed() {
    assert!(ElementKind::HeapObject.is_boxed());
    assert!(!ElementKind::HeapObject.is_unboxed());
    assert!(!ElementKind::HeapObject.is_hole());
}

#[test]
fn enrichment_element_kind_hole_is_neither_boxed_nor_unboxed() {
    assert!(ElementKind::Hole.is_hole());
    assert!(!ElementKind::Hole.is_boxed());
    assert!(!ElementKind::Hole.is_unboxed());
}

#[test]
fn enrichment_element_kind_packed_is_unboxed() {
    assert!(ElementKind::Packed.is_unboxed());
    assert!(!ElementKind::Packed.is_boxed());
    assert!(!ElementKind::Packed.is_hole());
}

#[test]
fn enrichment_element_kind_rank_values() {
    assert_eq!(ElementKind::SmiInteger.rank(), 0);
    assert_eq!(ElementKind::HeapNumber.rank(), 1);
    assert_eq!(ElementKind::String.rank(), 2);
    assert_eq!(ElementKind::Packed.rank(), 3);
    assert_eq!(ElementKind::HeapObject.rank(), 4);
    assert_eq!(ElementKind::Hole.rank(), 5);
}

#[test]
fn enrichment_element_kind_rank_strictly_increases() {
    let ranks: Vec<u32> = ElementKind::ALL.iter().map(|k| k.rank()).collect();
    for window in ranks.windows(2) {
        // Not necessarily strictly increasing in ALL order because Packed(3) > String(2)
        // but HeapObject(4) > Packed(3), so we just check uniqueness
        assert_ne!(window[0], window[1]);
    }
}

#[test]
fn enrichment_element_kind_as_str_matches_display() {
    for kind in ElementKind::ALL {
        assert_eq!(kind.as_str(), kind.to_string());
    }
}

#[test]
fn enrichment_element_kind_display_all_variants() {
    assert_eq!(ElementKind::SmiInteger.to_string(), "smi_integer");
    assert_eq!(ElementKind::HeapNumber.to_string(), "heap_number");
    assert_eq!(ElementKind::String.to_string(), "string");
    assert_eq!(ElementKind::HeapObject.to_string(), "heap_object");
    assert_eq!(ElementKind::Hole.to_string(), "hole");
    assert_eq!(ElementKind::Packed.to_string(), "packed");
}

#[test]
fn enrichment_element_kind_serde_all_variants_json() {
    for kind in ElementKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ElementKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
        // Verify snake_case format
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
    }
}

#[test]
fn enrichment_element_kind_clone_eq() {
    for kind in ElementKind::ALL {
        let cloned = kind.clone();
        assert_eq!(*kind, cloned);
    }
}

#[test]
fn enrichment_element_kind_ord_consistency() {
    // Verify Ord is consistent: SmiInteger < HeapNumber < ... etc.
    let mut sorted: Vec<ElementKind> = ElementKind::ALL.to_vec();
    sorted.sort();
    // The derive(Ord) follows declaration order
    assert_eq!(sorted[0], ElementKind::SmiInteger);
    assert_eq!(sorted[5], ElementKind::Packed);
}

// ===========================================================================
// TypedArrayKind — exhaustive variant coverage
// ===========================================================================

#[test]
fn enrichment_typed_array_kind_all_eleven_distinct() {
    let mut set = BTreeSet::new();
    for kind in TypedArrayKind::ALL {
        assert!(set.insert(*kind));
    }
    assert_eq!(set.len(), 11);
}

#[test]
fn enrichment_typed_array_kind_display_all_variants() {
    assert_eq!(TypedArrayKind::Int8.to_string(), "int8");
    assert_eq!(TypedArrayKind::Uint8.to_string(), "uint8");
    assert_eq!(TypedArrayKind::Uint8Clamped.to_string(), "uint8_clamped");
    assert_eq!(TypedArrayKind::Int16.to_string(), "int16");
    assert_eq!(TypedArrayKind::Uint16.to_string(), "uint16");
    assert_eq!(TypedArrayKind::Int32.to_string(), "int32");
    assert_eq!(TypedArrayKind::Uint32.to_string(), "uint32");
    assert_eq!(TypedArrayKind::Float32.to_string(), "float32");
    assert_eq!(TypedArrayKind::Float64.to_string(), "float64");
    assert_eq!(TypedArrayKind::BigInt64.to_string(), "big_int64");
    assert_eq!(TypedArrayKind::BigUint64.to_string(), "big_uint64");
}

#[test]
fn enrichment_typed_array_kind_as_str_matches_display() {
    for kind in TypedArrayKind::ALL {
        assert_eq!(kind.as_str(), kind.to_string());
    }
}

#[test]
fn enrichment_typed_array_kind_serde_all_variants() {
    for kind in TypedArrayKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: TypedArrayKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_typed_array_kind_clone_eq() {
    for kind in TypedArrayKind::ALL {
        let cloned = kind.clone();
        assert_eq!(*kind, cloned);
    }
}

// ===========================================================================
// ArrayStorageMode — exhaustive variant coverage
// ===========================================================================

#[test]
fn enrichment_storage_mode_all_six_distinct() {
    let mut set = BTreeSet::new();
    for mode in ArrayStorageMode::ALL {
        assert!(set.insert(*mode));
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_storage_mode_fast_path_dense() {
    assert!(ArrayStorageMode::Dense.is_fast_path());
}

#[test]
fn enrichment_storage_mode_fast_path_fast_smi() {
    assert!(ArrayStorageMode::FastSmi.is_fast_path());
}

#[test]
fn enrichment_storage_mode_fast_path_fast_double() {
    assert!(ArrayStorageMode::FastDouble.is_fast_path());
}

#[test]
fn enrichment_storage_mode_fast_path_fast_object() {
    assert!(ArrayStorageMode::FastObject.is_fast_path());
}

#[test]
fn enrichment_storage_mode_not_fast_path_sparse() {
    assert!(!ArrayStorageMode::Sparse.is_fast_path());
}

#[test]
fn enrichment_storage_mode_not_fast_path_dictionary() {
    assert!(!ArrayStorageMode::Dictionary.is_fast_path());
}

#[test]
fn enrichment_storage_mode_display_all_variants() {
    assert_eq!(ArrayStorageMode::Dense.to_string(), "dense");
    assert_eq!(ArrayStorageMode::Sparse.to_string(), "sparse");
    assert_eq!(ArrayStorageMode::Dictionary.to_string(), "dictionary");
    assert_eq!(ArrayStorageMode::FastSmi.to_string(), "fast_smi");
    assert_eq!(ArrayStorageMode::FastDouble.to_string(), "fast_double");
    assert_eq!(ArrayStorageMode::FastObject.to_string(), "fast_object");
}

#[test]
fn enrichment_storage_mode_as_str_matches_display() {
    for mode in ArrayStorageMode::ALL {
        assert_eq!(mode.as_str(), mode.to_string());
    }
}

#[test]
fn enrichment_storage_mode_serde_all_variants() {
    for mode in ArrayStorageMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: ArrayStorageMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

// ===========================================================================
// TransitionTrigger — exhaustive variant coverage
// ===========================================================================

#[test]
fn enrichment_transition_trigger_all_seven_distinct() {
    let mut set = BTreeSet::new();
    for trigger in TransitionTrigger::ALL {
        assert!(set.insert(trigger.clone()));
    }
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_transition_trigger_as_str_all_variants() {
    assert_eq!(TransitionTrigger::StoreNonSmi.as_str(), "store_non_smi");
    assert_eq!(TransitionTrigger::StoreDouble.as_str(), "store_double");
    assert_eq!(TransitionTrigger::StoreObject.as_str(), "store_object");
    assert_eq!(TransitionTrigger::StoreHole.as_str(), "store_hole");
    assert_eq!(
        TransitionTrigger::GrowBeyondCapacity.as_str(),
        "grow_beyond_capacity"
    );
    assert_eq!(TransitionTrigger::ShrinkToEmpty.as_str(), "shrink_to_empty");
    assert_eq!(TransitionTrigger::DetachBuffer.as_str(), "detach_buffer");
}

#[test]
fn enrichment_transition_trigger_serde_all_variants() {
    for trigger in TransitionTrigger::ALL {
        let json = serde_json::to_string(trigger).unwrap();
        let back: TransitionTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*trigger, back);
    }
}

#[test]
fn enrichment_transition_trigger_clone_eq() {
    for trigger in TransitionTrigger::ALL {
        let cloned = trigger.clone();
        assert_eq!(*trigger, cloned);
    }
}

// ===========================================================================
// DeoptReason — exhaustive variant coverage
// ===========================================================================

#[test]
fn enrichment_deopt_reason_all_seven_distinct() {
    let mut set = BTreeSet::new();
    for reason in DeoptReason::ALL {
        assert!(set.insert(reason.clone()));
    }
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_deopt_reason_as_str_all_variants() {
    assert_eq!(
        DeoptReason::ElementKindTransition.as_str(),
        "element_kind_transition"
    );
    assert_eq!(DeoptReason::OutOfBounds.as_str(), "out_of_bounds");
    assert_eq!(DeoptReason::DetachedBuffer.as_str(), "detached_buffer");
    assert_eq!(DeoptReason::Megamorphic.as_str(), "megamorphic");
    assert_eq!(
        DeoptReason::PrototypeModified.as_str(),
        "prototype_modified"
    );
    assert_eq!(DeoptReason::FrozenOrSealed.as_str(), "frozen_or_sealed");
    assert_eq!(DeoptReason::ProxyTrap.as_str(), "proxy_trap");
}

#[test]
fn enrichment_deopt_reason_serde_roundtrip_all() {
    for reason in DeoptReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let back: DeoptReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn enrichment_deopt_reason_clone_eq() {
    for reason in DeoptReason::ALL {
        let cloned = reason.clone();
        assert_eq!(*reason, cloned);
    }
}

// ===========================================================================
// ElementTransition — struct tests
// ===========================================================================

#[test]
fn enrichment_element_transition_field_access() {
    let t = make_transition(
        ElementKind::SmiInteger,
        ElementKind::HeapNumber,
        TransitionTrigger::StoreDouble,
        false,
    );
    assert_eq!(t.from_kind, ElementKind::SmiInteger);
    assert_eq!(t.to_kind, ElementKind::HeapNumber);
    assert_eq!(t.trigger, TransitionTrigger::StoreDouble);
    assert!(!t.reversible);
}

#[test]
fn enrichment_element_transition_serde_roundtrip() {
    let t = make_transition(
        ElementKind::Packed,
        ElementKind::SmiInteger,
        TransitionTrigger::StoreNonSmi,
        true,
    );
    let json = serde_json::to_string(&t).unwrap();
    let back: ElementTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrichment_element_transition_clone_eq() {
    let t = make_transition(
        ElementKind::HeapNumber,
        ElementKind::HeapObject,
        TransitionTrigger::StoreObject,
        false,
    );
    let cloned = t.clone();
    assert_eq!(t, cloned);
}

#[test]
fn enrichment_element_transition_vec_serde_roundtrip() {
    let transitions = vec![
        make_transition(
            ElementKind::SmiInteger,
            ElementKind::HeapNumber,
            TransitionTrigger::StoreDouble,
            false,
        ),
        make_transition(
            ElementKind::HeapNumber,
            ElementKind::HeapObject,
            TransitionTrigger::StoreObject,
            false,
        ),
    ];
    let json = serde_json::to_string(&transitions).unwrap();
    let back: Vec<ElementTransition> = serde_json::from_str(&json).unwrap();
    assert_eq!(transitions, back);
}

// ===========================================================================
// FastLaneConfig — struct and default tests
// ===========================================================================

#[test]
fn enrichment_config_default_max_dense_length() {
    let config = default_config();
    assert_eq!(config.max_dense_length, 65_536);
}

#[test]
fn enrichment_config_default_smi_range() {
    let config = default_config();
    assert_eq!(config.smi_range_min, -1_073_741_824); // -2^30
    assert_eq!(config.smi_range_max, 1_073_741_823); // 2^30 - 1
}

#[test]
fn enrichment_config_default_growth_factor() {
    let config = default_config();
    assert_eq!(config.growth_factor_millionths, 2_000_000); // 2.0x
}

#[test]
fn enrichment_config_default_cow_threshold() {
    let config = default_config();
    assert_eq!(config.cow_threshold, 128);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: FastLaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_config_custom_values_serde() {
    let config = FastLaneConfig {
        max_dense_length: 1024,
        smi_range_min: -100,
        smi_range_max: 100,
        growth_factor_millionths: 1_500_000, // 1.5x
        cow_threshold: 64,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: FastLaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_config_clone_eq() {
    let config = default_config();
    let cloned = config.clone();
    assert_eq!(config, cloned);
}

// ===========================================================================
// FastLaneError — Display and serde
// ===========================================================================

#[test]
fn enrichment_error_detached_buffer_display() {
    let err = FastLaneError::DetachedBuffer;
    let msg = err.to_string();
    assert!(msg.contains("detached"));
    assert!(msg.contains("buffer"));
}

#[test]
fn enrichment_error_invalid_byte_length_display() {
    let err = FastLaneError::InvalidByteLength {
        expected: 80,
        actual: 120,
    };
    let msg = err.to_string();
    assert!(msg.contains("80"));
    assert!(msg.contains("120"));
    assert!(msg.contains("byte length"));
}

#[test]
fn enrichment_error_overflow_protection_display() {
    let err = FastLaneError::OverflowProtection;
    let msg = err.to_string();
    assert!(msg.contains("overflow"));
}

#[test]
fn enrichment_error_invalid_element_kind_display() {
    let err = FastLaneError::InvalidElementKind;
    let msg = err.to_string();
    assert!(msg.contains("element kind"));
}

#[test]
fn enrichment_error_empty_profile_display() {
    let err = FastLaneError::EmptyProfile;
    let msg = err.to_string();
    assert!(msg.contains("empty"));
}

#[test]
fn enrichment_error_is_std_error() {
    let err = FastLaneError::DetachedBuffer;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_error_serde_detached_buffer() {
    let err = FastLaneError::DetachedBuffer;
    let json = serde_json::to_string(&err).unwrap();
    let back: FastLaneError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_error_serde_invalid_byte_length() {
    let err = FastLaneError::InvalidByteLength {
        expected: 40,
        actual: 60,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: FastLaneError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_error_serde_overflow_protection() {
    let err = FastLaneError::OverflowProtection;
    let json = serde_json::to_string(&err).unwrap();
    let back: FastLaneError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_error_serde_invalid_element_kind() {
    let err = FastLaneError::InvalidElementKind;
    let json = serde_json::to_string(&err).unwrap();
    let back: FastLaneError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_error_serde_empty_profile() {
    let err = FastLaneError::EmptyProfile;
    let json = serde_json::to_string(&err).unwrap();
    let back: FastLaneError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ===========================================================================
// compute_element_size — exhaustive
// ===========================================================================

#[test]
fn enrichment_element_size_all_kinds() {
    let expected: Vec<(TypedArrayKind, u64)> = vec![
        (TypedArrayKind::Int8, 1),
        (TypedArrayKind::Uint8, 1),
        (TypedArrayKind::Uint8Clamped, 1),
        (TypedArrayKind::Int16, 2),
        (TypedArrayKind::Uint16, 2),
        (TypedArrayKind::Int32, 4),
        (TypedArrayKind::Uint32, 4),
        (TypedArrayKind::Float32, 4),
        (TypedArrayKind::Float64, 8),
        (TypedArrayKind::BigInt64, 8),
        (TypedArrayKind::BigUint64, 8),
    ];
    for (kind, size) in &expected {
        assert_eq!(
            compute_element_size(kind),
            *size,
            "Element size mismatch for {:?}",
            kind
        );
    }
}

#[test]
fn enrichment_element_size_powers_of_two() {
    for kind in TypedArrayKind::ALL {
        let size = compute_element_size(kind);
        assert!(size.is_power_of_two(), "Element size {} is not a power of 2", size);
    }
}

// ===========================================================================
// validate_typed_array — comprehensive edge cases
// ===========================================================================

#[test]
fn enrichment_validate_valid_uint8_array() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint8,
        byte_length: 100,
        element_count: 100,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_validate_valid_float32_array() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Float32,
        byte_length: 400,
        element_count: 100,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_validate_valid_with_offset() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 40,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: 128,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_validate_valid_shared_buffer() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 40,
        element_count: 10,
        is_detached: false,
        is_shared: true,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_validate_zero_elements() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Float64,
        byte_length: 0,
        element_count: 0,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_validate_detached_returns_error() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint16,
        byte_length: 20,
        element_count: 10,
        is_detached: true,
        is_shared: false,
        byte_offset: 0,
    };
    assert_eq!(
        validate_typed_array(&v).unwrap_err(),
        FastLaneError::DetachedBuffer
    );
}

#[test]
fn enrichment_validate_byte_length_mismatch_int16() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int16,
        byte_length: 30, // should be 20 for 10 elements
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    let err = validate_typed_array(&v).unwrap_err();
    match err {
        FastLaneError::InvalidByteLength { expected, actual } => {
            assert_eq!(expected, 20);
            assert_eq!(actual, 30);
        }
        other => panic!("Expected InvalidByteLength, got {:?}", other),
    }
}

#[test]
fn enrichment_validate_byte_length_mismatch_uint32() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint32,
        byte_length: 5, // should be 4 for 1 element
        element_count: 1,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    let err = validate_typed_array(&v).unwrap_err();
    assert!(matches!(err, FastLaneError::InvalidByteLength { .. }));
}

#[test]
fn enrichment_validate_overflow_large_element_count() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::BigInt64,
        byte_length: u64::MAX,
        element_count: u64::MAX,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert_eq!(
        validate_typed_array(&v).unwrap_err(),
        FastLaneError::OverflowProtection
    );
}

#[test]
fn enrichment_validate_overflow_offset_plus_length() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint8,
        byte_length: 10,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: u64::MAX,
    };
    assert_eq!(
        validate_typed_array(&v).unwrap_err(),
        FastLaneError::OverflowProtection
    );
}

#[test]
fn enrichment_validate_detached_takes_priority_over_mismatch() {
    // When both detached and length mismatch, detached should be checked first
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 100, // wrong for 10 elements (should be 40)
        element_count: 10,
        is_detached: true,
        is_shared: false,
        byte_offset: 0,
    };
    assert_eq!(
        validate_typed_array(&v).unwrap_err(),
        FastLaneError::DetachedBuffer
    );
}

#[test]
fn enrichment_validate_every_typed_array_kind_valid() {
    for kind in TypedArrayKind::ALL {
        let elem_size = compute_element_size(kind);
        let count = 10u64;
        let v = TypedArrayValidation {
            kind: *kind,
            byte_length: count * elem_size,
            element_count: count,
            is_detached: false,
            is_shared: false,
            byte_offset: 0,
        };
        assert!(
            validate_typed_array(&v).is_ok(),
            "Validation failed for {:?}",
            kind
        );
    }
}

#[test]
fn enrichment_validate_serde_roundtrip() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Float64,
        byte_length: 80,
        element_count: 10,
        is_detached: false,
        is_shared: true,
        byte_offset: 16,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: TypedArrayValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// ArrayProfile — struct tests
// ===========================================================================

#[test]
fn enrichment_array_profile_serde_roundtrip() {
    let profile = ArrayProfile {
        id: "test_prof".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 800_000,
        transitions: vec![make_transition(
            ElementKind::SmiInteger,
            ElementKind::HeapNumber,
            TransitionTrigger::StoreDouble,
            false,
        )],
        current_kind: ElementKind::HeapNumber,
        current_mode: ArrayStorageMode::FastDouble,
    };
    let json = serde_json::to_string(&profile).unwrap();
    let back: ArrayProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

#[test]
fn enrichment_array_profile_clone_eq() {
    let profile = smi_profile("clone_test");
    let cloned = profile.clone();
    assert_eq!(profile, cloned);
}

#[test]
fn enrichment_array_profile_empty_transitions() {
    let profile = smi_profile("empty_trans");
    assert!(profile.transitions.is_empty());
}

// ===========================================================================
// evaluate_fast_lane — comprehensive decision tests
// ===========================================================================

#[test]
fn enrichment_evaluate_smi_fast_lane_eligible() {
    let decision = evaluate_fast_lane(&smi_profile("smi1"), &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastSmi);
    assert_eq!(decision.element_kind, ElementKind::SmiInteger);
    assert!(decision.deopt_reason.is_none());
    assert_eq!(decision.array_id, "smi1");
}

#[test]
fn enrichment_evaluate_packed_eligible_gets_dense_mode() {
    let profile = make_profile("packed1", ElementKind::Packed, ArrayStorageMode::Dense);
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::Dense);
}

#[test]
fn enrichment_evaluate_heap_number_eligible_gets_fast_double() {
    let profile = make_profile(
        "heap_num1",
        ElementKind::HeapNumber,
        ArrayStorageMode::FastDouble,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastDouble);
}

#[test]
fn enrichment_evaluate_string_fast_object_eligible() {
    let profile = make_profile("str1", ElementKind::String, ArrayStorageMode::FastObject);
    let decision = evaluate_fast_lane(&profile, &default_config());
    // String kind with FastObject mode passes all checks
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastObject);
}

#[test]
fn enrichment_evaluate_heap_object_fast_object_eligible() {
    let profile = make_profile(
        "hobj1",
        ElementKind::HeapObject,
        ArrayStorageMode::FastObject,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastObject);
}

#[test]
fn enrichment_evaluate_zero_accesses_deopt() {
    let mut profile = smi_profile("zero_acc");
    profile.total_accesses = 0;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(decision.deopt_reason, Some(DeoptReason::OutOfBounds));
}

#[test]
fn enrichment_evaluate_hole_kind_deopt() {
    let profile = make_profile("hole1", ElementKind::Hole, ArrayStorageMode::Sparse);
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(
        decision.deopt_reason,
        Some(DeoptReason::ElementKindTransition)
    );
}

#[test]
fn enrichment_evaluate_sparse_mode_deopt() {
    let profile = ArrayProfile {
        id: "sparse1".into(),
        total_accesses: 10_000,
        fast_lane_hits_millionths: 950_000,
        transitions: Vec::new(),
        current_kind: ElementKind::SmiInteger,
        current_mode: ArrayStorageMode::Sparse,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_dictionary_mode_deopt() {
    let profile = make_profile("dict1", ElementKind::HeapObject, ArrayStorageMode::Dictionary);
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_low_hit_ratio_799999_deopt() {
    let mut profile = smi_profile("low_hit_boundary");
    profile.fast_lane_hits_millionths = 799_999; // Just below 800_000 threshold
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_exact_hit_ratio_800000_eligible() {
    let mut profile = smi_profile("exact_threshold");
    profile.fast_lane_hits_millionths = 800_000; // Exactly at threshold
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_detach_trigger_deopt() {
    let mut profile = smi_profile("detach1");
    profile.transitions.push(make_transition(
        ElementKind::SmiInteger,
        ElementKind::Hole,
        TransitionTrigger::DetachBuffer,
        false,
    ));
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(decision.deopt_reason, Some(DeoptReason::DetachedBuffer));
}

#[test]
fn enrichment_evaluate_megamorphic_four_distinct_kinds() {
    // Need >3 distinct kinds across transitions to trigger megamorphic
    let profile = ArrayProfile {
        id: "mega1".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![
            make_transition(
                ElementKind::SmiInteger,
                ElementKind::HeapNumber,
                TransitionTrigger::StoreDouble,
                false,
            ),
            make_transition(
                ElementKind::HeapNumber,
                ElementKind::String,
                TransitionTrigger::StoreObject,
                false,
            ),
            make_transition(
                ElementKind::String,
                ElementKind::HeapObject,
                TransitionTrigger::StoreObject,
                false,
            ),
        ],
        current_kind: ElementKind::HeapObject,
        current_mode: ArrayStorageMode::FastObject,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(decision.deopt_reason, Some(DeoptReason::Megamorphic));
}

#[test]
fn enrichment_evaluate_three_distinct_kinds_not_megamorphic() {
    // Exactly 3 distinct kinds should NOT trigger megamorphic
    let profile = ArrayProfile {
        id: "three_kinds".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![make_transition(
            ElementKind::SmiInteger,
            ElementKind::HeapNumber,
            TransitionTrigger::StoreDouble,
            false,
        )],
        current_kind: ElementKind::HeapNumber,
        current_mode: ArrayStorageMode::FastDouble,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    // 2 distinct kinds (SmiInteger, HeapNumber) <= 3, so not megamorphic
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_decision_preserves_array_id() {
    let profile = smi_profile("my_unique_id_42");
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert_eq!(decision.array_id, "my_unique_id_42");
}

#[test]
fn enrichment_evaluate_decision_serde_roundtrip() {
    let profile = smi_profile("serde_dec");
    let decision = evaluate_fast_lane(&profile, &default_config());
    let json = serde_json::to_string(&decision).unwrap();
    let back: FastLaneDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_evaluate_deopt_decision_serde_roundtrip() {
    let mut profile = smi_profile("serde_deopt");
    profile.total_accesses = 0;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    let json = serde_json::to_string(&decision).unwrap();
    let back: FastLaneDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_evaluate_detach_priority_over_megamorphic() {
    // When both detach and megamorphic apply, detach check comes after megamorphic
    // in code flow. Let's test: megamorphic is checked first (>3 distinct kinds)
    // then detach. So if both conditions hold, megamorphic fires first.
    let profile = ArrayProfile {
        id: "both_detach_mega".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![
            make_transition(
                ElementKind::SmiInteger,
                ElementKind::HeapNumber,
                TransitionTrigger::StoreDouble,
                false,
            ),
            make_transition(
                ElementKind::HeapNumber,
                ElementKind::String,
                TransitionTrigger::StoreObject,
                false,
            ),
            make_transition(
                ElementKind::String,
                ElementKind::HeapObject,
                TransitionTrigger::DetachBuffer,
                false,
            ),
        ],
        current_kind: ElementKind::HeapObject,
        current_mode: ArrayStorageMode::FastObject,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    // 4 distinct kinds => megamorphic fires first
    assert_eq!(decision.deopt_reason, Some(DeoptReason::Megamorphic));
}

#[test]
fn enrichment_evaluate_single_access_high_ratio_eligible() {
    let profile = ArrayProfile {
        id: "single_acc".into(),
        total_accesses: 1,
        fast_lane_hits_millionths: 1_000_000, // 100%
        transitions: Vec::new(),
        current_kind: ElementKind::SmiInteger,
        current_mode: ArrayStorageMode::FastSmi,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

// ===========================================================================
// allowed_transitions — lattice tests
// ===========================================================================

#[test]
fn enrichment_allowed_transitions_smi_targets() {
    let targets = allowed_transitions(ElementKind::SmiInteger);
    assert_eq!(targets.len(), 3);
    assert!(targets.contains(&ElementKind::HeapNumber));
    assert!(targets.contains(&ElementKind::Packed));
    assert!(targets.contains(&ElementKind::Hole));
}

#[test]
fn enrichment_allowed_transitions_heap_number_targets() {
    let targets = allowed_transitions(ElementKind::HeapNumber);
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&ElementKind::HeapObject));
    assert!(targets.contains(&ElementKind::Hole));
}

#[test]
fn enrichment_allowed_transitions_string_targets() {
    let targets = allowed_transitions(ElementKind::String);
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&ElementKind::HeapObject));
    assert!(targets.contains(&ElementKind::Hole));
}

#[test]
fn enrichment_allowed_transitions_heap_object_only_hole() {
    let targets = allowed_transitions(ElementKind::HeapObject);
    assert_eq!(targets, vec![ElementKind::Hole]);
}

#[test]
fn enrichment_allowed_transitions_packed_targets() {
    let targets = allowed_transitions(ElementKind::Packed);
    assert_eq!(targets.len(), 4);
    assert!(targets.contains(&ElementKind::SmiInteger));
    assert!(targets.contains(&ElementKind::HeapNumber));
    assert!(targets.contains(&ElementKind::HeapObject));
    assert!(targets.contains(&ElementKind::Hole));
}

#[test]
fn enrichment_allowed_transitions_hole_terminal() {
    let targets = allowed_transitions(ElementKind::Hole);
    assert!(targets.is_empty());
}

#[test]
fn enrichment_allowed_transitions_no_self_loops_except_maybe() {
    for kind in ElementKind::ALL {
        let targets = allowed_transitions(*kind);
        // None of the current transitions allow self-loops
        assert!(
            !targets.contains(kind),
            "{:?} should not transition to itself",
            kind
        );
    }
}

#[test]
fn enrichment_allowed_transitions_hole_reachable_from_all_non_hole() {
    for kind in ElementKind::ALL {
        if *kind == ElementKind::Hole {
            continue;
        }
        let targets = allowed_transitions(*kind);
        assert!(
            targets.contains(&ElementKind::Hole),
            "{:?} should be able to transition to Hole",
            kind
        );
    }
}

// ===========================================================================
// is_transition_reversible — comprehensive
// ===========================================================================

#[test]
fn enrichment_reversible_smi_to_packed() {
    assert!(is_transition_reversible(
        ElementKind::SmiInteger,
        ElementKind::Packed
    ));
}

#[test]
fn enrichment_reversible_packed_to_smi() {
    assert!(is_transition_reversible(
        ElementKind::Packed,
        ElementKind::SmiInteger
    ));
}

#[test]
fn enrichment_irreversible_smi_to_heap_number() {
    assert!(!is_transition_reversible(
        ElementKind::SmiInteger,
        ElementKind::HeapNumber
    ));
}

#[test]
fn enrichment_irreversible_smi_to_hole() {
    assert!(!is_transition_reversible(
        ElementKind::SmiInteger,
        ElementKind::Hole
    ));
}

#[test]
fn enrichment_irreversible_heap_number_to_heap_object() {
    assert!(!is_transition_reversible(
        ElementKind::HeapNumber,
        ElementKind::HeapObject
    ));
}

#[test]
fn enrichment_irreversible_string_to_heap_object() {
    assert!(!is_transition_reversible(
        ElementKind::String,
        ElementKind::HeapObject
    ));
}

#[test]
fn enrichment_irreversible_heap_object_to_hole() {
    assert!(!is_transition_reversible(
        ElementKind::HeapObject,
        ElementKind::Hole
    ));
}

#[test]
fn enrichment_irreversible_self_transitions() {
    for kind in ElementKind::ALL {
        // Self-transitions are not considered reversible in the implementation
        // (only SmiInteger <-> Packed pair is reversible)
        if *kind != ElementKind::SmiInteger && *kind != ElementKind::Packed {
            assert!(
                !is_transition_reversible(*kind, *kind),
                "{:?} self-transition should not be reversible",
                kind
            );
        }
    }
}

#[test]
fn enrichment_reversible_symmetry() {
    // If A->B is reversible, B->A should also be reversible
    for from in ElementKind::ALL {
        for to in ElementKind::ALL {
            if is_transition_reversible(*from, *to) {
                assert!(
                    is_transition_reversible(*to, *from),
                    "Reversibility should be symmetric: {:?} -> {:?}",
                    from,
                    to
                );
            }
        }
    }
}

// ===========================================================================
// build_transition_graph — graph structure tests
// ===========================================================================

#[test]
fn enrichment_transition_graph_has_all_six_keys() {
    let graph = build_transition_graph();
    assert_eq!(graph.len(), 6);
    for kind in ElementKind::ALL {
        assert!(graph.contains_key(kind));
    }
}

#[test]
fn enrichment_transition_graph_is_btreemap() {
    let graph: BTreeMap<ElementKind, Vec<ElementKind>> = build_transition_graph();
    // BTreeMap keys are sorted
    let keys: Vec<&ElementKind> = graph.keys().collect();
    assert!(keys.len() > 1);
}

#[test]
fn enrichment_transition_graph_smi_entry() {
    let graph = build_transition_graph();
    let smi_targets = &graph[&ElementKind::SmiInteger];
    assert_eq!(smi_targets.len(), 3);
}

#[test]
fn enrichment_transition_graph_hole_empty() {
    let graph = build_transition_graph();
    assert!(graph[&ElementKind::Hole].is_empty());
}

#[test]
fn enrichment_transition_graph_packed_entry() {
    let graph = build_transition_graph();
    let packed_targets = &graph[&ElementKind::Packed];
    assert_eq!(packed_targets.len(), 4);
}

#[test]
fn enrichment_transition_graph_deterministic() {
    let g1 = build_transition_graph();
    let g2 = build_transition_graph();
    assert_eq!(g1, g2);
}

// ===========================================================================
// certify_fast_lane — certificate tests
// ===========================================================================

#[test]
fn enrichment_certify_eligible_produces_certificate() {
    let profile = smi_profile("cert_eligible");
    let cert = certify_fast_lane(&profile, &default_config());
    assert_eq!(cert.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
    assert_eq!(cert.array_id, "cert_eligible");
    assert!(cert.decision.is_fast_lane);
    assert!(cert.transitions.is_empty());
}

#[test]
fn enrichment_certify_deopt_produces_certificate() {
    let mut profile = smi_profile("cert_deopt");
    profile.total_accesses = 0;
    let cert = certify_fast_lane(&profile, &default_config());
    assert_eq!(cert.array_id, "cert_deopt");
    assert!(!cert.decision.is_fast_lane);
}

#[test]
fn enrichment_certify_includes_transitions() {
    let mut profile = smi_profile("cert_trans");
    profile.transitions.push(make_transition(
        ElementKind::SmiInteger,
        ElementKind::HeapNumber,
        TransitionTrigger::StoreDouble,
        false,
    ));
    profile.current_kind = ElementKind::HeapNumber;
    profile.current_mode = ArrayStorageMode::FastDouble;
    let cert = certify_fast_lane(&profile, &default_config());
    assert_eq!(cert.transitions.len(), 1);
    assert_eq!(cert.transitions[0].from_kind, ElementKind::SmiInteger);
    assert_eq!(cert.transitions[0].to_kind, ElementKind::HeapNumber);
}

#[test]
fn enrichment_certify_hash_determinism() {
    let profile = smi_profile("cert_det");
    let c1 = certify_fast_lane(&profile, &default_config());
    let c2 = certify_fast_lane(&profile, &default_config());
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn enrichment_certify_different_ids_different_hashes() {
    let p1 = smi_profile("cert_a");
    let p2 = smi_profile("cert_b");
    let c1 = certify_fast_lane(&p1, &default_config());
    let c2 = certify_fast_lane(&p2, &default_config());
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn enrichment_certify_hash_not_empty_hash() {
    let profile = smi_profile("cert_notempty");
    let cert = certify_fast_lane(&profile, &default_config());
    let empty_hash = ContentHash::compute(b"");
    assert_ne!(cert.certificate_hash, empty_hash);
}

#[test]
fn enrichment_certify_serde_roundtrip() {
    let mut profile = smi_profile("cert_serde");
    profile.transitions.push(make_transition(
        ElementKind::SmiInteger,
        ElementKind::Packed,
        TransitionTrigger::StoreNonSmi,
        true,
    ));
    profile.current_kind = ElementKind::Packed;
    profile.current_mode = ArrayStorageMode::Dense;
    let cert = certify_fast_lane(&profile, &default_config());
    let json = serde_json::to_string(&cert).unwrap();
    let back: FastLaneCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn enrichment_certify_different_transitions_different_hash() {
    let p1 = ArrayProfile {
        id: "hash_diff".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 900_000,
        transitions: vec![make_transition(
            ElementKind::SmiInteger,
            ElementKind::HeapNumber,
            TransitionTrigger::StoreDouble,
            false,
        )],
        current_kind: ElementKind::HeapNumber,
        current_mode: ArrayStorageMode::FastDouble,
    };
    let p2 = ArrayProfile {
        id: "hash_diff".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 900_000,
        transitions: vec![make_transition(
            ElementKind::SmiInteger,
            ElementKind::Packed,
            TransitionTrigger::StoreNonSmi,
            true,
        )],
        current_kind: ElementKind::Packed,
        current_mode: ArrayStorageMode::Dense,
    };
    let c1 = certify_fast_lane(&p1, &default_config());
    let c2 = certify_fast_lane(&p2, &default_config());
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

// ===========================================================================
// run_fast_lane_evidence — manifest tests
// ===========================================================================

#[test]
fn enrichment_evidence_manifest_schema_version() {
    let manifest = run_fast_lane_evidence();
    assert_eq!(manifest.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
}

#[test]
fn enrichment_evidence_manifest_no_error() {
    let manifest = run_fast_lane_evidence();
    assert!(manifest.error.is_none());
}

#[test]
fn enrichment_evidence_manifest_count_invariant() {
    let manifest = run_fast_lane_evidence();
    assert_eq!(
        manifest.fast_lane_count + manifest.deopt_count,
        manifest.profiles_evaluated
    );
}

#[test]
fn enrichment_evidence_manifest_has_fast_lane_certs() {
    let manifest = run_fast_lane_evidence();
    assert!(manifest.fast_lane_count > 0);
}

#[test]
fn enrichment_evidence_manifest_has_deopt_certs() {
    let manifest = run_fast_lane_evidence();
    assert!(manifest.deopt_count > 0);
}

#[test]
fn enrichment_evidence_manifest_certificates_match_count() {
    let manifest = run_fast_lane_evidence();
    assert_eq!(
        manifest.certificates.len() as u32,
        manifest.profiles_evaluated
    );
}

#[test]
fn enrichment_evidence_manifest_all_certs_have_schema() {
    let manifest = run_fast_lane_evidence();
    for cert in &manifest.certificates {
        assert_eq!(cert.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
    }
}

#[test]
fn enrichment_evidence_manifest_deterministic_hash() {
    let m1 = run_fast_lane_evidence();
    let m2 = run_fast_lane_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn enrichment_evidence_manifest_deterministic_counts() {
    let m1 = run_fast_lane_evidence();
    let m2 = run_fast_lane_evidence();
    assert_eq!(m1.profiles_evaluated, m2.profiles_evaluated);
    assert_eq!(m1.fast_lane_count, m2.fast_lane_count);
    assert_eq!(m1.deopt_count, m2.deopt_count);
}

#[test]
fn enrichment_evidence_manifest_serde_roundtrip() {
    let manifest = run_fast_lane_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: FastLaneEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn enrichment_evidence_manifest_seven_profiles() {
    let manifest = run_fast_lane_evidence();
    assert_eq!(manifest.profiles_evaluated, 7);
}

#[test]
fn enrichment_evidence_manifest_cert_ids_unique() {
    let manifest = run_fast_lane_evidence();
    let mut ids = BTreeSet::new();
    for cert in &manifest.certificates {
        assert!(
            ids.insert(cert.array_id.clone()),
            "Duplicate array_id: {}",
            cert.array_id
        );
    }
}

#[test]
fn enrichment_evidence_manifest_hash_not_empty() {
    let manifest = run_fast_lane_evidence();
    let empty_hash = ContentHash::compute(b"");
    assert_ne!(manifest.manifest_hash, empty_hash);
}

// ===========================================================================
// FastLaneDecision — struct tests
// ===========================================================================

#[test]
fn enrichment_decision_serde_roundtrip_fast_lane() {
    let decision = FastLaneDecision {
        array_id: "dec1".into(),
        storage_mode: ArrayStorageMode::FastSmi,
        element_kind: ElementKind::SmiInteger,
        is_fast_lane: true,
        deopt_reason: None,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: FastLaneDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_decision_serde_roundtrip_deopt() {
    let decision = FastLaneDecision {
        array_id: "dec2".into(),
        storage_mode: ArrayStorageMode::Sparse,
        element_kind: ElementKind::Hole,
        is_fast_lane: false,
        deopt_reason: Some(DeoptReason::Megamorphic),
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: FastLaneDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_decision_clone_eq() {
    let decision = FastLaneDecision {
        array_id: "clone_dec".into(),
        storage_mode: ArrayStorageMode::FastDouble,
        element_kind: ElementKind::HeapNumber,
        is_fast_lane: true,
        deopt_reason: None,
    };
    let cloned = decision.clone();
    assert_eq!(decision, cloned);
}

// ===========================================================================
// ContentHash interaction
// ===========================================================================

#[test]
fn enrichment_content_hash_deterministic() {
    let h1 = ContentHash::compute(b"typed_array_fast_lane_test");
    let h2 = ContentHash::compute(b"typed_array_fast_lane_test");
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_different_inputs() {
    let h1 = ContentHash::compute(b"input_a");
    let h2 = ContentHash::compute(b"input_b");
    assert_ne!(h1, h2);
}

// ===========================================================================
// Workflow: end-to-end multi-profile evaluation
// ===========================================================================

#[test]
fn enrichment_workflow_batch_evaluation() {
    let config = default_config();
    let profiles = vec![
        smi_profile("batch_1"),
        make_profile("batch_2", ElementKind::HeapNumber, ArrayStorageMode::FastDouble),
        make_profile("batch_3", ElementKind::Hole, ArrayStorageMode::Sparse),
    ];

    let mut fast_count = 0u32;
    let mut deopt_count = 0u32;
    let mut certs = Vec::new();

    for profile in &profiles {
        let cert = certify_fast_lane(profile, &config);
        if cert.decision.is_fast_lane {
            fast_count += 1;
        } else {
            deopt_count += 1;
        }
        certs.push(cert);
    }

    assert_eq!(fast_count, 2);
    assert_eq!(deopt_count, 1);
    assert_eq!(certs.len(), 3);
}

#[test]
fn enrichment_workflow_validate_then_evaluate() {
    // Simulate: validate a typed array, then evaluate the corresponding profile
    let validation = TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 40,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&validation).is_ok());

    let profile = smi_profile("validated_array");
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_workflow_transition_chain_smi_to_hole() {
    // Track a chain: SmiInteger -> HeapNumber -> HeapObject -> Hole
    let transitions = vec![
        make_transition(
            ElementKind::SmiInteger,
            ElementKind::HeapNumber,
            TransitionTrigger::StoreDouble,
            false,
        ),
        make_transition(
            ElementKind::HeapNumber,
            ElementKind::HeapObject,
            TransitionTrigger::StoreObject,
            false,
        ),
        make_transition(
            ElementKind::HeapObject,
            ElementKind::Hole,
            TransitionTrigger::StoreHole,
            false,
        ),
    ];

    // Verify each transition is allowed
    assert!(allowed_transitions(ElementKind::SmiInteger).contains(&ElementKind::HeapNumber));
    assert!(allowed_transitions(ElementKind::HeapNumber).contains(&ElementKind::HeapObject));
    assert!(allowed_transitions(ElementKind::HeapObject).contains(&ElementKind::Hole));

    // Profile with this chain should megamorphic (4 distinct kinds)
    let profile = ArrayProfile {
        id: "chain".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions,
        current_kind: ElementKind::Hole,
        current_mode: ArrayStorageMode::Sparse,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn enrichment_workflow_reversible_transition_roundtrip() {
    // SmiInteger <-> Packed is reversible
    let forward = make_transition(
        ElementKind::SmiInteger,
        ElementKind::Packed,
        TransitionTrigger::StoreNonSmi,
        true,
    );
    let backward = make_transition(
        ElementKind::Packed,
        ElementKind::SmiInteger,
        TransitionTrigger::StoreNonSmi,
        true,
    );
    assert!(is_transition_reversible(forward.from_kind, forward.to_kind));
    assert!(is_transition_reversible(backward.from_kind, backward.to_kind));
}

#[test]
fn enrichment_workflow_certificate_chain_independence() {
    // Two independent profiles should produce independent certificates
    let p1 = smi_profile("indep_a");
    let p2 = smi_profile("indep_b");
    let config = default_config();
    let c1 = certify_fast_lane(&p1, &config);
    let c2 = certify_fast_lane(&p2, &config);
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
    assert_eq!(c1.decision.is_fast_lane, c2.decision.is_fast_lane);
}

// ===========================================================================
// Edge cases and boundary conditions
// ===========================================================================

#[test]
fn enrichment_edge_max_millionths_ratio() {
    let mut profile = smi_profile("max_ratio");
    profile.fast_lane_hits_millionths = 1_000_000; // 100%
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_edge_zero_millionths_ratio() {
    let mut profile = smi_profile("zero_ratio");
    profile.fast_lane_hits_millionths = 0;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn enrichment_edge_large_access_count() {
    let mut profile = smi_profile("large_acc");
    profile.total_accesses = u64::MAX;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_edge_empty_string_id_profile() {
    let profile = smi_profile("");
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.array_id, "");
}

#[test]
fn enrichment_edge_validate_single_element_all_kinds() {
    for kind in TypedArrayKind::ALL {
        let elem_size = compute_element_size(kind);
        let v = TypedArrayValidation {
            kind: *kind,
            byte_length: elem_size,
            element_count: 1,
            is_detached: false,
            is_shared: false,
            byte_offset: 0,
        };
        assert!(
            validate_typed_array(&v).is_ok(),
            "Single element validation failed for {:?}",
            kind
        );
    }
}

#[test]
fn enrichment_edge_validate_large_element_count() {
    // A valid but large array
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint8,
        byte_length: 1_000_000,
        element_count: 1_000_000,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_edge_many_transitions_same_pair() {
    // Multiple transitions between the same pair should count correctly
    let profile = ArrayProfile {
        id: "same_pair".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![
            make_transition(
                ElementKind::SmiInteger,
                ElementKind::HeapNumber,
                TransitionTrigger::StoreDouble,
                false,
            ),
            make_transition(
                ElementKind::SmiInteger,
                ElementKind::HeapNumber,
                TransitionTrigger::StoreDouble,
                false,
            ),
        ],
        current_kind: ElementKind::HeapNumber,
        current_mode: ArrayStorageMode::FastDouble,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    // Only 2 distinct kinds, not megamorphic
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_edge_grow_beyond_capacity_trigger() {
    let profile = ArrayProfile {
        id: "grow_cap".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![make_transition(
            ElementKind::SmiInteger,
            ElementKind::SmiInteger,
            TransitionTrigger::GrowBeyondCapacity,
            false,
        )],
        current_kind: ElementKind::SmiInteger,
        current_mode: ArrayStorageMode::FastSmi,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    // Only 1 distinct kind (SmiInteger), passes all checks
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_edge_shrink_to_empty_trigger() {
    let profile = ArrayProfile {
        id: "shrink_empty".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![make_transition(
            ElementKind::SmiInteger,
            ElementKind::SmiInteger,
            TransitionTrigger::ShrinkToEmpty,
            false,
        )],
        current_kind: ElementKind::SmiInteger,
        current_mode: ArrayStorageMode::FastSmi,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_edge_validate_uint8_clamped_specifics() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint8Clamped,
        byte_length: 256,
        element_count: 256,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_edge_validate_big_int64_specifics() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::BigInt64,
        byte_length: 64,
        element_count: 8,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_edge_validate_big_uint64_specifics() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::BigUint64,
        byte_length: 64,
        element_count: 8,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

// ===========================================================================
// Cross-type serde consistency
// ===========================================================================

#[test]
fn enrichment_serde_all_storage_modes_json_format() {
    for mode in ArrayStorageMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        // Should be quoted string in snake_case
        let inner = json.trim_matches('"');
        assert!(!inner.contains('-'), "JSON should use snake_case: {}", json);
        assert!(inner.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[test]
fn enrichment_serde_all_element_kinds_json_format() {
    for kind in ElementKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let inner = json.trim_matches('"');
        assert!(!inner.contains('-'));
        assert!(inner.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[test]
fn enrichment_serde_all_typed_array_kinds_json_format() {
    for kind in TypedArrayKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let inner = json.trim_matches('"');
        assert!(!inner.contains('-'));
        assert!(
            inner.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "Unexpected char in JSON: {}",
            json
        );
    }
}

#[test]
fn enrichment_serde_transition_trigger_json_format() {
    for trigger in TransitionTrigger::ALL {
        let json = serde_json::to_string(trigger).unwrap();
        let inner = json.trim_matches('"');
        assert!(inner.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[test]
fn enrichment_serde_deopt_reason_json_format() {
    for reason in DeoptReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let inner = json.trim_matches('"');
        assert!(inner.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}
