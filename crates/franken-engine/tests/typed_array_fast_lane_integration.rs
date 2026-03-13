//! Integration tests for the typed-array fast-lane module (RGC-606C).

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

use frankenengine_engine::typed_array_fast_lane::{
    ArrayProfile, ArrayStorageMode, DeoptReason, ElementKind, ElementTransition,
    FastLaneCertificate, FastLaneConfig, FastLaneDecision, FastLaneError, FastLaneEvidenceManifest,
    TYPED_ARRAY_COMPONENT, TYPED_ARRAY_POLICY_ID, TYPED_ARRAY_SCHEMA_VERSION, TransitionTrigger,
    TypedArrayKind, TypedArrayValidation, allowed_transitions, build_transition_graph,
    certify_fast_lane, compute_element_size, evaluate_fast_lane, is_transition_reversible,
    run_fast_lane_evidence, validate_typed_array,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn smi_fast_profile(id: &str) -> ArrayProfile {
    ArrayProfile {
        id: id.into(),
        total_accesses: 10_000,
        fast_lane_hits_millionths: 950_000,
        transitions: Vec::new(),
        current_kind: ElementKind::SmiInteger,
        current_mode: ArrayStorageMode::FastSmi,
    }
}

fn default_config() -> FastLaneConfig {
    FastLaneConfig::default()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_nonempty() {
    assert!(!TYPED_ARRAY_SCHEMA_VERSION.is_empty());
    assert!(TYPED_ARRAY_SCHEMA_VERSION.contains("typed-array-fast-lane"));
}

#[test]
fn integration_component_name() {
    assert_eq!(TYPED_ARRAY_COMPONENT, "typed_array_fast_lane");
}

#[test]
fn integration_policy_id() {
    assert_eq!(TYPED_ARRAY_POLICY_ID, "RGC-606C");
}

// ---------------------------------------------------------------------------
// ElementKind
// ---------------------------------------------------------------------------

#[test]
fn integration_element_kind_all_has_six() {
    assert_eq!(ElementKind::ALL.len(), 6);
}

#[test]
fn integration_element_kind_serde_roundtrip() {
    for kind in ElementKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ElementKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn integration_element_kind_unboxed_vs_boxed() {
    assert!(ElementKind::SmiInteger.is_unboxed());
    assert!(ElementKind::Packed.is_unboxed());
    assert!(ElementKind::HeapNumber.is_boxed());
    assert!(ElementKind::String.is_boxed());
    assert!(ElementKind::HeapObject.is_boxed());
    assert!(!ElementKind::Hole.is_unboxed());
    assert!(!ElementKind::Hole.is_boxed());
}

#[test]
fn integration_element_kind_is_hole() {
    assert!(ElementKind::Hole.is_hole());
    assert!(!ElementKind::SmiInteger.is_hole());
}

#[test]
fn integration_element_kind_rank_ordering() {
    assert!(ElementKind::SmiInteger.rank() < ElementKind::Hole.rank());
    assert!(ElementKind::HeapNumber.rank() < ElementKind::HeapObject.rank());
}

#[test]
fn integration_element_kind_display() {
    assert_eq!(ElementKind::SmiInteger.to_string(), "smi_integer");
    assert_eq!(ElementKind::HeapNumber.to_string(), "heap_number");
    assert_eq!(ElementKind::Hole.to_string(), "hole");
}

// ---------------------------------------------------------------------------
// TypedArrayKind
// ---------------------------------------------------------------------------

#[test]
fn integration_typed_array_kind_all_has_eleven() {
    assert_eq!(TypedArrayKind::ALL.len(), 11);
}

#[test]
fn integration_typed_array_kind_serde_roundtrip() {
    for kind in TypedArrayKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: TypedArrayKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn integration_typed_array_kind_display() {
    assert_eq!(TypedArrayKind::Int8.to_string(), "int8");
    assert_eq!(TypedArrayKind::Float64.to_string(), "float64");
    assert_eq!(TypedArrayKind::BigUint64.to_string(), "big_uint64");
}

// ---------------------------------------------------------------------------
// ArrayStorageMode
// ---------------------------------------------------------------------------

#[test]
fn integration_storage_mode_serde_roundtrip() {
    for mode in ArrayStorageMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: ArrayStorageMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

#[test]
fn integration_storage_mode_fast_path_check() {
    assert!(ArrayStorageMode::Dense.is_fast_path());
    assert!(ArrayStorageMode::FastSmi.is_fast_path());
    assert!(ArrayStorageMode::FastDouble.is_fast_path());
    assert!(ArrayStorageMode::FastObject.is_fast_path());
    assert!(!ArrayStorageMode::Sparse.is_fast_path());
    assert!(!ArrayStorageMode::Dictionary.is_fast_path());
}

// ---------------------------------------------------------------------------
// TransitionTrigger
// ---------------------------------------------------------------------------

#[test]
fn integration_transition_trigger_all_has_seven() {
    assert_eq!(TransitionTrigger::ALL.len(), 7);
}

// ---------------------------------------------------------------------------
// DeoptReason
// ---------------------------------------------------------------------------

#[test]
fn integration_deopt_reason_serde_roundtrip() {
    for reason in DeoptReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let back: DeoptReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ---------------------------------------------------------------------------
// compute_element_size
// ---------------------------------------------------------------------------

#[test]
fn integration_element_size_byte_types() {
    assert_eq!(compute_element_size(&TypedArrayKind::Int8), 1);
    assert_eq!(compute_element_size(&TypedArrayKind::Uint8), 1);
    assert_eq!(compute_element_size(&TypedArrayKind::Uint8Clamped), 1);
}

#[test]
fn integration_element_size_two_byte_types() {
    assert_eq!(compute_element_size(&TypedArrayKind::Int16), 2);
    assert_eq!(compute_element_size(&TypedArrayKind::Uint16), 2);
}

#[test]
fn integration_element_size_four_byte_types() {
    assert_eq!(compute_element_size(&TypedArrayKind::Int32), 4);
    assert_eq!(compute_element_size(&TypedArrayKind::Uint32), 4);
    assert_eq!(compute_element_size(&TypedArrayKind::Float32), 4);
}

#[test]
fn integration_element_size_eight_byte_types() {
    assert_eq!(compute_element_size(&TypedArrayKind::Float64), 8);
    assert_eq!(compute_element_size(&TypedArrayKind::BigInt64), 8);
    assert_eq!(compute_element_size(&TypedArrayKind::BigUint64), 8);
}

// ---------------------------------------------------------------------------
// validate_typed_array
// ---------------------------------------------------------------------------

#[test]
fn integration_validate_typed_array_valid() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 40,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn integration_validate_typed_array_detached() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 40,
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
fn integration_validate_typed_array_byte_length_mismatch() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Float64,
        byte_length: 100,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    let err = validate_typed_array(&v).unwrap_err();
    assert!(matches!(err, FastLaneError::InvalidByteLength { .. }));
}

#[test]
fn integration_validate_typed_array_overflow() {
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

// ---------------------------------------------------------------------------
// evaluate_fast_lane
// ---------------------------------------------------------------------------

#[test]
fn integration_evaluate_fast_lane_eligible_smi() {
    let profile = smi_fast_profile("fl1");
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert!(decision.deopt_reason.is_none());
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastSmi);
}

#[test]
fn integration_evaluate_fast_lane_zero_accesses() {
    let profile = ArrayProfile {
        total_accesses: 0,
        ..smi_fast_profile("fl2")
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert!(decision.deopt_reason.is_some());
}

#[test]
fn integration_evaluate_fast_lane_megamorphic() {
    let profile = ArrayProfile {
        transitions: vec![
            ElementTransition {
                from_kind: ElementKind::SmiInteger,
                to_kind: ElementKind::HeapNumber,
                trigger: TransitionTrigger::StoreDouble,
                reversible: false,
            },
            ElementTransition {
                from_kind: ElementKind::HeapNumber,
                to_kind: ElementKind::HeapObject,
                trigger: TransitionTrigger::StoreObject,
                reversible: false,
            },
            ElementTransition {
                from_kind: ElementKind::HeapObject,
                to_kind: ElementKind::Hole,
                trigger: TransitionTrigger::StoreHole,
                reversible: false,
            },
        ],
        current_kind: ElementKind::Hole,
        current_mode: ArrayStorageMode::Sparse,
        ..smi_fast_profile("fl3")
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(decision.deopt_reason, Some(DeoptReason::Megamorphic));
}

#[test]
fn integration_evaluate_fast_lane_detached_buffer() {
    let profile = ArrayProfile {
        transitions: vec![ElementTransition {
            from_kind: ElementKind::SmiInteger,
            to_kind: ElementKind::Hole,
            trigger: TransitionTrigger::DetachBuffer,
            reversible: false,
        }],
        ..smi_fast_profile("fl4")
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(decision.deopt_reason, Some(DeoptReason::DetachedBuffer));
}

#[test]
fn integration_evaluate_fast_lane_low_hit_ratio() {
    let profile = ArrayProfile {
        fast_lane_hits_millionths: 500_000,
        ..smi_fast_profile("fl5")
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn integration_evaluate_fast_lane_dictionary_mode() {
    let profile = ArrayProfile {
        current_mode: ArrayStorageMode::Dictionary,
        ..smi_fast_profile("fl6")
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn integration_evaluate_fast_lane_heap_number() {
    let profile = ArrayProfile {
        id: "fl7".into(),
        total_accesses: 8_000,
        fast_lane_hits_millionths: 900_000,
        transitions: Vec::new(),
        current_kind: ElementKind::HeapNumber,
        current_mode: ArrayStorageMode::FastDouble,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastDouble);
}

// ---------------------------------------------------------------------------
// allowed_transitions
// ---------------------------------------------------------------------------

#[test]
fn integration_allowed_transitions_smi() {
    let targets = allowed_transitions(ElementKind::SmiInteger);
    assert!(targets.contains(&ElementKind::HeapNumber));
    assert!(targets.contains(&ElementKind::Packed));
    assert!(targets.contains(&ElementKind::Hole));
}

#[test]
fn integration_allowed_transitions_hole_terminal() {
    let targets = allowed_transitions(ElementKind::Hole);
    assert!(targets.is_empty());
}

// ---------------------------------------------------------------------------
// is_transition_reversible
// ---------------------------------------------------------------------------

#[test]
fn integration_smi_packed_reversible() {
    assert!(is_transition_reversible(
        ElementKind::SmiInteger,
        ElementKind::Packed
    ));
    assert!(is_transition_reversible(
        ElementKind::Packed,
        ElementKind::SmiInteger
    ));
}

#[test]
fn integration_heap_number_to_object_not_reversible() {
    assert!(!is_transition_reversible(
        ElementKind::HeapNumber,
        ElementKind::HeapObject
    ));
}

// ---------------------------------------------------------------------------
// build_transition_graph
// ---------------------------------------------------------------------------

#[test]
fn integration_transition_graph_covers_all_kinds() {
    let graph = build_transition_graph();
    assert_eq!(graph.len(), ElementKind::ALL.len());
    for kind in ElementKind::ALL {
        assert!(graph.contains_key(kind));
    }
}

// ---------------------------------------------------------------------------
// certify_fast_lane
// ---------------------------------------------------------------------------

#[test]
fn integration_certify_fast_lane_produces_certificate() {
    let profile = smi_fast_profile("cert1");
    let cert = certify_fast_lane(&profile, &default_config());
    assert_eq!(cert.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
    assert_eq!(cert.array_id, "cert1");
    assert!(cert.decision.is_fast_lane);
}

#[test]
fn integration_certify_fast_lane_hash_determinism() {
    let profile = smi_fast_profile("cert2");
    let c1 = certify_fast_lane(&profile, &default_config());
    let c2 = certify_fast_lane(&profile, &default_config());
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn integration_certify_fast_lane_serde_roundtrip() {
    let profile = smi_fast_profile("cert3");
    let cert = certify_fast_lane(&profile, &default_config());
    let json = serde_json::to_string(&cert).unwrap();
    let back: FastLaneCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// FastLaneError serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_fast_lane_error_serde_roundtrip() {
    let errors = vec![
        FastLaneError::DetachedBuffer,
        FastLaneError::InvalidByteLength {
            expected: 80,
            actual: 100,
        },
        FastLaneError::OverflowProtection,
        FastLaneError::InvalidElementKind,
        FastLaneError::EmptyProfile,
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let back: FastLaneError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn integration_fast_lane_error_display() {
    assert!(
        FastLaneError::DetachedBuffer
            .to_string()
            .contains("detached")
    );
    assert!(
        FastLaneError::OverflowProtection
            .to_string()
            .contains("overflow")
    );
    assert!(FastLaneError::EmptyProfile.to_string().contains("empty"));
}

// ---------------------------------------------------------------------------
// Evidence manifest
// ---------------------------------------------------------------------------

#[test]
fn integration_run_evidence_produces_manifest() {
    let manifest = run_fast_lane_evidence();
    assert_eq!(manifest.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
    assert!(manifest.profiles_evaluated >= 5);
    assert!(manifest.error.is_none());
    assert!(!manifest.certificates.is_empty());
}

#[test]
fn integration_evidence_hash_determinism() {
    let m1 = run_fast_lane_evidence();
    let m2 = run_fast_lane_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn integration_evidence_serde_roundtrip() {
    let manifest = run_fast_lane_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: FastLaneEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn integration_evidence_has_fast_and_deopt() {
    let manifest = run_fast_lane_evidence();
    assert!(manifest.fast_lane_count > 0);
    assert!(manifest.deopt_count > 0);
    assert_eq!(
        manifest.fast_lane_count + manifest.deopt_count,
        manifest.profiles_evaluated
    );
}

#[test]
fn integration_evidence_certificates_have_schema_version() {
    let manifest = run_fast_lane_evidence();
    for cert in &manifest.certificates {
        assert_eq!(cert.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
    }
}

// ---------------------------------------------------------------------------
// FastLaneConfig default
// ---------------------------------------------------------------------------

#[test]
fn integration_fast_lane_config_default() {
    let config = FastLaneConfig::default();
    assert!(config.max_dense_length > 0);
    assert!(config.smi_range_max > 0);
    assert!(config.smi_range_min < 0);
    assert!(config.growth_factor_millionths > 0);
    assert!(config.cow_threshold > 0);
}

#[test]
fn integration_fast_lane_config_serde_roundtrip() {
    let config = FastLaneConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: FastLaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// Enrichment tests (appended)
// ===========================================================================

// ---------------------------------------------------------------------------
// Helpers for enrichment
// ---------------------------------------------------------------------------

fn enrichment_profile(id: &str, kind: ElementKind, mode: ArrayStorageMode) -> ArrayProfile {
    ArrayProfile {
        id: id.into(),
        total_accesses: 10_000,
        fast_lane_hits_millionths: 950_000,
        transitions: Vec::new(),
        current_kind: kind,
        current_mode: mode,
    }
}

fn enrichment_transition(
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

// ---------------------------------------------------------------------------
// Debug impls
// ---------------------------------------------------------------------------

#[test]
fn enrichment_element_kind_debug_all_variants() {
    for kind in ElementKind::ALL {
        let dbg = format!("{:?}", kind);
        assert!(!dbg.is_empty(), "Debug should be non-empty for {:?}", kind);
    }
}

#[test]
fn enrichment_typed_array_kind_debug_all_variants() {
    for kind in TypedArrayKind::ALL {
        let dbg = format!("{:?}", kind);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_storage_mode_debug_all_variants() {
    for mode in ArrayStorageMode::ALL {
        let dbg = format!("{:?}", mode);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_transition_trigger_debug_all_variants() {
    for trigger in TransitionTrigger::ALL {
        let dbg = format!("{:?}", trigger);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_deopt_reason_debug_all_variants() {
    for reason in DeoptReason::ALL {
        let dbg = format!("{:?}", reason);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_fast_lane_error_debug_all_variants() {
    let errors = vec![
        FastLaneError::DetachedBuffer,
        FastLaneError::InvalidByteLength {
            expected: 1,
            actual: 2,
        },
        FastLaneError::OverflowProtection,
        FastLaneError::InvalidElementKind,
        FastLaneError::EmptyProfile,
    ];
    for e in &errors {
        let dbg = format!("{:?}", e);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_fast_lane_decision_debug() {
    let d = FastLaneDecision {
        array_id: "dbg_test".into(),
        storage_mode: ArrayStorageMode::FastSmi,
        element_kind: ElementKind::SmiInteger,
        is_fast_lane: true,
        deopt_reason: None,
    };
    let dbg = format!("{:?}", d);
    assert!(dbg.contains("dbg_test"));
    assert!(dbg.contains("FastSmi"));
}

#[test]
fn enrichment_fast_lane_certificate_debug() {
    let profile = smi_fast_profile("dbg_cert");
    let cert = certify_fast_lane(&profile, &default_config());
    let dbg = format!("{:?}", cert);
    assert!(dbg.contains("dbg_cert"));
    assert!(dbg.contains("schema_version"));
}

#[test]
fn enrichment_array_profile_debug() {
    let profile = smi_fast_profile("dbg_prof");
    let dbg = format!("{:?}", profile);
    assert!(dbg.contains("dbg_prof"));
    assert!(dbg.contains("total_accesses"));
}

#[test]
fn enrichment_typed_array_validation_debug() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Float32,
        byte_length: 40,
        element_count: 10,
        is_detached: false,
        is_shared: true,
        byte_offset: 8,
    };
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Float32"));
}

#[test]
fn enrichment_element_transition_debug() {
    let t = enrichment_transition(
        ElementKind::SmiInteger,
        ElementKind::HeapNumber,
        TransitionTrigger::StoreDouble,
        false,
    );
    let dbg = format!("{:?}", t);
    assert!(dbg.contains("SmiInteger"));
    assert!(dbg.contains("HeapNumber"));
}

#[test]
fn enrichment_fast_lane_config_debug() {
    let config = default_config();
    let dbg = format!("{:?}", config);
    assert!(dbg.contains("max_dense_length"));
    assert!(dbg.contains("smi_range_min"));
}

#[test]
fn enrichment_evidence_manifest_debug() {
    let manifest = run_fast_lane_evidence();
    let dbg = format!("{:?}", manifest);
    assert!(dbg.contains("profiles_evaluated"));
}

// ---------------------------------------------------------------------------
// JSON field-name verification for structs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_array_profile_json_field_names() {
    let profile = smi_fast_profile("field_test");
    let json = serde_json::to_string(&profile).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"total_accesses\""));
    assert!(json.contains("\"fast_lane_hits_millionths\""));
    assert!(json.contains("\"transitions\""));
    assert!(json.contains("\"current_kind\""));
    assert!(json.contains("\"current_mode\""));
}

#[test]
fn enrichment_fast_lane_decision_json_field_names() {
    let d = FastLaneDecision {
        array_id: "fn_test".into(),
        storage_mode: ArrayStorageMode::Dense,
        element_kind: ElementKind::Packed,
        is_fast_lane: true,
        deopt_reason: None,
    };
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("\"array_id\""));
    assert!(json.contains("\"storage_mode\""));
    assert!(json.contains("\"element_kind\""));
    assert!(json.contains("\"is_fast_lane\""));
    assert!(json.contains("\"deopt_reason\""));
}

#[test]
fn enrichment_fast_lane_certificate_json_field_names() {
    let cert = certify_fast_lane(&smi_fast_profile("cert_fn"), &default_config());
    let json = serde_json::to_string(&cert).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"array_id\""));
    assert!(json.contains("\"decision\""));
    assert!(json.contains("\"transitions\""));
    assert!(json.contains("\"certificate_hash\""));
}

#[test]
fn enrichment_typed_array_validation_json_field_names() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 40,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"byte_length\""));
    assert!(json.contains("\"element_count\""));
    assert!(json.contains("\"is_detached\""));
    assert!(json.contains("\"is_shared\""));
    assert!(json.contains("\"byte_offset\""));
}

#[test]
fn enrichment_element_transition_json_field_names() {
    let t = enrichment_transition(
        ElementKind::SmiInteger,
        ElementKind::Packed,
        TransitionTrigger::StoreNonSmi,
        true,
    );
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("\"from_kind\""));
    assert!(json.contains("\"to_kind\""));
    assert!(json.contains("\"trigger\""));
    assert!(json.contains("\"reversible\""));
}

#[test]
fn enrichment_fast_lane_config_json_field_names() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("\"max_dense_length\""));
    assert!(json.contains("\"smi_range_min\""));
    assert!(json.contains("\"smi_range_max\""));
    assert!(json.contains("\"growth_factor_millionths\""));
    assert!(json.contains("\"cow_threshold\""));
}

#[test]
fn enrichment_evidence_manifest_json_field_names() {
    let manifest = run_fast_lane_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"profiles_evaluated\""));
    assert!(json.contains("\"fast_lane_count\""));
    assert!(json.contains("\"deopt_count\""));
    assert!(json.contains("\"certificates\""));
    assert!(json.contains("\"manifest_hash\""));
    assert!(json.contains("\"error\""));
}

// ---------------------------------------------------------------------------
// Clone tests for structs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fast_lane_decision_clone() {
    let d = FastLaneDecision {
        array_id: "clone_d".into(),
        storage_mode: ArrayStorageMode::FastDouble,
        element_kind: ElementKind::HeapNumber,
        is_fast_lane: true,
        deopt_reason: None,
    };
    let cloned = d.clone();
    assert_eq!(d, cloned);
}

#[test]
fn enrichment_fast_lane_certificate_clone() {
    let cert = certify_fast_lane(&smi_fast_profile("clone_cert"), &default_config());
    let cloned = cert.clone();
    assert_eq!(cert, cloned);
}

#[test]
fn enrichment_typed_array_validation_clone() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Float64,
        byte_length: 80,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: 0,
    };
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn enrichment_evidence_manifest_clone() {
    let manifest = run_fast_lane_evidence();
    let cloned = manifest.clone();
    assert_eq!(manifest, cloned);
}

#[test]
fn enrichment_fast_lane_error_clone() {
    let errors = vec![
        FastLaneError::DetachedBuffer,
        FastLaneError::InvalidByteLength {
            expected: 10,
            actual: 20,
        },
        FastLaneError::OverflowProtection,
        FastLaneError::InvalidElementKind,
        FastLaneError::EmptyProfile,
    ];
    for e in &errors {
        let cloned = e.clone();
        assert_eq!(*e, cloned);
    }
}

// ---------------------------------------------------------------------------
// Serde pretty-print roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_serde_pretty_roundtrip() {
    let cert = certify_fast_lane(&smi_fast_profile("pretty_cert"), &default_config());
    let json = serde_json::to_string_pretty(&cert).unwrap();
    let back: FastLaneCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn enrichment_evidence_manifest_serde_pretty_roundtrip() {
    let manifest = run_fast_lane_evidence();
    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let back: FastLaneEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn enrichment_array_profile_serde_pretty_roundtrip() {
    let profile = ArrayProfile {
        id: "pretty_prof".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 900_000,
        transitions: vec![enrichment_transition(
            ElementKind::SmiInteger,
            ElementKind::HeapNumber,
            TransitionTrigger::StoreDouble,
            false,
        )],
        current_kind: ElementKind::HeapNumber,
        current_mode: ArrayStorageMode::FastDouble,
    };
    let json = serde_json::to_string_pretty(&profile).unwrap();
    let back: ArrayProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

// ---------------------------------------------------------------------------
// Ordering (Ord/PartialOrd) tests for Copy enums
// ---------------------------------------------------------------------------

#[test]
fn enrichment_element_kind_ord_total_order() {
    let mut kinds: Vec<ElementKind> = ElementKind::ALL.to_vec();
    kinds.sort();
    // derived Ord follows declaration order
    assert_eq!(kinds[0], ElementKind::SmiInteger);
    assert_eq!(kinds[1], ElementKind::HeapNumber);
    assert_eq!(kinds[2], ElementKind::String);
    assert_eq!(kinds[3], ElementKind::HeapObject);
    assert_eq!(kinds[4], ElementKind::Hole);
    assert_eq!(kinds[5], ElementKind::Packed);
}

#[test]
fn enrichment_typed_array_kind_ord_total_order() {
    let mut kinds: Vec<TypedArrayKind> = TypedArrayKind::ALL.to_vec();
    kinds.sort();
    // derived Ord follows declaration order
    assert_eq!(kinds[0], TypedArrayKind::Int8);
    assert_eq!(kinds[10], TypedArrayKind::BigUint64);
}

#[test]
fn enrichment_storage_mode_ord_total_order() {
    let mut modes: Vec<ArrayStorageMode> = ArrayStorageMode::ALL.to_vec();
    modes.sort();
    assert_eq!(modes[0], ArrayStorageMode::Dense);
    assert_eq!(modes[5], ArrayStorageMode::FastObject);
}

#[test]
fn enrichment_deopt_reason_ord_total_order() {
    let mut reasons: Vec<DeoptReason> = DeoptReason::ALL.to_vec();
    reasons.sort();
    assert_eq!(reasons[0], DeoptReason::ElementKindTransition);
    assert_eq!(reasons[6], DeoptReason::ProxyTrap);
}

// ---------------------------------------------------------------------------
// Hash consistency tests (BTreeSet insertion)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_element_kind_btreeset_all_unique() {
    let set: BTreeSet<ElementKind> = ElementKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_typed_array_kind_btreeset_all_unique() {
    let set: BTreeSet<TypedArrayKind> = TypedArrayKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), 11);
}

#[test]
fn enrichment_storage_mode_btreeset_all_unique() {
    let set: BTreeSet<ArrayStorageMode> = ArrayStorageMode::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_deopt_reason_btreeset_all_unique() {
    let set: BTreeSet<DeoptReason> = DeoptReason::ALL.iter().cloned().collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_transition_trigger_btreeset_all_unique() {
    let set: BTreeSet<TransitionTrigger> = TransitionTrigger::ALL.iter().cloned().collect();
    assert_eq!(set.len(), 7);
}

// ---------------------------------------------------------------------------
// BTreeMap usage with element kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_element_kind_btreemap_key() {
    let mut map = BTreeMap::new();
    for kind in ElementKind::ALL {
        map.insert(*kind, kind.rank());
    }
    assert_eq!(map.len(), 6);
    assert_eq!(map[&ElementKind::SmiInteger], 0);
    assert_eq!(map[&ElementKind::Hole], 5);
}

// ---------------------------------------------------------------------------
// Certificate hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certify_hash_sensitive_to_is_fast_lane() {
    // Same id, one eligible and one deopt => different hashes
    let eligible = smi_fast_profile("sens_id");
    let mut deopt_profile = smi_fast_profile("sens_id");
    deopt_profile.total_accesses = 0;

    let c_eligible = certify_fast_lane(&eligible, &default_config());
    let c_deopt = certify_fast_lane(&deopt_profile, &default_config());

    assert!(c_eligible.decision.is_fast_lane);
    assert!(!c_deopt.decision.is_fast_lane);
    assert_ne!(c_eligible.certificate_hash, c_deopt.certificate_hash);
}

#[test]
fn enrichment_certify_hash_sensitive_to_element_kind() {
    let p_smi = enrichment_profile(
        "kind_sens",
        ElementKind::SmiInteger,
        ArrayStorageMode::FastSmi,
    );
    let p_heap = enrichment_profile(
        "kind_sens",
        ElementKind::HeapNumber,
        ArrayStorageMode::FastDouble,
    );

    let c1 = certify_fast_lane(&p_smi, &default_config());
    let c2 = certify_fast_lane(&p_heap, &default_config());
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn enrichment_certify_hash_sensitive_to_storage_mode() {
    // Same profile id and kind but different storage mode path
    let p1 = enrichment_profile(
        "mode_sens",
        ElementKind::SmiInteger,
        ArrayStorageMode::FastSmi,
    );
    // HeapObject with FastObject will go through a different storage mode path
    let p2 = enrichment_profile(
        "mode_sens",
        ElementKind::HeapObject,
        ArrayStorageMode::FastObject,
    );

    let c1 = certify_fast_lane(&p1, &default_config());
    let c2 = certify_fast_lane(&p2, &default_config());
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn enrichment_certify_hash_sensitive_to_transition_reversibility() {
    let mut p1 = smi_fast_profile("rev_sens");
    p1.transitions.push(enrichment_transition(
        ElementKind::SmiInteger,
        ElementKind::Packed,
        TransitionTrigger::StoreNonSmi,
        true,
    ));
    p1.current_kind = ElementKind::Packed;
    p1.current_mode = ArrayStorageMode::Dense;

    let mut p2 = smi_fast_profile("rev_sens");
    p2.transitions.push(enrichment_transition(
        ElementKind::SmiInteger,
        ElementKind::Packed,
        TransitionTrigger::StoreNonSmi,
        false,
    ));
    p2.current_kind = ElementKind::Packed;
    p2.current_mode = ArrayStorageMode::Dense;

    let c1 = certify_fast_lane(&p1, &default_config());
    let c2 = certify_fast_lane(&p2, &default_config());
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn enrichment_certify_hash_sensitive_to_trigger_kind() {
    let mut p1 = smi_fast_profile("trig_sens");
    p1.transitions.push(enrichment_transition(
        ElementKind::SmiInteger,
        ElementKind::SmiInteger,
        TransitionTrigger::GrowBeyondCapacity,
        false,
    ));

    let mut p2 = smi_fast_profile("trig_sens");
    p2.transitions.push(enrichment_transition(
        ElementKind::SmiInteger,
        ElementKind::SmiInteger,
        TransitionTrigger::ShrinkToEmpty,
        false,
    ));

    let c1 = certify_fast_lane(&p1, &default_config());
    let c2 = certify_fast_lane(&p2, &default_config());
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

// ---------------------------------------------------------------------------
// evaluate_fast_lane — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_string_kind_fast_object_chosen_mode() {
    let profile = enrichment_profile(
        "str_mode",
        ElementKind::String,
        ArrayStorageMode::FastObject,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    // String kind => falls to _ arm => keeps current_mode (FastObject)
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastObject);
}

#[test]
fn enrichment_evaluate_heap_object_fast_object_chosen_mode() {
    let profile = enrichment_profile(
        "ho_mode",
        ElementKind::HeapObject,
        ArrayStorageMode::FastObject,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastObject);
}

#[test]
fn enrichment_evaluate_packed_dense_chosen_mode() {
    let profile = enrichment_profile(
        "packed_mode",
        ElementKind::Packed,
        ArrayStorageMode::FastObject,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    // Packed => ArrayStorageMode::Dense
    assert_eq!(decision.storage_mode, ArrayStorageMode::Dense);
}

#[test]
fn enrichment_evaluate_smi_ignores_current_mode_uses_fast_smi() {
    // Even if current_mode is Dense, if kind is SmiInteger the chosen mode is FastSmi
    let profile = enrichment_profile(
        "smi_override",
        ElementKind::SmiInteger,
        ArrayStorageMode::Dense,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastSmi);
}

#[test]
fn enrichment_evaluate_heap_number_overrides_to_fast_double() {
    // Even if current_mode is FastObject, if kind is HeapNumber the chosen mode is FastDouble
    let profile = enrichment_profile(
        "hn_override",
        ElementKind::HeapNumber,
        ArrayStorageMode::FastObject,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.storage_mode, ArrayStorageMode::FastDouble);
}

#[test]
fn enrichment_evaluate_exactly_three_distinct_kinds_passes() {
    // 3 distinct kinds from transitions should NOT trigger megamorphic (need >3)
    let profile = ArrayProfile {
        id: "three_kinds_pass".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![
            enrichment_transition(
                ElementKind::SmiInteger,
                ElementKind::HeapNumber,
                TransitionTrigger::StoreDouble,
                false,
            ),
            enrichment_transition(
                ElementKind::HeapNumber,
                ElementKind::HeapObject,
                TransitionTrigger::StoreObject,
                false,
            ),
        ],
        // 3 distinct: SmiInteger, HeapNumber, HeapObject
        current_kind: ElementKind::HeapObject,
        current_mode: ArrayStorageMode::FastObject,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_exactly_four_distinct_kinds_megamorphic() {
    let profile = ArrayProfile {
        id: "four_kinds_mega".into(),
        total_accesses: 5_000,
        fast_lane_hits_millionths: 950_000,
        transitions: vec![
            enrichment_transition(
                ElementKind::SmiInteger,
                ElementKind::HeapNumber,
                TransitionTrigger::StoreDouble,
                false,
            ),
            enrichment_transition(
                ElementKind::HeapNumber,
                ElementKind::String,
                TransitionTrigger::StoreObject,
                false,
            ),
            enrichment_transition(
                ElementKind::String,
                ElementKind::HeapObject,
                TransitionTrigger::StoreObject,
                false,
            ),
        ],
        // 4 distinct: SmiInteger, HeapNumber, String, HeapObject
        current_kind: ElementKind::HeapObject,
        current_mode: ArrayStorageMode::FastObject,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(decision.deopt_reason, Some(DeoptReason::Megamorphic));
}

#[test]
fn enrichment_evaluate_hit_ratio_exactly_799999_deopt() {
    let mut profile = smi_fast_profile("ratio_799999");
    profile.fast_lane_hits_millionths = 799_999;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_hit_ratio_exactly_800000_eligible() {
    let mut profile = smi_fast_profile("ratio_800000");
    profile.fast_lane_hits_millionths = 800_000;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_hit_ratio_exactly_800001_eligible() {
    let mut profile = smi_fast_profile("ratio_800001");
    profile.fast_lane_hits_millionths = 800_001;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_evaluate_sparse_mode_deopt() {
    let profile = enrichment_profile(
        "sparse_deopt",
        ElementKind::SmiInteger,
        ArrayStorageMode::Sparse,
    );
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
    assert_eq!(
        decision.deopt_reason,
        Some(DeoptReason::ElementKindTransition)
    );
}

#[test]
fn enrichment_evaluate_decision_preserves_element_kind() {
    for kind in &[
        ElementKind::SmiInteger,
        ElementKind::HeapNumber,
        ElementKind::String,
        ElementKind::HeapObject,
        ElementKind::Packed,
    ] {
        let mode = match kind {
            ElementKind::SmiInteger => ArrayStorageMode::FastSmi,
            ElementKind::HeapNumber => ArrayStorageMode::FastDouble,
            ElementKind::String | ElementKind::HeapObject => ArrayStorageMode::FastObject,
            ElementKind::Packed => ArrayStorageMode::Dense,
            _ => ArrayStorageMode::Dense,
        };
        let profile = enrichment_profile("ek_preserve", *kind, mode);
        let decision = evaluate_fast_lane(&profile, &default_config());
        assert_eq!(decision.element_kind, *kind);
    }
}

// ---------------------------------------------------------------------------
// validate_typed_array — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_every_kind_mismatch_by_one() {
    for kind in TypedArrayKind::ALL {
        let elem_size = compute_element_size(kind);
        let count = 10u64;
        let expected = count * elem_size;
        let v = TypedArrayValidation {
            kind: *kind,
            byte_length: expected + 1, // off by one
            element_count: count,
            is_detached: false,
            is_shared: false,
            byte_offset: 0,
        };
        let err = validate_typed_array(&v).unwrap_err();
        match err {
            FastLaneError::InvalidByteLength {
                expected: e,
                actual: a,
            } => {
                assert_eq!(e, expected);
                assert_eq!(a, expected + 1);
            }
            other => panic!("Expected InvalidByteLength for {:?}, got {:?}", kind, other),
        }
    }
}

#[test]
fn enrichment_validate_mul_overflow_int16() {
    // element_count * 2 overflows
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Int16,
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
fn enrichment_validate_mul_overflow_float32() {
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Float32,
        byte_length: u64::MAX,
        element_count: u64::MAX / 2,
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
fn enrichment_validate_offset_at_boundary() {
    // byte_offset + byte_length exactly u64::MAX should succeed
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint8,
        byte_length: 10,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: u64::MAX - 10, // exactly fits
    };
    assert!(validate_typed_array(&v).is_ok());
}

#[test]
fn enrichment_validate_offset_one_past_boundary() {
    // byte_offset + byte_length overflows by 1
    let v = TypedArrayValidation {
        kind: TypedArrayKind::Uint8,
        byte_length: 10,
        element_count: 10,
        is_detached: false,
        is_shared: false,
        byte_offset: u64::MAX - 9, // overflows
    };
    assert_eq!(
        validate_typed_array(&v).unwrap_err(),
        FastLaneError::OverflowProtection
    );
}

#[test]
fn enrichment_validate_shared_does_not_affect_result() {
    // shared vs non-shared should both pass with same dimensions
    let make_validation = |shared: bool| TypedArrayValidation {
        kind: TypedArrayKind::Int32,
        byte_length: 40,
        element_count: 10,
        is_detached: false,
        is_shared: shared,
        byte_offset: 0,
    };
    assert!(validate_typed_array(&make_validation(true)).is_ok());
    assert!(validate_typed_array(&make_validation(false)).is_ok());
}

// ---------------------------------------------------------------------------
// allowed_transitions — count verification for all kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_allowed_transitions_count_by_kind() {
    assert_eq!(allowed_transitions(ElementKind::SmiInteger).len(), 3);
    assert_eq!(allowed_transitions(ElementKind::HeapNumber).len(), 2);
    assert_eq!(allowed_transitions(ElementKind::String).len(), 2);
    assert_eq!(allowed_transitions(ElementKind::HeapObject).len(), 1);
    assert_eq!(allowed_transitions(ElementKind::Packed).len(), 4);
    assert_eq!(allowed_transitions(ElementKind::Hole).len(), 0);
}

#[test]
fn enrichment_transition_graph_matches_allowed_transitions() {
    let graph = build_transition_graph();
    for kind in ElementKind::ALL {
        assert_eq!(graph[kind], allowed_transitions(*kind));
    }
}

#[test]
fn enrichment_transition_graph_serde_roundtrip() {
    let graph = build_transition_graph();
    let json = serde_json::to_string(&graph).unwrap();
    let back: BTreeMap<ElementKind, Vec<ElementKind>> = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, back);
}

// ---------------------------------------------------------------------------
// is_transition_reversible — full matrix check
// ---------------------------------------------------------------------------

#[test]
fn enrichment_reversibility_full_matrix() {
    for from in ElementKind::ALL {
        for to in ElementKind::ALL {
            let rev = is_transition_reversible(*from, *to);
            let expected = matches!(
                (*from, *to),
                (ElementKind::SmiInteger, ElementKind::Packed)
                    | (ElementKind::Packed, ElementKind::SmiInteger)
            );
            assert_eq!(
                rev, expected,
                "Reversibility mismatch for {:?} -> {:?}",
                from, to
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence manifest — deeper structural checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_manifest_error_field_null() {
    let manifest = run_fast_lane_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(json.contains("\"error\":null"));
}

#[test]
fn enrichment_evidence_manifest_at_least_one_fast_lane_cert() {
    let manifest = run_fast_lane_evidence();
    let fast_certs: Vec<_> = manifest
        .certificates
        .iter()
        .filter(|c| c.decision.is_fast_lane)
        .collect();
    assert!(!fast_certs.is_empty());
    assert_eq!(fast_certs.len() as u32, manifest.fast_lane_count);
}

#[test]
fn enrichment_evidence_manifest_at_least_one_deopt_cert() {
    let manifest = run_fast_lane_evidence();
    let deopt_certs: Vec<_> = manifest
        .certificates
        .iter()
        .filter(|c| !c.decision.is_fast_lane)
        .collect();
    assert!(!deopt_certs.is_empty());
    assert_eq!(deopt_certs.len() as u32, manifest.deopt_count);
}

#[test]
fn enrichment_evidence_manifest_cert_hashes_all_distinct() {
    let manifest = run_fast_lane_evidence();
    let hashes: BTreeSet<_> = manifest
        .certificates
        .iter()
        .map(|c| c.certificate_hash.as_bytes().to_vec())
        .collect();
    assert_eq!(hashes.len(), manifest.certificates.len());
}

// ---------------------------------------------------------------------------
// FastLaneError — Display format specifics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_invalid_byte_length_format() {
    let err = FastLaneError::InvalidByteLength {
        expected: 40,
        actual: 60,
    };
    let msg = err.to_string();
    assert!(msg.contains("40"));
    assert!(msg.contains("60"));
    assert!(msg.contains("expected"));
}

#[test]
fn enrichment_error_display_invalid_element_kind_text() {
    let msg = FastLaneError::InvalidElementKind.to_string();
    assert!(msg.contains("invalid"));
    assert!(msg.contains("element kind"));
}

// ---------------------------------------------------------------------------
// Determinism across multiple sequential runs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_ten_runs_same_manifest_hash() {
    let hashes: Vec<_> = (0..10)
        .map(|_| {
            let m = run_fast_lane_evidence();
            m.manifest_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_determinism_ten_runs_same_cert_hashes() {
    let first = run_fast_lane_evidence();
    for _ in 0..10 {
        let m = run_fast_lane_evidence();
        assert_eq!(m.certificates.len(), first.certificates.len());
        for (a, b) in first.certificates.iter().zip(m.certificates.iter()) {
            assert_eq!(a.certificate_hash, b.certificate_hash);
        }
    }
}

// ---------------------------------------------------------------------------
// ContentHash interaction via certificate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_hash_bytes_nonzero() {
    let cert = certify_fast_lane(&smi_fast_profile("nonzero"), &default_config());
    let bytes = cert.certificate_hash.as_bytes();
    // At least some bytes should be nonzero
    assert!(bytes.iter().any(|b| *b != 0));
}

#[test]
fn enrichment_manifest_hash_bytes_nonzero() {
    let manifest = run_fast_lane_evidence();
    let bytes = manifest.manifest_hash.as_bytes();
    assert!(bytes.iter().any(|b| *b != 0));
}

// ---------------------------------------------------------------------------
// evaluate + certify workflow combos
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certify_all_fast_path_modes_eligible() {
    let modes = [
        (ElementKind::SmiInteger, ArrayStorageMode::FastSmi),
        (ElementKind::HeapNumber, ArrayStorageMode::FastDouble),
        (ElementKind::HeapObject, ArrayStorageMode::FastObject),
        (ElementKind::Packed, ArrayStorageMode::Dense),
    ];
    for (i, (kind, mode)) in modes.iter().enumerate() {
        let profile = enrichment_profile(&format!("fast_path_{}", i), *kind, *mode);
        let cert = certify_fast_lane(&profile, &default_config());
        assert!(
            cert.decision.is_fast_lane,
            "Expected fast lane for {:?}/{:?}",
            kind, mode
        );
    }
}

#[test]
fn enrichment_certify_all_non_fast_path_modes_deopt() {
    let non_fast_modes = [ArrayStorageMode::Sparse, ArrayStorageMode::Dictionary];
    for (i, mode) in non_fast_modes.iter().enumerate() {
        let profile =
            enrichment_profile(&format!("non_fast_{}", i), ElementKind::SmiInteger, *mode);
        let cert = certify_fast_lane(&profile, &default_config());
        assert!(!cert.decision.is_fast_lane, "Expected deopt for {:?}", mode);
    }
}

#[test]
fn enrichment_evaluate_then_validate_workflow() {
    // First validate a typed array, then evaluate the related profile
    for kind in TypedArrayKind::ALL {
        let elem_size = compute_element_size(kind);
        let count = 8u64;
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
    // Corresponding profile evaluation
    let profile = smi_fast_profile("post_validate");
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

// ---------------------------------------------------------------------------
// Millionths fixed-point boundary verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_millionths_zero_means_zero_percent() {
    let mut profile = smi_fast_profile("zero_pct");
    profile.fast_lane_hits_millionths = 0;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(!decision.is_fast_lane);
}

#[test]
fn enrichment_millionths_1m_means_hundred_percent() {
    let mut profile = smi_fast_profile("hundred_pct");
    profile.fast_lane_hits_millionths = 1_000_000;
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
}

#[test]
fn enrichment_config_growth_factor_2x_in_millionths() {
    let config = default_config();
    // 2x growth factor = 2_000_000 millionths
    assert_eq!(config.growth_factor_millionths, 2_000_000);
    assert_eq!(config.growth_factor_millionths / 1_000_000, 2);
}

// ---------------------------------------------------------------------------
// Misc edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_transitions_vec_serde_roundtrip() {
    let transitions: Vec<ElementTransition> = Vec::new();
    let json = serde_json::to_string(&transitions).unwrap();
    assert_eq!(json, "[]");
    let back: Vec<ElementTransition> = serde_json::from_str(&json).unwrap();
    assert!(back.is_empty());
}

#[test]
fn enrichment_profile_with_long_id() {
    let long_id = "a".repeat(1024);
    let profile = ArrayProfile {
        id: long_id.clone(),
        total_accesses: 100,
        fast_lane_hits_millionths: 950_000,
        transitions: Vec::new(),
        current_kind: ElementKind::SmiInteger,
        current_mode: ArrayStorageMode::FastSmi,
    };
    let decision = evaluate_fast_lane(&profile, &default_config());
    assert!(decision.is_fast_lane);
    assert_eq!(decision.array_id, long_id);
}

#[test]
fn enrichment_profile_with_unicode_id() {
    let profile = ArrayProfile {
        id: "\u{1F600}\u{1F4A9}".into(),
        total_accesses: 100,
        fast_lane_hits_millionths: 950_000,
        transitions: Vec::new(),
        current_kind: ElementKind::SmiInteger,
        current_mode: ArrayStorageMode::FastSmi,
    };
    let cert = certify_fast_lane(&profile, &default_config());
    assert_eq!(cert.array_id, "\u{1F600}\u{1F4A9}");
    // Hash should still be deterministic
    let cert2 = certify_fast_lane(&profile, &default_config());
    assert_eq!(cert.certificate_hash, cert2.certificate_hash);
}

#[test]
fn enrichment_deopt_reason_as_str_all_nonempty() {
    for reason in DeoptReason::ALL {
        assert!(!reason.as_str().is_empty());
    }
}

#[test]
fn enrichment_transition_trigger_as_str_all_nonempty() {
    for trigger in TransitionTrigger::ALL {
        assert!(!trigger.as_str().is_empty());
    }
}

#[test]
fn enrichment_element_kind_as_str_all_nonempty() {
    for kind in ElementKind::ALL {
        assert!(!kind.as_str().is_empty());
    }
}

#[test]
fn enrichment_typed_array_kind_as_str_all_nonempty() {
    for kind in TypedArrayKind::ALL {
        assert!(!kind.as_str().is_empty());
    }
}

#[test]
fn enrichment_storage_mode_as_str_all_nonempty() {
    for mode in ArrayStorageMode::ALL {
        assert!(!mode.as_str().is_empty());
    }
}

#[test]
fn enrichment_packed_transitions_include_smi_reverse() {
    let targets = allowed_transitions(ElementKind::Packed);
    assert!(targets.contains(&ElementKind::SmiInteger));
    // And Packed can reach HeapNumber, HeapObject, Hole too
    assert!(targets.contains(&ElementKind::HeapNumber));
    assert!(targets.contains(&ElementKind::HeapObject));
    assert!(targets.contains(&ElementKind::Hole));
}

#[test]
fn enrichment_smi_cannot_transition_to_string() {
    let targets = allowed_transitions(ElementKind::SmiInteger);
    assert!(!targets.contains(&ElementKind::String));
}

#[test]
fn enrichment_string_cannot_transition_to_smi() {
    let targets = allowed_transitions(ElementKind::String);
    assert!(!targets.contains(&ElementKind::SmiInteger));
    assert!(!targets.contains(&ElementKind::HeapNumber));
    assert!(!targets.contains(&ElementKind::Packed));
}

#[test]
fn enrichment_heap_number_cannot_transition_to_smi_or_string() {
    let targets = allowed_transitions(ElementKind::HeapNumber);
    assert!(!targets.contains(&ElementKind::SmiInteger));
    assert!(!targets.contains(&ElementKind::String));
    assert!(!targets.contains(&ElementKind::Packed));
}

#[test]
fn enrichment_decision_json_deopt_reason_null_when_none() {
    let d = FastLaneDecision {
        array_id: "null_test".into(),
        storage_mode: ArrayStorageMode::FastSmi,
        element_kind: ElementKind::SmiInteger,
        is_fast_lane: true,
        deopt_reason: None,
    };
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("\"deopt_reason\":null"));
}

#[test]
fn enrichment_decision_json_deopt_reason_present_when_some() {
    let d = FastLaneDecision {
        array_id: "some_test".into(),
        storage_mode: ArrayStorageMode::Sparse,
        element_kind: ElementKind::Hole,
        is_fast_lane: false,
        deopt_reason: Some(DeoptReason::Megamorphic),
    };
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("\"deopt_reason\":\"megamorphic\""));
}
