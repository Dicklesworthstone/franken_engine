//! Integration tests for the typed-array fast-lane module (RGC-606C).

use frankenengine_engine::typed_array_fast_lane::{
    ArrayProfile, ArrayStorageMode, DeoptReason, ElementKind, ElementTransition, FastLaneConfig,
    FastLaneCertificate, FastLaneError, FastLaneEvidenceManifest,
    TransitionTrigger, TypedArrayKind, TypedArrayValidation, TYPED_ARRAY_COMPONENT,
    TYPED_ARRAY_POLICY_ID, TYPED_ARRAY_SCHEMA_VERSION, allowed_transitions,
    build_transition_graph, certify_fast_lane, compute_element_size, evaluate_fast_lane,
    is_transition_reversible, run_fast_lane_evidence, validate_typed_array,
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
    assert_eq!(validate_typed_array(&v).unwrap_err(), FastLaneError::DetachedBuffer);
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
    assert!(FastLaneError::DetachedBuffer.to_string().contains("detached"));
    assert!(FastLaneError::OverflowProtection.to_string().contains("overflow"));
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
