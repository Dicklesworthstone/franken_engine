#![forbid(unsafe_code)]

//! Integration tests for the scalar replacement engine [RGC-622B].

use std::collections::BTreeMap;

use frankenengine_engine::escape_analysis_certificate::{
    AliasClassId, AllocationKind, AllocationSite, EscapeCertificate, EscapeState,
    InvalidationReason, LivenessEnvelope, OptimizationEligibilityEnvelope,
};
use frankenengine_engine::scalar_replacement_engine::{
    self, DeoptTrigger, DeoptWitness, FieldDescriptor, FieldLayout, FieldSourceKind, RegionScope,
    SRE_COMPONENT, SRE_EVENT_SCHEMA_VERSION, SRE_MANIFEST_SCHEMA_VERSION, SRE_POLICY_ID,
    SRE_SCHEMA_VERSION, ScalarField, ScalarFieldType, ScalarReplacementConfig,
    ScalarReplacementPlan, SideEffectBarrier, SideEffectKind, SreEventKind, SreEventLog,
    SreEvidenceInventory, SreExpectedOutcome, SreSpecimenFamily, SreVerdict, TransformDenialReason,
    TransformKind, TransformOutcome, TransformSummary, TranslationValidationReceipt,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_site(id: &str, kind: AllocationKind) -> AllocationSite {
    AllocationSite {
        site_id: id.to_string(),
        scope: "test_fn".to_string(),
        allocation_kind: kind,
        estimated_size_bytes: Some(64),
    }
}

fn make_cert(
    id: &str,
    kind: AllocationKind,
    escape: EscapeState,
    scalar_eligible: bool,
    stack_eligible: bool,
) -> EscapeCertificate {
    EscapeCertificate {
        schema_version: "v1".to_string(),
        site: make_site(id, kind),
        escape_state: escape,
        alias_class: AliasClassId::new(&format!("class_{id}")),
        liveness: LivenessEnvelope {
            first_use: Some(5),
            last_use: Some(20),
            precise: true,
        },
        scalar_replacement_eligible: scalar_eligible,
        stack_allocation_eligible: stack_eligible,
        confidence_millionths: 800_000,
        invalidation_reasons: vec![],
        abstention: false,
        certificate_hash: format!("hash_{id}"),
    }
}

fn make_abstained_cert(id: &str) -> EscapeCertificate {
    EscapeCertificate {
        schema_version: "v1".to_string(),
        site: make_site(id, AllocationKind::ObjectLiteral),
        escape_state: EscapeState::GlobalEscape,
        alias_class: AliasClassId::new(&format!("class_{id}")),
        liveness: LivenessEnvelope {
            first_use: None,
            last_use: None,
            precise: false,
        },
        scalar_replacement_eligible: false,
        stack_allocation_eligible: false,
        confidence_millionths: 0,
        invalidation_reasons: vec![],
        abstention: true,
        certificate_hash: format!("hash_{id}"),
    }
}

fn simple_layout(site_id: &str) -> FieldLayout {
    FieldLayout {
        fields: vec![
            FieldDescriptor {
                name: "x".to_string(),
                field_type: ScalarFieldType::Number,
                nesting_depth: 0,
                always_initialized: true,
            },
            FieldDescriptor {
                name: "y".to_string(),
                field_type: ScalarFieldType::Number,
                nesting_depth: 0,
                always_initialized: true,
            },
        ],
        total_size_bytes: 16,
        layout_sealed: true,
        site_id: site_id.to_string(),
    }
}

fn make_envelope(certs: Vec<EscapeCertificate>) -> OptimizationEligibilityEnvelope {
    OptimizationEligibilityEnvelope {
        scope_id: "test_scope".to_string(),
        certificates: certs,
        epoch: epoch(),
        envelope_hash: "env_hash".to_string(),
    }
}

fn default_config() -> ScalarReplacementConfig {
    ScalarReplacementConfig::default()
}

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_non_empty() {
    assert!(!SRE_SCHEMA_VERSION.is_empty());
    assert!(!SRE_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!SRE_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn component_and_policy_non_empty() {
    assert!(!SRE_COMPONENT.is_empty());
    assert!(!SRE_POLICY_ID.is_empty());
    assert!(SRE_POLICY_ID.starts_with("RGC-"));
}

#[test]
fn schema_versions_contain_module_name() {
    assert!(SRE_SCHEMA_VERSION.contains("scalar_replacement_engine"));
    assert!(SRE_MANIFEST_SCHEMA_VERSION.contains("scalar_replacement_engine"));
    assert!(SRE_EVENT_SCHEMA_VERSION.contains("scalar_replacement_engine"));
}

// ---------------------------------------------------------------------------
// TransformKind
// ---------------------------------------------------------------------------

#[test]
fn transform_kind_all_covers_all_variants() {
    assert_eq!(TransformKind::ALL.len(), 4);
    assert!(TransformKind::ALL.contains(&TransformKind::ScalarReplacement));
    assert!(TransformKind::ALL.contains(&TransformKind::RegionPromotion));
    assert!(TransformKind::ALL.contains(&TransformKind::AllocationSinking));
    assert!(TransformKind::ALL.contains(&TransformKind::NoTransform));
}

#[test]
fn transform_kind_as_str_roundtrip() {
    for kind in TransformKind::ALL {
        let s = kind.as_str();
        assert!(!s.is_empty());
        assert_eq!(format!("{kind}"), s);
    }
}

#[test]
fn transform_kind_serde_roundtrip() {
    for kind in TransformKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: TransformKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *kind);
    }
}

#[test]
fn transform_kind_ordering() {
    assert!(TransformKind::ScalarReplacement < TransformKind::NoTransform);
}

// ---------------------------------------------------------------------------
// ScalarFieldType
// ---------------------------------------------------------------------------

#[test]
fn scalar_field_type_register_safety() {
    assert!(ScalarFieldType::Number.is_register_safe());
    assert!(ScalarFieldType::Boolean.is_register_safe());
    assert!(ScalarFieldType::Undefined.is_register_safe());
    assert!(ScalarFieldType::Null.is_register_safe());
    assert!(!ScalarFieldType::StringRef.is_register_safe());
    assert!(!ScalarFieldType::ObjectRef.is_register_safe());
    assert!(!ScalarFieldType::SymbolRef.is_register_safe());
    assert!(!ScalarFieldType::BigIntRef.is_register_safe());
}

#[test]
fn scalar_field_type_serde_roundtrip() {
    let types = [
        ScalarFieldType::Number,
        ScalarFieldType::Boolean,
        ScalarFieldType::StringRef,
        ScalarFieldType::ObjectRef,
        ScalarFieldType::Undefined,
        ScalarFieldType::Null,
        ScalarFieldType::SymbolRef,
        ScalarFieldType::BigIntRef,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let back: ScalarFieldType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *t);
    }
}

#[test]
fn scalar_field_type_display_non_empty() {
    let types = [
        ScalarFieldType::Number,
        ScalarFieldType::Boolean,
        ScalarFieldType::StringRef,
    ];
    for t in &types {
        assert!(!t.as_str().is_empty());
        assert_eq!(format!("{t}"), t.as_str());
    }
}

// ---------------------------------------------------------------------------
// ScalarField
// ---------------------------------------------------------------------------

#[test]
fn scalar_field_serde_roundtrip() {
    let field = ScalarField {
        name: "count".to_string(),
        offset: 8,
        field_type: ScalarFieldType::Number,
        always_initialized: true,
        default_value: Some("0".to_string()),
    };
    let json = serde_json::to_string(&field).unwrap();
    let back: ScalarField = serde_json::from_str(&json).unwrap();
    assert_eq!(back, field);
}

// ---------------------------------------------------------------------------
// ScalarReplacementPlan
// ---------------------------------------------------------------------------

#[test]
fn scalar_replacement_plan_total_slots() {
    let plan = ScalarReplacementPlan {
        site_id: "s1".to_string(),
        fields: vec![],
        register_slots: 3,
        stack_slots: 2,
        decomposition_depth: 1,
        fully_register_safe: false,
        estimated_savings_bytes: 64,
    };
    assert_eq!(plan.total_slots(), 5);
}

#[test]
fn scalar_replacement_plan_total_slots_overflow_saturates() {
    let plan = ScalarReplacementPlan {
        site_id: "s1".to_string(),
        fields: vec![],
        register_slots: u32::MAX,
        stack_slots: 1,
        decomposition_depth: 0,
        fully_register_safe: true,
        estimated_savings_bytes: 0,
    };
    assert_eq!(plan.total_slots(), u32::MAX);
}

// ---------------------------------------------------------------------------
// RegionScope
// ---------------------------------------------------------------------------

#[test]
fn region_scope_serde_roundtrip() {
    let scopes = [
        RegionScope::FunctionLocal,
        RegionScope::BlockLocal,
        RegionScope::LoopIteration,
        RegionScope::CallerManaged,
    ];
    for scope in &scopes {
        let json = serde_json::to_string(scope).unwrap();
        let back: RegionScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *scope);
    }
}

#[test]
fn region_scope_display() {
    assert_eq!(RegionScope::FunctionLocal.as_str(), "function_local");
    assert_eq!(format!("{}", RegionScope::BlockLocal), "block_local");
}

// ---------------------------------------------------------------------------
// DeoptTrigger
// ---------------------------------------------------------------------------

#[test]
fn deopt_trigger_serde_roundtrip() {
    let triggers = [
        DeoptTrigger::MissingProperty,
        DeoptTrigger::IdentityComparison,
        DeoptTrigger::ExternalInspection,
        DeoptTrigger::TypeCheck,
        DeoptTrigger::StructuralEnumeration,
        DeoptTrigger::ProxyTrap,
        DeoptTrigger::DebugBreakpoint,
        DeoptTrigger::ExceptionHandler,
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let back: DeoptTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *t);
    }
}

// ---------------------------------------------------------------------------
// FieldSourceKind
// ---------------------------------------------------------------------------

#[test]
fn field_source_kind_serde_roundtrip() {
    let kinds = [
        FieldSourceKind::Register,
        FieldSourceKind::StackSlot,
        FieldSourceKind::Constant,
        FieldSourceKind::Undefined,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: FieldSourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *k);
    }
}

// ---------------------------------------------------------------------------
// TransformDenialReason
// ---------------------------------------------------------------------------

#[test]
fn transform_denial_reason_as_str_non_empty() {
    let reasons = [
        TransformDenialReason::CertificateAbstained,
        TransformDenialReason::TooManyFields,
        TransformDenialReason::UnsealedLayout,
        TransformDenialReason::DecompositionTooDeep,
        TransformDenialReason::GloballyEscaped,
        TransformDenialReason::ThreadEscaped,
        TransformDenialReason::SideEffectBarrier,
        TransformDenialReason::BudgetExhausted,
        TransformDenialReason::NoSinkablePosition,
        TransformDenialReason::InsufficientConfidence,
    ];
    for r in &reasons {
        assert!(!r.as_str().is_empty());
    }
}

#[test]
fn transform_denial_reason_serde_roundtrip() {
    let reason = TransformDenialReason::TooManyFields;
    let json = serde_json::to_string(&reason).unwrap();
    let back: TransformDenialReason = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reason);
}

// ---------------------------------------------------------------------------
// SideEffectKind
// ---------------------------------------------------------------------------

#[test]
fn side_effect_kind_serde_roundtrip() {
    let kinds = [
        SideEffectKind::ExternalCall,
        SideEffectKind::PropertyStore,
        SideEffectKind::GlobalAccess,
        SideEffectKind::Throw,
        SideEffectKind::Yield,
        SideEffectKind::Await,
        SideEffectKind::DebuggerStatement,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: SideEffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *k);
    }
}

#[test]
fn side_effect_kind_as_str_non_empty() {
    for k in &[SideEffectKind::ExternalCall, SideEffectKind::Throw] {
        assert!(!k.as_str().is_empty());
    }
}

// ---------------------------------------------------------------------------
// select_transform — integration tests
// ---------------------------------------------------------------------------

#[test]
fn select_transform_abstained_cert_returns_no_transform() {
    let cert = make_abstained_cert("abs1");
    let config = default_config();
    let (kind, denial) = scalar_replacement_engine::select_transform(&cert, None, &[], &config, 0);
    assert_eq!(kind, TransformKind::NoTransform);
    assert_eq!(denial, Some(TransformDenialReason::CertificateAbstained));
}

#[test]
fn select_transform_scalar_eligible_with_layout() {
    let cert = make_cert(
        "s1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = simple_layout("s1");
    let config = default_config();
    let (kind, denial) =
        scalar_replacement_engine::select_transform(&cert, Some(&layout), &[], &config, 0);
    assert_eq!(kind, TransformKind::ScalarReplacement);
    assert!(denial.is_none());
}

#[test]
fn select_transform_scalar_eligible_without_layout_falls_to_region() {
    let cert = make_cert(
        "s2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let mut config = default_config();
    config.enable_region_promotion = true;
    let (kind, _) = scalar_replacement_engine::select_transform(&cert, None, &[], &config, 0);
    assert_eq!(kind, TransformKind::RegionPromotion);
}

#[test]
fn select_transform_global_escape_denied() {
    let cert = make_cert(
        "s3",
        AllocationKind::ObjectLiteral,
        EscapeState::GlobalEscape,
        false,
        false,
    );
    let config = default_config();
    let (kind, _) = scalar_replacement_engine::select_transform(&cert, None, &[], &config, 0);
    assert_eq!(kind, TransformKind::NoTransform);
}

#[test]
fn select_transform_too_many_fields_falls_to_region() {
    let cert = make_cert(
        "s4",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let mut layout = simple_layout("s4");
    // Add many fields beyond the default max
    for i in 0..100 {
        layout.fields.push(FieldDescriptor {
            name: format!("f{i}"),
            field_type: ScalarFieldType::Number,
            nesting_depth: 0,
            always_initialized: true,
        });
    }
    let mut config = default_config();
    config.enable_region_promotion = true;
    let (kind, _) =
        scalar_replacement_engine::select_transform(&cert, Some(&layout), &[], &config, 0);
    assert_eq!(kind, TransformKind::RegionPromotion);
}

#[test]
fn select_transform_unsealed_layout_falls_to_region() {
    let cert = make_cert(
        "s5",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let mut layout = simple_layout("s5");
    layout.layout_sealed = false;
    let mut config = default_config();
    config.enable_region_promotion = true;
    let (kind, _) =
        scalar_replacement_engine::select_transform(&cert, Some(&layout), &[], &config, 0);
    assert_eq!(kind, TransformKind::RegionPromotion);
}

// ---------------------------------------------------------------------------
// build_scalar_plan
// ---------------------------------------------------------------------------

#[test]
fn build_scalar_plan_simple_object() {
    let cert = make_cert(
        "bp1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = simple_layout("bp1");
    let config = default_config();
    let plan = scalar_replacement_engine::build_scalar_plan(&cert, &layout, &config);
    assert!(plan.is_ok());
    let plan = plan.unwrap();
    assert_eq!(plan.site_id, "bp1");
    assert_eq!(plan.fields.len(), 2);
    assert!(plan.estimated_savings_bytes > 0);
}

#[test]
fn build_scalar_plan_register_safe_fields() {
    let cert = make_cert(
        "bp2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = FieldLayout {
        fields: vec![FieldDescriptor {
            name: "n".to_string(),
            field_type: ScalarFieldType::Number,
            nesting_depth: 0,
            always_initialized: true,
        }],
        total_size_bytes: 8,
        layout_sealed: true,
        site_id: "bp2".to_string(),
    };
    let config = default_config();
    let plan = scalar_replacement_engine::build_scalar_plan(&cert, &layout, &config).unwrap();
    assert!(plan.fully_register_safe);
    assert!(plan.register_slots > 0);
}

// ---------------------------------------------------------------------------
// build_region_plan
// ---------------------------------------------------------------------------

#[test]
fn build_region_plan_produces_valid_plan() {
    let cert = make_cert(
        "rp1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        false,
        true,
    );
    let plan = scalar_replacement_engine::build_region_plan(&cert);
    assert_eq!(plan.site_id, "rp1");
    assert!(!plan.containing_scope.is_empty());
}

#[test]
fn build_region_plan_scope_matches_site() {
    let cert = make_cert(
        "rp2",
        AllocationKind::ArrayLiteral,
        EscapeState::ArgEscape,
        false,
        true,
    );
    let plan = scalar_replacement_engine::build_region_plan(&cert);
    assert_eq!(plan.site_id, "rp2");
}

// ---------------------------------------------------------------------------
// build_sinking_plan
// ---------------------------------------------------------------------------

#[test]
fn build_sinking_plan_no_barriers() {
    let cert = make_cert(
        "sk1",
        AllocationKind::ObjectLiteral,
        EscapeState::ArgEscape,
        false,
        false,
    );
    let plan = scalar_replacement_engine::build_sinking_plan(&cert, &[]);
    assert!(plan.is_ok());
    let plan = plan.unwrap();
    assert_eq!(plan.site_id, "sk1");
    assert!(plan.sunk_position >= plan.original_position);
}

#[test]
fn build_sinking_plan_with_barrier() {
    let cert = make_cert(
        "sk2",
        AllocationKind::ObjectLiteral,
        EscapeState::ArgEscape,
        false,
        false,
    );
    let barrier = SideEffectBarrier {
        instruction_index: 10,
        kind: SideEffectKind::ExternalCall,
        description: "call foo()".to_string(),
    };
    let result = scalar_replacement_engine::build_sinking_plan(&cert, &[barrier]);
    // With a barrier, the plan may succeed (sinking before barrier) or fail
    // depending on implementation — just check it doesn't panic
    let _ = result;
}

// ---------------------------------------------------------------------------
// build_deopt_witness
// ---------------------------------------------------------------------------

#[test]
fn build_deopt_witness_scalar_replacement() {
    let cert = make_cert(
        "dw1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let fields = vec![
        ScalarField {
            name: "x".to_string(),
            offset: 0,
            field_type: ScalarFieldType::Number,
            always_initialized: true,
            default_value: None,
        },
        ScalarField {
            name: "y".to_string(),
            offset: 8,
            field_type: ScalarFieldType::Boolean,
            always_initialized: false,
            default_value: Some("false".to_string()),
        },
    ];
    let witness = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &fields,
        epoch(),
    );
    assert_eq!(witness.site_id, "dw1");
    assert_eq!(witness.transform_kind, TransformKind::ScalarReplacement);
    assert!(!witness.witness_hash.is_empty());
    assert!(!witness.deopt_triggers.is_empty());
}

#[test]
fn build_deopt_witness_region_promotion() {
    let cert = make_cert(
        "dw2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        false,
        true,
    );
    let witness = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::RegionPromotion,
        &[],
        epoch(),
    );
    assert_eq!(witness.transform_kind, TransformKind::RegionPromotion);
    assert!(!witness.deopt_triggers.is_empty());
}

#[test]
fn build_deopt_witness_hash_deterministic() {
    let cert = make_cert(
        "dw3",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let w1 = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::AllocationSinking,
        &[],
        epoch(),
    );
    let w2 = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::AllocationSinking,
        &[],
        epoch(),
    );
    assert_eq!(w1.witness_hash, w2.witness_hash);
}

// ---------------------------------------------------------------------------
// build_validation_receipt
// ---------------------------------------------------------------------------

#[test]
fn build_validation_receipt_passes() {
    let cert = make_cert(
        "vr1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let witness = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    let receipt = scalar_replacement_engine::build_validation_receipt(
        &cert,
        TransformKind::ScalarReplacement,
        &witness,
        "pre_hash",
        "post_hash",
        epoch(),
    );
    assert!(receipt.validation_passed);
    assert!(receipt.failure_reason.is_none());
    assert!(!receipt.receipt_hash.is_empty());
}

#[test]
fn build_validation_receipt_hash_deterministic() {
    let cert = make_cert(
        "vr2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let witness = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    let r1 = scalar_replacement_engine::build_validation_receipt(
        &cert,
        TransformKind::ScalarReplacement,
        &witness,
        "pre",
        "post",
        epoch(),
    );
    let r2 = scalar_replacement_engine::build_validation_receipt(
        &cert,
        TransformKind::ScalarReplacement,
        &witness,
        "pre",
        "post",
        epoch(),
    );
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// execute_transforms — full pipeline
// ---------------------------------------------------------------------------

#[test]
fn execute_transforms_empty_envelope() {
    let envelope = make_envelope(vec![]);
    let layouts = BTreeMap::new();
    let barriers = BTreeMap::new();
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    assert_eq!(summary.total_sites, 0);
    assert_eq!(summary.scalar_replacement_count, 0);
    assert_eq!(summary.region_promotion_count, 0);
    assert_eq!(summary.allocation_sinking_count, 0);
    assert_eq!(summary.no_transform_count, 0);
    assert!(summary.outcomes.is_empty());
}

#[test]
fn execute_transforms_single_scalar_replacement() {
    let cert = make_cert(
        "et1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let envelope = make_envelope(vec![cert]);
    let mut layouts = BTreeMap::new();
    layouts.insert("et1".to_string(), simple_layout("et1"));
    let barriers = BTreeMap::new();
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    assert_eq!(summary.total_sites, 1);
    assert_eq!(summary.scalar_replacement_count, 1);
    assert_eq!(summary.outcomes.len(), 1);
    let outcome = &summary.outcomes[0];
    assert_eq!(outcome.transform_kind, TransformKind::ScalarReplacement);
    assert!(outcome.scalar_plan.is_some());
    assert!(outcome.deopt_witness.is_some());
    assert!(outcome.validation_receipt.is_some());
    assert!(outcome.estimated_bytes_saved > 0);
}

#[test]
fn execute_transforms_region_promotion_fallback() {
    let cert = make_cert(
        "et2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let envelope = make_envelope(vec![cert]);
    // No layout → falls back to region promotion
    let layouts = BTreeMap::new();
    let barriers = BTreeMap::new();
    let mut config = default_config();
    config.enable_region_promotion = true;
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    assert_eq!(summary.total_sites, 1);
    assert_eq!(summary.region_promotion_count, 1);
    assert_eq!(
        summary.outcomes[0].transform_kind,
        TransformKind::RegionPromotion
    );
    assert!(summary.outcomes[0].region_plan.is_some());
}

#[test]
fn execute_transforms_abstained_cert_no_transform() {
    let cert = make_abstained_cert("et3");
    let envelope = make_envelope(vec![cert]);
    let layouts = BTreeMap::new();
    let barriers = BTreeMap::new();
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    assert_eq!(summary.total_sites, 1);
    assert_eq!(summary.no_transform_count, 1);
    assert_eq!(
        summary.outcomes[0].denial_reason,
        Some(TransformDenialReason::CertificateAbstained)
    );
}

#[test]
fn execute_transforms_multiple_sites_mixed() {
    let cert1 = make_cert(
        "m1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let cert2 = make_cert(
        "m2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        false,
        true,
    );
    let cert3 = make_abstained_cert("m3");
    let envelope = make_envelope(vec![cert1, cert2, cert3]);
    let mut layouts = BTreeMap::new();
    layouts.insert("m1".to_string(), simple_layout("m1"));
    let barriers = BTreeMap::new();
    let mut config = default_config();
    config.enable_region_promotion = true;
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    assert_eq!(summary.total_sites, 3);
    assert!(summary.scalar_replacement_count >= 1);
    assert!(!summary.summary_hash.is_empty());
}

#[test]
fn execute_transforms_summary_hash_deterministic() {
    let cert = make_cert(
        "det1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let envelope = make_envelope(vec![cert.clone()]);
    let mut layouts = BTreeMap::new();
    layouts.insert("det1".to_string(), simple_layout("det1"));
    let barriers = BTreeMap::new();
    let config = default_config();
    let s1 = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    let envelope2 = make_envelope(vec![cert]);
    let s2 = scalar_replacement_engine::execute_transforms(
        &envelope2,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    assert_eq!(s1.summary_hash, s2.summary_hash);
}

#[test]
fn execute_transforms_bytes_saved_accumulates() {
    let cert1 = make_cert(
        "bs1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let cert2 = make_cert(
        "bs2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let envelope = make_envelope(vec![cert1, cert2]);
    let mut layouts = BTreeMap::new();
    layouts.insert("bs1".to_string(), simple_layout("bs1"));
    layouts.insert("bs2".to_string(), simple_layout("bs2"));
    let barriers = BTreeMap::new();
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &barriers,
        &config,
        epoch(),
    );
    assert!(summary.total_bytes_saved > 0);
    let individual_sum: u64 = summary
        .outcomes
        .iter()
        .map(|o| o.estimated_bytes_saved)
        .sum();
    assert_eq!(summary.total_bytes_saved, individual_sum);
}

#[test]
fn execute_transforms_transform_rate_non_negative() {
    let cert = make_cert(
        "tr1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let envelope = make_envelope(vec![cert]);
    let mut layouts = BTreeMap::new();
    layouts.insert("tr1".to_string(), simple_layout("tr1"));
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &BTreeMap::new(),
        &config,
        epoch(),
    );
    assert!(summary.transform_rate_millionths() >= 0);
}

// ---------------------------------------------------------------------------
// TransformSummary serde
// ---------------------------------------------------------------------------

#[test]
fn transform_summary_serde_roundtrip() {
    let cert = make_cert(
        "ts1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let envelope = make_envelope(vec![cert]);
    let mut layouts = BTreeMap::new();
    layouts.insert("ts1".to_string(), simple_layout("ts1"));
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &BTreeMap::new(),
        &config,
        epoch(),
    );
    let json = serde_json::to_string(&summary).unwrap();
    let back: TransformSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_sites, summary.total_sites);
    assert_eq!(back.summary_hash, summary.summary_hash);
}

// ---------------------------------------------------------------------------
// SreSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn sre_specimen_family_all_covered() {
    assert_eq!(SreSpecimenFamily::ALL.len(), 10);
    for fam in SreSpecimenFamily::ALL {
        assert!(!fam.as_str().is_empty());
        assert_eq!(format!("{fam}"), fam.as_str());
    }
}

#[test]
fn sre_specimen_family_serde_roundtrip() {
    for fam in SreSpecimenFamily::ALL {
        let json = serde_json::to_string(fam).unwrap();
        let back: SreSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *fam);
    }
}

// ---------------------------------------------------------------------------
// SreExpectedOutcome
// ---------------------------------------------------------------------------

#[test]
fn sre_expected_outcome_serde_roundtrip() {
    let outcomes = [
        SreExpectedOutcome::TransformSelected,
        SreExpectedOutcome::TransformDenied,
        SreExpectedOutcome::PlanBuilt,
        SreExpectedOutcome::PlanDenied,
        SreExpectedOutcome::WitnessConstructed,
        SreExpectedOutcome::ReceiptConstructed,
        SreExpectedOutcome::PipelineComplete,
        SreExpectedOutcome::BudgetExhausted,
        SreExpectedOutcome::RoundtripPreserved,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: SreExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *o);
    }
}

// ---------------------------------------------------------------------------
// SreVerdict
// ---------------------------------------------------------------------------

#[test]
fn sre_verdict_serde_roundtrip() {
    for v in &[SreVerdict::Pass, SreVerdict::Fail] {
        let json = serde_json::to_string(v).unwrap();
        let back: SreVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *v);
    }
}

// ---------------------------------------------------------------------------
// SreEvidenceInventory
// ---------------------------------------------------------------------------

#[test]
fn sre_evidence_inventory_contract_satisfied_pass() {
    let inv = SreEvidenceInventory {
        schema_version: SRE_SCHEMA_VERSION.to_string(),
        component: SRE_COMPONENT.to_string(),
        specimen_count: 5,
        pass_count: 5,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
}

#[test]
fn sre_evidence_inventory_contract_satisfied_fail_with_failures() {
    let inv = SreEvidenceInventory {
        schema_version: SRE_SCHEMA_VERSION.to_string(),
        component: SRE_COMPONENT.to_string(),
        specimen_count: 5,
        pass_count: 4,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn sre_evidence_inventory_contract_satisfied_fail_empty() {
    let inv = SreEvidenceInventory {
        schema_version: SRE_SCHEMA_VERSION.to_string(),
        component: SRE_COMPONENT.to_string(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

// ---------------------------------------------------------------------------
// SreEventKind
// ---------------------------------------------------------------------------

#[test]
fn sre_event_kind_display_all() {
    let kinds = [
        SreEventKind::PipelineStarted,
        SreEventKind::TransformSelected,
        SreEventKind::TransformDenied,
        SreEventKind::DeoptWitnessEmitted,
        SreEventKind::ValidationReceiptEmitted,
        SreEventKind::PipelineCompleted,
        SreEventKind::BudgetExhausted,
    ];
    for k in &kinds {
        assert!(!k.as_str().is_empty());
        assert_eq!(format!("{k}"), k.as_str());
    }
}

// ---------------------------------------------------------------------------
// SreEventLog
// ---------------------------------------------------------------------------

#[test]
fn sre_event_log_new_empty() {
    let log = SreEventLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn sre_event_log_default_empty() {
    let log = SreEventLog::default();
    assert!(log.is_empty());
}

#[test]
fn sre_event_log_push_and_len() {
    let mut log = SreEventLog::new();
    let event = frankenengine_engine::scalar_replacement_engine::SreEvent {
        schema_version: SRE_EVENT_SCHEMA_VERSION.to_string(),
        kind: SreEventKind::PipelineStarted,
        scope_id: "scope1".to_string(),
        site_id: None,
        transform_kind: None,
        detail: "started".to_string(),
        epoch: epoch(),
        event_hash: "hash1".to_string(),
    };
    log.push(event);
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());
}

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

#[test]
fn config_default_sensible() {
    let config = ScalarReplacementConfig::default();
    assert!(config.max_fields > 0);
    assert!(config.max_decomposition_depth > 0);
    assert!(config.confidence_threshold_millionths > 0);
    assert!(config.max_transforms_per_scope > 0);
}

#[test]
fn config_serde_roundtrip() {
    let config = ScalarReplacementConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ScalarReplacementConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.max_fields, config.max_fields);
    assert_eq!(
        back.confidence_threshold_millionths,
        config.confidence_threshold_millionths
    );
}

// ---------------------------------------------------------------------------
// TransformOutcome serde
// ---------------------------------------------------------------------------

#[test]
fn transform_outcome_no_transform_serde_roundtrip() {
    let outcome = TransformOutcome {
        site_id: "no1".to_string(),
        transform_kind: TransformKind::NoTransform,
        scalar_plan: None,
        region_plan: None,
        sinking_plan: None,
        deopt_witness: None,
        validation_receipt: None,
        denial_reason: Some(TransformDenialReason::CertificateAbstained),
        estimated_bytes_saved: 0,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: TransformOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back.site_id, "no1");
    assert_eq!(back.transform_kind, TransformKind::NoTransform);
    assert_eq!(
        back.denial_reason,
        Some(TransformDenialReason::CertificateAbstained)
    );
}

// ---------------------------------------------------------------------------
// Deopt witness serde
// ---------------------------------------------------------------------------

#[test]
fn deopt_witness_serde_roundtrip() {
    let cert = make_cert(
        "dws1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let witness = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    let json = serde_json::to_string(&witness).unwrap();
    let back: DeoptWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(back.witness_hash, witness.witness_hash);
}

// ---------------------------------------------------------------------------
// Validation receipt serde
// ---------------------------------------------------------------------------

#[test]
fn validation_receipt_serde_roundtrip() {
    let cert = make_cert(
        "vrs1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let witness = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    let receipt = scalar_replacement_engine::build_validation_receipt(
        &cert,
        TransformKind::ScalarReplacement,
        &witness,
        "pre_hash",
        "post_hash",
        epoch(),
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let back: TranslationValidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.receipt_hash, receipt.receipt_hash);
    assert!(back.validation_passed);
}

// ---------------------------------------------------------------------------
// Cross-module integration: escape cert → transform pipeline
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_escape_cert_to_scalar_replacement() {
    use frankenengine_engine::escape_analysis_certificate;
    let site = AllocationSite {
        site_id: "e2e1".to_string(),
        scope: "hot_fn".to_string(),
        allocation_kind: AllocationKind::ObjectLiteral,
        estimated_size_bytes: Some(32),
    };
    let envelope = escape_analysis_certificate::analyze_escape(
        "hot_fn",
        &[site],
        &[],
        &escape_analysis_certificate::EscapeAnalyzerConfig::default(),
        epoch(),
    );
    // The escape analysis should produce at least one certificate
    assert!(!envelope.certificates.is_empty());
    let cert = &envelope.certificates[0];
    // With no invalidation reasons, should be eligible for scalar replacement
    assert!(cert.scalar_replacement_eligible);

    // Now run the scalar replacement pipeline
    let mut layouts = BTreeMap::new();
    layouts.insert(
        "e2e1".to_string(),
        FieldLayout {
            fields: vec![FieldDescriptor {
                name: "value".to_string(),
                field_type: ScalarFieldType::Number,
                nesting_depth: 0,
                always_initialized: true,
            }],
            total_size_bytes: 8,
            layout_sealed: true,
            site_id: "e2e1".to_string(),
        },
    );
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &BTreeMap::new(),
        &default_config(),
        epoch(),
    );
    assert_eq!(summary.total_sites, 1);
    assert_eq!(summary.scalar_replacement_count, 1);
    assert!(summary.total_bytes_saved > 0);
}

#[test]
fn end_to_end_escape_cert_global_escape_denied() {
    use frankenengine_engine::escape_analysis_certificate;
    let site = AllocationSite {
        site_id: "e2e2".to_string(),
        scope: "leak_fn".to_string(),
        allocation_kind: AllocationKind::ObjectLiteral,
        estimated_size_bytes: Some(32),
    };
    let envelope = escape_analysis_certificate::analyze_escape(
        "leak_fn",
        &[site],
        &[("e2e2", InvalidationReason::EscapesToGlobal)],
        &escape_analysis_certificate::EscapeAnalyzerConfig::default(),
        epoch(),
    );
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &default_config(),
        epoch(),
    );
    assert_eq!(summary.total_sites, 1);
    assert_eq!(summary.no_transform_count, 1);
}
