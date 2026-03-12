#![forbid(unsafe_code)]

//! Enrichment integration tests for scalar_replacement_engine [RGC-622B].

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

use frankenengine_engine::escape_analysis_certificate::{
    AliasClassId, AllocationKind, AllocationSite, EscapeCertificate, EscapeState,
    InvalidationReason, LivenessEnvelope, OptimizationEligibilityEnvelope,
};
use frankenengine_engine::scalar_replacement_engine::{
    self, AllocationSinkingPlan, DeoptTrigger, FieldDescriptor, FieldLayout, FieldSource,
    FieldSourceKind, MaterializationRecipe, RegionPromotionPlan, RegionScope, SRE_COMPONENT,
    SRE_EVENT_SCHEMA_VERSION, SRE_MANIFEST_SCHEMA_VERSION, SRE_SCHEMA_VERSION, ScalarField,
    ScalarFieldType, ScalarReplacementConfig, SideEffectBarrier, SideEffectKind, SreEvent,
    SreEventKind, SreEventLog, SreEvidenceInventory, SreExpectedOutcome, SreSpecimen,
    SreSpecimenEvidence, SreSpecimenFamily, SreVerdict, TransformDenialReason, TransformKind,
    TransformSummary,
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
        invalidation_reasons: vec![InvalidationReason::DynamicEval],
        abstention: true,
        certificate_hash: format!("hash_{id}"),
    }
}

fn make_layout(site_id: &str, field_count: usize) -> FieldLayout {
    let fields: Vec<FieldDescriptor> = (0..field_count)
        .map(|i| FieldDescriptor {
            name: format!("field_{i}"),
            field_type: if i % 2 == 0 {
                ScalarFieldType::Number
            } else {
                ScalarFieldType::StringRef
            },
            always_initialized: true,
            nesting_depth: 0,
        })
        .collect();
    FieldLayout {
        site_id: site_id.to_string(),
        fields,
        layout_sealed: true,
    }
}

fn make_envelope(certs: Vec<EscapeCertificate>) -> OptimizationEligibilityEnvelope {
    let len = certs.len() as u64;
    OptimizationEligibilityEnvelope {
        schema_version: "v1".to_string(),
        scope_id: "test_scope".to_string(),
        total_sites: len,
        scalar_replacement_count: 0,
        stack_allocation_count: 0,
        abstention_count: 0,
        alias_class_count: len,
        certificates: certs,
        overall_confidence_millionths: 800_000,
        epoch: epoch(),
        envelope_hash: "env_hash".to_string(),
    }
}

fn default_config() -> ScalarReplacementConfig {
    ScalarReplacementConfig::default()
}

// ---------------------------------------------------------------------------
// Display uniqueness across all enums
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transform_kind_display_strings_unique() {
    let strs: BTreeSet<&str> = TransformKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), TransformKind::ALL.len());
}

#[test]
fn enrichment_deopt_trigger_display_strings_unique() {
    let strs: BTreeSet<&str> = DeoptTrigger::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(strs.len(), DeoptTrigger::ALL.len());
}

#[test]
fn enrichment_sre_specimen_family_display_strings_unique() {
    let strs: BTreeSet<&str> = SreSpecimenFamily::ALL.iter().map(|f| f.as_str()).collect();
    assert_eq!(strs.len(), SreSpecimenFamily::ALL.len());
}

#[test]
fn enrichment_region_scope_display_strings_unique() {
    let scopes = [
        RegionScope::FunctionLocal,
        RegionScope::BlockLocal,
        RegionScope::LoopIteration,
        RegionScope::CallerManaged,
    ];
    let strs: BTreeSet<&str> = scopes.iter().map(|s| s.as_str()).collect();
    assert_eq!(strs.len(), scopes.len());
}

#[test]
fn enrichment_side_effect_kind_display_strings_unique() {
    let kinds = [
        SideEffectKind::Call,
        SideEffectKind::PropertyStore,
        SideEffectKind::ExceptionThrow,
        SideEffectKind::YieldAwait,
        SideEffectKind::DebuggerStatement,
    ];
    let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), kinds.len());
}

#[test]
fn enrichment_field_source_kind_display_strings_unique() {
    let kinds = [
        FieldSourceKind::Register,
        FieldSourceKind::StackSlot,
        FieldSourceKind::Constant,
        FieldSourceKind::RegionSlot,
    ];
    let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), kinds.len());
}

#[test]
fn enrichment_scalar_field_type_display_strings_unique() {
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
    let strs: BTreeSet<&str> = types.iter().map(|t| t.as_str()).collect();
    assert_eq!(strs.len(), types.len());
}

#[test]
fn enrichment_transform_denial_reason_display_strings_unique() {
    let reasons = [
        TransformDenialReason::CertificateAbstained,
        TransformDenialReason::EscapeBeyondScope,
        TransformDenialReason::TooManyFields,
        TransformDenialReason::DecompositionTooDeep,
        TransformDenialReason::NonDecomposableFields,
        TransformDenialReason::LivenessUnknown,
        TransformDenialReason::RegionScopeUnavailable,
        TransformDenialReason::SideEffectBarrier,
        TransformDenialReason::BudgetExhausted,
        TransformDenialReason::KindNotEligible,
    ];
    let strs: BTreeSet<&str> = reasons.iter().map(|r| r.as_str()).collect();
    assert_eq!(strs.len(), reasons.len());
}

#[test]
fn enrichment_sre_event_kind_display_strings_unique() {
    let kinds = [
        SreEventKind::PipelineStarted,
        SreEventKind::TransformSelected,
        SreEventKind::TransformDenied,
        SreEventKind::DeoptWitnessEmitted,
        SreEventKind::ValidationReceiptEmitted,
        SreEventKind::PipelineCompleted,
        SreEventKind::BudgetExhausted,
    ];
    let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), kinds.len());
}

// ---------------------------------------------------------------------------
// Serde roundtrips for struct types not covered by base tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sre_event_serde_roundtrip() {
    let event = SreEvent {
        schema_version: SRE_EVENT_SCHEMA_VERSION.to_string(),
        kind: SreEventKind::TransformSelected,
        scope_id: "scope_a".to_string(),
        site_id: Some("site_1".to_string()),
        transform_kind: Some(TransformKind::ScalarReplacement),
        detail: "selected scalar replacement".to_string(),
        epoch: epoch(),
        event_hash: "evt_hash_1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SreEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn enrichment_sre_event_none_fields_serde() {
    let event = SreEvent {
        schema_version: SRE_EVENT_SCHEMA_VERSION.to_string(),
        kind: SreEventKind::PipelineStarted,
        scope_id: "scope_b".to_string(),
        site_id: None,
        transform_kind: None,
        detail: "pipeline start".to_string(),
        epoch: epoch(),
        event_hash: "evt_hash_2".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SreEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.site_id, None);
    assert_eq!(back.transform_kind, None);
}

#[test]
fn enrichment_sre_event_log_serde_roundtrip() {
    let mut log = SreEventLog::new();
    log.push(SreEvent {
        schema_version: SRE_EVENT_SCHEMA_VERSION.to_string(),
        kind: SreEventKind::PipelineStarted,
        scope_id: "s".to_string(),
        site_id: None,
        transform_kind: None,
        detail: "start".to_string(),
        epoch: epoch(),
        event_hash: "h1".to_string(),
    });
    log.push(SreEvent {
        schema_version: SRE_EVENT_SCHEMA_VERSION.to_string(),
        kind: SreEventKind::PipelineCompleted,
        scope_id: "s".to_string(),
        site_id: None,
        transform_kind: None,
        detail: "done".to_string(),
        epoch: epoch(),
        event_hash: "h2".to_string(),
    });
    let json = serde_json::to_string(&log).unwrap();
    let back: SreEventLog = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
}

#[test]
fn enrichment_sre_specimen_serde_roundtrip() {
    let specimen = SreSpecimen {
        specimen_id: "spec_1".to_string(),
        description: "test transform selection".to_string(),
        family: SreSpecimenFamily::TransformSelection,
        expected_outcome: SreExpectedOutcome::TransformSelected,
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: SreSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(back, specimen);
}

#[test]
fn enrichment_sre_specimen_evidence_serde_roundtrip() {
    let evidence = SreSpecimenEvidence {
        specimen_id: "spec_1".to_string(),
        family: SreSpecimenFamily::ScalarPlanning,
        expected_outcome: SreExpectedOutcome::PlanBuilt,
        verdict: SreVerdict::Pass,
        actual_outcome: "plan built with 3 fields".to_string(),
        error_detail: None,
        evidence_hash: "ev_hash_1".to_string(),
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: SreSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evidence);
}

#[test]
fn enrichment_sre_specimen_evidence_with_error_serde() {
    let evidence = SreSpecimenEvidence {
        specimen_id: "spec_2".to_string(),
        family: SreSpecimenFamily::DenialClassification,
        expected_outcome: SreExpectedOutcome::TransformDenied,
        verdict: SreVerdict::Fail,
        actual_outcome: "unexpected pass".to_string(),
        error_detail: Some("expected denial but got approval".to_string()),
        evidence_hash: "ev_hash_2".to_string(),
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: SreSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(
        back.error_detail,
        Some("expected denial but got approval".to_string())
    );
}

#[test]
fn enrichment_sre_evidence_inventory_serde_roundtrip() {
    let mut family_cov = BTreeMap::new();
    family_cov.insert("transform_selection".to_string(), 3);
    family_cov.insert("scalar_planning".to_string(), 2);
    let inv = SreEvidenceInventory {
        schema_version: SRE_SCHEMA_VERSION.to_string(),
        component: SRE_COMPONENT.to_string(),
        specimen_count: 5,
        pass_count: 5,
        fail_count: 0,
        family_coverage: family_cov,
        evidence: vec![],
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: SreEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(back.specimen_count, 5);
    assert_eq!(back.family_coverage.len(), 2);
    assert!(back.contract_satisfied());
}

#[test]
fn enrichment_region_promotion_plan_serde_roundtrip() {
    let plan = RegionPromotionPlan {
        site_id: "rp_1".to_string(),
        region_scope: RegionScope::BlockLocal,
        estimated_size_bytes: 128,
        alignment_bytes: 16,
        containing_scope: "block_0".to_string(),
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: RegionPromotionPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(back, plan);
}

#[test]
fn enrichment_allocation_sinking_plan_serde_roundtrip() {
    let plan = AllocationSinkingPlan {
        site_id: "sk_1".to_string(),
        original_position: 0,
        sunk_position: 15,
        instructions_saved: 15,
        conditional: true,
        trigger_condition: Some("branch_to_use_at_15".to_string()),
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: AllocationSinkingPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(back, plan);
}

#[test]
fn enrichment_allocation_sinking_plan_unconditional_serde() {
    let plan = AllocationSinkingPlan {
        site_id: "sk_2".to_string(),
        original_position: 0,
        sunk_position: 0,
        instructions_saved: 0,
        conditional: false,
        trigger_condition: None,
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: AllocationSinkingPlan = serde_json::from_str(&json).unwrap();
    assert!(!back.conditional);
    assert_eq!(back.trigger_condition, None);
}

#[test]
fn enrichment_materialization_recipe_serde_roundtrip() {
    let recipe = MaterializationRecipe {
        site_id: "mat_1".to_string(),
        allocation_kind: AllocationKind::ObjectLiteral,
        field_sources: vec![
            FieldSource {
                name: "x".to_string(),
                source_kind: FieldSourceKind::Register,
                source_index: 0,
                field_type: ScalarFieldType::Number,
            },
            FieldSource {
                name: "y".to_string(),
                source_kind: FieldSourceKind::StackSlot,
                source_index: 1,
                field_type: ScalarFieldType::ObjectRef,
            },
        ],
        prototype_source: Some("object_prototype".to_string()),
        estimated_cost_millionths: 20_000,
    };
    let json = serde_json::to_string(&recipe).unwrap();
    let back: MaterializationRecipe = serde_json::from_str(&json).unwrap();
    assert_eq!(back, recipe);
}

#[test]
fn enrichment_field_source_serde_roundtrip() {
    let fs = FieldSource {
        name: "count".to_string(),
        source_kind: FieldSourceKind::Constant,
        source_index: 42,
        field_type: ScalarFieldType::Boolean,
    };
    let json = serde_json::to_string(&fs).unwrap();
    let back: FieldSource = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fs);
}

#[test]
fn enrichment_field_layout_serde_roundtrip() {
    let layout = make_layout("fl_test", 3);
    let json = serde_json::to_string(&layout).unwrap();
    let back: FieldLayout = serde_json::from_str(&json).unwrap();
    assert_eq!(back, layout);
}

#[test]
fn enrichment_field_descriptor_serde_roundtrip() {
    let fd = FieldDescriptor {
        name: "inner".to_string(),
        field_type: ScalarFieldType::SymbolRef,
        always_initialized: false,
        nesting_depth: 2,
    };
    let json = serde_json::to_string(&fd).unwrap();
    let back: FieldDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fd);
}

#[test]
fn enrichment_side_effect_barrier_serde_roundtrip() {
    let barrier = SideEffectBarrier {
        instruction_index: 99,
        effect_kind: SideEffectKind::YieldAwait,
        description: "await expression".to_string(),
    };
    let json = serde_json::to_string(&barrier).unwrap();
    let back: SideEffectBarrier = serde_json::from_str(&json).unwrap();
    assert_eq!(back, barrier);
}

// ---------------------------------------------------------------------------
// Deopt witness trigger set per allocation kind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_deopt_witness_array_literal_triggers() {
    let cert = make_cert(
        "arr1",
        AllocationKind::ArrayLiteral,
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
    // ArrayLiteral should include StructuralEnumeration
    assert!(
        witness
            .trigger_set
            .contains(&DeoptTrigger::StructuralEnumeration)
    );
    // But NOT IdentityComparison
    assert!(
        !witness
            .trigger_set
            .contains(&DeoptTrigger::IdentityComparison)
    );
    // Always includes ExternalInspection and DebugBreakpoint
    assert!(
        witness
            .trigger_set
            .contains(&DeoptTrigger::ExternalInspection)
    );
    assert!(witness.trigger_set.contains(&DeoptTrigger::DebugBreakpoint));
}

#[test]
fn enrichment_deopt_witness_spread_array_triggers() {
    let cert = make_cert(
        "spread1",
        AllocationKind::SpreadArray,
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
    assert!(
        witness
            .trigger_set
            .contains(&DeoptTrigger::StructuralEnumeration)
    );
    assert!(
        !witness
            .trigger_set
            .contains(&DeoptTrigger::IdentityComparison)
    );
}

#[test]
fn enrichment_deopt_witness_constructor_call_triggers() {
    let cert = make_cert(
        "ctor1",
        AllocationKind::ConstructorCall,
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
    assert!(
        witness
            .trigger_set
            .contains(&DeoptTrigger::IdentityComparison)
    );
    assert!(
        witness
            .trigger_set
            .contains(&DeoptTrigger::StructuralEnumeration)
    );
    assert!(witness.trigger_set.contains(&DeoptTrigger::TypeCheck));
}

#[test]
fn enrichment_deopt_witness_prototype_source_per_kind() {
    // ConstructorCall → "constructor_prototype"
    let ctor = make_cert(
        "ps1",
        AllocationKind::ConstructorCall,
        EscapeState::NoEscape,
        true,
        true,
    );
    let w1 = scalar_replacement_engine::build_deopt_witness(
        &ctor,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    assert_eq!(
        w1.materialization_recipe.prototype_source,
        Some("constructor_prototype".to_string())
    );

    // ObjectLiteral → "object_prototype"
    let obj = make_cert(
        "ps2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let w2 = scalar_replacement_engine::build_deopt_witness(
        &obj,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    assert_eq!(
        w2.materialization_recipe.prototype_source,
        Some("object_prototype".to_string())
    );

    // Closure → None
    let closure = make_cert(
        "ps3",
        AllocationKind::Closure,
        EscapeState::NoEscape,
        true,
        true,
    );
    let w3 = scalar_replacement_engine::build_deopt_witness(
        &closure,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    assert_eq!(w3.materialization_recipe.prototype_source, None);
}

#[test]
fn enrichment_deopt_witness_materialization_cost_proportional_to_fields() {
    let cert = make_cert(
        "mc1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let fields_2: Vec<ScalarField> = (0..2)
        .map(|i| ScalarField {
            name: format!("f{i}"),
            offset: i as u32,
            field_type: ScalarFieldType::Number,
            always_initialized: true,
            default_value: None,
        })
        .collect();
    let fields_5: Vec<ScalarField> = (0..5)
        .map(|i| ScalarField {
            name: format!("f{i}"),
            offset: i as u32,
            field_type: ScalarFieldType::Number,
            always_initialized: true,
            default_value: None,
        })
        .collect();
    let w2 = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &fields_2,
        epoch(),
    );
    let w5 = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &fields_5,
        epoch(),
    );
    assert!(
        w5.materialization_recipe.estimated_cost_millionths
            > w2.materialization_recipe.estimated_cost_millionths
    );
}

#[test]
fn enrichment_deopt_witness_field_source_kind_assignment() {
    let cert = make_cert(
        "fsk1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let fields = vec![
        ScalarField {
            name: "a".to_string(),
            offset: 0,
            field_type: ScalarFieldType::Number,
            always_initialized: true,
            default_value: None,
        },
        ScalarField {
            name: "b".to_string(),
            offset: 1,
            field_type: ScalarFieldType::ObjectRef,
            always_initialized: true,
            default_value: None,
        },
        ScalarField {
            name: "c".to_string(),
            offset: 2,
            field_type: ScalarFieldType::Boolean,
            always_initialized: true,
            default_value: None,
        },
        ScalarField {
            name: "d".to_string(),
            offset: 3,
            field_type: ScalarFieldType::BigIntRef,
            always_initialized: true,
            default_value: None,
        },
    ];
    let witness = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &fields,
        epoch(),
    );
    let sources = &witness.materialization_recipe.field_sources;
    assert_eq!(sources.len(), 4);
    // Number → Register (register-safe)
    assert_eq!(sources[0].source_kind, FieldSourceKind::Register);
    // ObjectRef → StackSlot (not register-safe)
    assert_eq!(sources[1].source_kind, FieldSourceKind::StackSlot);
    // Boolean → Register
    assert_eq!(sources[2].source_kind, FieldSourceKind::Register);
    // BigIntRef → StackSlot
    assert_eq!(sources[3].source_kind, FieldSourceKind::StackSlot);
}

// ---------------------------------------------------------------------------
// build_sinking_plan edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sinking_plan_first_use_zero_unconditional() {
    let mut cert = make_cert(
        "sk0",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        false,
    );
    cert.liveness = LivenessEnvelope {
        first_use: Some(0),
        last_use: Some(10),
        precise: true,
    };
    let plan = scalar_replacement_engine::build_sinking_plan(&cert, &[]).unwrap();
    assert!(!plan.conditional);
    assert_eq!(plan.trigger_condition, None);
    assert_eq!(plan.sunk_position, 0);
}

#[test]
fn enrichment_sinking_plan_multiple_barriers_picks_latest() {
    let mut cert = make_cert(
        "skm",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        false,
    );
    cert.liveness = LivenessEnvelope {
        first_use: Some(30),
        last_use: Some(50),
        precise: true,
    };
    let barriers = vec![
        SideEffectBarrier {
            instruction_index: 5,
            effect_kind: SideEffectKind::Call,
            description: "b1".to_string(),
        },
        SideEffectBarrier {
            instruction_index: 15,
            effect_kind: SideEffectKind::PropertyStore,
            description: "b2".to_string(),
        },
        SideEffectBarrier {
            instruction_index: 25,
            effect_kind: SideEffectKind::ExceptionThrow,
            description: "b3".to_string(),
        },
    ];
    let plan = scalar_replacement_engine::build_sinking_plan(&cert, &barriers).unwrap();
    // Should sink to just after the latest barrier before first_use (25 + 1 = 26)
    assert_eq!(plan.sunk_position, 26);
}

#[test]
fn enrichment_sinking_plan_barrier_at_first_use_boundary() {
    let mut cert = make_cert(
        "skb",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        false,
    );
    cert.liveness = LivenessEnvelope {
        first_use: Some(10),
        last_use: Some(20),
        precise: true,
    };
    // Barrier exactly at first_use — should not be "before first_use"
    let barriers = vec![SideEffectBarrier {
        instruction_index: 10,
        effect_kind: SideEffectKind::Call,
        description: "at boundary".to_string(),
    }];
    let plan = scalar_replacement_engine::build_sinking_plan(&cert, &barriers).unwrap();
    // Barrier at 10 is not < 10, so no blocking barrier applies → sunk to first_use
    assert_eq!(plan.sunk_position, 10);
}

// ---------------------------------------------------------------------------
// build_scalar_plan edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scalar_plan_uninitialized_field_gets_default() {
    let cert = make_cert(
        "sp_ui",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = FieldLayout {
        site_id: "sp_ui".to_string(),
        fields: vec![
            FieldDescriptor {
                name: "init".to_string(),
                field_type: ScalarFieldType::Number,
                always_initialized: true,
                nesting_depth: 0,
            },
            FieldDescriptor {
                name: "lazy".to_string(),
                field_type: ScalarFieldType::Boolean,
                always_initialized: false,
                nesting_depth: 0,
            },
        ],
        layout_sealed: true,
    };
    let config = default_config();
    let plan = scalar_replacement_engine::build_scalar_plan(&cert, &layout, &config).unwrap();
    assert_eq!(plan.fields[0].default_value, None);
    assert_eq!(plan.fields[1].default_value, Some("undefined".to_string()));
}

#[test]
fn enrichment_scalar_plan_decomposition_depth_tracked() {
    let cert = make_cert(
        "sp_dd",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = FieldLayout {
        site_id: "sp_dd".to_string(),
        fields: vec![
            FieldDescriptor {
                name: "top".to_string(),
                field_type: ScalarFieldType::Number,
                always_initialized: true,
                nesting_depth: 0,
            },
            FieldDescriptor {
                name: "mid".to_string(),
                field_type: ScalarFieldType::Number,
                always_initialized: true,
                nesting_depth: 2,
            },
            FieldDescriptor {
                name: "deep".to_string(),
                field_type: ScalarFieldType::Number,
                always_initialized: true,
                nesting_depth: 3,
            },
        ],
        layout_sealed: true,
    };
    let config = default_config();
    let plan = scalar_replacement_engine::build_scalar_plan(&cert, &layout, &config).unwrap();
    assert_eq!(plan.decomposition_depth, 3);
}

#[test]
fn enrichment_scalar_plan_empty_fields() {
    let cert = make_cert(
        "sp_ef",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = FieldLayout {
        site_id: "sp_ef".to_string(),
        fields: vec![],
        layout_sealed: true,
    };
    let config = default_config();
    let plan = scalar_replacement_engine::build_scalar_plan(&cert, &layout, &config).unwrap();
    assert_eq!(plan.fields.len(), 0);
    assert_eq!(plan.register_slots, 0);
    assert_eq!(plan.stack_slots, 0);
    assert!(plan.fully_register_safe); // 0 stack slots
    assert_eq!(plan.decomposition_depth, 0);
}

#[test]
fn enrichment_scalar_plan_estimated_savings_uses_cert_size() {
    let mut cert = make_cert(
        "sp_es",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    cert.site.estimated_size_bytes = Some(256);
    let layout = make_layout("sp_es", 2);
    let plan =
        scalar_replacement_engine::build_scalar_plan(&cert, &layout, &default_config()).unwrap();
    assert_eq!(plan.estimated_savings_bytes, 256);
}

#[test]
fn enrichment_scalar_plan_no_size_estimate_defaults_to_64() {
    let mut cert = make_cert(
        "sp_ns",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    cert.site.estimated_size_bytes = None;
    let layout = make_layout("sp_ns", 2);
    let plan =
        scalar_replacement_engine::build_scalar_plan(&cert, &layout, &default_config()).unwrap();
    assert_eq!(plan.estimated_savings_bytes, 64);
}

// ---------------------------------------------------------------------------
// Config customization
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_custom_max_fields() {
    let cert = make_cert(
        "cf1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = make_layout("cf1", 5);
    let mut config = default_config();
    config.max_fields = 3; // Only 3 fields allowed
    let result = scalar_replacement_engine::build_scalar_plan(&cert, &layout, &config);
    assert_eq!(result.unwrap_err(), TransformDenialReason::TooManyFields);
}

#[test]
fn enrichment_config_custom_decomposition_depth() {
    let cert = make_cert(
        "cf2",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let layout = FieldLayout {
        site_id: "cf2".to_string(),
        fields: vec![FieldDescriptor {
            name: "nested".to_string(),
            field_type: ScalarFieldType::Number,
            always_initialized: true,
            nesting_depth: 2,
        }],
        layout_sealed: true,
    };
    let mut config = default_config();
    config.max_decomposition_depth = 1; // Max depth 1
    let result = scalar_replacement_engine::build_scalar_plan(&cert, &layout, &config);
    assert_eq!(
        result.unwrap_err(),
        TransformDenialReason::DecompositionTooDeep
    );
}

#[test]
fn enrichment_config_sinking_disabled() {
    let mut cert = make_cert(
        "cf3",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        false,
    );
    cert.liveness = LivenessEnvelope {
        first_use: Some(10),
        last_use: Some(30),
        precise: true,
    };
    let mut config = default_config();
    config.enable_allocation_sinking = false;
    config.enable_region_promotion = false;
    let (kind, denial) = scalar_replacement_engine::select_transform(&cert, None, &[], &config, 0);
    assert_eq!(kind, TransformKind::NoTransform);
    assert!(denial.is_some());
}

#[test]
fn enrichment_config_region_disabled_skips_to_sinking() {
    let cert = make_cert(
        "cf4",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        false,
        true,
    );
    let mut config = default_config();
    config.enable_region_promotion = false;
    config.enable_allocation_sinking = true;
    let (kind, _) = scalar_replacement_engine::select_transform(&cert, None, &[], &config, 0);
    // With region disabled, should try sinking
    assert_eq!(kind, TransformKind::AllocationSinking);
}

// ---------------------------------------------------------------------------
// Execute transforms — sinking path
// ---------------------------------------------------------------------------

#[test]
fn enrichment_execute_transforms_sinking_path() {
    let mut cert = make_cert(
        "ets1",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        false,
    );
    cert.liveness = LivenessEnvelope {
        first_use: Some(10),
        last_use: Some(30),
        precise: true,
    };
    let envelope = make_envelope(vec![cert]);
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &config,
        epoch(),
    );
    assert_eq!(summary.total_sites, 1);
    assert_eq!(summary.allocation_sinking_count, 1);
    assert_eq!(
        summary.outcomes[0].transform_kind,
        TransformKind::AllocationSinking
    );
    assert!(summary.outcomes[0].sinking_plan.is_some());
    assert!(summary.outcomes[0].deopt_witness.is_some());
    assert!(summary.outcomes[0].validation_receipt.is_some());
}

#[test]
fn enrichment_execute_transforms_denial_histogram_populated() {
    let cert1 = make_abstained_cert("dh1");
    let cert2 = make_abstained_cert("dh2");
    let cert3 = make_abstained_cert("dh3");
    let envelope = make_envelope(vec![cert1, cert2, cert3]);
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &config,
        epoch(),
    );
    assert_eq!(summary.no_transform_count, 3);
    // All 3 should be denied for certificate_abstained
    let abstained_count = summary
        .denial_histogram
        .get("certificate_abstained")
        .copied()
        .unwrap_or(0);
    assert_eq!(abstained_count, 3);
}

#[test]
fn enrichment_execute_transforms_budget_exhaustion() {
    // Create many certs to exhaust budget (default 128)
    let certs: Vec<EscapeCertificate> = (0..130)
        .map(|i| {
            make_cert(
                &format!("be_{i}"),
                AllocationKind::ObjectLiteral,
                EscapeState::NoEscape,
                true,
                true,
            )
        })
        .collect();
    let envelope = make_envelope(certs);
    let mut layouts = BTreeMap::new();
    for i in 0..130 {
        layouts.insert(format!("be_{i}"), make_layout(&format!("be_{i}"), 2));
    }
    let config = default_config();
    let summary = scalar_replacement_engine::execute_transforms(
        &envelope,
        &layouts,
        &BTreeMap::new(),
        &config,
        epoch(),
    );
    assert_eq!(summary.total_sites, 130);
    // First 128 should succeed, last 2 denied
    assert_eq!(summary.scalar_replacement_count, 128);
    assert_eq!(summary.no_transform_count, 2);
    let budget_exhausted = summary
        .denial_histogram
        .get("budget_exhausted")
        .copied()
        .unwrap_or(0);
    assert_eq!(budget_exhausted, 2);
}

#[test]
fn enrichment_transform_summary_rate_full_transform() {
    let summary = TransformSummary {
        schema_version: SRE_SCHEMA_VERSION.to_string(),
        scope_id: "full".to_string(),
        total_sites: 5,
        scalar_replacement_count: 3,
        region_promotion_count: 1,
        allocation_sinking_count: 1,
        no_transform_count: 0,
        total_bytes_saved: 320,
        outcomes: vec![],
        denial_histogram: BTreeMap::new(),
        epoch: epoch(),
        summary_hash: "hash".to_string(),
    };
    // 5/5 = 1.0 = 1_000_000 millionths
    assert_eq!(summary.transform_rate_millionths(), 1_000_000);
}

// ---------------------------------------------------------------------------
// Hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_deopt_witness_hash_changes_with_site_id() {
    let cert_a = make_cert(
        "hsa",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let cert_b = make_cert(
        "hsb",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let w_a = scalar_replacement_engine::build_deopt_witness(
        &cert_a,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    let w_b = scalar_replacement_engine::build_deopt_witness(
        &cert_b,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    assert_ne!(w_a.witness_hash, w_b.witness_hash);
}

#[test]
fn enrichment_deopt_witness_hash_changes_with_transform_kind() {
    let cert = make_cert(
        "htk",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let w_sr = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::ScalarReplacement,
        &[],
        epoch(),
    );
    let w_rp = scalar_replacement_engine::build_deopt_witness(
        &cert,
        TransformKind::RegionPromotion,
        &[],
        epoch(),
    );
    assert_ne!(w_sr.witness_hash, w_rp.witness_hash);
}

#[test]
fn enrichment_validation_receipt_hash_changes_with_pre_hash() {
    let cert = make_cert(
        "vrph",
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
        "pre_A",
        "post",
        epoch(),
    );
    let r2 = scalar_replacement_engine::build_validation_receipt(
        &cert,
        TransformKind::ScalarReplacement,
        &witness,
        "pre_B",
        "post",
        epoch(),
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_validation_receipt_hash_changes_with_post_hash() {
    let cert = make_cert(
        "vrpo",
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
        "post_X",
        epoch(),
    );
    let r2 = scalar_replacement_engine::build_validation_receipt(
        &cert,
        TransformKind::ScalarReplacement,
        &witness,
        "pre",
        "post_Y",
        epoch(),
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_summary_hash_changes_with_scope() {
    let cert = make_cert(
        "sh1",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        true,
        true,
    );
    let env1 = {
        let mut e = make_envelope(vec![cert.clone()]);
        e.scope_id = "scope_A".to_string();
        e
    };
    let env2 = {
        let mut e = make_envelope(vec![cert]);
        e.scope_id = "scope_B".to_string();
        e
    };
    let mut layouts = BTreeMap::new();
    layouts.insert("sh1".to_string(), make_layout("sh1", 2));
    let config = default_config();
    let s1 = scalar_replacement_engine::execute_transforms(
        &env1,
        &layouts,
        &BTreeMap::new(),
        &config,
        epoch(),
    );
    let s2 = scalar_replacement_engine::execute_transforms(
        &env2,
        &layouts,
        &BTreeMap::new(),
        &config,
        epoch(),
    );
    assert_ne!(s1.summary_hash, s2.summary_hash);
}

// ---------------------------------------------------------------------------
// build_region_plan edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_region_plan_thread_escape_conservative_fallback() {
    let cert = make_cert(
        "rp_te",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        true,
    );
    let plan = scalar_replacement_engine::build_region_plan(&cert);
    // ThreadEscape gets conservative FunctionLocal
    assert_eq!(plan.region_scope, RegionScope::FunctionLocal);
}

#[test]
fn enrichment_region_plan_no_size_estimate_defaults_to_64() {
    let mut cert = make_cert(
        "rp_ns",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        false,
        true,
    );
    cert.site.estimated_size_bytes = None;
    let plan = scalar_replacement_engine::build_region_plan(&cert);
    assert_eq!(plan.estimated_size_bytes, 64);
}

#[test]
fn enrichment_region_plan_alignment_default_8() {
    let cert = make_cert(
        "rp_al",
        AllocationKind::ObjectLiteral,
        EscapeState::NoEscape,
        false,
        true,
    );
    let plan = scalar_replacement_engine::build_region_plan(&cert);
    assert_eq!(plan.alignment_bytes, 8);
}

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_prefix() {
    assert!(SRE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SRE_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SRE_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_constants_schema_versions_are_distinct() {
    let versions: BTreeSet<&str> = [
        SRE_SCHEMA_VERSION,
        SRE_MANIFEST_SCHEMA_VERSION,
        SRE_EVENT_SCHEMA_VERSION,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(versions.len(), 3);
}

// ---------------------------------------------------------------------------
// SreEventKind serde roundtrip (missing from base tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sre_event_kind_serde_roundtrip() {
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
        let json = serde_json::to_string(k).unwrap();
        let back: SreEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *k);
    }
}

// ---------------------------------------------------------------------------
// Validation receipt additional checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validation_receipt_schema_version_matches_constant() {
    let cert = make_cert(
        "vrc",
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
        "pre",
        "post",
        epoch(),
    );
    assert_eq!(receipt.schema_version, SRE_SCHEMA_VERSION);
    assert_eq!(receipt.certificate_hash, cert.certificate_hash);
    assert_eq!(receipt.witness_hash, witness.witness_hash);
    assert_eq!(receipt.pre_transform_hash, "pre");
    assert_eq!(receipt.post_transform_hash, "post");
}

// ---------------------------------------------------------------------------
// select_transform — sinking span threshold
// ---------------------------------------------------------------------------

#[test]
fn enrichment_select_transform_sinking_span_too_short() {
    let mut cert = make_cert(
        "ss1",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        false,
    );
    // Span of 2 < default min_sinking_span (5)
    cert.liveness = LivenessEnvelope {
        first_use: Some(3),
        last_use: Some(5),
        precise: true,
    };
    let config = default_config();
    let (kind, _) = scalar_replacement_engine::select_transform(&cert, None, &[], &config, 0);
    // Span too short, liveness known → falls through to denial
    assert_eq!(kind, TransformKind::NoTransform);
}

#[test]
fn enrichment_select_transform_custom_min_sinking_span() {
    let mut cert = make_cert(
        "ss2",
        AllocationKind::ObjectLiteral,
        EscapeState::ThreadEscape,
        false,
        false,
    );
    cert.liveness = LivenessEnvelope {
        first_use: Some(3),
        last_use: Some(5),
        precise: true,
    };
    let mut config = default_config();
    config.min_sinking_span = 2; // Lower the threshold
    let (kind, _) = scalar_replacement_engine::select_transform(&cert, None, &[], &config, 0);
    assert_eq!(kind, TransformKind::AllocationSinking);
}
