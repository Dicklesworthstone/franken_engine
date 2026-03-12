//! Integration tests for orchestration_context_contract.
//!
//! Tests: canonical context threading, child derivation, cleanup carving,
//! budget consumption, mock seam validation, determinism, and serde.

use frankenengine_engine::orchestration_context_contract::{
    COMPONENT, CanonicalContextDescriptor, ContextError, ContextOrigin, ContextState,
    DerivationEvent, DerivationRule, MockSeamClassification, MockSeamEntry, SCHEMA_VERSION,
    ValidationReport, cancel_context, carve_cleanup_context, consume_budget, create_root_context,
    derive_child_context, release_context, validate_threading,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn root_ctx(id: &str, budget_ms: u64) -> CanonicalContextDescriptor {
    create_root_context(id.to_string(), format!("trace-{id}"), budget_ms, epoch(1))
}

fn default_rule() -> DerivationRule {
    DerivationRule::new("default".to_string())
}

fn strict_rule() -> DerivationRule {
    DerivationRule::strict("strict".to_string())
}

fn make_seam(id: &str, class: MockSeamClassification, remediated: bool) -> MockSeamEntry {
    MockSeamEntry {
        seam_id: id.to_string(),
        file_path: format!("src/{id}.rs"),
        line_number: 42,
        classification: class,
        description: format!("seam {id}"),
        remediated,
    }
}

// ---------------------------------------------------------------------------
// Root context creation
// ---------------------------------------------------------------------------

#[test]
fn integration_root_context_fields() {
    let ctx = root_ctx("root-1", 10_000);
    assert_eq!(ctx.context_id, "root-1");
    assert_eq!(ctx.trace_id, "trace-root-1");
    assert_eq!(ctx.origin, ContextOrigin::Root);
    assert_eq!(ctx.state, ContextState::Active);
    assert!(ctx.parent_id.is_none());
    assert_eq!(ctx.budget_ms, 10_000);
    assert_eq!(ctx.consumed_ms, 0);
    assert_eq!(ctx.depth, 0);
    assert!(ctx.can_derive_child());
}

#[test]
fn integration_root_context_hash_deterministic() {
    let c1 = root_ctx("det", 5000);
    let c2 = root_ctx("det", 5000);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn integration_root_context_zero_budget() {
    let ctx = root_ctx("zero", 0);
    assert_eq!(ctx.remaining_ms(), 0);
    assert!(!ctx.can_derive_child());
}

// ---------------------------------------------------------------------------
// Child derivation
// ---------------------------------------------------------------------------

#[test]
fn integration_derive_child_consumes_parent_budget() {
    let mut parent = root_ctx("parent", 10_000);
    let rule = default_rule();
    let (child, _) = derive_child_context(
        &mut parent,
        "child-1".to_string(),
        3000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    assert_eq!(parent.consumed_ms, 3000);
    assert_eq!(parent.remaining_ms(), 7000);
    assert_eq!(child.budget_ms, 3000);
    assert_eq!(child.depth, 1);
}

#[test]
fn integration_derive_multiple_children() {
    let mut parent = root_ctx("parent", 10_000);
    let rule = default_rule();
    let mut children = Vec::new();
    let mut events = Vec::new();
    for i in 0..3 {
        let (child, event) = derive_child_context(
            &mut parent,
            format!("child-{i}"),
            2000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap();
        children.push(child);
        events.push(event);
    }
    assert_eq!(parent.consumed_ms, 6000);
    assert_eq!(children.len(), 3);
    assert_eq!(events.len(), 3);
    // All children have depth 1.
    for child in &children {
        assert_eq!(child.depth, 1);
    }
}

#[test]
fn integration_derive_nested_children() {
    let mut root = root_ctx("root", 10_000);
    let rule = default_rule();
    let (mut child1, _) = derive_child_context(
        &mut root,
        "child-1".to_string(),
        5000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    let (grandchild, _) = derive_child_context(
        &mut child1,
        "grandchild-1".to_string(),
        2000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    assert_eq!(grandchild.depth, 2);
    assert_eq!(grandchild.parent_id, Some("child-1".to_string()));
}

#[test]
fn integration_derive_child_exceeds_budget_error() {
    let mut parent = root_ctx("parent", 1000);
    let rule = default_rule();
    let err = derive_child_context(
        &mut parent,
        "child".to_string(),
        2000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap_err();
    assert!(matches!(err, ContextError::InsufficientBudget { .. }));
    // Parent budget should NOT be consumed on error.
    assert_eq!(parent.consumed_ms, 0);
}

#[test]
fn integration_derive_child_exceeds_fraction_strict() {
    let mut parent = root_ctx("parent", 10_000);
    let rule = strict_rule();
    // Strict allows 50% = 5000ms.
    let err = derive_child_context(
        &mut parent,
        "child".to_string(),
        6000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ContextError::ChildExceedsAllowedFraction { .. }
    ));
}

#[test]
fn integration_derive_child_depth_limit() {
    let mut parent = root_ctx("parent", 100_000);
    parent.depth = 63; // One below max of 64.
    let rule = default_rule();
    let err = derive_child_context(
        &mut parent,
        "child".to_string(),
        100,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap_err();
    assert!(matches!(err, ContextError::DepthExceeded { .. }));
}

#[test]
fn integration_derive_child_trace_id_derived() {
    let mut parent = root_ctx("parent", 10_000);
    let rule = default_rule();
    let (child, _) = derive_child_context(
        &mut parent,
        "child".to_string(),
        5000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    assert!(child.trace_id.starts_with("trace-parent.child."));
}

// ---------------------------------------------------------------------------
// Cleanup carving
// ---------------------------------------------------------------------------

#[test]
fn integration_carve_cleanup_10_percent() {
    let mut parent = root_ctx("parent", 10_000);
    let rule = default_rule();
    let (cleanup, event) =
        carve_cleanup_context(&mut parent, "cleanup".to_string(), &rule).unwrap();
    assert_eq!(cleanup.origin, ContextOrigin::CleanupCarve);
    assert_eq!(cleanup.budget_ms, 1000); // 10% of 10_000
    assert_eq!(event.child_origin, ContextOrigin::CleanupCarve);
}

#[test]
fn integration_carve_cleanup_after_child() {
    let mut parent = root_ctx("parent", 10_000);
    let rule = default_rule();
    // Derive child first.
    let _ = derive_child_context(
        &mut parent,
        "child".to_string(),
        5000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    // Now carve cleanup from remaining 5000.
    let (cleanup, _) = carve_cleanup_context(&mut parent, "cleanup".to_string(), &rule).unwrap();
    assert_eq!(cleanup.budget_ms, 500); // 10% of remaining 5000
}

#[test]
fn integration_carve_cleanup_too_small() {
    let mut parent = root_ctx("parent", 5); // Very small budget.
    let rule = default_rule();
    let err = carve_cleanup_context(&mut parent, "cleanup".to_string(), &rule).unwrap_err();
    assert!(matches!(err, ContextError::InsufficientBudget { .. }));
}

// ---------------------------------------------------------------------------
// Budget consumption
// ---------------------------------------------------------------------------

#[test]
fn integration_consume_budget_incremental() {
    let mut ctx = root_ctx("ctx", 1000);
    consume_budget(&mut ctx, 200).unwrap();
    consume_budget(&mut ctx, 300).unwrap();
    assert_eq!(ctx.consumed_ms, 500);
    assert_eq!(ctx.remaining_ms(), 500);
    assert_eq!(ctx.state, ContextState::Active);
}

#[test]
fn integration_consume_budget_exact_exhaustion() {
    let mut ctx = root_ctx("ctx", 1000);
    consume_budget(&mut ctx, 1000).unwrap();
    assert_eq!(ctx.state, ContextState::Exhausted);
    assert!(!ctx.state.is_consumable());
}

#[test]
fn integration_consume_budget_over_exhaustion() {
    let mut ctx = root_ctx("ctx", 100);
    let err = consume_budget(&mut ctx, 200).unwrap_err();
    assert!(matches!(err, ContextError::InsufficientBudget { .. }));
    assert_eq!(ctx.state, ContextState::Exhausted);
}

#[test]
fn integration_consume_budget_after_release() {
    let mut ctx = root_ctx("ctx", 1000);
    release_context(&mut ctx);
    let err = consume_budget(&mut ctx, 100).unwrap_err();
    assert!(matches!(err, ContextError::NotConsumable { .. }));
}

#[test]
fn integration_consume_budget_after_cancel() {
    let mut ctx = root_ctx("ctx", 1000);
    cancel_context(&mut ctx);
    let err = consume_budget(&mut ctx, 100).unwrap_err();
    assert!(matches!(err, ContextError::NotConsumable { .. }));
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn integration_validate_empty_passes() {
    let report = validate_threading(&[], &[], &[], &default_rule(), epoch(1));
    assert!(report.passed);
    assert_eq!(report.contexts_validated, 0);
}

#[test]
fn integration_validate_healthy_hierarchy() {
    let mut root = root_ctx("root", 10_000);
    let rule = default_rule();
    let (child, ev) = derive_child_context(
        &mut root,
        "child".to_string(),
        3000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    let report = validate_threading(&[root, child], &[ev], &[], &rule, epoch(1));
    assert!(report.passed);
    assert_eq!(report.contexts_validated, 2);
    assert_eq!(report.derivations_checked, 1);
}

#[test]
fn integration_validate_mock_seam_fails() {
    let seam = make_seam(
        "prod-seam",
        MockSeamClassification::MustFixProduction,
        false,
    );
    let report = validate_threading(&[], &[], &[seam], &default_rule(), epoch(1));
    assert!(!report.passed);
    assert!(!report.mock_free);
    assert_eq!(report.production_seams_found, 1);
}

#[test]
fn integration_validate_remediated_seam_passes() {
    let seam = make_seam("prod-seam", MockSeamClassification::MustFixProduction, true);
    let report = validate_threading(&[], &[], &[seam], &default_rule(), epoch(1));
    assert!(report.passed);
    assert!(report.mock_free);
}

#[test]
fn integration_validate_test_only_seam_passes() {
    let seam = make_seam(
        "test-seam",
        MockSeamClassification::AcceptableTestOnly,
        false,
    );
    let report = validate_threading(&[], &[], &[seam], &default_rule(), epoch(1));
    assert!(report.passed);
    assert!(report.mock_free);
}

#[test]
fn integration_validate_mixed_seams() {
    let seams = vec![
        make_seam("good", MockSeamClassification::AcceptableTestOnly, false),
        make_seam("bad", MockSeamClassification::MustFixProduction, false),
        make_seam("fp", MockSeamClassification::FalsePositive, false),
    ];
    let report = validate_threading(&[], &[], &seams, &default_rule(), epoch(1));
    assert!(!report.passed);
    assert_eq!(report.production_seams_found, 1);
    assert_eq!(report.seams_audited, 3);
}

#[test]
fn integration_validate_report_hash_deterministic() {
    let r1 = validate_threading(&[], &[], &[], &default_rule(), epoch(1));
    let r2 = validate_threading(&[], &[], &[], &default_rule(), epoch(1));
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.report_id, r2.report_id);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn integration_serde_context_roundtrip() {
    let ctx = root_ctx("serde-ctx", 5000);
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: CanonicalContextDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

#[test]
fn integration_serde_origin_snake_case() {
    let origin = ContextOrigin::CleanupCarve;
    let json = serde_json::to_string(&origin).unwrap();
    assert_eq!(json, "\"cleanup_carve\"");
}

#[test]
fn integration_serde_state_snake_case() {
    let state = ContextState::Exhausted;
    let json = serde_json::to_string(&state).unwrap();
    assert_eq!(json, "\"exhausted\"");
}

#[test]
fn integration_serde_rule_roundtrip() {
    let rule = strict_rule();
    let json = serde_json::to_string(&rule).unwrap();
    let restored: DerivationRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, restored);
}

#[test]
fn integration_serde_validation_report_roundtrip() {
    let report = validate_threading(&[], &[], &[], &default_rule(), epoch(1));
    let json = serde_json::to_string(&report).unwrap();
    let restored: ValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn integration_serde_error_roundtrip() {
    let err = ContextError::DepthExceeded {
        parent_id: "p1".to_string(),
        depth: 65,
        max_depth: 64,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ContextError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn integration_e2e_orchestration_lifecycle() {
    let rule = default_rule();

    // 1. Create root context (orchestrator entry).
    let mut root = create_root_context(
        "orch-root".to_string(),
        "trace-orch-001".to_string(),
        50_000,
        epoch(10),
    );
    assert!(root.can_derive_child());

    // 2. Derive child cell context.
    let (mut cell_ctx, ev1) = derive_child_context(
        &mut root,
        "cell-1".to_string(),
        20_000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();

    // 3. Execute within cell context.
    consume_budget(&mut cell_ctx, 15_000).unwrap();
    assert_eq!(cell_ctx.remaining_ms(), 5000);

    // 4. Carve cleanup from cell context.
    let (mut cleanup, ev2) =
        carve_cleanup_context(&mut cell_ctx, "cell-1-cleanup".to_string(), &rule).unwrap();
    let cleanup_budget = cleanup.budget_ms;
    consume_budget(&mut cleanup, cleanup_budget).unwrap();
    assert_eq!(cleanup.state, ContextState::Exhausted);

    // 5. Release cell context.
    release_context(&mut cell_ctx);

    // 6. Carve orchestrator cleanup.
    let (mut orch_cleanup, ev3) =
        carve_cleanup_context(&mut root, "orch-cleanup".to_string(), &rule).unwrap();
    let orch_cleanup_budget = orch_cleanup.budget_ms;
    consume_budget(&mut orch_cleanup, orch_cleanup_budget).unwrap();
    release_context(&mut orch_cleanup);

    // 7. Release root.
    release_context(&mut root);

    // 8. Validate the entire threading.
    let contexts = vec![root, cell_ctx, cleanup, orch_cleanup];
    let events = vec![ev1, ev2, ev3];
    let report = validate_threading(&contexts, &events, &[], &rule, epoch(10));
    assert!(report.passed);
    assert_eq!(report.contexts_validated, 4);
    assert_eq!(report.derivations_checked, 3);
}

#[test]
fn integration_e2e_determinism() {
    let run = || {
        let mut root = root_ctx("root", 10_000);
        let rule = default_rule();
        let (child, ev) = derive_child_context(
            &mut root,
            "child".to_string(),
            5000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap();
        validate_threading(&[root, child], &[ev], &[], &rule, epoch(1))
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.passed, r2.passed);
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn integration_error_display_all_variants() {
    let errors: Vec<ContextError> = vec![
        ContextError::InsufficientBudget {
            parent_id: "p".to_string(),
            remaining_ms: 10,
            requested_ms: 20,
        },
        ContextError::DepthExceeded {
            parent_id: "p".to_string(),
            depth: 65,
            max_depth: 64,
        },
        ContextError::NotConsumable {
            context_id: "c".to_string(),
            state: ContextState::Released,
        },
        ContextError::ChildExceedsAllowedFraction {
            parent_id: "p".to_string(),
            child_budget_ms: 100,
            max_allowed_ms: 50,
        },
        ContextError::CleanupExceedsMaxFraction {
            parent_id: "p".to_string(),
            cleanup_ms: 100,
            max_allowed_ms: 50,
        },
        ContextError::MockSeamDetected {
            seam_id: "s".to_string(),
            file_path: "f.rs".to_string(),
        },
        ContextError::ContextNotFound("c".to_string()),
        ContextError::EmptyInput,
    ];
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.is_empty());
        assert!(s.contains(COMPONENT));
    }
}

// ---------------------------------------------------------------------------
// Display formats
// ---------------------------------------------------------------------------

#[test]
fn integration_display_all_types() {
    let ctx = root_ctx("disp", 1000);
    assert!(format!("{ctx}").contains("disp"));

    let rule = default_rule();
    assert!(format!("{rule}").contains("default"));

    let seam = make_seam("s1", MockSeamClassification::AcceptableTestOnly, false);
    assert!(format!("{seam}").contains("s1"));

    let report = validate_threading(&[], &[], &[], &rule, epoch(1));
    assert!(format!("{report}").contains("validation"));
}

// ---------------------------------------------------------------------------
// Serde round-trips — additional types
// ---------------------------------------------------------------------------

#[test]
fn integration_serde_derivation_event_roundtrip() {
    let mut parent = root_ctx("p1", 10_000);
    let rule = default_rule();
    let (_, event) = derive_child_context(
        &mut parent,
        "c1".to_string(),
        3000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    let json = serde_json::to_string(&event).unwrap();
    let restored: DerivationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn integration_serde_mock_seam_entry_roundtrip() {
    let seam = make_seam("s-rt", MockSeamClassification::UnderInvestigation, false);
    let json = serde_json::to_string(&seam).unwrap();
    let restored: MockSeamEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(seam, restored);
}

#[test]
fn integration_serde_mock_seam_classification_all_variants() {
    let variants = vec![
        (
            MockSeamClassification::MustFixProduction,
            "\"must_fix_production\"",
        ),
        (
            MockSeamClassification::AcceptableTestOnly,
            "\"acceptable_test_only\"",
        ),
        (MockSeamClassification::FalsePositive, "\"false_positive\""),
        (
            MockSeamClassification::UnderInvestigation,
            "\"under_investigation\"",
        ),
    ];
    for (variant, expected_json) in variants {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, expected_json, "serde mismatch for {variant:?}");
        let restored: MockSeamClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, restored);
    }
}

// ---------------------------------------------------------------------------
// Constants and enum method coverage
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("orchestration-context-contract"));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn integration_context_origin_as_str_and_display_all_variants() {
    let origins = vec![
        (ContextOrigin::Root, "root"),
        (ContextOrigin::ChildDerivation, "child_derivation"),
        (ContextOrigin::CleanupCarve, "cleanup_carve"),
        (ContextOrigin::CellClose, "cell_close"),
        (ContextOrigin::Replay, "replay"),
    ];
    for (origin, expected_str) in origins {
        assert_eq!(origin.as_str(), expected_str);
        assert_eq!(format!("{origin}"), expected_str);
        // All origins are production-safe by construction.
        assert!(origin.is_production_safe());
    }
}

#[test]
fn integration_context_state_as_str_and_display_all_variants() {
    let states = vec![
        (ContextState::Active, "active", true),
        (ContextState::Exhausted, "exhausted", false),
        (ContextState::Released, "released", false),
        (ContextState::Cancelled, "cancelled", false),
    ];
    for (state, expected_str, expected_consumable) in states {
        assert_eq!(state.as_str(), expected_str);
        assert_eq!(format!("{state}"), expected_str);
        assert_eq!(state.is_consumable(), expected_consumable);
    }
}

#[test]
fn integration_mock_seam_classification_production_safety() {
    assert!(!MockSeamClassification::MustFixProduction.is_production_safe());
    assert!(MockSeamClassification::AcceptableTestOnly.is_production_safe());
    assert!(MockSeamClassification::FalsePositive.is_production_safe());
    assert!(!MockSeamClassification::UnderInvestigation.is_production_safe());
}

// ---------------------------------------------------------------------------
// Budget fraction edge cases
// ---------------------------------------------------------------------------

#[test]
fn integration_consumed_fraction_zero_budget_returns_million() {
    let ctx = root_ctx("zero-frac", 0);
    // Zero budget means 100% consumed (MILLION = 1_000_000).
    assert_eq!(ctx.consumed_fraction_millionths(), 1_000_000);
}

#[test]
fn integration_consumed_fraction_partial() {
    let mut ctx = root_ctx("partial", 1000);
    consume_budget(&mut ctx, 250).unwrap();
    // 250 / 1000 = 25% = 250_000 millionths.
    assert_eq!(ctx.consumed_fraction_millionths(), 250_000);
}

// ---------------------------------------------------------------------------
// Derivation from non-active parent
// ---------------------------------------------------------------------------

#[test]
fn integration_derive_child_from_released_parent_fails() {
    let mut parent = root_ctx("rel-parent", 10_000);
    release_context(&mut parent);
    let rule = default_rule();
    let err = derive_child_context(
        &mut parent,
        "child".to_string(),
        1000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap_err();
    assert!(matches!(err, ContextError::NotConsumable { .. }));
    if let ContextError::NotConsumable { state, .. } = &err {
        assert_eq!(*state, ContextState::Released);
    }
}

// ---------------------------------------------------------------------------
// DerivationEvent display and hash determinism
// ---------------------------------------------------------------------------

#[test]
fn integration_derivation_event_display_format() {
    let mut parent = root_ctx("dp", 10_000);
    let rule = default_rule();
    let (_, event) = derive_child_context(
        &mut parent,
        "dc".to_string(),
        2000,
        ContextOrigin::ChildDerivation,
        &rule,
    )
    .unwrap();
    let display = format!("{event}");
    assert!(display.contains("dp"));
    assert!(display.contains("dc"));
    assert!(display.contains("2000"));
}

#[test]
fn integration_derivation_event_hash_deterministic() {
    let make = || {
        let mut parent = root_ctx("hp", 10_000);
        let rule = default_rule();
        let (_, event) = derive_child_context(
            &mut parent,
            "hc".to_string(),
            3000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap();
        event
    };
    let e1 = make();
    let e2 = make();
    assert_eq!(e1.content_hash, e2.content_hash);
    assert_eq!(e1.event_id, e2.event_id);
}

// ---------------------------------------------------------------------------
// Validation with invalid context depth
// ---------------------------------------------------------------------------

#[test]
fn integration_validate_context_exceeding_rule_depth() {
    let mut ctx = root_ctx("deep", 100_000);
    ctx.depth = 200; // Exceeds default max_depth of 64.
    let rule = default_rule();
    let report = validate_threading(&[ctx], &[], &[], &rule, epoch(1));
    assert!(!report.passed);
    assert!(!report.all_contexts_valid);
    assert!(!report.failure_reasons.is_empty());
    assert!(report.failure_reasons[0].contains("exceeds max depth"));
}

// ---------------------------------------------------------------------------
// Different context IDs produce different hashes
// ---------------------------------------------------------------------------

#[test]
fn integration_different_ids_produce_different_hashes() {
    let c1 = root_ctx("alpha", 5000);
    let c2 = root_ctx("beta", 5000);
    assert_ne!(c1.content_hash, c2.content_hash);
    assert_ne!(c1.context_id, c2.context_id);
}
