//! Enrichment integration tests for `orchestration_context_contract` module.
//!
//! Covers: ContextOrigin, ContextState, MockSeamClassification,
//! CanonicalContextDescriptor, DerivationRule, DerivationEvent,
//! MockSeamEntry, ValidationReport, ContextError,
//! create_root_context, derive_child_context, carve_cleanup_context,
//! consume_budget, release_context, cancel_context, validate_threading.

use std::collections::BTreeSet;

use frankenengine_engine::orchestration_context_contract::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ──────────────────────────────────────────────────────────────

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn root(id: &str, budget: u64) -> CanonicalContextDescriptor {
    create_root_context(id.into(), format!("trace-{id}"), budget, epoch(1))
}

fn rule() -> DerivationRule {
    DerivationRule::new("default".into())
}

// ── ContextOrigin ────────────────────────────────────────────────────────

#[test]
fn enrichment_context_origin_display_unique() {
    let origins = [
        ContextOrigin::Root,
        ContextOrigin::ChildDerivation,
        ContextOrigin::CleanupCarve,
        ContextOrigin::CellClose,
        ContextOrigin::Replay,
    ];
    let displays: BTreeSet<String> = origins.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_context_origin_as_str_matches_display() {
    for o in [
        ContextOrigin::Root,
        ContextOrigin::ChildDerivation,
        ContextOrigin::CleanupCarve,
        ContextOrigin::CellClose,
        ContextOrigin::Replay,
    ] {
        assert_eq!(o.as_str(), o.to_string());
    }
}

#[test]
fn enrichment_context_origin_serde_all() {
    for o in [
        ContextOrigin::Root,
        ContextOrigin::ChildDerivation,
        ContextOrigin::CleanupCarve,
        ContextOrigin::CellClose,
        ContextOrigin::Replay,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: ContextOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

#[test]
fn enrichment_context_origin_all_production_safe() {
    for o in [
        ContextOrigin::Root,
        ContextOrigin::ChildDerivation,
        ContextOrigin::CleanupCarve,
        ContextOrigin::CellClose,
        ContextOrigin::Replay,
    ] {
        assert!(o.is_production_safe());
    }
}

// ── ContextState ─────────────────────────────────────────────────────────

#[test]
fn enrichment_context_state_display_unique() {
    let states = [
        ContextState::Active,
        ContextState::Exhausted,
        ContextState::Released,
        ContextState::Cancelled,
    ];
    let displays: BTreeSet<String> = states.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_context_state_as_str_matches_display() {
    for s in [
        ContextState::Active,
        ContextState::Exhausted,
        ContextState::Released,
        ContextState::Cancelled,
    ] {
        assert_eq!(s.as_str(), s.to_string());
    }
}

#[test]
fn enrichment_context_state_serde_all() {
    for s in [
        ContextState::Active,
        ContextState::Exhausted,
        ContextState::Released,
        ContextState::Cancelled,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ContextState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_context_state_only_active_consumable() {
    assert!(ContextState::Active.is_consumable());
    assert!(!ContextState::Exhausted.is_consumable());
    assert!(!ContextState::Released.is_consumable());
    assert!(!ContextState::Cancelled.is_consumable());
}

// ── MockSeamClassification ──────────────────────────────────────────────

#[test]
fn enrichment_mock_seam_display_unique() {
    let classes = [
        MockSeamClassification::MustFixProduction,
        MockSeamClassification::AcceptableTestOnly,
        MockSeamClassification::FalsePositive,
        MockSeamClassification::UnderInvestigation,
    ];
    let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_mock_seam_serde_all() {
    for c in [
        MockSeamClassification::MustFixProduction,
        MockSeamClassification::AcceptableTestOnly,
        MockSeamClassification::FalsePositive,
        MockSeamClassification::UnderInvestigation,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: MockSeamClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn enrichment_mock_seam_production_safety() {
    assert!(!MockSeamClassification::MustFixProduction.is_production_safe());
    assert!(MockSeamClassification::AcceptableTestOnly.is_production_safe());
    assert!(MockSeamClassification::FalsePositive.is_production_safe());
    assert!(!MockSeamClassification::UnderInvestigation.is_production_safe());
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn enrichment_component_constant() {
    assert_eq!(COMPONENT, "orchestration_context_contract");
}

#[test]
fn enrichment_schema_version_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

// ── CanonicalContextDescriptor ──────────────────────────────────────────

#[test]
fn enrichment_root_context_fields() {
    let ctx = root("r1", 10_000);
    assert_eq!(ctx.context_id, "r1");
    assert_eq!(ctx.trace_id, "trace-r1");
    assert_eq!(ctx.origin, ContextOrigin::Root);
    assert_eq!(ctx.state, ContextState::Active);
    assert!(ctx.parent_id.is_none());
    assert_eq!(ctx.budget_ms, 10_000);
    assert_eq!(ctx.consumed_ms, 0);
    assert_eq!(ctx.depth, 0);
    assert_eq!(ctx.epoch, epoch(1));
}

#[test]
fn enrichment_remaining_ms() {
    let ctx = root("r", 5000);
    assert_eq!(ctx.remaining_ms(), 5000);
}

#[test]
fn enrichment_consumed_fraction_zero() {
    let ctx = root("r", 1000);
    assert_eq!(ctx.consumed_fraction_millionths(), 0);
}

#[test]
fn enrichment_consumed_fraction_half() {
    let mut ctx = root("r", 1000);
    consume_budget(&mut ctx, 500).unwrap();
    assert_eq!(ctx.consumed_fraction_millionths(), 500_000);
}

#[test]
fn enrichment_consumed_fraction_zero_budget() {
    let ctx = root("r", 0);
    assert_eq!(ctx.consumed_fraction_millionths(), 1_000_000);
}

#[test]
fn enrichment_can_derive_child_active_with_budget() {
    let ctx = root("r", 100);
    assert!(ctx.can_derive_child());
}

#[test]
fn enrichment_cannot_derive_child_zero_budget() {
    let ctx = root("r", 0);
    assert!(!ctx.can_derive_child());
}

#[test]
fn enrichment_cannot_derive_child_exhausted() {
    let mut ctx = root("r", 100);
    let _ = consume_budget(&mut ctx, 200); // exhausts
    assert!(!ctx.can_derive_child());
}

#[test]
fn enrichment_descriptor_display_contains_context_id() {
    let ctx = root("test-ctx", 5000);
    let s = ctx.to_string();
    assert!(s.contains("test-ctx"));
    assert!(s.contains("root"));
}

#[test]
fn enrichment_descriptor_serde_roundtrip() {
    let ctx = root("sr", 5000);
    let json = serde_json::to_string(&ctx).unwrap();
    let back: CanonicalContextDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn enrichment_descriptor_content_hash_deterministic() {
    let a = root("det", 1000);
    let b = root("det", 1000);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_descriptor_content_hash_varies() {
    let a = root("a", 1000);
    let b = root("b", 1000);
    assert_ne!(a.content_hash, b.content_hash);
}

// ── DerivationRule ──────────────────────────────────────────────────────

#[test]
fn enrichment_derivation_rule_new_defaults() {
    let r = DerivationRule::new("test".into());
    assert_eq!(r.rule_id, "test");
    assert_eq!(r.max_child_fraction_millionths, 900_000);
    assert_eq!(r.cleanup_fraction_millionths, 100_000);
    assert!(r.require_trace_derivation);
    assert_eq!(r.max_depth, 64);
}

#[test]
fn enrichment_derivation_rule_strict() {
    let r = DerivationRule::strict("strict".into());
    assert_eq!(r.max_child_fraction_millionths, 500_000);
    assert_eq!(r.max_depth, 16);
}

#[test]
fn enrichment_derivation_rule_display() {
    let r = rule();
    let s = r.to_string();
    assert!(s.contains("rule:default"));
}

#[test]
fn enrichment_derivation_rule_serde_roundtrip() {
    let r = rule();
    let json = serde_json::to_string(&r).unwrap();
    let back: DerivationRule = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_derivation_rule_hash_deterministic() {
    let a = DerivationRule::new("same".into());
    let b = DerivationRule::new("same".into());
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_derivation_rule_hash_varies() {
    let a = DerivationRule::new("a".into());
    let b = DerivationRule::new("b".into());
    assert_ne!(a.content_hash, b.content_hash);
}

// ── derive_child_context ────────────────────────────────────────────────

#[test]
fn enrichment_derive_child_basic() {
    let mut parent = root("p", 10_000);
    let r = rule();
    let (child, event) = derive_child_context(
        &mut parent,
        "c1".into(),
        5000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    assert_eq!(child.context_id, "c1");
    assert_eq!(child.budget_ms, 5000);
    assert_eq!(child.depth, 1);
    assert_eq!(child.parent_id, Some("p".into()));
    assert_eq!(parent.consumed_ms, 5000);
    assert_eq!(event.child_id, "c1");
}

#[test]
fn enrichment_derive_child_trace_inherited() {
    let mut parent = root("p", 10_000);
    let r = rule();
    let (child, _) = derive_child_context(
        &mut parent,
        "c".into(),
        1000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    assert!(child.trace_id.starts_with("trace-p.child."));
}

#[test]
fn enrichment_derive_child_depth_increases() {
    let mut parent = root("p", 10_000);
    let r = rule();
    let (mut child, _) = derive_child_context(
        &mut parent,
        "c1".into(),
        3000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    let (grandchild, _) = derive_child_context(
        &mut child,
        "gc1".into(),
        1000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    assert_eq!(grandchild.depth, 2);
}

#[test]
fn enrichment_derive_child_insufficient_budget() {
    let mut parent = root("p", 100);
    let r = rule();
    let err = derive_child_context(
        &mut parent,
        "c".into(),
        200,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap_err();
    assert!(matches!(err, ContextError::InsufficientBudget { .. }));
}

#[test]
fn enrichment_derive_child_exceeds_fraction() {
    let mut parent = root("p", 10_000);
    let r = DerivationRule::strict("strict".into()); // 50% max
    let err = derive_child_context(
        &mut parent,
        "c".into(),
        6000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ContextError::ChildExceedsAllowedFraction { .. }
    ));
}

#[test]
fn enrichment_derive_child_depth_exceeded() {
    let mut parent = root("p", 10_000);
    // Hack depth to be at max
    let mut r = DerivationRule::new("depth-test".into());
    r.max_depth = 1;
    let (mut child, _) = derive_child_context(
        &mut parent,
        "c1".into(),
        5000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    // depth is now 1, max_depth is 1, next would be 2
    let err = derive_child_context(
        &mut child,
        "gc".into(),
        1000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap_err();
    assert!(matches!(err, ContextError::DepthExceeded { .. }));
}

#[test]
fn enrichment_derive_child_not_consumable() {
    let mut parent = root("p", 1000);
    release_context(&mut parent);
    let r = rule();
    let err = derive_child_context(
        &mut parent,
        "c".into(),
        500,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap_err();
    assert!(matches!(err, ContextError::NotConsumable { .. }));
}

// ── carve_cleanup_context ───────────────────────────────────────────────

#[test]
fn enrichment_carve_cleanup_basic() {
    let mut parent = root("p", 10_000);
    let r = rule();
    let (cleanup, _) = carve_cleanup_context(&mut parent, "cleanup-1".into(), &r).unwrap();
    assert_eq!(cleanup.origin, ContextOrigin::CleanupCarve);
    // Default cleanup fraction is 10% = 1000ms
    assert_eq!(cleanup.budget_ms, 1000);
}

#[test]
fn enrichment_carve_cleanup_insufficient_budget() {
    let mut parent = root("p", 0);
    let r = rule();
    let err = carve_cleanup_context(&mut parent, "cleanup".into(), &r).unwrap_err();
    assert!(matches!(err, ContextError::InsufficientBudget { .. }));
}

// ── consume_budget ──────────────────────────────────────────────────────

#[test]
fn enrichment_consume_budget_basic() {
    let mut ctx = root("c", 1000);
    consume_budget(&mut ctx, 300).unwrap();
    assert_eq!(ctx.consumed_ms, 300);
    assert_eq!(ctx.remaining_ms(), 700);
}

#[test]
fn enrichment_consume_budget_exact() {
    let mut ctx = root("c", 1000);
    consume_budget(&mut ctx, 1000).unwrap();
    assert_eq!(ctx.state, ContextState::Exhausted);
    assert_eq!(ctx.remaining_ms(), 0);
}

#[test]
fn enrichment_consume_budget_over_exhausts() {
    let mut ctx = root("c", 100);
    let err = consume_budget(&mut ctx, 200).unwrap_err();
    assert!(matches!(err, ContextError::InsufficientBudget { .. }));
    assert_eq!(ctx.state, ContextState::Exhausted);
}

#[test]
fn enrichment_consume_budget_not_consumable() {
    let mut ctx = root("c", 1000);
    cancel_context(&mut ctx);
    let err = consume_budget(&mut ctx, 100).unwrap_err();
    assert!(matches!(err, ContextError::NotConsumable { .. }));
}

// ── release_context / cancel_context ────────────────────────────────────

#[test]
fn enrichment_release_context() {
    let mut ctx = root("r", 1000);
    release_context(&mut ctx);
    assert_eq!(ctx.state, ContextState::Released);
    assert!(!ctx.state.is_consumable());
}

#[test]
fn enrichment_cancel_context() {
    let mut ctx = root("c", 1000);
    cancel_context(&mut ctx);
    assert_eq!(ctx.state, ContextState::Cancelled);
    assert!(!ctx.state.is_consumable());
}

// ── DerivationEvent ─────────────────────────────────────────────────────

#[test]
fn enrichment_derivation_event_display() {
    let mut parent = root("p", 10_000);
    let r = rule();
    let (_, event) = derive_child_context(
        &mut parent,
        "c".into(),
        1000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    let s = event.to_string();
    assert!(s.contains("p"));
    assert!(s.contains("c"));
}

#[test]
fn enrichment_derivation_event_serde_roundtrip() {
    let mut parent = root("p", 10_000);
    let r = rule();
    let (_, event) = derive_child_context(
        &mut parent,
        "c".into(),
        1000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    let json = serde_json::to_string(&event).unwrap();
    let back: DerivationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ── MockSeamEntry ───────────────────────────────────────────────────────

#[test]
fn enrichment_mock_seam_entry_display() {
    let entry = MockSeamEntry {
        seam_id: "seam-1".into(),
        file_path: "src/foo.rs".into(),
        line_number: 42,
        classification: MockSeamClassification::MustFixProduction,
        description: "mock context leak".into(),
        remediated: false,
    };
    let s = entry.to_string();
    assert!(s.contains("seam-1"));
    assert!(s.contains("src/foo.rs"));
}

#[test]
fn enrichment_mock_seam_entry_serde_roundtrip() {
    let entry = MockSeamEntry {
        seam_id: "seam-2".into(),
        file_path: "src/bar.rs".into(),
        line_number: 99,
        classification: MockSeamClassification::AcceptableTestOnly,
        description: "test double".into(),
        remediated: true,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: MockSeamEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ── validate_threading ──────────────────────────────────────────────────

#[test]
fn enrichment_validate_threading_empty_passes() {
    let r = rule();
    let report = validate_threading(&[], &[], &[], &r, epoch(1));
    assert!(report.passed);
    assert!(report.all_contexts_valid);
    assert!(report.all_derivations_compliant);
    assert!(report.mock_free);
}

#[test]
fn enrichment_validate_threading_valid_contexts() {
    let ctx = root("r", 1000);
    let r = rule();
    let report = validate_threading(&[ctx], &[], &[], &r, epoch(1));
    assert!(report.passed);
    assert_eq!(report.contexts_validated, 1);
}

#[test]
fn enrichment_validate_threading_detects_mock_seam() {
    let seam = MockSeamEntry {
        seam_id: "bad-seam".into(),
        file_path: "src/prod.rs".into(),
        line_number: 10,
        classification: MockSeamClassification::MustFixProduction,
        description: "leak".into(),
        remediated: false,
    };
    let r = rule();
    let report = validate_threading(&[], &[], &[seam], &r, epoch(1));
    assert!(!report.passed);
    assert!(!report.mock_free);
    assert_eq!(report.production_seams_found, 1);
}

#[test]
fn enrichment_validate_threading_remediated_seam_ok() {
    let seam = MockSeamEntry {
        seam_id: "fixed-seam".into(),
        file_path: "src/prod.rs".into(),
        line_number: 10,
        classification: MockSeamClassification::MustFixProduction,
        description: "leak".into(),
        remediated: true,
    };
    let r = rule();
    let report = validate_threading(&[], &[], &[seam], &r, epoch(1));
    assert!(report.passed);
    assert!(report.mock_free);
}

#[test]
fn enrichment_validate_threading_depth_exceeded() {
    let mut ctx = root("r", 1000);
    ctx.depth = 100; // Exceeds max_depth=64
    let r = rule();
    let report = validate_threading(&[ctx], &[], &[], &r, epoch(1));
    assert!(!report.passed);
    assert!(!report.all_contexts_valid);
}

// ── ValidationReport ────────────────────────────────────────────────────

#[test]
fn enrichment_validation_report_display() {
    let r = rule();
    let report = validate_threading(&[], &[], &[], &r, epoch(1));
    let s = report.to_string();
    assert!(s.contains("validation:"));
    assert!(s.contains("passed=true"));
}

#[test]
fn enrichment_validation_report_serde_roundtrip() {
    let r = rule();
    let report = validate_threading(&[], &[], &[], &r, epoch(1));
    let json = serde_json::to_string(&report).unwrap();
    let back: ValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_validation_report_hash_deterministic() {
    let r = rule();
    let a = validate_threading(&[], &[], &[], &r, epoch(1));
    let b = validate_threading(&[], &[], &[], &r, epoch(1));
    assert_eq!(a.content_hash, b.content_hash);
}

// ── ContextError Display uniqueness ─────────────────────────────────────

#[test]
fn enrichment_context_error_display_unique() {
    let errors: Vec<ContextError> = vec![
        ContextError::InsufficientBudget {
            parent_id: "p".into(),
            remaining_ms: 10,
            requested_ms: 20,
        },
        ContextError::DepthExceeded {
            parent_id: "p".into(),
            depth: 65,
            max_depth: 64,
        },
        ContextError::NotConsumable {
            context_id: "c".into(),
            state: ContextState::Exhausted,
        },
        ContextError::ChildExceedsAllowedFraction {
            parent_id: "p".into(),
            child_budget_ms: 100,
            max_allowed_ms: 50,
        },
        ContextError::CleanupExceedsMaxFraction {
            parent_id: "p".into(),
            cleanup_ms: 100,
            max_allowed_ms: 50,
        },
        ContextError::MockSeamDetected {
            seam_id: "s".into(),
            file_path: "f".into(),
        },
        ContextError::ContextNotFound("missing".into()),
        ContextError::EmptyInput,
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_context_error_serde_all() {
    let errors: Vec<ContextError> = vec![
        ContextError::InsufficientBudget {
            parent_id: "p".into(),
            remaining_ms: 10,
            requested_ms: 20,
        },
        ContextError::DepthExceeded {
            parent_id: "p".into(),
            depth: 65,
            max_depth: 64,
        },
        ContextError::NotConsumable {
            context_id: "c".into(),
            state: ContextState::Exhausted,
        },
        ContextError::ChildExceedsAllowedFraction {
            parent_id: "p".into(),
            child_budget_ms: 100,
            max_allowed_ms: 50,
        },
        ContextError::CleanupExceedsMaxFraction {
            parent_id: "p".into(),
            cleanup_ms: 100,
            max_allowed_ms: 50,
        },
        ContextError::MockSeamDetected {
            seam_id: "s".into(),
            file_path: "f".into(),
        },
        ContextError::ContextNotFound("missing".into()),
        ContextError::EmptyInput,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ContextError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_context_error_display_contains_component() {
    let err = ContextError::EmptyInput;
    assert!(err.to_string().contains(COMPONENT));
}

// ── Multi-step lifecycle ────────────────────────────────────────────────

#[test]
fn enrichment_full_lifecycle_derive_consume_release() {
    let mut parent = root("p", 10_000);
    let r = rule();

    // Derive child
    let (mut child, _) = derive_child_context(
        &mut parent,
        "c1".into(),
        3000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    assert_eq!(parent.remaining_ms(), 7000);

    // Consume from child
    consume_budget(&mut child, 1000).unwrap();
    assert_eq!(child.remaining_ms(), 2000);

    // Release child
    release_context(&mut child);
    assert_eq!(child.state, ContextState::Released);

    // Carve cleanup from parent
    let (cleanup, _) = carve_cleanup_context(&mut parent, "cleanup".into(), &r).unwrap();
    assert_eq!(cleanup.origin, ContextOrigin::CleanupCarve);
}

#[test]
fn enrichment_derive_multiple_children() {
    let mut parent = root("p", 10_000);
    let r = rule();

    for i in 0..5 {
        let (_, _) = derive_child_context(
            &mut parent,
            format!("c{i}"),
            1000,
            ContextOrigin::ChildDerivation,
            &r,
        )
        .unwrap();
    }
    assert_eq!(parent.consumed_ms, 5000);
    assert_eq!(parent.remaining_ms(), 5000);
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[test]
fn enrichment_root_context_epoch_propagates() {
    let ctx = create_root_context("r".into(), "t".into(), 1000, epoch(42));
    assert_eq!(ctx.epoch, epoch(42));
}

#[test]
fn enrichment_child_inherits_epoch() {
    let mut parent = create_root_context("p".into(), "t".into(), 10_000, epoch(99));
    let r = rule();
    let (child, _) = derive_child_context(
        &mut parent,
        "c".into(),
        1000,
        ContextOrigin::ChildDerivation,
        &r,
    )
    .unwrap();
    assert_eq!(child.epoch, epoch(99));
}

#[test]
fn enrichment_consume_budget_incremental() {
    let mut ctx = root("c", 1000);
    consume_budget(&mut ctx, 100).unwrap();
    consume_budget(&mut ctx, 200).unwrap();
    consume_budget(&mut ctx, 300).unwrap();
    assert_eq!(ctx.consumed_ms, 600);
    assert_eq!(ctx.remaining_ms(), 400);
}
