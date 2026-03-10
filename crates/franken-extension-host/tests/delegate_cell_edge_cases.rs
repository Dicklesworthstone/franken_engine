// Integration tests for delegate cell edge cases: budget validation, error display,
// delegation scope handling, guardplane penalty accumulation, event recording,
// and idempotent lifetime-expiry behavior.

use frankenengine_extension_host::{
    BudgetExhaustionPolicy, CancellationConfig, Capability, DataRef, DeclassificationDenialReason,
    DeclassificationOutcome, DeclassificationPurpose, DeclassificationRequest, DelegateCellError,
    DelegateCellEvidence, DelegateCellFactory, DelegateCellManifest, DelegateCellPolicy,
    DelegationScope, ExtensionManifest, ExtensionState, FlowEnforcementContext, FlowLabel,
    GuardplaneDecisionLogEntry, GuardplanePolicyAction, HostcallResult, HostcallSinkPolicy,
    HostcallType, IntegrityLevel, Labeled, LifecycleContext, LifecycleTransition, ResourceBudget,
    SecrecyLevel, MAX_DELEGATE_CPU_BUDGET_NS, MAX_DELEGATE_HOSTCALL_BUDGET,
    MAX_DELEGATE_LIFETIME_NS, MAX_DELEGATE_MEMORY_BUDGET_BYTES,
};

fn base_manifest(capabilities: &[Capability]) -> ExtensionManifest {
    use frankenengine_extension_host::compute_content_hash;
    let mut manifest = ExtensionManifest {
        name: "delegate-edge".to_string(),
        version: "1.0.0".to_string(),
        entrypoint: "dist/delegate.js".to_string(),
        capabilities: capabilities.iter().copied().collect(),
        publisher_signature: Some(vec![10, 20, 30]),
        content_hash: [0; 32],
        trust_chain_ref: Some("chain/edge-test".to_string()),
        min_engine_version: frankenengine_extension_host::CURRENT_ENGINE_VERSION.to_string(),
    };
    manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
    manifest
}

fn delegate_manifest(caps: &[Capability], max_lifetime_ns: u64) -> DelegateCellManifest {
    DelegateCellManifest {
        base_manifest: base_manifest(caps),
        delegation_scope: DelegationScope::DiagnosticCollection,
        delegator_id: "engine-core".to_string(),
        max_lifetime_ns,
    }
}

fn lctx() -> LifecycleContext<'static> {
    LifecycleContext::new("trace-edge", "decision-edge", "policy-edge")
}

fn fctx() -> FlowEnforcementContext<'static> {
    FlowEnforcementContext::new("trace-flow-edge", "decision-flow-edge", "policy-flow-edge")
}

fn valid_budget() -> ResourceBudget {
    ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 1_000)
}

fn factory() -> DelegateCellFactory {
    DelegateCellFactory::default()
}

fn run_mixed_guardplane_sequence(
    delegate: &mut frankenengine_extension_host::DelegateCell,
) -> Vec<GuardplaneDecisionLogEntry> {
    let denied = delegate
        .request_declassification(
            DeclassificationRequest {
                request_id: "req-mixed-0".to_string(),
                requester: delegate.delegate_id().to_string(),
                data_ref: DataRef::new("memory", "token"),
                current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                target_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
                purpose: DeclassificationPurpose::DiagnosticExport,
                justification: "expected denial".to_string(),
                timestamp_ns: 600,
            },
            &fctx(),
            &lctx(),
        )
        .expect("declassification outcome");
    assert!(matches!(
        denied,
        DeclassificationOutcome::Denied {
            reason: DeclassificationDenialReason::MissingCapability { .. },
            ..
        }
    ));

    let blocked_hostcall = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-attempt".to_string()),
            610,
            &fctx(),
            &lctx(),
        )
        .expect("hostcall outcome");
    assert!(matches!(
        blocked_hostcall.result,
        HostcallResult::Denied { .. }
    ));

    let allowed_hostcall = delegate
        .dispatch_hostcall(
            HostcallType::FsRead,
            Capability::FsRead,
            Labeled::system_generated("safe-read".to_string()),
            620,
            &fctx(),
            &lctx(),
        )
        .expect("allowed hostcall");
    assert!(matches!(allowed_hostcall.result, HostcallResult::Success));

    let second_denial = delegate
        .request_declassification(
            DeclassificationRequest {
                request_id: "req-mixed-1".to_string(),
                requester: delegate.delegate_id().to_string(),
                data_ref: DataRef::new("memory", "secret"),
                current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                target_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
                purpose: DeclassificationPurpose::DiagnosticExport,
                justification: "expected denial again".to_string(),
                timestamp_ns: 630,
            },
            &fctx(),
            &lctx(),
        )
        .expect("second declassification outcome");
    assert!(matches!(
        second_denial,
        DeclassificationOutcome::Denied {
            reason: DeclassificationDenialReason::MissingCapability { .. },
            ..
        }
    ));

    delegate.guardplane_decision_log().to_vec()
}

// ---------------------------------------------------------------------------
// Budget validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn rejects_zero_cpu_budget() {
    let result = factory().create_delegate_cell(
        "d-zero-cpu",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        ResourceBudget::new(0, 64 * 1024 * 1024, 1_000),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(
        result,
        Err(DelegateCellError::InvalidBudget {
            field: "cpu_time_ns_remaining",
            ..
        })
    ));
}

#[test]
fn rejects_cpu_budget_exceeding_max() {
    let result = factory().create_delegate_cell(
        "d-big-cpu",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        ResourceBudget::new(MAX_DELEGATE_CPU_BUDGET_NS + 1, 64 * 1024 * 1024, 1_000),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    match result {
        Err(DelegateCellError::InvalidBudget {
            field,
            value,
            max_allowed,
        }) => {
            assert_eq!(field, "cpu_time_ns_remaining");
            assert_eq!(value, MAX_DELEGATE_CPU_BUDGET_NS + 1);
            assert_eq!(max_allowed, MAX_DELEGATE_CPU_BUDGET_NS);
        }
        Err(other) => panic!("expected InvalidBudget, got {other}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

#[test]
fn rejects_zero_memory_budget() {
    let result = factory().create_delegate_cell(
        "d-zero-mem",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        ResourceBudget::new(1_000_000_000, 0, 1_000),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(
        result,
        Err(DelegateCellError::InvalidBudget {
            field: "memory_bytes_remaining",
            ..
        })
    ));
}

#[test]
fn rejects_memory_budget_exceeding_max() {
    let result = factory().create_delegate_cell(
        "d-big-mem",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        ResourceBudget::new(1_000_000_000, MAX_DELEGATE_MEMORY_BUDGET_BYTES + 1, 1_000),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(
        result,
        Err(DelegateCellError::InvalidBudget {
            field: "memory_bytes_remaining",
            ..
        })
    ));
}

#[test]
fn rejects_zero_hostcall_budget() {
    let result = factory().create_delegate_cell(
        "d-zero-hc",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 0),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(
        result,
        Err(DelegateCellError::InvalidBudget {
            field: "hostcall_count_remaining",
            ..
        })
    ));
}

#[test]
fn rejects_hostcall_budget_exceeding_max() {
    let result = factory().create_delegate_cell(
        "d-big-hc",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        ResourceBudget::new(
            1_000_000_000,
            64 * 1024 * 1024,
            MAX_DELEGATE_HOSTCALL_BUDGET + 1,
        ),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(
        result,
        Err(DelegateCellError::InvalidBudget {
            field: "hostcall_count_remaining",
            ..
        })
    ));
}

#[test]
fn accepts_exact_max_budget_values() {
    let result = factory().create_delegate_cell(
        "d-max-budget",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        ResourceBudget::new(
            MAX_DELEGATE_CPU_BUDGET_NS,
            MAX_DELEGATE_MEMORY_BUDGET_BYTES,
            MAX_DELEGATE_HOSTCALL_BUDGET,
        ),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Factory validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn rejects_empty_delegate_id() {
    let result = factory().create_delegate_cell(
        "",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        valid_budget(),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(result, Err(DelegateCellError::InvalidDelegateId)));
}

#[test]
fn rejects_whitespace_only_delegate_id() {
    let result = factory().create_delegate_cell(
        "   ",
        delegate_manifest(&[Capability::FsRead], 1_000_000),
        valid_budget(),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(result, Err(DelegateCellError::InvalidDelegateId)));
}

#[test]
fn rejects_lifetime_exceeding_max() {
    let result = factory().create_delegate_cell(
        "d-big-life",
        delegate_manifest(&[Capability::FsRead], MAX_DELEGATE_LIFETIME_NS + 1),
        valid_budget(),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(matches!(
        result,
        Err(DelegateCellError::InvalidMaxLifetime { .. })
    ));
}

#[test]
fn accepts_exact_max_lifetime() {
    let result = factory().create_delegate_cell(
        "d-max-life",
        delegate_manifest(&[Capability::FsRead], MAX_DELEGATE_LIFETIME_NS),
        valid_budget(),
        BudgetExhaustionPolicy::Suspend,
        100,
        &lctx(),
    );
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// DelegationScope coverage
// ---------------------------------------------------------------------------

#[test]
fn delegation_scope_as_str_matches_display_for_builtins() {
    let cases = [
        (DelegationScope::ModuleReplacement, "module_replacement"),
        (DelegationScope::ConfigUpdate, "config_update"),
        (
            DelegationScope::DiagnosticCollection,
            "diagnostic_collection",
        ),
        (DelegationScope::TrustChainRotation, "trust_chain_rotation"),
    ];
    for (scope, expected) in &cases {
        assert_eq!(scope.as_str(), *expected);
        assert_eq!(scope.to_string(), *expected);
    }
}

#[test]
fn delegation_scope_custom_has_prefix_in_display() {
    let scope = DelegationScope::Custom("my-workflow".to_string());
    assert_eq!(scope.as_str(), "custom");
    assert_eq!(scope.to_string(), "custom:my-workflow");
}

#[test]
fn factory_uses_manifest_delegation_scope_in_events() {
    let mut manifest = delegate_manifest(&[Capability::FsRead, Capability::HostCall], 1_000_000);
    manifest.delegation_scope = DelegationScope::TrustChainRotation;

    let delegate = factory()
        .create_delegate_cell(
            "d-scope",
            manifest,
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    assert!(delegate
        .events()
        .iter()
        .all(|e| e.delegation_scope == "trust_chain_rotation"));
}

// ---------------------------------------------------------------------------
// DelegateCellError display coverage
// ---------------------------------------------------------------------------

#[test]
fn error_display_messages_are_not_empty() {
    let errors: Vec<DelegateCellError> = vec![
        DelegateCellError::InvalidDelegateId,
        DelegateCellError::InvalidDelegatorId,
        DelegateCellError::InvalidMaxLifetime { requested_ns: 999 },
        DelegateCellError::MissingCapabilities,
        DelegateCellError::InvalidBudget {
            field: "cpu",
            value: 0,
            max_allowed: 100,
        },
        DelegateCellError::LifetimeExpired {
            delegate_id: "test".to_string(),
            expired_at_ns: 42,
        },
    ];
    for error in &errors {
        let msg = error.to_string();
        assert!(!msg.is_empty(), "empty display for {error:?}");
    }
}

#[test]
fn error_display_invalid_budget_includes_field_and_values() {
    let err = DelegateCellError::InvalidBudget {
        field: "hostcall_count_remaining",
        value: 999_999,
        max_allowed: 100_000,
    };
    let msg = err.to_string();
    assert!(msg.contains("hostcall_count_remaining"));
    assert!(msg.contains("999999"));
    assert!(msg.contains("100000"));
}

#[test]
fn error_display_lifetime_expired_includes_delegate_id() {
    let err = DelegateCellError::LifetimeExpired {
        delegate_id: "test-delegate-xyz".to_string(),
        expired_at_ns: 123_456,
    };
    let msg = err.to_string();
    assert!(msg.contains("test-delegate-xyz"));
    assert!(msg.contains("123456"));
}

// ---------------------------------------------------------------------------
// Accessor coverage
// ---------------------------------------------------------------------------

#[test]
fn delegate_accessors_return_correct_values() {
    let delegate = factory()
        .create_delegate_cell(
            "d-accessors",
            delegate_manifest(&[Capability::FsRead, Capability::NetClient], 500_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            1_000,
            &lctx(),
        )
        .expect("delegate created");

    assert_eq!(delegate.delegate_id(), "d-accessors");
    assert_eq!(delegate.manifest().delegator_id, "engine-core");
    assert_eq!(delegate.created_at_ns(), 1_000);
    assert_eq!(delegate.expires_at_ns(), 1_000 + 500_000);
    assert_eq!(delegate.state(), ExtensionState::Running);
    assert_eq!(delegate.guardplane_state().delegate_id, "d-accessors");
    assert!(!delegate.events().is_empty());
    assert!(delegate.evidence().is_empty());
    assert!(delegate.hostcall_violation_events().is_empty());
    assert!(delegate.declassification_receipts().is_empty());
}

// ---------------------------------------------------------------------------
// Guardplane penalty accumulation
// ---------------------------------------------------------------------------

#[test]
fn repeated_capability_escalations_accumulate_posterior() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-penalty",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    let initial = delegate.guardplane_state().posterior_micros;

    for i in 0..3 {
        let _ = delegate.dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated(format!("attempt-{i}")),
            200 + i as u64,
            &fctx(),
            &lctx(),
        );
    }

    let after = delegate.guardplane_state().posterior_micros;
    assert!(
        after > initial,
        "posterior should increase after violations"
    );
    assert_eq!(
        delegate
            .evidence()
            .iter()
            .filter(|e| matches!(e, DelegateCellEvidence::CapabilityEscalation { .. }))
            .count(),
        3
    );
}

#[test]
fn posterior_is_capped_at_one_million_micros() {
    let policy = DelegateCellPolicy {
        initial_posterior_micros: 999_990,
        capability_escalation_penalty_micros: 100,
        ..DelegateCellPolicy::default()
    };
    let fac = DelegateCellFactory {
        policy,
        ..DelegateCellFactory::default()
    };
    let mut delegate = fac
        .create_delegate_cell(
            "d-cap",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    // Trigger 200 escalations — posterior should not exceed 1_000_000
    for i in 0..200u64 {
        let _ = delegate.dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated(format!("cap-{i}")),
            200 + i,
            &fctx(),
            &lctx(),
        );
    }

    assert!(delegate.guardplane_state().posterior_micros <= 1_000_000);
}

#[test]
fn guardplane_safe_mode_fallback_escalates_nominal_challenge_to_sandbox_on_denial() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-safe-mode-denial",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");
    delegate.set_adaptive_components_available(false);

    let denied = delegate
        .request_declassification(
            DeclassificationRequest {
                request_id: "req-safe-mode-denial".to_string(),
                requester: "d-safe-mode-denial".to_string(),
                data_ref: DataRef::new("memory", "token"),
                current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                target_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
                purpose: DeclassificationPurpose::DiagnosticExport,
                justification: "expected denial".to_string(),
                timestamp_ns: 500,
            },
            &fctx(),
            &lctx(),
        )
        .expect("declassification outcome");

    assert!(matches!(
        denied,
        DeclassificationOutcome::Denied {
            reason: DeclassificationDenialReason::MissingCapability { .. },
            ..
        }
    ));

    let decision = delegate
        .guardplane_decision_log()
        .last()
        .expect("guardplane decision");
    assert_eq!(decision.posterior_micros, 310_000);
    assert_eq!(decision.action, GuardplanePolicyAction::Sandbox);
    assert!(decision.safe_mode_fallback);
    assert_eq!(decision.source_event, "delegate_declassification");
    assert_eq!(decision.resulting_state, ExtensionState::Running);

    let containment = delegate
        .containment_workflow_log()
        .last()
        .expect("containment workflow");
    assert_eq!(containment.action, GuardplanePolicyAction::Sandbox);
    assert_eq!(containment.event, "delegate_containment_action");
    assert_eq!(containment.source_event, "delegate_declassification");
    assert_eq!(containment.outcome, "ok");
    assert!(containment.error_code.is_none());
    assert!(containment.mesh_attempted_targets.is_empty());
}

#[test]
fn guardplane_decision_logs_are_replay_stable_for_mixed_fault_sequence() {
    let mut first = factory()
        .create_delegate_cell(
            "d-mixed",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("first delegate");
    let mut second = factory()
        .create_delegate_cell(
            "d-mixed",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("second delegate");

    let first_decisions = run_mixed_guardplane_sequence(&mut first);
    let second_decisions = run_mixed_guardplane_sequence(&mut second);

    assert_eq!(first_decisions, second_decisions);
    assert_eq!(
        first.containment_workflow_log(),
        second.containment_workflow_log()
    );
    assert_eq!(first.events(), second.events());
    assert_eq!(
        first
            .guardplane_decision_log()
            .iter()
            .map(|entry| entry.action)
            .collect::<Vec<_>>(),
        vec![
            GuardplanePolicyAction::Challenge,
            GuardplanePolicyAction::Sandbox,
            GuardplanePolicyAction::Sandbox,
            GuardplanePolicyAction::Suspend,
        ]
    );
}

// ---------------------------------------------------------------------------
// Lifetime expiry idempotency
// ---------------------------------------------------------------------------

#[test]
fn double_lifetime_check_returns_error_both_times() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-expire-twice",
            delegate_manifest(&[Capability::FsRead], 50),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    let err1 = delegate.check_lifetime(200, &lctx());
    assert!(err1.is_err());

    let err2 = delegate.check_lifetime(300, &lctx());
    assert!(err2.is_err());

    // Evidence should only be recorded once
    let lifetime_evidence_count = delegate
        .evidence()
        .iter()
        .filter(|e| matches!(e, DelegateCellEvidence::LifetimeExpired { .. }))
        .count();
    assert_eq!(
        lifetime_evidence_count, 1,
        "lifetime evidence should be recorded once"
    );
}

#[test]
fn hostcall_after_lifetime_expiry_is_rejected() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-post-expire",
            delegate_manifest(&[Capability::FsRead, Capability::HostCall], 50),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    // Expire it
    let _ = delegate.check_lifetime(200, &lctx());

    // Try a hostcall — should fail due to expired lifetime
    let result = delegate.dispatch_hostcall(
        HostcallType::FsRead,
        Capability::FsRead,
        Labeled::system_generated("data".to_string()),
        250,
        &fctx(),
        &lctx(),
    );
    assert!(result.is_err());
}

#[test]
fn declassification_after_lifetime_expiry_is_rejected() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-declass-expire",
            delegate_manifest(&[Capability::FsRead, Capability::Declassify], 50),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    let _ = delegate.check_lifetime(200, &lctx());

    let result = delegate.request_declassification(
        DeclassificationRequest {
            request_id: "req-after-expire".to_string(),
            requester: "d-declass-expire".to_string(),
            data_ref: DataRef::new("memory", "token"),
            current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
            target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated),
            purpose: DeclassificationPurpose::OperatorOverride,
            justification: "should not matter".to_string(),
            timestamp_ns: 250,
        },
        &fctx(),
        &lctx(),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Lifecycle transition through delegate
// ---------------------------------------------------------------------------

#[test]
fn apply_transition_suspends_running_delegate() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-suspend",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    assert_eq!(delegate.state(), ExtensionState::Running);

    let event = delegate
        .apply_transition(LifecycleTransition::Suspend, 200, &lctx())
        .expect("suspend transition");
    assert_eq!(delegate.state(), ExtensionState::Suspending);
    assert_eq!(event.to_state, ExtensionState::Suspending.as_str());
}

#[test]
fn apply_transition_with_expired_lifetime_fails() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-trans-expire",
            delegate_manifest(&[Capability::FsRead], 50),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    let result = delegate.apply_transition(LifecycleTransition::Suspend, 200, &lctx());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Event recording structure
// ---------------------------------------------------------------------------

#[test]
fn all_events_have_stable_component_field() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-events",
            delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    // Trigger a capability escalation to produce more events
    let _ = delegate.dispatch_hostcall(
        HostcallType::ProcessSpawn,
        Capability::ProcessSpawn,
        Labeled::system_generated("test".to_string()),
        200,
        &fctx(),
        &lctx(),
    );

    for event in delegate.events() {
        assert_eq!(event.component, "delegate_cell_policy");
        assert!(!event.delegate_id.is_empty());
        assert!(!event.delegation_scope.is_empty());
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn successful_hostcall_records_allowed_event() {
    let mut delegate = factory()
        .create_delegate_cell(
            "d-success-hc",
            delegate_manifest(&[Capability::FsRead, Capability::HostCall], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    let outcome = delegate
        .dispatch_hostcall(
            HostcallType::FsRead,
            Capability::FsRead,
            Labeled::system_generated("safe-data".to_string()),
            200,
            &fctx(),
            &lctx(),
        )
        .expect("dispatch");

    assert!(matches!(outcome.result, HostcallResult::Success));

    let hostcall_events: Vec<_> = delegate
        .events()
        .iter()
        .filter(|e| e.event == "delegate_hostcall")
        .collect();
    assert!(!hostcall_events.is_empty());
    assert!(hostcall_events.iter().any(|e| e.outcome == "allowed"));
}

// ---------------------------------------------------------------------------
// DelegateCellFactory default values
// ---------------------------------------------------------------------------

#[test]
fn factory_default_uses_default_policy_values() {
    let fac = DelegateCellFactory::default();
    let expected = DelegateCellPolicy::default();
    assert_eq!(fac.policy, expected);
    assert_eq!(fac.sink_policy, HostcallSinkPolicy::default());
    assert_eq!(fac.cancellation_config, CancellationConfig::default());
}

#[test]
fn custom_factory_policy_propagates_to_delegate_guardplane() {
    let policy = DelegateCellPolicy {
        initial_posterior_micros: 42_000,
        ..DelegateCellPolicy::default()
    };
    let fac = DelegateCellFactory {
        policy,
        ..DelegateCellFactory::default()
    };
    let delegate = fac
        .create_delegate_cell(
            "d-custom-policy",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    assert_eq!(delegate.guardplane_state().posterior_micros, 42_000);
}

// ---------------------------------------------------------------------------
// Terminate policy variant
// ---------------------------------------------------------------------------

#[test]
fn delegate_with_terminate_budget_policy_is_valid() {
    let delegate = factory()
        .create_delegate_cell(
            "d-term-policy",
            delegate_manifest(&[Capability::FsRead], 1_000_000),
            valid_budget(),
            BudgetExhaustionPolicy::Terminate,
            100,
            &lctx(),
        )
        .expect("delegate created");

    assert_eq!(delegate.state(), ExtensionState::Running);
}
