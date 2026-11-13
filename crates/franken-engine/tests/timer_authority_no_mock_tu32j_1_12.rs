#![forbid(unsafe_code)]

//! `[FRESH-REALITY][MOCK]` (`bd-performance-conformance-bridge-tu32j.1.12`):
//! No-mock integration and unit-boundary verification for deterministic timer
//! authority across public `FullCapsHandler` / `EngineCoreHandler` stacks and
//! live `ExecutionOrchestrator` execution cells.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use frankenengine_engine::algebraic_effects::{EffectError, Handler};
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    AllocKind, FunctionRef, HookAction, HookContext, InterpreterConfig, InterpreterError,
    InterpreterHook, ObjectRef, PropertyKey, QuickJsLane, Value,
};
use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::evidence_ledger::RuntimeEvidenceAuthority;
use frankenengine_engine::execution_cell::{
    CellExecutionAuthority, CellExecutionAuthoritySnapshot, CellExecutionError,
    CellExecutionEventKind, CellKind, ExecutionCell,
};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_effects_migration::{
    ComputeOnlyHandler, EngineCoreHandler, FullCapsHandler, InterpreterTimerOutcome,
    InterpreterTimerRequest, TIMER_PROVIDER_UNAVAILABLE_CODE, TimerEffectAuthority,
    TimerEffectAuthorityError, TimerEffectCompletion, TimerEffectPermit, TimerHostcallEffect,
    TimerOperation, create_effect_from_hostcall_tag, create_handler_stack_from_profile,
    create_handler_stack_from_profile_with_effect_providers,
    create_handler_stack_from_profile_with_host_io,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_extension_host::host_io::EnvironmentSnapshotHostIo;

fn production_orchestrator() -> ExecutionOrchestrator {
    let signing_key = SigningKey::from_bytes([0x5a; 32]).expect("valid non-zero ed25519 key");
    let authority = RuntimeEvidenceAuthority::from_signing_key(
        "timer-authority-runtime-producer",
        signing_key,
        SecurityEpoch::from_raw(1),
        1,
        None,
    )
    .expect("valid runtime evidence authority");
    ExecutionOrchestrator::try_new_with_runtime_authority(OrchestratorConfig::default(), authority)
        .expect("construct production orchestrator")
}

fn timer_effects_all_operations() -> [TimerHostcallEffect; 4] {
    [
        TimerHostcallEffect {
            operation: TimerOperation::SetTimeout,
            duration_ms: Some(10),
            timer_id: None,
        },
        TimerHostcallEffect {
            operation: TimerOperation::SetInterval,
            duration_ms: Some(25),
            timer_id: None,
        },
        TimerHostcallEffect {
            operation: TimerOperation::ClearTimeout,
            duration_ms: None,
            timer_id: Some(0),
        },
        TimerHostcallEffect {
            operation: TimerOperation::ClearInterval,
            duration_ms: None,
            timer_id: Some(1),
        },
    ]
}

#[test]
fn all_public_profile_stacks_reject_unbound_timers_without_constant_42_or_fake_prints() {
    let host_io = Arc::new(
        EnvironmentSnapshotHostIo::new(BTreeMap::new()).expect("empty environment snapshot"),
    );

    // Direct public handlers without an interpreter-owned event-loop provider.
    let full_default = FullCapsHandler::new();
    let full_with_io = FullCapsHandler::with_host_io(host_io.clone());
    let full_with_providers =
        FullCapsHandler::with_effect_providers(Some(host_io.clone()), None, None);
    let engine_core = EngineCoreHandler;
    let compute_only = ComputeOnlyHandler;

    for effect in &timer_effects_all_operations() {
        for handler in [
            &full_default as &dyn Handler,
            &full_with_io as &dyn Handler,
            &full_with_providers as &dyn Handler,
            &engine_core as &dyn Handler,
        ] {
            let err = handler
                .handle(effect)
                .expect_err("unbound timer must fail closed before recording success");
            assert!(
                matches!(
                    &err,
                    EffectError::HandlerError { code: Some(code), .. }
                        if code == TIMER_PROVIDER_UNAVAILABLE_CODE
                ),
                "expected TIMER_PROVIDER_UNAVAILABLE from {}, got {err:?}",
                handler.handler_name()
            );
        }
        assert!(matches!(
            compute_only.handle(effect),
            Err(EffectError::CapabilityDenied { .. })
        ));
    }

    // Audit all public profile stack constructors and legacy tag conversion.
    let tag_effects = [
        create_effect_from_hostcall_tag("timer:setTimeout", &[String::from("15")])
            .expect("valid setTimeout tag"),
        create_effect_from_hostcall_tag("timer:setInterval", &[String::from("30")])
            .expect("valid setInterval tag"),
        create_effect_from_hostcall_tag("timer:clearTimeout", &[String::from("0")])
            .expect("valid clearTimeout tag"),
        create_effect_from_hostcall_tag("timer:clearInterval", &[String::from("1")])
            .expect("valid clearInterval tag"),
    ];

    for profile in [CapabilityProfile::full(), CapabilityProfile::engine_core()] {
        let mut stack_plain = create_handler_stack_from_profile(&profile);
        let mut stack_io =
            create_handler_stack_from_profile_with_host_io(&profile, host_io.clone(), None);
        let mut stack_providers = create_handler_stack_from_profile_with_effect_providers(
            &profile,
            Some(host_io.clone()),
            None,
            None,
            None,
            None,
        );
        for effect in &tag_effects {
            for stack in [&mut stack_plain, &mut stack_io, &mut stack_providers] {
                let err = stack
                    .handle_effect(effect.as_ref())
                    .expect_err("public migration stack without interpreter provider must refuse");
                assert!(
                    matches!(
                        &err,
                        EffectError::HandlerError { code: Some(code), .. }
                            if code == TIMER_PROVIDER_UNAVAILABLE_CODE
                    ),
                    "profile {:?} returned unexpected timer outcome: {err:?}",
                    profile.kind()
                );
            }
        }
    }

    // Profiles lacking RuntimeCapability::Timer fail closed with CapabilityDenied.
    for profile in [
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ] {
        let mut stack = create_handler_stack_from_profile(&profile);
        for effect in &tag_effects {
            assert!(matches!(
                stack.handle_effect(effect.as_ref()),
                Err(EffectError::CapabilityDenied { .. })
            ));
        }
    }
}

#[test]
fn malformed_timer_effect_parameters_fail_before_provider_dispatch() {
    let malformed = [
        TimerHostcallEffect {
            operation: TimerOperation::SetTimeout,
            duration_ms: None,
            timer_id: None,
        },
        TimerHostcallEffect {
            operation: TimerOperation::SetInterval,
            duration_ms: Some(5),
            timer_id: Some(1),
        },
        TimerHostcallEffect {
            operation: TimerOperation::ClearTimeout,
            duration_ms: None,
            timer_id: None,
        },
        TimerHostcallEffect {
            operation: TimerOperation::ClearInterval,
            duration_ms: Some(5),
            timer_id: Some(1),
        },
    ];
    let full = FullCapsHandler::new();
    let engine = EngineCoreHandler;
    for effect in &malformed {
        assert!(matches!(
            full.handle(effect),
            Err(EffectError::InvalidParameters { .. })
        ));
        assert!(matches!(
            engine.handle(effect),
            Err(EffectError::InvalidParameters { .. })
        ));
    }
    assert!(create_effect_from_hostcall_tag("timer:setTimeout", &[]).is_err());
    assert!(create_effect_from_hostcall_tag("timer:setTimeout", &[String::from("nan")]).is_err());
    assert!(create_effect_from_hostcall_tag("timer:clearTimeout", &[]).is_err());
    assert!(create_effect_from_hostcall_tag("timer:set_timeout", &[String::from("10")]).is_err());
}

#[test]
fn no_mock_set_timeout_and_clear_timeout_allocate_distinct_handles_order_and_replay_transcript() {
    let package = ExtensionPackage {
        extension_id: "timer-no-mock-timeout-tu32j-1-12".to_string(),
        source: r#"
            const cancelled = setTimeout(() => console.log('cancelled'), 1);
            const first = setTimeout(() => console.log('first'), 1);
            const second = setTimeout(() => console.log('second'), 1);
            console.log(cancelled === first);
            clearTimeout(cancelled);
        "#
        .to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec![
            "vm_dispatch".to_string(),
            "heap_allocate".to_string(),
            "console".to_string(),
            "timer".to_string(),
        ],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };

    let mut orch_a = production_orchestrator();
    let mut orch_b = production_orchestrator();
    let result_a = orch_a.execute(&package).expect("run A succeeds");
    let result_b = orch_b.execute(&package).expect("run B succeeds");

    let console_a: Vec<&str> = result_a
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    let console_b: Vec<&str> = result_b
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(console_a, vec!["false", "first", "second"]);
    assert_eq!(console_a, console_b);

    let transcript_a = result_a
        .cell_execution_transcript
        .as_ref()
        .expect("cell transcript A");
    let transcript_b = result_b
        .cell_execution_transcript
        .as_ref()
        .expect("cell transcript B");
    transcript_a.verify().expect("transcript A verifies");
    transcript_b.verify().expect("transcript B verifies");

    let extract_timer_outcomes =
        |events: &[frankenengine_engine::execution_cell::CellExecutionEvent]| {
            events
                .iter()
                .filter_map(|event| match &event.kind {
                    CellExecutionEventKind::EffectCompleted { outcome, .. }
                        if outcome.starts_with("scheduled:") || outcome.starts_with("cleared:") =>
                    {
                        Some(outcome.clone())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

    let outcomes_a = extract_timer_outcomes(&transcript_a.events);
    let outcomes_b = extract_timer_outcomes(&transcript_b.events);
    assert_eq!(
        outcomes_a, outcomes_b,
        "timer evidence must replay identically"
    );
    assert_eq!(outcomes_a.len(), 4);
    assert!(outcomes_a[0].starts_with("scheduled:timer_id=0:registration="));
    assert!(outcomes_a[1].starts_with("scheduled:timer_id=1:registration="));
    assert!(outcomes_a[2].starts_with("scheduled:timer_id=2:registration="));
    assert_eq!(outcomes_a[3], "cleared:timer_id=0:was_active=true");

    // Negative control: constant-42 or constant-100 synthetic ids would fail both handle distinctness and exact id checks.
    assert!(
        outcomes_a
            .iter()
            .all(|outcome| !outcome.contains("timer_id=42") && !outcome.contains("timer_id=100")),
        "negative control: synthetic constant timer handles are forbidden"
    );
}

#[test]
fn no_mock_set_interval_repeats_until_exact_clear_interval_and_records_evidence() {
    let package = ExtensionPackage {
        extension_id: "timer-no-mock-interval-tu32j-1-12".to_string(),
        source: r#"
            let ticksA = 0;
            let ticksB = 0;
            const idA = setInterval(() => {
                ticksA += 1;
                console.log('A:' + ticksA);
                if (ticksA >= 3) {
                    clearInterval(idA);
                }
            }, 1);
            const idB = setInterval(() => {
                ticksB += 1;
                console.log('B:' + ticksB);
                clearInterval(idB);
            }, 1);
            console.log('same=' + (idA === idB));
        "#
        .to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec![
            "vm_dispatch".to_string(),
            "heap_allocate".to_string(),
            "console".to_string(),
            "timer".to_string(),
        ],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };

    let mut orchestrator = production_orchestrator();
    let result = orchestrator
        .execute(&package)
        .expect("setInterval/clearInterval program succeeds");
    let console: Vec<&str> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        console,
        vec!["same=false", "A:1", "B:1", "A:2", "A:3"],
        "clearInterval(idB) must stop only B after 1 tick while idA ticks 3 times"
    );

    let transcript = result
        .cell_execution_transcript
        .as_ref()
        .expect("interval execution cell transcript");
    transcript.verify().expect("interval transcript verifies");

    let outcomes: Vec<&str> = transcript
        .events
        .iter()
        .filter_map(|event| match &event.kind {
            CellExecutionEventKind::EffectCompleted { outcome, .. }
                if outcome.starts_with("scheduled:") || outcome.starts_with("cleared:") =>
            {
                Some(outcome.as_str())
            }
            _ => None,
        })
        .collect();
    assert!(
        outcomes
            .iter()
            .any(|o| o.starts_with("scheduled:timer_id=0:"))
    );
    assert!(
        outcomes
            .iter()
            .any(|o| o.starts_with("scheduled:timer_id=1:"))
    );
    assert!(outcomes.contains(&"cleared:timer_id=1:was_active=true"));
    assert!(outcomes.contains(&"cleared:timer_id=0:was_active=true"));
}

#[derive(Debug)]
struct CancelAfterMainTurnHook {
    token: CancellationToken,
}

impl InterpreterHook for CancelAfterMainTurnHook {
    fn pre_property_access(
        &self,
        _ctx: &HookContext,
        _target: &ObjectRef,
        _key: &PropertyKey,
    ) -> HookAction {
        HookAction::Allow
    }

    fn pre_call(&self, _ctx: &HookContext, callee: &FunctionRef, _args: &[Value]) -> HookAction {
        let callee_name = match callee {
            FunctionRef::Function { name, .. } | FunctionRef::Closure { name, .. } => {
                name.as_deref()
            }
        };
        if callee_name == Some("triggerCancel") {
            self.token.cancel();
        }
        HookAction::Allow
    }

    fn pre_allocation(
        &self,
        _ctx: &HookContext,
        _kind: AllocKind,
        _size_hint: usize,
    ) -> HookAction {
        HookAction::Allow
    }

    fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
        HookAction::Allow
    }
}

#[test]
fn timer_capability_denial_and_pre_turn_cancellation_prevent_delivery() {
    // 1. Capability denial through ExecutionOrchestrator when `timer` capability is absent.
    let unprivileged = ExtensionPackage {
        extension_id: "timer-cap-denied-tu32j-1-12".to_string(),
        source: "setTimeout(() => console.log('must-not-run'), 1);".to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec![
            "vm_dispatch".to_string(),
            "heap_allocate".to_string(),
            "console".to_string(),
        ],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut orchestrator = production_orchestrator();
    assert!(
        orchestrator.execute(&unprivileged).is_err(),
        "setTimeout without timer capability must fail closed"
    );

    // 2. Cancellation before the deferred timer turn prevents callback delivery.
    let source = r#"
        let delivered = false;
        function triggerCancel() { return 1; }
        setTimeout(() => { delivered = true; console.log('delivered'); }, 1);
        triggerCancel();
        delivered;
    "#;
    let syntax_tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "timer-cancel-tu32j-1-12.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parse cancellation script");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(syntax_tree, "timer-cancel-tu32j-1-12.js"),
        &LoweringContext::new("trace-cancel", "decision-cancel", "policy-cancel"),
    )
    .expect("lower cancellation script");

    let token = CancellationToken::new();
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Console,
        RuntimeCapability::Timer,
    ]);
    config.cancellation_token = Some(token.clone());
    config.checkpoint_density = 1;
    let lane = QuickJsLane::with_config(config);
    let hook: Arc<dyn InterpreterHook> = Arc::new(CancelAfterMainTurnHook {
        token: token.clone(),
    });
    let err = lane
        .execute_with_hook(&lowered.ir3, "trace-cancel", Some(hook))
        .expect_err("cancellation before timer turn must abort execution");
    assert!(
        matches!(err, InterpreterError::Cancelled),
        "expected InterpreterError::Cancelled, got {err:?}"
    );
}

#[derive(Debug)]
struct StaleProbeCompletion;

impl TimerEffectCompletion for StaleProbeCompletion {
    fn complete(
        self: Box<Self>,
        _outcome: &InterpreterTimerOutcome,
    ) -> Result<(), TimerEffectAuthorityError> {
        Ok(())
    }
}

#[derive(Debug)]
struct CellPermitTimerAuthority {
    permit: frankenengine_engine::execution_cell::CellExecutionPermit,
}

impl TimerEffectAuthority for CellPermitTimerAuthority {
    fn begin(
        &self,
        request: &InterpreterTimerRequest,
    ) -> Result<TimerEffectPermit, TimerEffectAuthorityError> {
        self.permit
            .observe_ifc_label(request.ifc_label.clone())
            .map_err(|err| match err {
                CellExecutionError::Cancelled => {
                    TimerEffectAuthorityError::new("TIMER_CELL_CANCELLED", err.to_string())
                }
                CellExecutionError::CapabilityDenied { .. } => {
                    TimerEffectAuthorityError::new("TIMER_CELL_CAPABILITY_DENIED", err.to_string())
                }
                CellExecutionError::InvalidPhase { .. } | CellExecutionError::StaleEpoch { .. } => {
                    TimerEffectAuthorityError::new("TIMER_CELL_STALE_OR_CLOSED", err.to_string())
                }
                other => TimerEffectAuthorityError::new("TIMER_CELL_DENIED", other.to_string()),
            })?;
        self.permit
            .begin_effect(
                "timer",
                request.request_kind(),
                ContentHash::compute(b"timer-probe"),
                RuntimeCapability::Timer,
            )
            .map_err(|err| match err {
                CellExecutionError::Cancelled => {
                    TimerEffectAuthorityError::new("TIMER_CELL_CANCELLED", err.to_string())
                }
                CellExecutionError::CapabilityDenied { .. } => {
                    TimerEffectAuthorityError::new("TIMER_CELL_CAPABILITY_DENIED", err.to_string())
                }
                CellExecutionError::InvalidPhase { .. } | CellExecutionError::StaleEpoch { .. } => {
                    TimerEffectAuthorityError::new("TIMER_CELL_STALE_OR_CLOSED", err.to_string())
                }
                other => {
                    TimerEffectAuthorityError::new("TIMER_CELL_AUTHORITY_DENIED", other.to_string())
                }
            })?;
        Ok(TimerEffectPermit::with_completion(Box::new(
            StaleProbeCompletion,
        )))
    }
}

#[test]
fn closed_or_stale_execution_cell_rejects_timer_effects_fail_closed() {
    let token = CancellationToken::new();
    let mut cell = ExecutionCell::with_context(
        "timer-cell-tu32j-1-12",
        CellKind::Extension,
        "trace-cell-tu32j",
        "decision-cell-tu32j",
        "policy-cell-tu32j",
    );
    cell.bind_execution_authority(CellExecutionAuthority::new(
        CellExecutionAuthoritySnapshot {
            cell_id: "timer-cell-tu32j-1-12".to_string(),
            trace_id: "trace-cell-tu32j".to_string(),
            decision_id: "decision-cell-tu32j".to_string(),
            policy_id: "policy-cell-tu32j".to_string(),
            policy_epoch: SecurityEpoch::from_raw(3),
            capabilities: BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::Timer]),
            initial_ifc_label: Label::Public,
            instruction_budget: 100,
            memory_budget_bytes: 1024 * 1024,
        },
        token,
    ))
    .expect("bind execution authority");

    let retained_permit = Arc::new(std::sync::Mutex::new(None));
    let retained_clone = retained_permit.clone();
    cell.run_interpreter(|permit| {
        *retained_clone.lock().expect("mutex") = Some(permit.clone());
        permit
            .settle_interpreter_budget(0)
            .expect("settle zero budget");
        Ok::<(), ()>(())
    })
    .expect("cell boundary")
    .expect("interpreter ok");

    let stale_permit = retained_permit
        .lock()
        .expect("mutex")
        .take()
        .expect("retained permit");
    let authority = CellPermitTimerAuthority {
        permit: stale_permit,
    };
    let req = InterpreterTimerRequest {
        operation: TimerOperation::SetTimeout,
        duration_ms: Some(5),
        timer_id: None,
        callback_id: Some(0),
        ifc_label: Label::Public,
    };
    let err = authority
        .begin(&req)
        .expect_err("closed/completed cell permit must reject timer proposal");
    assert_eq!(err.code, "TIMER_CELL_STALE_OR_CLOSED");
}
