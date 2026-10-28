//! Process lifecycle calls must cross the live effect membrane.
//!
//! These boundary tests exercise the real native builtin dispatch and journal.
//! The recording provider is an observation probe; they do not claim native
//! process transport acceptance (covered separately by the Unix integration suite).

use super::*;
use std::sync::Mutex;

use frankenengine_extension_host::host_effect_journal::HostEffectJournalEntry;
use frankenengine_extension_host::process_spawn::{
    ProcessSpawnCapability, ProcessSpawnOutcome,
};

#[derive(Debug, Default)]
struct LifecycleProvider {
    requests: Mutex<Vec<ProcessSpawnRequest>>,
    cleanup_count: Mutex<usize>,
}

impl ProcessSpawnProvider for LifecycleProvider {
    fn name(&self) -> &str {
        "process-lifecycle-boundary-probe"
    }

    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        assert_eq!(granted, &[ProcessSpawnCapability::Spawn]);
        self.requests.lock().unwrap().push(request.clone());
        match request {
            ProcessSpawnRequest::WriteStdin { data, .. } => {
                Ok(ProcessSpawnResponse::StdinWritten {
                    bytes_written: data.len() as u64,
                })
            }
            ProcessSpawnRequest::CloseStdin { .. } => Ok(ProcessSpawnResponse::StdinClosed),
            ProcessSpawnRequest::Kill { signal, .. } => Ok(ProcessSpawnResponse::Killed {
                signal: *signal,
                exit: ProcessExit {
                    success: false,
                    code: None,
                    signal: Some(15),
                },
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            _ => panic!("unexpected operation in lifecycle boundary test"),
        }
    }

    fn cleanup_handle(&self, handle: &str) -> ProcessSpawnOutcome {
        assert_eq!(handle, "fixture-child");
        *self.cleanup_count.lock().unwrap() += 1;
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    }
}

struct LifecycleHook {
    action: HookAction,
    observations: Mutex<Vec<(String, bool)>>,
}

impl InterpreterHook for LifecycleHook {
    fn instruction_hooks_enabled(&self) -> bool {
        false
    }

    fn pre_property_access(
        &self,
        _ctx: &HookContext,
        _target: &ObjectRef,
        _key: &PropertyKey,
    ) -> HookAction {
        HookAction::Allow
    }

    fn pre_call(&self, _ctx: &HookContext, _callee: &FunctionRef, _args: &[Value]) -> HookAction {
        HookAction::Allow
    }

    fn pre_allocation(&self, _ctx: &HookContext, _kind: AllocKind, _size: usize) -> HookAction {
        HookAction::Allow
    }

    fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
        HookAction::Allow
    }

    fn pre_hostcall(&self, _ctx: &HookContext, capability: &str, allowed: bool) -> HookAction {
        self.observations.lock().unwrap().push((capability.to_string(), allowed));
        self.action.clone()
    }
}

struct Fixture {
    core: InterpreterCore,
    child: ObjectId,
    stdin: ObjectId,
    provider: Arc<LifecycleProvider>,
    journal: Arc<InMemoryHostEffectJournal>,
    hook: Arc<LifecycleHook>,
}

impl Fixture {
    fn new(throughput: bool, action: HookAction) -> Self {
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::ProcessSpawn,
        ]);
        let mut core = InterpreterCore::new(config, "process-lifecycle-membrane");
        let child = core.alloc_branded_object("ChildProcess", &[]).unwrap();
        let stdin = core.alloc_branded_object("ChildProcessStdin", &[]).unwrap();
        core.child_process_handles.insert(child, "fixture-child".to_string());
        core.child_process_streams.insert(stdin, (child, ChildProcessStreamKind::Stdin));
        let provider = Arc::new(LifecycleProvider::default());
        let journal = Arc::new(InMemoryHostEffectJournal::recording());
        journal.begin_execution().unwrap();
        core.set_process_spawn(provider.clone(), journal.clone());
        let hook = Arc::new(LifecycleHook {
            action,
            observations: Mutex::new(Vec::new()),
        });
        core.hook = Some(hook.clone());
        core.write_reg(0, Value::str("public-bytes")).unwrap();
        core.set_register_label(0, Label::Public).unwrap();
        Self { core, child, stdin, provider, journal, hook }
    }

    fn invoke(&mut self, kind: BuiltinFunctionKind) -> Result<Value, InterpreterError> {
        let receiver = if kind == BuiltinFunctionKind::ChildProcessKill {
            self.child
        } else {
            self.stdin
        };
        self.core.write_reg(1, Value::Object(receiver))?;
        // A process handle has the source floor of the process result. It is
        // lifecycle identity, not the bytes sent through stdin.
        self.core.set_register_label(1, Label::Internal)?;
        let module = Ir3Module::new(
            ContentHash::compute(b"process-lifecycle-membrane"),
            "process-lifecycle-membrane",
        );
        self.core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(kind),
            RegRange {
                start: 0,
                count: u32::from(kind == BuiltinFunctionKind::ChildProcessStdinWrite),
            },
            Some(Value::Object(receiver)),
            Some(1),
        )
    }
}

fn lifecycle_kinds() -> [BuiltinFunctionKind; 3] {
    [
        BuiltinFunctionKind::ChildProcessStdinWrite,
        BuiltinFunctionKind::ChildProcessStdinEnd,
        BuiltinFunctionKind::ChildProcessKill,
    ]
}

#[test]
fn public_lifecycle_effects_are_authorized_and_observed_once_in_both_profiles() {
    for throughput in [false, true] {
        let mut fixture = Fixture::new(throughput, HookAction::Allow);
        assert_eq!(
            fixture.invoke(BuiltinFunctionKind::ChildProcessStdinWrite).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            fixture.invoke(BuiltinFunctionKind::ChildProcessStdinEnd).unwrap(),
            Value::Undefined
        );
        assert_eq!(
            fixture.invoke(BuiltinFunctionKind::ChildProcessKill).unwrap(),
            Value::Bool(true)
        );
        let requests = fixture.provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(matches!(
            &requests[0],
            ProcessSpawnRequest::WriteStdin { handle, data }
                if handle == "fixture-child" && data.as_slice() == b"public-bytes"
        ));
        assert!(matches!(&requests[1], ProcessSpawnRequest::CloseStdin { .. }));
        assert!(matches!(&requests[2], ProcessSpawnRequest::Kill { .. }));
        assert_eq!(fixture.journal.entries().len(), 3);
        assert_eq!(fixture.core.hostcall_decisions.len(), 3);
        assert!(fixture.core.hostcall_decisions.iter().all(|record| {
            record.capability.0 == "process_spawn" && record.allowed
        }));
        assert_eq!(
            *fixture.hook.observations.lock().unwrap(),
            vec![("process_spawn".to_string(), true); 3]
        );
    }
}

#[test]
fn a_retained_child_handle_does_not_replace_live_process_authority() {
    for throughput in [false, true] {
        for kind in lifecycle_kinds() {
            let mut fixture = Fixture::new(throughput, HookAction::Allow);
            fixture.core.config.granted_capabilities.remove(&RuntimeCapability::ProcessSpawn);
            assert!(matches!(
                fixture.invoke(kind),
                Err(InterpreterError::CapabilityDenied { capability })
                    if capability == "process_spawn"
            ), "{kind:?}");
            assert!(fixture.provider.requests.lock().unwrap().is_empty());
            assert!(fixture.journal.entries().is_empty());
            assert_eq!(fixture.core.hostcall_decisions.len(), 1);
            assert!(!fixture.core.hostcall_decisions[0].allowed);
            assert_eq!(
                *fixture.hook.observations.lock().unwrap(),
                vec![("process_spawn".to_string(), false)]
            );
        }
    }
}

#[test]
fn lifecycle_containment_precedes_the_effect_and_preserves_compensating_cleanup() {
    for throughput in [false, true] {
        for kind in lifecycle_kinds() {
            let mut fixture = Fixture::new(throughput, HookAction::Suspend);
            assert!(matches!(
                fixture.invoke(kind),
                Err(InterpreterError::ContainmentActionRequested { action, .. })
                    if action == "suspend"
            ), "containment must not be converted into kill() returning false: {kind:?}");
            assert!(fixture.provider.requests.lock().unwrap().is_empty());
            assert!(fixture.journal.entries().is_empty());
            assert_eq!(
                *fixture.hook.observations.lock().unwrap(),
                vec![("process_spawn".to_string(), true)]
            );

            fixture.core.config.granted_capabilities.remove(&RuntimeCapability::ProcessSpawn);
            fixture.core.cleanup_process_handle("fixture-child").unwrap();
            assert_eq!(*fixture.provider.cleanup_count.lock().unwrap(), 1);
            assert!(matches!(
                fixture.journal.entries().as_slice(),
                [HostEffectJournalEntry::ProcessSpawn {
                    request: ProcessSpawnRequest::Cleanup { .. },
                    outcome: Ok(ProcessSpawnResponse::Cleaned { was_present: true }),
                }]
            ));
            assert_eq!(fixture.hook.observations.lock().unwrap().len(), 1);
        }
    }
}

#[test]
fn stdin_preserves_scalar_backing_storage_and_callback_confidentiality() {
    for throughput in [false, true] {
        for source in ["register", "buffer-alias", "callback-context"] {
            let mut fixture = Fixture::new(throughput, HookAction::Allow);
            match source {
                "register" => {
                    fixture.core.set_register_label(0, Label::Secret).unwrap();
                }
                "buffer-alias" => {
                    let buffer = fixture.core.alloc_buffer_from_bytes(b"secret-bytes").unwrap();
                    fixture.core.join_binary_storage_label(buffer, &Label::Secret).unwrap();
                    let backing = fixture.core.array_buffer_id_for_object(buffer).unwrap();
                    let alias = fixture.core.alloc_buffer_view_object(backing, 0, 12).unwrap();
                    fixture.core.write_reg(0, Value::Object(alias)).unwrap();
                    fixture.core.set_register_label(0, Label::Public).unwrap();
                    assert_eq!(fixture.core.binary_storage_label(alias), Label::Secret);
                }
                "callback-context" => {
                    fixture.core.active_inline_callback_context_label = Some(Label::Secret);
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                fixture.invoke(BuiltinFunctionKind::ChildProcessStdinWrite),
                Err(InterpreterError::HostProcess { code, message, .. })
                    if code == "EACCES" && message.contains("FLOW_POLICY_BLOCKED")
            ), "{source}");
            assert!(fixture.provider.requests.lock().unwrap().is_empty(), "{source}");
            assert!(matches!(
                fixture.journal.entries().as_slice(),
                [HostEffectJournalEntry::ProcessSpawn {
                    request: ProcessSpawnRequest::WriteStdin { .. },
                    outcome: Err(ProcessSpawnError::FlowPolicyBlocked),
                }]
            ), "{source}");
            let recorded = fixture.journal.finish_execution().unwrap();
            let replay = Arc::new(InMemoryHostEffectJournal::replaying(recorded.clone()));
            replay.begin_execution().unwrap();
            fixture
                .core
                .set_process_spawn(fixture.provider.clone(), replay.clone());
            assert!(
                matches!(
                    fixture.invoke(BuiltinFunctionKind::ChildProcessStdinWrite),
                    Err(InterpreterError::HostProcess { code, message, .. })
                        if code == "EACCES" && message.contains("FLOW_POLICY_BLOCKED")
                ),
                "replay must preserve the actual IFC denial: {source}"
            );
            assert_eq!(replay.finish_execution().unwrap(), recorded, "{source}");
            assert!(
                fixture.provider.requests.lock().unwrap().is_empty(),
                "{source}"
            );
        }
    }
}

#[test]
fn ifc_denial_replay_rejects_wrong_outcome_request_and_unused_suffix() {
    use frankenengine_extension_host::host_effect_journal::HostEffectJournalError;

    for throughput in [false, true] {
        for mutation in ["success", "other-denial", "request", "suffix"] {
            let mut fixture = Fixture::new(throughput, HookAction::Allow);
            fixture.core.set_register_label(0, Label::Secret).unwrap();
            let mut request = ProcessSpawnRequest::WriteStdin {
                handle: "fixture-child".to_string(),
                data: b"public-bytes".to_vec(),
            };
            if mutation == "request" {
                request = ProcessSpawnRequest::WriteStdin {
                    handle: "fixture-child".to_string(),
                    data: b"changed-bytes".to_vec(),
                };
            }
            let outcome = match mutation {
                "success" => Ok(ProcessSpawnResponse::StdinWritten { bytes_written: 12 }),
                "other-denial" => Err(ProcessSpawnError::Denied {
                    reason: "different recorded denial".to_string(),
                }),
                _ => Err(ProcessSpawnError::FlowPolicyBlocked),
            };
            let entry = HostEffectJournalEntry::ProcessSpawn { request, outcome };
            let entries = if mutation == "suffix" {
                vec![entry.clone(), entry]
            } else {
                vec![entry]
            };
            let replay = Arc::new(InMemoryHostEffectJournal::replaying(entries));
            replay.begin_execution().unwrap();
            fixture
                .core
                .set_process_spawn(fixture.provider.clone(), replay.clone());
            assert!(
                fixture
                    .invoke(BuiltinFunctionKind::ChildProcessStdinWrite)
                    .is_err(),
                "{mutation}"
            );
            let error = replay
                .finish_execution()
                .expect_err("altered denial cannot certify");
            if mutation == "suffix" {
                assert!(
                    matches!(
                        error,
                        HostEffectJournalError::UnusedReplaySuffix {
                            index: 1,
                            remaining: 1
                        }
                    ),
                    "{error}"
                );
            } else {
                assert!(
                    matches!(error, HostEffectJournalError::ReplayDivergence { .. }),
                    "{mutation}: {error}"
                );
            }
            assert!(
                fixture.provider.requests.lock().unwrap().is_empty(),
                "{mutation}"
            );
        }
    }
}
