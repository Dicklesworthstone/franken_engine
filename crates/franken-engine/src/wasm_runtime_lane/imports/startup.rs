//! Resolver-owned startup with a fresh policy decision at every executor poll.
//!
//! The numeric startup future owns unpublished state and its cumulative meter.
//! This layer supplies only resolution authorization and host-scope binding; it
//! never reimplements the evaluator or exposes an unchecked partial instance.

use super::*;
use std::future::{Future, poll_fn};
use std::num::NonZeroU64;
use std::pin::Pin;
use std::task::Poll;

impl WasmNativeModule {
    /// Run a one-shot WASI command under the caller's current policy snapshot.
    /// This consumes the provider registry and never exposes a live instance
    /// after `_start` returns, exits or fails. Validate the command ABI before
    /// binary startup effects; retain the ordinary manifest/provider intersection
    /// and pinned recording/replay scope. Completed external effects survive.
    ///
    /// The supplied policy is a snapshot, not a subscription. Bind the existing
    /// live execution/service tokens for revocation during this synchronous run.
    /// Startup and `_start` retain their separate hard invocation budgets.
    pub fn run_wasi_command(
        &self,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
        mut imports: WasmHostImports,
    ) -> Result<super::super::wasi_preview1::WasiCommandOutcome, WasmNativeLoadError> {
        self.authorize(context, policy)?;
        imports.restrict_capabilities(&self.resolution.module.record.required_capabilities);
        imports
            .bind_module(self.resolution.module.content_hash)
            .map_err(WasmNumericVmError::from)?;
        Ok(super::super::wasi_preview1::run_command_with_outcome(
            &self.vm, imports,
        )?)
    }

    /// Create a lazy, executor-driven instantiation with no host services.
    /// `current_policy` is a trusted embedding callback that reads the CURRENT
    /// resolution context and capability policy, not a grant cached at loading.
    /// It is called before every startup poll and once more before publishing a
    /// successfully initialized instance. Reader failure or policy denial drops
    /// all unpublished guest state and terminates the future.
    ///
    /// Construction does not invoke the reader, allocate instance state, or run
    /// guest code. Initial allocation and active segments remain synchronous on
    /// the first authorized poll. The quantum bounds cooperative guest work,
    /// not wall-clock time: individual bulk instructions, setup and native
    /// callbacks remain indivisible. The original hard VM budget spans polls.
    ///
    /// The reader must return current snapshots and must not block the executor.
    /// For cancellation within a slice, bind the existing execution token through
    /// explicit imports. Neither snapshots nor cooperative polling preempt native
    /// callbacks. Dropping the future never rolls back completed external I/O.
    pub fn instantiate_cooperatively<'vm, P>(
        &'vm self,
        work: NonZeroU64,
        current_policy: P,
    ) -> impl Future<Output = Result<WasmNativeInstance<'vm>, WasmNativeLoadError>> + Send + 'vm
    where
        P: FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError>
            + Send
            + 'vm,
    {
        guarded_startup(
            self,
            move || Ok(self.vm.instantiate_cooperatively(work)),
            current_policy,
        )
    }

    /// Cooperative startup with explicit providers, narrowed to the pinned
    /// module's declared capabilities. Current policy must authorize that whole
    /// declaration before linking, on each later poll, and before publication.
    /// Provider grants cannot broaden the manifest or be restored by a policy
    /// change. All import signatures and live controls use the existing linker.
    ///
    /// Recording/replay remains bound to this exact resolution content hash;
    /// replaying an unscoped or another module's tape cannot execute startup.
    /// Completed provider effects survive a later refusal, but no failed partial
    /// instance is returned. After completion, calls and inspection still require
    /// current policy through the ordinary WasmNativeInstance methods.
    pub fn instantiate_cooperatively_with_imports<'vm, P>(
        &'vm self,
        imports: WasmHostImports,
        work: NonZeroU64,
        current_policy: P,
    ) -> impl Future<Output = Result<WasmNativeInstance<'vm>, WasmNativeLoadError>> + Send + 'vm
    where
        P: FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError>
            + Send
            + 'vm,
    {
        guarded_startup(
            self,
            move || {
                let mut imports = imports;
                imports.restrict_capabilities(&self.resolution.module.record.required_capabilities);
                imports
                    .bind_module(self.resolution.module.content_hash)
                    .map_err(WasmNumericVmError::from)?;
                Ok(self
                    .vm
                    .instantiate_cooperatively_with_imports(imports, work))
            },
            current_policy,
        )
    }
}

fn authorize_current<P>(
    module: &WasmNativeModule,
    reader: &mut P,
) -> Result<(), WasmNativeLoadError>
where
    P: FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError>,
{
    let (context, policy) = reader()?;
    module.authorize(&context, &policy)
}

fn guarded_startup<'vm, F, C, P>(
    module: &'vm WasmNativeModule,
    create: C,
    mut reader: P,
) -> impl Future<Output = Result<WasmNativeInstance<'vm>, WasmNativeLoadError>> + Send + 'vm
where
    F: Future<Output = Result<WasmNumericInstance<'vm>, WasmNumericVmError>> + Unpin + Send + 'vm,
    C: FnOnce() -> Result<F, WasmNativeLoadError> + Send + 'vm,
    P: FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError>
        + Send
        + 'vm,
{
    let mut create = Some(create);
    let mut active: Option<F> = None;
    let mut finished = false;
    poll_fn(move |cx| {
        assert!(
            !finished,
            "resolved startup polled after completion or panic"
        );
        // A panic in a policy reader, provider or waker cannot make a partially
        // consumed host callback resumable after catch_unwind and another poll.
        finished = true;
        if let Err(error) = authorize_current(module, &mut reader) {
            active = None;
            create = None;
            return Poll::Ready(Err(error));
        }
        if active.is_none() {
            match create.take().expect("unstarted resolved instantiation")() {
                Ok(future) => active = Some(future),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        match Pin::new(active.as_mut().expect("authorized startup future")).poll(cx) {
            Poll::Pending => {
                // The numeric future already wakes exactly once for a genuine
                // yield. No extra wake, new meter, or restart is introduced here.
                finished = false;
                Poll::Pending
            }
            Poll::Ready(Err(error)) => {
                active = None;
                // Preserve an execution failure over a later policy-reader error.
                Poll::Ready(Err(error.into()))
            }
            Poll::Ready(Ok(instance)) => {
                active = None;
                // A final host callback may have revoked policy before returning.
                // Check again even for no-start modules; denial drops the ready
                // but still unpublished instance instead of leaking its state.
                match authorize_current(module, &mut reader) {
                    Ok(()) => Poll::Ready(Ok(WasmNativeInstance { module, instance })),
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
        }
    })
}

impl WasmNativeModule {
    /// Prepare lazy startup for an embedder-driven scheduler. Unlike the Future
    /// API's policy-reader callback, this task takes a current policy SNAPSHOT
    /// and soft quantum on each resume. No grant is retained between turns.
    pub fn prepare_startup(&self) -> super::super::scheduler::WasmStartupTask<'_> {
        self.prepare_startup_bindings(None)
    }

    /// Prepare startup with owned providers. All import signatures, provider
    /// grants, manifest capabilities and transcript identity are checked before
    /// state allocation on the first authorized resume. Later resumes recheck
    /// the entire pinned module declaration; live host controls remain active.
    pub fn prepare_startup_with_imports(
        &self,
        imports: WasmHostImports,
    ) -> super::super::scheduler::WasmStartupTask<'_> {
        self.prepare_startup_bindings(Some(imports))
    }

    fn prepare_startup_bindings(
        &self,
        imports: Option<WasmHostImports>,
    ) -> super::super::scheduler::WasmStartupTask<'_> {
        let mut pending_imports = Some(imports);
        let mut driver = None;
        super::super::scheduler::WasmStartupTask::new(move |work, context, policy| {
            self.authorize(context, policy)?;
            if driver.is_none() {
                let mut imports = pending_imports
                    .take()
                    .expect("unstarted scheduled initialization");
                if let Some(imports) = imports.as_mut() {
                    imports.restrict_capabilities(
                        &self.resolution.module.record.required_capabilities,
                    );
                    imports
                        .bind_module(self.resolution.module.content_hash)
                        .map_err(WasmNumericVmError::from)?;
                }
                driver = Some(self.vm.cooperative_startup_driver(imports));
            }
            let (instructions, instance) = driver.as_mut().expect("prepared startup driver")(work)?;
            Ok((
                instructions,
                instance.map(|instance| WasmNativeInstance {
                    module: self,
                    instance,
                }),
            ))
        })
    }
}

impl WasmNativeModule {
    /// Run binary startup and `_start` cooperatively without exposing a partial
    /// or reusable command instance. Construction is lazy: the first poll checks
    /// CURRENT policy and the entry signature before any guest allocation or
    /// callback. Every subsequent startup/entry slice uses a new policy read;
    /// a final read also gates normal return and typed exit status publication.
    /// A reader may be called more than once per poll and must not block.
    ///
    /// Startup and entry retain their separate original hard invocation budgets;
    /// neither budget is replenished by yielding. A mandatory yield separates
    /// startup from entry so both cannot spend a whole quantum in one poll.
    /// Individual allocations, bulk operations and native callbacks remain
    /// indivisible: this is not a wall-clock or native-code preemption bound.
    ///
    /// The same resolved linker, activation machine and scoped host replay path
    /// execute both phases. Drop, denial and failure destroy private state but
    /// do not undo external effects already completed. A completed or panicked
    /// future cannot be polled again to repeat a provider or command entry.
    pub fn run_wasi_command_cooperatively<'vm, P>(
        &'vm self,
        imports: WasmHostImports,
        work: NonZeroU64,
        mut current_policy: P,
    ) -> impl Future<
        Output = Result<super::super::wasi_preview1::WasiCommandOutcome, WasmNativeLoadError>,
    > + Send
    + 'vm
    where
        P: FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError>
            + Send
            + 'vm,
    {
        use super::super::wasi_preview1::{WasiCommandOutcome, WasiCommandPhase};
        let command = async move {
            authorize_current(self, &mut current_policy)?;
            self.validate_command_entry()?;
            let mut imports = imports;
            imports.restrict_capabilities(&self.resolution.module.record.required_capabilities);
            imports
                .bind_module(self.resolution.module.content_hash)
                .map_err(WasmNumericVmError::from)?;
            let startup = {
                let mut future = self
                    .vm
                    .instantiate_cooperatively_with_imports(imports, work);
                poll_fn(|cx| {
                    if let Err(error) = authorize_current(self, &mut current_policy) {
                        return Poll::Ready(Err(error));
                    }
                    match Pin::new(&mut future).poll(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(result) => {
                            Poll::Ready(result.map_err(WasmNativeLoadError::from))
                        }
                    }
                })
                .await
            };
            let mut instance = match startup {
                Ok(instance) => WasmNativeInstance {
                    module: self,
                    instance,
                },
                Err(error) => {
                    // Ordinary failures keep precedence. Only a genuine exit
                    // reaches the final fresh-policy publication check.
                    let outcome = command_exit(error, WasiCommandPhase::Instantiation)?;
                    authorize_current(self, &mut current_policy)?;
                    return Ok(outcome);
                }
            };
            authorize_current(self, &mut current_policy)?;
            let startup_metrics = instance.instance.start_execution().cloned();
            let mut yielded = false;
            poll_fn(|cx| {
                if yielded {
                    return Poll::Ready(());
                }
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            })
            .await;

            let outcome = {
                let (context, policy) = current_policy()?;
                let mut pending = Some(instance.begin_call("_start", &[], &context, &policy)?);
                poll_fn(|cx| {
                    let (context, policy) = match current_policy() {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            pending = None;
                            return Poll::Ready(Err(error));
                        }
                    };
                    let call = pending.take().expect("unfinished command entry");
                    match call.resume(work, &context, &policy) {
                        Ok(WasmNativeCallStep::Pending(call)) => {
                            pending = Some(call);
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Ok(WasmNativeCallStep::Complete(execution)) => Poll::Ready(Ok(execution)),
                        Err(error) => Poll::Ready(Err(error)),
                    }
                })
                .await
            };
            let outcome = match outcome {
                Ok(execution) => WasiCommandOutcome::Returned {
                    startup: startup_metrics,
                    execution,
                },
                Err(error) => command_exit(error, WasiCommandPhase::Command)?,
            };
            // In particular, a final provider may revoke policy and then exit.
            // It cannot turn that revocation into an authorized status result.
            authorize_current(self, &mut current_policy)?;
            Ok(outcome)
        };
        let mut active = Some(Box::pin(command));
        let mut finished = false;
        poll_fn(move |cx| {
            assert!(!finished, "command future polled after completion or panic");
            // Also covers a panicking policy reader, callback or executor waker.
            finished = true;
            match active
                .as_mut()
                .expect("unfinished command")
                .as_mut()
                .poll(cx)
            {
                Poll::Pending => {
                    finished = false;
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    active = None; // Release private instance/providers now.
                    Poll::Ready(result)
                }
            }
        })
    }

    fn validate_command_entry(&self) -> Result<(), WasmNativeLoadError> {
        let signature = self.vm.export_signature("_start")?;
        if !signature.params.is_empty() || !signature.results.is_empty() {
            return Err(WasmNumericVmError::InvalidModule {
                detail: "WASI command _start must have no parameters or results".into(),
            }
            .into());
        }
        Ok(())
    }
}

fn command_exit(
    error: WasmNativeLoadError,
    phase: super::super::wasi_preview1::WasiCommandPhase,
) -> Result<super::super::wasi_preview1::WasiCommandOutcome, WasmNativeLoadError> {
    use super::super::numeric::{WasmHostError, WasmStateError};
    match error {
        WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::ProcessExit { code },
        ))) => Ok(super::super::wasi_preview1::WasiCommandOutcome::Exited { code, phase }),
        error => Err(error),
    }
}

impl WasmNativeModule {
    /// Prepare one lazy command: binary initialization followed by `_start`.
    /// Providers are explicit; no WASI services or process state are installed
    /// implicitly. The command ABI is checked before any initializer effects.
    /// Every resume checks the current policy, including the mandatory turn
    /// boundary between initialization and entry. One hard VM work budget spans
    /// both phases, unlike separately invoked startup and export APIs.
    pub fn prepare_command(
        &self,
        imports: WasmHostImports,
    ) -> super::super::command::WasmCommandTask<'_> {
        let mut pending_imports = Some(imports);
        let mut driver = None;
        super::super::command::WasmCommandTask::new(move |work, context, policy| {
            self.authorize(context, policy)?;
            if driver.is_none() {
                let mut imports = pending_imports.take().expect("unstarted command");
                imports.restrict_capabilities(&self.resolution.module.record.required_capabilities);
                imports
                    .bind_module(self.resolution.module.content_hash)
                    .map_err(WasmNumericVmError::from)?;
                driver = Some(self.vm.cooperative_command_driver(imports));
            }
            Ok(driver.as_mut().expect("prepared command driver")(work)?)
        })
    }
}
