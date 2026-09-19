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
        imports.bind_module(self.resolution.module.content_hash).map_err(WasmNumericVmError::from)?;
        Ok(super::super::wasi_preview1::run_command_with_outcome(&self.vm, imports)?)
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
            + Send + 'vm,
    {
        guarded_startup(self, move || Ok(self.vm.instantiate_cooperatively(work)), current_policy)
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
            + Send + 'vm,
    {
        guarded_startup(self, move || {
            let mut imports = imports;
            imports.restrict_capabilities(&self.resolution.module.record.required_capabilities);
            imports.bind_module(self.resolution.module.content_hash).map_err(WasmNumericVmError::from)?;
            Ok(self.vm.instantiate_cooperatively_with_imports(imports, work))
        }, current_policy)
    }
}

fn authorize_current<P>(module: &WasmNativeModule, reader: &mut P) -> Result<(), WasmNativeLoadError>
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
    P: FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError> + Send + 'vm,
{
    let mut create = Some(create);
    let mut active: Option<F> = None;
    let mut finished = false;
    poll_fn(move |cx| {
        assert!(!finished, "resolved startup polled after completion or panic");
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
                let mut imports = pending_imports.take().expect("unstarted scheduled initialization");
                if let Some(imports) = imports.as_mut() {
                    imports.restrict_capabilities(&self.resolution.module.record.required_capabilities);
                    imports.bind_module(self.resolution.module.content_hash).map_err(WasmNumericVmError::from)?;
                }
                driver = Some(self.vm.cooperative_startup_driver(imports));
            }
            let (instructions, instance) = driver.as_mut().expect("prepared startup driver")(work)?;
            Ok((instructions, instance.map(|instance| WasmNativeInstance { module: self, instance })))
        })
    }
}
