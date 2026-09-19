//! Executor-facing startup through the same activation machine as exports.
//!
//! Keep linking inside the host boundary so no public API can bypass its
//! signature, grant, revocation or transcript-scope checks. Unpublished state
//! belongs to one future, never to an externally accessible partial instance.

use super::*;
use super::super::super::activation::{Machine, Slice};
use std::borrow::Cow;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::task::{Context, Poll};

impl WasmNumericVm {
    /// Instantiate lazily on a Rust executor, yielding between startup work
    /// slices. Construction performs no state allocation, linking or guest work.
    /// The first poll initializes memory, tables and segments; the optional
    /// start function then uses one cumulative invocation budget across polls.
    /// Only successful completion publishes an instance. No start section means
    /// completion on the first poll, with `start_execution()` remaining None.
    ///
    /// Each Pending poll wakes the current task once. Quanta are soft work
    /// limits: initial state allocation/copying, individual bulk instructions,
    /// frame setup and trusted callbacks are indivisible, not preemptible.
    /// Providers must not block an executor thread and must meter variable work.
    /// Initial state construction retains the synchronous API's resource limits
    /// and is not included in guest instruction metrics.
    ///
    /// Dropping the future discards unpublished guest state and unfinished work;
    /// external effects of callbacks that already returned cannot be rolled back.
    /// Host functions remain unbound, just as with `instantiate()`.
    pub fn instantiate_cooperatively(
        &self,
        work: NonZeroU64,
    ) -> impl Future<Output = Result<WasmNumericInstance<'_>, WasmNumericVmError>>
           + Send + Sync + Unpin + '_ {
        Startup::new(self, None, work)
    }

    /// Cooperative startup with explicit, owned host bindings. The first poll
    /// checks cancellation and validates EVERY import before allocating instance
    /// state or entering any start function. Live execution cancellation is
    /// checked at every poll and guest boundary; service-specific and host-only
    /// signals retain their existing host-boundary semantics.
    ///
    /// Recording/replay uses the existing gate, so pending host calls never run
    /// twice. An observer retained by the embedder survives failed/dropped startup.
    /// Like all Rust futures, a completed or panicked future must not be polled
    /// again; this implementation panics before repeating any effects.
    pub fn instantiate_cooperatively_with_imports(
        &self,
        imports: WasmHostImports,
        work: NonZeroU64,
    ) -> impl Future<Output = Result<WasmNumericInstance<'_>, WasmNumericVmError>>
           + Send + Sync + Unpin + '_ {
        Startup::new(self, Some(imports), work)
    }

    /// Internal scheduler seam over the very same state owner as the Future.
    /// The caller supplies each quantum; neither path resets the startup meter.
    /// No linking, allocation or guest instruction runs while creating a driver.
    pub(crate) fn cooperative_startup_driver<'vm>(
        &'vm self,
        imports: Option<WasmHostImports>,
    ) -> impl FnMut(NonZeroU64) -> Result<
        (u64, Option<WasmNumericInstance<'vm>>), WasmNumericVmError,
    > + Send + Sync + 'vm {
        let mut startup = Startup::new(self, imports, NonZeroU64::MIN);
        move |work| {
            startup.work = work;
            let instance = startup.advance()?;
            Ok((startup.meter.instructions, instance))
        }
    }
}

struct Startup<'vm> {
    vm: &'vm WasmNumericVm,
    imports: Option<WasmHostImports>,
    instance: Option<WasmNumericInstance<'vm>>,
    machine: Option<Machine<'vm, 'static>>,
    meter: ExecutionMeter<'vm>,
    work: NonZeroU64,
    finished: bool,
}

impl<'vm> Startup<'vm> {
    fn new(vm: &'vm WasmNumericVm, imports: Option<WasmHostImports>, work: NonZeroU64) -> Self {
        Self {
            vm, imports, instance: None,
            machine: vm.state.start.map(|function| Machine::new(function, Cow::Borrowed(&[]), 1)),
            meter: ExecutionMeter::new(&vm.limits), work, finished: false,
        }
    }

    fn run_slice(&mut self) -> Result<bool, WasmNumericVmError> {
        if self.instance.is_none() {
            if let Some(imports) = self.imports.as_mut() {
                imports.check_cancellation()?;
                imports.validate(self.vm)?;
            }
            let mut state = self.vm.state.instantiate(&self.vm.limits)?;
            state.host_imports = self.imports.take();
            state.check_execution_cancellation()?;
            self.instance = Some(WasmNumericInstance {
                vm: self.vm, state, start_execution: None,
            });
        }
        let instance = self.instance.as_mut().expect("prepared startup state");
        instance.state.check_execution_cancellation()?;
        let Some(machine) = self.machine.as_mut() else { return Ok(true); };
        let slice = Slice { start: self.meter.instructions, work: self.work };
        let outcome = machine.run(self.vm, &mut self.meter, &mut instance.state, Some(slice))?;
        // Preserve the first execution failure; only successful execution or
        // suspension reaches this final cancellation check, as on sync calls.
        instance.state.check_execution_cancellation()?;
        let Some(results) = outcome else { return Ok(false); };
        instance.start_execution = Some(WasmNumericExecution {
            results,
            instructions_executed: self.meter.instructions,
            peak_stack_values: self.meter.peak_stack_values,
            max_call_depth: self.meter.max_call_depth,
        });
        Ok(true)
    }
}

impl<'vm> Startup<'vm> {
    fn advance(&mut self) -> Result<Option<WasmNumericInstance<'vm>>, WasmNumericVmError> {
        assert!(!self.finished, "startup future polled after completion or panic");
        // Pessimistic terminal state prevents reentry after a provider panic.
        self.finished = true;
        match self.run_slice() {
            Ok(false) => {
                self.finished = false;
                Ok(None)
            }
            Ok(true) => {
                self.machine = None;
                Ok(Some(self.instance.take().expect("completed startup state")))
            }
            Err(error) => {
                // Release unpublished state immediately. Independently retained
                // host recordings outlive both drivers, including a failed start.
                self.machine = None;
                self.instance = None;
                self.imports = None;
                Err(error)
            }
        }
    }
}

impl<'vm> Future for Startup<'vm> {
    type Output = Result<WasmNumericInstance<'vm>, WasmNumericVmError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.advance() {
            Ok(None) => {
                // A panicking waker must not leave this future resumable either.
                this.finished = true;
                cx.waker().wake_by_ref();
                this.finished = false;
                Poll::Pending
            }
            Ok(Some(instance)) => Poll::Ready(Ok(instance)),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}
