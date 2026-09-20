//! Non-refundable work admission for native JavaScript executions.
//!
//! The interpreter's instruction counter deliberately resets on `execute`.
//! Hosts that schedule multiple executions need a second, shared boundary:
//! an execution must reserve its entire configured instruction allowance
//! before constructing or entering the interpreter. Cloning a pool shares
//! its balance; success, traps, cancellation, unwinding, and dropping an
//! interpreter never refund a reservation.
//!
//! This is an admission limit, not a measurement of retired instructions or
//! wall-clock time. Parsing, compilation, host callbacks, and operations not
//! charged by the native instruction meter need their own resource limits.
//! Pool creation is a trusted host operation; pools are intentionally not
//! serializable. Existing raw interpreter entry points remain per-execution
//! APIs. Use `BudgetedInterpreter` or a single-use `ExecutionAdmission` for
//! every execution in a shared workload.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, InterpreterHook,
};
use crate::checkpoint::CancellationToken;
use crate::ir_contract::Ir3Module;

mod revocation;
mod scheduling;
pub use revocation::{MAX_WORK_POOL_DEPTH, WorkScopeRevocation};
pub use scheduling::ExecutionAdmission;

#[derive(Debug)]
struct WorkPoolState {
    limit: u64,
    remaining: AtomicU64,
    cancellation: CancellationToken,
    depth: usize,
}

/// A shared, non-renewable allowance for native instruction reservations.
///
/// Clones refer to the same atomic balance. A zero-limit pool denies all
/// execution. No operation increases this balance, including `Drop`.
#[derive(Debug, Clone)]
pub struct ExecutionWorkPool {
    state: Arc<WorkPoolState>,
}

impl ExecutionWorkPool {
    /// Establish a new allowance at a trusted scheduling boundary.
    pub fn new(instruction_limit: u64) -> Self {
        Self {
            state: Arc::new(WorkPoolState {
                limit: instruction_limit,
                remaining: AtomicU64::new(instruction_limit),
                cancellation: CancellationToken::new(),
                depth: 0,
            }),
        }
    }

    pub fn limit(&self) -> u64 {
        self.state.limit
    }

    /// The currently uncommitted allowance. Concurrent admission may reduce it.
    pub fn remaining(&self) -> u64 {
        self.state.remaining.load(Ordering::Acquire)
    }

    /// Reserved or delegated allowance, not an actual execution count.
    pub fn committed(&self) -> u64 {
        self.limit() - self.remaining()
    }

    fn charge(&self, instructions: u64) -> Result<(), WorkBudgetError> {
        self.ensure_active()?;
        if instructions == 0 {
            return Err(WorkBudgetError::ZeroInstructionBudget);
        }
        self.state
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(instructions)
            })
            .map(|_| ())
            .map_err(|remaining| WorkBudgetError::Exhausted {
                requested: instructions,
                remaining,
            })?;
        // A racing revocation may discard this reservation, never refund it.
        self.ensure_active()
    }
}

/// Admission errors remain distinguishable from native execution failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkBudgetError {
    ZeroInstructionBudget,
    /// This work scope or one of its ancestors has been permanently revoked.
    Revoked,
    /// Bound the cost of retaining and polling inherited scope signals.
    HierarchyDepthExceeded {
        max_depth: usize,
    },
    Exhausted {
        requested: u64,
        remaining: u64,
    },
    /// A previous native call unwound. Its interpreter cannot safely be reused.
    Interrupted,
    Interpreter(InterpreterError),
}

impl fmt::Display for WorkBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroInstructionBudget => f.write_str("instruction reservation must be nonzero"),
            Self::Revoked => f.write_str("execution work scope has been revoked"),
            Self::HierarchyDepthExceeded { max_depth } => {
                write!(f, "execution work scope hierarchy exceeds depth {max_depth}")
            }
            Self::Exhausted {
                requested,
                remaining,
            } => write!(
                f,
                "shared execution work budget exhausted: requested {requested}, remaining {remaining}"
            ),
            Self::Interrupted => f.write_str("native execution unwound; discard this interpreter"),
            Self::Interpreter(error) => fmt::Display::fmt(error, f),
        }
    }
}

// The native error already owns its diagnostics and implements Debug/Display.
// Make the existing typed cause usable through std::error::Error rather than
// erasing it, dropping the source chain, or weakening execution admission.
impl std::error::Error for InterpreterError {}

impl std::error::Error for WorkBudgetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Interpreter(error) => Some(error),
            _ => None,
        }
    }
}

/// A native interpreter whose every execution requires fresh shared admission.
///
/// The configured instruction budget is reserved in full on each call,
/// including calls that fail capability checks or reject invalid IR. The
/// native meter still enforces that per-call limit, including its existing
/// module/callback execution paths. Memory limits, capabilities, provenance,
/// and hooks are passed through unchanged. Caller cancellation is combined
/// with live work-scope revocation at the existing native checkpoints.
///
/// The raw interpreter is deliberately not exposed, and this owner is not
/// cloneable. A caller cannot reset its native counter without paying again.
/// Construction is lazy, so denied admission does not allocate a native VM.
/// After an unwind, subsequent calls fail closed even if the host catches it.
pub struct BudgetedInterpreter {
    pool: ExecutionWorkPool,
    config: InterpreterConfig,
    trace_id: String,
    hook: Option<Arc<dyn InterpreterHook>>,
    core: Option<InterpreterCore>,
    interrupted: bool,
}

impl fmt::Debug for BudgetedInterpreter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BudgetedInterpreter")
            .field("pool", &self.pool)
            .field("instruction_budget", &self.config.instruction_budget)
            .field("trace_id", &self.trace_id)
            .field("initialized", &self.core.is_some())
            .field("interrupted", &self.interrupted)
            .finish_non_exhaustive()
    }
}

impl BudgetedInterpreter {
    pub fn new(
        pool: ExecutionWorkPool,
        mut config: InterpreterConfig,
        trace_id: impl Into<String>,
    ) -> Result<Self, WorkBudgetError> {
        if config.instruction_budget == 0 {
            return Err(WorkBudgetError::ZeroInstructionBudget);
        }
        pool.ensure_active()?;
        revocation::bind_cancellation(&pool.state.cancellation, &mut config);
        Ok(Self {
            pool,
            config,
            trace_id: trace_id.into(),
            hook: None,
            core: None,
            interrupted: false,
        })
    }

    pub fn work_pool(&self) -> &ExecutionWorkPool {
        &self.pool
    }

    /// Install the host's existing policy hook without changing admission.
    pub fn set_hook(&mut self, hook: Arc<dyn InterpreterHook>) {
        if let Some(core) = &mut self.core {
            core.set_hook(Arc::clone(&hook));
        }
        self.hook = Some(hook);
    }

    pub fn execute(&mut self, module: &Ir3Module) -> Result<ExecutionResult, WorkBudgetError> {
        if self.interrupted {
            return Err(WorkBudgetError::Interrupted);
        }
        self.pool.charge(self.config.instruction_budget)?;
        // Set this before initialization as well as execution: any unwinding
        // path consumes admission and permanently invalidates this owner.
        self.interrupted = true;
        let config = &self.config;
        let trace_id = &self.trace_id;
        let hook = &self.hook;
        let core = self.core.get_or_insert_with(|| {
            let mut core = InterpreterCore::new(config.clone(), trace_id.clone());
            if let Some(hook) = hook {
                core.set_hook(Arc::clone(hook));
            }
            core
        });
        let result = core.execute(module);
        self.interrupted = false;
        result.map_err(WorkBudgetError::Interpreter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::baseline_interpreter::{
        AllocKind, FunctionRef, HookAction, HookContext, ObjectRef, PropertyKey, Value,
    };
    use crate::capability::RuntimeCapability;
    use crate::checkpoint::CancellationToken;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, Es2020Parser};
    use std::sync::Barrier;

    pub(super) fn module(source: &str) -> Ir3Module {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("work-budget source must parse");
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "work-budget.js"),
            &LoweringContext::new("work-budget", "work-budget", "work-budget"),
        )
        .expect("work-budget source must lower")
        .ir3
    }

    pub(super) fn config(budget: u64) -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = budget;
        config.granted_capabilities.extend([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        config
    }

    pub(super) fn interpreter(pool: &ExecutionWorkPool, budget: u64) -> BudgetedInterpreter {
        BudgetedInterpreter::new(pool.clone(), config(budget), "work-budget").unwrap()
    }

    #[test]
    fn native_result_and_provenance_are_preserved() {
        let module = module("40 + 2;");
        let expected = InterpreterCore::new(config(128), "work-budget")
            .execute(&module)
            .unwrap();
        let pool = ExecutionWorkPool::new(256);
        let actual = interpreter(&pool, 128).execute(&module).unwrap();
        assert_eq!(actual.value, expected.value);
        assert_eq!(actual.completion_label, expected.completion_label);
        assert_eq!(actual.instructions_executed, expected.instructions_executed);
        assert_eq!(actual.console_output, expected.console_output);
        assert!(actual.instructions_executed > 0);
        assert_eq!(pool.remaining(), 128);
        assert_eq!(pool.committed(), 128);
    }

    #[test]
    fn repeated_execute_cannot_reset_shared_fuel() {
        let module = module("1 + 2;");
        let pool = ExecutionWorkPool::new(256);
        let mut runtime = interpreter(&pool, 128);
        let first = runtime.execute(&module).unwrap();
        let second = runtime.execute(&module).unwrap();
        assert_eq!(first.value, second.value);
        assert!(matches!(
            runtime.execute(&module),
            Err(WorkBudgetError::Exhausted {
                requested: 128,
                remaining: 0
            })
        ));
    }

    #[test]
    fn separate_interpreters_share_one_balance() {
        let module = module("7;");
        let pool = ExecutionWorkPool::new(128);
        let mut first = interpreter(&pool, 128);
        let mut second = interpreter(&pool, 128);
        first.execute(&module).unwrap();
        assert!(matches!(
            second.execute(&module),
            Err(WorkBudgetError::Exhausted { .. })
        ));
        assert!(second.core.is_none(), "denial must precede VM allocation");
    }

    #[test]
    fn early_completion_and_drop_do_not_refund() {
        let module = module("7;");
        let pool = ExecutionWorkPool::new(128);
        let result = interpreter(&pool, 128).execute(&module).unwrap();
        assert!(result.instructions_executed < 128);
        assert_eq!(pool.remaining(), 0);
        assert_eq!(pool.clone().committed(), 128);
    }

    #[test]
    fn zero_pool_and_oversized_admission_fail_atomically() {
        let module = module("7;");
        let zero = ExecutionWorkPool::new(0);
        let mut runtime = interpreter(&zero, 1);
        assert!(matches!(
            runtime.execute(&module),
            Err(WorkBudgetError::Exhausted { remaining: 0, .. })
        ));
        assert!(runtime.core.is_none());
        let pool = ExecutionWorkPool::new(127);
        assert!(matches!(
            interpreter(&pool, 128).execute(&module),
            Err(WorkBudgetError::Exhausted { .. })
        ));
        assert_eq!(pool.remaining(), 127);
        assert_eq!(pool.committed(), 0);
    }

    #[test]
    fn zero_per_execution_budget_is_not_an_unmetered_mode() {
        let pool = ExecutionWorkPool::new(128);
        assert!(matches!(
            BudgetedInterpreter::new(pool.clone(), config(0), "zero"),
            Err(WorkBudgetError::ZeroInstructionBudget)
        ));
        assert_eq!(pool.remaining(), 128);
    }

    #[test]
    fn native_traps_consume_admission_and_retries_pay_again() {
        let module = module("throw 7;");
        let pool = ExecutionWorkPool::new(256);
        let mut runtime = interpreter(&pool, 128);
        for remaining in [128, 0] {
            assert!(matches!(
                runtime.execute(&module),
                Err(WorkBudgetError::Interpreter(InterpreterError::UncaughtException { .. }))
            ));
            assert_eq!(pool.remaining(), remaining);
        }
        assert!(matches!(
            runtime.execute(&module),
            Err(WorkBudgetError::Exhausted { .. })
        ));
    }

    #[test]
    fn native_instruction_exhaustion_never_refunds() {
        let module = module("while (true) {}");
        let pool = ExecutionWorkPool::new(128);
        assert!(matches!(
            interpreter(&pool, 128).execute(&module),
            Err(WorkBudgetError::Interpreter(InterpreterError::BudgetExhausted { .. }))
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn capability_denial_is_preserved_and_charged() {
        let module = module("7;");
        let pool = ExecutionWorkPool::new(128);
        let mut denied = config(128);
        denied.granted_capabilities.clear();
        let mut runtime = BudgetedInterpreter::new(pool.clone(), denied, "denied").unwrap();
        assert!(matches!(
            runtime.execute(&module),
            Err(WorkBudgetError::Interpreter(InterpreterError::CapabilityDenied { .. }))
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn native_memory_limits_are_preserved() {
        let module = module("let object = {}; object;");
        let pool = ExecutionWorkPool::new(128);
        let mut limited = config(128);
        limited.max_total_memory_bytes = 0;
        let mut runtime = BudgetedInterpreter::new(pool.clone(), limited, "memory").unwrap();
        assert!(matches!(
            runtime.execute(&module),
            Err(WorkBudgetError::Interpreter(InterpreterError::MemoryBudgetExceeded { .. }))
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn cancelled_execution_cannot_reclaim_admission() {
        let module = module("while (true) {}");
        let pool = ExecutionWorkPool::new(128);
        let token = CancellationToken::new();
        token.cancel();
        let mut cancelled = config(128);
        cancelled.cancellation_token = Some(token);
        cancelled.checkpoint_density = 1;
        let mut runtime = BudgetedInterpreter::new(pool.clone(), cancelled, "cancelled").unwrap();
        assert!(matches!(
            runtime.execute(&module),
            Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn maximum_u64_allowance_cannot_wrap() {
        let pool = ExecutionWorkPool::new(u64::MAX);
        pool.charge(u64::MAX).unwrap();
        assert_eq!(pool.remaining(), 0);
        assert_eq!(pool.committed(), u64::MAX);
        assert_eq!(
            pool.charge(1),
            Err(WorkBudgetError::Exhausted {
                requested: 1,
                remaining: 0
            })
        );
    }

    #[test]
    fn concurrent_admission_conserves_the_root_allowance() {
        let pool = ExecutionWorkPool::new(257);
        let start = Arc::new(Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let pool = pool.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    let mut admitted = 0;
                    while pool.charge(1).is_ok() {
                        admitted += 1;
                    }
                    admitted
                })
            })
            .collect();
        let admitted: u64 = handles
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .sum();
        assert_eq!(admitted, 257);
        assert_eq!(pool.remaining(), 0);
    }

    pub(super) struct PanickingHook;

    impl InterpreterHook for PanickingHook {
        fn pre_property_access(
            &self,
            _: &HookContext,
            _: &ObjectRef,
            _: &PropertyKey,
        ) -> HookAction {
            HookAction::Allow
        }
        fn pre_call(&self, _: &HookContext, _: &FunctionRef, _: &[Value]) -> HookAction {
            HookAction::Allow
        }
        fn pre_allocation(&self, _: &HookContext, _: AllocKind, _: usize) -> HookAction {
            panic!("host hook interrupted execution")
        }
        fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
            HookAction::Allow
        }
    }

    #[test]
    fn caught_host_unwind_poisoning_is_sticky_and_does_not_refund() {
        let module = module("let object = {}; object;");
        let pool = ExecutionWorkPool::new(256);
        let mut runtime = interpreter(&pool, 128);
        runtime.set_hook(Arc::new(PanickingHook));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.execute(&module)
        }));
        assert!(
            unwind.is_err(),
            "test must exercise the native allocation hook"
        );
        assert_eq!(pool.remaining(), 128);
        assert!(matches!(
            runtime.execute(&module),
            Err(WorkBudgetError::Interrupted)
        ));
        assert_eq!(
            pool.remaining(),
            128,
            "poison denial must not admit another run"
        );
        drop(runtime);
        assert_eq!(pool.remaining(), 128);
    }
}
