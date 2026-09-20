//! Irreversible tenant delegation and single-use scheduler admissions.

use std::sync::Arc;

use super::{ExecutionWorkPool, WorkBudgetError};
use crate::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterHook,
};
use crate::checkpoint::CancellationToken;
use crate::ir_contract::Ir3Module;

impl ExecutionWorkPool {
    /// Reserve work when enqueueing a job, before a native VM is constructed.
    ///
    /// The returned admission is movable but not cloneable or serializable.
    /// Moving it through a queue does not re-charge the pool; dropping it,
    /// including cancellation before dispatch, permanently discards the quota.
    /// An admission is only a work allowance, never a capability grant.
    pub fn reserve(&self, instructions: u64) -> Result<ExecutionAdmission, WorkBudgetError> {
        self.ensure_active()?;
        // Bind the scope before the irreversible debit. A job retains this
        // live signal even after it leaves the queue or its pool is dropped.
        let scope = self.state.cancellation.child_token();
        self.charge(instructions)?;
        Ok(ExecutionAdmission {
            instruction_limit: instructions,
            scope,
        })
    }
}

/// Single-use, prepaid permission to enter one native interpreter execution.
///
/// Dispatch consumes this owner. There is no raw-interpreter accessor, refund,
/// reset, clone, or deserialization path. The dispatcher must supply its
/// **current** authorized configuration and hook: the admission intentionally
/// does not preserve potentially stale capability grants from enqueue time.
/// Its reserved ceiling can tighten, but never enlarge, the native run limit.
/// A host panic consumes the owner just like any other failed dispatch.
/// Revoking its work scope denies a queued job before VM construction and
/// requests cancellation of a running job through native checkpoints.
#[derive(Debug)]
#[must_use = "dropping an admission permanently discards its reserved allowance"]
pub struct ExecutionAdmission {
    instruction_limit: u64,
    scope: CancellationToken,
}

impl ExecutionAdmission {
    pub fn instruction_limit(&self) -> u64 {
        self.instruction_limit
    }

    pub fn execute(
        self,
        module: &Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
    ) -> Result<ExecutionResult, WorkBudgetError> {
        self.execute_with_hook(module, current_config, trace_id, None)
    }

    pub fn execute_with_hook(
        self,
        module: &Ir3Module,
        mut current_config: InterpreterConfig,
        trace_id: impl Into<String>,
        current_hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, WorkBudgetError> {
        if self.scope.is_cancelled() {
            return Err(WorkBudgetError::Revoked);
        }
        if current_config.instruction_budget == 0 {
            return Err(WorkBudgetError::ZeroInstructionBudget);
        }
        super::revocation::bind_cancellation(&self.scope, &mut current_config);
        current_config.instruction_budget =
            current_config.instruction_budget.min(self.instruction_limit);
        let mut core = InterpreterCore::new(current_config, trace_id);
        if let Some(hook) = current_hook {
            core.set_hook(hook);
        }
        core.execute(module).map_err(WorkBudgetError::Interpreter)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{PanickingHook, config, interpreter, module};
    use super::*;
    use crate::baseline_interpreter::InterpreterError;
    use crate::checkpoint::CancellationToken;
    use std::collections::VecDeque;
    use std::sync::Barrier;

    #[test]
    fn tenant_exhaustion_does_not_steal_sibling_progress() {
        let source = module("7;");
        let root = ExecutionWorkPool::new(384);
        let tenant_a = root.partition(256).unwrap();
        let tenant_b = root.partition(128).unwrap();
        assert_eq!(root.remaining(), 0);
        let mut a = interpreter(&tenant_a, 128);
        a.execute(&source).unwrap();
        a.execute(&source).unwrap();
        assert!(matches!(
            a.execute(&source),
            Err(WorkBudgetError::Exhausted { .. })
        ));
        assert_eq!(tenant_b.remaining(), 128);
        interpreter(&tenant_b, 128).execute(&source).unwrap();
        assert_eq!(tenant_a.remaining() + tenant_b.remaining(), 0);
        assert_eq!(root.committed(), 384);
    }

    #[test]
    fn nested_delegation_conserves_all_root_credits() {
        let root = ExecutionWorkPool::new(1024);
        let tenant = root.partition(768).unwrap();
        let cell = tenant.partition(512).unwrap();
        assert_eq!(root.remaining(), 256);
        assert_eq!(tenant.remaining(), 256);
        assert_eq!(cell.remaining(), 512);
        drop(root.reserve(256).unwrap());
        drop(tenant.reserve(256).unwrap());
        drop(cell.reserve(512).unwrap());
        assert_eq!(root.remaining() + tenant.remaining() + cell.remaining(), 0);
    }

    #[test]
    fn child_clones_share_fuel_and_drop_never_refunds_parent() {
        let root = ExecutionWorkPool::new(512);
        let tenant = root.partition(256).unwrap();
        let alias = tenant.clone();
        drop(alias.reserve(128).unwrap());
        assert_eq!(tenant.remaining(), 128);
        drop(alias);
        drop(tenant);
        assert_eq!(root.remaining(), 256);
        drop(root.reserve(256).unwrap());
        assert_eq!(root.remaining(), 0);
    }

    #[test]
    fn partition_failures_and_empty_children_do_not_change_parent() {
        let root = ExecutionWorkPool::new(127);
        assert!(matches!(
            root.partition(128),
            Err(WorkBudgetError::Exhausted { .. })
        ));
        let empty = root.partition(0).unwrap();
        assert_eq!(empty.limit(), 0);
        assert!(matches!(
            empty.reserve(1),
            Err(WorkBudgetError::Exhausted { .. })
        ));
        assert_eq!(root.remaining(), 127);
        assert!(matches!(
            root.reserve(0),
            Err(WorkBudgetError::ZeroInstructionBudget)
        ));
        assert_eq!(root.remaining(), 127);
    }

    #[test]
    fn maximum_allowance_survives_nested_transfer_without_overflow() {
        let root = ExecutionWorkPool::new(u64::MAX);
        let tenant = root.partition(u64::MAX).unwrap();
        let cell = tenant.partition(u64::MAX).unwrap();
        assert_eq!(root.remaining(), 0);
        assert_eq!(tenant.remaining(), 0);
        assert_eq!(cell.remaining(), u64::MAX);
        drop(cell.reserve(u64::MAX).unwrap());
        assert_eq!(cell.committed(), u64::MAX);
        assert!(matches!(
            root.partition(1),
            Err(WorkBudgetError::Exhausted { .. })
        ));
    }

    #[test]
    fn withdrawing_and_requeueing_a_job_does_not_mint_or_double_charge() {
        let source = module("7;");
        let pool = ExecutionWorkPool::new(256);
        let mut queue = VecDeque::new();
        queue.push_back(pool.reserve(128).unwrap());
        assert_eq!(pool.remaining(), 128);
        let job = queue.pop_front().unwrap();
        assert_eq!(job.instruction_limit(), 128);
        queue.push_front(job);
        queue
            .pop_front()
            .unwrap()
            .execute(&source, config(128), "queued")
            .unwrap();
        assert_eq!(pool.remaining(), 128);
        queue.push_back(pool.reserve(128).unwrap());
        drop(queue);
        assert_eq!(pool.remaining(), 0, "withdrawing a job is not a refund");
    }

    #[test]
    fn dispatch_cannot_enlarge_the_prepaid_native_instruction_limit() {
        let source = module("while (true) {}");
        let pool = ExecutionWorkPool::new(8);
        let job = pool.reserve(8).unwrap();
        assert!(matches!(
            job.execute(&source, config(128), "clamped"),
            Err(WorkBudgetError::Interpreter(
                InterpreterError::BudgetExhausted { budget: 8, .. }
            ))
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn tighter_current_policy_is_not_relaxed_and_unused_work_is_not_refunded() {
        let source = module("while (true) {}");
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        assert!(matches!(
            job.execute(&source, config(8), "tightened"),
            Err(WorkBudgetError::Interpreter(
                InterpreterError::BudgetExhausted { budget: 8, .. }
            ))
        ));
        assert_eq!(pool.committed(), 128);
    }

    #[test]
    fn dispatch_uses_current_capabilities_not_enqueue_time_authority() {
        let source = module("7;");
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        let mut revoked = config(128);
        revoked.granted_capabilities.clear();
        assert!(matches!(
            job.execute(&source, revoked, "revoked"),
            Err(WorkBudgetError::Interpreter(InterpreterError::CapabilityDenied { .. }))
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn cancellation_after_enqueue_preserves_prepaid_accounting() {
        let source = module("while (true) {}");
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        let token = CancellationToken::new();
        let mut cancelled = config(128);
        cancelled.cancellation_token = Some(token.clone());
        cancelled.checkpoint_density = 1;
        token.cancel();
        assert!(matches!(
            job.execute(&source, cancelled, "cancelled-queue"),
            Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn invalid_dispatch_budget_does_not_restore_reserved_work() {
        let source = module("7;");
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        assert!(matches!(
            job.execute(&source, config(0), "zero-at-dispatch"),
            Err(WorkBudgetError::ZeroInstructionBudget)
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn native_hook_unwind_consumes_the_single_use_admission() {
        let source = module("let object = {}; object;");
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            job.execute_with_hook(
                &source,
                config(128),
                "unwind",
                Some(Arc::new(PanickingHook)),
            )
        }));
        assert!(unwind.is_err(), "test must enter the native policy hook");
        assert_eq!(pool.remaining(), 0);
        assert!(matches!(
            pool.reserve(1),
            Err(WorkBudgetError::Exhausted { .. })
        ));
    }

    #[test]
    fn concurrent_delegation_and_reservation_cannot_overcommit() {
        let root = ExecutionWorkPool::new(512);
        let start = Arc::new(Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|index| {
                let root = root.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    if index % 2 == 0 {
                        root.partition(32).unwrap().limit()
                    } else {
                        root.reserve(32).unwrap().instruction_limit()
                    }
                })
            })
            .collect();
        let committed: u64 = handles
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .sum();
        assert_eq!(committed, 512);
        assert_eq!(root.remaining(), 0);
    }

    #[test]
    fn queued_admission_moves_to_a_worker_without_moving_native_vm_state() {
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        let executed = std::thread::spawn(move || {
            let source = module("40 + 2;");
            job.execute(&source, config(128), "worker")
                .unwrap()
                .instructions_executed
        })
        .join()
        .unwrap();
        assert!(executed > 0 && executed <= 128);
        assert_eq!(pool.remaining(), 0);
    }
}
