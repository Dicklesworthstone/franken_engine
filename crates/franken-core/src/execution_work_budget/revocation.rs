//! Hierarchical, irreversible revocation for shared native work allowances.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use super::{ExecutionWorkPool, WorkBudgetError, WorkPoolState};
use crate::baseline_interpreter::InterpreterConfig;
use crate::checkpoint::CancellationToken;

/// Maximum nested work-pool partitions below a root (whose depth is zero).
/// This bounds the pool-owned part of checkpoint polling and retained signals.
pub const MAX_WORK_POOL_DEPTH: usize = 64;

/// Read-only, live cancellation of a work scope and its ancestors.
///
/// This is not an admission or a capability grant. It lets other runtime
/// consumers observe the same irreversible signal without gaining access to
/// `CancellationToken::reset` or the ability to cancel a parent or sibling.
/// It deliberately cannot be serialized: a snapshot is not a live binding.
#[derive(Debug, Clone)]
pub struct WorkScopeRevocation {
    scope: CancellationToken,
}

impl WorkScopeRevocation {
    pub fn is_revoked(&self) -> bool {
        self.scope.is_cancelled()
    }
}

impl ExecutionWorkPool {
    /// Observe revocation without granting execution or mutable token access.
    /// The signal remains live even after the pool and its other owners drop.
    pub fn revocation_signal(&self) -> WorkScopeRevocation {
        WorkScopeRevocation {
            scope: self.state.cancellation.clone(),
        }
    }

    /// The ordinary core orchestrator has already charged its selected lane.
    /// Bind that run to the pool without charging again or replacing any
    /// caller cancellation. The engine crate uses the read-only signal above
    /// at its execution-cell authority boundary instead.
    pub(crate) fn bind_interpreter_cancellation(&self, config: &mut InterpreterConfig) {
        bind_cancellation(&self.state.cancellation, config);
    }

    /// Permanently revoke this scope and all its descendants, including work
    /// admitted before this call. Clones share this request; siblings do not.
    ///
    /// Revocation never changes a balance or refunds a reservation. Already
    /// running native code observes it cooperatively at existing checkpoints;
    /// this does not interrupt a synchronous host callback, undo effects, or
    /// prove that drain/finalize has completed. The host still owns that lifecycle.
    /// A concurrent admission may consume credits and return `Revoked`.
    pub fn revoke(&self) {
        self.state.cancellation.cancel();
    }

    /// Whether this scope or an ancestor has been permanently revoked.
    pub fn is_revoked(&self) -> bool {
        self.state.cancellation.is_cancelled()
    }

    pub(super) fn ensure_active(&self) -> Result<(), WorkBudgetError> {
        if self.is_revoked() {
            Err(WorkBudgetError::Revoked)
        } else {
            Ok(())
        }
    }

    /// Irreversibly delegate part of this allowance to a tenant or execution cell.
    ///
    /// The child has an independent balance. Neither this pool nor its other
    /// children can spend that balance. Cloning a child shares its balance;
    /// nesting partitions cannot mint credits. Dropping an unused child never
    /// refunds its parent. A zero-size partition is an empty, unusable pool.
    /// Revocation flows from parent to child, never from child to parent or sibling.
    /// Hierarchy overflow, including empty partitions, is rejected before debit.
    pub fn partition(&self, instruction_limit: u64) -> Result<Self, WorkBudgetError> {
        self.ensure_active()?;
        if self.state.depth >= MAX_WORK_POOL_DEPTH {
            return Err(WorkBudgetError::HierarchyDepthExceeded {
                max_depth: MAX_WORK_POOL_DEPTH,
            });
        }
        // Allocate and bind before the irreversible debit. Descendants retain
        // live ancestor signals without retaining a recursive chain of pools.
        let child = Self {
            state: Arc::new(WorkPoolState {
                limit: instruction_limit,
                remaining: AtomicU64::new(instruction_limit),
                cancellation: self.state.cancellation.child_token(),
                depth: self.state.depth + 1,
            }),
        };
        if instruction_limit != 0 {
            self.charge(instruction_limit)?;
        } else {
            self.ensure_active()?;
        }
        Ok(child)
    }
}

pub(super) fn bind_cancellation(scope: &CancellationToken, config: &mut InterpreterConfig) {
    // A fresh child cannot reset or cancel either source. Do not replace the
    // caller's signal: both sources must remain live throughout native execution.
    let caller = config.cancellation_token.take();
    config.cancellation_token = Some(match caller {
        Some(caller) => scope.linked_with(&caller),
        None => scope.child_token(),
    });
    config.checkpoint_density = config.checkpoint_density.max(1);
}

#[cfg(test)]
mod tests {
    use super::super::BudgetedInterpreter;
    use super::super::tests::{PanickingHook, config, interpreter, module};
    use super::*;
    use crate::baseline_interpreter::{
        AllocKind, FunctionRef, HookAction, HookContext, InterpreterError, InterpreterHook,
        ObjectRef, PropertyKey, Value,
    };
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn read_only_revocation_signal_tracks_ancestors_after_pool_drop() {
        let root = ExecutionWorkPool::new(256);
        let child = root.partition(128).unwrap();
        let signal = child.revocation_signal();
        let alias = signal.clone();
        drop(child);
        assert!(!signal.is_revoked());
        root.revoke();
        drop(root);
        assert!(signal.is_revoked());
        assert!(alias.is_revoked());
    }

    #[test]
    fn read_only_revocation_signal_does_not_widen_child_cancellation() {
        let root = ExecutionWorkPool::new(256);
        let child = root.partition(128).unwrap();
        let sibling = root.partition(128).unwrap();
        let root_signal = root.revocation_signal();
        let sibling_signal = sibling.revocation_signal();
        child.revoke();
        assert!(child.revocation_signal().is_revoked());
        assert!(!root_signal.is_revoked());
        assert!(!sibling_signal.is_revoked());
        let _admission = sibling.reserve(128).unwrap();
        assert_eq!(root.remaining(), 0);
    }

    #[test]
    fn revoked_clones_deny_admission_and_delegation_without_debit() {
        let pool = ExecutionWorkPool::new(256);
        let alias = pool.clone();
        pool.revoke();
        pool.revoke();
        assert!(alias.is_revoked());
        for amount in [0, 1, 128] {
            assert!(matches!(
                alias.reserve(amount),
                Err(WorkBudgetError::Revoked)
            ));
            assert!(matches!(
                alias.partition(amount),
                Err(WorkBudgetError::Revoked)
            ));
        }
        assert!(matches!(
            BudgetedInterpreter::new(alias, config(128), "revoked"),
            Err(WorkBudgetError::Revoked)
        ));
        assert_eq!(pool.remaining(), 256);
        assert_eq!(pool.committed(), 0);
    }

    #[test]
    fn revocation_denies_a_lazy_interpreter_before_vm_allocation() {
        let pool = ExecutionWorkPool::new(128);
        let mut runtime = interpreter(&pool, 128);
        runtime.set_hook(Arc::new(PanickingHook));
        pool.revoke();
        assert!(matches!(
            runtime.execute(&module("let object = {}; object;")),
            Err(WorkBudgetError::Revoked)
        ));
        assert!(runtime.core.is_none());
        assert_eq!(pool.remaining(), 128);
    }

    #[test]
    fn revocation_denies_reuse_of_an_already_initialized_vm() {
        let pool = ExecutionWorkPool::new(256);
        let mut runtime = interpreter(&pool, 128);
        let source = module("7;");
        runtime.execute(&source).unwrap();
        assert!(runtime.core.is_some());
        pool.revoke();
        assert!(matches!(
            runtime.execute(&source),
            Err(WorkBudgetError::Revoked)
        ));
        assert_eq!(pool.remaining(), 128);
        assert_eq!(pool.committed(), 128);
    }

    #[test]
    fn exhausted_ancestor_still_revokes_prepaid_descendant_jobs() {
        let root = ExecutionWorkPool::new(256);
        let tenant = root.partition(256).unwrap();
        let cell = tenant.partition(256).unwrap();
        let first = cell.reserve(128).unwrap();
        let second = cell.reserve(128).unwrap();
        assert_eq!(root.remaining() + tenant.remaining() + cell.remaining(), 0);
        root.revoke();
        assert!(tenant.is_revoked() && cell.is_revoked());
        let source = module("7;");
        for job in [first, second] {
            assert!(matches!(
                job.execute(&source, config(128), "queued"),
                Err(WorkBudgetError::Revoked)
            ));
        }
        assert_eq!(cell.committed(), 256);
        assert_eq!(root.committed(), 256);
    }

    #[test]
    fn tenant_revocation_preserves_parent_and_sibling_progress() {
        let root = ExecutionWorkPool::new(384);
        let first = root.partition(128).unwrap();
        let second = root.partition(128).unwrap();
        let denied = first.reserve(128).unwrap();
        let allowed = second.reserve(128).unwrap();
        first.revoke();
        assert!(!root.is_revoked());
        assert!(!second.is_revoked());
        let source = module("7;");
        assert!(matches!(
            denied.execute(&source, config(128), "first"),
            Err(WorkBudgetError::Revoked)
        ));
        allowed.execute(&source, config(128), "second").unwrap();
        interpreter(&root, 128).execute(&source).unwrap();
        assert_eq!(root.remaining() + first.remaining() + second.remaining(), 0);
    }

    #[test]
    fn dropping_scope_owners_cannot_resurrect_an_admission() {
        let root = ExecutionWorkPool::new(128);
        let tenant = root.partition(128).unwrap();
        let job = tenant.reserve(128).unwrap();
        root.revoke();
        drop(root);
        drop(tenant);
        assert!(matches!(
            job.execute(&module("7;"), config(128), "orphan"),
            Err(WorkBudgetError::Revoked)
        ));
    }

    #[test]
    fn resetting_caller_cancellation_cannot_restore_revoked_work() {
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        let caller = CancellationToken::new();
        let mut current = config(128);
        current.cancellation_token = Some(caller.clone());
        pool.revoke();
        caller.cancel();
        caller.reset();
        assert!(matches!(
            job.execute(&module("7;"), current, "reset"),
            Err(WorkBudgetError::Revoked)
        ));
        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn caller_cancellation_and_explicit_reuse_remain_live_without_refunds() {
        let pool = ExecutionWorkPool::new(256);
        let caller = CancellationToken::new();
        let mut current = config(128);
        current.cancellation_token = Some(caller.clone());
        current.checkpoint_density = 1;
        let mut runtime = BudgetedInterpreter::new(pool.clone(), current, "caller").unwrap();
        caller.cancel();
        assert!(matches!(
            runtime.execute(&module("while (true) {}")),
            Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))
        ));
        assert_eq!(pool.remaining(), 128);
        assert!(!pool.is_revoked());
        caller.reset();
        runtime.execute(&module("7;")).unwrap();
        assert_eq!(pool.remaining(), 0);
    }

    struct RevokeOnAllocation {
        scope: ExecutionWorkPool,
        calls: Arc<AtomicUsize>,
        unwind: bool,
    }

    impl InterpreterHook for RevokeOnAllocation {
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
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.scope.revoke();
            assert!(!self.unwind, "host unwound after revocation");
            HookAction::Allow
        }
        fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
            HookAction::Allow
        }
    }

    #[test]
    fn running_reusable_vm_observes_ancestor_revocation_at_native_checkpoints() {
        let root = ExecutionWorkPool::new(256);
        let tenant = root.partition(256).unwrap();
        let cell = tenant.partition(256).unwrap();
        let mut current = config(128);
        current.checkpoint_density = 1;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut runtime = BudgetedInterpreter::new(cell.clone(), current, "running").unwrap();
        runtime.set_hook(Arc::new(RevokeOnAllocation {
            scope: root.clone(),
            calls: Arc::clone(&calls),
            unwind: false,
        }));
        assert!(matches!(
            runtime.execute(&module("let object = {}; while (true) {}")),
            Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))
        ));
        assert!(
            calls.load(Ordering::Relaxed) > 0,
            "must enter the actual native hook"
        );
        assert!(cell.is_revoked());
        assert_eq!(cell.remaining(), 128);
        assert!(matches!(
            runtime.execute(&module("7;")),
            Err(WorkBudgetError::Revoked)
        ));
        assert_eq!(cell.remaining(), 128);
    }

    #[test]
    fn running_prepaid_job_cancels_without_cancelling_its_callers_other_work() {
        let pool = ExecutionWorkPool::new(256);
        let job = pool.reserve(128).unwrap();
        let caller = CancellationToken::new();
        let mut current = config(128);
        current.checkpoint_density = 1;
        current.cancellation_token = Some(caller.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            job.execute_with_hook(
                &module("let object = {}; while (true) {}"),
                current,
                "running-job",
                Some(Arc::new(RevokeOnAllocation {
                    scope: pool.clone(),
                    calls: Arc::clone(&calls),
                    unwind: false,
                })),
            ),
            Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))
        ));
        assert!(calls.load(Ordering::Relaxed) > 0);
        assert!(!caller.is_cancelled());
        assert_eq!(pool.remaining(), 128);
    }

    #[test]
    fn host_unwind_after_revocation_preserves_poisoning_and_spent_work() {
        let pool = ExecutionWorkPool::new(256);
        let mut runtime = interpreter(&pool, 128);
        let calls = Arc::new(AtomicUsize::new(0));
        runtime.set_hook(Arc::new(RevokeOnAllocation {
            scope: pool.clone(),
            calls: Arc::clone(&calls),
            unwind: true,
        }));
        let source = module("let object = {}; object;");
        let unwind =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.execute(&source)));
        assert!(unwind.is_err());
        assert!(calls.load(Ordering::Relaxed) > 0);
        assert!(pool.is_revoked());
        assert!(matches!(
            runtime.execute(&source),
            Err(WorkBudgetError::Interrupted)
        ));
        assert_eq!(pool.remaining(), 128);
    }

    #[test]
    fn hierarchy_limit_bounds_polling_without_consuming_failed_delegations() {
        let root = ExecutionWorkPool::new(128);
        let mut leaf = root.clone();
        for _ in 0..MAX_WORK_POOL_DEPTH {
            leaf = leaf.partition(128).unwrap();
        }
        for amount in [0, 1, 128] {
            assert!(matches!(
                leaf.partition(amount),
                Err(WorkBudgetError::HierarchyDepthExceeded {
                    max_depth: MAX_WORK_POOL_DEPTH
                })
            ));
        }
        assert_eq!(leaf.remaining(), 128);
        let job = leaf.reserve(128).unwrap();
        root.revoke();
        assert!(leaf.is_revoked());
        assert!(matches!(
            job.execute(&module("7;"), config(128), "deep"),
            Err(WorkBudgetError::Revoked)
        ));
        assert_eq!(leaf.remaining(), 0);
    }

    #[test]
    fn empty_partitions_cannot_bypass_the_hierarchy_limit() {
        let root = ExecutionWorkPool::new(128);
        let mut leaf = root.clone();
        for _ in 0..MAX_WORK_POOL_DEPTH {
            leaf = leaf.partition(0).unwrap();
        }
        assert!(matches!(
            leaf.partition(0),
            Err(WorkBudgetError::HierarchyDepthExceeded { .. })
        ));
        assert_eq!(root.remaining(), 128);
        root.revoke();
        assert!(leaf.is_revoked());
    }

    struct CountingTrace(Arc<AtomicUsize>);

    impl From<CountingTrace> for String {
        fn from(trace: CountingTrace) -> Self {
            trace.0.fetch_add(1, Ordering::Relaxed);
            "converted".to_string()
        }
    }

    #[test]
    fn queued_denial_precedes_vm_setup_trace_conversion_and_hooks() {
        let pool = ExecutionWorkPool::new(128);
        let job = pool.reserve(128).unwrap();
        let conversions = Arc::new(AtomicUsize::new(0));
        pool.revoke();
        assert!(matches!(
            job.execute_with_hook(
                &module("let object = {}; object;"),
                config(128),
                CountingTrace(Arc::clone(&conversions)),
                Some(Arc::new(PanickingHook)),
            ),
            Err(WorkBudgetError::Revoked)
        ));
        assert_eq!(conversions.load(Ordering::Relaxed), 0);
        assert_eq!(pool.committed(), 128);
    }

    #[test]
    fn scope_binding_keeps_positive_density_and_prevents_disabled_polling() {
        for (requested, expected) in [(0, 1), (1, 1), (23, 23)] {
            let pool = ExecutionWorkPool::new(128);
            let mut current = config(128);
            current.checkpoint_density = requested;
            let runtime = BudgetedInterpreter::new(pool, current, "density").unwrap();
            assert_eq!(runtime.config.checkpoint_density, expected);
            assert!(runtime.config.cancellation_token.is_some());
        }
    }

    #[test]
    fn racing_revocation_cannot_restore_work_or_leave_accepted_jobs_executable() {
        let pool = ExecutionWorkPool::new(128);
        let start = Arc::new(Barrier::new(17));
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let pool = pool.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    pool.reserve(8)
                })
            })
            .collect();
        start.wait();
        pool.revoke();
        let source = module("7;");
        let mut accepted = 0;
        for worker in workers {
            match worker.join().unwrap() {
                Ok(job) => {
                    accepted += 8;
                    assert!(matches!(
                        job.execute(&source, config(8), "raced"),
                        Err(WorkBudgetError::Revoked)
                    ));
                }
                Err(WorkBudgetError::Revoked) => {}
                other => panic!("unexpected admission outcome: {other:?}"),
            }
        }
        assert!(pool.committed() >= accepted);
        assert_eq!(pool.remaining() + pool.committed(), 128);
        let remaining = pool.remaining();
        assert!(matches!(pool.reserve(1), Err(WorkBudgetError::Revoked)));
        assert_eq!(pool.remaining(), remaining);
    }
}
