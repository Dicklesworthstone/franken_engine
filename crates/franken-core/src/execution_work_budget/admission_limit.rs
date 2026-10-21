//! One outstanding-admission ceiling shared by a whole instruction-pool family.
//!
//! Slots are renewable; prepaid instruction credits are not. A slot follows the
//! existing non-cloneable admission through queues, host preparation and native
//! dispatch. Revocation requests cancellation but cannot free a slot still held
//! by an executing or blocked owner. There is no waiting while holding a slot:
//! nested admission fails immediately rather than deadlocking its caller.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use super::{ExecutionWorkPool, WorkBudgetError, WorkPoolState};
use crate::checkpoint::CancellationToken;

#[derive(Debug)]
pub(super) struct AdmissionSlots {
    limit: usize,
    occupied: AtomicUsize,
}

/// One owned slot. No Clone, reset, serialization, or public release operation.
#[derive(Debug)]
pub(super) struct AdmissionSlot {
    slots: Arc<AdmissionSlots>,
}

impl AdmissionSlot {
    pub(super) fn acquire(slots: &Arc<AdmissionSlots>) -> Result<Self, WorkBudgetError> {
        slots
            .occupied
            .try_update(Ordering::AcqRel, Ordering::Acquire, |occupied| {
                // The strict comparison also prevents overflow at usize::MAX.
                (occupied < slots.limit).then(|| occupied + 1)
            })
            .map_err(|_| WorkBudgetError::AdmissionLimit { limit: slots.limit })?;
        Ok(Self {
            slots: Arc::clone(slots),
        })
    }
}

impl Drop for AdmissionSlot {
    fn drop(&mut self) {
        // Only a successful increment constructs this owner. A failed debit,
        // dropped queue item, normal return or unwind drops it exactly once.
        let previous = self.slots.occupied.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "admission slot released without acquisition");
    }
}

impl ExecutionWorkPool {
    /// Create a trusted root with an instruction allowance AND a ceiling on
    /// outstanding admissions across this root, its clones and all partitions.
    /// Zero `max_admissions` denies every reservation without spending credits.
    /// Partitions delegate credits but share these slots; they cannot multiply
    /// capacity by creating more tenant pools or native task groups.
    ///
    /// `reserve` and each `BudgetedInterpreter::execute` acquire capacity before
    /// irreversible instruction debit. Slots include queued work and trusted
    /// preparation, not only running VMs. This
    /// intentionally conservative policy needs no second scheduler or waiter
    /// queue. Dropping the admission releases capacity but never refunds fuel.
    /// Cancellation alone does not release an outstanding slot.
    ///
    /// This is not a byte limit, fairness guarantee, join certificate or bound
    /// on independently created roots/raw interpreter entry points. Returned
    /// results and idle reusable VMs need their own retention limits; task groups
    /// still bound uncollected result counts. Retain admissions for the full
    /// lifetime of custom dispatch. Pool creation remains trusted host authority.
    pub fn with_admission_limit(instruction_limit: u64, max_admissions: usize) -> Self {
        Self::with_cancellation(instruction_limit, max_admissions, CancellationToken::new())
    }

    /// Create a live host work scope bounded by fuel, outstanding admissions
    /// and one absolute deadline. All clones, partitions, queued admissions,
    /// native checkpoints and bound provider controls inherit the deadline.
    /// Time spent queued or in preparation does not renew the allowance.
    ///
    /// Expiry uses the existing revocation/cancellation errors. It neither
    /// refunds fuel nor releases capacity held by unfinished work. Cancellation
    /// is cooperative, not a hard thread kill, provider drain or OS isolation.
    /// Plain `new`/`with_admission_limit` remain deadline-free. These live host
    /// limits are not a deterministic replay clock or serialized authority.
    pub fn with_deadline(
        instruction_limit: u64,
        max_admissions: usize,
        deadline: Instant,
    ) -> Self {
        Self::with_cancellation(
            instruction_limit,
            max_admissions,
            CancellationToken::new().with_deadline(deadline),
        )
    }

    /// The inherited absolute deadline, never a newly started duration.
    pub fn deadline(&self) -> Option<Instant> {
        self.state.cancellation.deadline()
    }

    fn with_cancellation(
        instruction_limit: u64,
        max_admissions: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            state: Arc::new(WorkPoolState {
                limit: instruction_limit,
                remaining: AtomicU64::new(instruction_limit),
                cancellation,
                depth: 0,
                admission_slots: Arc::new(AdmissionSlots {
                    limit: max_admissions,
                    occupied: AtomicUsize::new(0),
                }),
            }),
        }
    }

    /// The shared root-family ceiling, identical for every descendant.
    pub fn admission_limit(&self) -> usize {
        self.state.admission_slots.limit
    }

    /// Observed occupied slots across the entire family, including provisional
    /// reservations that have not yet debited fuel. Not a local execution count
    /// or authority to dispatch; another thread may change it immediately.
    pub fn outstanding_admissions(&self) -> usize {
        self.state.admission_slots.occupied.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn zero_and_full_limits_refuse_before_instruction_debit() {
        let zero = ExecutionWorkPool::with_admission_limit(100, 0);
        assert!(matches!(zero.reserve(1), Err(WorkBudgetError::AdmissionLimit { limit: 0 })));
        assert_eq!(zero.remaining(), 100);
        assert_eq!(zero.outstanding_admissions(), 0);
        let pool = ExecutionWorkPool::with_admission_limit(100, 1);
        let job = pool.reserve(10).unwrap();
        assert!(matches!(pool.reserve(20), Err(WorkBudgetError::AdmissionLimit { limit: 1 })));
        assert_eq!(pool.remaining(), 90);
        drop(job);
        assert_eq!(pool.outstanding_admissions(), 0);
        let _next = pool.reserve(20).unwrap();
        assert_eq!(pool.remaining(), 70);
    }

    #[test]
    fn nested_partitions_and_clones_share_slots_not_instruction_balances() {
        let root = ExecutionWorkPool::with_admission_limit(600, 2);
        let a = root.partition(200).unwrap();
        let b = root.partition(200).unwrap();
        let leaf = a.partition(100).unwrap();
        let alias = leaf.clone();
        assert_eq!(alias.admission_limit(), 2);
        let first = alias.reserve(10).unwrap();
        let second = b.reserve(20).unwrap();
        for scope in [&root, &a, &b, &leaf, &alias] {
            assert_eq!(scope.outstanding_admissions(), 2);
            assert!(matches!(scope.reserve(1), Err(WorkBudgetError::AdmissionLimit { limit: 2 })));
        }
        assert_eq!((root.remaining(), a.remaining(), b.remaining(), leaf.remaining()), (200, 100, 180, 90));
        drop(first);
        let third = root.reserve(30).unwrap();
        assert_eq!(root.outstanding_admissions(), 2);
        drop(second);
        drop(third);
        assert_eq!(alias.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 170);
    }

    #[test]
    fn invalid_or_unfunded_reservation_releases_any_provisional_slot() {
        let pool = ExecutionWorkPool::with_admission_limit(10, 1);
        assert!(matches!(pool.reserve(0), Err(WorkBudgetError::ZeroInstructionBudget)));
        assert!(matches!(pool.reserve(11), Err(WorkBudgetError::Exhausted { .. })));
        assert_eq!(pool.outstanding_admissions(), 0);
        let job = pool.reserve(10).unwrap();
        assert_eq!(pool.outstanding_admissions(), 1);
        drop(job);
        assert!(matches!(pool.reserve(1), Err(WorkBudgetError::Exhausted { .. })));
        assert_eq!(pool.outstanding_admissions(), 0);
        assert_eq!(pool.committed(), 10);
    }

    #[test]
    fn queue_moves_and_owner_drops_preserve_slot_and_cancellation_lifetimes() {
        let root = ExecutionWorkPool::with_admission_limit(30, 1);
        let child = root.partition(20).unwrap();
        let job = child.reserve(5).unwrap();
        let signal = job.execution_cancellation().unwrap();
        let control = job.task_control();
        let mut queue = std::collections::VecDeque::from([job]);
        drop(child);
        let job = queue.pop_front().unwrap();
        queue.push_back(job);
        assert_eq!(root.outstanding_admissions(), 1);
        assert!(!control.is_cancelled());
        drop(queue);
        assert!(control.is_cancelled());
        signal.reset();
        assert!(signal.is_cancelled());
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 10);
        let _next = root.reserve(5).unwrap();
    }

    #[test]
    fn revocation_does_not_release_live_capacity_or_revoke_a_sibling() {
        let root = ExecutionWorkPool::with_admission_limit(40, 1);
        let a = root.partition(20).unwrap();
        let b = root.partition(20).unwrap();
        let job = a.reserve(10).unwrap();
        a.revoke();
        job.task_control().cancel();
        assert_eq!(root.outstanding_admissions(), 1);
        assert!(matches!(a.reserve(1), Err(WorkBudgetError::Revoked)));
        assert!(matches!(b.reserve(10), Err(WorkBudgetError::AdmissionLimit { limit: 1 })));
        assert_eq!(b.remaining(), 20);
        drop(job);
        let _peer = b.reserve(10).unwrap();
        assert!(!root.is_revoked());
        assert!(!b.is_revoked());
    }

    #[test]
    fn unwinding_releases_capacity_but_never_refunds_spent_instructions() {
        let root = ExecutionWorkPool::with_admission_limit(30, 1);
        let outcome = std::panic::catch_unwind(|| {
            let _job = root.reserve(10).unwrap();
            assert_eq!(root.outstanding_admissions(), 1);
            panic!("injected owner unwind");
        });
        assert!(outcome.is_err());
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 20);
        let _next = root.reserve(10).unwrap();
    }

    #[test]
    fn concurrent_siblings_cannot_multiply_root_capacity() {
        let root = ExecutionWorkPool::with_admission_limit(320, 3);
        let ready = Arc::new(Barrier::new(33));
        let held = Arc::new(Barrier::new(33));
        let release = Arc::new(Barrier::new(33));
        let workers: Vec<_> = (0..32).map(|_| {
            let child = root.partition(10).unwrap();
            let (ready, held, release) = (ready.clone(), held.clone(), release.clone());
            std::thread::spawn(move || {
                ready.wait();
                let result = child.reserve(1);
                held.wait();
                release.wait();
                result
            })
        }).collect();
        ready.wait();
        held.wait();
        let observed = root.outstanding_admissions();
        release.wait();
        let mut admitted = Vec::new();
        for worker in workers {
            match worker.join().unwrap() {
                Ok(job) => admitted.push(job),
                Err(WorkBudgetError::AdmissionLimit { limit: 3 }) => {},
                other => panic!("unexpected reservation: {other:?}"),
            }
        }
        assert_eq!(observed, 3);
        assert_eq!(admitted.len(), 3);
        assert_eq!(root.outstanding_admissions(), 3);
        drop(admitted);
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 0, "delegated fuel is never refunded");
    }

    #[test]
    fn maximum_slot_count_cannot_wrap_and_independent_roots_do_not_share_it() {
        let slots = Arc::new(AdmissionSlots {
            limit: usize::MAX,
            occupied: AtomicUsize::new(usize::MAX - 1),
        });
        let slot = AdmissionSlot::acquire(&slots).unwrap();
        assert_eq!(slots.occupied.load(Ordering::Acquire), usize::MAX);
        assert!(matches!(AdmissionSlot::acquire(&slots), Err(WorkBudgetError::AdmissionLimit { limit: usize::MAX })));
        drop(slot);
        assert_eq!(slots.occupied.load(Ordering::Acquire), usize::MAX - 1);
        let first = ExecutionWorkPool::with_admission_limit(10, 1);
        let second = ExecutionWorkPool::with_admission_limit(10, 1);
        let _a = first.reserve(1).unwrap();
        let _b = second.reserve(1).unwrap();
        assert_eq!(first.outstanding_admissions(), 1);
        assert_eq!(second.outstanding_admissions(), 1);
    }

    #[test]
    fn reusable_vm_cannot_bypass_a_queued_siblings_admission() {
        use super::super::tests::{config, interpreter, module};
        use crate::baseline_interpreter::InterpreterCore;

        let root = ExecutionWorkPool::with_admission_limit(512, 1);
        let mut runtime = interpreter(&root, 128);
        let held = root.reserve(1).unwrap();
        assert!(matches!(
            runtime.execute(&module("40 + 2;")),
            Err(WorkBudgetError::AdmissionLimit { limit: 1 })
        ));
        assert!(runtime.core.is_none(), "refusal must precede VM creation");
        assert_eq!(root.remaining(), 511);
        drop(held);
        let source = module("40 + 2;");
        let expected = InterpreterCore::new(config(128), "work-budget")
            .execute(&source).unwrap();
        let actual = runtime.execute(&source).unwrap();
        assert_eq!(actual.value, expected.value);
        assert_eq!(actual.completion_label, expected.completion_label);
        assert_eq!(actual.instructions_executed, expected.instructions_executed);
        assert_eq!(actual.console_output, expected.console_output);
        assert_eq!(root.outstanding_admissions(), 0);
        let held = root.reserve(1).unwrap();
        assert!(matches!(
            runtime.execute(&source),
            Err(WorkBudgetError::AdmissionLimit { limit: 1 })
        ));
        assert_eq!(root.remaining(), 382);
        drop(held);
        runtime.execute(&source).unwrap();
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 254);
    }

    #[test]
    fn native_traps_and_rejected_dispatch_release_slots_not_fuel() {
        use super::super::tests::{config, module};
        use crate::baseline_interpreter::InterpreterError;

        let root = ExecutionWorkPool::with_admission_limit(512, 1);
        let job = root.reserve(128).unwrap();
        assert!(matches!(
            job.execute(&module("throw 7;"), config(128), "trap"),
            Err(WorkBudgetError::Interpreter(InterpreterError::UncaughtException { .. }))
        ));
        assert_eq!(root.outstanding_admissions(), 0);
        let job = root.reserve(128).unwrap();
        assert!(matches!(
            job.execute(&module("7;"), config(0), "invalid"),
            Err(WorkBudgetError::ZeroInstructionBudget)
        ));
        assert_eq!(root.outstanding_admissions(), 0);
        let job = root.reserve(128).unwrap();
        let mut denied = config(128);
        denied.granted_capabilities.clear();
        assert!(matches!(
            job.execute(&module("7;"), denied, "denied"),
            Err(WorkBudgetError::Interpreter(InterpreterError::CapabilityDenied { .. }))
        ));
        assert_eq!(root.outstanding_admissions(), 0);
        root.reserve(128).unwrap().execute(&module("7;"), config(128), "success").unwrap();
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 0);
    }

    #[test]
    fn caught_native_unwind_releases_the_slot_and_preserves_vm_poisoning() {
        use super::super::tests::{PanickingHook, config, interpreter, module};
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let root = ExecutionWorkPool::with_admission_limit(512, 1);
        let source = module("let object = {}; object;");
        let mut runtime = interpreter(&root, 128);
        runtime.set_hook(Arc::new(PanickingHook));
        assert!(catch_unwind(AssertUnwindSafe(|| runtime.execute(&source))).is_err());
        assert_eq!(root.outstanding_admissions(), 0);
        assert!(matches!(runtime.execute(&source), Err(WorkBudgetError::Interrupted)));
        assert_eq!(root.remaining(), 384);
        let job = root.reserve(128).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| {
            job.execute_with_hook(&source, config(128), "panic", Some(Arc::new(PanickingHook)))
        })).is_err());
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 256);
        root.reserve(128).unwrap().execute(&module("7;"), config(128), "peer").unwrap();
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 128);
    }

    #[test]
    fn cancelled_or_invalid_worker_start_releases_its_prepaid_slot() {
        use super::super::tests::{config, module};
        use crate::execution_work_budget::ExecutionTaskStartError;

        let root = ExecutionWorkPool::with_admission_limit(256, 1);
        let job = root.reserve(128).unwrap();
        job.task_control().cancel();
        assert!(matches!(
            job.spawn(module("7;"), config(128), "cancelled"),
            Err(ExecutionTaskStartError::Admission(WorkBudgetError::Revoked))
        ));
        assert_eq!(root.outstanding_admissions(), 0);
        let job = root.reserve(128).unwrap();
        assert!(matches!(
            job.spawn(module("7;"), config(0), "invalid"),
            Err(ExecutionTaskStartError::Admission(WorkBudgetError::ZeroInstructionBudget))
        ));
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 0);
    }
}
