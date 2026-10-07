use super::*;
use frankenengine_extension_host::host_io::HostIoResponse;
use std::sync::Barrier;
use std::sync::atomic::AtomicUsize;

fn pool(operations: u64, max_in_flight: usize) -> HostEffectWorkPool {
    HostEffectWorkPool::new(HostEffectLimits {
        operations,
        max_in_flight,
    })
}

fn request() -> HostIoRequest {
    HostIoRequest::NetworkSend {
        endpoint: "test.invalid:80".into(),
        payload: vec![1, 2],
    }
}

const GRANTED: &[HostIoCapability] = &[HostIoCapability::NetworkSend];

#[derive(Debug, Default)]
struct Counting(AtomicUsize);
impl HostIoProvider for Counting {
    fn name(&self) -> &str {
        "counting"
    }
    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        HostIoExceptionProvenance::ProviderInternal
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("adapter must forward the live operation control")
    }
    fn perform_controlled(
        &self,
        _: &HostIoRequest,
        _: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control.checkpoint()?;
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(HostIoResponse::NetworkSend { bytes_sent: 2 })
    }
}

fn denied(outcome: HostIoOutcome, code: &str) {
    assert!(matches!(outcome, Err(HostIoError::Denied { reason }) if reason == code));
}

#[test]
fn cloned_pools_and_providers_share_nonrenewable_allowance() {
    let budget = pool(2, 1);
    let alias = budget.clone();
    let work = ExecutionWorkPool::new(100);
    let inner = Arc::new(Counting::default());
    let first = budget.bind_host_io(inner.clone(), &work);
    let second = alias.bind_host_io(inner.clone(), &work);
    first.perform(&request(), GRANTED).unwrap();
    first.clone().perform(&request(), GRANTED).unwrap();
    denied(
        second.perform(&request(), GRANTED),
        "HOST_EFFECT_BUDGET_EXHAUSTED",
    );
    assert_eq!(inner.0.load(Ordering::SeqCst), 2);
    assert_eq!(
        budget.snapshot().unwrap(),
        HostEffectSnapshot {
            remaining_operations: 0,
            committed_operations: 2,
            in_flight: 0,
        }
    );
    assert_eq!(
        work.remaining(),
        100,
        "effect and instruction allowances are independent"
    );
}

#[test]
fn zero_limits_and_missing_capability_refuse_before_provider_or_debit() {
    for (operations, concurrency) in [(0, 1), (1, 0)] {
        let budget = pool(operations, concurrency);
        let inner = Arc::new(Counting::default());
        let provider = budget.bind_host_io(inner.clone(), &ExecutionWorkPool::new(10));
        assert!(provider.perform(&request(), GRANTED).is_err());
        assert_eq!(inner.0.load(Ordering::SeqCst), 0);
        assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
    }
    let budget = pool(10, 1);
    let inner = Arc::new(Counting::default());
    let provider = budget.bind_host_io(inner.clone(), &ExecutionWorkPool::new(10));
    assert!(matches!(
        provider.perform(&request(), &[]),
        Err(HostIoError::CapabilityMissing { .. })
    ));
    assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
    assert_eq!(inner.0.load(Ordering::SeqCst), 0);
    assert_eq!(provider.name(), inner.name());
    assert_eq!(
        provider.filesystem_exception_provenance(),
        HostIoExceptionProvenance::ProviderInternal
    );
}

#[derive(Debug)]
struct Failing {
    panic: bool,
}
impl HostIoProvider for Failing {
    fn name(&self) -> &str {
        "failing"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        unreachable!()
    }
    fn perform_controlled(
        &self,
        _: &HostIoRequest,
        _: &[HostIoCapability],
        _: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        assert!(!self.panic, "injected native unwind");
        Err(HostIoError::Io {
            detail: "native failure".into(),
        })
    }
}

#[test]
fn errors_and_unwinding_release_slots_without_refunding_effects() {
    let budget = pool(2, 1);
    let work = ExecutionWorkPool::new(10);
    let failing = budget.bind_host_io(Arc::new(Failing { panic: false }), &work);
    assert!(matches!(
        failing.perform(&request(), GRANTED),
        Err(HostIoError::Io { .. })
    ));
    let panicking = budget.bind_host_io(Arc::new(Failing { panic: true }), &work);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || panicking.perform(&request(), GRANTED)
        ))
        .is_err()
    );
    assert_eq!(
        budget.snapshot().unwrap(),
        HostEffectSnapshot {
            remaining_operations: 0,
            committed_operations: 2,
            in_flight: 0,
        }
    );
}

#[derive(Debug)]
struct Blocking {
    entered: Barrier,
    release: Barrier,
}
impl HostIoProvider for Blocking {
    fn name(&self) -> &str {
        "blocking"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        unreachable!()
    }
    fn perform_controlled(
        &self,
        _: &HostIoRequest,
        _: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.entered.wait();
        self.release.wait();
        control.checkpoint()?;
        Ok(HostIoResponse::NetworkSend { bytes_sent: 2 })
    }
}

#[test]
fn concurrent_provider_calls_cannot_oversubscribe_shared_slot_limit() {
    let budget = pool(3, 1);
    let work = ExecutionWorkPool::new(10);
    let blocker = Arc::new(Blocking {
        entered: Barrier::new(2),
        release: Barrier::new(2),
    });
    let provider = budget.bind_host_io(blocker.clone(), &work);
    let worker = std::thread::spawn(move || provider.perform(&request(), GRANTED));
    blocker.entered.wait();
    let inner = Arc::new(Counting::default());
    let other = budget.bind_host_io(inner.clone(), &work);
    denied(
        other.perform(&request(), GRANTED),
        "HOST_EFFECT_CONCURRENCY_LIMIT",
    );
    assert_eq!(inner.0.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    blocker.release.wait();
    worker.join().unwrap().unwrap();
    other.perform(&request(), GRANTED).unwrap();
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
}

#[test]
fn ancestor_revocation_reaches_active_effect_without_revoking_sibling_scope() {
    let budget = pool(3, 2);
    let root = ExecutionWorkPool::new(20);
    let child = root.partition(10).unwrap();
    let sibling = root.partition(10).unwrap();
    let blocker = Arc::new(Blocking {
        entered: Barrier::new(2),
        release: Barrier::new(2),
    });
    let provider = budget.bind_host_io(blocker.clone(), &child);
    let worker = std::thread::spawn(move || provider.perform(&request(), GRANTED));
    blocker.entered.wait();
    child.revoke();
    blocker.release.wait();
    denied(worker.join().unwrap(), "HOST_EFFECT_SCOPE_REVOKED");
    let inner = Arc::new(Counting::default());
    budget
        .bind_host_io(inner.clone(), &sibling)
        .perform(&request(), GRANTED)
        .unwrap();
    root.revoke();
    denied(
        budget
            .bind_host_io(inner.clone(), &sibling)
            .perform(&request(), GRANTED),
        "HOST_EFFECT_SCOPE_REVOKED",
    );
    assert_eq!(inner.0.load(Ordering::SeqCst), 1);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 2);
}

#[test]
fn pool_revocation_reaches_all_aliases_and_does_not_refund() {
    let budget = pool(5, 2);
    let alias = budget.clone();
    let work = ExecutionWorkPool::new(10);
    let inner = Arc::new(Counting::default());
    let provider = alias.bind_host_io(inner.clone(), &work);
    provider.perform(&request(), GRANTED).unwrap();
    budget.revoke();
    denied(
        provider.perform(&request(), GRANTED),
        "HOST_EFFECT_SCOPE_REVOKED",
    );
    assert!(alias.is_revoked());
    assert_eq!(budget.snapshot().unwrap().remaining_operations, 4);
    assert_eq!(inner.0.load(Ordering::SeqCst), 1);
}

#[derive(Debug, Default)]
struct ResettableControl(AtomicBool);
impl HostIoControl for ResettableControl {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        if self.0.load(Ordering::SeqCst) {
            Err(HostIoError::Fs {
                code: "private-code".into(),
                detail: "secret".into(),
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct ObserveThenReset(Arc<ResettableControl>);
impl HostIoProvider for ObserveThenReset {
    fn name(&self) -> &str {
        "resetter"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        unreachable!()
    }
    fn perform_controlled(
        &self,
        _: &HostIoRequest,
        _: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.0.0.store(true, Ordering::SeqCst);
        assert!(control.checkpoint().is_err());
        self.0.0.store(false, Ordering::SeqCst);
        // Even a custom provider swallowing cancellation cannot publish success.
        Ok(HostIoResponse::NetworkSend { bytes_sent: 2 })
    }
}

#[test]
fn caller_cancellation_is_forwarded_sticky_and_redacted() {
    let budget = pool(2, 1);
    let work = ExecutionWorkPool::new(10);
    let caller = Arc::new(ResettableControl::default());
    let provider = budget.bind_host_io(Arc::new(ObserveThenReset(caller.clone())), &work);
    denied(
        provider.perform_controlled(&request(), GRANTED, caller.clone()),
        "HOST_EFFECT_SCOPE_REVOKED",
    );
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    let counter = Arc::new(Counting::default());
    budget
        .bind_host_io(counter, &work)
        .perform_controlled(&request(), GRANTED, caller)
        .unwrap();
}

#[test]
fn many_concurrent_callers_cannot_mint_operation_credits() {
    let budget = pool(17, 32);
    let work = ExecutionWorkPool::new(10);
    let inner = Arc::new(Counting::default());
    let start = Arc::new(Barrier::new(32));
    let workers: Vec<_> = (0..32)
        .map(|_| {
            let start = start.clone();
            let provider = budget.bind_host_io(inner.clone(), &work);
            std::thread::spawn(move || {
                start.wait();
                provider.perform(&request(), GRANTED).is_ok()
            })
        })
        .collect();
    let successes = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 17);
    assert_eq!(inner.0.load(Ordering::SeqCst), 17);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
    assert_eq!(budget.snapshot().unwrap().remaining_operations, 0);
}
