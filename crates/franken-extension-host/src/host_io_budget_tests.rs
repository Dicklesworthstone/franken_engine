//! Behavioral tests for the live provider membrane, not just its counters.

use super::*;
use crate::host_io::{DenyAllHostIo, FsOperation, HostIoResponse};
use std::path::PathBuf;
use std::sync::Barrier;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

fn budget(requests: u64, bytes: u64, concurrent: usize) -> HostIoWorkBudget {
    HostIoWorkBudget::new(HostIoBudgetLimits {
        requests,
        request_bytes: bytes,
        max_in_flight: concurrent,
    })
}

fn write() -> HostIoRequest {
    HostIoRequest::FsWrite {
        path: "file".into(),
        data: b"value".to_vec(),
    }
}

fn assert_denied(outcome: HostIoOutcome, code: &str) {
    assert!(matches!(outcome, Err(HostIoError::Denied { reason }) if reason == code));
}

#[derive(Debug, Default)]
struct RecordingProvider {
    calls: AtomicUsize,
    controlled: AtomicUsize,
}

impl HostIoProvider for RecordingProvider {
    fn name(&self) -> &str {
        "recording-provider"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        HostIoExceptionProvenance::ProviderInternal
    }

    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(HostIoResponse::FsWrite { bytes_written: 5 })
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.controlled.fetch_add(1, Ordering::SeqCst);
        control.checkpoint()?;
        self.perform(request, granted)
    }
}

#[test]
fn admitted_call_keeps_its_credit_when_it_exhausts_the_pool() {
    let budget = budget(1, 9, 1);
    let provider = Arc::new(RecordingProvider::default());
    let wrapped = BudgetedHostIo::new(provider.clone(), budget.clone());
    assert!(
        wrapped
            .perform(&write(), &[HostIoCapability::FsWrite])
            .is_ok()
    );
    assert_eq!(
        budget.snapshot().unwrap(),
        HostIoBudgetSnapshot {
            remaining_requests: 0,
            remaining_request_bytes: 0,
            in_flight: 0,
            revoked: false,
        }
    );
    assert_denied(
        wrapped.perform(&write(), &[HostIoCapability::FsWrite]),
        "HOST_IO_REQUEST_BUDGET_EXHAUSTED",
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.controlled.load(Ordering::SeqCst), 1);
}

#[test]
fn clones_and_independent_wrappers_share_the_same_nonrenewable_work() {
    let budget = budget(2, 18, 2);
    let provider = Arc::new(RecordingProvider::default());
    let first = BudgetedHostIo::new(provider.clone(), budget.clone());
    let alias = first.clone();
    let second = BudgetedHostIo::new(provider.clone(), budget.clone());
    assert!(
        first
            .perform(&write(), &[HostIoCapability::FsWrite])
            .is_ok()
    );
    assert!(
        second
            .perform(&write(), &[HostIoCapability::FsWrite])
            .is_ok()
    );
    assert_denied(
        alias.perform(&write(), &[HostIoCapability::FsWrite]),
        "HOST_IO_REQUEST_BUDGET_EXHAUSTED",
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn byte_refusal_is_atomic_across_all_dimensions() {
    let budget = budget(5, 8, 1);
    let before = budget.snapshot().unwrap();
    let provider = Arc::new(RecordingProvider::default());
    let wrapped = BudgetedHostIo::new(provider.clone(), budget.clone());
    assert_denied(
        wrapped.perform(&write(), &[HostIoCapability::FsWrite]),
        "HOST_IO_REQUEST_BYTES_EXHAUSTED",
    );
    assert_eq!(budget.snapshot().unwrap(), before);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn missing_capability_never_reaches_provider_or_consumes_budget() {
    let budget = budget(1, 9, 1);
    let before = budget.snapshot().unwrap();
    let provider = Arc::new(RecordingProvider::default());
    let wrapped = BudgetedHostIo::new(provider.clone(), budget.clone());
    assert_eq!(
        wrapped.perform(&write(), &[]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsWrite,
        })
    );
    assert_eq!(budget.snapshot().unwrap(), before);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn provider_denial_consumes_admission_without_claiming_a_real_mechanism() {
    let budget = budget(1, 9, 1);
    let wrapped = BudgetedHostIo::new(Arc::new(DenyAllHostIo), budget.clone());
    assert_eq!(wrapped.name(), DenyAllHostIo.name());
    assert_eq!(
        wrapped.filesystem_exception_provenance(),
        DenyAllHostIo.filesystem_exception_provenance()
    );
    assert!(
        wrapped
            .perform(&write(), &[HostIoCapability::FsWrite])
            .is_err()
    );
    let state = budget.snapshot().unwrap();
    assert_eq!(state.remaining_requests, 0);
    assert_eq!(state.remaining_request_bytes, 0);
    assert_eq!(state.in_flight, 0);
}

#[test]
fn exception_provenance_and_provider_identity_are_preserved() {
    let wrapped = BudgetedHostIo::new(Arc::new(RecordingProvider::default()), budget(1, 9, 1));
    assert_eq!(wrapped.name(), "recording-provider");
    assert_eq!(
        wrapped.filesystem_exception_provenance(),
        HostIoExceptionProvenance::ProviderInternal
    );
}

#[test]
fn zero_requests_or_concurrency_denies_all_dispatch_without_debit() {
    for limits in [(0, 9, 1), (1, 9, 0)] {
        let budget = budget(limits.0, limits.1, limits.2);
        let before = budget.snapshot().unwrap();
        let provider = Arc::new(RecordingProvider::default());
        let wrapped = BudgetedHostIo::new(provider.clone(), budget.clone());
        assert!(
            wrapped
                .perform(&write(), &[HostIoCapability::FsWrite])
                .is_err()
        );
        assert_eq!(budget.snapshot().unwrap(), before);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn every_owned_request_payload_has_an_explicit_byte_charge() {
    let cases = [
        (HostIoRequest::FsRead { path: "é".into() }, 2),
        (write(), 9),
        (
            HostIoRequest::FsMeta {
                operation: FsOperation::Rename,
                path: "a".into(),
                arguments: vec!["bé".into(), "".into(), "z".into()],
                data: vec![0, 255],
            },
            7,
        ),
        (
            HostIoRequest::NetworkSend {
                endpoint: "a:1".into(),
                payload: vec![0, 1],
            },
            5,
        ),
        (
            HostIoRequest::NetworkRecv {
                endpoint: "a:1".into(),
                max_len: 1024,
            },
            3,
        ),
        (
            HostIoRequest::NetworkRequest {
                endpoint: "a:1".into(),
                payload: vec![0, 1],
                max_len: 1024,
                use_tls: true,
            },
            5,
        ),
        (HostIoRequest::RandomRead { byte_len: 32 }, 0),
    ];
    for (request, expected) in cases {
        assert_eq!(request_bytes(&request).unwrap(), expected);
    }
}

#[test]
fn u64_max_limits_do_not_wrap_on_admission() {
    let budget = budget(u64::MAX, u64::MAX, usize::MAX);
    let admission = budget.admit(&write()).unwrap();
    let snapshot = budget.snapshot().unwrap();
    assert_eq!(snapshot.remaining_requests, u64::MAX - 1);
    assert_eq!(snapshot.remaining_request_bytes, u64::MAX - 9);
    assert_eq!(snapshot.in_flight, 1);
    drop(admission);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
}

#[derive(Debug)]
struct BlockingProvider {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
}

impl HostIoProvider for BlockingProvider {
    fn name(&self) -> &str {
        "blocked"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        self.entered.send(()).expect("notify test owner");
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded test release");
        Ok(HostIoResponse::FsWrite { bytes_written: 5 })
    }
}

#[test]
fn concurrent_refusal_does_not_debit_and_capacity_is_released_after_return() {
    let (entered, entered_rx) = channel();
    let (release, release_rx) = channel();
    let budget = budget(3, 27, 1);
    let wrapped = BudgetedHostIo::new(
        Arc::new(BlockingProvider {
            entered,
            release: Mutex::new(release_rx),
        }),
        budget.clone(),
    );
    let alias = wrapped.clone();
    let worker = std::thread::spawn(move || alias.perform(&write(), &[HostIoCapability::FsWrite]));
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("provider entered");
    let before = budget.snapshot().unwrap();
    let refusal = wrapped.perform(&write(), &[HostIoCapability::FsWrite]);
    let after = budget.snapshot().unwrap();
    // Release the worker even if an assertion below fails.
    release.send(()).expect("release native stand-in");
    let first = worker.join().unwrap();
    assert!(first.is_ok());
    assert_denied(refusal, "HOST_IO_CONCURRENCY_EXHAUSTED");
    assert_eq!(before, after);
    assert_eq!(before.in_flight, 1);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
    // The permit is reusable, but the work credit was not refunded.
    let next = budget.admit(&write()).unwrap();
    assert_eq!(budget.snapshot().unwrap().remaining_requests, 1);
    drop(next);
}

#[test]
fn simultaneous_admission_never_overspends_any_dimension() {
    let budget = budget(7, 63, 32);
    let provider = Arc::new(RecordingProvider::default());
    let wrapped = BudgetedHostIo::new(provider.clone(), budget.clone());
    let barrier = Arc::new(Barrier::new(32));
    let workers: Vec<_> = (0..32)
        .map(|_| {
            let wrapped = wrapped.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                wrapped
                    .perform(&write(), &[HostIoCapability::FsWrite])
                    .is_ok()
            })
        })
        .collect();
    let successes = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 7);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 7);
    let snapshot = budget.snapshot().unwrap();
    assert_eq!(snapshot.remaining_requests, 0);
    assert_eq!(snapshot.remaining_request_bytes, 0);
    assert_eq!(snapshot.in_flight, 0);
}

#[test]
fn revocation_is_irreversible_across_clones_and_preserves_balances() {
    let budget = budget(3, 27, 1);
    let alias = budget.clone();
    let before = budget.snapshot().unwrap();
    budget.revoke();
    budget.revoke();
    assert!(alias.is_revoked());
    let wrapped = BudgetedHostIo::new(Arc::new(RecordingProvider::default()), alias);
    assert_denied(
        wrapped.perform(&write(), &[HostIoCapability::FsWrite]),
        "HOST_IO_BUDGET_REVOKED",
    );
    let after = budget.snapshot().unwrap();
    assert_eq!(after.remaining_requests, before.remaining_requests);
    assert_eq!(
        after.remaining_request_bytes,
        before.remaining_request_bytes
    );
    assert_eq!(after.in_flight, 0);
}

#[derive(Debug)]
struct RevokingProvider(HostIoWorkBudget);
impl HostIoProvider for RevokingProvider {
    fn name(&self) -> &str {
        "revokes-during-effect"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        self.0.revoke();
        Ok(HostIoResponse::FsWrite { bytes_written: 5 })
    }
}

#[test]
fn revocation_after_dispatch_prevents_success_publication_without_refund() {
    let budget = budget(1, 9, 1);
    let wrapped = BudgetedHostIo::new(Arc::new(RevokingProvider(budget.clone())), budget.clone());
    assert_denied(
        wrapped.perform(&write(), &[HostIoCapability::FsWrite]),
        "HOST_IO_BUDGET_REVOKED",
    );
    let snapshot = budget.snapshot().unwrap();
    assert_eq!(snapshot.remaining_requests, 0);
    assert_eq!(snapshot.remaining_request_bytes, 0);
    assert_eq!(snapshot.in_flight, 0);
}

#[derive(Debug)]
struct NetworkProvider {
    seen: Arc<Mutex<Option<Arc<dyn HostIoControl>>>>,
}
impl HostIoProvider for NetworkProvider {
    fn name(&self) -> &str {
        "controlled-network"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("budgeted networking must forward live control");
    }
    fn perform_controlled(
        &self,
        _: &HostIoRequest,
        _: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control.checkpoint()?;
        *self.seen.lock().unwrap() = Some(control);
        Ok(HostIoResponse::NetworkRecv { bytes: Vec::new() })
    }
}

#[test]
fn plain_perform_still_installs_live_network_revocation() {
    let budget = budget(2, 100, 1);
    let seen = Arc::new(Mutex::new(None));
    let wrapped = BudgetedHostIo::new(
        Arc::new(NetworkProvider { seen: seen.clone() }),
        budget.clone(),
    );
    assert!(
        wrapped
            .perform(
                &HostIoRequest::NetworkRecv {
                    endpoint: "localhost:80".into(),
                    max_len: 1,
                },
                &[HostIoCapability::NetworkRecv]
            )
            .is_ok()
    );
    let control = seen.lock().unwrap().clone().unwrap();
    assert!(control.checkpoint().is_ok());
    budget.revoke();
    assert!(control.checkpoint().is_err());
}

#[derive(Debug, Default)]
struct Supervisor(AtomicBool);
impl HostIoControl for Supervisor {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        if self.0.load(Ordering::Acquire) {
            Err(HostIoError::Fs {
                code: "EIO".into(),
                detail: "private supervisor diagnostic".into(),
            })
        } else {
            Ok(())
        }
    }
}

#[test]
fn caller_cancellation_is_sanitized_and_sticky_but_does_not_revoke_siblings() {
    let budget = budget(2, 18, 1);
    let supervisor = Arc::new(Supervisor::default());
    let control = BudgetControl {
        budget: budget.clone(),
        supervisor: supervisor.clone(),
        refused: AtomicBool::new(false),
    };
    supervisor.0.store(true, Ordering::Release);
    assert_eq!(
        control.checkpoint(),
        Err(HostIoError::Denied {
            reason: "HOST_IO_EXECUTION_CANCELLED".into()
        })
    );
    supervisor.0.store(false, Ordering::Release);
    assert!(control.checkpoint().is_err());
    assert!(!budget.is_revoked());
    let wrapped = BudgetedHostIo::new(Arc::new(RecordingProvider::default()), budget.clone());
    assert!(
        wrapped
            .perform(&write(), &[HostIoCapability::FsWrite])
            .is_ok()
    );
}

#[test]
fn already_cancelled_supervisor_is_refused_before_admission() {
    let budget = budget(1, 9, 1);
    let supervisor = Arc::new(Supervisor(AtomicBool::new(true)));
    let before = budget.snapshot().unwrap();
    let wrapped = BudgetedHostIo::new(Arc::new(RecordingProvider::default()), budget.clone());
    assert_denied(
        wrapped.perform_controlled(&write(), &[HostIoCapability::FsWrite], supervisor),
        "HOST_IO_EXECUTION_CANCELLED",
    );
    assert_eq!(budget.snapshot().unwrap(), before);
}

#[derive(Debug)]
struct Panics;
impl HostIoProvider for Panics {
    fn name(&self) -> &str {
        "panics"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("provider unwind");
    }
}

#[test]
fn caught_unwind_releases_concurrency_but_revokes_the_shared_owner() {
    let budget = budget(2, 18, 1);
    let wrapped = BudgetedHostIo::new(Arc::new(Panics), budget.clone());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wrapped.perform(&write(), &[HostIoCapability::FsWrite])
        }))
        .is_err()
    );
    assert_eq!(
        budget.snapshot().unwrap(),
        HostIoBudgetSnapshot {
            remaining_requests: 1,
            remaining_request_bytes: 9,
            in_flight: 0,
            revoked: true,
        }
    );
    assert_denied(
        wrapped.perform(&write(), &[HostIoCapability::FsWrite]),
        "HOST_IO_BUDGET_REVOKED",
    );
}

#[test]
fn poisoned_accounting_never_grants_new_work() {
    let budget = budget(2, 18, 1);
    let shared = budget.shared.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = shared.balance.lock().unwrap();
            panic!("accounting failure");
        })
        .join()
        .is_err()
    );
    assert_eq!(budget.snapshot(), Err(HostIoBudgetError::Poisoned));
    assert!(matches!(
        budget.admit(&write()),
        Err(HostIoBudgetError::Poisoned)
    ));
}

struct TempRoot(PathBuf);
impl TempRoot {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "franken-host-io-budget-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("create exclusively owned test sandbox");
        Self(root)
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[cfg(unix)]
fn native_filesystem_budget_refuses_the_second_mutation_before_it_changes_disk() {
    let root = TempRoot::new();
    let budget = budget(1, 9, 1);
    let sandbox = SandboxedHostIo::with_root(&root.0)
        .unwrap()
        .with_work_budget(budget.clone());
    assert!(
        sandbox
            .perform(&write(), &[HostIoCapability::FsWrite])
            .is_ok()
    );
    assert_eq!(std::fs::read(root.0.join("file")).unwrap(), b"value");
    let alias = sandbox.clone();
    let overwrite = HostIoRequest::FsWrite {
        path: "file".into(),
        data: b"wrong".to_vec(),
    };
    assert_denied(
        alias.perform(&overwrite, &[HostIoCapability::FsWrite]),
        "HOST_IO_REQUEST_BUDGET_EXHAUSTED",
    );
    assert_eq!(std::fs::read(root.0.join("file")).unwrap(), b"value");
}

#[test]
#[cfg(unix)]
fn native_filesystem_failure_is_not_refunded_and_preserves_the_native_error() {
    let root = TempRoot::new();
    let budget = budget(1, 100, 1);
    let native = SandboxedHostIo::with_root(&root.0).unwrap();
    let missing = HostIoRequest::FsRead {
        path: "missing".into(),
    };
    let expected = native.perform(&missing, &[HostIoCapability::FsRead]);
    assert!(expected.is_err());
    let sandbox = native.with_work_budget(budget.clone());
    assert_eq!(
        sandbox.perform(&missing, &[HostIoCapability::FsRead]),
        expected
    );
    assert_eq!(budget.snapshot().unwrap().remaining_requests, 0);
    assert_eq!(budget.snapshot().unwrap().remaining_request_bytes, 93);
}

#[test]
#[cfg(unix)]
fn native_blocked_network_read_observes_budget_revocation() {
    use std::net::TcpListener;
    use std::time::Instant;

    let root = TempRoot::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let budget = budget(1, endpoint.len() as u64, 1);
    let sandbox = SandboxedHostIo::with_root(&root.0)
        .unwrap()
        .with_network_timeout(Duration::from_secs(10))
        .unwrap()
        .with_work_budget(budget.clone());
    let (completed, completion) = channel();
    let worker = std::thread::spawn(move || {
        let outcome = sandbox.perform(
            &HostIoRequest::NetworkRecv {
                endpoint,
                max_len: 1,
            },
            &[HostIoCapability::NetworkRecv],
        );
        let _ = completed.send(outcome);
    });

    // The peer deliberately sends nothing. Its accepted stream stays open
    // until the cancellation result arrives, so EOF cannot make the test pass.
    let accept_deadline = Instant::now() + Duration::from_secs(5);
    let peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break Some(peer),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= accept_deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(_) => break None,
        }
    };
    budget.revoke();
    let outcome = completion.recv_timeout(Duration::from_secs(5));
    let connected = peer.is_some();
    // Always close the peer before joining/asserting, even on a regression.
    // A missing cancellation poll must not strand a test-owned worker forever.
    drop(peer);
    drop(listener);
    worker.join().unwrap();
    assert!(
        connected,
        "the native provider must establish a real connection"
    );
    assert_denied(
        outcome.expect("revocation must interrupt the native read before its deadline"),
        "HOST_IO_BUDGET_REVOKED",
    );
    assert_eq!(
        budget.snapshot().unwrap(),
        HostIoBudgetSnapshot {
            remaining_requests: 0,
            remaining_request_bytes: 0,
            in_flight: 0,
            revoked: true,
        }
    );
}
