use super::*;
use crate::host_io::budget::{HostIoBudgetError, HostIoBudgetLimits};
use crate::host_io::{
    HostIoCapability, HostIoError, HostIoProvider, HostIoRequest, SandboxedHostIo,
};
use std::sync::{Arc, Barrier, mpsc};

fn budget(requests: u64, concurrency: usize) -> HostIoWorkBudget {
    HostIoWorkBudget::new(HostIoBudgetLimits {
        requests,
        request_bytes: 4096,
        max_in_flight: concurrency,
    })
}

fn request() -> HostIoRequest {
    HostIoRequest::FsRead { path: "a".into() }
}

#[test]
fn idle_close_is_terminal_idempotent_and_does_not_spend_credits() {
    let pool = budget(4, 2);
    let before = pool.snapshot().unwrap();
    let closed = pool.revoke_and_drain(Duration::ZERO).unwrap();
    assert_eq!(closed.remaining_requests, before.remaining_requests);
    assert_eq!(
        closed.remaining_request_bytes,
        before.remaining_request_bytes
    );
    assert_eq!(closed.in_flight, 0);
    assert!(closed.revoked);
    assert_eq!(pool.revoke_and_drain(Duration::ZERO).unwrap(), closed);
    assert!(matches!(
        pool.admit(&request()),
        Err(HostIoBudgetError::Revoked)
    ));
    assert!(matches!(
        pool.partition(pool.limits()),
        Err(HostIoBudgetError::Revoked)
    ));
}

#[test]
fn timeout_leaves_scope_revoked_and_retry_waits_for_the_original_call() {
    let pool = budget(4, 2);
    let permit = pool.admit(&request()).unwrap();
    assert_eq!(
        pool.revoke_and_drain(Duration::ZERO),
        Err(HostIoDrainError::TimedOut { in_flight: 1 })
    );
    assert!(pool.is_revoked());
    assert!(matches!(
        pool.admit(&request()),
        Err(HostIoBudgetError::Revoked)
    ));
    drop(permit);
    let closed = pool.revoke_and_drain(Duration::ZERO).unwrap();
    assert_eq!(closed.remaining_requests, 3);
    assert_eq!(closed.remaining_request_bytes, 4095);
}

#[test]
fn root_waits_for_prepaid_grandchildren_not_just_direct_calls() {
    let root = budget(4, 2);
    let child = root.partition(root.limits()).unwrap();
    let leaf = child.partition(child.limits()).unwrap();
    let permit = leaf.admit(&request()).unwrap();
    assert_eq!(root.snapshot().unwrap().remaining_requests, 0);
    assert_eq!(
        root.revoke_and_drain(Duration::ZERO),
        Err(HostIoDrainError::TimedOut { in_flight: 1 })
    );
    assert!(leaf.is_revoked());
    drop(permit);
    assert_eq!(root.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
    assert_eq!(child.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
    assert_eq!(
        leaf.revoke_and_drain(Duration::ZERO)
            .unwrap()
            .remaining_requests,
        3
    );
}

#[test]
fn closing_one_tenant_does_not_wait_for_or_revoke_a_sibling() {
    let root = budget(4, 2);
    let limits = HostIoBudgetLimits {
        requests: 1,
        request_bytes: 1,
        max_in_flight: 1,
    };
    let first = root.partition(limits).unwrap();
    let second = root.partition(limits).unwrap();
    let permit = second.admit(&request()).unwrap();
    assert!(first.revoke_and_drain(Duration::ZERO).is_ok());
    assert!(!root.is_revoked());
    assert!(!second.is_revoked());
    assert_eq!(root.snapshot().unwrap().in_flight, 1);
    drop(permit);
    drop(root.admit(&request()).unwrap());
}

#[test]
fn all_concurrent_closers_are_released_by_the_last_permit() {
    let root = budget(4, 2);
    let child = root.partition(root.limits()).unwrap();
    let first = child.admit(&request()).unwrap();
    let last = child.admit(&request()).unwrap();
    let start = Arc::new(Barrier::new(5));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let root = root.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            root.revoke_and_drain(Duration::from_secs(5))
        }));
    }
    start.wait();
    drop(first);
    drop(last);
    for worker in workers {
        let closed = worker.join().unwrap().unwrap();
        assert!(closed.revoked);
        assert_eq!(closed.in_flight, 0);
        assert_eq!(closed.remaining_requests, 0);
    }
}

#[test]
fn spurious_notification_does_not_certify_an_in_flight_call() {
    let pool = budget(2, 1);
    let permit = pool.admit(&request()).unwrap();
    pool.shared.drained.notify_all();
    assert_eq!(
        pool.revoke_and_drain(Duration::from_millis(1)),
        Err(HostIoDrainError::TimedOut { in_flight: 1 })
    );
    drop(permit);
    assert!(pool.revoke_and_drain(Duration::ZERO).is_ok());
}

#[test]
fn unwinding_releases_every_ancestor_for_drain_without_refund() {
    let root = budget(2, 1);
    let child = root.partition(root.limits()).unwrap();
    let result = std::panic::catch_unwind(|| {
        let _permit = child.admit(&request()).unwrap();
        panic!("simulated owner unwind, not a provider response");
    });
    assert!(result.is_err());
    assert!(child.is_revoked());
    assert_eq!(
        child
            .revoke_and_drain(Duration::ZERO)
            .unwrap()
            .remaining_requests,
        1
    );
    assert_eq!(root.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
}

#[test]
fn poisoned_scope_or_ancestor_never_yields_a_successful_drain() {
    let root = budget(2, 1);
    let child = root.partition(root.limits()).unwrap();
    let _ = std::panic::catch_unwind(|| {
        let _lock = root.shared.balance.lock().unwrap();
        panic!("poison accounting");
    });
    assert_eq!(
        root.revoke_and_drain(Duration::ZERO),
        Err(HostIoDrainError::AccountingPoisoned)
    );
    assert_eq!(
        child.revoke_and_drain(Duration::ZERO),
        Err(HostIoDrainError::AccountingPoisoned)
    );
    assert!(root.is_revoked());
    assert!(child.is_revoked());
}

#[test]
fn impossible_deadline_still_revokes_the_scope() {
    let pool = budget(2, 1);
    assert_eq!(
        pool.revoke_and_drain(Duration::MAX),
        Err(HostIoDrainError::DeadlineOverflow)
    );
    assert!(pool.is_revoked());
    assert!(matches!(
        pool.admit(&request()),
        Err(HostIoBudgetError::Revoked)
    ));
}

#[test]
fn admission_racing_a_close_cannot_survive_a_successful_drain() {
    for _ in 0..64 {
        let pool = budget(1, 1);
        let child = pool.partition(pool.limits()).unwrap();
        let start = Arc::new(Barrier::new(2));
        let worker_start = start.clone();
        let worker = std::thread::spawn(move || {
            worker_start.wait();
            match child.admit(&request()) {
                Ok(permit) => drop(permit),
                Err(error) => assert_eq!(error, HostIoBudgetError::Revoked),
            }
            assert!(child.is_revoked() || child.snapshot().unwrap().in_flight == 0);
        });
        start.wait();
        let closed = pool.revoke_and_drain(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        assert_eq!(closed.in_flight, 0);
        assert_eq!(pool.snapshot().unwrap().in_flight, 0);
        assert!(pool.is_revoked());
    }
}

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fe-host-io-drain-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn a_drained_native_provider_cannot_mutate_the_filesystem() {
    let scratch = Scratch::new();
    let pool = budget(2, 1);
    let provider = SandboxedHostIo::with_root(&scratch.0)
        .unwrap()
        .with_work_budget(pool.clone());
    let write = HostIoRequest::FsWrite {
        path: "target".into(),
        data: b"before".to_vec(),
    };
    provider
        .perform(&write, &[HostIoCapability::FsWrite])
        .unwrap();
    let closed = pool.revoke_and_drain(Duration::ZERO).unwrap();
    let write = HostIoRequest::FsWrite {
        path: "target".into(),
        data: b"after".to_vec(),
    };
    assert!(matches!(
        provider.perform(&write, &[HostIoCapability::FsWrite]),
        Err(HostIoError::Denied { .. })
    ));
    assert_eq!(std::fs::read(scratch.0.join("target")).unwrap(), b"before");
    assert_eq!(pool.snapshot().unwrap(), closed);
}

#[test]
fn root_drain_cancels_and_joins_a_real_descendant_network_read() {
    use std::io::Read;
    use std::net::TcpListener;

    let scratch = Scratch::new();
    let root = budget(2, 1);
    let child = root.partition(root.limits()).unwrap();
    let provider = SandboxedHostIo::with_root(&scratch.0)
        .unwrap()
        .with_network_timeout(Duration::from_secs(8))
        .unwrap()
        .with_work_budget(child.clone());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    // Bound the listener loop too, so a pre-connect regression does not leave
    // an accept thread blocked forever when the test reports its failure.
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "native connect never arrived");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _ = accepted_tx.send(());
        // No response is sent. Only real cancellation/close can end the
        // client's native read before its operation deadline.
        let mut byte = [0];
        stream.read(&mut byte)
    });
    let worker = std::thread::spawn(move || {
        provider.perform(
            &HostIoRequest::NetworkRecv {
                endpoint: address.to_string(),
                max_len: 16,
            },
            &[HostIoCapability::NetworkRecv],
        )
    });
    let connected = accepted_rx.recv_timeout(Duration::from_secs(10));
    let drain = root.revoke_and_drain(Duration::from_secs(5));
    let outcome = worker.join().unwrap();
    let peer_close = server.join().unwrap();
    assert!(connected.is_ok());
    assert!(drain.is_ok(), "cooperative network drain failed: {drain:?}");
    assert!(matches!(outcome, Err(HostIoError::Denied { .. })));
    assert!(
        matches!(peer_close, Ok(0)),
        "native socket was not closed: {peer_close:?}"
    );
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
    assert_eq!(child.snapshot().unwrap().in_flight, 0);
    assert_eq!(child.snapshot().unwrap().remaining_requests, 1);
}
