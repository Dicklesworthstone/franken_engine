use super::*;
use crate::host_io::{DenyAllHostIo, HostIoResponse};

fn limits(requests: u64, request_bytes: u64, max_in_flight: usize) -> HostIoBudgetLimits {
    HostIoBudgetLimits {
        requests,
        request_bytes,
        max_in_flight,
    }
}

fn request() -> HostIoRequest {
    HostIoRequest::FsWrite {
        path: "a".into(),
        data: vec![7],
    }
}

#[test]
fn delegated_work_is_spendable_after_the_ancestor_balance_is_exhausted() {
    let root = HostIoWorkBudget::new(limits(4, 8, 2));
    let first = root.partition(limits(2, 4, 1)).unwrap();
    let second = root.partition(limits(2, 4, 1)).unwrap();
    assert_eq!(root.snapshot().unwrap().remaining_requests, 0);
    for child in [&first, &second] {
        for _ in 0..2 {
            drop(child.admit(&request()).unwrap());
        }
        assert!(matches!(
            child.admit(&request()),
            Err(HostIoBudgetError::RequestsExhausted)
        ));
        assert_eq!(child.snapshot().unwrap().remaining_request_bytes, 0);
    }
    assert_eq!(root.snapshot().unwrap().remaining_request_bytes, 0);
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[test]
fn a_nested_partition_cannot_mint_or_refund_work() {
    let root = HostIoWorkBudget::new(limits(8, 16, 2));
    let tenant = root.partition(limits(6, 12, 2)).unwrap();
    let cell = tenant.partition(limits(4, 8, 1)).unwrap();
    drop(cell.admit(&request()).unwrap());
    assert_eq!(root.snapshot().unwrap().remaining_requests, 2);
    assert_eq!(tenant.snapshot().unwrap().remaining_requests, 2);
    assert_eq!(cell.snapshot().unwrap().remaining_requests, 3);
    drop(cell);
    drop(tenant);
    assert_eq!(root.snapshot().unwrap().remaining_requests, 2);
    assert_eq!(root.snapshot().unwrap().remaining_request_bytes, 4);
}

#[test]
fn every_failed_partition_leaves_all_parent_dimensions_unchanged() {
    let root = HostIoWorkBudget::new(limits(3, 6, 2));
    let before = root.snapshot().unwrap();
    for invalid in [limits(4, 0, 1), limits(1, 7, 1), limits(1, 2, 3)] {
        assert!(root.partition(invalid).is_err());
        assert_eq!(root.snapshot().unwrap(), before);
    }
}

#[test]
fn global_concurrency_is_not_multiplied_by_tenant_partitions() {
    let root = HostIoWorkBudget::new(limits(4, 8, 1));
    let first = root.partition(limits(2, 4, 1)).unwrap();
    let second = root.partition(limits(2, 4, 1)).unwrap();
    let admission = first.admit(&request()).unwrap();
    assert_eq!(root.snapshot().unwrap().in_flight, 1);
    let before = second.snapshot().unwrap();
    assert!(matches!(
        second.admit(&request()),
        Err(HostIoBudgetError::TooManyInFlight)
    ));
    assert_eq!(second.snapshot().unwrap(), before);
    drop(admission);
    let admission = second.admit(&request()).unwrap();
    assert_eq!(root.snapshot().unwrap().in_flight, 1);
    assert_eq!(first.snapshot().unwrap().in_flight, 0);
    drop(admission);
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[test]
fn exhausted_child_releases_every_provisional_ancestor_permit() {
    let root = HostIoWorkBudget::new(limits(2, 4, 2));
    let empty = root.partition(limits(0, 0, 1)).unwrap();
    let no_bytes = root.partition(limits(1, 0, 1)).unwrap();
    let no_concurrency = root.partition(limits(0, 0, 0)).unwrap();
    for child in [empty, no_bytes, no_concurrency] {
        assert!(child.admit(&request()).is_err());
        assert_eq!(root.snapshot().unwrap().in_flight, 0);
        assert_eq!(child.snapshot().unwrap().in_flight, 0);
    }
    drop(root.admit(&request()).unwrap());
}

#[test]
fn root_revocation_stops_every_prepaid_descendant() {
    let root = HostIoWorkBudget::new(limits(2, 4, 1));
    let tenant = root.partition(limits(2, 4, 1)).unwrap();
    let cell = tenant.partition(limits(2, 4, 1)).unwrap();
    root.revoke();
    drop(root);
    drop(tenant);
    assert!(cell.is_revoked());
    assert!(matches!(
        cell.admit(&request()),
        Err(HostIoBudgetError::Revoked)
    ));
    assert_eq!(cell.snapshot().unwrap().remaining_requests, 2);
    assert!(matches!(
        cell.partition(limits(0, 0, 0)),
        Err(HostIoBudgetError::Revoked)
    ));
}

#[test]
fn child_revocation_cannot_cancel_parent_or_sibling_work() {
    let root = HostIoWorkBudget::new(limits(3, 6, 2));
    let first = root.partition(limits(1, 2, 1)).unwrap();
    let second = root.partition(limits(1, 2, 1)).unwrap();
    first.revoke();
    assert!(!root.is_revoked());
    assert!(!second.is_revoked());
    drop(second.admit(&request()).unwrap());
    drop(root.admit(&request()).unwrap());
    assert_eq!(first.snapshot().unwrap().remaining_requests, 1);
}

#[test]
fn ancestor_poison_is_fail_closed_even_when_the_child_balance_is_healthy() {
    let root = HostIoWorkBudget::new(limits(1, 2, 1));
    let child = root.partition(limits(1, 2, 1)).unwrap();
    let shared = root.shared.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = shared.balance.lock().unwrap();
            panic!("ancestor accounting failed");
        })
        .join()
        .is_err()
    );
    assert!(matches!(
        child.admit(&request()),
        Err(HostIoBudgetError::Poisoned)
    ));
    assert_eq!(child.snapshot().unwrap().remaining_requests, 1);
}

#[test]
fn maximum_depth_is_bounded_even_for_empty_partitions_and_debug_output() {
    let mut current = HostIoWorkBudget::new(limits(0, 0, 1));
    for _ in 0..MAX_HOST_IO_BUDGET_DEPTH {
        current = current.partition(limits(0, 0, 1)).unwrap();
    }
    let before = current.snapshot().unwrap();
    assert!(matches!(
        current.partition(limits(0, 0, 1)),
        Err(HostIoBudgetError::HierarchyDepthExceeded)
    ));
    assert_eq!(current.snapshot().unwrap(), before);
    assert!(format!("{current:?}").len() < 256);
}

#[test]
fn already_admitted_child_observes_live_ancestor_revocation() {
    let root = HostIoWorkBudget::new(limits(1, 2, 1));
    let child = root.partition(limits(1, 2, 1)).unwrap();
    let admission = child.admit(&request()).unwrap();
    let control = BudgetControl {
        budget: child,
        supervisor: Arc::new(UnrestrictedHostIoControl),
        refused: AtomicBool::new(false),
    };
    assert!(control.checkpoint().is_ok());
    root.revoke();
    assert!(control.checkpoint().is_err());
    drop(admission);
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[derive(Debug)]
struct Successful;
impl HostIoProvider for Successful {
    fn name(&self) -> &str {
        "successful"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        Ok(HostIoResponse::FsWrite { bytes_written: 1 })
    }
}

#[test]
fn live_provider_dispatch_uses_prepaid_tenant_credits_without_double_charging() {
    let root = HostIoWorkBudget::new(limits(1, 2, 1));
    let child = root.partition(limits(1, 2, 1)).unwrap();
    let wrapped = BudgetedHostIo::new(Arc::new(Successful), child.clone());
    assert!(
        wrapped
            .perform(&request(), &[HostIoCapability::FsWrite])
            .is_ok()
    );
    assert_eq!(child.snapshot().unwrap().remaining_requests, 0);
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[test]
fn denial_and_drop_do_not_refund_delegated_allowance() {
    let root = HostIoWorkBudget::new(limits(2, 4, 1));
    let child = root.partition(limits(2, 4, 1)).unwrap();
    let wrapped = BudgetedHostIo::new(Arc::new(DenyAllHostIo), child);
    assert!(
        wrapped
            .perform(&request(), &[HostIoCapability::FsWrite])
            .is_err()
    );
    drop(wrapped);
    assert_eq!(root.snapshot().unwrap().remaining_requests, 0);
    assert_eq!(root.snapshot().unwrap().remaining_request_bytes, 0);
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}
