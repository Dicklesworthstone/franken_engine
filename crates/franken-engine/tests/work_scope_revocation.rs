#![forbid(unsafe_code)]
//! Public cross-crate work-scope signals retain live cancellation, not authority.

use frankenengine_core::execution_work_budget::ExecutionWorkPool;
use frankenengine_engine::checkpoint::{
    CancellationToken, CheckpointAction, CheckpointGuard, CheckpointReason, DensityConfig, LoopSite,
};

fn guard(token: CancellationToken) -> CheckpointGuard {
    CheckpointGuard::new(
        LoopSite::BytecodeDispatch,
        "live-work-scope",
        "revocation-regression",
        DensityConfig {
            max_iterations: 1024,
            max_total_iterations: 4096,
        },
        token,
    )
}

#[test]
fn work_revocation_reaches_existing_and_new_guards_without_caller_cancellation() {
    let pool = ExecutionWorkPool::new(128);
    let caller = CancellationToken::new();
    let token = caller.with_work_scope_revocation(pool.revocation_signal());
    let mut existing = guard(token.clone());
    assert_eq!(existing.check(), CheckpointAction::Continue);
    pool.revoke();
    assert!(
        !caller.is_cancelled(),
        "scope revocation is not caller cancellation"
    );
    assert!(token.is_cancelled());
    assert_eq!(existing.check(), CheckpointAction::Drain);
    assert_eq!(guard(token).check(), CheckpointAction::Drain);
    let events = existing.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, CheckpointReason::CancelPending);
    assert_eq!(events[0].action, CheckpointAction::Drain);
    assert_eq!(events[0].total_iterations, 0);
    assert_eq!(pool.remaining(), 128);
    assert_eq!(pool.committed(), 0);
}

#[test]
fn reset_and_explicit_checkpoints_cannot_hide_scope_revocation_at_budget_limit() {
    for explicit in [false, true] {
        let pool = ExecutionWorkPool::new(128);
        let caller = CancellationToken::new();
        let token = caller.with_work_scope_revocation(pool.revocation_signal());
        let mut existing = CheckpointGuard::new(
            LoopSite::ReplayStep,
            "live-work-scope",
            "revocation-before-exhaustion",
            DensityConfig {
                max_iterations: 1,
                max_total_iterations: 1,
            },
            token.clone(),
        );
        existing.tick();
        pool.revoke();
        caller.reset();
        token.reset();
        let action = if explicit {
            existing.explicit_checkpoint()
        } else {
            existing.check()
        };
        assert_eq!(action, CheckpointAction::Drain);
        let events = existing.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, CheckpointReason::CancelPending);
        assert_eq!(events[0].total_iterations, 1);
        // Observing cancellation once must not make an irreversible scope usable.
        assert_eq!(existing.explicit_checkpoint(), CheckpointAction::Drain);
        assert_eq!(guard(token).explicit_checkpoint(), CheckpointAction::Drain);
        assert!(!caller.is_cancelled());
        assert_eq!(pool.remaining(), 128);
    }
}

#[test]
fn caller_cancel_then_reset_still_reaches_an_existing_linked_guard() {
    let pool = ExecutionWorkPool::new(128);
    let caller = CancellationToken::new();
    let token = caller.with_work_scope_revocation(pool.revocation_signal());
    let mut existing = guard(token.clone());
    caller.cancel();
    caller.reset();
    assert!(!token.is_cancelled(), "reset opens a new caller session");
    assert_eq!(existing.check(), CheckpointAction::Drain);
    assert_eq!(existing.check(), CheckpointAction::Continue);
    assert_eq!(guard(token).check(), CheckpointAction::Continue);
    assert!(!pool.is_revoked());
    assert_eq!(pool.committed(), 0);
}

#[test]
fn either_attached_scope_revokes_the_composite_without_mutating_earlier_tokens() {
    for revoke_first in [true, false] {
        let first = ExecutionWorkPool::new(128);
        let second = ExecutionWorkPool::new(128);
        let caller = CancellationToken::new();
        let first_only = caller.with_work_scope_revocation(first.revocation_signal());
        let combined = first_only.with_work_scope_revocation(second.revocation_signal());
        if revoke_first {
            first.revoke();
        } else {
            second.revoke();
        }
        combined.reset();
        assert!(combined.is_cancelled());
        assert_eq!(guard(combined).check(), CheckpointAction::Drain);
        assert_eq!(first_only.is_cancelled(), revoke_first);
        assert!(!caller.is_cancelled());
        assert_eq!(first.remaining() + second.remaining(), 256);
    }
}

#[test]
fn observing_and_cancelling_one_session_neither_grants_work_nor_revokes_other_sessions() {
    let pool = ExecutionWorkPool::new(128);
    let caller = CancellationToken::new();
    let first = caller.with_work_scope_revocation(pool.revocation_signal());
    let independent = CancellationToken::new().with_work_scope_revocation(pool.revocation_signal());
    let mut independent_guard = guard(independent.clone());
    assert_eq!(pool.remaining(), 128, "observation must not reserve work");
    first.cancel();
    assert!(
        caller.is_cancelled(),
        "the original session must remain linked"
    );
    assert!(!pool.is_revoked());
    assert!(!independent.is_cancelled());
    assert_eq!(independent_guard.check(), CheckpointAction::Continue);
    first.reset();
    assert!(!caller.is_cancelled());
    let admission = pool.reserve(32).unwrap();
    assert_eq!(pool.remaining(), 96);
    drop(admission);
    drop(first);
    assert_eq!(
        pool.remaining(),
        96,
        "dropping observers never refunds work"
    );
    assert_eq!(pool.committed(), 32);
    pool.revoke();
    assert_eq!(independent_guard.check(), CheckpointAction::Drain);
}

#[test]
fn tenant_scope_revocation_leaves_parent_and_sibling_guards_and_balances_usable() {
    let root = ExecutionWorkPool::new(384);
    let tenant = root.partition(128).unwrap();
    let sibling = root.partition(128).unwrap();
    let tenant_token =
        CancellationToken::new().with_work_scope_revocation(tenant.revocation_signal());
    let sibling_token =
        CancellationToken::new().with_work_scope_revocation(sibling.revocation_signal());
    let root_token = CancellationToken::new().with_work_scope_revocation(root.revocation_signal());
    tenant.revoke();
    assert_eq!(guard(tenant_token).check(), CheckpointAction::Drain);
    assert_eq!(guard(sibling_token).check(), CheckpointAction::Continue);
    assert_eq!(guard(root_token).check(), CheckpointAction::Continue);
    assert!(!root.is_revoked() && !sibling.is_revoked());
    let root_work = root.reserve(32).unwrap();
    let sibling_work = sibling.reserve(32).unwrap();
    drop((root_work, sibling_work));
    assert_eq!(root.remaining(), 96);
    assert_eq!(sibling.remaining(), 96);
    assert_eq!(tenant.remaining(), 128);
}

#[test]
fn concurrent_ancestor_revocation_survives_owner_drop_and_local_reset() {
    let root = ExecutionWorkPool::new(256);
    let child = root.partition(128).unwrap();
    let caller = CancellationToken::new();
    let token = caller.with_work_scope_revocation(child.revocation_signal());
    let mut existing = guard(token.clone());
    drop(child);
    std::thread::spawn(move || {
        root.revoke();
    })
    .join()
    .unwrap();
    caller.reset();
    token.reset();
    assert!(!caller.is_cancelled());
    assert!(token.is_cancelled());
    assert_eq!(existing.explicit_checkpoint(), CheckpointAction::Drain);
    assert_eq!(guard(token).check(), CheckpointAction::Drain);
}

#[test]
fn attaching_live_scope_does_not_clear_an_already_cancelled_caller() {
    let pool = ExecutionWorkPool::new(128);
    let caller = CancellationToken::new();
    caller.cancel();
    let token = caller.with_work_scope_revocation(pool.revocation_signal());
    assert!(token.is_cancelled());
    assert_eq!(guard(token.clone()).check(), CheckpointAction::Drain);
    assert!(!pool.is_revoked());
    caller.reset();
    assert_eq!(guard(token.clone()).check(), CheckpointAction::Continue);
    pool.revoke();
    token.reset();
    assert_eq!(guard(token).explicit_checkpoint(), CheckpointAction::Drain);
    assert_eq!(pool.remaining(), 128);
}
