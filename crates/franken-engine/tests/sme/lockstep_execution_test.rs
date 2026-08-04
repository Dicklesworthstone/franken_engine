use std::collections::BTreeSet;

use frankenengine_engine::secure_multi_execution_kernel::{
    HostcallInvocation, SecurityLevel, SmeHostcallKind,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::sme::lockstep_coordinator::{
    LockstepBarrierKind, LockstepInstruction, SmeLockstepCoordinator, SmeLockstepError,
};

fn instruction(id: &str) -> LockstepInstruction {
    LockstepInstruction::new(id, format!("opcode:{id}").as_bytes(), b"shared-input")
}

fn invocation(id: &str, kind: SmeHostcallKind, caller_level: SecurityLevel) -> HostcallInvocation {
    HostcallInvocation::new(id, kind, caller_level, id.as_bytes())
}

fn state_hashes(
    coordinator: &SmeLockstepCoordinator,
    level: SecurityLevel,
) -> Vec<frankenengine_engine::hash_tiers::ContentHash> {
    coordinator
        .runtime_state(level)
        .expect("runtime state")
        .instruction_hashes
        .clone()
}

#[test]
fn n2_confidential_hostcall_keeps_public_copy_suppressed() {
    let mut coordinator = SmeLockstepCoordinator::new(
        [SecurityLevel::Public, SecurityLevel::Confidential],
        SecurityEpoch::from_raw(11),
    )
    .expect("coordinator");
    coordinator.register_standard_hostcalls();

    let receipt = coordinator
        .execute_hostcall_at_barrier(
            instruction("write-confidential"),
            invocation(
                "fs-write",
                SmeHostcallKind::FsWrite,
                SecurityLevel::Confidential,
            ),
            b"confidential-bytes".to_vec(),
        )
        .expect("confidential write");

    assert_eq!(coordinator.runtime_count(), 2);
    assert!(coordinator.is_synchronized());
    assert_eq!(
        receipt.lockstep.synchronized_levels,
        BTreeSet::from([SecurityLevel::Public, SecurityLevel::Confidential])
    );
    assert_eq!(
        receipt.sme.delivered_to,
        BTreeSet::from([SecurityLevel::Confidential])
    );
    assert!(receipt.sme.suppressed_from.contains(&SecurityLevel::Public));
    assert_eq!(
        coordinator
            .visible_outputs(SecurityLevel::Public)
            .expect("public outputs")
            .len(),
        0
    );
    assert_eq!(
        coordinator
            .visible_outputs(SecurityLevel::Confidential)
            .expect("confidential outputs")
            .len(),
        1
    );
}

#[test]
fn n3_runtime_copies_process_identical_instruction_sequence() {
    let mut coordinator = SmeLockstepCoordinator::new(
        [
            SecurityLevel::Public,
            SecurityLevel::Internal,
            SecurityLevel::Secret,
        ],
        SecurityEpoch::from_raw(12),
    )
    .expect("coordinator");
    coordinator.register_standard_hostcalls();

    coordinator
        .execute_instruction(instruction("load-shared-input"))
        .expect("instruction");
    coordinator
        .synchronize_barrier("hostcall-boundary", LockstepBarrierKind::Synchronization)
        .expect("barrier");
    coordinator
        .execute_hostcall_at_barrier(
            instruction("read-clock"),
            invocation("clock", SmeHostcallKind::ClockRead, SecurityLevel::Public),
            b"now".to_vec(),
        )
        .expect("public clock");

    assert_eq!(coordinator.step_count(), 3);
    assert!(coordinator.is_synchronized());
    assert_eq!(
        state_hashes(&coordinator, SecurityLevel::Public),
        state_hashes(&coordinator, SecurityLevel::Internal)
    );
    assert_eq!(
        state_hashes(&coordinator, SecurityLevel::Internal),
        state_hashes(&coordinator, SecurityLevel::Secret)
    );
    for level in [
        SecurityLevel::Public,
        SecurityLevel::Internal,
        SecurityLevel::Secret,
    ] {
        assert_eq!(
            coordinator
                .visible_outputs(level)
                .expect("visible outputs")
                .len(),
            1
        );
    }
}

#[test]
fn n4_secret_memory_access_reaches_only_secret_copy() {
    let mut coordinator = SmeLockstepCoordinator::with_standard_levels(SecurityEpoch::from_raw(13));
    let access = invocation(
        "secret-memory-read",
        SmeHostcallKind::Custom("memory.read".to_string()),
        SecurityLevel::Secret,
    );

    let receipt = coordinator
        .deliver_labeled_output_at_barrier(
            instruction("memory-read-secret"),
            &access,
            SecurityLevel::Secret,
            b"secret-memory".to_vec(),
        )
        .expect("secret memory access");

    assert_eq!(coordinator.runtime_count(), 4);
    assert!(coordinator.is_synchronized());
    assert_eq!(
        receipt.sme.delivered_to,
        BTreeSet::from([SecurityLevel::Secret])
    );
    assert_eq!(
        receipt.sme.suppressed_from,
        BTreeSet::from([
            SecurityLevel::Public,
            SecurityLevel::Internal,
            SecurityLevel::Confidential,
        ])
    );
    for level in [
        SecurityLevel::Public,
        SecurityLevel::Internal,
        SecurityLevel::Confidential,
    ] {
        assert_eq!(
            coordinator
                .visible_outputs(level)
                .expect("visible outputs")
                .len(),
            0
        );
    }
}

#[test]
fn failed_hostcall_does_not_advance_lockstep_state() {
    let mut coordinator = SmeLockstepCoordinator::with_standard_levels(SecurityEpoch::from_raw(14));

    let err = coordinator
        .execute_hostcall_at_barrier(
            instruction("unknown-hostcall"),
            invocation(
                "custom",
                SmeHostcallKind::Custom("tenant.missing".to_string()),
                SecurityLevel::Secret,
            ),
            b"x".to_vec(),
        )
        .expect_err("unregistered hostcall should fail closed");

    assert!(matches!(err, SmeLockstepError::Kernel(_)));
    assert_eq!(coordinator.step_count(), 0);
    assert!(coordinator.is_synchronized());
}
