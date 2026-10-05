//! Live interpreter -> attempt authority -> journal -> shared work pool -> OS.
//! These tests launch real, policy-pinned executables, not simulated processes.
#![cfg(any(target_os = "linux", target_os = "freebsd"))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_core::execution_work_budget::ExecutionWorkPool;
use frankenengine_core::host_effect_budget::{HostEffectLimits, HostEffectWorkPool};
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, ProcessSpawnAttemptAuthority,
};
use frankenengine_extension_host::host_effect_journal::{
    HostEffectJournalEntry, InMemoryHostEffectJournal,
};
use frankenengine_extension_host::process_spawn::{
    NativeProcessSpawn, ProcessSpawnError, ProcessSpawnPolicy,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "franken-process-work-pool-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn native(scratch: &Scratch) -> Arc<NativeProcessSpawn> {
    let executable = ["/usr/bin/printf", "/bin/printf"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("native printf fixture");
    let mut policy = ProcessSpawnPolicy::jailed(&scratch.0).expect("jail");
    policy
        .authorize_alias("budget-printf", executable)
        .expect("pin executable digest");
    policy.limits.max_runtime_millis = 2000;
    Arc::new(NativeProcessSpawn::new(policy).expect("native provider"))
}

fn authority() -> ProcessSpawnAttemptAuthority {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis();
    ProcessSpawnAttemptAuthority::expiring_at_unix_ms(
        u64::try_from(now)
            .expect("timestamp")
            .saturating_add(60_000),
    )
}

fn package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "process-work-pool".into(),
        source: "const cp = require('child_process'); \
                 console.log(cp.execFileSync('budget-printf', ['pool-output'], \
                 { encoding: 'utf8' }));"
            .into(),
        source_file: None,
        module_root: None,
        capabilities: vec!["process_spawn".into()],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    }
}

#[test]
fn exhausted_process_budget_is_a_journaled_failure_on_the_real_js_execution_path() {
    let scratch = Scratch::new();
    let pool = HostEffectWorkPool::new(HostEffectLimits {
        operations: 0,
        max_in_flight: 1,
    });
    let work = ExecutionWorkPool::new(1);
    let provider = Arc::new(pool.bind_process_spawn(native(&scratch), &work));
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(
        provider,
        Arc::new(InMemoryHostEffectJournal::recording()),
        authority(),
    );
    orchestrator
        .execute(&package())
        .expect_err("no native work credit");
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::Denied { reason }),
            ..
        }] if reason == "HOST_EFFECT_BUDGET_EXHAUSTED"
    ));
    assert_eq!(pool.snapshot().unwrap().committed_operations, 0);
    assert_eq!(pool.snapshot().unwrap().in_flight, 0);
}

#[test]
fn fresh_attempt_authority_cannot_refill_work_and_replay_does_not_debit_it_again() {
    let scratch = Scratch::new();
    let pool = HostEffectWorkPool::new(HostEffectLimits {
        operations: 1,
        max_in_flight: 1,
    });
    let work = ExecutionWorkPool::new(1);
    let provider = Arc::new(pool.bind_process_spawn(native(&scratch), &work));
    let mut first = ExecutionOrchestrator::new(OrchestratorConfig::default());
    first.set_process_spawn(
        provider.clone(),
        Arc::new(InMemoryHostEffectJournal::recording()),
        authority(),
    );
    let recorded = first.execute(&package()).expect("real native printf");
    assert_eq!(recorded.console_output.len(), 1);
    assert_eq!(recorded.console_output[0].message, "pool-output");
    assert_eq!(recorded.host_effect_journal.len(), 1);
    assert_eq!(pool.snapshot().unwrap().committed_operations, 1);

    // A new orchestrator and new signed-attempt boundary cannot mint credits.
    let mut second = ExecutionOrchestrator::new(OrchestratorConfig::default());
    second.set_process_spawn(
        provider.clone(),
        Arc::new(InMemoryHostEffectJournal::recording()),
        authority(),
    );
    second
        .execute(&package())
        .expect_err("shared live pool is spent");
    assert!(matches!(
        second.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::Denied { reason }),
            ..
        }] if reason == "HOST_EFFECT_BUDGET_EXHAUSTED"
    ));

    // Revocation blocks live execution, not replay of an existing historical
    // effect. The wrapper still delegates canonical alias preparation while
    // the outer journal supplies the exact prior result without live dispatch.
    pool.revoke();
    work.revoke();
    let mut replay = ExecutionOrchestrator::new(OrchestratorConfig::default());
    replay.set_process_spawn(
        provider,
        Arc::new(InMemoryHostEffectJournal::replaying(
            recorded.host_effect_journal.clone(),
        )),
        authority(),
    );
    let replayed = replay.execute(&package()).expect("exact recorded replay");
    assert_eq!(replayed.host_effect_journal, recorded.host_effect_journal);
    assert_eq!(replayed.console_output[0].message, "pool-output");
    assert_eq!(pool.snapshot().unwrap().committed_operations, 1);
    assert_eq!(pool.snapshot().unwrap().in_flight, 0);
}

#[test]
fn supervised_drain_preserves_the_real_js_process_failure_journal() {
    use std::time::{Duration, Instant};

    let scratch = Scratch::new();
    let executable = ["/usr/bin/sleep", "/bin/sleep"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("native sleep fixture");
    let mut policy = ProcessSpawnPolicy::jailed(&scratch.0).expect("jail");
    policy
        .authorize_alias("budget-sleep", executable)
        .expect("pin native executable");
    policy.limits.max_runtime_millis = 10_000;
    let native = Arc::new(NativeProcessSpawn::new(policy).expect("native provider"));
    let pool = HostEffectWorkPool::new(HostEffectLimits {
        operations: 2,
        max_in_flight: 1,
    });
    let provider = Arc::new(pool.bind_process_spawn(native, &ExecutionWorkPool::new(1)));
    let worker = std::thread::spawn(move || {
        let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
        orchestrator.set_process_spawn(
            provider,
            Arc::new(InMemoryHostEffectJournal::recording()),
            authority(),
        );
        let mut package = package();
        package.source = "const cp = require('child_process'); \
                          cp.execFileSync('budget-sleep', ['5']);"
            .into();
        let failed = orchestrator.execute(&package).is_err();
        (failed, orchestrator.last_failed_host_effect_journal().to_vec())
    });

    let admission_deadline = Instant::now() + Duration::from_secs(10);
    while pool.snapshot().unwrap().in_flight == 0 {
        assert!(!worker.is_finished(), "guest never held native dispatch admission");
        assert!(Instant::now() < admission_deadline, "native dispatch did not start");
        std::thread::yield_now();
    }
    // This deliberately covers the admitted-launch race as well as an already
    // running process. Counting admission alone is NOT proof the OS child has
    // started. The native provider must account for either cancellation path.
    let drained = pool.revoke_and_drain(Duration::from_secs(5));
    // Dispatch drain does not commit/finalize the outer journal. Join the
    // orchestrator separately before inspecting its exact failed-effect prefix.
    let (failed, journal) = worker.join().expect("orchestrator thread");
    let snapshot = drained.expect("native process dispatch drained");
    assert!(failed, "revocation must not publish guest execution success");
    assert!(matches!(
        journal.as_slice(),
        [HostEffectJournalEntry::ProcessSpawn { outcome: Err(_), .. }]
    ));
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(snapshot.committed_operations, 1);
    assert_eq!(snapshot.remaining_operations, 1);
    assert_eq!(pool.snapshot().unwrap(), snapshot);
}

#[test]
fn tenant_exhaustion_and_close_preserve_sibling_execution_and_historical_replay() {
    use std::time::Duration;

    let scratch = Scratch::new();
    let root = HostEffectWorkPool::new(HostEffectLimits {
        operations: 3,
        max_in_flight: 2,
    });
    let first = root.partition(HostEffectLimits {
        operations: 1,
        max_in_flight: 1,
    }).unwrap();
    let sibling = root.partition(HostEffectLimits {
        operations: 2,
        max_in_flight: 1,
    }).unwrap();
    let work = ExecutionWorkPool::new(1);
    let native = native(&scratch);
    let first_provider = Arc::new(first.bind_process_spawn(native.clone(), &work));
    let sibling_provider = Arc::new(sibling.bind_process_spawn(native, &work));
    assert_eq!(root.snapshot().unwrap().remaining_operations, 0);

    let mut recording = ExecutionOrchestrator::new(OrchestratorConfig::default());
    recording.set_process_spawn(
        first_provider.clone(),
        Arc::new(InMemoryHostEffectJournal::recording()),
        authority(),
    );
    let recorded = recording.execute(&package()).expect("prepaid native execution");
    assert_eq!(recorded.console_output[0].message, "pool-output");
    assert_eq!(recorded.host_effect_journal.len(), 1);

    let mut retry = ExecutionOrchestrator::new(OrchestratorConfig::default());
    retry.set_process_spawn(
        first_provider.clone(),
        Arc::new(InMemoryHostEffectJournal::recording()),
        authority(),
    );
    retry.execute(&package()).expect_err("fresh authority cannot steal sibling credits");
    assert!(matches!(
        retry.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::Denied { reason }), ..
        }] if reason == "HOST_EFFECT_BUDGET_EXHAUSTED"
    ));
    first.revoke_and_drain(Duration::ZERO).unwrap();
    assert!(!root.is_revoked() && !sibling.is_revoked());
    assert_eq!(sibling.snapshot().unwrap().remaining_operations, 2);

    for remaining in [1, 0] {
        let mut peer = ExecutionOrchestrator::new(OrchestratorConfig::default());
        peer.set_process_spawn(
            sibling_provider.clone(),
            Arc::new(InMemoryHostEffectJournal::recording()),
            authority(),
        );
        let result = peer.execute(&package()).expect("reserved sibling execution");
        assert_eq!(result.console_output[0].message, "pool-output");
        assert_eq!(sibling.snapshot().unwrap().remaining_operations, remaining);
    }
    let root_snapshot = root.revoke_and_drain(Duration::ZERO).unwrap();
    let first_snapshot = first.snapshot().unwrap();
    let sibling_snapshot = sibling.snapshot().unwrap();
    let mut replay = ExecutionOrchestrator::new(OrchestratorConfig::default());
    replay.set_process_spawn(
        first_provider,
        Arc::new(InMemoryHostEffectJournal::replaying(recorded.host_effect_journal.clone())),
        authority(),
    );
    let replayed = replay.execute(&package()).expect("replay without live admission");
    assert_eq!(replayed.console_output[0].message, "pool-output");
    assert_eq!(replayed.host_effect_journal, recorded.host_effect_journal);
    assert_eq!(root.snapshot().unwrap(), root_snapshot);
    assert_eq!(first.snapshot().unwrap(), first_snapshot);
    assert_eq!(sibling.snapshot().unwrap(), sibling_snapshot);
}

#[test]
fn real_filesystem_and_process_work_spend_one_tenant_quota() {
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoError, HostIoProvider, HostIoRequest, SandboxedHostIo,
    };
    use frankenengine_extension_host::process_spawn::{
        ProcessLaunch, ProcessSpawnCapability, ProcessSpawnProvider, ProcessSpawnRequest,
        ProcessSpawnResponse, ProcessStdio,
    };

    let scratch = Scratch::new();
    let root = HostEffectWorkPool::new(HostEffectLimits { operations: 3, max_in_flight: 1 });
    let tenant = root.partition(HostEffectLimits { operations: 2, max_in_flight: 1 }).unwrap();
    let sibling = root.partition(HostEffectLimits { operations: 1, max_in_flight: 1 }).unwrap();
    let work = ExecutionWorkPool::new(1);
    let sandbox = Arc::new(SandboxedHostIo::with_root(&scratch.0).unwrap());
    let io = tenant.bind_host_io(sandbox.clone(), &work);
    let process = tenant.bind_process_spawn(native(&scratch), &work);
    let write = |path: &str, bytes: &[u8]| HostIoRequest::FsWrite {
        path: path.into(),
        data: bytes.to_vec(),
    };
    io.perform(&write("first.txt", b"original"), &[HostIoCapability::FsWrite]).unwrap();
    let request = ProcessSpawnRequest::Run {
        launch: ProcessLaunch {
            executable: "budget-printf".into(),
            argv: vec!["native-tenant".into()],
            env: BTreeMap::new(),
            cwd: None,
            shell: false,
            stdio: ProcessStdio::default(),
        },
        stdin: Vec::new(),
        timeout_millis: Some(2000),
    };
    let canonical = process.prepare_request(&request).unwrap();
    assert_eq!(tenant.snapshot().unwrap().remaining_operations, 1);
    let response = process.perform(&canonical, &[ProcessSpawnCapability::Spawn]).unwrap();
    let ProcessSpawnResponse::Run { exit, stdout, stderr } = response else {
        panic!("native process result");
    };
    assert!(exit.success);
    assert_eq!(stdout, b"native-tenant");
    assert!(stderr.is_empty());
    assert!(matches!(
        io.perform(&write("first.txt", b"forbidden overwrite"), &[HostIoCapability::FsWrite]),
        Err(HostIoError::Denied { reason }) if reason == "HOST_EFFECT_BUDGET_EXHAUSTED"
    ));
    assert_eq!(std::fs::read(scratch.0.join("first.txt")).unwrap(), b"original");
    sibling.bind_host_io(sandbox, &work)
        .perform(&write("sibling.txt", b"reserved"), &[HostIoCapability::FsWrite]).unwrap();
    assert_eq!(std::fs::read(scratch.0.join("sibling.txt")).unwrap(), b"reserved");
    assert_eq!(tenant.snapshot().unwrap().committed_operations, 2);
    assert_eq!(sibling.snapshot().unwrap().committed_operations, 1);
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[test]
fn native_descendant_process_and_sibling_io_share_concurrency_and_separate_close() {
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoError, HostIoProvider, HostIoRequest, SandboxedHostIo,
    };
    use std::time::{Duration, Instant};

    let scratch = Scratch::new();
    let executable = ["/usr/bin/sleep", "/bin/sleep"]
        .into_iter().map(PathBuf::from).find(|path| path.is_file()).expect("native sleep");
    let mut policy = ProcessSpawnPolicy::jailed(&scratch.0).unwrap();
    policy.authorize_alias("tenant-sleep", executable).unwrap();
    policy.limits.max_runtime_millis = 10_000;
    let root = HostEffectWorkPool::new(HostEffectLimits { operations: 2, max_in_flight: 1 });
    let child = root.partition(HostEffectLimits { operations: 1, max_in_flight: 1 }).unwrap();
    let sibling = root.partition(HostEffectLimits { operations: 1, max_in_flight: 1 }).unwrap();
    let work = ExecutionWorkPool::new(1);
    let provider = Arc::new(child.bind_process_spawn(Arc::new(NativeProcessSpawn::new(policy).unwrap()), &work));
    let io = sibling.bind_host_io(Arc::new(SandboxedHostIo::with_root(&scratch.0).unwrap()), &work);
    let worker = std::thread::spawn(move || {
        let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
        orchestrator.set_process_spawn(
            provider,
            Arc::new(InMemoryHostEffectJournal::recording()),
            authority(),
        );
        let mut package = package();
        package.source = "require('child_process').execFileSync('tenant-sleep', ['5']);".into();
        let failed = orchestrator.execute(&package).is_err();
        (failed, orchestrator.last_failed_host_effect_journal().to_vec())
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while root.snapshot().unwrap().in_flight == 0 {
        assert!(!worker.is_finished(), "native dispatch was never admitted");
        assert!(Instant::now() < deadline, "native admission timed out");
        std::thread::yield_now();
    }
    // Admission is the boundary under test, not a claim that the OS child has
    // already started. Revocation must cover both sides of that launch race.
    let write = HostIoRequest::FsWrite { path: "peer.txt".into(), data: b"peer survived".to_vec() };
    let refused = io.perform(&write, &[HostIoCapability::FsWrite]);
    let untouched = !scratch.0.join("peer.txt").exists();
    let remaining = sibling.snapshot().unwrap().remaining_operations;
    let drained = child.revoke_and_drain(Duration::from_secs(5));
    let (failed, journal) = worker.join().expect("native execution worker");
    assert!(matches!(refused, Err(HostIoError::Denied { reason }) if reason == "HOST_EFFECT_CONCURRENCY_LIMIT"));
    assert!(untouched);
    assert_eq!(remaining, 1);
    assert_eq!(drained.unwrap().in_flight, 0);
    assert!(failed);
    assert!(matches!(journal.as_slice(), [HostEffectJournalEntry::ProcessSpawn { outcome: Err(_), .. }]));
    assert!(!root.is_revoked() && !sibling.is_revoked());
    io.perform(&write, &[HostIoCapability::FsWrite]).unwrap();
    assert_eq!(std::fs::read(scratch.0.join("peer.txt")).unwrap(), b"peer survived");
    assert_eq!(root.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
}

#[test]
fn ancestor_close_does_not_disable_native_descendant_child_cleanup() {
    use frankenengine_extension_host::process_spawn::{
        ProcessLaunch, ProcessSpawnCapability, ProcessSpawnProvider, ProcessSpawnRequest,
        ProcessSpawnResponse, ProcessStdio,
    };
    use std::time::Duration;

    let scratch = Scratch::new();
    let mut policy = ProcessSpawnPolicy::jailed(&scratch.0).unwrap();
    let executable = policy.authorize_executable("/bin/cat").unwrap();
    policy.limits.max_runtime_millis = 2000;
    let root = HostEffectWorkPool::new(HostEffectLimits { operations: 2, max_in_flight: 1 });
    let tenant = root.partition(HostEffectLimits { operations: 2, max_in_flight: 1 }).unwrap();
    let cell = tenant.partition(HostEffectLimits { operations: 2, max_in_flight: 1 }).unwrap();
    let provider = cell.bind_process_spawn(
        Arc::new(NativeProcessSpawn::new(policy).unwrap()),
        &ExecutionWorkPool::new(1),
    );
    let response = provider.perform(&ProcessSpawnRequest::Spawn {
        launch: ProcessLaunch {
            executable,
            argv: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            shell: false,
            stdio: ProcessStdio::default(),
        },
    }, &[ProcessSpawnCapability::Spawn]).unwrap();
    let ProcessSpawnResponse::Spawned { handle } = response else {
        panic!("native child handle");
    };
    assert_eq!(root.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
    assert!(cell.is_revoked());
    let before_cleanup = cell.snapshot().unwrap();
    assert_eq!(provider.cleanup_handle(&handle), Ok(ProcessSpawnResponse::Cleaned { was_present: true }));
    assert_eq!(provider.cleanup_handle(&handle), Ok(ProcessSpawnResponse::Cleaned { was_present: false }));
    assert_eq!(cell.snapshot().unwrap(), before_cleanup);
    assert_eq!(before_cleanup.remaining_operations, 1);
}
