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
        u64::try_from(now).expect("timestamp").saturating_add(60_000),
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
    orchestrator.execute(&package()).expect_err("no native work credit");
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
    second.execute(&package()).expect_err("shared live pool is spent");
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
        Arc::new(InMemoryHostEffectJournal::replaying(recorded.host_effect_journal.clone())),
        authority(),
    );
    let replayed = replay.execute(&package()).expect("exact recorded replay");
    assert_eq!(replayed.host_effect_journal, recorded.host_effect_journal);
    assert_eq!(replayed.console_output[0].message, "pool-output");
    assert_eq!(pool.snapshot().unwrap().committed_operations, 1);
    assert_eq!(pool.snapshot().unwrap().in_flight, 0);
}
