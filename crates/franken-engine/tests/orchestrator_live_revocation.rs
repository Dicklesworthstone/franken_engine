#![forbid(unsafe_code)]
//! Live revocation through the public orchestrator, including real host effects.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use frankenengine_engine::baseline_interpreter::{InterpreterError, LaneChoice};
use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::capability_witness::{
    CapabilityWitness, CapabilityWitnessTrustRoot, ConfidenceInterval, LifecycleState,
    PromotionTheoremInput, ProofKind, ProofObligation, SourceCapabilitySet, WitnessBuilder,
};
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::execution_cell::{CellError, CellExecutionError};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExecutionWorkPool, ExtensionPackage, OrchestratorConfig,
    OrchestratorError, WorkBudgetError,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::revocation_chain::{
    Revocation, RevocationChain, RevocationReason, RevocationTargetType, revocation_schema_id,
};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, sign_preimage,
};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoExceptionProvenance, HostIoOutcome, HostIoProvider,
    HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn package(source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "live-orchestrator-work-scope".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: Vec::new(),
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn filesystem_package(source: &str) -> ExtensionPackage {
    let mut work = package(source);
    work.capabilities = ["vm_dispatch", "heap_allocate", "fs_read", "fs_write"]
        .into_iter()
        .map(str::to_string)
        .collect();
    work
}

fn orchestrator(pool: &ExecutionWorkPool, lane: Option<LaneChoice>) -> ExecutionOrchestrator {
    let mut runtime = RuntimeConfig::default();
    runtime.execution.deterministic_budget = 4096;
    runtime.execution.throughput_budget = 4096;
    ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: lane,
            work_pool: Some(pool.clone()),
            ..OrchestratorConfig::default()
        },
        runtime,
    )
    .expect("valid live-scope runtime configuration")
}

fn assert_closed(error: &OrchestratorError) {
    assert!(
        error
            .post_cell_failure()
            .expect("native refusal must retain execution-cell cleanup")
            .cleanup
            .close_succeeded()
    );
}

fn assert_live_refusal(error: &OrchestratorError) {
    assert_closed(error);
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Interpreter(InterpreterError::Cancelled)
                | OrchestratorError::Cell(CellError::ExecutionBoundary {
                    error: CellExecutionError::Cancelled,
                    ..
                })
        ),
        "expected typed live cancellation, not exhaustion or another error: {error:?}"
    );
}

#[derive(Debug)]
struct RevokeAfterWrite {
    inner: SandboxedHostIo,
    scope: ExecutionWorkPool,
    writes: Arc<AtomicUsize>,
}

impl HostIoProvider for RevokeAfterWrite {
    fn name(&self) -> &str {
        "revoke-after-real-write"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        // Delegate authorization and actual I/O; no fabricated successful effect.
        let outcome = self.inner.perform(request, granted);
        if matches!(request, HostIoRequest::FsWrite { .. }) && outcome.is_ok() {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.scope.revoke();
        }
        outcome
    }
}

#[test]
fn in_flight_revocation_blocks_further_effects_and_success_in_every_profile() {
    let sources = [
        "require('fs').writeFileSync('first.txt', 'committed'); \
         require('fs').writeFileSync('second.txt', 'forbidden');",
        "try { require('fs').writeFileSync('first.txt', 'committed'); } \
         catch (e) {} require('fs').writeFileSync('second.txt', 'forbidden');",
        "require('fs').writeFileSync('first.txt', 'committed'); while (true) {}",
        "require('fs').writeFileSync('first.txt', 'committed'); 42;",
    ];
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        for source in sources {
            let directory = tempfile::tempdir().unwrap();
            let pool = ExecutionWorkPool::new(8192);
            let writes = Arc::new(AtomicUsize::new(0));
            let recorder = Arc::new(InMemoryHostIoTranscript::recording());
            let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
            let provider = Arc::new(RevokeAfterWrite {
                inner: SandboxedHostIo::with_root(directory.path()).unwrap(),
                scope: pool.clone(),
                writes: Arc::clone(&writes),
            });
            let mut runtime = orchestrator(&pool, lane);
            runtime.set_host_io(provider, Some(recorder_dyn));
            let error = runtime.execute(&filesystem_package(source)).unwrap_err();
            assert_live_refusal(&error);
            assert_eq!(
                std::fs::read(directory.path().join("first.txt")).unwrap(),
                b"committed"
            );
            assert!(!directory.path().join("second.txt").exists());
            assert_eq!(writes.load(Ordering::Relaxed), 1);
            assert_eq!(runtime.execution_count(), 0);
            assert_eq!(pool.remaining(), 4096);
            assert_eq!(pool.committed(), 4096);
            let history = recorder.entries();
            assert_eq!(history.len(), 1, "retain the irreversible effect prefix");
            assert!(matches!(
                &history[0].0,
                HostIoRequest::FsWrite { path, .. } if path == "first.txt"
            ));
            assert!(history[0].1.is_ok());
            assert_eq!(runtime.last_failed_host_effect_journal().len(), 1);
            assert_eq!(runtime.last_failed_host_effect_journal_records().len(), 1);
            assert!(runtime.last_failed_trace_id().is_some());

            let retry = runtime
                .execute(&filesystem_package(
                    "require('fs').writeFileSync('second.txt', 'forbidden');",
                ))
                .unwrap_err();
            assert!(matches!(
                retry.primary_error(),
                OrchestratorError::WorkBudget(WorkBudgetError::Revoked)
            ));
            assert_closed(&retry);
            assert_eq!(
                recorder.entries(),
                history,
                "denied retry preserves history"
            );
            assert_eq!(pool.remaining(), 4096);
            assert_eq!(pool.committed(), 4096);
            assert_eq!(writes.load(Ordering::Relaxed), 1);
            assert!(!directory.path().join("second.txt").exists());
            assert_eq!(runtime.execution_count(), 0);
        }
    }
}

#[test]
fn revoking_running_tenant_preserves_parent_and_sibling_progress() {
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let root = ExecutionWorkPool::new(16_384);
        let tenant = root.partition(8192).unwrap();
        let sibling = root.partition(4096).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let mut running = orchestrator(&tenant, lane);
        let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
        running.set_host_io(
            Arc::new(RevokeAfterWrite {
                inner: SandboxedHostIo::with_root(directory.path()).unwrap(),
                scope: tenant.clone(),
                writes: Arc::clone(&writes),
            }),
            Some(recorder),
        );
        let error = running
            .execute(&filesystem_package(
                "require('fs').writeFileSync('first.txt', 'committed'); while (true) {}",
            ))
            .unwrap_err();
        assert_live_refusal(&error);
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        assert_eq!(
            std::fs::read(directory.path().join("first.txt")).unwrap(),
            b"committed"
        );
        assert!(tenant.is_revoked());
        assert!(!root.is_revoked() && !sibling.is_revoked());
        orchestrator(&root, lane).execute(&package("7;")).unwrap();
        orchestrator(&sibling, lane)
            .execute(&package("7;"))
            .unwrap();
        assert_eq!(root.remaining(), 0);
        assert_eq!(sibling.remaining(), 0);
        assert_eq!(tenant.remaining(), 4096);
        assert_eq!(tenant.committed(), 4096);
    }
}

#[derive(Debug)]
struct PausedWrite {
    inner: SandboxedHostIo,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    writes: Arc<AtomicUsize>,
}

impl HostIoProvider for PausedWrite {
    fn name(&self) -> &str {
        "paused-real-write"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        let outcome = self.inner.perform(request, granted);
        if matches!(request, HostIoRequest::FsWrite { .. })
            && outcome.is_ok()
            && self.writes.fetch_add(1, Ordering::Relaxed) == 0
        {
            self.entered
                .send(())
                .expect("controller is waiting for real host entry");
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .expect("controller must release the synchronous host callback");
        }
        outcome
    }
}

#[test]
fn concurrent_ancestor_revocation_during_host_call_stops_the_next_effect() {
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let root = ExecutionWorkPool::new(8192);
        let tenant = root.partition(8192).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let controller = std::thread::spawn(move || {
            entered_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("native execution must enter its first real host call");
            root.revoke();
            release_tx.send(()).unwrap();
            // The tenant's live signal must retain the now-dropped ancestor.
        });
        let provider = Arc::new(PausedWrite {
            inner: SandboxedHostIo::with_root(directory.path()).unwrap(),
            entered: entered_tx,
            release: Mutex::new(release_rx),
            writes: Arc::clone(&writes),
        });
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
        let mut runtime = orchestrator(&tenant, lane);
        runtime.set_host_io(provider, Some(recorder_dyn));
        let result = runtime.execute(&filesystem_package(
            "require('fs').writeFileSync('first.txt', 'committed'); \
             require('fs').writeFileSync('second.txt', 'forbidden');",
        ));
        controller.join().expect("concurrent revoker must finish");
        assert_live_refusal(&result.unwrap_err());
        // Cooperative revocation does not undo the synchronous effect in progress.
        assert_eq!(
            std::fs::read(directory.path().join("first.txt")).unwrap(),
            b"committed"
        );
        assert!(!directory.path().join("second.txt").exists());
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        assert_eq!(runtime.execution_count(), 0);
        assert_eq!(tenant.remaining(), 4096);
        assert_eq!(tenant.committed(), 4096);
        assert!(tenant.is_revoked());
        let history = recorder.entries();
        assert_eq!(history.len(), 1);
        assert!(history[0].1.is_ok());
        assert_eq!(runtime.last_failed_host_effect_journal().len(), 1);
        assert_eq!(runtime.last_failed_host_effect_journal_records().len(), 1);
    }
}

/// The controller knows only the work pool, never the provider's network kill
/// switch. A held-open real HTTP peer makes missing control propagation red.
#[test]
fn work_scope_revocation_interrupts_inflight_network_and_preserves_shared_provider() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;

    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let root = ExecutionWorkPool::new(16_384);
        let tenant = root.partition(8192).unwrap();
        let sibling = root.partition(4096).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let provider = Arc::new(
            SandboxedHostIo::with_root(directory.path())
                .unwrap()
                .with_network_timeout(Duration::from_secs(15))
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (entered, wait_entered) = mpsc::sync_channel(1);
        let (release, wait_release) = mpsc::sync_channel(1);
        let server = std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < end =>
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    other => panic!("expected native network dispatch: {other:?}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut byte = [0; 1];
            while !bytes.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
                assert!(bytes.len() <= 8192);
            }
            entered.send(()).unwrap();
            // Only the controller's observation of native completion releases
            // this socket. Peer EOF and the fifteen-second limit cannot explain
            // a successful cancellation test.
            let _ = wait_release.recv_timeout(Duration::from_secs(10));
            bytes
        });
        let mut work = filesystem_package(&format!(
            "require('http').get('http://{address}/once', () => {{ require('fs').writeFileSync('forbidden.txt', 'no'); }});"
        ));
        work.capabilities.push("network_egress".into());
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
        let mut runtime = orchestrator(&tenant, lane);
        runtime.set_host_io(provider.clone(), Some(recorder_dyn));
        let (done, wait_done) = mpsc::sync_channel(1);
        // Keep the interpreter on this test thread; the controller revokes the
        // tenant after receiving the actual request and never touches provider.
        let revoked_tenant = tenant.clone();
        let controller = std::thread::spawn(move || {
            let entered = wait_entered.recv_timeout(Duration::from_secs(10));
            revoked_tenant.revoke();
            let completed = wait_done.recv_timeout(Duration::from_secs(3));
            let _ = release.send(());
            assert!(entered.is_ok(), "interpreter never sent the real request");
            assert!(
                completed.is_ok(),
                "host network call ignored work-scope revocation"
            );
        });
        let result = runtime.execute(&work);
        let _ = done.send(());
        controller.join().unwrap();
        let observed = server.join().unwrap();
        assert!(observed.starts_with(b"GET /once HTTP/1.1\r\n"));
        let error = result.unwrap_err();
        assert_live_refusal(&error);
        assert_eq!(runtime.execution_count(), 0);
        assert!(!directory.path().join("forbidden.txt").exists());
        assert_eq!(tenant.committed(), 4096);
        assert_eq!(recorder.entries().len(), 1);
        assert!(matches!(
            &recorder.entries()[0].1,
            Err(HostIoError::Denied { .. })
        ));
        assert_eq!(runtime.last_failed_host_effect_journal().len(), 1);
        assert!(!provider.network_revocation().is_revoked());
        assert!(!root.is_revoked() && !sibling.is_revoked());

        // Positive sibling execution through the same provider, not merely a
        // boolean signal assertion: its HTTP response must reach native JS.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let end = Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < end =>
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    other => panic!("sibling network dispatch failed: {other:?}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });
        let mut sibling_work = filesystem_package(&format!(
            "require('http').get('http://{address}/sibling'); 42;"
        ));
        sibling_work.capabilities.push("network_egress".into());
        let mut sibling_runtime = orchestrator(&sibling, lane);
        let sibling_recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let recorder_dyn: Arc<dyn HostIoRecorder> = sibling_recorder.clone();
        sibling_runtime.set_host_io(provider, Some(recorder_dyn));
        let result = sibling_runtime.execute(&sibling_work);
        server.join().unwrap();
        assert!(result.is_ok(), "sibling must retain authority: {result:?}");
        let entries = sibling_recorder.entries();
        assert_eq!(entries.len(), 1);
        assert!(
            matches!(&entries[0].1, Ok(frankenengine_extension_host::host_io::HostIoResponse::NetworkRequest { response }) if response.ends_with(b"\r\n\r\nok"))
        );
    }
}

const LIVE_WITNESS_ZONE: &str = "orchestrator-live-witness";

fn witness_filesystem_package(source: &str) -> ExtensionPackage {
    let mut work = filesystem_package(source);
    // The native fs facade itself is an engine builtin.
    work.capabilities.push("builtin".to_string());
    work
}

/// A signed fixture for this test's explicit filesystem capability model.
/// The theorem model and confidence counts are synthetic test inputs, not
/// observations or a claim of production shadow validation.
fn active_live_witness(source: &str) -> (CapabilityWitness, CapabilityWitnessTrustRoot) {
    let key = SigningKey::from_bytes([0x71; 32]).unwrap();
    let schema = SchemaId::from_definition(b"live-witness-test-v1");
    let extension_id = derive_id(
        ObjectDomain::Attestation,
        LIVE_WITNESS_ZONE,
        &schema,
        b"host-effects",
    )
    .unwrap();
    let policy_id = derive_id(
        ObjectDomain::Attestation,
        LIVE_WITNESS_ZONE,
        &schema,
        b"filesystem-policy",
    )
    .unwrap();
    let mut builder = WitnessBuilder::new(
        extension_id,
        policy_id,
        SecurityEpoch::from_raw(1),
        1_700_000_000_000_000,
        key.clone(),
    )
    .confidence(ConfidenceInterval::from_trials(200, 195))
    .transcript_hash(ContentHash::compute(b"synthetic-live-revocation-test-evidence"))
    .meta("fixture_evidence_kind", "synthetic-test-inputs")
    .meta(
        "trusted_synthesizer_verification_key",
        key.verification_key().to_hex(),
    )
    .meta("source_sha256", ContentHash::compute(source.as_bytes()).to_hex())
    .meta("parse_goal", "script");
    for tag in ["vm_dispatch", "heap_allocate", "fs_read", "fs_write", "builtin"] {
        let capability = Capability::new(tag);
        let proof_artifact_id = derive_id(
            ObjectDomain::EvidenceRecord,
            LIVE_WITNESS_ZONE,
            &schema,
            tag.as_bytes(),
        )
        .unwrap();
        builder = builder.require(capability.clone()).proof(ProofObligation {
            capability,
            kind: ProofKind::StaticAnalysis,
            proof_artifact_id,
            justification: "explicit filesystem fixture capability model".to_string(),
            artifact_hash: ContentHash::compute(tag.as_bytes()),
        });
    }
    let mut witness = builder.build().unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "filesystem-fixture".to_string(),
            capabilities: witness.required_capabilities.clone(),
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness
        .evaluate_promotion_theorems_signed_by(&input, &key)
        .unwrap();
    assert!(report.all_passed);
    witness.apply_promotion_theorem_report(&report).unwrap();
    witness.transition_to(LifecycleState::Validated).unwrap();
    witness.add_promotion_signature(&key).unwrap();
    let root = CapabilityWitnessTrustRoot::single_authority(key.verification_key());
    witness
        .transition_to_with_trust_root(LifecycleState::Promoted, &root)
        .unwrap();
    witness
        .transition_to_with_trust_root(LifecycleState::Active, &root)
        .unwrap();
    (witness, root)
}

fn live_revocation_authority() -> (Arc<Mutex<RevocationChain>>, SigningKey, SigningKey) {
    let issuer = SigningKey::from_bytes([0x72; 32]).unwrap();
    let head = SigningKey::from_bytes([0x73; 32]).unwrap();
    let mut chain = RevocationChain::new(LIVE_WITNESS_ZONE)
        .with_authorized_revocation_key(issuer.verification_key())
        .with_authorized_head_key(head.verification_key());
    chain.set_current_epoch(SecurityEpoch::from_raw(1)).unwrap();
    (Arc::new(Mutex::new(chain)), issuer, head)
}

fn signed_live_revocation(
    target_id: &EngineObjectId,
    target_type: RevocationTargetType,
    reason: RevocationReason,
    issuer: &SigningKey,
) -> Revocation {
    let revocation_id = derive_id(
        ObjectDomain::Revocation,
        LIVE_WITNESS_ZONE,
        &revocation_schema_id(),
        target_id.as_bytes(),
    )
    .unwrap();
    let mut revocation = Revocation {
        revocation_id,
        target_type,
        target_id: target_id.clone(),
        reason,
        issued_by: PrincipalId::from_verification_key(&issuer.verification_key()),
        issued_at: DeterministicTimestamp(1000),
        zone: LIVE_WITNESS_ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    revocation.signature = sign_preimage(issuer, &revocation.preimage_bytes()).unwrap();
    revocation
}

#[derive(Debug)]
struct AppendWitnessRevocationAfterWrite {
    inner: SandboxedHostIo,
    chain: Arc<Mutex<RevocationChain>>,
    revocation: Revocation,
    head_key: SigningKey,
    writes: Arc<AtomicUsize>,
    accepted: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
}

impl HostIoProvider for AppendWitnessRevocationAfterWrite {
    fn name(&self) -> &str {
        "signed-witness-revocation-after-real-write"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        let outcome = self.inner.perform(request, granted);
        if matches!(request, HostIoRequest::FsWrite { .. })
            && outcome.is_ok()
            && self.writes.fetch_add(1, Ordering::Relaxed) == 0
        {
            // The callback commits through the real authenticated chain. It
            // has no cancellation token or work-pool revocation handle.
            let appended = self.chain.lock().unwrap().append(
                self.revocation.clone(),
                &self.head_key,
                "native-host-callback",
            );
            if appended.is_ok() {
                self.accepted.fetch_add(1, Ordering::Relaxed);
            } else {
                self.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
        outcome
    }
}

#[test]
fn signed_witness_revocation_during_host_effect_stops_execution_and_reinstallation() {
    let source = "require('fs').writeFileSync('first.txt', 'committed'); \
                  require('fs').writeFileSync('second.txt', 'forbidden');";
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        for (extension_target, reason) in [
            (false, RevocationReason::Compromised),
            (false, RevocationReason::Superseded),
            (true, RevocationReason::PolicyViolation),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let pool = ExecutionWorkPool::new(8192);
            let (witness, root) = active_live_witness(source);
            let (chain, issuer, head_key) = live_revocation_authority();
            let (target, target_type) = if extension_target {
                (&witness.extension_id, RevocationTargetType::Extension)
            } else {
                (&witness.witness_id, RevocationTargetType::Attestation)
            };
            let revocation = signed_live_revocation(target, target_type, reason, &issuer);
            let writes = Arc::new(AtomicUsize::new(0));
            let accepted = Arc::new(AtomicUsize::new(0));
            let rejected = Arc::new(AtomicUsize::new(0));
            let recorder = Arc::new(InMemoryHostIoTranscript::recording());
            let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
            let caller = CancellationToken::new();
            let mut runtime = orchestrator(&pool, lane);
            runtime.set_capability_witness_trust_root(root);
            runtime.set_capability_witness(witness.clone());
            runtime
                .bind_capability_witness_revocation(&mut chain.lock().unwrap())
                .unwrap();
            runtime.set_cancellation_token(caller.clone());
            runtime.set_host_io(
                Arc::new(AppendWitnessRevocationAfterWrite {
                    inner: SandboxedHostIo::with_root(directory.path()).unwrap(),
                    chain: Arc::clone(&chain),
                    revocation,
                    head_key,
                    writes: Arc::clone(&writes),
                    accepted: Arc::clone(&accepted),
                    rejected: Arc::clone(&rejected),
                }),
                Some(recorder_dyn),
            );

            let work = witness_filesystem_package(source);
            let error = runtime.execute(&work).unwrap_err();
            assert_live_refusal(&error);
            assert_eq!(accepted.load(Ordering::Relaxed), 1);
            assert_eq!(rejected.load(Ordering::Relaxed), 0);
            assert_eq!(writes.load(Ordering::Relaxed), 1);
            assert_eq!(
                std::fs::read(directory.path().join("first.txt")).unwrap(),
                b"committed"
            );
            assert!(!directory.path().join("second.txt").exists());
            assert!(!pool.is_revoked(), "witness authority does not revoke a tenant pool");
            assert!(!caller.is_cancelled(), "witness authority does not cancel its caller");
            assert_eq!(runtime.execution_count(), 0);
            let history = recorder.entries();
            assert_eq!(history.len(), 1);
            assert_eq!(runtime.last_failed_host_effect_journal().len(), 1);

            // Old authenticated artifacts and mutable supervisor tokens cannot
            // restore the now-invalidated source-owned authority.
            runtime.set_capability_witness(witness);
            caller.reset();
            let retry = runtime.execute(&work).unwrap_err();
            assert!(matches!(
                retry.primary_error(),
                OrchestratorError::CapabilityWitnessRejected { detail }
                    if detail.contains("revocation authority is invalidated")
            ));
            assert_eq!(writes.load(Ordering::Relaxed), 1);
            assert_eq!(recorder.entries(), history);
            assert!(!directory.path().join("second.txt").exists());
        }
    }
}

#[test]
fn forged_or_unrelated_revocations_preserve_real_authorized_execution() {
    let source = "require('fs').writeFileSync('first.txt', 'committed'); \
                  require('fs').writeFileSync('second.txt', 'authorized');";
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        for forged in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let pool = ExecutionWorkPool::new(8192);
            let (witness, root) = active_live_witness(source);
            let (chain, issuer, head_key) = live_revocation_authority();
            let target = if forged {
                witness.witness_id.clone()
            } else {
                EngineObjectId([0x79; 32])
            };
            let mut revocation = signed_live_revocation(
                &target,
                RevocationTargetType::Attestation,
                RevocationReason::Superseded,
                &issuer,
            );
            if forged {
                revocation.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
            }
            let writes = Arc::new(AtomicUsize::new(0));
            let accepted = Arc::new(AtomicUsize::new(0));
            let rejected = Arc::new(AtomicUsize::new(0));
            let recorder = Arc::new(InMemoryHostIoTranscript::recording());
            let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
            let mut runtime = orchestrator(&pool, lane);
            runtime.set_capability_witness_trust_root(root);
            runtime.set_capability_witness(witness);
            runtime
                .bind_capability_witness_revocation(&mut chain.lock().unwrap())
                .unwrap();
            runtime.set_host_io(
                Arc::new(AppendWitnessRevocationAfterWrite {
                    inner: SandboxedHostIo::with_root(directory.path()).unwrap(),
                    chain: Arc::clone(&chain),
                    revocation,
                    head_key,
                    writes: Arc::clone(&writes),
                    accepted: Arc::clone(&accepted),
                    rejected: Arc::clone(&rejected),
                }),
                Some(recorder_dyn),
            );
            let result = runtime.execute(&witness_filesystem_package(source));
            assert!(result.is_ok(), "valid authority must remain usable: {result:?}");
            assert_eq!(accepted.load(Ordering::Relaxed), usize::from(!forged));
            assert_eq!(rejected.load(Ordering::Relaxed), usize::from(forged));
            assert_eq!(writes.load(Ordering::Relaxed), 2);
            assert_eq!(
                std::fs::read(directory.path().join("first.txt")).unwrap(),
                b"committed"
            );
            assert_eq!(
                std::fs::read(directory.path().join("second.txt")).unwrap(),
                b"authorized"
            );
            assert_eq!(recorder.entries().len(), 2);
            assert_eq!(runtime.execution_count(), 1);
            assert!(!pool.is_revoked());
        }
    }
}

fn assert_witness_admission_refusal(
    runtime: &mut ExecutionOrchestrator,
    work: &ExtensionPackage,
    expected: &str,
) {
    use frankenengine_engine::storage_adapter::{EventContext, StoreKind, StoreQuery};

    let error = runtime.execute(work).unwrap_err();
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::CapabilityWitnessRejected { detail } if detail.contains(expected)
    ), "expected {expected:?}, got {error:?}");
    assert_eq!(runtime.execution_count(), 0);
    assert!(runtime.last_failed_console_output().is_empty());
    assert!(runtime.last_failed_host_effect_journal().is_empty());
    let context = EventContext::new("revocation-read", "revocation-read", "revocation-read").unwrap();
    assert!(
        runtime
            .storage_adapter_mut()
            .query(StoreKind::PlasWitness, &StoreQuery::default(), &context)
            .unwrap()
            .is_empty(),
        "revoked or mismatched authority must be refused before witness persistence"
    );
}

#[test]
fn witness_revocation_epoch_advance_and_source_loss_refuse_before_execution() {
    for invalidation in ["already-revoked", "signed", "epoch", "dropped"] {
        let pool = ExecutionWorkPool::new(8192);
        let source = "1 + 2;";
        let (witness, root) = active_live_witness(source);
        let (chain, issuer, head) = live_revocation_authority();
        if invalidation == "already-revoked" {
            chain
                .lock()
                .unwrap()
                .append(
                    signed_live_revocation(
                        &witness.witness_id,
                        RevocationTargetType::Attestation,
                        RevocationReason::Superseded,
                        &issuer,
                    ),
                    &head,
                    "before-binding",
                )
                .unwrap();
        }
        let mut runtime = orchestrator(&pool, None);
        runtime.set_capability_witness_trust_root(root);
        runtime.set_capability_witness(witness.clone());
        runtime
            .bind_capability_witness_revocation(&mut chain.lock().unwrap())
            .unwrap();
        match invalidation {
            "already-revoked" => {}
            "signed" => {
                chain
                    .lock()
                    .unwrap()
                    .append(
                        signed_live_revocation(
                            &witness.witness_id,
                            RevocationTargetType::Attestation,
                            RevocationReason::Superseded,
                            &issuer,
                        ),
                        &head,
                        "before-execution",
                    )
                    .unwrap();
            }
            "epoch" => {
                chain
                    .lock()
                    .unwrap()
                    .set_current_epoch(SecurityEpoch::from_raw(2))
                    .unwrap();
            }
            "dropped" => drop(chain),
            _ => unreachable!(),
        }
        runtime.set_capability_witness(witness);
        assert_witness_admission_refusal(
            &mut runtime,
            &witness_filesystem_package(source),
            "revocation authority is invalidated",
        );
        assert_eq!(pool.committed(), 0);
    }
}

#[test]
fn failed_revocation_binding_is_not_silently_optional() {
    let source = "1 + 2;";
    let (witness, root) = active_live_witness(source);
    for epoch_mismatch in [false, true] {
        let pool = ExecutionWorkPool::new(8192);
        let mut runtime = orchestrator(&pool, None);
        runtime.set_capability_witness_trust_root(root.clone());
        runtime.set_capability_witness(witness.clone());
        let mut chain = if epoch_mismatch {
            RevocationChain::new(LIVE_WITNESS_ZONE)
                .with_authorized_revocation_key(
                    SigningKey::from_bytes([0x72; 32]).unwrap().verification_key(),
                )
                .with_authorized_head_key(
                    SigningKey::from_bytes([0x73; 32]).unwrap().verification_key(),
                )
        } else {
            RevocationChain::new(LIVE_WITNESS_ZONE)
        };
        chain
            .set_current_epoch(SecurityEpoch::from_raw(if epoch_mismatch { 2 } else { 1 }))
            .unwrap();
        assert!(runtime.bind_capability_witness_revocation(&mut chain).is_err());
        runtime.set_capability_witness(witness.clone());
        assert_witness_admission_refusal(
            &mut runtime,
            &witness_filesystem_package(source),
            if epoch_mismatch {
                "epochs must match"
            } else {
                "require authorized issuer and head keys"
            },
        );
        assert_eq!(pool.committed(), 0);
    }
}

#[test]
fn replacing_witness_identity_requires_explicit_matching_revocation_binding() {
    let pool = ExecutionWorkPool::new(8192);
    let (old_witness, root) = active_live_witness("1 + 2;");
    let (new_witness, _) = active_live_witness("3 + 4;");
    assert_ne!(old_witness.content_hash, new_witness.content_hash);
    let (chain, _, _) = live_revocation_authority();
    let mut runtime = orchestrator(&pool, None);
    runtime.set_capability_witness_trust_root(root);
    runtime.set_capability_witness(old_witness);
    runtime
        .bind_capability_witness_revocation(&mut chain.lock().unwrap())
        .unwrap();
    runtime.set_capability_witness(new_witness);
    let work = witness_filesystem_package("3 + 4;");
    assert_witness_admission_refusal(
        &mut runtime,
        &work,
        "does not match its current identity or epoch",
    );
    assert_eq!(pool.committed(), 0);
    runtime
        .bind_capability_witness_revocation(&mut chain.lock().unwrap())
        .unwrap();
    runtime.execute(&work).unwrap();
    assert_eq!(runtime.execution_count(), 1);
}

#[test]
fn live_revocation_binding_does_not_replace_witness_authentication() {
    let source = "1 + 2;";
    let (witness, root) = active_live_witness(source);
    for corrupt_signature in [false, true] {
        let pool = ExecutionWorkPool::new(8192);
        let (chain, _, _) = live_revocation_authority();
        let mut runtime = orchestrator(&pool, None);
        let mut supplied = witness.clone();
        if corrupt_signature {
            supplied.synthesizer_signature = vec![0; 64];
            runtime.set_capability_witness_trust_root(root.clone());
        }
        runtime.set_capability_witness(supplied);
        runtime
            .bind_capability_witness_revocation(&mut chain.lock().unwrap())
            .unwrap();
        assert_witness_admission_refusal(
            &mut runtime,
            &witness_filesystem_package(source),
            if corrupt_signature {
                "not authorized by the trust root"
            } else {
                "externally pinned trust root"
            },
        );
        assert_eq!(pool.committed(), 0);
    }
}
