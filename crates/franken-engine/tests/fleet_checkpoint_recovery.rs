#![forbid(unsafe_code)]
//! Restart and failure-boundary regressions through the public recovery API.
//! Ed25519 signatures are real. Storage and the two independent external
//! authorities are deterministic contract fixtures; real database durability
//! is exercised separately by the concrete checkpoint store's tests.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use frankenengine_engine::fleet_checkpoint_recovery::{
    DurableFleetCheckpointStateV2, FleetCheckpointAnchorAuthority, FleetCheckpointAnchorClaim,
    FleetCheckpointRecoveryConfig, FleetCheckpointRecoveryContext, FleetCheckpointRecoveryError,
};
use frankenengine_engine::fleet_checkpoint_store::{
    FleetCheckpointStore, FleetCheckpointStoreCasOutcome, FleetCheckpointStoreError,
    FleetCheckpointStoreHead, FleetCheckpointStoreRecord,
};
use frankenengine_engine::fleet_checkpoint_v2::{FleetCheckpointQuorumV2, FleetCheckpointV2Error};
use frankenengine_engine::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, ContainmentAction, ContainmentIntent,
    DurableFleetVerificationRegistry, EvidencePacket, FleetAuthorityId, FleetIdentityError,
    FleetIngressV2Error, FleetRegistryAnchorAuthority, FleetRegistrySnapshotAnchorClaim,
    FleetSigner, FleetVerificationRegistryPersistence, GossipConfig, HeartbeatLiveness,
    MessageSignature, NodeId, ProtocolError, ProtocolVersion,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};

type RegistryTransition = (
    Option<FleetRegistrySnapshotAnchorClaim>,
    FleetRegistrySnapshotAnchorClaim,
);

#[derive(Default)]
struct RegistryAnchorState {
    current: Option<FleetRegistrySnapshotAnchorClaim>,
    permits: BTreeMap<Vec<u8>, RegistryTransition>,
    counter: u64,
}

struct RegistryAuthority {
    fleet: FleetAuthorityId,
    state: RefCell<RegistryAnchorState>,
    on_authenticate: RefCell<Option<Box<dyn Fn()>>>,
}

fn registry_error(detail: &str) -> FleetIdentityError {
    FleetIdentityError::UnverifiedRegistryAnchor {
        detail: detail.into(),
    }
}

impl FleetRegistryAnchorAuthority for RegistryAuthority {
    fn fleet_authority_id(&self) -> FleetAuthorityId {
        self.fleet
    }

    fn authenticate_current_registry_anchor(
        &self,
        claim: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        if self.state.borrow().current.as_ref() != Some(claim) {
            return Err(registry_error("registry anchor is not current"));
        }
        if let Some(callback) = self.on_authenticate.borrow().as_ref() {
            callback();
        }
        Ok("registry-current".into())
    }

    fn prepare_registry_anchor_advance(
        &self,
        expected: Option<&FleetRegistrySnapshotAnchorClaim>,
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<Vec<u8>, FleetIdentityError> {
        let mut state = self.state.borrow_mut();
        if state.current.as_ref() != expected || next.fleet_authority_id != self.fleet {
            return Err(registry_error("registry transition expected head differs"));
        }
        state.counter += 1;
        let permit = state.counter.to_be_bytes().to_vec();
        state
            .permits
            .insert(permit.clone(), (expected.cloned(), next.clone()));
        Ok(permit)
    }

    fn finalize_registry_anchor_advance(
        &self,
        permit: &[u8],
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        let mut state = self.state.borrow_mut();
        let (expected, authorized) = state
            .permits
            .get(permit)
            .cloned()
            .ok_or_else(|| registry_error("unissued registry permit"))?;
        if &authorized != next
            || (state.current != expected && state.current.as_ref() != Some(next))
        {
            return Err(registry_error("registry permit or current head differs"));
        }
        state.current = Some(next.clone());
        Ok("registry-finalized".into())
    }
}

type CheckpointTransition = (
    Option<FleetCheckpointAnchorClaim>,
    FleetCheckpointAnchorClaim,
);

#[derive(Default)]
struct CheckpointAnchorState {
    current: Option<FleetCheckpointAnchorClaim>,
    permits: BTreeMap<Vec<u8>, CheckpointTransition>,
    counter: u64,
}

#[derive(Clone, Copy, Default)]
enum FinalizeFault {
    #[default]
    None,
    BeforeAdvance,
    LostResponse,
}

struct CheckpointAuthority {
    fleet: FleetAuthorityId,
    node: NodeId,
    state: RefCell<CheckpointAnchorState>,
    finalize_fault: Cell<FinalizeFault>,
}

fn anchor_error(detail: &str) -> FleetCheckpointRecoveryError {
    FleetCheckpointRecoveryError::Anchor {
        detail: detail.into(),
    }
}

impl CheckpointAuthority {
    fn new(fleet: FleetAuthorityId, node: NodeId) -> Self {
        Self {
            fleet,
            node,
            state: RefCell::new(CheckpointAnchorState::default()),
            finalize_fault: Cell::new(FinalizeFault::None),
        }
    }

    fn inject_concurrent_advance_from(&self, revision: u64) {
        let mut state = self.state.borrow_mut();
        let Some(mut next) = state.current.clone() else {
            return;
        };
        if next.revision == revision {
            next.revision += 1;
            next.prior_state_hash = next.state_hash;
            next.state_hash =
                ContentHash::compute(b"independently accepted concurrent checkpoint state");
            state.current = Some(next);
        }
    }
}

impl FleetCheckpointAnchorAuthority for CheckpointAuthority {
    fn fleet_authority_id(&self) -> FleetAuthorityId {
        self.fleet
    }

    fn node_id(&self) -> &NodeId {
        &self.node
    }

    fn authenticate_current_checkpoint_anchor(
        &self,
        claim: &FleetCheckpointAnchorClaim,
    ) -> Result<String, FleetCheckpointRecoveryError> {
        if self.state.borrow().current.as_ref() != Some(claim) {
            return Err(anchor_error("checkpoint anchor is not current"));
        }
        Ok("checkpoint-current".into())
    }

    fn prepare_checkpoint_anchor_advance(
        &self,
        expected: Option<&FleetCheckpointAnchorClaim>,
        next: &FleetCheckpointAnchorClaim,
    ) -> Result<Vec<u8>, FleetCheckpointRecoveryError> {
        let mut state = self.state.borrow_mut();
        if state.current.as_ref() != expected
            || next.fleet_authority_id != self.fleet
            || next.node_id != self.node
            || expected.map_or(0, |claim| claim.revision).checked_add(1) != Some(next.revision)
            || next.prior_state_hash
                != expected.map_or_else(ContentHash::default, |claim| claim.state_hash)
        {
            return Err(anchor_error(
                "checkpoint transition namespace or expected head differs",
            ));
        }
        state.counter += 1;
        // The retained map authenticates the complete transition. The permit
        // is not parsed as trusted authority from storage-controlled bytes.
        let mut permit = b"checkpoint-domain:".to_vec();
        permit.extend_from_slice(&state.counter.to_be_bytes());
        state
            .permits
            .insert(permit.clone(), (expected.cloned(), next.clone()));
        Ok(permit)
    }

    fn finalize_checkpoint_anchor_advance(
        &self,
        permit: &[u8],
        next: &FleetCheckpointAnchorClaim,
    ) -> Result<String, FleetCheckpointRecoveryError> {
        let fault = self.finalize_fault.replace(FinalizeFault::None);
        if matches!(fault, FinalizeFault::BeforeAdvance) {
            return Err(anchor_error(
                "injected authority interruption before advance",
            ));
        }
        let mut state = self.state.borrow_mut();
        let (expected, authorized) = state
            .permits
            .get(permit)
            .cloned()
            .ok_or_else(|| anchor_error("unissued checkpoint permit"))?;
        if &authorized != next
            || (state.current != expected && state.current.as_ref() != Some(next))
        {
            return Err(anchor_error("checkpoint permit or current head differs"));
        }
        state.current = Some(next.clone());
        if matches!(fault, FinalizeFault::LostResponse) {
            return Err(anchor_error(
                "injected authority response loss after advance",
            ));
        }
        Ok("checkpoint-finalized".into())
    }
}

#[derive(Clone, Copy, Default)]
enum StoreFault {
    #[default]
    None,
    BeforeCommit,
    LostResponse,
    LostReadback,
    FalseSuccess,
}

#[derive(Default)]
struct Stored {
    record: Option<FleetCheckpointStoreRecord>,
    fault: StoreFault,
    failed_reads: usize,
    failed_confirmations: usize,
    confirmations: usize,
    on_load: Option<ReadbackHook>,
}

type ReadbackHook = Box<dyn Fn(&FleetCheckpointStoreRecord)>;

#[derive(Clone, Default)]
struct TestStore(Rc<RefCell<Stored>>);

fn storage_error(detail: &str) -> FleetCheckpointStoreError {
    FleetCheckpointStoreError::Backend {
        detail: detail.into(),
    }
}

impl TestStore {
    fn record(&self) -> FleetCheckpointStoreRecord {
        self.0.borrow().record.clone().unwrap()
    }

    fn fault(&self, fault: StoreFault) {
        self.0.borrow_mut().fault = fault;
    }

    fn replace_untrusted(&self, record: FleetCheckpointStoreRecord) {
        self.0.borrow_mut().record = Some(record);
    }
}

impl FleetCheckpointStore for TestStore {
    fn load(&mut self) -> Result<Option<FleetCheckpointStoreRecord>, FleetCheckpointStoreError> {
        let mut stored = self.0.borrow_mut();
        if stored.failed_reads != 0 {
            stored.failed_reads -= 1;
            return Err(storage_error("injected indeterminate readback"));
        }
        let record = stored.record.clone();
        if let (Some(record), Some(callback)) = (record.as_ref(), stored.on_load.as_ref()) {
            callback(record);
        }
        Ok(record)
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<&FleetCheckpointStoreHead>,
        candidate: &FleetCheckpointStoreRecord,
    ) -> Result<FleetCheckpointStoreCasOutcome, FleetCheckpointStoreError> {
        candidate.validate()?;
        let mut stored = self.0.borrow_mut();
        let fault = std::mem::take(&mut stored.fault);
        if matches!(fault, StoreFault::BeforeCommit) {
            return Err(storage_error("injected failure before commit"));
        }
        if matches!(fault, StoreFault::FalseSuccess) {
            return Ok(FleetCheckpointStoreCasOutcome::Applied(candidate.clone()));
        }
        if stored
            .record
            .as_ref()
            .map(FleetCheckpointStoreRecord::head)
            .as_ref()
            != expected
        {
            return Ok(FleetCheckpointStoreCasOutcome::Conflict {
                current: stored.record.clone(),
            });
        }
        if expected.map_or(0, |head| head.revision).checked_add(1) != Some(candidate.revision)
            || candidate.prior_state_hash
                != expected.map_or_else(ContentHash::default, |head| head.state_hash)
            || expected.is_some_and(|head| {
                head.fleet_authority_id != candidate.fleet_authority_id
                    || head.node_id != candidate.node_id
            })
        {
            return Err(storage_error("invalid fixture CAS transition"));
        }
        stored.record = Some(candidate.clone());
        match fault {
            StoreFault::LostResponse => {
                Err(storage_error("injected committed write response loss"))
            }
            StoreFault::LostReadback => {
                stored.failed_reads = 1;
                Ok(FleetCheckpointStoreCasOutcome::Applied(candidate.clone()))
            }
            _ => Ok(FleetCheckpointStoreCasOutcome::Applied(candidate.clone())),
        }
    }

    fn confirm_durable(
        &mut self,
        expected: &FleetCheckpointStoreRecord,
    ) -> Result<(), FleetCheckpointStoreError> {
        expected.validate()?;
        let mut stored = self.0.borrow_mut();
        if stored.failed_confirmations != 0 {
            stored.failed_confirmations -= 1;
            return Err(storage_error("injected stable-media confirmation failure"));
        }
        if stored.record.as_ref() != Some(expected) {
            return Err(storage_error("confirmation found different current bytes"));
        }
        stored.confirmations += 1;
        Ok(())
    }
}

struct Fleet {
    registry_authority: RegistryAuthority,
    registry: DurableFleetVerificationRegistry,
    signers: Vec<FleetSigner>,
    config: FleetCheckpointRecoveryConfig,
}

impl Fleet {
    fn new() -> Self {
        let fleet = FleetAuthorityId::from_provisioned_bytes([0xb4; 32]).unwrap();
        let epoch = SecurityEpoch::from_raw(7);
        let registry_authority = RegistryAuthority {
            fleet,
            state: RefCell::new(RegistryAnchorState::default()),
            on_authenticate: RefCell::new(None),
        };
        let signers: Vec<_> = (0..3)
            .map(|index| {
                FleetSigner::new(
                    fleet,
                    NodeId::new(format!("recovery-node-{index}")),
                    1,
                    SigningKey::from_bytes([0x41 + index as u8; 32]).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let mut storage = InMemoryStorageAdapter::new();
        let context =
            EventContext::new("recovery-trace", "recovery-decision", "recovery-policy").unwrap();
        let mut registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
            .prepare_initial_registration(
                signers[0].identity().signer.clone(),
                1,
                signers[0].verification_key().clone(),
                epoch,
                &registry_authority,
            )
            .unwrap()
            .finalize_and_publish(&registry_authority)
            .unwrap();
        for signer in &signers[1..] {
            registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
                .prepare_register_node(
                    &registry,
                    signer.identity().signer.clone(),
                    1,
                    signer.verification_key().clone(),
                    epoch,
                    &registry_authority,
                )
                .unwrap()
                .finalize_and_publish(&registry_authority)
                .unwrap();
        }
        let config = FleetCheckpointRecoveryConfig {
            fleet_authority_id: fleet,
            node_id: signers[0].identity().signer.clone(),
            gossip: GossipConfig::default(),
            quorum: FleetCheckpointQuorumV2::new(
                signers
                    .iter()
                    .map(|signer| signer.identity().signer.clone())
                    .collect::<BTreeSet<_>>(),
                500_000,
            )
            .unwrap(),
            minimum_epoch: epoch,
        };
        Self {
            registry_authority,
            registry,
            signers,
            config,
        }
    }

    fn authority(&self) -> CheckpointAuthority {
        CheckpointAuthority::new(self.config.fleet_authority_id, self.config.node_id.clone())
    }

    fn context<'a>(
        &'a self,
        checkpoint_authority: &'a CheckpointAuthority,
    ) -> FleetCheckpointRecoveryContext<'a, RegistryAuthority, CheckpointAuthority> {
        FleetCheckpointRecoveryContext {
            registry: &self.registry,
            registry_authority: &self.registry_authority,
            checkpoint_authority,
        }
    }

    fn heartbeat(&self, index: usize) -> HeartbeatLiveness {
        let node_id = self.signers[index].identity().signer.clone();
        HeartbeatLiveness {
            node_id: node_id.clone(),
            policy_version: 7,
            evidence_frontier_hash: ContentHash::compute(b"frontier"),
            local_health: BTreeMap::new(),
            epoch: self.config.minimum_epoch,
            sequence: 1,
            timestamp_ns: 100,
            signature: marker(node_id),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn evidence(&self, index: usize, sequence: u64) -> EvidencePacket {
        let node_id = self.signers[index].identity().signer.clone();
        EvidencePacket {
            trace_id: format!("evidence-{index}-{sequence}"),
            extension_id: "extension".into(),
            evidence_hash: ContentHash::compute(b"evidence"),
            posterior_delta_millionths: 123,
            policy_version: 7,
            epoch: self.config.minimum_epoch,
            node_id: node_id.clone(),
            sequence,
            timestamp_ns: 100,
            signature: marker(node_id),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn intent(&self, index: usize, sequence: u64) -> ContainmentIntent {
        let node_id = self.signers[index].identity().signer.clone();
        ContainmentIntent {
            intent_id: format!("intent-{index}-{sequence}"),
            extension_id: "extension".into(),
            proposed_action: ContainmentAction::Quarantine,
            confidence_millionths: 900_000,
            supporting_evidence_ids: Vec::new(),
            policy_version: 7,
            epoch: self.config.minimum_epoch,
            node_id: node_id.clone(),
            sequence,
            timestamp_ns: 100,
            signature: marker(node_id),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn populate(&self, state: &mut DurableFleetCheckpointStateV2, authority: &CheckpointAuthority) {
        let context = self.context(authority);
        for (index, signer) in self.signers.iter().enumerate() {
            let heartbeat = self.heartbeat(index);
            let signature = signer.sign_detached_message_v2(&heartbeat).unwrap();
            state
                .process_heartbeat(&heartbeat, &signature, &context)
                .unwrap();
        }
        let evidence = self.evidence(0, 2);
        state
            .process_evidence(
                &evidence,
                &self.signers[0].sign_detached_message_v2(&evidence).unwrap(),
                &context,
            )
            .unwrap();
        let intent = self.intent(0, 3);
        state
            .process_intent(
                &intent,
                &self.signers[0].sign_detached_message_v2(&intent).unwrap(),
                &context,
            )
            .unwrap();
    }

    fn peer(&self, index: usize) -> AuthenticatedFleetProtocolStateV2 {
        let mut state = AuthenticatedFleetProtocolStateV2::new(
            self.config.fleet_authority_id,
            self.signers[index].identity().signer.clone(),
            self.config.gossip.clone(),
            self.config.minimum_epoch,
        )
        .unwrap();
        for (index, signer) in self.signers.iter().enumerate() {
            let heartbeat = self.heartbeat(index);
            state
                .process_heartbeat(
                    &heartbeat,
                    &signer.sign_detached_message_v2(&heartbeat).unwrap(),
                    &self.registry,
                    &self.registry_authority,
                )
                .unwrap();
        }
        let evidence = self.evidence(0, 2);
        state
            .process_evidence(
                &evidence,
                &self.signers[0].sign_detached_message_v2(&evidence).unwrap(),
                &self.registry,
                &self.registry_authority,
            )
            .unwrap();
        let intent = self.intent(0, 3);
        state
            .process_intent(
                &intent,
                &self.signers[0].sign_detached_message_v2(&intent).unwrap(),
                &self.registry,
                &self.registry_authority,
            )
            .unwrap();
        state
    }
}

fn marker(node_id: NodeId) -> MessageSignature {
    MessageSignature {
        signer: node_id,
        hash: AuthenticityHash([0; 32]),
    }
}

#[test]
fn restored_vote_is_repeatable_but_never_retargets_the_same_round() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut state, &authority);
    let draft = state.draft_checkpoint_v2(100).unwrap();
    let signature = state
        .sign_checkpoint_v2(
            &draft,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority),
        )
        .unwrap();
    drop(state);
    let mut restored =
        DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    let resumed = restored.resumed_checkpoint_draft_v2().unwrap().unwrap();
    assert_eq!(resumed.checkpoint(), draft.checkpoint());
    let repeated = restored
        .sign_checkpoint_v2(
            &resumed,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority),
        )
        .unwrap();
    assert_eq!(signature, repeated);
    let conflicting = restored.draft_checkpoint_v2(101).unwrap();
    let before = store.record();
    assert!(matches!(
        restored.sign_checkpoint_v2(
            &conflicting,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority)
        ),
        Err(FleetCheckpointRecoveryError::Checkpoint(
            FleetCheckpointV2Error::ConflictingVote { .. }
        ))
    ));
    assert_eq!(store.record(), before);
    assert!(!restored.requires_recovery());
}

#[test]
fn restart_preserves_replay_frontiers_and_evidence_deduplication() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut state, &authority);
    state.flush(&mut store, &authority).unwrap();
    drop(state);
    let mut state =
        DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    let old = fleet.evidence(0, 2);
    assert!(matches!(
        state.process_evidence(
            &old,
            &fleet.signers[0].sign_detached_message_v2(&old).unwrap(),
            &fleet.context(&authority)
        ),
        Err(FleetCheckpointRecoveryError::Ingress(
            FleetIngressV2Error::Protocol(ProtocolError::ReplayDetected { .. })
        ))
    ));
    let mut duplicate = old;
    duplicate.sequence = 4;
    assert!(matches!(
        state.process_evidence(
            &duplicate,
            &fleet.signers[0]
                .sign_detached_message_v2(&duplicate)
                .unwrap(),
            &fleet.context(&authority)
        ),
        Err(FleetCheckpointRecoveryError::Ingress(
            FleetIngressV2Error::Protocol(ProtocolError::DuplicateEvidence { .. })
        ))
    ));
    assert_eq!(
        state
            .state()
            .unwrap()
            .sequence_tracker
            .last_sequence(&fleet.config.node_id),
        3
    );
    let fresh = fleet.evidence(0, 4);
    state
        .process_evidence(
            &fresh,
            &fleet.signers[0].sign_detached_message_v2(&fresh).unwrap(),
            &fleet.context(&authority),
        )
        .unwrap();
    assert_eq!(
        state.state().unwrap().evidence.evidence_count("extension"),
        2
    );
}

#[test]
fn evidence_totals_beyond_u64_survive_json_recovery_without_losing_cancellation() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    for sequence in 1..=3 {
        let mut packet = fleet.evidence(0, sequence);
        packet.posterior_delta_millionths = i64::MAX;
        let signature = fleet.signers[0].sign_detached_message_v2(&packet).unwrap();
        state
            .process_evidence(&packet, &signature, &fleet.context(&authority))
            .unwrap();
    }
    assert_eq!(
        state.state().unwrap().evidence.posterior_delta("extension"),
        i64::MAX
    );
    state.flush(&mut store, &authority).unwrap();
    drop(state);
    let mut state =
        DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    assert_eq!(
        state.state().unwrap().evidence.evidence_count("extension"),
        3
    );
    for sequence in 4..=5 {
        let mut packet = fleet.evidence(0, sequence);
        packet.posterior_delta_millionths = i64::MIN;
        let signature = fleet.signers[0].sign_detached_message_v2(&packet).unwrap();
        state
            .process_evidence(&packet, &signature, &fleet.context(&authority))
            .unwrap();
    }
    // 3*MAX + 2*MIN is MAX-2. A rounded JSON number or a restored
    // saturated i64 accumulator would produce a different public result.
    assert_eq!(
        state.state().unwrap().evidence.posterior_delta("extension"),
        i64::MAX - 2
    );
    assert_eq!(
        state.state().unwrap().evidence.evidence_count("extension"),
        5
    );
    assert_eq!(
        state
            .state()
            .unwrap()
            .sequence_tracker
            .last_sequence(&fleet.config.node_id),
        5,
    );
    let mut original = fleet.evidence(0, 1);
    original.posterior_delta_millionths = i64::MAX;
    let signature = fleet.signers[0]
        .sign_detached_message_v2(&original)
        .unwrap();
    assert!(matches!(
        state.process_evidence(&original, &signature, &fleet.context(&authority)),
        Err(FleetCheckpointRecoveryError::Ingress(
            FleetIngressV2Error::Protocol(ProtocolError::ReplayDetected { .. })
        ))
    ));
    original.sequence = 6;
    let signature = fleet.signers[0]
        .sign_detached_message_v2(&original)
        .unwrap();
    assert!(matches!(
        state.process_evidence(&original, &signature, &fleet.context(&authority)),
        Err(FleetCheckpointRecoveryError::Ingress(
            FleetIngressV2Error::Protocol(ProtocolError::DuplicateEvidence { .. })
        ))
    ));
    assert_eq!(
        state.state().unwrap().evidence.posterior_delta("extension"),
        i64::MAX - 2
    );
    assert_eq!(
        state.state().unwrap().evidence.evidence_count("extension"),
        5
    );
    assert_eq!(
        state
            .state()
            .unwrap()
            .sequence_tracker
            .last_sequence(&fleet.config.node_id),
        5,
    );
}

#[test]
fn frozen_round_survives_restart_and_finalization_retains_late_input() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut state, &authority);
    let draft = state.draft_checkpoint_v2(100).unwrap();
    state
        .sign_checkpoint_v2(
            &draft,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority),
        )
        .unwrap();
    let late_intent = fleet.intent(1, 2);
    state
        .process_intent(
            &late_intent,
            &fleet.signers[1]
                .sign_detached_message_v2(&late_intent)
                .unwrap(),
            &fleet.context(&authority),
        )
        .unwrap();
    let late_evidence = fleet.evidence(2, 2);
    state
        .process_evidence(
            &late_evidence,
            &fleet.signers[2]
                .sign_detached_message_v2(&late_evidence)
                .unwrap(),
            &fleet.context(&authority),
        )
        .unwrap();
    state.flush(&mut store, &authority).unwrap();
    drop(state);
    let mut state =
        DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    let mut resumed = state.resumed_checkpoint_draft_v2().unwrap().unwrap();
    assert_eq!(resumed.checkpoint(), draft.checkpoint());
    let local_vote = state
        .sign_checkpoint_v2(
            &resumed,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority),
        )
        .unwrap();
    resumed
        .add_signature(local_vote, &fleet.registry, &fleet.registry_authority)
        .unwrap();
    let peer_vote = fleet
        .peer(1)
        .sign_checkpoint_v2(
            &resumed,
            &fleet.config.quorum,
            &fleet.signers[1],
            &fleet.registry,
            &fleet.registry_authority,
        )
        .unwrap();
    resumed
        .add_signature(peer_vote, &fleet.registry, &fleet.registry_authority)
        .unwrap();
    let certificate = state
        .finalize_checkpoint_v2(&resumed, 101, &mut store, &fleet.context(&authority))
        .unwrap();
    assert_eq!(certificate.checkpoint.checkpoint_seq, 1);
    assert_eq!(state.state().unwrap().pending_intents["extension"].len(), 1);
    assert_eq!(
        state.state().unwrap().pending_intents["extension"][0].intent_id,
        late_intent.intent_id
    );
    assert_eq!(
        state.state().unwrap().evidence.evidence_count("extension"),
        2
    );
    drop(state);
    let state =
        DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    assert_eq!(state.state().unwrap().last_checkpoint_seq, 1);
    assert_eq!(
        state.last_finalized_checkpoint().unwrap(),
        Some(&certificate)
    );
    assert!(state.resumed_checkpoint_draft_v2().unwrap().is_none());
    assert_eq!(
        state.state().unwrap().pending_intents["extension"][0].intent_id,
        late_intent.intent_id
    );
}

#[test]
fn uncertain_committed_vote_releases_no_signature_until_recovery() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut state, &authority);
    let draft = state.draft_checkpoint_v2(100).unwrap();
    store.fault(StoreFault::LostReadback);
    assert!(
        state
            .sign_checkpoint_v2(
                &draft,
                &fleet.signers[0],
                &mut store,
                &fleet.context(&authority)
            )
            .is_err()
    );
    assert!(state.requires_recovery());
    assert!(matches!(
        state.state(),
        Err(FleetCheckpointRecoveryError::RecoveryRequired)
    ));
    assert_eq!(store.record().revision, 2);
    state.recover(&mut store, &authority).unwrap();
    let resumed = state.resumed_checkpoint_draft_v2().unwrap().unwrap();
    assert_eq!(resumed.checkpoint(), draft.checkpoint());
    state
        .sign_checkpoint_v2(
            &resumed,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority),
        )
        .unwrap();
    assert!(!state.requires_recovery());
}

#[test]
fn readable_bytes_after_failed_commit_require_a_successful_durability_confirmation() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut state, &authority);
    let draft = state.draft_checkpoint_v2(100).unwrap();
    store.fault(StoreFault::LostResponse);
    assert!(
        state
            .sign_checkpoint_v2(
                &draft,
                &fleet.signers[0],
                &mut store,
                &fleet.context(&authority),
            )
            .is_err()
    );
    assert!(state.requires_recovery());
    assert_eq!(store.load().unwrap().unwrap().revision, 2);
    assert_eq!(
        authority.state.borrow().current.as_ref().unwrap().revision,
        1
    );
    store.0.borrow_mut().failed_confirmations = 1;
    assert!(state.recover(&mut store, &authority).is_err());
    assert!(state.requires_recovery());
    assert_eq!(
        authority.state.borrow().current.as_ref().unwrap().revision,
        1
    );
    state.recover(&mut store, &authority).unwrap();
    assert_eq!(store.0.borrow().confirmations, 1);
    let resumed = state.resumed_checkpoint_draft_v2().unwrap().unwrap();
    assert_eq!(resumed.checkpoint(), draft.checkpoint());
    let signature = state
        .sign_checkpoint_v2(
            &resumed,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority),
        )
        .unwrap();
    fleet
        .registry
        .verify_live_detached_message_v2(
            draft.checkpoint(),
            &signature,
            fleet.config.minimum_epoch,
            &fleet.registry_authority,
        )
        .unwrap();
    assert!(!state.requires_recovery());
    assert_eq!(state.anchor_claim().revision, 3);
}

#[test]
fn both_external_anchor_crash_windows_recover_idempotently() {
    for fault in [FinalizeFault::BeforeAdvance, FinalizeFault::LostResponse] {
        let fleet = Fleet::new();
        let authority = fleet.authority();
        let mut store = TestStore::default();
        let mut state =
            DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
                .unwrap();
        fleet.populate(&mut state, &authority);
        let draft = state.draft_checkpoint_v2(100).unwrap();
        authority.finalize_fault.set(fault);
        assert!(
            state
                .sign_checkpoint_v2(
                    &draft,
                    &fleet.signers[0],
                    &mut store,
                    &fleet.context(&authority)
                )
                .is_err()
        );
        assert!(state.requires_recovery());
        drop(state);
        let mut state =
            DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority)
                .unwrap();
        let resumed = state.resumed_checkpoint_draft_v2().unwrap().unwrap();
        assert_eq!(resumed.checkpoint(), draft.checkpoint());
        state
            .sign_checkpoint_v2(
                &resumed,
                &fleet.signers[0],
                &mut store,
                &fleet.context(&authority),
            )
            .unwrap();
    }
}

#[test]
fn failed_or_falsely_acknowledged_writes_do_not_publish_a_vote() {
    for fault in [StoreFault::BeforeCommit, StoreFault::FalseSuccess] {
        let fleet = Fleet::new();
        let authority = fleet.authority();
        let mut store = TestStore::default();
        let mut state =
            DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
                .unwrap();
        fleet.populate(&mut state, &authority);
        let draft = state.draft_checkpoint_v2(100).unwrap();
        let previous = store.record();
        store.fault(fault);
        assert!(
            state
                .sign_checkpoint_v2(
                    &draft,
                    &fleet.signers[0],
                    &mut store,
                    &fleet.context(&authority)
                )
                .is_err()
        );
        assert!(state.requires_recovery());
        assert_eq!(store.record(), previous);
        state.recover(&mut store, &authority).unwrap();
        assert!(state.resumed_checkpoint_draft_v2().unwrap().is_none());
        // The inputs were explicitly volatile; no vote or checkpoint had
        // published their state before the failed boundary.
        assert_eq!(
            state.state().unwrap().evidence.evidence_count("extension"),
            0
        );
    }
}

#[test]
fn independent_anchor_rejects_database_rollback_and_rehashed_forgery() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    let old = store.record();
    fleet.populate(&mut state, &authority);
    state.flush(&mut store, &authority).unwrap();
    let current = store.record();
    store.replace_untrusted(old.clone());
    assert!(matches!(
        DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority),
        Err(FleetCheckpointRecoveryError::Anchor { .. })
    ));
    store.replace_untrusted(current);
    state.recover(&mut store, &authority).unwrap();

    let independent = fleet.authority();
    let mut separate_store = TestStore::default();
    let state = DurableFleetCheckpointStateV2::create(
        fleet.config.clone(),
        &mut separate_store,
        &independent,
    )
    .unwrap();
    drop(state);
    let mut forged = separate_store.record();
    assert!(forged.snapshot_json.contains("\"current_epoch\":7"));
    forged.snapshot_json = forged
        .snapshot_json
        .replace("\"current_epoch\":7", "\"current_epoch\":8");
    forged.state_hash = ContentHash::compute(forged.snapshot_json.as_bytes());
    forged.validate().unwrap();
    separate_store.replace_untrusted(forged);
    assert!(matches!(
        DurableFleetCheckpointStateV2::restore(
            fleet.config.clone(),
            &mut separate_store,
            &independent
        ),
        Err(FleetCheckpointRecoveryError::Anchor { .. })
    ));
}

#[test]
fn pending_commit_defeats_stale_writer_and_retains_one_recoverable_vote() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut first =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    let mut stale =
        DurableFleetCheckpointStateV2::restore(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut first, &authority);
    fleet.populate(&mut stale, &authority);
    let first_draft = first.draft_checkpoint_v2(100).unwrap();
    let stale_draft = stale.draft_checkpoint_v2(101).unwrap();
    authority.finalize_fault.set(FinalizeFault::BeforeAdvance);
    assert!(
        first
            .sign_checkpoint_v2(
                &first_draft,
                &fleet.signers[0],
                &mut store,
                &fleet.context(&authority)
            )
            .is_err()
    );
    let committed = store.record();
    assert!(matches!(
        stale.sign_checkpoint_v2(
            &stale_draft,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority)
        ),
        Err(FleetCheckpointRecoveryError::ConcurrentUpdate)
    ));
    assert_eq!(store.record(), committed);
    assert!(stale.requires_recovery());
    stale.recover(&mut store, &authority).unwrap();
    assert_eq!(
        stale
            .resumed_checkpoint_draft_v2()
            .unwrap()
            .unwrap()
            .checkpoint(),
        first_draft.checkpoint()
    );
    assert!(
        stale
            .sign_checkpoint_v2(
                &stale_draft,
                &fleet.signers[0],
                &mut store,
                &fleet.context(&authority)
            )
            .is_err()
    );
}

#[test]
fn epoch_advance_is_durable_and_preserves_replay_and_evidence_history() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut state, &authority);
    let draft = state.draft_checkpoint_v2(100).unwrap();
    state
        .sign_checkpoint_v2(
            &draft,
            &fleet.signers[0],
            &mut store,
            &fleet.context(&authority),
        )
        .unwrap();
    state
        .advance_epoch(SecurityEpoch::from_raw(8), &mut store, &authority)
        .unwrap();
    drop(state);
    let mut config = fleet.config.clone();
    config.minimum_epoch = SecurityEpoch::from_raw(8);
    let state = DurableFleetCheckpointStateV2::restore(config, &mut store, &authority).unwrap();
    assert_eq!(
        state.state().unwrap().current_epoch,
        SecurityEpoch::from_raw(8)
    );
    assert!(state.state().unwrap().pending_intents.is_empty());
    assert!(state.resumed_checkpoint_draft_v2().unwrap().is_none());
    assert_eq!(
        state.state().unwrap().evidence.evidence_count("extension"),
        1
    );
    assert_eq!(
        state
            .state()
            .unwrap()
            .sequence_tracker
            .last_sequence(&fleet.config.node_id),
        3
    );
}

#[test]
fn snapshot_backpressure_preserves_sequence_and_flush_allows_exact_retry() {
    let fleet = Fleet::new();
    let authority = fleet.authority();
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, &authority)
            .unwrap();
    fleet.populate(&mut state, &authority);
    // Control characters exercise JSON's maximum six-byte string escaping.
    // Reusing the extension makes the conservative admission charge larger
    // than the actual snapshot growth, so an explicit flush can rebase it.
    let extension = "\u{2}".repeat(230);
    let trace_suffix = "\u{1}".repeat(230);
    let mut rejected = None;
    for sequence in 4..20_000 {
        let mut packet = fleet.evidence(0, sequence);
        packet.extension_id = extension.clone();
        packet.trace_id = format!("{sequence:05}{trace_suffix}");
        let signature = fleet.signers[0].sign_detached_message_v2(&packet).unwrap();
        match state.process_evidence(&packet, &signature, &fleet.context(&authority)) {
            Ok(()) => {}
            Err(FleetCheckpointRecoveryError::AdmissionCapacityExceeded { actual, limit }) => {
                assert!(actual > limit);
                assert_eq!(
                    state
                        .state()
                        .unwrap()
                        .sequence_tracker
                        .last_sequence(&fleet.config.node_id),
                    sequence - 1,
                );
                rejected = Some((packet, signature));
                break;
            }
            Err(error) => {
                panic!("unexpected admission error while filling snapshot budget: {error}")
            }
        }
    }
    let (packet, signature) = rejected.expect("bounded snapshots must apply backpressure");
    assert!(!state.requires_recovery());
    state.flush(&mut store, &authority).unwrap();
    state
        .process_evidence(&packet, &signature, &fleet.context(&authority))
        .unwrap();
    assert_eq!(
        state
            .state()
            .unwrap()
            .sequence_tracker
            .last_sequence(&fleet.config.node_id),
        packet.sequence,
    );
    state.flush(&mut store, &authority).unwrap();
    assert!(!state.requires_recovery());
}

#[test]
fn checkpoint_anchor_advance_during_final_registry_callback_blocks_signature_release() {
    let fleet = Fleet::new();
    let authority = Rc::new(fleet.authority());
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, authority.as_ref())
            .unwrap();
    fleet.populate(&mut state, authority.as_ref());
    let draft = state.draft_checkpoint_v2(100).unwrap();
    let racing_authority = authority.clone();
    *fleet.registry_authority.on_authenticate.borrow_mut() = Some(Box::new(move || {
        // Initial registry checks see revision1. Only the final registry
        // callback after the vote's durable anchor reaches2 triggers the race.
        racing_authority.inject_concurrent_advance_from(2);
    }));
    assert!(matches!(
        state.sign_checkpoint_v2(
            &draft,
            &fleet.signers[0],
            &mut store,
            &fleet.context(authority.as_ref()),
        ),
        Err(FleetCheckpointRecoveryError::Anchor { .. })
    ));
    assert!(state.requires_recovery());
    assert_eq!(
        authority.state.borrow().current.as_ref().unwrap().revision,
        3
    );
    assert!(state.state().is_err());
}

#[test]
fn recovery_rechecks_anchor_after_the_final_store_readback_callback() {
    let fleet = Fleet::new();
    let authority = Rc::new(fleet.authority());
    let mut store = TestStore::default();
    let mut state =
        DurableFleetCheckpointStateV2::create(fleet.config.clone(), &mut store, authority.as_ref())
            .unwrap();
    fleet.populate(&mut state, authority.as_ref());
    let draft = state.draft_checkpoint_v2(100).unwrap();
    authority.finalize_fault.set(FinalizeFault::BeforeAdvance);
    assert!(
        state
            .sign_checkpoint_v2(
                &draft,
                &fleet.signers[0],
                &mut store,
                &fleet.context(authority.as_ref()),
            )
            .is_err()
    );
    let racing_authority = authority.clone();
    store.0.borrow_mut().on_load = Some(Box::new(move |record| {
        if record.revision == 2 {
            // The first restore read still sees anchor1. Once restore has
            // finalized anchor2, its final readback simulates a concurrent
            // independent authority advance before returning to the caller.
            racing_authority.inject_concurrent_advance_from(2);
        }
    }));
    assert!(matches!(
        state.recover(&mut store, authority.as_ref()),
        Err(FleetCheckpointRecoveryError::Anchor { .. })
    ));
    assert!(state.requires_recovery());
    assert_eq!(
        authority.state.borrow().current.as_ref().unwrap().revision,
        3
    );
}
